//! Encrypted per-user Vertex invocation ledger and content-free billing-plane
//! outbox. Starting an invocation is fail-closed until its pending intent is
//! durably persisted; terminal telemetry delivery is retried without repeating
//! a paid model call.

pub(crate) mod wal;

use std::{sync::Arc, time::Duration};

use rusqlite::{params, OptionalExtension};
use tracing::warn;

use super::{
    billing::{VertexCoverageSnapshot, VertexUsageEvent},
    vertex::{VertexMetadata, VertexOperation, VertexUsage},
    CpState,
};
use crate::error::{EnclaveError, Result};

const OUTBOX_BATCH: usize = 100;

fn refresh_coverage_conn(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute(
        "INSERT INTO vertex_usage_coverage
         (period,sequence,pending_events,lost_events,delivery_state)
         VALUES (
            strftime('%Y-%m','now'),
            1,
            (SELECT count(*) FROM vertex_usage_events
             WHERE delivery_state='pending'
               AND substr(observed_at,1,7)=strftime('%Y-%m','now')),
            0,
            'pending'
         )
         ON CONFLICT(period) DO UPDATE SET
            sequence=vertex_usage_coverage.sequence+1,
            pending_events=excluded.pending_events,
            lost_events=vertex_usage_coverage.lost_events,
            delivery_state='pending',
            updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        [],
    )?;
    Ok(())
}

fn ensure_coverage_conn(conn: &rusqlite::Connection) -> Result<bool> {
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO vertex_usage_coverage
         (period,sequence,pending_events,lost_events,delivery_state)
         VALUES (
            strftime('%Y-%m','now'),1,
            (SELECT count(*) FROM vertex_usage_events
             WHERE delivery_state='pending'
               AND substr(observed_at,1,7)=strftime('%Y-%m','now')),
            0,'pending')",
        [],
    )?;
    Ok(inserted != 0)
}

fn terminalize_prior_coverage_conn(
    conn: &rusqlite::Connection,
    current_period: &str,
) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE vertex_usage_coverage
         SET pending_events=0,
             lost_events=MAX(lost_events + pending_events,1),
             delivery_state='delivered',
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE period < ?1 AND delivery_state='pending'",
        [current_period],
    )?;
    Ok(changed != 0)
}

pub async fn begin_invocation(
    state: &CpState,
    user_id: &str,
    operation: VertexOperation,
    requested_model: &str,
    caller_anchor: &[u8; 32],
) -> Result<String> {
    state
        .repositories
        .model_usage()
        .begin_invocation(
            user_id,
            operation,
            requested_model,
            &state.config.vertex_location,
            caller_anchor,
        )
        .await
}

pub(crate) async fn legacy_begin_invocation(
    store: &crate::store::Store,
    user_id: &str,
    operation: VertexOperation,
    requested_model: &str,
    location: &str,
    caller_anchor: &[u8; 32],
) -> Result<String> {
    if store.is_wal_authoritative(user_id) {
        return begin_invocation_settled(
            store,
            user_id,
            operation,
            requested_model,
            location,
            caller_anchor,
        )
        .await;
    }
    let event_id = format!("vtx_{}", super::tokens::random_token_hex());
    let user = user_id.to_string();
    let id = event_id.clone();
    let model = requested_model.chars().take(256).collect::<String>();
    let location = location.chars().take(128).collect::<String>();
    store
        .with_user(&user, move |conn| {
            conn.execute(
                "INSERT INTO vertex_usage_events
                 (event_id,operation,requested_model,location,outcome)
                 VALUES (?1,?2,?3,?4,'started')",
                params![id, operation.as_str(), model, location],
            )?;
            refresh_coverage_conn(conn)?;
            Ok(())
        })
        .await?;
    // Cost attribution is a financial-integrity boundary: a paid request must
    // never leave before its content-free intent is durable.
    if let Err(error) = store.save_user(&user).await {
        let cleanup_id = event_id.clone();
        let _ = store
            .with_user(&user, move |conn| {
                conn.execute(
                    "DELETE FROM vertex_usage_events WHERE event_id=?1 AND outcome='started'",
                    [&cleanup_id],
                )?;
                refresh_coverage_conn(conn)?;
                Ok(())
            })
            .await;
        return Err(error);
    }
    Ok(event_id)
}

/// The WAL-authoritative half of `begin_invocation` (ADR-0022 F2).
///
/// Reads the lane sequence through the routed read, probes the previous slot
/// for a dangling intent (exact derived id, `outcome='started'`), and adopts
/// it rather than minting a second billed intent for the same logical
/// request. Otherwise it settles `VertexInvocationBeginPlan` at the observed
/// sequence. Witness settlement replaces the legacy `save_user` flush — the
/// paid request still cannot leave before its content-free intent is durable
/// — and the legacy compensating DELETE has no analogue: a failed settle
/// means no intent and no call.
async fn begin_invocation_settled(
    store: &crate::store::Store,
    user_id: &str,
    operation: VertexOperation,
    requested_model: &str,
    location: &str,
    caller_anchor: &[u8; 32],
) -> Result<String> {
    let model = requested_model.chars().take(256).collect::<String>();
    let location = location.chars().take(128).collect::<String>();
    let commitment = wal::request_commitment(operation, &model, &location, caller_anchor)
        .map_err(|_| EnclaveError::Store("vertex invocation identity derivation failed".into()))?;
    let lane = wal::VertexInvocationLane::for_operation(operation);
    // One re-read after a lost race; the lanes are single-threaded in
    // production, so a second conflict means something is genuinely wrong.
    for _ in 0..2 {
        let probe_user = user_id.to_owned();
        let (sequence, dangling) = store
            .wal_authoritative_read(user_id, move |conn| {
                let sequence = wal::read_lane_sequence(conn, lane)?;
                let dangling = if sequence > 0 {
                    let candidate =
                        wal::derive_event_id(&probe_user, lane, sequence - 1, &commitment)
                            .map_err(|_| {
                                crate::error::EnclaveError::Store(
                                    "vertex invocation identity derivation failed".into(),
                                )
                            })?;
                    let started: i64 = conn.query_row(
                        "SELECT COUNT(*) FROM vertex_usage_events
                         WHERE event_id=?1 AND outcome='started'",
                        [&candidate],
                        |row| row.get(0),
                    )?;
                    (started == 1).then_some(candidate)
                } else {
                    None
                };
                Ok((sequence, dangling))
            })
            .await?;
        if let Some(event_id) = dangling {
            // The previous slot holds OUR request's intent, still dangling:
            // the settle succeeded and the ack was lost. Adopt it.
            return Ok(event_id);
        }
        let plan = wal::VertexInvocationBeginPlan::new(
            user_id.to_owned(),
            operation,
            sequence,
            model.clone(),
            location.clone(),
            super::isotime::format_epoch_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
            ),
            caller_anchor,
        )
        .map_err(|_| EnclaveError::Store("vertex invocation plan construction failed".into()))?;
        let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
            .map_err(|_| {
                EnclaveError::Store("vertex invocation plan construction failed".into())
            })?;
        match store.wal_authoritative_submit(user_id, prepared).await {
            Ok(event_id) => return Ok(event_id),
            Err(EnclaveError::Conflict(_)) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(EnclaveError::Conflict(
        "vertex invocation lane sequence kept moving".into(),
    ))
}

/// ADR-0022: settle a terminal Response outcome as a REQUIRED operation for
/// a WAL-authoritative user — errors propagate instead of being deferred.
/// Idempotent on the event-id coordinate: a replay of an already-settled
/// outcome resolves from the ledger. Callers whose next step hard-depends on
/// the terminal row (the bound storyboard result) use this instead of the
/// best-effort `record_response` side effect.
pub(crate) async fn settle_response_required(
    state: &CpState,
    user_id: &str,
    event_id: &str,
    metadata: &VertexMetadata,
) -> Result<()> {
    state
        .repositories
        .model_usage()
        .settle_response(user_id, event_id, metadata)
        .await
}

pub async fn record_response(
    state: &CpState,
    user_id: &str,
    event_id: &str,
    metadata: &VertexMetadata,
) {
    if let Err(error) = state
        .repositories
        .model_usage()
        .settle_response(user_id, event_id, metadata)
        .await
    {
        warn!(error = %error, "Vertex usage response persistence deferred");
    }
}

pub(crate) async fn legacy_settle_response(
    store: &crate::store::Store,
    user_id: &str,
    event_id: &str,
    metadata: &VertexMetadata,
) -> Result<()> {
    let user = user_id.to_string();
    let event_id = event_id.to_string();
    if store.is_wal_authoritative(&user) {
        // ADR-0022: the terminal outcome settles on the F2-minted event id's
        // coordinate; the plan derives the metered/usage-missing fields from
        // the same metadata and refreshes coverage inside apply(). Same
        // best-effort semantics as the legacy arm.
        let prepared = wal::VertexUsageOutcomePlan::response(event_id, metadata)
            .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare)
            .map_err(|_| {
                EnclaveError::Store("vertex usage outcome plan construction failed".into())
            })?;
        return store.wal_authoritative_submit(&user, prepared).await;
    }
    let (model, normalized) = normalized_billable_response(metadata);
    let outcome = if normalized.is_some() {
        "metered"
    } else {
        "usage_missing"
    };
    let traffic = normalized_traffic_type(metadata.traffic_type.as_deref());
    store
        .with_user(&user, move |conn| {
            let normalized = normalized.unwrap_or_default();
            conn.execute(
                "UPDATE vertex_usage_events SET returned_model=?1,traffic_type=?2,
                 http_status=200,prompt_tokens=?3,input_text_tokens=?4,input_audio_tokens=?5,input_image_tokens=?6,
                 cached_input_tokens=?7,cached_input_text_tokens=?8,cached_input_audio_tokens=?9,
                 cached_input_image_tokens=?10,output_text_tokens=?11,thought_tokens=?12,total_tokens=?13,
                 outcome=?14,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE event_id=?15 AND outcome='started'",
                params![
                    model,
                    traffic,
                    to_i64(normalized.prompt_tokens),
                    to_i64(normalized.input_text_tokens),
                    to_i64(normalized.input_audio_tokens),
                    to_i64(normalized.input_image_tokens),
                    to_i64(normalized.cached_input_tokens),
                    to_i64(normalized.cached_input_text_tokens),
                    to_i64(normalized.cached_input_audio_tokens),
                    to_i64(normalized.cached_input_image_tokens),
                    to_i64(normalized.output_tokens),
                    to_i64(normalized.thought_tokens),
                    to_i64(normalized.total_tokens),
                    outcome,
                    event_id,
                ],
            )?;
            refresh_coverage_conn(conn)?;
            Ok(())
        })
        .await?;
    store.save_user(&user).await
}

pub(crate) fn normalized_billable_response(
    metadata: &VertexMetadata,
) -> (Option<String>, Option<VertexUsage>) {
    let model = metadata
        .model_version
        .as_deref()
        .filter(|value| super::vertex_model_name_is_billing_safe(value))
        .map(str::to_string);
    let usage = model.as_ref().and_then(|_| normalized_usage(metadata));
    (model, usage)
}

pub async fn record_ambiguous(
    state: &CpState,
    user_id: &str,
    event_id: &str,
    http_status: Option<u16>,
) {
    if let Err(error) = state
        .repositories
        .model_usage()
        .settle_ambiguous(user_id, event_id, http_status)
        .await
    {
        warn!(error = %error, "ambiguous Vertex usage persistence deferred");
    }
}

pub(crate) async fn legacy_settle_ambiguous(
    store: &crate::store::Store,
    user_id: &str,
    event_id: &str,
    http_status: Option<u16>,
) -> Result<()> {
    let user = user_id.to_string();
    let id = event_id.to_string();
    if store.is_wal_authoritative(&user) {
        let prepared = wal::VertexUsageOutcomePlan::ambiguous(id, http_status)
            .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare)
            .map_err(|_| {
                EnclaveError::Store("ambiguous Vertex usage plan construction failed".into())
            })?;
        return store.wal_authoritative_submit(&user, prepared).await;
    }
    store
        .with_user(&user, move |conn| {
            conn.execute(
                "UPDATE vertex_usage_events SET outcome='ambiguous',http_status=?1,
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE event_id=?2 AND outcome='started'",
                rusqlite::params![http_status, id],
            )?;
            refresh_coverage_conn(conn)?;
            Ok(())
        })
        .await?;
    store.save_user(&user).await
}

pub async fn record_not_billed(state: &CpState, user_id: &str, event_id: &str, http_status: u16) {
    if let Err(error) = state
        .repositories
        .model_usage()
        .settle_not_billed(user_id, event_id, http_status)
        .await
    {
        warn!(error = %error, "not-billed Vertex usage persistence deferred");
    }
}

pub(crate) async fn legacy_settle_not_billed(
    store: &crate::store::Store,
    user_id: &str,
    event_id: &str,
    http_status: u16,
) -> Result<()> {
    let user = user_id.to_string();
    let id = event_id.to_string();
    if store.is_wal_authoritative(&user) {
        let prepared = wal::VertexUsageOutcomePlan::not_billed(id, http_status)
            .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare)
            .map_err(|_| {
                EnclaveError::Store("not-billed Vertex usage plan construction failed".into())
            })?;
        return store.wal_authoritative_submit(&user, prepared).await;
    }
    store
        .with_user(&user, move |conn| {
            conn.execute(
                "UPDATE vertex_usage_events SET outcome='not_billed',delivery_state='delivered',http_status=?1,
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE event_id=?2 AND outcome='started'",
                rusqlite::params![http_status, id],
            )?;
            refresh_coverage_conn(conn)?;
            Ok(())
        })
        .await?;
    store.save_user(&user).await
}

pub(crate) fn normalized_traffic_type(value: Option<&str>) -> String {
    match value {
        Some("PROVISIONED_THROUGHPUT" | "provisioned_throughput") => {
            "provisioned_throughput".into()
        }
        Some("BATCH" | "batch") => "batch".into(),
        // These generateContent calls do not request batch or provisioned
        // throughput, so an omitted provider field means pay-as-you-go.
        _ => "on_demand".into(),
    }
}

fn normalized_usage(metadata: &VertexMetadata) -> Option<VertexUsage> {
    let usage = metadata.usage.as_ref()?;
    let prompt = usage.prompt_tokens.filter(|value| *value > 0)?;
    let total = usage.total_tokens.filter(|value| *value > 0)?;
    let output = usage.output_tokens?;
    // These requests configure no tools. A provider-reported tool prompt is an
    // unexpected cost component the billing contract cannot price safely.
    if usage.tool_use_prompt_tokens.unwrap_or(0) != 0 {
        return None;
    }
    if !usage.prompt_details_present {
        return None;
    }
    let input_text = usage.input_text_tokens.unwrap_or(0);
    let input_audio = usage.input_audio_tokens.unwrap_or(0);
    let input_image = usage.input_image_tokens.unwrap_or(0);
    let cached_total = usage.cached_input_tokens.unwrap_or(0);
    let (cached_text, cached_audio, cached_image) = if usage.cache_details_present {
        let values = (
            usage.cached_input_text_tokens.unwrap_or(0),
            usage.cached_input_audio_tokens.unwrap_or(0),
            usage.cached_input_image_tokens.unwrap_or(0),
        );
        if values.0.saturating_add(values.1).saturating_add(values.2) != cached_total
            || values.0 > input_text
            || values.1 > input_audio
            || values.2 > input_image
        {
            return None;
        }
        (Some(values.0), Some(values.1), Some(values.2))
    } else {
        (None, None, None)
    };
    Some(VertexUsage {
        prompt_details_present: true,
        cache_details_present: usage.cache_details_present,
        prompt_tokens: Some(prompt),
        input_text_tokens: Some(input_text),
        input_audio_tokens: Some(input_audio),
        input_image_tokens: Some(input_image),
        cached_input_tokens: Some(cached_total),
        cached_input_text_tokens: cached_text,
        cached_input_audio_tokens: cached_audio,
        cached_input_image_tokens: cached_image,
        output_tokens: Some(output),
        // Every request sets thinkingBudget=0; omission therefore means zero.
        thought_tokens: Some(usage.thought_tokens.unwrap_or(0)),
        total_tokens: Some(total),
        tool_use_prompt_tokens: usage.tool_use_prompt_tokens,
    })
}

pub(crate) fn to_i64(value: Option<u64>) -> Option<i64> {
    value.and_then(|value| i64::try_from(value).ok())
}

/// The shared timestamp shape for the settled branches: a clock hoisted out
/// of every `apply()` (R7).
fn settled_now_iso() -> String {
    super::isotime::format_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    )
}

/// The ordinary outbox's stale-intent cutoff: a durable `started` intent is
/// only crash residue once the longest generation timeout has elapsed.
const STALE_INTENT_CUTOFF_MILLIS: i64 = 180_000;

/// Account deletion's stale-intent cutoff. The deletion caller holds the
/// user's lifecycle fence, so no Vertex call can be in flight and *every*
/// remaining `started` row is already crash residue — waiting out the
/// generation timeout would only strand the ledger. This is the enumeration
/// side of the same reviewed reconcile plan: it changes which rows are named
/// as stale, never how they are settled.
const DELETION_STALE_INTENT_CUTOFF_MILLIS: i64 = 0;

/// The WAL-authoritative half of `pending_events` (ADR-0022 F3): the scan and
/// the safety partition run through the routed read with a hoisted cutoff;
/// the plan is submitted only when the resolved sets are non-empty, exactly
/// reproducing the clean-scan semantics.
async fn pending_events_settled(
    store: &crate::store::Store,
    user_id: &str,
    account_id: &str,
    stale_cutoff_millis: i64,
) -> Result<(Vec<VertexUsageEvent>, bool)> {
    let committed_at = settled_now_iso();
    let cutoff = super::isotime::format_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
            - stale_cutoff_millis,
    );
    let period = committed_at[..7].to_string();
    let account = account_id.to_string();
    let probe_period = period.clone();
    let probe_cutoff = cutoff.clone();
    let (events, stale, predecessor_lost) = store
        .wal_authoritative_read(user_id, move |conn| {
            let stale = {
                let mut statement = conn.prepare(
                    "SELECT event_id,observed_at FROM vertex_usage_events
                     WHERE outcome='started' AND observed_at <= ?1
                     ORDER BY event_id LIMIT ?2",
                )?;
                let rows = statement
                    .query_map(
                        rusqlite::params![probe_cutoff, OUTBOX_BATCH as i64],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                rows
            };
            let events = load_pending_usage_events(conn, &account)?;
            let predecessor_lost: i64 = conn
                .query_row(
                    "SELECT lost_events FROM vertex_usage_coverage WHERE period=?1",
                    [&probe_period],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            Ok((events, stale, predecessor_lost))
        })
        .await?;
    let (deliverable, poison): (Vec<_>, Vec<_>) =
        events.into_iter().partition(usage_event_models_are_safe);
    if stale.is_empty() && poison.is_empty() {
        return Ok((deliverable, false));
    }
    let mut stale_intents = stale
        .into_iter()
        .map(|(event_id, observed_at)| {
            wal::StaleIntent::new(event_id, observed_at)
                .map_err(|_| EnclaveError::Store("vertex reconcile construction failed".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    stale_intents.sort_by(|a, b| a.event_id_for_order().cmp(b.event_id_for_order()));
    let mut poison_intents = poison
        .iter()
        .map(|event| {
            wal::PoisonIntent::new(
                event.event_id.clone(),
                event.outcome.clone(),
                "pending".into(),
            )
            .map_err(|_| EnclaveError::Store("vertex reconcile construction failed".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    poison_intents.sort_by(|a, b| a.event_id_for_order().cmp(b.event_id_for_order()));
    let plan = wal::VertexIntentReconcilePlan::new(
        user_id.to_owned(),
        stale_intents,
        poison_intents,
        period,
        predecessor_lost,
        committed_at,
    )
    .map_err(|_| EnclaveError::Store("vertex reconcile construction failed".into()))?;
    let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
        .map_err(|_| EnclaveError::Store("vertex reconcile construction failed".into()))?;
    store.wal_authoritative_submit(user_id, prepared).await?;
    Ok((deliverable, true))
}

/// The exact legacy pending scan's row mapper, shared by both populations.
fn load_pending_usage_events(
    conn: &rusqlite::Connection,
    account: &str,
) -> std::result::Result<Vec<VertexUsageEvent>, rusqlite::Error> {
    let mut statement = conn.prepare(
        "SELECT event_id,operation,requested_model,returned_model,location,
                traffic_type,outcome,http_status,prompt_tokens,input_text_tokens,input_audio_tokens,input_image_tokens,
                cached_input_tokens,cached_input_text_tokens,cached_input_audio_tokens,cached_input_image_tokens,
                output_text_tokens,thought_tokens,total_tokens,observed_at
         FROM vertex_usage_events
         WHERE delivery_state='pending' AND outcome!='started'
         ORDER BY observed_at,event_id LIMIT ?1",
    )?;
    let rows = statement
        .query_map([OUTBOX_BATCH as i64], |row| {
            Ok(VertexUsageEvent {
                account_id: account.to_owned(),
                event_id: row.get(0)?,
                operation: row.get(1)?,
                requested_model: row.get(2)?,
                returned_model: row.get(3)?,
                location: row.get(4)?,
                traffic_type: row.get(5)?,
                outcome: row.get(6)?,
                http_status: row.get::<_, Option<u16>>(7)?,
                prompt_tokens: row.get::<_, Option<i64>>(8)?.and_then(nonnegative_u64),
                input_text_tokens: row.get::<_, Option<i64>>(9)?.and_then(nonnegative_u64),
                input_audio_tokens: row.get::<_, Option<i64>>(10)?.and_then(nonnegative_u64),
                input_image_tokens: row.get::<_, Option<i64>>(11)?.and_then(nonnegative_u64),
                cached_input_tokens: row.get::<_, Option<i64>>(12)?.and_then(nonnegative_u64),
                cached_input_text_tokens: row.get::<_, Option<i64>>(13)?.and_then(nonnegative_u64),
                cached_input_audio_tokens: row.get::<_, Option<i64>>(14)?.and_then(nonnegative_u64),
                cached_input_image_tokens: row.get::<_, Option<i64>>(15)?.and_then(nonnegative_u64),
                output_text_tokens: row.get::<_, Option<i64>>(16)?.and_then(nonnegative_u64),
                thought_tokens: row.get::<_, Option<i64>>(17)?.and_then(nonnegative_u64),
                total_tokens: row.get::<_, Option<i64>>(18)?.and_then(nonnegative_u64),
                observed_at: row.get(19)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub(crate) async fn legacy_pending_events(
    store: &crate::store::Store,
    user_id: &str,
    account_id: &str,
    force_started_ambiguous: bool,
) -> Result<Vec<VertexUsageEvent>> {
    let stale_cutoff_millis = if force_started_ambiguous {
        DELETION_STALE_INTENT_CUTOFF_MILLIS
    } else {
        STALE_INTENT_CUTOFF_MILLIS
    };
    if store.is_wal_authoritative(user_id) {
        loop {
            let (events, dirty) =
                pending_events_settled(store, user_id, account_id, stale_cutoff_millis).await?;
            if !events.is_empty() || !dirty {
                return Ok(events);
            }
        }
    }
    let user = user_id.to_string();
    let account = account_id.to_string();
    loop {
        let account = account.clone();
        let (events, dirty) = store
            .with_user_if_changed(&user, move |conn| {
            // A process crash can leave a durable intent without an observed
            // response. After the longest generation timeout, report it as
            // ambiguous rather than silently dropping or pricing it at zero.
            let stale_started = if force_started_ambiguous {
                conn.execute(
                    "UPDATE vertex_usage_events SET outcome='ambiguous',
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE outcome='started'",
                    [],
                )?
            } else {
                conn.execute(
                    "UPDATE vertex_usage_events SET outcome='ambiguous',
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE outcome='started'
                       AND observed_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now','-3 minutes')",
                    [],
                )?
            };
            let events = {
                let mut statement = conn.prepare(
                    "SELECT event_id,operation,requested_model,returned_model,location,
                            traffic_type,outcome,http_status,prompt_tokens,input_text_tokens,input_audio_tokens,input_image_tokens,
                            cached_input_tokens,cached_input_text_tokens,cached_input_audio_tokens,cached_input_image_tokens,
                            output_text_tokens,thought_tokens,total_tokens,observed_at
                     FROM vertex_usage_events
                     WHERE delivery_state='pending' AND outcome!='started'
                     ORDER BY observed_at,event_id LIMIT ?1",
                )?;
                let rows = statement
                    .query_map([OUTBOX_BATCH as i64], |row| {
                        Ok(VertexUsageEvent {
                            account_id: account.clone(),
                            event_id: row.get(0)?,
                            operation: row.get(1)?,
                            requested_model: row.get(2)?,
                            returned_model: row.get(3)?,
                            location: row.get(4)?,
                            traffic_type: row.get(5)?,
                            outcome: row.get(6)?,
                            http_status: row.get::<_, Option<u16>>(7)?,
                            prompt_tokens: row
                                .get::<_, Option<i64>>(8)?
                                .and_then(nonnegative_u64),
                            input_text_tokens: row
                                .get::<_, Option<i64>>(9)?
                                .and_then(nonnegative_u64),
                            input_audio_tokens: row
                                .get::<_, Option<i64>>(10)?
                                .and_then(nonnegative_u64),
                            input_image_tokens: row
                                .get::<_, Option<i64>>(11)?
                                .and_then(nonnegative_u64),
                            cached_input_tokens: row
                                .get::<_, Option<i64>>(12)?
                                .and_then(nonnegative_u64),
                            cached_input_text_tokens: row
                                .get::<_, Option<i64>>(13)?
                                .and_then(nonnegative_u64),
                            cached_input_audio_tokens: row
                                .get::<_, Option<i64>>(14)?
                                .and_then(nonnegative_u64),
                            cached_input_image_tokens: row
                                .get::<_, Option<i64>>(15)?
                                .and_then(nonnegative_u64),
                            output_text_tokens: row
                                .get::<_, Option<i64>>(16)?
                                .and_then(nonnegative_u64),
                            thought_tokens: row
                                .get::<_, Option<i64>>(17)?
                                .and_then(nonnegative_u64),
                            total_tokens: row
                                .get::<_, Option<i64>>(18)?
                                .and_then(nonnegative_u64),
                            observed_at: row.get(19)?,
                        })
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                rows
            };
            let (deliverable, poison): (Vec<_>, Vec<_>) =
                events.into_iter().partition(usage_event_models_are_safe);
            for event in &poison {
                conn.execute(
                    "UPDATE vertex_usage_events
                     SET returned_model=NULL,prompt_tokens=NULL,input_text_tokens=NULL,
                         input_audio_tokens=NULL,input_image_tokens=NULL,
                         cached_input_tokens=NULL,cached_input_text_tokens=NULL,
                         cached_input_audio_tokens=NULL,cached_input_image_tokens=NULL,
                         output_text_tokens=NULL,thought_tokens=NULL,total_tokens=NULL,
                         outcome='usage_missing',delivery_state='delivered',
                         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE event_id=?1",
                    [&event.event_id],
                )?;
            }
            let dirty = stale_started != 0 || !poison.is_empty();
            if dirty {
                refresh_coverage_conn(conn)?;
                if !poison.is_empty() {
                    conn.execute(
                        "UPDATE vertex_usage_coverage
                         SET lost_events=lost_events+?1,delivery_state='pending'
                         WHERE period=strftime('%Y-%m','now')",
                        [poison.len() as i64],
                    )?;
                }
            }
            Ok(((deliverable, dirty), dirty))
            })
            .await?;
        if dirty {
            store.save_user(&user).await?;
        }
        if !events.is_empty() || !dirty {
            return Ok(events);
        }
    }
}

fn usage_event_models_are_safe(event: &VertexUsageEvent) -> bool {
    super::vertex_model_name_is_billing_safe(&event.requested_model)
        && event
            .returned_model
            .as_deref()
            .is_none_or(super::vertex_model_name_is_billing_safe)
        && (event.outcome != "metered" || event.returned_model.is_some())
}

fn nonnegative_u64(value: i64) -> Option<u64> {
    u64::try_from(value).ok()
}

/// Routed read of the delivery predecessors for one enumerated id set,
/// ordered by event id as the plan requires.
async fn read_delivery_predecessors(
    store: &crate::store::Store,
    user_id: &str,
    event_ids: &[String],
) -> Result<Vec<wal::DeliveryEventPredecessor>> {
    let mut ids = event_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    store
        .wal_authoritative_read(user_id, move |conn| {
            let mut predecessors = Vec::with_capacity(ids.len());
            for id in &ids {
                let (attempts, updated): (i64, String) = conn.query_row(
                    "SELECT delivery_attempt_count,updated_at
                     FROM vertex_usage_events WHERE event_id=?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                predecessors.push(
                    wal::DeliveryEventPredecessor::new(id.clone(), attempts, updated).map_err(
                        |_| {
                            crate::error::EnclaveError::Store(
                                "vertex delivery predecessor construction failed".into(),
                            )
                        },
                    )?,
                );
            }
            Ok(predecessors)
        })
        .await
}

async fn settle_delivery(
    store: &crate::store::Store,
    user_id: &str,
    outcome: wal::DeliveryOutcome,
    event_ids: &[String],
) -> Result<()> {
    if event_ids.is_empty() {
        return Ok(());
    }
    let predecessors = read_delivery_predecessors(store, user_id, event_ids).await?;
    let plan = wal::VertexUsageDeliveryPlan::new(
        user_id.to_owned(),
        outcome,
        predecessors,
        settled_now_iso(),
    )
    .map_err(|_| EnclaveError::Store("vertex delivery plan construction failed".into()))?;
    let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
        .map_err(|_| EnclaveError::Store("vertex delivery plan construction failed".into()))?;
    store.wal_authoritative_submit(user_id, prepared).await
}

pub(crate) async fn legacy_complete_delivery(
    store: &crate::store::Store,
    user_id: &str,
    event_ids: &[String],
) -> Result<()> {
    if store.is_wal_authoritative(user_id) {
        return settle_delivery(store, user_id, wal::DeliveryOutcome::Delivered, event_ids).await;
    }
    let user = user_id.to_string();
    let ids = event_ids.to_vec();
    store
        .with_user(&user, move |conn| {
            let tx = conn.unchecked_transaction()?;
            for id in ids {
                tx.execute(
                    "UPDATE vertex_usage_events SET delivery_state='delivered',
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE event_id=?1",
                    [&id],
                )?;
            }
            refresh_coverage_conn(&tx)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    store.save_user(&user).await
}

/// Routed read of one coverage row's predecessor tuple.
async fn read_coverage_predecessor(
    store: &crate::store::Store,
    user_id: &str,
    period: &str,
) -> Result<Option<wal::CoveragePredecessor>> {
    let probe = period.to_string();
    store
        .wal_authoritative_read(user_id, move |conn| {
            conn.query_row(
                "SELECT sequence,pending_events,lost_events
                 FROM vertex_usage_coverage WHERE period=?1",
                [&probe],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(sequence, pending, lost)| {
                wal::CoveragePredecessor::new(probe.clone(), sequence, pending, lost).map_err(
                    |_| {
                        crate::error::EnclaveError::Store(
                            "coverage predecessor construction failed".into(),
                        )
                    },
                )
            })
            .transpose()
        })
        .await
}

async fn settle_coverage(
    store: &crate::store::Store,
    user_id: &str,
    transition: wal::CoverageTransition,
) -> Result<()> {
    let plan =
        wal::VertexCoverageLedgerPlan::new(user_id.to_owned(), transition, settled_now_iso())
            .map_err(|_| EnclaveError::Store("vertex coverage plan construction failed".into()))?;
    let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
        .map_err(|_| EnclaveError::Store("vertex coverage plan construction failed".into()))?;
    store.wal_authoritative_submit(user_id, prepared).await
}

/// The WAL-authoritative half of `pending_coverage` (ADR-0022 F5 rollover):
/// the prior-period enumeration runs through the routed read (R6), the
/// rollover settles only when something is actually stale or missing, and
/// the snapshot list is then re-read from settled state.
async fn pending_coverage_settled(
    store: &crate::store::Store,
    user_id: &str,
    account_id: &str,
) -> Result<(Vec<VertexCoverageSnapshot>, bool)> {
    let committed_at = settled_now_iso();
    let current_period = committed_at[..7].to_string();
    let account = account_id.to_string();
    let probe_period = current_period.clone();
    let (prior_pending, current_exists) = store
        .wal_authoritative_read(user_id, move |conn| {
            let mut statement = conn.prepare(
                "SELECT period,sequence,pending_events,lost_events
                 FROM vertex_usage_coverage
                 WHERE delivery_state='pending' AND period < ?1
                 ORDER BY period LIMIT 128",
            )?;
            let priors = statement
                .query_map([&probe_period], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let current: i64 = conn.query_row(
                "SELECT COUNT(*) FROM vertex_usage_coverage WHERE period=?1",
                [&probe_period],
                |row| row.get(0),
            )?;
            Ok((priors, current == 1))
        })
        .await?;
    let dirty = !prior_pending.is_empty() || !current_exists;
    if dirty {
        let priors = prior_pending
            .into_iter()
            .map(|(period, sequence, pending, lost)| {
                wal::CoveragePredecessor::new(period, sequence, pending, lost).map_err(|_| {
                    EnclaveError::Store("coverage predecessor construction failed".into())
                })
            })
            .collect::<Result<Vec<_>>>()?;
        settle_coverage(
            store,
            user_id,
            wal::CoverageTransition::Rollover {
                current_period: current_period.clone(),
                prior_pending: priors,
            },
        )
        .await?;
    }
    let probe_period = current_period.clone();
    let snapshots = store
        .wal_authoritative_read(user_id, move |conn| {
            let mut statement = conn.prepare(
                "SELECT period,sequence,pending_events,lost_events,updated_at
                 FROM vertex_usage_coverage
                 WHERE delivery_state='pending' AND period=?1
                 ORDER BY period LIMIT 12",
            )?;
            let rows = statement
                .query_map([&probe_period], |row| {
                    let sequence = checked_sql_u64(row.get(1)?, 1)?;
                    let pending_events = checked_sql_u64(row.get(2)?, 2)?;
                    let lost_events = checked_sql_u64(row.get(3)?, 3)?;
                    Ok(VertexCoverageSnapshot {
                        account_id: account.clone(),
                        period: row.get(0)?,
                        sequence,
                        pending_events,
                        lost_events,
                        observed_at: row.get(4)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await?;
    Ok((snapshots, dirty))
}

pub(crate) async fn legacy_pending_coverage(
    store: &crate::store::Store,
    user_id: &str,
    account_id: &str,
) -> Result<Vec<VertexCoverageSnapshot>> {
    if store.is_wal_authoritative(user_id) {
        return pending_coverage_settled(store, user_id, account_id)
            .await
            .map(|(snapshots, _dirty)| snapshots);
    }
    let user = user_id.to_string();
    let account = account_id.to_string();
    let (snapshots, dirty) = store
        .with_user_if_changed(&user, move |conn| {
            let current_period: String =
                conn.query_row("SELECT strftime('%Y-%m','now')", [], |row| row.get(0))?;
            let expired_terminalized = terminalize_prior_coverage_conn(conn, &current_period)?;
            let inserted = ensure_coverage_conn(conn)?;
            let mut statement = conn.prepare(
                "SELECT period,sequence,pending_events,lost_events,updated_at
                 FROM vertex_usage_coverage
                 WHERE delivery_state='pending' AND period=?1
                 ORDER BY period LIMIT 12",
            )?;
            let rows = statement.query_map([&current_period], |row| {
                let sequence = checked_sql_u64(row.get(1)?, 1)?;
                let pending_events = checked_sql_u64(row.get(2)?, 2)?;
                let lost_events = checked_sql_u64(row.get(3)?, 3)?;
                Ok(VertexCoverageSnapshot {
                    account_id: account.clone(),
                    period: row.get(0)?,
                    sequence,
                    pending_events,
                    lost_events,
                    observed_at: row.get(4)?,
                })
            })?;
            let snapshots = rows
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(crate::error::EnclaveError::from)?;
            let dirty = inserted || expired_terminalized;
            Ok(((snapshots, dirty), dirty))
        })
        .await?;
    if dirty {
        store.save_user(&user).await?;
    }
    Ok(snapshots)
}

fn checked_sql_u64(value: i64, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

pub(crate) async fn legacy_complete_coverage(
    store: &crate::store::Store,
    user_id: &str,
    period: &str,
    sequence: u64,
) -> Result<()> {
    if store.is_wal_authoritative(user_id) {
        let Some(predecessor) = read_coverage_predecessor(store, user_id, period).await? else {
            return Ok(());
        };
        if predecessor.sequence_for_caller() != i64::try_from(sequence).unwrap_or(-1) {
            // The row moved past the delivered snapshot; nothing to complete.
            return Ok(());
        }
        return settle_coverage(
            store,
            user_id,
            wal::CoverageTransition::CompleteDelivered { predecessor },
        )
        .await;
    }
    let user = user_id.to_string();
    let period = period.to_string();
    let sequence = i64::try_from(sequence)
        .map_err(|_| crate::error::EnclaveError::Config("coverage sequence overflow".into()))?;
    store
        .with_user(&user, move |conn| {
            conn.execute(
                "UPDATE vertex_usage_coverage SET delivery_state='delivered'
                 WHERE period=?1 AND sequence=?2 AND delivery_state='pending'",
                rusqlite::params![period, sequence],
            )?;
            Ok(())
        })
        .await?;
    store.save_user(&user).await
}

pub(crate) async fn legacy_persist_coverage_snapshot(
    store: &crate::store::Store,
    user_id: &str,
    predecessor: &VertexCoverageSnapshot,
    snapshot: &VertexCoverageSnapshot,
) -> Result<()> {
    if predecessor.period != snapshot.period {
        return Err(EnclaveError::Conflict(
            "coverage period changed during reconciliation".into(),
        ));
    }
    if store.is_wal_authoritative(user_id) {
        let Some(current) = read_coverage_predecessor(store, user_id, &snapshot.period).await?
        else {
            return Ok(());
        };
        if current.sequence_for_caller() != i64::try_from(predecessor.sequence).unwrap_or(-1) {
            return Err(EnclaveError::Conflict(
                "coverage predecessor changed during reconciliation".into(),
            ));
        }
        let sequence = i64::try_from(snapshot.sequence)
            .map_err(|_| crate::error::EnclaveError::Config("coverage sequence overflow".into()))?;
        let pending_events = i64::try_from(snapshot.pending_events)
            .map_err(|_| crate::error::EnclaveError::Config("coverage pending overflow".into()))?;
        let lost_events = i64::try_from(snapshot.lost_events)
            .map_err(|_| crate::error::EnclaveError::Config("coverage lost overflow".into()))?;
        return settle_coverage(
            store,
            user_id,
            wal::CoverageTransition::PersistSnapshot {
                predecessor: current,
                sequence,
                pending_events,
                lost_events,
                observed_at: snapshot.observed_at.clone(),
            },
        )
        .await;
    }
    let user = user_id.to_string();
    let period = snapshot.period.clone();
    let sequence = i64::try_from(snapshot.sequence)
        .map_err(|_| crate::error::EnclaveError::Config("coverage sequence overflow".into()))?;
    let pending_events = i64::try_from(snapshot.pending_events)
        .map_err(|_| crate::error::EnclaveError::Config("coverage pending overflow".into()))?;
    let lost_events = i64::try_from(snapshot.lost_events)
        .map_err(|_| crate::error::EnclaveError::Config("coverage lost overflow".into()))?;
    let predecessor_sequence = i64::try_from(predecessor.sequence)
        .map_err(|_| crate::error::EnclaveError::Config("coverage sequence overflow".into()))?;
    let observed_at = snapshot.observed_at.clone();
    let changed = store
        .with_user(&user, move |conn| {
            let changed = conn.execute(
                "UPDATE vertex_usage_coverage
                 SET sequence=?1,pending_events=?2,lost_events=?3,
                     delivery_state='pending',updated_at=?4
                 WHERE period=?5 AND sequence=?6",
                rusqlite::params![
                    sequence,
                    pending_events,
                    lost_events,
                    observed_at,
                    period,
                    predecessor_sequence
                ],
            )?;
            Ok(changed)
        })
        .await?;
    if changed == 0 {
        return Err(EnclaveError::Conflict(
            "coverage predecessor changed during reconciliation".into(),
        ));
    }
    store.save_user(&user).await
}

pub(crate) async fn legacy_invalidate_stale_coverage(
    store: &crate::store::Store,
    user_id: &str,
    period: &str,
    sequence: u64,
) -> Result<()> {
    if store.is_wal_authoritative(user_id) {
        let Some(predecessor) = read_coverage_predecessor(store, user_id, period).await? else {
            return Ok(());
        };
        if predecessor.sequence_for_caller() != i64::try_from(sequence).unwrap_or(-1) {
            return Ok(());
        }
        return settle_coverage(
            store,
            user_id,
            wal::CoverageTransition::InvalidateStale { predecessor },
        )
        .await;
    }
    let user = user_id.to_string();
    let period = period.to_string();
    let sequence = i64::try_from(sequence)
        .map_err(|_| crate::error::EnclaveError::Config("coverage sequence overflow".into()))?;
    store
        .with_user(&user, move |conn| {
            conn.execute(
                "UPDATE vertex_usage_coverage
                 SET sequence=sequence+1,lost_events=MAX(lost_events,1),
                     delivery_state='pending',
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE period=?1 AND sequence=?2",
                rusqlite::params![period, sequence],
            )?;
            Ok(())
        })
        .await?;
    store.save_user(&user).await
}

async fn drain_coverage(state: &CpState, user_id: &str, account_id: &str) {
    let snapshots = match state
        .repositories
        .model_usage()
        .pending_coverage(user_id, account_id)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            warn!(error = %error, "Vertex coverage snapshot read deferred");
            return;
        }
    };
    for claimed in snapshots {
        let claim_id = claimed.claim_id;
        let snapshot = claimed.snapshot;
        let anchor = match state
            .repositories
            .billing()
            .reconcile_vertex_coverage(
                user_id,
                &snapshot.period,
                snapshot.sequence,
                snapshot.pending_events,
                snapshot.lost_events,
                &snapshot.observed_at,
            )
            .await
        {
            Ok(anchor) => anchor,
            Err(error) => {
                warn!(error = %error, "Vertex coverage authority reconciliation deferred");
                continue;
            }
        };
        let anchored = VertexCoverageSnapshot {
            account_id: snapshot.account_id.clone(),
            period: anchor.period,
            sequence: anchor.sequence,
            pending_events: anchor.pending_events,
            lost_events: anchor.lost_events,
            observed_at: anchor.observed_at,
        };
        if anchored != snapshot {
            if let Err(error) = state
                .repositories
                .model_usage()
                .persist_coverage_snapshot(user_id, &claim_id, &snapshot, &anchored)
                .await
            {
                warn!(error = %error, "Vertex coverage rollback marker durability deferred");
                continue;
            }
        }
        match state.billing.report_vertex_coverage(&anchored).await {
            Ok(response) if response.acknowledged() => {
                if let Err(error) = state
                    .repositories
                    .model_usage()
                    .complete_coverage(user_id, &claim_id, &anchored.period, anchored.sequence)
                    .await
                {
                    warn!(error = %error, "Vertex coverage acknowledgement deferred");
                }
            }
            Ok(response) if response.stale => {
                if let Err(error) = state
                    .repositories
                    .model_usage()
                    .invalidate_stale_coverage(
                        user_id,
                        &claim_id,
                        &anchored.period,
                        anchored.sequence,
                    )
                    .await
                {
                    warn!(error = %error, "stale Vertex coverage invalidation deferred");
                }
            }
            _ => warn!("Vertex coverage delivery deferred"),
        }
    }
}

/// Account deletion cannot discard a terminal usage ledger that the billing
/// plane has not accounted for. The caller holds the user's lifecycle fence,
/// so every remaining `started` row is a crash residue rather than a live
/// request and can be finalized as ambiguous before delivery.
pub async fn settle_for_account_deletion(
    state: &CpState,
    user_id: &str,
    account_id: &str,
) -> Result<()> {
    loop {
        let Some(batch) = state
            .repositories
            .model_usage()
            .pending_events(user_id, account_id, true)
            .await?
        else {
            break;
        };
        let events = batch.events;
        let response = state
            .billing
            .report_vertex_usage(&events)
            .await
            .map_err(|_| {
                crate::error::EnclaveError::Config(
                    "Vertex usage settlement unavailable during deletion".into(),
                )
            })?;
        if !response.accounts_for(events.len()) {
            return Err(crate::error::EnclaveError::Config(
                "Vertex usage settlement incomplete during deletion".into(),
            ));
        }
        let ids = events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        state
            .repositories
            .model_usage()
            .complete_delivery(user_id, &batch.claim_id, &ids)
            .await?;
    }

    let snapshots = state
        .repositories
        .model_usage()
        .pending_coverage(user_id, account_id)
        .await?;
    for claimed in snapshots {
        let claim_id = claimed.claim_id;
        let snapshot = claimed.snapshot;
        let anchor = state
            .repositories
            .billing()
            .reconcile_vertex_coverage(
                user_id,
                &snapshot.period,
                snapshot.sequence,
                snapshot.pending_events,
                snapshot.lost_events,
                &snapshot.observed_at,
            )
            .await?;
        let anchored = VertexCoverageSnapshot {
            account_id: snapshot.account_id.clone(),
            period: anchor.period,
            sequence: anchor.sequence,
            pending_events: anchor.pending_events,
            lost_events: anchor.lost_events,
            observed_at: anchor.observed_at,
        };
        if anchored != snapshot {
            state
                .repositories
                .model_usage()
                .persist_coverage_snapshot(user_id, &claim_id, &snapshot, &anchored)
                .await?;
        }
        if anchored.pending_events != 0 {
            return Err(crate::error::EnclaveError::Config(
                "Vertex usage remains pending during deletion".into(),
            ));
        }
        let response = state
            .billing
            .report_vertex_coverage(&anchored)
            .await
            .map_err(|_| {
                crate::error::EnclaveError::Config(
                    "Vertex coverage settlement unavailable during deletion".into(),
                )
            })?;
        if !response.acknowledged() {
            return Err(crate::error::EnclaveError::Config(
                "Vertex coverage settlement incomplete during deletion".into(),
            ));
        }
        state
            .repositories
            .model_usage()
            .complete_coverage(user_id, &claim_id, &anchored.period, anchored.sequence)
            .await?;
    }
    Ok(())
}

pub(crate) async fn legacy_note_delivery_failure(
    store: &crate::store::Store,
    user_id: &str,
    event_ids: &[String],
) -> Result<()> {
    if store.is_wal_authoritative(user_id) {
        // Failure noting is best-effort in the legacy path too; a refused
        // settle leaves the attempt counter alone and the next drain retries.
        return settle_delivery(
            store,
            user_id,
            wal::DeliveryOutcome::AttemptFailed,
            event_ids,
        )
        .await;
    }
    let user = user_id.to_string();
    let ids = event_ids.to_vec();
    store
        .with_user(&user, move |conn| {
            for id in ids {
                conn.execute(
                    "UPDATE vertex_usage_events
                     SET delivery_attempt_count=delivery_attempt_count+1,
                         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE event_id=?1 AND delivery_state='pending'",
                    [&id],
                )?;
            }
            Ok(())
        })
        .await?;
    store.save_user(&user).await
}

pub fn spawn_delivery_worker(state: Arc<CpState>) {
    tokio::spawn(async move {
        loop {
            drain_outbox(&state).await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

pub async fn drain_outbox(state: &CpState) {
    let users = match state.repositories.work().active_account_ids().await {
        Ok(users) => users,
        Err(error) => {
            warn!(error = %error, "Vertex usage outbox user scan deferred");
            return;
        }
    };
    for user_id in users {
        let account_id = match state
            .repositories
            .billing()
            .billing_account_id(&user_id)
            .await
        {
            Ok(account_id) => account_id,
            Err(error) => {
                warn!(error = %error, "Vertex usage account mapping deferred");
                continue;
            }
        };
        let batch = match state
            .repositories
            .model_usage()
            .pending_events(&user_id, &account_id, false)
            .await
        {
            Ok(pending) => pending,
            Err(error) => {
                warn!(error = %error, "Vertex usage outbox read deferred");
                continue;
            }
        };
        if let Some(batch) = batch {
            let events = batch.events;
            let ids = events
                .iter()
                .map(|event| event.event_id.clone())
                .collect::<Vec<_>>();
            match state.billing.report_vertex_usage(&events).await {
                Ok(response) if response.accounts_for(events.len()) => {
                    if let Err(error) = state
                        .repositories
                        .model_usage()
                        .complete_delivery(&user_id, &batch.claim_id, &ids)
                        .await
                    {
                        warn!(error = %error, "Vertex usage acknowledgement persistence deferred");
                    }
                }
                Ok(_) | Err(_) => {
                    let _ = state
                        .repositories
                        .model_usage()
                        .note_delivery_failure(&user_id, &batch.claim_id, &ids)
                        .await;
                    warn!(events = events.len(), "Vertex usage delivery deferred");
                }
            }
        }
        drain_coverage(state, &user_id, &account_id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::billing::{
        BillingError, BillingGateway, CheckoutRequest, DetachResponse, RecordingLeaseGates,
        UrlResponse, UsageAuthorizeRequest, UsageAuthorizeResponse, VertexCoverageResponse,
        VertexUsageBatchResponse,
    };
    use crate::cp::vertex::VertexUsage;
    use async_trait::async_trait;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    struct SettlementGateway {
        batch_sizes: Arc<Mutex<Vec<usize>>>,
    }

    #[async_trait]
    impl BillingGateway for SettlementGateway {
        async fn summary(&self, _: &str) -> std::result::Result<Value, BillingError> {
            unreachable!()
        }

        async fn authorize(
            &self,
            _: &UsageAuthorizeRequest,
        ) -> std::result::Result<UsageAuthorizeResponse, BillingError> {
            unreachable!()
        }

        async fn checkout(
            &self,
            _: &str,
            _: &CheckoutRequest,
        ) -> std::result::Result<UrlResponse, BillingError> {
            unreachable!()
        }

        async fn portal(&self, _: &str) -> std::result::Result<UrlResponse, BillingError> {
            unreachable!()
        }

        async fn report_vertex_usage(
            &self,
            events: &[VertexUsageEvent],
        ) -> std::result::Result<VertexUsageBatchResponse, BillingError> {
            self.batch_sizes.lock().unwrap().push(events.len());
            Ok(VertexUsageBatchResponse {
                accepted: events.len(),
                duplicates: 0,
                unpriced: 0,
                ambiguous: 0,
            })
        }

        async fn report_vertex_coverage(
            &self,
            _: &VertexCoverageSnapshot,
        ) -> std::result::Result<VertexCoverageResponse, BillingError> {
            Ok(VertexCoverageResponse {
                accepted: true,
                duplicate: false,
                stale: false,
            })
        }

        async fn admin_margin(
            &self,
            _: &str,
            _: u8,
            _: Option<&str>,
        ) -> std::result::Result<Value, BillingError> {
            unreachable!()
        }

        async fn detach(&self, _: &str) -> std::result::Result<DetachResponse, BillingError> {
            unreachable!()
        }
    }

    fn settlement_state(batch_sizes: Arc<Mutex<Vec<usize>>>) -> Arc<CpState> {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let control = Arc::new(super::super::control_store::ControlStore::new(
            kms.clone(),
            gcs.clone(),
        ));
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        Arc::new(CpState {
            kms: Arc::clone(&store.kms),
            durable_recording_storage_bound: store.durable_recording_storage_bound(),
            store: Arc::clone(&store),
            control: Arc::clone(&control),
            repositories: crate::persistence::RepositorySet::legacy(control, store),
            billing: Arc::new(SettlementGateway { batch_sizes }),
            recording_lease_gate: Arc::new(RecordingLeaseGates::default()),
            config: Arc::new(super::super::CpConfig {
                base_url: "http://localhost:8080".into(),
                jwt_secrets: vec!["test".into()],
                google_desktop_client_id: "desktop".into(),
                google_ios_client_id: "ios".into(),
                google_web_client_id: "web".into(),
                google_web_client_secret: "secret".into(),
                admin_user_ids: vec![],
                signup_limit_per_day: crate::cp::control_store::TEST_SIGNUP_LIMIT,
                scheduler_sa_email: None,
                vertex_project: "project".into(),
                vertex_location: "global".into(),
                vertex_model: "gemini-3.5-flash".into(),
                quota_utterances_per_day: 1,
                quota_screenshots_per_day: 1,
                quota_mcp_calls_per_day: 1,
                quota_vertex_output_tokens_per_day: 1,
                web_origin: "http://localhost:3000".into(),
                reviewer_auth: None,
                apple_sign_in: None,
                billing_enforcement_mode: super::super::BillingEnforcementMode::Enforce,
            }),
            user_verifier: Arc::new(super::super::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            reference_batch_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            oauth_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            test_email_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
        })
    }

    #[test]
    fn coverage_refresh_never_clears_a_prior_rollback_loss() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vertex_usage_events (
                 observed_at TEXT NOT NULL,
                 delivery_state TEXT NOT NULL
             );
             CREATE TABLE vertex_usage_coverage (
                 period TEXT PRIMARY KEY,
                 sequence INTEGER NOT NULL,
                 pending_events INTEGER NOT NULL,
                 lost_events INTEGER NOT NULL,
                 delivery_state TEXT NOT NULL,
                 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
             );
             INSERT INTO vertex_usage_coverage
                 (period,sequence,pending_events,lost_events,delivery_state)
             VALUES (strftime('%Y-%m','now'),8,0,1,'delivered');
             INSERT INTO vertex_usage_events (observed_at,delivery_state)
             VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'),'pending');",
        )
        .unwrap();

        refresh_coverage_conn(&conn).unwrap();
        let after_invocation: (i64, i64, i64, String) = conn
            .query_row(
                "SELECT sequence,pending_events,lost_events,delivery_state
                 FROM vertex_usage_coverage",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(after_invocation, (9, 1, 1, "pending".into()));

        conn.execute(
            "UPDATE vertex_usage_events SET delivery_state='delivered'",
            [],
        )
        .unwrap();
        refresh_coverage_conn(&conn).unwrap();
        let after_delivery: (i64, i64, i64) = conn
            .query_row(
                "SELECT sequence,pending_events,lost_events FROM vertex_usage_coverage",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(after_delivery, (10, 0, 1));
    }

    #[test]
    fn ensuring_idle_coverage_is_dirty_only_on_first_insert() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vertex_usage_events (
                 observed_at TEXT NOT NULL,
                 delivery_state TEXT NOT NULL
             );
             CREATE TABLE vertex_usage_coverage (
                 period TEXT PRIMARY KEY,
                 sequence INTEGER NOT NULL,
                 pending_events INTEGER NOT NULL,
                 lost_events INTEGER NOT NULL,
                 delivery_state TEXT NOT NULL,
                 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
             );",
        )
        .unwrap();

        assert!(ensure_coverage_conn(&conn).unwrap());
        assert!(!ensure_coverage_conn(&conn).unwrap());
        conn.execute(
            "UPDATE vertex_usage_coverage SET delivery_state='delivered'",
            [],
        )
        .unwrap();
        for _ in 0..100 {
            assert!(!ensure_coverage_conn(&conn).unwrap());
        }
    }

    #[test]
    fn month_rollover_terminalizes_old_coverage_and_keeps_current_delivery_live() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vertex_usage_coverage (
                 period TEXT PRIMARY KEY,
                 sequence INTEGER NOT NULL,
                 pending_events INTEGER NOT NULL,
                 lost_events INTEGER NOT NULL,
                 delivery_state TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             INSERT INTO vertex_usage_coverage VALUES
                 ('2026-08',7,3,0,'pending','2026-08-31T23:59:59.000Z'),
                 ('2026-09',1,0,0,'pending','2026-09-01T00:00:01.000Z');",
        )
        .unwrap();

        assert!(terminalize_prior_coverage_conn(&conn, "2026-09").unwrap());
        let august: (i64, i64, String) = conn
            .query_row(
                "SELECT pending_events,lost_events,delivery_state
                 FROM vertex_usage_coverage WHERE period='2026-08'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(august, (0, 3, "delivered".into()));
        let september: (i64, i64, String) = conn
            .query_row(
                "SELECT pending_events,lost_events,delivery_state
                 FROM vertex_usage_coverage WHERE period='2026-09'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(september, (0, 0, "pending".into()));
        assert!(!terminalize_prior_coverage_conn(&conn, "2026-09").unwrap());
    }

    #[tokio::test]
    async fn repeated_idle_coverage_sweeps_do_not_advance_gcs_generation() {
        use crate::store::tests::{FakeGcs, FakeKms};
        use std::sync::Arc;

        let gcs = Arc::new(FakeGcs::new());
        let store = crate::store::Store::new(Arc::new(FakeKms), gcs.clone());
        let user_id = "idle-coverage-generation";
        let inserted = store
            .with_user(user_id, ensure_coverage_conn)
            .await
            .unwrap();
        assert!(inserted);
        store.save_user(user_id).await.unwrap();
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "UPDATE vertex_usage_coverage SET delivery_state='delivered'",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(user_id).await.unwrap();
        let object_name = format!("indexes/{user_id}.db.enc");
        let idle_baseline = gcs.exact_generation_count(&object_name);

        for _ in 0..100 {
            let dirty = store
                .with_user_if_changed(user_id, |conn| {
                    let dirty = ensure_coverage_conn(conn)?;
                    Ok((dirty, dirty))
                })
                .await
                .unwrap();
            if dirty {
                store.save_user(user_id).await.unwrap();
            }
        }
        assert_eq!(gcs.exact_generation_count(&object_name), idle_baseline);

        store
            .with_user(user_id, |conn| {
                refresh_coverage_conn(conn)?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(user_id).await.unwrap();
        assert_eq!(gcs.exact_generation_count(&object_name), idle_baseline + 1);
    }

    #[tokio::test]
    async fn account_deletion_settles_more_than_one_usage_batch_in_one_call() {
        let batch_sizes = Arc::new(Mutex::new(Vec::new()));
        let state = settlement_state(batch_sizes.clone());
        let user = state
            .control
            .upsert_user(
                "usage-settlement-subject",
                "settlement@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let user_id = user.id.clone();
        state
            .store
            .with_user(&user.id, move |conn| {
                let tx = conn.unchecked_transaction()?;
                for index in 0..250 {
                    tx.execute(
                        "INSERT INTO vertex_usage_events
                         (event_id,operation,requested_model,returned_model,location,
                          outcome,prompt_tokens,input_text_tokens,output_text_tokens,total_tokens)
                         VALUES (?1,'episode_summarization','gemini-3.5-flash',
                                 'gemini-3.5-flash-001','global','metered',10,10,2,12)",
                        [format!("event-{index:03}")],
                    )?;
                }
                refresh_coverage_conn(&tx)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .unwrap();
        state.store.save_user(&user.id).await.unwrap();

        settle_for_account_deletion(&state, &user.id, &format!("acct_{}", "a".repeat(64)))
            .await
            .unwrap();

        assert_eq!(*batch_sizes.lock().unwrap(), vec![100, 100, 50]);
        let remaining: i64 = state
            .store
            .read_user(&user_id, |conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM vertex_usage_events WHERE delivery_state='pending'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }

    /// ADR-0022 F5: a WAL-authoritative account's deletion must be able to
    /// BEGIN. The pre-deletion settlement used to open with a bare `with_user`
    /// sweep, which a selected user's legacy-load choke point refuses
    /// outright, so the deletion route 503'd forever and no archive was ever
    /// erased.
    ///
    /// The sweep is skipped, not rebuilt. What proves it here is the *shape*
    /// of the failure: settlement now fails at the routed lane (no serving
    /// authority is registered in this test) rather than at the legacy load.
    #[tokio::test]
    async fn deletion_settlement_never_takes_the_legacy_load_for_a_selected_user() {
        let state = settlement_state(Arc::new(Mutex::new(Vec::new())));
        let user = state
            .control
            .upsert_user(
                "wal-settlement-subject",
                "wal-settlement@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        state
            .store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    &user.id,
                    crate::archive_v3::ArchiveId::from_bytes([0x71; 16]),
                ),
            )
            .unwrap();

        let error =
            settle_for_account_deletion(&state, &user.id, &format!("acct_{}", "a".repeat(64)))
                .await
                .expect_err("no serving authority is registered in this test");
        let message = error.to_string();
        assert!(
            message.contains("no serving authority"),
            "settlement must reach the routed lane, got: {message}"
        );
        assert!(
            !message.contains("reads are routed"),
            "the bare legacy sweep must not run for a selected user, got: {message}"
        );
    }

    /// The legacy contract is byte-unchanged: an unselected account still gets
    /// the bare sweep that marks every `started` row ambiguous regardless of
    /// age, and the ordinary outbox still waits out the 180s generation
    /// timeout before calling one stale.
    #[tokio::test]
    async fn the_legacy_settlement_sweep_and_the_outbox_cutoff_are_unchanged() {
        assert_eq!(STALE_INTENT_CUTOFF_MILLIS, 180_000);
        assert_eq!(DELETION_STALE_INTENT_CUTOFF_MILLIS, 0);

        let state = settlement_state(Arc::new(Mutex::new(Vec::new())));
        let user = state
            .control
            .upsert_user(
                "legacy-settlement-subject",
                "legacy-settlement@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        state
            .store
            .with_user(&user.id, |conn| {
                // A `started` row observed *now* — far younger than the 180s
                // cutoff the outbox would apply.
                conn.execute(
                    "INSERT INTO vertex_usage_events
                     (event_id,operation,requested_model,location,outcome,observed_at)
                     VALUES ('fresh-started','episode_summarization','gemini-3.5-flash',
                             'global','started',strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    [],
                )?;
                refresh_coverage_conn(conn)?;
                Ok(())
            })
            .await
            .unwrap();
        state.store.save_user(&user.id).await.unwrap();

        settle_for_account_deletion(&state, &user.id, &format!("acct_{}", "b".repeat(64)))
            .await
            .unwrap();

        let outcome: String = state
            .store
            .read_user(&user.id, |conn| {
                Ok(conn.query_row(
                    "SELECT outcome FROM vertex_usage_events WHERE event_id='fresh-started'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(
            outcome, "ambiguous",
            "the legacy deletion sweep still settles every started row"
        );
    }

    #[test]
    fn token_conversion_never_wraps_or_invents_zero() {
        assert_eq!(to_i64(None), None);
        assert_eq!(to_i64(Some(7)), Some(7));
        assert_eq!(to_i64(Some(u64::MAX)), None);
    }

    #[test]
    fn missing_or_partial_usage_is_never_priced_as_zero() {
        assert!(normalized_usage(&VertexMetadata::default()).is_none());
        assert!(normalized_usage(&VertexMetadata {
            usage: Some(VertexUsage {
                prompt_details_present: true,
                prompt_tokens: Some(0),
                total_tokens: Some(0),
                output_tokens: Some(0),
                ..VertexUsage::default()
            }),
            ..VertexMetadata::default()
        })
        .is_none());

        let normalized = normalized_usage(&VertexMetadata {
            usage: Some(VertexUsage {
                prompt_details_present: true,
                prompt_tokens: Some(10),
                input_text_tokens: Some(10),
                output_tokens: Some(2),
                total_tokens: Some(12),
                ..VertexUsage::default()
            }),
            ..VertexMetadata::default()
        })
        .unwrap();
        assert_eq!(normalized.cached_input_tokens, Some(0));
        assert_eq!(normalized.input_audio_tokens, Some(0));
        assert_eq!(normalized.thought_tokens, Some(0));
    }

    #[test]
    fn inconsistent_cached_modality_breakdown_is_usage_missing() {
        assert!(normalized_usage(&VertexMetadata {
            usage: Some(VertexUsage {
                prompt_details_present: true,
                cache_details_present: true,
                prompt_tokens: Some(10),
                input_audio_tokens: Some(10),
                cached_input_tokens: Some(3),
                cached_input_audio_tokens: Some(4),
                output_tokens: Some(2),
                total_tokens: Some(12),
                ..VertexUsage::default()
            }),
            ..VertexMetadata::default()
        })
        .is_none());
    }

    #[test]
    fn unexpected_tool_tokens_are_usage_missing() {
        assert!(normalized_usage(&VertexMetadata {
            usage: Some(VertexUsage {
                prompt_details_present: true,
                prompt_tokens: Some(10),
                input_text_tokens: Some(10),
                output_tokens: Some(2),
                tool_use_prompt_tokens: Some(1),
                total_tokens: Some(13),
                ..VertexUsage::default()
            }),
            ..VertexMetadata::default()
        })
        .is_none());
    }

    #[test]
    fn traffic_type_is_normalized_with_known_on_demand_default() {
        assert_eq!(normalized_traffic_type(None), "on_demand");
        assert_eq!(
            normalized_traffic_type(Some("PROVISIONED_THROUGHPUT")),
            "provisioned_throughput"
        );
    }

    #[test]
    fn metered_response_requires_a_billing_safe_provider_model() {
        let complete_usage = VertexUsage {
            prompt_details_present: true,
            prompt_tokens: Some(10),
            input_text_tokens: Some(10),
            output_tokens: Some(2),
            total_tokens: Some(12),
            ..VertexUsage::default()
        };
        for model_version in [
            None,
            Some("publishers/google/models/gemini".to_string()),
            Some("m".repeat(129)),
        ] {
            let (model, usage) = normalized_billable_response(&VertexMetadata {
                model_version,
                usage: Some(complete_usage.clone()),
                ..VertexMetadata::default()
            });
            assert!(model.is_none());
            assert!(usage.is_none());
        }

        let (model, usage) = normalized_billable_response(&VertexMetadata {
            model_version: Some("gemini-3.5-flash-001".into()),
            usage: Some(complete_usage),
            ..VertexMetadata::default()
        });
        assert_eq!(model.as_deref(), Some("gemini-3.5-flash-001"));
        assert!(usage.is_some());
    }

    #[test]
    fn malformed_usage_event_does_not_poison_adjacent_valid_event() {
        let event =
            |id: &str, requested_model: &str, returned_model: Option<&str>| VertexUsageEvent {
                account_id: "acct".into(),
                event_id: id.into(),
                operation: "generate".into(),
                requested_model: requested_model.into(),
                returned_model: returned_model.map(str::to_string),
                location: "us-central1".into(),
                traffic_type: "on_demand".into(),
                outcome: "metered".into(),
                http_status: Some(200),
                prompt_tokens: Some(10),
                input_text_tokens: Some(10),
                input_audio_tokens: Some(0),
                input_image_tokens: Some(0),
                cached_input_tokens: Some(0),
                cached_input_text_tokens: None,
                cached_input_audio_tokens: None,
                cached_input_image_tokens: None,
                output_text_tokens: Some(2),
                thought_tokens: Some(0),
                total_tokens: Some(12),
                observed_at: "2026-08-09T00:00:00.000Z".into(),
            };
        let events = vec![
            event("bad", "publishers/google/models/gemini", Some("gemini")),
            event("good", "gemini-3.5-flash", Some("gemini-3.5-flash-001")),
        ];
        let (deliverable, poison): (Vec<_>, Vec<_>) =
            events.into_iter().partition(usage_event_models_are_safe);
        assert_eq!(deliverable[0].event_id, "good");
        assert_eq!(poison[0].event_id, "bad");
    }
}
