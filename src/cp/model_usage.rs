//! PostgreSQL-authoritative Vertex invocation ledger and billing outbox.
//!
//! Invocation intent is committed before provider I/O. Terminal settlement,
//! delivery claims, and billing acknowledgements are idempotent repository
//! operations so horizontal workers can safely reconcile the same work.

use std::{sync::Arc, time::Duration};

use tracing::warn;

use super::{
    billing::VertexCoverageSnapshot,
    vertex::{VertexMetadata, VertexOperation, VertexUsage},
    CpState,
};
use crate::error::Result;

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

pub(crate) fn normalized_traffic_type(value: Option<&str>) -> String {
    match value {
        Some("PROVISIONED_THROUGHPUT" | "provisioned_throughput") => {
            "provisioned_throughput".into()
        }
        Some("BATCH" | "batch") => "batch".into(),
        _ => "on_demand".into(),
    }
}

fn normalized_usage(metadata: &VertexMetadata) -> Option<VertexUsage> {
    let usage = metadata.usage.as_ref()?;
    let prompt = usage.prompt_tokens.filter(|value| *value > 0)?;
    let total = usage.total_tokens.filter(|value| *value > 0)?;
    let output = usage.output_tokens?;
    if usage.tool_use_prompt_tokens.unwrap_or(0) != 0 || !usage.prompt_details_present {
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
        thought_tokens: Some(usage.thought_tokens.unwrap_or(0)),
        total_tokens: Some(total),
        tool_use_prompt_tokens: usage.tool_use_prompt_tokens,
    })
}

pub(crate) fn to_i64(value: Option<u64>) -> Option<i64> {
    value.and_then(|value| i64::try_from(value).ok())
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

/// Flush all usage accounting before an account tombstone is finalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountDeletionSettlement {
    Complete,
    AlreadyFenced,
}

pub async fn settle_for_account_deletion(
    state: &CpState,
    user_id: &str,
    account_id: &str,
) -> Result<AccountDeletionSettlement> {
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
        let response = match state.billing.report_vertex_usage(&events).await {
            Ok(response) => response,
            Err(super::billing::BillingError::AccountDetaching) => {
                return Ok(AccountDeletionSettlement::AlreadyFenced);
            }
            Err(_) => {
                return Err(crate::error::EnclaveError::Config(
                    "Vertex usage settlement unavailable during deletion".into(),
                ));
            }
        };
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
        let response = match state.billing.report_vertex_coverage(&anchored).await {
            Ok(response) => response,
            Err(super::billing::BillingError::AccountDetaching) => {
                return Ok(AccountDeletionSettlement::AlreadyFenced);
            }
            Err(_) => {
                return Err(crate::error::EnclaveError::Config(
                    "Vertex coverage settlement unavailable during deletion".into(),
                ));
            }
        };
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
    Ok(AccountDeletionSettlement::Complete)
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

    #[test]
    fn traffic_type_is_normalized_to_billing_vocabulary() {
        assert_eq!(normalized_traffic_type(None), "on_demand");
        assert_eq!(normalized_traffic_type(Some("BATCH")), "batch");
        assert_eq!(
            normalized_traffic_type(Some("PROVISIONED_THROUGHPUT")),
            "provisioned_throughput"
        );
    }

    #[test]
    fn incomplete_provider_usage_is_never_marked_billable() {
        let metadata = VertexMetadata {
            model_version: Some("gemini-3.5-flash".into()),
            usage: Some(VertexUsage {
                prompt_tokens: Some(1),
                total_tokens: Some(2),
                output_tokens: Some(1),
                prompt_details_present: false,
                ..VertexUsage::default()
            }),
            traffic_type: None,
        };
        assert!(normalized_billable_response(&metadata).1.is_none());
    }
}
