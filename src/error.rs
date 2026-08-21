use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionPendingReason {
    SoftDeleteRetention,
    LegacySnapshotTooLarge,
    LegacyGenerationUnavailable,
    LegacyInventoryIncomplete,
    LegacyWriteIntentUnsettled,
    /// The archive reached the ADR-0022 `wal_authoritative` terminal, so the
    /// authoritative data lives in the archive-v3 keyspace that the legacy
    /// sweep cannot see, and this image has no archive-v3 deletion authority
    /// installed. Deletion stays pending — never falsely complete.
    ArchiveV3DeletionUnwired,
    /// The archive-v3 lane's rungs. Each one means "this stage is durable, the
    /// next is not yet" — the untouched reconciler retries and the account is
    /// never reported complete in between.
    ArchiveV3MediaInventoryPending,
    ArchiveV3TombstonePending,
    ArchiveV3InventoryPending,
    ArchiveV3ErasurePending,
    ArchiveV3MediaErasurePending,
    ArchiveV3DrainPending,
    ArchiveV3ControlCleanupPending,
    /// A class no retry can clear: an inventory bound was exceeded, the frozen
    /// archive could not be enumerated before key erasure, or the frozen
    /// billing ledger still holds an unsettleable intent. Keys are left intact
    /// for manual recovery and the operation parks.
    ArchiveV3ManualRequired,
}

impl DeletionPendingReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftDeleteRetention => "soft_delete_retention",
            Self::LegacySnapshotTooLarge => "legacy_snapshot_too_large",
            Self::LegacyGenerationUnavailable => "legacy_generation_unavailable",
            Self::LegacyInventoryIncomplete => "legacy_inventory_incomplete",
            Self::LegacyWriteIntentUnsettled => "legacy_write_intent_unsettled",
            Self::ArchiveV3DeletionUnwired => "archive_v3_deletion_unwired",
            Self::ArchiveV3MediaInventoryPending => "archive_v3_media_inventory_pending",
            Self::ArchiveV3TombstonePending => "archive_v3_tombstone_pending",
            Self::ArchiveV3InventoryPending => "archive_v3_inventory_pending",
            Self::ArchiveV3ErasurePending => "archive_v3_erasure_pending",
            Self::ArchiveV3MediaErasurePending => "archive_v3_media_erasure_pending",
            Self::ArchiveV3DrainPending => "archive_v3_drain_pending",
            Self::ArchiveV3ControlCleanupPending => "archive_v3_control_cleanup_pending",
            Self::ArchiveV3ManualRequired => "archive_v3_manual_required",
        }
    }
}

impl std::fmt::Display for DeletionPendingReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureReferenceFailureReason {
    CanonicalUnavailable,
    ContextFingerprintMismatch,
    TargetMismatch,
    CanonicalContextUnavailable,
    ContextTransition,
}

impl CaptureReferenceFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalUnavailable => "canonical_unavailable",
            Self::ContextFingerprintMismatch => "context_fingerprint_mismatch",
            Self::TargetMismatch => "target_mismatch",
            Self::CanonicalContextUnavailable => "canonical_context_unavailable",
            Self::ContextTransition => "context_transition",
        }
    }
}

impl std::fmt::Display for CaptureReferenceFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionPending {
    pub reason: DeletionPendingReason,
    pub retry_after_seconds: Option<u64>,
    pub hard_delete_time: Option<String>,
}

impl std::fmt::Display for DeletionPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "account deletion pending: {}", self.reason)
    }
}

/// ADR-0022 D4 — the registry of domains that have **not** migrated to the
/// WAL-authoritative lane.
///
/// A domain listed here still reaches its rows through the legacy per-user
/// store (`Store::with_user` and everything that delegates to it), which
/// refuses outright once a user's archive reaches the `wal_authoritative`
/// terminal. `with_user` refusing is deliberately loud, but a refusal that
/// falls into a generic retry inside a worker is pathological: the worker
/// re-leases its work unit every pass and burns provider budget. The gate
/// converts "loud but pathological" into "loud and inert".
///
/// Each constant is the stable, machine-readable name of one deferred domain.
/// It is the `domain` field of the `wal_domain_skipped` worker metric and of
/// the `wal_domain_unmigrated` REST refusal body, so the names are contract
/// surface. **Delete a constant only when its domain actually migrates** —
/// removing the gate while the domain still calls `with_user` restores the
/// spin this module exists to prevent.
pub mod wal_domain {
    // ── Background workers ──────────────────────────────────────────────────
    /// `media_worker`'s voice-embedding job lane (`voice_memory` leases,
    /// reconstruction, and enrolment). The media claim/result/retention lanes
    /// around it ARE migrated and must keep running.
    pub const MEDIA_WORKER_VOICE_EMBEDDING: &str = "media_worker.voice_embedding";
    /// The bounded voice-profile reconciliation and lineage tail at the end of
    /// `media_worker::process_user`, after the migrated work-unit lanes.
    pub const MEDIA_WORKER_VOICE_PROFILES: &str = "media_worker.voice_profiles";
    // The summarizer window (`summarizer.window`) and its ADR-0034
    // settled-tail gate (`summarizer.session_settled_gate`) were registered
    // here until their evidence reads migrated. Both are routed now — the
    // window reads, the F8 episode upsert at its tail, and the F9 embedding
    // batch all reach the WAL lane — so the constants are deleted rather than
    // left standing over a live domain.
    /// The email outbox scan (`Store::next_email_delivery`). The email
    /// settlement and cancellation ladders behind it ARE migrated.
    pub const EMAIL_WORKER_OUTBOX: &str = "email_worker.outbox";
    /// The push outbox scan (`Store::next_push_delivery`). The push
    /// settlement behind it IS migrated.
    pub const PUSH_OUTBOX: &str = "push.outbox";
    /// The webhook outbox scan. The delivery-state settlement and the
    /// subscription-delete cascade behind it ARE migrated.
    pub const WEBHOOK_WORKER_OUTBOX: &str = "webhook_worker.outbox";
    /// The shared finalized-episode body loader every outbound channel reads.
    pub const DELIVERY_FINALIZED_EPISODE: &str = "delivery.finalized_episode";

    // ── Request paths: the read lane ────────────────────────────────────────
    //
    // Every constant in this block now names a surface whose call site routes
    // through `Store::wal_authoritative_read`, and whose D4 gate is RETAINED
    // above it. That is the ANSWERABILITY RULE stated in full below, applied
    // here; read that first. Routing is kept because it is strictly better for
    // the unselected population — the fallthrough is `with_user_read`, so
    // their reads now run under SQLite's `query_only` guard, which the raw
    // `with_user` it replaced did not apply — and because it turns lifting
    // each gate into a one-line deletion at the gate site.
    //
    // The dependency graph was walked writer by writer, not assumed:
    //
    //   * `MEDIA_CAPTURE_EVENTS` defers the only route that produces a
    //     `media_disposition='canonical'` `capture_events` row and its
    //     `media_objects` sibling. Its migrated replacement,
    //     `CanonicalCaptureEventPlan`, has NO production constructor — every
    //     `::new` is inside a test module. So both tables start empty and stay
    //     empty.
    //   * With no `media_objects`/`media_processing_jobs` rows there is
    //     nothing for `MediaWorkClaimPlan` to claim, so `media_work_units`
    //     never gets a first row.
    //   * `utterances` and `screenshots` therefore stay empty. Note their WAL
    //     writers are LIVE, not deferred: `media_worker/wal/audio_result.rs`
    //     inserts `utterances`, `media_worker/wal/result.rs` inserts
    //     `screenshots`, and the audio lane's T24 `sqlite_sequence` gate now
    //     OPENS on a genesis archive because the sealed re-baseline added
    //     AUTOINCREMENT to `audio_segments`/`utterances`/`screenshots`. They
    //     are starved, not fenced — which is exactly why these gates cannot be
    //     inferred from "no writer exists" and have to be reasoned about.
    //   * With no evidence, `SUMMARIZER_WINDOW` (deferred) has nothing to
    //     build `episodes` from, and `summarizer/wal/window.rs` holds the only
    //     non-fixture `INSERT INTO episodes` in the tree.
    //
    // Three live writers touch these tables without refuting any of that: the
    // migrated ADR-0032 screen-reference-batch route inserts `capture_events`
    // but only a `reference` row bound to an existing canonical event, and
    // refuses `CanonicalUnavailable` before reaching any INSERT; the migrated
    // `CaptureSessionFinishPlan` only UPDATEs an existing session's
    // `ended_at`; and the finalizer and `query/wal/finalization_queue.rs` only
    // UPDATE an existing `episodes` row. None can write a first row.

    /// Every `/mcp` tool read. The gate sits at the single dispatch point, and
    /// answers with an `error` key so `isError` is set on the tool result —
    /// never an empty payload, which the assistant reports to the user as "you
    /// have no data" for an archive that is fully present.
    ///
    /// **The one known exception to the answerability rule below.**
    /// `reviewer::ensure_demo_archive` (production caller: `oauth.rs`) is a
    /// LIVE, migrated writer: for a WAL-authoritative user it settles
    /// `ReviewerFixturePlan` through `wal_authoritative_submit`, inserting
    /// `audio_segments`, `utterances`, `screenshots`, `episodes`,
    /// `episode_members` and `episode_final_briefs`. For exactly one account —
    /// the namespaced App Store reviewer identity — these reads would have
    /// real rows to answer with, and the gate refuses them.
    ///
    /// The gate stays anyway, because it is per DOMAIN and cannot be lifted
    /// for one account: lifting it ungates every ordinary selected user, whose
    /// archive is genuinely empty, and a false "you have no memories" is worse
    /// than a 503 that says to retry. Narrowing this to the reviewer identity
    /// is a separate, reviewed change.
    pub const MCP_TOOLS: &str = "mcp.tools";
    pub const QUERY_SEARCH: &str = "query.search";
    pub const QUERY_EPISODES: &str = "query.episodes";
    /// `DELETE /api/episodes/{id}`. The ONE read-lane route that is not a
    /// read, and the one gate here that does NOT rest on the answerability
    /// rule: it enumerates the episode's media keys, deletes those objects
    /// from GCS, then purges the rows. The purge is a durable mutation needing
    /// a sealed plan family of its own, so routing only its lookup would be
    /// strictly worse than deferring — a selected user would pass the routed
    /// read, have their media irreversibly deleted, and then fail on the
    /// legacy purge. Media gone, rows intact, no retry that repairs it.
    pub const QUERY_EPISODE_DELETE: &str = "query.episode_delete";
    pub const QUERY_EPISODE_MEMBERS: &str = "query.episode_members";
    pub const QUERY_BROWSER_SNAPSHOT: &str = "query.browser_snapshot";
    pub const QUERY_FEED: &str = "query.feed";
    pub const QUERY_SCREENSHOT_UPLOAD_PLAN: &str = "query.screenshot_upload_plan";
    /// `GET /api/screenshot-images/{id}/content`. Its identity tables —
    /// `screenshot_images` (legacy evidence) and `media_objects` (Cloud
    /// Capture v2) — have no live writer, so the route can only ever answer
    /// 404 for a selected user: an absence indistinguishable from a screenshot
    /// that was never captured. `app_metadata`, the third table it reads, DOES
    /// have a live writer (the migrated media-DEK install, reachable through
    /// the ungated `POST /api/screenshot-images`), but a wrapped key is not
    /// content and cannot make an image resolvable. The rule is applied to the
    /// tables that decide the answer.
    pub const QUERY_SCREENSHOT_IMAGE_CONTENT: &str = "query.screenshot_image_content";
    // ── The media read domains ──────────────────────────────────────────────
    //
    // THE ANSWERABILITY RULE (ADR-0022 D4, and the reason the six constants
    // below outlive their routing):
    //
    //   A read stays gated while every production writer of the tables it
    //   reads is itself a deferred domain. Such a read cannot answer anything
    //   but an absence, and an absence is indistinguishable from a truthful
    //   empty archive — which is the exact failure the deferral registry
    //   exists to prevent. These reads lift **together with** the domain that
    //   fills their tables, never before it.
    //
    // The rule is about ANSWERABILITY, not about mechanism. A read whose call
    // site already routes through `Store::wal_authoritative_read` satisfies
    // the mechanical half of the migration and is still not migrated: routing
    // decides *which store* answers, and the rule decides *whether an answer
    // exists to give*. Every constant below therefore names a domain whose
    // route is already written and whose gate fires above it, so lifting one
    // is a one-line deletion at the gate site — never a rewrite.
    //
    // The registry's "delete a constant only when its domain actually
    // migrates" instruction is read through this rule: a domain migrates when
    // its writers migrate, not when its readers are re-plumbed. Deleting one
    // of these early does not merely leave dead gate surface; it converts a
    // deferral into a 200 with an empty collection or a 404, which is the one
    // outcome no refusal is allowed to wear.
    //
    /// Capture ingest itself: the sole production writer of `capture_events`,
    /// `capture_streams` and every canonical `capture_sessions` row. Every
    /// other media read gate below is answerability-blocked on THIS one.
    pub const MEDIA_CAPTURE_EVENTS: &str = "media.capture_events";
    /// `stream_ack`'s contiguous-acknowledgement read over `capture_streams`.
    /// A pure SELECT, so it is not gated for writing — it is gated because
    /// every canonical stream it could name is created by
    /// `MEDIA_CAPTURE_EVENTS` above, so a routed answer is `NotFound` -> 404
    /// "no such stream" when the truth is "your ingest is deferred".
    pub const MEDIA_STREAM_ACK: &str = "media.stream_ack";
    /// `capture_status`'s single-event read over `capture_events`, whose only
    /// production writer is `MEDIA_CAPTURE_EVENTS`.
    pub const MEDIA_CAPTURE_EVENT_STATUS: &str = "media.capture_event_status";
    /// `list_capture_sessions`' bounded session listing. It answers a
    /// COLLECTION, so its ungated failure mode is the worst shape the rule
    /// names: `200 {"sessions": []}`, a refusal wearing a truthful-empty face.
    pub const MEDIA_CAPTURE_SESSIONS: &str = "media.capture_sessions";
    /// `capture_session_status`' single-session read. Its rows and its whole
    /// evidence rollup are written by ingest.
    pub const MEDIA_CAPTURE_SESSION_STATUS: &str = "media.capture_session_status";
    /// The four people reads (`list_people`, `person_profile`,
    /// `person_evidence`, `person_statements`). Every `people` and
    /// `person_facts` row is derived by `media_worker`'s result lanes from
    /// evidence that capture ingest supplies, so with `MEDIA_CAPTURE_EVENTS`
    /// deferred there is no work unit to derive a person from; and the
    /// `voice_profiles` the listing joins are written only by the deferred
    /// `MEDIA_WORKER_VOICE_EMBEDDING` and `MEDIA_WORKER_VOICE_PROFILES` lanes.
    /// No live writer reaches these tables.
    pub const MEDIA_PEOPLE: &str = "media.people";
    /// `GET /api/sync/status` — counts and freshness over `utterances`,
    /// `screenshots` and `episodes`. Ungated it answers `200 {"counts":
    /// {"utterances": 0, ...}}`, which is not "unavailable", it is "your
    /// archive is empty".
    pub const SYNC_STATUS: &str = "sync.status";
    /// `GET /api/export` — the widest read in the lane, dumping every logical
    /// table, so the answerability rule holds for it a fortiori. An ungated
    /// export hands the user a complete-looking document with every array
    /// empty and invites them to conclude their archive is gone.
    pub const SYNC_EXPORT: &str = "sync.export";
}

/// The stable machine-readable reason a refused deferred domain reports. It is
/// the `error` field of the 503 body and the `metric` label of both the worker
/// skip and the REST refusal. Callers switch on this, never on prose.
pub const WAL_DOMAIN_UNMIGRATED_REASON: &str = "wal_domain_unmigrated";

#[derive(Debug, Error)]
pub enum EnclaveError {
    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("KMS error: {0}")]
    Kms(String),

    #[error("GCS error: {0}")]
    Gcs(String),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("attestation error: {0}")]
    Attestation(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("embedding error: {0}")]
    Embedding(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("screen reference must be rebased: {0}")]
    CaptureReference(CaptureReferenceFailureReason),

    #[error(
        "screen reference batch item {index} at sequence {sequence} must be rebased: {reason}"
    )]
    CaptureReferenceBatch {
        reason: CaptureReferenceFailureReason,
        index: usize,
        sequence: i64,
    },

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    /// The service-wide daily new-account budget is exhausted. Existing
    /// accounts are unaffected; only creation is refused.
    #[error("signup limit reached")]
    SignupLimited,

    #[error("{0}")]
    DeletionPending(DeletionPending),

    /// ADR-0022 D4: the caller reached a domain that has not migrated to the
    /// WAL-authoritative lane for a user whose archive is WAL-authoritative.
    /// The payload is one [`wal_domain`] constant. This is a deferral, not a
    /// fault: it answers with a distinguishable 503, never a generic 500 and
    /// never an authoritative-looking empty success.
    #[error("domain not migrated to the WAL lane: {0}")]
    WalDomainUnmigrated(&'static str),
}

impl EnclaveError {
    /// ADR-0022 D4: refuse one deferred domain. `domain` must be a
    /// [`wal_domain`] constant so the reported name stays stable.
    pub fn wal_domain_unmigrated(domain: &'static str) -> Self {
        Self::WalDomainUnmigrated(domain)
    }
}

impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        if let EnclaveError::CaptureReference(reason) = &self {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "screen_reference_rebase_required",
                    "reason": reason.as_str(),
                })),
            )
                .into_response();
        }
        if let EnclaveError::CaptureReferenceBatch {
            reason,
            index,
            sequence,
        } = &self
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "screen_reference_rebase_required",
                    "reason": reason.as_str(),
                    "index": index,
                    "sequence": sequence,
                })),
            )
                .into_response();
        }
        if let EnclaveError::WalDomainUnmigrated(domain) = &self {
            // Loud and inert: the deferral is counted here so a refused route
            // is as visible as a refused worker pass, and the body names the
            // domain so "not migrated yet" can never be read as "no data".
            tracing::warn!(
                metric = WAL_DOMAIN_UNMIGRATED_REASON,
                domain,
                "route domain not migrated to WAL; refusing"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": WAL_DOMAIN_UNMIGRATED_REASON,
                    "domain": domain,
                })),
            )
                .into_response();
        }
        if matches!(self, EnclaveError::SignupLimited) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "signup_limit_reached"})),
            )
                .into_response();
        }
        let (status, message) = match &self {
            EnclaveError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            EnclaveError::CaptureReference(_) | EnclaveError::CaptureReferenceBatch { .. } => {
                unreachable!("handled above")
            }
            EnclaveError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            EnclaveError::Conflict(_) | EnclaveError::DeletionPending(_) => {
                (StatusCode::CONFLICT, self.to_string())
            }
            // Intentionally vague externally — log internally
            _ => {
                tracing::error!(error = %self, "internal enclave error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, EnclaveError>;

#[cfg(test)]
mod tests {
    use super::*;

    async fn response_body(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024)
            .await
            .expect("the refusal body is small and complete");
        serde_json::from_slice(&bytes).expect("the refusal body is JSON")
    }

    /// ADR-0022 D4: a deferred domain is a deferral, not a fault. It must be
    /// distinguishable from both a broken enclave (500) and an empty archive
    /// (200 with no rows), and its reason must be machine-readable so a client
    /// can retry rather than conclude the data is gone.
    #[tokio::test]
    async fn a_deferred_domain_answers_503_naming_the_domain() {
        let response = EnclaveError::wal_domain_unmigrated(wal_domain::QUERY_FEED).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_body(response).await;
        assert_eq!(body["error"], WAL_DOMAIN_UNMIGRATED_REASON);
        assert_eq!(body["domain"], wal_domain::QUERY_FEED);
    }

    /// The generic arm answers an opaque 500 `internal error`. A deferral
    /// falling into it would be indistinguishable from a real fault, which is
    /// exactly the failure D4 exists to prevent.
    #[tokio::test]
    async fn a_deferred_domain_never_falls_into_the_generic_internal_error() {
        for domain in [
            wal_domain::MEDIA_WORKER_VOICE_EMBEDDING,
            wal_domain::PUSH_OUTBOX,
            wal_domain::MEDIA_CAPTURE_EVENTS,
            wal_domain::SYNC_EXPORT,
        ] {
            let response = EnclaveError::wal_domain_unmigrated(domain).into_response();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{domain} must defer, not fault"
            );
            let body = response_body(response).await;
            assert_ne!(body["error"], "internal error", "{domain}");
            assert_eq!(body["domain"], domain);
        }
        // A neighbouring variant keeps its opaque 500 — the deferral arm is
        // additive, not a weakening of the generic handler.
        let generic = EnclaveError::Store("something broke".into()).into_response();
        assert_eq!(generic.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response_body(generic).await["error"], "internal error");
    }

    /// Every registered domain name is stable, machine-readable, and unique:
    /// they are metric labels and response fields, not prose.
    #[test]
    fn every_registered_domain_name_is_a_unique_stable_token() {
        let domains = [
            wal_domain::MEDIA_WORKER_VOICE_EMBEDDING,
            wal_domain::MEDIA_WORKER_VOICE_PROFILES,
            wal_domain::EMAIL_WORKER_OUTBOX,
            wal_domain::PUSH_OUTBOX,
            wal_domain::WEBHOOK_WORKER_OUTBOX,
            wal_domain::DELIVERY_FINALIZED_EPISODE,
            wal_domain::MCP_TOOLS,
            wal_domain::QUERY_SEARCH,
            wal_domain::QUERY_EPISODES,
            wal_domain::QUERY_EPISODE_DELETE,
            wal_domain::QUERY_EPISODE_MEMBERS,
            wal_domain::QUERY_BROWSER_SNAPSHOT,
            wal_domain::QUERY_FEED,
            wal_domain::QUERY_SCREENSHOT_UPLOAD_PLAN,
            wal_domain::QUERY_SCREENSHOT_IMAGE_CONTENT,
            wal_domain::MEDIA_CAPTURE_EVENTS,
            wal_domain::MEDIA_CAPTURE_EVENT_STATUS,
            wal_domain::MEDIA_CAPTURE_SESSIONS,
            wal_domain::MEDIA_CAPTURE_SESSION_STATUS,
            wal_domain::MEDIA_STREAM_ACK,
            wal_domain::MEDIA_PEOPLE,
            wal_domain::SYNC_STATUS,
            wal_domain::SYNC_EXPORT,
        ];
        let unique = domains.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), domains.len(), "domain names must be unique");
        for domain in domains {
            assert!(
                domain
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'.' | b'_')),
                "{domain} is not a stable machine-readable token"
            );
        }
    }
}
