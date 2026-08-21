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
    /// The summarizer window: its evidence reads (`fetch_range`,
    /// `fetch_open_episodes`) are legacy, so the whole window cannot complete
    /// even though the F8 episode upsert at its tail is migrated.
    pub const SUMMARIZER_WINDOW: &str = "summarizer.window";
    /// The ADR-0034 settled-tail gate the session-settled kick consults.
    pub const SUMMARIZER_SESSION_SETTLED: &str = "summarizer.session_settled_gate";
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

    // ── Request paths ───────────────────────────────────────────────────────
    /// Every `/mcp` tool read. None of the six is migrated, so the gate sits
    /// at the single dispatch point.
    pub const MCP_TOOLS: &str = "mcp.tools";
    pub const QUERY_SEARCH: &str = "query.search";
    pub const QUERY_EPISODES: &str = "query.episodes";
    pub const QUERY_EPISODE_DELETE: &str = "query.episode_delete";
    pub const QUERY_EPISODE_MEMBERS: &str = "query.episode_members";
    pub const QUERY_BROWSER_SNAPSHOT: &str = "query.browser_snapshot";
    pub const QUERY_FEED: &str = "query.feed";
    pub const QUERY_SCREENSHOT_UPLOAD_PLAN: &str = "query.screenshot_upload_plan";
    pub const QUERY_SCREENSHOT_IMAGE_CONTENT: &str = "query.screenshot_image_content";
    pub const MEDIA_CAPTURE_EVENTS: &str = "media.capture_events";
    pub const MEDIA_STREAM_ACK: &str = "media.stream_ack";
    // `media.capture_event_status`, `media.capture_sessions`,
    // `media.capture_session_status` and `media.people` were retired when
    // `cp::media`'s capture-status, session-status, session-list and the four
    // people read routes moved onto `wal_authoritative_read`. Per this
    // module's own rule, a constant is deleted exactly when its domain
    // migrates: leaving one behind is dead gate surface that `-D warnings`
    // rejects, and re-adding one would re-defer a domain that now routes.
    pub const SYNC_STATUS: &str = "sync.status";
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
            wal_domain::SUMMARIZER_WINDOW,
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
            wal_domain::SUMMARIZER_WINDOW,
            wal_domain::SUMMARIZER_SESSION_SETTLED,
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
            wal_domain::MEDIA_STREAM_ACK,
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
