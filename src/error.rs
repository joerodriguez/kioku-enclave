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
    // The summarizer window (`summarizer.window`) and its ADR-0034
    // settled-tail gate (`summarizer.session_settled_gate`) were registered
    // here until their evidence reads migrated. Both are routed now — the
    // window reads, the F8 episode upsert at its tail, and the F9 embedding
    // batch all reach the WAL lane — so the constants are deleted rather than
    // left standing over a live domain.
    // The delivery group has no remaining D4 gate. Email, push, and webhook
    // each route their selected scans, freeze the exact provider request
    // before I/O, acquire a durable Control disclosure fence, and settle from
    // the carried pre-send predecessor. Their legacy owners remain separate.

    // ── Request paths: the read lane ────────────────────────────────────────
    //
    // No request-path D4 constant remains in this block. The routed reads stay
    // because selected browser evidence and selected two-stage episode deletion
    // are now answerable, while the unselected fallthrough still benefits from
    // SQLite's `query_only` guard.
    //
    // **The evidence chain is LIVE end to end, and that is why this block is
    // now short.** It was walked writer by writer, per line, not per file:
    //
    //   * `upload_capture_event` (`cp/media.rs`) settles
    //     `CanonicalCaptureEventPlan`, whose `apply` calls
    //     `media::record_source_event_in_transaction` — the sole production
    //     writer of a canonical `capture_events` row, its `media_objects`
    //     sibling, its `capture_sessions`/`capture_streams` parents and its
    //     `media_processing_jobs` job.
    //   * Those jobs give `MediaWorkClaimPlan` something to claim, so
    //     `media_work_units` fills.
    //   * `process_work_unit` returns early for a selected user into
    //     `settle_audio_window_transcript` / `settle_screen_storyboard_result`
    //     (`media_worker.rs`), whose sealed families write the evidence:
    //     `media_worker/wal/audio_result.rs::write_turns` inserts
    //     `audio_segments`, `speaker_observations` and `utterances`;
    //     `media_worker/wal/result.rs::write_frame` inserts `screenshots` and
    //     `screen_observations` and flips `media_objects.processing_state` to
    //     `'ready'`. Both are reached ONLY on the WAL lane, so the early
    //     return is what makes them live, not what fences them.
    //   * `summarizer::wal_authoritative_upsert` settles
    //     `EpisodeWindowUpsertPlan`, whose `apply`
    //     (`summarizer/wal/window.rs`) holds the only non-fixture
    //     `INSERT INTO episodes` AND `INSERT ... INTO episode_members` in the
    //     tree.
    //
    // Classify such a hit by its nearest enclosing `#[cfg(test)]`, never by
    // its file: `summarizer/wal.rs` and `summarizer.rs` each carry a
    // convincing `INSERT INTO episodes` inside a test `seed()` helper, and
    // both have been mistaken for production writers.
    //
    // ── The media read domains ──────────────────────────────────────────────
    //
    // THE ANSWERABILITY RULE (ADR-0022 D4). It is the criterion every gate in
    // this registry is judged by, in BOTH directions:
    //
    //   A read stays gated while every production writer of the tables it
    //   reads is itself a deferred domain. Such a read cannot answer anything
    //   but an absence, and an absence is indistinguishable from a truthful
    //   empty archive — which is the exact failure the deferral registry
    //   exists to prevent. These reads lift **together with** the domain that
    //   fills their tables, never before it.
    //
    // The rule is about ANSWERABILITY, not about mechanism, and the two halves
    // are independent. Routing decides *which store* answers; the rule decides
    // *whether an answer exists to give*. A read can satisfy one and fail the
    // other, and each failure has its own signature:
    //
    //   * answerable but UNROUTED — lifting yields a `with_user` refusal on
    //     every call. That is the delivery group above, and it is why "the
    //     rows exist now" is not on its own a reason to delete a constant.
    //   * routed but UNANSWERABLE — lifting yields `200` with an empty
    //     collection or a bare 404. That was the historical browser/episode
    //     read shape before their exact writers and deletion lifecycle landed.
    //
    // The registry's "delete a constant only when its domain actually
    // migrates" instruction is read through this rule: a domain migrates when
    // its writers migrate AND its readers are re-plumbed. Deleting one early
    // does not merely leave dead gate surface; it converts a deferral into a
    // 200 with an empty collection or a 404, which is the one outcome no
    // refusal is allowed to wear.
    //
    // Capture ingest (`media.capture_events`) and the four reads that were
    // answerability-blocked on it — `media.stream_ack`,
    // `media.capture_event_status`, `media.capture_sessions` and
    // `media.capture_session_status` — MIGRATED and their constants are gone.
    // `upload_capture_event` now routes both of its dispositions through
    // sealed plan families (`CanonicalCaptureEventPlan` and
    // `MediaReferenceEventPlan`), so it is a live writer of `capture_events`,
    // `capture_streams` and every canonical `capture_sessions` row, and the
    // absences those four reads report are truthful again.
    //
    // Downstream of that, the whole evidence chain came alive, and the reads
    // that were blocked on it lifted with it: `mcp.tools`, `query.search`,
    // `query.episodes`, `query.episode_members`, `query.feed`, `sync.status`
    // and `sync.export` are gone from this registry. Each was answerable
    // (`utterances`, `screenshots`, `episodes`, `episode_members`,
    // `audio_segments` and `episode_final_briefs` all have live sealed
    // writers) AND already routed, so each lifted as the one-line deletion
    // this block promised. `sync.export` is the widest of them and lifted on
    // the same evidence rather than a fortiori against it: its dominant
    // collections carry rows. The last four people reads have now lifted as
    // well: audio v3 freezes only literal high-confidence self-identification,
    // and the provider-free VoiceProfile family exact-commits the corresponding
    // person, accepted name claim, facts, and profile binding. A selected
    // empty roster is therefore answerable rather than a deferred writer gap.
    //
    // No production D4 domain remains registered. Keep this empty module as
    // the stable home for the generic refusal machinery and as an explicit
    // assertion that a future deferred domain must be reviewed and named here.
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

    #[error("PostgreSQL error: {0}")]
    Postgres(#[from] sqlx::Error),

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

    const TEST_DEFERRED_DOMAIN: &str = "test.deferred";

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
        let response = EnclaveError::wal_domain_unmigrated(TEST_DEFERRED_DOMAIN).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_body(response).await;
        assert_eq!(body["error"], WAL_DOMAIN_UNMIGRATED_REASON);
        assert_eq!(body["domain"], TEST_DEFERRED_DOMAIN);
    }

    /// The generic arm answers an opaque 500 `internal error`. A deferral
    /// falling into it would be indistinguishable from a real fault, which is
    /// exactly the failure D4 exists to prevent.
    #[tokio::test]
    async fn a_deferred_domain_never_falls_into_the_generic_internal_error() {
        for domain in [TEST_DEFERRED_DOMAIN] {
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
    fn the_production_deferred_domain_registry_is_empty() {
        let registry_source = include_str!("error.rs");
        let registry = registry_source
            .split_once("pub mod wal_domain {")
            .and_then(|(_, tail)| tail.split_once("/// The stable machine-readable reason"))
            .map(|(body, _)| body)
            .expect("the named registry module must remain present");
        assert!(!registry.contains("pub const "));
    }
}
