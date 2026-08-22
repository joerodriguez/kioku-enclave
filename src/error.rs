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
    // ── The delivery group ──────────────────────────────────────────────────
    //
    // These three are NOT answerability gates, and the distinction matters
    // because the answerability rule stated below is what lifted seven of
    // their neighbours. The outbox genuinely FILLS for a selected user: the
    // finalizer's sealed `FinalizationCommitPlan` writes the brief and the
    // delivery rows in one `apply`
    // (`finalizer/wal.rs::write_brief`, `::write_deliveries`), reached from
    // `finalizer::finalize_commit_settled` on the `is_wal_authoritative`
    // branch at `finalizer.rs`. There is no gate anywhere on that enqueue
    // path. So the rows are there and the reads below could answer them.
    //
    // The three mechanically blocked domains still reach their rows through
    // `Store::with_user`, which refuses a selected user outright. Lifting a
    // gate above an unrouted read does not
    // produce an answer, it produces an `Err` on every worker pass — the
    // pathological spin this registry exists to convert into an inert skip.
    //
    // Operational consequence worth knowing, and NOT a reason to lift: for a
    // selected user the email and webhook rows accumulate in
    // `state='pending'` and nothing drains them. That is a deferral backlog,
    // not loss — the rows are durable and a migrated drain will find them.

    /// The email outbox scan (`Store::next_email_delivery`). The email
    /// settlement (`email_worker::settle_email_delivery`) and cancellation
    /// (`::cancel_user_email_deliveries_settled`) ladders behind it ARE
    /// migrated, and so is the enqueue in front of it.
    ///
    /// **Lift condition — all three, each checkable at a named call site.**
    /// (1) `Store::next_email_delivery` reads through
    /// `Store::wal_authoritative_read` instead of `with_user`. (2)
    /// `delivery::load_finalized_episode` does too — see
    /// [`DELIVERY_FINALIZED_EPISODE`]; the sweep calls it on every delivery.
    /// (3) The missing-brief arm of `email_worker::deliver_user_emails` stops
    /// calling `Store::update_email_delivery_state`, which is a durable
    /// `with_user` UPDATE with NO sealed family behind it. That arm is the
    /// one an audit skips because it looks like error handling: it fires
    /// exactly when a delivery row outlives its brief, and on the WAL lane it
    /// would refuse and abort the sweep mid-flight, after the provider send.
    pub const EMAIL_WORKER_OUTBOX: &str = "email_worker.outbox";
    /// The webhook outbox scan (`webhook_worker::next_delivery` — a private
    /// free function, not a `Store` method). The delivery-state settlement
    /// (`::set_delivery_state`) and the subscription-delete cascade behind it
    /// ARE migrated, and so is the enqueue in front of it.
    ///
    /// **Lift condition — both.** (1) `webhook_worker::next_delivery` reads
    /// through `Store::wal_authoritative_read`. (2)
    /// `delivery::load_finalized_episode` does too; the webhook sweep reads
    /// `None` from it as `event_data_missing` and TERMINALISES the delivery,
    /// so this one must be migrated before the scan is, never after.
    pub const WEBHOOK_WORKER_OUTBOX: &str = "webhook_worker.outbox";
    /// The shared finalized-episode body loader every outbound channel reads
    /// (`delivery::load_finalized_episode`). Its two tables, `episodes` and
    /// `episode_final_briefs`, are both written for a selected user by the
    /// sealed `FinalizationCommitPlan`, so the join has rows to return.
    ///
    /// **Lift condition.** The loader reads through
    /// `Store::wal_authoritative_read`. Note what the gate is protecting
    /// meanwhile: it must keep answering `Err`, never `Ok(None)`, because the
    /// webhook worker converts `None` into a terminal `event_data_missing`
    /// and would destroy the outbox instead of deferring it. Any migration
    /// that routes this read has to preserve that asymmetry — a routed read
    /// whose archive is unavailable must still surface as `Err`, not as a
    /// missing brief.
    pub const DELIVERY_FINALIZED_EPISODE: &str = "delivery.finalized_episode";

    // ── Request paths: the read lane ────────────────────────────────────────
    //
    // Every constant in this block names a surface whose call site routes
    // through `Store::wal_authoritative_read`, and whose D4 gate is RETAINED
    // above it. That is the ANSWERABILITY RULE stated in full below, applied
    // here; read that first. Routing is kept because it is strictly better for
    // the unselected population — the fallthrough is `with_user_read`, so
    // their reads now run under SQLite's `query_only` guard, which the raw
    // `with_user` it replaced did not apply — and because it turns lifting
    // each gate into a one-line deletion at the gate site.
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
    // What survives in this block is therefore NOT "the chain is starved". It
    // is three specific reads whose own predicates or own tables the live
    // chain still cannot satisfy, each said exactly once below.

    /// `DELETE /api/episodes/{id}`. The ONE read-lane route that is not a
    /// read, and the one gate here that does NOT rest on the answerability
    /// rule: it enumerates the episode's media keys, deletes those objects
    /// from GCS, then purges the rows. The purge is a durable mutation needing
    /// a sealed plan family of its own, so routing only its lookup would be
    /// strictly worse than deferring — a selected user would pass the routed
    /// read, have their media irreversibly deleted, and then fail on the
    /// legacy purge. Media gone, rows intact, no retry that repairs it.
    pub const QUERY_EPISODE_DELETE: &str = "query.episode_delete";
    /// `GET /api/browser-snapshots/{source_key}`. Not starved — **orphaned**.
    /// Its two tables, `browser_snapshots` and `browser_tabs`, have NO writer
    /// anywhere in this tree, on either lane: grep them and every hit is a
    /// `CREATE TABLE`, a `SELECT`, or a foreign key. Cloud Capture v2 records
    /// the same facts in DIFFERENT tables —
    /// `media::record_browser_observation` writes `browser_states_v2` and
    /// `browser_observations_v2` — and nothing backfills the v1 pair.
    ///
    /// The client cannot even reach a key for it: the only producer of the
    /// `source_key` this route takes is `screenshots.browser_snapshot_source_key`,
    /// and the sealed screen-result family
    /// (`media_worker/wal/result.rs::write_frame`) binds that column to
    /// `NULL` unconditionally.
    ///
    /// **Lift condition.** A live writer of `browser_snapshots`/`browser_tabs`
    /// (or this route re-pointed at the `_v2` pair it can actually be answered
    /// from), AND a live writer of
    /// `screenshots.browser_snapshot_source_key`. Both, because either alone
    /// leaves a route that can only 404. Migrating capture ingest did NOT lift
    /// this one and no amount of further evidence will: the gap is a schema
    /// rename nobody finished, not a missing upstream domain.
    pub const QUERY_BROWSER_SNAPSHOT: &str = "query.browser_snapshot";
    /// `GET /api/screenshot-images/plan`. Its tables fill now — `episodes`,
    /// `episode_members` and `screenshots` all have live migrated writers —
    /// and the route still cannot answer, because its own PREDICATE excludes
    /// every row the WAL lane can produce.
    ///
    /// `query_screenshot_upload_plan` selects candidates with
    /// `c.source_key LIKE '<device_id>:%'`, the shape the retired device-sync
    /// path minted (`dev1:7`). The only WAL-lane writer of `screenshots`,
    /// `media_worker/wal/result.rs::write_frame`, mints
    /// `format!("cloud-v2:{event_id}")` unconditionally, and
    /// `POST /api/sync/batch` — the source of every device-prefixed key — is a
    /// 410 tombstone. So the candidate set is structurally empty and the
    /// answer is always `200 {"episodes": []}`: the exact refusal-wearing-a-
    /// truthful-empty-face shape the rule forbids. Its budget half is starved
    /// independently: `screenshot_images` has no WAL-lane writer either,
    /// because `wal_selected_screenshot_image_upload` stops fail-closed at the
    /// durable `SendStarted` marker, before any row is recorded.
    ///
    /// **Lift condition.** A live writer that produces `screenshots` rows
    /// whose `source_key` a real caller's `device_id` prefix matches — or the
    /// predicate re-derived so `cloud-v2:` candidates are eligible, which is a
    /// product decision (those images are already in GCS as `media_objects`
    /// and the Mac has nothing to upload for them), not a mechanical one.
    /// Checkable either way: seed through the WAL lane and assert the route
    /// returns a non-empty `episodes` array.
    pub const QUERY_SCREENSHOT_UPLOAD_PLAN: &str = "query.screenshot_upload_plan";
    /// `GET /api/screenshot-images/{id}/content`. **The closest of the
    /// remaining gates to liftable, and the one whose old rationale is now
    /// wrong** — it claimed `media_objects` had no live writer. It does:
    /// canonical capture ingest inserts the row and
    /// `media_worker/wal/result.rs` flips its `processing_state` to `'ready'`,
    /// both sealed families on the WAL lane, and ingest encrypts the object
    /// under the same `store::media_blob_context(user_id, object_key)` this
    /// route decrypts with. So the `capture-v2:<asset_id>` arm of
    /// `screenshot_image_object_key` genuinely resolves for a selected user.
    ///
    /// It is retained on the weaker of the two grounds, said plainly rather
    /// than dressed up as the answerability rule: the legacy
    /// `screenshot_images` arm still has NO WAL-lane writer (see
    /// [`QUERY_SCREENSHOT_UPLOAD_PLAN`]), and nobody has yet built the
    /// end-to-end fixture that proves the v2 arm serves BYTES rather than
    /// merely resolving a key — the route's answer also depends on the GCS
    /// object, the `app_metadata` DEK install and an AEAD open, none of which
    /// a table-shaped test exercises.
    ///
    /// **Lift condition.** A test that settles a canonical screen capture and
    /// its storyboard result through `wal_authoritative_submit` for a selected
    /// user, then asserts this route answers `200 image/jpeg` with the exact
    /// plaintext. Not "asserts it is no longer 503" — this route has a
    /// legitimate 404 (`Ok(None)`) and two legitimate 500s (DEK unwrap, AEAD
    /// open) that a weaker assertion would pass straight through.
    pub const QUERY_SCREENSHOT_IMAGE_CONTENT: &str = "query.screenshot_image_content";
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
    //     collection or a bare 404. That is the three read gates above.
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
    // collections carry rows, and the arrays that stay empty (`people`,
    // `person_facts`, `voice_profiles`) are empty because those rows do not
    // exist, which is what an export is for.
    //
    /// The four people reads (`list_people`, `person_profile`,
    /// `person_evidence`, `person_statements`). Ingest migrating does NOT lift
    /// this one, and neither does the voice work — the blocker is elsewhere.
    ///
    /// **The writers.** Every production `people` row comes from
    /// `media_worker::create_person` and every `person_facts` row from
    /// `media_worker::persist_person_fact`. Both are reached ONLY from the
    /// audio and screen RESULT lanes — `persist_audio_window_result` (directly,
    /// and via `corroborated_active_screen_person`) and
    /// `persist_storyboard_results` -> `persist_screen_result_body` ->
    /// `promote_screen_name_if_corroborated`. Neither voice domain writes
    /// either table: the only `INSERT INTO people` in `voice_lineage.rs` is
    /// inside `mod tests`. `init_schema`'s one seeded row (`kind='owner'`) does
    /// not count — it defaults to `status='unknown'` and every one of these
    /// reads requires `status='identified'`.
    ///
    /// **Why retention is still correct even though those lanes are declared
    /// migrated.** The sealed result families deliberately commit NO identity,
    /// and the exclusion is structural rather than conditional:
    /// `media_worker::wal::audio_result::AudioTurnFact` has no constructor slot
    /// for `speaker_name*` or `person_facts` at all, and the screen family's
    /// subtype is literally `screen-storyboard-no-people-v1`. For a selected
    /// user `process_work_unit` returns early into
    /// `settle_audio_window_transcript` / `settle_screen_storyboard_result`, so
    /// the two legacy persisters that DO write these tables are unreachable.
    /// A routed read would therefore answer `200 {"people": []}` — a refusal
    /// wearing the face of "you know nobody", the exact shape the rule forbids.
    ///
    /// That exclusion is enforced, not merely intended:
    /// `audio_result::tests::e2_identity_exclusion_red_line_holds_after_apply`
    /// asserts zero rows in `people`, `person_facts` and every voice table
    /// after a transcript apply, and `test_wal_idempotency_gate.py` refuses an
    /// `INSERT INTO people` anywhere in the screen family's production half.
    /// A change that lifts this gate has to move one of those two first.
    ///
    /// **What actually lifts it.** A sealed WAL family that commits `people`
    /// and `person_facts` for a selected user, wired into those two settles.
    /// Migrating `MEDIA_WORKER_VOICE_EMBEDDING` and
    /// `MEDIA_WORKER_VOICE_PROFILES` is NOT sufficient and never was: the
    /// listing LEFT JOINs `voice_profiles`, so those lanes can only change a
    /// count on a row that already exists. Lifting on them would leave
    /// `GET /api/v2/people` permanently answering an authoritative-looking
    /// empty roster.
    pub const MEDIA_PEOPLE: &str = "media.people";
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
        let response =
            EnclaveError::wal_domain_unmigrated(wal_domain::QUERY_BROWSER_SNAPSHOT).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response_body(response).await;
        assert_eq!(body["error"], WAL_DOMAIN_UNMIGRATED_REASON);
        assert_eq!(body["domain"], wal_domain::QUERY_BROWSER_SNAPSHOT);
    }

    /// The generic arm answers an opaque 500 `internal error`. A deferral
    /// falling into it would be indistinguishable from a real fault, which is
    /// exactly the failure D4 exists to prevent.
    #[tokio::test]
    async fn a_deferred_domain_never_falls_into_the_generic_internal_error() {
        for domain in [
            wal_domain::MEDIA_WORKER_VOICE_EMBEDDING,
            wal_domain::MEDIA_PEOPLE,
            wal_domain::QUERY_SCREENSHOT_IMAGE_CONTENT,
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
            wal_domain::WEBHOOK_WORKER_OUTBOX,
            wal_domain::DELIVERY_FINALIZED_EPISODE,
            wal_domain::QUERY_EPISODE_DELETE,
            wal_domain::QUERY_BROWSER_SNAPSHOT,
            wal_domain::QUERY_SCREENSHOT_UPLOAD_PLAN,
            wal_domain::QUERY_SCREENSHOT_IMAGE_CONTENT,
            wal_domain::MEDIA_PEOPLE,
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
