//! Backend-neutral application persistence boundaries.
//!
//! Product code depends on the typed ports exposed here, never on a database
//! connection or SQL callback. PostgreSQL is the sole structured-state
//! authority; GCS remains behind the media-object port for encrypted bytes.

mod activation;
mod admission;
mod billing;
mod capture;
mod delivery_outbox;
mod entitlement;
mod episode;
mod episode_deletion;
mod finalization;
mod gcs_media;
mod identity;
mod lifecycle;
mod media_object;
mod media_processing;
mod memory_formation;
mod memory_reconciliation;
mod model_usage;
mod notification;
mod oauth;
mod playback;
mod postgres;
mod query;
mod recording_retention;
mod work;

use std::sync::Arc;

pub(crate) use activation::{
    ActiveReconciliationAuthority, MemoryReconciliationActivationPhase,
    MemoryReconciliationActivationRepository, MemoryReconciliationActivationStatus,
};
pub(crate) use admission::{AdmissionRepository, FleetAdmissionLease};
pub(crate) use billing::BillingRepository;
pub use billing::{RecordingLeaseRequestRow, RetainedAccountMetrics};
pub(crate) use capture::{
    CaptureCommit, CaptureCommitResult, CaptureEventStatus, CapturePreflight, CaptureRepository,
    CaptureSessionEvidence, CaptureSessionMemory, CaptureSessionProcessing, CaptureSessionStage,
    CaptureSessionStatus, ReferenceBatchCommit, ReferenceBatchCommitResult,
};
pub(crate) use delivery_outbox::{
    DeliveryRepository, EmailDeliveryCandidate, EmailDeliveryClaim, FrozenEmailDelivery,
    FrozenPushDelivery, FrozenWebhookDelivery, PushDeliveryCandidate, PushDeliveryClaim,
    WebhookDeliveryCandidate, WebhookDeliveryClaim,
};
pub(crate) use entitlement::{EntitlementRepository, VertexWorkClass};
pub(crate) use episode::{
    merge_minute_summaries, merge_substance, merge_visual_evidence, normalized_substance,
    normalized_visual_evidence, EpisodeInput, EpisodePurge, MinuteBucket,
};
pub(crate) use episode_deletion::{
    EpisodeDeletionPlan, EpisodeDeletionRepository, EpisodeDeletionStart,
};
pub(crate) use finalization::{
    FinalizationClaim, FinalizationClaimRequest, FinalizationEgressGuard, FinalizationEpisode,
    FinalizationRepository, FinalizationRequest, FinalizationScreenResult, FinalizationScreenshot,
    FinalizationSettlement, FinalizationUtterance,
};
pub(crate) use gcs_media::GcsMediaObjectStore;
pub(crate) use identity::{AccountStatus, AppleAccountGrant, IdentitySessionRepository};
pub use lifecycle::AccountDeletionOperation;
pub(crate) use lifecycle::AccountLifecycleRepository;
pub(crate) use media_object::MediaObjectStore;
pub(crate) use media_processing::{
    is_owner_source_audio, is_supported_self_identification, media_provider_attempt_identity,
    names_form_refinement, prefer_claimed_display_name, AudioMediaSettlement,
    MediaFailureDisposition, MediaFailurePolicy, MediaPersonEvidence, MediaProcessingClaim,
    MediaProcessingClass, MediaProcessingJob, MediaProcessingRepository, MediaProviderAttempt,
    MediaProviderStagedResponse, MediaScreenProjection, MediaUsageSettlement,
    ScreenMediaSettlement, MAX_MEDIA_PROVIDER_ATTEMPTS, MAX_MEDIA_PROVIDER_JOURNAL_BYTES,
    MAX_MEDIA_PROVIDER_RESPONSE_BYTES,
};
pub(crate) use memory_formation::{
    capture_formation_response_schema_v1, parse_capture_formation_provider_response,
    CaptureFormationClaim, CaptureFormationProviderRequest, CaptureFormationProviderResponse,
    CaptureFormationRetryDisposition, CaptureFormationSettlement, EpisodeEmbeddingSource,
    EpisodeEmbeddingWrite, MemoryFormationRepository, OpenEpisode, SummaryScreenshot,
    SummaryUtterance, SummaryWindowClaim, SummaryWindowSettlement,
    CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS, CAPTURE_FORMATION_PROVIDER_REQUEST_MAX_BYTES,
    CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE, CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE,
};
pub(crate) use memory_reconciliation::{
    oversized_keep_policy_commitment, reconciliation_outputs_commitment,
    reconciliation_provider_attempt_identity, MemoryHandleResolution, MemoryHandleState,
    MemoryReconciliationRepository, OversizedKeepPromotionPolicy, OversizedKeepPromotionResult,
    ReconciledMemoryWrite, ReconciliationClaim, ReconciliationDraft, ReconciliationEgressGuard,
    ReconciliationEvidenceAtom, ReconciliationPublish, ReconciliationPublishResult,
    ReconciliationSnapshot, ReconciliationStageWrite, StagedReconciliation,
    MAX_OVERSIZED_KEEP_SOURCES, OVERSIZED_KEEP_MODEL, OVERSIZED_KEEP_SOURCE_PAGE_SIZE,
};
pub(crate) use model_usage::{
    vertex_attempt_event_id, vertex_invocation_fingerprint, ClaimedVertexCoverage,
    ClaimedVertexUsageBatch, ModelUsageRepository, VertexInvocationAdmission,
    VertexInvocationAttempt,
};
pub(crate) use notification::NotificationRepository;
pub use notification::{PushInstallation, WebhookSubscription};
pub(crate) use oauth::{
    AuthorizationCodeExchange, ConsentApproval, DirectAuthorizationCode, NativeSessionRefresh,
    OAuthClient, OAuthClientDefinition, OAuthClientRegistration, OAuthClientRegistrationRequest,
    OAuthRepository, PendingConsent, RefreshTokenRotation,
};
pub(crate) use playback::PlaybackRepository;
pub(crate) use postgres::{
    verify_memory_reconciliation_activation_authorization,
    verify_schema_finalization_authorization, MemoryReconciliationActivationReceipt,
    MemoryReconciliationActivationSignature, PostgresPersistence, PostgresPoolConfig,
    SchemaFinalizationReceipt, SchemaFinalizationSignature,
    VerifiedMemoryReconciliationActivationReceipt, VerifiedSchemaFinalizationReceipt,
};
pub(crate) use query::{
    extract_speaker_filter, rrf_merge, CaptureStatus, EpisodeListPage, EpisodeListRequest,
    McpContextRequest, McpTimeRangeRequest, McpTranscriptSearchRequest, MemoryFeedPage,
    MemoryFeedRecord, MemoryFeedRequest, MemoryQueryRepository, PeopleListPage, PeopleListRequest,
    PersonEvidencePage, PersonEvidenceView, PersonFactView, PersonNameView, PersonProfile,
    PersonStatementPage, PersonStatementView, PersonSummary, ScreenshotMediaLocator, SearchHit,
    SearchRequest,
};
pub(crate) use recording_retention::{
    recording_retention_preview_fingerprint, recording_retention_request_fingerprint,
    valid_retention_idempotency_key, RecordingKeyEpoch, RecordingRetentionChange,
    RecordingRetentionChangeRequest, RecordingRetentionInventory, RecordingRetentionPolicy,
    RecordingRetentionPreference, RecordingRetentionPreview, RecordingRetentionRepository,
    RECORDING_RETENTION_CONSENT_VERSION,
};
pub(crate) use work::{
    EmailProviderOutcome, PushProviderOutcome, WebhookProviderOutcome, WorkRepository,
};

/// The persistence dependencies injected into application code.
///
/// The complete PostgreSQL-backed set is selected once at startup. Keeping
/// these domain ports makes handlers and workers independently testable
/// without exposing `sqlx` outside the adapter.
#[derive(Clone)]
pub(crate) struct RepositorySet {
    admission: Arc<dyn AdmissionRepository>,
    identity_sessions: Arc<dyn IdentitySessionRepository>,
    lifecycle: Arc<dyn AccountLifecycleRepository>,
    billing: Arc<dyn BillingRepository>,
    captures: Arc<dyn CaptureRepository>,
    oauth: Arc<dyn OAuthRepository>,
    playback: Arc<dyn PlaybackRepository>,
    entitlements: Arc<dyn EntitlementRepository>,
    episode_deletions: Arc<dyn EpisodeDeletionRepository>,
    deliveries: Arc<dyn DeliveryRepository>,
    finalization: Arc<dyn FinalizationRepository>,
    notifications: Arc<dyn NotificationRepository>,
    recording_retention: Arc<dyn RecordingRetentionRepository>,
    memory_queries: Arc<dyn MemoryQueryRepository>,
    media_objects: Arc<dyn MediaObjectStore>,
    media_processing: Arc<dyn MediaProcessingRepository>,
    memory_formation: Arc<dyn MemoryFormationRepository>,
    memory_reconciliation_activation: Arc<dyn MemoryReconciliationActivationRepository>,
    memory_reconciliation: Arc<dyn MemoryReconciliationRepository>,
    model_usage: Arc<dyn ModelUsageRepository>,
    work: Arc<dyn WorkRepository>,
}

impl RepositorySet {
    pub(crate) fn postgres(
        persistence: Arc<PostgresPersistence>,
        media_objects: Arc<dyn MediaObjectStore>,
    ) -> Self {
        Self {
            admission: Arc::clone(&persistence) as Arc<dyn AdmissionRepository>,
            identity_sessions: Arc::clone(&persistence) as Arc<dyn IdentitySessionRepository>,
            lifecycle: Arc::clone(&persistence) as Arc<dyn AccountLifecycleRepository>,
            billing: Arc::clone(&persistence) as Arc<dyn BillingRepository>,
            captures: Arc::clone(&persistence) as Arc<dyn CaptureRepository>,
            oauth: Arc::clone(&persistence) as Arc<dyn OAuthRepository>,
            playback: Arc::clone(&persistence) as Arc<dyn PlaybackRepository>,
            entitlements: Arc::clone(&persistence) as Arc<dyn EntitlementRepository>,
            episode_deletions: Arc::clone(&persistence) as Arc<dyn EpisodeDeletionRepository>,
            deliveries: Arc::clone(&persistence) as Arc<dyn DeliveryRepository>,
            finalization: Arc::clone(&persistence) as Arc<dyn FinalizationRepository>,
            notifications: Arc::clone(&persistence) as Arc<dyn NotificationRepository>,
            recording_retention: Arc::clone(&persistence) as Arc<dyn RecordingRetentionRepository>,
            memory_queries: Arc::clone(&persistence) as Arc<dyn MemoryQueryRepository>,
            media_objects,
            media_processing: Arc::clone(&persistence) as Arc<dyn MediaProcessingRepository>,
            memory_formation: Arc::clone(&persistence) as Arc<dyn MemoryFormationRepository>,
            memory_reconciliation_activation: Arc::clone(&persistence)
                as Arc<dyn MemoryReconciliationActivationRepository>,
            memory_reconciliation: Arc::clone(&persistence)
                as Arc<dyn MemoryReconciliationRepository>,
            model_usage: Arc::clone(&persistence) as Arc<dyn ModelUsageRepository>,
            work: persistence,
        }
    }

    pub(crate) fn identity_sessions(&self) -> &dyn IdentitySessionRepository {
        self.identity_sessions.as_ref()
    }

    pub(crate) fn admission(&self) -> &dyn AdmissionRepository {
        self.admission.as_ref()
    }

    pub(crate) fn admission_arc(&self) -> Arc<dyn AdmissionRepository> {
        Arc::clone(&self.admission)
    }

    pub(crate) fn lifecycle(&self) -> &dyn AccountLifecycleRepository {
        self.lifecycle.as_ref()
    }

    pub(crate) fn billing(&self) -> &dyn BillingRepository {
        self.billing.as_ref()
    }

    pub(crate) fn captures(&self) -> &dyn CaptureRepository {
        self.captures.as_ref()
    }

    pub(crate) fn oauth(&self) -> &dyn OAuthRepository {
        self.oauth.as_ref()
    }

    pub(crate) fn playback(&self) -> &dyn PlaybackRepository {
        self.playback.as_ref()
    }

    pub(crate) fn entitlements(&self) -> &dyn EntitlementRepository {
        self.entitlements.as_ref()
    }

    pub(crate) fn episode_deletions(&self) -> &dyn EpisodeDeletionRepository {
        self.episode_deletions.as_ref()
    }

    pub(crate) fn deliveries(&self) -> &dyn DeliveryRepository {
        self.deliveries.as_ref()
    }

    pub(crate) fn finalization(&self) -> &dyn FinalizationRepository {
        self.finalization.as_ref()
    }

    pub(crate) fn notifications(&self) -> &dyn NotificationRepository {
        self.notifications.as_ref()
    }

    pub(crate) fn recording_retention(&self) -> &dyn RecordingRetentionRepository {
        self.recording_retention.as_ref()
    }

    pub(crate) fn memory_queries(&self) -> &dyn MemoryQueryRepository {
        self.memory_queries.as_ref()
    }

    pub(crate) fn media_objects(&self) -> &dyn MediaObjectStore {
        self.media_objects.as_ref()
    }

    pub(crate) fn media_objects_arc(&self) -> Arc<dyn MediaObjectStore> {
        Arc::clone(&self.media_objects)
    }

    pub(crate) fn media_processing(&self) -> &dyn MediaProcessingRepository {
        self.media_processing.as_ref()
    }

    pub(crate) fn memory_formation(&self) -> &dyn MemoryFormationRepository {
        self.memory_formation.as_ref()
    }

    pub(crate) fn memory_reconciliation(&self) -> &dyn MemoryReconciliationRepository {
        self.memory_reconciliation.as_ref()
    }

    pub(crate) fn memory_reconciliation_activation(
        &self,
    ) -> &dyn MemoryReconciliationActivationRepository {
        self.memory_reconciliation_activation.as_ref()
    }

    pub(crate) fn model_usage(&self) -> &dyn ModelUsageRepository {
        self.model_usage.as_ref()
    }

    pub(crate) fn work(&self) -> &dyn WorkRepository {
        self.work.as_ref()
    }
}
