//! Lease-owned, provider-free voice identity persistence boundary.
use crate::{
    cp::voice_quality::VoiceDiagnostics,
    error::{EnclaveError, Result},
};
use async_trait::async_trait;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VoiceCohort {
    None,
    Explicit,
    All,
}
impl VoiceCohort {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Explicit => "explicit",
            Self::All => "all",
        }
    }
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "explicit" => Ok(Self::Explicit),
            "all" => Ok(Self::All),
            _ => Err(EnclaveError::InvalidRequest(
                "invalid voice identity cohort".into(),
            )),
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct VoiceIdentityControls {
    pub cohort: VoiceCohort,
    pub explicit_account_ids: Vec<String>,
    pub paused: bool,
    pub revision: i64,
}
impl VoiceIdentityControls {
    pub(crate) fn admits(&self, account_id: &str) -> bool {
        !self.paused
            && match self.cohort {
                VoiceCohort::None => false,
                VoiceCohort::All => true,
                VoiceCohort::Explicit => {
                    self.explicit_account_ids.iter().any(|id| id == account_id)
                }
            }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct VoiceEmbeddingSource {
    pub event_id: String,
    pub capture_session_id: String,
    pub stream_kind: String,
    pub audio_role: Option<String>,
    pub audio_route: Option<String>,
    pub mime_type: String,
    pub object_name: String,
    pub object_generation: i64,
    pub byte_length: i64,
    pub sha256: String,
    pub event_start_ms: i64,
    pub event_end_ms: i64,
    pub window_start_ms: i64,
}
#[derive(Clone, Debug)]
pub(crate) struct VoiceEmbeddingClaim {
    pub account_id: String,
    pub id: i64,
    pub speaker_observation_id: i64,
    pub lease_token: String,
    pub embedding_space: String,
    pub quality_version: i64,
    pub scorer_version: i64,
    pub overlap: bool,
    pub sources: Vec<VoiceEmbeddingSource>,
}
#[derive(Default)]
pub(crate) struct VoiceEmbeddingBatch {
    pub claims: Vec<VoiceEmbeddingClaim>,
    pub expired_count: u64,
    pub exhausted_count: u64,
}
pub(crate) enum VoiceEmbeddingOutcome {
    Sample {
        embedding: Vec<f32>,
        diagnostics: VoiceDiagnostics,
        channel_domain: String,
    },
    NoEmbedding {
        diagnostics: VoiceDiagnostics,
    },
    RawMediaExpired,
    Retry,
}
#[async_trait]
pub(crate) trait VoiceIdentityRepository: Send + Sync {
    async fn owner_voice_enrollment_status(
        &self,
        account_id: &str,
    ) -> Result<OwnerVoiceEnrollmentStatus>;
    async fn forget_owner_voice_enrollment(
        &self,
        account_id: &str,
    ) -> Result<OwnerVoiceEnrollmentStatus>;
    async fn maintain_owner_voice_enrollment(&self, account_id: &str) -> Result<()>;
    async fn voice_identity_controls(&self) -> Result<VoiceIdentityControls>;
    async fn claim_voice_embeddings(
        &self,
        account_id: &str,
        owner: &str,
    ) -> Result<VoiceEmbeddingBatch>;
    /// False means the lease was superseded or already settled; no effects were written.
    async fn settle_voice_embedding(
        &self,
        claim: &VoiceEmbeddingClaim,
        outcome: VoiceEmbeddingOutcome,
    ) -> Result<bool>;
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VoiceEnrollmentState {
    Recording,
    Processing,
    Enrolled,
    Inconclusive,
    Expired,
}

impl VoiceEnrollmentState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Processing => "processing",
            Self::Enrolled => "enrolled",
            Self::Inconclusive => "inconclusive",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "recording" => Ok(Self::Recording),
            "processing" => Ok(Self::Processing),
            "enrolled" => Ok(Self::Enrolled),
            "inconclusive" => Ok(Self::Inconclusive),
            "expired" => Ok(Self::Expired),
            _ => Err(crate::error::EnclaveError::Store(
                "invalid voice enrollment state".into(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VoiceEnrollmentReason {
    MarkerMissing,
    MarkerAfterOrdinaryStart,
    UnsupportedStream,
    MultipleStreams,
    MultipleDevices,
    RouteChanged,
    EnrollmentRevoked,
    NoSpeech,
    NoEligibleSample,
    NoDominantVoice,
    OverlappingSpeech,
    RawMediaExpired,
    SourceDeleted,
    Forgotten,
    ProcessingFailed,
    SourceChanged,
}

impl VoiceEnrollmentReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MarkerMissing => "marker_missing",
            Self::MarkerAfterOrdinaryStart => "marker_after_ordinary_start",
            Self::UnsupportedStream => "unsupported_stream",
            Self::MultipleStreams => "multiple_streams",
            Self::MultipleDevices => "multiple_devices",
            Self::RouteChanged => "route_changed",
            Self::EnrollmentRevoked => "enrollment_revoked",
            Self::NoSpeech => "no_speech",
            Self::NoEligibleSample => "no_eligible_sample",
            Self::NoDominantVoice => "no_dominant_voice",
            Self::OverlappingSpeech => "overlapping_speech",
            Self::RawMediaExpired => "raw_media_expired",
            Self::SourceDeleted => "source_deleted",
            Self::Forgotten => "forgotten",
            Self::ProcessingFailed => "processing_failed",
            Self::SourceChanged => "source_changed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "marker_missing" => Ok(Self::MarkerMissing),
            "marker_after_ordinary_start" => Ok(Self::MarkerAfterOrdinaryStart),
            "unsupported_stream" => Ok(Self::UnsupportedStream),
            "multiple_streams" => Ok(Self::MultipleStreams),
            "multiple_devices" => Ok(Self::MultipleDevices),
            "route_changed" => Ok(Self::RouteChanged),
            "enrollment_revoked" => Ok(Self::EnrollmentRevoked),
            "no_speech" => Ok(Self::NoSpeech),
            "no_eligible_sample" => Ok(Self::NoEligibleSample),
            "no_dominant_voice" => Ok(Self::NoDominantVoice),
            "overlapping_speech" => Ok(Self::OverlappingSpeech),
            "raw_media_expired" => Ok(Self::RawMediaExpired),
            "source_deleted" => Ok(Self::SourceDeleted),
            "forgotten" => Ok(Self::Forgotten),
            "processing_failed" => Ok(Self::ProcessingFailed),
            "source_changed" => Ok(Self::SourceChanged),
            _ => Err(crate::error::EnclaveError::Store(
                "invalid voice enrollment reason".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct CaptureEnrollmentStatus {
    pub(crate) state: VoiceEnrollmentState,
    pub(crate) reason: Option<VoiceEnrollmentReason>,
    pub(crate) channel_domain: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct OwnerVoiceEnrollmentAttempt {
    pub(crate) state: VoiceEnrollmentState,
    pub(crate) reason: Option<VoiceEnrollmentReason>,
    pub(crate) channel_domain: Option<String>,
    pub(crate) updated_at: String,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct OwnerVoiceDomainStatus {
    pub(crate) channel_domain: String,
    pub(crate) recognized: bool,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct OwnerVoiceEnrollmentStatus {
    pub(crate) enrollment_revision: i64,
    pub(crate) domains: Vec<OwnerVoiceDomainStatus>,
    pub(crate) latest_attempt: Option<OwnerVoiceEnrollmentAttempt>,
}
