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
