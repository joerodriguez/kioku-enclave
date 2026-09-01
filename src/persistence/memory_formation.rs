use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{error::Result, persistence::EpisodeInput};

pub(crate) const CAPTURE_FORMATION_UTTERANCE_PAGE_SIZE: i64 = 4_000;
pub(crate) const CAPTURE_FORMATION_SCREENSHOT_PAGE_SIZE: i64 = 2_000;
/// Exact persisted provider request ceiling. Oversized bounded-row pages are
/// settled providerlessly rather than truncated or retried forever.
pub(crate) const CAPTURE_FORMATION_PROVIDER_REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS: u32 = 8_192;

/// Immutable constrained-decoding schema for provider-request contract v1.
/// Any future schema change requires a new contract version rather than
/// silently reinterpreting an already admitted durable attempt.
pub(crate) fn capture_formation_response_schema_v1() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "episodes": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "episode_ref": {"type": "STRING"},
                        "started_at": {"type": "STRING"},
                        "ended_at": {"type": "STRING"},
                        "type": {"type": "STRING", "enum": ["meeting","lesson","call","coding","browsing","break","other"]},
                        "title": {"type": "STRING"},
                        "summary": {"type": "STRING"},
                        "participants": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "languages": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "action_items": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "substance": {"type": "STRING", "enum": ["none","low","normal"]},
                        "visual_evidence": {"type": "STRING", "enum": ["none","useful"]},
                        "minutes": {
                            "type": "ARRAY",
                            "items": {
                                "type": "OBJECT",
                                "properties": {
                                    "start": {"type": "STRING"},
                                    "gist": {"type": "STRING"}
                                },
                                "required": ["start","gist"]
                            }
                        }
                    },
                    "required": ["started_at","ended_at","title","summary","action_items","substance","visual_evidence","minutes"]
                }
            }
        },
        "required": ["episodes"]
    })
}

/// Structural classification of the exact staged provider bytes. Only an
/// object that explicitly contains an empty `episodes` array is a provider-
/// declared no-memory result. Missing, mistyped, or non-empty arrays must not
/// be collapsed to the same outcome after application-side normalization.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CaptureFormationProviderResponse {
    ExplicitNoMemory,
    CandidateEpisodes(Value),
}

pub(crate) fn parse_capture_formation_provider_response(
    response: &str,
) -> Option<CaptureFormationProviderResponse> {
    let parsed = serde_json::from_str::<Value>(response).ok()?;
    let episodes = parsed.as_object()?.get("episodes")?.as_array()?;
    if episodes.is_empty() {
        Some(CaptureFormationProviderResponse::ExplicitNoMemory)
    } else {
        Some(CaptureFormationProviderResponse::CandidateEpisodes(parsed))
    }
}

/// Exact provider request persisted with one page attempt before egress. A
/// claimant after a deploy reuses these bytes/settings rather than rebuilding
/// the same attempt identity under a changed prompt, model, or endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureFormationProviderRequest {
    pub(crate) contract_version: i64,
    pub(crate) vertex_project: String,
    pub(crate) vertex_location: String,
    pub(crate) api_version: String,
    pub(crate) publisher: String,
    pub(crate) model: String,
    pub(crate) method: String,
    pub(crate) system_prompt: String,
    pub(crate) user_message: String,
    pub(crate) response_schema: Value,
    pub(crate) max_output_tokens: u32,
    pub(crate) response_mime_type: String,
    pub(crate) thinking_budget: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SummaryUtterance {
    pub(crate) id: i64,
    pub(crate) started_at: String,
    pub(crate) speaker_label: String,
    pub(crate) language: Option<String>,
    pub(crate) text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SummaryScreenshot {
    pub(crate) id: i64,
    pub(crate) captured_at: String,
    pub(crate) active_app: Option<String>,
    pub(crate) window_title: Option<String>,
    pub(crate) ocr_text: Option<String>,
    pub(crate) salient_ocr_text: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) is_duplicate: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenEpisode {
    pub(crate) id: i64,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) episode_type: Option<String>,
    pub(crate) title: String,
    pub(crate) summary: Option<String>,
    pub(crate) participants: Vec<String>,
    pub(crate) action_items: Vec<String>,
    pub(crate) recent_minutes: Option<String>,
    pub(crate) utt_count: i64,
    pub(crate) scr_count: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SummaryWindowClaim {
    pub(crate) account_id: String,
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) claim_token: String,
}

#[derive(Clone, Debug)]
pub(crate) struct SummaryWindowSettlement {
    pub(crate) claim: SummaryWindowClaim,
    pub(crate) episodes: Vec<EpisodeInput>,
    /// `None` deliberately holds the forward-only cursor. A value advances it
    /// atomically with the episode writes and durable operation receipt.
    pub(crate) cursor: Option<String>,
}

/// Exact durable claim for one capture session's current formation revision.
/// Unlike the forward window, this claim may name source timestamps behind the
/// account cursor; settlement never changes that cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CaptureFormationClaim {
    pub(crate) account_id: String,
    pub(crate) capture_session_id: String,
    pub(crate) source_revision: i64,
    pub(crate) source_fingerprint: Vec<u8>,
    pub(crate) from: String,
    pub(crate) to: String,
    /// Zero-based, contiguous page within this exact source revision.
    pub(crate) page_index: i64,
    /// Commits to the revision fingerprint, complete covered-source ids,
    /// provider-visible subset, and `has_more` bit for this bounded page.
    pub(crate) page_source_commitment: Vec<u8>,
    /// Stable across ownership loss. Vertex's durable invocation ledger
    /// refuses to send this identity twice after an ambiguous response.
    pub(crate) provider_attempt_identity: Vec<u8>,
    /// Exact request contract for this attempt, if it was already admitted
    /// before a prior owner lost the page lease.
    pub(crate) provider_request: Option<CaptureFormationProviderRequest>,
    /// A response staged before parsing/settlement is replayed without a new
    /// provider call after a crash or claim expiry.
    pub(crate) staged_provider_response: Option<String>,
    pub(crate) staged_vertex_event_id: Option<String>,
    pub(crate) page_has_more: bool,
    pub(crate) covered_utterance_count: i64,
    pub(crate) covered_screenshot_count: i64,
    pub(crate) claim_token: String,
}

/// Only a provider-proven not-billed outcome may advance to a fresh durable
/// attempt identity. Every other retry reuses the existing identity, so an
/// ambiguous request can never be emitted twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureFormationRetryDisposition {
    PreserveProviderAttempt,
    AdvanceConfirmedNotBilled,
}

#[derive(Clone, Debug)]
pub(crate) struct CaptureFormationSettlement {
    pub(crate) claim: CaptureFormationClaim,
    pub(crate) episodes: Vec<EpisodeInput>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EpisodeEmbeddingSource {
    pub(crate) id: i64,
    pub(crate) text: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EpisodeEmbeddingWrite {
    pub(crate) id: i64,
    pub(crate) embedding: Vec<f32>,
}

/// PostgreSQL-owned memory formation boundary. Durable claims make one
/// summarizer window single-owner across the application fleet without
/// holding a database transaction open over a model call.
#[async_trait]
pub(crate) trait MemoryFormationRepository: Send + Sync {
    /// Seed the synthetic plugin-review account exactly once.
    async fn ensure_reviewer_fixture(&self, account_id: &str) -> Result<bool>;

    async fn claim_summary_window(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        claimed_at: &str,
        lease_seconds: i64,
    ) -> Result<Option<SummaryWindowClaim>>;

    async fn release_summary_window(
        &self,
        claim: &SummaryWindowClaim,
        released_at: &str,
        error_code: Option<&str>,
    ) -> Result<()>;

    /// Revalidate the exact plaintext sources immediately before provider
    /// egress. The implementation serializes with episode deletion and
    /// refuses missing projections, pending canonical families, stale open
    /// episodes, or a superseded durable claim.
    async fn authorize_summary_window_egress(
        &self,
        claim: &SummaryWindowClaim,
        utterance_ids: &[i64],
        screenshot_ids: &[i64],
        open_episode_ids: &[i64],
    ) -> Result<()>;

    async fn summary_evidence(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        utterance_limit: i64,
        screenshot_limit: i64,
    ) -> Result<(Vec<SummaryUtterance>, Vec<SummaryScreenshot>)>;

    /// Claim the oldest source-settled dirty capture-session revision using
    /// PostgreSQL time for eligibility and lease authority.
    async fn claim_capture_formation(
        &self,
        account_id: &str,
        lease_seconds: i64,
    ) -> Result<Option<CaptureFormationClaim>>;

    async fn release_capture_formation(
        &self,
        claim: &CaptureFormationClaim,
        error_code: Option<&str>,
        disposition: CaptureFormationRetryDisposition,
    ) -> Result<()>;

    async fn capture_formation_evidence(
        &self,
        claim: &CaptureFormationClaim,
        utterance_limit: i64,
        screenshot_limit: i64,
    ) -> Result<(Vec<SummaryUtterance>, Vec<SummaryScreenshot>)>;

    /// Revalidate one exact-session claim and its plaintext sources under the
    /// episode-deletion fence immediately before provider egress.
    async fn authorize_capture_formation_egress(
        &self,
        claim: &CaptureFormationClaim,
        utterance_ids: &[i64],
        screenshot_ids: &[i64],
        current_request: &CaptureFormationProviderRequest,
    ) -> Result<CaptureFormationProviderRequest>;

    /// Persist the exact successful provider response before parsing and
    /// topology mutation. Reclaiming the page returns these bytes and never
    /// performs provider egress again.
    async fn stage_capture_formation_response(
        &self,
        claim: &CaptureFormationClaim,
        response: &str,
        vertex_event_id: &str,
    ) -> Result<()>;

    /// Settle exactly the claimed revision. An empty episode list is an
    /// explicit durable `no_memory` result and never advances the account
    /// cursor.
    async fn settle_capture_formation(
        &self,
        settlement: CaptureFormationSettlement,
    ) -> Result<Vec<i64>>;

    async fn open_episodes(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        limit: i64,
    ) -> Result<Vec<OpenEpisode>>;

    async fn settle_summary_window(&self, settlement: SummaryWindowSettlement) -> Result<Vec<i64>>;

    async fn episode_embedding_sources(
        &self,
        account_id: &str,
        ids: &[i64],
    ) -> Result<Vec<EpisodeEmbeddingSource>>;

    async fn write_episode_embeddings(
        &self,
        account_id: &str,
        writes: &[EpisodeEmbeddingWrite],
    ) -> Result<()>;

    async fn session_tail_is_settled(&self, account_id: &str, recent_after: &str) -> Result<bool>;
}
