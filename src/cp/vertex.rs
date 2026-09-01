//! Vertex AI client for episode summarization and unified episode analysis. Gemini
//! `generateContent` uses a
//! constrained `responseSchema`. Credentials come from the VM metadata server
//! (cloud-platform scope), same pattern as the GCS/KMS clients.
//!
//! Only the Gemini path is implemented; `VERTEX_MODEL` defaults to the current
//! Gemini 3.5 Flash deployment, while settled reconciliation may route to a
//! separately qualified `VERTEX_RECONCILIATION_MODEL`. These calls send
//! bounded assembled text, decrypted audio windows, and screen storyboards to
//! Vertex outside the TEE.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Digest;
use std::time::Instant;

use crate::{
    error::{EnclaveError, Result},
    persistence::{
        capture_formation_response_schema_v1, media_provider_attempt_identity,
        CaptureFormationProviderRequest, MediaProviderAttempt, MediaProviderStagedResponse,
        VertexInvocationAdmission, CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS,
        MAX_MEDIA_PROVIDER_RESPONSE_BYTES,
    },
};

use super::{model_usage, CpState};

const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const GENERATION_TIMEOUT_SECONDS: u64 = 120;
pub(crate) const GENERATE_CONTENT_API_VERSION: &str = "v1";
pub(crate) const GENERATE_CONTENT_PUBLISHER: &str = "google";
pub(crate) const GENERATE_CONTENT_METHOD: &str = "generateContent";
pub(crate) const JSON_RESPONSE_MIME_TYPE: &str = "application/json";
pub(crate) const THINKING_BUDGET: i64 = 0;
pub(crate) const MAX_TEXT_OUTPUT_TOKENS: u32 = CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS;
pub(crate) const MAX_MEDIA_OUTPUT_TOKENS: u32 = 4_096;
pub(crate) const MAX_SCREEN_OUTPUT_TOKENS: u32 = 1_024;

async fn require_active_account(state: &CpState, user_id: &str) -> Result<()> {
    if !super::limits::account_active(&state.repositories, user_id).await? {
        return Err(EnclaveError::Auth("account inactive".into()));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VertexOperation {
    EpisodeSummary,
    EpisodeSummaryRepair,
    EpisodeReconciliation,
    FinalEpisodeAnalysis,
    AudioWindow,
    ScreenStoryboard,
}

impl VertexOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EpisodeSummary | Self::EpisodeSummaryRepair => "episode_summarization",
            Self::EpisodeReconciliation => "episode_reconciliation",
            Self::FinalEpisodeAnalysis => "episode_finalization",
            Self::AudioWindow => "audio_understanding",
            Self::ScreenStoryboard => "screen_understanding",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct VertexUsage {
    pub prompt_details_present: bool,
    pub cache_details_present: bool,
    pub prompt_tokens: Option<u64>,
    pub input_text_tokens: Option<u64>,
    pub input_audio_tokens: Option<u64>,
    pub input_image_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub cached_input_text_tokens: Option<u64>,
    pub cached_input_audio_tokens: Option<u64>,
    pub cached_input_image_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub tool_use_prompt_tokens: Option<u64>,
    pub thought_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

fn detail_token_count(
    usage: &serde_json::Map<String, Value>,
    details_key: &str,
    modality: &str,
) -> Option<u64> {
    usage
        .get(details_key)
        .and_then(Value::as_array)
        .and_then(|details| {
            details.iter().find_map(|detail| {
                (detail.get("modality").and_then(Value::as_str) == Some(modality))
                    .then(|| detail.get("tokenCount").and_then(Value::as_u64))
                    .flatten()
            })
        })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct VertexMetadata {
    pub usage: Option<VertexUsage>,
    pub model_version: Option<String>,
    pub traffic_type: Option<String>,
}

pub struct TextGeneration {
    pub text: String,
    /// Durable usage-ledger identity for the settled provider invocation. The
    /// finalization commit plan anchors on this exact value.
    pub event_id: String,
}

/// What the reconciliation worker may safely do after a classified provider
/// failure. This classification is deliberately about provider egress, not
/// HTTP convenience: only a pre-egress failure or a durably confirmed
/// not-billed response can be retried. An ambiguous attempt is terminal for
/// that request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VertexGenerationFailureDisposition {
    RetryableBeforeEgress,
    RetryableNotBilled,
    AmbiguousTerminal,
    ConfirmedInvalid,
}

#[derive(Debug)]
pub(crate) struct VertexGenerationFailure {
    pub(crate) disposition: VertexGenerationFailureDisposition,
    pub(crate) event_id: Option<String>,
    error: EnclaveError,
}

impl VertexGenerationFailure {
    fn before_egress(error: EnclaveError) -> Self {
        Self {
            disposition: VertexGenerationFailureDisposition::RetryableBeforeEgress,
            event_id: None,
            error,
        }
    }

    fn after_egress(
        disposition: VertexGenerationFailureDisposition,
        event_id: &str,
        error: EnclaveError,
    ) -> Self {
        Self {
            disposition,
            event_id: Some(event_id.to_owned()),
            error,
        }
    }

    pub(crate) fn into_error(self) -> EnclaveError {
        self.error
    }
}

fn durable_http_failure_disposition(status: u16) -> VertexGenerationFailureDisposition {
    match status {
        // These responses reject the request before model inference. They are
        // safe to account as not billed and may advance to a fresh durable
        // attempt identity. Timeouts, conflicts, and server failures are
        // deliberately absent: a response from those classes does not prove
        // that inference did not run.
        400 | 401 | 403 | 404 | 413 | 422 | 429 => {
            VertexGenerationFailureDisposition::RetryableNotBilled
        }
        _ => VertexGenerationFailureDisposition::AmbiguousTerminal,
    }
}

impl std::fmt::Display for VertexGenerationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

pub struct CustomTextGenerationRequest<'a> {
    pub operation: VertexOperation,
    pub system: &'a str,
    pub user_message: &'a str,
    pub schema: Value,
    pub max_output_tokens: u32,
    pub model: &'a str,
}

fn text_request_body_and_caller_anchor(
    system: &str,
    user_message: &str,
    schema: &Value,
    max_output_tokens: u32,
    response_mime_type: &str,
    thinking_budget: i64,
) -> Result<(Value, [u8; 32])> {
    let body = json!({
        "contents": [{ "role": "user", "parts": [{ "text": user_message }] }],
        "systemInstruction": { "parts": [{ "text": system }] },
        "generationConfig": {
            "maxOutputTokens": max_output_tokens,
            "responseMimeType": response_mime_type,
            "responseSchema": schema,
            "thinkingConfig": { "thinkingBudget": thinking_budget }
        }
    });
    let body_bytes = serde_json::to_vec(&body)?;
    Ok((body, sha2::Sha256::digest(body_bytes).into()))
}

/// Exact caller-owned text-body commitment used by the durable usage ledger.
/// Reconciliation and formation stage validation call this same helper, so a
/// prompt/schema/generation change cannot be relabeled as an older attempt.
pub(crate) fn custom_text_request_caller_anchor(
    request: &CustomTextGenerationRequest<'_>,
) -> Result<[u8; 32]> {
    Ok(text_request_body_and_caller_anchor(
        request.system,
        request.user_message,
        &request.schema,
        bounded_output_tokens(request.max_output_tokens),
        JSON_RESPONSE_MIME_TYPE,
        THINKING_BUDGET,
    )?
    .1)
}

pub struct MediaGeneration {
    pub text: String,
    pub metadata: VertexMetadata,
    pub latency_ms: u64,
    /// Durable usage-ledger identity minted before the provider request.
    /// PostgreSQL workers re-drive terminal settlement against this exact
    /// identity after a successful response.
    pub event_id: String,
}

fn bounded_output_tokens(requested: u32) -> u32 {
    requested.clamp(1, MAX_TEXT_OUTPUT_TOKENS)
}

fn bounded_media_output_tokens(requested: u32) -> u32 {
    requested.clamp(1, MAX_MEDIA_OUTPUT_TOKENS)
}

fn response_metadata(data: &Value) -> VertexMetadata {
    let usage = data
        .get("usageMetadata")
        .and_then(Value::as_object)
        .map(|usage| VertexUsage {
            prompt_details_present: usage
                .get("promptTokensDetails")
                .is_some_and(Value::is_array),
            cache_details_present: usage.get("cacheTokensDetails").is_some_and(Value::is_array),
            prompt_tokens: usage.get("promptTokenCount").and_then(Value::as_u64),
            input_text_tokens: detail_token_count(usage, "promptTokensDetails", "TEXT"),
            input_audio_tokens: detail_token_count(usage, "promptTokensDetails", "AUDIO"),
            input_image_tokens: detail_token_count(usage, "promptTokensDetails", "IMAGE"),
            cached_input_tokens: usage.get("cachedContentTokenCount").and_then(Value::as_u64),
            cached_input_text_tokens: detail_token_count(usage, "cacheTokensDetails", "TEXT"),
            cached_input_audio_tokens: detail_token_count(usage, "cacheTokensDetails", "AUDIO"),
            cached_input_image_tokens: detail_token_count(usage, "cacheTokensDetails", "IMAGE"),
            output_tokens: usage.get("candidatesTokenCount").and_then(Value::as_u64),
            tool_use_prompt_tokens: usage.get("toolUsePromptTokenCount").and_then(Value::as_u64),
            thought_tokens: usage.get("thoughtsTokenCount").and_then(Value::as_u64),
            total_tokens: usage.get("totalTokenCount").and_then(Value::as_u64),
        });
    VertexMetadata {
        traffic_type: data
            .get("usageMetadata")
            .and_then(|value| value.get("trafficType"))
            .and_then(Value::as_str)
            .map(str::to_string),
        usage,
        model_version: data
            .get("modelVersion")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

fn log_usage(
    metadata: &VertexMetadata,
    operation: VertexOperation,
    model: &str,
    output_limit: u32,
) {
    let usage = metadata.usage.as_ref();
    tracing::info!(
        operation = operation.as_str(),
        model,
        output_limit,
        usage_present = usage.is_some(),
        prompt_tokens = usage.and_then(|value| value.prompt_tokens),
        input_text_tokens = usage.and_then(|value| value.input_text_tokens),
        input_audio_tokens = usage.and_then(|value| value.input_audio_tokens),
        input_image_tokens = usage.and_then(|value| value.input_image_tokens),
        cached_input_tokens = usage.and_then(|value| value.cached_input_tokens),
        cached_input_text_tokens = usage.and_then(|value| value.cached_input_text_tokens),
        cached_input_audio_tokens = usage.and_then(|value| value.cached_input_audio_tokens),
        cached_input_image_tokens = usage.and_then(|value| value.cached_input_image_tokens),
        output_tokens = usage.and_then(|value| value.output_tokens),
        tool_use_prompt_tokens = usage.and_then(|value| value.tool_use_prompt_tokens),
        thought_tokens = usage.and_then(|value| value.thought_tokens),
        total_tokens = usage.and_then(|value| value.total_tokens),
        "Vertex inference usage"
    );
}

#[derive(Deserialize)]
struct TokenResp {
    access_token: String,
}

async fn access_token(http: &reqwest::Client) -> Result<String> {
    let tok: TokenResp = http
        .get(METADATA_TOKEN_URL)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(tok.access_token)
}

/// The constrained-decoding schema the model must emit (matches summarizer.js).
fn response_schema() -> Value {
    capture_formation_response_schema_v1()
}

/// Call Gemini and return the raw response text (expected to be JSON per the
/// schema). `Err` with a `quota` marker string on HTTP 429.
pub async fn generate(
    state: &CpState,
    user_id: &str,
    operation: VertexOperation,
    system: &str,
    user_message: &str,
) -> Result<TextGeneration> {
    generate_custom(
        state,
        user_id,
        operation,
        system,
        user_message,
        response_schema(),
        MAX_TEXT_OUTPUT_TOKENS,
    )
    .await
}

pub(crate) fn capture_formation_provider_request(
    state: &CpState,
    system: &str,
    user_message: &str,
) -> CaptureFormationProviderRequest {
    CaptureFormationProviderRequest {
        contract_version: 1,
        vertex_project: state.config.vertex_project.clone(),
        vertex_location: state.config.vertex_location.clone(),
        api_version: GENERATE_CONTENT_API_VERSION.into(),
        publisher: GENERATE_CONTENT_PUBLISHER.into(),
        model: state.config.vertex_model.clone(),
        method: GENERATE_CONTENT_METHOD.into(),
        system_prompt: system.into(),
        user_message: user_message.into(),
        response_schema: response_schema(),
        max_output_tokens: MAX_TEXT_OUTPUT_TOKENS,
        response_mime_type: JSON_RESPONSE_MIME_TYPE.into(),
        thinking_budget: THINKING_BUDGET,
    }
}

/// Execute the exact request contract durably bound to a formation page.
/// Reclaim after a deploy therefore cannot reuse an attempt identity with a
/// changed prompt, schema, model, endpoint, or generation setting.
pub(crate) async fn generate_with_persisted_attempt(
    state: &CpState,
    user_id: &str,
    request: &CaptureFormationProviderRequest,
    attempt_identity: &[u8; 32],
) -> std::result::Result<TextGeneration, VertexGenerationFailure> {
    if request.contract_version != 1
        || request.api_version != GENERATE_CONTENT_API_VERSION
        || request.publisher != GENERATE_CONTENT_PUBLISHER
        || request.method != GENERATE_CONTENT_METHOD
        || request.max_output_tokens != CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS
        || request.response_mime_type != JSON_RESPONSE_MIME_TYPE
        || request.thinking_budget != THINKING_BUDGET
        || request.response_schema != response_schema()
    {
        return Err(VertexGenerationFailure::before_egress(
            EnclaveError::InvalidRequest(
                "capture formation provider request contract is unsupported".into(),
            ),
        ));
    }
    generate_custom_with_model_inner(
        state,
        user_id,
        CustomTextGenerationRequest {
            operation: VertexOperation::EpisodeSummary,
            system: &request.system_prompt,
            user_message: &request.user_message,
            schema: request.response_schema.clone(),
            max_output_tokens: request.max_output_tokens,
            model: &request.model,
        },
        TextInvocationMode::Durable(attempt_identity),
        TextExecutionContract::Persisted {
            project: &request.vertex_project,
            location: &request.vertex_location,
            api_version: &request.api_version,
            publisher: &request.publisher,
            method: &request.method,
            response_mime_type: &request.response_mime_type,
            thinking_budget: request.thinking_budget,
        },
    )
    .await
}

/// Call Gemini with a caller-supplied constrained-decoding schema. The episode
/// summarizer uses [`generate`]; ADR-0009's one-time historical classifier uses
/// this entry point with a compact `{id, substance}` schema.
pub async fn generate_custom(
    state: &CpState,
    user_id: &str,
    operation: VertexOperation,
    system: &str,
    user_message: &str,
    schema: Value,
    max_output_tokens: u32,
) -> Result<TextGeneration> {
    generate_custom_with_model(
        state,
        user_id,
        CustomTextGenerationRequest {
            operation,
            system,
            user_message,
            schema,
            max_output_tokens,
            model: &state.config.vertex_model,
        },
    )
    .await
}

/// Variant of [`generate_custom`] for workers with a separately qualified
/// model. The selected model remains part of the durable usage identity.
pub async fn generate_custom_with_model(
    state: &CpState,
    user_id: &str,
    request: CustomTextGenerationRequest<'_>,
) -> Result<TextGeneration> {
    generate_custom_with_model_inner(
        state,
        user_id,
        request,
        TextInvocationMode::Legacy,
        TextExecutionContract::Current,
    )
    .await
    .map_err(VertexGenerationFailure::into_error)
}

/// Build and durably admit an attempt without crossing the provider boundary.
/// Callers with an additional database egress fence acquire it after this
/// returns and invoke [`PreparedTextRequest::send`] immediately afterward.
pub(crate) async fn prepare_custom_with_model_attempt(
    state: &CpState,
    user_id: &str,
    request: CustomTextGenerationRequest<'_>,
    attempt_identity: &[u8; 32],
) -> std::result::Result<PreparedTextRequest, VertexGenerationFailure> {
    prepare_custom_with_model_inner(
        state,
        user_id,
        request,
        TextInvocationMode::Durable(attempt_identity),
        TextExecutionContract::Current,
    )
    .await
}

#[derive(Clone, Copy)]
enum TextInvocationMode<'a> {
    Legacy,
    Durable(&'a [u8; 32]),
}

#[derive(Clone, Copy)]
enum TextExecutionContract<'a> {
    Current,
    Persisted {
        project: &'a str,
        location: &'a str,
        api_version: &'a str,
        publisher: &'a str,
        method: &'a str,
        response_mime_type: &'a str,
        thinking_budget: i64,
    },
}

pub(crate) struct PreparedTextRequest {
    http: reqwest::Client,
    request: reqwest::Request,
    invocation: String,
    durable: bool,
    operation: VertexOperation,
    model: String,
    max_output_tokens: u32,
}

impl PreparedTextRequest {
    /// Close a durably admitted attempt that lost its final local authority
    /// before HTTP egress. No synthetic status is recorded because no request
    /// reached the provider.
    pub(crate) async fn reject_before_egress(self, state: &CpState, user_id: &str) -> Result<()> {
        model_usage::settle_pre_egress_not_billed_required(state, user_id, &self.invocation).await
    }

    /// Perform the first provider-visible action, then retain ownership until
    /// the exact terminal usage receipt is durable. Callers may safely hold a
    /// topology/finalization fence across this method.
    pub(crate) async fn send(
        self,
        state: &CpState,
        user_id: &str,
    ) -> std::result::Result<TextGeneration, VertexGenerationFailure> {
        let Self {
            http,
            request,
            invocation,
            durable,
            operation,
            model,
            max_output_tokens,
        } = self;
        let response = http.execute(request).await;
        let resp = match response {
            Ok(response) => response,
            Err(error) => {
                let provider_error = EnclaveError::from(error);
                let settlement_error = if durable {
                    model_usage::settle_ambiguous_required(state, user_id, &invocation, None)
                        .await
                        .err()
                } else {
                    model_usage::record_ambiguous(state, user_id, &invocation, None).await;
                    None
                };
                return Err(VertexGenerationFailure::after_egress(
                    VertexGenerationFailureDisposition::AmbiguousTerminal,
                    &invocation,
                    settlement_error.unwrap_or(provider_error),
                ));
            }
        };

        let error_status = resp.status().as_u16();
        let resp = match resp.error_for_status() {
            Ok(response) => response,
            Err(error) => {
                let disposition = durable_http_failure_disposition(error_status);
                let provider_error = if error_status == 429 {
                    EnclaveError::Config("quota".into())
                } else {
                    EnclaveError::from(error)
                };
                if durable {
                    let settlement = match disposition {
                        VertexGenerationFailureDisposition::RetryableNotBilled => {
                            model_usage::settle_not_billed_required(
                                state,
                                user_id,
                                &invocation,
                                error_status,
                            )
                            .await
                        }
                        VertexGenerationFailureDisposition::AmbiguousTerminal => {
                            model_usage::settle_ambiguous_required(
                                state,
                                user_id,
                                &invocation,
                                Some(error_status),
                            )
                            .await
                        }
                        _ => unreachable!("HTTP failure disposition is exhaustive above"),
                    };
                    if let Err(settlement_error) = settlement {
                        return Err(VertexGenerationFailure::after_egress(
                            VertexGenerationFailureDisposition::AmbiguousTerminal,
                            &invocation,
                            settlement_error,
                        ));
                    }
                } else {
                    model_usage::record_not_billed(state, user_id, &invocation, error_status).await;
                }
                return Err(VertexGenerationFailure::after_egress(
                    disposition,
                    &invocation,
                    provider_error,
                ));
            }
        };
        let data: Value = match resp.json().await {
            Ok(data) => data,
            Err(error) => {
                let provider_error = EnclaveError::from(error);
                let settlement_error = if durable {
                    model_usage::settle_ambiguous_required(
                        state,
                        user_id,
                        &invocation,
                        Some(error_status),
                    )
                    .await
                    .err()
                } else {
                    model_usage::record_ambiguous(state, user_id, &invocation, Some(error_status))
                        .await;
                    None
                };
                return Err(VertexGenerationFailure::after_egress(
                    VertexGenerationFailureDisposition::AmbiguousTerminal,
                    &invocation,
                    settlement_error.unwrap_or(provider_error),
                ));
            }
        };
        let metadata = response_metadata(&data);
        log_usage(&metadata, operation, &model, max_output_tokens);
        if durable {
            if let Err(error) =
                model_usage::settle_response_required(state, user_id, &invocation, &metadata).await
            {
                // Settlement uncertainty is provider-effect uncertainty. Best
                // effort marks the ledger ambiguous, but never authorizes resend.
                model_usage::record_ambiguous(state, user_id, &invocation, Some(error_status))
                    .await;
                return Err(VertexGenerationFailure::after_egress(
                    VertexGenerationFailureDisposition::AmbiguousTerminal,
                    &invocation,
                    error,
                ));
            }
        } else {
            model_usage::record_response(state, user_id, &invocation, &metadata).await;
        }
        let text: String = data
            .get("candidates")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.as_array())
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                    .collect::<String>()
            })
            .unwrap_or_default();
        if text.is_empty() {
            let finish = data
                .get("candidates")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("finishReason"))
                .and_then(|f| f.as_str())
                .unwrap_or("<no candidates>");
            return Err(VertexGenerationFailure::after_egress(
                VertexGenerationFailureDisposition::ConfirmedInvalid,
                &invocation,
                EnclaveError::Config(format!(
                    "unexpected Vertex response shape (finishReason: {finish})"
                )),
            ));
        }
        Ok(TextGeneration {
            text,
            event_id: invocation,
        })
    }
}

async fn generate_custom_with_model_inner(
    state: &CpState,
    user_id: &str,
    request: CustomTextGenerationRequest<'_>,
    invocation_mode: TextInvocationMode<'_>,
    execution_contract: TextExecutionContract<'_>,
) -> std::result::Result<TextGeneration, VertexGenerationFailure> {
    prepare_custom_with_model_inner(state, user_id, request, invocation_mode, execution_contract)
        .await?
        .send(state, user_id)
        .await
}

async fn prepare_custom_with_model_inner(
    state: &CpState,
    user_id: &str,
    request: CustomTextGenerationRequest<'_>,
    invocation_mode: TextInvocationMode<'_>,
    execution_contract: TextExecutionContract<'_>,
) -> std::result::Result<PreparedTextRequest, VertexGenerationFailure> {
    let CustomTextGenerationRequest {
        operation,
        system,
        user_message,
        schema,
        max_output_tokens,
        model,
    } = request;
    // Hold through the durable terminal usage write on every response/error
    // path. Account deletion waits here before it destroys the usage ledger.
    require_active_account(state, user_id)
        .await
        .map_err(VertexGenerationFailure::before_egress)?;
    let (
        vertex_project,
        vertex_location,
        api_version,
        publisher,
        method,
        response_mime_type,
        thinking_budget,
        max_output_tokens,
    ) = match execution_contract {
        TextExecutionContract::Current => (
            state.config.vertex_project.as_str(),
            state.config.vertex_location.as_str(),
            GENERATE_CONTENT_API_VERSION,
            GENERATE_CONTENT_PUBLISHER,
            GENERATE_CONTENT_METHOD,
            JSON_RESPONSE_MIME_TYPE,
            THINKING_BUDGET,
            bounded_output_tokens(max_output_tokens),
        ),
        TextExecutionContract::Persisted {
            project,
            location,
            api_version,
            publisher,
            method,
            response_mime_type,
            thinking_budget,
        } => (
            project,
            location,
            api_version,
            publisher,
            method,
            response_mime_type,
            thinking_budget,
            max_output_tokens,
        ),
    };
    if vertex_project.is_empty()
        || vertex_location.is_empty()
        || model.is_empty()
        || max_output_tokens == 0
        || max_output_tokens > 65_535
        || !(0..=65_535).contains(&thinking_budget)
        || api_version != GENERATE_CONTENT_API_VERSION
        || publisher != GENERATE_CONTENT_PUBLISHER
        || method != GENERATE_CONTENT_METHOD
        || response_mime_type != JSON_RESPONSE_MIME_TYPE
        || [vertex_project, vertex_location, model]
            .into_iter()
            .any(|value| {
                !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            })
    {
        return Err(VertexGenerationFailure::before_egress(
            EnclaveError::Config("Vertex text request contract is invalid".into()),
        ));
    }
    // The output ceiling makes two minutes sufficient. A shorter client
    // timeout also limits how long a lost response can block the serialized
    // workers; retries are bounded separately by their durable queues.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(GENERATION_TIMEOUT_SECONDS))
        .build()
        .map_err(EnclaveError::from)
        .map_err(VertexGenerationFailure::before_egress)?;
    let token = access_token(&http)
        .await
        .map_err(VertexGenerationFailure::before_egress)?;

    let url = format!(
        "https://aiplatform.googleapis.com/{}/projects/{}/locations/{}/publishers/{}/models/{}:{}",
        api_version, vertex_project, vertex_location, publisher, model, method,
    );
    // The body commitment deliberately excludes the attempt identity. A
    // confirmed retry therefore receives a new billing identity while still
    // proving byte-for-byte equality of the model-visible request Value.
    let (body, caller_anchor) = text_request_body_and_caller_anchor(
        system,
        user_message,
        &schema,
        max_output_tokens,
        response_mime_type,
        thinking_budget,
    )
    .map_err(VertexGenerationFailure::before_egress)?;
    // Build every fallible request component before admitting durable usage.
    // After admission, only an explicit local egress fence may precede send.
    let request = http
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .build()
        .map_err(EnclaveError::from)
        .map_err(VertexGenerationFailure::before_egress)?;
    let invocation = match invocation_mode {
        TextInvocationMode::Legacy => state
            .repositories
            .model_usage()
            .begin_invocation(user_id, operation, model, vertex_location, &caller_anchor)
            .await
            .map_err(VertexGenerationFailure::before_egress)?,
        TextInvocationMode::Durable(attempt_identity) => {
            let attempt = state
                .repositories
                .model_usage()
                .begin_invocation_attempt(
                    user_id,
                    operation,
                    model,
                    vertex_location,
                    &caller_anchor,
                    attempt_identity,
                )
                .await
                .map_err(VertexGenerationFailure::before_egress)?;
            match attempt.admission {
                VertexInvocationAdmission::Send => attempt.event_id,
                VertexInvocationAdmission::ConfirmedNotBilled => {
                    return Err(VertexGenerationFailure::after_egress(
                        VertexGenerationFailureDisposition::RetryableNotBilled,
                        &attempt.event_id,
                        EnclaveError::Conflict(
                            "Vertex invocation attempt was already confirmed not billed".into(),
                        ),
                    ));
                }
                VertexInvocationAdmission::AmbiguousTerminal => {
                    return Err(VertexGenerationFailure::after_egress(
                        VertexGenerationFailureDisposition::AmbiguousTerminal,
                        &attempt.event_id,
                        EnclaveError::Conflict(
                            "Vertex invocation attempt cannot be safely resent".into(),
                        ),
                    ));
                }
            }
        }
    };
    let durable = matches!(invocation_mode, TextInvocationMode::Durable(_));
    Ok(PreparedTextRequest {
        http,
        request,
        invocation,
        durable,
        operation,
        model: model.to_owned(),
        max_output_tokens,
    })
}

fn media_request_body(
    prompt: &str,
    mime_type: &str,
    media: &[u8],
    schema: Value,
    audio_timestamp: bool,
) -> Value {
    json!({
        "contents": [{
            "role": "user",
            "parts": [
                {"inlineData": {"mimeType": mime_type, "data": B64.encode(media)}},
                {"text": prompt}
            ]
        }],
        "generationConfig": {
            "maxOutputTokens": MAX_MEDIA_OUTPUT_TOKENS,
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "audioTimestamp": audio_timestamp,
            "thinkingConfig": {"thinkingBudget": 0}
        }
    })
}

pub struct MediaInput<'a> {
    pub id: &'a str,
    pub mime_type: &'a str,
    pub media: &'a [u8],
}

impl<'a> MediaInput<'a> {
    pub fn new(id: &'a str, mime_type: &'a str, media: &'a [u8]) -> Self {
        Self {
            id,
            mime_type,
            media,
        }
    }
}

fn media_parts_request_body(
    prompt: &str,
    inputs: &[MediaInput<'_>],
    schema: Value,
    audio_timestamp: bool,
    max_output_tokens: u32,
) -> Value {
    let mut parts = Vec::with_capacity(inputs.len().saturating_mul(2).saturating_add(1));
    for input in inputs {
        parts.push(json!({"text": format!("frame_id: {}", input.id)}));
        parts.push(json!({
            "inlineData": {
                "mimeType": input.mime_type,
                "data": B64.encode(input.media),
            }
        }));
    }
    parts.push(json!({"text": prompt}));
    json!({
        "contents": [{"role":"user", "parts": parts}],
        "generationConfig": {
            "maxOutputTokens": bounded_media_output_tokens(max_output_tokens),
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "audioTimestamp": audio_timestamp,
            "thinkingConfig": {"thinkingBudget": 0}
        }
    })
}

pub(crate) enum PreparedMediaInvocation {
    Send(Box<PreparedMediaRequest>),
    ConfirmedNotBilled(MediaProviderAttempt),
    AmbiguousTerminal(MediaProviderAttempt),
}

pub(crate) struct PreparedMediaRequest {
    http: reqwest::Client,
    request: reqwest::Request,
    attempt: MediaProviderAttempt,
}

impl PreparedMediaRequest {
    pub(crate) fn attempt(&self) -> &MediaProviderAttempt {
        &self.attempt
    }

    /// This method performs no awaited work before the provider HTTP send.
    /// Callers must invoke it immediately after their final durable local
    /// egress authorization returns.
    pub(crate) async fn send(
        self,
    ) -> std::result::Result<MediaProviderStagedResponse, VertexGenerationFailure> {
        let started = Instant::now();
        let mut response = self.http.execute(self.request).await.map_err(|error| {
            VertexGenerationFailure::after_egress(
                VertexGenerationFailureDisposition::AmbiguousTerminal,
                &self.attempt.event_id,
                error.into(),
            )
        })?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_MEDIA_PROVIDER_RESPONSE_BYTES as u64)
        {
            return Err(VertexGenerationFailure::after_egress(
                VertexGenerationFailureDisposition::AmbiguousTerminal,
                &self.attempt.event_id,
                EnclaveError::Config("Vertex media response exceeds its byte bound".into()),
            ));
        }
        let mut response_bytes = Vec::new();
        loop {
            let chunk = response.chunk().await.map_err(|error| {
                VertexGenerationFailure::after_egress(
                    VertexGenerationFailureDisposition::AmbiguousTerminal,
                    &self.attempt.event_id,
                    error.into(),
                )
            })?;
            let Some(chunk) = chunk else {
                break;
            };
            if response_bytes.len().saturating_add(chunk.len()) > MAX_MEDIA_PROVIDER_RESPONSE_BYTES
            {
                return Err(VertexGenerationFailure::after_egress(
                    VertexGenerationFailureDisposition::AmbiguousTerminal,
                    &self.attempt.event_id,
                    EnclaveError::Config("Vertex media response exceeds its byte bound".into()),
                ));
            }
            response_bytes.extend_from_slice(&chunk);
        }
        Ok(MediaProviderStagedResponse {
            attempt: self.attempt,
            http_status: status,
            response_sha256: sha2::Sha256::digest(&response_bytes).into(),
            response_bytes,
            latency_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        })
    }
}

async fn prepare_media_request(
    state: &CpState,
    user_id: &str,
    work_unit_id: &str,
    attempt_number: i64,
    body: Value,
    operation: VertexOperation,
) -> std::result::Result<PreparedMediaInvocation, VertexGenerationFailure> {
    require_active_account(state, user_id)
        .await
        .map_err(VertexGenerationFailure::before_egress)?;
    let config = &state.config;
    if config.vertex_project.is_empty()
        || config.vertex_model.is_empty()
        || config.vertex_location.is_empty()
        || config.vertex_model.chars().count() > 256
        || config.vertex_location.chars().count() > 128
    {
        return Err(VertexGenerationFailure::before_egress(
            EnclaveError::Config("Vertex media provider configuration is invalid".into()),
        ));
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(GENERATION_TIMEOUT_SECONDS))
        .build()
        .map_err(EnclaveError::from)
        .map_err(VertexGenerationFailure::before_egress)?;
    let token = access_token(&http)
        .await
        .map_err(VertexGenerationFailure::before_egress)?;
    let url = format!(
        "https://aiplatform.googleapis.com/{}/projects/{}/locations/{}/publishers/{}/models/{}:{}",
        GENERATE_CONTENT_API_VERSION,
        config.vertex_project,
        config.vertex_location,
        GENERATE_CONTENT_PUBLISHER,
        config.vertex_model,
        GENERATE_CONTENT_METHOD,
    );
    let body_bytes = serde_json::to_vec(&body)
        .map_err(EnclaveError::from)
        .map_err(VertexGenerationFailure::before_egress)?;
    let mut request_commitment = sha2::Sha256::new();
    request_commitment.update(b"kioku.media-provider-request.v1\0");
    request_commitment.update(url.as_bytes());
    request_commitment.update([0]);
    request_commitment.update(&body_bytes);
    let request_sha256: [u8; 32] = request_commitment.finalize().into();
    // Fully build the request before durable invocation admission. Every
    // failure above this line is provably pre-egress and leaves no started
    // usage intent behind.
    let request = http
        .post(url)
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, JSON_RESPONSE_MIME_TYPE)
        .body(body_bytes)
        .build()
        .map_err(EnclaveError::from)
        .map_err(VertexGenerationFailure::before_egress)?;
    let identity_sha256 =
        media_provider_attempt_identity(user_id, work_unit_id, attempt_number, &request_sha256);
    let invocation = model_usage::begin_invocation_attempt(
        state,
        user_id,
        operation,
        &config.vertex_model,
        &request_sha256,
        &identity_sha256,
    )
    .await
    .map_err(VertexGenerationFailure::before_egress)?;
    let attempt = MediaProviderAttempt {
        number: attempt_number,
        identity_sha256,
        request_sha256,
        event_id: invocation.event_id,
        requested_model: config.vertex_model.clone(),
        location: config.vertex_location.clone(),
    };
    if attempt.event_id != crate::persistence::vertex_attempt_event_id(&identity_sha256) {
        return Err(VertexGenerationFailure::before_egress(EnclaveError::Store(
            "Vertex media attempt identity is inconsistent".into(),
        )));
    }
    match invocation.admission {
        VertexInvocationAdmission::Send => Ok(PreparedMediaInvocation::Send(Box::new(
            PreparedMediaRequest {
                http,
                request,
                attempt,
            },
        ))),
        VertexInvocationAdmission::ConfirmedNotBilled => {
            Ok(PreparedMediaInvocation::ConfirmedNotBilled(attempt))
        }
        VertexInvocationAdmission::AmbiguousTerminal => {
            Ok(PreparedMediaInvocation::AmbiguousTerminal(attempt))
        }
    }
}

pub(crate) fn parse_staged_media_response(
    response: &MediaProviderStagedResponse,
    operation: VertexOperation,
    max_output_tokens: u32,
) -> std::result::Result<MediaGeneration, VertexGenerationFailure> {
    if response.response_bytes.len() > MAX_MEDIA_PROVIDER_RESPONSE_BYTES
        || <[u8; 32]>::from(sha2::Sha256::digest(&response.response_bytes))
            != response.response_sha256
    {
        return Err(VertexGenerationFailure::after_egress(
            VertexGenerationFailureDisposition::AmbiguousTerminal,
            &response.attempt.event_id,
            EnclaveError::Conflict("staged Vertex media response commitment is invalid".into()),
        ));
    }
    if !(200..300).contains(&response.http_status) {
        let disposition = durable_http_failure_disposition(response.http_status);
        let error = if response.http_status == 429 {
            EnclaveError::Config("quota".into())
        } else {
            EnclaveError::Config(format!(
                "Vertex media request failed with HTTP {}",
                response.http_status
            ))
        };
        return Err(VertexGenerationFailure::after_egress(
            disposition,
            &response.attempt.event_id,
            error,
        ));
    }
    let data: Value = serde_json::from_slice(&response.response_bytes).map_err(|error| {
        VertexGenerationFailure::after_egress(
            VertexGenerationFailureDisposition::AmbiguousTerminal,
            &response.attempt.event_id,
            error.into(),
        )
    })?;
    let metadata = response_metadata(&data);
    log_usage(
        &metadata,
        operation,
        metadata.model_version.as_deref().unwrap_or("unknown"),
        bounded_media_output_tokens(max_output_tokens),
    );
    let text = data
        .get("candidates")
        .and_then(|candidates| candidates.get(0))
        .and_then(|candidate| candidate.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .collect::<String>()
        })
        .unwrap_or_default();
    Ok(MediaGeneration {
        text,
        metadata,
        latency_ms: response.latency_ms,
        event_id: response.attempt.event_id.clone(),
    })
}

/// Send one bounded audio or screenshot asset to Gemini using inline data.
/// `audioTimestamp` is enabled for audio-only inputs as required by Vertex's
/// audio understanding API. The caller supplies a constrained JSON schema and
/// validates the returned timestamps again before persistence.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_media_custom(
    state: &CpState,
    user_id: &str,
    work_unit_id: &str,
    attempt_number: i64,
    operation: VertexOperation,
    prompt: &str,
    mime_type: &str,
    media: &[u8],
    schema: Value,
    audio_timestamp: bool,
) -> std::result::Result<PreparedMediaInvocation, VertexGenerationFailure> {
    prepare_media_request(
        state,
        user_id,
        work_unit_id,
        attempt_number,
        media_request_body(prompt, mime_type, media, schema, audio_timestamp),
        operation,
    )
    .await
}

/// Send a bounded storyboard with opaque frame identifiers. Callers must
/// validate exact response coverage before projecting any result.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_media_parts_custom(
    state: &CpState,
    user_id: &str,
    work_unit_id: &str,
    attempt_number: i64,
    operation: VertexOperation,
    prompt: &str,
    inputs: &[MediaInput<'_>],
    schema: Value,
    max_output_tokens: u32,
) -> std::result::Result<PreparedMediaInvocation, VertexGenerationFailure> {
    if inputs.is_empty() || inputs.len() > super::media_planner::MAX_SCREEN_FRAMES {
        return Err(VertexGenerationFailure::before_egress(
            EnclaveError::InvalidRequest("storyboard frame count is outside allowed bounds".into()),
        ));
    }
    if inputs.iter().any(|input| input.id.is_empty()) {
        return Err(VertexGenerationFailure::before_egress(
            EnclaveError::InvalidRequest("storyboard frame id is empty".into()),
        ));
    }
    prepare_media_request(
        state,
        user_id,
        work_unit_id,
        attempt_number,
        media_parts_request_body(prompt, inputs, schema, false, max_output_tokens),
        operation,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn episode_schema_requires_recall_fields_and_visual_evidence() {
        let schema = response_schema();
        let episode = &schema["properties"]["episodes"]["items"];
        let properties = episode["properties"]
            .as_object()
            .expect("episode properties");

        assert!(properties.contains_key("summary"));
        assert!(properties.contains_key("action_items"));
        assert_eq!(
            properties["visual_evidence"]["enum"],
            json!(["none", "useful"])
        );

        let required = episode["required"].as_array().expect("required fields");
        for field in ["summary", "action_items", "visual_evidence"] {
            assert!(
                required.iter().any(|value| value.as_str() == Some(field)),
                "{field} must be required by constrained decoding"
            );
        }
    }

    #[test]
    fn only_explicit_pre_inference_http_rejections_authorize_a_retry() {
        for status in [400, 401, 403, 404, 413, 422, 429] {
            assert_eq!(
                durable_http_failure_disposition(status),
                VertexGenerationFailureDisposition::RetryableNotBilled,
                "HTTP {status} is an explicit request rejection"
            );
        }
        for status in [408, 409, 425, 500, 502, 503, 504] {
            assert_eq!(
                durable_http_failure_disposition(status),
                VertexGenerationFailureDisposition::AmbiguousTerminal,
                "HTTP {status} cannot prove that inference did not run"
            );
        }
    }

    #[test]
    fn audio_request_inlines_bytes_and_enables_timestamp_understanding() {
        let body = media_request_body(
            "transcribe",
            "audio/m4a",
            b"test-audio",
            json!({"type":"OBJECT"}),
            true,
        );
        assert_eq!(
            body["contents"][0]["parts"][0]["inlineData"]["mimeType"],
            "audio/m4a"
        );
        assert_eq!(body["generationConfig"]["audioTimestamp"], true);
        assert_eq!(
            body["generationConfig"]["maxOutputTokens"],
            MAX_MEDIA_OUTPUT_TOKENS
        );
        assert!(body["contents"][0]["parts"][0]["inlineData"]["data"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }

    #[test]
    fn caller_cannot_request_an_unbounded_text_response() {
        assert_eq!(bounded_output_tokens(65_535), MAX_TEXT_OUTPUT_TOKENS);
        assert_eq!(
            bounded_output_tokens(MAX_TEXT_OUTPUT_TOKENS),
            MAX_TEXT_OUTPUT_TOKENS
        );
        assert_eq!(bounded_output_tokens(1_024), 1_024);
        assert_eq!(MAX_TEXT_OUTPUT_TOKENS, 8_192);
        assert_eq!(MAX_MEDIA_OUTPUT_TOKENS, 4_096);
    }

    #[test]
    fn storyboard_request_has_opaque_frame_ids_and_a_1024_token_ceiling() {
        let frames = vec![
            MediaInput::new("frame-a", "image/jpeg", b"a"),
            MediaInput::new("frame-b", "image/jpeg", b"b"),
        ];
        let body = media_parts_request_body(
            "inspect each frame",
            &frames,
            json!({"type":"OBJECT"}),
            false,
            MAX_SCREEN_OUTPUT_TOKENS,
        );
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 1_024);
        assert_eq!(body["generationConfig"]["audioTimestamp"], false);
        let parts = body["contents"][0]["parts"].as_array().unwrap();
        assert_eq!(parts[0]["text"], "frame_id: frame-a");
        assert_eq!(parts[2]["text"], "frame_id: frame-b");
        assert_eq!(parts.last().unwrap()["text"], "inspect each frame");
    }

    #[test]
    fn media_output_ceiling_is_never_exceeded() {
        assert_eq!(bounded_media_output_tokens(65_535), 4_096);
        assert_eq!(bounded_media_output_tokens(0), 1);
        assert_eq!(bounded_media_output_tokens(1_024), 1_024);
    }

    #[test]
    fn usage_metadata_is_nullable_and_preserves_model_and_modality() {
        let metadata = response_metadata(&json!({
            "modelVersion": "gemini-test-001",
            "usageMetadata": {
                "promptTokenCount": 123,
                "promptTokensDetails": [
                    {"modality":"TEXT","tokenCount":23},
                    {"modality":"AUDIO","tokenCount":100}
                ],
                "cachedContentTokenCount": 45,
                "candidatesTokenCount": 67,
                "toolUsePromptTokenCount": 2,
                "thoughtsTokenCount": 8,
                "totalTokenCount": 200,
                "trafficType": "ON_DEMAND"
            }
        }));
        let usage = metadata.usage.unwrap();
        assert_eq!(usage.prompt_tokens, Some(123));
        assert_eq!(usage.input_text_tokens, Some(23));
        assert_eq!(usage.input_audio_tokens, Some(100));
        assert_eq!(usage.input_image_tokens, None);
        assert_eq!(usage.cached_input_tokens, Some(45));
        assert_eq!(usage.output_tokens, Some(67));
        assert_eq!(usage.tool_use_prompt_tokens, Some(2));
        assert_eq!(usage.thought_tokens, Some(8));
        assert_eq!(usage.total_tokens, Some(200));
        assert_eq!(metadata.model_version.as_deref(), Some("gemini-test-001"));
        assert_eq!(metadata.traffic_type.as_deref(), Some("ON_DEMAND"));
    }

    #[test]
    fn missing_usage_metadata_is_not_zero() {
        let metadata = response_metadata(&json!({"candidates": []}));
        assert_eq!(metadata.usage, None);
    }
}
