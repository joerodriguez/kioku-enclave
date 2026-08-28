//! Encrypted large-media object storage on Google Cloud Storage.
//!
//! PostgreSQL owns all structured state. This module owns only opaque encrypted
//! object bytes, exact GCS generations, and the canonical object-key/context
//! rules that bind those bytes to an account.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

/// Maximum accepted account identifier length. Real identifiers are UUIDs.
pub const MAX_USER_ID_LEN: usize = 128;

/// Validate an account identifier before using it in an object name.
pub fn validate_user_id(user_id: &str) -> Result<()> {
    let valid = !user_id.is_empty()
        && user_id.len() <= MAX_USER_ID_LEN
        && user_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(EnclaveError::InvalidRequest(
            "invalid user_id: must match [A-Za-z0-9_-]{1,128}".into(),
        ))
    }
}

/// Build the sole object key accepted for a canonical Cloud Capture asset.
pub(crate) fn canonical_capture_media_object_key(user_id: &str, asset_id: &str) -> Result<String> {
    validate_user_id(user_id)?;
    validate_asset_id(asset_id, "canonical capture")?;
    Ok(format!("raw/{user_id}/{asset_id}.enc"))
}

/// Build the sole object key accepted for a durable source recording.
pub(crate) fn canonical_recording_media_object_key(
    user_id: &str,
    asset_id: &str,
) -> Result<String> {
    validate_user_id(user_id)?;
    validate_asset_id(asset_id, "durable recording")?;
    Ok(format!("recordings/{user_id}/{asset_id}.enc"))
}

fn validate_asset_id(asset_id: &str, kind: &str) -> Result<()> {
    let valid = !asset_id.is_empty()
        && asset_id.len() <= 128
        && asset_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(EnclaveError::InvalidRequest(format!(
            "invalid {kind} asset identifier"
        )))
    }
}

/// AEAD associated data for ordinary processing-media ciphertext.
pub(crate) fn media_blob_context(user_id: &str, object_key: &str) -> Vec<u8> {
    format!("media\0{user_id}\0{object_key}").into_bytes()
}

/// Provider metadata for a durable recording points at its PostgreSQL key epoch.
pub(crate) fn recording_media_key_reference(key_epoch: i64, policy_epoch: &str) -> Result<String> {
    if key_epoch <= 0
        || policy_epoch.len() != 68
        || !policy_epoch.starts_with("rpe_")
        || !policy_epoch[4..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EnclaveError::InvalidRequest(
            "invalid durable recording key reference".into(),
        ));
    }
    Ok(format!(
        "recording-key-v1:{key_epoch}:{:x}",
        Sha256::digest(policy_epoch.as_bytes())
    ))
}

/// Strict v1 AEAD context for a durable canonical source segment.
#[allow(
    clippy::too_many_arguments,
    reason = "the AEAD context constructor keeps every authenticated source fact explicit"
)]
pub(crate) fn recording_media_blob_context(
    user_id: &str,
    object_key: &str,
    key_epoch: i64,
    policy_epoch: &str,
    event_id: &str,
    asset_id: &str,
    capture_session_id: &str,
    stream_kind: &str,
    codec: &str,
    byte_length: i64,
    plaintext_sha256: &str,
) -> Result<Vec<u8>> {
    validate_user_id(user_id)?;
    if object_key != canonical_recording_media_object_key(user_id, asset_id)?
        || key_epoch <= 0
        || policy_epoch.len() != 68
        || !policy_epoch.starts_with("rpe_")
        || !policy_epoch[4..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || byte_length <= 0
        || plaintext_sha256.len() != 64
        || !plaintext_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || [event_id, capture_session_id, stream_kind, codec]
            .into_iter()
            .any(|value| {
                value.is_empty()
                    || value.len() > 128
                    || value
                        .bytes()
                        .any(|byte| byte == 0 || byte.is_ascii_control())
            })
    {
        return Err(EnclaveError::InvalidRequest(
            "invalid durable recording encryption context".into(),
        ));
    }

    fn append_field(target: &mut Vec<u8>, value: &[u8]) -> Result<()> {
        let length = u32::try_from(value.len()).map_err(|_| {
            EnclaveError::InvalidRequest("durable recording context is too large".into())
        })?;
        target.extend_from_slice(&length.to_be_bytes());
        target.extend_from_slice(value);
        Ok(())
    }

    let mut context = Vec::with_capacity(512);
    context.extend_from_slice(b"kioku.recording-media.v1\0");
    let byte_length_text = byte_length.to_string();
    let normalized_sha256 = plaintext_sha256.to_ascii_lowercase();
    for value in [
        user_id,
        object_key,
        policy_epoch,
        event_id,
        asset_id,
        capture_session_id,
        stream_kind,
        codec,
        byte_length_text.as_str(),
        normalized_sha256.as_str(),
    ] {
        append_field(&mut context, value.as_bytes())?;
    }
    context.extend_from_slice(&key_epoch.to_be_bytes());
    Ok(context)
}

#[derive(Debug)]
pub struct GcsGetResponse {
    pub ciphertext: Vec<u8>,
    pub wrapped_dek_b64: String,
    pub generation: i64,
}

/// One concrete GCS object generation. Names are routing metadata and must not
/// be logged because they can identify an account.
#[derive(Clone, PartialEq, Eq)]
pub struct GcsObjectVersion {
    pub name: String,
    pub generation: i64,
    /// Present only for provider soft-deleted inventory.
    pub hard_delete_time: Option<String>,
}

#[derive(Clone, Default)]
pub struct GcsListVersionsResponse {
    pub versions: Vec<GcsObjectVersion>,
    pub next_page_token: Option<String>,
}

/// Opaque encrypted-object operations needed by the media repository.
#[async_trait::async_trait]
pub trait GcsClient: Send + Sync {
    async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse>;

    /// Fetch one exact live or noncurrent generation, including its historical
    /// wrapped-DEK metadata.
    async fn get_object_generation(
        &self,
        object_name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse>;

    /// Conditional write. `if_generation_match == 0` means create only.
    async fn put_object(
        &self,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
        if_generation_match: i64,
    ) -> Result<i64>;

    /// List live and noncurrent generations under an exact caller-owned prefix.
    async fn list_object_versions(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse>;

    /// List currently live objects under an exact caller-owned prefix.
    async fn list_live_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse>;

    /// Delete one exact generation. Not-found is success for retryability.
    async fn delete_object_generation(&self, object_name: &str, generation: i64) -> Result<()>;

    /// Inventory provider-retained soft-deleted generations and deadlines.
    async fn list_soft_deleted_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse>;
}

/// Fixed prefix router separating bounded processing media from durable audio.
pub(crate) struct RoutedMediaGcsClient {
    processing: Arc<dyn GcsClient>,
    recordings: Arc<dyn GcsClient>,
}

impl RoutedMediaGcsClient {
    pub(crate) fn new(processing: Arc<dyn GcsClient>, recordings: Arc<dyn GcsClient>) -> Self {
        Self {
            processing,
            recordings,
        }
    }

    fn provider(&self, name_or_prefix: &str) -> Result<Arc<dyn GcsClient>> {
        if name_or_prefix.starts_with("recordings/") {
            Ok(Arc::clone(&self.recordings))
        } else if name_or_prefix.starts_with("raw/") {
            Ok(Arc::clone(&self.processing))
        } else {
            Err(EnclaveError::InvalidRequest(
                "invalid media object namespace".into(),
            ))
        }
    }
}

#[async_trait::async_trait]
impl GcsClient for RoutedMediaGcsClient {
    async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse> {
        self.provider(object_name)?.get_object(object_name).await
    }

    async fn get_object_generation(
        &self,
        object_name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse> {
        self.provider(object_name)?
            .get_object_generation(object_name, generation)
            .await
    }

    async fn put_object(
        &self,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
        if_generation_match: i64,
    ) -> Result<i64> {
        self.provider(object_name)?
            .put_object(
                object_name,
                ciphertext,
                wrapped_dek_b64,
                if_generation_match,
            )
            .await
    }

    async fn list_object_versions(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        self.provider(prefix)?
            .list_object_versions(prefix, page_token)
            .await
    }

    async fn list_live_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        self.provider(prefix)?
            .list_live_objects(prefix, page_token)
            .await
    }

    async fn delete_object_generation(&self, object_name: &str, generation: i64) -> Result<()> {
        self.provider(object_name)?
            .delete_object_generation(object_name, generation)
            .await
    }

    async fn list_soft_deleted_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        self.provider(prefix)?
            .list_soft_deleted_objects(prefix, page_token)
            .await
    }
}

const GCS_LIST_PAGE_SIZE: usize = 1_000;
const MAX_GCS_LIST_PAGES: usize = 1_000_000;

pub(crate) async fn list_all_object_versions(
    gcs: &dyn GcsClient,
    prefix: &str,
) -> Result<Vec<GcsObjectVersion>> {
    let mut versions = Vec::new();
    let mut page_token: Option<String> = None;
    for _ in 0..MAX_GCS_LIST_PAGES {
        let page = gcs
            .list_object_versions(prefix, page_token.as_deref())
            .await?;
        versions.extend(page.versions);
        match page.next_page_token {
            None => return Ok(versions),
            Some(next) if page_token.as_deref() != Some(next.as_str()) => page_token = Some(next),
            Some(_) => {
                return Err(EnclaveError::Gcs(
                    "GCS version listing repeated a page cursor".into(),
                ));
            }
        }
    }
    Err(EnclaveError::Gcs(
        "GCS version listing exceeded its page bound".into(),
    ))
}

pub(crate) async fn delete_all_object_generations(
    gcs: &dyn GcsClient,
    object_name: &str,
) -> Result<()> {
    for version in list_all_object_versions(gcs, object_name)
        .await?
        .into_iter()
        .filter(|version| version.name == object_name)
    {
        gcs.delete_object_generation(&version.name, version.generation)
            .await?;
    }
    if list_all_object_versions(gcs, object_name)
        .await?
        .iter()
        .any(|version| version.name == object_name)
    {
        return Err(EnclaveError::Gcs(
            "GCS object generations remain after deletion".into(),
        ));
    }

    let mut page_token: Option<String> = None;
    let mut retained = false;
    let mut completed = false;
    for _ in 0..MAX_GCS_LIST_PAGES {
        let page = gcs
            .list_soft_deleted_objects(object_name, page_token.as_deref())
            .await?;
        retained |= page
            .versions
            .iter()
            .any(|version| version.name == object_name);
        match page.next_page_token {
            None => {
                completed = true;
                break;
            }
            Some(next) if page_token.as_deref() != Some(next.as_str()) => page_token = Some(next),
            Some(_) => {
                return Err(EnclaveError::Gcs(
                    "GCS soft-deleted listing repeated a page cursor".into(),
                ));
            }
        }
    }
    if !completed {
        return Err(EnclaveError::Gcs(
            "GCS soft-deleted listing exceeded its page bound".into(),
        ));
    }
    if retained {
        return Err(EnclaveError::Gcs(
            "GCS object remains under provider soft-delete retention".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct GcsApiObjectMetadata {
    generation: String,
    metadata: Option<GcsCustomMetadata>,
}

#[derive(Debug, Deserialize)]
struct GcsCustomMetadata {
    #[serde(rename = "x-kioku-wrapped-dek")]
    wrapped_dek: Option<String>,
}

#[derive(Deserialize)]
struct GcsListVersionsPage {
    #[serde(default)]
    items: Vec<GcsVersionMetadata>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct GcsVersionMetadata {
    name: String,
    generation: String,
    #[serde(rename = "hardDeleteTime")]
    hard_delete_time: Option<String>,
}

#[derive(Deserialize)]
struct GcsErrorEnvelope {
    error: GcsErrorBody,
}

#[derive(Deserialize)]
struct GcsErrorBody {
    code: u16,
    #[serde(default)]
    errors: Vec<GcsErrorDetail>,
}

#[derive(Deserialize)]
struct GcsErrorDetail {
    reason: String,
}

fn decode_gcs_versions_page(
    body: &[u8],
    generation_label: &str,
) -> Result<GcsListVersionsResponse> {
    let page: GcsListVersionsPage = serde_json::from_slice(body)?;
    let versions = page
        .items
        .into_iter()
        .map(|item| {
            Ok(GcsObjectVersion {
                name: item.name,
                generation: item.generation.parse().map_err(|_| {
                    EnclaveError::Gcs(format!("invalid {generation_label} generation"))
                })?,
                hard_delete_time: item.hard_delete_time,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(GcsListVersionsResponse {
        versions,
        next_page_token: page.next_page_token,
    })
}

fn decode_soft_deleted_list_response(
    status: reqwest::StatusCode,
    body: &[u8],
    first_page: bool,
) -> Result<GcsListVersionsResponse> {
    if status.is_success() {
        return decode_gcs_versions_page(body, "soft-deleted");
    }
    // A first-page 400 with only these provider reasons means that the bucket
    // has no soft-delete policy. Never extend this exception to continuation
    // requests, where it could hide a malformed cursor.
    let policy_disabled =
        status == reqwest::StatusCode::BAD_REQUEST
            && first_page
            && serde_json::from_slice::<GcsErrorEnvelope>(body).is_ok_and(|envelope| {
                envelope.error.code == 400
                    && !envelope.error.errors.is_empty()
                    && envelope.error.errors.iter().all(|detail| {
                        matches!(detail.reason.as_str(), "invalid" | "invalidArgument")
                    })
            });
    if policy_disabled {
        return Ok(GcsListVersionsResponse::default());
    }
    Err(EnclaveError::Gcs(format!(
        "GCS soft-delete listing failed with HTTP {}",
        status.as_u16()
    )))
}

pub struct GcpGcsClient {
    http: reqwest::Client,
    bucket: String,
    api_base: String,
    metadata_token_url: String,
}

impl GcpGcsClient {
    pub fn from_bucket(bucket: String) -> Self {
        Self::from_parts(
            bucket,
            "https://storage.googleapis.com".into(),
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
                .into(),
        )
    }

    fn from_parts(bucket: String, api_base: String, metadata_token_url: String) -> Self {
        Self {
            http: gcs_http_client(),
            bucket,
            api_base,
            metadata_token_url,
        }
    }

    async fn access_token(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }

        let token: TokenResponse = self
            .http
            .get(&self.metadata_token_url)
            .header("Metadata-Flavor", "Google")
            .timeout(Duration::from_secs(3))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(token.access_token)
    }

    async fn object_metadata(
        &self,
        object_name: &str,
        generation: Option<i64>,
    ) -> Result<(i64, String)> {
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(object_name);
        let generation_query = generation
            .map(|value| format!("?generation={value}"))
            .unwrap_or_default();
        let url = format!(
            "{}/storage/v1/b/{}/o/{}{}",
            self.api_base, self.bucket, encoded, generation_query
        );
        let response = self.http.get(url).bearer_auth(token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(EnclaveError::NotFound);
        }
        let metadata = response
            .error_for_status()?
            .json::<GcsApiObjectMetadata>()
            .await?;
        let generation = metadata
            .generation
            .parse()
            .map_err(|_| EnclaveError::Gcs("invalid generation".into()))?;
        let wrapped_dek = metadata
            .metadata
            .and_then(|metadata| metadata.wrapped_dek)
            .ok_or_else(|| EnclaveError::Gcs("missing wrapped DEK in object metadata".into()))?;
        Ok((generation, wrapped_dek))
    }

    async fn get_object_at_generation(
        &self,
        object_name: &str,
        requested_generation: Option<i64>,
    ) -> Result<GcsGetResponse> {
        let (generation, wrapped_dek_b64) = self
            .object_metadata(object_name, requested_generation)
            .await?;
        if requested_generation.is_some_and(|requested| requested != generation) {
            return Err(EnclaveError::Gcs(
                "GCS returned an unexpected object generation".into(),
            ));
        }
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(object_name);
        let url = format!(
            "{}/download/storage/v1/b/{}/o/{}?alt=media&generation={generation}",
            self.api_base, self.bucket, encoded
        );
        let response = self.http.get(url).bearer_auth(token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(EnclaveError::NotFound);
        }
        let ciphertext = response.error_for_status()?.bytes().await?.to_vec();
        Ok(GcsGetResponse {
            ciphertext,
            wrapped_dek_b64,
            generation,
        })
    }

    async fn list_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
        mode: &str,
    ) -> Result<GcsListVersionsResponse> {
        let token = self.access_token().await?;
        let mode_query = match mode {
            "versions" => "versions=true&",
            "soft-deleted" => "softDeleted=true&",
            "live" => "",
            _ => return Err(EnclaveError::Gcs("invalid GCS list mode".into())),
        };
        let mut url = format!(
            "{}/storage/v1/b/{}/o?{mode_query}maxResults={}&prefix={}",
            self.api_base,
            self.bucket,
            GCS_LIST_PAGE_SIZE,
            urlencoding::encode(prefix)
        );
        if let Some(page_token) = page_token {
            url.push_str("&pageToken=");
            url.push_str(&urlencoding::encode(page_token));
        }
        let response = self.http.get(url).bearer_auth(token).send().await?;
        if mode == "soft-deleted" {
            let status = response.status();
            let body = response.bytes().await?;
            decode_soft_deleted_list_response(status, &body, page_token.is_none())
        } else {
            let response = response.error_for_status()?;
            decode_gcs_versions_page(&response.bytes().await?, mode)
        }
    }
}

fn gcs_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(300))
        .build()
        .expect("static GCS HTTP client configuration is valid")
}

#[async_trait::async_trait]
impl GcsClient for GcpGcsClient {
    async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse> {
        self.get_object_at_generation(object_name, None).await
    }

    async fn get_object_generation(
        &self,
        object_name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse> {
        if generation <= 0 {
            return Err(EnclaveError::Gcs(
                "exact GCS generation must be positive".into(),
            ));
        }
        self.get_object_at_generation(object_name, Some(generation))
            .await
    }

    async fn put_object(
        &self,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
        if_generation_match: i64,
    ) -> Result<i64> {
        if if_generation_match < 0 {
            return Err(EnclaveError::Gcs(
                "GCS generation precondition must not be negative".into(),
            ));
        }
        let token = self.access_token().await?;
        let upload_url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=multipart&name={}&ifGenerationMatch={}",
            self.api_base,
            self.bucket,
            urlencoding::encode(object_name),
            if_generation_match
        );
        let metadata_json = serde_json::json!({
            "metadata": { "x-kioku-wrapped-dek": wrapped_dek_b64 }
        })
        .to_string();
        let boundary = format!(
            "kioku-boundary-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata_json}\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(ciphertext);
        body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());

        let response = self
            .http
            .post(upload_url)
            .bearer_auth(token)
            .header(
                "Content-Type",
                format!("multipart/related; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::PRECONDITION_FAILED {
            return Err(EnclaveError::Conflict(
                "GCS generation mismatch — concurrent write detected; reload and retry".into(),
            ));
        }
        let metadata = response
            .error_for_status()?
            .json::<GcsApiObjectMetadata>()
            .await?;
        metadata
            .generation
            .parse()
            .map_err(|error| EnclaveError::Gcs(format!("bad generation in PUT response: {error}")))
    }

    async fn list_object_versions(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        self.list_objects(prefix, page_token, "versions").await
    }

    async fn list_live_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        self.list_objects(prefix, page_token, "live").await
    }

    async fn delete_object_generation(&self, object_name: &str, generation: i64) -> Result<()> {
        if generation <= 0 {
            return Err(EnclaveError::Gcs(
                "exact GCS generation must be positive".into(),
            ));
        }
        let token = self.access_token().await?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?generation={generation}",
            self.api_base,
            self.bucket,
            urlencoding::encode(object_name)
        );
        let response = self.http.delete(url).bearer_auth(token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        response.error_for_status()?;
        Ok(())
    }

    async fn list_soft_deleted_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        self.list_objects(prefix, page_token, "soft-deleted").await
    }
}

#[cfg(test)]
pub(crate) use tests::FakeGcs;

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, AtomicI64, Ordering},
            Mutex,
        },
    };

    use super::*;

    #[derive(Clone)]
    struct FakeObject {
        ciphertext: Vec<u8>,
        wrapped_dek_b64: String,
        generation: i64,
        live: bool,
        soft_deleted: bool,
        hard_delete_time: Option<String>,
    }

    /// Hermetic GCS fake for media-repository contract tests.
    pub(crate) struct FakeGcs {
        objects: Mutex<HashMap<String, Vec<FakeObject>>>,
        next_generation: AtomicI64,
        soft_delete: AtomicBool,
        hard_delete_time: Mutex<Option<String>>,
    }

    impl FakeGcs {
        pub(crate) fn new() -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
                next_generation: AtomicI64::new(1),
                soft_delete: AtomicBool::new(false),
                hard_delete_time: Mutex::new(Some("2099-01-01T00:00:00.000Z".into())),
            }
        }

        pub(crate) fn set_soft_delete_enabled(&self, enabled: bool) {
            self.soft_delete.store(enabled, Ordering::SeqCst);
        }

        fn response(object: &FakeObject) -> GcsGetResponse {
            GcsGetResponse {
                ciphertext: object.ciphertext.clone(),
                wrapped_dek_b64: object.wrapped_dek_b64.clone(),
                generation: object.generation,
            }
        }

        fn list_matching(
            &self,
            prefix: &str,
            include: impl Fn(&FakeObject) -> bool,
        ) -> GcsListVersionsResponse {
            let objects = self.objects.lock().unwrap();
            let mut versions = objects
                .iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .flat_map(|(name, versions)| {
                    versions
                        .iter()
                        .filter(|object| include(object))
                        .map(|object| GcsObjectVersion {
                            name: name.clone(),
                            generation: object.generation,
                            hard_delete_time: object.hard_delete_time.clone(),
                        })
                })
                .collect::<Vec<_>>();
            versions.sort_by(|left, right| {
                left.name
                    .cmp(&right.name)
                    .then(left.generation.cmp(&right.generation))
            });
            GcsListVersionsResponse {
                versions,
                next_page_token: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for FakeGcs {
        async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse> {
            let objects = self.objects.lock().unwrap();
            objects
                .get(object_name)
                .and_then(|versions| versions.iter().rev().find(|object| object.live))
                .map(Self::response)
                .ok_or(EnclaveError::NotFound)
        }

        async fn get_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> Result<GcsGetResponse> {
            let objects = self.objects.lock().unwrap();
            objects
                .get(object_name)
                .and_then(|versions| {
                    versions
                        .iter()
                        .find(|object| object.generation == generation && !object.soft_deleted)
                })
                .map(Self::response)
                .ok_or(EnclaveError::NotFound)
        }

        async fn put_object(
            &self,
            object_name: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            if_generation_match: i64,
        ) -> Result<i64> {
            let mut objects = self.objects.lock().unwrap();
            let versions = objects.entry(object_name.into()).or_default();
            let current = versions.iter().rev().find(|object| object.live);
            let precondition_matches = match (if_generation_match, current) {
                (0, None) => true,
                (expected, Some(current)) if expected == current.generation => true,
                _ => false,
            };
            if !precondition_matches {
                return Err(EnclaveError::Conflict(
                    "GCS generation mismatch — concurrent write detected; reload and retry".into(),
                ));
            }
            for object in versions.iter_mut() {
                object.live = false;
            }
            let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
            versions.push(FakeObject {
                ciphertext: ciphertext.to_vec(),
                wrapped_dek_b64: wrapped_dek_b64.into(),
                generation,
                live: true,
                soft_deleted: false,
                hard_delete_time: None,
            });
            Ok(generation)
        }

        async fn list_object_versions(
            &self,
            prefix: &str,
            _page_token: Option<&str>,
        ) -> Result<GcsListVersionsResponse> {
            Ok(self.list_matching(prefix, |object| !object.soft_deleted))
        }

        async fn list_live_objects(
            &self,
            prefix: &str,
            _page_token: Option<&str>,
        ) -> Result<GcsListVersionsResponse> {
            Ok(self.list_matching(prefix, |object| object.live))
        }

        async fn delete_object_generation(&self, object_name: &str, generation: i64) -> Result<()> {
            let mut objects = self.objects.lock().unwrap();
            let Some(versions) = objects.get_mut(object_name) else {
                return Ok(());
            };
            if self.soft_delete.load(Ordering::SeqCst) {
                if let Some(object) = versions
                    .iter_mut()
                    .find(|object| object.generation == generation)
                {
                    object.live = false;
                    object.soft_deleted = true;
                    object.hard_delete_time = self.hard_delete_time.lock().unwrap().clone();
                }
            } else {
                versions.retain(|object| object.generation != generation);
            }
            if versions.is_empty() {
                objects.remove(object_name);
            }
            Ok(())
        }

        async fn list_soft_deleted_objects(
            &self,
            prefix: &str,
            _page_token: Option<&str>,
        ) -> Result<GcsListVersionsResponse> {
            Ok(self.list_matching(prefix, |object| object.soft_deleted))
        }
    }

    #[test]
    fn canonical_media_keys_reject_routing_characters() {
        assert_eq!(
            canonical_capture_media_object_key("account-1", "asset_1").unwrap(),
            "raw/account-1/asset_1.enc"
        );
        assert_eq!(
            canonical_recording_media_object_key("account-1", "asset_1").unwrap(),
            "recordings/account-1/asset_1.enc"
        );
        for invalid in ["", "../other", "a/b", "has space"] {
            assert!(canonical_capture_media_object_key("account-1", invalid).is_err());
        }
        assert!(validate_user_id("../other").is_err());
    }

    #[tokio::test]
    async fn fake_preserves_exact_generations_and_conditional_writes() {
        let gcs = FakeGcs::new();
        let first = gcs.put_object("raw/a/x", b"one", "dek-1", 0).await.unwrap();
        let second = gcs
            .put_object("raw/a/x", b"two", "dek-2", first)
            .await
            .unwrap();
        assert_eq!(
            gcs.get_object_generation("raw/a/x", first)
                .await
                .unwrap()
                .ciphertext,
            b"one"
        );
        assert_eq!(gcs.get_object("raw/a/x").await.unwrap().generation, second);
        assert!(matches!(
            gcs.put_object("raw/a/x", b"stale", "dek", first).await,
            Err(EnclaveError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn routed_media_accepts_only_current_object_namespaces() {
        let processing: Arc<dyn GcsClient> = Arc::new(FakeGcs::new());
        let recordings: Arc<dyn GcsClient> = Arc::new(FakeGcs::new());
        let routed = RoutedMediaGcsClient::new(Arc::clone(&processing), Arc::clone(&recordings));

        routed
            .put_object("raw/account/asset.enc", b"raw", "dek", 0)
            .await
            .unwrap();
        routed
            .put_object("recordings/account/asset.enc", b"recording", "dek", 0)
            .await
            .unwrap();

        assert!(processing.get_object("raw/account/asset.enc").await.is_ok());
        assert!(recordings
            .get_object("recordings/account/asset.enc")
            .await
            .is_ok());
        assert!(matches!(
            routed
                .put_object("indexes/account.db.enc", b"database", "dek", 0)
                .await,
            Err(EnclaveError::InvalidRequest(_))
        ));
    }

    #[test]
    fn soft_delete_policy_absence_is_only_accepted_on_the_first_page() {
        let body = br#"{"error":{"code":400,"errors":[{"reason":"invalid"}]}}"#;
        assert!(
            decode_soft_deleted_list_response(reqwest::StatusCode::BAD_REQUEST, body, true)
                .unwrap()
                .versions
                .is_empty()
        );
        assert!(
            decode_soft_deleted_list_response(reqwest::StatusCode::BAD_REQUEST, body, false)
                .is_err()
        );
    }
}
