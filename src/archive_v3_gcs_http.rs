#![allow(
    dead_code,
    reason = "inactive ADR-0022 GCS HTTP transport is intentionally not wired to runtime authority"
)]

//! Concrete, but inactive, Google Cloud Storage REST transport for archive-v3.
//!
//! This module deliberately exposes no environment constructor and is not
//! connected to the Store, VFS, witness, routes, Terraform, or write
//! authority. Callers must supply a narrow bearer-token provider; this code
//! neither contacts metadata service nor logs credentials, URLs, object names,
//! opaque IDs, hashes, response bodies, or pagination tokens.

use crate::{
    archive_v3::{ObjectId, MAX_ENCODED_ENVELOPE_BYTES},
    archive_v3_gcs::{
        canonical_object_id, valid_archive_prefix, ArchiveV3GcsTransport, GcsArchiveV3ClaimResult,
        GcsArchiveV3CreateResult, GcsArchiveV3DeleteResult, GcsArchiveV3Page,
        GcsArchiveV3TransportError, MAX_CANONICAL_OBJECT_KEY_BYTES, MAX_ENUMERATION_PAGE_BYTES,
    },
};
use serde::Deserialize;
use std::{collections::BTreeSet, fmt, net::Ipv4Addr, sync::Arc, time::Duration};
use zeroize::Zeroizing;

const MAX_CLAIM_BYTES: usize = 2 * 1024;
const MAX_METADATA_BYTES: usize = 8 * 1024;
const MAX_LIST_RESPONSE_BYTES: usize = MAX_ENUMERATION_PAGE_BYTES + 128 * 1024;
const MAX_PROVIDER_PAGE_RESULTS: usize = 1_000;
const MAX_DELETE_PAGES: usize = 128;
const MAX_DELETE_PASSES: usize = 3;
const MAX_PAGE_TOKEN_BYTES: usize = 2 * 1024;
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Supplies only a short-lived bearer token. A production implementation must
/// obtain it through the attestation-bound identity path; metadata-service
/// tokens are expressly outside this transport's contract.
#[async_trait::async_trait]
pub(crate) trait ArchiveV3BearerTokenProvider: Send + Sync {
    async fn bearer_token(
        &self,
    ) -> std::result::Result<Zeroizing<String>, GcsArchiveV3TransportError>;
}

/// Authenticates the rollout invariant that bucket soft delete is disabled and
/// every object retained by an earlier policy has passed its hard-delete time.
/// A production implementation must derive this from provider/audit evidence
/// and trusted time; a configuration boolean is not sufficient.
#[async_trait::async_trait]
pub(crate) trait ArchiveV3SoftDeleteDrainGate: Send + Sync {
    async fn disabled_and_drained(
        &self,
        canonical_bucket: &str,
    ) -> std::result::Result<bool, GcsArchiveV3TransportError>;
}

/// Concrete REST implementation of [`ArchiveV3GcsTransport`]. It has no
/// `Debug` output containing endpoint or bucket material.
pub(crate) struct GcpArchiveV3HttpTransport {
    http: reqwest::Client,
    endpoint: String,
    bucket: String,
    tokens: Arc<dyn ArchiveV3BearerTokenProvider>,
    soft_delete_drain: Arc<dyn ArchiveV3SoftDeleteDrainGate>,
}

impl GcpArchiveV3HttpTransport {
    /// Create a transport for the normal GCS JSON API endpoint. This does not
    /// perform I/O and does not inspect process environment.
    pub(crate) fn new(
        bucket: String,
        tokens: Arc<dyn ArchiveV3BearerTokenProvider>,
        soft_delete_drain: Arc<dyn ArchiveV3SoftDeleteDrainGate>,
    ) -> std::result::Result<Self, GcsArchiveV3TransportError> {
        Self::new_with_endpoint(
            "https://storage.googleapis.com",
            bucket,
            tokens,
            soft_delete_drain,
        )
    }

    /// Endpoint injection is solely an inactive-construction seam for explicit
    /// deployment wiring and local HTTP tests. It must be an absolute HTTPS
    /// origin without a path/query/fragment; plaintext HTTP is loopback-only.
    pub(crate) fn new_with_endpoint(
        endpoint: &str,
        bucket: String,
        tokens: Arc<dyn ArchiveV3BearerTokenProvider>,
        soft_delete_drain: Arc<dyn ArchiveV3SoftDeleteDrainGate>,
    ) -> std::result::Result<Self, GcsArchiveV3TransportError> {
        if !valid_bucket_name(&bucket) || !valid_endpoint(endpoint) {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        Ok(Self {
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            bucket,
            tokens,
            soft_delete_drain,
        })
    }

    async fn authenticated(
        &self,
        request: reqwest::RequestBuilder,
    ) -> std::result::Result<reqwest::RequestBuilder, GcsArchiveV3TransportError> {
        let token = self.tokens.bearer_token().await?;
        if !valid_bearer_token(token.as_bytes()) {
            return Err(GcsArchiveV3TransportError::Unavailable);
        }
        Ok(request.bearer_auth(token.as_str()))
    }

    fn object_metadata_url(&self, key: &str, generation: Option<&str>) -> String {
        let mut url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.endpoint,
            canonical_url_component(&self.bucket),
            canonical_url_component(key)
        );
        if let Some(generation) = generation {
            url.push_str("?generation=");
            url.push_str(&canonical_url_component(generation));
        }
        url
    }

    fn object_media_url(&self, key: &str, generation: Option<&str>) -> String {
        let mut url = format!(
            "{}/download/storage/v1/b/{}/o/{}?alt=media",
            self.endpoint,
            canonical_url_component(&self.bucket),
            canonical_url_component(key)
        );
        if let Some(generation) = generation {
            url.push_str("&generation=");
            url.push_str(&canonical_url_component(generation));
        }
        url
    }

    fn simple_upload_url(&self, key: &str, if_generation_match: Option<&str>) -> String {
        let mut url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.endpoint,
            canonical_url_component(&self.bucket),
            canonical_url_component(key)
        );
        if let Some(generation) = if_generation_match {
            url.push_str("&ifGenerationMatch=");
            url.push_str(&canonical_url_component(generation));
        }
        url
    }

    fn list_url(
        &self,
        prefix: &str,
        start_offset: Option<&str>,
        versions: bool,
        soft_deleted: bool,
        page_token: Option<&str>,
        max_results: usize,
    ) -> String {
        let mut url = format!(
            "{}/storage/v1/b/{}/o?maxResults={}&prefix={}",
            self.endpoint,
            canonical_url_component(&self.bucket),
            max_results,
            canonical_url_component(prefix)
        );
        if versions {
            url.push_str("&versions=true");
        }
        if soft_deleted {
            url.push_str("&softDeleted=true");
        }
        if let Some(start_offset) = start_offset {
            url.push_str("&startOffset=");
            url.push_str(&canonical_url_component(start_offset));
        }
        if let Some(page_token) = page_token {
            url.push_str("&pageToken=");
            url.push_str(&canonical_url_component(page_token));
        }
        url
    }

    fn generation_delete_url(&self, key: &str, generation: &str) -> String {
        format!(
            "{}?generation={}",
            self.object_metadata_url(key, None),
            canonical_url_component(generation)
        )
    }

    async fn get_metadata(
        &self,
        key: &str,
    ) -> std::result::Result<Option<ObjectMetadata>, GcsArchiveV3TransportError> {
        let request = self.http.get(self.object_metadata_url(key, None));
        let response = self
            .authenticated(request)
            .await?
            .send()
            .await
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(read_status(response.status()));
        }
        let bytes = bounded_body(response, MAX_METADATA_BYTES).await?;
        let metadata: ObjectMetadata =
            serde_json::from_slice(&bytes).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
        if !canonical_generation(&metadata.generation) {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        Ok(Some(metadata))
    }

    async fn read_object(
        &self,
        key: &str,
        generation: Option<&str>,
        max_bytes: usize,
    ) -> std::result::Result<Option<Vec<u8>>, GcsArchiveV3TransportError> {
        let request = self.http.get(self.object_media_url(key, generation));
        let response = self
            .authenticated(request)
            .await?
            .send()
            .await
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(read_status(response.status()));
        }
        bounded_body(response, max_bytes).await.map(Some)
    }

    async fn create_object(
        &self,
        key: &str,
        bytes: &[u8],
        if_generation_match: &str,
    ) -> std::result::Result<GcsArchiveV3CreateResult, GcsArchiveV3TransportError> {
        let request = self
            .http
            .post(self.simple_upload_url(key, Some(if_generation_match)))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes.to_vec());
        // Any transport failure from a mutation is ambiguous: GCS may have
        // committed the request even when no response reached us.
        let response = self
            .authenticated(request)
            .await?
            .send()
            .await
            .map_err(|_| GcsArchiveV3TransportError::OutcomeUnknown)?;
        if response.status().is_success() {
            Ok(GcsArchiveV3CreateResult::Created)
        } else if response.status() == reqwest::StatusCode::PRECONDITION_FAILED {
            Ok(GcsArchiveV3CreateResult::PreconditionFailed)
        } else if response.status().is_server_error()
            || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            || response.status() == reqwest::StatusCode::REQUEST_TIMEOUT
        {
            Err(GcsArchiveV3TransportError::OutcomeUnknown)
        } else if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            Err(GcsArchiveV3TransportError::Unavailable)
        } else {
            Err(GcsArchiveV3TransportError::Protocol)
        }
    }

    fn claim_key(
        canonical_archive_prefix: &str,
        object_id: ObjectId,
    ) -> std::result::Result<String, GcsArchiveV3TransportError> {
        let archive_id = canonical_archive_prefix
            .strip_prefix("archive/v3/")
            .and_then(|suffix| suffix.strip_suffix('/'))
            .filter(|id| id.len() == 32 && id.bytes().all(is_lower_hex))
            .ok_or(GcsArchiveV3TransportError::Protocol)?;
        Ok(format!(
            "archive/v3-claims/{archive_id}/objects/{}.claim",
            hex_bytes(object_id.as_bytes())
        ))
    }

    async fn read_claim(
        &self,
        claim_key: &str,
    ) -> std::result::Result<Option<(ObjectMetadata, ClaimWire)>, GcsArchiveV3TransportError> {
        let Some(metadata) = self.get_metadata(claim_key).await? else {
            return Ok(None);
        };
        let Some(bytes) = self
            .read_object(claim_key, Some(&metadata.generation), MAX_CLAIM_BYTES)
            .await?
        else {
            // A claim metadata/media race cannot be treated as a fresh ID.
            return Err(GcsArchiveV3TransportError::OutcomeUnknown);
        };
        let claim: ClaimWire =
            serde_json::from_slice(&bytes).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
        claim.validate()?;
        Ok(Some((metadata, claim)))
    }

    async fn classify_claim(
        &self,
        claim_key: &str,
        canonical_key: &str,
        ciphertext_hash: [u8; 32],
    ) -> std::result::Result<Option<(ObjectMetadata, ClaimState, bool)>, GcsArchiveV3TransportError>
    {
        let Some((metadata, claim)) = self.read_claim(claim_key).await? else {
            return Ok(None);
        };
        let binding_matches =
            claim.key == canonical_key && claim.hash == hex_bytes(&ciphertext_hash);
        Ok(Some((metadata, claim.state, binding_matches)))
    }

    async fn delete_generation(
        &self,
        key: &str,
        generation: &str,
    ) -> std::result::Result<(), GcsArchiveV3TransportError> {
        let request = self
            .http
            .delete(self.generation_delete_url(key, generation));
        let response = self
            .authenticated(request)
            .await?
            .send()
            .await
            .map_err(|_| GcsArchiveV3TransportError::OutcomeUnknown)?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else if response.status().is_server_error()
            || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            || response.status() == reqwest::StatusCode::REQUEST_TIMEOUT
        {
            Err(GcsArchiveV3TransportError::OutcomeUnknown)
        } else if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            Err(GcsArchiveV3TransportError::Unavailable)
        } else {
            Err(GcsArchiveV3TransportError::Protocol)
        }
    }

    async fn list_generations_exact(
        &self,
        key: &str,
    ) -> std::result::Result<Vec<String>, GcsArchiveV3TransportError> {
        let mut token: Option<String> = None;
        let mut seen_tokens = BTreeSet::new();
        let mut generations = BTreeSet::new();
        for _ in 0..MAX_DELETE_PAGES {
            let request = self.http.get(self.list_url(
                key,
                None,
                true,
                false,
                token.as_deref(),
                MAX_PROVIDER_PAGE_RESULTS,
            ));
            let response = self
                .authenticated(request)
                .await?
                .send()
                .await
                .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
            if !response.status().is_success() {
                return Err(read_status(response.status()));
            }
            let bytes = bounded_body(response, MAX_LIST_RESPONSE_BYTES).await?;
            let page: ListWire =
                serde_json::from_slice(&bytes).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
            if page.items.len() > MAX_PROVIDER_PAGE_RESULTS {
                return Err(GcsArchiveV3TransportError::TooLarge);
            }
            for item in page.items {
                if item.name != key || !canonical_generation(&item.generation) {
                    // Prefix listing must never be allowed to delete an adjacent key.
                    return Err(GcsArchiveV3TransportError::Protocol);
                }
                if !generations.insert(item.generation) {
                    return Err(GcsArchiveV3TransportError::Protocol);
                }
            }
            match page.next_page_token {
                None => return Ok(generations.into_iter().collect()),
                Some(next) => {
                    if next.is_empty()
                        || next.len() > MAX_PAGE_TOKEN_BYTES
                        || !seen_tokens.insert(next.clone())
                    {
                        return Err(GcsArchiveV3TransportError::Protocol);
                    }
                    token = Some(next);
                }
            }
        }
        Err(GcsArchiveV3TransportError::TooLarge)
    }

    /// Soft-deleted generations cannot be physically removed by the JSON API.
    /// Seeing one therefore prevents this transport from claiming exact physical
    /// deletion. A 400 from `softDeleted=true` succeeds only when the separate
    /// authenticated drain gate proves earlier retained generations aged out.
    async fn has_soft_deleted_generation_exact(
        &self,
        key: &str,
    ) -> std::result::Result<bool, GcsArchiveV3TransportError> {
        let mut token: Option<String> = None;
        let mut seen_tokens = BTreeSet::new();
        for _ in 0..MAX_DELETE_PAGES {
            let request = self.http.get(self.list_url(
                key,
                None,
                false,
                true,
                token.as_deref(),
                MAX_PROVIDER_PAGE_RESULTS,
            ));
            let response = self
                .authenticated(request)
                .await?
                .send()
                .await
                .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
            if response.status() == reqwest::StatusCode::BAD_REQUEST {
                // With soft delete disabled, GCS rejects softDeleted=true.
                // That response is not itself evidence that older retained
                // generations have drained, so require an independent gate.
                return self
                    .soft_delete_drain
                    .disabled_and_drained(&self.bucket)
                    .await?
                    .then_some(false)
                    .ok_or(GcsArchiveV3TransportError::Protocol);
            }
            if !response.status().is_success() {
                return Err(read_status(response.status()));
            }
            let bytes = bounded_body(response, MAX_LIST_RESPONSE_BYTES).await?;
            let page: ListWire =
                serde_json::from_slice(&bytes).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
            if page.items.len() > MAX_PROVIDER_PAGE_RESULTS {
                return Err(GcsArchiveV3TransportError::TooLarge);
            }
            if page
                .items
                .iter()
                .any(|item| item.name != key || !canonical_generation(&item.generation))
            {
                return Err(GcsArchiveV3TransportError::Protocol);
            }
            if !page.items.is_empty() {
                return Ok(true);
            }
            match page.next_page_token {
                None => return Ok(false),
                Some(next) => {
                    if next.is_empty()
                        || next.len() > MAX_PAGE_TOKEN_BYTES
                        || !seen_tokens.insert(next.clone())
                    {
                        return Err(GcsArchiveV3TransportError::Protocol);
                    }
                    token = Some(next);
                }
            }
        }
        Err(GcsArchiveV3TransportError::TooLarge)
    }

    async fn list_names_once(
        &self,
        canonical_prefix: &str,
        start_offset: Option<&str>,
        page_token: Option<&str>,
        max_results: usize,
    ) -> std::result::Result<ListWire, GcsArchiveV3TransportError> {
        let request = self.http.get(self.list_url(
            canonical_prefix,
            start_offset,
            false,
            false,
            page_token,
            max_results,
        ));
        let response = self
            .authenticated(request)
            .await?
            .send()
            .await
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        if !response.status().is_success() {
            return Err(read_status(response.status()));
        }
        let bytes = bounded_body(response, MAX_LIST_RESPONSE_BYTES).await?;
        let wire: ListWire =
            serde_json::from_slice(&bytes).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
        if wire.items.len() > max_results {
            return Err(GcsArchiveV3TransportError::TooLarge);
        }
        Ok(wire)
    }
}

#[async_trait::async_trait]
impl ArchiveV3GcsTransport for GcpArchiveV3HttpTransport {
    async fn claim_object_id(
        &self,
        canonical_archive_prefix: &str,
        object_id: ObjectId,
        canonical_key: &str,
        ciphertext_hash: [u8; 32],
    ) -> std::result::Result<GcsArchiveV3ClaimResult, GcsArchiveV3TransportError> {
        if !valid_archive_prefix(canonical_archive_prefix)
            || !canonical_key.starts_with(canonical_archive_prefix)
            || canonical_object_id(canonical_key) != Some(object_id)
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        let claim_key = Self::claim_key(canonical_archive_prefix, object_id)?;
        let reserved =
            ClaimWire::new(canonical_key, ciphertext_hash, ClaimState::Reserved).encode();
        match self.create_object(&claim_key, &reserved, "0").await {
            Ok(GcsArchiveV3CreateResult::Created) => Ok(GcsArchiveV3ClaimResult::Reserved),
            Ok(GcsArchiveV3CreateResult::PreconditionFailed)
            | Err(GcsArchiveV3TransportError::OutcomeUnknown) => {
                match self
                    .classify_claim(&claim_key, canonical_key, ciphertext_hash)
                    .await?
                {
                    Some((_, _, false)) => Ok(GcsArchiveV3ClaimResult::Conflict),
                    Some((_, ClaimState::Reserved, true)) => {
                        Ok(GcsArchiveV3ClaimResult::AlreadyReserved)
                    }
                    Some((_, ClaimState::Materialized, true)) => {
                        Ok(GcsArchiveV3ClaimResult::AlreadyMaterialized)
                    }
                    None => Err(GcsArchiveV3TransportError::OutcomeUnknown),
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn mark_object_id_materialized(
        &self,
        canonical_archive_prefix: &str,
        object_id: ObjectId,
        canonical_key: &str,
        ciphertext_hash: [u8; 32],
    ) -> std::result::Result<(), GcsArchiveV3TransportError> {
        if !valid_archive_prefix(canonical_archive_prefix)
            || !canonical_key.starts_with(canonical_archive_prefix)
            || canonical_object_id(canonical_key) != Some(object_id)
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        let claim_key = Self::claim_key(canonical_archive_prefix, object_id)?;
        let Some((metadata, state, binding_matches)) = self
            .classify_claim(&claim_key, canonical_key, ciphertext_hash)
            .await?
        else {
            return Err(GcsArchiveV3TransportError::Protocol);
        };
        if !binding_matches {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        if state == ClaimState::Materialized {
            return Ok(());
        }
        let materialized =
            ClaimWire::new(canonical_key, ciphertext_hash, ClaimState::Materialized).encode();
        match self
            .create_object(&claim_key, &materialized, &metadata.generation)
            .await
        {
            Ok(GcsArchiveV3CreateResult::Created) => Ok(()),
            Ok(GcsArchiveV3CreateResult::PreconditionFailed)
            | Err(GcsArchiveV3TransportError::OutcomeUnknown) => {
                match self
                    .classify_claim(&claim_key, canonical_key, ciphertext_hash)
                    .await?
                {
                    Some((_, ClaimState::Materialized, true)) => Ok(()),
                    Some((_, _, false)) => Err(GcsArchiveV3TransportError::Protocol),
                    Some((_, ClaimState::Reserved, true)) | None => {
                        Err(GcsArchiveV3TransportError::OutcomeUnknown)
                    }
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn create_if_absent(
        &self,
        canonical_key: &str,
        bytes: &[u8],
    ) -> std::result::Result<GcsArchiveV3CreateResult, GcsArchiveV3TransportError> {
        if canonical_object_id(canonical_key).is_none()
            || bytes.is_empty()
            || bytes.len() > MAX_ENCODED_ENVELOPE_BYTES
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        self.create_object(canonical_key, bytes, "0").await
    }

    async fn read_exact(
        &self,
        canonical_key: &str,
        max_bytes: usize,
    ) -> std::result::Result<Option<Vec<u8>>, GcsArchiveV3TransportError> {
        if canonical_object_id(canonical_key).is_none()
            || max_bytes == 0
            || max_bytes > MAX_ENCODED_ENVELOPE_BYTES
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        self.read_object(canonical_key, None, max_bytes).await
    }

    async fn list_after(
        &self,
        canonical_prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> std::result::Result<GcsArchiveV3Page, GcsArchiveV3TransportError> {
        if !valid_archive_prefix(canonical_prefix)
            || limit == 0
            || limit > MAX_PROVIDER_PAGE_RESULTS + 1
            || after.is_some_and(|key| {
                !key.starts_with(canonical_prefix) || canonical_object_id(key).is_none()
            })
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        // GCS recommends at most 1,000 results per provider page, while the
        // backend requests 1,001 to compute a safe public key cursor. Provider
        // tokens remain private to this call; the returned cursor is key-based.
        let mut page_token: Option<String> = None;
        let mut seen_tokens = BTreeSet::new();
        let mut previous = after.map(str::to_owned);
        let mut page_bytes = 0usize;
        let mut skipped_inclusive_boundary = false;
        let mut names = Vec::with_capacity(limit);
        for _ in 0..MAX_DELETE_PAGES {
            if names.len() >= limit {
                return Ok(GcsArchiveV3Page { names });
            }
            let remaining = limit - names.len();
            let boundary_allowance = usize::from(page_token.is_none() && after.is_some());
            let request_limit = remaining
                .saturating_add(boundary_allowance)
                .min(MAX_PROVIDER_PAGE_RESULTS);
            let page = self
                .list_names_once(
                    canonical_prefix,
                    after,
                    page_token.as_deref(),
                    request_limit,
                )
                .await?;
            for item in page.items {
                if item.name.len() > MAX_CANONICAL_OBJECT_KEY_BYTES
                    || !item.name.starts_with(canonical_prefix)
                    || canonical_object_id(&item.name).is_none()
                    || !canonical_generation(&item.generation)
                    || previous
                        .as_deref()
                        .is_some_and(|value| item.name.as_str() < value)
                {
                    return Err(GcsArchiveV3TransportError::Protocol);
                }
                if previous
                    .as_deref()
                    .is_some_and(|value| item.name.as_str() == value)
                {
                    // startOffset is inclusive. Only the first item of the
                    // first provider page may equal the public boundary.
                    if page_token.is_some()
                        || after.is_none()
                        || !names.is_empty()
                        || skipped_inclusive_boundary
                    {
                        return Err(GcsArchiveV3TransportError::Protocol);
                    }
                    skipped_inclusive_boundary = true;
                    continue;
                }
                page_bytes = page_bytes
                    .checked_add(item.name.len())
                    .ok_or(GcsArchiveV3TransportError::TooLarge)?;
                if page_bytes > MAX_ENUMERATION_PAGE_BYTES {
                    return Err(GcsArchiveV3TransportError::TooLarge);
                }
                previous = Some(item.name.clone());
                names.push(item.name);
                if names.len() >= limit {
                    return Ok(GcsArchiveV3Page { names });
                }
            }
            match page.next_page_token {
                None => return Ok(GcsArchiveV3Page { names }),
                Some(next) => {
                    if next.is_empty()
                        || next.len() > MAX_PAGE_TOKEN_BYTES
                        || !seen_tokens.insert(next.clone())
                    {
                        return Err(GcsArchiveV3TransportError::Protocol);
                    }
                    page_token = Some(next);
                }
            }
        }
        Err(GcsArchiveV3TransportError::TooLarge)
    }

    async fn delete_all_generations_exact(
        &self,
        canonical_key: &str,
    ) -> std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError> {
        if canonical_object_id(canonical_key).is_none() {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        let mut observed_any = false;
        for _ in 0..MAX_DELETE_PASSES {
            let generations = self.list_generations_exact(canonical_key).await?;
            if generations.is_empty() {
                if self
                    .has_soft_deleted_generation_exact(canonical_key)
                    .await?
                {
                    return Err(GcsArchiveV3TransportError::Protocol);
                }
                return Ok(if observed_any {
                    GcsArchiveV3DeleteResult::DeletedAllGenerations
                } else {
                    GcsArchiveV3DeleteResult::Absent
                });
            }
            observed_any = true;
            for generation in generations {
                self.delete_generation(canonical_key, &generation).await?;
            }
        }
        // New generations kept appearing while deleting. Do not report a
        // successful deletion when the exact inventory cannot be proven empty.
        Err(GcsArchiveV3TransportError::Protocol)
    }
}

#[derive(Deserialize)]
struct ObjectMetadata {
    generation: String,
}

#[derive(Deserialize)]
struct ListWire {
    #[serde(default)]
    items: Vec<ListItemWire>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct ListItemWire {
    name: String,
    generation: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimState {
    Reserved,
    Materialized,
}

struct ClaimWire {
    key: String,
    hash: String,
    state: ClaimState,
}

impl ClaimWire {
    fn new(key: &str, ciphertext_hash: [u8; 32], state: ClaimState) -> Self {
        Self {
            key: key.to_owned(),
            hash: hex_bytes(&ciphertext_hash),
            state,
        }
    }

    // Every field is canonical ASCII from validated archive paths / fixed hex,
    // so this exact JSON encoding has no escaping ambiguity.
    fn encode(&self) -> Vec<u8> {
        format!(
            "{{\"v\":1,\"key\":\"{}\",\"hash\":\"{}\",\"state\":\"{}\"}}",
            self.key,
            self.hash,
            match self.state {
                ClaimState::Reserved => "reserved",
                ClaimState::Materialized => "materialized",
            }
        )
        .into_bytes()
    }

    fn validate(&self) -> std::result::Result<(), GcsArchiveV3TransportError> {
        if self.key.is_empty()
            || self.key.len() > MAX_CANONICAL_OBJECT_KEY_BYTES
            || self.hash.len() != 64
            || !self.hash.bytes().all(is_lower_hex)
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ClaimWire {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawClaim {
            v: u8,
            key: String,
            hash: String,
            state: String,
        }
        let raw = RawClaim::deserialize(deserializer)?;
        let state = match raw.state.as_str() {
            "reserved" => ClaimState::Reserved,
            "materialized" => ClaimState::Materialized,
            _ => return Err(serde::de::Error::custom("invalid claim state")),
        };
        if raw.v != 1 {
            return Err(serde::de::Error::custom("invalid claim version"));
        }
        Ok(Self {
            key: raw.key,
            hash: raw.hash,
            state,
        })
    }
}

fn valid_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    let secure_or_loopback = match (url.scheme(), url.host_str()) {
        ("https", Some(_)) => true,
        ("http", Some("localhost")) => true,
        ("http", Some(host)) => host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        _ => false,
    };
    secure_or_loopback
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

fn valid_bucket_name(bucket: &str) -> bool {
    let length_ok = if bucket.contains('.') {
        bucket.len() <= 222
            && bucket
                .split('.')
                .all(|component| !component.is_empty() && component.len() <= 63)
    } else {
        bucket.len() <= 63
    };
    length_ok
        && bucket.len() >= 3
        && bucket.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && bucket
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && bucket.parse::<Ipv4Addr>().is_err()
        && !bucket.starts_with("goog")
        && !bucket.contains("google")
        && !bucket.contains("g00gle")
}

fn valid_bearer_token(token: &[u8]) -> bool {
    if token.is_empty() || token.len() > MAX_BEARER_TOKEN_BYTES {
        return false;
    }
    let mut padding = false;
    token.iter().all(|byte| {
        if *byte == b'=' {
            padding = true;
            true
        } else if padding {
            false
        } else {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        }
    })
}

fn canonical_url_component(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

async fn bounded_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, GcsArchiveV3TransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(GcsArchiveV3TransportError::TooLarge);
    }
    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GcsArchiveV3TransportError::Unavailable)?
    {
        let total = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(GcsArchiveV3TransportError::TooLarge)?;
        if total > max_bytes {
            return Err(GcsArchiveV3TransportError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn read_status(status: reqwest::StatusCode) -> GcsArchiveV3TransportError {
    if status == reqwest::StatusCode::PRECONDITION_FAILED {
        GcsArchiveV3TransportError::PreconditionFailed
    } else if status == reqwest::StatusCode::NOT_FOUND {
        GcsArchiveV3TransportError::NotFound
    } else if status.is_server_error()
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
    {
        GcsArchiveV3TransportError::Unavailable
    } else {
        GcsArchiveV3TransportError::Protocol
    }
}

fn canonical_generation(generation: &str) -> bool {
    !generation.is_empty()
        && generation.bytes().all(|byte| byte.is_ascii_digit())
        && generation
            .parse::<u64>()
            .is_ok_and(|value| value.to_string() == generation)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

impl fmt::Debug for GcpArchiveV3HttpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GcpArchiveV3HttpTransport(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    struct FixedToken;
    #[async_trait::async_trait]
    impl ArchiveV3BearerTokenProvider for FixedToken {
        async fn bearer_token(
            &self,
        ) -> std::result::Result<Zeroizing<String>, GcsArchiveV3TransportError> {
            Ok(Zeroizing::new("test-token".to_owned()))
        }
    }

    struct FixedDrainGate(bool);
    #[async_trait::async_trait]
    impl ArchiveV3SoftDeleteDrainGate for FixedDrainGate {
        async fn disabled_and_drained(
            &self,
            canonical_bucket: &str,
        ) -> std::result::Result<bool, GcsArchiveV3TransportError> {
            assert_eq!(canonical_bucket, "test-bucket");
            Ok(self.0)
        }
    }

    struct MockReply {
        status: &'static str,
        body: Vec<u8>,
        close_without_response: bool,
    }
    #[derive(Debug)]
    struct CapturedRequest {
        method: String,
        target: String,
        headers: String,
        body_len: usize,
    }
    struct MockServer {
        endpoint: String,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        task: JoinHandle<()>,
    }
    impl MockServer {
        async fn new(replies: Vec<MockReply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let task = tokio::spawn(async move {
                for reply in replies {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let request = read_request(&mut stream).await;
                    recorded.lock().unwrap().push(request);
                    if reply.close_without_response {
                        continue;
                    }
                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.write_all(&reply.body).await.unwrap();
                }
            });
            Self {
                endpoint,
                requests,
                task,
            }
        }

        async fn finish(self) -> Vec<CapturedRequest> {
            self.task.await.unwrap();
            Arc::try_unwrap(self.requests)
                .unwrap()
                .into_inner()
                .unwrap()
        }
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> CapturedRequest {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .or_else(|| {
                headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
            })
            .unwrap_or("0")
            .parse::<usize>()
            .unwrap();
        while bytes.len() - header_end < content_length {
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            bytes.extend_from_slice(&chunk[..read]);
        }
        let mut first = headers.lines().next().unwrap().split_whitespace();
        CapturedRequest {
            method: first.next().unwrap().to_owned(),
            target: first.next().unwrap().to_owned(),
            headers,
            body_len: content_length,
        }
    }

    fn reply(status: &'static str, body: &str) -> MockReply {
        MockReply {
            status,
            body: body.as_bytes().to_vec(),
            close_without_response: false,
        }
    }
    fn make_transport(server: &MockServer) -> GcpArchiveV3HttpTransport {
        make_transport_with_drain_gate(server, true)
    }
    fn make_transport_with_drain_gate(
        server: &MockServer,
        disabled_and_drained: bool,
    ) -> GcpArchiveV3HttpTransport {
        GcpArchiveV3HttpTransport::new_with_endpoint(
            &server.endpoint,
            "test-bucket".to_owned(),
            Arc::new(FixedToken),
            Arc::new(FixedDrainGate(disabled_and_drained)),
        )
        .unwrap()
    }
    fn archive_prefix() -> &'static str {
        "archive/v3/01010101010101010101010101010101/"
    }
    fn object_key() -> &'static str {
        "archive/v3/01010101010101010101010101010101/extents/02020202020202020202020202020202/7/03030303030303030303030303030303.extx"
    }

    fn enumerated_key(id: u128) -> String {
        format!(
            "archive/v3/01010101010101010101010101010101/extents/02020202020202020202020202020202/7/{id:032x}.extx"
        )
    }

    fn list_body(ids: &[u128], next_page_token: Option<&str>) -> String {
        let items = ids
            .iter()
            .map(|id| {
                format!(
                    "{{\"name\":\"{}\",\"generation\":\"{}\"}}",
                    enumerated_key(*id),
                    id + 1
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let token = next_page_token
            .map(|token| format!(",\"nextPageToken\":\"{token}\""))
            .unwrap_or_default();
        format!("{{\"items\":[{items}]{token}}}")
    }

    #[tokio::test]
    async fn canonical_url_and_bearer_shape_are_exact() {
        assert_eq!(canonical_url_component("a/b ?%"), "a%2Fb%20%3F%25");
        let server = MockServer::new(vec![reply("200 OK", "abc")]).await;
        let transport = make_transport(&server);
        assert_eq!(
            transport.read_exact(object_key(), 3).await.unwrap(),
            Some(b"abc".to_vec())
        );
        let requests = server.finish().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(
            requests[0].target,
            format!(
                "/download/storage/v1/b/test-bucket/o/{}?alt=media",
                canonical_url_component(object_key())
            )
        );
        assert!(
            requests[0]
                .headers
                .contains("authorization: Bearer test-token")
                || requests[0]
                    .headers
                    .contains("Authorization: Bearer test-token")
        );
    }

    #[tokio::test]
    async fn bounded_read_and_mutation_lost_outcome_are_classified() {
        let server = MockServer::new(vec![reply("200 OK", "abcd")]).await;
        let transport = make_transport(&server);
        assert_eq!(
            transport.read_exact(object_key(), 3).await,
            Err(GcsArchiveV3TransportError::TooLarge)
        );
        let _ = server.finish().await;

        let server = MockServer::new(vec![MockReply {
            status: "",
            body: Vec::new(),
            close_without_response: true,
        }])
        .await;
        let transport = make_transport(&server);
        assert_eq!(
            transport.create_if_absent(object_key(), b"bytes").await,
            Err(GcsArchiveV3TransportError::OutcomeUnknown)
        );
        let requests = server.finish().await;
        assert_eq!(requests[0].method, "POST");
        assert!(requests[0].target.contains("ifGenerationMatch=0"));
        assert_eq!(requests[0].body_len, 5);

        let server = MockServer::new(vec![reply("408 Request Timeout", "")]).await;
        let transport = make_transport(&server);
        assert_eq!(
            transport.create_if_absent(object_key(), b"bytes").await,
            Err(GcsArchiveV3TransportError::OutcomeUnknown)
        );
        let _ = server.finish().await;
    }

    #[tokio::test]
    async fn claim_reserve_and_one_way_materialize_use_conditional_cas() {
        let server = MockServer::new(vec![
            reply("200 OK", "{}"),
            reply("200 OK", "{\"generation\":\"9\"}"),
            reply(
                "200 OK",
                &String::from_utf8(
                    ClaimWire::new(object_key(), [7; 32], ClaimState::Reserved).encode(),
                )
                .unwrap(),
            ),
            reply("200 OK", "{}"),
        ])
        .await;
        let transport = make_transport(&server);
        let id = ObjectId::from_bytes([3; 16]);
        assert_eq!(
            transport
                .claim_object_id(archive_prefix(), id, object_key(), [7; 32])
                .await
                .unwrap(),
            GcsArchiveV3ClaimResult::Reserved
        );
        transport
            .mark_object_id_materialized(archive_prefix(), id, object_key(), [7; 32])
            .await
            .unwrap();
        let requests = server.finish().await;
        assert!(requests[0].target.contains("archive%2Fv3-claims%2F"));
        assert!(requests[0].target.contains("ifGenerationMatch=0"));
        assert!(requests[3].target.contains("ifGenerationMatch=9"));
    }

    #[tokio::test]
    async fn listing_consumes_short_provider_pages_but_returns_only_key_cursor_data() {
        let server = MockServer::new(vec![
            reply("200 OK", &list_body(&[0, 1], Some("provider-secret"))),
            reply("200 OK", &list_body(&[2, 3], None)),
        ])
        .await;
        let transport = make_transport(&server);
        let after = enumerated_key(0);
        let page = transport
            .list_after(archive_prefix(), Some(&after), 3)
            .await
            .unwrap();
        assert_eq!(
            page.names,
            vec![enumerated_key(1), enumerated_key(2), enumerated_key(3)]
        );
        let requests = server.finish().await;
        assert_eq!(requests.len(), 2);
        assert!(requests[0].target.contains("maxResults=4"));
        assert!(!requests[0].target.contains("pageToken="));
        assert!(requests[1].target.contains("maxResults=2"));
        assert!(requests[1].target.contains("pageToken=provider-secret"));
        assert!(requests
            .iter()
            .all(|request| request.target.contains("startOffset=")));
    }

    #[test]
    fn constructor_rejects_noncanonical_bucket_and_non_tls_remote_endpoint() {
        let tokens: Arc<dyn ArchiveV3BearerTokenProvider> = Arc::new(FixedToken);
        assert!(GcpArchiveV3HttpTransport::new_with_endpoint(
            "https://storage.googleapis.com",
            "bucket name".to_owned(),
            Arc::clone(&tokens),
            Arc::new(FixedDrainGate(true)),
        )
        .is_err());
        assert!(GcpArchiveV3HttpTransport::new_with_endpoint(
            "http://storage.googleapis.com",
            "test-bucket".to_owned(),
            tokens,
            Arc::new(FixedDrainGate(true)),
        )
        .is_err());
        assert!(valid_bucket_name("test-bucket"));
        assert!(!valid_bucket_name("192.168.1.1"));
        assert!(!valid_bucket_name("goog-bucket"));
        assert!(valid_bearer_token(b"abc.DEF_123-~+/="));
        assert!(!valid_bearer_token(b"abc\r\ndef"));
    }

    #[tokio::test]
    async fn exact_version_delete_rechecks_residue_and_rejects_repeated_cursor() {
        let server = MockServer::new(vec![
            reply(
                "200 OK",
                &format!(
                    "{{\"items\":[{{\"name\":\"{}\",\"generation\":\"1\"}},{{\"name\":\"{}\",\"generation\":\"2\"}}]}}",
                    object_key(),
                    object_key()
                ),
            ),
            reply("204 No Content", ""),
            reply("204 No Content", ""),
            reply("200 OK", "{}"),
            reply("400 Bad Request", "{}"),
        ])
        .await;
        let transport = make_transport(&server);
        assert_eq!(
            transport
                .delete_all_generations_exact(object_key())
                .await
                .unwrap(),
            GcsArchiveV3DeleteResult::DeletedAllGenerations
        );
        let requests = server.finish().await;
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "DELETE")
                .count(),
            2
        );
        assert!(requests
            .iter()
            .all(|request| !request.target.contains("pageToken=")));
        assert!(requests.last().unwrap().target.contains("softDeleted=true"));

        let server =
            MockServer::new(vec![reply("200 OK", "{}"), reply("400 Bad Request", "{}")]).await;
        let transport = make_transport_with_drain_gate(&server, false);
        assert_eq!(
            transport.delete_all_generations_exact(object_key()).await,
            Err(GcsArchiveV3TransportError::Protocol),
            "a disabled policy is not evidence that historical residue drained"
        );
        let _ = server.finish().await;

        let server = MockServer::new(vec![
            reply("200 OK", "{}"),
            reply(
                "200 OK",
                &format!(
                    "{{\"items\":[{{\"name\":\"{}\",\"generation\":\"3\"}}]}}",
                    object_key()
                ),
            ),
        ])
        .await;
        let transport = make_transport(&server);
        assert_eq!(
            transport.delete_all_generations_exact(object_key()).await,
            Err(GcsArchiveV3TransportError::Protocol),
            "soft-deleted residue cannot be reported as physical deletion"
        );
        let _ = server.finish().await;

        let server = MockServer::new(vec![
            reply("200 OK", "{\"items\":[],\"nextPageToken\":\"loop\"}"),
            reply("200 OK", "{\"items\":[],\"nextPageToken\":\"loop\"}"),
        ])
        .await;
        let transport = make_transport(&server);
        assert_eq!(
            transport.delete_all_generations_exact(object_key()).await,
            Err(GcsArchiveV3TransportError::Protocol)
        );
        let requests = server.finish().await;
        assert!(requests[1].target.contains("pageToken=loop"));
    }
}
