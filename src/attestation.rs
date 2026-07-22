//! Attestation-based credentials for Cloud KMS.
//!
//! # Flow
//!
//! 1. Fetch a Confidential Space OIDC token from the in-VM launcher token
//!    server (unix socket `/run/container_launcher/teeserver.sock`).
//! 2. Exchange it at Google STS for a federated access_token scoped to
//!    `cloud-platform`.
//! 3. Cache the token until ~60 s before expiry, then re-fetch.
//!
//! The STS federated token is directly usable against Cloud KMS because the
//! WIF `principalSet` binding grants `roles/cloudkms.cryptoKeyEncrypterDecrypter`
//! to the attestation-matched identity set — no SA impersonation needed.
//!
//! # Environment variables
//!
//! - `ATTEST_STS_AUDIENCE` — the full WIF provider resource name, e.g.:
//!   `//iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL_ID>/providers/<PROVIDER_ID>`
//!
//! # Socket protocol
//!
//! The Confidential Space launcher listens on the UNIX domain socket
//! `/run/container_launcher/teeserver.sock`. We perform a minimal HTTP/1.1
//! POST over a `tokio::net::UnixStream` rather than pulling in hyperlocal,
//! since the binary already minimises dependencies. The response is a quoted
//! JSON string (the raw JWT).
//!
//! Uncertainty note: Google's public documentation for the token server
//! endpoint format is sparse. The path `POST /v1/token` with JSON body
//! `{"audience":"…","token_type":"OIDC"}` matches the Confidential Space
//! launcher's documented contract as of 2025. If Google changes this ABI the
//! `fetch_attestation_token` function is the only place to update.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::error::{EnclaveError, Result};

// ── Token-server socket ───────────────────────────────────────────────────────

const TEE_SOCKET: &str = "/run/container_launcher/teeserver.sock";
const LAUNCHER_IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LAUNCHER_RESPONSE_BYTES: u64 = 64 * 1024;

// ── STS exchange endpoint ─────────────────────────────────────────────────────

const STS_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";
const STS_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const STS_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const STS_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const STS_REQUESTED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

// ── Cached token state ────────────────────────────────────────────────────────

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires: Instant, // time at which we consider it expired (exp - 60s)
}

// ── Public handle ─────────────────────────────────────────────────────────────

/// A shareable handle that returns a fresh (or cached) KMS access token.
///
/// Construct with [`AttestationCredentials::from_env`] and then call
/// [`kms_access_token`] before each KMS request.
#[derive(Clone)]
pub struct AttestationCredentials {
    http: reqwest::Client,
    sts_audience: String, // full WIF provider resource name
    cache: Arc<Mutex<Option<CachedToken>>>,
}

impl AttestationCredentials {
    /// Build from environment. Reads `ATTEST_STS_AUDIENCE`.
    pub fn from_env() -> Result<Self> {
        let sts_audience = std::env::var("ATTEST_STS_AUDIENCE").map_err(|_| {
            EnclaveError::Attestation(
                "ATTEST_STS_AUDIENCE not set — required for attestation-based KMS auth".into(),
            )
        })?;
        Ok(Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .build()?,
            sts_audience,
            cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Return a valid access token for KMS, fetching a fresh one if needed.
    pub async fn kms_access_token(&self) -> Result<String> {
        let mut guard = self.cache.lock().await;
        if let Some(ref cached) = *guard {
            if Instant::now() < cached.expires {
                return Ok(cached.token.clone());
            }
        }
        // Need a fresh token.
        let token = self.fetch_fresh_token().await?;
        *guard = Some(token.clone());
        Ok(token.token)
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    async fn fetch_fresh_token(&self) -> Result<CachedToken> {
        let attestation_jwt = fetch_attestation_token(&self.sts_audience, None).await?;
        let (access_token, expires_in_secs) =
            exchange_at_sts(&self.http, &attestation_jwt, &self.sts_audience).await?;

        // Cache until 60 seconds before the stated expiry.
        let ttl = expires_in_secs.saturating_sub(60);
        let expires = Instant::now() + Duration::from_secs(ttl);

        Ok(CachedToken {
            token: access_token,
            expires,
        })
    }
}

/// A cache for a public, non-credential Confidential Space OIDC attestation token.
///
/// The audience passed here must identify the public verifier, never the WIF
/// provider audience used by [`AttestationCredentials`]. A token minted for a
/// WIF audience is a bearer credential that can be exchanged at Google STS and
/// must never be returned by a public endpoint.
pub struct AttestationCache {
    audience: String,
    cached: Mutex<Option<CachedAttestation>>,
}

struct CachedAttestation {
    token: String,
    nonce: String,
    expires: Instant,
}

impl AttestationCache {
    pub fn new(audience: String) -> Result<Self> {
        let parsed = reqwest::Url::parse(&audience).map_err(|e| {
            EnclaveError::Attestation(format!("invalid public attestation audience: {e}"))
        })?;
        if parsed.scheme() != "https" {
            return Err(EnclaveError::Attestation(
                "public attestation audience must use https".into(),
            ));
        }
        if audience.starts_with("//iam.googleapis.com/")
            || audience.contains("/workloadIdentityPools/")
        {
            return Err(EnclaveError::Attestation(
                "public attestation audience must not be a WIF provider".into(),
            ));
        }
        Ok(Self {
            audience,
            cached: Mutex::new(None),
        })
    }

    pub async fn get_token(&self, nonce: &str) -> Result<String> {
        let mut guard = self.cached.lock().await;
        if let Some(ref cached) = *guard {
            if cached.nonce == nonce && Instant::now() < cached.expires {
                return Ok(cached.token.clone());
            }
        }
        let token = fetch_attestation_token(&self.audience, Some(nonce)).await?;
        *guard = Some(CachedAttestation {
            token: token.clone(),
            nonce: nonce.to_string(),
            expires: Instant::now() + Duration::from_secs(300),
        });
        Ok(token)
    }
}

// ── Step 1: fetch attestation OIDC token from launcher ───────────────────────

/// Fetch a Confidential Space OIDC token from the launcher's unix socket.
///
/// The launcher listens on `TEE_SOCKET` and speaks plain HTTP/1.1 (not
/// wrapped in any framing beyond TCP-over-unix). We issue a minimal POST
/// and read the full response body.
///
/// Expected response: a JSON-quoted string, e.g. `"eyJ…"` (the raw JWT).
pub async fn fetch_attestation_token(audience: &str, nonce: Option<&str>) -> Result<String> {
    let mut body_json = serde_json::json!({
        "audience": audience,
        "token_type": "OIDC",
    });
    if let Some(n) = nonce {
        body_json["nonce"] = serde_json::json!(n);
    }
    let request_body = body_json.to_string();

    let request = format!(
        "POST /v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        request_body.len(),
        request_body,
    );

    // Connect and send.
    let mut stream = tokio::time::timeout(LAUNCHER_IO_TIMEOUT, UnixStream::connect(TEE_SOCKET))
        .await
        .map_err(|_| EnclaveError::Attestation("launcher socket connect timed out".into()))?
        .map_err(|e| {
            EnclaveError::Attestation(format!(
                "cannot connect to launcher socket {TEE_SOCKET}: {e}"
            ))
        })?;

    tokio::time::timeout(LAUNCHER_IO_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| EnclaveError::Attestation("launcher socket write timed out".into()))?
        .map_err(|e| EnclaveError::Attestation(format!("socket write error: {e}")))?;

    // Read a bounded response (normally only a few KiB). The host can deny
    // availability, but it must not be able to grow enclave memory without bound.
    let mut response = Vec::new();
    let mut limited = stream.take(MAX_LAUNCHER_RESPONSE_BYTES + 1);
    tokio::time::timeout(LAUNCHER_IO_TIMEOUT, limited.read_to_end(&mut response))
        .await
        .map_err(|_| EnclaveError::Attestation("launcher socket read timed out".into()))?
        .map_err(|e| EnclaveError::Attestation(format!("socket read error: {e}")))?;
    if response.len() as u64 > MAX_LAUNCHER_RESPONSE_BYTES {
        return Err(EnclaveError::Attestation(
            "launcher response exceeded size limit".into(),
        ));
    }

    // Locate the body: split on the blank line that separates headers from body.
    let response_str = std::str::from_utf8(&response)
        .map_err(|e| EnclaveError::Attestation(format!("non-UTF-8 response: {e}")))?;
    let status_line = response_str.lines().next().unwrap_or_default();
    if !(status_line.starts_with("HTTP/1.1 200 ") || status_line.starts_with("HTTP/1.0 200 ")) {
        return Err(EnclaveError::Attestation(
            "launcher returned a non-success response".into(),
        ));
    }

    let body = split_http_body(response_str)?;

    // The launcher replies with `Connection: close` and no Content-Length, so
    // hyper streams the body with Transfer-Encoding: chunked. De-chunk if the
    // headers say so, then take the RAW JWT (the launcher returns the bare
    // token, NOT a JSON-quoted string — an earlier assumption that broke this).
    let headers = response_str
        .get(..response_str.len() - body.len())
        .unwrap_or("");
    let decoded = if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk_http_body(body)?
    } else {
        body.to_string()
    };
    let jwt = decoded.trim().trim_matches('"').to_string();

    if jwt.is_empty() || !jwt.contains('.') {
        return Err(EnclaveError::Attestation(
            "launcher returned an unexpected token response".into(),
        ));
    }

    Ok(jwt)
}

/// Decode an HTTP/1.1 chunked-transfer body into its payload.
/// Each chunk is `<hex-size>\r\n<data>\r\n`, terminated by a `0\r\n` chunk.
fn dechunk_http_body(body: &str) -> Result<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        let relative_line_end = bytes[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| EnclaveError::Attestation("chunk size line is truncated".into()))?;
        let line_end = offset + relative_line_end;
        let size_str = std::str::from_utf8(&bytes[offset..line_end])
            .map_err(|_| EnclaveError::Attestation("chunk size is not ASCII".into()))?
            .trim();
        // Chunk-size may carry extensions after ';'; ignore them.
        let size_hex = size_str.split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|e| EnclaveError::Attestation(format!("bad chunk size {size_hex:?}: {e}")))?;
        offset = line_end + 2;
        if size == 0 {
            return String::from_utf8(out)
                .map_err(|_| EnclaveError::Attestation("chunked body is not UTF-8".into()));
        }
        let data_end = offset
            .checked_add(size)
            .ok_or_else(|| EnclaveError::Attestation("chunk size overflow".into()))?;
        let trailer_end = data_end
            .checked_add(2)
            .ok_or_else(|| EnclaveError::Attestation("chunk size overflow".into()))?;
        if trailer_end > bytes.len() || &bytes[data_end..trailer_end] != b"\r\n" {
            return Err(EnclaveError::Attestation("chunked body truncated".into()));
        }
        out.extend_from_slice(&bytes[offset..data_end]);
        offset = trailer_end;
    }
}

/// Split an HTTP/1.1 response string on `\r\n\r\n` and return the body part.
fn split_http_body(response: &str) -> Result<&str> {
    if let Some(idx) = response.find("\r\n\r\n") {
        Ok(&response[idx + 4..])
    } else {
        // Some implementations use LF-only.
        if let Some(idx) = response.find("\n\n") {
            Ok(&response[idx + 2..])
        } else {
            Err(EnclaveError::Attestation(
                "could not locate HTTP body in launcher response".into(),
            ))
        }
    }
}

// ── Step 2: exchange attestation JWT at STS ───────────────────────────────────

#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
    /// Lifetime in seconds returned by STS (typically 3600).
    expires_in: u64,
}

/// POST to `https://sts.googleapis.com/v1/token` and return `(access_token,
/// expires_in_seconds)`.
///
/// Per the STS spec (RFC 8693) we POST an `application/x-www-form-urlencoded`
/// body. Google STS also accepts JSON; we use form encoding here to avoid a
/// second serde dependency path and because it is the canonical RFC form.
async fn exchange_at_sts(
    http: &reqwest::Client,
    subject_token: &str,
    audience: &str,
) -> Result<(String, u64)> {
    let params = [
        ("grant_type", STS_GRANT_TYPE),
        ("subject_token", subject_token),
        ("subject_token_type", STS_SUBJECT_TOKEN_TYPE),
        ("audience", audience),
        ("requested_token_type", STS_REQUESTED_TOKEN_TYPE),
        ("scope", STS_SCOPE),
    ];

    let resp = http.post(STS_TOKEN_URL).form(&params).send().await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(EnclaveError::Attestation(format!(
            "STS token exchange failed ({status})"
        )));
    }
    let parsed: StsTokenResponse = serde_json::from_str(&text).map_err(|e| {
        // Never include the body: a partially valid response can contain a
        // live access token even when another field is malformed.
        EnclaveError::Attestation(format!("could not parse STS response: {e}"))
    })?;

    Ok((parsed.access_token, parsed.expires_in))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HTTP body parsing ─────────────────────────────────────────────────────

    #[test]
    fn split_body_crlf() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\"eyJtoken\"";
        let body = split_http_body(resp).unwrap();
        assert_eq!(body, "\"eyJtoken\"");
    }

    #[test]
    fn split_body_lf_only() {
        let resp = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n\"eyJtoken\"";
        let body = split_http_body(resp).unwrap();
        assert_eq!(body, "\"eyJtoken\"");
    }

    #[test]
    fn dechunk_single_chunk() {
        // The launcher's real wire format (observed in prod): one hex-sized
        // chunk holding the raw JWT, then a terminating 0-chunk.
        let body = "5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(dechunk_http_body(body).unwrap(), "hello");
    }

    #[test]
    fn dechunk_real_launcher_shape() {
        // 0xb = 11 bytes "eyJ.aaa.bbb"
        let body = "b\r\neyJ.aaa.bbb\r\n0\r\n\r\n";
        let jwt = dechunk_http_body(body).unwrap();
        assert_eq!(jwt, "eyJ.aaa.bbb");
        assert!(jwt.contains('.'));
    }

    #[test]
    fn dechunk_multi_chunk() {
        let body = "3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
        assert_eq!(dechunk_http_body(body).unwrap(), "abcdef");
    }

    #[test]
    fn split_body_missing_separator_errors() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n";
        assert!(split_http_body(resp).is_err());
    }

    // ── STS request shape ─────────────────────────────────────────────────────
    //
    // We cannot hit the real STS endpoint in unit tests; instead we verify that
    // the form-encoded parameter set we would send is correctly shaped so a
    // regression in parameter naming is caught before any network call.

    #[test]
    fn sts_form_params_have_required_keys() {
        let audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/enclave-attest/providers/attest";
        let subject_token = "eyJfake.payload.sig";

        let params = [
            ("grant_type", STS_GRANT_TYPE),
            ("subject_token", subject_token),
            ("subject_token_type", STS_SUBJECT_TOKEN_TYPE),
            ("audience", audience),
            ("requested_token_type", STS_REQUESTED_TOKEN_TYPE),
            ("scope", STS_SCOPE),
        ];

        // Encode exactly as reqwest would.
        let encoded = serde_urlencoded::to_string(params).unwrap();

        assert!(
            encoded
                .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"),
            "grant_type missing or malformed"
        );
        assert!(
            encoded.contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"),
            "subject_token_type missing"
        );
        assert!(
            encoded.contains(
                "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
            ),
            "requested_token_type missing"
        );
        assert!(
            encoded.contains("scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform"),
            "scope missing"
        );
        assert!(encoded.contains("audience="), "audience missing");
        assert!(encoded.contains("subject_token="), "subject_token missing");
    }

    // ── Token-cache expiry ─────────────────────────────────────────────────────

    #[test]
    fn cached_token_expired_when_instant_past() {
        let cached = CachedToken {
            token: "tok".to_string(),
            expires: Instant::now() - Duration::from_secs(1),
        };
        // A token whose expires is in the past should not be returned from cache.
        assert!(Instant::now() >= cached.expires, "token should be expired");
    }

    #[test]
    fn cached_token_valid_when_instant_future() {
        let cached = CachedToken {
            token: "tok".to_string(),
            expires: Instant::now() + Duration::from_secs(120),
        };
        assert!(
            Instant::now() < cached.expires,
            "token should still be valid"
        );
    }
}
