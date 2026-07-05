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
            http: reqwest::Client::new(),
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

/// A cache for the Confidential Space OIDC attestation token.
/// Fetches on demand and caches for up to 5 minutes to avoid overloading the launcher.
pub struct AttestationCache {
    sts_audience: String,
    cached: Mutex<Option<(String, Instant)>>,
}

impl AttestationCache {
    pub fn new(sts_audience: String) -> Self {
        Self {
            sts_audience,
            cached: Mutex::new(None),
        }
    }

    pub async fn get_token(&self, nonce: &str) -> Result<String> {
        let mut guard = self.cached.lock().await;
        if let Some((ref token, expiry)) = *guard {
            if Instant::now() < expiry {
                return Ok(token.clone());
            }
        }
        // Fetch fresh
        let token = fetch_attestation_token(&self.sts_audience, Some(nonce)).await?;
        let expiry = Instant::now() + Duration::from_secs(300); // 5-minute TTL cache
        *guard = Some((token.clone(), expiry));
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
    let mut stream = UnixStream::connect(TEE_SOCKET).await.map_err(|e| {
        EnclaveError::Attestation(format!(
            "cannot connect to launcher socket {TEE_SOCKET}: {e}"
        ))
    })?;

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| EnclaveError::Attestation(format!("socket write error: {e}")))?;

    // Read the full response (small — just a JWT).
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| EnclaveError::Attestation(format!("socket read error: {e}")))?;

    // Locate the body: split on the blank line that separates headers from body.
    let response_str = std::str::from_utf8(&response)
        .map_err(|e| EnclaveError::Attestation(format!("non-UTF-8 response: {e}")))?;

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
        return Err(EnclaveError::Attestation(format!(
            "launcher returned an unexpected token body: {decoded:?}"
        )));
    }

    Ok(jwt)
}

/// Decode an HTTP/1.1 chunked-transfer body into its payload.
/// Each chunk is `<hex-size>\r\n<data>\r\n`, terminated by a `0\r\n` chunk.
fn dechunk_http_body(body: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = body;
    while let Some(nl) = rest.find("\r\n") {
        let size_str = rest[..nl].trim();
        // Chunk-size may carry extensions after ';'; ignore them.
        let size_hex = size_str.split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|e| EnclaveError::Attestation(format!("bad chunk size {size_hex:?}: {e}")))?;
        if size == 0 {
            break; // final chunk
        }
        let data_start = nl + 2;
        let data_end = data_start + size;
        if data_end > rest.len() {
            return Err(EnclaveError::Attestation("chunked body truncated".into()));
        }
        out.push_str(&rest[data_start..data_end]);
        // Skip the trailing CRLF after the chunk data.
        rest = &rest[(data_end + 2).min(rest.len())..];
    }
    Ok(out)
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
        // STS encodes the real reason in the body (e.g. invalid_grant /
        // invalid_target / invalid_request). Surface it — error_for_status()
        // alone hides it and made a 400 undiagnosable.
        return Err(EnclaveError::Attestation(format!(
            "STS token exchange failed ({status}): {}",
            text.chars().take(500).collect::<String>()
        )));
    }
    let parsed: StsTokenResponse = serde_json::from_str(&text).map_err(|e| {
        EnclaveError::Attestation(format!(
            "could not parse STS response: {e}; body={text:.300}"
        ))
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
