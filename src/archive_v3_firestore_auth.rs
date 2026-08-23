#![allow(
    dead_code,
    reason = "active signed-runtime Firestore witness bearer retains test-only constructors"
)]

//! Dedicated Confidential Space bearer credentials for Firestore.
//!
//! This module is intentionally separate from both KMS
//! [`crate::attestation::AttestationCredentials`] and public attestation. It
//! has no environment constructor, metadata-server fallback, service-account
//! impersonation, KMS cache, Store/VFS/route connection, or caller-selected
//! authority. The signed runtime mints a no-nonce launcher OIDC token only for the exact dedicated
//! [`FirestoreWitnessAudience`], then exchanges it at the fixed Google STS
//! endpoint for a short-lived Firestore bearer token.

use crate::{
    archive_v3_firestore_witness::{
        FirestoreWitnessAudience, FirestoreWitnessBearerToken, FirestoreWitnessBearerTokenProvider,
        FirestoreWitnessTransportError,
    },
    attestation::fetch_internal_wif_attestation_token,
};
use serde::Deserialize;
use serde_json::value::RawValue;
#[cfg(test)]
use std::net::IpAddr;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const STS_TOKEN_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";
const STS_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const STS_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const STS_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const STS_REQUESTED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const STS_ISSUED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const MAX_LAUNCHER_JWT_BYTES: usize = 64 * 1024;
const MAX_STS_RESPONSE_BYTES: usize = 32 * 1024;
// Google currently documents a 12 KiB maximum for a successful STS access
// token. Keep a smaller bound than the generic Firestore bearer wrapper.
const MAX_STS_ACCESS_TOKEN_BYTES: usize = 12 * 1024;
const MAX_STS_EXPIRES_IN_SECONDS: u64 = 60 * 60;
const CACHE_EARLY_EXPIRY: Duration = Duration::from_secs(60);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Owns an encoded STS form for as long as any reqwest/Bytes body clone exists.
/// Dropping the final clone drops this owner and zeroizes its backing buffer.
struct ZeroizingStsBody(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for ZeroizingStsBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Firestore-only bearer source. It can only return a token for the one
/// audience it owns, and its single async mutex coalesces refreshes.
pub(crate) struct FirestoreWitnessAttestationBearer {
    audience: FirestoreWitnessAudience,
    launcher: Arc<dyn FirestoreWitnessLauncherOidc>,
    sts: Arc<dyn FirestoreWitnessStsExchange>,
    cache: Mutex<Option<CachedBearerToken>>,
}

impl FirestoreWitnessAttestationBearer {
    /// Construct the production-only, fixed-endpoint path. This does no I/O.
    pub(crate) fn new(
        audience: FirestoreWitnessAudience,
    ) -> std::result::Result<Self, FirestoreWitnessTransportError> {
        Ok(Self {
            audience,
            launcher: Arc::new(ConfidentialSpaceFirestoreWitnessLauncher),
            sts: Arc::new(GcpFirestoreWitnessSts::new()?),
            cache: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn with_test_boundaries(
        audience: FirestoreWitnessAudience,
        launcher: Arc<dyn FirestoreWitnessLauncherOidc>,
        sts: Arc<dyn FirestoreWitnessStsExchange>,
    ) -> Self {
        Self {
            audience,
            launcher,
            sts,
            cache: Mutex::new(None),
        }
    }

    async fn fresh_token(
        &self,
    ) -> std::result::Result<FirestoreWitnessStsToken, FirestoreWitnessTransportError> {
        // The typed boundary permits no nonce argument. Production reaches the
        // launcher only through `fetch_internal_wif_attestation_token`, whose
        // sole launcher request form omits nonces.
        let subject_token = self.launcher.oidc_token(&self.audience).await?;
        self.sts.exchange(&self.audience, &subject_token).await
    }
}

#[async_trait::async_trait]
impl FirestoreWitnessBearerTokenProvider for FirestoreWitnessAttestationBearer {
    async fn bearer_token(
        &self,
        expected_audience: &str,
    ) -> std::result::Result<FirestoreWitnessBearerToken, FirestoreWitnessTransportError> {
        // Do not permit a caller to use this credential source as a generic
        // WIF-token minting oracle, even for another syntactically valid
        // archive-witness provider resource.
        if expected_audience != self.audience.as_str() {
            return Err(FirestoreWitnessTransportError::Protocol);
        }

        // Holding this mutex through refresh deliberately coalesces concurrent
        // callers. The network path is bounded by finite launcher and STS
        // timeouts, so a failed refresh cannot retain it indefinitely.
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            if Instant::now() < cached.refresh_at {
                return Ok(cached.token.duplicate());
            }
        }
        // Remove expired material before any await. A failed or cancelled
        // refresh therefore drops the old zeroizing token immediately and
        // leaves the cache empty.
        cache.take();
        let fresh = self.fresh_token().await?;
        // Revalidate here as well as in the concrete parser. This keeps every
        // cache/Instant operation bounded if a later exchange implementation
        // or a test seam violates the response contract.
        let refresh_at = token_refresh_deadline(fresh.expires_in)?;
        let token = fresh.token;
        *cache = Some(CachedBearerToken {
            token: token.duplicate(),
            refresh_at,
        });
        Ok(token)
    }
}

impl fmt::Debug for FirestoreWitnessAttestationBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreWitnessAttestationBearer(<redacted>)")
    }
}

struct CachedBearerToken {
    token: FirestoreWitnessBearerToken,
    refresh_at: Instant,
}

/// The isolated launcher boundary accepts only the already-validated dedicated
/// audience. It intentionally has no nonce parameter, no public-token path,
/// and no relationship to the KMS credential cache.
#[async_trait::async_trait]
trait FirestoreWitnessLauncherOidc: Send + Sync {
    async fn oidc_token(
        &self,
        audience: &FirestoreWitnessAudience,
    ) -> std::result::Result<Zeroizing<String>, FirestoreWitnessTransportError>;
}

struct ConfidentialSpaceFirestoreWitnessLauncher;

#[async_trait::async_trait]
impl FirestoreWitnessLauncherOidc for ConfidentialSpaceFirestoreWitnessLauncher {
    async fn oidc_token(
        &self,
        audience: &FirestoreWitnessAudience,
    ) -> std::result::Result<Zeroizing<String>, FirestoreWitnessTransportError> {
        let token = fetch_internal_wif_attestation_token(audience)
            .await
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)?;
        if !valid_launcher_jwt(&token) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        Ok(token)
    }
}

/// A parsed STS result is deliberately opaque: its bearer token is zeroized on
/// drop and it has no `Debug` implementation.
struct FirestoreWitnessStsToken {
    token: FirestoreWitnessBearerToken,
    expires_in: u64,
}

#[async_trait::async_trait]
trait FirestoreWitnessStsExchange: Send + Sync {
    async fn exchange(
        &self,
        audience: &FirestoreWitnessAudience,
        subject_token: &str,
    ) -> std::result::Result<FirestoreWitnessStsToken, FirestoreWitnessTransportError>;
}

/// Fixed, rustls-only, no-proxy/no-redirect STS client. The only production
/// constructor fixes the endpoint to Google's HTTPS STS token endpoint.
struct GcpFirestoreWitnessSts {
    http: reqwest::Client,
    endpoint: reqwest::Url,
}

impl GcpFirestoreWitnessSts {
    fn new() -> std::result::Result<Self, FirestoreWitnessTransportError> {
        Self::from_fixed_endpoint(STS_TOKEN_ENDPOINT)
    }

    fn from_fixed_endpoint(
        endpoint: &str,
    ) -> std::result::Result<Self, FirestoreWitnessTransportError> {
        let parsed =
            reqwest::Url::parse(endpoint).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
        if endpoint != STS_TOKEN_ENDPOINT || !is_exact_sts_endpoint(&parsed) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)?;
        Ok(Self {
            http,
            endpoint: parsed,
        })
    }

    #[cfg(test)]
    fn with_test_origin(origin: &str) -> std::result::Result<Self, FirestoreWitnessTransportError> {
        let parsed =
            reqwest::Url::parse(origin).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
        if !is_loopback_test_origin(&parsed) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let endpoint = parsed
            .join("/v1/token")
            .map_err(|_| FirestoreWitnessTransportError::Protocol)?;
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)?;
        Ok(Self { http, endpoint })
    }

    fn request(
        &self,
        audience: &FirestoreWitnessAudience,
        subject_token: &str,
    ) -> std::result::Result<reqwest::Request, FirestoreWitnessTransportError> {
        if !valid_launcher_jwt(subject_token) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let encoded = sts_form_body(audience, subject_token);
        let body = reqwest::Body::from(bytes::Bytes::from_owner(ZeroizingStsBody(encoded)));
        let request = self
            .http
            .post(self.endpoint.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .build()
            .map_err(|_| FirestoreWitnessTransportError::Protocol)?;
        // The client has no default auth header; retain this check as a
        // defense against a future client-builder change.
        if request
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION)
        {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        Ok(request)
    }
}

#[async_trait::async_trait]
impl FirestoreWitnessStsExchange for GcpFirestoreWitnessSts {
    async fn exchange(
        &self,
        audience: &FirestoreWitnessAudience,
        subject_token: &str,
    ) -> std::result::Result<FirestoreWitnessStsToken, FirestoreWitnessTransportError> {
        let request = self.request(audience, subject_token)?;
        let response = self
            .http
            .execute(request)
            .await
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)?;
        if !response.status().is_success() {
            // Never consume or report an STS error body: it is provider input
            // and could itself contain credential material.
            return Err(FirestoreWitnessTransportError::Unavailable);
        }
        parse_sts_response(&bounded_response(response, MAX_STS_RESPONSE_BYTES).await?)
    }
}

fn is_exact_sts_endpoint(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("sts.googleapis.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/v1/token"
        && url.query().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
fn is_loopback_test_origin(url: &reqwest::Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback())
        && url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && (url.path().is_empty() || url.path() == "/")
        && url.query().is_none()
        && url.fragment().is_none()
}

fn valid_launcher_jwt(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_LAUNCHER_JWT_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && token.split('.').count() == 3
        && token.split('.').all(|part| !part.is_empty())
}

fn sts_form_body(audience: &FirestoreWitnessAudience, subject_token: &str) -> Zeroizing<Vec<u8>> {
    let pairs = [
        ("grant_type", STS_GRANT_TYPE),
        ("subject_token", subject_token),
        ("subject_token_type", STS_SUBJECT_TOKEN_TYPE),
        ("audience", audience.as_str()),
        ("requested_token_type", STS_REQUESTED_TOKEN_TYPE),
        ("scope", STS_SCOPE),
    ];
    let capacity = pairs
        .iter()
        .map(|(key, value)| key.len().saturating_add(value.len()).saturating_add(2))
        .sum();
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    for (index, (key, value)) in pairs.into_iter().enumerate() {
        if index != 0 {
            encoded.push(b'&');
        }
        push_form_component(&mut encoded, key.as_bytes());
        encoded.push(b'=');
        push_form_component(&mut encoded, value.as_bytes());
    }
    encoded
}

fn push_form_component(output: &mut Vec<u8>, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                output.push(*byte);
            }
            b' ' => output.push(b'+'),
            other => {
                output.push(b'%');
                output.push(HEX[usize::from(other >> 4)]);
                output.push(HEX[usize::from(other & 0x0f)]);
            }
        }
    }
}

async fn bounded_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> std::result::Result<Zeroizing<Vec<u8>>, FirestoreWitnessTransportError> {
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| FirestoreWitnessTransportError::Unavailable)?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|total| total > max_bytes)
        {
            return Err(FirestoreWitnessTransportError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StsResponseWire<'a> {
    #[serde(borrow)]
    access_token: &'a RawValue,
    token_type: &'a str,
    issued_token_type: &'a str,
    expires_in: u64,
}

fn parse_sts_response(
    bytes: &[u8],
) -> std::result::Result<FirestoreWitnessStsToken, FirestoreWitnessTransportError> {
    if bytes.is_empty() || bytes.len() > MAX_STS_RESPONSE_BYTES {
        return Err(if bytes.len() > MAX_STS_RESPONSE_BYTES {
            FirestoreWitnessTransportError::TooLarge
        } else {
            FirestoreWitnessTransportError::Protocol
        });
    }
    let response: StsResponseWire<'_> =
        serde_json::from_slice(bytes).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    if response.token_type != "Bearer"
        || response.issued_token_type != STS_ISSUED_TOKEN_TYPE
        || !valid_sts_lifetime(response.expires_in)
    {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let raw_token = response.access_token.get();
    let token = raw_token
        .strip_prefix('"')
        .and_then(|token| token.strip_suffix('"'))
        .filter(|token| !token.is_empty() && token.len() <= MAX_STS_ACCESS_TOKEN_BYTES)
        // Requiring the exact token grammar also rejects every JSON escape:
        // an escaped JSON string necessarily contains a backslash in RawValue.
        .ok_or(FirestoreWitnessTransportError::Protocol)
        .and_then(FirestoreWitnessBearerToken::new)?;
    Ok(FirestoreWitnessStsToken {
        token,
        expires_in: response.expires_in,
    })
}

fn valid_sts_lifetime(expires_in: u64) -> bool {
    ((CACHE_EARLY_EXPIRY.as_secs() + 1)..=MAX_STS_EXPIRES_IN_SECONDS).contains(&expires_in)
}

fn token_refresh_deadline(
    expires_in: u64,
) -> std::result::Result<Instant, FirestoreWitnessTransportError> {
    if !valid_sts_lifetime(expires_in) {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let reusable_for = Duration::from_secs(expires_in)
        .checked_sub(CACHE_EARLY_EXPIRY)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    Instant::now()
        .checked_add(reusable_for)
        .ok_or(FirestoreWitnessTransportError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, future::pending, sync::Mutex as StdMutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Notify,
    };

    const AUDIENCE: &str = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/archive-witness-attest/providers/archive-witness";
    const JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJmaXJlYmFzZSJ9.c2ln";

    struct FakeLauncher {
        calls: StdMutex<Vec<String>>,
        responses: StdMutex<VecDeque<std::result::Result<String, FirestoreWitnessTransportError>>>,
    }
    impl FakeLauncher {
        fn new(
            responses: impl IntoIterator<
                Item = std::result::Result<&'static str, FirestoreWitnessTransportError>,
            >,
        ) -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                responses: StdMutex::new(
                    responses
                        .into_iter()
                        .map(|result| result.map(str::to_owned))
                        .collect(),
                ),
            }
        }
    }
    #[async_trait::async_trait]
    impl FirestoreWitnessLauncherOidc for FakeLauncher {
        async fn oidc_token(
            &self,
            audience: &FirestoreWitnessAudience,
        ) -> std::result::Result<Zeroizing<String>, FirestoreWitnessTransportError> {
            self.calls
                .lock()
                .unwrap()
                .push(audience.as_str().to_owned());
            tokio::task::yield_now().await;
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(FirestoreWitnessTransportError::Protocol))
                .map(Zeroizing::new)
        }
    }

    struct BlockingLauncher {
        started: Notify,
    }

    #[async_trait::async_trait]
    impl FirestoreWitnessLauncherOidc for BlockingLauncher {
        async fn oidc_token(
            &self,
            _audience: &FirestoreWitnessAudience,
        ) -> std::result::Result<Zeroizing<String>, FirestoreWitnessTransportError> {
            self.started.notify_one();
            pending().await
        }
    }

    struct FakeSts {
        calls: StdMutex<Vec<(String, String)>>,
        responses: StdMutex<
            VecDeque<std::result::Result<(&'static str, u64), FirestoreWitnessTransportError>>,
        >,
    }
    impl FakeSts {
        fn new(
            responses: impl IntoIterator<
                Item = std::result::Result<(&'static str, u64), FirestoreWitnessTransportError>,
            >,
        ) -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                responses: StdMutex::new(responses.into_iter().collect()),
            }
        }
    }
    #[async_trait::async_trait]
    impl FirestoreWitnessStsExchange for FakeSts {
        async fn exchange(
            &self,
            audience: &FirestoreWitnessAudience,
            subject_token: &str,
        ) -> std::result::Result<FirestoreWitnessStsToken, FirestoreWitnessTransportError> {
            self.calls
                .lock()
                .unwrap()
                .push((audience.as_str().to_owned(), subject_token.to_owned()));
            let (token, expires_in) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(FirestoreWitnessTransportError::Protocol))?;
            Ok(FirestoreWitnessStsToken {
                token: FirestoreWitnessBearerToken::new(token)?,
                expires_in,
            })
        }
    }

    fn audience() -> FirestoreWitnessAudience {
        FirestoreWitnessAudience::new(AUDIENCE).unwrap()
    }
    fn bearer(
        launcher: Arc<dyn FirestoreWitnessLauncherOidc>,
        sts: Arc<dyn FirestoreWitnessStsExchange>,
    ) -> FirestoreWitnessAttestationBearer {
        FirestoreWitnessAttestationBearer::with_test_boundaries(audience(), launcher, sts)
    }

    async fn spawn_sts_server(
        status: &str,
        headers: Vec<(String, String)>,
        fragments: Vec<Vec<u8>>,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let status = status.to_owned();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_test_request(&mut stream).await;
            let body_len: usize = fragments.iter().map(Vec::len).sum();
            let mut head =
                format!("HTTP/1.1 {status}\r\nContent-Length: {body_len}\r\nConnection: close\r\n");
            for (name, value) in headers {
                head.push_str(&name);
                head.push_str(": ");
                head.push_str(&value);
                head.push_str("\r\n");
            }
            head.push_str("\r\n");
            stream.write_all(head.as_bytes()).await.unwrap();
            for fragment in fragments {
                if stream.write_all(&fragment).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            request
        });
        (origin, handle)
    }

    async fn read_test_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        const MAX_TEST_REQUEST_BYTES: usize = 128 * 1024;
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 1_024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count != 0, "request ended before its complete form body");
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() <= MAX_TEST_REQUEST_BYTES);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let body_start = header_end + 4;
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .expect("request has Content-Length");
            let request_end = body_start
                .checked_add(content_length)
                .expect("test request length does not overflow");
            assert!(request_end <= MAX_TEST_REQUEST_BYTES);
            if request.len() >= request_end {
                return request;
            }
        }
    }

    fn request_head_and_body(request: &[u8]) -> (&str, &[u8]) {
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        (
            std::str::from_utf8(&request[..header_end]).unwrap(),
            &request[header_end + 4..],
        )
    }

    fn expected_form_pairs() -> Vec<(String, String)> {
        vec![
            ("grant_type".to_owned(), STS_GRANT_TYPE.to_owned()),
            ("subject_token".to_owned(), JWT.to_owned()),
            (
                "subject_token_type".to_owned(),
                STS_SUBJECT_TOKEN_TYPE.to_owned(),
            ),
            ("audience".to_owned(), AUDIENCE.to_owned()),
            (
                "requested_token_type".to_owned(),
                STS_REQUESTED_TOKEN_TYPE.to_owned(),
            ),
            ("scope".to_owned(), STS_SCOPE.to_owned()),
        ]
    }

    #[tokio::test]
    async fn launcher_and_sts_receive_the_same_exact_dedicated_audience_without_nonce() {
        let launcher = Arc::new(FakeLauncher::new([Ok(JWT)]));
        let sts = Arc::new(FakeSts::new([Ok(("firestore-token", 120))]));
        let provider = bearer(launcher.clone(), sts.clone());
        provider.bearer_token(AUDIENCE).await.unwrap();
        assert_eq!(
            launcher.calls.lock().unwrap().clone(),
            vec![AUDIENCE.to_owned()]
        );
        assert_eq!(
            sts.calls.lock().unwrap().as_slice(),
            [(AUDIENCE.to_owned(), JWT.to_owned())]
        );
        assert!(matches!(
            provider.bearer_token("//iam.googleapis.com/projects/9/locations/global/workloadIdentityPools/archive-witness-attest/providers/archive-witness").await,
            Err(FirestoreWitnessTransportError::Protocol)
        ));
    }

    #[tokio::test]
    async fn cache_coalesces_hits_and_refreshes_sixty_seconds_early() {
        let launcher = Arc::new(FakeLauncher::new([Ok(JWT)]));
        let sts = Arc::new(FakeSts::new([Ok(("first-token", 120))]));
        let provider = Arc::new(bearer(launcher.clone(), sts.clone()));
        let (first, second) = tokio::join!(
            provider.bearer_token(AUDIENCE),
            provider.bearer_token(AUDIENCE)
        );
        assert!(first.is_ok() && second.is_ok());
        assert_eq!(
            launcher.calls.lock().unwrap().len(),
            1,
            "concurrent requests coalesce"
        );
        assert_eq!(sts.calls.lock().unwrap().len(), 1);
        provider.bearer_token(AUDIENCE).await.unwrap();
        assert_eq!(sts.calls.lock().unwrap().len(), 1, "fresh cache hit");

        let too_short = bearer(
            Arc::new(FakeLauncher::new([Ok(JWT)])),
            Arc::new(FakeSts::new([Ok(("short-token", 60))])),
        );
        assert!(matches!(
            too_short.bearer_token(AUDIENCE).await,
            Err(FirestoreWitnessTransportError::Protocol)
        ));
        assert!(too_short.cache.lock().await.is_none());
    }

    #[test]
    fn fixed_sts_form_has_all_rfc8693_fields_and_no_authorization_header() {
        let client = GcpFirestoreWitnessSts::new().unwrap();
        let request = client.request(&audience(), JWT).unwrap();
        assert_eq!(request.url().as_str(), STS_TOKEN_ENDPOINT);
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-www-form-urlencoded")
        );
        assert!(!request
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION));
        let cloned = request
            .try_clone()
            .expect("owned Bytes body is retry-cloneable");
        drop(request);
        let body = cloned
            .body()
            .and_then(reqwest::Body::as_bytes)
            .expect("fixed body bytes survive request clone");
        let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body).unwrap();
        assert_eq!(pairs, expected_form_pairs());
    }

    #[tokio::test]
    async fn loopback_sts_uses_exact_path_headers_form_and_fragmented_response() {
        let body = serde_json::to_vec(&serde_json::json!({
            "access_token": "loopback-firestore-token",
            "token_type": "Bearer",
            "issued_token_type": STS_ISSUED_TOKEN_TYPE,
            "expires_in": 120,
        }))
        .unwrap();
        let split = body.len() / 2;
        let (origin, server) = spawn_sts_server(
            "200 OK",
            Vec::new(),
            vec![body[..split].to_vec(), body[split..].to_vec()],
        )
        .await;
        let sts = GcpFirestoreWitnessSts::with_test_origin(&origin).unwrap();

        assert!(sts.exchange(&audience(), JWT).await.is_ok());
        let request = server.await.unwrap();
        let (head, body) = request_head_and_body(&request);
        assert_eq!(head.lines().next(), Some("POST /v1/token HTTP/1.1"));
        assert!(head.lines().any(|line| {
            line.eq_ignore_ascii_case("content-type: application/x-www-form-urlencoded")
        }));
        assert!(!head.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        }));
        let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body).unwrap();
        assert_eq!(pairs, expected_form_pairs());
    }

    #[tokio::test]
    async fn loopback_sts_rejects_fragmented_oversized_response() {
        let (origin, server) = spawn_sts_server(
            "200 OK",
            Vec::new(),
            vec![
                vec![b' '; MAX_STS_RESPONSE_BYTES / 2],
                vec![b' '; MAX_STS_RESPONSE_BYTES / 2 + 1],
            ],
        )
        .await;
        let sts = GcpFirestoreWitnessSts::with_test_origin(&origin).unwrap();

        assert!(matches!(
            sts.exchange(&audience(), JWT).await,
            Err(FirestoreWitnessTransportError::TooLarge)
        ));
        let request = server.await.unwrap();
        assert_eq!(
            request_head_and_body(&request).0.lines().next(),
            Some("POST /v1/token HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn loopback_sts_rejects_failure_body_without_retry() {
        let (origin, server) = spawn_sts_server(
            "500 Internal Server Error",
            Vec::new(),
            vec![b"provider-body-must-not-be-read".to_vec()],
        )
        .await;
        let sts = GcpFirestoreWitnessSts::with_test_origin(&origin).unwrap();

        assert!(matches!(
            sts.exchange(&audience(), JWT).await,
            Err(FirestoreWitnessTransportError::Unavailable)
        ));
        let request = server.await.unwrap();
        assert_eq!(
            request_head_and_body(&request).0.lines().next(),
            Some("POST /v1/token HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn loopback_sts_does_not_follow_redirects() {
        let redirect_target = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let location = format!(
            "http://{}/must-not-follow",
            redirect_target.local_addr().unwrap()
        );
        let (origin, server) = spawn_sts_server(
            "302 Found",
            vec![("Location".to_owned(), location)],
            Vec::new(),
        )
        .await;
        let sts = GcpFirestoreWitnessSts::with_test_origin(&origin).unwrap();

        assert!(matches!(
            sts.exchange(&audience(), JWT).await,
            Err(FirestoreWitnessTransportError::Unavailable)
        ));
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), redirect_target.accept())
                .await
                .is_err(),
            "redirect target unexpectedly received a connection"
        );
    }

    #[test]
    fn sts_response_schema_is_bounded_and_strict() {
        let valid = serde_json::json!({
            "access_token": "opaque-firestore-access-token",
            "token_type": "Bearer",
            "issued_token_type": STS_ISSUED_TOKEN_TYPE,
            "expires_in": 120,
        });
        assert!(parse_sts_response(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for invalid in [
            serde_json::json!({"access_token":"x","token_type":"bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":"jwt","expires_in":120}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":0}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":60}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":3601}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120,"scope":STS_SCOPE}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120,"access_boundary_session_key":"unexpected"}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120,"unexpected":true}),
        ] {
            assert!(matches!(
                parse_sts_response(&serde_json::to_vec(&invalid).unwrap()),
                Err(FirestoreWitnessTransportError::Protocol)
            ));
        }
        assert!(matches!(
            parse_sts_response(&vec![b' '; MAX_STS_RESPONSE_BYTES + 1]),
            Err(FirestoreWitnessTransportError::TooLarge)
        ));
        let oversized_token = serde_json::json!({
            "access_token": "x".repeat(MAX_STS_ACCESS_TOKEN_BYTES + 1),
            "token_type": "Bearer",
            "issued_token_type": STS_ISSUED_TOKEN_TYPE,
            "expires_in": 120,
        });
        assert!(matches!(
            parse_sts_response(&serde_json::to_vec(&oversized_token).unwrap()),
            Err(FirestoreWitnessTransportError::Protocol)
        ));
        let escaped_token = format!(
            r#"{{"access_token":"opaque\u002dtoken","token_type":"Bearer","issued_token_type":"{STS_ISSUED_TOKEN_TYPE}","expires_in":120}}"#
        );
        assert!(matches!(
            parse_sts_response(escaped_token.as_bytes()),
            Err(FirestoreWitnessTransportError::Protocol)
        ));
    }

    #[test]
    fn non_loopback_test_origins_are_rejected() {
        let accepted = GcpFirestoreWitnessSts::with_test_origin("http://127.0.0.1:3456").unwrap();
        assert_eq!(accepted.endpoint.path(), "/v1/token");
        for endpoint in [
            "https://sts.googleapis.com/v1/token",
            "http://example.test:3456",
            "http://localhost:3456",
            "http://127.0.0.1:3456/path",
            "http://127.0.0.1:3456/?query=1",
        ] {
            assert_eq!(
                GcpFirestoreWitnessSts::with_test_origin(endpoint).map(|_| ()),
                Err(FirestoreWitnessTransportError::Protocol),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn credentials_are_redacted() {
        let provider = FirestoreWitnessAttestationBearer::new(audience()).unwrap();
        assert_eq!(
            format!("{provider:?}"),
            "FirestoreWitnessAttestationBearer(<redacted>)"
        );
        assert_eq!(
            format!(
                "{:?}",
                FirestoreWitnessBearerToken::new("opaque-token").unwrap()
            ),
            "FirestoreWitnessBearerToken(<opaque>)"
        );
        assert!(std::any::type_name::<FirestoreWitnessAttestationBearer>()
            .contains("archive_v3_firestore_auth"));
    }

    #[tokio::test]
    async fn firestore_bearer_instances_do_not_share_a_kms_or_global_cache() {
        let launcher_one = Arc::new(FakeLauncher::new([Ok(JWT)]));
        let sts_one = Arc::new(FakeSts::new([Ok(("first-firestore-token", 120))]));
        let launcher_two = Arc::new(FakeLauncher::new([Ok(JWT)]));
        let sts_two = Arc::new(FakeSts::new([Ok(("second-firestore-token", 120))]));
        let first = bearer(launcher_one.clone(), sts_one.clone());
        let second = bearer(launcher_two.clone(), sts_two.clone());

        first.bearer_token(AUDIENCE).await.unwrap();
        second.bearer_token(AUDIENCE).await.unwrap();
        first.bearer_token(AUDIENCE).await.unwrap();
        second.bearer_token(AUDIENCE).await.unwrap();

        assert_eq!(launcher_one.calls.lock().unwrap().len(), 1);
        assert_eq!(sts_one.calls.lock().unwrap().len(), 1);
        assert_eq!(launcher_two.calls.lock().unwrap().len(), 1);
        assert_eq!(sts_two.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cache_boundary_rejects_out_of_contract_lifetimes_before_instant_math() {
        let provider = bearer(
            Arc::new(FakeLauncher::new([Ok(JWT)])),
            Arc::new(FakeSts::new([Ok(("untrusted-lifetime-token", 3_601))])),
        );
        assert!(matches!(
            provider.bearer_token(AUDIENCE).await,
            Err(FirestoreWitnessTransportError::Protocol)
        ));
        assert!(provider.cache.lock().await.is_none());
    }

    #[tokio::test]
    async fn failed_refresh_drops_expired_cache_and_leaves_it_empty() {
        let provider = bearer(
            Arc::new(FakeLauncher::new([Err(
                FirestoreWitnessTransportError::Unavailable,
            )])),
            Arc::new(FakeSts::new(std::iter::empty())),
        );
        *provider.cache.lock().await = Some(CachedBearerToken {
            token: FirestoreWitnessBearerToken::new("expired-token").unwrap(),
            refresh_at: Instant::now() - Duration::from_secs(1),
        });

        assert!(matches!(
            provider.bearer_token(AUDIENCE).await,
            Err(FirestoreWitnessTransportError::Unavailable)
        ));
        assert!(provider.cache.lock().await.is_none());
    }

    #[tokio::test]
    async fn cancelled_refresh_drops_expired_cache_and_leaves_it_empty() {
        let launcher = Arc::new(BlockingLauncher {
            started: Notify::new(),
        });
        let provider = Arc::new(bearer(
            launcher.clone(),
            Arc::new(FakeSts::new(std::iter::empty())),
        ));
        *provider.cache.lock().await = Some(CachedBearerToken {
            token: FirestoreWitnessBearerToken::new("expired-token").unwrap(),
            refresh_at: Instant::now() - Duration::from_secs(1),
        });
        let started = launcher.started.notified();
        let refresh = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.bearer_token(AUDIENCE).await })
        };
        started.await;
        refresh.abort();
        assert!(refresh.await.unwrap_err().is_cancelled());
        assert!(provider.cache.lock().await.is_none());
    }
}
