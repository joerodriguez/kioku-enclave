#![allow(
    dead_code,
    reason = "active signed-runtime archive-GCS bearer retains test-only constructors"
)]

//! Dedicated Confidential Space bearer credentials for archive GCS.
//!
//! This is intentionally *not* the legacy GCS client identity, the KMS
//! credential path, the public attestation path, or the Firestore-witness
//! bearer source. It has no environment constructor, metadata/default
//! credential fallback, service-account impersonation, Store/VFS/route
//! connection, or caller-selected authority. The signed runtime alone supplies
//! its typed, exact archive-GCS WIF
//! audience is minted without a nonce and exchanged only at fixed Google STS
//! for the fixed archive-GCS scope.

use crate::{
    archive_v3_gcs::GcsArchiveV3TransportError, archive_v3_gcs_http::ArchiveV3BearerTokenProvider,
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

const ARCHIVE_GCS_WIF_AUDIENCE_PREFIX: &str = "//iam.googleapis.com/projects/";
const ARCHIVE_GCS_WIF_AUDIENCE_SUFFIX: &str =
    "/locations/global/workloadIdentityPools/archive-gcs-attest/providers/archive-gcs";
const STS_TOKEN_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";
const ARCHIVE_GCS_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_write";
const STS_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const STS_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const STS_REQUESTED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const STS_ISSUED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const MAX_LAUNCHER_JWT_BYTES: usize = 64 * 1024;
const MAX_STS_RESPONSE_BYTES: usize = 32 * 1024;
// Google documents a 12 KiB maximum for a successful STS access token.
const MAX_STS_ACCESS_TOKEN_BYTES: usize = 12 * 1024;
const MAX_STS_EXPIRES_IN_SECONDS: u64 = 60 * 60;
const CACHE_EARLY_EXPIRY: Duration = Duration::from_secs(60);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Exact, dedicated WIF provider resource for the future archive-GCS writer.
/// This is an STS bearer-token audience, never a public verifier audience.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ArchiveV3GcsAudience(String);

impl ArchiveV3GcsAudience {
    /// Derive the only accepted archive-GCS provider resource. Production
    /// callers cannot supply an arbitrary full audience string.
    pub(crate) fn for_project_number(
        project_number: &str,
    ) -> std::result::Result<Self, GcsArchiveV3TransportError> {
        if !(1..=20).contains(&project_number.len())
            || project_number.starts_with('0')
            || !project_number.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        Ok(Self(format!(
            "{ARCHIVE_GCS_WIF_AUDIENCE_PREFIX}{project_number}{ARCHIVE_GCS_WIF_AUDIENCE_SUFFIX}"
        )))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArchiveV3GcsAudience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveV3GcsAudience(<redacted>)")
    }
}

/// Owns an encoded STS form for as long as a reqwest body can retain it.
struct ZeroizingStsBody(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for ZeroizingStsBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Archive-GCS-only bearer source with its own mutex-coalesced zeroizing cache.
pub(crate) struct ArchiveV3GcsAttestationBearer {
    audience: ArchiveV3GcsAudience,
    launcher: Arc<dyn ArchiveV3GcsLauncherOidc>,
    sts: Arc<dyn ArchiveV3GcsStsExchange>,
    cache: Mutex<Option<CachedBearerToken>>,
}

impl ArchiveV3GcsAttestationBearer {
    /// Constructs the fixed production endpoint path without doing I/O.
    pub(crate) fn new(
        audience: ArchiveV3GcsAudience,
    ) -> std::result::Result<Self, GcsArchiveV3TransportError> {
        Ok(Self {
            audience,
            launcher: Arc::new(ConfidentialSpaceArchiveV3GcsLauncher),
            sts: Arc::new(GcpArchiveV3GcsSts::new()?),
            cache: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn with_test_boundaries(
        audience: ArchiveV3GcsAudience,
        launcher: Arc<dyn ArchiveV3GcsLauncherOidc>,
        sts: Arc<dyn ArchiveV3GcsStsExchange>,
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
    ) -> std::result::Result<ArchiveV3GcsStsToken, GcsArchiveV3TransportError> {
        let subject_token = self.launcher.oidc_token(&self.audience).await?;
        self.sts.exchange(&self.audience, &subject_token).await
    }
}

#[async_trait::async_trait]
impl ArchiveV3BearerTokenProvider for ArchiveV3GcsAttestationBearer {
    async fn bearer_token(
        &self,
    ) -> std::result::Result<Zeroizing<String>, GcsArchiveV3TransportError> {
        // Refresh is intentionally coalesced. Its finite launcher/STS timeouts
        // ensure a failed peer cannot retain the cache lock indefinitely.
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            if Instant::now() < cached.refresh_at {
                return Ok(Zeroizing::new(cached.token.as_str().to_owned()));
            }
        }
        // Remove before await: failure or cancellation drops all expired cache
        // secret material and never revives it.
        cache.take();
        let fresh = self.fresh_token().await?;
        let refresh_at = token_refresh_deadline(fresh.expires_in)?;
        let token = fresh.token;
        let caller_copy = Zeroizing::new(token.as_str().to_owned());
        *cache = Some(CachedBearerToken { token, refresh_at });
        Ok(caller_copy)
    }
}

impl fmt::Debug for ArchiveV3GcsAttestationBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveV3GcsAttestationBearer(<redacted>)")
    }
}

struct CachedBearerToken {
    token: Zeroizing<String>,
    refresh_at: Instant,
}

#[async_trait::async_trait]
trait ArchiveV3GcsLauncherOidc: Send + Sync {
    async fn oidc_token(
        &self,
        audience: &ArchiveV3GcsAudience,
    ) -> std::result::Result<Zeroizing<String>, GcsArchiveV3TransportError>;
}

struct ConfidentialSpaceArchiveV3GcsLauncher;
#[async_trait::async_trait]
impl ArchiveV3GcsLauncherOidc for ConfidentialSpaceArchiveV3GcsLauncher {
    async fn oidc_token(
        &self,
        audience: &ArchiveV3GcsAudience,
    ) -> std::result::Result<Zeroizing<String>, GcsArchiveV3TransportError> {
        let token = fetch_internal_wif_attestation_token(audience)
            .await
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        if !valid_launcher_jwt(&token) {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        Ok(token)
    }
}

struct ArchiveV3GcsStsToken {
    token: Zeroizing<String>,
    expires_in: u64,
}

#[async_trait::async_trait]
trait ArchiveV3GcsStsExchange: Send + Sync {
    async fn exchange(
        &self,
        audience: &ArchiveV3GcsAudience,
        subject_token: &str,
    ) -> std::result::Result<ArchiveV3GcsStsToken, GcsArchiveV3TransportError>;
}

/// Fixed rustls-only/no-proxy/no-redirect/no-retry STS client. Test injection
/// accepts only an explicit loopback origin and never changes production setup.
struct GcpArchiveV3GcsSts {
    http: reqwest::Client,
    endpoint: reqwest::Url,
}
impl GcpArchiveV3GcsSts {
    fn new() -> std::result::Result<Self, GcsArchiveV3TransportError> {
        Self::from_fixed_endpoint(STS_TOKEN_ENDPOINT)
    }
    fn from_fixed_endpoint(
        endpoint: &str,
    ) -> std::result::Result<Self, GcsArchiveV3TransportError> {
        let parsed =
            reqwest::Url::parse(endpoint).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
        if endpoint != STS_TOKEN_ENDPOINT || !is_exact_sts_endpoint(&parsed) {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        Ok(Self {
            http: hardened_http()?,
            endpoint: parsed,
        })
    }
    #[cfg(test)]
    fn with_test_origin(origin: &str) -> std::result::Result<Self, GcsArchiveV3TransportError> {
        let parsed =
            reqwest::Url::parse(origin).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
        if !is_loopback_test_origin(&parsed) {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        let endpoint = parsed
            .join("/v1/token")
            .map_err(|_| GcsArchiveV3TransportError::Protocol)?;
        Ok(Self {
            http: hardened_http()?,
            endpoint,
        })
    }
    fn request(
        &self,
        audience: &ArchiveV3GcsAudience,
        subject_token: &str,
    ) -> std::result::Result<reqwest::Request, GcsArchiveV3TransportError> {
        if !valid_launcher_jwt(subject_token) {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        let body = reqwest::Body::from(bytes::Bytes::from_owner(ZeroizingStsBody(sts_form_body(
            audience,
            subject_token,
        ))));
        let request = self
            .http
            .post(self.endpoint.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .build()
            .map_err(|_| GcsArchiveV3TransportError::Protocol)?;
        if request
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION)
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        Ok(request)
    }
}

fn hardened_http() -> std::result::Result<reqwest::Client, GcsArchiveV3TransportError> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .build()
        .map_err(|_| GcsArchiveV3TransportError::Unavailable)
}

#[async_trait::async_trait]
impl ArchiveV3GcsStsExchange for GcpArchiveV3GcsSts {
    async fn exchange(
        &self,
        audience: &ArchiveV3GcsAudience,
        subject_token: &str,
    ) -> std::result::Result<ArchiveV3GcsStsToken, GcsArchiveV3TransportError> {
        let response = self
            .http
            .execute(self.request(audience, subject_token)?)
            .await
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        if !response.status().is_success() {
            return Err(GcsArchiveV3TransportError::Unavailable);
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
            .is_some_and(|ip| ip.is_loopback())
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
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && token.split('.').count() == 3
        && token.split('.').all(|part| !part.is_empty())
}
fn valid_bearer_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_STS_ACCESS_TOKEN_BYTES
        && token
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\'))
}
fn sts_form_body(audience: &ArchiveV3GcsAudience, subject_token: &str) -> Zeroizing<Vec<u8>> {
    let pairs = [
        ("grant_type", STS_GRANT_TYPE),
        ("subject_token", subject_token),
        ("subject_token_type", STS_SUBJECT_TOKEN_TYPE),
        ("audience", audience.as_str()),
        ("requested_token_type", STS_REQUESTED_TOKEN_TYPE),
        ("scope", ARCHIVE_GCS_SCOPE),
    ];
    let mut output = Zeroizing::new(Vec::with_capacity(
        pairs
            .iter()
            .map(|(k, v)| k.len().saturating_add(v.len()).saturating_add(2))
            .sum(),
    ));
    for (index, (key, value)) in pairs.into_iter().enumerate() {
        if index != 0 {
            output.push(b'&');
        }
        push_form_component(&mut output, key.as_bytes());
        output.push(b'=');
        push_form_component(&mut output, value.as_bytes());
    }
    output
}
fn push_form_component(output: &mut Vec<u8>, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                output.push(*byte)
            }
            b' ' => output.push(b'+'),
            other => {
                output.push(b'%');
                output.push(HEX[usize::from(other >> 4)]);
                output.push(HEX[usize::from(other & 15)]);
            }
        }
    }
}
async fn bounded_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> std::result::Result<Zeroizing<Vec<u8>>, GcsArchiveV3TransportError> {
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GcsArchiveV3TransportError::Unavailable)?
    {
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|total| total > max_bytes)
        {
            return Err(GcsArchiveV3TransportError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
) -> std::result::Result<ArchiveV3GcsStsToken, GcsArchiveV3TransportError> {
    if bytes.is_empty() || bytes.len() > MAX_STS_RESPONSE_BYTES {
        return Err(if bytes.len() > MAX_STS_RESPONSE_BYTES {
            GcsArchiveV3TransportError::TooLarge
        } else {
            GcsArchiveV3TransportError::Protocol
        });
    }
    let response: StsResponseWire<'_> =
        serde_json::from_slice(bytes).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
    if response.token_type != "Bearer"
        || response.issued_token_type != STS_ISSUED_TOKEN_TYPE
        || !valid_sts_lifetime(response.expires_in)
    {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    let token = response
        .access_token
        .get()
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .filter(|v| valid_bearer_token(v))
        .ok_or(GcsArchiveV3TransportError::Protocol)?;
    Ok(ArchiveV3GcsStsToken {
        token: Zeroizing::new(token.to_owned()),
        expires_in: response.expires_in,
    })
}
fn valid_sts_lifetime(expires_in: u64) -> bool {
    ((CACHE_EARLY_EXPIRY.as_secs() + 1)..=MAX_STS_EXPIRES_IN_SECONDS).contains(&expires_in)
}
fn token_refresh_deadline(
    expires_in: u64,
) -> std::result::Result<Instant, GcsArchiveV3TransportError> {
    if !valid_sts_lifetime(expires_in) {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    Instant::now()
        .checked_add(
            Duration::from_secs(expires_in)
                .checked_sub(CACHE_EARLY_EXPIRY)
                .ok_or(GcsArchiveV3TransportError::Protocol)?,
        )
        .ok_or(GcsArchiveV3TransportError::Protocol)
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

    const AUDIENCE: &str = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/archive-gcs-attest/providers/archive-gcs";
    const JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJnY3MifQ.c2ln";
    fn audience() -> ArchiveV3GcsAudience {
        ArchiveV3GcsAudience::for_project_number("123456789").unwrap()
    }

    struct FakeLauncher {
        calls: StdMutex<Vec<String>>,
        responses: StdMutex<VecDeque<std::result::Result<String, GcsArchiveV3TransportError>>>,
    }
    impl FakeLauncher {
        fn new(
            responses: impl IntoIterator<
                Item = std::result::Result<&'static str, GcsArchiveV3TransportError>,
            >,
        ) -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                responses: StdMutex::new(
                    responses
                        .into_iter()
                        .map(|r| r.map(str::to_owned))
                        .collect(),
                ),
            }
        }
    }
    #[async_trait::async_trait]
    impl ArchiveV3GcsLauncherOidc for FakeLauncher {
        async fn oidc_token(
            &self,
            audience: &ArchiveV3GcsAudience,
        ) -> std::result::Result<Zeroizing<String>, GcsArchiveV3TransportError> {
            self.calls
                .lock()
                .unwrap()
                .push(audience.as_str().to_owned());
            tokio::task::yield_now().await;
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(GcsArchiveV3TransportError::Protocol))
                .map(Zeroizing::new)
        }
    }
    struct BlockingLauncher {
        started: Notify,
    }
    #[async_trait::async_trait]
    impl ArchiveV3GcsLauncherOidc for BlockingLauncher {
        async fn oidc_token(
            &self,
            _: &ArchiveV3GcsAudience,
        ) -> std::result::Result<Zeroizing<String>, GcsArchiveV3TransportError> {
            self.started.notify_one();
            pending().await
        }
    }
    struct FakeSts {
        calls: StdMutex<Vec<(String, String)>>,
        responses: StdMutex<
            VecDeque<std::result::Result<(&'static str, u64), GcsArchiveV3TransportError>>,
        >,
    }
    impl FakeSts {
        fn new(
            responses: impl IntoIterator<
                Item = std::result::Result<(&'static str, u64), GcsArchiveV3TransportError>,
            >,
        ) -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                responses: StdMutex::new(responses.into_iter().collect()),
            }
        }
    }
    #[async_trait::async_trait]
    impl ArchiveV3GcsStsExchange for FakeSts {
        async fn exchange(
            &self,
            audience: &ArchiveV3GcsAudience,
            subject: &str,
        ) -> std::result::Result<ArchiveV3GcsStsToken, GcsArchiveV3TransportError> {
            self.calls
                .lock()
                .unwrap()
                .push((audience.as_str().to_owned(), subject.to_owned()));
            let (token, expires_in) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(GcsArchiveV3TransportError::Protocol))?;
            Ok(ArchiveV3GcsStsToken {
                token: Zeroizing::new(token.to_owned()),
                expires_in,
            })
        }
    }
    fn bearer(
        launcher: Arc<dyn ArchiveV3GcsLauncherOidc>,
        sts: Arc<dyn ArchiveV3GcsStsExchange>,
    ) -> ArchiveV3GcsAttestationBearer {
        ArchiveV3GcsAttestationBearer::with_test_boundaries(audience(), launcher, sts)
    }

    async fn spawn_sts_server(
        status: &str,
        headers: Vec<(String, String)>,
        body: Vec<Vec<u8>>,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let status = status.to_owned();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            let length: usize = body.iter().map(Vec::len).sum();
            let mut head =
                format!("HTTP/1.1 {status}\r\nContent-Length: {length}\r\nConnection: close\r\n");
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            stream.write_all(head.as_bytes()).await.unwrap();
            for fragment in body {
                if stream.write_all(&fragment).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            request
        });
        (origin, task)
    }
    async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&chunk[..n]);
            assert!(request.len() <= 128 * 1024);
            let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let head = std::str::from_utf8(&request[..end]).unwrap();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            if request.len() >= end + 4 + length {
                return request;
            }
        }
    }
    fn head_body(request: &[u8]) -> (&str, &[u8]) {
        let end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        (
            std::str::from_utf8(&request[..end]).unwrap(),
            &request[end + 4..],
        )
    }
    fn expected_form() -> Vec<(String, String)> {
        vec![
            ("grant_type".into(), STS_GRANT_TYPE.into()),
            ("subject_token".into(), JWT.into()),
            ("subject_token_type".into(), STS_SUBJECT_TOKEN_TYPE.into()),
            ("audience".into(), AUDIENCE.into()),
            (
                "requested_token_type".into(),
                STS_REQUESTED_TOKEN_TYPE.into(),
            ),
            ("scope".into(), ARCHIVE_GCS_SCOPE.into()),
        ]
    }

    #[test]
    fn audience_rejects_firestore_kms_and_wrong_archive_provider() {
        for bad in ["", "0123", "project-id", "123456789/locations/global/workloadIdentityPools/archive-witness-attest/providers/archive-witness"] { assert_eq!(ArchiveV3GcsAudience::for_project_number(bad), Err(GcsArchiveV3TransportError::Protocol)); }
    }
    #[tokio::test]
    async fn provider_mints_only_the_exact_dedicated_audience_and_uses_its_own_cache() {
        let launcher = Arc::new(FakeLauncher::new([Ok(JWT)]));
        let sts = Arc::new(FakeSts::new([Ok(("archive-gcs-token", 120))]));
        let provider = Arc::new(bearer(launcher.clone(), sts.clone()));
        let (one, two) = tokio::join!(provider.bearer_token(), provider.bearer_token());
        assert!(one.is_ok() && two.is_ok());
        assert_eq!(launcher.calls.lock().unwrap().as_slice(), [AUDIENCE]);
        assert_eq!(
            sts.calls.lock().unwrap().as_slice(),
            [(AUDIENCE.to_owned(), JWT.to_owned())]
        );
    }
    #[tokio::test]
    async fn cancellation_and_failed_refresh_empty_expired_zeroizing_cache() {
        let launcher = Arc::new(BlockingLauncher {
            started: Notify::new(),
        });
        let provider = Arc::new(bearer(
            launcher.clone(),
            Arc::new(FakeSts::new(std::iter::empty())),
        ));
        *provider.cache.lock().await = Some(CachedBearerToken {
            token: Zeroizing::new("expired".into()),
            refresh_at: Instant::now() - Duration::from_secs(1),
        });
        let started = launcher.started.notified();
        let refresh = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.bearer_token().await })
        };
        started.await;
        refresh.abort();
        assert!(refresh.await.unwrap_err().is_cancelled());
        assert!(provider.cache.lock().await.is_none());
        let failed = bearer(
            Arc::new(FakeLauncher::new([Err(
                GcsArchiveV3TransportError::Unavailable,
            )])),
            Arc::new(FakeSts::new(std::iter::empty())),
        );
        assert!(matches!(
            failed.bearer_token().await,
            Err(GcsArchiveV3TransportError::Unavailable)
        ));
        assert!(failed.cache.lock().await.is_none());
    }
    #[test]
    fn strict_form_has_fixed_archive_scope_and_no_authorization() {
        let request = GcpArchiveV3GcsSts::new()
            .unwrap()
            .request(&audience(), JWT)
            .unwrap();
        assert_eq!(request.url().as_str(), STS_TOKEN_ENDPOINT);
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap(),
            "application/x-www-form-urlencoded"
        );
        assert!(!request
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION));
        let body = request.body().and_then(reqwest::Body::as_bytes).unwrap();
        assert_eq!(
            serde_urlencoded::from_bytes::<Vec<(String, String)>>(body).unwrap(),
            expected_form()
        );
    }
    #[tokio::test]
    async fn loopback_sts_checks_path_form_headers_and_fragmented_response() {
        let payload = serde_json::to_vec(&serde_json::json!({"access_token":"loopback-archive-gcs-token","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120})).unwrap();
        let split = payload.len() / 2;
        let (origin, server) = spawn_sts_server(
            "200 OK",
            vec![],
            vec![payload[..split].to_vec(), payload[split..].to_vec()],
        )
        .await;
        assert!(GcpArchiveV3GcsSts::with_test_origin(&origin)
            .unwrap()
            .exchange(&audience(), JWT)
            .await
            .is_ok());
        let request = server.await.unwrap();
        let (head, body) = head_body(&request);
        assert_eq!(head.lines().next(), Some("POST /v1/token HTTP/1.1"));
        assert!(head.lines().any(
            |line| line.eq_ignore_ascii_case("content-type: application/x-www-form-urlencoded")
        ));
        assert!(!head.to_ascii_lowercase().contains("authorization:"));
        assert_eq!(
            serde_urlencoded::from_bytes::<Vec<(String, String)>>(body).unwrap(),
            expected_form()
        );
    }
    #[tokio::test]
    async fn loopback_sts_does_not_retransmit_after_accepted_connection_closes() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut first_stream, _) = listener.accept().await.unwrap();
            let first_request = read_request(&mut first_stream).await;
            // The full credential exchange reached the server. Keep the
            // listener live after closing this connection so a retry cannot
            // hide behind connection-refused behavior.
            drop(first_stream);
            let retransmit =
                match tokio::time::timeout(Duration::from_secs(1), listener.accept()).await {
                    Ok(Ok((mut stream, _))) => Some(read_request(&mut stream).await),
                    Ok(Err(error)) => panic!("loopback listener failed: {error}"),
                    Err(_) => None,
                };
            (first_request, retransmit)
        });

        assert!(matches!(
            GcpArchiveV3GcsSts::with_test_origin(&origin)
                .unwrap()
                .exchange(&audience(), JWT)
                .await,
            Err(GcsArchiveV3TransportError::Unavailable)
        ));
        let (first_request, retransmit) = server.await.unwrap();
        assert_eq!(
            head_body(&first_request).0.lines().next(),
            Some("POST /v1/token HTTP/1.1")
        );
        assert!(
            retransmit.is_none(),
            "STS exchange retransmitted after provider acceptance"
        );
    }
    #[tokio::test]
    async fn loopback_sts_rejects_oversize_500_and_redirect_without_retry() {
        let (origin, server) = spawn_sts_server(
            "200 OK",
            vec![],
            vec![
                vec![b' '; MAX_STS_RESPONSE_BYTES / 2],
                vec![b' '; MAX_STS_RESPONSE_BYTES / 2 + 1],
            ],
        )
        .await;
        assert!(matches!(
            GcpArchiveV3GcsSts::with_test_origin(&origin)
                .unwrap()
                .exchange(&audience(), JWT)
                .await,
            Err(GcsArchiveV3TransportError::TooLarge)
        ));
        server.await.unwrap();
        let (origin, server) = spawn_sts_server(
            "500 Internal Server Error",
            vec![],
            vec![b"provider-secret-body".to_vec()],
        )
        .await;
        assert!(matches!(
            GcpArchiveV3GcsSts::with_test_origin(&origin)
                .unwrap()
                .exchange(&audience(), JWT)
                .await,
            Err(GcsArchiveV3TransportError::Unavailable)
        ));
        server.await.unwrap();
        let target = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let (origin, server) = spawn_sts_server(
            "302 Found",
            vec![(
                "Location".into(),
                format!("http://{}/forbidden", target.local_addr().unwrap()),
            )],
            vec![],
        )
        .await;
        assert!(matches!(
            GcpArchiveV3GcsSts::with_test_origin(&origin)
                .unwrap()
                .exchange(&audience(), JWT)
                .await,
            Err(GcsArchiveV3TransportError::Unavailable)
        ));
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }
    #[test]
    fn strict_response_rejects_escapes_unknown_fields_and_bad_lifetime() {
        let valid = serde_json::json!({"access_token":"opaque-gcs-token","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120});
        assert!(parse_sts_response(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for bad in [
            serde_json::json!({"access_token":"x","token_type":"bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120}),
            serde_json::json!({"access_token":"x\\ny","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":60}),
            serde_json::json!({"access_token":"x".repeat(MAX_STS_ACCESS_TOKEN_BYTES + 1),"token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120}),
            serde_json::json!({"access_token":"x","token_type":"Bearer","issued_token_type":STS_ISSUED_TOKEN_TYPE,"expires_in":120,"extra":true}),
        ] {
            assert!(matches!(
                parse_sts_response(&serde_json::to_vec(&bad).unwrap()),
                Err(GcsArchiveV3TransportError::Protocol)
            ));
        }
    }
}
