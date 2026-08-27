//! Token and cryptographic helpers for the in-enclave control plane:
//! HS256 JWTs (access tokens, OAuth state, OAuth authorization codes), PKCE S256,
//! sha256-hex (refresh-token hashing), opaque random tokens, and UUIDs.
//!
//! All HMAC/JWT work uses `jsonwebtoken` (rust_crypto provider, already in the
//! musl FROM-scratch build); no OpenSSL.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

const LEGACY_ACCESS_TOKEN_AUD: &str = "kioku-mcp";
const ACCESS_TOKEN_TTL_SECS: u64 = 15 * 60;
const STATE_TTL_SECS: u64 = 600; // 10m
const AUTH_CODE_TTL_SECS: u64 = 300; // 5m
const CONSENT_TTL_SECS: u64 = 300; // 5m
const RECORDING_RETENTION_LEASE_DOMAIN: &[u8] = b"kioku.recording-retention-lease.v1\0";

type HmacSha256 = Hmac<Sha256>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Hashing / PKCE / random ─────────────────────────────────────────────────────

/// Lowercase hex SHA-256 (refresh-token hashing — never store the raw token).
pub fn sha256_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// PKCE S256: base64url-nopad(sha256(verifier)).
pub fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// 256-bit opaque token, lowercase hex (refresh tokens).
pub fn random_token_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A random UUIDv4 string (user ids, oauth client ids). Avoids a `uuid` dep.
pub fn new_uuid() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Derive a stable, deterministic UUIDv5-like string from a legacy Google
/// subject using SHA-256. This exact function is retained so existing Google
/// accounts keep their encrypted archive object names.
/// This prevents orphaning user index GCS blobs on control DB resets.
pub fn derive_stable_uuid(google_sub: &str) -> String {
    // Fixed namespace UUID for Kioku user IDs (randomly generated once)
    const NAMESPACE_KIOKU_USER: [u8; 16] = [
        0xa7, 0x4f, 0x6e, 0x9c, 0xc4, 0x76, 0x4b, 0x8f, 0x83, 0x8e, 0x92, 0xd3, 0xf6, 0x04, 0x2e,
        0x9a,
    ];
    let mut hasher = Sha256::new();
    hasher.update(NAMESPACE_KIOKU_USER);
    hasher.update(google_sub.as_bytes());
    let digest = hasher.finalize();

    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0f) | 0x50; // version 5 (name-based)
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Derive the canonical Kioku account id for a newly created provider
/// identity. Google deliberately preserves the historical derivation. Other
/// providers are domain-separated so equal opaque subjects cannot collide.
pub fn derive_provider_uuid(provider: &str, subject: &str) -> String {
    if provider == "google" {
        derive_stable_uuid(subject)
    } else {
        derive_stable_uuid(&format!("{provider}\0{subject}"))
    }
}

// ── Recording-retention lease authority ─────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordingRetentionLeaseClaims {
    pub(crate) user_id: String,
    pub(crate) lease_id: String,
    pub(crate) policy_revision: i64,
    pub(crate) policy_epoch: String,
    pub(crate) valid_from_epoch_millis: i64,
    pub(crate) capture_started_before_epoch_millis: i64,
    pub(crate) valid_until_epoch_millis: i64,
}

fn valid_recording_retention_lease_claims(claims: &RecordingRetentionLeaseClaims) -> bool {
    crate::store::validate_user_id(&claims.user_id).is_ok()
        && claims.lease_id.starts_with("lease_")
        && claims.lease_id.len() == 70
        && claims
            .lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && claims.policy_revision > 0
        && claims.policy_epoch.starts_with("rpe_")
        && claims.policy_epoch.len() == 68
        && claims.policy_epoch[4..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        && claims.valid_from_epoch_millis >= 0
        && claims.capture_started_before_epoch_millis > claims.valid_from_epoch_millis
        && claims.valid_until_epoch_millis >= claims.capture_started_before_epoch_millis
        && claims
            .valid_until_epoch_millis
            .saturating_sub(claims.valid_from_epoch_millis)
            <= 5 * 60 * 1_000
}

pub(crate) fn issue_recording_retention_lease(
    secret: &str,
    claims: &RecordingRetentionLeaseClaims,
) -> Result<String> {
    if secret.len() < 16 || !valid_recording_retention_lease_claims(claims) {
        return Err(EnclaveError::InvalidRequest(
            "invalid recording retention lease authority".into(),
        ));
    }
    let payload = serde_json::to_vec(claims)?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| EnclaveError::Auth("invalid recording authority key".into()))?;
    mac.update(RECORDING_RETENTION_LEASE_DOMAIN);
    mac.update(encoded.as_bytes());
    let signature = mac.finalize().into_bytes();
    Ok(format!("rrl1.{encoded}.{}", hex_bytes(&signature)))
}

pub(crate) fn verify_recording_retention_lease(
    secrets: &[String],
    token: &str,
) -> Result<RecordingRetentionLeaseClaims> {
    if token.len() > 2_048 {
        return Err(EnclaveError::Auth(
            "recording retention lease rejected".into(),
        ));
    }
    let mut parts = token.split('.');
    let (Some("rrl1"), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(EnclaveError::Auth(
            "recording retention lease rejected".into(),
        ));
    };
    let signature = decode_hex_32(signature)
        .ok_or_else(|| EnclaveError::Auth("recording retention lease rejected".into()))?;
    let authenticated = secrets.iter().any(|secret| {
        HmacSha256::new_from_slice(secret.as_bytes()).is_ok_and(|mut mac| {
            mac.update(RECORDING_RETENTION_LEASE_DOMAIN);
            mac.update(payload.as_bytes());
            mac.verify_slice(&signature).is_ok()
        })
    });
    if !authenticated {
        return Err(EnclaveError::Auth(
            "recording retention lease rejected".into(),
        ));
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| EnclaveError::Auth("recording retention lease rejected".into()))?;
    let claims: RecordingRetentionLeaseClaims = serde_json::from_slice(&decoded)
        .map_err(|_| EnclaveError::Auth("recording retention lease rejected".into()))?;
    if !valid_recording_retention_lease_claims(&claims) {
        return Err(EnclaveError::Auth(
            "recording retention lease rejected".into(),
        ));
    }
    Ok(claims)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, slot) in decoded.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

// ── Access token (our own HS256 JWT) ────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct AccessClaims {
    sub: String,
    iss: String,
    aud: String,
    #[serde(default)]
    iat: Option<u64>,
    exp: u64,
}

/// Issue a 15-minute HS256 access JWT for a user id.
pub fn issue_access_token(secret: &str, base_url: &str, user_id: &str) -> Result<String> {
    let claims = AccessClaims {
        sub: user_id.to_string(),
        iss: base_url.to_string(),
        aud: base_url.to_string(),
        iat: Some(now_secs()),
        exp: now_secs() + ACCESS_TOKEN_TTL_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| EnclaveError::Auth(format!("issue access token: {e}")))
}

/// Verify one of our own access JWTs against the current secret, then any
/// rotation-fallback secrets. Returns the `sub` (user id). Alg pinned to HS256.
#[cfg(test)]
pub fn verify_access_token(secrets: &[String], base_url: &str, token: &str) -> Result<String> {
    verify_access_token_with_issued_at(secrets, base_url, token).map(|(subject, _)| subject)
}

pub(crate) fn verify_access_token_with_issued_at(
    secrets: &[String],
    base_url: &str,
    token: &str,
) -> Result<(String, Option<u64>)> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[base_url]);
    // The canonical resource URL is the MCP authorization audience. Keep the
    // legacy audience valid until already-issued tokens naturally
    // expire during the production rollout.
    validation.set_audience(&[base_url, LEGACY_ACCESS_TOKEN_AUD]);

    let mut last_err = None;
    for secret in secrets {
        match decode::<AccessClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        ) {
            Ok(data) => return Ok((data.claims.sub, data.claims.iat)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(EnclaveError::Auth(format!(
        "access token rejected: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no secret configured".into())
    )))
}

// ── OAuth state JWT (10m) ───────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct StateClaims {
    pub client_id: String,
    pub redirect_uri: String,
    pub client_state: String,
    pub code_challenge: String,
    #[serde(default)]
    pub resource: String,
    /// Present only while the browser Sign in with Apple round-trip is in
    /// flight. It is signed into the same short-lived state token as the
    /// downstream OAuth request, so the Apple identity token cannot be replayed
    /// against a different assistant/web authorization.
    #[serde(default)]
    pub apple_nonce: String,
    /// Present only for an authenticated browser request to attach an Apple
    /// identity to an existing Kioku account. The user ID is signed and never
    /// accepted from Apple's response or from a query parameter.
    #[serde(default)]
    pub apple_link_user_id: String,
    pub exp: u64,
}

pub fn issue_state(secret: &str, claims: &StateClaims) -> Result<String> {
    let mut c = StateClaims {
        client_id: claims.client_id.clone(),
        redirect_uri: claims.redirect_uri.clone(),
        client_state: claims.client_state.clone(),
        code_challenge: claims.code_challenge.clone(),
        resource: claims.resource.clone(),
        apple_nonce: claims.apple_nonce.clone(),
        apple_link_user_id: claims.apple_link_user_id.clone(),
        exp: now_secs() + STATE_TTL_SECS,
    };
    if claims.exp != 0 {
        c.exp = claims.exp;
    }
    encode(
        &Header::new(Algorithm::HS256),
        &c,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| EnclaveError::Auth(format!("issue state: {e}")))
}

pub fn verify_state(secret: &str, token: &str) -> Result<StateClaims> {
    decode::<StateClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &exp_only_validation(),
    )
    .map(|d| d.claims)
    .map_err(|e| EnclaveError::Auth(format!("invalid state: {e}")))
}

// ── OAuth authorization code JWT (5m) ───────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct AuthCodeClaims {
    pub user_id: String,
    pub client_id: String,
    pub code_challenge: String,
    #[serde(default)]
    pub resource: String,
    pub exp: u64,
}

pub fn issue_auth_code(
    secret: &str,
    user_id: &str,
    client_id: &str,
    code_challenge: &str,
    resource: &str,
) -> Result<String> {
    let claims = AuthCodeClaims {
        user_id: user_id.to_string(),
        client_id: client_id.to_string(),
        code_challenge: code_challenge.to_string(),
        resource: resource.to_string(),
        exp: now_secs() + AUTH_CODE_TTL_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| EnclaveError::Auth(format!("issue auth code: {e}")))
}

pub fn verify_auth_code(secret: &str, token: &str) -> Result<AuthCodeClaims> {
    decode::<AuthCodeClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &exp_only_validation(),
    )
    .map(|d| d.claims)
    .map_err(|e| EnclaveError::Auth(format!("invalid auth code: {e}")))
}

// ── OAuth consent grant (5m) ─────────────────────────────────────────────────────────────────────

/// Signed handoff between the Google callback and Kioku's explicit client
/// consent page. The raw JWT is also persisted by hash and consumed once.
#[derive(Serialize, Deserialize)]
pub struct ConsentClaims {
    pub user_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub client_state: String,
    pub code_challenge: String,
    #[serde(default)]
    pub resource: String,
    pub exp: u64,
}

pub fn issue_consent(secret: &str, claims: &ConsentClaims) -> Result<String> {
    let claims = ConsentClaims {
        user_id: claims.user_id.clone(),
        client_id: claims.client_id.clone(),
        redirect_uri: claims.redirect_uri.clone(),
        client_state: claims.client_state.clone(),
        code_challenge: claims.code_challenge.clone(),
        resource: claims.resource.clone(),
        exp: now_secs() + CONSENT_TTL_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| EnclaveError::Auth(format!("issue consent: {e}")))
}

pub fn verify_consent(secret: &str, token: &str) -> Result<ConsentClaims> {
    decode::<ConsentClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &exp_only_validation(),
    )
    .map(|d| d.claims)
    .map_err(|e| EnclaveError::Auth(format!("invalid consent: {e}")))
}

/// Validation that checks only HS256 + expiry (no iss/aud) — used for the
/// internal state and authorization-code JWTs, which carry neither.
fn exp_only_validation() -> Validation {
    let mut v = Validation::new(Algorithm::HS256);
    v.validate_aud = false;
    v.required_spec_claims = std::collections::HashSet::new();
    v.validate_exp = true;
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_known_vector() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn access_token_round_trips() {
        let secret = "test-secret";
        let base = "https://kioku.example";
        let tok = issue_access_token(secret, base, "user-123").unwrap();
        let sub = verify_access_token(&[secret.to_string()], base, &tok).unwrap();
        assert_eq!(sub, "user-123");
    }

    #[test]
    fn access_token_rejects_wrong_secret() {
        let tok = issue_access_token("a", "https://k", "u").unwrap();
        assert!(verify_access_token(&["b".to_string()], "https://k", &tok).is_err());
    }

    #[test]
    fn access_token_rotation_fallback() {
        let tok = issue_access_token("old", "https://k", "u").unwrap();
        // current secret "new" fails, previous "old" succeeds
        let sub = verify_access_token(&["new".to_string(), "old".to_string()], "https://k", &tok)
            .unwrap();
        assert_eq!(sub, "u");
    }

    #[test]
    fn recording_retention_lease_is_owner_epoch_and_signature_bound() {
        let claims = RecordingRetentionLeaseClaims {
            user_id: "11111111-1111-4111-8111-111111111111".into(),
            lease_id: format!("lease_{}", "a".repeat(64)),
            policy_revision: 7,
            policy_epoch: format!("rpe_{}", "b".repeat(64)),
            valid_from_epoch_millis: 1_800_000_000_000,
            capture_started_before_epoch_millis: 1_800_000_060_000,
            valid_until_epoch_millis: 1_800_000_060_000,
        };
        let secret = "recording-retention-test-secret";
        let token = issue_recording_retention_lease(secret, &claims).unwrap();
        assert_eq!(
            verify_recording_retention_lease(&[secret.into()], &token).unwrap(),
            claims
        );
        assert!(
            verify_recording_retention_lease(&["different-secret-value".into()], &token).is_err()
        );
        let mut tampered = token.into_bytes();
        let index = tampered.len() / 2;
        tampered[index] = if tampered[index] == b'a' { b'b' } else { b'a' };
        assert!(verify_recording_retention_lease(
            &[secret.into()],
            &String::from_utf8(tampered).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn auth_code_round_trips() {
        let c = issue_auth_code("s", "u1", "c1", "chal", "https://kioku.example").unwrap();
        let claims = verify_auth_code("s", &c).unwrap();
        assert_eq!(claims.user_id, "u1");
        assert_eq!(claims.client_id, "c1");
        assert_eq!(claims.code_challenge, "chal");
        assert_eq!(claims.resource, "https://kioku.example");
    }

    #[test]
    fn consent_round_trips_and_rejects_wrong_secret() {
        let token = issue_consent(
            "secret",
            &ConsentClaims {
                user_id: "u1".into(),
                client_id: "c1".into(),
                redirect_uri: "https://client.example/cb".into(),
                client_state: "state".into(),
                code_challenge: "challenge".into(),
                resource: "https://kioku.example".into(),
                exp: 0,
            },
        )
        .unwrap();
        let claims = verify_consent("secret", &token).unwrap();
        assert_eq!(claims.user_id, "u1");
        assert_eq!(claims.redirect_uri, "https://client.example/cb");
        assert_eq!(claims.resource, "https://kioku.example");
        assert!(verify_consent("wrong", &token).is_err());
    }

    #[test]
    fn apple_browser_state_round_trips_nonce_and_authenticated_link_target() {
        let token = issue_state(
            "secret",
            &StateClaims {
                client_id: String::new(),
                redirect_uri: String::new(),
                client_state: String::new(),
                code_challenge: String::new(),
                resource: String::new(),
                apple_nonce: "n".repeat(43),
                apple_link_user_id: "user-123".into(),
                exp: 0,
            },
        )
        .unwrap();
        let claims = verify_state("secret", &token).unwrap();
        assert_eq!(claims.apple_nonce, "n".repeat(43));
        assert_eq!(claims.apple_link_user_id, "user-123");
        assert!(verify_state("wrong", &token).is_err());
    }

    #[test]
    fn uuid_shape() {
        let u = new_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[14], b'4'); // version nibble
    }

    #[test]
    fn derive_stable_uuid_determinism_and_shape() {
        let sub = "12345678901234567890";
        let u1 = derive_stable_uuid(sub);
        let u2 = derive_stable_uuid(sub);
        assert_eq!(u1, u2, "must be deterministic");

        assert_eq!(u1.len(), 36);
        assert_eq!(u1.as_bytes()[14], b'5', "must be version 5");
        assert!(
            u1.as_bytes()[19] == b'8'
                || u1.as_bytes()[19] == b'9'
                || u1.as_bytes()[19] == b'a'
                || u1.as_bytes()[19] == b'b',
            "must be variant 1 (8, 9, a, b)"
        );

        let u3 = derive_stable_uuid("different_sub");
        assert_ne!(u1, u3);
    }

    #[test]
    fn provider_ids_preserve_google_and_domain_separate_apple() {
        let subject = "same-provider-subject";
        assert_eq!(
            derive_provider_uuid("google", subject),
            derive_stable_uuid(subject)
        );
        assert_ne!(
            derive_provider_uuid("apple", subject),
            derive_stable_uuid(subject)
        );
        assert_ne!(
            derive_provider_uuid("apple", subject),
            derive_provider_uuid("other", subject)
        );
    }
}
