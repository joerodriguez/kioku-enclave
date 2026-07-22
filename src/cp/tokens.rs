//! Token and cryptographic helpers for the in-enclave control plane:
//! HS256 JWTs (access tokens, OAuth state, OAuth authorization codes), PKCE S256,
//! sha256-hex (refresh-token hashing), opaque random tokens, and UUIDs.
//!
//! All HMAC/JWT work uses `jsonwebtoken` (rust_crypto provider, already in the
//! musl FROM-scratch build); no OpenSSL.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

const ACCESS_TOKEN_AUD: &str = "kioku-mcp";
const ACCESS_TOKEN_TTL_SECS: u64 = 3600; // 1h
const STATE_TTL_SECS: u64 = 600; // 10m
const AUTH_CODE_TTL_SECS: u64 = 300; // 5m
const CONSENT_TTL_SECS: u64 = 300; // 5m

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

/// Derive a stable, deterministic UUIDv5-like string from google_sub using SHA-256.
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

// ── Access token (our own HS256 JWT) ────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct AccessClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

/// Issue a 1-hour HS256 access JWT for a user id.
pub fn issue_access_token(secret: &str, base_url: &str, user_id: &str) -> Result<String> {
    let claims = AccessClaims {
        sub: user_id.to_string(),
        iss: base_url.to_string(),
        aud: ACCESS_TOKEN_AUD.to_string(),
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
pub fn verify_access_token(secrets: &[String], base_url: &str, token: &str) -> Result<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[base_url]);
    validation.set_audience(&[ACCESS_TOKEN_AUD]);

    let mut last_err = None;
    for secret in secrets {
        match decode::<AccessClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        ) {
            Ok(data) => return Ok(data.claims.sub),
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
    pub exp: u64,
}

pub fn issue_state(secret: &str, claims: &StateClaims) -> Result<String> {
    let mut c = StateClaims {
        client_id: claims.client_id.clone(),
        redirect_uri: claims.redirect_uri.clone(),
        client_state: claims.client_state.clone(),
        code_challenge: claims.code_challenge.clone(),
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
    pub exp: u64,
}

pub fn issue_auth_code(
    secret: &str,
    user_id: &str,
    client_id: &str,
    code_challenge: &str,
) -> Result<String> {
    let claims = AuthCodeClaims {
        user_id: user_id.to_string(),
        client_id: client_id.to_string(),
        code_challenge: code_challenge.to_string(),
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
    pub exp: u64,
}

pub fn issue_consent(secret: &str, claims: &ConsentClaims) -> Result<String> {
    let claims = ConsentClaims {
        user_id: claims.user_id.clone(),
        client_id: claims.client_id.clone(),
        redirect_uri: claims.redirect_uri.clone(),
        client_state: claims.client_state.clone(),
        code_challenge: claims.code_challenge.clone(),
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

#[derive(Serialize, Deserialize)]
pub struct GmailOAuthStateClaims {
    pub user_id: String,
    pub exp: u64,
}

pub fn issue_gmail_state(secret: &str, user_id: &str) -> Result<String> {
    let claims = GmailOAuthStateClaims {
        user_id: user_id.to_string(),
        exp: now_secs() + STATE_TTL_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| EnclaveError::Auth(format!("issue gmail state: {e}")))
}

pub fn verify_gmail_state(secret: &str, token: &str) -> Result<GmailOAuthStateClaims> {
    decode::<GmailOAuthStateClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &exp_only_validation(),
    )
    .map(|data| data.claims)
    .map_err(|e| EnclaveError::Auth(format!("verify gmail state: {e}")))
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
    fn auth_code_round_trips() {
        let c = issue_auth_code("s", "u1", "c1", "chal").unwrap();
        let claims = verify_auth_code("s", &c).unwrap();
        assert_eq!(claims.user_id, "u1");
        assert_eq!(claims.client_id, "c1");
        assert_eq!(claims.code_challenge, "chal");
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
                exp: 0,
            },
        )
        .unwrap();
        let claims = verify_consent("secret", &token).unwrap();
        assert_eq!(claims.user_id, "u1");
        assert_eq!(claims.redirect_uri, "https://client.example/cb");
        assert!(verify_consent("wrong", &token).is_err());
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
}
