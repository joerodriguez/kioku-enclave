//! Google ID-token verification for control-plane caller authentication.
//!
//! # Purpose
//!
//! Instead of a shared bearer-secret environment variable (which an operator
//! could inject at VM launch time), the enclave verifies that every caller
//! holds a Google-signed ID token issued to the designated control-plane
//! service account. Because the token is signed by Google's asymmetric RSA
//! key (which the enclave cannot forge), the *identity* of the caller is
//! cryptographically bound and not operator-injectable via launch metadata.
//!
//! # Verification steps
//!
//! 1. Parse the token header → extract `kid` (key ID).
//! 2. Fetch Google's JWKS (`https://www.googleapis.com/oauth2/v3/certs`) and
//!    find the matching public key by `kid`.  Keys are cached per-`kid` with
//!    a short TTL so we don't hit Google on every request.
//! 3. Verify the RS256 signature using `jsonwebtoken`.
//! 4. Check `exp > now`, `aud == ENCLAVE_AUDIENCE`, `email == RUN_SA_EMAIL`,
//!    `email_verified == true`.
//! 5. Verify `iss` is `https://accounts.google.com` (Service Account ID tokens)
//!    or `accounts.google.com`.
//!
//! # Caveats / uncertainty
//!
//! Google's JWKS endpoint (`/oauth2/v3/certs`) contains a `Cache-Control`
//! max-age header; we honour that by caching the full key set until max-age
//! expires (defaulting to 5 minutes if no header).  Clock skew tolerance of
//! 30 seconds is applied to `exp`.
//!
//! The `jsonwebtoken` crate's `DecodingKey::from_jwk` accepts the Google JWK
//! format (RSA `n`/`e` fields).  If Google ever rotates to EC keys the `use_jwk`
//! feature and this code remain valid (jsonwebtoken supports both).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::error::{EnclaveError, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Acceptable Google issuers for service-account ID tokens.
const GOOGLE_ISSUERS: &[&str] = &["https://accounts.google.com", "accounts.google.com"];

/// Clock-skew tolerance when validating `exp`.
const EXP_LEEWAY_SECS: u64 = 30;

/// Default JWKS cache TTL when the server doesn't send Cache-Control.
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(300); // 5 min

// ── ID-token claims ───────────────────────────────────────────────────────────

/// Subset of Google ID-token claims we need to validate.
#[derive(Debug, Deserialize)]
pub struct GoogleIdClaims {
    #[allow(dead_code)]
    pub iss: String,
    #[allow(dead_code)]
    pub aud: String,
    pub email: String,
    pub email_verified: bool,
    /// Expiry (Unix timestamp). Validated by jsonwebtoken automatically.
    #[allow(dead_code)]
    pub exp: u64,
}

// ── JWKS cache entry ──────────────────────────────────────────────────────────

struct JwksCache {
    /// kid → JWK JSON (stored as raw serde_json::Value for key construction).
    keys: HashMap<String, serde_json::Value>,
    expires: Instant,
}

// ── Verifier ──────────────────────────────────────────────────────────────────

/// Verifies Google-signed RS256 ID tokens for the control-plane SA.
///
/// Thread-safe; cheap to clone (Arc-backed).
pub struct IdTokenVerifier {
    http: reqwest::Client,
    enclave_audience: String,
    run_sa_email: String,
    jwks_cache: Mutex<Option<JwksCache>>,
}

impl IdTokenVerifier {
    /// Construct. `enclave_audience` = `ENCLAVE_AUDIENCE` env var value;
    /// `run_sa_email` = `RUN_SA_EMAIL` env var value.
    pub fn new(enclave_audience: String, run_sa_email: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            enclave_audience,
            run_sa_email,
            jwks_cache: Mutex::new(None),
        }
    }

    /// Verify a bearer token as a Google ID token.
    ///
    /// Returns the parsed claims on success, or an error describing why
    /// verification failed.
    pub async fn verify(&self, token: &str) -> Result<GoogleIdClaims> {
        // Decode the header to get the kid — no signature validation yet.
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| EnclaveError::Auth(format!("could not decode JWT header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| EnclaveError::Auth("JWT header missing 'kid'".into()))?;

        // Look up the public key.
        let jwk = self.get_jwk(&kid).await?;

        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            EnclaveError::Auth(format!("failed to build DecodingKey from JWK: {e}"))
        })?;

        // Build validation params.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.enclave_audience]);
        validation.set_issuer(GOOGLE_ISSUERS);
        validation.leeway = EXP_LEEWAY_SECS;

        let token_data = jsonwebtoken::decode::<GoogleIdClaims>(token, &decoding_key, &validation)
            .map_err(|e| EnclaveError::Auth(format!("JWT verification failed: {e}")))?;

        let claims = token_data.claims;

        // Explicit claim checks (belt-and-suspenders on top of jsonwebtoken).
        if claims.email != self.run_sa_email {
            return Err(EnclaveError::Auth(format!(
                "ID token email '{}' does not match expected SA '{}'",
                claims.email, self.run_sa_email
            )));
        }
        if !claims.email_verified {
            return Err(EnclaveError::Auth(
                "ID token email_verified is false".into(),
            ));
        }

        Ok(claims)
    }

    // ── JWKS fetch + cache ────────────────────────────────────────────────────

    async fn get_jwk(&self, kid: &str) -> Result<jsonwebtoken::jwk::Jwk> {
        let mut cache = self.jwks_cache.lock().await;

        // Refresh if cache is missing or expired.
        let refresh = match cache.as_ref() {
            None => true,
            Some(c) => Instant::now() >= c.expires,
        };

        if refresh {
            let new_cache = self.fetch_jwks().await?;
            *cache = Some(new_cache);
        }

        let cache = cache.as_ref().expect("just populated");
        let jwk_value = cache.keys.get(kid).ok_or_else(|| {
            EnclaveError::Auth(format!(
                "no JWK found for kid={kid}; Google may have rotated keys"
            ))
        })?;

        serde_json::from_value(jwk_value.clone())
            .map_err(|e| EnclaveError::Auth(format!("could not parse JWK: {e}")))
    }

    async fn fetch_jwks(&self) -> Result<JwksCache> {
        let resp = self
            .http
            .get(GOOGLE_JWKS_URL)
            .send()
            .await?
            .error_for_status()?;

        // Best-effort parse of Cache-Control max-age.
        let ttl = parse_cache_control_max_age(resp.headers()).unwrap_or(DEFAULT_JWKS_TTL);

        let body: JwksBody = resp.json().await?;

        let mut keys: HashMap<String, serde_json::Value> = HashMap::new();
        for key in body.keys {
            if let Some(kid) = key.get("kid").and_then(|v| v.as_str()) {
                keys.insert(kid.to_owned(), key);
            }
        }

        Ok(JwksCache {
            keys,
            expires: Instant::now() + ttl,
        })
    }
}

// ── JWKS response shape ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JwksBody {
    keys: Vec<serde_json::Value>,
}

// ── Cache-Control parser ──────────────────────────────────────────────────────

/// Extract `max-age=N` from a `Cache-Control` header, if present.
fn parse_cache_control_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
    for part in value.split(',') {
        let part = part.trim();
        if let Some(age_str) = part.strip_prefix("max-age=") {
            if let Ok(secs) = age_str.trim().parse::<u64>() {
                return Some(Duration::from_secs(secs));
            }
        }
    }
    None
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Live probe: reproduces the production ID-token verify path against the
    // REAL Google JWKS + a REAL token. Ignored by default (needs network + a
    // token via env). Run: PROBE_TOKEN=... PROBE_AUD=... PROBE_EMAIL=... \
    //   cargo test verify_probe -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn verify_probe() {
        let token = std::env::var("PROBE_TOKEN").unwrap();
        let aud = std::env::var("PROBE_AUD").unwrap();
        let email = std::env::var("PROBE_EMAIL").unwrap();
        let v = IdTokenVerifier::new(aud, email);
        match v.verify(&token).await {
            Ok(c) => println!("PROBE OK: {c:?}"),
            Err(e) => println!("PROBE ERR (clean, no panic): {e}"),
        }
    }

    #[test]
    fn parse_cache_control_present() {
        let mut map = reqwest::header::HeaderMap::new();
        map.insert(
            reqwest::header::CACHE_CONTROL,
            "public, max-age=3600".parse().unwrap(),
        );
        let ttl = parse_cache_control_max_age(&map);
        assert_eq!(ttl, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn parse_cache_control_no_max_age() {
        let mut map = reqwest::header::HeaderMap::new();
        map.insert(
            reqwest::header::CACHE_CONTROL,
            "no-cache, no-store".parse().unwrap(),
        );
        let ttl = parse_cache_control_max_age(&map);
        assert_eq!(ttl, None);
    }

    #[test]
    fn parse_cache_control_absent() {
        let map = reqwest::header::HeaderMap::new();
        assert_eq!(parse_cache_control_max_age(&map), None);
    }

    /// Verify that a token whose header `kid` does not appear in a populated
    /// (but fake) cache returns an appropriate error.
    #[tokio::test]
    async fn unknown_kid_returns_auth_error() {
        let verifier = IdTokenVerifier::new(
            "http://localhost:8080".to_string(),
            "sa@project.iam.gserviceaccount.com".to_string(),
        );

        // Populate the cache with a fake key under a different kid.
        let fake_cache = JwksCache {
            keys: {
                let mut m = HashMap::new();
                m.insert(
                    "other_kid".to_string(),
                    serde_json::json!({"kid":"other_kid"}),
                );
                m
            },
            expires: Instant::now() + Duration::from_secs(600),
        };
        *verifier.jwks_cache.lock().await = Some(fake_cache);

        let result = verifier.get_jwk("missing_kid").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("missing_kid"),
            "error should mention the kid: {err_msg}"
        );
    }

    /// Verify that an obviously malformed JWT (not three dot-separated parts)
    /// fails at the header-decode step, not inside the KMS or network.
    #[tokio::test]
    async fn malformed_jwt_fails_header_decode() {
        let verifier = IdTokenVerifier::new(
            "http://localhost:8080".to_string(),
            "sa@project.iam.gserviceaccount.com".to_string(),
        );
        let result = verifier.verify("not-a-jwt").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("JWT header"),
            "expected header decode error, got: {err}"
        );
    }

    // ── Forged-token rejection ────────────────────────────────────────────────
    //
    // Build a structurally-valid JWT with correct-looking claims but a bogus
    // signature, and confirm verify() returns an error (never panics, never
    // accepts). With a fake JWK injected into the cache the failure happens at
    // the signature step rather than the network fetch, so the test is
    // deterministic and offline. The full positive crypto round-trip requires
    // a real Google-signed token and is covered by the ignored `verify_probe`
    // integration test above.
    #[tokio::test]
    async fn forged_jwt_with_valid_claims_is_rejected() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let verifier = IdTokenVerifier::new(
            "http://localhost:8080".to_string(),
            "sa@project.iam.gserviceaccount.com".to_string(),
        );

        // Inject a syntactically valid (but unrelated) RSA JWK under the kid
        // the forged token will reference, so verification proceeds to the
        // signature check without any network access.
        let fake_jwk = serde_json::json!({
            "kty": "RSA",
            "kid": "test-kid",
            "use": "sig",
            "alg": "RS256",
            // 2048-bit modulus of a throwaway public key (public material only).
            "n": "urtirVayyldM5CUcLGR1Gn-d3o1VsnU5K5tNrPwbyB3csxvPhsjB03O0Ah9azxCFIUlRvn3-5hApu4QxJ6NBVCOKu2xzVTHcX0fUowUUjFskGOBrMHwGwq56-YnvwRiKOIekz3r4sG1MvpcAulWa0qQQ6i4ZFoODN0-_kmCRMhJNgIXBK9v6G4ZhsRP9AzTmJMqVD19t7Z-MWcDZb6eVwFoZlpV-VatYA43vO4FFxwEUuhgcB-9kURSvufPqwUuXGoPCOvt3z3jN_h9ZDW_ZcmWf-C1RN4FZakZNOjQEE8Onth8yhEbvRqxAnuXeNE-FbH_Rl8lS2_PH7gxuHvWXSw",
            "e": "AQAB"
        });
        let fake_cache = JwksCache {
            keys: {
                let mut m = HashMap::new();
                m.insert("test-kid".to_string(), fake_jwk);
                m
            },
            expires: Instant::now() + Duration::from_secs(600),
        };
        *verifier.jwks_cache.lock().await = Some(fake_cache);

        // Forge a token whose claims would all pass, but whose signature is junk.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use base64::Engine;

        let header_json = r#"{"alg":"RS256","kid":"test-kid","typ":"JWT"}"#;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims_json = format!(
            r#"{{"iss":"https://accounts.google.com","aud":"http://localhost:8080","email":"sa@project.iam.gserviceaccount.com","email_verified":true,"exp":{}}}"#,
            now + 3600
        );
        let header_b64 = B64URL.encode(header_json.as_bytes());
        let claims_b64 = B64URL.encode(claims_json.as_bytes());
        let fake_sig = B64URL.encode(b"fakesignature");
        let fake_jwt = format!("{header_b64}.{claims_b64}.{fake_sig}");

        let result = verifier.verify(&fake_jwt).await;
        assert!(
            result.is_err(),
            "expected verify to reject a forged signature, but got Ok"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("JWT verification failed"),
            "expected signature-verification failure, got: {err}"
        );
    }
}
