//! Inactive nonce-bound Confidential Space claim production for the Phase-1 canary.
//!
//! The Phase-1 GO packet requires a **fresh nonce-bound Confidential Space claim**
//! proving the exact image digest and workload identity to the independent
//! image-attestation custodian. This module supplies the in-enclave half:
//! - [`derive_phase1_challenge_nonce`] deterministically derives the exact claim
//!   nonce from the live [`HeldPhase1Window`]'s scope-challenge commitment and
//!   maintenance-window ID (domain-separated SHA-256, lowercase hex). The custodian
//!   recomputes the same nonce from the signed runtime-admission facts, so a claim
//!   minted for any other window or challenge cannot satisfy the packet.
//! - [`Phase1ClaimProducer`] is the injectable launcher seam; the concrete
//!   [`LauncherPhase1ClaimProducer`] wraps the existing hardened public
//!   [`AttestationCache`] (https-only, WIF-audience-refusing, launcher-socket
//!   protocol with zeroizing intermediates). Its constructor takes the custodian's
//!   verifier audience as an explicit argument — there is no configuration,
//!   environment, or startup source in this slice, so nothing can construct it in
//!   production until the separately reviewed activation change supplies the
//!   reviewed audience.
//! - [`Phase1AttestationClaimEvidence`] carries the raw claim only in zeroizing
//!   storage for custodian export, is Debug-opaque, and exposes a content-free
//!   commitment (domain-separated SHA-256 over audience, nonce, and claim bytes)
//!   for Control rows and telemetry.
//!
//! No route, worker, config, credential, or startup wiring exists. The launcher
//! socket path is exercised only inside the enclave during the Phase-1 drills.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{window::HeldPhase1Window, AdvisoryOwnerError, Result};
use crate::attestation::AttestationCache;

const PHASE1_CLAIM_NONCE_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-claim-nonce/v1\0";
const PHASE1_CLAIM_EVIDENCE_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-claim-evidence/v1\0";

/// Derive the exact nonce the image-attestation custodian expects for this window.
pub(crate) fn derive_phase1_challenge_nonce(window: &HeldPhase1Window) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PHASE1_CLAIM_NONCE_DOMAIN);
    hasher.update(window.challenge_commitment());
    hasher.update(window.maintenance_window_id());
    let digest = hasher.finalize();
    let mut nonce = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut nonce, "{byte:02x}");
    }
    nonce
}

/// Injectable producer of one nonce-bound Confidential Space OIDC claim.
#[async_trait::async_trait]
pub(crate) trait Phase1ClaimProducer: Send + Sync {
    async fn produce_claim(&self, nonce: &str) -> Result<Zeroizing<String>>;
}

/// Concrete producer over the hardened launcher-socket attestation path. The
/// audience must be the image-attestation custodian's public verifier URL; the
/// wrapped [`AttestationCache`] refuses non-https and WIF-provider audiences.
pub(crate) struct LauncherPhase1ClaimProducer {
    cache: AttestationCache,
}

impl std::fmt::Debug for LauncherPhase1ClaimProducer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LauncherPhase1ClaimProducer(<opaque>)")
    }
}

impl LauncherPhase1ClaimProducer {
    /// Construct for the custodian's reviewed verifier audience. No production
    /// caller exists in this slice: the audience arrives only with the separately
    /// reviewed activation change, so this cannot run outside the Phase-1 drills.
    pub(crate) fn for_custodian_audience(audience: String) -> Result<Self> {
        let cache = AttestationCache::new(audience).map_err(|_| AdvisoryOwnerError::Conflict)?;
        Ok(Self { cache })
    }
}

#[async_trait::async_trait]
impl Phase1ClaimProducer for LauncherPhase1ClaimProducer {
    async fn produce_claim(&self, nonce: &str) -> Result<Zeroizing<String>> {
        self.cache
            .get_token(nonce)
            .await
            .map(Zeroizing::new)
            .map_err(|_| AdvisoryOwnerError::Persistence)
    }
}

/// One produced claim, bound to its exact window nonce, held zeroizing for
/// custodian export with a content-free commitment for Control and telemetry.
pub(crate) struct Phase1AttestationClaimEvidence {
    claim: Zeroizing<String>,
    nonce: String,
    commitment: [u8; 32],
}

impl std::fmt::Debug for Phase1AttestationClaimEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Phase1AttestationClaimEvidence(<opaque>)")
    }
}

impl Phase1AttestationClaimEvidence {
    /// Produce one claim for the live window through the supplied producer. The
    /// nonce is derived, never caller-chosen, so a claim can only ever bind to the
    /// exact held window.
    pub(crate) async fn produce_for_window(
        window: &HeldPhase1Window,
        producer: &dyn Phase1ClaimProducer,
        custodian_audience_commitment: [u8; 32],
    ) -> Result<Self> {
        if custodian_audience_commitment == [0; 32] {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let nonce = derive_phase1_challenge_nonce(window);
        let claim = producer.produce_claim(&nonce).await?;
        if claim.is_empty() {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let mut hasher = Sha256::new();
        hasher.update(PHASE1_CLAIM_EVIDENCE_DOMAIN);
        hasher.update(custodian_audience_commitment);
        hasher.update((nonce.len() as u32).to_be_bytes());
        hasher.update(nonce.as_bytes());
        hasher.update((claim.len() as u32).to_be_bytes());
        hasher.update(claim.as_bytes());
        let commitment = hasher.finalize().into();
        Ok(Self {
            claim,
            nonce,
            commitment,
        })
    }

    /// Content-free commitment for Control rows and telemetry.
    pub(crate) const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub(crate) fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The raw claim for custodian export only. Callers must not log or persist it
    /// outside the GO-packet export channel.
    pub(crate) fn claim_for_custodian_export(&self) -> &Zeroizing<String> {
        &self.claim
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn make_window() -> HeldPhase1Window {
        HeldPhase1Window::new(
            [0x11; 16], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32], [0x77; 32],
            1_000, 2_000,
        )
        .unwrap()
    }

    struct RecordingProducer {
        nonces: Mutex<Vec<String>>,
        claim: String,
    }

    #[async_trait::async_trait]
    impl Phase1ClaimProducer for RecordingProducer {
        async fn produce_claim(&self, nonce: &str) -> Result<Zeroizing<String>> {
            self.nonces.lock().unwrap().push(nonce.to_string());
            Ok(Zeroizing::new(self.claim.clone()))
        }
    }

    #[test]
    fn nonce_derivation_is_deterministic_and_window_exact() {
        let window = make_window();
        let nonce = derive_phase1_challenge_nonce(&window);
        assert_eq!(nonce.len(), 64);
        assert_eq!(nonce, derive_phase1_challenge_nonce(&window));

        // A different challenge commitment yields a different nonce.
        let other = HeldPhase1Window::new(
            [0x11; 16], [0x22; 32], [0x33; 32], [0x99; 32], [0x55; 32], [0x66; 32], [0x77; 32],
            1_000, 2_000,
        )
        .unwrap();
        assert_ne!(nonce, derive_phase1_challenge_nonce(&other));

        // A different window ID also yields a different nonce.
        let other_window_id = HeldPhase1Window::new(
            [0x12; 16], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32], [0x77; 32],
            1_000, 2_000,
        )
        .unwrap();
        assert_ne!(nonce, derive_phase1_challenge_nonce(&other_window_id));
    }

    #[tokio::test]
    async fn evidence_binds_derived_nonce_and_commits_content_free() {
        let window = make_window();
        let producer = RecordingProducer {
            nonces: Mutex::new(Vec::new()),
            claim: "header.payload.signature".to_string(),
        };
        let evidence =
            Phase1AttestationClaimEvidence::produce_for_window(&window, &producer, [0xAB; 32])
                .await
                .unwrap();

        // The producer received exactly the derived nonce; it is never caller-chosen.
        {
            let seen = producer.nonces.lock().unwrap();
            assert_eq!(seen.as_slice(), [derive_phase1_challenge_nonce(&window)]);
        }
        assert_eq!(evidence.nonce(), derive_phase1_challenge_nonce(&window));

        assert_ne!(evidence.commitment(), [0; 32]);
        assert_eq!(
            evidence.claim_for_custodian_export().as_str(),
            "header.payload.signature"
        );
        assert_eq!(
            format!("{evidence:?}"),
            "Phase1AttestationClaimEvidence(<opaque>)"
        );

        // Zero audience commitment and empty claims fail closed.
        assert!(
            Phase1AttestationClaimEvidence::produce_for_window(&window, &producer, [0; 32])
                .await
                .is_err()
        );
        let empty = RecordingProducer {
            nonces: Mutex::new(Vec::new()),
            claim: String::new(),
        };
        assert!(matches!(
            Phase1AttestationClaimEvidence::produce_for_window(&window, &empty, [0xAB; 32]).await,
            Err(AdvisoryOwnerError::Corrupt)
        ));
    }

    #[test]
    fn launcher_producer_refuses_invalid_audiences() {
        // Non-https audience.
        assert!(
            LauncherPhase1ClaimProducer::for_custodian_audience("http://verifier".into()).is_err()
        );
        // WIF provider audiences are bearer-credential audiences and are refused.
        assert!(LauncherPhase1ClaimProducer::for_custodian_audience(
            "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x"
                .into()
        )
        .is_err());
        // A well-formed public verifier audience constructs (no I/O happens here).
        assert!(LauncherPhase1ClaimProducer::for_custodian_audience(
            "https://verifier.example/phase1".into()
        )
        .is_ok());
    }
}
