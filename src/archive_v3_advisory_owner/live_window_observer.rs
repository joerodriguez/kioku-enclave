//! Inactive live deployment-window observer for the Phase-1 advisory canary.
//!
//! Implements [`Phase1WindowObserver`] by verifying **signed window observations**
//! produced by the independent deployment-observer custodian (the third canary trust
//! root) instead of trusting any process-local clock or unauthenticated API response:
//! - Every observation is a fixed-format, domain-separated, Ed25519-signed statement
//!   naming the exact maintenance window, window-intent commitment, scope challenge
//!   commitment, zero-serving-replica witness digest, observer sequence, and the
//!   custodian's trusted timestamp ticks.
//! - Verification binds the observation to the live [`HeldPhase1Window`]'s exact
//!   coordinates — including the challenge commitment, which the held window's own
//!   revalidation check does not cover — before the sealed proof is minted; monotonic
//!   sequence and timestamp enforcement then happen inside the held window's atomics.
//! - The production constructor takes its verifying root only from the pinned canary
//!   trust set, whose deployment-observer key is deliberately an invalid zero root
//!   until the separately reviewed activation change lands, so this observer is
//!   **unconstructible in production today** and fails closed rather than dormant.
//! - The observation transport is an injectable source seam with no production
//!   implementation in this slice: no HTTP client, credential, endpoint, or startup
//!   wiring exists. A reviewed concrete source arrives with the cloud-resource
//!   activation change.

use std::sync::Arc;

use async_trait::async_trait;

use super::{
    canary_trust,
    window::{HeldPhase1Window, Phase1WindowObserver, VerifiedWindowRevalidation},
    AdvisoryOwnerError, Result,
};

const WINDOW_OBSERVATION_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-window-observation/v1\0";
const WINDOW_OBSERVATION_FORMAT_V1: u16 = 1;
const WINDOW_OBSERVATION_BYTES: usize = 2 + 16 + 32 + 32 + 32 + 8 + 8;
const ED25519_SIGNATURE_BYTES: usize = 64;

/// One signed observation document as produced by the deployment-observer custodian.
/// Payload bytes are the exact signed message body; the signature covers the
/// domain-separated payload.
pub(crate) struct SignedWindowObservation {
    pub(crate) payload: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

impl std::fmt::Debug for SignedWindowObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignedWindowObservation(<opaque>)")
    }
}

/// Injectable source of the latest signed window observation. No production
/// implementation exists in this slice; the reviewed concrete transport lands with
/// the cloud-resource activation change.
#[async_trait]
pub(crate) trait SignedWindowObservationSource: Send + Sync {
    async fn fetch_latest(&self) -> Result<SignedWindowObservation>;
}

/// Live window observer verifying custodian-signed observations against the pinned
/// deployment-observer trust root.
pub(crate) struct LiveDeploymentWindowObserver {
    observer_root: [u8; 32],
    source: Arc<dyn SignedWindowObservationSource>,
}

impl std::fmt::Debug for LiveDeploymentWindowObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LiveDeploymentWindowObserver(<opaque>)")
    }
}

impl LiveDeploymentWindowObserver {
    /// Production constructor: the verifying key is exactly the pinned
    /// deployment-observer root. While the pinned roots remain deliberately invalid
    /// zero roots, this constructor fails closed and the observer cannot exist.
    pub(crate) fn from_pinned_root(source: Arc<dyn SignedWindowObservationSource>) -> Result<Self> {
        Ok(Self {
            observer_root: canary_trust::pinned_deployment_observer_root()?,
            source,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_root_for_test(
        observer_root: [u8; 32],
        source: Arc<dyn SignedWindowObservationSource>,
    ) -> Self {
        Self {
            observer_root,
            source,
        }
    }

    fn parse_and_verify(
        &self,
        window: &HeldPhase1Window,
        observation: &SignedWindowObservation,
    ) -> Result<(u64, [u8; 32], u64)> {
        if observation.signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let bytes: &[u8; WINDOW_OBSERVATION_BYTES] = observation
            .payload
            .as_slice()
            .try_into()
            .map_err(|_| AdvisoryOwnerError::Corrupt)?;
        if u16::from_be_bytes([bytes[0], bytes[1]]) != WINDOW_OBSERVATION_FORMAT_V1 {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        // Signature first: no field of an unauthenticated payload is compared.
        canary_trust::verify_observer_signature(
            &self.observer_root,
            WINDOW_OBSERVATION_DOMAIN,
            &observation.payload,
            &observation.signature,
        )?;

        let maintenance_window_id: [u8; 16] = bytes[2..18]
            .try_into()
            .map_err(|_| AdvisoryOwnerError::Corrupt)?;
        let intent_commitment: [u8; 32] = bytes[18..50]
            .try_into()
            .map_err(|_| AdvisoryOwnerError::Corrupt)?;
        let challenge_commitment: [u8; 32] = bytes[50..82]
            .try_into()
            .map_err(|_| AdvisoryOwnerError::Corrupt)?;
        let zero_replica_witness_digest: [u8; 32] = bytes[82..114]
            .try_into()
            .map_err(|_| AdvisoryOwnerError::Corrupt)?;
        let sequence = u64::from_be_bytes(
            bytes[114..122]
                .try_into()
                .map_err(|_| AdvisoryOwnerError::Corrupt)?,
        );
        let timestamp_ticks = u64::from_be_bytes(
            bytes[122..130]
                .try_into()
                .map_err(|_| AdvisoryOwnerError::Corrupt)?,
        );

        // Exact binding to the live held window, including the scope challenge the
        // held window's own revalidation check does not re-verify.
        if maintenance_window_id != window.maintenance_window_id()
            || intent_commitment != window.intent_commitment()
            || challenge_commitment != window.challenge_commitment()
            || zero_replica_witness_digest == [0; 32]
            || zero_replica_witness_digest != window.expected_zero_replica_digest()
            || sequence == 0
            || timestamp_ticks < window.window_start_ticks()
            || timestamp_ticks > window.window_end_ticks()
        {
            return Err(AdvisoryOwnerError::Conflict);
        }

        Ok((sequence, zero_replica_witness_digest, timestamp_ticks))
    }
}

#[async_trait]
impl Phase1WindowObserver for LiveDeploymentWindowObserver {
    async fn revalidate_window(
        &self,
        window: &HeldPhase1Window,
    ) -> Result<VerifiedWindowRevalidation> {
        let observation = self.source.fetch_latest().await?;
        let (sequence, zero_replica_witness_digest, timestamp_ticks) =
            self.parse_and_verify(window, &observation)?;
        VerifiedWindowRevalidation::mint_for_verified_observer(
            window,
            sequence,
            zero_replica_witness_digest,
            timestamp_ticks,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::sync::Mutex;

    fn observer_key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn public_root(key: &Ed25519KeyPair) -> [u8; 32] {
        key.public_key().as_ref().try_into().unwrap()
    }

    fn make_window() -> HeldPhase1Window {
        HeldPhase1Window::new(
            [0x11; 16], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32], [0x77; 32],
            1_000, 2_000,
        )
        .unwrap()
    }

    fn encode_observation(
        window: &HeldPhase1Window,
        sequence: u64,
        timestamp_ticks: u64,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(WINDOW_OBSERVATION_BYTES);
        payload.extend_from_slice(&WINDOW_OBSERVATION_FORMAT_V1.to_be_bytes());
        payload.extend_from_slice(&window.maintenance_window_id());
        payload.extend_from_slice(&window.intent_commitment());
        payload.extend_from_slice(&window.challenge_commitment());
        payload.extend_from_slice(&window.expected_zero_replica_digest());
        payload.extend_from_slice(&sequence.to_be_bytes());
        payload.extend_from_slice(&timestamp_ticks.to_be_bytes());
        payload
    }

    fn sign(key: &Ed25519KeyPair, payload: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(WINDOW_OBSERVATION_DOMAIN.len() + payload.len());
        message.extend_from_slice(WINDOW_OBSERVATION_DOMAIN);
        message.extend_from_slice(payload);
        key.sign(&message).as_ref().to_vec()
    }

    struct QueueSource {
        queue: Mutex<Vec<SignedWindowObservation>>,
    }

    impl QueueSource {
        fn of(observations: Vec<SignedWindowObservation>) -> Arc<Self> {
            Arc::new(Self {
                queue: Mutex::new(observations),
            })
        }
    }

    #[async_trait]
    impl SignedWindowObservationSource for QueueSource {
        async fn fetch_latest(&self) -> Result<SignedWindowObservation> {
            self.queue
                .lock()
                .unwrap()
                .pop()
                .ok_or(AdvisoryOwnerError::Persistence)
        }
    }

    fn observation(
        key: &Ed25519KeyPair,
        window: &HeldPhase1Window,
        sequence: u64,
        timestamp_ticks: u64,
    ) -> SignedWindowObservation {
        let payload = encode_observation(window, sequence, timestamp_ticks);
        let signature = sign(key, &payload);
        SignedWindowObservation { payload, signature }
    }

    #[tokio::test]
    async fn verifies_exactly_bound_signed_observation_and_enforces_monotonic_sequence() {
        let key = observer_key(0x0A);
        let window = make_window();
        let source = QueueSource::of(vec![
            observation(&key, &window, 2, 1_600),
            observation(&key, &window, 1, 1_500),
        ]);
        let observer = LiveDeploymentWindowObserver::with_root_for_test(public_root(&key), source);

        let proof = observer.revalidate_window(&window).await.unwrap();
        assert_eq!(proof.sequence(), 1);
        window.verify_revalidation_proof(&proof).unwrap();

        let proof2 = observer.revalidate_window(&window).await.unwrap();
        assert_eq!(proof2.sequence(), 2);
        window.verify_revalidation_proof(&proof2).unwrap();

        // Replaying the already-consumed sequence fails at the held window.
        assert!(window.verify_revalidation_proof(&proof).is_err());
    }

    #[tokio::test]
    async fn rejects_signature_root_and_format_violations() {
        let key = observer_key(0x0B);
        let wrong_key = observer_key(0x0C);
        let window = make_window();

        // Wrong signing key.
        let source = QueueSource::of(vec![observation(&wrong_key, &window, 1, 1_500)]);
        let observer = LiveDeploymentWindowObserver::with_root_for_test(public_root(&key), source);
        assert!(matches!(
            observer.revalidate_window(&window).await,
            Err(AdvisoryOwnerError::Conflict)
        ));

        // Tampered payload byte after signing.
        let mut tampered = observation(&key, &window, 1, 1_500);
        tampered.payload[30] ^= 0xFF;
        let observer = LiveDeploymentWindowObserver::with_root_for_test(
            public_root(&key),
            QueueSource::of(vec![tampered]),
        );
        assert!(observer.revalidate_window(&window).await.is_err());

        // Truncated payload.
        let mut short = observation(&key, &window, 1, 1_500);
        short.payload.truncate(WINDOW_OBSERVATION_BYTES - 1);
        let observer = LiveDeploymentWindowObserver::with_root_for_test(
            public_root(&key),
            QueueSource::of(vec![short]),
        );
        assert!(matches!(
            observer.revalidate_window(&window).await,
            Err(AdvisoryOwnerError::Corrupt)
        ));

        // Wrong format version, correctly signed.
        let mut wrong_format = encode_observation(&window, 1, 1_500);
        wrong_format[0..2].copy_from_slice(&2u16.to_be_bytes());
        let signature = sign(&key, &wrong_format);
        let observer = LiveDeploymentWindowObserver::with_root_for_test(
            public_root(&key),
            QueueSource::of(vec![SignedWindowObservation {
                payload: wrong_format,
                signature,
            }]),
        );
        assert!(matches!(
            observer.revalidate_window(&window).await,
            Err(AdvisoryOwnerError::Corrupt)
        ));
    }

    #[tokio::test]
    async fn rejects_observations_bound_to_other_windows_or_stale_time() {
        let key = observer_key(0x0D);
        let window = make_window();

        // Different window (different challenge commitment) signed by the right key.
        let other_window = HeldPhase1Window::new(
            [0x11; 16], [0x22; 32], [0x33; 32], [0x99; 32], // different challenge
            [0x55; 32], [0x66; 32], [0x77; 32], 1_000, 2_000,
        )
        .unwrap();
        let observer = LiveDeploymentWindowObserver::with_root_for_test(
            public_root(&key),
            QueueSource::of(vec![observation(&key, &other_window, 1, 1_500)]),
        );
        assert!(matches!(
            observer.revalidate_window(&window).await,
            Err(AdvisoryOwnerError::Conflict)
        ));

        // Timestamp outside the window bounds.
        let observer = LiveDeploymentWindowObserver::with_root_for_test(
            public_root(&key),
            QueueSource::of(vec![observation(&key, &window, 1, 2_001)]),
        );
        assert!(matches!(
            observer.revalidate_window(&window).await,
            Err(AdvisoryOwnerError::Conflict)
        ));

        // Zero sequence.
        let observer = LiveDeploymentWindowObserver::with_root_for_test(
            public_root(&key),
            QueueSource::of(vec![observation(&key, &window, 0, 1_500)]),
        );
        assert!(matches!(
            observer.revalidate_window(&window).await,
            Err(AdvisoryOwnerError::Conflict)
        ));
    }

    #[tokio::test]
    async fn production_constructor_verifies_against_the_real_pinned_root() {
        // Real solo-operator roots are pinned (docs/adr/0022-solo-operator-activation.md),
        // so the production constructor now succeeds — and must verify observations
        // against exactly that pinned root: a well-formed observation signed by any
        // other key is rejected. (The real private key never enters this repository,
        // so a positive-path signature check is impossible here by design.)
        let window = make_window();
        let wrong_key = observer_key(0x5A);
        let observer =
            LiveDeploymentWindowObserver::from_pinned_root(QueueSource::of(vec![observation(
                &wrong_key, &window, 1, 1_500,
            )]))
            .expect("pinned deployment-observer root is real and nonzero");
        assert!(matches!(
            observer.revalidate_window(&window).await,
            Err(AdvisoryOwnerError::Conflict)
        ));
    }
}
