//! Live trusted observer and continuous window validation for Phase-1 advisory canary.
//!
//! Enforces:
//! - Pre-import window intent verification.
//! - Non-cloneable `HeldPhase1Window` tracking exact window coordinates.
//! - Continuous live zero-serving and window validity revalidation across import,
//!   handoff, owner reservation, fence release, local admission resumption, and settlement.
//! - Strict matching between pre-import window intent and post-import 3-root authorization.

use sha2::{Digest, Sha256};

use super::{AdvisoryOwnerError, Result, VerifiedAdvisoryCanaryAuthorization};

const WINDOW_INTENT_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-window-intent/v1\0";

/// Non-cloneable token holding verified Phase-1 maintenance window coordinates.
#[derive(Debug)]
pub(crate) struct HeldPhase1Window {
    maintenance_window_id: [u8; 16],
    deployment_target_commitment: [u8; 32],
    deployment_revision_commitment: [u8; 32],
    challenge_commitment: [u8; 32],
    monitoring_policy_commitment: [u8; 32],
    rollback_policy_commitment: [u8; 32],
    intent_commitment: [u8; 32],
    expected_zero_replica_digest: [u8; 32],
    window_start_ticks: u64,
    window_end_ticks: u64,
    last_verified_sequence: std::sync::atomic::AtomicU64,
    last_verified_timestamp_ticks: std::sync::atomic::AtomicU64,
}

impl HeldPhase1Window {
    /// Construct a verified window token from non-zero coordinates and window validity bounds.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        maintenance_window_id: [u8; 16],
        deployment_target_commitment: [u8; 32],
        deployment_revision_commitment: [u8; 32],
        challenge_commitment: [u8; 32],
        monitoring_policy_commitment: [u8; 32],
        rollback_policy_commitment: [u8; 32],
        expected_zero_replica_digest: [u8; 32],
        window_start_ticks: u64,
        window_end_ticks: u64,
    ) -> Result<Self> {
        if maintenance_window_id == [0; 16]
            || deployment_target_commitment == [0; 32]
            || deployment_revision_commitment == [0; 32]
            || challenge_commitment == [0; 32]
            || monitoring_policy_commitment == [0; 32]
            || rollback_policy_commitment == [0; 32]
            || expected_zero_replica_digest == [0; 32]
            || window_start_ticks == 0
            || window_end_ticks <= window_start_ticks
        {
            return Err(AdvisoryOwnerError::Conflict);
        }

        let mut hasher = Sha256::new();
        hasher.update(WINDOW_INTENT_DOMAIN);
        hasher.update(maintenance_window_id);
        hasher.update(deployment_target_commitment);
        hasher.update(deployment_revision_commitment);
        hasher.update(challenge_commitment);
        hasher.update(monitoring_policy_commitment);
        hasher.update(rollback_policy_commitment);
        let intent_commitment = hasher.finalize().into();

        Ok(Self {
            maintenance_window_id,
            deployment_target_commitment,
            deployment_revision_commitment,
            challenge_commitment,
            monitoring_policy_commitment,
            rollback_policy_commitment,
            intent_commitment,
            expected_zero_replica_digest,
            window_start_ticks,
            window_end_ticks,
            last_verified_sequence: std::sync::atomic::AtomicU64::new(0),
            last_verified_timestamp_ticks: std::sync::atomic::AtomicU64::new(window_start_ticks),
        })
    }

    pub(crate) const fn maintenance_window_id(&self) -> [u8; 16] {
        self.maintenance_window_id
    }

    pub(crate) const fn intent_commitment(&self) -> [u8; 32] {
        self.intent_commitment
    }

    pub(crate) const fn deployment_target_commitment(&self) -> [u8; 32] {
        self.deployment_target_commitment
    }

    pub(crate) const fn challenge_commitment(&self) -> [u8; 32] {
        self.challenge_commitment
    }

    pub(crate) const fn expected_zero_replica_digest(&self) -> [u8; 32] {
        self.expected_zero_replica_digest
    }

    pub(crate) const fn window_start_ticks(&self) -> u64 {
        self.window_start_ticks
    }

    pub(crate) const fn window_end_ticks(&self) -> u64 {
        self.window_end_ticks
    }

    /// Match this live held window against a post-import 3-root verified authorization.
    pub(crate) fn verify_matches_authorization(
        &self,
        authorization: &VerifiedAdvisoryCanaryAuthorization,
    ) -> Result<()> {
        authorization.verify_matches_window(
            &self.maintenance_window_id,
            &self.deployment_target_commitment,
            &self.deployment_revision_commitment,
            &self.challenge_commitment,
            &self.monitoring_policy_commitment,
            &self.rollback_policy_commitment,
        )
    }

    /// Match this live held window against a verified revalidation proof, enforcing
    /// monotonic sequence, trusted timestamp freshness within window bounds, non-zero
    /// zero-replica witness digest match, and exact window ID/intent coordinates.
    pub(crate) fn verify_revalidation_proof(
        &self,
        proof: &VerifiedWindowRevalidation,
    ) -> Result<()> {
        if proof.maintenance_window_id != self.maintenance_window_id
            || proof.intent_commitment != self.intent_commitment
            || proof.zero_replica_witness_digest == [0; 32]
            || proof.zero_replica_witness_digest != self.expected_zero_replica_digest
            || proof.timestamp_ticks < self.window_start_ticks
            || proof.timestamp_ticks > self.window_end_ticks
        {
            return Err(AdvisoryOwnerError::Conflict);
        }

        let last_seq = self
            .last_verified_sequence
            .load(std::sync::atomic::Ordering::SeqCst);
        if proof.sequence <= last_seq {
            return Err(AdvisoryOwnerError::Conflict);
        }

        let last_ts = self
            .last_verified_timestamp_ticks
            .load(std::sync::atomic::Ordering::SeqCst);
        if proof.timestamp_ticks < last_ts {
            return Err(AdvisoryOwnerError::Conflict);
        }

        self.last_verified_sequence
            .store(proof.sequence, std::sync::atomic::Ordering::SeqCst);
        self.last_verified_timestamp_ticks
            .store(proof.timestamp_ticks, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Non-cloneable proof of successful live window and zero-replica revalidation.
/// Construction is strictly private and authenticated against exact window coordinates,
/// freshness timestamp, monotonic sequence counter, and zero-replica witness digest.
#[derive(Debug)]
pub(crate) struct VerifiedWindowRevalidation {
    maintenance_window_id: [u8; 16],
    intent_commitment: [u8; 32],
    sequence: u64,
    zero_replica_witness_digest: [u8; 32],
    timestamp_ticks: u64,
}

impl VerifiedWindowRevalidation {
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn zero_replica_witness_digest(&self) -> [u8; 32] {
        self.zero_replica_witness_digest
    }

    pub(crate) const fn timestamp_ticks(&self) -> u64 {
        self.timestamp_ticks
    }

    pub(super) fn mint_for_verified_observer(
        window: &HeldPhase1Window,
        sequence: u64,
        zero_replica_witness_digest: [u8; 32],
        timestamp_ticks: u64,
    ) -> Result<Self> {
        if zero_replica_witness_digest == [0; 32] || timestamp_ticks == 0 {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(Self {
            maintenance_window_id: window.maintenance_window_id(),
            intent_commitment: window.intent_commitment(),
            sequence,
            zero_replica_witness_digest,
            timestamp_ticks,
        })
    }
}

/// Live trusted observer verifying ongoing maintenance window validity and zero serving replicas.
#[async_trait::async_trait]
pub(crate) trait Phase1WindowObserver: Send + Sync {
    /// Revalidate that the maintenance window is active, trusted time is within bounds,
    /// and zero serving replicas are running.
    async fn revalidate_window(
        &self,
        window: &HeldPhase1Window,
    ) -> Result<VerifiedWindowRevalidation>;
}

/// In-memory window observer for testing.
#[cfg(test)]
pub(crate) struct TestPhase1WindowObserver {
    should_fail: std::sync::atomic::AtomicBool,
    sequence: std::sync::atomic::AtomicU64,
    timestamp: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl TestPhase1WindowObserver {
    pub(crate) fn new() -> Self {
        Self {
            should_fail: std::sync::atomic::AtomicBool::new(false),
            sequence: std::sync::atomic::AtomicU64::new(1),
            timestamp: std::sync::atomic::AtomicU64::new(1_700_000_000),
        }
    }

    pub(crate) fn with_failing_revalidation() -> Self {
        Self {
            should_fail: std::sync::atomic::AtomicBool::new(true),
            sequence: std::sync::atomic::AtomicU64::new(1),
            timestamp: std::sync::atomic::AtomicU64::new(1_700_000_000),
        }
    }

    pub(crate) fn set_should_fail(&self, fail: bool) {
        self.should_fail
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl Phase1WindowObserver for TestPhase1WindowObserver {
    async fn revalidate_window(
        &self,
        window: &HeldPhase1Window,
    ) -> Result<VerifiedWindowRevalidation> {
        if self.should_fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let ts = self
            .timestamp
            .fetch_add(10, std::sync::atomic::Ordering::SeqCst);
        VerifiedWindowRevalidation::mint_for_verified_observer(
            window,
            seq,
            window.expected_zero_replica_digest(),
            ts,
        )
    }
}
