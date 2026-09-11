use async_trait::async_trait;

use crate::error::Result;

/// Durable, database-authoritative topology-writer state.
///
/// `Preactive` means the additive v27 contract has not been installed. Once an
/// account has an assignment, finalization remains reconciliation-only in
/// every later phase, including `Paused`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemoryReconciliationActivationPhase {
    Preactive,
    Installed,
    Draining,
    Active,
    Paused,
}

impl MemoryReconciliationActivationPhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Preactive => "preactive",
            Self::Installed => "installed",
            Self::Draining => "draining",
            Self::Active => "active",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MemoryReconciliationActivationStatus {
    pub(crate) phase: MemoryReconciliationActivationPhase,
    pub(crate) generation: i64,
    pub(crate) rollout_basis_points: i64,
    pub(crate) explicit_canary_accounts: usize,
    pub(crate) assigned_accounts: i64,
    pub(crate) formation_backfill_generation: Option<i64>,
    pub(crate) formation_backfill_complete: bool,
    pub(crate) finalization_claim_drain_complete: bool,
    pub(crate) receipt_sha256: Option<String>,
    pub(crate) contract_version: Option<u32>,
    pub(crate) candidate_fleet_image_digest: Option<String>,
    pub(crate) reconciliation_producer_contract_sha256: Option<String>,
    pub(crate) reconciliation_model: Option<String>,
    pub(crate) vertex_location: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActiveReconciliationAuthority {
    pub(crate) generation: i64,
    pub(crate) producer_contract_sha256: Vec<u8>,
    pub(crate) reconciliation_model: String,
    pub(crate) vertex_location: String,
}

/// The reconciliation producer this process actually runs: the compiled
/// producer contract plus the configured model and location. Serving registers
/// it once at startup (ADR-0046). The signed activation authority records the
/// producer that was signed when reconciliation was activated; that is history
/// and the pause kill switch, not the release authority for the running
/// producer, which is the reviewed image digest pinned by the deployment
/// repository. Claims, provider attempts, stages, and publication bind the
/// registered runtime producer so every replica of one image agrees with itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeReconciliationProducer {
    pub(crate) producer_contract_sha256: Vec<u8>,
    pub(crate) reconciliation_model: String,
    pub(crate) vertex_location: String,
}

impl RuntimeReconciliationProducer {
    /// The `sha256:<hex>` label of the registered producer contract.
    pub(crate) fn producer_contract_label(&self) -> String {
        use std::fmt::Write as _;
        let mut label = String::with_capacity(7 + self.producer_contract_sha256.len() * 2);
        label.push_str("sha256:");
        for byte in &self.producer_contract_sha256 {
            let _ = write!(&mut label, "{byte:02x}");
        }
        label
    }
}

#[async_trait]
pub(crate) trait MemoryReconciliationActivationRepository: Send + Sync {
    /// Returns a verified, content-free projection of the append-only
    /// activation chain. It never treats a process-local flag as authority.
    async fn memory_reconciliation_activation_status(
        &self,
    ) -> Result<MemoryReconciliationActivationStatus>;
}
