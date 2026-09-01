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

#[async_trait]
pub(crate) trait MemoryReconciliationActivationRepository: Send + Sync {
    /// Returns a verified, content-free projection of the append-only
    /// activation chain. It never treats a process-local flag as authority.
    async fn memory_reconciliation_activation_status(
        &self,
    ) -> Result<MemoryReconciliationActivationStatus>;
}
