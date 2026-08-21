//! Inactive single-archive launcher ownership boundary.
//!
//! This child can be constructed only from one non-cloneable serving
//! handoff: the completed maintenance handoff carrying exact terminal
//! Control/parity evidence, or the genesis-ledger handoff carrying the
//! durable genesis owner reservation over the ledger's exact released
//! terminal. It owns one heterogeneous WAL actor for the archive and accepts
//! only the repository's sealed, already-prepared logical plans. Nothing
//! outside the private WAL-owner family can construct or call it, and it has
//! no startup, route, configuration, Store-registry, acknowledgement,
//! provider-list, provider-delete, deployment, or cloud integration.

use crate::{
    archive_v3_shadow_runtime::WalServingHandoff,
    archive_v3_wal_idempotency::{PreparedLogicalMutation, WalLogicalDomainPlan},
};

use super::{publisher::SingleArchiveWalPublisher, Result, WalOwnerHandle};

/// Sole composition owner for one archive's reviewed logical domains. The
/// actor handle is never exposed, cloned, or split by domain.
pub(super) struct SingleArchiveWalLauncherOwner {
    owner: WalOwnerHandle,
}

impl SingleArchiveWalLauncherOwner {
    pub(super) async fn launch(handoff: WalServingHandoff) -> Result<Self> {
        Ok(Self {
            owner: SingleArchiveWalPublisher::start(handoff).await?,
        })
    }

    pub(super) async fn submit<P: WalLogicalDomainPlan>(
        &self,
        prepared: PreparedLogicalMutation<P>,
    ) -> Result<P::Output> {
        self.owner.submit(prepared).await
    }

    /// Query-only read on the settled authoritative state, serialized behind
    /// every in-flight apply's full settle-advance ladder.
    pub(super) async fn read<F, T>(
        &self,
        read: F,
    ) -> Result<std::result::Result<T, crate::error::EnclaveError>>
    where
        F: FnOnce(&rusqlite::Connection) -> std::result::Result<T, crate::error::EnclaveError>
            + Send
            + 'static,
        T: Send + 'static,
    {
        self.owner.read(read).await
    }

    /// Forwarded relaunch trigger: the actor task's own termination.
    pub(super) fn is_terminal(&self) -> bool {
        self.owner.is_terminal()
    }

    /// Forwarded proof of death. An `Err` means "not provably dead" and must
    /// be quarantined by the caller, never treated as death.
    pub(super) async fn join_terminated(&self, deadline: std::time::Duration) -> Result<()> {
        self.owner.join_terminated(deadline).await
    }

    #[cfg(test)]
    pub(super) async fn terminal_for_relaunch_test() -> Self {
        Self {
            owner: WalOwnerHandle::terminated_for_relaunch_test().await,
        }
    }

    #[cfg(test)]
    pub(super) fn live_for_relaunch_test() -> Self {
        Self {
            owner: WalOwnerHandle::live_for_relaunch_test(),
        }
    }

    #[cfg(test)]
    pub(super) fn stuck_for_relaunch_test() -> (Self, super::StuckLaneRelease) {
        let (owner, release) = WalOwnerHandle::stuck_lane_for_relaunch_test();
        (Self { owner }, release)
    }
}

impl std::fmt::Debug for SingleArchiveWalLauncherOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SingleArchiveWalLauncherOwner(<inactive>)")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn launcher_surface_stays_private_and_inactive() {
        let source = include_str!("launcher.rs");
        for required in [
            "pub(super) struct SingleArchiveWalLauncherOwner",
            "WalServingHandoff",
            "SingleArchiveWalPublisher::start(handoff)",
            "pub(super) async fn submit<P: WalLogicalDomainPlan>",
            // The relaunch trigger and its proof of death are forwarded, not
            // reimplemented: this child must never grow its own launch path.
            "pub(super) fn is_terminal(&self) -> bool",
            "pub(super) async fn join_terminated(&self, deadline: std::time::Duration)",
            "self.owner.is_terminal()",
            "self.owner.join_terminated(deadline)",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        for forbidden in [
            concat!("pub(crate) struct SingleArchiveWal", "LauncherOwner"),
            concat!("impl Clone", " for SingleArchiveWalLauncherOwner"),
            concat!("Store::", "new"),
            concat!("list_", "objects"),
            concat!("delete_", "exact"),
            concat!("std::env", "::var"),
            concat!("crate::", "main"),
        ] {
            assert!(!source.contains(forbidden), "found forbidden {forbidden}");
        }
    }
}
