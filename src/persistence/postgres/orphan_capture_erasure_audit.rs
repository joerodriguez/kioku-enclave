//! Metadata-only erasure gates, read inside the aggregate audit's existing
//! repeatable-read/read-only snapshot. No account or source identifier escapes.

use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};

use crate::error::Result;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OrphanErasureAudit {
    pub(crate) schema_installed: bool,
    pub(crate) pending_operations: i64,
    pub(crate) provider_verified_operations: i64,
    pub(crate) complete_fenced_operations: i64,
    pub(crate) released_operations: i64,
    pub(crate) inventory_objects: i64,
    pub(crate) coherence_violations: i64,
}

impl OrphanErasureAudit {
    pub(super) fn quiescent(&self) -> bool {
        self.pending_operations == 0
            && self.provider_verified_operations == 0
            && self.inventory_objects == 0
            && self.coherence_violations == 0
    }

    pub(super) fn complete(&self) -> bool {
        self.schema_installed && self.quiescent()
    }

    pub(super) fn unfenced(&self) -> bool {
        self.complete() && self.complete_fenced_operations == 0
    }

    // Verified absence is not completion or restored capture. This is only an
    // activation precondition for the compatible predecessor serving fleet.
    pub(super) fn clear_for_activation(&self) -> bool {
        self.valid() && (!self.schema_installed || self.complete())
    }

    pub(super) fn valid(&self) -> bool {
        let counts = [
            self.pending_operations,
            self.provider_verified_operations,
            self.complete_fenced_operations,
            self.released_operations,
            self.inventory_objects,
            self.coherence_violations,
        ];
        counts.into_iter().all(|count| count >= 0)
            && (self.schema_installed || counts.into_iter().all(|count| count == 0))
    }
}

pub(super) async fn snapshot(connection: &mut PgConnection) -> Result<OrphanErasureAudit> {
    if !super::orphan_capture_erasure::verify_schema_if_installed(connection).await? {
        return Ok(OrphanErasureAudit::default());
    }
    let row = sqlx::query(include_str!("orphan_capture_erasure_audit.sql"))
        .fetch_one(connection)
        .await?;
    Ok(OrphanErasureAudit {
        schema_installed: true,
        pending_operations: row.try_get("pending_operations")?,
        provider_verified_operations: row.try_get("provider_verified_operations")?,
        complete_fenced_operations: row.try_get("complete_fenced_operations")?,
        released_operations: row.try_get("released_operations")?,
        inventory_objects: row.try_get("inventory_objects")?,
        coherence_violations: row.try_get("coherence_violations")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_fenced_is_not_pending_or_capture_available() {
        let absent = OrphanErasureAudit::default();
        assert!(absent.valid() && absent.quiescent());
        assert!(!absent.complete() && !absent.unfenced());
        assert!(absent.clear_for_activation());
        let mut audit = OrphanErasureAudit {
            schema_installed: true,
            ..absent
        };
        assert!(audit.complete() && audit.unfenced());
        audit.pending_operations = 1;
        assert!(!audit.quiescent() && !audit.complete() && !audit.unfenced());
        audit.pending_operations = 0;
        audit.provider_verified_operations = 1;
        assert!(!audit.quiescent());
        audit.provider_verified_operations = 0;
        audit.complete_fenced_operations = 1;
        assert!(audit.complete() && !audit.unfenced());
        audit.complete_fenced_operations = 0;
        audit.released_operations = 1;
        assert!(audit.complete() && audit.unfenced());
        audit.inventory_objects = 1;
        assert!(!audit.complete());
        audit.inventory_objects = 0;
        audit.coherence_violations = 1;
        assert!(!audit.complete());
        audit.schema_installed = false;
        assert!(!audit.valid());
    }
}
