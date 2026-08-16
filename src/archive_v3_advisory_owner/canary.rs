//! Opaque one-shot admission capability for one inactive Phase-1 advisory
//! owner. Production issuance is intentionally absent: a future issuer must
//! first authenticate an operator statement and an independently attested
//! release image. Encrypted Control may reconstruct the capability, while
//! tests may mint exact fixtures.

use std::fmt;

use super::{AdvisoryOwnerError, Result};
use crate::archive_v3_maintenance_import::MaintenanceImportOperationId;

pub(crate) struct AdvisoryCanaryScope {
    scope_id: [u8; 16],
    operation_id: MaintenanceImportOperationId,
    release_image_digest: [u8; 32],
    operator_statement_commitment: [u8; 32],
    authorization_commitment: [u8; 32],
}

impl AdvisoryCanaryScope {
    pub(crate) fn from_control(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        scope_id: [u8; 16],
        operation_id: MaintenanceImportOperationId,
        release_image_digest: [u8; 32],
        operator_statement_commitment: [u8; 32],
        authorization_commitment: [u8; 32],
    ) -> Result<Self> {
        if scope_id == [0; 16]
            || release_image_digest == [0; 32]
            || operator_statement_commitment == [0; 32]
            || authorization_commitment == [0; 32]
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            scope_id,
            operation_id,
            release_image_digest,
            operator_statement_commitment,
            authorization_commitment,
        })
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> (
        &[u8; 16],
        MaintenanceImportOperationId,
        &[u8; 32],
        &[u8; 32],
        &[u8; 32],
    ) {
        (
            &self.scope_id,
            self.operation_id,
            &self.release_image_digest,
            &self.operator_statement_commitment,
            &self.authorization_commitment,
        )
    }
}

impl fmt::Debug for AdvisoryCanaryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvisoryCanaryScope(<opaque>)")
    }
}
