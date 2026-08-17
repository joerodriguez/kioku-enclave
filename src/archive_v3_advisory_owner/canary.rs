//! Opaque one-shot admission capability for one inactive Phase-1 advisory
//! owner. A separate private child now verifies an exact operator statement
//! and independent release-image assertion before encrypted Control may issue
//! this capability. Production roots remain intentionally unset and there is
//! no live caller, while tests may mint exact fixtures.

use std::fmt;

use super::{AdvisoryOwnerError, Result};
use crate::archive_v3_maintenance_import::MaintenanceImportOperationId;

pub(crate) struct AdvisoryCanaryScope {
    scope_id: [u8; 16],
    operation_id: MaintenanceImportOperationId,
    release_image_digest: [u8; 32],
    operator_statement_commitment: [u8; 32],
    activation_preconditions_commitment: [u8; 32],
    authorization_commitment: [u8; 32],
}

pub(crate) type AdvisoryCanaryScopeControlView<'a> = (
    &'a [u8; 16],
    MaintenanceImportOperationId,
    &'a [u8; 32],
    &'a [u8; 32],
    &'a [u8; 32],
    &'a [u8; 32],
);

impl AdvisoryCanaryScope {
    pub(crate) fn from_control(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        scope_id: [u8; 16],
        operation_id: MaintenanceImportOperationId,
        release_image_digest: [u8; 32],
        operator_statement_commitment: [u8; 32],
        activation_preconditions_commitment: [u8; 32],
        authorization_commitment: [u8; 32],
    ) -> Result<Self> {
        if scope_id == [0; 16]
            || release_image_digest == [0; 32]
            || operator_statement_commitment == [0; 32]
            || activation_preconditions_commitment == [0; 32]
            || authorization_commitment == [0; 32]
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            scope_id,
            operation_id,
            release_image_digest,
            operator_statement_commitment,
            activation_preconditions_commitment,
            authorization_commitment,
        })
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> AdvisoryCanaryScopeControlView<'_> {
        (
            &self.scope_id,
            self.operation_id,
            &self.release_image_digest,
            &self.operator_statement_commitment,
            &self.activation_preconditions_commitment,
            &self.authorization_commitment,
        )
    }

    pub(crate) const fn scope_id(&self) -> [u8; 16] {
        self.scope_id
    }

    pub(crate) const fn release_image_digest(&self) -> [u8; 32] {
        self.release_image_digest
    }

    pub(crate) const fn operator_statement_commitment(&self) -> [u8; 32] {
        self.operator_statement_commitment
    }

    #[cfg(test)]
    pub(crate) const fn scope_id_for_test(&self) -> [u8; 16] {
        self.scope_id
    }
}

impl fmt::Debug for AdvisoryCanaryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvisoryCanaryScope(<opaque>)")
    }
}
