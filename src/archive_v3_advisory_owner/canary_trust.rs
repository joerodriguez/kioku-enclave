//! Cryptographic admission boundary for one inactive Phase-1 advisory canary.
//!
//! An operator signature selects one exact already-parity-verified target. A
//! separate image-attestation verifier signature binds that statement to the
//! exact release-image digest. A third deployment-controller signature binds
//! the same statement and image to a zero-replica maintenance window, an empty
//! authoritative-mutation set, legacy-only acknowledgements, and exact
//! content-free monitoring/rollback policies. The three Ed25519 roots must be
//! nonzero and pairwise distinct. Production roots intentionally remain unset,
//! so this verifier cannot currently mint an authorization and has no caller.

use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

use super::{AdvisoryOwnerError, Result};
use crate::{archive_v3::ArchiveId, archive_v3_maintenance_import::MaintenanceImportOperationId};

const OPERATOR_STATEMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-canary/operator-statement/v1\0";
const OPERATOR_STATEMENT_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-canary/operator-statement-commitment/v1\0";
const IMAGE_ATTESTATION_DOMAIN: &[u8] = b"kioku/archive-v3/advisory-canary/image-attestation/v1\0";
const RUNTIME_ADMISSION_DOMAIN: &[u8] = b"kioku/archive-v3/advisory-canary/runtime-admission/v1\0";
const RUNTIME_ADMISSION_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-canary/runtime-admission-commitment/v1\0";
const EMPTY_PHASE1_MUTATION_SET_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-canary/authoritative-mutation-set/empty/v1\0";
const AUTHORIZATION_EVIDENCE_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-canary/authorization-evidence/v1\0";

const OPERATOR_STATEMENT_FORMAT_V1: u16 = 1;
const IMAGE_ATTESTATION_FORMAT_V1: u16 = 1;
const RUNTIME_ADMISSION_FORMAT_V1: u16 = 1;
const OPERATOR_STATEMENT_BYTES: usize = 242;
const IMAGE_ATTESTATION_BYTES: usize = 82;
const RUNTIME_ADMISSION_BYTES: usize = 298;
const ED25519_SIGNATURE_BYTES: usize = 64;
const PHASE1_ADVISORY: u8 = 1;
const LEGACY_ACKNOWLEDGEMENT_ONLY: u8 = 1;

// Real solo-operator roots pinned per the accepted amendment
// docs/adr/0022-solo-operator-activation.md: three distinct Ed25519 keys minted
// and held by the one operator (custody, rotation, and revocation recorded
// there; private keys never enter this repository). A caller cannot replace
// any root through configuration, environment, or a request; rotation or
// revocation requires a reviewed PR changing these constants.
const PINNED_OPERATOR_PUBLIC_KEY: [u8; 32] = [
    0x5f, 0xd7, 0xb3, 0xa4, 0x21, 0xe0, 0xdb, 0x60, 0x64, 0x0b, 0x95, 0x87, 0x53, 0x4f, 0xa3, 0x61,
    0x7b, 0xb0, 0xf1, 0x18, 0x17, 0xc9, 0x9d, 0x27, 0x62, 0x86, 0x75, 0x38, 0xe1, 0xbb, 0xd2, 0xa5,
];
const PINNED_IMAGE_ATTESTATION_PUBLIC_KEY: [u8; 32] = [
    0x43, 0x17, 0x20, 0xe1, 0x98, 0x3a, 0x92, 0x0e, 0x18, 0x3b, 0x08, 0xc9, 0x84, 0x2d, 0x4e, 0x72,
    0x03, 0x54, 0xb1, 0x7b, 0x0b, 0x91, 0xad, 0x9c, 0xcd, 0x95, 0x4c, 0x33, 0x62, 0x97, 0x59, 0x00,
];
const PINNED_RUNTIME_ADMISSION_PUBLIC_KEY: [u8; 32] = [
    0x56, 0x09, 0x2a, 0x35, 0x29, 0x1f, 0x7b, 0xc0, 0xcb, 0xfe, 0xfc, 0xe7, 0x8a, 0x69, 0xa2, 0x38,
    0x33, 0x7b, 0xfd, 0xb9, 0x0e, 0x65, 0x4a, 0x68, 0xd9, 0xd2, 0xe0, 0x85, 0xe6, 0xda, 0x85, 0xf5,
];

struct CanaryTrustRoots {
    operator: [u8; 32],
    image_attestation: [u8; 32],
    runtime_admission: [u8; 32],
}

impl CanaryTrustRoots {
    fn pinned() -> Result<Self> {
        Self::validated(
            PINNED_OPERATOR_PUBLIC_KEY,
            PINNED_IMAGE_ATTESTATION_PUBLIC_KEY,
            PINNED_RUNTIME_ADMISSION_PUBLIC_KEY,
        )
    }

    fn validated(
        operator: [u8; 32],
        image_attestation: [u8; 32],
        runtime_admission: [u8; 32],
    ) -> Result<Self> {
        if operator == [0; 32]
            || image_attestation == [0; 32]
            || runtime_admission == [0; 32]
            || operator == image_attestation
            || operator == runtime_admission
            || image_attestation == runtime_admission
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(Self {
            operator,
            image_attestation,
            runtime_admission,
        })
    }
}

struct ParsedOperatorStatement {
    scope_id: [u8; 16],
    user_id_commitment: [u8; 32],
    archive_id: ArchiveId,
    operation_id: [u8; 16],
    operation_commitment: [u8; 32],
    source_commitment: [u8; 32],
    parity_commitment: [u8; 32],
    terminal_witness_hash: [u8; 32],
    release_image_digest: [u8; 32],
}

struct ParsedRuntimeAdmission {
    empty_mutation_set_commitment: [u8; 32],
    deployment_target_commitment: [u8; 32],
    maintenance_window_id: [u8; 16],
    deployment_revision_commitment: [u8; 32],
    challenge_commitment: [u8; 32],
    monitoring_policy_commitment: [u8; 32],
    rollback_policy_commitment: [u8; 32],
}

/// Signature-authenticated, image-attested authority to insert one exact
/// inactive canary scope. It is non-cloneable, has no provider/Store/runtime
/// operation, and exposes its binding only to encrypted Control.
pub(crate) struct VerifiedAdvisoryCanaryAuthorization {
    statement: ParsedOperatorStatement,
    operator_statement_commitment: [u8; 32],
    activation_preconditions_commitment: [u8; 32],
    runtime_admission: ParsedRuntimeAdmission,
}

impl VerifiedAdvisoryCanaryAuthorization {
    pub(crate) fn operation_id_for_control(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> [u8; 16] {
        self.statement.operation_id
    }

    pub(crate) const fn scope_id(&self) -> [u8; 16] {
        self.statement.scope_id
    }

    pub(crate) const fn release_image_digest(&self) -> [u8; 32] {
        self.statement.release_image_digest
    }

    pub(crate) const fn operator_statement_commitment(&self) -> [u8; 32] {
        self.operator_statement_commitment
    }

    pub(crate) fn verify_matches_window(
        &self,
        window_id: &[u8; 16],
        target_commitment: &[u8; 32],
        revision_commitment: &[u8; 32],
        challenge_commitment: &[u8; 32],
        monitoring_commitment: &[u8; 32],
        rollback_commitment: &[u8; 32],
    ) -> Result<()> {
        if &self.runtime_admission.maintenance_window_id != window_id
            || &self.runtime_admission.deployment_target_commitment != target_commitment
            || &self.runtime_admission.deployment_revision_commitment != revision_commitment
            || &self.runtime_admission.challenge_commitment != challenge_commitment
            || &self.runtime_admission.monitoring_policy_commitment != monitoring_commitment
            || &self.runtime_admission.rollback_policy_commitment != rollback_commitment
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticate_for_control(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        user_id: &str,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        operation_commitment: &[u8; 32],
        source_commitment: &[u8; 32],
        parity_commitment: &[u8; 32],
        terminal_witness_hash: &[u8; 32],
    ) -> Result<AdvisoryCanaryAuthorizationControlView> {
        let expected_user = user_id_commitment(&self.statement.scope_id, user_id)?;
        if self.statement.scope_id == [0; 16]
            || self.statement.release_image_digest == [0; 32]
            || self.operator_statement_commitment == [0; 32]
            || self.statement.user_id_commitment != expected_user
            || self.statement.archive_id != archive_id
            || &self.statement.operation_id != operation_id.as_bytes()
            || &self.statement.operation_commitment != operation_commitment
            || &self.statement.source_commitment != source_commitment
            || &self.statement.parity_commitment != parity_commitment
            || &self.statement.terminal_witness_hash != terminal_witness_hash
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(AdvisoryCanaryAuthorizationControlView {
            scope_id: self.statement.scope_id,
            release_image_digest: self.statement.release_image_digest,
            operator_statement_commitment: self.operator_statement_commitment,
            activation_preconditions_commitment: self.activation_preconditions_commitment,
            empty_mutation_set_commitment: self.runtime_admission.empty_mutation_set_commitment,
            deployment_target_commitment: self.runtime_admission.deployment_target_commitment,
            maintenance_window_id: self.runtime_admission.maintenance_window_id,
            deployment_revision_commitment: self.runtime_admission.deployment_revision_commitment,
            challenge_commitment: self.runtime_admission.challenge_commitment,
            monitoring_policy_commitment: self.runtime_admission.monitoring_policy_commitment,
            rollback_policy_commitment: self.runtime_admission.rollback_policy_commitment,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_control_test(
        scope_id: [u8; 16],
        user_id: &str,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        operation_commitment: [u8; 32],
        source_commitment: [u8; 32],
        parity_commitment: [u8; 32],
        terminal_witness_hash: [u8; 32],
        release_image_digest: [u8; 32],
        operator_statement_commitment: [u8; 32],
        activation_preconditions_commitment: [u8; 32],
    ) -> Result<Self> {
        let statement = ParsedOperatorStatement {
            scope_id,
            user_id_commitment: user_id_commitment(&scope_id, user_id)?,
            archive_id,
            operation_id: *operation_id.as_bytes(),
            operation_commitment,
            source_commitment,
            parity_commitment,
            terminal_witness_hash,
            release_image_digest,
        };
        let runtime_admission = ParsedRuntimeAdmission {
            empty_mutation_set_commitment: empty_phase1_mutation_set_commitment(),
            deployment_target_commitment: [0xa1; 32],
            maintenance_window_id: [0xa2; 16],
            deployment_revision_commitment: [0xa3; 32],
            challenge_commitment: [0xa4; 32],
            monitoring_policy_commitment: [0xa5; 32],
            rollback_policy_commitment: [0xa6; 32],
        };
        if scope_id == [0; 16]
            || release_image_digest == [0; 32]
            || operator_statement_commitment == [0; 32]
            || activation_preconditions_commitment == [0; 32]
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            statement,
            operator_statement_commitment,
            activation_preconditions_commitment,
            runtime_admission,
        })
    }
}

pub(crate) struct AdvisoryCanaryAuthorizationControlView {
    pub(crate) scope_id: [u8; 16],
    pub(crate) release_image_digest: [u8; 32],
    pub(crate) operator_statement_commitment: [u8; 32],
    pub(crate) activation_preconditions_commitment: [u8; 32],
    pub(crate) empty_mutation_set_commitment: [u8; 32],
    pub(crate) deployment_target_commitment: [u8; 32],
    pub(crate) maintenance_window_id: [u8; 16],
    pub(crate) deployment_revision_commitment: [u8; 32],
    pub(crate) challenge_commitment: [u8; 32],
    pub(crate) monitoring_policy_commitment: [u8; 32],
    pub(crate) rollback_policy_commitment: [u8; 32],
}

impl std::fmt::Debug for VerifiedAdvisoryCanaryAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedAdvisoryCanaryAuthorization(<opaque>)")
    }
}

/// Verify the three detached signatures against compile-time trust roots. The
/// pinned roots are intentionally invalid today, so production cannot issue a
/// scope until a separately reviewed activation change supplies real anchors.
pub(crate) fn verify_pinned_advisory_canary_authorization(
    statement: &[u8],
    operator_signature: &[u8],
    image_attestation: &[u8],
    image_attestation_signature: &[u8],
    runtime_admission: &[u8],
    runtime_admission_signature: &[u8],
) -> Result<VerifiedAdvisoryCanaryAuthorization> {
    verify_advisory_canary_authorization_with_roots(
        CanaryTrustRoots::pinned()?,
        statement,
        operator_signature,
        image_attestation,
        image_attestation_signature,
        runtime_admission,
        runtime_admission_signature,
    )
}

fn verify_advisory_canary_authorization_with_roots(
    roots: CanaryTrustRoots,
    statement: &[u8],
    operator_signature: &[u8],
    image_attestation: &[u8],
    image_attestation_signature: &[u8],
    runtime_admission: &[u8],
    runtime_admission_signature: &[u8],
) -> Result<VerifiedAdvisoryCanaryAuthorization> {
    if operator_signature.len() != ED25519_SIGNATURE_BYTES
        || image_attestation_signature.len() != ED25519_SIGNATURE_BYTES
        || runtime_admission_signature.len() != ED25519_SIGNATURE_BYTES
    {
        return Err(AdvisoryOwnerError::Corrupt);
    }
    let parsed = parse_operator_statement(statement)?;
    verify_ed25519(
        &roots.operator,
        OPERATOR_STATEMENT_DOMAIN,
        statement,
        operator_signature,
    )?;
    let statement_commitment =
        signed_operator_statement_commitment(statement, &roots.operator, operator_signature);
    authenticate_image_attestation(
        image_attestation,
        &parsed,
        &statement_commitment,
        &roots.image_attestation,
        image_attestation_signature,
    )?;
    let parsed_runtime_admission = authenticate_runtime_admission(
        runtime_admission,
        &parsed,
        &statement_commitment,
        &roots.runtime_admission,
        runtime_admission_signature,
    )?;
    let activation_preconditions_commitment = runtime_admission_commitment(
        &roots.runtime_admission,
        runtime_admission,
        runtime_admission_signature,
    );
    let evidence_commitment = authorization_evidence_commitment(
        SignedEvidence {
            public_key: &roots.operator,
            payload: statement,
            signature: operator_signature,
        },
        SignedEvidence {
            public_key: &roots.image_attestation,
            payload: image_attestation,
            signature: image_attestation_signature,
        },
        SignedEvidence {
            public_key: &roots.runtime_admission,
            payload: runtime_admission,
            signature: runtime_admission_signature,
        },
    );
    Ok(VerifiedAdvisoryCanaryAuthorization {
        statement: parsed,
        operator_statement_commitment: evidence_commitment,
        activation_preconditions_commitment,
        runtime_admission: parsed_runtime_admission,
    })
}

fn parse_operator_statement(value: &[u8]) -> Result<ParsedOperatorStatement> {
    let bytes: &[u8; OPERATOR_STATEMENT_BYTES] =
        value.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)?;
    if u16::from_be_bytes([bytes[0], bytes[1]]) != OPERATOR_STATEMENT_FORMAT_V1 {
        return Err(AdvisoryOwnerError::Corrupt);
    }
    let scope_id = fixed::<16>(&bytes[2..18])?;
    let user_id_commitment = fixed::<32>(&bytes[18..50])?;
    let archive_id = ArchiveId::from_bytes(fixed::<16>(&bytes[50..66])?);
    let operation_id = fixed::<16>(&bytes[66..82])?;
    let operation_commitment = fixed::<32>(&bytes[82..114])?;
    let source_commitment = fixed::<32>(&bytes[114..146])?;
    let parity_commitment = fixed::<32>(&bytes[146..178])?;
    let terminal_witness_hash = fixed::<32>(&bytes[178..210])?;
    let release_image_digest = fixed::<32>(&bytes[210..242])?;
    if scope_id == [0; 16]
        || user_id_commitment == [0; 32]
        || archive_id.as_bytes() == &[0; 16]
        || operation_id == [0; 16]
        || operation_commitment == [0; 32]
        || source_commitment == [0; 32]
        || parity_commitment == [0; 32]
        || terminal_witness_hash == [0; 32]
        || release_image_digest == [0; 32]
    {
        return Err(AdvisoryOwnerError::Corrupt);
    }
    Ok(ParsedOperatorStatement {
        scope_id,
        user_id_commitment,
        archive_id,
        operation_id,
        operation_commitment,
        source_commitment,
        parity_commitment,
        terminal_witness_hash,
        release_image_digest,
    })
}

fn authenticate_image_attestation(
    value: &[u8],
    statement: &ParsedOperatorStatement,
    statement_commitment: &[u8; 32],
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let bytes: &[u8; IMAGE_ATTESTATION_BYTES] =
        value.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)?;
    if u16::from_be_bytes([bytes[0], bytes[1]]) != IMAGE_ATTESTATION_FORMAT_V1
        || fixed::<16>(&bytes[2..18])? != statement.scope_id
        || fixed::<32>(&bytes[18..50])? != *statement_commitment
        || fixed::<32>(&bytes[50..82])? != statement.release_image_digest
    {
        return Err(AdvisoryOwnerError::Conflict);
    }
    verify_ed25519(public_key, IMAGE_ATTESTATION_DOMAIN, value, signature)
}

fn authenticate_runtime_admission(
    value: &[u8],
    statement: &ParsedOperatorStatement,
    statement_commitment: &[u8; 32],
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<ParsedRuntimeAdmission> {
    let bytes: &[u8; RUNTIME_ADMISSION_BYTES] =
        value.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)?;
    if u16::from_be_bytes([bytes[0], bytes[1]]) != RUNTIME_ADMISSION_FORMAT_V1
        || fixed::<16>(&bytes[2..18])? != statement.scope_id
        || fixed::<32>(&bytes[18..50])? != *statement_commitment
        || fixed::<32>(&bytes[50..82])? != statement.release_image_digest
        || fixed::<32>(&bytes[82..114])? != empty_phase1_mutation_set_commitment()
        || fixed::<32>(&bytes[114..146])? == [0; 32]
        || fixed::<16>(&bytes[146..162])? == [0; 16]
        || fixed::<32>(&bytes[162..194])? == [0; 32]
        || fixed::<32>(&bytes[194..226])? == [0; 32]
        || fixed::<32>(&bytes[226..258])? == [0; 32]
        || fixed::<32>(&bytes[258..290])? == [0; 32]
        || bytes[290] != PHASE1_ADVISORY
        || u16::from_be_bytes([bytes[291], bytes[292]]) != 0
        || bytes[293] != LEGACY_ACKNOWLEDGEMENT_ONLY
        || u32::from_be_bytes([bytes[294], bytes[295], bytes[296], bytes[297]]) != 0
    {
        return Err(AdvisoryOwnerError::Conflict);
    }
    verify_ed25519(public_key, RUNTIME_ADMISSION_DOMAIN, value, signature)?;
    Ok(ParsedRuntimeAdmission {
        empty_mutation_set_commitment: fixed::<32>(&bytes[82..114])?,
        deployment_target_commitment: fixed::<32>(&bytes[114..146])?,
        maintenance_window_id: fixed::<16>(&bytes[146..162])?,
        deployment_revision_commitment: fixed::<32>(&bytes[162..194])?,
        challenge_commitment: fixed::<32>(&bytes[194..226])?,
        monitoring_policy_commitment: fixed::<32>(&bytes[226..258])?,
        rollback_policy_commitment: fixed::<32>(&bytes[258..290])?,
    })
}

/// Narrow accessor for the pinned deployment-observer (runtime-admission) root,
/// used by the live window observer's production constructor. Fails closed while
/// the pinned roots remain deliberately invalid zero roots.
pub(super) fn pinned_deployment_observer_root() -> Result<[u8; 32]> {
    Ok(CanaryTrustRoots::pinned()?.runtime_admission)
}

/// Domain-separated Ed25519 verification for sibling advisory-owner modules.
pub(super) fn verify_observer_signature(
    public_key: &[u8; 32],
    domain: &[u8],
    value: &[u8],
    signature: &[u8],
) -> Result<()> {
    verify_ed25519(public_key, domain, value, signature)
}

fn verify_ed25519(
    public_key: &[u8; 32],
    domain: &[u8],
    value: &[u8],
    signature: &[u8],
) -> Result<()> {
    let mut message = Vec::with_capacity(domain.len() + value.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(value);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, signature)
        .map_err(|_| AdvisoryOwnerError::Conflict)
}

fn signed_operator_statement_commitment(
    value: &[u8],
    public_key: &[u8; 32],
    signature: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OPERATOR_STATEMENT_COMMITMENT_DOMAIN);
    hasher.update(public_key);
    hasher.update(value);
    hasher.update(signature);
    hasher.finalize().into()
}

struct SignedEvidence<'a> {
    public_key: &'a [u8; 32],
    payload: &'a [u8],
    signature: &'a [u8],
}

fn authorization_evidence_commitment(
    operator: SignedEvidence<'_>,
    image_attestation: SignedEvidence<'_>,
    runtime_admission: SignedEvidence<'_>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORIZATION_EVIDENCE_COMMITMENT_DOMAIN);
    for evidence in [operator, image_attestation, runtime_admission] {
        hasher.update(evidence.public_key);
        hasher.update(evidence.payload);
        hasher.update(evidence.signature);
    }
    hasher.finalize().into()
}

fn runtime_admission_commitment(public_key: &[u8; 32], value: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RUNTIME_ADMISSION_COMMITMENT_DOMAIN);
    hasher.update(public_key);
    hasher.update(value);
    hasher.update(signature);
    hasher.finalize().into()
}

fn empty_phase1_mutation_set_commitment() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EMPTY_PHASE1_MUTATION_SET_DOMAIN);
    hasher.update(1_u16.to_be_bytes());
    hasher.update(0_u16.to_be_bytes());
    hasher.finalize().into()
}

fn user_id_commitment(scope_id: &[u8; 16], user_id: &str) -> Result<[u8; 32]> {
    let length = u64::try_from(user_id.len()).map_err(|_| AdvisoryOwnerError::Corrupt)?;
    if user_id.is_empty() {
        return Err(AdvisoryOwnerError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"kioku/archive-v3/advisory-canary/user/v1\0");
    hasher.update(scope_id);
    hasher.update(length.to_be_bytes());
    hasher.update(user_id.as_bytes());
    Ok(hasher.finalize().into())
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N]> {
    value.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn operation(byte: u8) -> MaintenanceImportOperationId {
        MaintenanceImportOperationId::from_control(
            crate::cp::control_store::MaintenancePersistenceContext::for_test(),
            [byte; 16],
        )
        .unwrap()
    }

    type SignedFixture = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        CanaryTrustRoots,
    );

    fn signed_fixture() -> SignedFixture {
        let operator = key(0x11);
        let image = key(0x22);
        let runtime = key(0x23);
        let mut statement = Vec::with_capacity(OPERATOR_STATEMENT_BYTES);
        statement.extend_from_slice(&OPERATOR_STATEMENT_FORMAT_V1.to_be_bytes());
        statement.extend_from_slice(&[0x31; 16]);
        statement.extend_from_slice(&user_id_commitment(&[0x31; 16], "canary-user").unwrap());
        statement.extend_from_slice(&[0x32; 16]);
        statement.extend_from_slice(&[0x33; 16]);
        statement.extend_from_slice(&[0x34; 32]);
        statement.extend_from_slice(&[0x35; 32]);
        statement.extend_from_slice(&[0x36; 32]);
        statement.extend_from_slice(&[0x37; 32]);
        statement.extend_from_slice(&[0x38; 32]);
        assert_eq!(statement.len(), OPERATOR_STATEMENT_BYTES);
        let mut operator_message = OPERATOR_STATEMENT_DOMAIN.to_vec();
        operator_message.extend_from_slice(&statement);
        let operator_signature = operator.sign(&operator_message).as_ref().to_vec();
        let commitment = signed_operator_statement_commitment(
            &statement,
            operator.public_key().as_ref().try_into().unwrap(),
            &operator_signature,
        );
        let mut attestation = Vec::with_capacity(IMAGE_ATTESTATION_BYTES);
        attestation.extend_from_slice(&IMAGE_ATTESTATION_FORMAT_V1.to_be_bytes());
        attestation.extend_from_slice(&[0x31; 16]);
        attestation.extend_from_slice(&commitment);
        attestation.extend_from_slice(&[0x38; 32]);
        assert_eq!(attestation.len(), IMAGE_ATTESTATION_BYTES);
        let mut image_message = IMAGE_ATTESTATION_DOMAIN.to_vec();
        image_message.extend_from_slice(&attestation);
        let image_signature = image.sign(&image_message).as_ref().to_vec();
        let mut runtime_admission = Vec::with_capacity(RUNTIME_ADMISSION_BYTES);
        runtime_admission.extend_from_slice(&RUNTIME_ADMISSION_FORMAT_V1.to_be_bytes());
        runtime_admission.extend_from_slice(&[0x31; 16]);
        runtime_admission.extend_from_slice(&commitment);
        runtime_admission.extend_from_slice(&[0x38; 32]);
        runtime_admission.extend_from_slice(&empty_phase1_mutation_set_commitment());
        runtime_admission.extend_from_slice(&[0x41; 32]);
        runtime_admission.extend_from_slice(&[0x42; 16]);
        runtime_admission.extend_from_slice(&[0x43; 32]);
        runtime_admission.extend_from_slice(&[0x44; 32]);
        runtime_admission.extend_from_slice(&[0x45; 32]);
        runtime_admission.extend_from_slice(&[0x46; 32]);
        runtime_admission.push(PHASE1_ADVISORY);
        runtime_admission.extend_from_slice(&0_u16.to_be_bytes());
        runtime_admission.push(LEGACY_ACKNOWLEDGEMENT_ONLY);
        runtime_admission.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(runtime_admission.len(), RUNTIME_ADMISSION_BYTES);
        let mut runtime_message = RUNTIME_ADMISSION_DOMAIN.to_vec();
        runtime_message.extend_from_slice(&runtime_admission);
        let runtime_signature = runtime.sign(&runtime_message).as_ref().to_vec();
        let roots = CanaryTrustRoots::validated(
            operator.public_key().as_ref().try_into().unwrap(),
            image.public_key().as_ref().try_into().unwrap(),
            runtime.public_key().as_ref().try_into().unwrap(),
        )
        .unwrap();
        (
            statement,
            operator_signature,
            attestation,
            image_signature,
            runtime_admission,
            runtime_signature,
            roots,
        )
    }

    #[test]
    fn exact_three_root_authorization_authenticates_control_target() {
        let (
            statement,
            operator_signature,
            attestation,
            image_signature,
            runtime_admission,
            runtime_signature,
            roots,
        ) = signed_fixture();
        let verified = verify_advisory_canary_authorization_with_roots(
            roots,
            &statement,
            &operator_signature,
            &attestation,
            &image_signature,
            &runtime_admission,
            &runtime_signature,
        )
        .unwrap();
        let view = verified
            .authenticate_for_control(
                crate::cp::control_store::AdvisoryOwnerPersistenceContext::for_test(),
                "canary-user",
                ArchiveId::from_bytes([0x32; 16]),
                operation(0x33),
                &[0x34; 32],
                &[0x35; 32],
                &[0x36; 32],
                &[0x37; 32],
            )
            .unwrap();
        assert_eq!(view.scope_id, [0x31; 16]);
        assert_eq!(view.release_image_digest, [0x38; 32]);
        let operator = key(0x11);
        let image = key(0x22);
        let runtime = key(0x23);
        assert_eq!(
            view.operator_statement_commitment,
            authorization_evidence_commitment(
                SignedEvidence {
                    public_key: operator.public_key().as_ref().try_into().unwrap(),
                    payload: &statement,
                    signature: &operator_signature,
                },
                SignedEvidence {
                    public_key: image.public_key().as_ref().try_into().unwrap(),
                    payload: &attestation,
                    signature: &image_signature,
                },
                SignedEvidence {
                    public_key: runtime.public_key().as_ref().try_into().unwrap(),
                    payload: &runtime_admission,
                    signature: &runtime_signature,
                },
            )
        );
        assert_eq!(
            view.activation_preconditions_commitment,
            runtime_admission_commitment(
                runtime.public_key().as_ref().try_into().unwrap(),
                &runtime_admission,
                &runtime_signature,
            )
        );

        macro_rules! reject_target {
            ($user:expr, $archive:expr, $operation:expr, $maintenance:expr, $source:expr, $parity:expr, $witness:expr) => {
                assert!(verified
                    .authenticate_for_control(
                        crate::cp::control_store::AdvisoryOwnerPersistenceContext::for_test(),
                        $user,
                        $archive,
                        $operation,
                        &$maintenance,
                        &$source,
                        &$parity,
                        &$witness,
                    )
                    .is_err());
            };
        }
        reject_target!(
            "other-user",
            ArchiveId::from_bytes([0x32; 16]),
            operation(0x33),
            [0x34; 32],
            [0x35; 32],
            [0x36; 32],
            [0x37; 32]
        );
        reject_target!(
            "canary-user",
            ArchiveId::from_bytes([0x42; 16]),
            operation(0x33),
            [0x34; 32],
            [0x35; 32],
            [0x36; 32],
            [0x37; 32]
        );
        reject_target!(
            "canary-user",
            ArchiveId::from_bytes([0x32; 16]),
            operation(0x43),
            [0x34; 32],
            [0x35; 32],
            [0x36; 32],
            [0x37; 32]
        );
        for changed in 0..4 {
            let mut bindings = [[0x34; 32], [0x35; 32], [0x36; 32], [0x37; 32]];
            bindings[changed][0] ^= 1;
            reject_target!(
                "canary-user",
                ArchiveId::from_bytes([0x32; 16]),
                operation(0x33),
                bindings[0],
                bindings[1],
                bindings[2],
                bindings[3]
            );
        }
    }

    #[test]
    fn every_signed_binding_and_attestation_binding_fails_closed() {
        let (
            statement,
            operator_signature,
            attestation,
            image_signature,
            runtime_admission,
            runtime_signature,
            _,
        ) = signed_fixture();
        let operator = key(0x11);
        let image = key(0x22);
        let runtime = key(0x23);
        for offset in [2, 18, 50, 66, 82, 114, 146, 178, 210] {
            let mut changed = statement.clone();
            changed[offset] ^= 1;
            let roots = CanaryTrustRoots::validated(
                operator.public_key().as_ref().try_into().unwrap(),
                image.public_key().as_ref().try_into().unwrap(),
                runtime.public_key().as_ref().try_into().unwrap(),
            )
            .unwrap();
            assert!(verify_advisory_canary_authorization_with_roots(
                roots,
                &changed,
                &operator_signature,
                &attestation,
                &image_signature,
                &runtime_admission,
                &runtime_signature,
            )
            .is_err());
        }
        for offset in [2, 18, 50] {
            let mut changed = attestation.clone();
            changed[offset] ^= 1;
            let roots = CanaryTrustRoots::validated(
                operator.public_key().as_ref().try_into().unwrap(),
                image.public_key().as_ref().try_into().unwrap(),
                runtime.public_key().as_ref().try_into().unwrap(),
            )
            .unwrap();
            assert!(verify_advisory_canary_authorization_with_roots(
                roots,
                &statement,
                &operator_signature,
                &changed,
                &image_signature,
                &runtime_admission,
                &runtime_signature,
            )
            .is_err());
        }
        for offset in [
            2, 18, 50, 82, 114, 146, 162, 194, 226, 258, 290, 291, 293, 294,
        ] {
            let mut changed = runtime_admission.clone();
            changed[offset] ^= 1;
            let roots = CanaryTrustRoots::validated(
                operator.public_key().as_ref().try_into().unwrap(),
                image.public_key().as_ref().try_into().unwrap(),
                runtime.public_key().as_ref().try_into().unwrap(),
            )
            .unwrap();
            assert!(verify_advisory_canary_authorization_with_roots(
                roots,
                &statement,
                &operator_signature,
                &attestation,
                &image_signature,
                &changed,
                &runtime_signature,
            )
            .is_err());
        }
    }

    #[test]
    fn signed_runtime_policy_must_remain_phase1_empty_legacy_and_zero_replica() {
        let (statement, operator_signature, attestation, image_signature, runtime_admission, _, _) =
            signed_fixture();
        let operator = key(0x11);
        let image = key(0x22);
        let runtime = key(0x23);
        for (offset, value) in [
            (82, 0_u8),
            (114, 0_u8),
            (146, 0_u8),
            (162, 0_u8),
            (194, 0_u8),
            (226, 0_u8),
            (258, 0_u8),
            (290, 2_u8),
            (292, 1_u8),
            (293, 2_u8),
            (297, 1_u8),
        ] {
            let mut changed = runtime_admission.clone();
            if value == 0 {
                let length = if offset == 146 { 16 } else { 32 };
                changed[offset..offset + length].fill(0);
            } else {
                changed[offset] = value;
            }
            let mut message = RUNTIME_ADMISSION_DOMAIN.to_vec();
            message.extend_from_slice(&changed);
            let changed_signature = runtime.sign(&message);
            let roots = CanaryTrustRoots::validated(
                operator.public_key().as_ref().try_into().unwrap(),
                image.public_key().as_ref().try_into().unwrap(),
                runtime.public_key().as_ref().try_into().unwrap(),
            )
            .unwrap();
            assert!(verify_advisory_canary_authorization_with_roots(
                roots,
                &statement,
                &operator_signature,
                &attestation,
                &image_signature,
                &changed,
                changed_signature.as_ref(),
            )
            .is_err());
        }
    }

    #[test]
    fn malformed_domains_roots_and_signatures_never_authorize() {
        let (
            statement,
            operator_signature,
            attestation,
            image_signature,
            runtime_admission,
            runtime_signature,
            _,
        ) = signed_fixture();
        assert!(CanaryTrustRoots::validated([0; 32], [2; 32], [3; 32]).is_err());
        assert!(CanaryTrustRoots::validated([1; 32], [0; 32], [3; 32]).is_err());
        assert!(CanaryTrustRoots::validated([1; 32], [2; 32], [0; 32]).is_err());
        assert!(CanaryTrustRoots::validated([1; 32], [1; 32], [3; 32]).is_err());
        assert!(CanaryTrustRoots::validated([1; 32], [2; 32], [1; 32]).is_err());
        assert!(CanaryTrustRoots::validated([1; 32], [2; 32], [2; 32]).is_err());
        assert!(verify_pinned_advisory_canary_authorization(
            &statement,
            &operator_signature,
            &attestation,
            &image_signature,
            &runtime_admission,
            &runtime_signature,
        )
        .is_err());
        let operator = key(0x11);
        let image = key(0x22);
        let runtime = key(0x23);
        let roots = || {
            CanaryTrustRoots::validated(
                operator.public_key().as_ref().try_into().unwrap(),
                image.public_key().as_ref().try_into().unwrap(),
                runtime.public_key().as_ref().try_into().unwrap(),
            )
            .unwrap()
        };
        assert!(verify_advisory_canary_authorization_with_roots(
            roots(),
            &statement[..statement.len() - 1],
            &operator_signature,
            &attestation,
            &image_signature,
            &runtime_admission,
            &runtime_signature,
        )
        .is_err());
        assert!(verify_advisory_canary_authorization_with_roots(
            roots(),
            &statement,
            &operator_signature[..63],
            &attestation,
            &image_signature,
            &runtime_admission,
            &runtime_signature,
        )
        .is_err());
        let mut wrong_domain_message = b"wrong-domain\0".to_vec();
        wrong_domain_message.extend_from_slice(&statement);
        let wrong_domain_signature = operator.sign(&wrong_domain_message);
        assert!(verify_advisory_canary_authorization_with_roots(
            roots(),
            &statement,
            wrong_domain_signature.as_ref(),
            &attestation,
            &image_signature,
            &runtime_admission,
            &runtime_signature,
        )
        .is_err());
        let wrong_key_signature =
            operator.sign(&[IMAGE_ATTESTATION_DOMAIN, attestation.as_slice()].concat());
        assert!(verify_advisory_canary_authorization_with_roots(
            roots(),
            &statement,
            &operator_signature,
            &attestation,
            wrong_key_signature.as_ref(),
            &runtime_admission,
            &runtime_signature,
        )
        .is_err());
        let wrong_runtime_signature =
            image.sign(&[RUNTIME_ADMISSION_DOMAIN, runtime_admission.as_slice()].concat());
        assert!(verify_advisory_canary_authorization_with_roots(
            roots(),
            &statement,
            &operator_signature,
            &attestation,
            &image_signature,
            &runtime_admission,
            wrong_runtime_signature.as_ref(),
        )
        .is_err());
    }
}
