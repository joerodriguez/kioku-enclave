//! Cryptographic admission boundary for one inactive Phase-1 advisory canary.
//!
//! An operator signature selects one exact already-parity-verified target. A
//! separate image-attestation verifier signature binds that statement to the
//! exact release-image digest. The two Ed25519 roots must be nonzero and
//! distinct. Production roots intentionally remain unset, so this verifier
//! cannot currently mint an authorization and has no live caller.

use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

use super::{AdvisoryOwnerError, Result};
use crate::{archive_v3::ArchiveId, archive_v3_maintenance_import::MaintenanceImportOperationId};

const OPERATOR_STATEMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-canary/operator-statement/v1\0";
const OPERATOR_STATEMENT_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-canary/operator-statement-commitment/v1\0";
const IMAGE_ATTESTATION_DOMAIN: &[u8] = b"kioku/archive-v3/advisory-canary/image-attestation/v1\0";
const AUTHORIZATION_EVIDENCE_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-canary/authorization-evidence/v1\0";

const OPERATOR_STATEMENT_FORMAT_V1: u16 = 1;
const IMAGE_ATTESTATION_FORMAT_V1: u16 = 1;
const OPERATOR_STATEMENT_BYTES: usize = 242;
const IMAGE_ATTESTATION_BYTES: usize = 82;
const ED25519_SIGNATURE_BYTES: usize = 64;

// These are deliberately invalid until a separately reviewed activation
// change pins two real, independently controlled Ed25519 public keys. A caller
// cannot replace either root through configuration, environment, or a request.
const PINNED_OPERATOR_PUBLIC_KEY: [u8; 32] = [0; 32];
const PINNED_IMAGE_ATTESTATION_PUBLIC_KEY: [u8; 32] = [0; 32];

struct CanaryTrustRoots {
    operator: [u8; 32],
    image_attestation: [u8; 32],
}

impl CanaryTrustRoots {
    fn pinned() -> Result<Self> {
        Self::validated(
            PINNED_OPERATOR_PUBLIC_KEY,
            PINNED_IMAGE_ATTESTATION_PUBLIC_KEY,
        )
    }

    fn validated(operator: [u8; 32], image_attestation: [u8; 32]) -> Result<Self> {
        if operator == [0; 32] || image_attestation == [0; 32] || operator == image_attestation {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(Self {
            operator,
            image_attestation,
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

/// Signature-authenticated, image-attested authority to insert one exact
/// inactive canary scope. It is non-cloneable, has no provider/Store/runtime
/// operation, and exposes its binding only to encrypted Control.
pub(crate) struct VerifiedAdvisoryCanaryAuthorization {
    statement: ParsedOperatorStatement,
    operator_statement_commitment: [u8; 32],
}

impl VerifiedAdvisoryCanaryAuthorization {
    pub(crate) fn operation_id_for_control(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> [u8; 16] {
        self.statement.operation_id
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
        if scope_id == [0; 16]
            || release_image_digest == [0; 32]
            || operator_statement_commitment == [0; 32]
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            statement,
            operator_statement_commitment,
        })
    }
}

pub(crate) struct AdvisoryCanaryAuthorizationControlView {
    pub(crate) scope_id: [u8; 16],
    pub(crate) release_image_digest: [u8; 32],
    pub(crate) operator_statement_commitment: [u8; 32],
}

impl std::fmt::Debug for VerifiedAdvisoryCanaryAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedAdvisoryCanaryAuthorization(<opaque>)")
    }
}

/// Verify the two detached signatures against compile-time trust roots. The
/// pinned roots are intentionally invalid today, so production cannot issue a
/// scope until a separately reviewed activation change supplies real anchors.
pub(crate) fn verify_pinned_advisory_canary_authorization(
    statement: &[u8],
    operator_signature: &[u8],
    image_attestation: &[u8],
    image_attestation_signature: &[u8],
) -> Result<VerifiedAdvisoryCanaryAuthorization> {
    verify_advisory_canary_authorization_with_roots(
        CanaryTrustRoots::pinned()?,
        statement,
        operator_signature,
        image_attestation,
        image_attestation_signature,
    )
}

fn verify_advisory_canary_authorization_with_roots(
    roots: CanaryTrustRoots,
    statement: &[u8],
    operator_signature: &[u8],
    image_attestation: &[u8],
    image_attestation_signature: &[u8],
) -> Result<VerifiedAdvisoryCanaryAuthorization> {
    if operator_signature.len() != ED25519_SIGNATURE_BYTES
        || image_attestation_signature.len() != ED25519_SIGNATURE_BYTES
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
    let evidence_commitment = authorization_evidence_commitment(
        statement,
        &roots.operator,
        operator_signature,
        image_attestation,
        &roots.image_attestation,
        image_attestation_signature,
    );
    Ok(VerifiedAdvisoryCanaryAuthorization {
        statement: parsed,
        operator_statement_commitment: evidence_commitment,
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

fn authorization_evidence_commitment(
    statement: &[u8],
    operator_public_key: &[u8; 32],
    operator_signature: &[u8],
    image_attestation: &[u8],
    image_attestation_public_key: &[u8; 32],
    image_attestation_signature: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORIZATION_EVIDENCE_COMMITMENT_DOMAIN);
    hasher.update(operator_public_key);
    hasher.update(statement);
    hasher.update(operator_signature);
    hasher.update(image_attestation_public_key);
    hasher.update(image_attestation);
    hasher.update(image_attestation_signature);
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

    fn signed_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, CanaryTrustRoots) {
        let operator = key(0x11);
        let image = key(0x22);
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
        let roots = CanaryTrustRoots::validated(
            operator.public_key().as_ref().try_into().unwrap(),
            image.public_key().as_ref().try_into().unwrap(),
        )
        .unwrap();
        (
            statement,
            operator_signature,
            attestation,
            image_signature,
            roots,
        )
    }

    #[test]
    fn exact_two_root_authorization_authenticates_control_target() {
        let (statement, operator_signature, attestation, image_signature, roots) = signed_fixture();
        let verified = verify_advisory_canary_authorization_with_roots(
            roots,
            &statement,
            &operator_signature,
            &attestation,
            &image_signature,
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
        assert_eq!(
            view.operator_statement_commitment,
            authorization_evidence_commitment(
                &statement,
                operator.public_key().as_ref().try_into().unwrap(),
                &operator_signature,
                &attestation,
                image.public_key().as_ref().try_into().unwrap(),
                &image_signature,
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
        let (statement, operator_signature, attestation, image_signature, _) = signed_fixture();
        let operator = key(0x11);
        let image = key(0x22);
        for offset in [2, 18, 50, 66, 82, 114, 146, 178, 210] {
            let mut changed = statement.clone();
            changed[offset] ^= 1;
            let roots = CanaryTrustRoots::validated(
                operator.public_key().as_ref().try_into().unwrap(),
                image.public_key().as_ref().try_into().unwrap(),
            )
            .unwrap();
            assert!(verify_advisory_canary_authorization_with_roots(
                roots,
                &changed,
                &operator_signature,
                &attestation,
                &image_signature,
            )
            .is_err());
        }
        for offset in [2, 18, 50] {
            let mut changed = attestation.clone();
            changed[offset] ^= 1;
            let roots = CanaryTrustRoots::validated(
                operator.public_key().as_ref().try_into().unwrap(),
                image.public_key().as_ref().try_into().unwrap(),
            )
            .unwrap();
            assert!(verify_advisory_canary_authorization_with_roots(
                roots,
                &statement,
                &operator_signature,
                &changed,
                &image_signature,
            )
            .is_err());
        }
    }

    #[test]
    fn malformed_domains_roots_and_signatures_never_authorize() {
        let (statement, operator_signature, attestation, image_signature, _) = signed_fixture();
        assert!(CanaryTrustRoots::validated([0; 32], [2; 32]).is_err());
        assert!(CanaryTrustRoots::validated([1; 32], [0; 32]).is_err());
        assert!(CanaryTrustRoots::validated([1; 32], [1; 32]).is_err());
        assert!(verify_pinned_advisory_canary_authorization(
            &statement,
            &operator_signature,
            &attestation,
            &image_signature,
        )
        .is_err());
        let operator = key(0x11);
        let image = key(0x22);
        let roots = || {
            CanaryTrustRoots::validated(
                operator.public_key().as_ref().try_into().unwrap(),
                image.public_key().as_ref().try_into().unwrap(),
            )
            .unwrap()
        };
        assert!(verify_advisory_canary_authorization_with_roots(
            roots(),
            &statement[..statement.len() - 1],
            &operator_signature,
            &attestation,
            &image_signature,
        )
        .is_err());
        assert!(verify_advisory_canary_authorization_with_roots(
            roots(),
            &statement,
            &operator_signature[..63],
            &attestation,
            &image_signature,
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
        )
        .is_err());
    }
}
