//! Cryptographic admission boundary for the Phase-2 WAL-authority acquisition.
//!
//! Phase 1's [`VerifiedAdvisoryCanaryAuthorization`](super::canary_trust) cryptographically
//! fixes an **empty** authoritative mutation set and legacy-only acknowledgements, so it can
//! never authorize a cutover. This module is its deliberately distinct Phase-2 counterpart:
//! the same three pinned operator-held roots sign the same 242-byte operator statement and
//! 82-byte image attestation shapes under **Phase-2 domains**, and a 298-byte runtime
//! admission that hard-requires:
//! - the canonical **full reviewed mutation-set commitment** — a domain-separated hash over
//!   every [`WalOperationKind`] ordinal, exhaustively matched so adding a kind fails
//!   compilation until a new reviewed commitment (and a fresh operator signature) exists;
//!   the empty Phase-1 set is structurally unacceptable here, and any other subset is
//!   rejected byte-exactly;
//! - the `PHASE2_WAL_AUTHORITY` phase marker and `ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT`
//!   acknowledgement policy marker — acknowledgement on local SQLite commit alone is not
//!   representable in this format;
//! - the same window/target/challenge/monitoring/rollback commitments the live window
//!   verifies, so a Phase-2 admission binds one exact maintenance window.
//!
//! A signature under a Phase-1 domain can never verify under a Phase-2 domain (and vice
//! versa), so replaying advisory evidence into an authority acquisition is impossible.
//! This slice ships the format and verifier only: the sole intended consumer is the
//! separately reviewed acquisition transition that alone may select
//! `MaintenanceImportTarget::WalAuthoritative`.

use sha2::{Digest, Sha256};

use super::{canary_trust, AdvisoryOwnerError, Result};
use crate::archive_v3::ArchiveId;
use crate::archive_v3_wal_idempotency::WalOperationKind;

const PHASE2_OPERATOR_STATEMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/phase2-authority/operator-statement/v1\0";
const PHASE2_OPERATOR_STATEMENT_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/phase2-authority/operator-statement-commitment/v1\0";
const PHASE2_IMAGE_ATTESTATION_DOMAIN: &[u8] =
    b"kioku/archive-v3/phase2-authority/image-attestation/v1\0";
const PHASE2_RUNTIME_ADMISSION_DOMAIN: &[u8] =
    b"kioku/archive-v3/phase2-authority/runtime-admission/v1\0";
const FULL_REVIEWED_MUTATION_SET_DOMAIN: &[u8] =
    b"kioku/archive-v3/phase2-authority/authoritative-mutation-set/full-reviewed/v1\0";
const PHASE2_EVIDENCE_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/phase2-authority/authorization-evidence/v1\0";

const OPERATOR_STATEMENT_FORMAT_V1: u16 = 1;
const IMAGE_ATTESTATION_FORMAT_V1: u16 = 1;
const RUNTIME_ADMISSION_FORMAT_V1: u16 = 1;
const OPERATOR_STATEMENT_BYTES: usize = 242;
const IMAGE_ATTESTATION_BYTES: usize = 82;
const RUNTIME_ADMISSION_BYTES: usize = 298;
const ED25519_SIGNATURE_BYTES: usize = 64;
const PHASE2_WAL_AUTHORITY: u8 = 2;
const ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT: u8 = 2;

/// Canonical commitment to the complete reviewed mutation set: every
/// [`WalOperationKind`] ordinal, ascending. The exhaustive match means a newly added
/// kind fails compilation here until this commitment (and every signed Phase-2
/// admission) is deliberately re-reviewed.
pub(crate) fn full_reviewed_mutation_set_commitment() -> [u8; 32] {
    let kinds = [
        WalOperationKind::MediaCaptureEvent,
        WalOperationKind::CaptureSessionFinish,
        WalOperationKind::SelectedScreenshot,
        WalOperationKind::FinalizationQueue,
        WalOperationKind::FinalizationCommit,
        WalOperationKind::DeterministicMediaWorkResult,
        WalOperationKind::VertexUsage,
        WalOperationKind::WebhookDelivery,
        WalOperationKind::EmailDelivery,
        WalOperationKind::PushDelivery,
        WalOperationKind::Retention,
        WalOperationKind::ReviewerBackfill,
    ];
    // Compile-time exhaustiveness: adding a WalOperationKind variant breaks this match
    // until it is deliberately added to the reviewed set above.
    for kind in kinds {
        match kind {
            WalOperationKind::MediaCaptureEvent
            | WalOperationKind::CaptureSessionFinish
            | WalOperationKind::SelectedScreenshot
            | WalOperationKind::FinalizationQueue
            | WalOperationKind::FinalizationCommit
            | WalOperationKind::DeterministicMediaWorkResult
            | WalOperationKind::VertexUsage
            | WalOperationKind::WebhookDelivery
            | WalOperationKind::EmailDelivery
            | WalOperationKind::PushDelivery
            | WalOperationKind::Retention
            | WalOperationKind::ReviewerBackfill => {}
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(FULL_REVIEWED_MUTATION_SET_DOMAIN);
    hasher.update(1_u16.to_be_bytes());
    hasher.update((kinds.len() as u16).to_be_bytes());
    for kind in kinds {
        hasher.update((kind as u16).to_be_bytes());
    }
    hasher.finalize().into()
}

/// Parsed Phase-2 operator statement (same 242-byte shape as Phase 1, distinct domain).
pub(crate) struct ParsedPhase2Statement {
    pub(crate) scope_id: [u8; 16],
    pub(crate) user_id_commitment: [u8; 32],
    pub(crate) archive_id: ArchiveId,
    pub(crate) operation_id: [u8; 16],
    pub(crate) operation_commitment: [u8; 32],
    pub(crate) source_commitment: [u8; 32],
    pub(crate) parity_commitment: [u8; 32],
    pub(crate) terminal_witness_hash: [u8; 32],
    pub(crate) release_image_digest: [u8; 32],
}

impl std::fmt::Debug for ParsedPhase2Statement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ParsedPhase2Statement(<opaque>)")
    }
}

/// Parsed Phase-2 runtime admission facts.
pub(crate) struct ParsedPhase2Admission {
    pub(crate) enabled_mutation_set_commitment: [u8; 32],
    pub(crate) deployment_target_commitment: [u8; 32],
    pub(crate) maintenance_window_id: [u8; 16],
    pub(crate) deployment_revision_commitment: [u8; 32],
    pub(crate) challenge_commitment: [u8; 32],
    pub(crate) monitoring_policy_commitment: [u8; 32],
    pub(crate) rollback_policy_commitment: [u8; 32],
}

impl std::fmt::Debug for ParsedPhase2Admission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ParsedPhase2Admission(<opaque>)")
    }
}

/// Non-cloneable proof that the three pinned roots authorized one exact Phase-2
/// WAL-authority acquisition. Constructible only by [`verify_pinned_phase2_authority`].
pub(crate) struct VerifiedPhase2AuthorityAuthorization {
    statement: ParsedPhase2Statement,
    admission: ParsedPhase2Admission,
    evidence_commitment: [u8; 32],
}

impl std::fmt::Debug for VerifiedPhase2AuthorityAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedPhase2AuthorityAuthorization(<opaque>)")
    }
}

impl VerifiedPhase2AuthorityAuthorization {
    pub(crate) fn statement(&self) -> &ParsedPhase2Statement {
        &self.statement
    }

    pub(crate) fn admission(&self) -> &ParsedPhase2Admission {
        &self.admission
    }

    pub(crate) const fn evidence_commitment(&self) -> [u8; 32] {
        self.evidence_commitment
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)
}

fn parse_statement(value: &[u8]) -> Result<ParsedPhase2Statement> {
    let bytes: &[u8; OPERATOR_STATEMENT_BYTES] =
        value.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)?;
    if u16::from_be_bytes([bytes[0], bytes[1]]) != OPERATOR_STATEMENT_FORMAT_V1 {
        return Err(AdvisoryOwnerError::Corrupt);
    }
    let statement = ParsedPhase2Statement {
        scope_id: fixed::<16>(&bytes[2..18])?,
        user_id_commitment: fixed::<32>(&bytes[18..50])?,
        archive_id: ArchiveId::from_bytes(fixed::<16>(&bytes[50..66])?),
        operation_id: fixed::<16>(&bytes[66..82])?,
        operation_commitment: fixed::<32>(&bytes[82..114])?,
        source_commitment: fixed::<32>(&bytes[114..146])?,
        parity_commitment: fixed::<32>(&bytes[146..178])?,
        terminal_witness_hash: fixed::<32>(&bytes[178..210])?,
        release_image_digest: fixed::<32>(&bytes[210..242])?,
    };
    if statement.scope_id == [0; 16]
        || statement.user_id_commitment == [0; 32]
        || statement.archive_id.as_bytes() == &[0; 16]
        || statement.operation_id == [0; 16]
        || statement.operation_commitment == [0; 32]
        || statement.source_commitment == [0; 32]
        || statement.parity_commitment == [0; 32]
        || statement.terminal_witness_hash == [0; 32]
        || statement.release_image_digest == [0; 32]
    {
        return Err(AdvisoryOwnerError::Corrupt);
    }
    Ok(statement)
}

fn statement_commitment(value: &[u8], public_key: &[u8; 32], signature: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PHASE2_OPERATOR_STATEMENT_COMMITMENT_DOMAIN);
    hasher.update(public_key);
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
    hasher.update((signature.len() as u32).to_be_bytes());
    hasher.update(signature);
    hasher.finalize().into()
}

fn authenticate_image_attestation(
    value: &[u8],
    statement: &ParsedPhase2Statement,
    commitment: &[u8; 32],
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let bytes: &[u8; IMAGE_ATTESTATION_BYTES] =
        value.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)?;
    if u16::from_be_bytes([bytes[0], bytes[1]]) != IMAGE_ATTESTATION_FORMAT_V1
        || fixed::<16>(&bytes[2..18])? != statement.scope_id
        || fixed::<32>(&bytes[18..50])? != *commitment
        || fixed::<32>(&bytes[50..82])? != statement.release_image_digest
    {
        return Err(AdvisoryOwnerError::Conflict);
    }
    canary_trust::verify_observer_signature(
        public_key,
        PHASE2_IMAGE_ATTESTATION_DOMAIN,
        value,
        signature,
    )
}

fn authenticate_runtime_admission(
    value: &[u8],
    statement: &ParsedPhase2Statement,
    commitment: &[u8; 32],
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<ParsedPhase2Admission> {
    let bytes: &[u8; RUNTIME_ADMISSION_BYTES] =
        value.try_into().map_err(|_| AdvisoryOwnerError::Corrupt)?;
    let enabled_mutation_set_commitment = fixed::<32>(&bytes[82..114])?;
    if u16::from_be_bytes([bytes[0], bytes[1]]) != RUNTIME_ADMISSION_FORMAT_V1
        || fixed::<16>(&bytes[2..18])? != statement.scope_id
        || fixed::<32>(&bytes[18..50])? != *commitment
        || fixed::<32>(&bytes[50..82])? != statement.release_image_digest
        // The enabled set must be exactly the full reviewed set: never empty, never
        // a subset, never anything a signer improvised.
        || enabled_mutation_set_commitment != full_reviewed_mutation_set_commitment()
        || fixed::<32>(&bytes[114..146])? == [0; 32]
        || fixed::<16>(&bytes[146..162])? == [0; 16]
        || fixed::<32>(&bytes[162..194])? == [0; 32]
        || fixed::<32>(&bytes[194..226])? == [0; 32]
        || fixed::<32>(&bytes[226..258])? == [0; 32]
        || fixed::<32>(&bytes[258..290])? == [0; 32]
        || bytes[290] != PHASE2_WAL_AUTHORITY
        || u16::from_be_bytes([bytes[291], bytes[292]]) != 0
        || bytes[293] != ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT
        || u32::from_be_bytes([bytes[294], bytes[295], bytes[296], bytes[297]]) != 0
    {
        return Err(AdvisoryOwnerError::Conflict);
    }
    canary_trust::verify_observer_signature(
        public_key,
        PHASE2_RUNTIME_ADMISSION_DOMAIN,
        value,
        signature,
    )?;
    Ok(ParsedPhase2Admission {
        enabled_mutation_set_commitment,
        deployment_target_commitment: fixed::<32>(&bytes[114..146])?,
        maintenance_window_id: fixed::<16>(&bytes[146..162])?,
        deployment_revision_commitment: fixed::<32>(&bytes[162..194])?,
        challenge_commitment: fixed::<32>(&bytes[194..226])?,
        monitoring_policy_commitment: fixed::<32>(&bytes[226..258])?,
        rollback_policy_commitment: fixed::<32>(&bytes[258..290])?,
    })
}

/// Verify one complete Phase-2 authority authorization against the pinned roots.
pub(crate) fn verify_pinned_phase2_authority(
    statement: &[u8],
    operator_signature: &[u8],
    image_attestation: &[u8],
    image_attestation_signature: &[u8],
    runtime_admission: &[u8],
    runtime_admission_signature: &[u8],
) -> Result<VerifiedPhase2AuthorityAuthorization> {
    if operator_signature.len() != ED25519_SIGNATURE_BYTES
        || image_attestation_signature.len() != ED25519_SIGNATURE_BYTES
        || runtime_admission_signature.len() != ED25519_SIGNATURE_BYTES
    {
        return Err(AdvisoryOwnerError::Corrupt);
    }
    let (operator_root, image_root, deployment_root) = canary_trust::pinned_roots_for_phase2()?;
    let parsed = parse_statement(statement)?;
    canary_trust::verify_observer_signature(
        &operator_root,
        PHASE2_OPERATOR_STATEMENT_DOMAIN,
        statement,
        operator_signature,
    )?;
    let commitment = statement_commitment(statement, &operator_root, operator_signature);
    authenticate_image_attestation(
        image_attestation,
        &parsed,
        &commitment,
        &image_root,
        image_attestation_signature,
    )?;
    let admission = authenticate_runtime_admission(
        runtime_admission,
        &parsed,
        &commitment,
        &deployment_root,
        runtime_admission_signature,
    )?;

    let mut hasher = Sha256::new();
    hasher.update(PHASE2_EVIDENCE_COMMITMENT_DOMAIN);
    for (payload, signature) in [
        (statement, operator_signature),
        (image_attestation, image_attestation_signature),
        (runtime_admission, runtime_admission_signature),
    ] {
        hasher.update((payload.len() as u32).to_be_bytes());
        hasher.update(payload);
        hasher.update((signature.len() as u32).to_be_bytes());
        hasher.update(signature);
    }
    let evidence_commitment = hasher.finalize().into();

    Ok(VerifiedPhase2AuthorityAuthorization {
        statement: parsed,
        admission,
        evidence_commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn sign(key: &Ed25519KeyPair, domain: &[u8], value: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(domain.len() + value.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(value);
        key.sign(&message).as_ref().to_vec()
    }

    fn statement_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(OPERATOR_STATEMENT_BYTES);
        bytes.extend_from_slice(&OPERATOR_STATEMENT_FORMAT_V1.to_be_bytes());
        bytes.extend_from_slice(&[0x11; 16]); // scope
        bytes.extend_from_slice(&[0x22; 32]); // user commitment
        bytes.extend_from_slice(&[0x33; 16]); // archive
        bytes.extend_from_slice(&[0x44; 16]); // operation id
        bytes.extend_from_slice(&[0x55; 32]); // operation commitment
        bytes.extend_from_slice(&[0x66; 32]); // source
        bytes.extend_from_slice(&[0x77; 32]); // parity
        bytes.extend_from_slice(&[0x88; 32]); // terminal witness
        bytes.extend_from_slice(&[0x99; 32]); // image digest
        bytes
    }

    fn admission_bytes(
        statement_commitment: [u8; 32],
        mutation_set: [u8; 32],
        phase: u8,
        ack: u8,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RUNTIME_ADMISSION_BYTES);
        bytes.extend_from_slice(&RUNTIME_ADMISSION_FORMAT_V1.to_be_bytes());
        bytes.extend_from_slice(&[0x11; 16]); // scope
        bytes.extend_from_slice(&statement_commitment);
        bytes.extend_from_slice(&[0x99; 32]); // image digest
        bytes.extend_from_slice(&mutation_set);
        bytes.extend_from_slice(&[0xAA; 32]); // target
        bytes.extend_from_slice(&[0xBB; 16]); // window id
        bytes.extend_from_slice(&[0xCC; 32]); // revision
        bytes.extend_from_slice(&[0xDD; 32]); // challenge
        bytes.extend_from_slice(&[0xEE; 32]); // monitoring
        bytes.extend_from_slice(&[0xFF; 32]); // rollback
        bytes.push(phase);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.push(ack);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(bytes.len(), RUNTIME_ADMISSION_BYTES);
        bytes
    }

    fn attestation_bytes(statement_commitment: [u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(IMAGE_ATTESTATION_BYTES);
        bytes.extend_from_slice(&IMAGE_ATTESTATION_FORMAT_V1.to_be_bytes());
        bytes.extend_from_slice(&[0x11; 16]);
        bytes.extend_from_slice(&statement_commitment);
        bytes.extend_from_slice(&[0x99; 32]);
        bytes
    }

    #[test]
    fn full_reviewed_set_commitment_is_stable_nonempty_and_distinct_from_phase1_empty() {
        let full = full_reviewed_mutation_set_commitment();
        assert_eq!(full, full_reviewed_mutation_set_commitment());
        assert_ne!(full, [0; 32]);
        // The Phase-1 empty-set commitment (different domain, zero kinds) can never
        // collide with the full reviewed set.
        let mut hasher = Sha256::new();
        hasher.update(b"kioku/archive-v3/advisory-canary/authoritative-mutation-set/empty/v1\0");
        hasher.update(1_u16.to_be_bytes());
        hasher.update(0_u16.to_be_bytes());
        let empty: [u8; 32] = hasher.finalize().into();
        assert_ne!(full, empty);
    }

    #[test]
    fn phase2_verification_requires_pinned_roots_so_fixture_keys_fail() {
        // The pinned production roots are real operator keys whose private halves
        // never enter this repository, so a fixture-signed authorization must fail
        // exactly like any forgery: at signature verification against the roots.
        let operator = key(0x01);
        let statement = statement_bytes();
        let operator_signature = sign(&operator, PHASE2_OPERATOR_STATEMENT_DOMAIN, &statement);
        let commitment = statement_commitment(
            &statement,
            operator.public_key().as_ref().try_into().unwrap(),
            &operator_signature,
        );
        let attestation = attestation_bytes(commitment);
        let admission = admission_bytes(
            commitment,
            full_reviewed_mutation_set_commitment(),
            PHASE2_WAL_AUTHORITY,
            ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT,
        );
        let image = key(0x02);
        let deploy = key(0x03);
        let result = verify_pinned_phase2_authority(
            &statement,
            &operator_signature,
            &attestation,
            &sign(&image, PHASE2_IMAGE_ATTESTATION_DOMAIN, &attestation),
            &admission,
            &sign(&deploy, PHASE2_RUNTIME_ADMISSION_DOMAIN, &admission),
        );
        assert!(matches!(result, Err(AdvisoryOwnerError::Conflict)));
    }

    #[test]
    fn admission_shape_rejects_empty_set_wrong_phase_and_wrong_ack_with_test_roots() {
        // Drive the shape checks below the root verification by verifying against
        // test roots through the internal functions.
        let operator = key(0x0A);
        let statement = statement_bytes();
        let operator_signature = sign(&operator, PHASE2_OPERATOR_STATEMENT_DOMAIN, &statement);
        let operator_root: [u8; 32] = operator.public_key().as_ref().try_into().unwrap();
        let parsed = parse_statement(&statement).unwrap();
        canary_trust::verify_observer_signature(
            &operator_root,
            PHASE2_OPERATOR_STATEMENT_DOMAIN,
            &statement,
            &operator_signature,
        )
        .unwrap();
        let commitment = statement_commitment(&statement, &operator_root, &operator_signature);

        let deploy = key(0x0B);
        let deploy_root: [u8; 32] = deploy.public_key().as_ref().try_into().unwrap();
        let good = admission_bytes(
            commitment,
            full_reviewed_mutation_set_commitment(),
            PHASE2_WAL_AUTHORITY,
            ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT,
        );
        let admission = authenticate_runtime_admission(
            &good,
            &parsed,
            &commitment,
            &deploy_root,
            &sign(&deploy, PHASE2_RUNTIME_ADMISSION_DOMAIN, &good),
        )
        .unwrap();
        assert_eq!(
            admission.enabled_mutation_set_commitment,
            full_reviewed_mutation_set_commitment()
        );

        // The Phase-1 empty set is rejected even when correctly signed.
        let mut hasher = Sha256::new();
        hasher.update(b"kioku/archive-v3/advisory-canary/authoritative-mutation-set/empty/v1\0");
        hasher.update(1_u16.to_be_bytes());
        hasher.update(0_u16.to_be_bytes());
        let empty: [u8; 32] = hasher.finalize().into();
        let bad_set = admission_bytes(
            commitment,
            empty,
            PHASE2_WAL_AUTHORITY,
            ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT,
        );
        assert!(authenticate_runtime_admission(
            &bad_set,
            &parsed,
            &commitment,
            &deploy_root,
            &sign(&deploy, PHASE2_RUNTIME_ADMISSION_DOMAIN, &bad_set),
        )
        .is_err());

        // Phase-1 marker and legacy-only acknowledgement are unrepresentable.
        for (phase, ack) in [
            (1u8, ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT),
            (PHASE2_WAL_AUTHORITY, 1u8),
        ] {
            let bad = admission_bytes(
                commitment,
                full_reviewed_mutation_set_commitment(),
                phase,
                ack,
            );
            assert!(authenticate_runtime_admission(
                &bad,
                &parsed,
                &commitment,
                &deploy_root,
                &sign(&deploy, PHASE2_RUNTIME_ADMISSION_DOMAIN, &bad),
            )
            .is_err());
        }

        // A Phase-1-domain signature never verifies under the Phase-2 domain.
        let cross = sign(
            &deploy,
            b"kioku/archive-v3/advisory-canary/runtime-admission/v1\0",
            &good,
        );
        assert!(
            authenticate_runtime_admission(&good, &parsed, &commitment, &deploy_root, &cross,)
                .is_err()
        );
    }
}
