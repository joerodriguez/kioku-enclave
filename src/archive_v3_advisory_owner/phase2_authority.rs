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

    /// Copy the exact verified statement and admission facts encrypted
    /// control consumes for the one-shot acquisition mint. The bridge is
    /// content-free: it carries only identities, commitments, and hashes the
    /// three pinned roots signed, never the signed payloads themselves.
    pub(crate) fn acquisition_evidence(&self) -> Phase2AuthorityAcquisitionEvidence {
        Phase2AuthorityAcquisitionEvidence {
            scope_id: self.statement.scope_id,
            user_id_commitment: self.statement.user_id_commitment,
            archive_id: self.statement.archive_id,
            operation_id: self.statement.operation_id,
            operation_commitment: self.statement.operation_commitment,
            source_commitment: self.statement.source_commitment,
            parity_commitment: self.statement.parity_commitment,
            terminal_witness_hash: self.statement.terminal_witness_hash,
            release_image_digest: self.statement.release_image_digest,
            maintenance_window_id: self.admission.maintenance_window_id,
            evidence_commitment: self.evidence_commitment,
        }
    }

    /// Test-only mint of an already-"verified" authorization from parsed
    /// parts. Production instances exist only through
    /// [`verify_pinned_phase2_authority`].
    #[cfg(test)]
    pub(crate) fn mint_for_test(
        statement: ParsedPhase2Statement,
        admission: ParsedPhase2Admission,
        evidence_commitment: [u8; 32],
    ) -> Self {
        Self {
            statement,
            admission,
            evidence_commitment,
        }
    }
}

/// Content-free bridge from one pinned-root-verified Phase-2 authorization to
/// encrypted control's acquisition mint. Constructible only from a
/// [`VerifiedPhase2AuthorityAuthorization`]; control byte-compares every field
/// against its durable advisory-terminal rows inside one transaction.
pub(crate) struct Phase2AuthorityAcquisitionEvidence {
    scope_id: [u8; 16],
    user_id_commitment: [u8; 32],
    archive_id: ArchiveId,
    operation_id: [u8; 16],
    operation_commitment: [u8; 32],
    source_commitment: [u8; 32],
    parity_commitment: [u8; 32],
    terminal_witness_hash: [u8; 32],
    release_image_digest: [u8; 32],
    maintenance_window_id: [u8; 16],
    evidence_commitment: [u8; 32],
}

impl std::fmt::Debug for Phase2AuthorityAcquisitionEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Phase2AuthorityAcquisitionEvidence(<opaque>)")
    }
}

impl Phase2AuthorityAcquisitionEvidence {
    pub(crate) const fn scope_id(&self) -> [u8; 16] {
        self.scope_id
    }

    pub(crate) const fn user_id_commitment(&self) -> [u8; 32] {
        self.user_id_commitment
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    pub(crate) const fn operation_commitment(&self) -> [u8; 32] {
        self.operation_commitment
    }

    pub(crate) const fn source_commitment(&self) -> [u8; 32] {
        self.source_commitment
    }

    pub(crate) const fn parity_commitment(&self) -> [u8; 32] {
        self.parity_commitment
    }

    pub(crate) const fn terminal_witness_hash(&self) -> [u8; 32] {
        self.terminal_witness_hash
    }

    pub(crate) const fn release_image_digest(&self) -> [u8; 32] {
        self.release_image_digest
    }

    pub(crate) const fn maintenance_window_id(&self) -> [u8; 16] {
        self.maintenance_window_id
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

    // Evidence produced by scripts/phase2_sign_authority.py with the real
    // operator-held roots over synthetic facts. Verifier acceptance pins the
    // byte-exact signer/verifier wire contract for the Phase-2 domains; the
    // synthetic facts can never satisfy any durable Control predicate.
    const SIGNER_FIXTURE_STATEMENT: &[&str] = &[
        "0001111111111111111111111111111111112222222222222222222222222222",
        "2222222222222222222222222222222222223333333333333333333333333333",
        "3333444444444444444444444444444444445555555555555555555555555555",
        "5555555555555555555555555555555555556666666666666666666666666666",
        "6666666666666666666666666666666666667777777777777777777777777777",
        "7777777777777777777777777777777777778888888888888888888888888888",
        "8888888888888888888888888888888888889999999999999999999999999999",
        "999999999999999999999999999999999999",
    ];
    const SIGNER_FIXTURE_STATEMENT_SIGNATURE: &[&str] = &[
        "39ad1a68bdb24acad3547bfda68a916058f973de7d4b0e9d827e9530f1cd5a60",
        "2e6cd49ce18ec35660394b475e496127c08c1a7e70899b8f667a114df35aad09",
    ];
    const SIGNER_FIXTURE_ATTESTATION: &[&str] = &[
        "000111111111111111111111111111111111b9d94876edccc0498c7c562dc0cc",
        "c771df556cb2e3c0a502de76a984db1a74659999999999999999999999999999",
        "999999999999999999999999999999999999",
    ];
    const SIGNER_FIXTURE_ATTESTATION_SIGNATURE: &[&str] = &[
        "1d49ba9be14bd91ba3fc2480da598f939e4028480e03ee37e6bcf8f378513bcb",
        "b04d3a960c39312da8f8838c6151f1c9f400ab55683b67ab947689c2cbe16b0b",
    ];
    const SIGNER_FIXTURE_ADMISSION: &[&str] = &[
        "000111111111111111111111111111111111b9d94876edccc0498c7c562dc0cc",
        "c771df556cb2e3c0a502de76a984db1a74659999999999999999999999999999",
        "999999999999999999999999999999999999943dd3496bd5cabc5a054605caed",
        "f27969ec0fa3a0af574d902284b246b217b7aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "ccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "ddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "eeee0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
        "0f0f0200000200000000",
    ];
    const SIGNER_FIXTURE_ADMISSION_SIGNATURE: &[&str] = &[
        "cad962f4983fdfa157361de42ba13f6a26114ff5f6af8c895e17cbc21f0de33e",
        "0ea151067ed6548f30410ff86202a5406f5919e44466689a5e71e630e859b80f",
    ];

    fn signer_fixture(parts: &[&str]) -> Vec<u8> {
        let mut joined = String::new();
        for part in parts {
            joined.push_str(part);
        }
        (0..joined.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&joined[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn pinned_phase2_verifier_accepts_the_offline_signer_tool_evidence_exactly() {
        let statement = signer_fixture(SIGNER_FIXTURE_STATEMENT);
        let statement_signature = signer_fixture(SIGNER_FIXTURE_STATEMENT_SIGNATURE);
        let attestation = signer_fixture(SIGNER_FIXTURE_ATTESTATION);
        let attestation_signature = signer_fixture(SIGNER_FIXTURE_ATTESTATION_SIGNATURE);
        let admission = signer_fixture(SIGNER_FIXTURE_ADMISSION);
        let admission_signature = signer_fixture(SIGNER_FIXTURE_ADMISSION_SIGNATURE);
        let authorization = verify_pinned_phase2_authority(
            &statement,
            &statement_signature,
            &attestation,
            &attestation_signature,
            &admission,
            &admission_signature,
        )
        .expect("signer-produced Phase-2 evidence must verify against the pinned roots");
        assert_eq!(authorization.statement().scope_id, [0x11; 16]);

        for tamper in 0..6 {
            let mut parts = [
                statement.clone(),
                statement_signature.clone(),
                attestation.clone(),
                attestation_signature.clone(),
                admission.clone(),
                admission_signature.clone(),
            ];
            parts[tamper][0] ^= 0x01;
            assert!(
                verify_pinned_phase2_authority(
                    &parts[0], &parts[1], &parts[2], &parts[3], &parts[4], &parts[5],
                )
                .is_err(),
                "tampered Phase-2 element {tamper} must refuse"
            );
        }
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
