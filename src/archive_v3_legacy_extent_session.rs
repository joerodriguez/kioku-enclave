#![allow(
    dead_code,
    reason = "inactive ADR-0022 legacy extent conversion codec is compiled before any source, provider, or authority wiring"
)]

//! Content-free durable identity for a future legacy SQLite-to-extent conversion.
//!
//! This module deliberately owns neither a legacy source nor a provider.  In
//! particular, its candidate is not a witness acknowledgement and cannot
//! advance a root.

use std::fmt;

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    archive_v3::{ArchiveRoot, ObjectContext},
    archive_v3_extent::AuthenticatedLegacyExtentRootReadback,
    archive_v3_operation::{OperationId, RequestFingerprint},
    archive_v3_witness::{DeletionState, MigrationState, WitnessLease, WitnessRecord},
};

const MAGIC: &[u8; 8] = b"KALESv2\0";
const VERSION: u8 = 2;
const SESSION_DOMAIN: &[u8] = b"kioku:archive:v3:legacy-extent-session\0";
const WITNESS_DOMAIN: &[u8] = b"kioku:archive:v3:legacy-extent-witness\0";
const ROOT_AAD_DOMAIN: &[u8] = b"kioku:archive:v3:legacy-extent-root-aad\0";
const MAX_ORPHAN_INVENTORY_OBJECTS: u32 = 32_898;
pub(crate) const LEGACY_EXTENT_SESSION_RECORD_BYTES: usize = 436;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LegacyExtentSessionId([u8; 16]);
impl LegacyExtentSessionId {
    pub(crate) fn for_binding(binding: LegacyExtentSessionBinding) -> Result<Self> {
        if !binding.valid() {
            return Err(LegacyExtentSessionError::Malformed("binding"));
        }
        Self::for_stable_identity(
            binding.archive_id,
            binding.database_epoch,
            binding.operation_id,
        )
    }
    pub(crate) fn for_stable_identity(
        archive_id: [u8; 16],
        database_epoch: [u8; 16],
        operation_id: [u8; 16],
    ) -> Result<Self> {
        if !nonzero(&archive_id) || !nonzero(&database_epoch) || !nonzero(&operation_id) {
            return Err(LegacyExtentSessionError::Malformed("session identity"));
        }
        let mut hash = Sha256::new();
        hash.update(SESSION_DOMAIN);
        hash.update(archive_id);
        hash.update(database_epoch);
        hash.update(operation_id);
        let digest: [u8; 32] = hash.finalize().into();
        let mut value = [0; 16];
        value.copy_from_slice(&digest[..16]);
        Ok(Self(value))
    }
    const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }
    #[cfg(test)]
    pub(crate) const fn from_bytes_for_test(value: [u8; 16]) -> Self {
        Self::from_bytes(value)
    }
    pub(crate) const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}
impl fmt::Debug for LegacyExtentSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentSessionId(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LegacyExtentAttemptId([u8; 16]);
impl LegacyExtentAttemptId {
    pub(crate) fn random() -> Self {
        let mut value = [0; 16];
        loop {
            OsRng.fill_bytes(&mut value);
            if nonzero(&value) {
                return Self(value);
            }
        }
    }
    const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }
    #[cfg(test)]
    pub(crate) const fn from_bytes_for_test(value: [u8; 16]) -> Self {
        Self::from_bytes(value)
    }
    pub(crate) const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}
impl fmt::Debug for LegacyExtentAttemptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentAttemptId(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum LegacyExtentSessionState {
    Prepared = 1,
    CandidateReady = 2,
    OrphanPendingGrace = 3,
}
impl LegacyExtentSessionState {
    pub(crate) fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::CandidateReady),
            3 => Ok(Self::OrphanPendingGrace),
            _ => Err(LegacyExtentSessionError::Corrupt),
        }
    }
    fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Prepared,
                Self::CandidateReady | Self::OrphanPendingGrace
            )
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyExtentCandidate {
    root_seq: u64,
    object_id: [u8; 16],
    ciphertext_hash: [u8; 32],
}
impl LegacyExtentCandidate {
    pub(crate) fn new(
        root_seq: u64,
        object_id: [u8; 16],
        ciphertext_hash: [u8; 32],
    ) -> Result<Self> {
        let value = Self {
            root_seq,
            object_id,
            ciphertext_hash,
        };
        (root_seq != 0 && nonzero(&object_id) && nonzero(&ciphertext_hash))
            .then_some(value)
            .ok_or(LegacyExtentSessionError::Malformed("candidate"))
    }
    pub(crate) const fn root_seq(self) -> u64 {
        self.root_seq
    }
    pub(crate) const fn object_id(self) -> [u8; 16] {
        self.object_id
    }
    pub(crate) const fn ciphertext_hash(self) -> [u8; 32] {
        self.ciphertext_hash
    }
}
impl fmt::Debug for LegacyExtentCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentCandidate(<opaque>)")
    }
}

/// Opaque proof that an exact immutable root readback was authenticated,
/// decoded, context-validated, and bound to this conversion session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyExtentRootAdmission {
    candidate: LegacyExtentCandidate,
    binding: LegacyExtentSessionBinding,
    root_aad_commitment: [u8; 32],
}
impl LegacyExtentRootAdmission {
    pub(crate) const fn candidate(self) -> LegacyExtentCandidate {
        self.candidate
    }
    pub(crate) fn matches(self, binding: LegacyExtentSessionBinding) -> bool {
        self.binding == binding
    }
    pub(crate) fn matches_root_aad(self, canonical_aad: &[u8]) -> bool {
        let mut hash = Sha256::new();
        hash.update(ROOT_AAD_DOMAIN);
        hash.update(canonical_aad);
        let commitment: [u8; 32] = hash.finalize().into();
        self.root_aad_commitment == commitment
    }

    /// Only the sealed extent staging adapter can supply the private-field
    /// readback token.  Raw root/context/hash values are deliberately not a
    /// production admission API.
    pub(crate) fn from_authenticated_readback(
        binding: LegacyExtentSessionBinding,
        readback: AuthenticatedLegacyExtentRootReadback,
    ) -> Result<Self> {
        Self::from_validated_root(
            readback.root(),
            readback.context(),
            readback.ciphertext_hash(),
            binding,
        )
    }

    fn from_validated_root(
        root: &ArchiveRoot,
        context: &ObjectContext,
        ciphertext_hash: [u8; 32],
        binding: LegacyExtentSessionBinding,
    ) -> Result<Self> {
        root.validate_for_context(context)
            .map_err(|_| LegacyExtentSessionError::BindingConflict)?;
        let parent_matches = root.parent.as_ref().is_some_and(|parent| {
            parent.object_id.as_bytes() == &binding.base_root_object_id
                && parent.envelope_hash == binding.base_root_ciphertext_hash
        });
        if context.archive_id().as_bytes() != &binding.archive_id
            || root.database_epoch.as_bytes() != &binding.database_epoch
            || root.key_epoch.as_bytes() != &binding.key_epoch
            || root.root_seq
                != binding
                    .base_root_seq
                    .checked_add(1)
                    .ok_or(LegacyExtentSessionError::Malformed("root sequence"))?
            || !parent_matches
            || root.owner_fencing_epoch != binding.owner_fence
            || root.sqlite_page_size != binding.sqlite_page_size
            || root.logical_file_length != binding.plaintext_len
            || root.storage_format_version != binding.archive_format_version
            || root.extent_tree_root.is_none()
            || root.checkpoint_root.is_some()
            || root.wal_commit_tail.is_some()
            || root.wal_generation != 0
            || root.wal_commit_count != 0
            || root.wal_segment_count != 0
            || root.wal_tail_bytes != 0
            || !nonzero(&ciphertext_hash)
        {
            return Err(LegacyExtentSessionError::BindingConflict);
        }
        let canonical_aad = context.canonical_aad();
        let mut hash = Sha256::new();
        hash.update(ROOT_AAD_DOMAIN);
        hash.update(&canonical_aad);
        Ok(Self {
            candidate: LegacyExtentCandidate::new(
                root.root_seq,
                *context.object_id().as_bytes(),
                ciphertext_hash,
            )?,
            binding,
            root_aad_commitment: hash.finalize().into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_validated_root_for_test(
        root: &ArchiveRoot,
        context: &ObjectContext,
        ciphertext_hash: [u8; 32],
        binding: LegacyExtentSessionBinding,
    ) -> Result<Self> {
        Self::from_validated_root(root, context, ciphertext_hash, binding)
    }
}
impl fmt::Debug for LegacyExtentRootAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentRootAdmission(<opaque>)")
    }
}

/// Exact witness, registry, root, fence, request, and authenticated-source facts.
/// It intentionally excludes source identity, generation, AAD, path, URL, provider,
/// plaintext digest, user identity, and every WAL field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyExtentSessionBinding {
    archive_id: [u8; 16],
    database_epoch: [u8; 16],
    database_epoch_generation: u64,
    key_epoch: [u8; 16],
    rotation_generation: u64,
    registry_object_id: [u8; 16],
    registry_ciphertext_hash: [u8; 32],
    base_root_seq: u64,
    base_root_object_id: [u8; 16],
    base_root_ciphertext_hash: [u8; 32],
    owner_fence: u64,
    operation_id: [u8; 16],
    request_fingerprint: [u8; 32],
    witness_record_hash: [u8; 32],
    legacy_source_binding: [u8; 32],
    plaintext_len: u64,
    sqlite_page_size: u32,
    archive_format_version: u8,
}
impl LegacyExtentSessionBinding {
    pub(crate) fn from_witness(
        witness: &WitnessRecord,
        lease: WitnessLease,
        operation_id: OperationId,
        request_fingerprint: RequestFingerprint,
        legacy_source_binding: [u8; 32],
        plaintext_len: u64,
    ) -> Result<Self> {
        if witness.deletion() != DeletionState::Active
            || witness.migration() != MigrationState::Legacy
            || !witness.authorizes_lease(lease)
        {
            return Err(LegacyExtentSessionError::BindingConflict);
        }
        let root = witness.root().root();
        let registry = witness.registry();
        let mut hash = Sha256::new();
        hash.update(WITNESS_DOMAIN);
        hash.update(witness.encode());
        let value = Self {
            archive_id: *witness.archive_id().as_bytes(),
            database_epoch: *witness.database_epoch().as_bytes(),
            database_epoch_generation: witness.database_epoch_generation(),
            key_epoch: *registry.key_epoch().as_bytes(),
            rotation_generation: registry.rotation_generation(),
            registry_object_id: *registry.object_id().as_bytes(),
            registry_ciphertext_hash: registry.ciphertext_hash(),
            base_root_seq: root.sequence(),
            base_root_object_id: *root.object_id().as_bytes(),
            base_root_ciphertext_hash: root.ciphertext_hash(),
            owner_fence: lease.fencing_epoch(),
            operation_id: *operation_id.as_bytes(),
            request_fingerprint: *request_fingerprint.as_bytes(),
            witness_record_hash: hash.finalize().into(),
            legacy_source_binding,
            plaintext_len,
            sqlite_page_size: crate::archive_v3::SQLITE_PAGE_SIZE,
            archive_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
        };
        value
            .valid()
            .then_some(value)
            .ok_or(LegacyExtentSessionError::Malformed("binding"))
    }
    fn valid(self) -> bool {
        nonzero(&self.archive_id)
            && nonzero(&self.database_epoch)
            && nonzero(&self.key_epoch)
            && nonzero(&self.registry_object_id)
            && nonzero(&self.registry_ciphertext_hash)
            && self.database_epoch_generation <= 1
            && self.base_root_seq.checked_add(1).is_some()
            && nonzero(&self.base_root_object_id)
            && nonzero(&self.base_root_ciphertext_hash)
            && self.owner_fence != 0
            && nonzero(&self.operation_id)
            && nonzero(&self.request_fingerprint)
            && nonzero(&self.witness_record_hash)
            && nonzero(&self.legacy_source_binding)
            && self.plaintext_len != 0
            && self.plaintext_len <= crate::archive_v3::MAX_DATABASE_BYTES
            && self
                .plaintext_len
                .is_multiple_of(u64::from(crate::archive_v3::SQLITE_PAGE_SIZE))
            && self.sqlite_page_size == crate::archive_v3::SQLITE_PAGE_SIZE
            && self.archive_format_version == crate::archive_v3::ARCHIVE_FORMAT_VERSION
    }
    pub(crate) const fn archive_id(self) -> [u8; 16] {
        self.archive_id
    }
    pub(crate) const fn database_epoch(self) -> [u8; 16] {
        self.database_epoch
    }
    pub(crate) const fn key_epoch(self) -> [u8; 16] {
        self.key_epoch
    }
    pub(crate) const fn registry_rotation_generation(self) -> u64 {
        self.rotation_generation
    }
    pub(crate) const fn registry_object_id(self) -> [u8; 16] {
        self.registry_object_id
    }
    pub(crate) const fn registry_ciphertext_hash(self) -> [u8; 32] {
        self.registry_ciphertext_hash
    }
    pub(crate) const fn base_root_seq(self) -> u64 {
        self.base_root_seq
    }
    pub(crate) const fn base_root_object_id(self) -> [u8; 16] {
        self.base_root_object_id
    }
    pub(crate) const fn base_root_ciphertext_hash(self) -> [u8; 32] {
        self.base_root_ciphertext_hash
    }
    pub(crate) const fn owner_fence(self) -> u64 {
        self.owner_fence
    }
    pub(crate) const fn plaintext_len(self) -> u64 {
        self.plaintext_len
    }
    pub(crate) const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }
    pub(crate) const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }
    pub(crate) const fn legacy_source_binding(self) -> [u8; 32] {
        self.legacy_source_binding
    }
    #[cfg(test)]
    pub(crate) fn fixture_for_test(
        archive_id: [u8; 16],
        database_epoch: [u8; 16],
        key_epoch: [u8; 16],
        operation_id: [u8; 16],
        request_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            archive_id,
            database_epoch,
            database_epoch_generation: 0,
            key_epoch,
            rotation_generation: 1,
            registry_object_id: [4; 16],
            registry_ciphertext_hash: [5; 32],
            base_root_seq: 0,
            base_root_object_id: [6; 16],
            base_root_ciphertext_hash: [7; 32],
            owner_fence: 1,
            operation_id,
            request_fingerprint,
            witness_record_hash: [8; 32],
            legacy_source_binding: [9; 32],
            plaintext_len: u64::from(crate::archive_v3::SQLITE_PAGE_SIZE),
            sqlite_page_size: crate::archive_v3::SQLITE_PAGE_SIZE,
            archive_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
        }
    }
    #[cfg(test)]
    pub(crate) fn with_registry_for_test(
        mut self,
        rotation_generation: u64,
        object_id: [u8; 16],
        ciphertext_hash: [u8; 32],
    ) -> Self {
        self.rotation_generation = rotation_generation;
        self.registry_object_id = object_id;
        self.registry_ciphertext_hash = ciphertext_hash;
        self
    }
}
impl fmt::Debug for LegacyExtentSessionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentSessionBinding(<opaque>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacyExtentSessionRecord {
    session_id: LegacyExtentSessionId,
    attempt_id: LegacyExtentAttemptId,
    binding: LegacyExtentSessionBinding,
    state: LegacyExtentSessionState,
    candidate: Option<LegacyExtentCandidate>,
    orphan_inventory_count: u32,
    orphan_inventory_commitment: [u8; 32],
}
impl LegacyExtentSessionRecord {
    pub(crate) fn prepared(
        session_id: LegacyExtentSessionId,
        attempt_id: LegacyExtentAttemptId,
        binding: LegacyExtentSessionBinding,
    ) -> Result<Self> {
        let value = Self {
            session_id,
            attempt_id,
            binding,
            state: LegacyExtentSessionState::Prepared,
            candidate: None,
            orphan_inventory_count: 0,
            orphan_inventory_commitment: [0; 32],
        };
        value
            .valid()
            .then_some(value)
            .ok_or(LegacyExtentSessionError::Malformed("record"))
    }
    pub(crate) const fn session_id(&self) -> LegacyExtentSessionId {
        self.session_id
    }
    pub(crate) const fn attempt_id(&self) -> LegacyExtentAttemptId {
        self.attempt_id
    }
    pub(crate) const fn binding(&self) -> LegacyExtentSessionBinding {
        self.binding
    }
    pub(crate) const fn state(&self) -> LegacyExtentSessionState {
        self.state
    }
    pub(crate) const fn candidate(&self) -> Option<LegacyExtentCandidate> {
        self.candidate
    }
    pub(crate) const fn orphan_inventory_proof(&self) -> Option<(u32, [u8; 32])> {
        if matches!(self.state, LegacyExtentSessionState::OrphanPendingGrace) {
            Some((
                self.orphan_inventory_count,
                self.orphan_inventory_commitment,
            ))
        } else {
            None
        }
    }
    pub(crate) fn require_binding(&self, value: LegacyExtentSessionBinding) -> Result<()> {
        (self.binding == value)
            .then_some(())
            .ok_or(LegacyExtentSessionError::BindingConflict)
    }
    pub(crate) fn persist_candidate(&mut self, candidate: LegacyExtentCandidate) -> Result<()> {
        if candidate.root_seq
            != self
                .binding
                .base_root_seq
                .checked_add(1)
                .ok_or(LegacyExtentSessionError::Malformed("root sequence"))?
        {
            return Err(LegacyExtentSessionError::BindingConflict);
        }
        match self.candidate {
            Some(existing) if existing != candidate => {
                Err(LegacyExtentSessionError::CandidateConflict)
            }
            Some(_) => Ok(()),
            None if self.state == LegacyExtentSessionState::Prepared => {
                self.candidate = Some(candidate);
                self.state = LegacyExtentSessionState::CandidateReady;
                Ok(())
            }
            None => Err(LegacyExtentSessionError::InvalidTransition),
        }
    }
    pub(crate) fn transition(&mut self, next: LegacyExtentSessionState) -> Result<()> {
        if !self.state.permits(next) {
            return Err(LegacyExtentSessionError::InvalidTransition);
        }
        if next == LegacyExtentSessionState::CandidateReady && self.candidate.is_none() {
            return Err(LegacyExtentSessionError::Malformed("candidate required"));
        }
        if next == LegacyExtentSessionState::OrphanPendingGrace {
            return Err(LegacyExtentSessionError::Malformed(
                "orphan inventory proof required",
            ));
        }
        self.state = next;
        Ok(())
    }
    pub(crate) fn orphan_with_inventory(&mut self, count: u32, commitment: [u8; 32]) -> Result<()> {
        if self.state != LegacyExtentSessionState::Prepared
            || self.candidate.is_some()
            || count > MAX_ORPHAN_INVENTORY_OBJECTS
            || !nonzero(&commitment)
        {
            return Err(LegacyExtentSessionError::InvalidTransition);
        }
        self.orphan_inventory_count = count;
        self.orphan_inventory_commitment = commitment;
        self.state = LegacyExtentSessionState::OrphanPendingGrace;
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<[u8; LEGACY_EXTENT_SESSION_RECORD_BYTES]> {
        if !self.valid() {
            return Err(LegacyExtentSessionError::Corrupt);
        }
        let mut out = [0; LEGACY_EXTENT_SESSION_RECORD_BYTES];
        let mut p = 0;
        put(&mut out, &mut p, MAGIC);
        put(&mut out, &mut p, &[VERSION, self.state as u8]);
        put(&mut out, &mut p, &self.session_id.0);
        put(&mut out, &mut p, &self.attempt_id.0);
        let b = self.binding;
        put(&mut out, &mut p, &b.archive_id);
        put(&mut out, &mut p, &b.database_epoch);
        u64put(&mut out, &mut p, b.database_epoch_generation);
        put(&mut out, &mut p, &b.key_epoch);
        u64put(&mut out, &mut p, b.rotation_generation);
        put(&mut out, &mut p, &b.registry_object_id);
        put(&mut out, &mut p, &b.registry_ciphertext_hash);
        u64put(&mut out, &mut p, b.base_root_seq);
        put(&mut out, &mut p, &b.base_root_object_id);
        put(&mut out, &mut p, &b.base_root_ciphertext_hash);
        u64put(&mut out, &mut p, b.owner_fence);
        put(&mut out, &mut p, &b.operation_id);
        put(&mut out, &mut p, &b.request_fingerprint);
        put(&mut out, &mut p, &b.witness_record_hash);
        put(&mut out, &mut p, &b.legacy_source_binding);
        u64put(&mut out, &mut p, b.plaintext_len);
        u32put(&mut out, &mut p, b.sqlite_page_size);
        put(&mut out, &mut p, &[b.archive_format_version]);
        u32put(&mut out, &mut p, self.orphan_inventory_count);
        put(&mut out, &mut p, &self.orphan_inventory_commitment);
        match self.candidate {
            Some(c) => {
                put(&mut out, &mut p, &[1]);
                u64put(&mut out, &mut p, c.root_seq);
                put(&mut out, &mut p, &c.object_id);
                put(&mut out, &mut p, &c.ciphertext_hash);
            }
            None => {
                put(&mut out, &mut p, &[0]);
                put(&mut out, &mut p, &[0; 56]);
            }
        }
        debug_assert_eq!(p, out.len());
        Ok(out)
    }
    pub(crate) fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != LEGACY_EXTENT_SESSION_RECORD_BYTES {
            return Err(LegacyExtentSessionError::Corrupt);
        }
        let mut p = 0;
        if take(input, &mut p, 8)? != MAGIC || take(input, &mut p, 1)?[0] != VERSION {
            return Err(LegacyExtentSessionError::Corrupt);
        }
        let state = LegacyExtentSessionState::decode(take(input, &mut p, 1)?[0])?;
        let session_id = LegacyExtentSessionId::from_bytes(array(take(input, &mut p, 16)?)?);
        let attempt_id = LegacyExtentAttemptId::from_bytes(array(take(input, &mut p, 16)?)?);
        let binding = LegacyExtentSessionBinding {
            archive_id: array(take(input, &mut p, 16)?)?,
            database_epoch: array(take(input, &mut p, 16)?)?,
            database_epoch_generation: u64get(input, &mut p)?,
            key_epoch: array(take(input, &mut p, 16)?)?,
            rotation_generation: u64get(input, &mut p)?,
            registry_object_id: array(take(input, &mut p, 16)?)?,
            registry_ciphertext_hash: array(take(input, &mut p, 32)?)?,
            base_root_seq: u64get(input, &mut p)?,
            base_root_object_id: array(take(input, &mut p, 16)?)?,
            base_root_ciphertext_hash: array(take(input, &mut p, 32)?)?,
            owner_fence: u64get(input, &mut p)?,
            operation_id: array(take(input, &mut p, 16)?)?,
            request_fingerprint: array(take(input, &mut p, 32)?)?,
            witness_record_hash: array(take(input, &mut p, 32)?)?,
            legacy_source_binding: array(take(input, &mut p, 32)?)?,
            plaintext_len: u64get(input, &mut p)?,
            sqlite_page_size: u32get(input, &mut p)?,
            archive_format_version: take(input, &mut p, 1)?[0],
        };
        let orphan_inventory_count = u32get(input, &mut p)?;
        let orphan_inventory_commitment = array(take(input, &mut p, 32)?)?;
        let candidate = match take(input, &mut p, 1)?[0] {
            0 => {
                if take(input, &mut p, 56)?.iter().any(|x| *x != 0) {
                    return Err(LegacyExtentSessionError::Corrupt);
                }
                None
            }
            1 => Some(
                LegacyExtentCandidate::new(
                    u64get(input, &mut p)?,
                    array(take(input, &mut p, 16)?)?,
                    array(take(input, &mut p, 32)?)?,
                )
                .map_err(|_| LegacyExtentSessionError::Corrupt)?,
            ),
            _ => return Err(LegacyExtentSessionError::Corrupt),
        };
        let value = Self {
            session_id,
            attempt_id,
            binding,
            state,
            candidate,
            orphan_inventory_count,
            orphan_inventory_commitment,
        };
        value
            .valid()
            .then_some(value)
            .ok_or(LegacyExtentSessionError::Corrupt)
    }
    fn valid(&self) -> bool {
        nonzero(&self.session_id.0)
            && nonzero(&self.attempt_id.0)
            && self.binding.valid()
            && LegacyExtentSessionId::for_binding(self.binding)
                .is_ok_and(|derived| derived == self.session_id)
            && match (self.state, self.candidate) {
                (LegacyExtentSessionState::Prepared, None) => {
                    self.orphan_inventory_count == 0 && !nonzero(&self.orphan_inventory_commitment)
                }
                (LegacyExtentSessionState::OrphanPendingGrace, None) => {
                    self.orphan_inventory_count <= MAX_ORPHAN_INVENTORY_OBJECTS
                        && nonzero(&self.orphan_inventory_commitment)
                }
                (LegacyExtentSessionState::CandidateReady, Some(c)) => {
                    self.binding.base_root_seq.checked_add(1) == Some(c.root_seq)
                        && self.orphan_inventory_count == 0
                        && !nonzero(&self.orphan_inventory_commitment)
                }
                _ => false,
            }
    }
}
impl fmt::Debug for LegacyExtentSessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyExtentSessionRecord(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum LegacyExtentSessionError {
    #[error("archive-v3 legacy extent session is malformed: {0}")]
    Malformed(&'static str),
    #[error("archive-v3 legacy extent session record is corrupt")]
    Corrupt,
    #[error("archive-v3 legacy extent session transition is invalid")]
    InvalidTransition,
    #[error("archive-v3 legacy extent binding does not match")]
    BindingConflict,
    #[error("archive-v3 legacy extent candidate is immutable")]
    CandidateConflict,
}
pub(crate) type Result<T> = std::result::Result<T, LegacyExtentSessionError>;
fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|x| *x != 0)
}
fn put(out: &mut [u8], p: &mut usize, value: &[u8]) {
    out[*p..*p + value.len()].copy_from_slice(value);
    *p += value.len();
}
fn take<'a>(input: &'a [u8], p: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = p
        .checked_add(len)
        .ok_or(LegacyExtentSessionError::Corrupt)?;
    let value = input
        .get(*p..end)
        .ok_or(LegacyExtentSessionError::Corrupt)?;
    *p = end;
    Ok(value)
}
fn array<const N: usize>(value: &[u8]) -> Result<[u8; N]> {
    value
        .try_into()
        .map_err(|_| LegacyExtentSessionError::Corrupt)
}
fn u64put(out: &mut [u8], p: &mut usize, value: u64) {
    put(out, p, &value.to_be_bytes())
}
fn u32put(out: &mut [u8], p: &mut usize, value: u32) {
    put(out, p, &value.to_be_bytes())
}
fn u64get(input: &[u8], p: &mut usize) -> Result<u64> {
    Ok(u64::from_be_bytes(array(take(input, p, 8)?)?))
}
fn u32get(input: &[u8], p: &mut usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(take(input, p, 4)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> LegacyExtentSessionBinding {
        LegacyExtentSessionBinding {
            archive_id: [1; 16],
            database_epoch: [2; 16],
            database_epoch_generation: 1,
            key_epoch: [3; 16],
            rotation_generation: 10,
            registry_object_id: [4; 16],
            registry_ciphertext_hash: [5; 32],
            base_root_seq: 11,
            base_root_object_id: [6; 16],
            base_root_ciphertext_hash: [7; 32],
            owner_fence: 12,
            operation_id: [8; 16],
            request_fingerprint: [9; 32],
            witness_record_hash: [10; 32],
            legacy_source_binding: [11; 32],
            plaintext_len: u64::from(crate::archive_v3::SQLITE_PAGE_SIZE),
            sqlite_page_size: crate::archive_v3::SQLITE_PAGE_SIZE,
            archive_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
        }
    }

    #[test]
    fn fixed_codec_round_trips_and_rejects_corruption() {
        let binding = binding();
        let record = LegacyExtentSessionRecord::prepared(
            LegacyExtentSessionId::for_binding(binding).unwrap(),
            LegacyExtentAttemptId::from_bytes_for_test([12; 16]),
            binding,
        )
        .unwrap();
        let encoded = record.encode().unwrap();
        assert_eq!(LegacyExtentSessionRecord::decode(&encoded).unwrap(), record);
        assert!(LegacyExtentSessionRecord::decode(
            &encoded[..LEGACY_EXTENT_SESSION_RECORD_BYTES - 1]
        )
        .is_err());
        let mut corrupt = encoded;
        corrupt[0] ^= 1;
        assert!(LegacyExtentSessionRecord::decode(&corrupt).is_err());
        let mut impossible = encoded;
        impossible[9] = LegacyExtentSessionState::CandidateReady as u8;
        assert!(LegacyExtentSessionRecord::decode(&impossible).is_err());

        let mut orphan = record.clone();
        orphan.orphan_with_inventory(0, [17; 32]).unwrap();
        let encoded = orphan.encode().unwrap();
        assert_eq!(LegacyExtentSessionRecord::decode(&encoded).unwrap(), orphan);
        let mut over_cap = record;
        assert!(over_cap
            .orphan_with_inventory(MAX_ORPHAN_INVENTORY_OBJECTS + 1, [17; 32])
            .is_err());
    }

    #[test]
    fn candidate_is_exact_and_state_machine_never_witnesses() {
        let binding = binding();
        let mut record = LegacyExtentSessionRecord::prepared(
            LegacyExtentSessionId::for_binding(binding).unwrap(),
            LegacyExtentAttemptId::from_bytes_for_test([12; 16]),
            binding,
        )
        .unwrap();
        assert!(record
            .transition(LegacyExtentSessionState::CandidateReady)
            .is_err());
        assert!(record
            .persist_candidate(LegacyExtentCandidate::new(13, [13; 16], [14; 32]).unwrap())
            .is_err());
        record
            .persist_candidate(LegacyExtentCandidate::new(12, [13; 16], [14; 32]).unwrap())
            .unwrap();
        assert_eq!(record.state(), LegacyExtentSessionState::CandidateReady);
        assert!(record
            .transition(LegacyExtentSessionState::OrphanPendingGrace)
            .is_err());
    }

    #[test]
    fn genesis_base_root_zero_accepts_first_candidate() {
        let mut binding = binding();
        binding.base_root_seq = 0;
        let mut record = LegacyExtentSessionRecord::prepared(
            LegacyExtentSessionId::for_binding(binding).unwrap(),
            LegacyExtentAttemptId::from_bytes_for_test([12; 16]),
            binding,
        )
        .unwrap();
        record
            .persist_candidate(LegacyExtentCandidate::new(1, [13; 16], [14; 32]).unwrap())
            .unwrap();
        assert_eq!(record.candidate().unwrap().root_seq(), 1);
    }

    #[test]
    fn ids_and_debug_are_redacted() {
        let binding = binding();
        let id = LegacyExtentSessionId::for_binding(binding).unwrap();
        assert_eq!(id, LegacyExtentSessionId::for_binding(binding).unwrap());
        let mut changed = binding;
        changed.request_fingerprint[0] ^= 1;
        assert_eq!(id, LegacyExtentSessionId::for_binding(changed).unwrap());
        let mut changed_operation = binding;
        changed_operation.operation_id[0] ^= 1;
        assert_ne!(
            id,
            LegacyExtentSessionId::for_binding(changed_operation).unwrap()
        );
        let mut invalid = binding;
        invalid.operation_id = [0; 16];
        assert!(LegacyExtentSessionId::for_binding(invalid).is_err());
        assert!(!format!("{id:?}").contains("010101"));
        assert!(!format!("{binding:?}").contains("111111"));

        let mut alternate = id.as_bytes();
        alternate[0] ^= 1;
        let alternate = LegacyExtentSessionId::from_bytes_for_test(alternate);
        assert!(LegacyExtentSessionRecord::prepared(
            alternate,
            LegacyExtentAttemptId::from_bytes_for_test([12; 16]),
            binding,
        )
        .is_err());
    }

    fn root_and_context(binding: LegacyExtentSessionBinding) -> (ArchiveRoot, ObjectContext) {
        let parent = crate::archive_v3::ParentReference {
            object_id: crate::archive_v3::ObjectId::from_bytes(binding.base_root_object_id()),
            envelope_hash: binding.base_root_ciphertext_hash(),
        };
        let context = ObjectContext::new(
            crate::archive_v3::ArchiveId::from_bytes(binding.archive_id()),
            crate::archive_v3::DatabaseEpoch::from_bytes(binding.database_epoch()),
            crate::archive_v3::KeyEpoch::from_bytes(binding.key_epoch()),
            crate::archive_v3::ObjectRole::RootV3,
            crate::archive_v3::LogicalLocation::Root { root_seq: 12 },
            crate::archive_v3::ObjectId::from_bytes([13; 16]),
            Some(parent.clone()),
        )
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 12,
            parent: Some(parent),
            database_epoch: crate::archive_v3::DatabaseEpoch::from_bytes(binding.database_epoch()),
            key_epoch: crate::archive_v3::KeyEpoch::from_bytes(binding.key_epoch()),
            owner_fencing_epoch: binding.owner_fence(),
            sqlite_page_size: crate::archive_v3::SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: 0,
            logical_file_length: binding.plaintext_len(),
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: None,
            extent_tree_root: Some(crate::archive_v3::ImmutableReference {
                object_id: crate::archive_v3::ObjectId::from_bytes([14; 16]),
                envelope_hash: [15; 32],
            }),
            wal_commit_tail: None,
        };
        (root, context)
    }

    #[test]
    fn root_admission_binds_parent_fence_length_epoch_and_conversion_shape() {
        let binding = binding();
        let (root, context) = root_and_context(binding);
        assert!(LegacyExtentRootAdmission::from_validated_root_for_test(
            &root, &context, [16; 32], binding,
        )
        .is_ok());

        let mut wrong = root.clone();
        wrong.owner_fencing_epoch += 1;
        assert!(LegacyExtentRootAdmission::from_validated_root_for_test(
            &wrong, &context, [16; 32], binding
        )
        .is_err());
        let mut wrong = root.clone();
        wrong.logical_file_length += u64::from(crate::archive_v3::SQLITE_PAGE_SIZE);
        assert!(LegacyExtentRootAdmission::from_validated_root_for_test(
            &wrong, &context, [16; 32], binding
        )
        .is_err());

        let mut wrong = root.clone();
        wrong.database_epoch = crate::archive_v3::DatabaseEpoch::from_bytes([17; 16]);
        let wrong_context = ObjectContext::new(
            context.archive_id(),
            wrong.database_epoch,
            context.key_epoch(),
            context.role(),
            context.location().clone(),
            context.object_id(),
            context.parent().cloned(),
        )
        .unwrap();
        assert!(LegacyExtentRootAdmission::from_validated_root_for_test(
            &wrong,
            &wrong_context,
            [16; 32],
            binding
        )
        .is_err());

        let wrong_parent = crate::archive_v3::ParentReference {
            object_id: crate::archive_v3::ObjectId::from_bytes([18; 16]),
            envelope_hash: [19; 32],
        };
        let mut wrong = root.clone();
        wrong.parent = Some(wrong_parent.clone());
        let wrong_context = ObjectContext::new(
            context.archive_id(),
            context.database_epoch(),
            context.key_epoch(),
            context.role(),
            context.location().clone(),
            context.object_id(),
            Some(wrong_parent),
        )
        .unwrap();
        assert!(LegacyExtentRootAdmission::from_validated_root_for_test(
            &wrong,
            &wrong_context,
            [16; 32],
            binding
        )
        .is_err());

        let mut absent = root.clone();
        absent.parent = None;
        let absent_context = ObjectContext::new(
            context.archive_id(),
            context.database_epoch(),
            context.key_epoch(),
            context.role(),
            context.location().clone(),
            context.object_id(),
            None,
        )
        .unwrap();
        assert!(LegacyExtentRootAdmission::from_validated_root_for_test(
            &absent,
            &absent_context,
            [16; 32],
            binding
        )
        .is_err());

        let mut wal = root;
        wal.extent_tree_root = None;
        wal.checkpoint_logical_file_length = binding.plaintext_len();
        wal.checkpoint_root = Some(crate::archive_v3::ImmutableReference {
            object_id: crate::archive_v3::ObjectId::from_bytes([20; 16]),
            envelope_hash: [21; 32],
        });
        wal.wal_commit_tail = Some(crate::archive_v3::ImmutableReference {
            object_id: crate::archive_v3::ObjectId::from_bytes([22; 16]),
            envelope_hash: [23; 32],
        });
        wal.wal_generation = 1;
        wal.wal_commit_count = 1;
        wal.wal_segment_count = 1;
        wal.wal_tail_bytes = u64::from(32 + 24 + crate::archive_v3::SQLITE_PAGE_SIZE);
        assert!(wal.validate_for_context(&context).is_ok());
        assert!(LegacyExtentRootAdmission::from_validated_root_for_test(
            &wal, &context, [16; 32], binding
        )
        .is_err());
    }
}
