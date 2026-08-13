#![allow(
    dead_code,
    reason = "inactive ADR-0022 archive bootstrap seam is compiled and fake-tested before authority wiring"
)]

//! Restart-safe, inactive archive-v3 genesis coordination.
//!
//! This module deliberately owns no provider construction.  A control-plane
//! binding supplies the opaque archive ID and a caller supplies already-made
//! immutable candidate bytes.  Construction is synchronous and performs no
//! provider I/O; the injected backend is used only by [`ArchiveGenesis::resolve`].
//! In particular, this is not a Store, VFS, route, credential, or feature-flag
//! integration.
//!
//! Before the first call to `resolve`, future runtime wiring must durably retain
//! the binding, every [`GenesisIds`] value, the exact wrapped registry bytes,
//! and the exact root envelope. Partial pre-witness creates must remain in the
//! account-deletion inventory. This inactive seam cannot establish either
//! prerequisite because it deliberately owns no persistence or deletion path.

use crate::{
    archive_v3::{
        resolve_archive_cipher, ArchiveId, ArchiveV3Error, CiphertextEnvelope, DatabaseEpoch,
        ExactKeyRegistryProvider, KeyEpoch, KeyKind, KeyRegistryContext, LogicalLocation,
        ObjectContext, ObjectId, ObjectRole, ParentReference, MAX_ENCODED_ENVELOPE_BYTES,
        MAX_WRAPPED_KEY_REGISTRY_BYTES,
    },
    archive_v3_witness::{
        DeletionState, ExactRootProvider, KeyRegistryReference, RootCommitment, RootReference,
        WitnessBootstrap, WitnessError, WitnessRecord,
    },
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// A control-plane-owned, opaque persistent archive binding.  It intentionally
/// accepts neither a user ID nor a value derived from one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArchiveBinding {
    archive_id: ArchiveId,
}

impl ArchiveBinding {
    pub(crate) fn new(archive_id: ArchiveId) -> Result<Self, BootstrapError> {
        if archive_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(BootstrapError::MalformedCandidate);
        }
        Ok(Self { archive_id })
    }

    pub(crate) const fn archive_id(self) -> ArchiveId {
        self.archive_id
    }
}

impl fmt::Debug for ArchiveBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveBinding(<opaque>)")
    }
}

/// A stable set of preallocated opaque IDs.  Retrying a bootstrap must retain
/// this material; generating replacements after an ambiguous provider outcome
/// would create an unresolvable competing candidate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenesisIds {
    pub database_epoch: DatabaseEpoch,
    pub key_epoch: KeyEpoch,
    pub registry_object_id: ObjectId,
    pub root_object_id: ObjectId,
}

impl fmt::Debug for GenesisIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenesisIds(<opaque>)")
    }
}

/// Immutable, retry-stable genesis bytes. Wrapped registry ciphertext is never
/// archive-encrypted; the root envelope uses the existing archive-v3 AAD.
pub(crate) struct GenesisCandidate {
    binding: ArchiveBinding,
    ids: GenesisIds,
    registry_context: KeyRegistryContext,
    registry: KeyRegistryReference,
    root_context: ObjectContext,
    root_envelope: CiphertextEnvelope,
    wrapped_registry: Zeroizing<Vec<u8>>,
}

impl GenesisCandidate {
    /// Performs only bounded local validation.  It never reads, writes, or
    /// constructs a provider, KMS client, credential, or network authority.
    pub(crate) fn new(
        binding: ArchiveBinding,
        ids: GenesisIds,
        wrapped_registry: &[u8],
        root_envelope: CiphertextEnvelope,
    ) -> Result<Self, BootstrapError> {
        if ids.database_epoch.as_bytes().iter().all(|byte| *byte == 0)
            || ids.key_epoch.as_bytes().iter().all(|byte| *byte == 0)
            || ids
                .registry_object_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || ids.root_object_id.as_bytes().iter().all(|byte| *byte == 0)
            || ids.registry_object_id == ids.root_object_id
            || wrapped_registry.is_empty()
            || wrapped_registry.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
            || root_envelope.encode().len() > MAX_ENCODED_ENVELOPE_BYTES
        {
            return Err(BootstrapError::MalformedCandidate);
        }
        let registry_context =
            KeyRegistryContext::new(binding.archive_id(), KeyKind::Archive, ids.key_epoch);
        let registry = KeyRegistryReference::new(
            ids.key_epoch,
            registry_context.rotation_generation(),
            ids.registry_object_id,
            Sha256::digest(wrapped_registry).into(),
        );
        let root_context = ObjectContext::new(
            binding.archive_id(),
            ids.database_epoch,
            ids.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ids.root_object_id,
            None,
        )
        .map_err(BootstrapError::Archive)?;
        Ok(Self {
            binding,
            ids,
            registry_context,
            registry,
            root_context,
            root_envelope,
            wrapped_registry: Zeroizing::new(wrapped_registry.to_vec()),
        })
    }

    fn expected_root(&self) -> RootCommitment {
        RootCommitment::genesis(
            self.ids.database_epoch,
            self.ids.key_epoch,
            RootReference::new(0, self.ids.root_object_id, self.root_envelope.hash()),
        )
    }

    async fn authenticated_bootstrap(
        &self,
        backend: &dyn ArchiveGenesisBackend,
    ) -> Result<WitnessBootstrap, BootstrapError> {
        let cipher = resolve_archive_cipher(
            &self.registry_context,
            self.ids.registry_object_id,
            self.registry.ciphertext_hash(),
            backend,
        )
        .await
        .map_err(BootstrapError::Archive)?;
        WitnessBootstrap::from_authenticated_genesis(
            self.binding.archive_id(),
            self.registry,
            &self.root_context,
            backend,
            &cipher,
        )
        .await
        .map_err(BootstrapError::Witness)
    }
}

impl fmt::Debug for GenesisCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenesisCandidate(<opaque>)")
    }
}

/// The only create outcomes this seam accepts. Provider ambiguity remains an
/// error until an exact read establishes byte-for-byte equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootstrapCreate {
    Created,
    AlreadyPresent,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub(crate) enum BootstrapError {
    #[error("archive genesis candidate is malformed")]
    MalformedCandidate,
    #[error("archive genesis object conflicts with an existing immutable object")]
    Conflict,
    #[error("archive genesis provider outcome is unknown; resolve with an exact read")]
    OutcomeUnknown,
    #[error("archive genesis cannot proceed from a tombstoned/deleting witness")]
    Tombstoned,
    #[error("archive genesis witness changed during exact authentication")]
    WitnessChanged,
    #[error("archive genesis provider data is invalid")]
    Archive(ArchiveV3Error),
    #[error("archive genesis witness data is invalid")]
    Witness(WitnessError),
}

/// Narrow injected provider boundary.  Implementations must use immutable,
/// create-if-absent semantics.  No implementation is constructed here.
#[async_trait]
pub(crate) trait ArchiveGenesisBackend:
    ExactRootProvider + ExactKeyRegistryProvider
{
    async fn read_witness(
        &self,
        archive_id: ArchiveId,
    ) -> Result<Option<WitnessRecord>, BootstrapError>;

    async fn create_registry_if_absent(
        &self,
        context: &KeyRegistryContext,
        object_id: ObjectId,
        wrapped_registry: &[u8],
    ) -> Result<BootstrapCreate, BootstrapError>;

    async fn create_root_if_absent(
        &self,
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
    ) -> Result<BootstrapCreate, BootstrapError>;

    async fn create_witness_if_absent(
        &self,
        bootstrap: WitnessBootstrap,
    ) -> Result<BootstrapCreate, BootstrapError>;
}

/// Result only reveals the state transition, never archive identifiers or
/// content.  Both variants have authenticated the exact witness/root/registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenesisResolution {
    Existing,
    Created,
}

/// Inactive coordinator. Its constructor is intentionally I/O-free; `resolve`
/// is the sole method that can invoke an injected provider.
pub(crate) struct ArchiveGenesis {
    candidate: GenesisCandidate,
}

impl ArchiveGenesis {
    pub(crate) const fn new(candidate: GenesisCandidate) -> Self {
        Self { candidate }
    }

    pub(crate) async fn resolve(
        &self,
        backend: &dyn ArchiveGenesisBackend,
    ) -> Result<GenesisResolution, BootstrapError> {
        if let Some(record) = backend
            .read_witness(self.candidate.binding.archive_id())
            .await?
        {
            self.authenticate_stable_record(backend, &record).await?;
            return Ok(GenesisResolution::Existing);
        }

        self.create_or_compare_registry(backend).await?;
        self.create_or_compare_root(backend).await?;
        let bootstrap = self.candidate.authenticated_bootstrap(backend).await?;
        match backend.create_witness_if_absent(bootstrap).await {
            Ok(BootstrapCreate::Created)
            | Ok(BootstrapCreate::AlreadyPresent)
            | Err(BootstrapError::OutcomeUnknown) => {
                let record = backend
                    .read_witness(self.candidate.binding.archive_id())
                    .await?
                    .ok_or(BootstrapError::OutcomeUnknown)?;
                if record.root() != self.candidate.expected_root()
                    || record.registry() != self.candidate.registry
                {
                    return Err(BootstrapError::Conflict);
                }
                self.authenticate_stable_record(backend, &record).await?;
                Ok(GenesisResolution::Created)
            }
            Err(error) => Err(error),
        }
    }

    async fn create_or_compare_registry(
        &self,
        backend: &dyn ArchiveGenesisBackend,
    ) -> Result<(), BootstrapError> {
        match backend
            .create_registry_if_absent(
                &self.candidate.registry_context,
                self.candidate.ids.registry_object_id,
                &self.candidate.wrapped_registry,
            )
            .await
        {
            Ok(BootstrapCreate::Created)
            | Ok(BootstrapCreate::AlreadyPresent)
            | Err(BootstrapError::OutcomeUnknown) => {
                let mut actual = Zeroizing::new([0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES]);
                let len = backend
                    .read_exact_wrapped(
                        &self.candidate.registry_context,
                        self.candidate.ids.registry_object_id,
                        actual.as_mut_slice(),
                    )
                    .await
                    .map_err(BootstrapError::Archive)?;
                if len > actual.len() {
                    return Err(BootstrapError::Archive(ArchiveV3Error::TooLarge(
                        "wrapped key registry",
                    )));
                }
                if actual[..len] != *self.candidate.wrapped_registry {
                    return Err(BootstrapError::Conflict);
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    async fn create_or_compare_root(
        &self,
        backend: &dyn ArchiveGenesisBackend,
    ) -> Result<(), BootstrapError> {
        match backend
            .create_root_if_absent(&self.candidate.root_context, &self.candidate.root_envelope)
            .await
        {
            Ok(BootstrapCreate::Created)
            | Ok(BootstrapCreate::AlreadyPresent)
            | Err(BootstrapError::OutcomeUnknown) => {
                let actual = backend
                    .read_exact(&self.candidate.root_context)
                    .await
                    .map_err(BootstrapError::Witness)?;
                if actual != self.candidate.root_envelope {
                    return Err(BootstrapError::Conflict);
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    async fn authenticate_existing(
        &self,
        backend: &dyn ArchiveGenesisBackend,
        record: &WitnessRecord,
    ) -> Result<(), BootstrapError> {
        if record.archive_id() != self.candidate.binding.archive_id() {
            return Err(BootstrapError::Conflict);
        }
        if record.deletion() != DeletionState::Active {
            return Err(BootstrapError::Tombstoned);
        }
        let registry = record.registry();
        let registry_context = KeyRegistryContext::with_rotation_generation(
            record.archive_id(),
            KeyKind::Archive,
            registry.key_epoch(),
            registry.rotation_generation(),
        );
        let cipher = resolve_archive_cipher(
            &registry_context,
            registry.object_id(),
            registry.ciphertext_hash(),
            backend,
        )
        .await
        .map_err(BootstrapError::Archive)?;
        let root = record.root();
        let context = ObjectContext::new(
            record.archive_id(),
            record.database_epoch(),
            registry.key_epoch(),
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: root.root().sequence(),
            },
            root.root().object_id(),
            root.parent().map(|parent| ParentReference {
                object_id: parent.object_id(),
                envelope_hash: parent.ciphertext_hash(),
            }),
        )
        .map_err(BootstrapError::Archive)?;
        let authenticated = RootCommitment::from_authenticated_provider_object(
            record.archive_id(),
            registry,
            &context,
            backend,
            &cipher,
        )
        .await
        .map_err(BootstrapError::Witness)?;
        (authenticated == root)
            .then_some(())
            .ok_or(BootstrapError::Conflict)
    }

    /// Authenticate one exact snapshot, then make a final exact witness read.
    /// Both paths use this helper so no successful return crosses an await
    /// after the final active/equality decision.
    async fn authenticate_stable_record(
        &self,
        backend: &dyn ArchiveGenesisBackend,
        snapshot: &WitnessRecord,
    ) -> Result<(), BootstrapError> {
        self.authenticate_existing(backend, snapshot).await?;
        let Some(current) = backend
            .read_witness(self.candidate.binding.archive_id())
            .await?
        else {
            return Err(BootstrapError::WitnessChanged);
        };
        if current.deletion() != DeletionState::Active {
            return Err(BootstrapError::Tombstoned);
        }
        if &current != snapshot {
            return Err(BootstrapError::WitnessChanged);
        }
        Ok(())
    }
}

impl fmt::Debug for ArchiveGenesis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveGenesis(<opaque>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{
            ArchiveCipher, ArchiveDek, ArchiveRoot, ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
        },
        archive_v3_witness::{InMemoryWitness, Witness},
    };
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum WriteMode {
        Normal,
        LostResponse,
        LostResponseMismatch,
        Collision,
    }

    #[derive(Clone, Copy)]
    enum WitnessInterleave {
        Tombstone,
        RootAdvance,
        RegistryAdvance,
    }

    struct FakeBackend {
        witness: InMemoryWitness,
        forced_record: Mutex<Option<WitnessRecord>>,
        roots: Mutex<BTreeMap<ObjectId, CiphertextEnvelope>>,
        registries: Mutex<BTreeMap<ObjectId, Vec<u8>>>,
        registry_plaintext: Vec<u8>,
        registry_mode: WriteMode,
        root_mode: WriteMode,
        witness_mode: WriteMode,
        interleave: Mutex<Option<WitnessInterleave>>,
        io: Mutex<usize>,
    }

    impl FakeBackend {
        fn new(plaintext: Vec<u8>) -> Self {
            Self {
                witness: InMemoryWitness::new(),
                forced_record: Mutex::new(None),
                roots: Mutex::new(BTreeMap::new()),
                registries: Mutex::new(BTreeMap::new()),
                registry_plaintext: plaintext,
                registry_mode: WriteMode::Normal,
                root_mode: WriteMode::Normal,
                witness_mode: WriteMode::Normal,
                interleave: Mutex::new(None),
                io: Mutex::new(0),
            }
        }
        fn io_count(&self) -> usize {
            *self.io.lock().unwrap()
        }
        fn hit(&self) {
            *self.io.lock().unwrap() += 1;
        }
        fn result_for(mode: WriteMode, inserted: bool) -> Result<BootstrapCreate, BootstrapError> {
            if matches!(
                mode,
                WriteMode::LostResponse | WriteMode::LostResponseMismatch
            ) && inserted
            {
                Err(BootstrapError::OutcomeUnknown)
            } else if inserted {
                Ok(BootstrapCreate::Created)
            } else {
                Ok(BootstrapCreate::AlreadyPresent)
            }
        }

        fn mismatched_envelope(envelope: &CiphertextEnvelope) -> CiphertextEnvelope {
            let mut encoded = envelope.encode();
            // The nonce is inside the canonical envelope framing, so this is
            // a bounded, parseable, byte-inequal immutable collision.
            encoded[9] ^= 1;
            CiphertextEnvelope::decode(&encoded).expect("bounded envelope")
        }

        fn set_interleave(&self, action: WitnessInterleave) {
            *self.interleave.lock().unwrap() = Some(action);
        }

        fn interleave_witness_after_auth_read(&self, archive_id: ArchiveId) {
            let Some(record) = self.witness.read_current(archive_id).unwrap() else {
                // On the create path, leave the action armed until the witness
                // has actually been created and its root is authenticated.
                return;
            };
            let Some(action) = self.interleave.lock().unwrap().take() else {
                return;
            };
            let changed = match action {
                WitnessInterleave::Tombstone => record.tombstoned_for_test(),
                WitnessInterleave::RootAdvance => {
                    record.with_root_for_test(RootCommitment::genesis(
                        record.database_epoch(),
                        record.registry().key_epoch(),
                        RootReference::new(0, ObjectId::from_bytes([14; 16]), [15; 32]),
                    ))
                }
                WitnessInterleave::RegistryAdvance => {
                    record.with_registry_for_test(KeyRegistryReference::new(
                        record.registry().key_epoch(),
                        record.registry().rotation_generation() + 1,
                        ObjectId::from_bytes([16; 16]),
                        [17; 32],
                    ))
                }
            };
            *self.forced_record.lock().unwrap() = Some(changed);
        }
    }

    #[async_trait]
    impl ExactRootProvider for FakeBackend {
        async fn read_exact(
            &self,
            context: &ObjectContext,
        ) -> std::result::Result<CiphertextEnvelope, WitnessError> {
            self.hit();
            let envelope = self
                .roots
                .lock()
                .unwrap()
                .get(&context.object_id())
                .cloned()
                .ok_or(WitnessError::MissingRootObject)?;
            self.interleave_witness_after_auth_read(context.archive_id());
            Ok(envelope)
        }
    }
    #[async_trait]
    impl ExactKeyRegistryProvider for FakeBackend {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            destination: &mut [u8],
        ) -> std::result::Result<usize, ArchiveV3Error> {
            self.hit();
            let value = self
                .registries
                .lock()
                .unwrap()
                .get(&object_id)
                .cloned()
                .ok_or(ArchiveV3Error::Unavailable)?;
            if value.len() > destination.len() {
                return Err(ArchiveV3Error::TooLarge("wrapped key registry"));
            }
            destination[..value.len()].copy_from_slice(&value);
            Ok(value.len())
        }
        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            _wrapped: &[u8],
            destination: &mut [u8],
        ) -> std::result::Result<usize, ArchiveV3Error> {
            self.hit();
            if self.registry_plaintext.len() > destination.len() {
                return Err(ArchiveV3Error::TooLarge("key registry plaintext"));
            }
            destination[..self.registry_plaintext.len()].copy_from_slice(&self.registry_plaintext);
            Ok(self.registry_plaintext.len())
        }
    }
    #[async_trait]
    impl ArchiveGenesisBackend for FakeBackend {
        async fn read_witness(
            &self,
            archive: ArchiveId,
        ) -> Result<Option<WitnessRecord>, BootstrapError> {
            self.hit();
            if let Some(record) = self.forced_record.lock().unwrap().clone() {
                return Ok(Some(record));
            }
            self.witness
                .read_current(archive)
                .map_err(BootstrapError::Witness)
        }
        async fn create_registry_if_absent(
            &self,
            _context: &KeyRegistryContext,
            id: ObjectId,
            bytes: &[u8],
        ) -> Result<BootstrapCreate, BootstrapError> {
            self.hit();
            let mut values = self.registries.lock().unwrap();
            if let Some(existing) = values.get(&id) {
                return if existing == bytes {
                    Ok(BootstrapCreate::AlreadyPresent)
                } else {
                    Err(BootstrapError::Conflict)
                };
            }
            if matches!(
                self.registry_mode,
                WriteMode::Collision | WriteMode::LostResponseMismatch
            ) {
                values.insert(id, vec![7]);
            } else {
                values.insert(id, bytes.to_vec());
            }
            Self::result_for(self.registry_mode, true)
        }
        async fn create_root_if_absent(
            &self,
            context: &ObjectContext,
            envelope: &CiphertextEnvelope,
        ) -> Result<BootstrapCreate, BootstrapError> {
            self.hit();
            let mut values = self.roots.lock().unwrap();
            let id = context.object_id();
            if let Some(existing) = values.get(&id) {
                return if existing == envelope {
                    Ok(BootstrapCreate::AlreadyPresent)
                } else {
                    Err(BootstrapError::Conflict)
                };
            }
            if matches!(
                self.root_mode,
                WriteMode::Collision | WriteMode::LostResponseMismatch
            ) {
                values.insert(id, Self::mismatched_envelope(envelope));
            } else {
                values.insert(id, envelope.clone());
            }
            if self.root_mode == WriteMode::Collision {
                return Err(BootstrapError::Conflict);
            }
            Self::result_for(self.root_mode, true)
        }
        async fn create_witness_if_absent(
            &self,
            bootstrap: WitnessBootstrap,
        ) -> Result<BootstrapCreate, BootstrapError> {
            self.hit();
            let result = self
                .witness
                .bootstrap(bootstrap)
                .map_err(|error| match error {
                    WitnessError::AlreadyExists => BootstrapError::Conflict,
                    other => BootstrapError::Witness(other),
                })?;
            let _ = result;
            Self::result_for(self.witness_mode, true)
        }
    }

    fn candidate() -> (ArchiveGenesis, Vec<u8>) {
        let binding = ArchiveBinding::new(ArchiveId::from_bytes([1; 16])).unwrap();
        let ids = GenesisIds {
            database_epoch: DatabaseEpoch::from_bytes([2; 16]),
            key_epoch: KeyEpoch::from_bytes([3; 16]),
            registry_object_id: ObjectId::from_bytes([4; 16]),
            root_object_id: ObjectId::from_bytes([5; 16]),
        };
        let registry_context =
            KeyRegistryContext::new(binding.archive_id(), KeyKind::Archive, ids.key_epoch);
        let plaintext = crate::archive_v3::KeyRegistryPlaintext::encode_archive(
            &registry_context,
            &ArchiveDek::from_bytes([9; 32]),
        )
        .unwrap()
        .to_vec();
        let cipher = ArchiveCipher::new(ArchiveDek::from_bytes([9; 32]));
        let root_context = ObjectContext::new(
            binding.archive_id(),
            ids.database_epoch,
            ids.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ids.root_object_id,
            None,
        )
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: ids.database_epoch,
            key_epoch: ids.key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: 0,
            logical_file_length: 0,
            user_schema_version: 0,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let envelope = cipher.seal(&root_context, &root.encode().unwrap()).unwrap();
        (
            ArchiveGenesis::new(
                GenesisCandidate::new(binding, ids, b"wrapped-registry", envelope).unwrap(),
            ),
            plaintext,
        )
    }

    #[tokio::test]
    async fn first_genesis_is_authenticated_and_constructor_does_no_io() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(plaintext);
        assert_eq!(backend.io_count(), 0);
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        assert!(backend.io_count() > 0);
    }
    #[tokio::test]
    async fn restart_reads_existing_exact_state() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(plaintext);
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Existing
        );
    }
    #[tokio::test]
    async fn existing_path_rejects_tombstone_during_authentication() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(plaintext);
        genesis.resolve(&backend).await.unwrap();
        backend.set_interleave(WitnessInterleave::Tombstone);
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Tombstoned)
        );
    }
    #[tokio::test]
    async fn existing_path_rejects_root_and_registry_advance_during_authentication() {
        for action in [
            WitnessInterleave::RootAdvance,
            WitnessInterleave::RegistryAdvance,
        ] {
            let (genesis, plaintext) = candidate();
            let backend = FakeBackend::new(plaintext);
            genesis.resolve(&backend).await.unwrap();
            backend.set_interleave(action);
            assert_eq!(
                genesis.resolve(&backend).await,
                Err(BootstrapError::WitnessChanged)
            );
        }
    }
    #[tokio::test]
    async fn create_path_rejects_finalization_interleave() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(plaintext);
        backend.set_interleave(WitnessInterleave::Tombstone);
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Tombstoned)
        );
    }
    #[tokio::test]
    async fn collision_and_lost_response_are_reconciled_only_by_equality() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend {
            registry_mode: WriteMode::LostResponse,
            root_mode: WriteMode::LostResponse,
            witness_mode: WriteMode::LostResponse,
            ..FakeBackend::new(plaintext)
        };
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend {
            registry_mode: WriteMode::Collision,
            ..FakeBackend::new(plaintext)
        };
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Conflict)
        );
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend {
            root_mode: WriteMode::LostResponseMismatch,
            ..FakeBackend::new(plaintext)
        };
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Conflict)
        );
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(plaintext);
        backend.roots.lock().unwrap().insert(
            genesis.candidate.root_context.object_id(),
            genesis.candidate.root_envelope.clone(),
        );
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend {
            registry_mode: WriteMode::LostResponseMismatch,
            ..FakeBackend::new(plaintext)
        };
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Conflict)
        );
    }
    #[tokio::test]
    async fn malformed_provider_data_and_tombstones_fail_closed() {
        let (genesis, mut plaintext) = candidate();
        plaintext.push(1);
        let backend = FakeBackend::new(plaintext);
        assert!(matches!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Archive(_))
        ));
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(plaintext);
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        *backend.forced_record.lock().unwrap() = backend
            .witness
            .read_current(genesis.candidate.binding.archive_id())
            .unwrap()
            .map(|record| record.tombstoned_for_test());
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Tombstoned)
        );
        let (genesis, _) = candidate();
        let backend = FakeBackend::new(vec![0; MAX_WRAPPED_KEY_REGISTRY_BYTES + 1]);
        assert!(matches!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Archive(ArchiveV3Error::TooLarge(_)))
        ));
    }
}
