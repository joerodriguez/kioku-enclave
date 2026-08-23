#![allow(
    dead_code,
    reason = "active deletion-only reachability visitor retains test-only graph fixtures"
)]

//! Non-authorizing authenticated reachability visitor for ADR-0022 deletion.
//!
//! The visitor starts only from the current and optional predecessor roots in
//! one witness-produced [`RecoveryRoot`]. It follows exact authenticated
//! references without prefix enumeration, opens every metadata and WAL object,
//! and records checkpoint chunks and extent leaves from their authenticated
//! parent edges without downloading their content. The returned report grants
//! no lifecycle, deletion, page-store, provider, or witness authority.

use crate::{
    archive_v3::{
        ArchiveId, ArchiveRoot, ArchiveV3Error, CiphertextEnvelope, DatabaseEpoch,
        ImmutableReference, KeyKind, KeyRegistryContext, LogicalLocation, MerkleEntries,
        MerkleNode, ObjectContext, ObjectId, ObjectKey, ObjectRole, ParentReference,
        VerifiedArchiveCipher, MAX_DATABASE_BYTES, MAX_ENCODED_ENVELOPE_BYTES, MAX_NODE_BYTES,
        MAX_NODE_FANOUT, MAX_ROOT_BYTES, MAX_WRAPPED_KEY_REGISTRY_BYTES, SQLITE_PAGE_SIZE,
    },
    archive_v3_extent::EXTENT_BYTES,
    archive_v3_journal::{
        resolve_verified_wal_commit_descriptor, resolve_verified_wal_segment,
        validate_wal_commit_chain, CheckpointManifestEntries, CheckpointManifestNode,
        ResolvedWalCommitDescriptor, ResolvedWalSegment, WalCommitDescriptor,
        CHECKPOINT_CHUNK_BYTES, MAX_CHECKPOINT_MANIFEST_BYTES, MAX_CHECKPOINT_MANIFEST_FANOUT,
        MAX_WAL_COMMIT_DESCRIPTOR_BYTES, MAX_WAL_SEGMENTS_PER_COMMIT, MAX_WAL_SEGMENT_BYTES,
    },
    archive_v3_witness::{KeyRegistryReference, RecoveryRoot, RootCommitment},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_ROOT_GRAPHS: usize = 2;
const MAX_CHECKPOINT_CHUNKS: u32 = 32_768;
const MAX_CHECKPOINT_MANIFESTS: usize = 129;
const MAX_EXTENT_LEAVES: usize = 32_768;
const MAX_EXTENT_NODES: usize = 129;
const MAX_WAL_DESCRIPTORS: usize = 1_024;
const MAX_WAL_SEGMENTS: usize = 16_384;
const MAX_WAL_TAIL_BYTES: u64 = 1_073_741_824;
const MAX_GRAPH_DEPTH: u8 = 64;
const MAX_REACHABLE_OBJECTS: usize = 131_072;
const MAX_REACHABLE_KEY_BYTES: usize = 64 * 1024 * 1024;
const MAX_AUTHENTICATED_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_ONE_WAL_COMMIT_BYTES: usize = 16 * 1024 * 1024;
const ROOT_FACT_DOMAIN: &[u8] = b"kioku/archive-v3/reachability-root-fact/v2\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactReachabilityReadError {
    Unavailable,
    Cancelled,
    TooLarge,
    Protocol,
}

/// Narrow transport boundary: exact canonical names only, with an explicit
/// response cap. There is intentionally no enumerate, prefix, mutation,
/// provider-construction, credential, or continuation-token operation.
#[async_trait]
pub(crate) trait ExactReachabilityReader: Send + Sync {
    async fn read_exact(
        &self,
        key: &ObjectKey,
        max_encoded_bytes: usize,
    ) -> std::result::Result<Option<Vec<u8>>, ExactReachabilityReadError>;
}

#[cfg(test)]
struct CoordinatorTestRegistryProvider {
    wrapped: Vec<u8>,
    plaintext: Vec<u8>,
}

#[cfg(test)]
#[async_trait]
impl crate::archive_v3::ExactKeyRegistryProvider for CoordinatorTestRegistryProvider {
    async fn read_exact_wrapped(
        &self,
        _context: &KeyRegistryContext,
        _object_id: ObjectId,
        destination: &mut [u8],
    ) -> std::result::Result<usize, ArchiveV3Error> {
        destination[..self.wrapped.len()].copy_from_slice(&self.wrapped);
        Ok(self.wrapped.len())
    }

    async fn kms_unwrap_exact(
        &self,
        _context: &KeyRegistryContext,
        _wrapped_registry_ciphertext: &[u8],
        destination: &mut [u8],
    ) -> std::result::Result<usize, ArchiveV3Error> {
        destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
        Ok(self.plaintext.len())
    }
}

/// The registry binding, its resolved cipher, and the exact wrapped-registry
/// bytes behind it, for a test that must drive a whole deletion ladder: the
/// witness record, the lifecycle create-ahead rows and the graph walk all have
/// to agree on the same registry object ID and ciphertext hash, and only the
/// wrapped bytes make the lifecycle row's `Sha256` match.
#[cfg(test)]
pub(crate) async fn registry_binding_for_deletion_test(
    archive_id: ArchiveId,
    key_epoch: crate::archive_v3::KeyEpoch,
    registry_object_id: ObjectId,
) -> (
    crate::archive_v3_witness::KeyRegistryReference,
    VerifiedArchiveCipher,
    Vec<u8>,
) {
    let context = KeyRegistryContext::new(archive_id, KeyKind::Archive, key_epoch);
    let wrapped = vec![0x62, 0x63, 0x64];
    let wrapped_hash: [u8; 32] = Sha256::digest(&wrapped).into();
    let plaintext = crate::archive_v3::KeyRegistryPlaintext::encode_archive(
        &context,
        &crate::archive_v3::ArchiveDek::from_bytes([0x65; 32]),
    )
    .unwrap()
    .to_vec();
    let cipher = crate::archive_v3::resolve_archive_cipher(
        &context,
        registry_object_id,
        wrapped_hash,
        &CoordinatorTestRegistryProvider {
            wrapped: wrapped.clone(),
            plaintext,
        },
    )
    .await
    .unwrap();
    (
        crate::archive_v3_witness::KeyRegistryReference::new(
            key_epoch,
            0,
            registry_object_id,
            wrapped_hash,
        ),
        cipher,
        wrapped,
    )
}

#[cfg(test)]
pub(crate) async fn verified_cipher_for_coordinator_test(
    archive_id: ArchiveId,
) -> VerifiedArchiveCipher {
    let key_epoch = crate::archive_v3::KeyEpoch::from_bytes([0x61; 16]);
    let context = KeyRegistryContext::new(archive_id, KeyKind::Archive, key_epoch);
    let wrapped = vec![0x62, 0x63, 0x64];
    let plaintext = crate::archive_v3::KeyRegistryPlaintext::encode_archive(
        &context,
        &crate::archive_v3::ArchiveDek::from_bytes([0x65; 32]),
    )
    .unwrap()
    .to_vec();
    crate::archive_v3::resolve_archive_cipher(
        &context,
        ObjectId::from_bytes([0x66; 16]),
        Sha256::digest(&wrapped).into(),
        &CoordinatorTestRegistryProvider { wrapped, plaintext },
    )
    .await
    .unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum ReachabilityError {
    #[error("archive-v3 reachability snapshot or registry binding is invalid")]
    InvalidSnapshot,
    #[error("archive-v3 reachability edge or object authentication failed")]
    Authentication,
    #[error("archive-v3 reachability object is missing")]
    Missing,
    #[error("archive-v3 reachability graph contains a duplicate or cycle")]
    DuplicateOrCycle,
    #[error("archive-v3 reachability graph exceeded a fixed bound")]
    Limit,
    #[error("archive-v3 reachability exact reader is unavailable")]
    Unavailable,
    #[error("archive-v3 reachability visit was cancelled")]
    Cancelled,
}

/// A content-free exact object fact. Private fields and the absence of any
/// conversion into a lifecycle/deletion capability keep this report
/// non-authorizing. Most identities commit the complete AEAD/KMS context. A
/// root identity instead commits only the archive, authenticated
/// database namespace, sequence, object ID, and envelope hash because its
/// parent reference does not reveal a historical key epoch. `fetched`
/// distinguishes an exactly opened object from a reference authenticated by
/// its already-opened parent.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ReachableObject {
    key: ObjectKey,
    role: ObjectRole,
    ciphertext_hash: [u8; 32],
    identity_commitment: [u8; 32],
    fetched: bool,
}

impl ReachableObject {
    #[cfg(test)]
    pub(crate) fn for_test(key: ObjectKey, role: ObjectRole, ciphertext_hash: [u8; 32]) -> Self {
        Self {
            key,
            role,
            ciphertext_hash,
            identity_commitment: [0x7f; 32],
            fetched: true,
        }
    }

    pub(crate) fn key(&self) -> &ObjectKey {
        &self.key
    }

    pub(crate) const fn role(&self) -> ObjectRole {
        self.role
    }

    pub(crate) const fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }

    pub(crate) const fn was_fetched(&self) -> bool {
        self.fetched
    }
}

impl fmt::Debug for ReachableObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReachableObject(<opaque>)")
    }
}

/// Opaque, deterministic, content-free visit report. This type is not a seal,
/// admission, inventory, or deletion receipt and cannot mint any of them.
pub(crate) struct AuthenticatedReachabilityVisit {
    objects: Vec<ReachableObject>,
    graph_count: u8,
    exact_get_count: u32,
    authenticated_metadata_bytes: u64,
}

impl AuthenticatedReachabilityVisit {
    pub(crate) fn objects(&self) -> &[ReachableObject] {
        &self.objects
    }

    pub(crate) const fn graph_count(&self) -> u8 {
        self.graph_count
    }

    pub(crate) const fn exact_get_count(&self) -> u32 {
        self.exact_get_count
    }

    pub(crate) const fn authenticated_metadata_bytes(&self) -> u64 {
        self.authenticated_metadata_bytes
    }
}

impl fmt::Debug for AuthenticatedReachabilityVisit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedReachabilityVisit(<opaque, non-authorizing>)")
    }
}

struct GraphBinding<'a> {
    root: RootCommitment,
    registry: KeyRegistryReference,
    cipher: &'a VerifiedArchiveCipher,
    witnessed_predecessor: Option<RootCommitment>,
}

/// Authenticate every exactly reachable object in the witness-selected
/// current graph and optional predecessor graph. The caller must provide the
/// already exact-registry-resolved cipher for each graph; those bindings are
/// rechecked before the first archive-object read.
pub(crate) async fn visit_witness_reachability(
    recovery: &RecoveryRoot,
    reader: &dyn ExactReachabilityReader,
    current_cipher: &VerifiedArchiveCipher,
    predecessor_cipher: Option<&VerifiedArchiveCipher>,
) -> Result<AuthenticatedReachabilityVisit, ReachabilityError> {
    let predecessor = match (
        recovery.predecessor_root(),
        recovery.predecessor_registry(),
        predecessor_cipher,
    ) {
        (None, None, None) => None,
        (Some(root), Some(registry), Some(cipher)) => Some((root, registry, cipher)),
        _ => return Err(ReachabilityError::InvalidSnapshot),
    };
    let mut graphs = Vec::with_capacity(MAX_ROOT_GRAPHS);
    graphs.push(GraphBinding {
        root: recovery.root(),
        registry: recovery.registry(),
        cipher: current_cipher,
        witnessed_predecessor: predecessor.map(|value| value.0),
    });
    if let Some((root, registry, cipher)) = predecessor {
        graphs.push(GraphBinding {
            root,
            registry,
            cipher,
            witnessed_predecessor: None,
        });
    }
    visit_graph_bindings(recovery.archive_id(), reader, graphs).await
}

async fn visit_graph_bindings(
    archive_id: ArchiveId,
    reader: &dyn ExactReachabilityReader,
    graphs: Vec<GraphBinding<'_>>,
) -> Result<AuthenticatedReachabilityVisit, ReachabilityError> {
    if graphs.is_empty() || graphs.len() > MAX_ROOT_GRAPHS {
        return Err(ReachabilityError::InvalidSnapshot);
    }

    // Validate the whole witness-selected set before issuing the first exact
    // archive read. In particular, an invalid predecessor cipher must not be
    // discovered only after the current graph has already caused I/O.
    for graph in &graphs {
        validate_graph_binding(archive_id, graph)?;
    }

    let mut tracker = VisitTracker::new(archive_id);
    for graph in &graphs {
        visit_graph(reader, &mut tracker, graph).await?;
    }
    tracker.objects.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.role.cmp(&right.role))
            .then_with(|| left.ciphertext_hash.cmp(&right.ciphertext_hash))
    });
    Ok(AuthenticatedReachabilityVisit {
        objects: tracker.objects,
        graph_count: u8::try_from(graphs.len()).map_err(|_| ReachabilityError::Limit)?,
        exact_get_count: u32::try_from(tracker.exact_gets).map_err(|_| ReachabilityError::Limit)?,
        authenticated_metadata_bytes: u64::try_from(tracker.metadata_bytes)
            .map_err(|_| ReachabilityError::Limit)?,
    })
}

async fn visit_graph(
    reader: &dyn ExactReachabilityReader,
    tracker: &mut VisitTracker,
    graph: &GraphBinding<'_>,
) -> Result<(), ReachabilityError> {
    let registry_context = KeyRegistryContext::with_rotation_generation(
        tracker.archive_id,
        KeyKind::Archive,
        graph.registry.key_epoch(),
        graph.registry.rotation_generation(),
    );
    tracker.register_edge(
        registry_context.object_key(graph.registry.object_id()),
        ObjectRole::KeyRegistryV3,
        graph.registry.ciphertext_hash(),
        registry_context.canonical_kms_aad().as_slice(),
    )?;
    tracker.add_metadata(MAX_WRAPPED_KEY_REGISTRY_BYTES)?;

    let commitment = graph.root;
    let reference = commitment.root();
    let parent = commitment.parent().map(|value| ParentReference {
        object_id: value.object_id(),
        envelope_hash: value.ciphertext_hash(),
    });
    let context = ObjectContext::new(
        tracker.archive_id,
        commitment.database_epoch(),
        commitment.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: reference.sequence(),
        },
        reference.object_id(),
        parent,
    )
    .map_err(map_archive_error)?;
    let root_reference = ImmutableReference {
        object_id: reference.object_id(),
        envelope_hash: reference.ciphertext_hash(),
    };
    if let Some(parent) = commitment.parent() {
        let parent = ParentReference {
            object_id: parent.object_id(),
            envelope_hash: parent.ciphertext_hash(),
        };
        let sequence = reference
            .sequence()
            .checked_sub(1)
            .ok_or(ReachabilityError::Authentication)?;
        let _new = register_historical_root(tracker, graph, sequence, &parent)?;
    }
    tracker.ensure_metadata_capacity(MAX_ROOT_BYTES + 64)?;
    let (envelope, encoded_len) = read_exact_envelope(
        reader,
        tracker,
        &context,
        &root_reference,
        MAX_ROOT_BYTES + 64,
    )
    .await?;
    tracker.add_metadata(encoded_len)?;
    let plaintext = Zeroizing::new(
        graph
            .cipher
            .open(&context, &envelope)
            .map_err(map_archive_error)?,
    );
    let root = ArchiveRoot::decode(plaintext.as_slice()).map_err(map_archive_error)?;
    root.validate_for_context(&context)
        .map_err(map_archive_error)?;
    if root.root_seq != reference.sequence()
        || root.parent.as_ref() != context.parent()
        || root.database_epoch != commitment.database_epoch()
        || root.key_epoch != commitment.key_epoch()
        || root.owner_fencing_epoch != commitment.owner_fencing_epoch()
    {
        return Err(ReachabilityError::Authentication);
    }
    if let Some(parent) = &root.parent {
        let sequence = root
            .root_seq
            .checked_sub(1)
            .ok_or(ReachabilityError::Authentication)?;
        let _new = register_historical_root(tracker, graph, sequence, parent)?;
    }

    if let Some(reference) = root.checkpoint_root.clone() {
        visit_checkpoint(reader, tracker, graph.cipher, &root, reference).await?;
    }
    if let Some(reference) = root.extent_tree_root.clone() {
        visit_extents(reader, tracker, graph.cipher, &root, reference).await?;
    }
    if root.wal_commit_tail.is_some() {
        visit_wal(reader, tracker, graph, &root).await?;
    }
    Ok(())
}

fn validate_graph_binding(
    archive_id: ArchiveId,
    graph: &GraphBinding<'_>,
) -> Result<(), ReachabilityError> {
    let root = graph.root;
    let registry = graph.registry;
    if zero_bytes(archive_id.as_bytes())
        || zero_bytes(root.database_epoch().as_bytes())
        || zero_bytes(root.key_epoch().as_bytes())
        || zero_bytes(registry.key_epoch().as_bytes())
        || zero_id(root.root().object_id())
        || zero_hash(root.root().ciphertext_hash())
        || root.parent().is_some_and(|parent| {
            zero_id(parent.object_id()) || zero_hash(parent.ciphertext_hash())
        })
        || zero_id(registry.object_id())
        || zero_hash(registry.ciphertext_hash())
        || graph.cipher.archive_id() != archive_id
        || graph.cipher.key_epoch() != root.key_epoch()
        || registry.key_epoch() != root.key_epoch()
        || graph.cipher.registry_rotation_generation() != registry.rotation_generation()
        || graph.cipher.registry_object_id() != registry.object_id()
        || graph.cipher.registry_ciphertext_hash() != registry.ciphertext_hash()
        || match root.parent() {
            None => root.root().sequence() != 0 || root.owner_fencing_epoch() != 0,
            Some(parent) => {
                parent.sequence().checked_add(1) != Some(root.root().sequence())
                    || root.owner_fencing_epoch() == 0
            }
        }
    {
        return Err(ReachabilityError::InvalidSnapshot);
    }
    Ok(())
}

struct CheckpointTask {
    level: u8,
    range_start: u32,
    range_end: u32,
    reference: ImmutableReference,
    depth: u8,
}

async fn visit_checkpoint(
    reader: &dyn ExactReachabilityReader,
    tracker: &mut VisitTracker,
    cipher: &VerifiedArchiveCipher,
    root: &ArchiveRoot,
    root_reference: ImmutableReference,
) -> Result<(), ReachabilityError> {
    let total_chunks = checkpoint_chunks(root.checkpoint_logical_file_length)?;
    let root_level = checkpoint_height(total_chunks)?;
    if root_reference
        .object_id
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || zero_hash(root_reference.envelope_hash)
    {
        return Err(ReachabilityError::Authentication);
    }
    let checkpoint_id = root_reference.object_id;
    let mut stack = vec![CheckpointTask {
        level: root_level,
        range_start: 0,
        range_end: total_chunks,
        reference: root_reference,
        depth: 0,
    }];
    let mut manifest_count = 0usize;
    let mut chunk_count = 0u32;
    let mut expected_descriptor: Option<(u64, u32, [u8; 32])> = None;
    while let Some(task) = stack.pop() {
        check_graph_depth(task.depth)?;
        bounded_count(&mut manifest_count, 1, MAX_CHECKPOINT_MANIFESTS)?;
        let context = ObjectContext::new(
            tracker.archive_id,
            root.database_epoch,
            root.key_epoch,
            ObjectRole::CheckpointManifestV3,
            LogicalLocation::CheckpointManifest {
                checkpoint_id,
                level: task.level,
                range_start: task.range_start,
                range_end: task.range_end,
            },
            task.reference.object_id,
            None,
        )
        .map_err(map_archive_error)?;
        tracker.ensure_metadata_capacity(MAX_CHECKPOINT_MANIFEST_BYTES + 64)?;
        let (envelope, encoded_len) = read_exact_envelope(
            reader,
            tracker,
            &context,
            &task.reference,
            MAX_CHECKPOINT_MANIFEST_BYTES + 64,
        )
        .await?;
        tracker.add_metadata(encoded_len)?;
        let plaintext = Zeroizing::new(
            cipher
                .open(&context, &envelope)
                .map_err(map_archive_error)?,
        );
        let node =
            CheckpointManifestNode::decode(plaintext.as_slice()).map_err(map_archive_error)?;
        node.validate_for_context(&context)
            .map_err(map_archive_error)?;
        validate_checkpoint_hashes(&node)?;
        if node.checkpoint_id != checkpoint_id
            || node.level != task.level
            || node.range_start != task.range_start
            || node.range_end != task.range_end
            || node.total_chunks != total_chunks
            || node.logical_file_length != root.checkpoint_logical_file_length
            || node.sqlite_page_size != SQLITE_PAGE_SIZE
        {
            return Err(ReachabilityError::Authentication);
        }
        tracker.mark_fetched(task.reference.object_id)?;
        let descriptor = (
            node.logical_file_length,
            node.total_chunks,
            node.database_plaintext_hash,
        );
        if expected_descriptor.get_or_insert(descriptor) != &descriptor {
            return Err(ReachabilityError::Authentication);
        }
        match node.entries {
            CheckpointManifestEntries::Chunks(entries) => {
                let entry_count =
                    u32::try_from(entries.len()).map_err(|_| ReachabilityError::Limit)?;
                chunk_count = chunk_count
                    .checked_add(entry_count)
                    .filter(|count| *count <= MAX_CHECKPOINT_CHUNKS)
                    .ok_or(ReachabilityError::Limit)?;
                for entry in entries {
                    let context = ObjectContext::new(
                        tracker.archive_id,
                        root.database_epoch,
                        root.key_epoch,
                        ObjectRole::CheckpointChunkV3,
                        LogicalLocation::CheckpointChunk {
                            checkpoint_id,
                            chunk_index: entry.chunk_index,
                            logical_offset: entry.logical_offset,
                            byte_len: entry.logical_byte_len,
                        },
                        entry.reference.object_id,
                        None,
                    )
                    .map_err(map_archive_error)?;
                    let _new = tracker.register_context_edge(&context, &entry.reference)?;
                }
            }
            CheckpointManifestEntries::Children(children) => {
                let child_level = task
                    .level
                    .checked_sub(1)
                    .ok_or(ReachabilityError::Authentication)?;
                let child_depth = task.depth.checked_add(1).ok_or(ReachabilityError::Limit)?;
                for child in children.into_iter().rev() {
                    let child_context = ObjectContext::new(
                        tracker.archive_id,
                        root.database_epoch,
                        root.key_epoch,
                        ObjectRole::CheckpointManifestV3,
                        LogicalLocation::CheckpointManifest {
                            checkpoint_id,
                            level: child_level,
                            range_start: child.range_start,
                            range_end: child.range_end,
                        },
                        child.reference.object_id,
                        None,
                    )
                    .map_err(map_archive_error)?;
                    if tracker.register_context_edge(&child_context, &child.reference)? {
                        stack.push(CheckpointTask {
                            level: child_level,
                            range_start: child.range_start,
                            range_end: child.range_end,
                            reference: child.reference,
                            depth: child_depth,
                        });
                    }
                }
            }
        }
    }
    if chunk_count != total_chunks || manifest_count == 0 {
        return Err(ReachabilityError::Authentication);
    }
    Ok(())
}

struct ExtentTask {
    level: u8,
    range_start: u64,
    range_end: u64,
    reference: ImmutableReference,
    depth: u8,
}

async fn visit_extents(
    reader: &dyn ExactReachabilityReader,
    tracker: &mut VisitTracker,
    cipher: &VerifiedArchiveCipher,
    root: &ArchiveRoot,
    root_reference: ImmutableReference,
) -> Result<(), ReachabilityError> {
    let slots = extent_slots(root.logical_file_length)?;
    let root_level = extent_height(slots)?;
    let mut stack = vec![ExtentTask {
        level: root_level,
        range_start: 0,
        range_end: slots,
        reference: root_reference,
        depth: 0,
    }];
    let mut node_count = 0usize;
    let mut leaf_count = 0usize;
    while let Some(task) = stack.pop() {
        check_graph_depth(task.depth)?;
        bounded_count(&mut node_count, 1, MAX_EXTENT_NODES)?;
        let context = ObjectContext::new(
            tracker.archive_id,
            root.database_epoch,
            root.key_epoch,
            ObjectRole::MerkleNodeV3,
            LogicalLocation::MerkleNode {
                level: task.level,
                range_start: task.range_start,
                range_end: task.range_end,
            },
            task.reference.object_id,
            None,
        )
        .map_err(map_archive_error)?;
        tracker.ensure_metadata_capacity(MAX_NODE_BYTES + 64)?;
        let (envelope, encoded_len) = read_exact_envelope(
            reader,
            tracker,
            &context,
            &task.reference,
            MAX_NODE_BYTES + 64,
        )
        .await?;
        tracker.add_metadata(encoded_len)?;
        let plaintext = Zeroizing::new(
            cipher
                .open(&context, &envelope)
                .map_err(map_archive_error)?,
        );
        let node = MerkleNode::decode(plaintext.as_slice()).map_err(map_archive_error)?;
        node.validate().map_err(map_archive_error)?;
        if node.level != task.level
            || node.range_start != task.range_start
            || node.range_end != task.range_end
        {
            return Err(ReachabilityError::Authentication);
        }
        tracker.mark_fetched(task.reference.object_id)?;
        match node.entries {
            MerkleEntries::Leaf(entries) => {
                bounded_count(&mut leaf_count, entries.len(), MAX_EXTENT_LEAVES)?;
                for entry in entries {
                    validate_extent_reference(&entry, slots, root.logical_file_length)?;
                    let context = ObjectContext::new(
                        tracker.archive_id,
                        root.database_epoch,
                        root.key_epoch,
                        ObjectRole::ExtentV3,
                        LogicalLocation::Extent {
                            extent_no: entry.extent_no,
                            byte_len: entry.logical_byte_len,
                        },
                        entry.reference.object_id,
                        None,
                    )
                    .map_err(map_archive_error)?;
                    let _new = tracker.register_context_edge(&context, &entry.reference)?;
                }
            }
            MerkleEntries::Internal(children) => {
                let child_level = task
                    .level
                    .checked_sub(1)
                    .ok_or(ReachabilityError::Authentication)?;
                let child_depth = task.depth.checked_add(1).ok_or(ReachabilityError::Limit)?;
                for child in children.into_iter().rev() {
                    let child_context = ObjectContext::new(
                        tracker.archive_id,
                        root.database_epoch,
                        root.key_epoch,
                        ObjectRole::MerkleNodeV3,
                        LogicalLocation::MerkleNode {
                            level: child_level,
                            range_start: child.range_start,
                            range_end: child.range_end,
                        },
                        child.reference.object_id,
                        None,
                    )
                    .map_err(map_archive_error)?;
                    if tracker.register_context_edge(&child_context, &child.reference)? {
                        stack.push(ExtentTask {
                            level: child_level,
                            range_start: child.range_start,
                            range_end: child.range_end,
                            reference: child.reference,
                            depth: child_depth,
                        });
                    }
                }
            }
        }
    }
    if node_count == 0 || leaf_count == 0 {
        return Err(ReachabilityError::Authentication);
    }
    Ok(())
}

async fn visit_wal(
    reader: &dyn ExactReachabilityReader,
    tracker: &mut VisitTracker,
    graph: &GraphBinding<'_>,
    root: &ArchiveRoot,
) -> Result<(), ReachabilityError> {
    let cipher = graph.cipher;
    let final_reference = root
        .wal_commit_tail
        .clone()
        .ok_or(ReachabilityError::Authentication)?;
    validate_wal_root_bounds(root)?;
    let checkpoint_root = root
        .checkpoint_root
        .clone()
        .ok_or(ReachabilityError::Authentication)?;
    let mut reversed = Vec::with_capacity(root.wal_commit_count as usize);
    let mut expected_reference = Some(final_reference);
    let mut expected_root_seq = root.root_seq;
    let mut expected_parent = root
        .parent
        .clone()
        .ok_or(ReachabilityError::Authentication)?;
    let mut expected_after_length = root.logical_file_length;
    for expected_count in (1..=root.wal_commit_count).rev() {
        let reference = expected_reference
            .take()
            .ok_or(ReachabilityError::Authentication)?;
        let context = wal_commit_context(
            root,
            tracker.archive_id,
            expected_root_seq,
            reference.object_id,
        )?;
        tracker.ensure_metadata_capacity(MAX_WAL_COMMIT_DESCRIPTOR_BYTES + 64)?;
        let (envelope, encoded_len) = read_exact_envelope(
            reader,
            tracker,
            &context,
            &reference,
            MAX_WAL_COMMIT_DESCRIPTOR_BYTES + 64,
        )
        .await?;
        tracker.add_metadata(encoded_len)?;
        let resolved = resolve_verified_wal_commit_descriptor(cipher, context, reference, envelope)
            .map_err(map_archive_error)?;
        tracker.mark_fetched(resolved.reference().object_id)?;
        let descriptor = resolved.descriptor();
        validate_one_wal_commit_bounds(
            descriptor.commit_segment_count,
            descriptor.commit_wal_bytes,
        )?;
        if descriptor.root_seq != expected_root_seq
            || descriptor.parent_root != expected_parent
            || descriptor.checkpoint_root != checkpoint_root
            || descriptor.checkpoint_logical_file_length != root.checkpoint_logical_file_length
            || descriptor.after_logical_file_length != expected_after_length
            || descriptor.cumulative_commit_count != expected_count
            || (expected_count == root.wal_commit_count
                && (descriptor.cumulative_segment_count != root.wal_segment_count
                    || descriptor.cumulative_wal_bytes != root.wal_tail_bytes
                    || descriptor.wal_generation != root.wal_generation))
        {
            return Err(ReachabilityError::Authentication);
        }
        let parent_sequence = descriptor
            .root_seq
            .checked_sub(1)
            .ok_or(ReachabilityError::Authentication)?;
        let _new =
            register_historical_root(tracker, graph, parent_sequence, &descriptor.parent_root)?;
        if let Some(grandparent) = &descriptor.parent_root_parent {
            let grandparent_sequence = descriptor
                .root_seq
                .checked_sub(2)
                .ok_or(ReachabilityError::Authentication)?;
            let _new = register_historical_root(tracker, graph, grandparent_sequence, grandparent)?;
        }
        let final_segment_context = ObjectContext::new(
            tracker.archive_id,
            root.database_epoch,
            root.key_epoch,
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq: descriptor.root_seq,
                wal_generation: descriptor.wal_generation,
                segment_index: descriptor
                    .commit_segment_count
                    .checked_sub(1)
                    .ok_or(ReachabilityError::Authentication)?,
            },
            descriptor.final_segment.object_id,
            None,
        )
        .map_err(map_archive_error)?;
        if !tracker.register_context_edge(&final_segment_context, &descriptor.final_segment)? {
            return Err(ReachabilityError::DuplicateOrCycle);
        }
        expected_reference = descriptor.previous_commit.clone();
        let next_root_seq = expected_root_seq
            .checked_sub(1)
            .ok_or(ReachabilityError::Authentication)?;
        if let Some(previous) = &expected_reference {
            let previous_context =
                wal_commit_context(root, tracker.archive_id, next_root_seq, previous.object_id)?;
            if !tracker.register_context_edge(&previous_context, previous)? {
                return Err(ReachabilityError::DuplicateOrCycle);
            }
        }
        expected_root_seq = next_root_seq;
        expected_parent = descriptor
            .parent_root_parent
            .clone()
            .unwrap_or_else(|| descriptor.parent_root.clone());
        expected_after_length = descriptor.before_logical_file_length;
        reversed.push(resolved);
    }
    if expected_reference.is_some()
        || expected_after_length != root.checkpoint_logical_file_length
        || expected_root_seq.checked_add(u64::from(root.wal_commit_count)) != Some(root.root_seq)
    {
        return Err(ReachabilityError::Authentication);
    }
    reversed.reverse();
    validate_descriptor_continuity(root, &reversed)?;

    let mut segment_total = 0usize;
    for resolved in &reversed {
        let descriptor = resolved.descriptor();
        let segments = load_commit_segments(reader, tracker, cipher, root, descriptor).await?;
        let commit_bytes = segments.iter().try_fold(0usize, |total, segment| {
            total
                .checked_add(segment.segment().frames.len())
                .ok_or(ReachabilityError::Limit)
        })?;
        if commit_bytes > MAX_ONE_WAL_COMMIT_BYTES {
            return Err(ReachabilityError::Limit);
        }
        validate_wal_commit_chain(descriptor, &segments).map_err(map_archive_error)?;
        segment_total = segment_total
            .checked_add(segments.len())
            .ok_or(ReachabilityError::Limit)?;
        if segment_total > MAX_WAL_SEGMENTS {
            return Err(ReachabilityError::Limit);
        }
        // `ResolvedWalSegment` owns `WalSegment`; dropping this one-commit
        // vector zeroizes every frame buffer before the next commit loads.
        drop(segments);
    }
    if u32::try_from(segment_total).ok() != Some(root.wal_segment_count) {
        return Err(ReachabilityError::Authentication);
    }
    Ok(())
}

fn validate_descriptor_continuity(
    root: &ArchiveRoot,
    descriptors: &[ResolvedWalCommitDescriptor],
) -> Result<(), ReachabilityError> {
    let mut previous: Option<&WalCommitDescriptor> = None;
    for resolved in descriptors {
        let descriptor = resolved.descriptor();
        if let Some(previous) = previous {
            let expected_frame = previous
                .first_frame_no
                .checked_add(u64::from(previous.frame_count))
                .ok_or(ReachabilityError::Authentication)?;
            let same_generation = descriptor.wal_generation == previous.wal_generation
                && descriptor.first_frame_no == expected_frame
                && descriptor.wal_header_hash == previous.wal_header_hash
                && descriptor.checksum_before == previous.checksum_after;
            let next_generation = descriptor.wal_generation
                == previous
                    .wal_generation
                    .checked_add(1)
                    .ok_or(ReachabilityError::Authentication)?
                && descriptor.first_frame_no == 1;
            if Some(descriptor.root_seq) != previous.root_seq.checked_add(1)
                || descriptor.parent_root_parent.as_ref() != Some(&previous.parent_root)
                || descriptor.before_logical_file_length != previous.after_logical_file_length
                || descriptor.cumulative_commit_count != previous.cumulative_commit_count + 1
                || descriptor.cumulative_segment_count
                    != previous.cumulative_segment_count + descriptor.commit_segment_count
                || descriptor.cumulative_wal_bytes
                    != previous.cumulative_wal_bytes + descriptor.commit_wal_bytes
                || !(same_generation || next_generation)
            {
                return Err(ReachabilityError::Authentication);
            }
        } else if descriptor.cumulative_commit_count != 1
            || descriptor.cumulative_segment_count != descriptor.commit_segment_count
            || descriptor.cumulative_wal_bytes != descriptor.commit_wal_bytes
            || descriptor.before_logical_file_length != root.checkpoint_logical_file_length
            || descriptor.wal_generation != 1
            || descriptor.first_frame_no != 1
        {
            return Err(ReachabilityError::Authentication);
        }
        previous = Some(descriptor);
    }
    Ok(())
}

async fn load_commit_segments(
    reader: &dyn ExactReachabilityReader,
    tracker: &mut VisitTracker,
    cipher: &VerifiedArchiveCipher,
    root: &ArchiveRoot,
    descriptor: &WalCommitDescriptor,
) -> Result<Vec<ResolvedWalSegment>, ReachabilityError> {
    let capacity =
        usize::try_from(descriptor.commit_segment_count).map_err(|_| ReachabilityError::Limit)?;
    if capacity == 0 || capacity > MAX_WAL_SEGMENTS_PER_COMMIT as usize {
        return Err(ReachabilityError::Limit);
    }
    let mut reversed = Vec::with_capacity(capacity);
    let mut expected_reference = Some(descriptor.final_segment.clone());
    for segment_index in (0..descriptor.commit_segment_count).rev() {
        let reference = expected_reference
            .take()
            .ok_or(ReachabilityError::Authentication)?;
        let context = ObjectContext::new(
            tracker.archive_id,
            root.database_epoch,
            root.key_epoch,
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq: descriptor.root_seq,
                wal_generation: descriptor.wal_generation,
                segment_index,
            },
            reference.object_id,
            None,
        )
        .map_err(map_archive_error)?;
        tracker.ensure_metadata_capacity(138)?;
        let (envelope, _encoded_len) = read_exact_envelope(
            reader,
            tracker,
            &context,
            &reference,
            MAX_WAL_SEGMENT_BYTES + 64,
        )
        .await?;
        let resolved = resolve_verified_wal_segment(cipher, context, reference, envelope)
            .map_err(map_archive_error)?;
        tracker.mark_fetched(resolved.reference().object_id)?;
        // The segment codec's fixed framing is 90 bytes plus one optional
        // 48-byte predecessor reference. Do not call `encode` here: that
        // would duplicate attacker-sized frame plaintext into a non-zeroizing
        // temporary merely to measure metadata.
        let segment_metadata = 90usize
            .checked_add(
                resolved
                    .segment()
                    .previous_segment
                    .as_ref()
                    .map_or(0, |_| 48),
            )
            .ok_or(ReachabilityError::Limit)?;
        tracker.add_metadata(segment_metadata)?;
        expected_reference = resolved.segment().previous_segment.clone();
        if let Some(previous) = &expected_reference {
            let previous_index = segment_index
                .checked_sub(1)
                .ok_or(ReachabilityError::Authentication)?;
            let previous_context = ObjectContext::new(
                tracker.archive_id,
                root.database_epoch,
                root.key_epoch,
                ObjectRole::WalSegmentV3,
                LogicalLocation::Wal {
                    root_seq: descriptor.root_seq,
                    wal_generation: descriptor.wal_generation,
                    segment_index: previous_index,
                },
                previous.object_id,
                None,
            )
            .map_err(map_archive_error)?;
            if !tracker.register_context_edge(&previous_context, previous)? {
                return Err(ReachabilityError::DuplicateOrCycle);
            }
        }
        reversed.push(resolved);
    }
    if expected_reference.is_some() {
        return Err(ReachabilityError::Authentication);
    }
    reversed.reverse();
    Ok(reversed)
}

fn wal_commit_context(
    root: &ArchiveRoot,
    archive_id: ArchiveId,
    root_seq: u64,
    object_id: ObjectId,
) -> Result<ObjectContext, ReachabilityError> {
    ObjectContext::new(
        archive_id,
        root.database_epoch,
        root.key_epoch,
        ObjectRole::WalCommitDescriptorV3,
        LogicalLocation::WalCommitDescriptor { root_seq },
        object_id,
        None,
    )
    .map_err(map_archive_error)
}

async fn read_exact_envelope(
    reader: &dyn ExactReachabilityReader,
    tracker: &mut VisitTracker,
    context: &ObjectContext,
    reference: &ImmutableReference,
    max_encoded_bytes: usize,
) -> Result<(CiphertextEnvelope, usize), ReachabilityError> {
    tracker.register_context_direct(context, reference)?;
    tracker.exact_gets = tracker
        .exact_gets
        .checked_add(1)
        .ok_or(ReachabilityError::Limit)?;
    let encoded = reader
        .read_exact(&context.object_key(), max_encoded_bytes)
        .await
        .map_err(map_reader_error)?
        .ok_or(ReachabilityError::Missing)?;
    if encoded.is_empty()
        || encoded.len() > max_encoded_bytes
        || encoded.len() > MAX_ENCODED_ENVELOPE_BYTES
    {
        return Err(ReachabilityError::Limit);
    }
    let envelope = CiphertextEnvelope::decode(&encoded).map_err(map_archive_error)?;
    if envelope.hash() != reference.envelope_hash {
        return Err(ReachabilityError::Authentication);
    }
    Ok((envelope, encoded.len()))
}

#[derive(Clone, PartialEq, Eq)]
struct VisitIdentity {
    key: ObjectKey,
    role: ObjectRole,
    ciphertext_hash: [u8; 32],
    identity_commitment: [u8; 32],
}

struct VisitEntry {
    identity: VisitIdentity,
    object_index: usize,
}

struct VisitTracker {
    archive_id: ArchiveId,
    identities: BTreeMap<ObjectId, VisitEntry>,
    objects: Vec<ReachableObject>,
    key_bytes: usize,
    metadata_bytes: usize,
    exact_gets: usize,
}

impl VisitTracker {
    fn new(archive_id: ArchiveId) -> Self {
        Self {
            archive_id,
            identities: BTreeMap::new(),
            objects: Vec::new(),
            key_bytes: 0,
            metadata_bytes: 0,
            exact_gets: 0,
        }
    }

    fn register_context_direct(
        &mut self,
        context: &ObjectContext,
        reference: &ImmutableReference,
    ) -> Result<(), ReachabilityError> {
        let identity = identity_for_context(context, reference)?;
        if let Some(previous) = self.identities.get(&reference.object_id) {
            if previous.identity != identity {
                return Err(ReachabilityError::DuplicateOrCycle);
            }
            let object = self
                .objects
                .get_mut(previous.object_index)
                .ok_or(ReachabilityError::Authentication)?;
            if object.fetched {
                return Err(ReachabilityError::DuplicateOrCycle);
            }
            object.fetched = true;
            return Ok(());
        }
        self.insert(identity, true).map(|_| ())
    }

    fn register_context_edge(
        &mut self,
        context: &ObjectContext,
        reference: &ImmutableReference,
    ) -> Result<bool, ReachabilityError> {
        let identity = identity_for_context(context, reference)?;
        self.insert(identity, false)
    }

    fn register_edge(
        &mut self,
        key: ObjectKey,
        role: ObjectRole,
        ciphertext_hash: [u8; 32],
        canonical_context: &[u8],
    ) -> Result<(), ReachabilityError> {
        if zero_id(key.object_id()) || zero_hash(ciphertext_hash) || canonical_context.is_empty() {
            return Err(ReachabilityError::Authentication);
        }
        self.insert(
            VisitIdentity {
                key,
                role,
                ciphertext_hash,
                identity_commitment: Sha256::digest(canonical_context).into(),
            },
            false,
        )
        .map(|_| ())
    }

    fn insert(
        &mut self,
        identity: VisitIdentity,
        fetched: bool,
    ) -> Result<bool, ReachabilityError> {
        if let Some(previous) = self.identities.get(&identity.key.object_id()) {
            return if previous.identity == identity {
                Ok(false)
            } else {
                Err(ReachabilityError::DuplicateOrCycle)
            };
        }
        let next_key_bytes = self
            .key_bytes
            .checked_add(identity.key.as_str().len())
            .ok_or(ReachabilityError::Limit)?;
        if self.objects.len() >= MAX_REACHABLE_OBJECTS || next_key_bytes > MAX_REACHABLE_KEY_BYTES {
            return Err(ReachabilityError::Limit);
        }
        self.key_bytes = next_key_bytes;
        let object_index = self.objects.len();
        self.objects.push(ReachableObject {
            key: identity.key.clone(),
            role: identity.role,
            ciphertext_hash: identity.ciphertext_hash,
            identity_commitment: identity.identity_commitment,
            fetched,
        });
        self.identities.insert(
            identity.key.object_id(),
            VisitEntry {
                identity,
                object_index,
            },
        );
        Ok(true)
    }

    fn add_metadata(&mut self, bytes: usize) -> Result<(), ReachabilityError> {
        self.metadata_bytes = self
            .metadata_bytes
            .checked_add(bytes)
            .ok_or(ReachabilityError::Limit)?;
        if self.metadata_bytes > MAX_AUTHENTICATED_METADATA_BYTES {
            return Err(ReachabilityError::Limit);
        }
        Ok(())
    }

    fn ensure_metadata_capacity(&self, bytes: usize) -> Result<(), ReachabilityError> {
        self.metadata_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_AUTHENTICATED_METADATA_BYTES)
            .map(|_| ())
            .ok_or(ReachabilityError::Limit)
    }

    fn mark_fetched(&mut self, object_id: ObjectId) -> Result<(), ReachabilityError> {
        let index = self
            .identities
            .get(&object_id)
            .map(|entry| entry.object_index)
            .ok_or(ReachabilityError::Authentication)?;
        self.objects
            .get_mut(index)
            .map(|object| object.fetched = true)
            .ok_or(ReachabilityError::Authentication)
    }
}

fn register_historical_root(
    tracker: &mut VisitTracker,
    graph: &GraphBinding<'_>,
    sequence: u64,
    reference: &ParentReference,
) -> Result<bool, ReachabilityError> {
    if zero_id(reference.object_id) || zero_hash(reference.envelope_hash) {
        return Err(ReachabilityError::Authentication);
    }
    let database_epoch = historical_root_database_epoch(graph, sequence, reference)?;
    // `ObjectKey` intentionally omits the key epoch for immutable root
    // candidates. Use ObjectContext only as the canonical path formatter; the
    // unfetched fact below does not retain this naming-only key value or any
    // guessed AEAD/parent context.
    let naming_context = ObjectContext::new(
        tracker.archive_id,
        database_epoch,
        graph.root.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root { root_seq: sequence },
        reference.object_id,
        None,
    )
    .map_err(map_archive_error)?;
    tracker.insert(
        VisitIdentity {
            key: naming_context.object_key(),
            role: ObjectRole::RootV3,
            ciphertext_hash: reference.envelope_hash,
            identity_commitment: root_fact_commitment(
                tracker.archive_id,
                database_epoch,
                sequence,
                reference.object_id,
                reference.envelope_hash,
            ),
        },
        false,
    )
}

fn historical_root_database_epoch(
    graph: &GraphBinding<'_>,
    sequence: u64,
    reference: &ParentReference,
) -> Result<DatabaseEpoch, ReachabilityError> {
    let Some(predecessor) = graph.witnessed_predecessor else {
        return Ok(graph.root.database_epoch());
    };
    let predecessor_root = predecessor.root();
    if reference.object_id == predecessor_root.object_id()
        && reference.envelope_hash == predecessor_root.ciphertext_hash()
        && sequence != predecessor_root.sequence()
    {
        return Err(ReachabilityError::Authentication);
    }
    if sequence == predecessor_root.sequence()
        && (reference.object_id != predecessor_root.object_id()
            || reference.envelope_hash != predecessor_root.ciphertext_hash())
    {
        return Err(ReachabilityError::Authentication);
    }
    if sequence <= predecessor_root.sequence() {
        Ok(predecessor.database_epoch())
    } else {
        Ok(graph.root.database_epoch())
    }
}

fn identity_for_context(
    context: &ObjectContext,
    reference: &ImmutableReference,
) -> Result<VisitIdentity, ReachabilityError> {
    if context.object_id() != reference.object_id
        || zero_id(reference.object_id)
        || zero_hash(reference.envelope_hash)
    {
        return Err(ReachabilityError::Authentication);
    }
    let identity_commitment = match (context.role(), context.location()) {
        (ObjectRole::RootV3, LogicalLocation::Root { root_seq }) => root_fact_commitment(
            context.archive_id(),
            context.database_epoch(),
            *root_seq,
            reference.object_id,
            reference.envelope_hash,
        ),
        _ => Sha256::digest(context.canonical_aad()).into(),
    };
    Ok(VisitIdentity {
        key: context.object_key(),
        role: context.role(),
        ciphertext_hash: reference.envelope_hash,
        identity_commitment,
    })
}

fn root_fact_commitment(
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    sequence: u64,
    object_id: ObjectId,
    ciphertext_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_FACT_DOMAIN);
    hasher.update(archive_id.as_bytes());
    hasher.update(database_epoch.as_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(object_id.as_bytes());
    hasher.update(ciphertext_hash);
    hasher.finalize().into()
}

fn checkpoint_chunks(length: u64) -> Result<u32, ReachabilityError> {
    if length == 0
        || length > MAX_DATABASE_BYTES
        || !length.is_multiple_of(u64::from(SQLITE_PAGE_SIZE))
    {
        return Err(ReachabilityError::Authentication);
    }
    let chunks = length.div_ceil(u64::from(CHECKPOINT_CHUNK_BYTES));
    let chunks = u32::try_from(chunks).map_err(|_| ReachabilityError::Limit)?;
    if chunks == 0 || chunks > MAX_CHECKPOINT_CHUNKS {
        return Err(ReachabilityError::Limit);
    }
    Ok(chunks)
}

fn validate_checkpoint_hashes(node: &CheckpointManifestNode) -> Result<(), ReachabilityError> {
    let invalid_entry = match &node.entries {
        CheckpointManifestEntries::Chunks(chunks) => chunks.iter().any(|chunk| {
            zero_hash(chunk.plaintext_hash)
                || zero_id(chunk.reference.object_id)
                || zero_hash(chunk.reference.envelope_hash)
        }),
        CheckpointManifestEntries::Children(children) => children.iter().any(|child| {
            zero_id(child.reference.object_id) || zero_hash(child.reference.envelope_hash)
        }),
    };
    if zero_id(node.checkpoint_id) || zero_hash(node.database_plaintext_hash) || invalid_entry {
        return Err(ReachabilityError::Authentication);
    }
    Ok(())
}

fn check_graph_depth(depth: u8) -> Result<(), ReachabilityError> {
    (depth <= MAX_GRAPH_DEPTH)
        .then_some(())
        .ok_or(ReachabilityError::Limit)
}

fn bounded_count(
    count: &mut usize,
    increment: usize,
    maximum: usize,
) -> Result<(), ReachabilityError> {
    *count = count
        .checked_add(increment)
        .filter(|next| *next <= maximum)
        .ok_or(ReachabilityError::Limit)?;
    Ok(())
}

fn validate_wal_root_bounds(root: &ArchiveRoot) -> Result<(), ReachabilityError> {
    if root.wal_commit_count == 0
        || usize::try_from(root.wal_commit_count).map_or(true, |count| count > MAX_WAL_DESCRIPTORS)
        || root.wal_segment_count == 0
        || usize::try_from(root.wal_segment_count).map_or(true, |count| count > MAX_WAL_SEGMENTS)
        || root.wal_tail_bytes == 0
        || root.wal_tail_bytes > MAX_WAL_TAIL_BYTES
    {
        return Err(ReachabilityError::Limit);
    }
    Ok(())
}

fn validate_one_wal_commit_bounds(
    segment_count: u32,
    encoded_wal_bytes: u64,
) -> Result<(), ReachabilityError> {
    if segment_count == 0
        || segment_count > MAX_WAL_SEGMENTS_PER_COMMIT
        || encoded_wal_bytes == 0
        || usize::try_from(encoded_wal_bytes).map_or(true, |bytes| bytes > MAX_ONE_WAL_COMMIT_BYTES)
    {
        return Err(ReachabilityError::Limit);
    }
    Ok(())
}

fn checkpoint_height(total_chunks: u32) -> Result<u8, ReachabilityError> {
    let leaf_count = total_chunks.div_ceil(MAX_CHECKPOINT_MANIFEST_FANOUT as u32);
    bounded_height(u64::from(leaf_count), MAX_CHECKPOINT_MANIFEST_FANOUT as u64)
}

fn extent_slots(length: u64) -> Result<u64, ReachabilityError> {
    if length == 0
        || length > MAX_DATABASE_BYTES
        || !length.is_multiple_of(u64::from(SQLITE_PAGE_SIZE))
    {
        return Err(ReachabilityError::Authentication);
    }
    let slots = length.div_ceil(u64::from(EXTENT_BYTES));
    if slots == 0 || slots > MAX_EXTENT_LEAVES as u64 {
        return Err(ReachabilityError::Limit);
    }
    Ok(slots)
}

fn extent_height(slots: u64) -> Result<u8, ReachabilityError> {
    let leaf_count = slots.div_ceil(MAX_NODE_FANOUT as u64);
    bounded_height(leaf_count, MAX_NODE_FANOUT as u64)
}

fn bounded_height(mut count: u64, fanout: u64) -> Result<u8, ReachabilityError> {
    let mut height = 0u8;
    while count > 1 {
        count = count.div_ceil(fanout);
        height = height.checked_add(1).ok_or(ReachabilityError::Limit)?;
        if height > MAX_GRAPH_DEPTH {
            return Err(ReachabilityError::Limit);
        }
    }
    Ok(height)
}

fn validate_extent_reference(
    entry: &crate::archive_v3::ExtentReference,
    slots: u64,
    logical_file_length: u64,
) -> Result<(), ReachabilityError> {
    entry.validate().map_err(map_archive_error)?;
    if entry.extent_no >= slots {
        return Err(ReachabilityError::Authentication);
    }
    let offset = entry
        .extent_no
        .checked_mul(u64::from(EXTENT_BYTES))
        .ok_or(ReachabilityError::Authentication)?;
    let expected = logical_file_length
        .checked_sub(offset)
        .ok_or(ReachabilityError::Authentication)?
        .min(u64::from(EXTENT_BYTES));
    if u64::from(entry.logical_byte_len) != expected || entry.revision == 0 {
        return Err(ReachabilityError::Authentication);
    }
    Ok(())
}

fn zero_id(id: ObjectId) -> bool {
    zero_bytes(id.as_bytes())
}

fn zero_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn zero_hash(hash: [u8; 32]) -> bool {
    hash.iter().all(|byte| *byte == 0)
}

fn map_archive_error(error: ArchiveV3Error) -> ReachabilityError {
    match error {
        ArchiveV3Error::TooLarge(_) => ReachabilityError::Limit,
        ArchiveV3Error::Unavailable => ReachabilityError::Unavailable,
        _ => ReachabilityError::Authentication,
    }
}

fn map_reader_error(error: ExactReachabilityReadError) -> ReachabilityError {
    match error {
        ExactReachabilityReadError::Cancelled => ReachabilityError::Cancelled,
        ExactReachabilityReadError::Unavailable => ReachabilityError::Unavailable,
        ExactReachabilityReadError::TooLarge => ReachabilityError::Limit,
        ExactReachabilityReadError::Protocol => ReachabilityError::Authentication,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{
            resolve_archive_cipher, ArchiveDek, ExactKeyRegistryProvider, ExtentReference,
            KeyEpoch, KeyRegistryPlaintext,
        },
        archive_v3_journal::{CheckpointChunkEntry, WalSegment},
        archive_v3_witness::{
            ExactRootProvider, InMemoryWitness, MigrationState, RootAdvance, RootReference,
            Witness, WitnessBootstrap, WitnessError,
        },
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use tokio::sync::Notify;

    const WAL_HEADER_BYTES: usize = 32;
    const WAL_FRAME_HEADER_BYTES: usize = 24;

    struct RegistryProvider {
        wrapped: Vec<u8>,
        plaintext: Vec<u8>,
    }

    #[async_trait]
    impl ExactKeyRegistryProvider for RegistryProvider {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            _object_id: ObjectId,
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            destination[..self.wrapped.len()].copy_from_slice(&self.wrapped);
            Ok(self.wrapped.len())
        }

        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            _wrapped_registry_ciphertext: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }

    #[derive(Clone, Copy)]
    enum ReadFault {
        None,
        CancelOnce,
        Missing,
        Oversized,
        Tamper,
    }

    struct FakeReader {
        objects: Mutex<BTreeMap<ObjectKey, Vec<u8>>>,
        calls: Mutex<Vec<ObjectKey>>,
        fault: Mutex<ReadFault>,
        key_faults: Mutex<BTreeMap<ObjectKey, ReadFault>>,
    }

    impl FakeReader {
        fn new() -> Self {
            Self {
                objects: Mutex::new(BTreeMap::new()),
                calls: Mutex::new(Vec::new()),
                fault: Mutex::new(ReadFault::None),
                key_faults: Mutex::new(BTreeMap::new()),
            }
        }

        fn insert(&self, context: &ObjectContext, envelope: &CiphertextEnvelope) {
            self.objects
                .lock()
                .unwrap()
                .insert(context.object_key(), envelope.encode());
        }

        fn calls(&self) -> Vec<ObjectKey> {
            self.calls.lock().unwrap().clone()
        }

        fn set_fault(&self, fault: ReadFault) {
            *self.fault.lock().unwrap() = fault;
        }

        fn set_key_fault(&self, key: ObjectKey, fault: ReadFault) {
            self.key_faults.lock().unwrap().insert(key, fault);
        }

        fn call_count(&self, key: &ObjectKey) -> usize {
            self.calls()
                .iter()
                .filter(|candidate| *candidate == key)
                .count()
        }

        fn swap_encoded(&self, left: &ObjectKey, right: &ObjectKey) {
            let mut objects = self.objects.lock().unwrap();
            let left_value = objects.get(left).unwrap().clone();
            let right_value = objects.get(right).unwrap().clone();
            objects.insert(left.clone(), right_value);
            objects.insert(right.clone(), left_value);
        }
    }

    #[async_trait]
    impl ExactReachabilityReader for FakeReader {
        async fn read_exact(
            &self,
            key: &ObjectKey,
            max_encoded_bytes: usize,
        ) -> std::result::Result<Option<Vec<u8>>, ExactReachabilityReadError> {
            self.calls.lock().unwrap().push(key.clone());
            let fault = self
                .key_faults
                .lock()
                .unwrap()
                .get(key)
                .copied()
                .unwrap_or_else(|| *self.fault.lock().unwrap());
            match fault {
                ReadFault::CancelOnce => {
                    *self.fault.lock().unwrap() = ReadFault::None;
                    return Err(ExactReachabilityReadError::Cancelled);
                }
                ReadFault::Missing => return Ok(None),
                ReadFault::Oversized => return Ok(Some(vec![0; max_encoded_bytes + 1])),
                ReadFault::None | ReadFault::Tamper => {}
            }
            let mut value = self.objects.lock().unwrap().get(key).cloned();
            if matches!(fault, ReadFault::Tamper) {
                if let Some(value) = &mut value {
                    if let Some(last) = value.last_mut() {
                        *last ^= 1;
                    }
                }
            }
            Ok(value)
        }
    }

    struct StallingReader {
        inner: Arc<FakeReader>,
        stall_once: AtomicBool,
        stall_key: Option<ObjectKey>,
        entered: Notify,
        release: Notify,
    }

    #[async_trait]
    impl ExactReachabilityReader for StallingReader {
        async fn read_exact(
            &self,
            key: &ObjectKey,
            max_encoded_bytes: usize,
        ) -> std::result::Result<Option<Vec<u8>>, ExactReachabilityReadError> {
            if self
                .stall_key
                .as_ref()
                .is_none_or(|stall_key| stall_key == key)
                && self.stall_once.swap(false, Ordering::SeqCst)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.inner.read_exact(key, max_encoded_bytes).await
        }
    }

    struct Fixture {
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        registry: KeyRegistryReference,
        cipher: VerifiedArchiveCipher,
        reader: Arc<FakeReader>,
        recovery: RecoveryRoot,
        chunk_key: ObjectKey,
        extent_key: ObjectKey,
    }

    async fn resolved_cipher(
        archive_id: ArchiveId,
        key_epoch: KeyEpoch,
        registry_object_id: ObjectId,
        rotation: u64,
    ) -> (KeyRegistryReference, VerifiedArchiveCipher) {
        let context = KeyRegistryContext::with_rotation_generation(
            archive_id,
            KeyKind::Archive,
            key_epoch,
            rotation,
        );
        let wrapped = vec![0x91, 0x92, rotation as u8, 0x94];
        let wrapped_hash = Sha256::digest(&wrapped).into();
        let plaintext =
            KeyRegistryPlaintext::encode_archive(&context, &ArchiveDek::from_bytes([0x44; 32]))
                .unwrap()
                .to_vec();
        let provider = RegistryProvider { wrapped, plaintext };
        let cipher = resolve_archive_cipher(&context, registry_object_id, wrapped_hash, &provider)
            .await
            .unwrap();
        (
            KeyRegistryReference::new(key_epoch, rotation, registry_object_id, wrapped_hash),
            cipher,
        )
    }

    async fn checkpoint_extent_fixture(shared_leaf_id: bool) -> Fixture {
        let archive_id = ArchiveId::from_bytes([1; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([2; 16]);
        let key_epoch = KeyEpoch::from_bytes([3; 16]);
        let (registry, cipher) =
            resolved_cipher(archive_id, key_epoch, ObjectId::from_bytes([4; 16]), 0).await;
        let reader = Arc::new(FakeReader::new());

        let checkpoint_id = ObjectId::from_bytes([5; 16]);
        let chunk_object_id = ObjectId::from_bytes([6; 16]);
        let chunk_reference = ImmutableReference {
            object_id: chunk_object_id,
            envelope_hash: [0x61; 32],
        };
        let manifest = CheckpointManifestNode {
            checkpoint_id,
            level: 0,
            range_start: 0,
            range_end: 1,
            total_chunks: 1,
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            sqlite_page_size: SQLITE_PAGE_SIZE,
            database_plaintext_hash: [0x62; 32],
            entries: CheckpointManifestEntries::Chunks(vec![CheckpointChunkEntry {
                chunk_index: 0,
                logical_offset: 0,
                logical_byte_len: SQLITE_PAGE_SIZE,
                plaintext_hash: [0x63; 32],
                reference: chunk_reference.clone(),
            }]),
        };
        let manifest_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::CheckpointManifestV3,
            LogicalLocation::CheckpointManifest {
                checkpoint_id,
                level: 0,
                range_start: 0,
                range_end: 1,
            },
            checkpoint_id,
            None,
        )
        .unwrap();
        let manifest_envelope = cipher
            .seal(&manifest_context, &manifest.encode().unwrap())
            .unwrap();
        reader.insert(&manifest_context, &manifest_envelope);
        let checkpoint_reference = ImmutableReference {
            object_id: checkpoint_id,
            envelope_hash: manifest_envelope.hash(),
        };

        let extent_object_id = if shared_leaf_id {
            chunk_object_id
        } else {
            ObjectId::from_bytes([7; 16])
        };
        let extent_reference = ImmutableReference {
            object_id: extent_object_id,
            envelope_hash: [0x71; 32],
        };
        let extent_node = MerkleNode {
            level: 0,
            range_start: 0,
            range_end: 1,
            entries: MerkleEntries::Leaf(vec![ExtentReference {
                extent_no: 0,
                logical_byte_len: SQLITE_PAGE_SIZE,
                revision: 1,
                reference: extent_reference.clone(),
            }]),
        };
        let node_id = ObjectId::from_bytes([8; 16]);
        let node_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::MerkleNodeV3,
            LogicalLocation::MerkleNode {
                level: 0,
                range_start: 0,
                range_end: 1,
            },
            node_id,
            None,
        )
        .unwrap();
        let node_envelope = cipher
            .seal(&node_context, &extent_node.encode().unwrap())
            .unwrap();
        reader.insert(&node_context, &node_envelope);
        let extent_root = ImmutableReference {
            object_id: node_id,
            envelope_hash: node_envelope.hash(),
        };

        let root_id = ObjectId::from_bytes([9; 16]);
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: Some(checkpoint_reference),
            extent_tree_root: Some(extent_root),
            wal_commit_tail: None,
        };
        let root_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_id,
            None,
        )
        .unwrap();
        let root_envelope = cipher.seal(&root_context, &root.encode().unwrap()).unwrap();
        reader.insert(&root_context, &root_envelope);
        let commitment = RootCommitment::genesis(
            database_epoch,
            key_epoch,
            RootReference::new(0, root_id, root_envelope.hash()),
        );
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                commitment,
                registry,
            ))
            .unwrap();
        let recovery = witness.recovery_root(archive_id).unwrap();
        let chunk_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::CheckpointChunkV3,
            LogicalLocation::CheckpointChunk {
                checkpoint_id,
                chunk_index: 0,
                logical_offset: 0,
                byte_len: SQLITE_PAGE_SIZE,
            },
            chunk_object_id,
            None,
        )
        .unwrap();
        let extent_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 0,
                byte_len: SQLITE_PAGE_SIZE,
            },
            extent_object_id,
            None,
        )
        .unwrap();
        Fixture {
            archive_id,
            database_epoch,
            key_epoch,
            registry,
            cipher,
            reader,
            recovery,
            chunk_key: chunk_context.object_key(),
            extent_key: extent_context.object_key(),
        }
    }

    fn object_id(value: u32) -> ObjectId {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xa5;
        bytes[12..].copy_from_slice(&value.to_be_bytes());
        ObjectId::from_bytes(bytes)
    }

    fn reference(value: u32) -> ImmutableReference {
        let mut hasher = Sha256::new();
        hasher.update(b"reachability-test-reference");
        hasher.update(value.to_be_bytes());
        ImmutableReference {
            object_id: object_id(value),
            envelope_hash: hasher.finalize().into(),
        }
    }

    #[tokio::test]
    async fn authenticates_internal_manifest_and_sparse_extent_topologies() {
        let archive_id = ArchiveId::from_bytes([0x11; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([0x12; 16]);
        let key_epoch = KeyEpoch::from_bytes([0x13; 16]);
        let (registry, cipher) = resolved_cipher(archive_id, key_epoch, object_id(1), 0).await;
        let reader = Arc::new(FakeReader::new());
        let logical_length = 257 * u64::from(CHECKPOINT_CHUNK_BYTES);
        let checkpoint_id = object_id(10);
        let descriptor_hash = [0x17; 32];

        let mut chunk_entries = Vec::with_capacity(257);
        for chunk_index in 0..257u32 {
            chunk_entries.push(CheckpointChunkEntry {
                chunk_index,
                logical_offset: u64::from(chunk_index) * u64::from(CHECKPOINT_CHUNK_BYTES),
                logical_byte_len: CHECKPOINT_CHUNK_BYTES,
                plaintext_hash: [0x21; 32],
                reference: reference(1_000 + chunk_index),
            });
        }
        let leaf_specs = [(0u32, 256u32, object_id(11)), (256, 257, object_id(12))];
        let mut manifest_children = Vec::new();
        for (start, end, node_id) in leaf_specs {
            let node = CheckpointManifestNode {
                checkpoint_id,
                level: 0,
                range_start: start,
                range_end: end,
                total_chunks: 257,
                logical_file_length: logical_length,
                sqlite_page_size: SQLITE_PAGE_SIZE,
                database_plaintext_hash: descriptor_hash,
                entries: CheckpointManifestEntries::Chunks(
                    chunk_entries[start as usize..end as usize].to_vec(),
                ),
            };
            let context = ObjectContext::new(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectRole::CheckpointManifestV3,
                LogicalLocation::CheckpointManifest {
                    checkpoint_id,
                    level: 0,
                    range_start: start,
                    range_end: end,
                },
                node_id,
                None,
            )
            .unwrap();
            let envelope = cipher.seal(&context, &node.encode().unwrap()).unwrap();
            reader.insert(&context, &envelope);
            manifest_children.push(crate::archive_v3_journal::CheckpointManifestChild {
                range_start: start,
                range_end: end,
                reference: ImmutableReference {
                    object_id: node_id,
                    envelope_hash: envelope.hash(),
                },
            });
        }
        let manifest_root = CheckpointManifestNode {
            checkpoint_id,
            level: 1,
            range_start: 0,
            range_end: 257,
            total_chunks: 257,
            logical_file_length: logical_length,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            database_plaintext_hash: descriptor_hash,
            entries: CheckpointManifestEntries::Children(manifest_children),
        };
        let manifest_root_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::CheckpointManifestV3,
            LogicalLocation::CheckpointManifest {
                checkpoint_id,
                level: 1,
                range_start: 0,
                range_end: 257,
            },
            checkpoint_id,
            None,
        )
        .unwrap();
        let manifest_root_envelope = cipher
            .seal(&manifest_root_context, &manifest_root.encode().unwrap())
            .unwrap();
        reader.insert(&manifest_root_context, &manifest_root_envelope);

        let extent_specs = [(0u64, 1u64, object_id(21)), (256, 257, object_id(22))];
        let mut extent_children = Vec::new();
        for (start, end, node_id) in extent_specs {
            let node = MerkleNode {
                level: 0,
                range_start: start,
                range_end: end,
                entries: MerkleEntries::Leaf(vec![ExtentReference {
                    extent_no: start,
                    logical_byte_len: EXTENT_BYTES,
                    revision: 1,
                    reference: reference(2_000 + start as u32),
                }]),
            };
            let context = ObjectContext::new(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectRole::MerkleNodeV3,
                LogicalLocation::MerkleNode {
                    level: 0,
                    range_start: start,
                    range_end: end,
                },
                node_id,
                None,
            )
            .unwrap();
            let envelope = cipher.seal(&context, &node.encode().unwrap()).unwrap();
            reader.insert(&context, &envelope);
            extent_children.push(crate::archive_v3::MerkleChild {
                range_start: start,
                range_end: end,
                reference: ImmutableReference {
                    object_id: node_id,
                    envelope_hash: envelope.hash(),
                },
            });
        }
        let extent_root_id = object_id(20);
        let extent_root = MerkleNode {
            level: 1,
            range_start: 0,
            range_end: 257,
            entries: MerkleEntries::Internal(extent_children),
        };
        let extent_root_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::MerkleNodeV3,
            LogicalLocation::MerkleNode {
                level: 1,
                range_start: 0,
                range_end: 257,
            },
            extent_root_id,
            None,
        )
        .unwrap();
        let extent_root_envelope = cipher
            .seal(&extent_root_context, &extent_root.encode().unwrap())
            .unwrap();
        reader.insert(&extent_root_context, &extent_root_envelope);

        let root_id = object_id(30);
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: logical_length,
            logical_file_length: logical_length,
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: Some(ImmutableReference {
                object_id: checkpoint_id,
                envelope_hash: manifest_root_envelope.hash(),
            }),
            extent_tree_root: Some(ImmutableReference {
                object_id: extent_root_id,
                envelope_hash: extent_root_envelope.hash(),
            }),
            wal_commit_tail: None,
        };
        let root_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_id,
            None,
        )
        .unwrap();
        let root_envelope = cipher.seal(&root_context, &root.encode().unwrap()).unwrap();
        reader.insert(&root_context, &root_envelope);
        let commitment = RootCommitment::genesis(
            database_epoch,
            key_epoch,
            RootReference::new(0, root_id, root_envelope.hash()),
        );
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                commitment,
                registry,
            ))
            .unwrap();
        let visit = visit_witness_reachability(
            &witness.recovery_root(archive_id).unwrap(),
            reader.as_ref(),
            &cipher,
            None,
        )
        .await
        .unwrap();
        assert_eq!(visit.exact_get_count(), 7);
        assert_eq!(visit.objects().len(), 267);
        assert_eq!(reader.calls().len(), 7);

        let child_manifest_keys = reader
            .objects
            .lock()
            .unwrap()
            .keys()
            .filter(|key| key.as_str().contains("/manifest/0-"))
            .cloned()
            .collect::<Vec<_>>();
        let child_extent_keys = reader
            .objects
            .lock()
            .unwrap()
            .keys()
            .filter(|key| key.as_str().contains("/nodes/") && key.as_str().contains("/0/"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(child_manifest_keys.len(), 2);
        assert_eq!(child_extent_keys.len(), 2);
        for (key, fault, expected) in [
            (
                child_manifest_keys[1].clone(),
                ReadFault::Missing,
                ReachabilityError::Missing,
            ),
            (
                child_extent_keys[1].clone(),
                ReadFault::Tamper,
                ReachabilityError::Authentication,
            ),
        ] {
            reader.set_key_fault(key.clone(), fault);
            assert_eq!(
                visit_witness_reachability(
                    &witness.recovery_root(archive_id).unwrap(),
                    reader.as_ref(),
                    &cipher,
                    None,
                )
                .await
                .unwrap_err(),
                expected
            );
            reader.set_key_fault(key, ReadFault::None);
        }
        reader.swap_encoded(&child_manifest_keys[0], &child_manifest_keys[1]);
        assert_eq!(
            visit_witness_reachability(
                &witness.recovery_root(archive_id).unwrap(),
                reader.as_ref(),
                &cipher,
                None,
            )
            .await
            .unwrap_err(),
            ReachabilityError::Authentication
        );
        reader.swap_encoded(&child_manifest_keys[0], &child_manifest_keys[1]);
        reader.swap_encoded(&child_extent_keys[0], &child_extent_keys[1]);
        assert_eq!(
            visit_witness_reachability(
                &witness.recovery_root(archive_id).unwrap(),
                reader.as_ref(),
                &cipher,
                None,
            )
            .await
            .unwrap_err(),
            ReachabilityError::Authentication
        );
        reader.swap_encoded(&child_extent_keys[0], &child_extent_keys[1]);
    }

    #[tokio::test]
    async fn authenticates_checkpoint_and_extent_graph_without_fetching_leaf_content() {
        let fixture = checkpoint_extent_fixture(false).await;
        let visit = visit_witness_reachability(
            &fixture.recovery,
            fixture.reader.as_ref(),
            &fixture.cipher,
            None,
        )
        .await
        .unwrap();
        assert_eq!(visit.graph_count(), 1);
        assert_eq!(visit.exact_get_count(), 3);
        assert_eq!(visit.objects().len(), 6);
        assert!(visit.authenticated_metadata_bytes() > 0);
        assert!(!fixture.reader.calls().contains(&fixture.chunk_key));
        assert!(!fixture.reader.calls().contains(&fixture.extent_key));
        assert!(visit
            .objects()
            .iter()
            .any(|object| object.key() == &fixture.chunk_key && !object.was_fetched()));
        assert!(visit
            .objects()
            .iter()
            .any(|object| object.key() == &fixture.extent_key && !object.was_fetched()));
        assert_eq!(
            format!("{visit:?}"),
            "AuthenticatedReachabilityVisit(<opaque, non-authorizing>)"
        );
    }

    #[tokio::test]
    async fn cancelled_exact_get_restarts_from_the_same_witness_graph() {
        let fixture = checkpoint_extent_fixture(false).await;
        fixture.reader.set_fault(ReadFault::CancelOnce);
        assert_eq!(
            visit_witness_reachability(
                &fixture.recovery,
                fixture.reader.as_ref(),
                &fixture.cipher,
                None,
            )
            .await
            .unwrap_err(),
            ReachabilityError::Cancelled
        );
        let visit = visit_witness_reachability(
            &fixture.recovery,
            fixture.reader.as_ref(),
            &fixture.cipher,
            None,
        )
        .await
        .unwrap();
        assert_eq!(visit.exact_get_count(), 3);
        assert_eq!(visit.objects().len(), 6);
    }

    #[tokio::test]
    async fn dropped_stalled_get_leaves_no_progress_and_exact_retry_succeeds() {
        let fixture = Arc::new(checkpoint_extent_fixture(false).await);
        let reader = Arc::new(StallingReader {
            inner: fixture.reader.clone(),
            stall_once: AtomicBool::new(true),
            stall_key: None,
            entered: Notify::new(),
            release: Notify::new(),
        });
        let task = {
            let fixture = fixture.clone();
            let reader = reader.clone();
            tokio::spawn(async move {
                visit_witness_reachability(
                    &fixture.recovery,
                    reader.as_ref(),
                    &fixture.cipher,
                    None,
                )
                .await
            })
        };
        reader.entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        reader.release.notify_waiters();

        let visit =
            visit_witness_reachability(&fixture.recovery, reader.as_ref(), &fixture.cipher, None)
                .await
                .unwrap();
        assert_eq!(visit.exact_get_count(), 3);
        assert_eq!(visit.objects().len(), 6);
    }

    #[tokio::test]
    async fn missing_oversized_and_tampered_exact_reads_fail_closed() {
        for (fault, expected) in [
            (ReadFault::Missing, ReachabilityError::Missing),
            (ReadFault::Oversized, ReachabilityError::Limit),
            (ReadFault::Tamper, ReachabilityError::Authentication),
        ] {
            let fixture = checkpoint_extent_fixture(false).await;
            fixture.reader.set_fault(fault);
            assert_eq!(
                visit_witness_reachability(
                    &fixture.recovery,
                    fixture.reader.as_ref(),
                    &fixture.cipher,
                    None,
                )
                .await
                .unwrap_err(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn deep_manifest_and_extent_reads_fail_closed_without_descendant_io() {
        for (path_fragment, fault, expected) in [
            ("/manifest/", ReadFault::Missing, ReachabilityError::Missing),
            (
                "/manifest/",
                ReadFault::Tamper,
                ReachabilityError::Authentication,
            ),
            ("/nodes/", ReadFault::Missing, ReachabilityError::Missing),
            (
                "/nodes/",
                ReadFault::Tamper,
                ReachabilityError::Authentication,
            ),
        ] {
            let fixture = checkpoint_extent_fixture(false).await;
            let key = fixture
                .reader
                .objects
                .lock()
                .unwrap()
                .keys()
                .find(|key| key.as_str().contains(path_fragment))
                .cloned()
                .unwrap();
            fixture.reader.set_key_fault(key.clone(), fault);
            assert_eq!(
                visit_witness_reachability(
                    &fixture.recovery,
                    fixture.reader.as_ref(),
                    &fixture.cipher,
                    None,
                )
                .await
                .unwrap_err(),
                expected
            );
            assert_eq!(fixture.reader.call_count(&key), 1);
            assert!(!fixture.reader.calls().contains(&fixture.chunk_key));
            assert!(!fixture.reader.calls().contains(&fixture.extent_key));
        }
    }

    #[tokio::test]
    async fn reordered_internal_metadata_is_rejected_at_its_exact_name() {
        let fixture = checkpoint_extent_fixture(false).await;
        let keys = fixture
            .reader
            .objects
            .lock()
            .unwrap()
            .keys()
            .filter(|key| key.as_str().contains("/manifest/") || key.as_str().contains("/nodes/"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 2);
        fixture.reader.swap_encoded(&keys[0], &keys[1]);
        assert_eq!(
            visit_witness_reachability(
                &fixture.recovery,
                fixture.reader.as_ref(),
                &fixture.cipher,
                None,
            )
            .await
            .unwrap_err(),
            ReachabilityError::Authentication
        );
    }

    #[tokio::test]
    async fn conflicting_duplicate_object_id_is_rejected_without_leaf_get() {
        let fixture = checkpoint_extent_fixture(true).await;
        assert_eq!(
            visit_witness_reachability(
                &fixture.recovery,
                fixture.reader.as_ref(),
                &fixture.cipher,
                None,
            )
            .await
            .unwrap_err(),
            ReachabilityError::DuplicateOrCycle
        );
        assert!(!fixture.reader.calls().contains(&fixture.chunk_key));
        assert!(!fixture.reader.calls().contains(&fixture.extent_key));
    }

    #[tokio::test]
    async fn wrong_registry_bound_cipher_rejects_before_object_io() {
        let fixture = checkpoint_extent_fixture(false).await;
        let (_other_registry, other_cipher) = resolved_cipher(
            fixture.archive_id,
            fixture.key_epoch,
            ObjectId::from_bytes([99; 16]),
            1,
        )
        .await;
        assert_eq!(
            visit_witness_reachability(
                &fixture.recovery,
                fixture.reader.as_ref(),
                &other_cipher,
                None,
            )
            .await
            .unwrap_err(),
            ReachabilityError::InvalidSnapshot
        );
        assert!(fixture.reader.calls().is_empty());
    }

    #[tokio::test]
    async fn zero_identifier_and_hash_snapshot_matrix_rejects_before_io() {
        let fixture = checkpoint_extent_fixture(false).await;
        let valid_root = fixture.recovery.root().root();
        let valid_registry = fixture.registry;
        let cases = [
            (
                RootCommitment::genesis(
                    DatabaseEpoch::from_bytes([0; 16]),
                    fixture.key_epoch,
                    valid_root,
                ),
                valid_registry,
            ),
            (
                RootCommitment::genesis(
                    fixture.database_epoch,
                    KeyEpoch::from_bytes([0; 16]),
                    valid_root,
                ),
                valid_registry,
            ),
            (
                RootCommitment::genesis(
                    fixture.database_epoch,
                    fixture.key_epoch,
                    RootReference::new(0, ObjectId::from_bytes([0; 16]), [1; 32]),
                ),
                valid_registry,
            ),
            (
                RootCommitment::genesis(
                    fixture.database_epoch,
                    fixture.key_epoch,
                    RootReference::new(0, ObjectId::from_bytes([1; 16]), [0; 32]),
                ),
                valid_registry,
            ),
            (
                fixture.recovery.root(),
                KeyRegistryReference::new(
                    fixture.key_epoch,
                    0,
                    ObjectId::from_bytes([0; 16]),
                    [1; 32],
                ),
            ),
            (
                fixture.recovery.root(),
                KeyRegistryReference::new(
                    fixture.key_epoch,
                    0,
                    ObjectId::from_bytes([1; 16]),
                    [0; 32],
                ),
            ),
        ];
        for (root, registry) in cases {
            assert_eq!(
                validate_graph_binding(
                    fixture.archive_id,
                    &GraphBinding {
                        root,
                        registry,
                        cipher: &fixture.cipher,
                        witnessed_predecessor: None,
                    },
                ),
                Err(ReachabilityError::InvalidSnapshot)
            );
        }
        let graph = GraphBinding {
            root: fixture.recovery.root(),
            registry: fixture.registry,
            cipher: &fixture.cipher,
            witnessed_predecessor: None,
        };
        let mut tracker = VisitTracker::new(fixture.archive_id);
        for reference in [
            ParentReference {
                object_id: ObjectId::from_bytes([0; 16]),
                envelope_hash: [1; 32],
            },
            ParentReference {
                object_id: ObjectId::from_bytes([1; 16]),
                envelope_hash: [0; 32],
            },
        ] {
            assert_eq!(
                register_historical_root(&mut tracker, &graph, 0, &reference),
                Err(ReachabilityError::Authentication)
            );
        }
        let leaf_context = ObjectContext::new(
            fixture.archive_id,
            fixture.database_epoch,
            fixture.key_epoch,
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 0,
                byte_len: SQLITE_PAGE_SIZE,
            },
            ObjectId::from_bytes([0x41; 16]),
            None,
        )
        .unwrap();
        for reference in [
            ImmutableReference {
                object_id: ObjectId::from_bytes([0; 16]),
                envelope_hash: [0x42; 32],
            },
            ImmutableReference {
                object_id: leaf_context.object_id(),
                envelope_hash: [0; 32],
            },
        ] {
            assert!(matches!(
                identity_for_context(&leaf_context, &reference),
                Err(ReachabilityError::Authentication)
            ));
        }
        assert!(fixture.reader.calls().is_empty());
    }

    #[test]
    fn zero_checkpoint_identifier_and_hash_matrix_fails_closed() {
        let valid = CheckpointManifestNode {
            checkpoint_id: object_id(10),
            level: 0,
            range_start: 0,
            range_end: 1,
            total_chunks: 1,
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            sqlite_page_size: SQLITE_PAGE_SIZE,
            database_plaintext_hash: [0x11; 32],
            entries: CheckpointManifestEntries::Chunks(vec![CheckpointChunkEntry {
                chunk_index: 0,
                logical_offset: 0,
                logical_byte_len: SQLITE_PAGE_SIZE,
                plaintext_hash: [0x12; 32],
                reference: reference(11),
            }]),
        };
        assert_eq!(validate_checkpoint_hashes(&valid), Ok(()));
        let mut cases = Vec::new();
        let mut zero_checkpoint = valid.clone();
        zero_checkpoint.checkpoint_id = ObjectId::from_bytes([0; 16]);
        cases.push(zero_checkpoint);
        let mut zero_database_hash = valid.clone();
        zero_database_hash.database_plaintext_hash = [0; 32];
        cases.push(zero_database_hash);
        let mut zero_chunk_hash = valid.clone();
        if let CheckpointManifestEntries::Chunks(chunks) = &mut zero_chunk_hash.entries {
            chunks[0].plaintext_hash = [0; 32];
        }
        cases.push(zero_chunk_hash);
        let mut zero_object = valid.clone();
        if let CheckpointManifestEntries::Chunks(chunks) = &mut zero_object.entries {
            chunks[0].reference.object_id = ObjectId::from_bytes([0; 16]);
        }
        cases.push(zero_object);
        let mut zero_envelope = valid;
        if let CheckpointManifestEntries::Chunks(chunks) = &mut zero_envelope.entries {
            chunks[0].reference.envelope_hash = [0; 32];
        }
        cases.push(zero_envelope);
        for node in cases {
            assert_eq!(
                validate_checkpoint_hashes(&node),
                Err(ReachabilityError::Authentication)
            );
        }
    }

    struct OneRootProvider(CiphertextEnvelope);

    #[async_trait]
    impl ExactRootProvider for OneRootProvider {
        async fn read_exact(
            &self,
            _context: &ObjectContext,
        ) -> std::result::Result<CiphertextEnvelope, WitnessError> {
            Ok(self.0.clone())
        }
    }

    struct SealedRoot {
        commitment: RootCommitment,
        context: ObjectContext,
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_simple_root(
        reader: &FakeReader,
        cipher: &VerifiedArchiveCipher,
        registry: KeyRegistryReference,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        sequence: u64,
        parent: Option<RootReference>,
        owner_fencing_epoch: u64,
        root_id: ObjectId,
    ) -> SealedRoot {
        let parent = parent.map(|parent| ParentReference {
            object_id: parent.object_id(),
            envelope_hash: parent.ciphertext_hash(),
        });
        let root = ArchiveRoot {
            root_seq: sequence,
            parent: parent.clone(),
            database_epoch,
            key_epoch,
            owner_fencing_epoch,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: 0,
            logical_file_length: 0,
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: sequence },
            root_id,
            parent,
        )
        .unwrap();
        let envelope = cipher.seal(&context, &root.encode().unwrap()).unwrap();
        reader.insert(&context, &envelope);
        let commitment = RootCommitment::from_authenticated_provider_object(
            archive_id,
            registry,
            &context,
            &OneRootProvider(envelope),
            cipher,
        )
        .await
        .unwrap();
        SealedRoot {
            commitment,
            context,
        }
    }

    fn next_database_epoch_for_test(
        archive_id: ArchiveId,
        commitment: RootCommitment,
    ) -> DatabaseEpoch {
        fn push_root(out: &mut Vec<u8>, root: RootReference) {
            out.extend_from_slice(&root.sequence().to_be_bytes());
            out.extend_from_slice(root.object_id().as_bytes());
            out.extend_from_slice(&root.ciphertext_hash());
        }
        let mut encoded = Vec::with_capacity(153);
        push_root(&mut encoded, commitment.root());
        encoded.extend_from_slice(commitment.database_epoch().as_bytes());
        encoded.extend_from_slice(commitment.key_epoch().as_bytes());
        encoded.extend_from_slice(&commitment.owner_fencing_epoch().to_be_bytes());
        match commitment.parent() {
            Some(parent) => {
                encoded.push(1);
                push_root(&mut encoded, parent);
            }
            None => {
                encoded.push(0);
                encoded.extend_from_slice(&[0; 56]);
            }
        }
        assert_eq!(encoded.len(), 153);
        let mut hasher = Sha256::new();
        hasher.update(b"kioku:archive:v3:database-epoch\0");
        hasher.update(archive_id.as_bytes());
        hasher.update(commitment.database_epoch().as_bytes());
        hasher.update(1u64.to_be_bytes());
        hasher.update(encoded);
        let digest = hasher.finalize();
        let mut epoch = [0; 16];
        epoch.copy_from_slice(&digest[..16]);
        DatabaseEpoch::from_bytes(epoch)
    }

    #[tokio::test]
    async fn two_graphs_prevalidate_and_fetch_witnessed_predecessor_once_in_its_epoch() {
        let archive_id = ArchiveId::from_bytes([0x81; 16]);
        let predecessor_database_epoch = DatabaseEpoch::from_bytes([0x82; 16]);
        let predecessor_key_epoch = KeyEpoch::from_bytes([0x83; 16]);
        let current_database_epoch = DatabaseEpoch::from_bytes([0x84; 16]);
        let current_key_epoch = KeyEpoch::from_bytes([0x85; 16]);
        let (predecessor_registry, predecessor_cipher) = resolved_cipher(
            archive_id,
            predecessor_key_epoch,
            ObjectId::from_bytes([0x86; 16]),
            0,
        )
        .await;
        let (current_registry, current_cipher) = resolved_cipher(
            archive_id,
            current_key_epoch,
            ObjectId::from_bytes([0x87; 16]),
            1,
        )
        .await;
        let reader = FakeReader::new();
        let root_zero = RootReference::new(0, ObjectId::from_bytes([0x88; 16]), [0x89; 32]);
        let predecessor = insert_simple_root(
            &reader,
            &predecessor_cipher,
            predecessor_registry,
            archive_id,
            predecessor_database_epoch,
            predecessor_key_epoch,
            1,
            Some(root_zero),
            7,
            ObjectId::from_bytes([0x8a; 16]),
        )
        .await;
        let current = insert_simple_root(
            &reader,
            &current_cipher,
            current_registry,
            archive_id,
            current_database_epoch,
            current_key_epoch,
            2,
            Some(predecessor.commitment.root()),
            8,
            ObjectId::from_bytes([0x8b; 16]),
        )
        .await;

        let (_wrong_registry, wrong_predecessor_cipher) = resolved_cipher(
            archive_id,
            predecessor_key_epoch,
            ObjectId::from_bytes([0x8c; 16]),
            2,
        )
        .await;
        let invalid = vec![
            GraphBinding {
                root: current.commitment,
                registry: current_registry,
                cipher: &current_cipher,
                witnessed_predecessor: Some(predecessor.commitment),
            },
            GraphBinding {
                root: predecessor.commitment,
                registry: predecessor_registry,
                cipher: &wrong_predecessor_cipher,
                witnessed_predecessor: None,
            },
        ];
        assert_eq!(
            visit_graph_bindings(archive_id, &reader, invalid)
                .await
                .unwrap_err(),
            ReachabilityError::InvalidSnapshot
        );
        assert!(reader.calls().is_empty());
        let over_limit = (0..=MAX_ROOT_GRAPHS)
            .map(|_| GraphBinding {
                root: current.commitment,
                registry: current_registry,
                cipher: &current_cipher,
                witnessed_predecessor: Some(predecessor.commitment),
            })
            .collect();
        assert_eq!(
            visit_graph_bindings(archive_id, &reader, over_limit)
                .await
                .unwrap_err(),
            ReachabilityError::InvalidSnapshot
        );
        assert!(reader.calls().is_empty());

        let visit = visit_graph_bindings(
            archive_id,
            &reader,
            vec![
                GraphBinding {
                    root: current.commitment,
                    registry: current_registry,
                    cipher: &current_cipher,
                    witnessed_predecessor: Some(predecessor.commitment),
                },
                GraphBinding {
                    root: predecessor.commitment,
                    registry: predecessor_registry,
                    cipher: &predecessor_cipher,
                    witnessed_predecessor: None,
                },
            ],
        )
        .await
        .unwrap();
        let predecessor_key = predecessor.context.object_key();
        let old_root_zero_key = ObjectContext::new(
            archive_id,
            predecessor_database_epoch,
            predecessor_key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_zero.object_id(),
            None,
        )
        .unwrap()
        .object_key();
        assert_eq!(visit.graph_count(), 2);
        assert_eq!(reader.call_count(&current.context.object_key()), 1);
        assert_eq!(reader.call_count(&predecessor_key), 1);
        assert!(visit.objects().iter().any(|object| {
            object.key() == &predecessor_key
                && object.role() == ObjectRole::RootV3
                && object.was_fetched()
        }));
        assert!(visit.objects().iter().any(|object| {
            object.key() == &old_root_zero_key
                && object.role() == ObjectRole::RootV3
                && !object.was_fetched()
        }));
        assert!(!reader.calls().contains(&old_root_zero_key));
    }

    #[tokio::test]
    async fn witness_cutover_recovery_visits_current_and_predecessor_end_to_end() {
        let archive_id = ArchiveId::from_bytes([0xb1; 16]);
        let old_database_epoch = DatabaseEpoch::from_bytes([0xb2; 16]);
        let key_epoch = KeyEpoch::from_bytes([0xb3; 16]);
        let (registry, cipher) =
            resolved_cipher(archive_id, key_epoch, ObjectId::from_bytes([0xb4; 16]), 0).await;
        let reader = FakeReader::new();
        let genesis = insert_simple_root(
            &reader,
            &cipher,
            registry,
            archive_id,
            old_database_epoch,
            key_epoch,
            0,
            None,
            0,
            ObjectId::from_bytes([0xb5; 16]),
        )
        .await;
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                old_database_epoch,
                genesis.commitment,
                registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive_id,
                old_database_epoch,
                key_epoch,
                ObjectId::from_bytes([0xb6; 16]),
                100,
            )
            .unwrap();
        let shadow = insert_simple_root(
            &reader,
            &cipher,
            registry,
            archive_id,
            old_database_epoch,
            key_epoch,
            1,
            Some(genesis.commitment.root()),
            lease.fencing_epoch(),
            ObjectId::from_bytes([0xb7; 16]),
        )
        .await;
        let shadow_receipt = witness
            .advance_migration(
                RootAdvance::new(lease, genesis.commitment, registry, shadow.commitment),
                MigrationState::ShadowExtents,
            )
            .unwrap();
        let predecessor = insert_simple_root(
            &reader,
            &cipher,
            registry,
            archive_id,
            old_database_epoch,
            key_epoch,
            2,
            Some(shadow.commitment.root()),
            lease.fencing_epoch(),
            ObjectId::from_bytes([0xb8; 16]),
        )
        .await;
        let predecessor_receipt = witness
            .advance_migration(
                RootAdvance::new(
                    lease,
                    shadow_receipt.record().root(),
                    registry,
                    predecessor.commitment,
                ),
                MigrationState::ExtentAuthoritative,
            )
            .unwrap();
        let new_database_epoch = next_database_epoch_for_test(archive_id, predecessor.commitment);
        let current = insert_simple_root(
            &reader,
            &cipher,
            registry,
            archive_id,
            new_database_epoch,
            key_epoch,
            3,
            Some(predecessor.commitment.root()),
            lease.fencing_epoch(),
            ObjectId::from_bytes([0xb9; 16]),
        )
        .await;
        witness
            .cut_over_database_epoch(
                RootAdvance::new(
                    lease,
                    predecessor_receipt.record().root(),
                    registry,
                    current.commitment,
                ),
                new_database_epoch,
            )
            .unwrap();
        let recovery = witness.recovery_root(archive_id).unwrap();
        assert_eq!(recovery.predecessor_root(), Some(predecessor.commitment));

        let (_wrong_registry, wrong_predecessor_cipher) =
            resolved_cipher(archive_id, key_epoch, ObjectId::from_bytes([0xba; 16]), 1).await;
        assert_eq!(
            visit_witness_reachability(
                &recovery,
                &reader,
                &cipher,
                Some(&wrong_predecessor_cipher),
            )
            .await
            .unwrap_err(),
            ReachabilityError::InvalidSnapshot
        );
        assert!(reader.calls().is_empty());

        let visit = visit_witness_reachability(&recovery, &reader, &cipher, Some(&cipher))
            .await
            .unwrap();
        assert_eq!(visit.graph_count(), 2);
        assert_eq!(reader.call_count(&current.context.object_key()), 1);
        assert_eq!(reader.call_count(&predecessor.context.object_key()), 1);
        assert_eq!(reader.call_count(&genesis.context.object_key()), 0);
        assert_eq!(reader.call_count(&shadow.context.object_key()), 0);
        assert!(visit
            .objects()
            .iter()
            .any(|object| object.key() == &shadow.context.object_key()));
    }

    #[tokio::test]
    async fn witness_key_rotation_retains_parent_without_guessing_old_key_epoch() {
        let archive_id = ArchiveId::from_bytes([0xc1; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([0xc2; 16]);
        let old_key_epoch = KeyEpoch::from_bytes([0xc3; 16]);
        let new_key_epoch = KeyEpoch::from_bytes([0xc4; 16]);
        let (old_registry, old_cipher) = resolved_cipher(
            archive_id,
            old_key_epoch,
            ObjectId::from_bytes([0xc5; 16]),
            0,
        )
        .await;
        let (new_registry, new_cipher) = resolved_cipher(
            archive_id,
            new_key_epoch,
            ObjectId::from_bytes([0xc6; 16]),
            1,
        )
        .await;
        let reader = FakeReader::new();
        let genesis = insert_simple_root(
            &reader,
            &old_cipher,
            old_registry,
            archive_id,
            database_epoch,
            old_key_epoch,
            0,
            None,
            0,
            ObjectId::from_bytes([0xc7; 16]),
        )
        .await;
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                genesis.commitment,
                old_registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive_id,
                database_epoch,
                old_key_epoch,
                ObjectId::from_bytes([0xc8; 16]),
                100,
            )
            .unwrap();
        let rotated = insert_simple_root(
            &reader,
            &new_cipher,
            new_registry,
            archive_id,
            database_epoch,
            new_key_epoch,
            1,
            Some(genesis.commitment.root()),
            lease.fencing_epoch(),
            ObjectId::from_bytes([0xc9; 16]),
        )
        .await;
        let rotated_envelope = CiphertextEnvelope::decode(
            reader
                .objects
                .lock()
                .unwrap()
                .get(&rotated.context.object_key())
                .unwrap(),
        )
        .unwrap();
        let rotation = RootAdvance::from_authenticated_candidate(
            lease,
            genesis.commitment,
            old_registry,
            new_registry,
            &rotated.context,
            &OneRootProvider(rotated_envelope),
            &new_cipher,
        )
        .await
        .unwrap();
        witness.rotate_key_registry(rotation, new_registry).unwrap();
        let recovery = witness.recovery_root(archive_id).unwrap();
        let visit = visit_witness_reachability(&recovery, &reader, &new_cipher, None)
            .await
            .unwrap();
        assert_eq!(visit.graph_count(), 1);
        assert_eq!(reader.call_count(&rotated.context.object_key()), 1);
        assert_eq!(reader.call_count(&genesis.context.object_key()), 0);

        let root_reference = ImmutableReference {
            object_id: genesis.commitment.root().object_id(),
            envelope_hash: genesis.commitment.root().ciphertext_hash(),
        };
        let old_context = ObjectContext::new(
            archive_id,
            database_epoch,
            old_key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_reference.object_id,
            None,
        )
        .unwrap();
        let new_context = ObjectContext::new(
            archive_id,
            database_epoch,
            new_key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_reference.object_id,
            None,
        )
        .unwrap();
        let old_identity = identity_for_context(&old_context, &root_reference).unwrap();
        let new_identity = identity_for_context(&new_context, &root_reference).unwrap();
        assert!(old_identity == new_identity);
        let parent = visit
            .objects()
            .iter()
            .find(|object| object.key() == &old_context.object_key())
            .unwrap();
        assert!(!parent.was_fetched());
        assert_eq!(
            parent.identity_commitment,
            root_fact_commitment(
                archive_id,
                database_epoch,
                0,
                root_reference.object_id,
                root_reference.envelope_hash,
            )
        );
    }

    #[tokio::test]
    async fn authenticates_full_single_commit_wal_lineage_and_streams_segments() {
        let fixture = checkpoint_extent_fixture(false).await;
        let root_zero = fixture.recovery.root().root();
        let (wal_header, frames, header_checksum, final_checksum) = fixture_wal_frames();
        let segment = WalSegment {
            root_seq: 1,
            wal_generation: 1,
            segment_index: 0,
            segment_count: 1,
            previous_segment: None,
            first_frame_no: 1,
            checksum_before: header_checksum,
            wal_header,
            frames,
        };
        let segment_id = ObjectId::from_bytes([41; 16]);
        let segment_context = ObjectContext::new(
            fixture.archive_id,
            fixture.database_epoch,
            fixture.key_epoch,
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq: 1,
                wal_generation: 1,
                segment_index: 0,
            },
            segment_id,
            None,
        )
        .unwrap();
        let segment_envelope = fixture
            .cipher
            .seal(&segment_context, &segment.encode().unwrap())
            .unwrap();
        fixture.reader.insert(&segment_context, &segment_envelope);
        let segment_reference = ImmutableReference {
            object_id: segment_id,
            envelope_hash: segment_envelope.hash(),
        };
        let checkpoint_key = fixture
            .reader
            .objects
            .lock()
            .unwrap()
            .keys()
            .find(|key| key.as_str().contains("/manifest/"))
            .cloned()
            .unwrap();
        let checkpoint_bytes = fixture
            .reader
            .objects
            .lock()
            .unwrap()
            .get(&checkpoint_key)
            .unwrap()
            .clone();
        let checkpoint_reference = ImmutableReference {
            object_id: checkpoint_key.object_id(),
            envelope_hash: CiphertextEnvelope::decode(&checkpoint_bytes)
                .unwrap()
                .hash(),
        };
        let descriptor = WalCommitDescriptor {
            root_seq: 1,
            owner_fencing_epoch: 11,
            operation_id: [0x31; 16],
            request_fingerprint: [0x32; 32],
            checkpoint_root: checkpoint_reference.clone(),
            parent_root: ParentReference {
                object_id: root_zero.object_id(),
                envelope_hash: root_zero.ciphertext_hash(),
            },
            parent_root_parent: None,
            previous_commit: None,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            before_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            after_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            wal_generation: 1,
            first_frame_no: 1,
            wal_header_hash: Sha256::digest(wal_header).into(),
            checksum_before: header_checksum,
            checksum_after: final_checksum,
            frame_count: 1,
            commit_segment_count: 1,
            cumulative_commit_count: 1,
            cumulative_segment_count: 1,
            commit_wal_bytes: (WAL_HEADER_BYTES
                + WAL_FRAME_HEADER_BYTES
                + SQLITE_PAGE_SIZE as usize) as u64,
            cumulative_wal_bytes: (WAL_HEADER_BYTES
                + WAL_FRAME_HEADER_BYTES
                + SQLITE_PAGE_SIZE as usize) as u64,
            final_segment: segment_reference,
        };
        let descriptor_id = ObjectId::from_bytes([42; 16]);
        let descriptor_context = ObjectContext::new(
            fixture.archive_id,
            fixture.database_epoch,
            fixture.key_epoch,
            ObjectRole::WalCommitDescriptorV3,
            LogicalLocation::WalCommitDescriptor { root_seq: 1 },
            descriptor_id,
            None,
        )
        .unwrap();
        let descriptor_envelope = fixture
            .cipher
            .seal(&descriptor_context, &descriptor.encode().unwrap())
            .unwrap();
        fixture
            .reader
            .insert(&descriptor_context, &descriptor_envelope);

        let root = ArchiveRoot {
            root_seq: 1,
            parent: Some(ParentReference {
                object_id: root_zero.object_id(),
                envelope_hash: root_zero.ciphertext_hash(),
            }),
            database_epoch: fixture.database_epoch,
            key_epoch: fixture.key_epoch,
            owner_fencing_epoch: 11,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 1,
            wal_commit_count: 1,
            wal_segment_count: 1,
            wal_tail_bytes: descriptor.cumulative_wal_bytes,
            checkpoint_root: Some(checkpoint_reference),
            extent_tree_root: None,
            wal_commit_tail: Some(ImmutableReference {
                object_id: descriptor_id,
                envelope_hash: descriptor_envelope.hash(),
            }),
        };
        let root_id = ObjectId::from_bytes([43; 16]);
        let root_context = ObjectContext::new(
            fixture.archive_id,
            fixture.database_epoch,
            fixture.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 1 },
            root_id,
            root.parent.clone(),
        )
        .unwrap();
        let root_envelope = fixture
            .cipher
            .seal(&root_context, &root.encode().unwrap())
            .unwrap();
        fixture.reader.insert(&root_context, &root_envelope);
        let commitment = RootCommitment::from_authenticated_provider_object(
            fixture.archive_id,
            fixture.registry,
            &root_context,
            &OneRootProvider(root_envelope),
            &fixture.cipher,
        )
        .await
        .unwrap();
        let mut tracker = VisitTracker::new(fixture.archive_id);
        visit_graph(
            fixture.reader.as_ref(),
            &mut tracker,
            &GraphBinding {
                root: commitment,
                registry: fixture.registry,
                cipher: &fixture.cipher,
                witnessed_predecessor: None,
            },
        )
        .await
        .unwrap();
        assert!(tracker
            .objects
            .iter()
            .any(|object| object.role == ObjectRole::WalCommitDescriptorV3));
        assert!(tracker
            .objects
            .iter()
            .any(|object| object.role == ObjectRole::WalSegmentV3));
        let historical_root_key = ObjectContext::new(
            fixture.archive_id,
            fixture.database_epoch,
            fixture.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_zero.object_id(),
            None,
        )
        .unwrap()
        .object_key();
        assert!(tracker.objects.iter().any(|object| {
            object.key() == &historical_root_key
                && object.role() == ObjectRole::RootV3
                && !object.was_fetched()
        }));
        assert_eq!(fixture.reader.call_count(&historical_root_key), 0);
        assert!(tracker.metadata_bytes < MAX_AUTHENTICATED_METADATA_BYTES);
    }

    #[tokio::test]
    async fn authenticates_multi_commit_rollover_and_multi_segment_history() {
        let fixture = checkpoint_extent_fixture(false).await;
        let root_zero = fixture.recovery.root().root();
        let root_one = RootReference::new(1, ObjectId::from_bytes([0x51; 16]), [0x52; 32]);
        let root_two = RootReference::new(2, ObjectId::from_bytes([0x53; 16]), [0x54; 32]);
        let checkpoint_key = fixture
            .reader
            .objects
            .lock()
            .unwrap()
            .keys()
            .find(|key| key.as_str().contains("/manifest/"))
            .cloned()
            .unwrap();
        let checkpoint_bytes = fixture
            .reader
            .objects
            .lock()
            .unwrap()
            .get(&checkpoint_key)
            .unwrap()
            .clone();
        let checkpoint_reference = ImmutableReference {
            object_id: checkpoint_key.object_id(),
            envelope_hash: CiphertextEnvelope::decode(&checkpoint_bytes)
                .unwrap()
                .hash(),
        };
        let (wal_header, _, header_checksum, _) = fixture_wal_frames();
        let frame_bytes = (WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize) as u64;

        let (frames_one, checksum_one) = fixture_wal_frame(wal_header, header_checksum, 1, 1, 0x61);
        let (segment_one, segment_one_key) = insert_wal_segment(
            &fixture,
            1,
            1,
            0,
            1,
            None,
            1,
            header_checksum,
            wal_header,
            frames_one,
            ObjectId::from_bytes([0x61; 16]),
        );
        let commit_one_bytes = WAL_HEADER_BYTES as u64 + frame_bytes;
        let descriptor_one = WalCommitDescriptor {
            root_seq: 1,
            owner_fencing_epoch: 21,
            operation_id: [0x11; 16],
            request_fingerprint: [0x12; 32],
            checkpoint_root: checkpoint_reference.clone(),
            parent_root: ParentReference {
                object_id: root_zero.object_id(),
                envelope_hash: root_zero.ciphertext_hash(),
            },
            parent_root_parent: None,
            previous_commit: None,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            before_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            after_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            wal_generation: 1,
            first_frame_no: 1,
            wal_header_hash: Sha256::digest(wal_header).into(),
            checksum_before: header_checksum,
            checksum_after: checksum_one,
            frame_count: 1,
            commit_segment_count: 1,
            cumulative_commit_count: 1,
            cumulative_segment_count: 1,
            commit_wal_bytes: commit_one_bytes,
            cumulative_wal_bytes: commit_one_bytes,
            final_segment: segment_one,
        };
        let (descriptor_one_reference, descriptor_one_key) =
            insert_wal_descriptor(&fixture, &descriptor_one, ObjectId::from_bytes([0x62; 16]));

        let (frames_two_a, checksum_two_a) =
            fixture_wal_frame(wal_header, checksum_one, 1, 0, 0x63);
        let (segment_two_a, segment_two_a_key) = insert_wal_segment(
            &fixture,
            2,
            1,
            0,
            2,
            None,
            2,
            checksum_one,
            wal_header,
            frames_two_a,
            ObjectId::from_bytes([0x63; 16]),
        );
        let (frames_two_b, checksum_two_b) =
            fixture_wal_frame(wal_header, checksum_two_a, 1, 1, 0xa7);
        let (segment_two_b, segment_two_b_key) = insert_wal_segment(
            &fixture,
            2,
            1,
            1,
            2,
            Some(segment_two_a.clone()),
            3,
            checksum_two_a,
            wal_header,
            frames_two_b,
            ObjectId::from_bytes([0x64; 16]),
        );
        let commit_two_bytes = WAL_HEADER_BYTES as u64 + 2 * frame_bytes;
        let descriptor_two = WalCommitDescriptor {
            root_seq: 2,
            owner_fencing_epoch: 21,
            operation_id: [0x21; 16],
            request_fingerprint: [0x22; 32],
            checkpoint_root: checkpoint_reference.clone(),
            parent_root: ParentReference {
                object_id: root_one.object_id(),
                envelope_hash: root_one.ciphertext_hash(),
            },
            parent_root_parent: Some(ParentReference {
                object_id: root_zero.object_id(),
                envelope_hash: root_zero.ciphertext_hash(),
            }),
            previous_commit: Some(descriptor_one_reference.clone()),
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            before_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            after_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            wal_generation: 1,
            first_frame_no: 2,
            wal_header_hash: Sha256::digest(wal_header).into(),
            checksum_before: checksum_one,
            checksum_after: checksum_two_b,
            frame_count: 2,
            commit_segment_count: 2,
            cumulative_commit_count: 2,
            cumulative_segment_count: 3,
            commit_wal_bytes: commit_two_bytes,
            cumulative_wal_bytes: commit_one_bytes + commit_two_bytes,
            final_segment: segment_two_b,
        };
        let (descriptor_two_reference, descriptor_two_key) =
            insert_wal_descriptor(&fixture, &descriptor_two, ObjectId::from_bytes([0x65; 16]));

        let (frames_three, checksum_three) =
            fixture_wal_frame(wal_header, header_checksum, 1, 1, 0x66);
        let (segment_three, segment_three_key) = insert_wal_segment(
            &fixture,
            3,
            2,
            0,
            1,
            None,
            1,
            header_checksum,
            wal_header,
            frames_three,
            ObjectId::from_bytes([0x66; 16]),
        );
        let commit_three_bytes = WAL_HEADER_BYTES as u64 + frame_bytes;
        let descriptor_three = WalCommitDescriptor {
            root_seq: 3,
            owner_fencing_epoch: 21,
            operation_id: [0x31; 16],
            request_fingerprint: [0x32; 32],
            checkpoint_root: checkpoint_reference.clone(),
            parent_root: ParentReference {
                object_id: root_two.object_id(),
                envelope_hash: root_two.ciphertext_hash(),
            },
            parent_root_parent: Some(ParentReference {
                object_id: root_one.object_id(),
                envelope_hash: root_one.ciphertext_hash(),
            }),
            previous_commit: Some(descriptor_two_reference.clone()),
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            before_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            after_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            wal_generation: 2,
            first_frame_no: 1,
            wal_header_hash: Sha256::digest(wal_header).into(),
            checksum_before: header_checksum,
            checksum_after: checksum_three,
            frame_count: 1,
            commit_segment_count: 1,
            cumulative_commit_count: 3,
            cumulative_segment_count: 4,
            commit_wal_bytes: commit_three_bytes,
            cumulative_wal_bytes: commit_one_bytes + commit_two_bytes + commit_three_bytes,
            final_segment: segment_three,
        };
        let (descriptor_three_reference, descriptor_three_key) = insert_wal_descriptor(
            &fixture,
            &descriptor_three,
            ObjectId::from_bytes([0x67; 16]),
        );

        let root = ArchiveRoot {
            root_seq: 3,
            parent: Some(ParentReference {
                object_id: root_two.object_id(),
                envelope_hash: root_two.ciphertext_hash(),
            }),
            database_epoch: fixture.database_epoch,
            key_epoch: fixture.key_epoch,
            owner_fencing_epoch: 21,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 2,
            wal_commit_count: 3,
            wal_segment_count: 4,
            wal_tail_bytes: descriptor_three.cumulative_wal_bytes,
            checkpoint_root: Some(checkpoint_reference),
            extent_tree_root: None,
            wal_commit_tail: Some(descriptor_three_reference),
        };
        let root_context = ObjectContext::new(
            fixture.archive_id,
            fixture.database_epoch,
            fixture.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 3 },
            ObjectId::from_bytes([0x68; 16]),
            root.parent.clone(),
        )
        .unwrap();
        let root_envelope = fixture
            .cipher
            .seal(&root_context, &root.encode().unwrap())
            .unwrap();
        fixture.reader.insert(&root_context, &root_envelope);
        let commitment = RootCommitment::from_authenticated_provider_object(
            fixture.archive_id,
            fixture.registry,
            &root_context,
            &OneRootProvider(root_envelope),
            &fixture.cipher,
        )
        .await
        .unwrap();
        let graph = GraphBinding {
            root: commitment,
            registry: fixture.registry,
            cipher: &fixture.cipher,
            witnessed_predecessor: None,
        };
        let mut tracker = VisitTracker::new(fixture.archive_id);
        visit_graph(fixture.reader.as_ref(), &mut tracker, &graph)
            .await
            .unwrap();
        for key in [
            &descriptor_one_key,
            &descriptor_two_key,
            &descriptor_three_key,
            &segment_one_key,
            &segment_two_a_key,
            &segment_two_b_key,
            &segment_three_key,
        ] {
            assert_eq!(fixture.reader.call_count(key), 1);
        }
        for root_reference in [root_zero, root_one, root_two] {
            let key = ObjectContext::new(
                fixture.archive_id,
                fixture.database_epoch,
                fixture.key_epoch,
                ObjectRole::RootV3,
                LogicalLocation::Root {
                    root_seq: root_reference.sequence(),
                },
                root_reference.object_id(),
                None,
            )
            .unwrap()
            .object_key();
            assert!(tracker.objects.iter().any(|object| object.key() == &key));
            assert_eq!(fixture.reader.call_count(&key), 0);
        }

        fixture
            .reader
            .set_key_fault(descriptor_one_key.clone(), ReadFault::Missing);
        assert_eq!(
            visit_graph(
                fixture.reader.as_ref(),
                &mut VisitTracker::new(fixture.archive_id),
                &graph,
            )
            .await
            .unwrap_err(),
            ReachabilityError::Missing
        );
        fixture
            .reader
            .set_key_fault(descriptor_one_key.clone(), ReadFault::None);
        fixture
            .reader
            .set_key_fault(segment_two_a_key.clone(), ReadFault::Tamper);
        assert_eq!(
            visit_graph(
                fixture.reader.as_ref(),
                &mut VisitTracker::new(fixture.archive_id),
                &graph,
            )
            .await
            .unwrap_err(),
            ReachabilityError::Authentication
        );
        fixture
            .reader
            .set_key_fault(segment_two_a_key.clone(), ReadFault::None);
        fixture
            .reader
            .swap_encoded(&descriptor_one_key, &descriptor_two_key);
        assert_eq!(
            visit_graph(
                fixture.reader.as_ref(),
                &mut VisitTracker::new(fixture.archive_id),
                &graph,
            )
            .await
            .unwrap_err(),
            ReachabilityError::Authentication
        );
        fixture
            .reader
            .swap_encoded(&descriptor_one_key, &descriptor_two_key);
        fixture
            .reader
            .swap_encoded(&segment_two_a_key, &segment_two_b_key);
        assert_eq!(
            visit_graph(
                fixture.reader.as_ref(),
                &mut VisitTracker::new(fixture.archive_id),
                &graph,
            )
            .await
            .unwrap_err(),
            ReachabilityError::Authentication
        );
        fixture
            .reader
            .swap_encoded(&segment_two_a_key, &segment_two_b_key);

        let before = crate::archive_v3_journal::wal_segment_zeroization_observations();
        let stalled = StallingReader {
            inner: fixture.reader.clone(),
            stall_once: AtomicBool::new(true),
            stall_key: Some(segment_two_a_key),
            entered: Notify::new(),
            release: Notify::new(),
        };
        let mut cancelled_tracker = VisitTracker::new(fixture.archive_id);
        let mut visit = Box::pin(visit_graph(&stalled, &mut cancelled_tracker, &graph));
        tokio::select! {
            _ = stalled.entered.notified() => {}
            result = &mut visit => panic!("visit completed before predecessor segment stalled: {result:?}"),
        }
        drop(visit);
        assert!(crate::archive_v3_journal::wal_segment_zeroization_observations() > before);
    }

    fn fixture_wal_frames() -> ([u8; 32], Vec<u8>, [u32; 2], [u32; 2]) {
        let mut header = [0u8; 32];
        header[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        header[4..8].copy_from_slice(&3_007_000u32.to_be_bytes());
        header[8..12].copy_from_slice(&SQLITE_PAGE_SIZE.to_be_bytes());
        header[12..16].copy_from_slice(&1u32.to_be_bytes());
        header[16..20].copy_from_slice(&[11, 12, 13, 14]);
        header[20..24].copy_from_slice(&[21, 22, 23, 24]);
        let header_checksum = checksum_little(&header[..24], [0, 0]);
        header[24..28].copy_from_slice(&header_checksum[0].to_be_bytes());
        header[28..32].copy_from_slice(&header_checksum[1].to_be_bytes());

        let mut frame = vec![0u8; WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize];
        frame[0..4].copy_from_slice(&1u32.to_be_bytes());
        frame[4..8].copy_from_slice(&1u32.to_be_bytes());
        frame[8..16].copy_from_slice(&header[16..24]);
        frame[24..].fill(0x55);
        let checksum = checksum_little(&frame[..8], header_checksum);
        let checksum = checksum_little(&frame[24..], checksum);
        frame[16..20].copy_from_slice(&checksum[0].to_be_bytes());
        frame[20..24].copy_from_slice(&checksum[1].to_be_bytes());
        (header, frame, header_checksum, checksum)
    }

    fn fixture_wal_frame(
        header: [u8; 32],
        checksum_before: [u32; 2],
        page_number: u32,
        commit_pages: u32,
        fill: u8,
    ) -> (Vec<u8>, [u32; 2]) {
        let mut frame = vec![0u8; WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize];
        frame[0..4].copy_from_slice(&page_number.to_be_bytes());
        frame[4..8].copy_from_slice(&commit_pages.to_be_bytes());
        frame[8..16].copy_from_slice(&header[16..24]);
        frame[24..].fill(fill);
        let checksum = checksum_little(&frame[..8], checksum_before);
        let checksum = checksum_little(&frame[24..], checksum);
        frame[16..20].copy_from_slice(&checksum[0].to_be_bytes());
        frame[20..24].copy_from_slice(&checksum[1].to_be_bytes());
        (frame, checksum)
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_wal_segment(
        fixture: &Fixture,
        root_seq: u64,
        wal_generation: u64,
        segment_index: u32,
        segment_count: u32,
        previous_segment: Option<ImmutableReference>,
        first_frame_no: u64,
        checksum_before: [u32; 2],
        wal_header: [u8; 32],
        frames: Vec<u8>,
        object_id: ObjectId,
    ) -> (ImmutableReference, ObjectKey) {
        let segment = WalSegment {
            root_seq,
            wal_generation,
            segment_index,
            segment_count,
            previous_segment,
            first_frame_no,
            checksum_before,
            wal_header,
            frames,
        };
        let context = ObjectContext::new(
            fixture.archive_id,
            fixture.database_epoch,
            fixture.key_epoch,
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq,
                wal_generation,
                segment_index,
            },
            object_id,
            None,
        )
        .unwrap();
        let envelope = fixture
            .cipher
            .seal(&context, &segment.encode().unwrap())
            .unwrap();
        fixture.reader.insert(&context, &envelope);
        (
            ImmutableReference {
                object_id,
                envelope_hash: envelope.hash(),
            },
            context.object_key(),
        )
    }

    fn insert_wal_descriptor(
        fixture: &Fixture,
        descriptor: &WalCommitDescriptor,
        object_id: ObjectId,
    ) -> (ImmutableReference, ObjectKey) {
        let context = ObjectContext::new(
            fixture.archive_id,
            fixture.database_epoch,
            fixture.key_epoch,
            ObjectRole::WalCommitDescriptorV3,
            LogicalLocation::WalCommitDescriptor {
                root_seq: descriptor.root_seq,
            },
            object_id,
            None,
        )
        .unwrap();
        let envelope = fixture
            .cipher
            .seal(&context, &descriptor.encode().unwrap())
            .unwrap();
        fixture.reader.insert(&context, &envelope);
        (
            ImmutableReference {
                object_id,
                envelope_hash: envelope.hash(),
            },
            context.object_key(),
        )
    }

    fn checksum_little(input: &[u8], mut state: [u32; 2]) -> [u32; 2] {
        for words in input.chunks_exact(8) {
            let first = u32::from_le_bytes(words[..4].try_into().unwrap());
            let second = u32::from_le_bytes(words[4..8].try_into().unwrap());
            state[0] = state[0].wrapping_add(first).wrapping_add(state[1]);
            state[1] = state[1].wrapping_add(second).wrapping_add(state[0]);
        }
        state
    }

    #[test]
    fn fixed_geometry_caps_are_exact() {
        assert_eq!(checkpoint_chunks(MAX_DATABASE_BYTES).unwrap(), 32_768);
        assert!(checkpoint_chunks(MAX_DATABASE_BYTES + u64::from(SQLITE_PAGE_SIZE)).is_err());
        assert_eq!(checkpoint_height(32_768).unwrap(), 1);
        assert_eq!(extent_slots(MAX_DATABASE_BYTES).unwrap(), 32_768);
        assert!(extent_slots(MAX_DATABASE_BYTES + u64::from(SQLITE_PAGE_SIZE)).is_err());
        assert_eq!(extent_height(32_768).unwrap(), 1);
        assert_eq!(MAX_CHECKPOINT_MANIFESTS, 129);
        assert_eq!(MAX_EXTENT_NODES, 129);
        assert_eq!(MAX_WAL_DESCRIPTORS, 1_024);
        assert_eq!(MAX_WAL_SEGMENTS, 16_384);
    }

    #[test]
    fn every_fixed_boundary_accepts_at_limit_and_rejects_plus_one() {
        assert_eq!(check_graph_depth(MAX_GRAPH_DEPTH), Ok(()));
        assert_eq!(
            check_graph_depth(MAX_GRAPH_DEPTH + 1),
            Err(ReachabilityError::Limit)
        );
        let mut checkpoint_manifests = MAX_CHECKPOINT_MANIFESTS - 1;
        assert_eq!(
            bounded_count(&mut checkpoint_manifests, 1, MAX_CHECKPOINT_MANIFESTS),
            Ok(())
        );
        assert_eq!(
            bounded_count(&mut checkpoint_manifests, 1, MAX_CHECKPOINT_MANIFESTS),
            Err(ReachabilityError::Limit)
        );
        let mut extent_nodes = MAX_EXTENT_NODES - 1;
        assert_eq!(
            bounded_count(&mut extent_nodes, 1, MAX_EXTENT_NODES),
            Ok(())
        );
        assert_eq!(
            bounded_count(&mut extent_nodes, 1, MAX_EXTENT_NODES),
            Err(ReachabilityError::Limit)
        );

        let archive_id = ArchiveId::from_bytes([0x91; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([0x92; 16]);
        let key_epoch = KeyEpoch::from_bytes([0x93; 16]);
        let context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 0,
                byte_len: SQLITE_PAGE_SIZE,
            },
            ObjectId::from_bytes([0x94; 16]),
            None,
        )
        .unwrap();
        let reference = ImmutableReference {
            object_id: context.object_id(),
            envelope_hash: [0x95; 32],
        };
        let identity = identity_for_context(&context, &reference).unwrap();
        let prototype = ReachableObject {
            key: identity.key.clone(),
            role: identity.role,
            ciphertext_hash: identity.ciphertext_hash,
            identity_commitment: identity.identity_commitment,
            fetched: false,
        };
        let mut object_tracker = VisitTracker::new(archive_id);
        object_tracker
            .objects
            .resize(MAX_REACHABLE_OBJECTS - 1, prototype);
        assert!(object_tracker
            .register_context_edge(&context, &reference)
            .unwrap());
        let next_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 1,
                byte_len: SQLITE_PAGE_SIZE,
            },
            ObjectId::from_bytes([0x96; 16]),
            None,
        )
        .unwrap();
        assert_eq!(
            object_tracker.register_context_edge(
                &next_context,
                &ImmutableReference {
                    object_id: next_context.object_id(),
                    envelope_hash: [0x97; 32],
                },
            ),
            Err(ReachabilityError::Limit)
        );

        let mut key_tracker = VisitTracker::new(archive_id);
        key_tracker.key_bytes = MAX_REACHABLE_KEY_BYTES - context.object_key().as_str().len();
        assert!(key_tracker
            .register_context_edge(&context, &reference)
            .unwrap());
        assert_eq!(key_tracker.key_bytes, MAX_REACHABLE_KEY_BYTES);
        assert_eq!(
            key_tracker.register_context_edge(
                &next_context,
                &ImmutableReference {
                    object_id: next_context.object_id(),
                    envelope_hash: [0x97; 32],
                },
            ),
            Err(ReachabilityError::Limit)
        );

        let mut metadata_tracker = VisitTracker::new(archive_id);
        metadata_tracker.metadata_bytes = MAX_AUTHENTICATED_METADATA_BYTES - 1;
        assert_eq!(metadata_tracker.add_metadata(1), Ok(()));
        assert_eq!(
            metadata_tracker.add_metadata(1),
            Err(ReachabilityError::Limit)
        );
        assert_eq!(
            metadata_tracker.ensure_metadata_capacity(1),
            Err(ReachabilityError::Limit)
        );

        let mut wal_root = ArchiveRoot {
            root_seq: MAX_WAL_DESCRIPTORS as u64,
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes([0x98; 16]),
                envelope_hash: [0x99; 32],
            }),
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 1,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 1,
            wal_commit_count: MAX_WAL_DESCRIPTORS as u32,
            wal_segment_count: MAX_WAL_SEGMENTS as u32,
            wal_tail_bytes: MAX_WAL_TAIL_BYTES,
            checkpoint_root: Some(reference.clone()),
            extent_tree_root: None,
            wal_commit_tail: Some(reference),
        };
        assert_eq!(validate_wal_root_bounds(&wal_root), Ok(()));
        assert_eq!(
            validate_one_wal_commit_bounds(
                MAX_WAL_SEGMENTS_PER_COMMIT,
                MAX_ONE_WAL_COMMIT_BYTES as u64,
            ),
            Ok(())
        );
        assert_eq!(
            validate_one_wal_commit_bounds(
                MAX_WAL_SEGMENTS_PER_COMMIT + 1,
                MAX_ONE_WAL_COMMIT_BYTES as u64,
            ),
            Err(ReachabilityError::Limit)
        );
        assert_eq!(
            validate_one_wal_commit_bounds(
                MAX_WAL_SEGMENTS_PER_COMMIT,
                MAX_ONE_WAL_COMMIT_BYTES as u64 + 1,
            ),
            Err(ReachabilityError::Limit)
        );
        wal_root.wal_commit_count = MAX_WAL_DESCRIPTORS as u32 + 1;
        assert_eq!(
            validate_wal_root_bounds(&wal_root),
            Err(ReachabilityError::Limit)
        );
        wal_root.wal_commit_count = MAX_WAL_DESCRIPTORS as u32;
        wal_root.wal_segment_count = MAX_WAL_SEGMENTS as u32 + 1;
        assert_eq!(
            validate_wal_root_bounds(&wal_root),
            Err(ReachabilityError::Limit)
        );
        wal_root.wal_segment_count = MAX_WAL_SEGMENTS as u32;
        wal_root.wal_tail_bytes = MAX_WAL_TAIL_BYTES + 1;
        assert_eq!(
            validate_wal_root_bounds(&wal_root),
            Err(ReachabilityError::Limit)
        );
    }

    #[test]
    fn high_cardinality_tracker_uses_stable_logarithmic_indices() {
        const HIGH_CARDINALITY: u32 = 100_000;
        let archive_id = ArchiveId::from_bytes([0xa1; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([0xa2; 16]);
        let key_epoch = KeyEpoch::from_bytes([0xa3; 16]);
        let mut tracker = VisitTracker::new(archive_id);
        let mut final_context = None;
        let mut final_reference = None;
        for value in 1..=HIGH_CARDINALITY {
            let context = ObjectContext::new(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectRole::ExtentV3,
                LogicalLocation::Extent {
                    extent_no: u64::from(value % MAX_EXTENT_LEAVES as u32),
                    byte_len: SQLITE_PAGE_SIZE,
                },
                object_id(value),
                None,
            )
            .unwrap();
            let reference = reference(value);
            assert!(tracker.register_context_edge(&context, &reference).unwrap());
            final_context = Some(context);
            final_reference = Some(reference);
        }
        assert_eq!(tracker.identities.len(), HIGH_CARDINALITY as usize);
        assert_eq!(tracker.objects.len(), HIGH_CARDINALITY as usize);
        let context = final_context.unwrap();
        let reference = final_reference.unwrap();
        tracker
            .register_context_direct(&context, &reference)
            .unwrap();
        let entry = tracker.identities.get(&reference.object_id).unwrap();
        assert_eq!(entry.object_index, HIGH_CARDINALITY as usize - 1);
        assert!(tracker.objects[entry.object_index].was_fetched());
    }

    #[test]
    fn identical_leaf_fact_deduplicates_but_metadata_refetch_is_rejected() {
        let archive_id = ArchiveId::from_bytes([1; 16]);
        let context = ObjectContext::new(
            archive_id,
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 0,
                byte_len: SQLITE_PAGE_SIZE,
            },
            ObjectId::from_bytes([4; 16]),
            None,
        )
        .unwrap();
        let reference = ImmutableReference {
            object_id: context.object_id(),
            envelope_hash: [5; 32],
        };
        let mut tracker = VisitTracker::new(archive_id);
        assert!(tracker.register_context_edge(&context, &reference).unwrap());
        assert!(!tracker.register_context_edge(&context, &reference).unwrap());
        assert_eq!(tracker.objects.len(), 1);
        tracker
            .register_context_direct(&context, &reference)
            .unwrap();
        assert_eq!(
            tracker.register_context_direct(&context, &reference),
            Err(ReachabilityError::DuplicateOrCycle)
        );
    }

    #[test]
    fn static_contract_has_no_runtime_wiring_or_authority_mint() {
        let source = include_str!("archive_v3_reachability.rs");
        assert!(source.contains("trait ExactReachabilityReader"));
        for forbidden in [
            ["ImmutableObject", "Backend"].concat(),
            ["FullReachability", "Seal"].concat(),
            ["CompleteDeletion", "Inventory"].concat(),
            ["ArchiveLifecycle", "PageStore"].concat(),
            ["Control", "Store"].concat(),
            ["crate::store::", "Store"].concat(),
            ["std::", "env"].concat(),
            ["enumerate", "("].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
        assert!(source.contains("Zeroizing"));
        assert!(source.contains("drop(segments)"));
        let journal = include_str!("archive_v3_journal.rs");
        assert!(journal.contains("impl Drop for WalSegment"));
        assert!(journal.contains("self.frames.zeroize()"));
    }
}
