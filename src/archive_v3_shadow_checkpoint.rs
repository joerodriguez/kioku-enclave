#![allow(
    dead_code,
    reason = "inactive ADR-0022 checkpoint upload/recovery is compiled and tested before shadow authority wiring"
)]

//! Inactive, bounded ADR-0022 checkpoint upload and recovery.
//!
//! A future shadow coordinator supplies a stable SQLite snapshot through
//! [`CheckpointSource`], then publishes the returned [`UploadedCheckpoint`]
//! only inside a separately witnessed root.  This module never lists storage,
//! starts a VFS drain, mutates `Store`, or grants write authority.  Recovery
//! starts at the *one exact root* returned by [`Witness::recovery_root`]; it
//! cannot select a newer-looking orphan checkpoint by enumeration.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    archive_v3::{
        ArchiveId, ArchiveV3Error, CiphertextEnvelope, DatabaseEpoch, ImmutableObjectBackend,
        ImmutableReference, LogicalLocation, ObjectContext, ObjectId, ObjectRole, ParentReference,
        Result as ArchiveResult, SQLITE_PAGE_SIZE,
    },
    archive_v3_journal::{
        CheckpointChunkEntry, CheckpointManifestChild, CheckpointManifestEntries,
        CheckpointManifestNode, CHECKPOINT_CHUNK_BYTES, MAX_CHECKPOINT_MANIFEST_FANOUT,
    },
    archive_v3_witness::{RecoveryRoot, RootReference, Witness, WitnessError},
};

/// The recovery walk retains at most this many manifest work items.  The
/// fixed 256-way tree needs fewer than 1,021 entries even for the largest
/// representable checkpoint; this is a defensive independent ceiling.
pub const MAX_RECOVERY_MANIFEST_STACK: usize = 4_096;

#[derive(Debug, Error)]
pub enum ShadowCheckpointError {
    #[error(transparent)]
    Archive(#[from] ArchiveV3Error),
    #[error("checkpoint witness rejected recovery")]
    Witness(#[source] WitnessError),
    #[error("the exact immutable checkpoint object is absent")]
    MissingObject,
    #[error("checkpoint source did not provide its declared bytes")]
    Source,
    #[error("checkpoint recovery sink rejected output")]
    Sink,
}

pub type Result<T> = std::result::Result<T, ShadowCheckpointError>;

/// Read-only stable snapshot boundary.  Implementations must fill exactly
/// `destination.len()` bytes for every accepted range.  The caller supplies a
/// maximum 1 MiB destination, so a source must never force an unbounded read.
pub trait CheckpointSource {
    fn logical_file_length(&self) -> Result<u64>;
    fn read_exact(&mut self, logical_offset: u64, destination: &mut [u8]) -> Result<()>;
}

/// Recovery destination with a fixed caller-owned capacity or a streamed
/// tmpfs implementation. `abort` is mandatory because the final plaintext
/// hash can only be checked after streaming the last chunk.
pub trait CheckpointSink {
    fn write_exact(&mut self, logical_offset: u64, bytes: &[u8]) -> Result<()>;
    fn commit(&mut self, logical_file_length: u64) -> Result<()>;
    fn abort(&mut self);
}

/// Cipher boundary shared by the verified production cipher and small test
/// fakes.  Implementors must reject a context outside their verified archive
/// and key epoch before sealing or opening it.
pub trait CheckpointCipher: Send + Sync {
    fn archive_id(&self) -> ArchiveId;
    fn key_epoch(&self) -> crate::archive_v3::KeyEpoch;
    fn seal(&self, context: &ObjectContext, plaintext: &[u8]) -> ArchiveResult<CiphertextEnvelope>;
    fn open(
        &self,
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
    ) -> ArchiveResult<Vec<u8>>;
}

impl CheckpointCipher for crate::archive_v3::VerifiedArchiveCipher {
    fn archive_id(&self) -> ArchiveId {
        crate::archive_v3::VerifiedArchiveCipher::archive_id(self)
    }

    fn key_epoch(&self) -> crate::archive_v3::KeyEpoch {
        crate::archive_v3::VerifiedArchiveCipher::key_epoch(self)
    }

    fn seal(&self, context: &ObjectContext, plaintext: &[u8]) -> ArchiveResult<CiphertextEnvelope> {
        crate::archive_v3::VerifiedArchiveCipher::seal(self, context, plaintext)
    }

    fn open(
        &self,
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
    ) -> ArchiveResult<Vec<u8>> {
        crate::archive_v3::VerifiedArchiveCipher::open(self, context, envelope)
    }
}

/// Stable metadata returned after all immutable chunk and manifest creates
/// have succeeded.  It is deliberately not an `ArchiveRoot`: a future
/// coordinator must still authenticate it in a root and advance that root via
/// the witness before this checkpoint can have authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadedCheckpoint {
    checkpoint_id: ObjectId,
    root: ImmutableReference,
    logical_file_length: u64,
    total_chunks: u32,
    database_plaintext_hash: [u8; 32],
}

impl UploadedCheckpoint {
    pub fn checkpoint_id(&self) -> ObjectId {
        self.checkpoint_id
    }

    pub fn root(&self) -> &ImmutableReference {
        &self.root
    }

    pub fn logical_file_length(&self) -> u64 {
        self.logical_file_length
    }

    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    pub fn database_plaintext_hash(&self) -> [u8; 32] {
        self.database_plaintext_hash
    }
}

/// Uploads a page-aligned SQLite snapshot as independently authenticated 1 MiB
/// chunks followed by a fixed-fanout manifest tree.  At most one chunk plus
/// one 256-entry pending group per tree level is retained; no storage listing
/// is used for deduplication or recovery selection.
pub async fn upload_checkpoint<C: CheckpointCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    source: &mut dyn CheckpointSource,
) -> Result<UploadedCheckpoint> {
    if cipher.archive_id() != archive_id {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let logical_file_length = source.logical_file_length()?;
    let total_chunks = validate_snapshot_length(logical_file_length)?;
    // Hash first so the digest can be authenticated in *every* manifest node.
    // A stable snapshot source is read a second time for upload; the second
    // pass is checked against this digest before a root descriptor is returned.
    let database_plaintext_hash = hash_snapshot(source, logical_file_length, total_chunks)?;
    let checkpoint_id = ObjectId::random();
    let tree_height = manifest_tree_height(total_chunks)?;
    let mut pending: Vec<Vec<ManifestSpan>> =
        (0..usize::from(tree_height)).map(|_| Vec::new()).collect();
    let mut root: Option<ManifestSpan> = None;
    let mut leaf_entries = Vec::with_capacity(MAX_CHECKPOINT_MANIFEST_FANOUT);
    let mut uploaded_hash = Sha256::new();

    for chunk_index in 0..total_chunks {
        let logical_offset = u64::from(chunk_index) * u64::from(CHECKPOINT_CHUNK_BYTES);
        let remaining = logical_file_length
            .checked_sub(logical_offset)
            .ok_or(ArchiveV3Error::Malformed("checkpoint offset"))?;
        let logical_byte_len = remaining.min(u64::from(CHECKPOINT_CHUNK_BYTES)) as u32;
        let mut chunk = Zeroizing::new(vec![0u8; logical_byte_len as usize]);
        source.read_exact(logical_offset, chunk.as_mut_slice())?;
        uploaded_hash.update(chunk.as_slice());
        let plaintext_hash: [u8; 32] = Sha256::digest(chunk.as_slice()).into();
        let context = ObjectContext::new(
            archive_id,
            database_epoch,
            cipher.key_epoch(),
            ObjectRole::CheckpointChunkV3,
            LogicalLocation::CheckpointChunk {
                checkpoint_id,
                chunk_index,
                logical_offset,
                byte_len: logical_byte_len,
            },
            ObjectId::random(),
            None,
        )?;
        let envelope = cipher.seal(&context, chunk.as_slice())?;
        backend
            .create_if_absent(context.object_key(), envelope.clone())
            .await?;
        leaf_entries.push(CheckpointChunkEntry {
            chunk_index,
            logical_offset,
            logical_byte_len,
            plaintext_hash,
            reference: ImmutableReference {
                object_id: context.object_id(),
                envelope_hash: envelope.hash(),
            },
        });

        if leaf_entries.len() == MAX_CHECKPOINT_MANIFEST_FANOUT || chunk_index + 1 == total_chunks {
            let range_end = chunk_index + 1;
            let range_start = range_end
                .checked_sub(leaf_entries.len() as u32)
                .ok_or(ArchiveV3Error::Malformed("checkpoint leaf range"))?;
            let span = seal_manifest(
                backend,
                cipher,
                archive_id,
                database_epoch,
                checkpoint_id,
                0,
                range_start,
                range_end,
                total_chunks,
                logical_file_length,
                database_plaintext_hash,
                CheckpointManifestEntries::Chunks(std::mem::take(&mut leaf_entries)),
                tree_height == 0,
            )
            .await?;
            add_manifest_span(
                backend,
                cipher,
                archive_id,
                database_epoch,
                checkpoint_id,
                total_chunks,
                logical_file_length,
                tree_height,
                &mut pending,
                &mut root,
                span,
                database_plaintext_hash,
            )
            .await?;
        }
    }

    if <[u8; 32]>::from(uploaded_hash.finalize()) != database_plaintext_hash {
        return Err(ShadowCheckpointError::Source);
    }
    for level in 0..usize::from(tree_height) {
        if !pending[level].is_empty() {
            let children = std::mem::take(&mut pending[level]);
            let span = seal_parent_manifest(
                backend,
                cipher,
                archive_id,
                database_epoch,
                checkpoint_id,
                total_chunks,
                logical_file_length,
                tree_height,
                level as u8,
                children,
                database_plaintext_hash,
            )
            .await?;
            add_manifest_span(
                backend,
                cipher,
                archive_id,
                database_epoch,
                checkpoint_id,
                total_chunks,
                logical_file_length,
                tree_height,
                &mut pending,
                &mut root,
                span,
                database_plaintext_hash,
            )
            .await?;
        }
    }
    let root = root.ok_or(ArchiveV3Error::Malformed("checkpoint manifest root"))?;
    if root.level != tree_height || root.range_start != 0 || root.range_end != total_chunks {
        return Err(ArchiveV3Error::Malformed("checkpoint manifest root").into());
    }
    Ok(UploadedCheckpoint {
        checkpoint_id,
        root: root.reference,
        logical_file_length,
        total_chunks,
        database_plaintext_hash,
    })
}

/// Recovers only the checkpoint nominated by the current witness root.  The
/// supplied cipher must have already been resolved from the same witnessed key
/// registry epoch; this function does not accept a caller-selected root,
/// manifest ID, prefix, or provider continuation token.
pub async fn recover_witness_checkpoint<C: CheckpointCipher>(
    witness: &dyn Witness,
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    sink: &mut dyn CheckpointSink,
) -> Result<UploadedCheckpoint> {
    let recovery = match witness.recovery_root(archive_id) {
        Ok(recovery) => recovery,
        Err(error) => {
            sink.abort();
            return Err(ShadowCheckpointError::Witness(error));
        }
    };
    recover_checkpoint_from_recovery_root(&recovery, backend, cipher, archive_id, sink).await
}

/// Async coordinators should obtain the exact [`RecoveryRoot`] from their
/// provider first, then call this entrypoint. This avoids invoking a
/// synchronous witness wrapper from within a Tokio runtime while retaining the
/// same exact-root recovery proof as [`recover_witness_checkpoint`].
pub async fn recover_checkpoint_from_recovery_root<C: CheckpointCipher>(
    recovery: &RecoveryRoot,
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    sink: &mut dyn CheckpointSink,
) -> Result<UploadedCheckpoint> {
    let result =
        recover_checkpoint_from_recovery_root_inner(recovery, backend, cipher, archive_id, sink)
            .await;
    if result.is_err() {
        sink.abort();
    }
    result
}

async fn recover_checkpoint_from_recovery_root_inner<C: CheckpointCipher>(
    recovery: &RecoveryRoot,
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    sink: &mut dyn CheckpointSink,
) -> Result<UploadedCheckpoint> {
    if cipher.archive_id() != archive_id {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let commitment = recovery.root();
    if cipher.key_epoch() != commitment.key_epoch() {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let root = load_witness_root(
        backend,
        cipher,
        archive_id,
        commitment.root(),
        commitment.parent(),
        commitment.database_epoch(),
        commitment.key_epoch(),
        commitment.owner_fencing_epoch(),
    )
    .await?;
    let checkpoint_reference = root
        .checkpoint_root
        .as_ref()
        .ok_or(ArchiveV3Error::Malformed("witness root has no checkpoint"))?
        .clone();
    let total_chunks = validate_snapshot_length(root.logical_file_length)?;
    let tree_height = manifest_tree_height(total_chunks)?;
    // Root manifest IDs intentionally equal their checkpoint ID. Together
    // with the deterministic fanout-derived root level/range, every context
    // needed to fetch the first manifest is available from the witnessed root.
    let checkpoint_id = checkpoint_reference.object_id;
    let root_manifest_context = manifest_context(
        archive_id,
        commitment.database_epoch(),
        commitment.key_epoch(),
        checkpoint_id,
        tree_height,
        0,
        total_chunks,
        checkpoint_reference.object_id,
    )?;
    let root_manifest = load_manifest(
        backend,
        cipher,
        &root_manifest_context,
        &checkpoint_reference,
    )
    .await?;
    let expected_hash = root_manifest.database_plaintext_hash;
    let expected = ManifestExpectation {
        checkpoint_id,
        total_chunks,
        logical_file_length: root.logical_file_length,
        database_plaintext_hash: expected_hash,
    };
    validate_manifest_shape(&root_manifest, tree_height, 0, total_chunks, &expected)?;

    let mut stack = vec![ManifestTask {
        level: tree_height,
        range_start: 0,
        range_end: total_chunks,
        reference: checkpoint_reference.clone(),
    }];
    let mut database_hash = Sha256::new();
    while let Some(task) = stack.pop() {
        if stack.len() > MAX_RECOVERY_MANIFEST_STACK {
            return Err(ArchiveV3Error::TooLarge("checkpoint recovery stack").into());
        }
        let context = manifest_context(
            archive_id,
            commitment.database_epoch(),
            commitment.key_epoch(),
            checkpoint_id,
            task.level,
            task.range_start,
            task.range_end,
            task.reference.object_id,
        )?;
        let node = load_manifest(backend, cipher, &context, &task.reference).await?;
        validate_manifest_shape(
            &node,
            task.level,
            task.range_start,
            task.range_end,
            &expected,
        )?;
        match node.entries {
            CheckpointManifestEntries::Chunks(entries) => {
                for entry in entries {
                    let context = ObjectContext::new(
                        archive_id,
                        commitment.database_epoch(),
                        commitment.key_epoch(),
                        ObjectRole::CheckpointChunkV3,
                        LogicalLocation::CheckpointChunk {
                            checkpoint_id,
                            chunk_index: entry.chunk_index,
                            logical_offset: entry.logical_offset,
                            byte_len: entry.logical_byte_len,
                        },
                        entry.reference.object_id,
                        None,
                    )?;
                    let envelope = load_exact_envelope(backend, &context, &entry.reference).await?;
                    let plaintext = Zeroizing::new(cipher.open(&context, &envelope)?);
                    if plaintext.len() != entry.logical_byte_len as usize
                        || <[u8; 32]>::from(Sha256::digest(plaintext.as_slice()))
                            != entry.plaintext_hash
                    {
                        return Err(ArchiveV3Error::Authentication.into());
                    }
                    database_hash.update(plaintext.as_slice());
                    sink.write_exact(entry.logical_offset, plaintext.as_slice())?;
                }
            }
            CheckpointManifestEntries::Children(children) => {
                if stack.len().saturating_add(children.len()) > MAX_RECOVERY_MANIFEST_STACK {
                    return Err(ArchiveV3Error::TooLarge("checkpoint recovery stack").into());
                }
                for child in children.into_iter().rev() {
                    stack.push(ManifestTask {
                        level: task
                            .level
                            .checked_sub(1)
                            .ok_or(ArchiveV3Error::Malformed("checkpoint child level"))?,
                        range_start: child.range_start,
                        range_end: child.range_end,
                        reference: child.reference,
                    });
                }
            }
        }
    }
    if <[u8; 32]>::from(database_hash.finalize()) != expected_hash {
        return Err(ArchiveV3Error::Authentication.into());
    }
    sink.commit(root.logical_file_length)?;
    Ok(UploadedCheckpoint {
        checkpoint_id,
        root: checkpoint_reference,
        logical_file_length: root.logical_file_length,
        total_chunks,
        database_plaintext_hash: expected_hash,
    })
}

#[derive(Clone)]
struct ManifestSpan {
    level: u8,
    range_start: u32,
    range_end: u32,
    reference: ImmutableReference,
}

struct ManifestTask {
    level: u8,
    range_start: u32,
    range_end: u32,
    reference: ImmutableReference,
}

struct ManifestExpectation {
    checkpoint_id: ObjectId,
    total_chunks: u32,
    logical_file_length: u64,
    database_plaintext_hash: [u8; 32],
}

fn validate_snapshot_length(length: u64) -> Result<u32> {
    if length == 0 || !length.is_multiple_of(u64::from(SQLITE_PAGE_SIZE)) {
        return Err(ArchiveV3Error::Malformed("checkpoint file length").into());
    }
    let chunks = length.div_ceil(u64::from(CHECKPOINT_CHUNK_BYTES));
    u32::try_from(chunks).map_err(|_| ArchiveV3Error::TooLarge("checkpoint chunk count").into())
}

fn manifest_tree_height(total_chunks: u32) -> Result<u8> {
    let leaf_count = total_chunks.div_ceil(MAX_CHECKPOINT_MANIFEST_FANOUT as u32);
    let mut height = 0u8;
    let mut capacity = 1u64;
    while capacity < u64::from(leaf_count) {
        capacity = capacity
            .checked_mul(MAX_CHECKPOINT_MANIFEST_FANOUT as u64)
            .ok_or(ArchiveV3Error::TooLarge("checkpoint manifest height"))?;
        height = height
            .checked_add(1)
            .ok_or(ArchiveV3Error::TooLarge("checkpoint manifest height"))?;
    }
    Ok(height)
}

fn hash_snapshot(
    source: &mut dyn CheckpointSource,
    logical_file_length: u64,
    total_chunks: u32,
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    for chunk_index in 0..total_chunks {
        let logical_offset = u64::from(chunk_index) * u64::from(CHECKPOINT_CHUNK_BYTES);
        let remaining = logical_file_length
            .checked_sub(logical_offset)
            .ok_or(ArchiveV3Error::Malformed("checkpoint offset"))?;
        let byte_len = remaining.min(u64::from(CHECKPOINT_CHUNK_BYTES)) as usize;
        let mut bytes = Zeroizing::new(vec![0u8; byte_len]);
        source.read_exact(logical_offset, bytes.as_mut_slice())?;
        hash.update(bytes.as_slice());
    }
    Ok(hash.finalize().into())
}

#[allow(clippy::too_many_arguments)]
async fn add_manifest_span<C: CheckpointCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    checkpoint_id: ObjectId,
    total_chunks: u32,
    logical_file_length: u64,
    tree_height: u8,
    pending: &mut [Vec<ManifestSpan>],
    root: &mut Option<ManifestSpan>,
    mut span: ManifestSpan,
    database_plaintext_hash: [u8; 32],
) -> Result<()> {
    loop {
        if span.level == tree_height {
            if root.replace(span).is_some() {
                return Err(ArchiveV3Error::Malformed("multiple checkpoint roots").into());
            }
            return Ok(());
        }
        let level = usize::from(span.level);
        let values = pending
            .get_mut(level)
            .ok_or(ArchiveV3Error::Malformed("checkpoint manifest level"))?;
        values.push(span);
        if values.len() < MAX_CHECKPOINT_MANIFEST_FANOUT {
            return Ok(());
        }
        let children = std::mem::take(values);
        span = seal_parent_manifest(
            backend,
            cipher,
            archive_id,
            database_epoch,
            checkpoint_id,
            total_chunks,
            logical_file_length,
            tree_height,
            level as u8,
            children,
            database_plaintext_hash,
        )
        .await?;
    }
}

#[allow(clippy::too_many_arguments)]
async fn seal_parent_manifest<C: CheckpointCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    checkpoint_id: ObjectId,
    total_chunks: u32,
    logical_file_length: u64,
    tree_height: u8,
    child_level: u8,
    children: Vec<ManifestSpan>,
    database_plaintext_hash: [u8; 32],
) -> Result<ManifestSpan> {
    let range_start = children
        .first()
        .ok_or(ArchiveV3Error::Malformed("empty checkpoint parent"))?
        .range_start;
    let range_end = children
        .last()
        .ok_or(ArchiveV3Error::Malformed("empty checkpoint parent"))?
        .range_end;
    let level = child_level
        .checked_add(1)
        .ok_or(ArchiveV3Error::TooLarge("checkpoint manifest height"))?;
    let entries = children
        .into_iter()
        .map(|child| CheckpointManifestChild {
            range_start: child.range_start,
            range_end: child.range_end,
            reference: child.reference,
        })
        .collect();
    seal_manifest(
        backend,
        cipher,
        archive_id,
        database_epoch,
        checkpoint_id,
        level,
        range_start,
        range_end,
        total_chunks,
        logical_file_length,
        database_plaintext_hash,
        CheckpointManifestEntries::Children(entries),
        level == tree_height,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn seal_manifest<C: CheckpointCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    checkpoint_id: ObjectId,
    level: u8,
    range_start: u32,
    range_end: u32,
    total_chunks: u32,
    logical_file_length: u64,
    database_plaintext_hash: [u8; 32],
    entries: CheckpointManifestEntries,
    is_root: bool,
) -> Result<ManifestSpan> {
    let object_id = if is_root {
        checkpoint_id
    } else {
        ObjectId::random()
    };
    let node = CheckpointManifestNode {
        checkpoint_id,
        level,
        range_start,
        range_end,
        total_chunks,
        logical_file_length,
        sqlite_page_size: SQLITE_PAGE_SIZE,
        database_plaintext_hash,
        entries,
    };
    let context = manifest_context(
        archive_id,
        database_epoch,
        cipher.key_epoch(),
        checkpoint_id,
        level,
        range_start,
        range_end,
        object_id,
    )?;
    let envelope = cipher.seal(&context, &node.encode()?)?;
    backend
        .create_if_absent(context.object_key(), envelope.clone())
        .await?;
    Ok(ManifestSpan {
        level,
        range_start,
        range_end,
        reference: ImmutableReference {
            object_id,
            envelope_hash: envelope.hash(),
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn manifest_context(
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: crate::archive_v3::KeyEpoch,
    checkpoint_id: ObjectId,
    level: u8,
    range_start: u32,
    range_end: u32,
    object_id: ObjectId,
) -> ArchiveResult<ObjectContext> {
    ObjectContext::new(
        archive_id,
        database_epoch,
        key_epoch,
        ObjectRole::CheckpointManifestV3,
        LogicalLocation::CheckpointManifest {
            checkpoint_id,
            level,
            range_start,
            range_end,
        },
        object_id,
        None,
    )
}

async fn load_exact_envelope(
    backend: &dyn ImmutableObjectBackend,
    context: &ObjectContext,
    reference: &ImmutableReference,
) -> Result<CiphertextEnvelope> {
    if context.object_id() != reference.object_id {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let envelope = backend
        .get(&context.object_key())
        .await?
        .ok_or(ShadowCheckpointError::MissingObject)?;
    if envelope.hash() != reference.envelope_hash {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(envelope)
}

async fn load_manifest<C: CheckpointCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    context: &ObjectContext,
    reference: &ImmutableReference,
) -> Result<CheckpointManifestNode> {
    let envelope = load_exact_envelope(backend, context, reference).await?;
    let plaintext = cipher.open(context, &envelope)?;
    let manifest = CheckpointManifestNode::decode(&plaintext)?;
    manifest.validate_for_context(context)?;
    Ok(manifest)
}

fn validate_manifest_shape(
    node: &CheckpointManifestNode,
    level: u8,
    range_start: u32,
    range_end: u32,
    expected: &ManifestExpectation,
) -> Result<()> {
    if node.checkpoint_id != expected.checkpoint_id
        || node.level != level
        || node.range_start != range_start
        || node.range_end != range_end
        || node.total_chunks != expected.total_chunks
        || node.logical_file_length != expected.logical_file_length
        || node.sqlite_page_size != SQLITE_PAGE_SIZE
        || node.database_plaintext_hash != expected.database_plaintext_hash
    {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn load_witness_root<C: CheckpointCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    reference: RootReference,
    parent: Option<RootReference>,
    database_epoch: DatabaseEpoch,
    key_epoch: crate::archive_v3::KeyEpoch,
    owner_fencing_epoch: u64,
) -> Result<crate::archive_v3::ArchiveRoot> {
    let parent = parent.map(|parent| ParentReference {
        object_id: parent.object_id(),
        envelope_hash: parent.ciphertext_hash(),
    });
    let context = ObjectContext::new(
        archive_id,
        database_epoch,
        key_epoch,
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: reference.sequence(),
        },
        reference.object_id(),
        parent,
    )?;
    let expected = ImmutableReference {
        object_id: reference.object_id(),
        envelope_hash: reference.ciphertext_hash(),
    };
    let envelope = load_exact_envelope(backend, &context, &expected).await?;
    let plaintext = cipher.open(&context, &envelope)?;
    let root = crate::archive_v3::ArchiveRoot::decode(&plaintext)?;
    root.validate_for_context(&context)?;
    if root.database_epoch != database_epoch
        || root.key_epoch != key_epoch
        || root.owner_fencing_epoch != owner_fencing_epoch
    {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(root)
}

/// Secure, atomic `/tmp` destination for future recovery wiring.  It writes a
/// private sibling temp file and hard-links it into the requested final path
/// only after all integrity checks succeed, so it never replaces an existing
/// file or leaves a trusted-looking partial database after `abort`.
pub struct TmpfsCheckpointSink {
    temporary_path: PathBuf,
    final_path: PathBuf,
    file: Option<File>,
    next_offset: u64,
    committed: bool,
}

impl TmpfsCheckpointSink {
    pub fn create(final_path: impl AsRef<Path>) -> Result<Self> {
        let final_path = final_path.as_ref();
        if !final_path.is_absolute()
            || final_path.exists()
            || final_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(ShadowCheckpointError::Sink);
        }
        let filename = final_path.file_name().ok_or(ShadowCheckpointError::Sink)?;
        let tmpfs_root = fs::canonicalize("/tmp").map_err(|_| ShadowCheckpointError::Sink)?;
        let supplied_parent = final_path.parent().ok_or(ShadowCheckpointError::Sink)?;
        // Only a direct child of the tmpfs root is accepted.  Accept the
        // `/tmp` spelling as well as its platform canonical spelling (for
        // example `/private/tmp` on macOS), but never a caller-controlled
        // nested directory whose rename/symlink state could change afterwards.
        if supplied_parent != Path::new("/tmp") && supplied_parent != tmpfs_root {
            return Err(ShadowCheckpointError::Sink);
        }
        let parent = fs::canonicalize(supplied_parent).map_err(|_| ShadowCheckpointError::Sink)?;
        if parent != tmpfs_root {
            return Err(ShadowCheckpointError::Sink);
        }
        let final_path = tmpfs_root.join(filename);
        for _ in 0..16 {
            let temporary_path = parent.join(format!(".kioku-v3-checkpoint-{}", random_suffix()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&temporary_path) {
                Ok(file) => {
                    return Ok(Self {
                        temporary_path,
                        final_path: final_path.clone(),
                        file: Some(file),
                        next_offset: 0,
                        committed: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ShadowCheckpointError::Sink),
            }
        }
        Err(ShadowCheckpointError::Sink)
    }
}

impl CheckpointSink for TmpfsCheckpointSink {
    fn write_exact(&mut self, logical_offset: u64, bytes: &[u8]) -> Result<()> {
        if logical_offset != self.next_offset || bytes.len() > CHECKPOINT_CHUNK_BYTES as usize {
            return Err(ShadowCheckpointError::Sink);
        }
        let file = self.file.as_mut().ok_or(ShadowCheckpointError::Sink)?;
        file.write_all(bytes)
            .map_err(|_| ShadowCheckpointError::Sink)?;
        self.next_offset = self
            .next_offset
            .checked_add(bytes.len() as u64)
            .ok_or(ShadowCheckpointError::Sink)?;
        Ok(())
    }

    fn commit(&mut self, logical_file_length: u64) -> Result<()> {
        if self.next_offset != logical_file_length || self.committed {
            return Err(ShadowCheckpointError::Sink);
        }
        let file = self.file.take().ok_or(ShadowCheckpointError::Sink)?;
        file.sync_data().map_err(|_| ShadowCheckpointError::Sink)?;
        fs::hard_link(&self.temporary_path, &self.final_path)
            .map_err(|_| ShadowCheckpointError::Sink)?;
        self.committed = true;
        // The final hard link is now durable enough to be considered success.
        // A later cleanup failure must not report recovery failure and make the
        // caller treat a valid final checkpoint as an untrusted partial file.
        let _ = fs::remove_file(&self.temporary_path);
        Ok(())
    }

    fn abort(&mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.temporary_path);
    }
}

impl Drop for TmpfsCheckpointSink {
    fn drop(&mut self) {
        self.abort();
    }
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut suffix = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    suffix
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Mutex};

    use super::*;
    use crate::{
        archive_v3::{
            ArchiveCipher, ArchiveDek, ArchiveRoot, CreateIfAbsent, InMemoryImmutableBackend,
            KeyEpoch, ObjectKey, ARCHIVE_FORMAT_VERSION,
        },
        archive_v3_witness::{
            InMemoryWitness, KeyRegistryReference, RootCommitment, RootReference, WitnessBootstrap,
        },
    };

    struct TestCipher {
        archive_id: ArchiveId,
        key_epoch: KeyEpoch,
        cipher: ArchiveCipher,
    }

    impl TestCipher {
        fn new(archive_id: ArchiveId, key_epoch: KeyEpoch) -> Self {
            Self {
                archive_id,
                key_epoch,
                cipher: ArchiveCipher::new(ArchiveDek::from_bytes([0x44; 32])),
            }
        }
    }

    impl CheckpointCipher for TestCipher {
        fn archive_id(&self) -> ArchiveId {
            self.archive_id
        }
        fn key_epoch(&self) -> KeyEpoch {
            self.key_epoch
        }
        fn seal(
            &self,
            context: &ObjectContext,
            plaintext: &[u8],
        ) -> ArchiveResult<CiphertextEnvelope> {
            if context.archive_id() != self.archive_id || context.key_epoch() != self.key_epoch {
                return Err(ArchiveV3Error::InvalidContext);
            }
            self.cipher.seal(context, plaintext)
        }
        fn open(
            &self,
            context: &ObjectContext,
            envelope: &CiphertextEnvelope,
        ) -> ArchiveResult<Vec<u8>> {
            if context.archive_id() != self.archive_id || context.key_epoch() != self.key_epoch {
                return Err(ArchiveV3Error::InvalidContext);
            }
            self.cipher.open(context, envelope)
        }
    }

    struct VecSource(Vec<u8>);
    impl CheckpointSource for VecSource {
        fn logical_file_length(&self) -> Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact(&mut self, offset: u64, destination: &mut [u8]) -> Result<()> {
            let start = usize::try_from(offset).map_err(|_| ShadowCheckpointError::Source)?;
            let end = start
                .checked_add(destination.len())
                .ok_or(ShadowCheckpointError::Source)?;
            let input = self
                .0
                .get(start..end)
                .ok_or(ShadowCheckpointError::Source)?;
            destination.copy_from_slice(input);
            Ok(())
        }
    }

    #[derive(Default)]
    struct VecSink {
        bytes: Vec<u8>,
        committed: bool,
        aborted: bool,
    }
    impl CheckpointSink for VecSink {
        fn write_exact(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
            if offset != self.bytes.len() as u64 {
                return Err(ShadowCheckpointError::Sink);
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }
        fn commit(&mut self, length: u64) -> Result<()> {
            if self.bytes.len() as u64 != length {
                return Err(ShadowCheckpointError::Sink);
            }
            self.committed = true;
            Ok(())
        }
        fn abort(&mut self) {
            self.aborted = true;
            self.bytes.clear();
        }
    }

    struct FaultBackend {
        inner: InMemoryImmutableBackend,
        fault: Mutex<Fault>,
    }
    #[derive(Clone, Copy, Default)]
    enum Fault {
        #[default]
        None,
        Missing(ObjectId),
        MissingFirstChunk,
        Tampered(ObjectId),
        Swap(ObjectId),
        Truncated(ObjectId),
    }
    impl FaultBackend {
        fn new() -> Self {
            Self {
                inner: InMemoryImmutableBackend::new(),
                fault: Mutex::new(Fault::None),
            }
        }
    }
    #[async_trait::async_trait]
    impl ImmutableObjectBackend for FaultBackend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: CiphertextEnvelope,
        ) -> ArchiveResult<CreateIfAbsent> {
            self.inner.create_if_absent(key, value).await
        }
        async fn get(&self, key: &ObjectKey) -> ArchiveResult<Option<CiphertextEnvelope>> {
            let fault = *self.fault.lock().unwrap();
            match fault {
                Fault::Missing(id) if id == key.object_id() => Ok(None),
                Fault::MissingFirstChunk if key.as_str().contains("/chunks/") => Ok(None),
                Fault::Tampered(id) if id == key.object_id() => Err(ArchiveV3Error::Authentication),
                Fault::Truncated(id) if id == key.object_id() => {
                    Err(ArchiveV3Error::Malformed("truncated immutable object"))
                }
                Fault::Swap(id) if id == key.object_id() => {
                    let mut other = None;
                    let prefix = crate::archive_v3::ArchivePrefix::for_archive(
                        ArchiveId::from_bytes([1; 16]),
                    );
                    let page = self
                        .inner
                        .enumerate(
                            &prefix,
                            None,
                            crate::archive_v3::EnumerationLimit::new(1_000)?,
                        )
                        .await?;
                    for candidate in page.objects {
                        if candidate.object_id() != id {
                            other = self.inner.get(&candidate).await?;
                            break;
                        }
                    }
                    Ok(other)
                }
                _ => self.inner.get(key).await,
            }
        }
        async fn enumerate(
            &self,
            prefix: &crate::archive_v3::ArchivePrefix,
            cursor: Option<&crate::archive_v3::EnumerationCursor>,
            limit: crate::archive_v3::EnumerationLimit,
        ) -> ArchiveResult<crate::archive_v3::EnumerationPage> {
            self.inner.enumerate(prefix, cursor, limit).await
        }
        async fn delete_exact(&self, key: &ObjectKey) -> ArchiveResult<bool> {
            self.inner.delete_exact(key).await
        }
    }

    fn ids() -> (ArchiveId, DatabaseEpoch, KeyEpoch) {
        (
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
        )
    }
    fn snapshot(chunks: usize) -> Vec<u8> {
        let mut bytes =
            vec![0u8; chunks * CHECKPOINT_CHUNK_BYTES as usize + SQLITE_PAGE_SIZE as usize];
        for (index, value) in bytes.iter_mut().enumerate() {
            *value = (index % 251) as u8;
        }
        bytes
    }

    async fn witness_for_checkpoint(
        backend: &dyn ImmutableObjectBackend,
        cipher: &TestCipher,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        uploaded: &UploadedCheckpoint,
    ) -> InMemoryWitness {
        let root_context = ObjectContext::new(
            archive_id,
            database_epoch,
            cipher.key_epoch(),
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ObjectId::from_bytes([0x77; 16]),
            None,
        )
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch: cipher.key_epoch(),
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: uploaded.logical_file_length(),
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: Some(uploaded.root().clone()),
            extent_tree_root: None,
            wal_chain_root: None,
        };
        let envelope = cipher.seal(&root_context, &root.encode().unwrap()).unwrap();
        backend
            .create_if_absent(root_context.object_key(), envelope.clone())
            .await
            .unwrap();
        let root_reference = RootReference::new(0, root_context.object_id(), envelope.hash());
        let registry = KeyRegistryReference::new(
            cipher.key_epoch(),
            0,
            ObjectId::from_bytes([0x66; 16]),
            [0x55; 32],
        );
        let bootstrap = WitnessBootstrap::new(
            archive_id,
            database_epoch,
            RootCommitment::genesis(database_epoch, cipher.key_epoch(), root_reference),
            registry,
        );
        let witness = InMemoryWitness::new();
        witness.bootstrap(bootstrap).unwrap();
        witness
    }

    #[tokio::test]
    async fn uploads_fixed_chunks_and_recovers_the_exact_witness_checkpoint() {
        let (archive_id, database_epoch, key_epoch) = ids();
        let cipher = TestCipher::new(archive_id, key_epoch);
        let backend = FaultBackend::new();
        let input = snapshot(2);
        let uploaded = upload_checkpoint(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            &mut VecSource(input.clone()),
        )
        .await
        .unwrap();
        assert_eq!(uploaded.total_chunks(), 3);
        assert_eq!(uploaded.root().object_id, uploaded.checkpoint_id());
        let witness =
            witness_for_checkpoint(&backend, &cipher, archive_id, database_epoch, &uploaded).await;
        let mut sink = VecSink::default();
        let recovered =
            recover_witness_checkpoint(&witness, &backend, &cipher, archive_id, &mut sink)
                .await
                .unwrap();
        assert_eq!(recovered, uploaded);
        assert_eq!(sink.bytes, input);
        assert!(sink.committed && !sink.aborted);
    }

    #[tokio::test]
    async fn witness_recovery_rejects_tampered_swapped_truncated_and_missing_objects() {
        let (archive_id, database_epoch, key_epoch) = ids();
        for fault_kind in 0..5 {
            let cipher = TestCipher::new(archive_id, key_epoch);
            let backend = FaultBackend::new();
            let uploaded = upload_checkpoint(
                &backend,
                &cipher,
                archive_id,
                database_epoch,
                &mut VecSource(snapshot(2)),
            )
            .await
            .unwrap();
            let witness =
                witness_for_checkpoint(&backend, &cipher, archive_id, database_epoch, &uploaded)
                    .await;
            *backend.fault.lock().unwrap() = match fault_kind {
                0 => Fault::Missing(uploaded.root().object_id),
                1 => Fault::Tampered(uploaded.root().object_id),
                2 => Fault::Swap(uploaded.root().object_id),
                3 => Fault::Truncated(uploaded.root().object_id),
                _ => Fault::MissingFirstChunk,
            };
            let mut sink = VecSink::default();
            assert!(
                recover_witness_checkpoint(&witness, &backend, &cipher, archive_id, &mut sink)
                    .await
                    .is_err()
            );
            assert!(sink.aborted && sink.bytes.is_empty());
        }
    }

    #[test]
    fn rejects_non_page_aligned_and_unbounded_snapshot_lengths() {
        assert!(matches!(
            validate_snapshot_length(0),
            Err(ShadowCheckpointError::Archive(_))
        ));
        assert!(matches!(
            validate_snapshot_length(1),
            Err(ShadowCheckpointError::Archive(_))
        ));
        assert_eq!(manifest_tree_height(1).unwrap(), 0);
        assert_eq!(manifest_tree_height(256).unwrap(), 0);
        assert_eq!(manifest_tree_height(257).unwrap(), 1);
        assert_eq!(manifest_tree_height(65_536).unwrap(), 1);
        assert_eq!(manifest_tree_height(65_537).unwrap(), 2);
        assert_eq!(
            manifest_tree_height(257 * MAX_CHECKPOINT_MANIFEST_FANOUT as u32).unwrap(),
            2
        );
    }

    fn tmpfs_test_path() -> PathBuf {
        PathBuf::from("/tmp").join(format!("kioku-v3-checkpoint-test-{}", random_suffix()))
    }

    #[test]
    fn tmpfs_sink_commits_atomically_and_abort_removes_only_staging() {
        let output = tmpfs_test_path();
        let mut sink = TmpfsCheckpointSink::create(&output).unwrap();
        let staging = sink.temporary_path.clone();
        sink.write_exact(0, b"checkpoint bytes").unwrap();
        sink.commit(16).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"checkpoint bytes");
        assert!(!staging.exists());
        sink.abort();
        assert!(output.exists());
        fs::remove_file(output).unwrap();

        let output = tmpfs_test_path();
        let mut sink = TmpfsCheckpointSink::create(&output).unwrap();
        let staging = sink.temporary_path.clone();
        sink.write_exact(0, b"partial").unwrap();
        sink.abort();
        assert!(!staging.exists());
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn tmpfs_sink_rejects_parent_components_and_symlink_escape() {
        assert!(TmpfsCheckpointSink::create("/tmp/../tmp/not-allowed").is_err());

        let nested =
            PathBuf::from("/tmp").join(format!("kioku-v3-checkpoint-dir-{}", random_suffix()));
        fs::create_dir(&nested).unwrap();
        assert!(TmpfsCheckpointSink::create(nested.join("nested.db")).is_err());
        fs::remove_dir(&nested).unwrap();

        let outside = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let link =
            PathBuf::from("/tmp").join(format!("kioku-v3-checkpoint-link-{}", random_suffix()));
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(TmpfsCheckpointSink::create(link.join("escaped.db")).is_err());
        fs::remove_file(link).unwrap();
    }
}
