#![allow(
    dead_code,
    reason = "inactive ADR-0022 extent tree is compiled and fake-tested before storage or authority wiring"
)]

//! Inactive, bounded ADR-0022 extent-tree upload and range recovery.
//!
//! This is a data-format seam, not a persistence path. It has no `Store`,
//! SQLite VFS, GCS provider/credential, witness, route, flag, or authority
//! connection. A crate-private mint accepts only an active [`RecoveryRoot`],
//! then reads, hashes, decrypts, and validates the exact [`ArchiveRoot`]
//! selected by the independent witness, and re-admits that exact current
//! witness state after the asynchronous object read before issuing the sealed
//! recovery capability. This module never lists storage.

use std::cmp::{max, min};

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::archive_v3::{
    ArchiveId, ArchiveRoot, ArchiveV3Error, CiphertextEnvelope, DatabaseEpoch, ExtentReference,
    ImmutableObjectBackend, ImmutableReference, KeyEpoch, LogicalLocation, MerkleChild,
    MerkleEntries, MerkleNode, ObjectContext, ObjectId, ObjectRole, ParentReference,
    Result as ArchiveResult, VerifiedArchiveCipher, MAX_DATABASE_BYTES, MAX_DATABASE_EXTENT_SLOTS,
    SQLITE_PAGE_SIZE,
};
use crate::archive_v3_shadow_checkpoint::{ShadowCheckpointError, ShadowObjectStaging};
use crate::archive_v3_witness::{DeletionState, ExactCurrentRecoveryAdmission, RecoveryRoot};

pub const EXTENT_BYTES: u32 = 1_048_576;
pub const MAX_RANGE_RECONSTRUCTION_BYTES: usize = EXTENT_BYTES as usize;
pub const MAX_EXTENT_TREE_DEPTH: u8 = 8;
pub const MAX_EXTENT_TREE_STACK: usize = 1_024;
/// Total immutable `get` operations (both nodes and extents) permitted for one
/// bounded reconstruction request.
pub const MAX_EXTENT_TREE_OBJECT_GETS_PER_RANGE: usize = 1_024;
/// The largest representable sparse extent tree has one object per extent,
/// 128 leaf nodes, and one root node. The separately staged root candidate
/// consumes the final shared attempt slot.
pub const MAX_EXTENT_TREE_STAGED_OBJECTS: usize = MAX_DATABASE_EXTENT_SLOTS as usize
    + (MAX_DATABASE_EXTENT_SLOTS as usize / crate::archive_v3::MAX_NODE_FANOUT)
    + 1;
const _: () = assert!(
    MAX_EXTENT_TREE_STAGED_OBJECTS < crate::archive_v3_operation::MAX_SHADOW_OBJECTS_PER_ATTEMPT
);

#[derive(Debug, Error)]
pub enum ExtentTreeError {
    #[error(transparent)]
    Archive(#[from] ArchiveV3Error),
    #[error("extent source did not produce a valid bounded stream")]
    Source,
    #[error(transparent)]
    Staging(#[from] ShadowCheckpointError),
    #[error("the exact immutable extent-tree object is absent")]
    MissingObject,
    #[error("extent range is outside the authenticated logical file")]
    Range,
}
pub type Result<T> = std::result::Result<T, ExtentTreeError>;

pub trait ExtentCipher: Send + Sync {
    fn archive_id(&self) -> ArchiveId;
    fn key_epoch(&self) -> KeyEpoch;
    fn seal(&self, context: &ObjectContext, plaintext: &[u8]) -> ArchiveResult<CiphertextEnvelope>;
    fn open(
        &self,
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
    ) -> ArchiveResult<Vec<u8>>;
}

impl ExtentCipher for crate::archive_v3::VerifiedArchiveCipher {
    fn archive_id(&self) -> ArchiveId {
        crate::archive_v3::VerifiedArchiveCipher::archive_id(self)
    }
    fn key_epoch(&self) -> KeyEpoch {
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

/// Omitted extent numbers are intentional all-zero sparse holes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceExtent {
    pub extent_no: u64,
    pub logical_byte_len: u32,
}

/// `next_extent` asynchronously returns strictly increasing extent numbers and
/// fills exactly `logical_byte_len` bytes at the start of the caller-owned 1 MiB
/// buffer. The caller clears that buffer before every invocation, so an
/// underfilling buggy source is deterministic (zero-filled) rather than able to
/// reuse prior extent bytes; it still violates this source contract.
#[async_trait::async_trait]
pub trait ExtentSource: Send {
    fn logical_file_length(&self) -> Result<u64>;
    async fn next_extent(&mut self, destination: &mut [u8]) -> Result<Option<SourceExtent>>;
}

/// Attempt-scoped immutable-object publication capability used by the extent
/// uploader. Implementations must preserve this indivisible order for every
/// object: durable exact reservation, immutable create, exact readback,
/// caller-supplied authenticated verification, then durable materialization.
/// A failed or cancelled verification must leave the object unmaterialized.
///
/// Static dispatch is intentional. It lets a future legacy-conversion attempt
/// provide its own durable, content-free binding without accepting or forging
/// the WAL-only [`ShadowSessionBinding`](crate::archive_v3_shadow_session::ShadowSessionBinding),
/// while keeping the verification callback inside the staging capability. The
/// private supertrait keeps implementations centralized in this module for
/// explicit review; callers cannot add an adapter that merely claims to honor
/// the ordering contract.
mod extent_staging_sealed {
    pub trait Sealed {}
}

#[async_trait::async_trait]
pub(crate) trait ExtentObjectStaging: extent_staging_sealed::Sealed + Send + Sync {
    async fn create_and_readback_verified<F>(
        &self,
        backend: &dyn ImmutableObjectBackend,
        context: &ObjectContext,
        envelope: CiphertextEnvelope,
        verify: F,
    ) -> Result<()>
    where
        F: FnOnce(&CiphertextEnvelope) -> ArchiveResult<()> + Send;
}

impl extent_staging_sealed::Sealed for ShadowObjectStaging<'_> {}

#[async_trait::async_trait]
impl ExtentObjectStaging for ShadowObjectStaging<'_> {
    async fn create_and_readback_verified<F>(
        &self,
        backend: &dyn ImmutableObjectBackend,
        context: &ObjectContext,
        envelope: CiphertextEnvelope,
        verify: F,
    ) -> Result<()>
    where
        F: FnOnce(&CiphertextEnvelope) -> ArchiveResult<()> + Send,
    {
        ShadowObjectStaging::create_and_readback_verified(self, backend, context, envelope, verify)
            .await?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct UploadedExtentTree {
    root: ImmutableReference,
    logical_file_length: u64,
    extent_slots: u64,
    tree_height: u8,
    extent_count: u64,
    sparse_content_commitment: [u8; 32],
}
impl UploadedExtentTree {
    pub fn root(&self) -> &ImmutableReference {
        &self.root
    }
    pub const fn logical_file_length(&self) -> u64 {
        self.logical_file_length
    }
    pub const fn extent_slots(&self) -> u64 {
        self.extent_slots
    }
    pub const fn tree_height(&self) -> u8 {
        self.tree_height
    }
    pub const fn extent_count(&self) -> u64 {
        self.extent_count
    }
    /// Domain-separated commitment to this sparse source stream, including
    /// its logical length, stored extent numbers, lengths, and bytes. It is
    /// not a hash of a logical SQLite image because omitted sparse holes are
    /// represented by their absence rather than hashed zero-filled bytes.
    pub const fn sparse_content_commitment(&self) -> [u8; 32] {
        self.sparse_content_commitment
    }
}
impl std::fmt::Debug for UploadedExtentTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UploadedExtentTree(<opaque>)")
    }
}

/// Exact root facts minted only from an independently witness-selected and
/// readback-authenticated root object. No generic production constructor
/// exists.
#[derive(Clone, Debug)]
pub struct AuthenticatedExtentRoot {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
    root: ImmutableReference,
    logical_file_length: u64,
    extent_slots: u64,
    tree_height: u8,
}
impl AuthenticatedExtentRoot {
    /// Test-only fixture constructor. Production code cannot turn a raw root
    /// into recovery authority.
    #[cfg(test)]
    fn from_test_verified_archive_root(archive_id: ArchiveId, root: &ArchiveRoot) -> Result<Self> {
        root.validate()?;
        let extent_slots = extent_slots(root.logical_file_length)?;
        Ok(Self {
            archive_id,
            database_epoch: root.database_epoch,
            key_epoch: root.key_epoch,
            root: root
                .extent_tree_root
                .as_ref()
                .ok_or(ArchiveV3Error::Malformed("root has no extent tree"))?
                .clone(),
            logical_file_length: root.logical_file_length,
            extent_slots,
            tree_height: extent_tree_height(extent_slots)?,
        })
    }
    pub fn root(&self) -> &ImmutableReference {
        &self.root
    }
    pub const fn logical_file_length(&self) -> u64 {
        self.logical_file_length
    }
}

/// Mint the sealed extent-recovery capability from the active exact root named
/// by the witness. This re-admits the exact current witness state before and
/// after one exact object read, and never enumerates or deletes storage. The
/// resolved archive cipher is itself bound to the exact witness registry
/// object/hash before this function can use it.
pub(crate) async fn mint_authenticated_extent_root(
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    recovery: &RecoveryRoot,
    admission: &dyn ExactCurrentRecoveryAdmission,
) -> Result<AuthenticatedExtentRoot> {
    let commitment = recovery.root();
    let registry = recovery.registry();
    if recovery.deletion() != DeletionState::Active
        || cipher.archive_id() != recovery.archive_id()
        || cipher.key_epoch() != commitment.key_epoch()
        || commitment.key_epoch() != registry.key_epoch()
        || cipher.registry_rotation_generation() != registry.rotation_generation()
        || cipher.registry_object_id() != registry.object_id()
        || cipher.registry_ciphertext_hash() != registry.ciphertext_hash()
    {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    admission
        .admit_exact_current(recovery)
        .await
        .map_err(|_| ArchiveV3Error::InvalidContext)?;

    let root_reference = commitment.root();
    let parent = commitment.parent().map(|parent| ParentReference {
        object_id: parent.object_id(),
        envelope_hash: parent.ciphertext_hash(),
    });
    let context = ObjectContext::new(
        recovery.archive_id(),
        commitment.database_epoch(),
        commitment.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: root_reference.sequence(),
        },
        root_reference.object_id(),
        parent,
    )?;
    let envelope = load_exact(
        backend,
        &context,
        &ImmutableReference {
            object_id: root_reference.object_id(),
            envelope_hash: root_reference.ciphertext_hash(),
        },
    )
    .await?;
    let plaintext = Zeroizing::new(cipher.open(&context, &envelope)?);
    let root = ArchiveRoot::decode(plaintext.as_slice())?;
    root.validate_for_context(&context)?;
    if root.root_seq != root_reference.sequence()
        || root.parent.as_ref() != context.parent()
        || root.database_epoch != commitment.database_epoch()
        || root.key_epoch != commitment.key_epoch()
        || root.owner_fencing_epoch != commitment.owner_fencing_epoch()
    {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let logical_file_length = root.logical_file_length;
    let root = root
        .extent_tree_root
        .ok_or(ArchiveV3Error::Malformed("root has no extent tree"))?;
    let extent_slots = extent_slots(logical_file_length)?;
    admission
        .admit_exact_current(recovery)
        .await
        .map_err(|_| ArchiveV3Error::InvalidContext)?;
    Ok(AuthenticatedExtentRoot {
        archive_id: recovery.archive_id(),
        database_epoch: commitment.database_epoch(),
        key_epoch: commitment.key_epoch(),
        root,
        logical_file_length,
        extent_slots,
        tree_height: extent_tree_height(extent_slots)?,
    })
}

/// Streams bounded immutable extent objects and fixed-fanout persistent nodes.
/// Sparse holes have no object and reconstruct as zeroes. An all-hole file is
/// rejected: the existing on-wire Merkle codec deliberately has no empty root.
pub(crate) async fn upload_extent_tree<C: ExtentCipher, S: ExtentObjectStaging>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    source: &mut dyn ExtentSource,
    staging: S,
) -> Result<UploadedExtentTree> {
    if cipher.archive_id() != archive_id {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let logical_file_length = source.logical_file_length()?;
    let slots = extent_slots(logical_file_length)?;
    let tree_height = extent_tree_height(slots)?;
    let mut buffer = Zeroizing::new(vec![0u8; EXTENT_BYTES as usize]);
    let mut leaves = Vec::with_capacity(crate::archive_v3::MAX_NODE_FANOUT);
    let mut pending: Vec<Vec<NodeSpan>> =
        (0..usize::from(tree_height)).map(|_| Vec::new()).collect();
    let mut root = None;
    let mut last = None;
    let mut count = 0u64;
    let mut sparse_content_commitment = Sha256::new();
    sparse_content_commitment.update(b"kioku:archive:v3:sparse-extent-content\0");
    sparse_content_commitment.update([crate::archive_v3::ARCHIVE_FORMAT_VERSION]);
    sparse_content_commitment.update(logical_file_length.to_be_bytes());
    loop {
        // The trait requires an exact fill. Clearing nevertheless makes an
        // underfilling buggy source deterministic rather than allowing bytes
        // from a prior extent to cross an immutable object boundary.
        buffer.fill(0);
        let Some(item) = source.next_extent(buffer.as_mut_slice()).await? else {
            break;
        };
        validate_source_extent(item, slots, logical_file_length, last)?;
        let bytes = &buffer[..item.logical_byte_len as usize];
        let object_id = ObjectId::random();
        let context = extent_context(
            archive_id,
            database_epoch,
            cipher.key_epoch(),
            item.extent_no,
            item.logical_byte_len,
            object_id,
        )?;
        let envelope = cipher.seal(&context, bytes)?;
        staging
            .create_and_readback_verified(backend, &context, envelope.clone(), |readback| {
                verify_staged_extent(cipher, &context, bytes, readback)
            })
            .await?;
        let reference = ImmutableReference {
            object_id,
            envelope_hash: envelope.hash(),
        };
        sparse_content_commitment.update(item.extent_no.to_be_bytes());
        sparse_content_commitment.update(item.logical_byte_len.to_be_bytes());
        sparse_content_commitment.update(bytes);
        leaves.push(ExtentReference {
            extent_no: item.extent_no,
            logical_byte_len: item.logical_byte_len,
            revision: 1,
            reference,
        });
        last = Some(item.extent_no);
        count = count
            .checked_add(1)
            .ok_or(ArchiveV3Error::TooLarge("extent count"))?;
        if leaves.len() == crate::archive_v3::MAX_NODE_FANOUT {
            let span = seal_leaf(
                backend,
                cipher,
                archive_id,
                database_epoch,
                std::mem::take(&mut leaves),
                tree_height == 0,
                slots,
                &staging,
            )
            .await?;
            add_span(
                backend,
                cipher,
                archive_id,
                database_epoch,
                slots,
                tree_height,
                &mut pending,
                &mut root,
                span,
                &staging,
            )
            .await?;
        }
    }
    if !leaves.is_empty() {
        let span = seal_leaf(
            backend,
            cipher,
            archive_id,
            database_epoch,
            std::mem::take(&mut leaves),
            tree_height == 0,
            slots,
            &staging,
        )
        .await?;
        add_span(
            backend,
            cipher,
            archive_id,
            database_epoch,
            slots,
            tree_height,
            &mut pending,
            &mut root,
            span,
            &staging,
        )
        .await?;
    }
    for level in 0..usize::from(tree_height) {
        if !pending[level].is_empty() {
            let span = seal_parent(
                backend,
                cipher,
                archive_id,
                database_epoch,
                std::mem::take(&mut pending[level]),
                level as u8,
                level + 1 == usize::from(tree_height),
                slots,
                &staging,
            )
            .await?;
            add_span(
                backend,
                cipher,
                archive_id,
                database_epoch,
                slots,
                tree_height,
                &mut pending,
                &mut root,
                span,
                &staging,
            )
            .await?;
        }
    }
    let root = root.ok_or(ArchiveV3Error::Malformed("empty extent tree"))?;
    if root.level != tree_height || root.range_start != 0 || root.range_end != slots {
        return Err(ArchiveV3Error::Malformed("extent tree root").into());
    }
    Ok(UploadedExtentTree {
        root: root.reference,
        logical_file_length,
        extent_slots: slots,
        tree_height,
        extent_count: count,
        sparse_content_commitment: sparse_content_commitment.finalize().into(),
    })
}

/// Bounded no-list reconstruction. All bytes are staged in a zeroizing
/// caller-bounded scratch buffer and copied to `destination` only after every
/// selected object has authenticated, so failure or cancellation cannot expose
/// a trusted-looking partial reconstruction.
pub async fn reconstruct_extent_range<C: ExtentCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    root: &AuthenticatedExtentRoot,
    logical_offset: u64,
    destination: &mut [u8],
) -> Result<()> {
    if cipher.archive_id() != root.archive_id || cipher.key_epoch() != root.key_epoch {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    validate_database_length(root.logical_file_length)?;
    validate_range(root.logical_file_length, logical_offset, destination.len())?;
    if destination.is_empty() {
        return Ok(());
    }
    let mut staged = Zeroizing::new(vec![0u8; destination.len()]);
    let end = logical_offset
        .checked_add(destination.len() as u64)
        .ok_or(ExtentTreeError::Range)?;
    let first = logical_offset / u64::from(EXTENT_BYTES);
    let last = end.saturating_sub(1) / u64::from(EXTENT_BYTES);
    let mut stack = vec![NodeTask {
        level: root.tree_height,
        range_start: 0,
        range_end: root.extent_slots,
        reference: root.root.clone(),
    }];
    let mut budget = RecoveryGetBudget::default();
    while let Some(task) = stack.pop() {
        if stack.len() > MAX_EXTENT_TREE_STACK {
            return Err(ArchiveV3Error::TooLarge("extent traversal stack").into());
        }
        budget.consume()?;
        let context = node_context(
            root.archive_id,
            root.database_epoch,
            root.key_epoch,
            task.level,
            task.range_start,
            task.range_end,
            task.reference.object_id,
        )?;
        let node = load_node(backend, cipher, &context, &task.reference).await?;
        validate_node_shape(&node, task.level, task.range_start, task.range_end)?;
        match node.entries {
            MerkleEntries::Leaf(entries) => {
                for entry in entries {
                    if entry.extent_no >= first && entry.extent_no <= last {
                        validate_recovery_extent_reference(
                            &entry,
                            root.extent_slots,
                            root.logical_file_length,
                        )?;
                        copy_intersection(
                            backend,
                            cipher,
                            root,
                            &entry,
                            logical_offset,
                            end,
                            staged.as_mut_slice(),
                            &mut budget,
                        )
                        .await?;
                    }
                }
            }
            MerkleEntries::Internal(children) => {
                let next_level = task
                    .level
                    .checked_sub(1)
                    .ok_or(ArchiveV3Error::Malformed("extent child level"))?;
                for child in children.into_iter().rev() {
                    if overlaps(child.range_start, child.range_end, first, last + 1) {
                        if stack.len() >= MAX_EXTENT_TREE_STACK {
                            return Err(ArchiveV3Error::TooLarge("extent traversal stack").into());
                        }
                        stack.push(NodeTask {
                            level: next_level,
                            range_start: child.range_start,
                            range_end: child.range_end,
                            reference: child.reference,
                        });
                    }
                }
            }
        }
    }
    destination.copy_from_slice(staged.as_slice());
    Ok(())
}

struct NodeSpan {
    level: u8,
    range_start: u64,
    range_end: u64,
    reference: ImmutableReference,
}
struct NodeTask {
    level: u8,
    range_start: u64,
    range_end: u64,
    reference: ImmutableReference,
}
#[derive(Default)]
struct RecoveryGetBudget {
    gets: usize,
}
impl RecoveryGetBudget {
    fn consume(&mut self) -> Result<()> {
        self.gets = self
            .gets
            .checked_add(1)
            .ok_or(ArchiveV3Error::TooLarge("extent recovery object gets"))?;
        if self.gets > MAX_EXTENT_TREE_OBJECT_GETS_PER_RANGE {
            return Err(ArchiveV3Error::TooLarge("extent recovery object gets").into());
        }
        Ok(())
    }
}

fn extent_slots(length: u64) -> Result<u64> {
    validate_database_length(length)?;
    Ok(length.div_ceil(u64::from(EXTENT_BYTES)))
}
fn validate_database_length(length: u64) -> Result<()> {
    if length == 0 || !length.is_multiple_of(u64::from(SQLITE_PAGE_SIZE)) {
        return Err(ArchiveV3Error::Malformed("extent logical file length").into());
    }
    if length > MAX_DATABASE_BYTES {
        return Err(ArchiveV3Error::TooLarge("logical database").into());
    }
    Ok(())
}
fn extent_tree_height(slots: u64) -> Result<u8> {
    if slots == 0 || slots > MAX_DATABASE_EXTENT_SLOTS {
        return Err(ArchiveV3Error::TooLarge("extent tree slots").into());
    }
    let leaves = slots.div_ceil(crate::archive_v3::MAX_NODE_FANOUT as u64);
    let mut height = 0u8;
    let mut capacity = 1u64;
    while capacity < leaves {
        capacity = capacity
            .checked_mul(crate::archive_v3::MAX_NODE_FANOUT as u64)
            .ok_or(ArchiveV3Error::TooLarge("extent tree height"))?;
        height = height
            .checked_add(1)
            .ok_or(ArchiveV3Error::TooLarge("extent tree height"))?;
        if height > MAX_EXTENT_TREE_DEPTH {
            return Err(ArchiveV3Error::TooLarge("extent tree height").into());
        }
    }
    Ok(height)
}
fn validate_source_extent(
    item: SourceExtent,
    slots: u64,
    length: u64,
    last: Option<u64>,
) -> Result<()> {
    if item.logical_byte_len == 0
        || item.logical_byte_len > EXTENT_BYTES
        || !item.logical_byte_len.is_multiple_of(SQLITE_PAGE_SIZE)
        || item.extent_no >= slots
        || last.is_some_and(|previous| item.extent_no <= previous)
    {
        return Err(ExtentTreeError::Source);
    }
    let offset = item
        .extent_no
        .checked_mul(u64::from(EXTENT_BYTES))
        .ok_or(ExtentTreeError::Source)?;
    if u64::from(item.logical_byte_len)
        != min(
            length.checked_sub(offset).ok_or(ExtentTreeError::Source)?,
            u64::from(EXTENT_BYTES),
        )
    {
        return Err(ExtentTreeError::Source);
    }
    Ok(())
}
fn validate_recovery_extent_reference(
    entry: &ExtentReference,
    slots: u64,
    logical_file_length: u64,
) -> Result<()> {
    entry.validate()?;
    if entry.extent_no >= slots {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let offset = entry
        .extent_no
        .checked_mul(u64::from(EXTENT_BYTES))
        .ok_or(ArchiveV3Error::Authentication)?;
    let expected = min(
        logical_file_length
            .checked_sub(offset)
            .ok_or(ArchiveV3Error::Authentication)?,
        u64::from(EXTENT_BYTES),
    );
    if u64::from(entry.logical_byte_len) != expected {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(())
}
fn validate_range(length: u64, offset: u64, bytes: usize) -> Result<()> {
    if bytes > MAX_RANGE_RECONSTRUCTION_BYTES {
        return Err(ArchiveV3Error::TooLarge("extent range").into());
    }
    let end = offset
        .checked_add(bytes as u64)
        .ok_or(ExtentTreeError::Range)?;
    if offset > length || end > length {
        return Err(ExtentTreeError::Range);
    }
    Ok(())
}
fn overlaps(start: u64, end: u64, wanted_start: u64, wanted_end: u64) -> bool {
    start < wanted_end && wanted_start < end
}

#[allow(clippy::too_many_arguments)]
async fn seal_leaf<C: ExtentCipher, S: ExtentObjectStaging>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive: ArchiveId,
    epoch: DatabaseEpoch,
    entries: Vec<ExtentReference>,
    is_root: bool,
    slots: u64,
    staging: &S,
) -> Result<NodeSpan> {
    let first = entries.first().ok_or(ExtentTreeError::Source)?.extent_no;
    let last = entries
        .last()
        .ok_or(ExtentTreeError::Source)?
        .extent_no
        .checked_add(1)
        .ok_or(ArchiveV3Error::TooLarge("extent range"))?;
    seal_node(
        backend,
        cipher,
        archive,
        epoch,
        MerkleNode {
            level: 0,
            range_start: if is_root { 0 } else { first },
            range_end: if is_root { slots } else { last },
            entries: MerkleEntries::Leaf(entries),
        },
        staging,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn seal_parent<C: ExtentCipher, S: ExtentObjectStaging>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive: ArchiveId,
    epoch: DatabaseEpoch,
    spans: Vec<NodeSpan>,
    child_level: u8,
    is_root: bool,
    slots: u64,
    staging: &S,
) -> Result<NodeSpan> {
    let first = spans.first().ok_or(ExtentTreeError::Source)?.range_start;
    let last = spans.last().ok_or(ExtentTreeError::Source)?.range_end;
    let level = child_level
        .checked_add(1)
        .ok_or(ArchiveV3Error::TooLarge("extent tree height"))?;
    let entries = spans
        .into_iter()
        .map(|span| MerkleChild {
            range_start: span.range_start,
            range_end: span.range_end,
            reference: span.reference,
        })
        .collect();
    seal_node(
        backend,
        cipher,
        archive,
        epoch,
        MerkleNode {
            level,
            range_start: if is_root { 0 } else { first },
            range_end: if is_root { slots } else { last },
            entries: MerkleEntries::Internal(entries),
        },
        staging,
    )
    .await
}
async fn seal_node<C: ExtentCipher, S: ExtentObjectStaging>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive: ArchiveId,
    epoch: DatabaseEpoch,
    node: MerkleNode,
    staging: &S,
) -> Result<NodeSpan> {
    node.validate()?;
    let object_id = ObjectId::random();
    let context = node_context(
        archive,
        epoch,
        cipher.key_epoch(),
        node.level,
        node.range_start,
        node.range_end,
        object_id,
    )?;
    let envelope = cipher.seal(&context, &node.encode()?)?;
    staging
        .create_and_readback_verified(backend, &context, envelope.clone(), |readback| {
            verify_staged_node(cipher, &context, &node, readback)
        })
        .await?;
    let reference = ImmutableReference {
        object_id,
        envelope_hash: envelope.hash(),
    };
    Ok(NodeSpan {
        level: node.level,
        range_start: node.range_start,
        range_end: node.range_end,
        reference,
    })
}
#[allow(clippy::too_many_arguments)]
async fn add_span<C: ExtentCipher, S: ExtentObjectStaging>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive: ArchiveId,
    epoch: DatabaseEpoch,
    slots: u64,
    height: u8,
    pending: &mut [Vec<NodeSpan>],
    root: &mut Option<NodeSpan>,
    mut span: NodeSpan,
    staging: &S,
) -> Result<()> {
    loop {
        if span.level == height {
            if root.replace(span).is_some() {
                return Err(ArchiveV3Error::Malformed("multiple extent tree roots").into());
            }
            return Ok(());
        }
        let values = pending
            .get_mut(usize::from(span.level))
            .ok_or(ArchiveV3Error::Malformed("extent tree level"))?;
        values.push(span);
        if values.len() < crate::archive_v3::MAX_NODE_FANOUT {
            return Ok(());
        }
        let child_level = values
            .first()
            .ok_or(ArchiveV3Error::Malformed("empty extent parent"))?
            .level;
        span = seal_parent(
            backend,
            cipher,
            archive,
            epoch,
            std::mem::take(values),
            child_level,
            child_level + 1 == height,
            slots,
            staging,
        )
        .await?;
    }
}
fn extent_context(
    archive: ArchiveId,
    epoch: DatabaseEpoch,
    key: KeyEpoch,
    extent_no: u64,
    byte_len: u32,
    object_id: ObjectId,
) -> ArchiveResult<ObjectContext> {
    ObjectContext::new(
        archive,
        epoch,
        key,
        ObjectRole::ExtentV3,
        LogicalLocation::Extent {
            extent_no,
            byte_len,
        },
        object_id,
        None,
    )
}
fn node_context(
    archive: ArchiveId,
    epoch: DatabaseEpoch,
    key: KeyEpoch,
    level: u8,
    range_start: u64,
    range_end: u64,
    object_id: ObjectId,
) -> ArchiveResult<ObjectContext> {
    ObjectContext::new(
        archive,
        epoch,
        key,
        ObjectRole::MerkleNodeV3,
        LogicalLocation::MerkleNode {
            level,
            range_start,
            range_end,
        },
        object_id,
        None,
    )
}
async fn load_exact(
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
        .ok_or(ExtentTreeError::MissingObject)?;
    if envelope.hash() != reference.envelope_hash {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(envelope)
}
async fn load_node<C: ExtentCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    context: &ObjectContext,
    reference: &ImmutableReference,
) -> Result<MerkleNode> {
    let envelope = load_exact(backend, context, reference).await?;
    let plaintext = Zeroizing::new(cipher.open(context, &envelope)?);
    let node = MerkleNode::decode(plaintext.as_slice())?;
    if !matches!(context.location(), LogicalLocation::MerkleNode { level, range_start, range_end } if *level == node.level && *range_start == node.range_start && *range_end == node.range_end)
    {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    Ok(node)
}
fn verify_staged_extent<C: ExtentCipher>(
    cipher: &C,
    context: &ObjectContext,
    expected: &[u8],
    envelope: &CiphertextEnvelope,
) -> ArchiveResult<()> {
    let plaintext = Zeroizing::new(cipher.open(context, envelope)?);
    if plaintext.as_slice() != expected {
        return Err(ArchiveV3Error::Authentication);
    }
    Ok(())
}
fn verify_staged_node<C: ExtentCipher>(
    cipher: &C,
    context: &ObjectContext,
    expected: &MerkleNode,
    envelope: &CiphertextEnvelope,
) -> ArchiveResult<()> {
    let plaintext = Zeroizing::new(cipher.open(context, envelope)?);
    let node = MerkleNode::decode(plaintext.as_slice())?;
    if node != *expected || plaintext.as_slice() != expected.encode()?.as_slice() {
        return Err(ArchiveV3Error::Authentication);
    }
    node.validate()?;
    if !matches!(context.location(), LogicalLocation::MerkleNode { level, range_start, range_end } if *level == node.level && *range_start == node.range_start && *range_end == node.range_end)
    {
        return Err(ArchiveV3Error::InvalidContext);
    }
    Ok(())
}
fn validate_node_shape(node: &MerkleNode, level: u8, start: u64, end: u64) -> Result<()> {
    node.validate()?;
    if node.level != level || node.range_start != start || node.range_end != end {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn copy_intersection<C: ExtentCipher>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    root: &AuthenticatedExtentRoot,
    entry: &ExtentReference,
    requested_start: u64,
    requested_end: u64,
    destination: &mut [u8],
    budget: &mut RecoveryGetBudget,
) -> Result<()> {
    let extent_start = entry
        .extent_no
        .checked_mul(u64::from(EXTENT_BYTES))
        .ok_or(ArchiveV3Error::Malformed("extent offset"))?;
    let extent_end = extent_start
        .checked_add(u64::from(entry.logical_byte_len))
        .ok_or(ArchiveV3Error::Malformed("extent offset"))?;
    if extent_end > root.logical_file_length {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let context = extent_context(
        root.archive_id,
        root.database_epoch,
        root.key_epoch,
        entry.extent_no,
        entry.logical_byte_len,
        entry.reference.object_id,
    )?;
    budget.consume()?;
    let envelope = load_exact(backend, &context, &entry.reference).await?;
    let plaintext = Zeroizing::new(cipher.open(&context, &envelope)?);
    if plaintext.len() != entry.logical_byte_len as usize {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let copy_start = max(extent_start, requested_start);
    let copy_end = min(extent_end, requested_end);
    if copy_start < copy_end {
        let source_start =
            usize::try_from(copy_start - extent_start).map_err(|_| ExtentTreeError::Range)?;
        let source_end =
            usize::try_from(copy_end - extent_start).map_err(|_| ExtentTreeError::Range)?;
        let output_start =
            usize::try_from(copy_start - requested_start).map_err(|_| ExtentTreeError::Range)?;
        let output_end =
            usize::try_from(copy_end - requested_start).map_err(|_| ExtentTreeError::Range)?;
        destination[output_start..output_end].copy_from_slice(&plaintext[source_start..source_end]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{
        resolve_archive_cipher, ArchiveCipher, ArchiveDek, CreateIfAbsent,
        ExactKeyRegistryProvider, InMemoryImmutableBackend, KeyKind, KeyRegistryContext,
        KeyRegistryPlaintext, ObjectKey,
    };
    use crate::archive_v3_operation::{
        RecordOutcome, ShadowObjectFacts, ShadowObjectInventoryPage, MAX_SHADOW_OBJECTS_PER_ATTEMPT,
    };
    use crate::archive_v3_shadow_checkpoint::{ShadowObjectInventory, ShadowObjectInventoryError};
    use crate::archive_v3_shadow_session::{
        ShadowAttemptId, ShadowSessionBinding, ShadowSessionId,
    };
    use crate::archive_v3_witness::{
        deletion_driver_test_fixture, InMemoryWitness, KeyRegistryReference, RootCommitment,
        RootReference, Witness, WitnessBootstrap, WitnessError,
    };
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    };
    struct TestCipher {
        archive: ArchiveId,
        epoch: KeyEpoch,
        cipher: ArchiveCipher,
        seal_fault: Option<(usize, TestSealFault)>,
        seal_count: AtomicUsize,
        verify_events: Option<Arc<Mutex<Vec<&'static str>>>>,
    }
    #[derive(Clone, Copy)]
    enum TestSealFault {
        WrongPlaintext,
        WrongContext,
    }
    impl TestCipher {
        fn new(archive: ArchiveId, epoch: KeyEpoch) -> Self {
            Self {
                archive,
                epoch,
                cipher: ArchiveCipher::new(ArchiveDek::from_bytes([7; 32])),
                seal_fault: None,
                seal_count: AtomicUsize::new(0),
                verify_events: None,
            }
        }

        fn with_seal_fault(
            archive: ArchiveId,
            epoch: KeyEpoch,
            seal_index: usize,
            seal_fault: TestSealFault,
            verify_events: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                archive,
                epoch,
                cipher: ArchiveCipher::new(ArchiveDek::from_bytes([7; 32])),
                seal_fault: Some((seal_index, seal_fault)),
                seal_count: AtomicUsize::new(0),
                verify_events: Some(verify_events),
            }
        }

        fn with_verify_events(
            archive: ArchiveId,
            epoch: KeyEpoch,
            verify_events: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            let mut cipher = Self::new(archive, epoch);
            cipher.verify_events = Some(verify_events);
            cipher
        }
    }
    impl ExtentCipher for TestCipher {
        fn archive_id(&self) -> ArchiveId {
            self.archive
        }
        fn key_epoch(&self) -> KeyEpoch {
            self.epoch
        }
        fn seal(&self, c: &ObjectContext, p: &[u8]) -> ArchiveResult<CiphertextEnvelope> {
            let seal_index = self.seal_count.fetch_add(1, Ordering::Relaxed);
            match self.seal_fault.filter(|(index, _)| *index == seal_index) {
                Some((_, TestSealFault::WrongPlaintext)) => {
                    let mut wrong = Zeroizing::new(p.to_vec());
                    let byte = wrong
                        .first_mut()
                        .ok_or(ArchiveV3Error::Malformed("test plaintext"))?;
                    *byte ^= 0x01;
                    self.cipher.seal(c, wrong.as_slice())
                }
                Some((_, TestSealFault::WrongContext)) => {
                    let location = match c.location() {
                        LogicalLocation::Extent {
                            extent_no,
                            byte_len,
                        } => LogicalLocation::Extent {
                            extent_no: extent_no.saturating_add(1),
                            byte_len: *byte_len,
                        },
                        LogicalLocation::MerkleNode {
                            level,
                            range_start,
                            range_end,
                        } => LogicalLocation::MerkleNode {
                            level: *level,
                            range_start: *range_start,
                            range_end: range_end.saturating_add(1),
                        },
                        _ => return Err(ArchiveV3Error::InvalidContext),
                    };
                    let wrong = ObjectContext::new(
                        c.archive_id(),
                        c.database_epoch(),
                        c.key_epoch(),
                        c.role(),
                        location,
                        c.object_id(),
                        None,
                    )?;
                    self.cipher.seal(&wrong, p)
                }
                None => self.cipher.seal(c, p),
            }
        }
        fn open(&self, c: &ObjectContext, e: &CiphertextEnvelope) -> ArchiveResult<Vec<u8>> {
            if let Some(events) = &self.verify_events {
                events.lock().unwrap().push("verify");
            }
            self.cipher.open(c, e)
        }
    }
    struct VecSource {
        length: u64,
        entries: Vec<(u64, Vec<u8>)>,
        next: usize,
    }
    #[async_trait::async_trait]
    impl ExtentSource for VecSource {
        fn logical_file_length(&self) -> Result<u64> {
            Ok(self.length)
        }
        async fn next_extent(&mut self, output: &mut [u8]) -> Result<Option<SourceExtent>> {
            let Some((no, bytes)) = self.entries.get(self.next) else {
                return Ok(None);
            };
            self.next += 1;
            output[..bytes.len()].copy_from_slice(bytes);
            Ok(Some(SourceExtent {
                extent_no: *no,
                logical_byte_len: bytes.len() as u32,
            }))
        }
    }
    struct UnderfillingSource {
        next: u8,
    }

    /// A test source that can suspend an asynchronous upload before a chosen
    /// pull. It deliberately owns no extent-sized buffer: production owns and
    /// clears the sole bounded destination buffer.
    struct PausingSource {
        length: u64,
        entries: Vec<(u64, Vec<u8>)>,
        next: usize,
        pause_at: usize,
        entered: Option<tokio::sync::oneshot::Sender<()>>,
        resume: Option<tokio::sync::oneshot::Receiver<()>>,
    }
    #[async_trait::async_trait]
    impl ExtentSource for PausingSource {
        fn logical_file_length(&self) -> Result<u64> {
            Ok(self.length)
        }

        async fn next_extent(&mut self, output: &mut [u8]) -> Result<Option<SourceExtent>> {
            if self.next == self.pause_at {
                self.entered
                    .take()
                    .expect("test source pauses once")
                    .send(())
                    .expect("upload observes the source pause");
                self.resume
                    .take()
                    .expect("test source has a resume channel")
                    .await
                    .map_err(|_| ExtentTreeError::Source)?;
            }
            let Some((no, bytes)) = self.entries.get(self.next) else {
                return Ok(None);
            };
            self.next += 1;
            output[..bytes.len()].copy_from_slice(bytes);
            Ok(Some(SourceExtent {
                extent_no: *no,
                logical_byte_len: bytes.len() as u32,
            }))
        }
    }

    struct PointerTrackingSource {
        length: u64,
        entries: Vec<(u64, Vec<u8>)>,
        next: usize,
        destinations: Arc<Mutex<Vec<(usize, usize)>>>,
    }
    #[async_trait::async_trait]
    impl ExtentSource for PointerTrackingSource {
        fn logical_file_length(&self) -> Result<u64> {
            Ok(self.length)
        }

        async fn next_extent(&mut self, output: &mut [u8]) -> Result<Option<SourceExtent>> {
            self.destinations
                .lock()
                .unwrap()
                .push((output.as_ptr() as usize, output.len()));
            let Some((no, bytes)) = self.entries.get(self.next) else {
                return Ok(None);
            };
            self.next += 1;
            output[..bytes.len()].copy_from_slice(bytes);
            Ok(Some(SourceExtent {
                extent_no: *no,
                logical_byte_len: bytes.len() as u32,
            }))
        }
    }

    struct AcceptingInventory;
    #[async_trait::async_trait]
    impl ShadowObjectInventory for AcceptingInventory {
        async fn reserve_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
            Ok(RecordOutcome::Recorded)
        }

        async fn mark_materialized_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
            Ok(RecordOutcome::Recorded)
        }

        async fn load_exact_attempt_page(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _after_ordinal: Option<u32>,
        ) -> std::result::Result<ShadowObjectInventoryPage, ShadowObjectInventoryError> {
            Ok(ShadowObjectInventoryPage::empty())
        }
    }
    static ACCEPTING_INVENTORY: AcceptingInventory = AcceptingInventory;

    /// Deliberately has no shadow-session or WAL binding. This exercises the
    /// generic extent staging contract a legacy conversion attempt will use,
    /// while retaining the same ordered publication invariants.
    #[derive(Clone)]
    struct NonWalTestStaging {
        events: Arc<Mutex<Vec<&'static str>>>,
        next_ordinal: Arc<AtomicUsize>,
        materialized: Arc<AtomicUsize>,
        records: Arc<Mutex<Vec<(ShadowObjectFacts, bool)>>>,
        fail_materialize: Arc<AtomicBool>,
    }

    impl NonWalTestStaging {
        fn new(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                next_ordinal: Arc::new(AtomicUsize::new(0)),
                materialized: Arc::new(AtomicUsize::new(0)),
                records: Arc::new(Mutex::new(Vec::new())),
                fail_materialize: Arc::new(AtomicBool::new(false)),
            }
        }

        fn record_counts(&self) -> (usize, usize) {
            let records = self.records.lock().unwrap();
            (
                records.len(),
                records
                    .iter()
                    .filter(|(_, materialized)| *materialized)
                    .count(),
            )
        }
    }

    impl extent_staging_sealed::Sealed for NonWalTestStaging {}

    #[async_trait::async_trait]
    impl ExtentObjectStaging for NonWalTestStaging {
        async fn create_and_readback_verified<F>(
            &self,
            backend: &dyn ImmutableObjectBackend,
            context: &ObjectContext,
            envelope: CiphertextEnvelope,
            verify: F,
        ) -> Result<()>
        where
            F: FnOnce(&CiphertextEnvelope) -> ArchiveResult<()> + Send,
        {
            let ordinal = self
                .next_ordinal
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |ordinal| {
                    (ordinal < MAX_SHADOW_OBJECTS_PER_ATTEMPT).then_some(ordinal + 1)
                })
                .map_err(|_| {
                    ExtentTreeError::Staging(ShadowCheckpointError::Inventory(
                        ShadowObjectInventoryError::AttemptExhausted,
                    ))
                })?;
            let facts = ShadowObjectFacts::from_sealed(context, &envelope, ordinal as u32)
                .map_err(|_| ExtentTreeError::Source)?;
            {
                let mut records = self.records.lock().unwrap();
                if records.iter().any(|(existing, _)| existing == &facts) {
                    return Err(ExtentTreeError::Staging(ShadowCheckpointError::Inventory(
                        ShadowObjectInventoryError::Conflict,
                    )));
                }
                records.push((facts.clone(), false));
            }
            self.events.lock().unwrap().push("reserve");
            backend
                .create_if_absent(context.object_key(), envelope.clone())
                .await?;
            let readback = backend
                .get(&context.object_key())
                .await?
                .ok_or(ExtentTreeError::MissingObject)?;
            if readback != envelope {
                return Err(ArchiveV3Error::Authentication.into());
            }
            self.events.lock().unwrap().push("verify");
            verify(&readback)?;
            self.events.lock().unwrap().push("materialize");
            if self.fail_materialize.load(Ordering::Relaxed) {
                return Err(ExtentTreeError::Staging(ShadowCheckpointError::Inventory(
                    ShadowObjectInventoryError::Unavailable,
                )));
            }
            let mut records = self.records.lock().unwrap();
            let (_, materialized) = records
                .iter_mut()
                .find(|(reserved, _)| reserved == &facts)
                .ok_or({
                    ExtentTreeError::Staging(ShadowCheckpointError::Inventory(
                        ShadowObjectInventoryError::Conflict,
                    ))
                })?;
            if *materialized {
                return Err(ExtentTreeError::Staging(ShadowCheckpointError::Inventory(
                    ShadowObjectInventoryError::Conflict,
                )));
            }
            *materialized = true;
            self.materialized.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn staging_for(inventory: &dyn ShadowObjectInventory) -> ShadowObjectStaging<'_> {
        ShadowObjectStaging::new(
            inventory,
            ShadowSessionId::from_bytes([0x91; 16]),
            ShadowAttemptId::from_bytes([0x92; 16]),
            ShadowSessionBinding::new(
                [1; 16], [2; 16], 1, [3; 16], 1, [4; 16], [5; 32], 1, [6; 16], [7; 32], 1, [8; 16],
                [9; 32], 1, 1, 1, 1,
            )
            .unwrap(),
        )
    }

    fn staging() -> ShadowObjectStaging<'static> {
        staging_for(&ACCEPTING_INVENTORY)
    }

    struct EventInventory {
        events: Arc<Mutex<Vec<&'static str>>>,
        reserve_failure: bool,
        materialize_failure: bool,
        reserved: AtomicUsize,
        materialized: AtomicUsize,
    }
    impl EventInventory {
        fn new(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                reserve_failure: false,
                materialize_failure: false,
                reserved: AtomicUsize::new(0),
                materialized: AtomicUsize::new(0),
            }
        }

        fn rejecting(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                reserve_failure: true,
                materialize_failure: false,
                reserved: AtomicUsize::new(0),
                materialized: AtomicUsize::new(0),
            }
        }

        fn materialize_failing(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                reserve_failure: false,
                materialize_failure: true,
                reserved: AtomicUsize::new(0),
                materialized: AtomicUsize::new(0),
            }
        }
    }
    #[async_trait::async_trait]
    impl ShadowObjectInventory for EventInventory {
        async fn reserve_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
            self.events.lock().unwrap().push("reserve");
            if self.reserve_failure {
                Err(ShadowObjectInventoryError::Unavailable)
            } else {
                self.reserved.fetch_add(1, Ordering::Relaxed);
                Ok(RecordOutcome::Recorded)
            }
        }

        async fn mark_materialized_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
            self.events.lock().unwrap().push("materialize");
            if self.materialize_failure {
                return Err(ShadowObjectInventoryError::Unavailable);
            }
            self.materialized.fetch_add(1, Ordering::Relaxed);
            Ok(RecordOutcome::Recorded)
        }

        async fn load_exact_attempt_page(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _after_ordinal: Option<u32>,
        ) -> std::result::Result<ShadowObjectInventoryPage, ShadowObjectInventoryError> {
            Ok(ShadowObjectInventoryPage::empty())
        }
    }
    #[async_trait::async_trait]
    impl ExtentSource for UnderfillingSource {
        fn logical_file_length(&self) -> Result<u64> {
            Ok(u64::from(EXTENT_BYTES) * 2)
        }
        async fn next_extent(&mut self, output: &mut [u8]) -> Result<Option<SourceExtent>> {
            match self.next {
                0 => {
                    self.next = 1;
                    output.fill(0x7e);
                    Ok(Some(SourceExtent {
                        extent_no: 0,
                        logical_byte_len: EXTENT_BYTES,
                    }))
                }
                1 => {
                    self.next = 2;
                    output[..SQLITE_PAGE_SIZE as usize].fill(0x6e);
                    Ok(Some(SourceExtent {
                        extent_no: 1,
                        logical_byte_len: EXTENT_BYTES,
                    }))
                }
                _ => Ok(None),
            }
        }
    }
    const WRAPPED_REGISTRY: &[u8] = b"extent-root-test-registry";

    struct FakeKeyRegistryProvider {
        registry_object_id: ObjectId,
        plaintext: Vec<u8>,
    }
    #[async_trait::async_trait]
    impl ExactKeyRegistryProvider for FakeKeyRegistryProvider {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            destination: &mut [u8],
        ) -> ArchiveResult<usize> {
            if object_id != self.registry_object_id {
                return Err(ArchiveV3Error::InvalidContext);
            }
            destination[..WRAPPED_REGISTRY.len()].copy_from_slice(WRAPPED_REGISTRY);
            Ok(WRAPPED_REGISTRY.len())
        }

        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            wrapped_registry_ciphertext: &[u8],
            destination: &mut [u8],
        ) -> ArchiveResult<usize> {
            if wrapped_registry_ciphertext != WRAPPED_REGISTRY {
                return Err(ArchiveV3Error::InvalidContext);
            }
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }

    async fn verified_cipher(
        archive_id: ArchiveId,
        key_epoch: KeyEpoch,
        registry: KeyRegistryReference,
    ) -> VerifiedArchiveCipher {
        let context = KeyRegistryContext::with_rotation_generation(
            archive_id,
            KeyKind::Archive,
            key_epoch,
            registry.rotation_generation(),
        );
        let provider = FakeKeyRegistryProvider {
            registry_object_id: registry.object_id(),
            plaintext: KeyRegistryPlaintext::encode_archive(
                &context,
                &ArchiveDek::from_bytes([7; 32]),
            )
            .unwrap()
            .to_vec(),
        };
        resolve_archive_cipher(
            &context,
            registry.object_id(),
            registry.ciphertext_hash(),
            &provider,
        )
        .await
        .unwrap()
    }

    /// A deliberately get-only adapter. Any accidental enumerate/delete call
    /// fails the mint test immediately, while the exact read count remains
    /// observable.
    #[derive(Default)]
    struct ExactGetOnlyBackend {
        inner: InMemoryImmutableBackend,
        gets: AtomicUsize,
        enumerations: AtomicUsize,
        missing: AtomicBool,
        substitutions: Mutex<Option<CiphertextEnvelope>>,
        on_next_get: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    }
    #[async_trait::async_trait]
    impl ImmutableObjectBackend for ExactGetOnlyBackend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: CiphertextEnvelope,
        ) -> ArchiveResult<CreateIfAbsent> {
            self.inner.create_if_absent(key, value).await
        }

        async fn get(&self, key: &ObjectKey) -> ArchiveResult<Option<CiphertextEnvelope>> {
            self.gets.fetch_add(1, Ordering::Relaxed);
            if let Some(callback) = self.on_next_get.lock().unwrap().take() {
                callback();
            }
            if self.missing.load(Ordering::Relaxed) {
                return Ok(None);
            }
            if let Some(substitution) = self.substitutions.lock().unwrap().clone() {
                return Ok(Some(substitution));
            }
            self.inner.get(key).await
        }

        async fn enumerate(
            &self,
            _prefix: &crate::archive_v3::ArchivePrefix,
            _cursor: Option<&crate::archive_v3::EnumerationCursor>,
            _limit: crate::archive_v3::EnumerationLimit,
        ) -> ArchiveResult<crate::archive_v3::EnumerationPage> {
            self.enumerations.fetch_add(1, Ordering::Relaxed);
            Err(ArchiveV3Error::Authentication)
        }

        async fn delete_exact(&self, _key: &ObjectKey) -> ArchiveResult<bool> {
            panic!("the extent-root mint must never delete")
        }
    }

    fn root_fixture() -> ArchiveRoot {
        ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: DatabaseEpoch::from_bytes([2; 16]),
            key_epoch: KeyEpoch::from_bytes([3; 16]),
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([8; 16]),
                envelope_hash: [9; 32],
            }),
            wal_chain_root: None,
        }
    }

    async fn mint_fixture(
        wire_root: ArchiveRoot,
    ) -> (
        ExactGetOnlyBackend,
        VerifiedArchiveCipher,
        RecoveryRoot,
        Arc<InMemoryWitness>,
    ) {
        mint_fixture_bytes(wire_root.encode().unwrap(), false).await
    }

    async fn mint_fixture_bytes(
        wire_root: Vec<u8>,
        tamper_envelope: bool,
    ) -> (
        ExactGetOnlyBackend,
        VerifiedArchiveCipher,
        RecoveryRoot,
        Arc<InMemoryWitness>,
    ) {
        let archive = ArchiveId::from_bytes([1; 16]);
        let database = DatabaseEpoch::from_bytes([2; 16]);
        let key = KeyEpoch::from_bytes([3; 16]);
        let registry = KeyRegistryReference::new(
            key,
            0,
            ObjectId::from_bytes([4; 16]),
            Sha256::digest(WRAPPED_REGISTRY).into(),
        );
        let cipher = verified_cipher(archive, key, registry).await;
        let root_id = ObjectId::from_bytes([5; 16]);
        let context = ObjectContext::new(
            archive,
            database,
            key,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_id,
            None,
        )
        .unwrap();
        let mut envelope = cipher.seal(&context, &wire_root).unwrap();
        if tamper_envelope {
            let mut encoded = envelope.encode();
            *encoded.last_mut().unwrap() ^= 1;
            envelope = CiphertextEnvelope::decode(&encoded).unwrap();
        }
        let backend = ExactGetOnlyBackend::default();
        backend
            .create_if_absent(context.object_key(), envelope.clone())
            .await
            .unwrap();
        let witness = Arc::new(InMemoryWitness::new());
        witness
            .bootstrap(WitnessBootstrap::new(
                archive,
                database,
                RootCommitment::genesis(
                    database,
                    key,
                    RootReference::new(0, root_id, envelope.hash()),
                ),
                registry,
            ))
            .unwrap();
        let recovery = witness.recovery_root(archive).unwrap();
        (backend, cipher, recovery, witness)
    }

    async fn minted_sparse_root_fixture() -> (
        ExactGetOnlyBackend,
        VerifiedArchiveCipher,
        RecoveryRoot,
        Arc<InMemoryWitness>,
    ) {
        let archive = ArchiveId::from_bytes([1; 16]);
        let database = DatabaseEpoch::from_bytes([2; 16]);
        let key = KeyEpoch::from_bytes([3; 16]);
        let registry = KeyRegistryReference::new(
            key,
            0,
            ObjectId::from_bytes([4; 16]),
            Sha256::digest(WRAPPED_REGISTRY).into(),
        );
        let cipher = verified_cipher(archive, key, registry).await;
        let backend = ExactGetOnlyBackend::default();
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x6a))],
            next: 0,
        };
        let uploaded = upload_extent_tree(
            &backend,
            &TestCipher::new(archive, key),
            archive,
            database,
            &mut source,
            staging(),
        )
        .await
        .unwrap();
        let root_id = ObjectId::from_bytes([5; 16]);
        let context = ObjectContext::new(
            archive,
            database,
            key,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_id,
            None,
        )
        .unwrap();
        let mut root = root_fixture();
        root.logical_file_length = uploaded.logical_file_length();
        root.extent_tree_root = Some(uploaded.root().clone());
        let envelope = cipher.seal(&context, &root.encode().unwrap()).unwrap();
        backend
            .create_if_absent(context.object_key(), envelope.clone())
            .await
            .unwrap();
        let witness = Arc::new(InMemoryWitness::new());
        witness
            .bootstrap(WitnessBootstrap::new(
                archive,
                database,
                RootCommitment::genesis(
                    database,
                    key,
                    RootReference::new(0, root_id, envelope.hash()),
                ),
                registry,
            ))
            .unwrap();
        let recovery = witness.recovery_root(archive).unwrap();
        (backend, cipher, recovery, witness)
    }
    #[derive(Default)]
    struct FaultBackend {
        inner: InMemoryImmutableBackend,
        fault: Mutex<Fault>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    #[derive(Clone, Default)]
    enum Fault {
        #[default]
        None,
        Missing(ObjectId),
        Tamper(ObjectId),
        MissingOnRead(usize),
        TamperOnRead(usize),
        BlockOnRead(usize),
        CreateUnavailable,
        CreateReturnsAlreadyPresent,
        Substitute(ObjectId, CiphertextEnvelope),
        Block,
    }
    #[async_trait::async_trait]
    impl ImmutableObjectBackend for FaultBackend {
        async fn create_if_absent(
            &self,
            k: ObjectKey,
            v: CiphertextEnvelope,
        ) -> ArchiveResult<CreateIfAbsent> {
            self.events.lock().unwrap().push("create");
            if matches!(&*self.fault.lock().unwrap(), Fault::CreateUnavailable) {
                return Err(ArchiveV3Error::Unavailable);
            }
            let created = self.inner.create_if_absent(k, v).await?;
            if matches!(
                &*self.fault.lock().unwrap(),
                Fault::CreateReturnsAlreadyPresent
            ) {
                Ok(CreateIfAbsent::AlreadyPresentIdentical)
            } else {
                Ok(created)
            }
        }
        async fn get(&self, k: &ObjectKey) -> ArchiveResult<Option<CiphertextEnvelope>> {
            self.events.lock().unwrap().push("get");
            let one_shot = {
                let mut fault = self.fault.lock().unwrap();
                match &mut *fault {
                    Fault::MissingOnRead(reads) if *reads == 1 => {
                        *fault = Fault::None;
                        Some(1u8)
                    }
                    Fault::TamperOnRead(reads) if *reads == 1 => {
                        *fault = Fault::None;
                        Some(2u8)
                    }
                    Fault::BlockOnRead(reads) if *reads == 1 => {
                        *fault = Fault::None;
                        Some(3u8)
                    }
                    Fault::MissingOnRead(reads)
                    | Fault::TamperOnRead(reads)
                    | Fault::BlockOnRead(reads) => {
                        *reads -= 1;
                        None
                    }
                    _ => None,
                }
            };
            if let Some(action) = one_shot {
                match action {
                    1 => return Ok(None),
                    2 => {
                        let mut encoded = self
                            .inner
                            .get(k)
                            .await?
                            .ok_or(ArchiveV3Error::Authentication)?
                            .encode();
                        *encoded.last_mut().ok_or(ArchiveV3Error::Authentication)? ^= 0x01;
                        return Ok(Some(CiphertextEnvelope::decode(&encoded)?));
                    }
                    _ => return std::future::pending().await,
                }
            }
            let fault = { self.fault.lock().unwrap().clone() };
            match fault {
                Fault::Missing(id) if id == k.object_id() => Ok(None),
                Fault::Tamper(id) if id == k.object_id() => Err(ArchiveV3Error::Authentication),
                Fault::Substitute(id, value) if id == k.object_id() => Ok(Some(value)),
                Fault::Block => std::future::pending().await,
                _ => self.inner.get(k).await,
            }
        }
        async fn enumerate(
            &self,
            p: &crate::archive_v3::ArchivePrefix,
            c: Option<&crate::archive_v3::EnumerationCursor>,
            l: crate::archive_v3::EnumerationLimit,
        ) -> ArchiveResult<crate::archive_v3::EnumerationPage> {
            self.events.lock().unwrap().push("enumerate");
            self.inner.enumerate(p, c, l).await
        }
        async fn delete_exact(&self, k: &ObjectKey) -> ArchiveResult<bool> {
            self.events.lock().unwrap().push("delete");
            self.inner.delete_exact(k).await
        }
    }
    fn ids() -> (ArchiveId, DatabaseEpoch, KeyEpoch) {
        (
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
        )
    }
    fn bytes(pages: usize, byte: u8) -> Vec<u8> {
        vec![byte; pages * SQLITE_PAGE_SIZE as usize]
    }
    fn descriptor(
        archive: ArchiveId,
        database: DatabaseEpoch,
        key: KeyEpoch,
        uploaded: &UploadedExtentTree,
    ) -> AuthenticatedExtentRoot {
        AuthenticatedExtentRoot::from_test_verified_archive_root(
            archive,
            &ArchiveRoot {
                root_seq: 0,
                parent: None,
                database_epoch: database,
                key_epoch: key,
                owner_fencing_epoch: 0,
                sqlite_page_size: SQLITE_PAGE_SIZE,
                logical_file_length: uploaded.logical_file_length(),
                user_schema_version: 1,
                storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
                wal_generation: 0,
                wal_segment_count: 0,
                checkpoint_root: None,
                extent_tree_root: Some(uploaded.root().clone()),
                wal_chain_root: None,
            },
        )
        .unwrap()
    }
    async fn sparse_commitment(
        archive: ArchiveId,
        database: DatabaseEpoch,
        key: KeyEpoch,
        length: u64,
        entries: Vec<(u64, Vec<u8>)>,
    ) -> [u8; 32] {
        let cipher = TestCipher::new(archive, key);
        let backend = FaultBackend::default();
        let mut source = VecSource {
            length,
            entries,
            next: 0,
        };
        upload_extent_tree(&backend, &cipher, archive, database, &mut source, staging())
            .await
            .unwrap()
            .sparse_content_commitment()
    }

    #[tokio::test]
    async fn witness_recovery_root_mints_extent_capability_from_one_exact_get() {
        let (backend, cipher, recovery, witness) = mint_fixture(root_fixture()).await;

        let capability = mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
            .await
            .unwrap();

        assert_eq!(capability.root().object_id, ObjectId::from_bytes([8; 16]));
        assert_eq!(
            capability.logical_file_length(),
            u64::from(SQLITE_PAGE_SIZE)
        );
        assert_eq!(backend.gets.load(Ordering::Relaxed), 1);
        assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn witness_root_mint_requires_the_exact_authenticated_nonempty_root() {
        let (backend, cipher, recovery, witness) = mint_fixture(root_fixture()).await;
        backend.missing.store(true, Ordering::Relaxed);
        assert!(
            mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                .await
                .is_err()
        );
        assert_eq!(backend.gets.load(Ordering::Relaxed), 1);
        assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);

        let (backend, cipher, recovery, witness) =
            mint_fixture_bytes(root_fixture().encode().unwrap(), true).await;
        assert!(
            mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                .await
                .is_err()
        );
        assert_eq!(backend.gets.load(Ordering::Relaxed), 1);
        assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);

        let mut all_hole = root_fixture();
        all_hole.logical_file_length = 0;
        all_hole.extent_tree_root = None;
        let (backend, cipher, recovery, witness) = mint_fixture(all_hole).await;
        assert!(
            mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                .await
                .is_err()
        );
        assert_eq!(backend.gets.load(Ordering::Relaxed), 1);
        assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn witness_root_mint_retains_root_length_bounds_before_capability_issue() {
        let encoded = root_fixture().encode().unwrap();
        let mut over_capacity = encoded.clone();
        over_capacity[61..69]
            .copy_from_slice(&(MAX_DATABASE_BYTES + u64::from(SQLITE_PAGE_SIZE)).to_be_bytes());
        let mut misaligned = encoded;
        misaligned[61..69].copy_from_slice(&1u64.to_be_bytes());
        for malformed in [over_capacity, misaligned] {
            let (backend, cipher, recovery, witness) = mint_fixture_bytes(malformed, false).await;
            assert!(
                mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                    .await
                    .is_err()
            );
            assert_eq!(backend.gets.load(Ordering::Relaxed), 1);
            assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn witness_root_mint_rejects_envelope_and_root_field_substitutions() {
        let (backend, cipher, recovery, witness) = mint_fixture(root_fixture()).await;
        let substituted = cipher
            .seal(
                &ObjectContext::new(
                    recovery.archive_id(),
                    recovery.root().database_epoch(),
                    recovery.root().key_epoch(),
                    ObjectRole::RootV3,
                    LogicalLocation::Root { root_seq: 0 },
                    ObjectId::from_bytes([47; 16]),
                    None,
                )
                .unwrap(),
                b"substituted root envelope",
            )
            .unwrap();
        *backend.substitutions.lock().unwrap() = Some(substituted);
        assert!(
            mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                .await
                .is_err()
        );
        assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);

        let mut wrong_database = root_fixture();
        wrong_database.database_epoch = DatabaseEpoch::from_bytes([41; 16]);
        let mut wrong_key = root_fixture();
        wrong_key.key_epoch = KeyEpoch::from_bytes([42; 16]);
        let mut wrong_sequence_and_parent = root_fixture();
        wrong_sequence_and_parent.root_seq = 1;
        wrong_sequence_and_parent.parent = Some(ParentReference {
            object_id: ObjectId::from_bytes([43; 16]),
            envelope_hash: [44; 32],
        });
        let mut wrong_fence = root_fixture();
        wrong_fence.owner_fencing_epoch = 1;
        for root in [
            wrong_database,
            wrong_key,
            wrong_sequence_and_parent,
            wrong_fence,
        ] {
            let (backend, cipher, recovery, witness) = mint_fixture(root).await;
            assert!(
                mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                    .await
                    .is_err()
            );
            assert_eq!(backend.gets.load(Ordering::Relaxed), 1);
            assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);
        }

        let (backend, _cipher, recovery, witness) = mint_fixture(root_fixture()).await;
        let wrong_registry = KeyRegistryReference::new(
            recovery.registry().key_epoch(),
            recovery.registry().rotation_generation(),
            ObjectId::from_bytes([45; 16]),
            recovery.registry().ciphertext_hash(),
        );
        let wrong_registry_cipher = verified_cipher(
            recovery.archive_id(),
            recovery.root().key_epoch(),
            wrong_registry,
        )
        .await;
        assert!(mint_authenticated_extent_root(
            &backend,
            &wrong_registry_cipher,
            &recovery,
            &*witness
        )
        .await
        .is_err());
        assert_eq!(backend.gets.load(Ordering::Relaxed), 0);
        assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);

        let wrong_archive_cipher = verified_cipher(
            ArchiveId::from_bytes([46; 16]),
            recovery.root().key_epoch(),
            recovery.registry(),
        )
        .await;
        assert!(mint_authenticated_extent_root(
            &backend,
            &wrong_archive_cipher,
            &recovery,
            &*witness
        )
        .await
        .is_err());
        assert_eq!(backend.gets.load(Ordering::Relaxed), 0);
        assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn stale_recovery_snapshot_is_denied_before_any_object_read() {
        let (backend, cipher, recovery, witness) = mint_fixture(root_fixture()).await;
        let current = witness
            .read_current(recovery.archive_id())
            .unwrap()
            .unwrap();
        witness
            .replace_current_for_test(current.tombstoned_for_test())
            .unwrap();
        assert!(
            mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                .await
                .is_err()
        );
        assert_eq!(backend.gets.load(Ordering::Relaxed), 0);

        let (backend, cipher, recovery, witness) = mint_fixture(root_fixture()).await;
        let current = witness
            .read_current(recovery.archive_id())
            .unwrap()
            .unwrap();
        witness
            .replace_current_for_test(current.with_candidate_root_for_test(
                RootReference::new(1, ObjectId::from_bytes([48; 16]), [49; 32]),
                1,
            ))
            .unwrap();
        assert!(
            mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                .await
                .is_err()
        );
        assert_eq!(backend.gets.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn final_witness_reread_denies_tombstone_racing_the_exact_get() {
        let (backend, cipher, recovery, witness) = mint_fixture(root_fixture()).await;
        let race_witness = Arc::clone(&witness);
        let race_archive = recovery.archive_id();
        *backend.on_next_get.lock().unwrap() = Some(Arc::new(move || {
            let current = race_witness.read_current(race_archive).unwrap().unwrap();
            race_witness
                .replace_current_for_test(current.tombstoned_for_test())
                .unwrap();
        }));
        assert!(
            mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
                .await
                .is_err()
        );
        assert_eq!(backend.gets.load(Ordering::Relaxed), 1);
        assert_eq!(backend.enumerations.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn deletion_closure_cannot_supply_a_recovery_root_to_the_mint() {
        let fixture = deletion_driver_test_fixture();
        let archive = fixture.tombstone.receipt().record().archive_id();
        assert_eq!(
            fixture.witness.recovery_root(archive),
            Err(WitnessError::InvalidTransition)
        );
    }

    #[tokio::test]
    async fn minted_capability_keeps_reconstruction_output_transactional() {
        let (backend, cipher, recovery, witness) = minted_sparse_root_fixture().await;
        let capability = mint_authenticated_extent_root(&backend, &cipher, &recovery, &*witness)
            .await
            .unwrap();
        let mut successful_output = vec![0; SQLITE_PAGE_SIZE as usize];
        reconstruct_extent_range(&backend, &cipher, &capability, 0, &mut successful_output)
            .await
            .unwrap();
        assert_eq!(successful_output, vec![0x6a; SQLITE_PAGE_SIZE as usize]);
        let context = node_context(
            recovery.archive_id(),
            recovery.root().database_epoch(),
            recovery.root().key_epoch(),
            capability.tree_height,
            0,
            capability.extent_slots,
            capability.root.object_id,
        )
        .unwrap();
        *backend.substitutions.lock().unwrap() =
            Some(cipher.seal(&context, b"wrong node").unwrap());
        let mut output = vec![0xa5; SQLITE_PAGE_SIZE as usize];
        assert!(
            reconstruct_extent_range(&backend, &cipher, &capability, 0, &mut output)
                .await
                .is_err()
        );
        assert_eq!(output, vec![0xa5; SQLITE_PAGE_SIZE as usize]);
    }

    #[tokio::test]
    async fn sparse_content_commitment_binds_length_position_and_data() {
        let (a, d, k) = ids();
        let base =
            sparse_commitment(a, d, k, u64::from(EXTENT_BYTES), vec![(0, bytes(256, 1))]).await;
        let length = sparse_commitment(
            a,
            d,
            k,
            u64::from(EXTENT_BYTES) * 2,
            vec![(0, bytes(256, 1))],
        )
        .await;
        let position = sparse_commitment(
            a,
            d,
            k,
            u64::from(EXTENT_BYTES) * 2,
            vec![(1, bytes(256, 1))],
        )
        .await;
        let data =
            sparse_commitment(a, d, k, u64::from(EXTENT_BYTES), vec![(0, bytes(256, 2))]).await;
        assert_ne!(base, length);
        assert_ne!(length, position);
        assert_ne!(base, data);
    }
    #[tokio::test]
    async fn max_database_geometry_accepts_a_high_sparse_extent_and_rejects_over_cap() {
        let (a, d, k) = ids();
        assert_eq!(
            MAX_DATABASE_BYTES / u64::from(SQLITE_PAGE_SIZE),
            u64::from(crate::archive_v3::MAX_DATABASE_PAGES)
        );
        assert_eq!(MAX_EXTENT_TREE_STAGED_OBJECTS, 32_897);
        assert_eq!(
            MAX_EXTENT_TREE_STAGED_OBJECTS + 1,
            MAX_SHADOW_OBJECTS_PER_ATTEMPT
        );
        assert_eq!(extent_tree_height(255).unwrap(), 0);
        assert_eq!(extent_tree_height(256).unwrap(), 0);
        assert_eq!(extent_tree_height(257).unwrap(), 1);
        assert_eq!(
            extent_tree_height(MAX_DATABASE_BYTES / u64::from(EXTENT_BYTES)).unwrap(),
            1
        );
        assert!(extent_tree_height(MAX_DATABASE_BYTES / u64::from(EXTENT_BYTES) + 1).is_err());
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let last_extent = MAX_DATABASE_BYTES / u64::from(EXTENT_BYTES) - 1;
        let mut source = VecSource {
            length: MAX_DATABASE_BYTES,
            entries: vec![(last_extent, bytes(256, 0x4c))],
            next: 0,
        };
        let uploaded = upload_extent_tree(&backend, &cipher, a, d, &mut source, staging())
            .await
            .unwrap();
        let root = descriptor(a, d, k, &uploaded);
        let mut output = vec![0; SQLITE_PAGE_SIZE as usize];
        reconstruct_extent_range(
            &backend,
            &cipher,
            &root,
            last_extent * u64::from(EXTENT_BYTES),
            &mut output,
        )
        .await
        .unwrap();
        assert_eq!(output, vec![0x4c; SQLITE_PAGE_SIZE as usize]);
        let mut rejected = VecSource {
            length: MAX_DATABASE_BYTES + u64::from(SQLITE_PAGE_SIZE),
            entries: Vec::new(),
            next: 0,
        };
        assert!(
            upload_extent_tree(&backend, &cipher, a, d, &mut rejected, staging())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn all_hole_and_underfilled_sources_are_deterministic() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let mut all_hole = VecSource {
            length: u64::from(SQLITE_PAGE_SIZE),
            entries: Vec::new(),
            next: 0,
        };
        assert!(
            upload_extent_tree(&backend, &cipher, a, d, &mut all_hole, staging())
                .await
                .is_err()
        );
        let mut underfilled = UnderfillingSource { next: 0 };
        let uploaded = upload_extent_tree(&backend, &cipher, a, d, &mut underfilled, staging())
            .await
            .unwrap();
        let root = descriptor(a, d, k, &uploaded);
        let mut output = vec![0xff; SQLITE_PAGE_SIZE as usize];
        reconstruct_extent_range(
            &backend,
            &cipher,
            &root,
            u64::from(EXTENT_BYTES) + u64::from(SQLITE_PAGE_SIZE),
            &mut output,
        )
        .await
        .unwrap();
        assert_eq!(output, vec![0; SQLITE_PAGE_SIZE as usize]);
    }
    #[tokio::test]
    async fn reconstruction_failure_or_cancellation_never_changes_caller_output() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES) * 2,
            entries: vec![(0, bytes(256, 0x11)), (1, bytes(256, 0x22))],
            next: 0,
        };
        let uploaded = upload_extent_tree(&backend, &cipher, a, d, &mut source, staging())
            .await
            .unwrap();
        let root = descriptor(a, d, k, &uploaded);
        for fault in [Fault::MissingOnRead(3), Fault::TamperOnRead(3)] {
            *backend.fault.lock().unwrap() = fault;
            let mut output = vec![0xa5; 8192];
            assert!(reconstruct_extent_range(
                &backend,
                &cipher,
                &root,
                u64::from(EXTENT_BYTES) - 4096,
                &mut output,
            )
            .await
            .is_err());
            assert_eq!(output, vec![0xa5; 8192]);
        }
        *backend.fault.lock().unwrap() = Fault::BlockOnRead(3);
        let mut output = vec![0xa5; 8192];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            reconstruct_extent_range(
                &backend,
                &cipher,
                &root,
                u64::from(EXTENT_BYTES) - 4096,
                &mut output,
            ),
        )
        .await
        .is_err());
        assert_eq!(output, vec![0xa5; 8192]);
    }
    #[tokio::test]
    async fn extent_and_node_each_reserve_create_read_back_and_materialize_before_linking() {
        let (a, d, k) = ids();
        let backend = FaultBackend::default();
        let cipher = TestCipher::with_verify_events(a, k, Arc::clone(&backend.events));
        let inventory = EventInventory::new(Arc::clone(&backend.events));
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x71))],
            next: 0,
        };
        upload_extent_tree(
            &backend,
            &cipher,
            a,
            d,
            &mut source,
            staging_for(&inventory),
        )
        .await
        .unwrap();
        // One source extent produces exactly one leaf/root node at this
        // geometry, so the two complete sequences prove both kinds of object
        // are durable before either reference can be linked into the tree.
        assert_eq!(
            *backend.events.lock().unwrap(),
            [
                "reserve",
                "create",
                "get",
                "verify",
                "materialize",
                "reserve",
                "create",
                "get",
                "verify",
                "materialize",
            ]
        );
        assert_eq!(inventory.materialized.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn already_present_identical_is_exactly_read_back_before_materialization_or_linking() {
        let (a, d, k) = ids();
        let backend = FaultBackend::default();
        let cipher = TestCipher::with_verify_events(a, k, Arc::clone(&backend.events));
        *backend.fault.lock().unwrap() = Fault::CreateReturnsAlreadyPresent;
        let inventory = EventInventory::new(Arc::clone(&backend.events));
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x71))],
            next: 0,
        };
        upload_extent_tree(
            &backend,
            &cipher,
            a,
            d,
            &mut source,
            staging_for(&inventory),
        )
        .await
        .unwrap();
        assert_eq!(
            *backend.events.lock().unwrap(),
            [
                "reserve",
                "create",
                "get",
                "verify",
                "materialize",
                "reserve",
                "create",
                "get",
                "verify",
                "materialize",
            ]
        );
    }

    #[tokio::test]
    async fn reserve_failure_makes_zero_provider_calls() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let inventory = EventInventory::rejecting(Arc::clone(&backend.events));
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x71))],
            next: 0,
        };
        assert!(upload_extent_tree(
            &backend,
            &cipher,
            a,
            d,
            &mut source,
            staging_for(&inventory),
        )
        .await
        .is_err());
        assert_eq!(*backend.events.lock().unwrap(), ["reserve"]);
        assert_eq!(inventory.materialized.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn missing_or_tampered_readback_never_materializes_or_links_that_object() {
        let (a, d, k) = ids();
        for (fault, prior_materializations) in [
            (Fault::MissingOnRead(1), 0),
            (Fault::TamperOnRead(1), 0),
            // A one-extent source creates its extent first and then its root
            // node, so the second read exercises the node path.
            (Fault::MissingOnRead(2), 1),
            (Fault::TamperOnRead(2), 1),
        ] {
            let cipher = TestCipher::new(a, k);
            let backend = FaultBackend::default();
            let inventory = EventInventory::new(Arc::clone(&backend.events));
            *backend.fault.lock().unwrap() = fault;
            let mut source = VecSource {
                length: u64::from(EXTENT_BYTES),
                entries: vec![(0, bytes(256, 0x6a))],
                next: 0,
            };
            assert!(upload_extent_tree(
                &backend,
                &cipher,
                a,
                d,
                &mut source,
                staging_for(&inventory),
            )
            .await
            .is_err());
            let events = backend.events.lock().unwrap();
            assert_eq!(events.last(), Some(&"get"));
            assert_eq!(
                events.len(),
                prior_materializations * 4 + 3,
                "the failed object is never materialized or linked onward"
            );
            assert_eq!(
                inventory.materialized.load(Ordering::Relaxed),
                prior_materializations
            );
        }
    }

    #[tokio::test]
    async fn missealed_extent_or_node_is_verified_before_materialization_or_linking() {
        let (a, d, k) = ids();
        for (seal_index, fault, prior_materializations) in [
            (0, TestSealFault::WrongPlaintext, 0),
            (0, TestSealFault::WrongContext, 0),
            // One extent is sealed first and the root node second.
            (1, TestSealFault::WrongPlaintext, 1),
            (1, TestSealFault::WrongContext, 1),
        ] {
            let backend = FaultBackend::default();
            let cipher =
                TestCipher::with_seal_fault(a, k, seal_index, fault, Arc::clone(&backend.events));
            let inventory = EventInventory::new(Arc::clone(&backend.events));
            let mut source = VecSource {
                length: u64::from(EXTENT_BYTES),
                entries: vec![(0, bytes(256, 0x6a))],
                next: 0,
            };
            assert!(upload_extent_tree(
                &backend,
                &cipher,
                a,
                d,
                &mut source,
                staging_for(&inventory),
            )
            .await
            .is_err());
            let events = backend.events.lock().unwrap();
            for sequence in events[..prior_materializations * 5].chunks_exact(5) {
                assert_eq!(
                    sequence,
                    ["reserve", "create", "get", "verify", "materialize"]
                );
            }
            assert_eq!(
                &events[prior_materializations * 5..],
                ["reserve", "create", "get", "verify"]
            );
            assert_eq!(
                inventory.materialized.load(Ordering::Relaxed),
                prior_materializations
            );
        }
    }

    #[tokio::test]
    async fn non_wal_staging_drives_the_same_verified_extent_upload_order() {
        let (a, d, k) = ids();
        let backend = FaultBackend::default();
        let cipher = TestCipher::new(a, k);
        let staging = NonWalTestStaging::new(Arc::clone(&backend.events));
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x6b))],
            next: 0,
        };

        let uploaded = upload_extent_tree(&backend, &cipher, a, d, &mut source, staging.clone())
            .await
            .unwrap();

        assert_eq!(uploaded.extent_count(), 1);
        assert_eq!(staging.next_ordinal.load(Ordering::Relaxed), 2);
        assert_eq!(staging.materialized.load(Ordering::Relaxed), 2);
        assert_eq!(staging.record_counts(), (2, 2));
        assert_eq!(
            *backend.events.lock().unwrap(),
            [
                "reserve",
                "create",
                "get",
                "verify",
                "materialize",
                "reserve",
                "create",
                "get",
                "verify",
                "materialize",
            ]
        );
    }

    #[tokio::test]
    async fn non_wal_staging_never_materializes_failed_authenticated_readback() {
        let (a, d, k) = ids();
        let backend = FaultBackend::default();
        let cipher = TestCipher::with_seal_fault(
            a,
            k,
            0,
            TestSealFault::WrongPlaintext,
            Arc::new(Mutex::new(Vec::new())),
        );
        let staging = NonWalTestStaging::new(Arc::clone(&backend.events));
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x6c))],
            next: 0,
        };

        assert!(
            upload_extent_tree(&backend, &cipher, a, d, &mut source, staging.clone(),)
                .await
                .is_err()
        );
        assert_eq!(staging.next_ordinal.load(Ordering::Relaxed), 1);
        assert_eq!(staging.materialized.load(Ordering::Relaxed), 0);
        assert_eq!(staging.record_counts(), (1, 0));
        assert_eq!(
            *backend.events.lock().unwrap(),
            ["reserve", "create", "get", "verify"]
        );
    }

    #[tokio::test]
    async fn sealed_non_wal_adapter_retains_exact_reservation_on_provider_failure_or_cancel() {
        let (a, d, k) = ids();
        for fault in [
            Fault::CreateUnavailable,
            Fault::MissingOnRead(1),
            Fault::TamperOnRead(1),
        ] {
            let backend = FaultBackend::default();
            *backend.fault.lock().unwrap() = fault;
            let staging = NonWalTestStaging::new(Arc::clone(&backend.events));
            let mut source = VecSource {
                length: u64::from(EXTENT_BYTES),
                entries: vec![(0, bytes(256, 0x6d))],
                next: 0,
            };
            assert!(upload_extent_tree(
                &backend,
                &TestCipher::new(a, k),
                a,
                d,
                &mut source,
                staging.clone(),
            )
            .await
            .is_err());
            assert_eq!(staging.record_counts(), (1, 0));
        }

        let backend = FaultBackend::default();
        *backend.fault.lock().unwrap() = Fault::BlockOnRead(1);
        let staging = NonWalTestStaging::new(Arc::clone(&backend.events));
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x6e))],
            next: 0,
        };
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            upload_extent_tree(
                &backend,
                &TestCipher::new(a, k),
                a,
                d,
                &mut source,
                staging.clone(),
            ),
        )
        .await
        .is_err());
        assert_eq!(staging.record_counts(), (1, 0));
    }

    #[tokio::test]
    async fn sealed_non_wal_adapter_materialization_failure_and_attempt_cap_fail_closed() {
        let (a, d, k) = ids();
        let backend = FaultBackend::default();
        let staging = NonWalTestStaging::new(Arc::clone(&backend.events));
        staging.fail_materialize.store(true, Ordering::Relaxed);
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x6f))],
            next: 0,
        };
        assert!(upload_extent_tree(
            &backend,
            &TestCipher::new(a, k),
            a,
            d,
            &mut source,
            staging.clone(),
        )
        .await
        .is_err());
        assert_eq!(staging.record_counts(), (1, 0));

        let backend = FaultBackend::default();
        let staging = NonWalTestStaging::new(Arc::clone(&backend.events));
        staging
            .next_ordinal
            .store(MAX_SHADOW_OBJECTS_PER_ATTEMPT - 1, Ordering::Relaxed);
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x70))],
            next: 0,
        };
        assert!(matches!(
            upload_extent_tree(
                &backend,
                &TestCipher::new(a, k),
                a,
                d,
                &mut source,
                staging.clone(),
            )
            .await,
            Err(ExtentTreeError::Staging(ShadowCheckpointError::Inventory(
                ShadowObjectInventoryError::AttemptExhausted
            )))
        ));
        assert_eq!(staging.record_counts(), (1, 1));
        assert_eq!(
            staging.next_ordinal.load(Ordering::Relaxed),
            MAX_SHADOW_OBJECTS_PER_ATTEMPT
        );
    }

    #[tokio::test]
    async fn provider_or_materialization_transient_leaves_the_reserved_object_unlinked() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let inventory = EventInventory::new(Arc::clone(&backend.events));
        *backend.fault.lock().unwrap() = Fault::CreateUnavailable;
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x71))],
            next: 0,
        };
        assert!(upload_extent_tree(
            &backend,
            &cipher,
            a,
            d,
            &mut source,
            staging_for(&inventory),
        )
        .await
        .is_err());
        assert_eq!(*backend.events.lock().unwrap(), ["reserve", "create"]);
        assert_eq!(inventory.reserved.load(Ordering::Relaxed), 1);
        assert_eq!(inventory.materialized.load(Ordering::Relaxed), 0);

        let backend = FaultBackend::default();
        let cipher = TestCipher::with_verify_events(a, k, Arc::clone(&backend.events));
        let inventory = EventInventory::materialize_failing(Arc::clone(&backend.events));
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x71))],
            next: 0,
        };
        assert!(upload_extent_tree(
            &backend,
            &cipher,
            a,
            d,
            &mut source,
            staging_for(&inventory),
        )
        .await
        .is_err());
        assert_eq!(
            *backend.events.lock().unwrap(),
            ["reserve", "create", "get", "verify", "materialize"]
        );
        assert_eq!(inventory.reserved.load(Ordering::Relaxed), 1);
        assert_eq!(inventory.materialized.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cancellation_after_create_leaves_the_durable_object_reserved() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let inventory = EventInventory::new(Arc::clone(&backend.events));
        *backend.fault.lock().unwrap() = Fault::BlockOnRead(1);
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x71))],
            next: 0,
        };
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            upload_extent_tree(
                &backend,
                &cipher,
                a,
                d,
                &mut source,
                staging_for(&inventory),
            ),
        )
        .await
        .is_err());
        assert_eq!(
            *backend.events.lock().unwrap(),
            ["reserve", "create", "get"]
        );
        assert_eq!(inventory.reserved.load(Ordering::Relaxed), 1);
        assert_eq!(inventory.materialized.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn async_source_can_pend_before_create_and_cancellation_leaves_no_inventory_entry() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let inventory = EventInventory::new(Arc::clone(&backend.events));
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (_resume, resume_rx) = tokio::sync::oneshot::channel();
        let mut source = PausingSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x71))],
            next: 0,
            pause_at: 0,
            entered: Some(entered),
            resume: Some(resume_rx),
        };
        {
            let future = upload_extent_tree(
                &backend,
                &cipher,
                a,
                d,
                &mut source,
                staging_for(&inventory),
            );
            tokio::pin!(future);
            tokio::select! {
                result = entered_rx => result.expect("source entered its async pause"),
                result = &mut future => panic!("paused source unexpectedly completed: {result:?}"),
            }
        }
        assert!(backend.events.lock().unwrap().is_empty());
        assert_eq!(inventory.reserved.load(Ordering::Relaxed), 0);
        assert_eq!(inventory.materialized.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn async_source_can_pend_between_extents_and_keeps_prior_materialization_ledgered() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let inventory = EventInventory::new(Arc::clone(&backend.events));
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (_resume, resume_rx) = tokio::sync::oneshot::channel();
        let mut source = PausingSource {
            length: u64::from(EXTENT_BYTES) * 2,
            entries: vec![(0, bytes(256, 0x71)), (1, bytes(256, 0x72))],
            next: 0,
            pause_at: 1,
            entered: Some(entered),
            resume: Some(resume_rx),
        };
        {
            let future = upload_extent_tree(
                &backend,
                &cipher,
                a,
                d,
                &mut source,
                staging_for(&inventory),
            );
            tokio::pin!(future);
            tokio::select! {
                result = entered_rx => result.expect("source paused between extent pulls"),
                result = &mut future => panic!("paused source unexpectedly completed: {result:?}"),
            }
        }
        assert_eq!(
            *backend.events.lock().unwrap(),
            ["reserve", "create", "get", "materialize"]
        );
        assert_eq!(inventory.reserved.load(Ordering::Relaxed), 1);
        assert_eq!(inventory.materialized.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn async_source_reuses_the_one_mib_caller_buffer_for_every_pull() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let destinations = Arc::new(Mutex::new(Vec::new()));
        let mut source = PointerTrackingSource {
            length: u64::from(EXTENT_BYTES) * 2,
            entries: vec![(0, bytes(256, 0x71)), (1, bytes(256, 0x72))],
            next: 0,
            destinations: Arc::clone(&destinations),
        };
        upload_extent_tree(&backend, &cipher, a, d, &mut source, staging())
            .await
            .unwrap();
        let destinations = destinations.lock().unwrap();
        assert_eq!(destinations.len(), 3, "two extents plus the EOF pull");
        assert!(destinations
            .iter()
            .all(|(_, length)| *length == EXTENT_BYTES as usize));
        assert!(destinations.windows(2).all(|pair| pair[0].0 == pair[1].0));
    }

    #[tokio::test]
    async fn ordinal_cap_rejects_the_node_before_any_node_provider_call() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let inventory = EventInventory::new(Arc::clone(&backend.events));
        let staging = staging_for(&inventory);
        staging.set_next_ordinal_for_test((MAX_SHADOW_OBJECTS_PER_ATTEMPT - 1) as u32);
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x71))],
            next: 0,
        };
        assert!(matches!(
            upload_extent_tree(&backend, &cipher, a, d, &mut source, staging).await,
            Err(ExtentTreeError::Staging(ShadowCheckpointError::Inventory(
                ShadowObjectInventoryError::AttemptExhausted
            )))
        ));
        assert_eq!(
            *backend.events.lock().unwrap(),
            ["reserve", "create", "get", "materialize"]
        );
        assert_eq!(inventory.materialized.load(Ordering::Relaxed), 1);
    }
    #[tokio::test]
    async fn authenticated_short_nonfinal_extent_is_not_a_sparse_hole() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let node_id = ObjectId::from_bytes([0x61; 16]);
        let node = MerkleNode {
            level: 0,
            range_start: 0,
            range_end: 1,
            entries: MerkleEntries::Leaf(vec![ExtentReference {
                extent_no: 0,
                logical_byte_len: SQLITE_PAGE_SIZE,
                revision: 1,
                reference: ImmutableReference {
                    object_id: ObjectId::from_bytes([0x62; 16]),
                    envelope_hash: [0x63; 32],
                },
            }]),
        };
        let context = node_context(a, d, k, 0, 0, 1, node_id).unwrap();
        let envelope = cipher.seal(&context, &node.encode().unwrap()).unwrap();
        backend
            .create_if_absent(context.object_key(), envelope.clone())
            .await
            .unwrap();
        let root = AuthenticatedExtentRoot::from_test_verified_archive_root(
            a,
            &ArchiveRoot {
                root_seq: 0,
                parent: None,
                database_epoch: d,
                key_epoch: k,
                owner_fencing_epoch: 0,
                sqlite_page_size: SQLITE_PAGE_SIZE,
                logical_file_length: u64::from(EXTENT_BYTES),
                user_schema_version: 1,
                storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
                wal_generation: 0,
                wal_segment_count: 0,
                checkpoint_root: None,
                extent_tree_root: Some(ImmutableReference {
                    object_id: node_id,
                    envelope_hash: envelope.hash(),
                }),
                wal_chain_root: None,
            },
        )
        .unwrap();
        let mut output = vec![0; SQLITE_PAGE_SIZE as usize];
        assert!(reconstruct_extent_range(
            &backend,
            &cipher,
            &root,
            SQLITE_PAGE_SIZE.into(),
            &mut output,
        )
        .await
        .is_err());
    }
    #[tokio::test]
    async fn sparse_final_partial_and_range_recovery_are_bounded() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let length = u64::from(EXTENT_BYTES) * 3 + 8192;
        let mut source = VecSource {
            length,
            entries: vec![
                (0, bytes(256, 0x11)),
                (2, bytes(256, 0x22)),
                (3, bytes(2, 0x33)),
            ],
            next: 0,
        };
        let uploaded = upload_extent_tree(&backend, &cipher, a, d, &mut source, staging())
            .await
            .unwrap();
        let root = descriptor(a, d, k, &uploaded);
        let mut output = vec![0xff; 12288];
        reconstruct_extent_range(
            &backend,
            &cipher,
            &root,
            u64::from(EXTENT_BYTES) - 4096,
            &mut output,
        )
        .await
        .unwrap();
        assert_eq!(&output[..4096], &[0x11; 4096]);
        assert_eq!(&output[4096..], &[0; 8192]);
        let mut final_bytes = vec![0; 8192];
        reconstruct_extent_range(
            &backend,
            &cipher,
            &root,
            u64::from(EXTENT_BYTES) * 3,
            &mut final_bytes,
        )
        .await
        .unwrap();
        assert_eq!(final_bytes, vec![0x33; 8192]);
    }
    #[tokio::test]
    async fn exact_object_faults_and_cancellation_fail_closed() {
        let (a, d, k) = ids();
        let cipher = TestCipher::new(a, k);
        let backend = FaultBackend::default();
        let mut source = VecSource {
            length: u64::from(EXTENT_BYTES),
            entries: vec![(0, bytes(256, 0x52))],
            next: 0,
        };
        let uploaded = upload_extent_tree(&backend, &cipher, a, d, &mut source, staging())
            .await
            .unwrap();
        let root = descriptor(a, d, k, &uploaded);
        for kind in 0..4 {
            *backend.fault.lock().unwrap() = match kind {
                0 => Fault::Missing(uploaded.root().object_id),
                1 => Fault::Tamper(uploaded.root().object_id),
                2 => Fault::Substitute(
                    uploaded.root().object_id,
                    cipher
                        .seal(
                            &extent_context(
                                a,
                                d,
                                k,
                                0,
                                SQLITE_PAGE_SIZE,
                                ObjectId::from_bytes([9; 16]),
                            )
                            .unwrap(),
                            &bytes(1, 0x9a),
                        )
                        .unwrap(),
                ),
                _ => Fault::Block,
            };
            let mut out = vec![0; 4096];
            if kind < 3 {
                assert!(
                    reconstruct_extent_range(&backend, &cipher, &root, 0, &mut out)
                        .await
                        .is_err()
                )
            } else {
                {
                    let future = reconstruct_extent_range(&backend, &cipher, &root, 0, &mut out);
                    assert!(
                        tokio::time::timeout(std::time::Duration::from_millis(10), future)
                            .await
                            .is_err()
                    );
                }
                assert_eq!(out, vec![0; 4096]);
            }
        }
    }
    #[test]
    fn rejects_depth_byte_count_and_source_mismatches() {
        assert!(extent_slots(0).is_err());
        assert!(extent_slots(1).is_err());
        assert_eq!(extent_tree_height(257).unwrap(), 1);
        // A sparse unary height-two tree would require more than the shared
        // 32-GiB ceiling, so it is intentionally unrepresentable.
        assert!(extent_tree_height(65_537).is_err());
        assert!(validate_range(4096, 0, MAX_RANGE_RECONSTRUCTION_BYTES + 1).is_err());
        assert!(validate_source_extent(
            SourceExtent {
                extent_no: 1,
                logical_byte_len: 4096
            },
            1,
            4096,
            None
        )
        .is_err());
        assert!(validate_source_extent(
            SourceExtent {
                extent_no: 0,
                logical_byte_len: 8192
            },
            1,
            4096,
            None
        )
        .is_err());
    }
}
