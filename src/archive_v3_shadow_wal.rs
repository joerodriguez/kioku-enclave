#![allow(
    dead_code,
    reason = "inactive ADR-0022 WAL publication/recovery is compiled and tested before authority wiring"
)]

//! Inactive, bounded ADR-0022 captured-WAL publication and recovery.
//!
//! This is deliberately below the publication coordinator: it turns one
//! already-validated [`CapturedWalCommit`] into sealed immutable segments,
//! reads every created segment back under its exact context, and composes the
//! checkpoint-plus-WAL portion of a future root. Recovery starts at the one
//! exact root named by a [`RecoveryRoot`] and follows predecessor references
//! backwards; it never lists objects or accepts a caller-selected WAL object.
//!
//! No runtime installs a VFS, drains a capture, invokes these functions from a
//! `Store`, truncates a local WAL, or gives this module witness authority.

use async_trait::async_trait;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    archive_v3::{
        ArchiveId, ArchiveRoot, ArchiveV3Error, CiphertextEnvelope, DatabaseEpoch,
        ImmutableObjectBackend, ImmutableReference, LogicalLocation, ObjectContext, ObjectId,
        ObjectRole, ParentReference, VerifiedArchiveCipher, ARCHIVE_FORMAT_VERSION,
        MAX_WAL_COMMITS_PER_ROOT, MAX_WAL_SEGMENTS_PER_ROOT, MAX_WAL_TAIL_BYTES, SQLITE_PAGE_SIZE,
    },
    archive_v3_journal::{
        resolve_verified_wal_commit_descriptor, resolve_verified_wal_segment,
        validate_wal_commit_chain, ResolvedWalCommitDescriptor, ResolvedWalSegment,
        WalCommitDescriptor, WalSegment, MAX_WAL_COMMIT_DESCRIPTOR_BYTES, MAX_WAL_SEGMENT_BYTES,
    },
    archive_v3_shadow::CapturedWalCommit,
    archive_v3_shadow_checkpoint::{
        recover_checkpoint_from_recovery_root, ExactImmutableObjectBackend, ShadowCheckpointError,
        ShadowObjectStaging, TmpfsCheckpointSink, UploadedCheckpoint,
    },
    archive_v3_shadow_parity::OwnedPrivateStagedSqliteCopy,
    archive_v3_witness::{
        DeletionState, MigrationState, RecoveryRoot, RootCommitment, RootReference, WitnessLease,
        WitnessRecord,
    },
};

const SQLITE_WAL_HEADER_BYTES: usize = 32;
const SQLITE_WAL_FRAME_HEADER_BYTES: usize = 24;
const SQLITE_WAL_FRAME_BYTES: usize = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
// The largest encoded predecessor-bearing `WalSegment` fixed prefix is 138
// bytes. Keep this independent of the encoder's allocation strategy.
const MAX_WAL_SEGMENT_FIXED_BYTES: usize = 138;
const MAX_WAL_FRAMES_PER_SEGMENT: usize =
    (MAX_WAL_SEGMENT_BYTES - MAX_WAL_SEGMENT_FIXED_BYTES) / SQLITE_WAL_FRAME_BYTES;

/// A VFS capture has its own 8-MiB ceiling. This independent publication cap
/// makes recovery allocation and object fanout explicit even if that capture
/// implementation changes later.
pub const MAX_WAL_SEGMENTS_PER_COMMIT: u32 = 16;

#[derive(Debug, Error)]
pub enum ShadowWalError {
    #[error(transparent)]
    Archive(#[from] ArchiveV3Error),
    #[error("the exact immutable WAL object is absent")]
    MissingObject,
    #[error("the witnessed root has no checkpoint-plus-WAL recovery state")]
    MissingCheckpointOrWal,
    #[error("WAL recovery sink rejected output")]
    Sink,
    #[error("the authenticated WAL lineage reached its checkpointing cap")]
    CheckpointRequired,
    #[error("private composite SQLite recovery failed")]
    CompositeRecovery,
}

pub type Result<T> = std::result::Result<T, ShadowWalError>;

/// Opaque description of immutable objects that were sealed and then read
/// back successfully. It has no authority until a separately authenticated
/// root names `final_segment` and that root is witnessed.
#[derive(Clone, PartialEq, Eq)]
pub struct UploadedWalCommit {
    root_seq: u64,
    wal_generation: u64,
    segment_count: u32,
    effective_logical_file_length: u64,
    final_segment: ImmutableReference,
    descriptor: ImmutableReference,
    candidate_root: ArchiveRoot,
}

struct UploadedWalSegments {
    root_seq: u64,
    wal_generation: u64,
    segment_count: u32,
    frame_count: u32,
    commit_wal_bytes: u64,
    effective_logical_file_length: u64,
    final_segment: ImmutableReference,
}

struct WalCommitPreflight {
    effective_logical_file_length: u64,
    frame_count: u32,
    segment_count: u32,
    commit_wal_bytes: u64,
}

struct WalSegmentUploadContext<'a> {
    backend: &'a dyn ExactImmutableObjectBackend,
    cipher: &'a VerifiedArchiveCipher,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    root_seq: u64,
    staging: &'a dyn WalObjectStaging,
}

/// Exact create/readback boundary used by the inactive WAL publisher. The
/// production implementation reserves one Control row before provider create
/// and materializes that same row only after exact readback. The direct
/// adapter remains private to this module for existing foundation tests.
#[async_trait]
pub(crate) trait WalObjectStaging: Send + Sync {
    async fn create_and_readback(
        &self,
        backend: &dyn ExactImmutableObjectBackend,
        context: &ObjectContext,
        envelope: CiphertextEnvelope,
    ) -> Result<CiphertextEnvelope>;
}

struct DirectWalObjectStaging;

#[async_trait]
impl WalObjectStaging for DirectWalObjectStaging {
    async fn create_and_readback(
        &self,
        backend: &dyn ExactImmutableObjectBackend,
        context: &ObjectContext,
        envelope: CiphertextEnvelope,
    ) -> Result<CiphertextEnvelope> {
        backend
            .create_if_absent(context.object_key(), envelope.clone())
            .await?;
        let readback = backend
            .get(&context.object_key())
            .await?
            .ok_or(ShadowWalError::MissingObject)?;
        if readback != envelope {
            return Err(ArchiveV3Error::Authentication.into());
        }
        Ok(readback)
    }
}

/// Sized, owned adapter used only to carry either the legacy full backend or
/// the WAL publisher's create/get-only backend into the cancellation-owned
/// recovery task. It deliberately implements only the narrow exact-name
/// capability even when its legacy variant internally owns the older broad
/// trait object.
enum OwnedExactBackend {
    Legacy(Arc<dyn ImmutableObjectBackend>),
    Narrow(Arc<dyn ExactImmutableObjectBackend>),
}

#[async_trait]
impl ExactImmutableObjectBackend for OwnedExactBackend {
    async fn create_if_absent(
        &self,
        key: crate::archive_v3::ObjectKey,
        value: CiphertextEnvelope,
    ) -> crate::archive_v3::Result<crate::archive_v3::CreateIfAbsent> {
        match self {
            Self::Legacy(backend) => {
                ImmutableObjectBackend::create_if_absent(backend.as_ref(), key, value).await
            }
            Self::Narrow(backend) => backend.create_if_absent(key, value).await,
        }
    }

    async fn get(
        &self,
        key: &crate::archive_v3::ObjectKey,
    ) -> crate::archive_v3::Result<Option<CiphertextEnvelope>> {
        match self {
            Self::Legacy(backend) => ImmutableObjectBackend::get(backend.as_ref(), key).await,
            Self::Narrow(backend) => backend.get(key).await,
        }
    }
}

impl UploadedWalCommit {
    pub(crate) fn root_seq(&self) -> u64 {
        self.root_seq
    }

    pub(crate) fn wal_generation(&self) -> u64 {
        self.wal_generation
    }

    pub(crate) fn segment_count(&self) -> u32 {
        self.segment_count
    }

    pub(crate) fn effective_logical_file_length(&self) -> u64 {
        self.effective_logical_file_length
    }

    pub(crate) fn final_segment(&self) -> &ImmutableReference {
        &self.final_segment
    }

    pub(crate) fn descriptor(&self) -> &ImmutableReference {
        &self.descriptor
    }

    pub(crate) fn candidate_root(&self) -> &ArchiveRoot {
        &self.candidate_root
    }
}

impl std::fmt::Debug for UploadedWalCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UploadedWalCommit(<opaque>)")
    }
}

/// Upload one capture-bound SQLite commit as predecessor-linked immutable
/// segments. The caller cannot substitute raw WAL bytes: the capture has
/// already validated complete `xSync`-durable commit boundaries, rolling
/// checksums, salts, and frame order. Each newly sealed object is immediately
/// fetched, hash-checked, AEAD-opened, and decoded before the next object is
/// created.
async fn upload_captured_wal_segments(
    context: WalSegmentUploadContext<'_>,
    capture: &CapturedWalCommit,
    preflight: &WalCommitPreflight,
) -> Result<UploadedWalSegments> {
    let WalSegmentUploadContext {
        backend,
        cipher,
        archive_id,
        database_epoch,
        root_seq,
        staging,
    } = context;
    if cipher.archive_id() != archive_id || root_seq == 0 {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let frames = capture.replay_frames();
    let frame_count = usize::try_from(preflight.frame_count)
        .map_err(|_| ArchiveV3Error::TooLarge("WAL frame count"))?;
    let segment_count = preflight.segment_count;

    let mut previous_segment = None;
    for segment_index in 0..segment_count {
        let start_frame = segment_index as usize * MAX_WAL_FRAMES_PER_SEGMENT;
        let end_frame = (start_frame + MAX_WAL_FRAMES_PER_SEGMENT).min(frame_count);
        let frame_start = start_frame * SQLITE_WAL_FRAME_BYTES;
        let frame_end = end_frame * SQLITE_WAL_FRAME_BYTES;
        let checksum_before = if segment_index == 0 {
            capture.replay_checksum_before()
        } else {
            let checksum_offset = frame_start
                .checked_sub(SQLITE_WAL_FRAME_BYTES)
                .and_then(|offset| offset.checked_add(16))
                .ok_or(ArchiveV3Error::Malformed("WAL checksum offset"))?;
            [
                u32::from_be_bytes(
                    frames[checksum_offset..checksum_offset + 4]
                        .try_into()
                        .map_err(|_| ArchiveV3Error::Malformed("WAL checksum"))?,
                ),
                u32::from_be_bytes(
                    frames[checksum_offset + 4..checksum_offset + 8]
                        .try_into()
                        .map_err(|_| ArchiveV3Error::Malformed("WAL checksum"))?,
                ),
            ]
        };
        let segment = WalSegment {
            root_seq,
            wal_generation: capture.wal_generation(),
            segment_index,
            segment_count,
            previous_segment: previous_segment.clone(),
            first_frame_no: capture
                .first_frame_no()
                .checked_add(start_frame as u64)
                .ok_or(ArchiveV3Error::Malformed("WAL frame sequence overflow"))?,
            checksum_before,
            wal_header: *capture.replay_header(),
            frames: frames[frame_start..frame_end].to_vec(),
        };
        let object_id = ObjectId::random();
        let context = wal_context(
            archive_id,
            database_epoch,
            cipher.key_epoch(),
            root_seq,
            capture.wal_generation(),
            segment_index,
            object_id,
        )?;
        // The encoded WAL object is plaintext until `seal` returns. Keep that
        // bounded transient zeroized on success, error, and cancellation.
        let encoded = Zeroizing::new(segment.encode()?);
        let envelope = cipher.seal(&context, encoded.as_slice())?;
        let exact = staging
            .create_and_readback(backend, &context, envelope.clone())
            .await?;
        let reference = ImmutableReference {
            object_id,
            envelope_hash: envelope.hash(),
        };
        // Do not return a root-composable reference until the exact object is
        // proven readable and valid under the context derived above.
        if exact.hash() != reference.envelope_hash {
            return Err(ArchiveV3Error::Authentication.into());
        }
        let resolved = load_exact_wal_segment(backend, cipher, &context, &reference).await?;
        if resolved.reference() != &reference || resolved.segment() != &segment {
            return Err(ArchiveV3Error::Authentication.into());
        }
        previous_segment = Some(reference);
    }

    Ok(UploadedWalSegments {
        root_seq,
        wal_generation: capture.wal_generation(),
        segment_count,
        frame_count: preflight.frame_count,
        commit_wal_bytes: preflight.commit_wal_bytes,
        effective_logical_file_length: preflight.effective_logical_file_length,
        final_segment: previous_segment.ok_or(ArchiveV3Error::Malformed("empty WAL upload"))?,
    })
}

fn preflight_captured_wal_commit(
    root_seq: u64,
    capture: &CapturedWalCommit,
) -> Result<WalCommitPreflight> {
    if root_seq == 0 {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let effective_logical_file_length = capture.effective_logical_file_length(root_seq)?;
    let frames = capture.replay_frames();
    if frames.is_empty() || !frames.len().is_multiple_of(SQLITE_WAL_FRAME_BYTES) {
        return Err(ArchiveV3Error::Malformed("captured WAL frames").into());
    }
    let frame_count = frames.len() / SQLITE_WAL_FRAME_BYTES;
    let segment_count = captured_wal_segment_count(capture)?;
    let frame_count =
        u32::try_from(frame_count).map_err(|_| ArchiveV3Error::TooLarge("WAL frame count"))?;
    let commit_wal_bytes = u64::from(SQLITE_WAL_HEADER_BYTES as u32)
        .checked_add(
            u64::from(frame_count)
                .checked_mul(u64::from(SQLITE_WAL_FRAME_BYTES as u32))
                .ok_or(ArchiveV3Error::TooLarge("WAL commit bytes"))?,
        )
        .ok_or(ArchiveV3Error::TooLarge("WAL commit bytes"))?;
    Ok(WalCommitPreflight {
        effective_logical_file_length,
        frame_count,
        segment_count,
        commit_wal_bytes,
    })
}

/// Shared deterministic split preflight used by both the uploader and the
/// durable publication candidate. It exposes only the bounded object count,
/// never captured bytes or provider authority.
pub(crate) fn captured_wal_segment_count(
    capture: &CapturedWalCommit,
) -> std::result::Result<u32, ArchiveV3Error> {
    let frames = capture.replay_frames();
    if frames.is_empty() || !frames.len().is_multiple_of(SQLITE_WAL_FRAME_BYTES) {
        return Err(ArchiveV3Error::Malformed("captured WAL frames"));
    }
    let frame_count = frames.len() / SQLITE_WAL_FRAME_BYTES;
    let segment_count = frame_count
        .checked_add(MAX_WAL_FRAMES_PER_SEGMENT - 1)
        .ok_or(ArchiveV3Error::TooLarge("WAL segment count"))?
        / MAX_WAL_FRAMES_PER_SEGMENT;
    let segment_count =
        u32::try_from(segment_count).map_err(|_| ArchiveV3Error::TooLarge("WAL segment count"))?;
    if segment_count == 0 || segment_count > MAX_WAL_SEGMENTS_PER_COMMIT {
        return Err(ArchiveV3Error::TooLarge("WAL commit segments"));
    }
    Ok(segment_count)
}

/// Exact pre-mutation checkpoint admission for the inactive single-archive
/// owner. The reserve leaves room for the largest accepted logical commit, so
/// a mutation can never cross a lineage cap after it has entered SQLite.
pub(crate) async fn wal_owner_checkpoint_required(
    recovery: &RecoveryRoot,
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
) -> Result<bool> {
    validate_recovery_cipher(recovery, cipher, archive_id)?;
    let commitment = recovery.root();
    let root = load_root(
        backend,
        cipher,
        archive_id,
        commitment.root(),
        commitment.parent(),
        commitment.database_epoch(),
        commitment.key_epoch(),
    )
    .await?;
    if root.owner_fencing_epoch != commitment.owner_fencing_epoch() {
        return Err(ArchiveV3Error::Authentication.into());
    }
    root.validate()?;
    Ok(wal_owner_checkpoint_geometry_requires(
        u64::from(root.wal_commit_count),
        u64::from(root.wal_segment_count),
        root.wal_tail_bytes,
    ))
}

fn wal_owner_checkpoint_geometry_requires(
    commit_count: u64,
    segment_count: u64,
    tail_bytes: u64,
) -> bool {
    commit_count >= u64::from(MAX_WAL_COMMITS_PER_ROOT)
        || segment_count
            > u64::from(MAX_WAL_SEGMENTS_PER_ROOT.saturating_sub(MAX_WAL_SEGMENTS_PER_COMMIT))
        || tail_bytes > MAX_WAL_TAIL_BYTES.saturating_sub(8 * 1024 * 1024)
}

/// Upload one captured commit and its authenticated lineage descriptor from
/// the exact root named by a witness snapshot. The returned root remains only
/// a candidate; this inactive function neither seals a root nor advances a
/// witness.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_captured_wal_commit(
    recovery: &RecoveryRoot,
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    owner_fencing_epoch: u64,
    operation_id: [u8; 16],
    request_fingerprint: [u8; 32],
    capture: &CapturedWalCommit,
) -> Result<UploadedWalCommit> {
    validate_recovery_cipher(recovery, cipher, archive_id)?;
    let commitment = recovery.root();
    let base = load_root(
        backend,
        cipher,
        archive_id,
        commitment.root(),
        commitment.parent(),
        commitment.database_epoch(),
        commitment.key_epoch(),
    )
    .await?;
    if base.owner_fencing_epoch != commitment.owner_fencing_epoch() {
        return Err(ArchiveV3Error::Authentication.into());
    }
    upload_captured_wal_commit_from_base(
        backend,
        cipher,
        archive_id,
        &base,
        commitment.root(),
        commitment.parent(),
        owner_fencing_epoch,
        operation_id,
        request_fingerprint,
        capture,
        &DirectWalObjectStaging,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn upload_captured_wal_commit_from_base(
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    base: &ArchiveRoot,
    base_reference: RootReference,
    base_parent_reference: Option<RootReference>,
    owner_fencing_epoch: u64,
    operation_id: [u8; 16],
    request_fingerprint: [u8; 32],
    capture: &CapturedWalCommit,
    staging: &dyn WalObjectStaging,
) -> Result<UploadedWalCommit> {
    base.validate()?;
    if base.checkpoint_root.is_none()
        || base.extent_tree_root.is_some()
        || owner_fencing_epoch == 0
        || operation_id.iter().all(|byte| *byte == 0)
        || request_fingerprint.iter().all(|byte| *byte == 0)
    {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    if base.wal_commit_count >= MAX_WAL_COMMITS_PER_ROOT
        || base.wal_segment_count >= MAX_WAL_SEGMENTS_PER_ROOT
        || base.wal_tail_bytes >= MAX_WAL_TAIL_BYTES
    {
        return Err(ShadowWalError::CheckpointRequired);
    }
    let root_seq = base
        .root_seq
        .checked_add(1)
        .ok_or(ArchiveV3Error::Malformed("root sequence overflow"))?;
    // Derive every per-commit and cumulative cap before continuity readback or
    // immutable creation. A base just below a lineage cap must not leave
    // orphaned segments when this commit would cross that cap.
    let preflight = preflight_captured_wal_commit(root_seq, capture)?;
    let cumulative_commit_count = base
        .wal_commit_count
        .checked_add(1)
        .ok_or(ShadowWalError::CheckpointRequired)?;
    let cumulative_segment_count = base
        .wal_segment_count
        .checked_add(preflight.segment_count)
        .ok_or(ShadowWalError::CheckpointRequired)?;
    let cumulative_wal_bytes = base
        .wal_tail_bytes
        .checked_add(preflight.commit_wal_bytes)
        .ok_or(ShadowWalError::CheckpointRequired)?;
    if cumulative_commit_count > MAX_WAL_COMMITS_PER_ROOT
        || cumulative_segment_count > MAX_WAL_SEGMENTS_PER_ROOT
        || cumulative_wal_bytes > MAX_WAL_TAIL_BYTES
    {
        return Err(ShadowWalError::CheckpointRequired);
    }
    validate_capture_continuity(backend, cipher, archive_id, base, capture).await?;
    let uploaded = upload_captured_wal_segments(
        WalSegmentUploadContext {
            backend,
            cipher,
            archive_id,
            database_epoch: base.database_epoch,
            root_seq,
            staging,
        },
        capture,
        &preflight,
    )
    .await?;
    let parent = ParentReference {
        object_id: base_reference.object_id(),
        envelope_hash: base_reference.ciphertext_hash(),
    };
    let parent_parent = base_parent_reference.map(|reference| ParentReference {
        object_id: reference.object_id(),
        envelope_hash: reference.ciphertext_hash(),
    });
    let descriptor = WalCommitDescriptor {
        root_seq,
        owner_fencing_epoch,
        operation_id,
        request_fingerprint,
        checkpoint_root: base
            .checkpoint_root
            .clone()
            .ok_or(ShadowWalError::MissingCheckpointOrWal)?,
        parent_root: parent.clone(),
        parent_root_parent: parent_parent,
        previous_commit: base.wal_commit_tail.clone(),
        checkpoint_logical_file_length: base.checkpoint_logical_file_length,
        before_logical_file_length: base.logical_file_length,
        after_logical_file_length: uploaded.effective_logical_file_length,
        wal_generation: uploaded.wal_generation,
        first_frame_no: capture.first_frame_no(),
        wal_header_hash: Sha256::digest(capture.replay_header()).into(),
        checksum_before: capture.replay_checksum_before(),
        checksum_after: captured_terminal_checksum(capture)?,
        frame_count: uploaded.frame_count,
        commit_segment_count: uploaded.segment_count,
        cumulative_commit_count,
        cumulative_segment_count,
        commit_wal_bytes: uploaded.commit_wal_bytes,
        cumulative_wal_bytes,
        final_segment: uploaded.final_segment.clone(),
    };
    descriptor.validate()?;
    let descriptor_object_id = ObjectId::random();
    let descriptor_context = wal_commit_context(
        archive_id,
        base.database_epoch,
        base.key_epoch,
        root_seq,
        descriptor_object_id,
    )?;
    let encoded = Zeroizing::new(descriptor.encode()?);
    if encoded.len() > MAX_WAL_COMMIT_DESCRIPTOR_BYTES {
        return Err(ArchiveV3Error::TooLarge("WAL commit descriptor").into());
    }
    let envelope = cipher.seal(&descriptor_context, encoded.as_slice())?;
    let exact_descriptor = staging
        .create_and_readback(backend, &descriptor_context, envelope.clone())
        .await?;
    let descriptor_reference = ImmutableReference {
        object_id: descriptor_object_id,
        envelope_hash: envelope.hash(),
    };
    if exact_descriptor.hash() != descriptor_reference.envelope_hash {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let readback = load_exact_wal_commit_descriptor(
        backend,
        cipher,
        &descriptor_context,
        &descriptor_reference,
    )
    .await?;
    if readback.reference() != &descriptor_reference || readback.descriptor() != &descriptor {
        return Err(ArchiveV3Error::Authentication.into());
    }

    let root = ArchiveRoot {
        root_seq,
        parent: Some(parent),
        database_epoch: base.database_epoch,
        key_epoch: base.key_epoch,
        owner_fencing_epoch,
        sqlite_page_size: SQLITE_PAGE_SIZE,
        checkpoint_logical_file_length: base.checkpoint_logical_file_length,
        logical_file_length: uploaded.effective_logical_file_length,
        user_schema_version: base.user_schema_version,
        storage_format_version: ARCHIVE_FORMAT_VERSION,
        wal_generation: uploaded.wal_generation,
        wal_commit_count: cumulative_commit_count,
        wal_segment_count: cumulative_segment_count,
        wal_tail_bytes: cumulative_wal_bytes,
        checkpoint_root: base.checkpoint_root.clone(),
        extent_tree_root: None,
        wal_commit_tail: Some(descriptor_reference),
    };
    root.validate()?;
    Ok(UploadedWalCommit {
        root_seq,
        wal_generation: uploaded.wal_generation,
        segment_count: uploaded.segment_count,
        effective_logical_file_length: uploaded.effective_logical_file_length,
        final_segment: uploaded.final_segment,
        descriptor: root
            .wal_commit_tail
            .clone()
            .ok_or(ShadowWalError::MissingCheckpointOrWal)?,
        candidate_root: root,
    })
}

/// WAL-owner-only upload path. Every immutable segment, descriptor, and root
/// crosses the supplied durable staging boundary before provider creation.
/// The returned commitment is derived from the exact root readback and cannot
/// be reconstructed from caller-selected bytes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_captured_wal_commit_controlled(
    recovery: &RecoveryRoot,
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    owner_fencing_epoch: u64,
    operation_id: [u8; 16],
    request_fingerprint: [u8; 32],
    capture: &CapturedWalCommit,
    staging: &dyn WalObjectStaging,
) -> Result<crate::archive_v3_witness::RootCommitment> {
    validate_recovery_cipher(recovery, cipher, archive_id)?;
    let commitment = recovery.root();
    let base = load_root(
        backend,
        cipher,
        archive_id,
        commitment.root(),
        commitment.parent(),
        commitment.database_epoch(),
        commitment.key_epoch(),
    )
    .await?;
    let uploaded = upload_captured_wal_commit_from_base(
        backend,
        cipher,
        archive_id,
        &base,
        commitment.root(),
        commitment.parent(),
        owner_fencing_epoch,
        operation_id,
        request_fingerprint,
        capture,
        staging,
    )
    .await?;
    let root_id = ObjectId::random();
    let parent = ParentReference {
        object_id: commitment.root().object_id(),
        envelope_hash: commitment.root().ciphertext_hash(),
    };
    let context = ObjectContext::new(
        archive_id,
        commitment.database_epoch(),
        commitment.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: uploaded.root_seq(),
        },
        root_id,
        Some(parent),
    )?;
    let encoded = Zeroizing::new(uploaded.candidate_root().encode()?);
    let envelope = cipher.seal(&context, encoded.as_slice())?;
    let exact = staging
        .create_and_readback(backend, &context, envelope.clone())
        .await?;
    if exact != envelope {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let root = RootReference::new(uploaded.root_seq(), root_id, exact.hash());
    crate::archive_v3_witness::RootCommitment::from_persisted_wal_candidate(
        crate::archive_v3_wal_owner::WalWitnessAdvanceContext::for_publisher(),
        commitment.database_epoch(),
        commitment.key_epoch(),
        owner_fencing_epoch,
        commitment.root(),
        root,
    )
    .map_err(|_| ArchiveV3Error::Authentication.into())
}

/// Build the canonical zero-WAL root after a Store-owned checkpoint source has
/// been uploaded and exactly read back through durable Control staging. The
/// witness, lease, parent, archive/database/key epochs, and root sequence are
/// not caller-selectable independent facts.
pub(crate) async fn create_wal_owner_checkpoint_root(
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    expected: &WitnessRecord,
    lease: WitnessLease,
    checkpoint: &UploadedCheckpoint,
    staging: &ShadowObjectStaging<'_>,
) -> Result<RootCommitment> {
    if expected.deletion() != DeletionState::Active
        || expected.migration() != MigrationState::WalAuthoritative
        || !expected.authorizes_lease(lease)
        || cipher.archive_id() != expected.archive_id()
        || cipher.key_epoch() != expected.registry().key_epoch()
        || checkpoint.logical_file_length() == 0
        || checkpoint.database_plaintext_hash() == [0; 32]
    {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let previous = expected.root().root();
    let root_seq = previous
        .sequence()
        .checked_add(1)
        .ok_or(ArchiveV3Error::Malformed("root sequence"))?;
    let parent = ParentReference {
        object_id: previous.object_id(),
        envelope_hash: previous.ciphertext_hash(),
    };
    let object_id = ObjectId::random();
    let context = ObjectContext::new(
        expected.archive_id(),
        expected.database_epoch(),
        expected.registry().key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root { root_seq },
        object_id,
        Some(parent.clone()),
    )?;
    let root = ArchiveRoot {
        root_seq,
        parent: Some(parent),
        database_epoch: expected.database_epoch(),
        key_epoch: expected.registry().key_epoch(),
        owner_fencing_epoch: lease.fencing_epoch(),
        sqlite_page_size: SQLITE_PAGE_SIZE,
        checkpoint_logical_file_length: checkpoint.logical_file_length(),
        logical_file_length: checkpoint.logical_file_length(),
        user_schema_version: checkpoint.user_schema_version(),
        storage_format_version: ARCHIVE_FORMAT_VERSION,
        wal_generation: 0,
        wal_commit_count: 0,
        wal_segment_count: 0,
        wal_tail_bytes: 0,
        checkpoint_root: Some(checkpoint.root().clone()),
        extent_tree_root: None,
        wal_commit_tail: None,
    };
    root.validate_for_context(&context)?;
    let encoded = Zeroizing::new(root.encode()?);
    let envelope = cipher.seal(&context, encoded.as_slice())?;
    staging
        .create_and_readback_verified(backend, &context, envelope.clone(), |readback| {
            (readback == &envelope)
                .then_some(())
                .ok_or(ArchiveV3Error::Authentication)
        })
        .await
        .map_err(|error| match error {
            ShadowCheckpointError::Archive(error) => ShadowWalError::Archive(error),
            ShadowCheckpointError::MissingObject => ShadowWalError::MissingObject,
            _ => ShadowWalError::CompositeRecovery,
        })?;
    RootCommitment::from_persisted_wal_candidate(
        crate::archive_v3_wal_owner::WalWitnessAdvanceContext::for_publisher(),
        expected.database_epoch(),
        expected.registry().key_epoch(),
        lease.fencing_epoch(),
        previous,
        RootReference::new(root_seq, object_id, envelope.hash()),
    )
    .map_err(|_| ArchiveV3Error::Authentication.into())
}

/// A private staging adapter receives one fully authenticated lineage in
/// chronological order. Generation boundaries are explicit because SQLite
/// must recover/checkpoint one generation before a different WAL header can be
/// applied to the same base.
#[async_trait]
pub trait WalRecoverySink: Send {
    async fn begin_generation(
        &mut self,
        wal_generation: u64,
        header: &[u8; SQLITE_WAL_HEADER_BYTES],
        before_logical_file_length: u64,
    ) -> Result<()>;
    async fn write_wal_frames(&mut self, first_frame_no: u64, frames: &[u8]) -> Result<()>;
    async fn finish_generation(&mut self, after_logical_file_length: u64) -> Result<()>;
    fn abort(&mut self);
}

/// Unforgeable handoff from exact composite recovery to the parity module.
/// The path field and production constructor stay private to this module, so
/// crate siblings cannot mint a trusted staging capability from an arbitrary
/// SQLite file even though the proof type crosses one reviewed module seam.
pub(super) struct CompositeRecoveryProof {
    path: PathBuf,
}

impl CompositeRecoveryProof {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(super) fn into_path(self) -> PathBuf {
        self.path
    }

    #[cfg(test)]
    pub(super) fn for_test(path: PathBuf) -> Self {
        Self::new(path)
    }
}

impl std::fmt::Debug for CompositeRecoveryProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CompositeRecoveryProof(<redacted>)")
    }
}

/// Materialize one exact witnessed checkpoint+WAL lineage into a fresh owned
/// `/tmp` database. The complete operation runs in an owned task: cancellation
/// of the caller cannot detach a plaintext staging file from its cleanup
/// owner. No Store path or caller-selected filename is accepted.
pub(crate) async fn recover_owned_private_staging(
    recovery: RecoveryRoot,
    backend: Arc<dyn ImmutableObjectBackend>,
    cipher: Arc<VerifiedArchiveCipher>,
    archive_id: ArchiveId,
) -> Result<OwnedPrivateStagedSqliteCopy> {
    recover_owned_private_staging_inner(
        recovery,
        Arc::new(OwnedExactBackend::Legacy(backend)),
        cipher,
        archive_id,
        None,
        false,
    )
    .await
    .map(|recovered| recovered.owned)
}

/// Maintenance-only recovery result. It binds the owned recovered SQLite file
/// to the authenticated checkpoint metadata from the same exact witnessed
/// root, including the canonical zero-WAL case.
pub(crate) struct RecoveredMaintenanceStaging {
    owned: OwnedPrivateStagedSqliteCopy,
    checkpoint: crate::archive_v3_shadow_checkpoint::UploadedCheckpoint,
    recovered: RecoveredWitnessWal,
}

impl RecoveredMaintenanceStaging {
    pub(crate) fn owned(&self) -> &OwnedPrivateStagedSqliteCopy {
        &self.owned
    }

    pub(crate) fn checkpoint(&self) -> &crate::archive_v3_shadow_checkpoint::UploadedCheckpoint {
        &self.checkpoint
    }

    pub(crate) fn authenticate_wal_owner(
        self,
        recovery: &RecoveryRoot,
        binding: &crate::archive_v3_wal_owner::WalOwnerStoreBinding,
    ) -> Result<crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging> {
        crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging::from_exact_recovery(
            self.owned,
            recovery,
            &self.checkpoint,
            &self.recovered,
            binding,
        )
        .map_err(|_| ShadowWalError::CompositeRecovery)
    }
}

impl std::fmt::Debug for RecoveredMaintenanceStaging {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecoveredMaintenanceStaging(<redacted>)")
    }
}

pub(crate) async fn recover_owned_maintenance_staging(
    recovery: RecoveryRoot,
    backend: Arc<dyn ImmutableObjectBackend>,
    cipher: Arc<VerifiedArchiveCipher>,
    archive_id: ArchiveId,
) -> Result<RecoveredMaintenanceStaging> {
    if recovery.migration() != MigrationState::ShadowWal
        || recovery.deletion() != DeletionState::Active
    {
        return Err(ShadowWalError::CompositeRecovery);
    }
    recover_owned_private_staging_inner(
        recovery,
        Arc::new(OwnedExactBackend::Legacy(backend)),
        cipher,
        archive_id,
        None,
        true,
    )
    .await
}

/// Inactive WAL-owner recovery path. The exact WalAuthoritative recovery root
/// is consumed by composite recovery and then rebound to the same checkpoint
/// metadata before Store can open the owned staging copy.
pub(crate) async fn recover_owned_wal_owner_staging(
    recovery: RecoveryRoot,
    backend: Arc<dyn ExactImmutableObjectBackend>,
    cipher: Arc<VerifiedArchiveCipher>,
    archive_id: ArchiveId,
    binding: &crate::archive_v3_wal_owner::WalOwnerStoreBinding,
) -> Result<crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging> {
    if recovery.migration() != MigrationState::WalAuthoritative
        || recovery.deletion() != DeletionState::Active
    {
        return Err(ShadowWalError::CompositeRecovery);
    }
    let retained = recovery.clone();
    recover_owned_private_staging_inner(
        recovery,
        Arc::new(OwnedExactBackend::Narrow(backend)),
        cipher,
        archive_id,
        None,
        false,
    )
    .await?
    .authenticate_wal_owner(&retained, binding)
}

#[cfg(test)]
struct RecoveryObserver {
    path_sender: tokio::sync::oneshot::Sender<PathBuf>,
    cleanup_sender: tokio::sync::oneshot::Sender<()>,
}

#[cfg(not(test))]
struct RecoveryObserver;

#[cfg(test)]
async fn recover_owned_private_staging_observed(
    recovery: RecoveryRoot,
    backend: Arc<dyn ImmutableObjectBackend>,
    cipher: Arc<VerifiedArchiveCipher>,
    archive_id: ArchiveId,
    path_sender: tokio::sync::oneshot::Sender<PathBuf>,
    cleanup_sender: tokio::sync::oneshot::Sender<()>,
) -> Result<OwnedPrivateStagedSqliteCopy> {
    recover_owned_private_staging_inner(
        recovery,
        Arc::new(OwnedExactBackend::Legacy(backend)),
        cipher,
        archive_id,
        Some(RecoveryObserver {
            path_sender,
            cleanup_sender,
        }),
        false,
    )
    .await
    .map(|recovered| recovered.owned)
}

async fn recover_owned_private_staging_inner(
    recovery: RecoveryRoot,
    backend: Arc<OwnedExactBackend>,
    cipher: Arc<VerifiedArchiveCipher>,
    archive_id: ArchiveId,
    observer: Option<RecoveryObserver>,
    allow_maintenance_zero_wal: bool,
) -> Result<RecoveredMaintenanceStaging> {
    tokio::spawn(async move {
        let path = fresh_recovery_path()?;
        let mut cleanup = CompositeRecoveryCleanup::new(path.clone());
        observe_recovery(observer, &path, &mut cleanup);
        let mut checkpoint =
            TmpfsCheckpointSink::create(&path).map_err(|_| ShadowWalError::CompositeRecovery)?;
        let checkpoint_metadata = recover_checkpoint_from_recovery_root(
            &recovery,
            backend.as_ref(),
            cipher.as_ref(),
            archive_id,
            &mut checkpoint,
        )
        .await
        .map_err(|_| ShadowWalError::CompositeRecovery)?;
        let mut wal = CompositeWalRecoverySink::new(path.clone());
        let recovered = if allow_maintenance_zero_wal {
            recover_maintenance_zero_wal(
                &recovery,
                backend.as_ref(),
                cipher.as_ref(),
                archive_id,
                &mut wal,
            )
            .await?
        } else {
            recover_witness_nominated_wal(
                &recovery,
                backend.as_ref(),
                cipher.as_ref(),
                archive_id,
                &mut wal,
            )
            .await?
        };
        ensure_sqlite_sidecars_absent(&path).await?;
        let owned =
            OwnedPrivateStagedSqliteCopy::from_recovery_proof(CompositeRecoveryProof::new(path))
                .map_err(|_| ShadowWalError::CompositeRecovery)?;
        #[cfg(test)]
        let mut owned = owned;
        #[cfg(test)]
        owned.observe_cleanup_for_test(cleanup.cleanup_sender.take());
        cleanup.disarm();
        Ok(RecoveredMaintenanceStaging {
            owned,
            checkpoint: checkpoint_metadata,
            recovered,
        })
    })
    .await
    .map_err(|_| ShadowWalError::CompositeRecovery)?
}

fn observe_recovery(
    observer: Option<RecoveryObserver>,
    path: &Path,
    cleanup: &mut CompositeRecoveryCleanup,
) {
    #[cfg(test)]
    if let Some(observer) = observer {
        let _ = observer.path_sender.send(path.to_path_buf());
        cleanup.cleanup_sender = Some(observer.cleanup_sender);
    }
    #[cfg(not(test))]
    let _ = (observer, path, cleanup);
}

struct CompositeRecoveryCleanup {
    path: PathBuf,
    armed: bool,
    #[cfg(test)]
    cleanup_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl CompositeRecoveryCleanup {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            armed: true,
            #[cfg(test)]
            cleanup_sender: None,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CompositeRecoveryCleanup {
    fn drop(&mut self) {
        if self.armed {
            remove_private_sqlite_family(&self.path);
            #[cfg(test)]
            if let Some(cleanup_sender) = self.cleanup_sender.take() {
                let _ = cleanup_sender.send(());
            }
        }
    }
}

fn remove_private_sqlite_family(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(sqlite_sidecar_path(path, "-wal"));
    let _ = std::fs::remove_file(sqlite_sidecar_path(path, "-shm"));
}

struct CompositeWalRecoverySink {
    database_path: PathBuf,
    wal_path: PathBuf,
    file: Option<File>,
    generation: Option<u64>,
    next_frame_no: u64,
    aborted: bool,
}

impl CompositeWalRecoverySink {
    fn new(database_path: PathBuf) -> Self {
        Self {
            wal_path: sqlite_sidecar_path(&database_path, "-wal"),
            database_path,
            file: None,
            generation: None,
            next_frame_no: 0,
            aborted: false,
        }
    }
}

#[async_trait]
impl WalRecoverySink for CompositeWalRecoverySink {
    async fn begin_generation(
        &mut self,
        wal_generation: u64,
        header: &[u8; SQLITE_WAL_HEADER_BYTES],
        before_logical_file_length: u64,
    ) -> Result<()> {
        if self.aborted
            || self.file.is_some()
            || self.generation.is_some()
            || wal_generation == 0
            || self.wal_path.exists()
            || sqlite_sidecar_path(&self.database_path, "-shm").exists()
            || tokio::fs::metadata(&self.database_path)
                .await
                .map_err(|_| ShadowWalError::Sink)?
                .len()
                != before_logical_file_length
        {
            return Err(ShadowWalError::Sink);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.wal_path)
            .map_err(|_| ShadowWalError::Sink)?;
        file.write_all(header).map_err(|_| ShadowWalError::Sink)?;
        self.file = Some(file);
        self.generation = Some(wal_generation);
        self.next_frame_no = 1;
        Ok(())
    }

    async fn write_wal_frames(&mut self, first_frame_no: u64, frames: &[u8]) -> Result<()> {
        if self.aborted
            || first_frame_no != self.next_frame_no
            || frames.is_empty()
            || !frames.len().is_multiple_of(SQLITE_WAL_FRAME_BYTES)
        {
            return Err(ShadowWalError::Sink);
        }
        self.file
            .as_mut()
            .ok_or(ShadowWalError::Sink)?
            .write_all(frames)
            .map_err(|_| ShadowWalError::Sink)?;
        self.next_frame_no = self
            .next_frame_no
            .checked_add((frames.len() / SQLITE_WAL_FRAME_BYTES) as u64)
            .ok_or(ShadowWalError::Sink)?;
        Ok(())
    }

    async fn finish_generation(&mut self, after_logical_file_length: u64) -> Result<()> {
        if self.aborted || self.generation.is_none() || self.next_frame_no <= 1 {
            return Err(ShadowWalError::Sink);
        }
        let file = self.file.take().ok_or(ShadowWalError::Sink)?;
        let database_path = self.database_path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            file.sync_data().map_err(|_| ShadowWalError::Sink)?;
            drop(file);
            crate::store::init_vec_extension();
            let connection = rusqlite::Connection::open_with_flags(
                &database_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            )
            .map_err(|_| ShadowWalError::Sink)?;
            let (busy, remaining, checkpointed): (i64, i64, i64) = connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(|_| ShadowWalError::Sink)?;
            if busy != 0 || remaining != checkpointed {
                return Err(ShadowWalError::Sink);
            }
            drop(connection);
            let length = std::fs::metadata(&database_path)
                .map_err(|_| ShadowWalError::Sink)?
                .len();
            (length == after_logical_file_length)
                .then_some(())
                .ok_or(ShadowWalError::Sink)
        })
        .await
        .map_err(|_| ShadowWalError::Sink)??;
        remove_sidecar_strict(&self.wal_path).await?;
        remove_sidecar_strict(&sqlite_sidecar_path(&self.database_path, "-shm")).await?;
        ensure_sqlite_sidecars_absent(&self.database_path).await?;
        self.generation = None;
        self.next_frame_no = 0;
        Ok(())
    }

    fn abort(&mut self) {
        self.aborted = true;
        self.file.take();
        let _ = std::fs::remove_file(&self.wal_path);
        let _ = std::fs::remove_file(sqlite_sidecar_path(&self.database_path, "-shm"));
    }
}

impl Drop for CompositeWalRecoverySink {
    fn drop(&mut self) {
        self.abort();
    }
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

async fn remove_sidecar_strict(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ShadowWalError::Sink),
    }
}

async fn ensure_sqlite_sidecars_absent(path: &Path) -> Result<()> {
    for sidecar in [
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
    ] {
        match tokio::fs::symlink_metadata(sidecar).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(ShadowWalError::Sink),
        }
    }
    Ok(())
}

fn fresh_recovery_path() -> Result<PathBuf> {
    let tmp = std::fs::canonicalize("/tmp").map_err(|_| ShadowWalError::CompositeRecovery)?;
    for _ in 0..16 {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let mut suffix = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut suffix, "{byte:02x}");
        }
        let path = tmp.join(format!(".kioku-v3-recovery-{suffix}.db"));
        if !path.exists()
            && !sqlite_sidecar_path(&path, "-wal").exists()
            && !sqlite_sidecar_path(&path, "-shm").exists()
        {
            return Ok(path);
        }
    }
    Err(ShadowWalError::CompositeRecovery)
}

/// Opaque proof that the exact witnessed root had a checkpoint and either a
/// complete verified WAL chain or the one canonical maintenance-import
/// zero-WAL geometry. The composite staging path consumes this internally and
/// never exposes a partial checkpoint or WAL to its caller.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveredWitnessWal {
    checkpoint_root: ImmutableReference,
    root_seq: u64,
    wal_generation: u64,
    commit_count: u32,
    segment_count: u32,
    wal_tail_bytes: u64,
    logical_file_length: u64,
    user_schema_version: u32,
}

impl RecoveredWitnessWal {
    pub(super) const fn logical_file_length(&self) -> u64 {
        self.logical_file_length
    }

    pub(super) const fn user_schema_version(&self) -> u32 {
        self.user_schema_version
    }
}

impl std::fmt::Debug for RecoveredWitnessWal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveredWitnessWal(<opaque>)")
    }
}

/// Recover exactly the checkpoint-plus-WAL state nominated by an independently
/// obtained witness recovery record. It derives every root and WAL context
/// from that record and follows only authenticated predecessor references.
/// There is no prefix enumeration, orphan selection, or fallback to a newer
/// local WAL. The caller's checkpoint staging flow must use this *same*
/// `RecoveryRoot` before its composite sink publishes either temporary file.
pub(crate) async fn recover_witness_nominated_wal(
    recovery: &RecoveryRoot,
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    sink: &mut dyn WalRecoverySink,
) -> Result<RecoveredWitnessWal> {
    let result =
        recover_witness_nominated_wal_inner(recovery, backend, cipher, archive_id, sink, false)
            .await;
    if result.is_err() {
        sink.abort();
    }
    result
}

async fn recover_witness_nominated_wal_inner(
    recovery: &RecoveryRoot,
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    sink: &mut dyn WalRecoverySink,
    allow_maintenance_zero_wal: bool,
) -> Result<RecoveredWitnessWal> {
    validate_recovery_cipher(recovery, cipher, archive_id)?;
    let commitment = recovery.root();
    let root = load_root(
        backend,
        cipher,
        archive_id,
        commitment.root(),
        commitment.parent(),
        commitment.database_epoch(),
        commitment.key_epoch(),
    )
    .await?;
    if root.owner_fencing_epoch != commitment.owner_fencing_epoch() {
        return Err(ArchiveV3Error::Authentication.into());
    }
    recover_exact_root_wal_mode(
        &root,
        backend,
        cipher,
        archive_id,
        sink,
        allow_maintenance_zero_wal,
    )
    .await
}

async fn recover_maintenance_zero_wal(
    recovery: &RecoveryRoot,
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    sink: &mut dyn WalRecoverySink,
) -> Result<RecoveredWitnessWal> {
    let result =
        recover_witness_nominated_wal_inner(recovery, backend, cipher, archive_id, sink, true)
            .await;
    if result.is_err() {
        sink.abort();
    }
    result
}

/// This private helper is deliberately reachable only after
/// `load_witness_root` has authenticated the root. Keeping the chain walker
/// separate makes that proof boundary auditable and testable without creating
/// a second root-selection API.
async fn recover_exact_root_wal(
    root: &ArchiveRoot,
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    sink: &mut dyn WalRecoverySink,
) -> Result<RecoveredWitnessWal> {
    recover_exact_root_wal_mode(root, backend, cipher, archive_id, sink, false).await
}

async fn recover_exact_root_wal_mode(
    root: &ArchiveRoot,
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    sink: &mut dyn WalRecoverySink,
    allow_maintenance_zero_wal: bool,
) -> Result<RecoveredWitnessWal> {
    root.validate()?;
    let checkpoint_root = root
        .checkpoint_root
        .clone()
        .ok_or(ShadowWalError::MissingCheckpointOrWal)?;
    if allow_maintenance_zero_wal
        && root.wal_commit_tail.is_none()
        && root.wal_generation == 0
        && root.wal_commit_count == 0
        && root.wal_segment_count == 0
        && root.wal_tail_bytes == 0
        && root.extent_tree_root.is_none()
        && root.checkpoint_logical_file_length == root.logical_file_length
    {
        return Ok(RecoveredWitnessWal {
            checkpoint_root,
            root_seq: root.root_seq,
            wal_generation: 0,
            commit_count: 0,
            segment_count: 0,
            wal_tail_bytes: 0,
            logical_file_length: root.logical_file_length,
            user_schema_version: root.user_schema_version,
        });
    }
    let final_reference = root
        .wal_commit_tail
        .clone()
        .ok_or(ShadowWalError::MissingCheckpointOrWal)?;
    if root.wal_generation == 0
        || root.wal_commit_count == 0
        || root.wal_segment_count == 0
        || root.wal_tail_bytes == 0
    {
        return Err(ShadowWalError::MissingCheckpointOrWal);
    }

    // Retain only bounded descriptors until the whole root/descriptor topology
    // validates. The sink therefore observes no authenticated prefix from a
    // lineage that later proves disconnected.
    let mut reversed_commits = Vec::with_capacity(root.wal_commit_count as usize);
    let mut expected_reference = Some(final_reference);
    let mut expected_root_seq = root.root_seq;
    let mut expected_parent = root
        .parent
        .clone()
        .ok_or(ArchiveV3Error::Malformed("WAL root parent"))?;
    let mut expected_after_length = root.logical_file_length;
    for expected_commit_count in (1..=root.wal_commit_count).rev() {
        let reference = expected_reference
            .take()
            .ok_or(ArchiveV3Error::Malformed("WAL commit predecessor"))?;
        let context = wal_commit_context(
            archive_id,
            root.database_epoch,
            root.key_epoch,
            expected_root_seq,
            reference.object_id,
        )?;
        let resolved =
            load_exact_wal_commit_descriptor(backend, cipher, &context, &reference).await?;
        let descriptor = resolved.descriptor();
        if descriptor.root_seq != expected_root_seq
            || descriptor.parent_root != expected_parent
            || descriptor.checkpoint_root != checkpoint_root
            || descriptor.checkpoint_logical_file_length != root.checkpoint_logical_file_length
            || descriptor.after_logical_file_length != expected_after_length
            || descriptor.cumulative_commit_count != expected_commit_count
            || (expected_commit_count == root.wal_commit_count
                && (descriptor.cumulative_segment_count != root.wal_segment_count
                    || descriptor.cumulative_wal_bytes != root.wal_tail_bytes
                    || descriptor.wal_generation != root.wal_generation))
        {
            return Err(ArchiveV3Error::Authentication.into());
        }
        expected_reference = descriptor.previous_commit.clone();
        expected_root_seq = expected_root_seq
            .checked_sub(1)
            .ok_or(ArchiveV3Error::Malformed("WAL root sequence"))?;
        expected_parent = descriptor
            .parent_root_parent
            .clone()
            .unwrap_or_else(|| descriptor.parent_root.clone());
        expected_after_length = descriptor.before_logical_file_length;
        reversed_commits.push(resolved);
    }
    if expected_reference.is_some()
        || expected_after_length != root.checkpoint_logical_file_length
        || expected_root_seq.checked_add(root.wal_commit_count as u64) != Some(root.root_seq)
    {
        return Err(ArchiveV3Error::Malformed("WAL lineage base").into());
    }
    reversed_commits.reverse();
    let mut previous: Option<&WalCommitDescriptor> = None;
    for resolved in &reversed_commits {
        let descriptor = resolved.descriptor();
        if let Some(previous) = previous {
            if Some(descriptor.root_seq) != previous.root_seq.checked_add(1)
                || descriptor.parent_root_parent.as_ref() != Some(&previous.parent_root)
                || descriptor.before_logical_file_length != previous.after_logical_file_length
                || descriptor.cumulative_commit_count != previous.cumulative_commit_count + 1
                || descriptor.cumulative_segment_count
                    != previous.cumulative_segment_count + descriptor.commit_segment_count
                || descriptor.cumulative_wal_bytes
                    != previous.cumulative_wal_bytes + descriptor.commit_wal_bytes
                || (descriptor.wal_generation == previous.wal_generation
                    && (descriptor.first_frame_no
                        != previous
                            .first_frame_no
                            .checked_add(u64::from(previous.frame_count))
                            .ok_or(ArchiveV3Error::Malformed("WAL frame sequence"))?
                        || descriptor.wal_header_hash != previous.wal_header_hash
                        || descriptor.checksum_before != previous.checksum_after))
                || (descriptor.wal_generation != previous.wal_generation
                    && (Some(descriptor.wal_generation) != previous.wal_generation.checked_add(1)
                        || descriptor.first_frame_no != 1))
            {
                return Err(ArchiveV3Error::Malformed("WAL commit continuity").into());
            }
        } else if descriptor.cumulative_commit_count != 1
            || descriptor.cumulative_segment_count != descriptor.commit_segment_count
            || descriptor.cumulative_wal_bytes != descriptor.commit_wal_bytes
            || descriptor.before_logical_file_length != root.checkpoint_logical_file_length
            || descriptor.wal_generation != 1
            || descriptor.first_frame_no != 1
        {
            return Err(ArchiveV3Error::Malformed("WAL first commit").into());
        }
        previous = Some(descriptor);
    }

    let mut active_generation = None;
    for resolved in &reversed_commits {
        let descriptor = resolved.descriptor();
        let segments = load_commit_segments(backend, cipher, archive_id, root, descriptor).await?;
        validate_wal_commit_chain(descriptor, &segments)?;
        if active_generation != Some(descriptor.wal_generation) {
            if active_generation.is_some() {
                sink.finish_generation(descriptor.before_logical_file_length)
                    .await?;
            }
            sink.begin_generation(
                descriptor.wal_generation,
                &segments[0].segment().wal_header,
                descriptor.before_logical_file_length,
            )
            .await?;
            active_generation = Some(descriptor.wal_generation);
        }
        for entry in &segments {
            sink.write_wal_frames(entry.segment().first_frame_no, &entry.segment().frames)
                .await?;
        }
    }
    sink.finish_generation(root.logical_file_length).await?;
    Ok(RecoveredWitnessWal {
        checkpoint_root,
        root_seq: root.root_seq,
        wal_generation: root.wal_generation,
        commit_count: root.wal_commit_count,
        segment_count: root.wal_segment_count,
        wal_tail_bytes: root.wal_tail_bytes,
        logical_file_length: root.logical_file_length,
        user_schema_version: root.user_schema_version,
    })
}

fn wal_context(
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: crate::archive_v3::KeyEpoch,
    root_seq: u64,
    wal_generation: u64,
    segment_index: u32,
    object_id: ObjectId,
) -> std::result::Result<ObjectContext, ArchiveV3Error> {
    ObjectContext::new(
        archive_id,
        database_epoch,
        key_epoch,
        ObjectRole::WalSegmentV3,
        LogicalLocation::Wal {
            root_seq,
            wal_generation,
            segment_index,
        },
        object_id,
        None,
    )
}

fn wal_commit_context(
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: crate::archive_v3::KeyEpoch,
    root_seq: u64,
    object_id: ObjectId,
) -> std::result::Result<ObjectContext, ArchiveV3Error> {
    ObjectContext::new(
        archive_id,
        database_epoch,
        key_epoch,
        ObjectRole::WalCommitDescriptorV3,
        LogicalLocation::WalCommitDescriptor { root_seq },
        object_id,
        None,
    )
}

async fn load_exact_wal_segment(
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    context: &ObjectContext,
    reference: &ImmutableReference,
) -> Result<ResolvedWalSegment> {
    if context.object_id() != reference.object_id {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let envelope = backend
        .get(&context.object_key())
        .await?
        .ok_or(ShadowWalError::MissingObject)?;
    Ok(resolve_verified_wal_segment(
        cipher,
        context.clone(),
        reference.clone(),
        envelope,
    )?)
}

async fn load_exact_wal_commit_descriptor(
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    context: &ObjectContext,
    reference: &ImmutableReference,
) -> Result<ResolvedWalCommitDescriptor> {
    if context.object_id() != reference.object_id {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let envelope = backend
        .get(&context.object_key())
        .await?
        .ok_or(ShadowWalError::MissingObject)?;
    Ok(resolve_verified_wal_commit_descriptor(
        cipher,
        context.clone(),
        reference.clone(),
        envelope,
    )?)
}

async fn load_commit_segments(
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    root: &ArchiveRoot,
    descriptor: &WalCommitDescriptor,
) -> Result<Vec<ResolvedWalSegment>> {
    let mut reversed = Vec::with_capacity(descriptor.commit_segment_count as usize);
    let mut expected_reference = Some(descriptor.final_segment.clone());
    for segment_index in (0..descriptor.commit_segment_count).rev() {
        let reference = expected_reference
            .take()
            .ok_or(ArchiveV3Error::Malformed("WAL missing predecessor"))?;
        let context = wal_context(
            archive_id,
            root.database_epoch,
            root.key_epoch,
            descriptor.root_seq,
            descriptor.wal_generation,
            segment_index,
            reference.object_id,
        )?;
        let resolved = load_exact_wal_segment(backend, cipher, &context, &reference).await?;
        expected_reference = resolved.segment().previous_segment.clone();
        reversed.push(resolved);
    }
    if expected_reference.is_some() {
        return Err(ArchiveV3Error::Malformed("WAL first predecessor").into());
    }
    reversed.reverse();
    Ok(reversed)
}

async fn validate_capture_continuity(
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    base: &ArchiveRoot,
    capture: &CapturedWalCommit,
) -> Result<()> {
    let Some(reference) = base.wal_commit_tail.as_ref() else {
        return if base.wal_commit_count == 0
            && base.wal_generation == 0
            && base.wal_segment_count == 0
            && base.wal_tail_bytes == 0
            && capture.first_frame_no() == 1
        {
            Ok(())
        } else {
            Err(ArchiveV3Error::Malformed("WAL initial capture").into())
        };
    };
    let context = wal_commit_context(
        archive_id,
        base.database_epoch,
        base.key_epoch,
        base.root_seq,
        reference.object_id,
    )?;
    let previous = load_exact_wal_commit_descriptor(backend, cipher, &context, reference).await?;
    let previous = previous.descriptor();
    let same_generation = capture.wal_generation() == previous.wal_generation;
    let next_generation = capture.wal_generation() == previous.wal_generation.saturating_add(1);
    if (same_generation
        && capture.first_frame_no()
            == previous
                .first_frame_no
                .checked_add(u64::from(previous.frame_count))
                .ok_or(ArchiveV3Error::Malformed("WAL frame sequence"))?
        && <[u8; 32]>::from(Sha256::digest(capture.replay_header())) == previous.wal_header_hash
        && capture.replay_checksum_before() == previous.checksum_after)
        || (next_generation && capture.first_frame_no() == 1)
    {
        Ok(())
    } else {
        Err(ArchiveV3Error::Malformed("WAL capture continuity").into())
    }
}

fn captured_terminal_checksum(capture: &CapturedWalCommit) -> Result<[u32; 2]> {
    let frames = capture.replay_frames();
    let offset = frames
        .len()
        .checked_sub(SQLITE_WAL_FRAME_BYTES)
        .ok_or(ArchiveV3Error::Malformed("WAL terminal checksum"))?;
    let last = frames
        .get(offset..)
        .ok_or(ArchiveV3Error::Malformed("WAL terminal checksum"))?;
    Ok([
        u32::from_be_bytes(
            last[16..20]
                .try_into()
                .map_err(|_| ArchiveV3Error::Malformed("WAL terminal checksum"))?,
        ),
        u32::from_be_bytes(
            last[20..24]
                .try_into()
                .map_err(|_| ArchiveV3Error::Malformed("WAL terminal checksum"))?,
        ),
    ])
}

fn validate_recovery_cipher(
    recovery: &RecoveryRoot,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
) -> Result<()> {
    let commitment = recovery.root();
    let registry = recovery.registry();
    if recovery.archive_id() != archive_id
        || cipher.archive_id() != archive_id
        || cipher.key_epoch() != commitment.key_epoch()
        || registry.key_epoch() != commitment.key_epoch()
        || registry.rotation_generation() != cipher.registry_rotation_generation()
        || registry.object_id() != cipher.registry_object_id()
        || registry.ciphertext_hash() != cipher.registry_ciphertext_hash()
    {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn load_root(
    backend: &dyn ExactImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    reference: RootReference,
    parent: Option<RootReference>,
    database_epoch: DatabaseEpoch,
    key_epoch: crate::archive_v3::KeyEpoch,
) -> Result<ArchiveRoot> {
    let parent = parent.map(|value| ParentReference {
        object_id: value.object_id(),
        envelope_hash: value.ciphertext_hash(),
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
    let envelope = backend
        .get(&context.object_key())
        .await?
        .ok_or(ShadowWalError::MissingObject)?;
    if envelope.hash() != expected.envelope_hash {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let plaintext = Zeroizing::new(cipher.open(&context, &envelope)?);
    let root = ArchiveRoot::decode(plaintext.as_slice())?;
    root.validate_for_context(&context)?;
    if root.database_epoch != database_epoch || root.key_epoch != key_epoch {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn wal_owner_checkpoint_gate_reserves_one_maximum_commit_exactly() {
        assert!(!wal_owner_checkpoint_geometry_requires(
            u64::from(MAX_WAL_COMMITS_PER_ROOT - 1),
            u64::from(MAX_WAL_SEGMENTS_PER_ROOT - MAX_WAL_SEGMENTS_PER_COMMIT),
            MAX_WAL_TAIL_BYTES - 8 * 1024 * 1024,
        ));
        assert!(wal_owner_checkpoint_geometry_requires(
            u64::from(MAX_WAL_COMMITS_PER_ROOT),
            0,
            0,
        ));
        assert!(wal_owner_checkpoint_geometry_requires(
            0,
            u64::from(MAX_WAL_SEGMENTS_PER_ROOT - MAX_WAL_SEGMENTS_PER_COMMIT + 1),
            0,
        ));
        assert!(wal_owner_checkpoint_geometry_requires(
            0,
            0,
            MAX_WAL_TAIL_BYTES - 8 * 1024 * 1024 + 1,
        ));
    }
    use crate::{
        archive_v3::{
            resolve_archive_cipher, ArchiveDek, ArchivePrefix, CiphertextEnvelope, CreateIfAbsent,
            EnumerationCursor, EnumerationLimit, EnumerationPage, ExactKeyRegistryProvider,
            InMemoryImmutableBackend, KeyEpoch, KeyKind, KeyRegistryContext, KeyRegistryPlaintext,
            ObjectKey,
        },
        archive_v3_operation::{RecordOutcome, ShadowObjectFacts, ShadowObjectInventoryPage},
        archive_v3_shadow::{ShadowSyncOutcome, WalCaptureState},
        archive_v3_shadow_checkpoint::{
            upload_checkpoint, CheckpointSource, ShadowCheckpointError, ShadowObjectInventory,
            ShadowObjectInventoryError, ShadowObjectStaging,
        },
        archive_v3_shadow_session::{ShadowAttemptId, ShadowSessionBinding, ShadowSessionId},
        archive_v3_witness::{
            ExactRootProvider, InMemoryWitness, KeyRegistryReference, RootAdvance, RootCommitment,
            Witness, WitnessBootstrap, WitnessError,
        },
    };
    use std::sync::Mutex;

    const WRAPPED: &[u8] = b"shadow-wal-test-registry";

    struct TestInventory;

    #[async_trait]
    impl ShadowObjectInventory for TestInventory {
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

    static TEST_INVENTORY: TestInventory = TestInventory;

    fn test_staging() -> ShadowObjectStaging<'static> {
        ShadowObjectStaging::new(
            &TEST_INVENTORY,
            ShadowSessionId::from_bytes([0x91; 16]),
            ShadowAttemptId::from_bytes([0x92; 16]),
            ShadowSessionBinding::new(
                [1; 16], [2; 16], 1, [3; 16], 1, [4; 16], [5; 32], 1, [6; 16], [7; 32], 1, [8; 16],
                [9; 32], 1, 1, 1, 1,
            )
            .unwrap(),
        )
    }

    struct VecCheckpointSource(Vec<u8>);

    impl CheckpointSource for VecCheckpointSource {
        fn logical_file_length(&self) -> crate::archive_v3_shadow_checkpoint::Result<u64> {
            Ok(self.0.len() as u64)
        }

        fn read_exact(
            &mut self,
            logical_offset: u64,
            destination: &mut [u8],
        ) -> crate::archive_v3_shadow_checkpoint::Result<()> {
            let start =
                usize::try_from(logical_offset).map_err(|_| ShadowCheckpointError::Source)?;
            let end = start
                .checked_add(destination.len())
                .ok_or(ShadowCheckpointError::Source)?;
            destination.copy_from_slice(
                self.0
                    .get(start..end)
                    .ok_or(ShadowCheckpointError::Source)?,
            );
            Ok(())
        }
    }

    struct RegistryProvider {
        plaintext: Vec<u8>,
    }

    /// A provider fault after an accepted immutable create. Publication must
    /// fail before a caller receives a root-composable reference.
    struct MissingReadbackBackend {
        inner: InMemoryImmutableBackend,
    }

    struct NoListBackend {
        inner: InMemoryImmutableBackend,
    }

    #[derive(Clone)]
    enum ReadFault {
        None,
        Missing(String),
        Tampered(String),
        Swap(String),
        StallOnOccurrence {
            object_id: ObjectId,
            occurrence: usize,
        },
    }

    struct FaultingBackend {
        archive_id: ArchiveId,
        inner: InMemoryImmutableBackend,
        fault: Mutex<ReadFault>,
        creates: Mutex<usize>,
        matching_reads: Mutex<usize>,
        stall_started: tokio::sync::Notify,
        stall_release: tokio::sync::Notify,
    }

    impl FaultingBackend {
        fn new(archive_id: ArchiveId) -> Self {
            Self {
                archive_id,
                inner: InMemoryImmutableBackend::new(),
                fault: Mutex::new(ReadFault::None),
                creates: Mutex::new(0),
                matching_reads: Mutex::new(0),
                stall_started: tokio::sync::Notify::new(),
                stall_release: tokio::sync::Notify::new(),
            }
        }

        fn set_fault(&self, fault: ReadFault) {
            *self.fault.lock().unwrap() = fault;
            *self.matching_reads.lock().unwrap() = 0;
        }

        fn create_count(&self) -> usize {
            *self.creates.lock().unwrap()
        }
    }

    #[async_trait]
    impl ImmutableObjectBackend for FaultingBackend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: CiphertextEnvelope,
        ) -> crate::archive_v3::Result<CreateIfAbsent> {
            *self.creates.lock().unwrap() += 1;
            ImmutableObjectBackend::create_if_absent(&self.inner, key, value).await
        }

        async fn get(
            &self,
            key: &ObjectKey,
        ) -> crate::archive_v3::Result<Option<CiphertextEnvelope>> {
            let fault = self.fault.lock().unwrap().clone();
            match fault {
                ReadFault::Missing(pattern) if key.as_str().contains(&pattern) => return Ok(None),
                ReadFault::Tampered(pattern) if key.as_str().contains(&pattern) => {
                    let Some(envelope) = ImmutableObjectBackend::get(&self.inner, key).await?
                    else {
                        return Ok(None);
                    };
                    let mut encoded = envelope.encode();
                    let last = encoded
                        .last_mut()
                        .ok_or(ArchiveV3Error::Malformed("test envelope"))?;
                    *last ^= 1;
                    return Ok(Some(CiphertextEnvelope::decode(&encoded)?));
                }
                ReadFault::Swap(pattern) if key.as_str().contains(&pattern) => {
                    let prefix = ArchivePrefix::for_archive(self.archive_id);
                    let page = self
                        .inner
                        .enumerate(&prefix, None, EnumerationLimit::new(1_000)?)
                        .await?;
                    for candidate in page.objects {
                        if candidate != *key && candidate.as_str().contains(&pattern) {
                            return ImmutableObjectBackend::get(&self.inner, &candidate).await;
                        }
                    }
                    return Ok(None);
                }
                ReadFault::StallOnOccurrence {
                    object_id,
                    occurrence,
                } if key.object_id() == object_id => {
                    let should_stall = {
                        let mut reads = self.matching_reads.lock().unwrap();
                        *reads += 1;
                        *reads == occurrence
                    };
                    if should_stall {
                        self.stall_started.notify_one();
                        self.stall_release.notified().await;
                    }
                }
                _ => {}
            }
            ImmutableObjectBackend::get(&self.inner, key).await
        }

        async fn enumerate(
            &self,
            _prefix: &ArchivePrefix,
            _cursor: Option<&EnumerationCursor>,
            _limit: EnumerationLimit,
        ) -> crate::archive_v3::Result<EnumerationPage> {
            panic!("WAL publication and recovery must never list storage")
        }

        async fn delete_exact(&self, key: &ObjectKey) -> crate::archive_v3::Result<bool> {
            self.inner.delete_exact(key).await
        }
    }

    #[async_trait]
    impl ExactRootProvider for FaultingBackend {
        async fn read_exact(
            &self,
            context: &ObjectContext,
        ) -> std::result::Result<CiphertextEnvelope, WitnessError> {
            ImmutableObjectBackend::get(self, &context.object_key())
                .await
                .map_err(|_| WitnessError::Malformed)?
                .ok_or(WitnessError::MissingRootObject)
        }
    }

    #[async_trait]
    impl ImmutableObjectBackend for NoListBackend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: crate::archive_v3::CiphertextEnvelope,
        ) -> crate::archive_v3::Result<CreateIfAbsent> {
            ImmutableObjectBackend::create_if_absent(&self.inner, key, value).await
        }

        async fn get(
            &self,
            key: &ObjectKey,
        ) -> crate::archive_v3::Result<Option<crate::archive_v3::CiphertextEnvelope>> {
            ImmutableObjectBackend::get(&self.inner, key).await
        }

        async fn enumerate(
            &self,
            _prefix: &ArchivePrefix,
            _cursor: Option<&EnumerationCursor>,
            _limit: EnumerationLimit,
        ) -> crate::archive_v3::Result<EnumerationPage> {
            panic!("WAL publication and recovery must never list storage")
        }

        async fn delete_exact(&self, key: &ObjectKey) -> crate::archive_v3::Result<bool> {
            self.inner.delete_exact(key).await
        }
    }

    #[async_trait]
    impl ImmutableObjectBackend for MissingReadbackBackend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: crate::archive_v3::CiphertextEnvelope,
        ) -> crate::archive_v3::Result<CreateIfAbsent> {
            ImmutableObjectBackend::create_if_absent(&self.inner, key, value).await
        }

        async fn get(
            &self,
            _key: &ObjectKey,
        ) -> crate::archive_v3::Result<Option<crate::archive_v3::CiphertextEnvelope>> {
            Ok(None)
        }

        async fn enumerate(
            &self,
            prefix: &ArchivePrefix,
            cursor: Option<&EnumerationCursor>,
            limit: EnumerationLimit,
        ) -> crate::archive_v3::Result<EnumerationPage> {
            self.inner.enumerate(prefix, cursor, limit).await
        }

        async fn delete_exact(&self, key: &ObjectKey) -> crate::archive_v3::Result<bool> {
            self.inner.delete_exact(key).await
        }
    }

    #[async_trait]
    impl ExactKeyRegistryProvider for RegistryProvider {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            _object_id: ObjectId,
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            destination[..WRAPPED.len()].copy_from_slice(WRAPPED);
            Ok(WRAPPED.len())
        }

        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            _wrapped: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }

    async fn test_cipher(archive: ArchiveId, key: KeyEpoch) -> VerifiedArchiveCipher {
        let context = KeyRegistryContext::new(archive, KeyKind::Archive, key);
        let plaintext =
            KeyRegistryPlaintext::encode_archive(&context, &ArchiveDek::from_bytes([7; 32]))
                .unwrap()
                .to_vec();
        resolve_archive_cipher(
            &context,
            ObjectId::from_bytes([9; 16]),
            Sha256::digest(WRAPPED).into(),
            &RegistryProvider { plaintext },
        )
        .await
        .unwrap()
    }

    async fn upload_captured_wal_commit(
        backend: &dyn ExactImmutableObjectBackend,
        cipher: &VerifiedArchiveCipher,
        archive: ArchiveId,
        database: DatabaseEpoch,
        root_seq: u64,
        capture: &CapturedWalCommit,
    ) -> Result<UploadedWalCommit> {
        let base_seq = root_seq.checked_sub(1).unwrap();
        let base_reference = RootReference::new(base_seq, ObjectId::from_bytes([6; 16]), [7; 32]);
        let base_parent_reference = base_seq
            .checked_sub(1)
            .map(|sequence| RootReference::new(sequence, ObjectId::from_bytes([8; 16]), [9; 32]));
        let base = ArchiveRoot {
            root_seq: base_seq,
            parent: base_parent_reference.map(|value| ParentReference {
                object_id: value.object_id(),
                envelope_hash: value.ciphertext_hash(),
            }),
            database_epoch: database,
            key_epoch: cipher.key_epoch(),
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([4; 16]),
                envelope_hash: [5; 32],
            }),
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        super::upload_captured_wal_commit_from_base(
            backend,
            cipher,
            archive,
            &base,
            base_reference,
            base_parent_reference,
            1,
            [10; 16],
            [11; 32],
            capture,
            &super::DirectWalObjectStaging,
        )
        .await
    }

    fn checksum(input: &[u8], mut state: [u32; 2]) -> [u32; 2] {
        for pair in input.chunks_exact(8) {
            let first = u32::from_le_bytes(pair[..4].try_into().unwrap());
            let second = u32::from_le_bytes(pair[4..].try_into().unwrap());
            state[0] = state[0].wrapping_add(first).wrapping_add(state[1]);
            state[1] = state[1].wrapping_add(second).wrapping_add(state[0]);
        }
        state
    }

    fn captured_commit(frames: usize) -> CapturedWalCommit {
        captured_commit_with_page_count(frames, 1)
    }

    fn captured_commit_with_page_count(frames: usize, page_count: u32) -> CapturedWalCommit {
        let mut header = [0u8; SQLITE_WAL_HEADER_BYTES];
        header[..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        header[4..8].copy_from_slice(&3_007_000u32.to_be_bytes());
        header[8..12].copy_from_slice(&SQLITE_PAGE_SIZE.to_be_bytes());
        header[12..16].copy_from_slice(&1u32.to_be_bytes());
        header[16..20].copy_from_slice(&[11, 12, 13, 14]);
        header[20..24].copy_from_slice(&[21, 22, 23, 24]);
        let header_checksum = checksum(&header[..24], [0, 0]);
        header[24..28].copy_from_slice(&header_checksum[0].to_be_bytes());
        header[28..32].copy_from_slice(&header_checksum[1].to_be_bytes());

        let mut all_frames = vec![0; frames * SQLITE_WAL_FRAME_BYTES];
        let mut rolling = header_checksum;
        for frame_index in 0..frames {
            let frame = &mut all_frames
                [frame_index * SQLITE_WAL_FRAME_BYTES..(frame_index + 1) * SQLITE_WAL_FRAME_BYTES];
            frame[..4].copy_from_slice(&(frame_index as u32 + 1).to_be_bytes());
            if frame_index + 1 == frames {
                frame[4..8].copy_from_slice(&page_count.to_be_bytes());
            }
            frame[8..16].copy_from_slice(&header[16..24]);
            frame[24..].fill((frame_index % 251) as u8);
            rolling = checksum(&frame[..8], rolling);
            rolling = checksum(&frame[24..], rolling);
            frame[16..20].copy_from_slice(&rolling[0].to_be_bytes());
            frame[20..24].copy_from_slice(&rolling[1].to_be_bytes());
        }
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &header);
        capture.observe_write(SQLITE_WAL_HEADER_BYTES as i64, &all_frames);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        capture.drain_completed().pop().unwrap()
    }

    fn two_captured_commits() -> Vec<CapturedWalCommit> {
        two_captured_commits_with_page_counts([1, 1])
    }

    fn two_captured_commits_with_page_counts(page_counts: [u32; 2]) -> Vec<CapturedWalCommit> {
        let mut header = [0u8; SQLITE_WAL_HEADER_BYTES];
        header[..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        header[4..8].copy_from_slice(&3_007_000u32.to_be_bytes());
        header[8..12].copy_from_slice(&SQLITE_PAGE_SIZE.to_be_bytes());
        header[12..16].copy_from_slice(&1u32.to_be_bytes());
        header[16..20].copy_from_slice(&[11, 12, 13, 14]);
        header[20..24].copy_from_slice(&[21, 22, 23, 24]);
        let mut rolling = checksum(&header[..24], [0, 0]);
        header[24..28].copy_from_slice(&rolling[0].to_be_bytes());
        header[28..32].copy_from_slice(&rolling[1].to_be_bytes());
        let mut frames = vec![0; 2 * SQLITE_WAL_FRAME_BYTES];
        for index in 0..2 {
            let frame =
                &mut frames[index * SQLITE_WAL_FRAME_BYTES..(index + 1) * SQLITE_WAL_FRAME_BYTES];
            frame[..4].copy_from_slice(&(index as u32 + 1).to_be_bytes());
            frame[4..8].copy_from_slice(&page_counts[index].to_be_bytes());
            frame[8..16].copy_from_slice(&header[16..24]);
            frame[24..].fill(index as u8);
            rolling = checksum(&frame[..8], rolling);
            rolling = checksum(&frame[24..], rolling);
            frame[16..20].copy_from_slice(&rolling[0].to_be_bytes());
            frame[20..24].copy_from_slice(&rolling[1].to_be_bytes());
        }
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &header);
        capture.observe_write(SQLITE_WAL_HEADER_BYTES as i64, &frames);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        capture.drain_completed()
    }

    fn real_sqlite_checkpoint_and_commits() -> (Vec<u8>, Vec<CapturedWalCommit>) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lineage.db");
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "PRAGMA page_size=4096;
                 PRAGMA journal_mode=WAL;
                 PRAGMA wal_autocheckpoint=0;
                 CREATE TABLE recovered_values(value TEXT NOT NULL);
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .unwrap();
        let checkpoint = std::fs::read(&path).unwrap();
        assert!(checkpoint.len().is_multiple_of(SQLITE_PAGE_SIZE as usize));

        let mut capture = WalCaptureState::new();
        connection
            .execute("INSERT INTO recovered_values VALUES('first')", [])
            .unwrap();
        let wal_path = sqlite_sidecar_path(&path, "-wal");
        let first_wal = std::fs::read(&wal_path).unwrap();
        capture.observe_write(0, &first_wal);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        let mut commits = capture.drain_completed();

        connection
            .execute("INSERT INTO recovered_values VALUES('second')", [])
            .unwrap();
        let second_wal = std::fs::read(&wal_path).unwrap();
        assert!(second_wal.starts_with(&first_wal));
        capture.observe_write(first_wal.len() as i64, &second_wal[first_wal.len()..]);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        commits.extend(capture.drain_completed());
        assert_eq!(commits.len(), 2);
        (checkpoint, commits)
    }

    fn real_sqlite_grow_then_shrink() -> (Vec<u8>, Vec<CapturedWalCommit>, u64, u64) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("grow-shrink.db");
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "PRAGMA page_size=4096;
                 PRAGMA auto_vacuum=FULL;
                 VACUUM;
                 PRAGMA journal_mode=WAL;
                 PRAGMA wal_autocheckpoint=0;
                 CREATE TABLE recovered_values(value BLOB NOT NULL);
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .unwrap();
        let checkpoint = std::fs::read(&path).unwrap();
        assert!(checkpoint.len().is_multiple_of(SQLITE_PAGE_SIZE as usize));

        let mut capture = WalCaptureState::new();
        connection
            .execute_batch(
                "WITH RECURSIVE counter(value) AS (
                     VALUES(1)
                     UNION ALL
                     SELECT value + 1 FROM counter WHERE value < 128
                 )
                 INSERT INTO recovered_values(value)
                 SELECT zeroblob(3000) FROM counter;",
            )
            .unwrap();
        let wal_path = sqlite_sidecar_path(&path, "-wal");
        let grown_wal = std::fs::read(&wal_path).unwrap();
        capture.observe_write(0, &grown_wal);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        let mut commits = capture.drain_completed();

        connection
            .execute_batch("DELETE FROM recovered_values;")
            .unwrap();
        let shrunk_wal = std::fs::read(&wal_path).unwrap();
        assert!(shrunk_wal.starts_with(&grown_wal));
        capture.observe_write(grown_wal.len() as i64, &shrunk_wal[grown_wal.len()..]);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        commits.extend(capture.drain_completed());
        assert_eq!(commits.len(), 2);

        let grown_length = commits[0].effective_logical_file_length(1).unwrap();
        let shrunk_length = commits[1].effective_logical_file_length(2).unwrap();
        assert!(grown_length > checkpoint.len() as u64);
        assert!(shrunk_length < grown_length);
        (checkpoint, commits, grown_length, shrunk_length)
    }

    fn generation_rollover_commits() -> Vec<CapturedWalCommit> {
        fn wal(seed: u8) -> Vec<u8> {
            let mut header = [0u8; SQLITE_WAL_HEADER_BYTES];
            header[..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
            header[4..8].copy_from_slice(&3_007_000u32.to_be_bytes());
            header[8..12].copy_from_slice(&SQLITE_PAGE_SIZE.to_be_bytes());
            header[12..16].copy_from_slice(&u32::from(seed).to_be_bytes());
            header[16..20].fill(seed);
            header[20..24].fill(seed.wrapping_add(1));
            let mut rolling = checksum(&header[..24], [0, 0]);
            header[24..28].copy_from_slice(&rolling[0].to_be_bytes());
            header[28..32].copy_from_slice(&rolling[1].to_be_bytes());
            let mut frame = vec![0u8; SQLITE_WAL_FRAME_BYTES];
            frame[..4].copy_from_slice(&1u32.to_be_bytes());
            frame[4..8].copy_from_slice(&1u32.to_be_bytes());
            frame[8..16].copy_from_slice(&header[16..24]);
            frame[24..].fill(seed);
            rolling = checksum(&frame[..8], rolling);
            rolling = checksum(&frame[24..], rolling);
            frame[16..20].copy_from_slice(&rolling[0].to_be_bytes());
            frame[20..24].copy_from_slice(&rolling[1].to_be_bytes());
            [header.as_slice(), frame.as_slice()].concat()
        }
        let mut state = WalCaptureState::new();
        let first = wal(1);
        state.observe_write(0, &first);
        assert_eq!(state.observe_sync(true), ShadowSyncOutcome::Captured);
        let mut commits = state.drain_completed();
        state.observe_truncate(0, true);
        let second = wal(2);
        state.observe_write(0, &second);
        assert_eq!(state.observe_sync(true), ShadowSyncOutcome::Captured);
        commits.extend(state.drain_completed());
        assert_eq!(commits[0].wal_generation(), 1);
        assert_eq!(commits[1].wal_generation(), 2);
        commits
    }

    struct CompositeFixture {
        archive: ArchiveId,
        backend: Arc<FaultingBackend>,
        cipher: Arc<VerifiedArchiveCipher>,
        recovery: RecoveryRoot,
        final_root_object_id: ObjectId,
    }

    async fn composite_fixture() -> CompositeFixture {
        let (checkpoint_bytes, commits) = real_sqlite_checkpoint_and_commits();
        composite_fixture_from(checkpoint_bytes, commits).await
    }

    async fn composite_fixture_from(
        checkpoint_bytes: Vec<u8>,
        commits: Vec<CapturedWalCommit>,
    ) -> CompositeFixture {
        let archive = ArchiveId::from_bytes([0xa1; 16]);
        let database = DatabaseEpoch::from_bytes([0xa2; 16]);
        let key = KeyEpoch::from_bytes([0xa3; 16]);
        let backend = Arc::new(FaultingBackend::new(archive));
        let cipher = Arc::new(test_cipher(archive, key).await);
        let checkpoint = upload_checkpoint(
            backend.as_ref(),
            cipher.as_ref(),
            archive,
            database,
            &mut VecCheckpointSource(checkpoint_bytes),
            test_staging(),
        )
        .await
        .unwrap();
        let root_zero_id = ObjectId::from_bytes([0xa4; 16]);
        let root_zero_context = ObjectContext::new(
            archive,
            database,
            key,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_zero_id,
            None,
        )
        .unwrap();
        let root_zero = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: checkpoint.logical_file_length(),
            logical_file_length: checkpoint.logical_file_length(),
            user_schema_version: checkpoint.user_schema_version(),
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: Some(checkpoint.root().clone()),
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let root_zero_envelope = cipher
            .seal(&root_zero_context, &root_zero.encode().unwrap())
            .unwrap();
        ImmutableObjectBackend::create_if_absent(
            backend.as_ref(),
            root_zero_context.object_key(),
            root_zero_envelope.clone(),
        )
        .await
        .unwrap();
        let registry = KeyRegistryReference::new(
            key,
            cipher.registry_rotation_generation(),
            cipher.registry_object_id(),
            cipher.registry_ciphertext_hash(),
        );
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive,
                database,
                RootCommitment::genesis(
                    database,
                    key,
                    RootReference::new(0, root_zero_id, root_zero_envelope.hash()),
                ),
                registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive,
                database,
                key,
                ObjectId::from_bytes([0xa5; 16]),
                600,
            )
            .unwrap();
        let mut final_root_object_id = root_zero_id;
        for (index, capture) in commits.iter().enumerate() {
            let recovery = witness.recovery_root(archive).unwrap();
            let uploaded = super::upload_captured_wal_commit(
                &recovery,
                backend.as_ref(),
                cipher.as_ref(),
                archive,
                lease.fencing_epoch(),
                [0xb0 + index as u8; 16],
                [0xc0 + index as u8; 32],
                capture,
            )
            .await
            .unwrap();
            final_root_object_id = ObjectId::from_bytes([0xd0 + index as u8; 16]);
            let root = uploaded.candidate_root();
            let context = ObjectContext::new(
                archive,
                database,
                key,
                ObjectRole::RootV3,
                LogicalLocation::Root {
                    root_seq: root.root_seq,
                },
                final_root_object_id,
                root.parent.clone(),
            )
            .unwrap();
            let envelope = cipher.seal(&context, &root.encode().unwrap()).unwrap();
            ImmutableObjectBackend::create_if_absent(
                backend.as_ref(),
                context.object_key(),
                envelope,
            )
            .await
            .unwrap();
            let advance = RootAdvance::from_authenticated_candidate(
                lease,
                recovery.root(),
                recovery.registry(),
                recovery.registry(),
                &context,
                backend.as_ref(),
                cipher.as_ref(),
            )
            .await
            .unwrap();
            witness.compare_and_advance_root(advance).unwrap();
        }
        CompositeFixture {
            archive,
            backend,
            cipher,
            recovery: witness.recovery_root(archive).unwrap(),
            final_root_object_id,
        }
    }

    struct RecordingSink {
        header: Option<[u8; SQLITE_WAL_HEADER_BYTES]>,
        generations: Vec<u64>,
        frames: Vec<(u64, Vec<u8>)>,
        aborted: bool,
        reject: bool,
        reject_frame_write: bool,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                header: None,
                generations: Vec::new(),
                frames: Vec::new(),
                aborted: false,
                reject: false,
                reject_frame_write: false,
            }
        }
    }

    #[async_trait]
    impl WalRecoverySink for RecordingSink {
        async fn begin_generation(
            &mut self,
            _wal_generation: u64,
            header: &[u8; SQLITE_WAL_HEADER_BYTES],
            _before_logical_file_length: u64,
        ) -> Result<()> {
            if self.reject {
                return Err(ShadowWalError::Sink);
            }
            self.header = Some(*header);
            self.generations.push(_wal_generation);
            Ok(())
        }

        async fn write_wal_frames(&mut self, first_frame_no: u64, frames: &[u8]) -> Result<()> {
            if self.reject || self.reject_frame_write {
                return Err(ShadowWalError::Sink);
            }
            self.frames.push((first_frame_no, frames.to_vec()));
            Ok(())
        }

        async fn finish_generation(&mut self, _after_logical_file_length: u64) -> Result<()> {
            if self.reject {
                return Err(ShadowWalError::Sink);
            }
            Ok(())
        }

        fn abort(&mut self) {
            self.aborted = true;
            self.header = None;
            self.generations.clear();
            self.frames.clear();
        }
    }

    fn bootstrap_recovery(
        archive: ArchiveId,
        database: DatabaseEpoch,
        key: KeyEpoch,
        registry: KeyRegistryReference,
    ) -> crate::archive_v3_witness::RecoveryRoot {
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive,
                database,
                RootCommitment::genesis(
                    database,
                    key,
                    RootReference::new(0, ObjectId::from_bytes([31; 16]), [32; 32]),
                ),
                registry,
            ))
            .unwrap();
        witness.recovery_root(archive).unwrap()
    }

    #[tokio::test]
    async fn public_recovery_binds_the_exact_registry_and_aborts_its_sink() {
        let archive = ArchiveId::from_bytes([21; 16]);
        let database = DatabaseEpoch::from_bytes([22; 16]);
        let key = KeyEpoch::from_bytes([23; 16]);
        let cipher = test_cipher(archive, key).await;
        let wrong_registry = KeyRegistryReference::new(
            key,
            cipher.registry_rotation_generation().saturating_add(1),
            ObjectId::from_bytes([24; 16]),
            [25; 32],
        );
        let recovery = bootstrap_recovery(archive, database, key, wrong_registry);
        let backend = NoListBackend {
            inner: InMemoryImmutableBackend::new(),
        };
        let mut sink = RecordingSink::new();
        assert!(matches!(
            recover_witness_nominated_wal(&recovery, &backend, &cipher, archive, &mut sink).await,
            Err(ShadowWalError::Archive(ArchiveV3Error::Authentication))
        ));
        assert!(sink.aborted);
        assert!(sink.header.is_none() && sink.frames.is_empty());
    }

    #[tokio::test]
    async fn public_recovery_aborts_on_a_missing_witness_nominated_root() {
        let archive = ArchiveId::from_bytes([26; 16]);
        let database = DatabaseEpoch::from_bytes([27; 16]);
        let key = KeyEpoch::from_bytes([28; 16]);
        let cipher = test_cipher(archive, key).await;
        let registry = KeyRegistryReference::new(
            key,
            cipher.registry_rotation_generation(),
            cipher.registry_object_id(),
            cipher.registry_ciphertext_hash(),
        );
        let recovery = bootstrap_recovery(archive, database, key, registry);
        let backend = InMemoryImmutableBackend::new();
        let mut sink = RecordingSink::new();
        assert!(matches!(
            recover_witness_nominated_wal(&recovery, &backend, &cipher, archive, &mut sink).await,
            Err(ShadowWalError::MissingObject)
        ));
        assert!(sink.aborted);
        assert!(sink.header.is_none() && sink.frames.is_empty());
    }

    #[tokio::test]
    async fn upload_requires_exact_readback_before_returning_a_reference() {
        let archive = ArchiveId::from_bytes([41; 16]);
        let database = DatabaseEpoch::from_bytes([42; 16]);
        let key = KeyEpoch::from_bytes([43; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = MissingReadbackBackend {
            inner: InMemoryImmutableBackend::new(),
        };
        assert!(matches!(
            upload_captured_wal_commit(
                &backend,
                &cipher,
                archive,
                database,
                1,
                &captured_commit(1),
            )
            .await,
            Err(ShadowWalError::MissingObject)
        ));
    }

    #[tokio::test]
    async fn upload_readback_composes_bounded_checkpoint_wal_root_and_replays_on_restart() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let database = DatabaseEpoch::from_bytes([2; 16]);
        let key = KeyEpoch::from_bytes([3; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = InMemoryImmutableBackend::new();
        // 255 frames force two sealed predecessor-linked objects at 4-KiB
        // pages, exercising the boundary the bundled SQLite oracle produces.
        let capture = captured_commit(255);
        let uploaded =
            upload_captured_wal_commit(&backend, &cipher, archive, database, 1, &capture)
                .await
                .unwrap();
        assert_eq!(uploaded.segment_count(), 2);
        assert_eq!(
            uploaded.effective_logical_file_length(),
            SQLITE_PAGE_SIZE as u64
        );

        let checkpoint = ImmutableReference {
            object_id: ObjectId::from_bytes([4; 16]),
            envelope_hash: [5; 32],
        };
        let base = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: SQLITE_PAGE_SIZE as u64,
            logical_file_length: SQLITE_PAGE_SIZE as u64,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: Some(checkpoint),
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        assert_eq!(
            uploaded.candidate_root().checkpoint_root.as_ref(),
            base.checkpoint_root.as_ref()
        );
        let root = uploaded.candidate_root().clone();

        let mut first = RecordingSink::new();
        recover_exact_root_wal(&root, &backend, &cipher, archive, &mut first)
            .await
            .unwrap();
        let mut restarted = RecordingSink::new();
        recover_exact_root_wal(&root, &backend, &cipher, archive, &mut restarted)
            .await
            .unwrap();
        assert_eq!(first.header, restarted.header);
        assert_eq!(first.frames, restarted.frames);
        assert_eq!(first.frames.len(), 2);
    }

    #[tokio::test]
    async fn recovery_sink_failure_aborts_without_accepting_a_partial_chain() {
        let archive = ArchiveId::from_bytes([11; 16]);
        let database = DatabaseEpoch::from_bytes([12; 16]);
        let key = KeyEpoch::from_bytes([13; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = InMemoryImmutableBackend::new();
        let uploaded = upload_captured_wal_commit(
            &backend,
            &cipher,
            archive,
            database,
            1,
            &captured_commit(1),
        )
        .await
        .unwrap();
        let root = uploaded.candidate_root().clone();
        let mut sink = RecordingSink::new();
        sink.reject_frame_write = true;
        assert!(
            recover_exact_root_wal(&root, &backend, &cipher, archive, &mut sink)
                .await
                .is_err()
        );
        // The public witness entrypoint calls abort on this same error path;
        // direct walker tests establish that no complete chain is accepted.
    }

    #[tokio::test]
    async fn exact_254_frame_boundary_stays_one_segment_and_255_splits() {
        let archive = ArchiveId::from_bytes([51; 16]);
        let database = DatabaseEpoch::from_bytes([52; 16]);
        let key = KeyEpoch::from_bytes([53; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = InMemoryImmutableBackend::new();
        assert_eq!(
            captured_wal_segment_count(&captured_commit(254)).unwrap(),
            1
        );
        assert_eq!(
            captured_wal_segment_count(&captured_commit(255)).unwrap(),
            2
        );
        assert_eq!(
            upload_captured_wal_commit(
                &backend,
                &cipher,
                archive,
                database,
                1,
                &captured_commit(254),
            )
            .await
            .unwrap()
            .segment_count(),
            1
        );
        assert_eq!(
            upload_captured_wal_commit(
                &backend,
                &cipher,
                archive,
                database,
                2,
                &captured_commit(255),
            )
            .await
            .unwrap()
            .segment_count(),
            2
        );
    }

    #[tokio::test]
    async fn exact_tail_recovers_two_dense_commits_without_object_listing() {
        let archive = ArchiveId::from_bytes([71; 16]);
        let database = DatabaseEpoch::from_bytes([72; 16]);
        let key = KeyEpoch::from_bytes([73; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = NoListBackend {
            inner: InMemoryImmutableBackend::new(),
        };
        let commits = two_captured_commits();
        assert_eq!(commits.len(), 2);
        let first =
            upload_captured_wal_commit(&backend, &cipher, archive, database, 1, &commits[0])
                .await
                .unwrap();
        let root_zero = RootReference::new(0, ObjectId::from_bytes([6; 16]), [7; 32]);
        let root_one = RootReference::new(1, ObjectId::from_bytes([74; 16]), [75; 32]);
        let second = super::upload_captured_wal_commit_from_base(
            &backend,
            &cipher,
            archive,
            first.candidate_root(),
            root_one,
            Some(root_zero),
            2,
            [76; 16],
            [77; 32],
            &commits[1],
            &super::DirectWalObjectStaging,
        )
        .await
        .unwrap();
        assert_eq!(second.candidate_root().wal_commit_count, 2);
        let mut sink = RecordingSink::new();
        let recovered = recover_exact_root_wal(
            second.candidate_root(),
            &backend,
            &cipher,
            archive,
            &mut sink,
        )
        .await
        .unwrap();
        assert_eq!(recovered.commit_count, 2);
        assert_eq!(sink.frames.len(), 2);
        assert_eq!(sink.frames[0].0, 1);
        assert_eq!(sink.frames[1].0, 2);

        let mut tampered = second.candidate_root().clone();
        tampered.wal_tail_bytes += 1;
        let mut rejected = RecordingSink::new();
        assert!(
            recover_exact_root_wal(&tampered, &backend, &cipher, archive, &mut rejected,)
                .await
                .is_err()
        );
        assert!(rejected.frames.is_empty());
    }

    #[tokio::test]
    async fn generation_rollover_is_exact_and_checkpoints_between_headers() {
        let archive = ArchiveId::from_bytes([0x81; 16]);
        let database = DatabaseEpoch::from_bytes([0x82; 16]);
        let key = KeyEpoch::from_bytes([0x83; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = NoListBackend {
            inner: InMemoryImmutableBackend::new(),
        };
        let captures = generation_rollover_commits();
        let first =
            upload_captured_wal_commit(&backend, &cipher, archive, database, 1, &captures[0])
                .await
                .unwrap();
        let root_zero = RootReference::new(0, ObjectId::from_bytes([6; 16]), [7; 32]);
        let second = super::upload_captured_wal_commit_from_base(
            &backend,
            &cipher,
            archive,
            first.candidate_root(),
            RootReference::new(1, ObjectId::from_bytes([0x84; 16]), [0x85; 32]),
            Some(root_zero),
            2,
            [0x86; 16],
            [0x87; 32],
            &captures[1],
            &super::DirectWalObjectStaging,
        )
        .await
        .unwrap();
        let mut sink = RecordingSink::new();
        recover_exact_root_wal(
            second.candidate_root(),
            &backend,
            &cipher,
            archive,
            &mut sink,
        )
        .await
        .unwrap();
        assert_eq!(sink.generations, vec![1, 2]);
        assert_eq!(
            sink.frames.iter().map(|entry| entry.0).collect::<Vec<_>>(),
            vec![1, 1]
        );
    }

    #[tokio::test]
    async fn full_fake_checkpoint_multi_wal_composite_recovers_sqlite_and_owns_cleanup() {
        let fixture = composite_fixture().await;
        let backend: Arc<dyn ImmutableObjectBackend> = fixture.backend.clone();
        let owned = recover_owned_private_staging(
            fixture.recovery,
            backend,
            fixture.cipher,
            fixture.archive,
        )
        .await
        .unwrap();
        let path = owned.path_for_test().to_path_buf();
        assert!(!sqlite_sidecar_path(&path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&path, "-shm").exists());
        let connection = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let values = connection
            .prepare("SELECT value FROM recovered_values ORDER BY rowid")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(values, vec!["first", "second"]);
        drop(connection);
        drop(owned);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn maintenance_recovery_accepts_only_checkpointed_canonical_zero_wal_geometry() {
        let (checkpoint, _) = real_sqlite_checkpoint_and_commits();
        let fixture = composite_fixture_from(checkpoint, Vec::new()).await;
        let backend: Arc<dyn ImmutableObjectBackend> = fixture.backend.clone();
        assert!(recover_owned_private_staging(
            fixture.recovery.clone(),
            Arc::clone(&backend),
            Arc::clone(&fixture.cipher),
            fixture.archive,
        )
        .await
        .is_err());
        let recovered = recover_owned_maintenance_staging(
            fixture
                .recovery
                .with_migration_for_test(MigrationState::ShadowWal),
            backend,
            fixture.cipher,
            fixture.archive,
        )
        .await
        .unwrap();
        assert_eq!(
            recovered.checkpoint().logical_file_length(),
            std::fs::metadata(recovered.owned().path_for_test())
                .unwrap()
                .len()
        );
        let path = recovered.owned().path_for_test().to_path_buf();
        assert!(!sqlite_sidecar_path(&path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&path, "-shm").exists());
        drop(recovered);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn real_sqlite_composite_recovers_growth_then_shrink() {
        let (checkpoint, commits, grown_length, shrunk_length) = real_sqlite_grow_then_shrink();
        let checkpoint_length = checkpoint.len() as u64;
        assert!(grown_length > checkpoint_length);
        assert!(shrunk_length < grown_length);
        let fixture = composite_fixture_from(checkpoint, commits).await;
        let backend: Arc<dyn ImmutableObjectBackend> = fixture.backend.clone();
        let owned = recover_owned_private_staging(
            fixture.recovery,
            backend,
            fixture.cipher,
            fixture.archive,
        )
        .await
        .unwrap();
        let path = owned.path_for_test().to_path_buf();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), shrunk_length);
        assert!(!sqlite_sidecar_path(&path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&path, "-shm").exists());
        let connection = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let row_count: i64 = connection
            .query_row("SELECT count(*) FROM recovered_values", [], |row| {
                row.get(0)
            })
            .unwrap();
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(row_count, 0);
        assert_eq!(integrity, "ok");
        drop(connection);
        drop(owned);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn missing_tampered_and_reordered_descriptors_and_segments_abort_atomically() {
        let fixture = composite_fixture().await;
        for fault in [
            ReadFault::Missing("/wal-commits/".into()),
            ReadFault::Tampered("/wal-commits/".into()),
            ReadFault::Swap("/wal-commits/".into()),
            ReadFault::Missing("/wal/".into()),
            ReadFault::Tampered("/wal/".into()),
            ReadFault::Swap("/wal/".into()),
        ] {
            fixture.backend.set_fault(fault);
            let mut sink = RecordingSink::new();
            assert!(recover_witness_nominated_wal(
                &fixture.recovery,
                fixture.backend.as_ref(),
                fixture.cipher.as_ref(),
                fixture.archive,
                &mut sink,
            )
            .await
            .is_err());
            assert!(sink.aborted);
            assert!(sink.frames.is_empty());
        }
        fixture.backend.set_fault(ReadFault::None);
    }

    #[tokio::test]
    async fn lineage_caps_reject_before_any_immutable_create() {
        let archive = ArchiveId::from_bytes([0x88; 16]);
        let database = DatabaseEpoch::from_bytes([0x89; 16]);
        let key = KeyEpoch::from_bytes([0x8a; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = FaultingBackend::new(archive);
        let base = ArchiveRoot {
            root_seq: u64::from(MAX_WAL_COMMITS_PER_ROOT),
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes([1; 16]),
                envelope_hash: [1; 32],
            }),
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 1,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 1,
            wal_commit_count: MAX_WAL_COMMITS_PER_ROOT,
            wal_segment_count: MAX_WAL_COMMITS_PER_ROOT,
            wal_tail_bytes: 1,
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([2; 16]),
                envelope_hash: [2; 32],
            }),
            extent_tree_root: None,
            wal_commit_tail: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([3; 16]),
                envelope_hash: [3; 32],
            }),
        };
        for capped in [
            base.clone(),
            ArchiveRoot {
                root_seq: 1,
                wal_commit_count: 1,
                wal_segment_count: 1,
                wal_tail_bytes: MAX_WAL_TAIL_BYTES,
                ..base.clone()
            },
        ] {
            assert!(matches!(
                super::upload_captured_wal_commit_from_base(
                    &backend,
                    &cipher,
                    archive,
                    &capped,
                    RootReference::new(capped.root_seq, ObjectId::from_bytes([4; 16]), [4; 32]),
                    Some(RootReference::new(
                        capped.root_seq - 1,
                        ObjectId::from_bytes([1; 16]),
                        [1; 32]
                    )),
                    2,
                    [5; 16],
                    [6; 32],
                    &captured_commit(1),
                    &super::DirectWalObjectStaging,
                )
                .await,
                Err(ShadowWalError::CheckpointRequired)
            ));
        }
        assert_eq!(backend.create_count(), 0);
    }

    #[tokio::test]
    async fn near_segment_cap_rejects_oversized_commit_before_any_create() {
        let archive = ArchiveId::from_bytes([0x8b; 16]);
        let database = DatabaseEpoch::from_bytes([0x8c; 16]);
        let key = KeyEpoch::from_bytes([0x8d; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = FaultingBackend::new(archive);
        let base = ArchiveRoot {
            root_seq: 1,
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes([1; 16]),
                envelope_hash: [1; 32],
            }),
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 1,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 1,
            wal_commit_count: 1,
            wal_segment_count: MAX_WAL_SEGMENTS_PER_ROOT - 1,
            wal_tail_bytes: 1,
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([2; 16]),
                envelope_hash: [2; 32],
            }),
            extent_tree_root: None,
            wal_commit_tail: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([3; 16]),
                envelope_hash: [3; 32],
            }),
        };
        assert!(matches!(
            super::upload_captured_wal_commit_from_base(
                &backend,
                &cipher,
                archive,
                &base,
                RootReference::new(1, ObjectId::from_bytes([4; 16]), [4; 32]),
                Some(RootReference::new(
                    0,
                    ObjectId::from_bytes([1; 16]),
                    [1; 32]
                )),
                2,
                [5; 16],
                [6; 32],
                &captured_commit(255),
                &super::DirectWalObjectStaging,
            )
            .await,
            Err(ShadowWalError::CheckpointRequired)
        ));
        assert_eq!(backend.create_count(), 0);
    }

    #[tokio::test]
    async fn near_byte_cap_rejects_oversized_commit_before_any_create() {
        let archive = ArchiveId::from_bytes([0x8e; 16]);
        let database = DatabaseEpoch::from_bytes([0x8f; 16]);
        let key = KeyEpoch::from_bytes([0x90; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = FaultingBackend::new(archive);
        let one_frame_commit_bytes = u64::from(SQLITE_WAL_HEADER_BYTES as u32)
            .checked_add(u64::from(SQLITE_WAL_FRAME_BYTES as u32))
            .unwrap();
        let base = ArchiveRoot {
            root_seq: 1,
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes([1; 16]),
                envelope_hash: [1; 32],
            }),
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 1,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            logical_file_length: u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 1,
            wal_commit_count: 1,
            wal_segment_count: 1,
            wal_tail_bytes: MAX_WAL_TAIL_BYTES - one_frame_commit_bytes + 1,
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([2; 16]),
                envelope_hash: [2; 32],
            }),
            extent_tree_root: None,
            wal_commit_tail: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([3; 16]),
                envelope_hash: [3; 32],
            }),
        };
        assert!(matches!(
            super::upload_captured_wal_commit_from_base(
                &backend,
                &cipher,
                archive,
                &base,
                RootReference::new(1, ObjectId::from_bytes([4; 16]), [4; 32]),
                Some(RootReference::new(
                    0,
                    ObjectId::from_bytes([1; 16]),
                    [1; 32]
                )),
                2,
                [5; 16],
                [6; 32],
                &captured_commit(1),
                &super::DirectWalObjectStaging,
            )
            .await,
            Err(ShadowWalError::CheckpointRequired)
        ));
        assert_eq!(backend.create_count(), 0);
    }

    #[tokio::test]
    async fn local_sqlite_sink_atomically_checkpoints_a_real_wal() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.db");
        let recovered = directory.path().join("recovered.db");
        let connection = rusqlite::Connection::open(&source).unwrap();
        connection
            .execute_batch(
                "PRAGMA page_size=4096;
                 PRAGMA journal_mode=WAL;
                 PRAGMA wal_autocheckpoint=0;
                 CREATE TABLE values_for_recovery(value TEXT NOT NULL);
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .unwrap();
        std::fs::copy(&source, &recovered).unwrap();
        let before = std::fs::metadata(&recovered).unwrap().len();
        connection
            .execute("INSERT INTO values_for_recovery VALUES('settled')", [])
            .unwrap();
        let wal = std::fs::read(sqlite_sidecar_path(&source, "-wal")).unwrap();
        assert!(wal.len() > SQLITE_WAL_HEADER_BYTES);
        assert!((wal.len() - SQLITE_WAL_HEADER_BYTES).is_multiple_of(SQLITE_WAL_FRAME_BYTES));
        let final_frame = &wal[wal.len() - SQLITE_WAL_FRAME_BYTES..];
        let after = u64::from(u32::from_be_bytes(final_frame[4..8].try_into().unwrap()))
            * u64::from(SQLITE_PAGE_SIZE);
        let header: [u8; SQLITE_WAL_HEADER_BYTES] =
            wal[..SQLITE_WAL_HEADER_BYTES].try_into().unwrap();
        let mut sink = CompositeWalRecoverySink::new(recovered.clone());
        sink.begin_generation(1, &header, before).await.unwrap();
        sink.write_wal_frames(1, &wal[SQLITE_WAL_HEADER_BYTES..])
            .await
            .unwrap();
        sink.finish_generation(after).await.unwrap();
        assert!(!sqlite_sidecar_path(&recovered, "-wal").exists());
        assert!(!sqlite_sidecar_path(&recovered, "-shm").exists());
        let restored = rusqlite::Connection::open_with_flags(
            recovered,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let value: String = restored
            .query_row("SELECT value FROM values_for_recovery", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(value, "settled");
    }

    #[tokio::test]
    async fn caller_cancellation_leaves_cleanup_owned_until_inner_task_settles() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owned.db");
        std::fs::write(&path, b"private").unwrap();
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let inner_path = path.clone();
        let inner_started = started.clone();
        let inner_release = release.clone();
        let caller = tokio::spawn(async move {
            tokio::spawn(async move {
                let _cleanup = CompositeRecoveryCleanup::new(inner_path);
                inner_started.notify_one();
                inner_release.notified().await;
            })
            .await
            .unwrap();
        });
        started.notified().await;
        caller.abort();
        let _ = caller.await;
        assert!(path.exists());
        release.notify_waiters();
        for _ in 0..32 {
            if !path.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn actual_stalled_backend_cancellation_retains_then_cleans_owned_plaintext() {
        let fixture = composite_fixture().await;
        fixture.backend.set_fault(ReadFault::StallOnOccurrence {
            object_id: fixture.final_root_object_id,
            occurrence: 2,
        });
        let backend: Arc<dyn ImmutableObjectBackend> = fixture.backend.clone();
        let cipher = fixture.cipher.clone();
        let archive = fixture.archive;
        let (path_sender, path_receiver) = tokio::sync::oneshot::channel();
        let (cleanup_sender, cleanup_receiver) = tokio::sync::oneshot::channel();
        let caller = tokio::spawn(recover_owned_private_staging_observed(
            fixture.recovery,
            backend,
            cipher,
            archive,
            path_sender,
            cleanup_sender,
        ));
        let created = path_receiver.await.unwrap();
        fixture.backend.stall_started.notified().await;
        assert!(created.exists());
        caller.abort();
        let _ = caller.await;
        assert!(created.exists());
        fixture.backend.stall_release.notify_one();
        cleanup_receiver.await.unwrap();
        assert!(!created.exists());
        assert!(!sqlite_sidecar_path(&created, "-wal").exists());
        assert!(!sqlite_sidecar_path(&created, "-shm").exists());
    }

    #[tokio::test]
    async fn format_four_binds_checkpoint_length_across_wal_growth_and_shrink() {
        let archive = ArchiveId::from_bytes([61; 16]);
        let database = DatabaseEpoch::from_bytes([62; 16]);
        let key = KeyEpoch::from_bytes([63; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = InMemoryImmutableBackend::new();
        let base = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: SQLITE_PAGE_SIZE as u64,
            logical_file_length: SQLITE_PAGE_SIZE as u64,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([64; 16]),
                envelope_hash: [65; 32],
            }),
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let commits = two_captured_commits_with_page_counts([2, 1]);
        let root_zero = RootReference::new(0, ObjectId::from_bytes([66; 16]), [67; 32]);
        let grow = super::upload_captured_wal_commit_from_base(
            &backend,
            &cipher,
            archive,
            &base,
            root_zero,
            None,
            1,
            [68; 16],
            [69; 32],
            &commits[0],
            &super::DirectWalObjectStaging,
        )
        .await
        .unwrap();
        assert_eq!(grow.candidate_root().checkpoint_logical_file_length, 4096);
        assert_eq!(grow.candidate_root().logical_file_length, 8192);
        let shrink = super::upload_captured_wal_commit_from_base(
            &backend,
            &cipher,
            archive,
            grow.candidate_root(),
            RootReference::new(1, ObjectId::from_bytes([70; 16]), [71; 32]),
            Some(root_zero),
            2,
            [72; 16],
            [73; 32],
            &commits[1],
            &super::DirectWalObjectStaging,
        )
        .await
        .unwrap();
        assert_eq!(shrink.candidate_root().checkpoint_logical_file_length, 4096);
        assert_eq!(shrink.candidate_root().logical_file_length, 4096);
    }
}
