#![allow(
    dead_code,
    reason = "inactive ADR-0022 WAL shadow capture state remains unwired to a comparison worker"
)]

//! Synchronous, bounded WAL capture state for ADR-0022 shadow mode.
//!
//! The opt-in journal-capture VFS calls [`WalCaptureState::observe_write`] only
//! after its underlying `xWrite` succeeds, calls [`WalCaptureState::observe_sync`]
//! with the underlying `xSync` result, and mirrors `xTruncate` through
//! [`WalCaptureState::observe_truncate`].  This module deliberately performs no
//! filesystem, SQLite callback registration, async, provider, witness, or Store
//! work itself. Capture failure is diagnostic and disposable: it cannot be
//! returned through the legacy VFS operation or affect the authoritative
//! whole-blob save.

use std::collections::VecDeque;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::archive_v3::{ArchiveV3Error, ImmutableReference, ObjectId, Result, SQLITE_PAGE_SIZE};
use crate::archive_v3_journal::{WalSegment, MAX_WAL_SEGMENT_BYTES};

const SQLITE_WAL_HEADER_BYTES: usize = 32;
const SQLITE_WAL_FRAME_HEADER_BYTES: usize = 24;
const SQLITE_WAL_FRAME_BYTES: usize = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
const SQLITE_WAL_MAGIC_LE_CHECKSUM: u32 = 0x377f_0682;
const SQLITE_WAL_MAGIC_BE_CHECKSUM: u32 = 0x377f_0683;
const SQLITE_WAL_FORMAT_VERSION: u32 = 3_007_000;

/// A capture generation is bounded independently of the database size.  The
/// owner batch is at most 1 MiB of logical mutations; the larger ceiling gives
/// FTS/vector page amplification room without permitting an unbounded VFS
/// callback allocation.  A transaction that exceeds it is simply not mirrored.
pub const MAX_SHADOW_WAL_BYTES: usize = 8 * 1024 * 1024;
/// Completed commits must be drained by the owner actor.  Queue saturation
/// disables the current shadow generation instead of backpressuring SQLite.
pub const MAX_COMPLETED_SHADOW_COMMITS: usize = 8;
/// Completed commit payloads share one byte budget rather than each retaining
/// a full WAL-sized allocation. Together with `MAX_SHADOW_WAL_BYTES`, this
/// bounds steady-state retained payload bytes to 16 MiB per owner state.
pub const MAX_COMPLETED_SHADOW_BYTES: usize = MAX_SHADOW_WAL_BYTES;
const MAX_COVERAGE_RANGES: usize = 4_096;
const CAPTURE_PUBLICATION_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/wal-owner-captured-commit/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowCaptureFault {
    InvalidWrite,
    TooLarge,
    TooManyWriteRanges,
    MalformedWal,
    QueueFull,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShadowCaptureMetrics {
    pub commits_captured: u64,
    pub generations_dropped: u64,
    pub invalid_writes: u64,
    pub oversized_writes: u64,
    pub malformed_syncs: u64,
    pub queue_full: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShadowSyncOutcome {
    NoCommit,
    Captured,
    Dropped(ShadowCaptureFault),
}

/// Exact WAL frames made durable by one successful underlying `xSync`.
/// Private fields prevent callers from relabeling an arbitrary post-commit
/// `-wal` read as a capture-bound commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedWalCommit {
    wal_generation: u64,
    first_frame_no: u64,
    checksum_before: [u32; 2],
    wal_header: [u8; SQLITE_WAL_HEADER_BYTES],
    frames: Vec<u8>,
}

impl Drop for CapturedWalCommit {
    fn drop(&mut self) {
        self.frames.zeroize();
        self.wal_header.zeroize();
        self.checksum_before.zeroize();
    }
}

impl CapturedWalCommit {
    pub fn wal_generation(&self) -> u64 {
        self.wal_generation
    }

    pub fn first_frame_no(&self) -> u64 {
        self.first_frame_no
    }

    pub fn frame_count(&self) -> u32 {
        (self.frames.len() / SQLITE_WAL_FRAME_BYTES) as u32
    }

    /// Content-free commitment consumed by the durable publication protocol.
    /// It binds the exact captured bytes without exposing them through the
    /// owner/control boundary.
    pub(crate) fn publication_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CAPTURE_PUBLICATION_COMMITMENT_DOMAIN);
        hasher.update(self.wal_generation.to_be_bytes());
        hasher.update(self.first_frame_no.to_be_bytes());
        hasher.update(self.frame_count().to_be_bytes());
        hasher.update(self.checksum_before[0].to_be_bytes());
        hasher.update(self.checksum_before[1].to_be_bytes());
        hasher.update(self.wal_header);
        hasher.update((self.frames.len() as u64).to_be_bytes());
        hasher.update(&self.frames);
        hasher.finalize().into()
    }

    /// Convert a bounded one-object capture through the existing archive-v3
    /// WAL validator.  Multi-object encryption/linking is intentionally left
    /// to the later shadow uploader because predecessor references are hashes
    /// of the sealed objects, not facts available inside a VFS callback.
    pub fn validated_single_segment(&self, root_seq: u64) -> Result<WalSegment> {
        let segment = WalSegment {
            root_seq,
            wal_generation: self.wal_generation,
            segment_index: 0,
            segment_count: 1,
            previous_segment: None,
            first_frame_no: self.first_frame_no,
            checksum_before: self.checksum_before,
            wal_header: self.wal_header,
            frames: self.frames.clone(),
        };
        if segment.encode()?.len() > MAX_WAL_SEGMENT_BYTES {
            return Err(ArchiveV3Error::TooLarge("WAL segment"));
        }
        segment.validate()?;
        Ok(segment)
    }

    /// Validate a capture of any permitted size by splitting it at the same
    /// fixed frame boundary used by the future immutable uploader. The dummy
    /// predecessor is only a presence marker for payload validation; the real
    /// uploader replaces it with each previously sealed segment's exact hash.
    pub(crate) fn validate_segments(&self, root_seq: u64) -> Result<()> {
        const WORST_CASE_HEADER_BYTES: usize = 138;
        let frames_per_segment =
            (MAX_WAL_SEGMENT_BYTES - WORST_CASE_HEADER_BYTES) / SQLITE_WAL_FRAME_BYTES;
        if frames_per_segment == 0 {
            return Err(ArchiveV3Error::TooLarge("WAL segment"));
        }
        if self.frames.is_empty() || !self.frames.len().is_multiple_of(SQLITE_WAL_FRAME_BYTES) {
            return Err(ArchiveV3Error::Malformed("WAL frame length"));
        }
        let frame_count = self.frames.len() / SQLITE_WAL_FRAME_BYTES;
        let segment_count = frame_count.div_ceil(frames_per_segment);
        let predecessor = ImmutableReference {
            object_id: ObjectId::from_bytes([0x55; 16]),
            envelope_hash: [0x66; 32],
        };
        for segment_index in 0..segment_count {
            let start_frame = segment_index * frames_per_segment;
            let end_frame = (start_frame + frames_per_segment).min(frame_count);
            let checksum_before = if start_frame == 0 {
                self.checksum_before
            } else {
                let previous = (start_frame - 1) * SQLITE_WAL_FRAME_BYTES;
                [
                    read_be_u32(&self.frames[previous + 16..previous + 20]),
                    read_be_u32(&self.frames[previous + 20..previous + 24]),
                ]
            };
            WalSegment {
                root_seq,
                wal_generation: self.wal_generation,
                segment_index: u32::try_from(segment_index)
                    .map_err(|_| ArchiveV3Error::TooLarge("WAL segment count"))?,
                segment_count: u32::try_from(segment_count)
                    .map_err(|_| ArchiveV3Error::TooLarge("WAL segment count"))?,
                previous_segment: (segment_index != 0).then_some(predecessor.clone()),
                first_frame_no: self.first_frame_no
                    + u64::try_from(start_frame)
                        .map_err(|_| ArchiveV3Error::TooLarge("WAL frame count"))?,
                checksum_before,
                wal_header: self.wal_header,
                frames: self.frames
                    [start_frame * SQLITE_WAL_FRAME_BYTES..end_frame * SQLITE_WAL_FRAME_BYTES]
                    .to_vec(),
            }
            .validate()?;
        }
        Ok(())
    }

    /// Effective SQLite database length stated by this commit's final frame.
    /// The capture is first validated with the exact publication split so the
    /// parsed marker is guaranteed to be the one final commit marker.
    pub(crate) fn effective_logical_file_length(&self, root_seq: u64) -> Result<u64> {
        self.validate_segments(root_seq)?;
        let final_frame = self
            .frames
            .get(self.frames.len().saturating_sub(SQLITE_WAL_FRAME_BYTES)..)
            .ok_or(ArchiveV3Error::Malformed("WAL final frame"))?;
        let pages = read_be_u32(&final_frame[4..8]);
        if pages == 0 {
            return Err(ArchiveV3Error::Malformed("WAL final commit size"));
        }
        u64::from(pages)
            .checked_mul(u64::from(SQLITE_PAGE_SIZE))
            .ok_or(ArchiveV3Error::TooLarge("SQLite database"))
    }

    pub(crate) fn replay_header(&self) -> &[u8; SQLITE_WAL_HEADER_BYTES] {
        &self.wal_header
    }

    /// The rolling checksum immediately before the first captured frame. This
    /// is comparison data from the validated VFS capture, never caller input.
    pub(crate) fn replay_checksum_before(&self) -> [u32; 2] {
        self.checksum_before
    }

    pub(crate) fn replay_frames(&self) -> &[u8] {
        &self.frames
    }

    #[cfg(test)]
    pub(crate) fn with_wal_generation_for_test(mut self, wal_generation: u64) -> Self {
        self.wal_generation = wal_generation;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_first_frame_no_for_test(mut self, first_frame_no: u64) -> Self {
        self.first_frame_no = first_frame_no;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_replay_header_byte_for_test(mut self, value: u8) -> Self {
        self.wal_header[0] = value;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_checksum_before_for_test(mut self, checksum: [u32; 2]) -> Self {
        self.checksum_before = checksum;
        self
    }
}

/// Owner-local state populated synchronously by a future wrapper VFS.
pub struct WalCaptureState {
    wal_generation: u64,
    image: Vec<u8>,
    covered: Vec<(usize, usize)>,
    accepted_header_prefix: Option<[u8; 24]>,
    published_frames: usize,
    completed: VecDeque<CapturedWalCommit>,
    completed_bytes: usize,
    reserved_completed_commits: usize,
    reserved_completed_bytes: usize,
    disabled: Option<ShadowCaptureFault>,
    metrics: ShadowCaptureMetrics,
}

impl Drop for WalCaptureState {
    fn drop(&mut self) {
        // `completed` owns `CapturedWalCommit`s, whose Drop implementation
        // zeroizes their frame/header/checksum material. Clear explicitly so
        // that invariant remains visible at this owning boundary too.
        self.completed.clear();
        self.image.zeroize();
        self.accepted_header_prefix.zeroize();
        self.covered.clear();
    }
}

impl Default for WalCaptureState {
    fn default() -> Self {
        Self::new()
    }
}

impl WalCaptureState {
    pub fn new() -> Self {
        Self {
            wal_generation: 1,
            image: Vec::new(),
            covered: Vec::new(),
            accepted_header_prefix: None,
            published_frames: 0,
            completed: VecDeque::new(),
            completed_bytes: 0,
            reserved_completed_commits: 0,
            reserved_completed_bytes: 0,
            disabled: None,
            metrics: ShadowCaptureMetrics::default(),
        }
    }

    /// Observe bytes only after the real VFS has successfully written them.
    /// This method never returns an error to the legacy operation.
    pub fn observe_write(&mut self, offset: i64, bytes: &[u8]) {
        let Ok(start) = usize::try_from(offset) else {
            self.drop_generation(ShadowCaptureFault::InvalidWrite);
            self.metrics.invalid_writes = self.metrics.invalid_writes.saturating_add(1);
            return;
        };
        let Some(end) = start.checked_add(bytes.len()) else {
            self.drop_generation(ShadowCaptureFault::InvalidWrite);
            self.metrics.invalid_writes = self.metrics.invalid_writes.saturating_add(1);
            return;
        };
        if end > MAX_SHADOW_WAL_BYTES {
            self.drop_generation(ShadowCaptureFault::TooLarge);
            self.metrics.oversized_writes = self.metrics.oversized_writes.saturating_add(1);
            return;
        }
        if self.disabled.is_some() {
            return;
        }

        // Any write that changes the accepted header prefix starts a fresh WAL
        // generation even when SQLite fragments the header rewrite or omits an
        // explicit xTruncate(0). Reset before copying so no stale frame or
        // coverage from the previous generation can be relabeled.
        let header_overlap_end = end.min(24);
        if start < header_overlap_end
            && self.accepted_header_prefix.is_some_and(|accepted| {
                accepted[start..header_overlap_end] != bytes[..header_overlap_end - start]
            })
            && !self.reset_generation()
        {
            return;
        }

        if self.image.len() < end {
            self.image.resize(end, 0);
        }
        self.image[start..end].copy_from_slice(bytes);
        if !self.insert_coverage(start, end) {
            self.drop_generation(ShadowCaptureFault::TooManyWriteRanges);
        }
    }

    /// Mirror a successful underlying truncate.  Truncation itself never
    /// becomes a shadow error on the authoritative legacy path.
    pub fn observe_truncate(&mut self, length: i64, succeeded: bool) {
        if !succeeded {
            return;
        }
        let Ok(length) = usize::try_from(length) else {
            self.drop_generation(ShadowCaptureFault::InvalidWrite);
            self.metrics.invalid_writes = self.metrics.invalid_writes.saturating_add(1);
            return;
        };
        if length == 0 {
            self.reset_generation();
            return;
        }
        if length > MAX_SHADOW_WAL_BYTES {
            self.drop_generation(ShadowCaptureFault::TooLarge);
            self.metrics.oversized_writes = self.metrics.oversized_writes.saturating_add(1);
            return;
        }
        // `Vec::truncate` drops the logical tail but deliberately preserves
        // its allocation. Scrub raw WAL bytes before shrinking so a later
        // resize/write cannot expose a previous generation's contents.
        if length < self.image.len() {
            self.image[length..].zeroize();
            self.image.truncate(length);
        }
        for range in &mut self.covered {
            range.1 = range.1.min(length);
        }
        self.covered.retain(|(start, end)| start < end);
        let complete_frames =
            length.saturating_sub(SQLITE_WAL_HEADER_BYTES) / SQLITE_WAL_FRAME_BYTES;
        if complete_frames < self.published_frames {
            self.drop_generation(ShadowCaptureFault::MalformedWal);
            self.metrics.malformed_syncs = self.metrics.malformed_syncs.saturating_add(1);
        }
    }

    /// Publish only the exact complete commit-frame prefix visible after the
    /// real VFS reports a successful `xSync`.
    pub fn observe_sync(&mut self, succeeded: bool) -> ShadowSyncOutcome {
        if !succeeded {
            return ShadowSyncOutcome::NoCommit;
        }
        if let Some(fault) = self.disabled {
            return ShadowSyncOutcome::Dropped(fault);
        }
        match self.capture_synced_commits() {
            Ok(commits) if commits.is_empty() => ShadowSyncOutcome::NoCommit,
            Ok(commits) => {
                let new_bytes = commits
                    .iter()
                    .map(|commit| commit.frames.len())
                    .sum::<usize>();
                if self
                    .completed
                    .len()
                    .saturating_add(self.reserved_completed_commits)
                    .saturating_add(commits.len())
                    > MAX_COMPLETED_SHADOW_COMMITS
                    || self
                        .completed_bytes
                        .saturating_add(self.reserved_completed_bytes)
                        .saturating_add(new_bytes)
                        > MAX_COMPLETED_SHADOW_BYTES
                {
                    self.metrics.queue_full = self.metrics.queue_full.saturating_add(1);
                    self.drop_generation(ShadowCaptureFault::QueueFull);
                    return ShadowSyncOutcome::Dropped(ShadowCaptureFault::QueueFull);
                }
                let captured = commits.len() as u64;
                self.published_frames += commits
                    .iter()
                    .map(|commit| commit.frame_count() as usize)
                    .sum::<usize>();
                self.accepted_header_prefix = Some(
                    commits[0].wal_header[..24]
                        .try_into()
                        .expect("fixed WAL header prefix"),
                );
                self.completed_bytes += new_bytes;
                self.completed.extend(commits);
                self.metrics.commits_captured =
                    self.metrics.commits_captured.saturating_add(captured);
                ShadowSyncOutcome::Captured
            }
            Err(fault) => {
                self.metrics.malformed_syncs = self.metrics.malformed_syncs.saturating_add(1);
                self.drop_generation(fault);
                ShadowSyncOutcome::Dropped(fault)
            }
        }
    }

    pub fn drain_completed(&mut self) -> Vec<CapturedWalCommit> {
        self.drain_completed_prefix(self.completed.len())
            .expect("the complete queue is always a valid drain prefix")
    }

    /// Remove exactly the already-observed prefix selected by a capture-drain
    /// lease. Commits captured after that lease began remain queued for the
    /// next attempt; a caller cannot accidentally relabel them as part of the
    /// earlier legacy save.
    pub(crate) fn drain_completed_prefix(
        &mut self,
        count: usize,
    ) -> Option<Vec<CapturedWalCommit>> {
        if count > self.completed.len() {
            return None;
        }
        let drained_bytes = self
            .completed
            .iter()
            .take(count)
            .try_fold(0usize, |total, commit| {
                total.checked_add(commit.frames.len())
            })?;
        let remaining_bytes = self.completed_bytes.checked_sub(drained_bytes)?;
        let mut commits = Vec::with_capacity(count);
        for _ in 0..count {
            let commit = self.completed.pop_front()?;
            commits.push(commit);
        }
        self.completed_bytes = remaining_bytes;
        Some(commits)
    }

    /// Detach one exact prefix while retaining its count and byte budget.
    /// Only one VFS drain can be active, so restoration can later require an
    /// exact match rather than accepting caller-selected reservation facts.
    pub(crate) fn drain_completed_prefix_with_reservation(
        &mut self,
        count: usize,
    ) -> Option<Vec<CapturedWalCommit>> {
        let drained_bytes = self
            .completed
            .iter()
            .take(count)
            .try_fold(0usize, |total, commit| {
                total.checked_add(commit.frames.len())
            })?;
        let reserved_completed_commits = self.reserved_completed_commits.checked_add(count)?;
        let reserved_completed_bytes = self.reserved_completed_bytes.checked_add(drained_bytes)?;
        if reserved_completed_commits > MAX_COMPLETED_SHADOW_COMMITS
            || reserved_completed_bytes > MAX_COMPLETED_SHADOW_BYTES
        {
            return None;
        }
        let commits = self.drain_completed_prefix(count)?;
        self.reserved_completed_commits = reserved_completed_commits;
        self.reserved_completed_bytes = reserved_completed_bytes;
        Some(commits)
    }

    /// Permanently consume the one exact detached reservation after its
    /// authenticated owner settlement has succeeded.
    pub(crate) fn release_completed_reservation(&mut self, commits: &[CapturedWalCommit]) -> bool {
        let Some(committed_bytes) = commits.iter().try_fold(0usize, |total, commit| {
            total.checked_add(commit.frames.len())
        }) else {
            return false;
        };
        if self.reserved_completed_commits != commits.len()
            || self.reserved_completed_bytes != committed_bytes
        {
            return false;
        }
        self.reserved_completed_commits = 0;
        self.reserved_completed_bytes = 0;
        true
    }

    /// Restore an exact previously drained prefix ahead of commits observed
    /// later. This is used only by the owner-scoped publication lease when a
    /// candidate has not durably settled. The original ordering and byte
    /// accounting are restored; any impossible bound/accounting state fails
    /// closed and lets the owned commits zeroize on drop.
    pub(crate) fn restore_completed_prefix(
        &mut self,
        mut commits: Vec<CapturedWalCommit>,
    ) -> std::result::Result<(), Vec<CapturedWalCommit>> {
        let restored_bytes = match commits.iter().try_fold(0usize, |total, commit| {
            total.checked_add(commit.frames.len())
        }) {
            Some(value) => value,
            None => return Err(commits),
        };
        if self.reserved_completed_commits != commits.len()
            || self.reserved_completed_bytes != restored_bytes
            || self.completed.len().saturating_add(commits.len()) > MAX_COMPLETED_SHADOW_COMMITS
            || self
                .completed_bytes
                .checked_add(restored_bytes)
                .is_none_or(|value| value > MAX_COMPLETED_SHADOW_BYTES)
        {
            return Err(commits);
        }
        while let Some(commit) = commits.pop() {
            self.completed.push_front(commit);
        }
        self.completed_bytes += restored_bytes;
        self.reserved_completed_commits = 0;
        self.reserved_completed_bytes = 0;
        Ok(())
    }

    pub(crate) fn completed_len(&self) -> usize {
        self.completed.len()
    }

    #[cfg(test)]
    pub(crate) fn is_scrubbed_for_test(&self) -> bool {
        self.image.is_empty()
            && self.covered.is_empty()
            && self.accepted_header_prefix.is_none()
            && self.published_frames == 0
            && self.completed.is_empty()
            && self.completed_bytes == 0
            && self.reserved_completed_commits == 0
            && self.reserved_completed_bytes == 0
    }

    pub fn metrics(&self) -> ShadowCaptureMetrics {
        self.metrics
    }

    pub fn disabled_fault(&self) -> Option<ShadowCaptureFault> {
        self.disabled
    }

    fn capture_synced_commits(
        &self,
    ) -> std::result::Result<Vec<CapturedWalCommit>, ShadowCaptureFault> {
        if !self.range_is_covered(0, SQLITE_WAL_HEADER_BYTES) {
            return Ok(Vec::new());
        }
        let header: [u8; SQLITE_WAL_HEADER_BYTES] = self.image[..SQLITE_WAL_HEADER_BYTES]
            .try_into()
            .map_err(|_| ShadowCaptureFault::MalformedWal)?;
        validate_header_shape(&header)?;

        let available_frames =
            self.image.len().saturating_sub(SQLITE_WAL_HEADER_BYTES) / SQLITE_WAL_FRAME_BYTES;
        let mut contiguous_frames = 0usize;
        for index in 0..available_frames {
            let start = SQLITE_WAL_HEADER_BYTES + index * SQLITE_WAL_FRAME_BYTES;
            if !self.range_is_covered(start, start + SQLITE_WAL_FRAME_BYTES) {
                break;
            }
            contiguous_frames += 1;
        }
        if contiguous_frames <= self.published_frames {
            return Ok(Vec::new());
        }

        let mut commit_ends = Vec::new();
        for index in self.published_frames..contiguous_frames {
            let start = SQLITE_WAL_HEADER_BYTES + index * SQLITE_WAL_FRAME_BYTES;
            if read_be_u32(&self.image[start + 4..start + 8]) != 0 {
                commit_ends.push(index + 1);
            }
        }
        if commit_ends.is_empty() {
            return Ok(Vec::new());
        }

        let mut commits = Vec::with_capacity(commit_ends.len());
        let mut commit_start_frames = self.published_frames;
        for commit_end_frames in commit_ends {
            let frames_start =
                SQLITE_WAL_HEADER_BYTES + commit_start_frames * SQLITE_WAL_FRAME_BYTES;
            let frames_end = SQLITE_WAL_HEADER_BYTES + commit_end_frames * SQLITE_WAL_FRAME_BYTES;
            let checksum_before = if commit_start_frames == 0 {
                [read_be_u32(&header[24..28]), read_be_u32(&header[28..32])]
            } else {
                let previous =
                    SQLITE_WAL_HEADER_BYTES + (commit_start_frames - 1) * SQLITE_WAL_FRAME_BYTES;
                [
                    read_be_u32(&self.image[previous + 16..previous + 20]),
                    read_be_u32(&self.image[previous + 20..previous + 24]),
                ]
            };
            let commit = CapturedWalCommit {
                wal_generation: self.wal_generation,
                first_frame_no: commit_start_frames as u64 + 1,
                checksum_before,
                wal_header: header,
                frames: self.image[frames_start..frames_end].to_vec(),
            };
            // Existing validation rejects salt, checksum, page, ordering, and
            // commit-placement corruption before this capture can leave the actor.
            commit
                .validate_segments(1)
                .map_err(|_| ShadowCaptureFault::MalformedWal)?;
            commits.push(commit);
            commit_start_frames = commit_end_frames;
        }
        Ok(commits)
    }

    fn range_is_covered(&self, start: usize, end: usize) -> bool {
        self.covered
            .iter()
            .any(|(covered_start, covered_end)| *covered_start <= start && *covered_end >= end)
    }

    fn insert_coverage(&mut self, start: usize, end: usize) -> bool {
        if start == end {
            return true;
        }
        self.covered.push((start, end));
        self.covered.sort_unstable_by_key(|range| range.0);
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.covered.len());
        for range in self.covered.drain(..) {
            if let Some(last) = merged.last_mut() {
                if range.0 <= last.1 {
                    last.1 = last.1.max(range.1);
                    continue;
                }
            }
            merged.push(range);
        }
        if merged.len() > MAX_COVERAGE_RANGES {
            return false;
        }
        self.covered = merged;
        true
    }

    fn reset_generation(&mut self) -> bool {
        let Some(next) = self.wal_generation.checked_add(1) else {
            self.drop_generation(ShadowCaptureFault::GenerationExhausted);
            return false;
        };
        self.wal_generation = next;
        self.image.zeroize();
        self.image = Vec::new();
        self.covered = Vec::new();
        self.accepted_header_prefix.zeroize();
        self.accepted_header_prefix = None;
        self.published_frames = 0;
        self.disabled = None;
        true
    }

    fn drop_generation(&mut self, fault: ShadowCaptureFault) {
        if self.disabled.is_none() {
            self.metrics.generations_dropped = self.metrics.generations_dropped.saturating_add(1);
        }
        self.disabled = Some(fault);
        self.image.zeroize();
        self.image = Vec::new();
        self.covered = Vec::new();
        self.accepted_header_prefix.zeroize();
        self.accepted_header_prefix = None;
        self.published_frames = 0;
    }
}

fn validate_header_shape(
    header: &[u8; SQLITE_WAL_HEADER_BYTES],
) -> std::result::Result<(), ShadowCaptureFault> {
    if !matches!(
        read_be_u32(&header[0..4]),
        SQLITE_WAL_MAGIC_LE_CHECKSUM | SQLITE_WAL_MAGIC_BE_CHECKSUM
    ) || read_be_u32(&header[4..8]) != SQLITE_WAL_FORMAT_VERSION
        || read_be_u32(&header[8..12]) != SQLITE_PAGE_SIZE
    {
        return Err(ShadowCaptureFault::MalformedWal);
    }
    Ok(())
}

fn read_be_u32(input: &[u8]) -> u32 {
    u32::from_be_bytes(input.try_into().expect("fixed WAL integer slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum ChecksumOrder {
        Little,
        Big,
    }

    fn wal_checksum(order: ChecksumOrder, input: &[u8], mut state: [u32; 2]) -> [u32; 2] {
        for words in input.chunks_exact(8) {
            let first = match order {
                ChecksumOrder::Little => u32::from_le_bytes(words[..4].try_into().unwrap()),
                ChecksumOrder::Big => u32::from_be_bytes(words[..4].try_into().unwrap()),
            };
            let second = match order {
                ChecksumOrder::Little => u32::from_le_bytes(words[4..].try_into().unwrap()),
                ChecksumOrder::Big => u32::from_be_bytes(words[4..].try_into().unwrap()),
            };
            state[0] = state[0].wrapping_add(first).wrapping_add(state[1]);
            state[1] = state[1].wrapping_add(second).wrapping_add(state[0]);
        }
        state
    }

    fn fixture_wal(commit_frames: &[usize], frame_count: usize) -> Vec<u8> {
        fixture_wal_with_checkpoint_sequence(commit_frames, frame_count, 1)
    }

    fn fixture_wal_with_checkpoint_sequence(
        commit_frames: &[usize],
        frame_count: usize,
        checkpoint_sequence: u32,
    ) -> Vec<u8> {
        let order = ChecksumOrder::Little;
        let mut header = [0u8; SQLITE_WAL_HEADER_BYTES];
        header[0..4].copy_from_slice(&SQLITE_WAL_MAGIC_LE_CHECKSUM.to_be_bytes());
        header[4..8].copy_from_slice(&SQLITE_WAL_FORMAT_VERSION.to_be_bytes());
        header[8..12].copy_from_slice(&SQLITE_PAGE_SIZE.to_be_bytes());
        header[12..16].copy_from_slice(&checkpoint_sequence.to_be_bytes());
        header[16..20].copy_from_slice(&[11, 12, 13, 14]);
        header[20..24].copy_from_slice(&[21, 22, 23, 24]);
        let mut checksum = wal_checksum(order, &header[..24], [0, 0]);
        header[24..28].copy_from_slice(&checksum[0].to_be_bytes());
        header[28..32].copy_from_slice(&checksum[1].to_be_bytes());

        let mut wal =
            Vec::with_capacity(SQLITE_WAL_HEADER_BYTES + frame_count * SQLITE_WAL_FRAME_BYTES);
        wal.extend_from_slice(&header);
        for index in 0..frame_count {
            let mut frame = vec![0u8; SQLITE_WAL_FRAME_BYTES];
            frame[0..4].copy_from_slice(&(index as u32 + 1).to_be_bytes());
            let commit_size = if commit_frames.contains(&(index + 1)) {
                (index as u32 + 1).max(1)
            } else {
                0
            };
            frame[4..8].copy_from_slice(&commit_size.to_be_bytes());
            frame[8..16].copy_from_slice(&header[16..24]);
            frame[24..].fill(index as u8);
            checksum = wal_checksum(order, &frame[..8], checksum);
            checksum = wal_checksum(order, &frame[24..], checksum);
            frame[16..20].copy_from_slice(&checksum[0].to_be_bytes());
            frame[20..24].copy_from_slice(&checksum[1].to_be_bytes());
            wal.extend_from_slice(&frame);
        }
        wal
    }

    #[test]
    fn successful_sync_captures_exact_commit_and_drains_once() {
        let wal = fixture_wal(&[2], 2);
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &wal[..32]);
        capture.observe_write(32, &wal[32..]);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::NoCommit);
        let commits = capture.drain_completed();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].first_frame_no(), 1);
        assert_eq!(commits[0].frame_count(), 2);
        commits[0].validated_single_segment(7).unwrap();
        assert!(capture.drain_completed().is_empty());
    }

    #[test]
    fn failed_sync_and_uncommitted_tail_never_publish() {
        let wal = fixture_wal(&[], 2);
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &wal);
        assert_eq!(capture.observe_sync(false), ShadowSyncOutcome::NoCommit);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::NoCommit);
        assert!(capture.drain_completed().is_empty());
        assert_eq!(capture.disabled_fault(), None);
    }

    #[test]
    fn consecutive_syncs_capture_only_the_new_commit_frames() {
        let wal = fixture_wal(&[1, 2], 2);
        let first_end = SQLITE_WAL_HEADER_BYTES + SQLITE_WAL_FRAME_BYTES;
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &wal[..first_end]);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        capture.observe_write(first_end as i64, &wal[first_end..]);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        let commits = capture.drain_completed();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].first_frame_no(), 1);
        assert_eq!(commits[1].first_frame_no(), 2);
        commits[0].validated_single_segment(7).unwrap();
        commits[1].validated_single_segment(8).unwrap();
    }

    #[test]
    fn multi_segment_commit_is_validated_without_one_unbounded_object() {
        let wal = fixture_wal(&[255], 255);
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &wal);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        let commit = capture.drain_completed().pop().unwrap();
        assert_eq!(commit.frame_count(), 255);
        commit.validate_segments(9).unwrap();
        assert_eq!(
            commit.validated_single_segment(9),
            Err(ArchiveV3Error::TooLarge("WAL segment"))
        );
    }

    #[test]
    fn queue_saturation_drops_shadow_without_relabeling_later_frames() {
        let commits: Vec<_> = (1..=MAX_COMPLETED_SHADOW_COMMITS + 1).collect();
        let wal = fixture_wal(&commits, commits.len());
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &wal[..SQLITE_WAL_HEADER_BYTES]);
        for index in 0..MAX_COMPLETED_SHADOW_COMMITS {
            let start = SQLITE_WAL_HEADER_BYTES + index * SQLITE_WAL_FRAME_BYTES;
            capture.observe_write(start as i64, &wal[start..start + SQLITE_WAL_FRAME_BYTES]);
            assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        }
        let final_start =
            SQLITE_WAL_HEADER_BYTES + MAX_COMPLETED_SHADOW_COMMITS * SQLITE_WAL_FRAME_BYTES;
        capture.observe_write(
            final_start as i64,
            &wal[final_start..final_start + SQLITE_WAL_FRAME_BYTES],
        );
        assert_eq!(
            capture.observe_sync(true),
            ShadowSyncOutcome::Dropped(ShadowCaptureFault::QueueFull)
        );
        assert_eq!(capture.metrics().queue_full, 1);
        assert_eq!(
            capture.drain_completed().len(),
            MAX_COMPLETED_SHADOW_COMMITS
        );
    }

    #[test]
    fn out_of_order_covered_writes_are_valid_but_holes_are_not() {
        let wal = fixture_wal(&[1], 1);
        let mut capture = WalCaptureState::new();
        capture.observe_write(32, &wal[32..]);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::NoCommit);
        capture.observe_write(0, &wal[..32]);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);

        let mut hole = WalCaptureState::new();
        hole.observe_write(0, &wal[..32]);
        hole.observe_write(33, &wal[33..]);
        assert_eq!(hole.observe_sync(true), ShadowSyncOutcome::NoCommit);
    }

    #[test]
    fn malformed_sync_drops_only_shadow_generation() {
        let mut malformed = fixture_wal(&[1], 1);
        malformed[32 + 24] ^= 1;
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &malformed);
        assert_eq!(
            capture.observe_sync(true),
            ShadowSyncOutcome::Dropped(ShadowCaptureFault::MalformedWal)
        );
        assert!(capture.drain_completed().is_empty());
    }

    #[test]
    fn one_sync_can_publish_multiple_complete_transactions() {
        let multiple = fixture_wal(&[1, 2], 2);
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &multiple);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        let commits = capture.drain_completed();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].first_frame_no(), 1);
        assert_eq!(commits[0].frame_count(), 1);
        assert_eq!(commits[1].first_frame_no(), 2);
        assert_eq!(commits[1].frame_count(), 1);
        commits[0].validated_single_segment(7).unwrap();
        commits[1].validated_single_segment(8).unwrap();
    }

    #[test]
    fn split_header_rewrite_never_mixes_wal_generations() {
        let first = fixture_wal(&[1], 1);
        let second = fixture_wal_with_checkpoint_sequence(&[2], 2, 2);
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &first);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);

        capture.observe_write(0, &second[..24]);
        capture.observe_write(24, &second[24..SQLITE_WAL_HEADER_BYTES]);
        capture.observe_write(
            SQLITE_WAL_HEADER_BYTES as i64,
            &second[SQLITE_WAL_HEADER_BYTES..],
        );
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);

        let commits = capture.drain_completed();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].wal_generation(), 1);
        assert_eq!(commits[1].wal_generation(), 2);
        assert_eq!(commits[1].first_frame_no(), 1);
        assert_eq!(commits[1].frame_count(), 2);
        commits[1].validated_single_segment(8).unwrap();
    }

    #[test]
    fn truncate_and_new_header_start_fresh_monotonic_generations() {
        let first = fixture_wal(&[1], 1);
        let second = fixture_wal_with_checkpoint_sequence(&[1], 1, 2);

        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &first);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        assert_eq!(capture.drain_completed()[0].wal_generation(), 1);
        capture.observe_truncate(0, true);
        capture.observe_write(0, &second);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        assert_eq!(capture.drain_completed()[0].wal_generation(), 2);

        capture.observe_write(0, &first);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        assert_eq!(capture.drain_completed()[0].wal_generation(), 3);
    }

    #[test]
    fn oversize_is_fail_open_and_recovers_only_after_new_generation() {
        let mut capture = WalCaptureState::new();
        capture.observe_write(MAX_SHADOW_WAL_BYTES as i64, &[1]);
        assert_eq!(
            capture.observe_sync(true),
            ShadowSyncOutcome::Dropped(ShadowCaptureFault::TooLarge)
        );
        assert_eq!(capture.metrics().oversized_writes, 1);

        let wal = fixture_wal(&[1], 1);
        capture.observe_write(0, &wal);
        assert!(capture.drain_completed().is_empty());
        capture.observe_truncate(0, true);
        capture.observe_write(0, &wal);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
    }
}
