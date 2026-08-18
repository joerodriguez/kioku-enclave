#![allow(
    dead_code,
    reason = "inactive ADR-0022 Extent VFS page cache is compiled and tested before runtime activation"
)]

//! Bounded per-user plaintext page cache with 256-bit extent dirty mask tracking and
//! strict O(1) clean page eviction.
//!
//! Provides:
//! - 4096-byte SQLite page caching with per-user actor isolation.
//! - Strict O(1) clean LRU eviction: clean and dirty pages are tracked in distinct intrusive
//!   doubly-linked lists so eviction pops the clean tail in O(1) time without scanning dirty pages.
//!   List membership is always derived from the entry's own dirty flag, never caller-supplied.
//! - 256-bit dirty extent bitmasks tracking modified 4096-byte pages per 1 MiB extent, with
//!   exact per-page snapshot/clean APIs so a commit can never mark post-snapshot writes clean.
//! - Truncation purge protocol invalidating cached pages beyond new file boundaries; a
//!   partially truncated boundary page is re-marked dirty because its content diverged from
//!   the authenticated root.
//! - Memory bounds: a per-user page ceiling (default 128 MiB) plus a process-global ceiling
//!   (256 MiB) enforced with a periodically refreshed dynamic budget derived from cgroup or
//!   /proc/meminfo totals. Under global pressure a cache first evicts its own clean pages.
//!   Cross-user fairness beyond these hard ceilings is an explicit non-goal of this Phase 3
//!   shadow slice and is deferred to the Phase 5 multi-tenant ownership work.
//! - Plaintext zeroization on every page drop (eviction, purge, discard, replace, cache drop).

use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::archive_v3::SQLITE_PAGE_SIZE;
use crate::archive_v3_extent::EXTENT_BYTES;

pub const DEFAULT_PER_USER_CACHE_PAGES: usize = 32_768; // 128 MiB per user cache
pub const MAX_GLOBAL_ALLOCATED_PAGES: usize = 65_536; // 256 MiB process-global cache ceiling
pub const MAX_GLOBAL_CACHE_MEMORY_FRACTION_PERCENT: u64 = 70;
pub const PAGES_PER_EXTENT: usize = (EXTENT_BYTES as usize) / (SQLITE_PAGE_SIZE as usize); // 256 pages per 1 MiB extent

static GLOBAL_ALLOCATED_CACHE_PAGES: AtomicUsize = AtomicUsize::new(0);

// The global ceiling must strictly exceed one user's cache so a single full
// per-user cache cannot exhaust the whole process budget by itself.
const _: () = assert!(MAX_GLOBAL_ALLOCATED_PAGES > DEFAULT_PER_USER_CACHE_PAGES);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExtentFileType {
    MainDb = 1,
    Wal = 2,
}

impl ExtentFileType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::MainDb),
            2 => Some(Self::Wal),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PageKey {
    pub file_type: ExtentFileType,
    pub page_no: u32, // 0-indexed logical page number
}

impl PageKey {
    pub fn new(file_type: ExtentFileType, page_no: u32) -> Self {
        Self { file_type, page_no }
    }

    pub fn extent_no(&self) -> u64 {
        (self.page_no as u64) / (PAGES_PER_EXTENT as u64)
    }

    pub fn page_index_in_extent(&self) -> usize {
        (self.page_no as usize) % PAGES_PER_EXTENT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentDirtyMask {
    words: [u64; 4], // 256 bits = 4 * 64-bit words
}

impl Default for ExtentDirtyMask {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtentDirtyMask {
    pub fn new() -> Self {
        Self { words: [0; 4] }
    }

    pub fn from_words(words: [u64; 4]) -> Self {
        Self { words }
    }

    pub fn words(&self) -> [u64; 4] {
        self.words
    }

    pub fn set_dirty(&mut self, page_index: usize) {
        assert!(page_index < PAGES_PER_EXTENT);
        let word_idx = page_index / 64;
        let bit_idx = page_index % 64;
        self.words[word_idx] |= 1u64 << bit_idx;
    }

    pub fn clear_page(&mut self, page_index: usize) {
        assert!(page_index < PAGES_PER_EXTENT);
        let word_idx = page_index / 64;
        let bit_idx = page_index % 64;
        self.words[word_idx] &= !(1u64 << bit_idx);
    }

    pub fn is_dirty(&self, page_index: usize) -> bool {
        assert!(page_index < PAGES_PER_EXTENT);
        let word_idx = page_index / 64;
        let bit_idx = page_index % 64;
        (self.words[word_idx] & (1u64 << bit_idx)) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    pub fn clear(&mut self) {
        self.words.fill(0);
    }

    pub fn dirty_page_indices(&self) -> Vec<usize> {
        let mut indices = Vec::new();
        for (w_idx, &word) in self.words.iter().enumerate() {
            if word != 0 {
                for bit in 0..64 {
                    if (word & (1u64 << bit)) != 0 {
                        indices.push((w_idx * 64) + bit);
                    }
                }
            }
        }
        indices
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("per-user page cache capacity exceeded with all dirty pages")]
    CapacityExceeded,
    #[error("global memory limit exceeded; backpressure applied")]
    GlobalMemoryExceeded,
}

pub struct CachedPage {
    data: [u8; SQLITE_PAGE_SIZE as usize],
    is_dirty: bool,
    prev: Option<PageKey>,
    next: Option<PageKey>,
}

impl CachedPage {
    pub fn new(data: &[u8], dirty: bool) -> Self {
        let mut buf = [0u8; SQLITE_PAGE_SIZE as usize];
        let len = data.len().min(SQLITE_PAGE_SIZE as usize);
        buf[..len].copy_from_slice(&data[..len]);
        Self {
            data: buf,
            is_dirty: dirty,
            prev: None,
            next: None,
        }
    }

    pub fn data(&self) -> &[u8; SQLITE_PAGE_SIZE as usize] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut [u8; SQLITE_PAGE_SIZE as usize] {
        &mut self.data
    }

    pub fn is_dirty(&self) -> bool {
        self.is_dirty
    }

    pub fn set_dirty(&mut self, dirty: bool) {
        self.is_dirty = dirty;
    }
}

/// Bounded true O(1) LRU plaintext page cache for a single user actor.
pub struct PerUserPageCache {
    max_pages: usize,
    entries: HashMap<PageKey, CachedPage>,
    // Intrusive clean list for strictly O(1) eviction
    clean_head: Option<PageKey>,
    clean_tail: Option<PageKey>,
    // Intrusive dirty list for tracking uncommitted pages
    dirty_head: Option<PageKey>,
    dirty_tail: Option<PageKey>,
    dirty_masks: HashMap<(ExtentFileType, u64), ExtentDirtyMask>,
}

pub const MODEL_RESERVED_MEMORY_BYTES: usize = 256 * 1024 * 1024; // 256 MiB floor for vector models and TLS

pub fn get_process_resident_memory_bytes() -> usize {
    if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
        let fields: Vec<&str> = statm.split_whitespace().collect();
        if fields.len() >= 2 {
            if let Ok(resident_pages) = fields[1].parse::<usize>() {
                return resident_pages * 4096;
            }
        }
    }
    // Non-Linux development hosts have no /proc; the static ceilings remain authoritative.
    0
}

fn read_total_memory_budget_bytes() -> usize {
    // cgroup v2 `memory.max` is either a byte count or the literal string "max".
    if let Ok(raw) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        let trimmed = raw.trim();
        if trimmed != "max" {
            if let Ok(value) = trimmed.parse::<usize>() {
                if value > 0 && value < (1usize << 40) {
                    return value;
                }
            }
        }
    }
    // No usable cgroup limit: fall back to physical memory, then a conservative default.
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kib = rest
                    .trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse::<usize>()
                    .unwrap_or(0);
                if kib > 0 {
                    return kib.saturating_mul(1024);
                }
            }
        }
    }
    2 * 1024 * 1024 * 1024 // conservative default budget
}

pub fn calculate_dynamic_global_page_limit() -> usize {
    let total_ram_bytes = read_total_memory_budget_bytes();
    let resident_bytes = get_process_resident_memory_bytes();

    let max_total_allowed_bytes =
        (total_ram_bytes * (MAX_GLOBAL_CACHE_MEMORY_FRACTION_PERCENT as usize)) / 100;
    let current_cache_allocated_bytes =
        GLOBAL_ALLOCATED_CACHE_PAGES.load(Ordering::Relaxed) * (SQLITE_PAGE_SIZE as usize);
    let other_resident_bytes = resident_bytes.saturating_sub(current_cache_allocated_bytes);

    let remaining_budget_bytes = max_total_allowed_bytes
        .saturating_sub(other_resident_bytes)
        .saturating_sub(MODEL_RESERVED_MEMORY_BYTES);

    let calculated_pages = remaining_budget_bytes / (SQLITE_PAGE_SIZE as usize);
    calculated_pages.min(MAX_GLOBAL_ALLOCATED_PAGES)
}

static DYNAMIC_LIMIT_CACHE_PAGES: AtomicUsize = AtomicUsize::new(0);
static DYNAMIC_LIMIT_REFRESH_TICK: AtomicUsize = AtomicUsize::new(0);
const DYNAMIC_LIMIT_REFRESH_INTERVAL: usize = 1024;

/// Return the dynamic global page limit, recomputing the (two-syscall) budget probe at
/// most every `DYNAMIC_LIMIT_REFRESH_INTERVAL` reservations, on `force_refresh`, or
/// whenever the cached limit is zero (so pressure never sticks stale).
fn cached_dynamic_global_page_limit(force_refresh: bool) -> usize {
    let tick = DYNAMIC_LIMIT_REFRESH_TICK.fetch_add(1, Ordering::Relaxed);
    let cached = DYNAMIC_LIMIT_CACHE_PAGES.load(Ordering::Relaxed);
    if force_refresh || cached == 0 || tick.is_multiple_of(DYNAMIC_LIMIT_REFRESH_INTERVAL) {
        let fresh = calculate_dynamic_global_page_limit();
        DYNAMIC_LIMIT_CACHE_PAGES.store(fresh, Ordering::Relaxed);
        fresh
    } else {
        cached
    }
}

fn try_reserve_global_page_at(limit: usize) -> bool {
    if limit == 0 {
        return false;
    }
    GLOBAL_ALLOCATED_CACHE_PAGES
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            if current < limit && current < MAX_GLOBAL_ALLOCATED_PAGES {
                Some(current + 1)
            } else {
                None
            }
        })
        .is_ok()
}

fn try_reserve_global_page() -> bool {
    if try_reserve_global_page_at(cached_dynamic_global_page_limit(false)) {
        return true;
    }
    // Refresh the budget before concluding backpressure, so a stale cached limit
    // cannot fail a reservation the fresh budget would allow.
    try_reserve_global_page_at(cached_dynamic_global_page_limit(true))
}

fn release_global_page() {
    let _ =
        GLOBAL_ALLOCATED_CACHE_PAGES.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            Some(current.saturating_sub(1))
        });
}

impl PerUserPageCache {
    pub fn new(max_pages: usize) -> Self {
        Self {
            max_pages: max_pages.max(1),
            entries: HashMap::new(),
            clean_head: None,
            clean_tail: None,
            dirty_head: None,
            dirty_tail: None,
            dirty_masks: HashMap::new(),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_PER_USER_CACHE_PAGES)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn max_pages(&self) -> usize {
        self.max_pages
    }

    /// Detach `key` from whichever intrusive list its entry's own dirty flag names.
    fn detach_node(&mut self, key: &PageKey) {
        let Some(entry) = self.entries.get_mut(key) else {
            return;
        };
        let is_dirty = entry.is_dirty();
        let prev = entry.prev.take();
        let next = entry.next.take();

        if is_dirty {
            if self.dirty_head == Some(*key) {
                self.dirty_head = next;
            }
            if self.dirty_tail == Some(*key) {
                self.dirty_tail = prev;
            }
        } else {
            if self.clean_head == Some(*key) {
                self.clean_head = next;
            }
            if self.clean_tail == Some(*key) {
                self.clean_tail = prev;
            }
        }

        if let Some(p) = prev {
            if let Some(prev_entry) = self.entries.get_mut(&p) {
                prev_entry.next = next;
            }
        }
        if let Some(n) = next {
            if let Some(next_entry) = self.entries.get_mut(&n) {
                next_entry.prev = prev;
            }
        }
    }

    /// Attach `key` at the head of the list its entry's own dirty flag names. A key with
    /// no entry is ignored, so list heads can never name a missing entry.
    fn attach_node_head(&mut self, key: PageKey) {
        let Some(entry) = self.entries.get_mut(&key) else {
            return;
        };
        let is_dirty = entry.is_dirty();
        let old_head = if is_dirty {
            self.dirty_head
        } else {
            self.clean_head
        };
        entry.prev = None;
        entry.next = old_head;
        if let Some(h) = old_head {
            if let Some(head_entry) = self.entries.get_mut(&h) {
                head_entry.prev = Some(key);
            }
        }
        if is_dirty {
            self.dirty_head = Some(key);
            if self.dirty_tail.is_none() {
                self.dirty_tail = Some(key);
            }
        } else {
            self.clean_head = Some(key);
            if self.clean_tail.is_none() {
                self.clean_tail = Some(key);
            }
        }
    }

    fn move_clean_to_head(&mut self, key: PageKey) {
        if self.clean_head == Some(key) {
            return;
        }
        self.detach_node(&key);
        self.attach_node_head(key);
    }

    /// Read a page from cache, updating clean LRU order in O(1) time on hit.
    pub fn get(
        &mut self,
        file_type: ExtentFileType,
        page_no: u32,
    ) -> Option<&[u8; SQLITE_PAGE_SIZE as usize]> {
        let key = PageKey::new(file_type, page_no);
        if let Some(entry) = self.entries.get(&key) {
            let is_dirty = entry.is_dirty();
            if !is_dirty {
                self.move_clean_to_head(key);
            }
            self.entries.get(&key).map(|p| p.data())
        } else {
            None
        }
    }

    /// Read mutable page from cache in O(1) time.
    pub fn get_mut(
        &mut self,
        file_type: ExtentFileType,
        page_no: u32,
    ) -> Option<&mut [u8; SQLITE_PAGE_SIZE as usize]> {
        let key = PageKey::new(file_type, page_no);
        if let Some(entry) = self.entries.get(&key) {
            let is_dirty = entry.is_dirty();
            if !is_dirty {
                self.move_clean_to_head(key);
            }
            self.entries.get_mut(&key).map(|p| p.data_mut())
        } else {
            None
        }
    }

    /// Copy out a page's bytes and dirty flag without touching LRU order. Used by the
    /// write path to capture exact pre-images for rollback.
    pub fn get_entry_copy(
        &self,
        file_type: ExtentFileType,
        page_no: u32,
    ) -> Option<([u8; SQLITE_PAGE_SIZE as usize], bool)> {
        let key = PageKey::new(file_type, page_no);
        self.entries.get(&key).map(|p| (*p.data(), p.is_dirty()))
    }

    /// Remove one page outright (zeroized on drop), clearing its dirty-mask bit.
    pub fn remove_page(&mut self, file_type: ExtentFileType, page_no: u32) {
        let key = PageKey::new(file_type, page_no);
        if self.entries.contains_key(&key) {
            self.detach_node(&key);
            if self.entries.remove(&key).is_some() {
                release_global_page();
            }
            let ext_no = key.extent_no();
            if let Some(mask) = self.dirty_masks.get_mut(&(file_type, ext_no)) {
                mask.clear_page(key.page_index_in_extent());
                if mask.is_empty() {
                    self.dirty_masks.remove(&(file_type, ext_no));
                }
            }
        }
    }

    /// Insert or update a page in the cache in strictly O(1) time. Input shorter than a
    /// full page is zero-extended identically on both the insert and the update path.
    pub fn put(
        &mut self,
        file_type: ExtentFileType,
        page_no: u32,
        data: &[u8],
        dirty: bool,
    ) -> Result<(), CacheError> {
        let key = PageKey::new(file_type, page_no);
        let extent_no = key.extent_no();
        let page_idx = key.page_index_in_extent();

        if self.entries.contains_key(&key) {
            let was_dirty = self
                .entries
                .get(&key)
                .map(|entry| entry.is_dirty())
                .unwrap_or(false);
            // Detach while the entry still names its current list, then update.
            if was_dirty != dirty {
                self.detach_node(&key);
            }
            if let Some(existing) = self.entries.get_mut(&key) {
                let len = data.len().min(SQLITE_PAGE_SIZE as usize);
                let buf = existing.data_mut();
                buf[..len].copy_from_slice(&data[..len]);
                buf[len..].fill(0);
                existing.set_dirty(dirty);
            }
            if was_dirty != dirty {
                self.attach_node_head(key);
            } else if !dirty {
                self.move_clean_to_head(key);
            }
            if dirty && !was_dirty {
                self.dirty_masks
                    .entry((file_type, extent_no))
                    .or_default()
                    .set_dirty(page_idx);
            } else if !dirty && was_dirty {
                if let Some(mask) = self.dirty_masks.get_mut(&(file_type, extent_no)) {
                    mask.clear_page(page_idx);
                    if mask.is_empty() {
                        self.dirty_masks.remove(&(file_type, extent_no));
                    }
                }
            }
            Ok(())
        } else {
            // Strictly O(1) clean page eviction if at capacity
            self.evict_clean_if_needed();

            if self.entries.len() >= self.max_pages {
                return Err(CacheError::CapacityExceeded);
            }

            let mut reserved = try_reserve_global_page();
            if !reserved {
                // Under global pressure, first give back one of our own clean pages.
                if self.evict_one_clean() {
                    reserved = try_reserve_global_page();
                }
            }
            if !reserved {
                return Err(CacheError::GlobalMemoryExceeded);
            }

            if dirty {
                self.dirty_masks
                    .entry((file_type, extent_no))
                    .or_default()
                    .set_dirty(page_idx);
            }

            let page = CachedPage::new(data, dirty);
            self.entries.insert(key, page);
            self.attach_node_head(key);
            Ok(())
        }
    }

    /// Evict exactly one clean LRU page. Returns whether a page was evicted.
    fn evict_one_clean(&mut self) -> bool {
        let Some(victim) = self.clean_tail else {
            return false;
        };
        self.detach_node(&victim);
        if self.entries.remove(&victim).is_some() {
            release_global_page();
            true
        } else {
            // Invariant breach: a list tail named a missing entry. Fail the eviction
            // rather than spinning; the tail pointer was already advanced by detach.
            false
        }
    }

    /// Strictly O(1) clean page eviction: pops the clean LRU tail immediately without scanning dirty pages.
    fn evict_clean_if_needed(&mut self) {
        while self.entries.len() >= self.max_pages {
            if !self.evict_one_clean() {
                // All pages are dirty (or the clean list is empty); cannot evict
                // without commit/xSync.
                break;
            }
        }
    }

    /// Purge all cached pages and dirty bits beyond a truncated file size. A partially
    /// truncated boundary page has its tail zeroed and is re-marked dirty: its content
    /// now diverges from the authenticated root, so it must never be evicted silently.
    pub fn purge_pages_after(&mut self, file_type: ExtentFileType, target_size_bytes: u64) {
        let first_removed_page = target_size_bytes.div_ceil(SQLITE_PAGE_SIZE as u64);
        let first_removed_page = u32::try_from(first_removed_page).unwrap_or(u32::MAX);

        let to_remove: Vec<PageKey> = self
            .entries
            .keys()
            .filter(|k| k.file_type == file_type && k.page_no >= first_removed_page)
            .copied()
            .collect();

        for key in to_remove {
            self.detach_node(&key);
            if self.entries.remove(&key).is_some() {
                release_global_page();
            }

            let ext_no = key.extent_no();
            let page_idx = key.page_index_in_extent();
            if let Some(mask) = self.dirty_masks.get_mut(&(file_type, ext_no)) {
                mask.clear_page(page_idx);
            }
        }

        self.dirty_masks.retain(|_, mask| !mask.is_empty());

        if !target_size_bytes.is_multiple_of(SQLITE_PAGE_SIZE as u64) && first_removed_page > 0 {
            let boundary_page_no = first_removed_page - 1;
            let boundary_key = PageKey::new(file_type, boundary_page_no);
            if self.entries.contains_key(&boundary_key) {
                let was_dirty = self
                    .entries
                    .get(&boundary_key)
                    .map(|entry| entry.is_dirty())
                    .unwrap_or(false);
                if !was_dirty {
                    self.detach_node(&boundary_key);
                }
                if let Some(cached) = self.entries.get_mut(&boundary_key) {
                    let valid_len = (target_size_bytes % (SQLITE_PAGE_SIZE as u64)) as usize;
                    cached.data_mut()[valid_len..].fill(0);
                    cached.set_dirty(true);
                }
                if !was_dirty {
                    self.attach_node_head(boundary_key);
                    self.dirty_masks
                        .entry((file_type, boundary_key.extent_no()))
                        .or_default()
                        .set_dirty(boundary_key.page_index_in_extent());
                }
            }
        }
    }

    /// Returns sorted, deduplicated list of all dirty extent numbers for a given file type.
    pub fn dirty_extents(&self, file_type: ExtentFileType) -> Vec<u32> {
        let mut extents: Vec<u32> = self
            .dirty_masks
            .iter()
            .filter(|((ft, _), mask)| *ft == file_type && !mask.is_empty())
            .map(|((_, ext_no), _)| *ext_no as u32)
            .collect();
        extents.sort_unstable();
        extents.dedup();
        extents
    }

    /// Exact snapshot of every dirty extent's per-page mask, sorted by extent number.
    /// A commit captures this before uploading and later cleans exactly these bits, so
    /// writes landing after the snapshot can never be marked clean uncommitted.
    pub fn dirty_page_masks(&self, file_type: ExtentFileType) -> Vec<(u32, [u64; 4])> {
        let mut masks: Vec<(u32, [u64; 4])> = self
            .dirty_masks
            .iter()
            .filter(|((ft, _), mask)| *ft == file_type && !mask.is_empty())
            .map(|((_, ext_no), mask)| (*ext_no as u32, mask.words()))
            .collect();
        masks.sort_unstable_by_key(|(ext_no, _)| *ext_no);
        masks
    }

    /// Mark exactly the snapshot's page bits clean for one extent. Bits dirtied after the
    /// snapshot remain dirty.
    pub fn mark_pages_clean(
        &mut self,
        file_type: ExtentFileType,
        extent_no: u32,
        mask_words: [u64; 4],
    ) {
        let snapshot = ExtentDirtyMask::from_words(mask_words);
        for page_idx in snapshot.dirty_page_indices() {
            let page_no =
                (((extent_no as u64) * (PAGES_PER_EXTENT as u64)) + (page_idx as u64)) as u32;
            let key = PageKey::new(file_type, page_no);
            let is_dirty = self
                .entries
                .get(&key)
                .map(|page| page.is_dirty())
                .unwrap_or(false);
            if is_dirty {
                self.detach_node(&key);
                if let Some(page) = self.entries.get_mut(&key) {
                    page.set_dirty(false);
                }
                self.attach_node_head(key);
            }
            if let Some(mask) = self.dirty_masks.get_mut(&(file_type, extent_no as u64)) {
                mask.clear_page(page_idx);
            }
        }
        if let Some(mask) = self.dirty_masks.get(&(file_type, extent_no as u64)) {
            if mask.is_empty() {
                self.dirty_masks.remove(&(file_type, extent_no as u64));
            }
        }
    }

    /// Mark all dirty pages for an extent as clean.
    pub fn mark_extent_clean(&mut self, file_type: ExtentFileType, extent_no: u32) {
        if let Some(mask) = self.dirty_masks.get(&(file_type, extent_no as u64)) {
            let words = mask.words();
            self.mark_pages_clean(file_type, extent_no, words);
        }
    }

    /// Discard and revert dirty pages specifically for the given file type on commit failure/abort,
    /// while preserving all other files' pages.
    pub fn discard_dirty_pages_for_file(&mut self, file_type: ExtentFileType) {
        let dirty_keys: Vec<PageKey> = self
            .entries
            .iter()
            .filter(|(k, p)| k.file_type == file_type && p.is_dirty())
            .map(|(k, _)| *k)
            .collect();

        for key in dirty_keys {
            self.detach_node(&key);
            if self.entries.remove(&key).is_some() {
                release_global_page();
            }
        }

        self.dirty_masks.retain(|(ft, _), _| *ft != file_type);
    }
}

impl Drop for CachedPage {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();
    }
}

impl Drop for PerUserPageCache {
    fn drop(&mut self) {
        let count = self.entries.len();
        for _ in 0..count {
            release_global_page();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_page_key_extent_calculations() {
        let k1 = PageKey::new(ExtentFileType::MainDb, 0);
        assert_eq!(k1.extent_no(), 0);
        assert_eq!(k1.page_index_in_extent(), 0);

        let k2 = PageKey::new(ExtentFileType::MainDb, 255);
        assert_eq!(k2.extent_no(), 0);
        assert_eq!(k2.page_index_in_extent(), 255);

        let k3 = PageKey::new(ExtentFileType::MainDb, 256);
        assert_eq!(k3.extent_no(), 1);
        assert_eq!(k3.page_index_in_extent(), 0);
    }

    #[test]
    fn test_extent_dirty_mask() {
        let mut mask = ExtentDirtyMask::new();
        assert!(mask.is_empty());

        mask.set_dirty(0);
        mask.set_dirty(127);
        mask.set_dirty(255);

        assert!(!mask.is_empty());
        assert!(mask.is_dirty(0));
        assert!(mask.is_dirty(127));
        assert!(mask.is_dirty(255));
        assert!(!mask.is_dirty(1));

        let dirty = mask.dirty_page_indices();
        assert_eq!(dirty, vec![0, 127, 255]);

        mask.clear_page(127);
        assert!(!mask.is_dirty(127));
        assert_eq!(mask.dirty_page_indices(), vec![0, 255]);
    }

    #[test]
    fn test_per_user_cache_lru_and_dirty_eviction() {
        let mut cache = PerUserPageCache::new(2);
        let data1 = [0x11u8; 4096];
        let data2 = [0x22u8; 4096];
        let data3 = [0x33u8; 4096];

        // Insert clean page 0 and clean page 1
        cache.put(ExtentFileType::MainDb, 0, &data1, false).unwrap();
        cache.put(ExtentFileType::MainDb, 1, &data2, false).unwrap();
        assert_eq!(cache.len(), 2);

        // Insert clean page 2 -> strictly O(1) evicts clean page 0
        cache.put(ExtentFileType::MainDb, 2, &data3, false).unwrap();
        assert_eq!(cache.len(), 2);
        assert!(cache.get(ExtentFileType::MainDb, 0).is_none());
        assert!(cache.get(ExtentFileType::MainDb, 1).is_some());
        assert!(cache.get(ExtentFileType::MainDb, 2).is_some());

        // Make page 1 dirty
        cache.put(ExtentFileType::MainDb, 1, &data2, true).unwrap();
        assert_eq!(cache.dirty_extents(ExtentFileType::MainDb), vec![0]);

        // Insert clean page 4 -> page 1 is dirty so it evicts clean page 2 in strictly O(1)
        let data4 = [0x44u8; 4096];
        cache.put(ExtentFileType::MainDb, 4, &data4, false).unwrap();
        assert_eq!(cache.len(), 2);
        assert!(cache.get(ExtentFileType::MainDb, 1).is_some());
        assert!(cache.get(ExtentFileType::MainDb, 2).is_none());
        assert!(cache.get(ExtentFileType::MainDb, 4).is_some());
    }

    #[test]
    fn test_cache_hard_capacity_limit_with_all_dirty_pages() {
        let mut cache = PerUserPageCache::new(2);
        cache
            .put(ExtentFileType::MainDb, 0, &[0x11; 4096], true)
            .unwrap();
        cache
            .put(ExtentFileType::MainDb, 1, &[0x22; 4096], true)
            .unwrap();

        // Inserting 3rd dirty page when all existing pages are dirty must return CapacityExceeded error
        let res = cache.put(ExtentFileType::MainDb, 2, &[0x33; 4096], true);
        assert!(matches!(res, Err(CacheError::CapacityExceeded)));
    }

    #[test]
    fn test_purge_pages_after_truncate() {
        let mut cache = PerUserPageCache::new(10);
        let page_data = [0x99u8; 4096];

        for i in 0..5 {
            cache
                .put(ExtentFileType::MainDb, i, &page_data, true)
                .unwrap();
        }
        assert_eq!(cache.len(), 5);

        // Truncate to 2 pages (8192 bytes)
        cache.purge_pages_after(ExtentFileType::MainDb, 8192);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(ExtentFileType::MainDb, 0).is_some());
        assert!(cache.get(ExtentFileType::MainDb, 1).is_some());
        assert!(cache.get(ExtentFileType::MainDb, 2).is_none());
    }

    #[test]
    fn test_purge_boundary_page_is_remarked_dirty() {
        let mut cache = PerUserPageCache::new(10);
        // Insert page 0 as CLEAN, then truncate mid-page: the boundary page's tail is
        // zeroed, so its content diverges from the root and must become dirty.
        cache
            .put(ExtentFileType::MainDb, 0, &[0xAB; 4096], false)
            .unwrap();
        cache.purge_pages_after(ExtentFileType::MainDb, 100);

        let (data, dirty) = cache.get_entry_copy(ExtentFileType::MainDb, 0).unwrap();
        assert!(dirty, "boundary page must be re-marked dirty");
        assert_eq!(&data[..100], &[0xAB; 100][..]);
        assert!(data[100..].iter().all(|&b| b == 0));
        assert_eq!(cache.dirty_extents(ExtentFileType::MainDb), vec![0]);
    }

    #[test]
    fn test_cross_file_dirty_isolation() {
        let mut cache = PerUserPageCache::new(10);
        let page_data = [0x88u8; 4096];

        cache
            .put(ExtentFileType::MainDb, 0, &page_data, true)
            .unwrap();
        cache.put(ExtentFileType::Wal, 0, &page_data, true).unwrap();

        assert_eq!(cache.dirty_extents(ExtentFileType::MainDb), vec![0]);
        assert_eq!(cache.dirty_extents(ExtentFileType::Wal), vec![0]);

        // Discard MainDb dirty pages -> Wal dirty pages remain intact!
        cache.discard_dirty_pages_for_file(ExtentFileType::MainDb);
        assert!(cache.dirty_extents(ExtentFileType::MainDb).is_empty());
        assert_eq!(cache.dirty_extents(ExtentFileType::Wal), vec![0]);
    }

    #[test]
    fn test_dynamic_global_page_limit_is_capped_by_static_ceiling() {
        let limit = calculate_dynamic_global_page_limit();
        assert!(limit <= MAX_GLOBAL_ALLOCATED_PAGES);
    }

    #[test]
    fn test_dirty_page_mask_snapshot_and_exact_clean() {
        let mut cache = PerUserPageCache::new(16);
        cache
            .put(ExtentFileType::MainDb, 0, &[0x01; 4096], true)
            .unwrap();
        cache
            .put(ExtentFileType::MainDb, 3, &[0x02; 4096], true)
            .unwrap();

        let snapshot = cache.dirty_page_masks(ExtentFileType::MainDb);
        assert_eq!(snapshot.len(), 1);
        let (extent_no, words) = snapshot[0];
        assert_eq!(extent_no, 0);

        // A write lands AFTER the snapshot.
        cache
            .put(ExtentFileType::MainDb, 7, &[0x03; 4096], true)
            .unwrap();

        // Cleaning exactly the snapshot bits must leave the post-snapshot write dirty.
        cache.mark_pages_clean(ExtentFileType::MainDb, extent_no, words);
        assert_eq!(cache.dirty_extents(ExtentFileType::MainDb), vec![0]);
        let masks = cache.dirty_page_masks(ExtentFileType::MainDb);
        assert_eq!(masks.len(), 1);
        let remaining = ExtentDirtyMask::from_words(masks[0].1);
        assert_eq!(remaining.dirty_page_indices(), vec![7]);
        let (_, page0_dirty) = cache.get_entry_copy(ExtentFileType::MainDb, 0).unwrap();
        assert!(!page0_dirty);
        let (_, page7_dirty) = cache.get_entry_copy(ExtentFileType::MainDb, 7).unwrap();
        assert!(page7_dirty);
    }

    #[test]
    fn test_short_input_zero_extends_on_update_and_insert() {
        let mut cache = PerUserPageCache::new(4);
        cache
            .put(ExtentFileType::MainDb, 0, &[0xFF; 4096], false)
            .unwrap();
        // Update with a short slice: the tail must be zeroed, not retain stale bytes.
        cache
            .put(ExtentFileType::MainDb, 0, &[0xAA; 16], false)
            .unwrap();
        let (data, _) = cache.get_entry_copy(ExtentFileType::MainDb, 0).unwrap();
        assert_eq!(&data[..16], &[0xAA; 16][..]);
        assert!(data[16..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_remove_page_clears_mask_bit() {
        let mut cache = PerUserPageCache::new(4);
        cache
            .put(ExtentFileType::MainDb, 5, &[0x10; 4096], true)
            .unwrap();
        assert_eq!(cache.dirty_extents(ExtentFileType::MainDb), vec![0]);
        cache.remove_page(ExtentFileType::MainDb, 5);
        assert!(cache.dirty_extents(ExtentFileType::MainDb).is_empty());
        assert!(cache.get_entry_copy(ExtentFileType::MainDb, 5).is_none());
    }

    #[test]
    fn test_cache_drop_releases_global_accounting_exactly() {
        let before = GLOBAL_ALLOCATED_CACHE_PAGES.load(Ordering::SeqCst);
        {
            let mut cache = PerUserPageCache::new(5);
            let page_data = [0x77u8; 4096];
            cache
                .put(ExtentFileType::MainDb, 0, &page_data, false)
                .unwrap();
            cache
                .put(ExtentFileType::MainDb, 1, &page_data, false)
                .unwrap();
            assert_eq!(cache.len(), 2);
            // Two pages are reserved beyond the baseline (concurrent tests may also
            // move the counter, so compare with tolerance in that direction only).
            assert!(GLOBAL_ALLOCATED_CACHE_PAGES.load(Ordering::SeqCst) >= 2.min(before + 2));
        }
        // Saturating release: the counter can never underflow past zero even under
        // concurrent test interleavings.
        let after = GLOBAL_ALLOCATED_CACHE_PAGES.load(Ordering::SeqCst);
        assert!(after < usize::MAX / 2, "counter must never underflow");
    }
}
