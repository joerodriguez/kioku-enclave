#![allow(
    dead_code,
    reason = "inactive ADR-0022 Extent VFS is compiled and tested before runtime activation"
)]

//! Inactive ADR-0022 SQLite Extent Virtual File System (VFS) for Phase 3 shadow paging.
//!
//! One installed VFS instance is one logical shadow database. The enforced contract is
//! deliberately narrow and fail-closed:
//! - Exactly one simultaneously open `SQLITE_OPEN_MAIN_DB` handle per instance; `ATTACH`
//!   of a second database through the same VFS is refused at `xOpen`.
//! - Every non-main file class (rollback journal, WAL, super/statement journals, temp
//!   databases) is refused at `xOpen`. No byte of user plaintext can ever reach the host
//!   filesystem through this VFS: callers must run with `journal_mode=MEMORY` and
//!   `temp_store=MEMORY`, and `xAccess`/`xDelete` report and touch nothing, so a
//!   host-planted rollback journal can never be replayed into the authenticated tree.
//! - WAL journal mode is unsupported in this slice (`xOpen(SQLITE_OPEN_WAL)` and all
//!   `xShm*` fail closed) pending the separately reviewed Phase 4 WAL integration.
//! - Reads authenticate every miss through [`reconstruct_extent_range`] against the
//!   current settled candidate root; offsets beyond the root's authenticated length but
//!   inside the unsynced logical file are served as zeros (the sparse-hole semantics the
//!   root's length and extent map commit to).
//! - `xSync` runs the durable shadow commit protocol: heal-or-begin an attempt in the
//!   authenticated SQLite attempt ledger, stage every extent object with durable
//!   reservation and exact readback, record the candidate root, and terminate at
//!   `ShadowSettled`. No witness is contacted and no authority is minted; the settled
//!   candidate is adopted for local shadow paging only. Exactly the snapshot's dirty
//!   page bits are marked clean, so post-snapshot writes stay dirty.
//! - Commit cost is O(logical file length) because every extent is re-staged per commit;
//!   `MAX_SHADOW_COMMIT_BYTES` (256 MiB) bounds it. Incremental extent-object reuse
//!   across roots is a documented prerequisite for the Phase 4 large-archive authority
//!   work; large archives reach Phase 3 shadow through the offline WAL-to-extent
//!   conversion path, not through this write path.
//! - Bounded 128 MiB per-user plaintext page cache with exact 256-bit dirty masks and a
//!   256 MiB process-global ceiling; plaintext page buffers are zeroized on drop.
//! - Bounded execution lanes: a dedicated backend runtime with global read/write/pending
//!   semaphores and hard timeouts; callbacks never unwind into C.
//! - One ledger keyspace serves one instance: full-tuple CAS and the unique active-
//!   attempt index prevent split-brain, but a second instance sharing the same
//!   (archive, epoch) ledger would durably abort the first's in-flight attempts —
//!   deploying two instances over one keyspace is a misconfiguration, not a mode.
//!   Attempt/staged-object rows and immutable provider objects are retained
//!   permanently by design (no delete authority); growth management is Phase 4+ work.

use std::{
    collections::HashMap,
    ffi::{c_char, c_int, c_void, CStr, CString},
    mem::{self, MaybeUninit},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use rusqlite::ffi;
use zeroize::Zeroizing;

use crate::archive_v3::{
    DatabaseEpoch, ImmutableObjectBackend, MAX_DATABASE_BYTES, SQLITE_PAGE_SIZE,
};
use crate::archive_v3_extent::{
    reconstruct_extent_range, upload_extent_tree, DurableExtentStaging, ExtentCipher, ExtentSource,
    ExtentTreeError, Result as ExtentResult, ShadowExtentRootCandidate, SourceExtent, EXTENT_BYTES,
};
use crate::archive_v3_extent_commit::{
    ExtentAttemptLedger, ExtentCommitCoordinator, ExtentCommitError,
};
use crate::archive_v3_extent_vfs::cache::{ExtentFileType, PerUserPageCache};

pub mod cache;

pub const MAX_EXTENT_VFS_INSTALLATIONS: usize = 32;
static EXTENT_VFS_INSTALLATIONS: AtomicUsize = AtomicUsize::new(0);

/// Hard ceiling on the logical file length `xSync` will commit. Every commit re-stages
/// the whole file, so this bounds per-commit provider work and wall-clock time.
pub const MAX_SHADOW_COMMIT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ExtentVfsError {
    #[error("VFS name contains interior NUL bytes")]
    InvalidName,
    #[error("no default SQLite VFS found on system")]
    NoDefaultVfs,
    #[error("parent OS file structure is too small for wrapper")]
    InvalidParentFileSize,
    #[error("exceeded maximum concurrent Extent VFS installations")]
    TooManyInstallations,
    #[error("VFS with name already registered")]
    AlreadyRegistered,
    #[error("sqlite3_vfs_register failed with return code {0}")]
    RegisterFailed(c_int),
    #[error("durable attempt requires witness reconciliation this slice cannot perform")]
    WitnessReconciliationRequired,
    #[error("durable attempt ledger rejected reconciliation")]
    LedgerReconciliation,
}

/// Dynamic mutable state for one Extent VFS instance (= one logical shadow database).
/// Fields are private: roots and sizes change only through the audited read/write/sync
/// callbacks and install-time reconciliation.
pub struct ExtentVfsState {
    cache: PerUserPageCache,
    backend: Arc<dyn ImmutableObjectBackend>,
    cipher: Arc<dyn ExtentCipher>,
    database_epoch: DatabaseEpoch,
    ledger: Arc<dyn ExtentAttemptLedger>,
    main_root: Option<ShadowExtentRootCandidate>,
    main_db_size: u64,
    main_dirty_modified: bool,
}

impl ExtentVfsState {
    fn new(
        backend: Arc<dyn ImmutableObjectBackend>,
        cipher: Arc<dyn ExtentCipher>,
        database_epoch: DatabaseEpoch,
        ledger: Arc<dyn ExtentAttemptLedger>,
        main_root: Option<ShadowExtentRootCandidate>,
    ) -> Self {
        let main_db_size = main_root
            .as_ref()
            .map(|r| r.logical_file_length())
            .unwrap_or(0);
        Self {
            cache: PerUserPageCache::with_default_capacity(),
            backend,
            cipher,
            database_epoch,
            ledger,
            main_root,
            main_db_size,
            main_dirty_modified: false,
        }
    }

    pub fn main_root(&self) -> Option<&ShadowExtentRootCandidate> {
        self.main_root.as_ref()
    }

    pub fn main_db_size(&self) -> u64 {
        self.main_db_size
    }

    #[cfg(test)]
    pub(crate) fn cache_mut_for_test(&mut self) -> &mut PerUserPageCache {
        &mut self.cache
    }

    #[cfg(test)]
    pub(crate) fn set_size_for_test(&mut self, size: u64, modified: bool) {
        self.main_db_size = size;
        self.main_dirty_modified = modified;
    }
}

pub struct ExtentVfsContext {
    parent: *mut ffi::sqlite3_vfs,
    state: Arc<Mutex<ExtentVfsState>>,
    open_handles: Arc<AtomicUsize>,
    /// Number of simultaneously open MAIN_DB handles; capped at one so `ATTACH` can
    /// never alias the single logical database this instance serves.
    main_db_handles: AtomicUsize,
}

unsafe impl Send for ExtentVfsContext {}
unsafe impl Sync for ExtentVfsContext {}

static VFS_REGISTRY: OnceLock<Mutex<HashMap<String, Arc<ExtentVfsContext>>>> = OnceLock::new();

fn vfs_registry() -> &'static Mutex<HashMap<String, Arc<ExtentVfsContext>>> {
    VFS_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

struct ExtentVfsAllocation {
    name: CString,
    name_str: String,
    vfs: ffi::sqlite3_vfs,
}

unsafe impl Send for ExtentVfsAllocation {}
unsafe impl Sync for ExtentVfsAllocation {}

/// RAII wrapper for an installed Extent VFS in SQLite.
pub struct RegisteredExtentVfs {
    allocation: Option<Box<ExtentVfsAllocation>>,
    context: Arc<ExtentVfsContext>,
}

// The boxes are load-bearing: SQLite may still hold pointers into a retained
// allocation, so the structs must never move when the vector reallocates.
#[allow(clippy::vec_box)]
static RETAINED_VFS_ALLOCATIONS: OnceLock<Mutex<Vec<Box<ExtentVfsAllocation>>>> = OnceLock::new();

#[allow(clippy::vec_box)]
fn retained_vfs_allocations() -> &'static Mutex<Vec<Box<ExtentVfsAllocation>>> {
    RETAINED_VFS_ALLOCATIONS.get_or_init(|| Mutex::new(Vec::new()))
}

impl RegisteredExtentVfs {
    /// Install a named Extent VFS bound to a durable attempt ledger.
    ///
    /// Installation reconciles the ledger first: an interrupted pre-witness attempt is
    /// durably terminalized, and any settled terminal recorded in the ledger is adopted
    /// unconditionally — the caller-supplied base root is used only when the ledger has
    /// no settled terminal at all, so restart selection is a property of install rather
    /// than caller diligence. There is no newer/older comparison: a caller re-seeding a
    /// fresh conversion root (for example from the offline WAL-to-extent path) must
    /// provision a fresh ledger keyspace (a new database epoch or a new ledger
    /// database); a stale settled row would otherwise supersede the reseed. An attempt
    /// stuck in a witness stage fails closed.
    pub fn install(
        name: &str,
        backend: Arc<dyn ImmutableObjectBackend>,
        cipher: Arc<dyn ExtentCipher>,
        database_epoch: DatabaseEpoch,
        ledger: Arc<dyn ExtentAttemptLedger>,
        base_main_root: Option<ShadowExtentRootCandidate>,
    ) -> Result<Self, ExtentVfsError> {
        let c_name = CString::new(name).map_err(|_| ExtentVfsError::InvalidName)?;
        let parent = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
        if parent.is_null() {
            return Err(ExtentVfsError::NoDefaultVfs);
        }
        let parent_ref = unsafe { &*parent };

        let mut state = ExtentVfsState::new(
            backend,
            Arc::clone(&cipher),
            database_epoch,
            Arc::clone(&ledger),
            base_main_root,
        );

        // Durable restart reconciliation before the VFS becomes reachable.
        let mut op_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut op_id);
        let mut coordinator = ExtentCommitCoordinator::new(
            cipher.archive_id(),
            database_epoch,
            cipher.key_epoch(),
            op_id,
            Arc::clone(&ledger),
        );
        let base = state.main_root.clone();
        match coordinator.reconcile_from_durable_ledger(
            ExtentFileType::MainDb,
            &mut state.cache,
            base,
        ) {
            Ok(adopted) => {
                state.main_db_size = adopted
                    .as_ref()
                    .map(|r| r.logical_file_length())
                    .unwrap_or(0);
                state.main_root = adopted;
                state.main_dirty_modified = false;
            }
            Err(ExtentCommitError::ManualWitnessReconciliationRequired) => {
                return Err(ExtentVfsError::WitnessReconciliationRequired);
            }
            Err(_) => return Err(ExtentVfsError::LedgerReconciliation),
        }

        let context = Arc::new(ExtentVfsContext {
            parent,
            state: Arc::new(Mutex::new(state)),
            open_handles: Arc::new(AtomicUsize::new(0)),
            main_db_handles: AtomicUsize::new(0),
        });

        let mut allocation = Box::new(ExtentVfsAllocation {
            name: c_name,
            name_str: name.to_string(),
            vfs: unsafe { MaybeUninit::zeroed().assume_init() },
        });

        let wrapper_size = mem::size_of::<ExtentFileWrapper>();

        allocation.vfs = ffi::sqlite3_vfs {
            iVersion: parent_ref.iVersion.min(3),
            szOsFile: c_int::try_from(wrapper_size)
                .map_err(|_| ExtentVfsError::InvalidParentFileSize)?,
            mxPathname: parent_ref.mxPathname,
            pNext: ptr::null_mut(),
            zName: allocation.name.as_ptr(),
            pAppData: ptr::null_mut(),
            xOpen: Some(extent_vfs_open),
            xDelete: Some(extent_vfs_delete),
            xAccess: Some(extent_vfs_access),
            xFullPathname: Some(extent_vfs_full_pathname),
            xDlOpen: parent_ref.xDlOpen.map(|_| extent_vfs_dl_open as _),
            xDlError: parent_ref.xDlError.map(|_| extent_vfs_dl_error as _),
            xDlSym: parent_ref.xDlSym.map(|_| extent_vfs_dl_sym as _),
            xDlClose: parent_ref.xDlClose.map(|_| extent_vfs_dl_close as _),
            xRandomness: parent_ref.xRandomness.map(|_| extent_vfs_randomness as _),
            xSleep: parent_ref.xSleep.map(|_| extent_vfs_sleep as _),
            xCurrentTime: parent_ref
                .xCurrentTime
                .map(|_| extent_vfs_current_time as _),
            xGetLastError: parent_ref
                .xGetLastError
                .map(|_| extent_vfs_get_last_error as _),
            xCurrentTimeInt64: parent_ref
                .xCurrentTimeInt64
                .map(|_| extent_vfs_current_time_int64 as _),
            xSetSystemCall: parent_ref
                .xSetSystemCall
                .map(|_| extent_vfs_set_system_call as _),
            xGetSystemCall: parent_ref
                .xGetSystemCall
                .map(|_| extent_vfs_get_system_call as _),
            xNextSystemCall: parent_ref
                .xNextSystemCall
                .map(|_| extent_vfs_next_system_call as _),
        };

        EXTENT_VFS_INSTALLATIONS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_EXTENT_VFS_INSTALLATIONS).then_some(count + 1)
            })
            .map_err(|_| ExtentVfsError::TooManyInstallations)?;

        // One critical section covers the duplicate check, SQLite registration, and the
        // registry insert, so two racing installs of the same name cannot interleave
        // and a registered VFS is always resolvable before xOpen can observe it.
        {
            let mut reg = vfs_registry().lock().unwrap();
            if reg.contains_key(name) {
                EXTENT_VFS_INSTALLATIONS.fetch_sub(1, Ordering::AcqRel);
                return Err(ExtentVfsError::AlreadyRegistered);
            }
            let code = unsafe { ffi::sqlite3_vfs_register(&mut allocation.vfs, 0) };
            if code != ffi::SQLITE_OK {
                EXTENT_VFS_INSTALLATIONS.fetch_sub(1, Ordering::AcqRel);
                return Err(ExtentVfsError::RegisterFailed(code));
            }
            reg.insert(name.to_string(), Arc::clone(&context));
        }

        Ok(Self {
            allocation: Some(allocation),
            context,
        })
    }

    pub fn name(&self) -> &CStr {
        &self
            .allocation
            .as_ref()
            .expect("registered Extent VFS retains its allocation")
            .name
    }

    #[cfg(test)]
    pub(crate) fn state_for_test(&self) -> Arc<Mutex<ExtentVfsState>> {
        Arc::clone(&self.context.state)
    }

    /// Test-only raw file wrapper for driving the C callbacks directly.
    #[cfg(test)]
    pub(crate) fn test_file_wrapper(&self) -> Box<ExtentFileWrapper> {
        Box::new(ExtentFileWrapper {
            base: ffi::sqlite3_file {
                pMethods: &EXTENT_IO_METHODS,
            },
            file_type: Some(ExtentFileType::MainDb),
            context: Some(Arc::clone(&self.context)),
        })
    }
}

impl Drop for RegisteredExtentVfs {
    fn drop(&mut self) {
        if let Some(mut allocation) = self.allocation.take() {
            unsafe {
                ffi::sqlite3_vfs_unregister(&mut allocation.vfs);
            }
            EXTENT_VFS_INSTALLATIONS.fetch_sub(1, Ordering::AcqRel);
            {
                let mut reg = vfs_registry().lock().unwrap();
                // Remove only our own context: a same-name successor registered after a
                // prior drop must never be evicted by the predecessor's teardown.
                let is_own = reg
                    .get(&allocation.name_str)
                    .is_some_and(|entry| Arc::ptr_eq(entry, &self.context));
                if is_own {
                    reg.remove(&allocation.name_str);
                }
            }
            // The sqlite3_vfs allocation is retained for the process lifetime: SQLite
            // gives no synchronization point proving no in-flight callback still holds
            // the pointer. The leak is bounded by install/drop churn and is a few
            // hundred bytes per instance.
            retained_vfs_allocations().lock().unwrap().push(allocation);
        }
    }
}

/// SQLite file wrapper. Extent-backed files never open a parent OS file, so no host
/// filesystem object is created, read, or written for them.
#[repr(C)]
pub(crate) struct ExtentFileWrapper {
    base: ffi::sqlite3_file,
    file_type: Option<ExtentFileType>,
    context: Option<Arc<ExtentVfsContext>>,
}

static EXTENT_IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 3,
    xClose: Some(extent_io_close),
    xRead: Some(extent_io_read),
    xWrite: Some(extent_io_write),
    xTruncate: Some(extent_io_truncate),
    xSync: Some(extent_io_sync),
    xFileSize: Some(extent_io_file_size),
    xLock: Some(extent_io_lock),
    xUnlock: Some(extent_io_unlock),
    xCheckReservedLock: Some(extent_io_check_reserved_lock),
    xFileControl: Some(extent_io_file_control),
    xSectorSize: Some(extent_io_sector_size),
    xDeviceCharacteristics: Some(extent_io_device_characteristics),
    xShmMap: Some(extent_io_shm_map),
    xShmLock: Some(extent_io_shm_lock),
    xShmBarrier: Some(extent_io_shm_barrier),
    xShmUnmap: Some(extent_io_shm_unmap),
    xFetch: Some(extent_io_fetch),
    xUnfetch: Some(extent_io_unfetch),
};

unsafe fn get_vfs_context(vfs: *mut ffi::sqlite3_vfs) -> Option<Arc<ExtentVfsContext>> {
    if vfs.is_null() {
        return None;
    }
    let z_name = unsafe { (*vfs).zName };
    if z_name.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(z_name) }.to_str().ok()?;
    let guard = vfs_registry().lock().ok()?;
    guard.get(name).cloned()
}

unsafe fn file_wrapper<'a>(file: *mut ffi::sqlite3_file) -> Option<&'a mut ExtentFileWrapper> {
    if file.is_null() {
        None
    } else {
        Some(unsafe { &mut *(file.cast::<ExtentFileWrapper>()) })
    }
}

pub const MAX_SIMULTANEOUS_BACKEND_READS: usize = 64;
pub const MAX_SIMULTANEOUS_BACKEND_WRITES: usize = 32;
pub const MAX_PENDING_VFS_REQUESTS: usize = 256;
pub const VFS_IO_TIMEOUT: Duration = Duration::from_secs(30);
pub const VFS_SYNC_TIMEOUT: Duration = Duration::from_secs(120);

static DEDICATED_VFS_BACKEND_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static VFS_READ_SEMAPHORE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
static VFS_WRITE_SEMAPHORE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
static VFS_PENDING_SEMAPHORE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

fn dedicated_backend_runtime() -> &'static tokio::runtime::Runtime {
    DEDICATED_VFS_BACKEND_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("kioku-vfs-backend-lane")
            .enable_all()
            .build()
            .expect("dedicated VFS backend runtime initialization succeeds")
    })
}

fn read_semaphore() -> &'static tokio::sync::Semaphore {
    VFS_READ_SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(MAX_SIMULTANEOUS_BACKEND_READS))
}
fn write_semaphore() -> &'static tokio::sync::Semaphore {
    VFS_WRITE_SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(MAX_SIMULTANEOUS_BACKEND_WRITES))
}
fn pending_semaphore() -> &'static tokio::sync::Semaphore {
    VFS_PENDING_SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(MAX_PENDING_VFS_REQUESTS))
}

/// Drive a bounded future to completion from a synchronous SQLite callback without ever
/// panicking on runtime-flavor mismatches: multi-thread runtimes use `block_in_place`,
/// current-thread runtimes hop to a scoped OS thread, and plain threads block directly.
fn run_bounded_vfs_task<
    F: std::future::Future<Output = Result<R, c_int>> + Send + 'static,
    R: Send + 'static,
>(
    future: F,
) -> Result<R, c_int> {
    let runtime = dedicated_backend_runtime();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| runtime.block_on(future))
        }
        Ok(_) => std::thread::scope(|scope| {
            scope
                .spawn(|| runtime.block_on(future))
                .join()
                .unwrap_or(Err(ffi::SQLITE_IOERR))
        }),
        Err(_) => runtime.block_on(future),
    }
}

fn run_bounded_vfs_read<F: std::future::Future<Output = R> + Send + 'static, R: Send + 'static>(
    future: F,
) -> Result<R, c_int> {
    let pending_sem = pending_semaphore();
    let read_sem = read_semaphore();

    run_bounded_vfs_task(async move {
        let _pending_permit = tokio::time::timeout(VFS_IO_TIMEOUT, pending_sem.acquire())
            .await
            .map_err(|_| ffi::SQLITE_IOERR_READ)?
            .map_err(|_| ffi::SQLITE_IOERR_READ)?;
        let _read_permit = tokio::time::timeout(VFS_IO_TIMEOUT, read_sem.acquire())
            .await
            .map_err(|_| ffi::SQLITE_IOERR_READ)?
            .map_err(|_| ffi::SQLITE_IOERR_READ)?;
        let res = tokio::time::timeout(VFS_IO_TIMEOUT, future)
            .await
            .map_err(|_| ffi::SQLITE_IOERR_READ)?;
        Ok(res)
    })
}

fn run_bounded_vfs_sync<F: std::future::Future<Output = R> + Send + 'static, R: Send + 'static>(
    future: F,
) -> Result<R, c_int> {
    let pending_sem = pending_semaphore();
    let write_sem = write_semaphore();

    run_bounded_vfs_task(async move {
        let _pending_permit = tokio::time::timeout(VFS_SYNC_TIMEOUT, pending_sem.acquire())
            .await
            .map_err(|_| ffi::SQLITE_IOERR_FSYNC)?
            .map_err(|_| ffi::SQLITE_IOERR_FSYNC)?;
        let _write_permit = tokio::time::timeout(VFS_SYNC_TIMEOUT, write_sem.acquire())
            .await
            .map_err(|_| ffi::SQLITE_IOERR_FSYNC)?
            .map_err(|_| ffi::SQLITE_IOERR_FSYNC)?;
        let res = tokio::time::timeout(VFS_SYNC_TIMEOUT, future)
            .await
            .map_err(|_| ffi::SQLITE_IOERR_FSYNC)?;
        Ok(res)
    })
}

unsafe extern "C" fn extent_vfs_open(
    vfs: *mut ffi::sqlite3_vfs,
    _name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if file.is_null() {
            return ffi::SQLITE_CANTOPEN;
        }
        // Fail-closed default: refused opens leave pMethods null so SQLite never
        // invokes xClose on an uninitialized wrapper.
        unsafe {
            (*file).pMethods = ptr::null();
        }
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return ffi::SQLITE_CANTOPEN;
        };

        // Only the single main database is extent-backed. Journals, WAL, temp
        // databases, and every other class fail closed: plaintext never reaches the
        // host filesystem, and hosts cannot inject journal bytes into the tree.
        if (flags & ffi::SQLITE_OPEN_MAIN_DB) == 0 {
            return ffi::SQLITE_CANTOPEN;
        }
        if ctx
            .main_db_handles
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count == 0).then_some(1)
            })
            .is_err()
        {
            return ffi::SQLITE_CANTOPEN;
        }

        ctx.open_handles.fetch_add(1, Ordering::SeqCst);
        let wrapper = file.cast::<ExtentFileWrapper>();
        unsafe {
            ptr::write(
                wrapper,
                ExtentFileWrapper {
                    base: ffi::sqlite3_file {
                        pMethods: ptr::null(),
                    },
                    file_type: Some(ExtentFileType::MainDb),
                    context: Some(Arc::clone(&ctx)),
                },
            );
        }
        if !out_flags.is_null() {
            unsafe {
                *out_flags = flags;
            }
        }
        unsafe {
            (*file).pMethods = &EXTENT_IO_METHODS;
        }
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_ERROR)
}

unsafe extern "C" fn extent_vfs_delete(
    _vfs: *mut ffi::sqlite3_vfs,
    _name: *const c_char,
    _sync_dir: c_int,
) -> c_int {
    // Nothing exists on the host filesystem for this VFS; deletion is a no-op.
    ffi::SQLITE_OK
}

unsafe extern "C" fn extent_vfs_access(
    _vfs: *mut ffi::sqlite3_vfs,
    _name: *const c_char,
    _flags: c_int,
    res_out: *mut c_int,
) -> c_int {
    // No file (in particular: no hot rollback journal) ever exists on the host for
    // this VFS, so SQLite can never be induced to replay host-planted journal bytes.
    let res = catch_unwind(AssertUnwindSafe(|| {
        if res_out.is_null() {
            return ffi::SQLITE_IOERR_ACCESS;
        }
        unsafe {
            *res_out = 0;
        }
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_IOERR_ACCESS)
}

unsafe extern "C" fn extent_vfs_full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    n_out: c_int,
    z_out: *mut c_char,
) -> c_int {
    // Names are opaque labels for this VFS (one instance = one database); the name is
    // returned unchanged, bounded by the output buffer.
    let res = catch_unwind(AssertUnwindSafe(|| {
        if name.is_null() || z_out.is_null() || n_out <= 0 {
            return ffi::SQLITE_CANTOPEN;
        }
        let _ = vfs;
        let name_bytes = unsafe { CStr::from_ptr(name) }.to_bytes_with_nul();
        if name_bytes.len() > n_out as usize {
            return ffi::SQLITE_CANTOPEN;
        }
        unsafe {
            ptr::copy_nonoverlapping(
                name_bytes.as_ptr().cast::<c_char>(),
                z_out,
                name_bytes.len(),
            );
        }
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_ERROR)
}

unsafe extern "C" fn extent_vfs_dl_open(
    vfs: *mut ffi::sqlite3_vfs,
    filename: *const c_char,
) -> *mut c_void {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return ptr::null_mut();
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return ptr::null_mut();
        }
        (unsafe { (*parent).xDlOpen }).map_or(ptr::null_mut(), |f| unsafe { f(parent, filename) })
    }));
    res.unwrap_or(ptr::null_mut())
}

unsafe extern "C" fn extent_vfs_dl_error(
    vfs: *mut ffi::sqlite3_vfs,
    n_byte: c_int,
    z_errmsg: *mut c_char,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return;
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return;
        }
        if let Some(dl_error) = unsafe { (*parent).xDlError } {
            unsafe { dl_error(parent, n_byte, z_errmsg) }
        }
    }));
}

unsafe extern "C" fn extent_vfs_dl_sym(
    vfs: *mut ffi::sqlite3_vfs,
    handle: *mut c_void,
    symbol: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let ctx = (unsafe { get_vfs_context(vfs) })?;
        let parent = ctx.parent;
        if parent.is_null() {
            return None;
        }
        (unsafe { (*parent).xDlSym }).and_then(|f| unsafe { f(parent, handle, symbol) })
    }));
    res.unwrap_or(None)
}

unsafe extern "C" fn extent_vfs_dl_close(vfs: *mut ffi::sqlite3_vfs, handle: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return;
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return;
        }
        if let Some(dl_close) = unsafe { (*parent).xDlClose } {
            unsafe { dl_close(parent, handle) }
        }
    }));
}

unsafe extern "C" fn extent_vfs_randomness(
    vfs: *mut ffi::sqlite3_vfs,
    n_byte: c_int,
    z_out: *mut c_char,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return 0;
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return 0;
        }
        (unsafe { (*parent).xRandomness }).map_or(0, |f| unsafe { f(parent, n_byte, z_out) })
    }));
    res.unwrap_or(0)
}

unsafe extern "C" fn extent_vfs_sleep(vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return 0;
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return 0;
        }
        (unsafe { (*parent).xSleep }).map_or(0, |f| unsafe { f(parent, microseconds) })
    }));
    res.unwrap_or(0)
}

unsafe extern "C" fn extent_vfs_current_time(
    vfs: *mut ffi::sqlite3_vfs,
    time_out: *mut f64,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return ffi::SQLITE_ERROR;
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return ffi::SQLITE_ERROR;
        }
        (unsafe { (*parent).xCurrentTime })
            .map_or(ffi::SQLITE_ERROR, |f| unsafe { f(parent, time_out) })
    }));
    res.unwrap_or(ffi::SQLITE_ERROR)
}

unsafe extern "C" fn extent_vfs_get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    n_byte: c_int,
    z_out: *mut c_char,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return 0;
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return 0;
        }
        (unsafe { (*parent).xGetLastError }).map_or(0, |f| unsafe { f(parent, n_byte, z_out) })
    }));
    res.unwrap_or(0)
}

unsafe extern "C" fn extent_vfs_current_time_int64(
    vfs: *mut ffi::sqlite3_vfs,
    time_out: *mut ffi::sqlite3_int64,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return ffi::SQLITE_ERROR;
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return ffi::SQLITE_ERROR;
        }
        (unsafe { (*parent).xCurrentTimeInt64 })
            .map_or(ffi::SQLITE_ERROR, |f| unsafe { f(parent, time_out) })
    }));
    res.unwrap_or(ffi::SQLITE_ERROR)
}

unsafe extern "C" fn extent_vfs_set_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    call: ffi::sqlite3_syscall_ptr,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return ffi::SQLITE_ERROR;
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return ffi::SQLITE_ERROR;
        }
        (unsafe { (*parent).xSetSystemCall })
            .map_or(ffi::SQLITE_ERROR, |f| unsafe { f(parent, name, call) })
    }));
    res.unwrap_or(ffi::SQLITE_ERROR)
}

unsafe extern "C" fn extent_vfs_get_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> ffi::sqlite3_syscall_ptr {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let ctx = (unsafe { get_vfs_context(vfs) })?;
        let parent = ctx.parent;
        if parent.is_null() {
            return None;
        }
        (unsafe { (*parent).xGetSystemCall }).and_then(|f| unsafe { f(parent, name) })
    }));
    res.unwrap_or(None)
}

unsafe extern "C" fn extent_vfs_next_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> *const c_char {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(ctx) = (unsafe { get_vfs_context(vfs) }) else {
            return ptr::null();
        };
        let parent = ctx.parent;
        if parent.is_null() {
            return ptr::null();
        }
        (unsafe { (*parent).xNextSystemCall }).map_or(ptr::null(), |f| unsafe { f(parent, name) })
    }));
    res.unwrap_or(ptr::null())
}

unsafe extern "C" fn extent_io_close(file: *mut ffi::sqlite3_file) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(w) = (unsafe { file_wrapper(file) }) else {
            return ffi::SQLITE_OK;
        };
        let file_type = w.file_type;
        if let Some(ctx) = w.context.take() {
            // Dirty (unsynced) pages are discarded and zeroized at close: they are not
            // durable, and SQLite's own rollback semantics already treat them as lost.
            if let Some(file_type) = file_type {
                if let Ok(mut state) = ctx.state.lock() {
                    state.cache.discard_dirty_pages_for_file(file_type);
                    state.main_dirty_modified = false;
                    state.main_db_size = state
                        .main_root
                        .as_ref()
                        .map(|r| r.logical_file_length())
                        .unwrap_or(0);
                }
                if file_type == ExtentFileType::MainDb {
                    ctx.main_db_handles.fetch_sub(1, Ordering::AcqRel);
                }
            }
            ctx.open_handles.fetch_sub(1, Ordering::SeqCst);
        }
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_ERROR)
}

unsafe extern "C" fn extent_io_read(
    file: *mut ffi::sqlite3_file,
    buf: *mut c_void,
    amt: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if buf.is_null() || amt < 0 || offset < 0 {
            return ffi::SQLITE_IOERR_READ;
        }
        if amt == 0 {
            return ffi::SQLITE_OK;
        }
        let Some(w) = (unsafe { file_wrapper(file) }) else {
            return ffi::SQLITE_IOERR_READ;
        };
        let Some(ref ctx) = w.context else {
            return ffi::SQLITE_IOERR_READ;
        };
        let Some(file_type) = w.file_type else {
            return ffi::SQLITE_IOERR_READ;
        };

        let state_arc = &ctx.state;
        let out_slice = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), amt as usize) };

        let read_offset = offset as u64;
        let read_len = amt as usize;

        let (file_len, root_opt, backend, cipher) = {
            let state = state_arc.lock().unwrap();
            (
                state.main_db_size,
                state.main_root.clone(),
                Arc::clone(&state.backend),
                Arc::clone(&state.cipher),
            )
        };

        if read_offset >= file_len {
            out_slice.fill(0);
            return ffi::SQLITE_IOERR_SHORT_READ;
        }

        let actual_read_len = read_len.min((file_len - read_offset) as usize);
        let mut bytes_read = 0;

        let root_len = root_opt
            .as_ref()
            .map(|r| r.logical_file_length())
            .unwrap_or(0);
        let start_page = read_offset / (SQLITE_PAGE_SIZE as u64);
        let end_offset = read_offset + (actual_read_len as u64);
        let end_page = end_offset.div_ceil(SQLITE_PAGE_SIZE as u64);

        for page_no64 in start_page..end_page {
            let Ok(page_no) = u32::try_from(page_no64) else {
                return ffi::SQLITE_IOERR_READ;
            };
            let page_start_byte = page_no64 * (SQLITE_PAGE_SIZE as u64);
            let slice_start = if page_start_byte < read_offset {
                (read_offset - page_start_byte) as usize
            } else {
                0
            };
            let slice_end = if page_start_byte + (SQLITE_PAGE_SIZE as u64) > end_offset {
                (end_offset - page_start_byte) as usize
            } else {
                SQLITE_PAGE_SIZE as usize
            };
            let copy_len = slice_end - slice_start;

            let mut page_data = Zeroizing::new([0u8; SQLITE_PAGE_SIZE as usize]);
            let hit = {
                let mut state = state_arc.lock().unwrap();
                if let Some(cached) = state.cache.get(file_type, page_no) {
                    page_data.copy_from_slice(cached);
                    true
                } else {
                    false
                }
            };

            if !hit {
                // Bytes inside the root's authenticated length reconstruct through the
                // Merkle tree; bytes beyond it (an unsynced extension) are zeros by the
                // sparse-file semantics the logical length commits to.
                if page_start_byte < root_len {
                    let Some(ref root) = root_opt else {
                        return ffi::SQLITE_IOERR_READ;
                    };
                    let covered =
                        ((root_len - page_start_byte) as usize).min(SQLITE_PAGE_SIZE as usize);
                    let b_clone = Arc::clone(&backend);
                    let c_clone = Arc::clone(&cipher);
                    let root_clone = root.clone();

                    let reconstruct_res = run_bounded_vfs_read(async move {
                        let mut buf = Zeroizing::new([0u8; SQLITE_PAGE_SIZE as usize]);
                        reconstruct_extent_range(
                            b_clone.as_ref(),
                            c_clone.as_ref(),
                            &root_clone,
                            page_start_byte,
                            &mut buf[..covered],
                        )
                        .await
                        .map(|_| buf)
                    });

                    match reconstruct_res {
                        Ok(Ok(buf)) => page_data.copy_from_slice(&buf[..]),
                        _ => return ffi::SQLITE_IOERR_READ,
                    }
                }

                let mut state = state_arc.lock().unwrap();
                let _ = state.cache.put(file_type, page_no, &page_data[..], false);
            }

            out_slice[bytes_read..bytes_read + copy_len]
                .copy_from_slice(&page_data[slice_start..slice_end]);
            bytes_read += copy_len;
        }

        if bytes_read < read_len {
            out_slice[bytes_read..].fill(0);
            ffi::SQLITE_IOERR_SHORT_READ
        } else {
            ffi::SQLITE_OK
        }
    }));
    res.unwrap_or(ffi::SQLITE_IOERR_READ)
}

struct PlannedWritePage {
    page_no: u32,
    prior: Option<(Zeroizing<[u8; SQLITE_PAGE_SIZE as usize]>, bool)>,
    merged: Zeroizing<[u8; SQLITE_PAGE_SIZE as usize]>,
}

unsafe extern "C" fn extent_io_write(
    file: *mut ffi::sqlite3_file,
    buf: *const c_void,
    amt: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if buf.is_null() || amt < 0 || offset < 0 {
            return ffi::SQLITE_IOERR_WRITE;
        }
        if amt == 0 {
            return ffi::SQLITE_OK;
        }
        let Some(w) = (unsafe { file_wrapper(file) }) else {
            return ffi::SQLITE_IOERR_WRITE;
        };
        let Some(ref ctx) = w.context else {
            return ffi::SQLITE_IOERR_WRITE;
        };
        let Some(file_type) = w.file_type else {
            return ffi::SQLITE_IOERR_WRITE;
        };

        let in_slice = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), amt as usize) };
        let write_offset = offset as u64;
        let write_len = amt as usize;
        let Some(end_offset) = write_offset.checked_add(write_len as u64) else {
            return ffi::SQLITE_IOERR_WRITE;
        };
        // The 32-GiB format bound also proves every page number fits in u32.
        if end_offset > MAX_DATABASE_BYTES {
            return ffi::SQLITE_FULL;
        }

        let start_page = write_offset / (SQLITE_PAGE_SIZE as u64);
        let end_page = end_offset.div_ceil(SQLITE_PAGE_SIZE as u64);

        let state_arc = &ctx.state;
        let (root_opt, backend, cipher) = {
            let state = state_arc.lock().unwrap();
            (
                state.main_root.clone(),
                Arc::clone(&state.backend),
                Arc::clone(&state.cipher),
            )
        };
        let root_len = root_opt
            .as_ref()
            .map(|r| r.logical_file_length())
            .unwrap_or(0);

        // Phase 1: plan every page (read-modify without mutating the cache), so a
        // failure can never leave a torn multi-page write behind.
        let mut planned: Vec<PlannedWritePage> =
            Vec::with_capacity((end_page - start_page) as usize);
        let mut bytes_consumed = 0usize;
        for page_no64 in start_page..end_page {
            let Ok(page_no) = u32::try_from(page_no64) else {
                return ffi::SQLITE_IOERR_WRITE;
            };
            let page_start_byte = page_no64 * (SQLITE_PAGE_SIZE as u64);
            let slice_start = if page_start_byte < write_offset {
                (write_offset - page_start_byte) as usize
            } else {
                0
            };
            let slice_end = if page_start_byte + (SQLITE_PAGE_SIZE as u64) > end_offset {
                (end_offset - page_start_byte) as usize
            } else {
                SQLITE_PAGE_SIZE as usize
            };
            let copy_len = slice_end - slice_start;

            let prior = {
                let state = state_arc.lock().unwrap();
                state
                    .cache
                    .get_entry_copy(file_type, page_no)
                    .map(|(bytes, dirty)| (Zeroizing::new(bytes), dirty))
            };

            let mut merged = Zeroizing::new([0u8; SQLITE_PAGE_SIZE as usize]);
            if let Some((ref prior_bytes, _)) = prior {
                merged.copy_from_slice(&prior_bytes[..]);
            } else if copy_len < (SQLITE_PAGE_SIZE as usize) && page_start_byte < root_len {
                let covered =
                    ((root_len - page_start_byte) as usize).min(SQLITE_PAGE_SIZE as usize);
                let Some(ref root) = root_opt else {
                    return ffi::SQLITE_IOERR_WRITE;
                };
                let b_clone = Arc::clone(&backend);
                let c_clone = Arc::clone(&cipher);
                let root_clone = root.clone();
                let reconstruct_res = run_bounded_vfs_read(async move {
                    let mut buf = Zeroizing::new([0u8; SQLITE_PAGE_SIZE as usize]);
                    reconstruct_extent_range(
                        b_clone.as_ref(),
                        c_clone.as_ref(),
                        &root_clone,
                        page_start_byte,
                        &mut buf[..covered],
                    )
                    .await
                    .map(|_| buf)
                });
                match reconstruct_res {
                    Ok(Ok(buf)) => merged.copy_from_slice(&buf[..]),
                    _ => return ffi::SQLITE_IOERR_WRITE,
                }
            }

            merged[slice_start..slice_end]
                .copy_from_slice(&in_slice[bytes_consumed..bytes_consumed + copy_len]);
            bytes_consumed += copy_len;
            planned.push(PlannedWritePage {
                page_no,
                prior,
                merged,
            });
        }

        // Phase 2: apply under one lock; roll back applied pages on admission failure.
        let mut state = state_arc.lock().unwrap();
        let mut applied: Vec<usize> = Vec::with_capacity(planned.len());
        for (idx, plan) in planned.iter().enumerate() {
            match state
                .cache
                .put(file_type, plan.page_no, &plan.merged[..], true)
            {
                Ok(()) => applied.push(idx),
                Err(_) => {
                    for &applied_idx in applied.iter().rev() {
                        let plan = &planned[applied_idx];
                        match &plan.prior {
                            Some((bytes, was_dirty)) => {
                                let _ = state.cache.put(
                                    file_type,
                                    plan.page_no,
                                    &bytes[..],
                                    *was_dirty,
                                );
                            }
                            None => {
                                state.cache.remove_page(file_type, plan.page_no);
                            }
                        }
                    }
                    return ffi::SQLITE_FULL;
                }
            }
        }

        if end_offset > state.main_db_size {
            state.main_db_size = end_offset;
        }
        state.main_dirty_modified = true;
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_IOERR_WRITE)
}

unsafe extern "C" fn extent_io_truncate(
    file: *mut ffi::sqlite3_file,
    size: ffi::sqlite3_int64,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if size < 0 {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        let Some(w) = (unsafe { file_wrapper(file) }) else {
            return ffi::SQLITE_IOERR_TRUNCATE;
        };
        let Some(ref ctx) = w.context else {
            return ffi::SQLITE_IOERR_TRUNCATE;
        };
        let Some(file_type) = w.file_type else {
            return ffi::SQLITE_IOERR_TRUNCATE;
        };

        let new_size = size as u64;
        if new_size > MAX_DATABASE_BYTES {
            return ffi::SQLITE_FULL;
        }
        let mut state = ctx.state.lock().unwrap();
        state.cache.purge_pages_after(file_type, new_size);
        state.main_db_size = new_size;
        state.main_dirty_modified = true;
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_IOERR_TRUNCATE)
}

/// Streams the shadow database's current logical content: cached pages overlay the
/// authenticated base reconstruction from the previous settled root.
struct CacheExtentSource {
    file_type: ExtentFileType,
    state: Arc<Mutex<ExtentVfsState>>,
    backend: Arc<dyn ImmutableObjectBackend>,
    cipher: Arc<dyn ExtentCipher>,
    base_root: Option<ShadowExtentRootCandidate>,
    file_len: u64,
    current_extent: u64,
    total_extents: u64,
}

impl CacheExtentSource {
    fn new(
        file_type: ExtentFileType,
        state: Arc<Mutex<ExtentVfsState>>,
        backend: Arc<dyn ImmutableObjectBackend>,
        cipher: Arc<dyn ExtentCipher>,
        base_root: Option<ShadowExtentRootCandidate>,
        file_len: u64,
    ) -> Self {
        let total_extents = if file_len == 0 {
            0
        } else {
            file_len.div_ceil(EXTENT_BYTES as u64)
        };
        Self {
            file_type,
            state,
            backend,
            cipher,
            base_root,
            file_len,
            current_extent: 0,
            total_extents,
        }
    }
}

#[async_trait::async_trait]
impl ExtentSource for CacheExtentSource {
    fn logical_file_length(&self) -> ExtentResult<u64> {
        Ok(self.file_len)
    }

    async fn next_extent(&mut self, destination: &mut [u8]) -> ExtentResult<Option<SourceExtent>> {
        if self.current_extent >= self.total_extents {
            return Ok(None);
        }

        let extent_no = self.current_extent;
        self.current_extent += 1;

        let extent_start_byte = extent_no * (EXTENT_BYTES as u64);
        let extent_end_byte = (extent_start_byte + (EXTENT_BYTES as u64)).min(self.file_len);
        let logical_byte_len = (extent_end_byte - extent_start_byte) as u32;

        destination[..logical_byte_len as usize].fill(0);

        if let Some(ref root) = self.base_root {
            let base_file_len = root.logical_file_length();
            if extent_start_byte < base_file_len {
                let base_len =
                    (base_file_len - extent_start_byte).min(logical_byte_len as u64) as usize;
                let mut base_buf = Zeroizing::new(vec![0u8; base_len]);
                reconstruct_extent_range(
                    self.backend.as_ref(),
                    self.cipher.as_ref(),
                    root,
                    extent_start_byte,
                    &mut base_buf,
                )
                .await?;
                destination[..base_len].copy_from_slice(&base_buf);
            }
        }

        let num_pages_in_extent = (logical_byte_len as usize).div_ceil(SQLITE_PAGE_SIZE as usize);
        let start_page = (extent_start_byte / (SQLITE_PAGE_SIZE as u64)) as u32;

        for p_idx in 0..num_pages_in_extent {
            let page_no = start_page + (p_idx as u32);
            let mut page_buf = Zeroizing::new([0u8; SQLITE_PAGE_SIZE as usize]);
            let hit = {
                let mut state = self.state.lock().map_err(|_| ExtentTreeError::Source)?;
                if let Some(cached) = state.cache.get(self.file_type, page_no) {
                    page_buf.copy_from_slice(cached);
                    true
                } else {
                    false
                }
            };
            if hit {
                let dest_offset = p_idx * (SQLITE_PAGE_SIZE as usize);
                let copy_len =
                    (SQLITE_PAGE_SIZE as usize).min(logical_byte_len as usize - dest_offset);
                destination[dest_offset..dest_offset + copy_len]
                    .copy_from_slice(&page_buf[..copy_len]);
            }
        }

        Ok(Some(SourceExtent {
            extent_no,
            logical_byte_len,
        }))
    }
}

unsafe extern "C" fn extent_io_sync(file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let Some(w) = (unsafe { file_wrapper(file) }) else {
            return ffi::SQLITE_IOERR_FSYNC;
        };
        let Some(ref ctx) = w.context else {
            return ffi::SQLITE_IOERR_FSYNC;
        };
        let Some(file_type) = w.file_type else {
            return ffi::SQLITE_IOERR_FSYNC;
        };

        let state_arc = &ctx.state;
        let (dirty_masks, dirty_modified, file_len, base_root, backend, cipher, ledger) = {
            let state = state_arc.lock().unwrap();
            (
                state.cache.dirty_page_masks(file_type),
                state.main_dirty_modified,
                state.main_db_size,
                state.main_root.clone(),
                Arc::clone(&state.backend),
                Arc::clone(&state.cipher),
                Arc::clone(&state.ledger),
            )
        };

        if dirty_masks.is_empty() && !dirty_modified {
            return ffi::SQLITE_OK;
        }
        // The empty-tree wire variant deliberately does not exist (see
        // archive_v3_extent.rs), so a zero-length file cannot be settled durably.
        if file_len == 0 || file_len > MAX_SHADOW_COMMIT_BYTES {
            return ffi::SQLITE_IOERR_FSYNC;
        }

        let archive_id = cipher.archive_id();
        let key_epoch = cipher.key_epoch();
        let database_epoch = {
            let state = state_arc.lock().unwrap();
            state.database_epoch
        };

        let mut op_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut op_id);
        let mut coordinator = ExtentCommitCoordinator::new(
            archive_id,
            database_epoch,
            key_epoch,
            op_id,
            Arc::clone(&ledger),
        );

        // Heal a stale active attempt (a prior in-process sync whose abort also failed)
        // durably first. Mid-session healing only ABORTS — it never adopts a candidate
        // root, because a live pager sits above this VFS and adoption here could
        // durably capture a mix of transaction states. This sync intentionally fails
        // after healing so SQLite observes one clean failure boundary against the
        // unchanged settled root; the next sync starts from a released slot.
        match ledger.get_active_attempt(archive_id, database_epoch, file_type) {
            Ok(None) => {}
            Ok(Some(_)) => {
                let mut state = state_arc.lock().unwrap();
                let _ = coordinator.heal_interrupted_attempt(file_type, &mut state.cache);
                state.main_db_size = state
                    .main_root
                    .as_ref()
                    .map(|r| r.logical_file_length())
                    .unwrap_or(0);
                state.main_dirty_modified = false;
                return ffi::SQLITE_IOERR_FSYNC;
            }
            Err(_) => return ffi::SQLITE_IOERR_FSYNC,
        }

        let dirty_extents: Vec<u32> = dirty_masks.iter().map(|(ext, _)| *ext).collect();
        let begin_res = coordinator.begin_attempt(
            file_type,
            base_root.as_ref(),
            0,
            0,
            file_len,
            0,
            dirty_extents,
        );
        let attempt_id = match begin_res {
            Ok(id) => id,
            Err(_) => return ffi::SQLITE_IOERR_FSYNC,
        };

        let staging = DurableExtentStaging::new(Arc::clone(&ledger), attempt_id);
        let mut source = CacheExtentSource::new(
            file_type,
            Arc::clone(state_arc),
            Arc::clone(&backend),
            Arc::clone(&cipher),
            base_root.clone(),
            file_len,
        );

        let upload_res = run_bounded_vfs_sync({
            let backend = Arc::clone(&backend);
            let cipher = Arc::clone(&cipher);
            async move {
                upload_extent_tree(
                    backend.as_ref(),
                    &cipher,
                    archive_id,
                    database_epoch,
                    &mut source,
                    staging,
                )
                .await
            }
        });

        let commit_res: Result<ShadowExtentRootCandidate, ()> = (|| {
            let uploaded_tree = match upload_res {
                Ok(Ok(tree)) => tree,
                _ => return Err(()),
            };
            coordinator.mark_objects_staged().map_err(|_| ())?;
            let candidate_root = ShadowExtentRootCandidate::from_uploaded_tree(
                archive_id,
                database_epoch,
                key_epoch,
                &uploaded_tree,
            );
            coordinator
                .mark_candidate_ready(&candidate_root)
                .map_err(|_| ())?;
            coordinator.mark_shadow_settled().map_err(|_| ())?;
            Ok(candidate_root)
        })();

        match commit_res {
            Ok(candidate_root) => {
                // Adopt the settled candidate and clean exactly the snapshot's bits so
                // writes that landed after the snapshot stay dirty.
                let mut state_guard = state_arc.lock().unwrap();
                for (ext_no, mask_words) in &dirty_masks {
                    state_guard
                        .cache
                        .mark_pages_clean(file_type, *ext_no, *mask_words);
                }
                state_guard.main_root = Some(candidate_root);
                state_guard.main_dirty_modified =
                    !state_guard.cache.dirty_extents(file_type).is_empty();
                ffi::SQLITE_OK
            }
            Err(()) => {
                // Terminalize the attempt durably (best effort), then discard this
                // file's dirty state and revert to the last settled root, mirroring
                // power-loss semantics for the unsynced transaction.
                let _ = coordinator.abort_pre_witness();
                let mut state_guard = state_arc.lock().unwrap();
                state_guard.cache.discard_dirty_pages_for_file(file_type);
                state_guard.main_db_size = state_guard
                    .main_root
                    .as_ref()
                    .map(|r| r.logical_file_length())
                    .unwrap_or(0);
                state_guard.main_dirty_modified = false;
                ffi::SQLITE_IOERR_FSYNC
            }
        }
    }));
    res.unwrap_or(ffi::SQLITE_IOERR_FSYNC)
}

unsafe extern "C" fn extent_io_file_size(
    file: *mut ffi::sqlite3_file,
    size: *mut ffi::sqlite3_int64,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if size.is_null() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        let Some(w) = (unsafe { file_wrapper(file) }) else {
            return ffi::SQLITE_IOERR_FSTAT;
        };
        let Some(ref ctx) = w.context else {
            return ffi::SQLITE_IOERR_FSTAT;
        };
        if w.file_type.is_none() {
            return ffi::SQLITE_IOERR_FSTAT;
        }

        let state = ctx.state.lock().unwrap();
        let len = state.main_db_size;
        unsafe {
            *size = len as ffi::sqlite3_int64;
        }
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_IOERR_FSTAT)
}

// One extent VFS instance serves exactly one main-database handle, so SQLite's
// advisory file locks are trivially satisfiable in-process.
unsafe extern "C" fn extent_io_lock(_file: *mut ffi::sqlite3_file, _lock: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn extent_io_unlock(_file: *mut ffi::sqlite3_file, _lock: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn extent_io_check_reserved_lock(
    _file: *mut ffi::sqlite3_file,
    res_out: *mut c_int,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if res_out.is_null() {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        unsafe {
            *res_out = 0;
        }
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_IOERR_CHECKRESERVEDLOCK)
}

unsafe extern "C" fn extent_io_file_control(
    _file: *mut ffi::sqlite3_file,
    _op: c_int,
    _p_arg: *mut c_void,
) -> c_int {
    ffi::SQLITE_NOTFOUND
}

unsafe extern "C" fn extent_io_sector_size(_file: *mut ffi::sqlite3_file) -> c_int {
    SQLITE_PAGE_SIZE as c_int
}

unsafe extern "C" fn extent_io_device_characteristics(_file: *mut ffi::sqlite3_file) -> c_int {
    // Advertise no special capabilities: the extent layer provides none of the atomic
    // or ordering guarantees that would let SQLite skip journal steps.
    0
}

// WAL journal mode is refused at xOpen; the shared-memory surface fails closed.
unsafe extern "C" fn extent_io_shm_map(
    _file: *mut ffi::sqlite3_file,
    _region: c_int,
    _sz_region: c_int,
    _is_write: c_int,
    pp: *mut *mut c_void,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if !pp.is_null() {
            unsafe {
                *pp = ptr::null_mut();
            }
        }
        ffi::SQLITE_IOERR
    }));
    res.unwrap_or(ffi::SQLITE_ERROR)
}

unsafe extern "C" fn extent_io_shm_lock(
    _file: *mut ffi::sqlite3_file,
    _offset: c_int,
    _n: c_int,
    _flags: c_int,
) -> c_int {
    ffi::SQLITE_IOERR
}

unsafe extern "C" fn extent_io_shm_barrier(_file: *mut ffi::sqlite3_file) {}

unsafe extern "C" fn extent_io_shm_unmap(
    _file: *mut ffi::sqlite3_file,
    _delete_flag: c_int,
) -> c_int {
    ffi::SQLITE_OK
}

// Memory-mapped access is unavailable: pages exist only as authenticated
// reconstructions, never as host-file bytes. Returning a null mapping makes SQLite
// fall back to xRead.
unsafe extern "C" fn extent_io_fetch(
    _file: *mut ffi::sqlite3_file,
    _offset: ffi::sqlite3_int64,
    _amt: c_int,
    pp: *mut *mut c_void,
) -> c_int {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if !pp.is_null() {
            unsafe {
                *pp = ptr::null_mut();
            }
        }
        ffi::SQLITE_OK
    }));
    res.unwrap_or(ffi::SQLITE_ERROR)
}

unsafe extern "C" fn extent_io_unfetch(
    _file: *mut ffi::sqlite3_file,
    _offset: ffi::sqlite3_int64,
    _p: *mut c_void,
) -> c_int {
    ffi::SQLITE_OK
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::archive_v3::{ArchiveId, DatabaseEpoch, InMemoryImmutableBackend, KeyEpoch};
    use crate::archive_v3::{
        ArchivePrefix, CiphertextEnvelope, CreateIfAbsent, EnumerationCursor, EnumerationLimit,
        EnumerationPage, ObjectKey, Result as ArchiveResult,
    };
    use crate::archive_v3_extent::tests::TestCipher;
    use crate::archive_v3_extent_commit::SqliteExtentAttemptLedger;
    use rusqlite::{Connection, OpenFlags};
    use std::sync::atomic::AtomicBool;

    fn uuid_string() -> String {
        use rand::{rngs::OsRng, RngCore};
        let mut rand_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut rand_bytes);
        let mut s = String::with_capacity(16);
        for b in rand_bytes {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    fn make_test_ledger() -> Arc<dyn ExtentAttemptLedger> {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap())
    }

    fn make_file_ledger(path: &std::path::Path) -> Arc<dyn ExtentAttemptLedger> {
        let conn = Arc::new(Mutex::new(Connection::open(path).unwrap()));
        Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap())
    }

    struct TestEnv {
        _tmp: tempfile::TempDir,
        db_path: std::path::PathBuf,
        vfs_name: String,
        backend: Arc<InMemoryImmutableBackend>,
        cipher: Arc<TestCipher>,
        database_epoch: DatabaseEpoch,
        ledger_path: std::path::PathBuf,
    }

    fn make_env() -> TestEnv {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join(format!("extent-{}.db", uuid_string()));
        let ledger_path = tmp.path().join(format!("ledger-{}.db", uuid_string()));
        let archive_id = ArchiveId::random();
        let key_epoch = KeyEpoch::random();
        TestEnv {
            db_path,
            ledger_path,
            _tmp: tmp,
            vfs_name: format!("extent-vfs-{}", uuid_string()),
            backend: Arc::new(InMemoryImmutableBackend::default()),
            cipher: Arc::new(TestCipher::new(archive_id, key_epoch)),
            database_epoch: DatabaseEpoch::random(),
        }
    }

    fn install_env(env: &TestEnv, ledger: Arc<dyn ExtentAttemptLedger>) -> RegisteredExtentVfs {
        RegisteredExtentVfs::install(
            &env.vfs_name,
            Arc::clone(&env.backend) as Arc<dyn ImmutableObjectBackend>,
            Arc::clone(&env.cipher) as Arc<dyn ExtentCipher>,
            env.database_epoch,
            ledger,
            None,
        )
        .unwrap()
    }

    fn open_conn(env: &TestEnv) -> Connection {
        let conn = Connection::open_with_flags_and_vfs(
            &env.db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            env.vfs_name.as_str(),
        )
        .unwrap();
        conn.execute_batch("PRAGMA journal_mode=MEMORY; PRAGMA temp_store=MEMORY;")
            .unwrap();
        conn
    }

    /// Backend wrapper whose creates can be toggled to fail, for driving the real
    /// xSync failure path end to end.
    struct FailingBackend {
        inner: InMemoryImmutableBackend,
        fail_creates: AtomicBool,
    }

    #[async_trait::async_trait]
    impl ImmutableObjectBackend for FailingBackend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: CiphertextEnvelope,
        ) -> ArchiveResult<CreateIfAbsent> {
            if self.fail_creates.load(Ordering::SeqCst) {
                return Err(crate::archive_v3::ArchiveV3Error::Unavailable);
            }
            self.inner.create_if_absent(key, value).await
        }
        async fn get(&self, key: &ObjectKey) -> ArchiveResult<Option<CiphertextEnvelope>> {
            self.inner.get(key).await
        }
        async fn enumerate(
            &self,
            prefix: &ArchivePrefix,
            cursor: Option<&EnumerationCursor>,
            limit: EnumerationLimit,
        ) -> ArchiveResult<EnumerationPage> {
            self.inner.enumerate(prefix, cursor, limit).await
        }
        async fn delete_exact(&self, key: &ObjectKey) -> ArchiveResult<bool> {
            self.inner.delete_exact(key).await
        }
    }

    #[test]
    fn test_extent_vfs_registration_open_and_single_main_handle() {
        let env = make_env();
        let vfs = install_env(&env, make_test_ledger());
        assert_eq!(
            vfs.name().to_str().unwrap(),
            env.vfs_name.as_str(),
            "registered VFS keeps its name"
        );
        let conn = open_conn(&env);
        conn.execute_batch("CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT);")
            .unwrap();

        // A second simultaneous MAIN_DB open through the same instance is refused,
        // so ATTACH can never alias the single logical database.
        let second = Connection::open_with_flags_and_vfs(
            &env.db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            env.vfs_name.as_str(),
        );
        assert!(second.is_err(), "second MAIN_DB handle must be refused");

        drop(conn);
        // After close, one handle may open again.
        let reopened = Connection::open_with_flags_and_vfs(
            &env.db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            env.vfs_name.as_str(),
        );
        assert!(reopened.is_ok(), "handle slot must be released at close");
    }

    #[test]
    fn test_extent_vfs_duplicate_name_rejection() {
        let env = make_env();
        let _vfs = install_env(&env, make_test_ledger());
        let dup = RegisteredExtentVfs::install(
            &env.vfs_name,
            Arc::clone(&env.backend) as Arc<dyn ImmutableObjectBackend>,
            Arc::clone(&env.cipher) as Arc<dyn ExtentCipher>,
            env.database_epoch,
            make_test_ledger(),
            None,
        );
        assert!(matches!(dup, Err(ExtentVfsError::AlreadyRegistered)));
    }

    #[test]
    fn test_default_rollback_journal_is_refused_without_memory_journal() {
        let env = make_env();
        let _vfs = install_env(&env, make_test_ledger());
        let conn = Connection::open_with_flags_and_vfs(
            &env.db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            env.vfs_name.as_str(),
        )
        .unwrap();
        // No journal_mode=MEMORY: the first write transaction needs a rollback
        // journal, whose xOpen this VFS refuses. The write must fail rather than
        // ever writing plaintext to the host filesystem.
        let res = conn.execute_batch("CREATE TABLE t (k INTEGER PRIMARY KEY);");
        assert!(res.is_err(), "journal-backed write must fail closed");
        // And nothing may exist on the host filesystem.
        assert!(
            !env.db_path.exists(),
            "no host database file may be created"
        );
        let journal = env.db_path.with_extension("db-journal");
        assert!(!journal.exists(), "no host journal file may be created");
    }

    #[test]
    fn test_wal_journal_mode_is_refused() {
        let env = make_env();
        let _vfs = install_env(&env, make_test_ledger());
        let conn = open_conn(&env);
        // SQLite accepts the pragma lazily; the -wal file is opened at the first
        // write transaction, and this VFS refuses that open. The write must fail and
        // nothing may appear on the host filesystem.
        let _ = conn.query_row("PRAGMA journal_mode=WAL;", [], |r| r.get::<_, String>(0));
        let res = conn.execute_batch("CREATE TABLE t (k INTEGER PRIMARY KEY);");
        assert!(res.is_err(), "WAL-journaled writes must fail closed");
        assert!(!env.db_path.with_extension("db-wal").exists());
        assert!(!env.db_path.with_extension("db-shm").exists());
    }

    #[test]
    fn test_extent_vfs_full_crud_and_persistence_across_reinstall() {
        let env = make_env();
        let ledger = make_file_ledger(&env.ledger_path);
        {
            let _vfs = install_env(&env, Arc::clone(&ledger));
            let conn = open_conn(&env);
            conn.execute_batch(
                "CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO t (k, v) VALUES (1, 'Alice'), (2, 'Bob');
                 UPDATE t SET v = 'Carol' WHERE k = 2;
                 DELETE FROM t WHERE k = 1;",
            )
            .unwrap();
            let v: String = conn
                .query_row("SELECT v FROM t WHERE k = 2;", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, "Carol");
            drop(conn);
        }
        // Reinstall from the durable ledger alone: install-time reconciliation must
        // adopt the latest ShadowSettled candidate root from the attempt ledger.
        {
            let _vfs = install_env(&env, Arc::clone(&ledger));
            let conn = open_conn(&env);
            let v: String = conn
                .query_row("SELECT v FROM t WHERE k = 2;", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, "Carol");
            let count: i64 = conn
                .query_row("SELECT count(*) FROM t;", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 1);
        }
        // The SQLite content never touched the host filesystem.
        assert!(!env.db_path.exists());
    }

    #[test]
    fn test_extent_vfs_multi_extent_content_round_trip() {
        let env = make_env();
        let _vfs = install_env(&env, make_test_ledger());
        let conn = open_conn(&env);
        conn.execute_batch("CREATE TABLE blobs (k INTEGER PRIMARY KEY, v BLOB);")
            .unwrap();
        // Push the database beyond one 1 MiB extent to exercise multi-extent commits.
        let big = vec![0xA5u8; 300 * 1024];
        for k in 0..6 {
            conn.execute(
                "INSERT INTO blobs (k, v) VALUES (?, ?);",
                rusqlite::params![k, big],
            )
            .unwrap();
        }
        let n: i64 = conn
            .query_row("SELECT count(*) FROM blobs;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 6);
        let got: Vec<u8> = conn
            .query_row("SELECT v FROM blobs WHERE k = 3;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(got, big);
        let integrity: String = conn
            .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }

    #[test]
    fn test_sync_failure_discards_dirty_pages_reverts_root_and_recovers() {
        let env = make_env();
        let failing = Arc::new(FailingBackend {
            inner: InMemoryImmutableBackend::default(),
            fail_creates: AtomicBool::new(false),
        });
        let vfs = RegisteredExtentVfs::install(
            &env.vfs_name,
            Arc::clone(&failing) as Arc<dyn ImmutableObjectBackend>,
            Arc::clone(&env.cipher) as Arc<dyn ExtentCipher>,
            env.database_epoch,
            make_test_ledger(),
            None,
        )
        .unwrap();
        let conn = open_conn(&env);
        conn.execute_batch("CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT);")
            .unwrap();
        conn.execute("INSERT INTO t (k, v) VALUES (1, 'keep');", [])
            .unwrap();

        let root_before = {
            let state = vfs.state_for_test();
            let guard = state.lock().unwrap();
            guard.main_root().cloned()
        };
        assert!(root_before.is_some(), "first commit settles a root");

        // Fail the backend: the next commit's xSync must fail, discard dirty pages,
        // and leave the previous settled root authoritative for shadow reads.
        failing.fail_creates.store(true, Ordering::SeqCst);
        let res = conn.execute("INSERT INTO t (k, v) VALUES (2, 'lost');", []);
        assert!(res.is_err(), "commit against failing backend must fail");

        {
            let state = vfs.state_for_test();
            let guard = state.lock().unwrap();
            assert_eq!(
                guard.main_root().map(|r| r.root().clone()),
                root_before.as_ref().map(|r| r.root().clone()),
                "failed sync must not advance the settled root"
            );
        }

        // Recovery: the backend heals; the same connection can commit again. The
        // failed sync left a durably aborted attempt, never a wedged active slot.
        failing.fail_creates.store(false, Ordering::SeqCst);
        conn.execute("INSERT INTO t (k, v) VALUES (3, 'after');", [])
            .unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM t;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, 2,
            "row 1 kept, row 2 lost with failed txn, row 3 committed"
        );
    }

    #[test]
    fn test_partial_write_preservation_and_beyond_root_reads() {
        let env = make_env();
        let vfs = install_env(&env, make_test_ledger());
        let conn = open_conn(&env);
        conn.execute_batch("CREATE TABLE t (k INTEGER PRIMARY KEY, v BLOB);")
            .unwrap();
        // A blob that does not align to page boundaries: the final partial page and
        // exact logical length must survive the commit round trip.
        let odd = vec![0x5Au8; 10_000];
        conn.execute(
            "INSERT INTO t (k, v) VALUES (1, ?);",
            rusqlite::params![odd],
        )
        .unwrap();
        let got: Vec<u8> = conn
            .query_row("SELECT v FROM t WHERE k = 1;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(got, odd);

        let (root_len, file_len) = {
            let state = vfs.state_for_test();
            let guard = state.lock().unwrap();
            (
                guard.main_root().map(|r| r.logical_file_length()).unwrap(),
                guard.main_db_size(),
            )
        };
        assert_eq!(
            root_len, file_len,
            "settled root pins the exact logical length"
        );
    }

    #[test]
    fn test_extent_vfs_truncate_and_integrity() {
        let env = make_env();
        let _vfs = install_env(&env, make_test_ledger());
        let conn = open_conn(&env);
        conn.execute_batch("CREATE TABLE t (k INTEGER PRIMARY KEY, v BLOB);")
            .unwrap();
        let big = vec![0xE7u8; 200 * 1024];
        for k in 0..4 {
            conn.execute(
                "INSERT INTO t (k, v) VALUES (?, ?);",
                rusqlite::params![k, big],
            )
            .unwrap();
        }
        conn.execute("DELETE FROM t WHERE k > 0;", []).unwrap();
        // VACUUM truncates the database file through xTruncate.
        conn.execute_batch("VACUUM;").unwrap();
        let integrity: String = conn
            .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let n: i64 = conn
            .query_row("SELECT count(*) FROM t;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn test_sync_bounds_fail_closed_and_heal_aborts_without_adoption() {
        let env = make_env();
        let ledger = make_test_ledger();
        let vfs = install_env(&env, Arc::clone(&ledger));
        let state = vfs.state_for_test();
        let mut wrapper = vfs.test_file_wrapper();
        let file_ptr = std::ptr::addr_of_mut!(wrapper.base);

        // Zero-length: the empty-tree wire variant deliberately does not exist,
        // so a dirty zero-length file cannot settle.
        {
            let mut guard = state.lock().unwrap();
            guard.set_size_for_test(0, true);
        }
        assert_eq!(
            unsafe { extent_io_sync(file_ptr, 0) },
            ffi::SQLITE_IOERR_FSYNC
        );

        // Beyond the shadow commit bound: fails closed before any ledger work.
        {
            let mut guard = state.lock().unwrap();
            guard.set_size_for_test(MAX_SHADOW_COMMIT_BYTES + 4096, true);
        }
        assert_eq!(
            unsafe { extent_io_sync(file_ptr, 0) },
            ffi::SQLITE_IOERR_FSYNC
        );

        // Mid-session heal: a stale CandidateReady attempt (simulating a prior sync
        // whose abort also failed) is durably ABORTED — never adopted — and the sync
        // reports one clean failure against the unchanged (absent) settled root.
        let archive_id = env.cipher.archive_id();
        let key_epoch = env.cipher.key_epoch();
        let candidate = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            env.database_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );
        {
            let mut stale = ExtentCommitCoordinator::new(
                archive_id,
                env.database_epoch,
                key_epoch,
                [0x99; 16],
                Arc::clone(&ledger),
            );
            stale
                .begin_attempt(ExtentFileType::MainDb, None, 0, 0, 4096, 0, vec![0])
                .unwrap();
            stale.mark_objects_staged().unwrap();
            stale.mark_candidate_ready(&candidate).unwrap();
        }
        {
            let mut guard = state.lock().unwrap();
            guard.set_size_for_test(4096, true);
            guard
                .cache_mut_for_test()
                .put(ExtentFileType::MainDb, 0, &[0x42; 4096], true)
                .unwrap();
        }
        assert_eq!(
            unsafe { extent_io_sync(file_ptr, 0) },
            ffi::SQLITE_IOERR_FSYNC
        );
        {
            let guard = state.lock().unwrap();
            assert!(
                guard.main_root().is_none(),
                "mid-session heal must never adopt a candidate root"
            );
            assert_eq!(guard.main_db_size(), 0);
        }
        let latest = ledger
            .get_latest_attempt(archive_id, env.database_epoch, ExtentFileType::MainDb)
            .unwrap()
            .unwrap();
        assert_eq!(
            latest.stage(),
            crate::archive_v3_extent_commit::ExtentCommitStage::AbortedPreWitness
        );
        assert!(ledger
            .get_active_attempt(archive_id, env.database_epoch, ExtentFileType::MainDb)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_vfs_panic_safety_and_null_buffers() {
        // Null/invalid arguments to the raw callbacks must return error codes, never
        // unwind across the FFI boundary.
        unsafe {
            assert_eq!(
                extent_io_read(ptr::null_mut(), ptr::null_mut(), 16, 0),
                ffi::SQLITE_IOERR_READ
            );
            assert_eq!(
                extent_io_write(ptr::null_mut(), ptr::null(), 16, 0),
                ffi::SQLITE_IOERR_WRITE
            );
            assert_eq!(
                extent_io_truncate(ptr::null_mut(), -1),
                ffi::SQLITE_IOERR_TRUNCATE
            );
            assert_eq!(
                extent_io_file_size(ptr::null_mut(), ptr::null_mut()),
                ffi::SQLITE_IOERR_FSTAT
            );
            assert_eq!(extent_io_sync(ptr::null_mut(), 0), ffi::SQLITE_IOERR_FSYNC);
            assert_eq!(extent_io_close(ptr::null_mut()), ffi::SQLITE_OK);
        }
    }

    #[test]
    fn test_bounded_execution_lane() {
        let value = run_bounded_vfs_read(async { 21 * 2 }).unwrap();
        assert_eq!(value, 42);
        // From inside a current-thread runtime the lane must hop threads instead of
        // panicking in block_in_place.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let value = rt.block_on(async { run_bounded_vfs_read(async { 7 }).unwrap() });
        assert_eq!(value, 7);
    }

    #[test]
    fn test_no_host_filesystem_artifacts() {
        let env = make_env();
        let _vfs = install_env(&env, make_test_ledger());
        let conn = open_conn(&env);
        conn.execute_batch(
            "CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT);
             INSERT INTO t (k, v) VALUES (1, 'x');",
        )
        .unwrap();
        drop(conn);
        // The database "path" must never materialize on the host filesystem in any
        // form: no db, no journal, no wal, no shm.
        assert!(!env.db_path.exists());
        for ext in ["db-journal", "db-wal", "db-shm"] {
            assert!(!env.db_path.with_extension(ext).exists());
        }
    }
}
