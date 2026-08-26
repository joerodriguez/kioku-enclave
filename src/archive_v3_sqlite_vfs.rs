#![allow(
    dead_code,
    reason = "inactive ADR-0022 SQLite VFS capture is compiled and oracle-tested before runtime wiring"
)]

//! An inactive, transparent SQLite VFS wrapper for ADR-0022 WAL shadowing.
//!
//! This module is deliberately an adapter, not an archive backend.  It wraps
//! the VFS selected as SQLite's default at installation time, forwards every
//! VFS and file callback to that VFS, and *after* successful WAL `xWrite`,
//! `xTruncate`, and `xSync` calls mirrors the callback to
//! [`WalCaptureState`].  The capture path has no return channel to SQLite:
//! a missing registration, poisoned capture mutex, malformed WAL, or capture
//! panic leaves the underlying return code untouched.
//!
//! The wrapper is opt-in and is not registered by application startup. Store
//! constructors remain disabled; only the inactive advisory terminal may
//! install one exact-user selection before reopening local admission. That
//! owner may hold an opaque cancellation-safe prefix, but no comparison or
//! settlement worker, provider, route, recovery, or serving wiring exists.

use std::{
    collections::BTreeMap,
    ffi::{c_char, c_int, c_void, CStr, CString},
    mem::{self, MaybeUninit},
    os::unix::ffi::OsStrExt,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    ptr,
    sync::{Arc, Mutex},
};

use rand::{rngs::OsRng, RngCore};
use rusqlite::ffi;
use sha2::{Digest, Sha256};

use crate::archive_v3_shadow::{CapturedWalCommit, ShadowCaptureMetrics, WalCaptureState};
use crate::archive_v3_shadow_session::{ShadowAttemptId, ShadowSessionId};
use crate::archive_v3_wal_owner::{AuthenticatedWalSettlement, WalOwnerContext};

/// The registry deliberately has a small fixed owner count. Ordinary callers
/// retire a path registration after closing SQLite. The reviewed inactive
/// advisory terminal may retire its exact registration in place; callbacks
/// retain their allocation but become capture-disabled.
pub const MAX_CAPTURE_REGISTRATIONS: usize = 64;
/// VFS allocations are retained until process exit so a live SQLite
/// connection can never dereference freed callbacks after the name is
/// unregistered. Bound that deliberate retention independently of owners.
pub const MAX_CAPTURE_VFS_INSTALLATIONS: usize = 8;
const MAX_CAPTURE_PATH_BYTES: usize = 4096;
const MAX_CAPTURE_DRAINS_PER_STREAM: usize = 1024;
static CAPTURE_VFS_INSTALLATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const MAX_CAPTURE_STREAM_ID_CANDIDATES: usize = 16;
const CAPTURE_STREAM_BINDING_DOMAIN: &[u8] = b"kioku/archive-v3/wal-owner-capture-stream/v1\0";

/// Random process-local identity for one exact open Store connection. It is
/// never derived from an archive, account, session, or publication attempt,
/// and its representation is never formatted or logged.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CaptureStreamId([u8; 16]);

impl CaptureStreamId {
    /// Bind this process-local stream into a publication context without ever
    /// persisting, logging, or exposing the raw random stream identifier.
    pub(crate) fn wal_owner_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CAPTURE_STREAM_BINDING_DOMAIN);
        hasher.update(self.0);
        hasher.finalize().into()
    }

    #[cfg(test)]
    pub(crate) const fn from_test_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for CaptureStreamId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CaptureStreamId(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ActiveDrain {
    token: u64,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    commit_count: usize,
}

struct RegisteredCaptureState {
    capture: WalCaptureState,
    advisory_detached: Option<Vec<CapturedWalCommit>>,
    retired: bool,
    next_drain_token: u64,
    active_drain: Option<ActiveDrain>,
    settled_drains: Vec<([u8; 16], [u8; 16])>,
}

impl RegisteredCaptureState {
    fn new() -> Self {
        Self {
            capture: WalCaptureState::new(),
            advisory_detached: None,
            retired: false,
            next_drain_token: 0,
            active_drain: None,
            settled_drains: Vec::new(),
        }
    }

    fn new_after_generation(previous_generation: u64) -> Option<Self> {
        Some(Self {
            capture: WalCaptureState::new_after_generation(previous_generation)?,
            advisory_detached: None,
            retired: false,
            next_drain_token: 0,
            active_drain: None,
            settled_drains: Vec::new(),
        })
    }

    fn retire_and_scrub(&mut self) {
        // Replacement drops the prior WalCaptureState while this mutex is
        // held. Its Drop implementation zeroizes raw image/header bytes and
        // every queued commit before any outstanding lease or live VFS
        // callback can observe the retired state.
        self.capture = WalCaptureState::new();
        self.advisory_detached.take();
        self.active_drain = None;
        self.settled_drains.clear();
        self.next_drain_token = 0;
        self.retired = true;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRegistryError {
    TooManyRegistrations,
    PathTooLong,
    PathNotCanonicalizable,
    DuplicatePath,
    StreamIdUnavailable,
    InvalidAttempt,
    DrainActive,
    AttemptAlreadySettled,
    TooManyDrains,
    DrainMismatch,
    Retired,
    StateUnavailable,
}

impl std::fmt::Display for CaptureRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::TooManyRegistrations => "capture registry is full",
            Self::PathTooLong => "capture path exceeds the fixed registry bound",
            Self::PathNotCanonicalizable => {
                "capture path must have a canonicalizable existing parent"
            }
            Self::DuplicatePath => "capture path is already registered",
            Self::StreamIdUnavailable => "capture stream identity generation exhausted",
            Self::InvalidAttempt => "capture drain attempt identity is invalid",
            Self::DrainActive => "capture registration already has an active drain",
            Self::AttemptAlreadySettled => "capture drain attempt was already settled",
            Self::TooManyDrains => "capture stream drain limit is exhausted",
            Self::DrainMismatch => "capture drain lease no longer matches its registration",
            Self::Retired => "capture registration is retired",
            Self::StateUnavailable => "capture registration state is unavailable",
        })
    }
}

impl std::error::Error for CaptureRegistryError {}

#[derive(Clone, Default)]
pub struct CaptureRegistry {
    inner: Arc<Mutex<RegistryInner>>,
}

#[derive(Default)]
struct RegistryInner {
    next_token: u64,
    slots: BTreeMap<Vec<u8>, RegistrySlot>,
}

struct RegistrySlot {
    stream_id: CaptureStreamId,
    token: u64,
    retiring: bool,
    main_open_count: usize,
    state: Arc<Mutex<RegisteredCaptureState>>,
}

/// A path/owner-scoped capture registration.  Dropping it prevents new main
/// connections from attaching.  Existing main connections retain their Arc
/// until `xClose`, so an in-flight SQLite connection cannot use freed state.
pub struct CaptureRegistration {
    registry: CaptureRegistry,
    path: Vec<u8>,
    stream_id: CaptureStreamId,
    token: u64,
    state: Arc<Mutex<RegisteredCaptureState>>,
}

/// Exclusive selection of the commit prefix visible when one exact shadow
/// attempt began. Drop/cancellation leaves that prefix queued. Only `commit`
/// detaches it, and commits observed later remain for a subsequent attempt.
pub(crate) struct CaptureDrainLease {
    state: Arc<Mutex<RegisteredCaptureState>>,
    stream_id: CaptureStreamId,
    token: u64,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    commit_count: usize,
    settled: bool,
}

/// Unforgeable owned handoff minted only by successfully settling an exact
/// capture drain lease. Its private fields prevent relabeling commits across
/// connections or publication attempts.
pub(crate) struct CapturedCommitBatch {
    stream_id: CaptureStreamId,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    commits: Vec<CapturedWalCommit>,
}

/// Non-cloneable publication owner for one exact captured commit. Taking it
/// detaches the selected queue prefix but leaves the registration's drain
/// active. Drop restores that prefix at the front while the registration is
/// live; retirement instead scrubs it. Only an authenticated settlement can
/// consume the prefix permanently.
pub(crate) struct OwnedCapturedDrain {
    state: Arc<Mutex<RegisteredCaptureState>>,
    stream_id: CaptureStreamId,
    token: u64,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    commits: Option<Vec<CapturedWalCommit>>,
    settled: bool,
}

/// Opaque proof that the exact advisory prefix was restored atomically while
/// its capture registration was still live. Only Store can request this
/// transition, and the proof carries no captured bytes or settlement power.
pub(crate) struct AdvisoryComparisonRestored(());

impl CaptureRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn is_empty_for_test(&self) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.slots.is_empty())
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub(crate) fn contains_stream_for_test(&self, stream_id: CaptureStreamId) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.slots.values().any(|slot| slot.stream_id == stream_id))
            .unwrap_or(true)
    }

    #[cfg(test)]
    pub(crate) fn contains_path_for_test(&self, path: &Path) -> bool {
        let Ok(path) = canonical_scope_path(path.as_os_str().as_bytes()) else {
            return true;
        };
        self.inner
            .lock()
            .map(|inner| inner.slots.contains_key(&path))
            .unwrap_or(true)
    }

    /// Register one exact SQLite main-database filename.  `path` is retained
    /// only as in-memory comparison data and this module never emits it.
    pub(crate) fn register(
        &self,
        path: &CStr,
    ) -> Result<CaptureRegistration, CaptureRegistryError> {
        let stream_id = self.fresh_stream_id()?;
        self.register_exact(stream_id, path)
    }

    pub(crate) fn register_after_generation(
        &self,
        path: &CStr,
        previous_generation: u64,
    ) -> Result<CaptureRegistration, CaptureRegistryError> {
        let stream_id = self.fresh_stream_id()?;
        self.register_exact_after_generation(stream_id, path, previous_generation)
    }

    fn fresh_stream_id(&self) -> Result<CaptureStreamId, CaptureRegistryError> {
        for _ in 0..MAX_CAPTURE_STREAM_ID_CANDIDATES {
            let mut bytes = [0u8; 16];
            OsRng.fill_bytes(&mut bytes);
            let candidate = CaptureStreamId(bytes);
            if bytes != [0; 16]
                && self
                    .inner
                    .lock()
                    .is_ok_and(|inner| inner.slots.values().all(|slot| slot.stream_id != candidate))
            {
                return Ok(candidate);
            }
        }
        Err(CaptureRegistryError::StreamIdUnavailable)
    }

    fn register_exact(
        &self,
        stream_id: CaptureStreamId,
        path: &CStr,
    ) -> Result<CaptureRegistration, CaptureRegistryError> {
        self.register_exact_with_state(stream_id, path, RegisteredCaptureState::new())
    }

    fn register_exact_after_generation(
        &self,
        stream_id: CaptureStreamId,
        path: &CStr,
        previous_generation: u64,
    ) -> Result<CaptureRegistration, CaptureRegistryError> {
        let state = RegisteredCaptureState::new_after_generation(previous_generation)
            .ok_or(CaptureRegistryError::StateUnavailable)?;
        self.register_exact_with_state(stream_id, path, state)
    }

    fn register_exact_with_state(
        &self,
        stream_id: CaptureStreamId,
        path: &CStr,
        state: RegisteredCaptureState,
    ) -> Result<CaptureRegistration, CaptureRegistryError> {
        if stream_id.0 == [0; 16] {
            return Err(CaptureRegistryError::StreamIdUnavailable);
        }
        let path = canonical_scope_path(path.to_bytes())?;
        if path.len() > MAX_CAPTURE_PATH_BYTES {
            return Err(CaptureRegistryError::PathTooLong);
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CaptureRegistryError::TooManyRegistrations)?;
        if inner.slots.contains_key(&path) {
            return Err(CaptureRegistryError::DuplicatePath);
        }
        if inner.slots.values().any(|slot| slot.stream_id == stream_id) {
            return Err(CaptureRegistryError::StreamIdUnavailable);
        }
        if inner.slots.len() >= MAX_CAPTURE_REGISTRATIONS {
            return Err(CaptureRegistryError::TooManyRegistrations);
        }
        let Some(token) = inner.next_token.checked_add(1) else {
            return Err(CaptureRegistryError::TooManyRegistrations);
        };
        inner.next_token = token;
        let state = Arc::new(Mutex::new(state));
        inner.slots.insert(
            path.clone(),
            RegistrySlot {
                stream_id,
                token,
                retiring: false,
                main_open_count: 0,
                state: Arc::clone(&state),
            },
        );
        Ok(CaptureRegistration {
            registry: self.clone(),
            path,
            stream_id,
            token,
            state,
        })
    }

    fn attach(&self, path: &[u8], is_main: bool, is_wal: bool) -> Option<FileCapture> {
        let mut inner = self.inner.lock().ok()?;
        let main_path = if is_main {
            canonical_scope_path(path).ok()?
        } else if is_wal {
            canonical_scope_path(path.strip_suffix(b"-wal")?).ok()?
        } else {
            return None;
        };
        let slot = inner.slots.get_mut(&main_path)?;
        // A retiring scope may finish an already-open main connection, but it
        // cannot attach a new connection after its owner has released it.
        if slot.retiring && is_main {
            return None;
        }
        if is_main {
            slot.main_open_count = slot.main_open_count.saturating_add(1);
        }
        Some(FileCapture {
            registry: self.clone(),
            path: main_path,
            token: slot.token,
            is_main,
            is_wal,
            state: Arc::clone(&slot.state),
        })
    }

    fn release_main(&self, path: &[u8], token: u64) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let remove = if let Some(slot) = inner.slots.get_mut(path) {
            if slot.token != token {
                false
            } else {
                slot.main_open_count = slot.main_open_count.saturating_sub(1);
                slot.retiring && slot.main_open_count == 0
            }
        } else {
            false
        };
        if remove {
            inner.slots.remove(path);
        }
    }

    fn retire(&self, path: &[u8], stream_id: CaptureStreamId, token: u64) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let remove = if let Some(slot) = inner.slots.get_mut(path) {
            if slot.stream_id != stream_id || slot.token != token {
                false
            } else {
                slot.retiring = true;
                slot.main_open_count == 0
            }
        } else {
            false
        };
        if remove {
            inner.slots.remove(path);
        }
    }
}

/// Bind registration and VFS callback names to the same physical parent path.
/// In particular, macOS commonly accepts `/var/...` from a caller but hands
/// the VFS `/private/var/...`.  The final database name is deliberately *not*
/// canonicalized: this avoids silently changing an exact registered path when
/// a pre-existing database leaf is a symlink or is replaced between opens.
fn canonical_scope_path(bytes: &[u8]) -> Result<Vec<u8>, CaptureRegistryError> {
    if bytes.len() > MAX_CAPTURE_PATH_BYTES {
        return Err(CaptureRegistryError::PathTooLong);
    }
    let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
    let parent = path
        .parent()
        .ok_or(CaptureRegistryError::PathNotCanonicalizable)?;
    let name = path
        .file_name()
        .ok_or(CaptureRegistryError::PathNotCanonicalizable)?;
    let canonical = std::fs::canonicalize(parent)
        .map_err(|_| CaptureRegistryError::PathNotCanonicalizable)?
        .join(name);
    let result = canonical.as_os_str().as_bytes().to_vec();
    if result.len() > MAX_CAPTURE_PATH_BYTES {
        return Err(CaptureRegistryError::PathTooLong);
    }
    Ok(result)
}

impl CaptureRegistration {
    pub(crate) fn belongs_to(&self, registry: &CaptureRegistry) -> bool {
        Arc::ptr_eq(&self.registry.inner, &registry.inner)
    }

    pub(crate) fn begin_exact_one_drain(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
    ) -> Result<CaptureDrainLease, CaptureRegistryError> {
        let lease = self.begin_drain(session_id, attempt_id)?;
        if lease.commit_count != 1 {
            drop(lease);
            return Err(CaptureRegistryError::DrainMismatch);
        }
        Ok(lease)
    }

    pub(crate) fn begin_drain(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
    ) -> Result<CaptureDrainLease, CaptureRegistryError> {
        if session_id.as_bytes().iter().all(|byte| *byte == 0)
            || attempt_id.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(CaptureRegistryError::InvalidAttempt);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| CaptureRegistryError::StateUnavailable)?;
        if state.retired {
            return Err(CaptureRegistryError::Retired);
        }
        if state.active_drain.is_some() {
            return Err(CaptureRegistryError::DrainActive);
        }
        let drain_identity = (*session_id.as_bytes(), *attempt_id.as_bytes());
        if state.settled_drains.contains(&drain_identity) {
            return Err(CaptureRegistryError::AttemptAlreadySettled);
        }
        if state.settled_drains.len() >= MAX_CAPTURE_DRAINS_PER_STREAM {
            return Err(CaptureRegistryError::TooManyDrains);
        }
        let token = state
            .next_drain_token
            .checked_add(1)
            .ok_or(CaptureRegistryError::StateUnavailable)?;
        state.next_drain_token = token;
        let commit_count = state.capture.completed_len();
        state.active_drain = Some(ActiveDrain {
            token,
            session_id,
            attempt_id,
            commit_count,
        });
        drop(state);
        Ok(CaptureDrainLease {
            state: Arc::clone(&self.state),
            stream_id: self.stream_id,
            token,
            session_id,
            attempt_id,
            commit_count,
            settled: false,
        })
    }

    pub(crate) fn metrics(&self) -> ShadowCaptureMetrics {
        self.state
            .lock()
            .map(|state| state.capture.metrics())
            .unwrap_or_default()
    }

    pub(crate) fn stream_id(&self) -> CaptureStreamId {
        self.stream_id
    }

    pub(crate) fn completed_len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.capture.completed_len())
            .unwrap_or(usize::MAX)
    }

    #[cfg(test)]
    fn attached_main_count(&self) -> usize {
        self.registry
            .inner
            .lock()
            .ok()
            .and_then(|inner| inner.slots.get(&self.path).map(|slot| slot.main_open_count))
            .unwrap_or_default()
    }
}

impl Drop for CaptureRegistration {
    fn drop(&mut self) {
        // Capture callbacks are panic-contained. If one ever poisoned this
        // mutex, retirement must still recover ownership and scrub plaintext
        // rather than retain it behind the poison marker.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retire_and_scrub();
        self.registry.retire(&self.path, self.stream_id, self.token);
    }
}

impl CaptureDrainLease {
    pub(crate) fn take_for_publication(
        mut self,
    ) -> Result<OwnedCapturedDrain, CaptureRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CaptureRegistryError::StateUnavailable)?;
        if state.retired {
            return Err(CaptureRegistryError::Retired);
        }
        let expected = ActiveDrain {
            token: self.token,
            session_id: self.session_id,
            attempt_id: self.attempt_id,
            commit_count: self.commit_count,
        };
        if self.commit_count != 1 || state.active_drain != Some(expected) {
            return Err(CaptureRegistryError::DrainMismatch);
        }
        let commits = state
            .capture
            .drain_completed_prefix_with_reservation(1)
            .ok_or(CaptureRegistryError::DrainMismatch)?;
        drop(state);
        self.settled = true;
        Ok(OwnedCapturedDrain {
            state: Arc::clone(&self.state),
            stream_id: self.stream_id,
            token: self.token,
            session_id: self.session_id,
            attempt_id: self.attempt_id,
            commits: Some(commits),
            settled: false,
        })
    }

    pub(crate) fn commit(mut self) -> Result<CapturedCommitBatch, CaptureRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CaptureRegistryError::StateUnavailable)?;
        if state.retired {
            return Err(CaptureRegistryError::Retired);
        }
        let expected = ActiveDrain {
            token: self.token,
            session_id: self.session_id,
            attempt_id: self.attempt_id,
            commit_count: self.commit_count,
        };
        if state.active_drain != Some(expected) {
            return Err(CaptureRegistryError::DrainMismatch);
        }
        let commits = state
            .capture
            .drain_completed_prefix(expected.commit_count)
            .ok_or(CaptureRegistryError::DrainMismatch)?;
        state.active_drain = None;
        state
            .settled_drains
            .push((*self.session_id.as_bytes(), *self.attempt_id.as_bytes()));
        self.settled = true;
        Ok(CapturedCommitBatch {
            stream_id: self.stream_id,
            session_id: self.session_id,
            attempt_id: self.attempt_id,
            commits,
        })
    }
}

impl OwnedCapturedDrain {
    pub(crate) fn observed_wal_generation(
        &self,
        _token: crate::archive_v3_wal_owner::WalOwnerStoreContext,
    ) -> Result<u64, CaptureRegistryError> {
        let commits = self
            .commits
            .as_deref()
            .ok_or(CaptureRegistryError::DrainMismatch)?;
        commits
            .first()
            .filter(|_| commits.len() == 1)
            .map(CapturedWalCommit::wal_generation)
            .filter(|generation| *generation != 0)
            .ok_or(CaptureRegistryError::DrainMismatch)
    }

    pub(crate) fn exact_commit<'a>(
        &'a self,
        context: &WalOwnerContext,
    ) -> Result<&'a CapturedWalCommit, CaptureRegistryError> {
        let commits = self
            .commits
            .as_deref()
            .ok_or(CaptureRegistryError::DrainMismatch)?;
        let commit = commits
            .first()
            .filter(|_| commits.len() == 1)
            .ok_or(CaptureRegistryError::DrainMismatch)?;
        if !context.matches_capture(
            self.stream_id,
            self.session_id,
            self.attempt_id,
            commit.wal_generation(),
        ) {
            return Err(CaptureRegistryError::DrainMismatch);
        }
        Ok(commit)
    }

    pub(crate) fn settle(
        mut self,
        context: &WalOwnerContext,
        settlement: AuthenticatedWalSettlement,
    ) -> Result<crate::archive_v3_wal_owner::WalOwnerStoreBinding, CaptureRegistryError> {
        let commitment = self.exact_commit(context)?.publication_commitment();
        if !settlement.authenticates(context, commitment) {
            return Err(CaptureRegistryError::DrainMismatch);
        }
        let next_binding = settlement.next_binding().clone();
        let mut state = self
            .state
            .lock()
            .map_err(|_| CaptureRegistryError::StateUnavailable)?;
        let expected = ActiveDrain {
            token: self.token,
            session_id: self.session_id,
            attempt_id: self.attempt_id,
            commit_count: 1,
        };
        if state.retired || state.active_drain != Some(expected) {
            return Err(CaptureRegistryError::DrainMismatch);
        }
        if !state.capture.release_completed_reservation(
            self.commits
                .as_deref()
                .ok_or(CaptureRegistryError::DrainMismatch)?,
        ) {
            return Err(CaptureRegistryError::DrainMismatch);
        }
        state.active_drain = None;
        state
            .settled_drains
            .push((*self.session_id.as_bytes(), *self.attempt_id.as_bytes()));
        self.commits.take();
        self.settled = true;
        Ok(next_binding)
    }

    pub(crate) fn stream_id(&self) -> CaptureStreamId {
        self.stream_id
    }
}

impl Drop for OwnedCapturedDrain {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let Some(commits) = self.commits.take() else {
            return;
        };
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let expected = ActiveDrain {
            token: self.token,
            session_id: self.session_id,
            attempt_id: self.attempt_id,
            commit_count: 1,
        };
        if state.retired || state.active_drain != Some(expected) {
            return;
        }
        state.active_drain = None;
        let _ = state.capture.restore_completed_prefix(commits);
    }
}

impl std::fmt::Debug for OwnedCapturedDrain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnedCapturedDrain(<opaque>)")
    }
}

impl Drop for CaptureDrainLease {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.active_drain.is_some_and(|active| {
            active.token == self.token
                && active.session_id == self.session_id
                && active.attempt_id == self.attempt_id
        }) {
            state.active_drain = None;
        }
    }
}

impl CapturedCommitBatch {
    pub(crate) fn stream_id(&self) -> CaptureStreamId {
        self.stream_id
    }

    pub(crate) fn session_id(&self) -> ShadowSessionId {
        self.session_id
    }

    pub(crate) fn attempt_id(&self) -> ShadowAttemptId {
        self.attempt_id
    }

    pub(crate) fn commits(&self) -> &[CapturedWalCommit] {
        &self.commits
    }
}

impl std::fmt::Debug for CapturedCommitBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CapturedCommitBatch(<redacted>)")
    }
}

struct FileCapture {
    registry: CaptureRegistry,
    path: Vec<u8>,
    token: u64,
    is_main: bool,
    is_wal: bool,
    state: Arc<Mutex<RegisteredCaptureState>>,
}

impl FileCapture {
    fn write(&self, offset: i64, bytes: &[u8]) {
        if !self.is_wal {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut state) = self.state.lock() {
                if state.retired {
                    return;
                }
                state.capture.observe_write(offset, bytes);
            }
        }));
    }

    fn truncate(&self, length: i64) {
        if !self.is_wal {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut state) = self.state.lock() {
                if state.retired {
                    return;
                }
                state.capture.observe_truncate(length, true);
            }
        }));
    }

    fn sync(&self) {
        if !self.is_wal {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut state) = self.state.lock() {
                if state.retired {
                    return;
                }
                let _ = state.capture.observe_sync(true);
            }
        }));
    }
}

impl Drop for FileCapture {
    fn drop(&mut self) {
        if self.is_main {
            self.registry.release_main(&self.path, self.token);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureVfsError {
    NoDefaultVfs,
    InvalidParentFileSize,
    InvalidName,
    TooManyInstallations,
    RegisterFailed(c_int),
}

impl std::fmt::Display for CaptureVfsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDefaultVfs => formatter.write_str("SQLite has no default VFS"),
            Self::InvalidParentFileSize => {
                formatter.write_str("default SQLite VFS has an invalid file size")
            }
            Self::InvalidName => formatter.write_str("SQLite VFS name contains a NUL byte"),
            Self::TooManyInstallations => {
                formatter.write_str("SQLite VFS installation limit is exhausted")
            }
            Self::RegisterFailed(code) => {
                write!(formatter, "SQLite VFS registration failed with code {code}")
            }
        }
    }
}

impl std::error::Error for CaptureVfsError {}

/// An explicitly installed wrapper around the VFS SQLite selected as default
/// at installation time. It is not made SQLite's default VFS. Dropping this
/// value deliberately retains its registered name and bounded callback
/// allocation until process exit so already-open SQLite connections remain
/// memory-safe and functional if they later open attached or temporary files.
pub struct RegisteredCaptureVfs {
    allocation: Option<Box<VfsAllocation>>,
}

struct VfsContext {
    parent: *mut ffi::sqlite3_vfs,
    registry: CaptureRegistry,
}

struct VfsAllocation {
    name: CString,
    context: VfsContext,
    vfs: ffi::sqlite3_vfs,
}

impl RegisteredCaptureVfs {
    /// Install a named wrapper over the currently selected SQLite default VFS.
    /// This is intended only for an inactive owner-scoped shadow experiment.
    pub fn install(name: &str, registry: CaptureRegistry) -> Result<Self, CaptureVfsError> {
        let name = CString::new(name).map_err(|_| CaptureVfsError::InvalidName)?;
        // SAFETY: SQLite initializes its built-in default VFS before normal
        // connection use. We only read its immutable callback table.
        let parent = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
        if parent.is_null() {
            return Err(CaptureVfsError::NoDefaultVfs);
        }
        // SAFETY: checked non-null above; the parent VFS remains registered for
        // the lifetime of SQLite and we do not unregister or mutate it.
        let parent_ref = unsafe { &*parent };
        if parent_ref.szOsFile < mem::size_of::<ffi::sqlite3_file>() as c_int {
            return Err(CaptureVfsError::InvalidParentFileSize);
        }
        let mut allocation = Box::new(VfsAllocation {
            name,
            context: VfsContext { parent, registry },
            vfs: unsafe { MaybeUninit::zeroed().assume_init() },
        });
        let required_file_size =
            parent_ref.szOsFile as usize + mem::offset_of!(WrappedFile, parent_file);
        allocation.vfs = ffi::sqlite3_vfs {
            // We expose only the ABI represented by this bundled binding,
            // even if a future parent VFS advertises a later version.
            iVersion: parent_ref.iVersion.min(3),
            szOsFile: c_int::try_from(required_file_size)
                .map_err(|_| CaptureVfsError::InvalidParentFileSize)?,
            mxPathname: parent_ref.mxPathname,
            pNext: ptr::null_mut(),
            zName: allocation.name.as_ptr(),
            pAppData: (&mut allocation.context as *mut VfsContext).cast(),
            xOpen: Some(vfs_open),
            xDelete: Some(vfs_delete),
            xAccess: Some(vfs_access),
            xFullPathname: Some(vfs_full_pathname),
            xDlOpen: parent_ref.xDlOpen.map(|_| vfs_dl_open as _),
            xDlError: parent_ref.xDlError.map(|_| vfs_dl_error as _),
            xDlSym: parent_ref.xDlSym.map(|_| vfs_dl_sym as _),
            xDlClose: parent_ref.xDlClose.map(|_| vfs_dl_close as _),
            xRandomness: parent_ref.xRandomness.map(|_| vfs_randomness as _),
            xSleep: parent_ref.xSleep.map(|_| vfs_sleep as _),
            xCurrentTime: parent_ref.xCurrentTime.map(|_| vfs_current_time as _),
            xGetLastError: parent_ref.xGetLastError.map(|_| vfs_get_last_error as _),
            xCurrentTimeInt64: parent_ref
                .xCurrentTimeInt64
                .map(|_| vfs_current_time_int64 as _),
            xSetSystemCall: parent_ref.xSetSystemCall.map(|_| vfs_set_system_call as _),
            xGetSystemCall: parent_ref.xGetSystemCall.map(|_| vfs_get_system_call as _),
            xNextSystemCall: parent_ref
                .xNextSystemCall
                .map(|_| vfs_next_system_call as _),
        };
        CAPTURE_VFS_INSTALLATIONS
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |count| (count < MAX_CAPTURE_VFS_INSTALLATIONS).then_some(count + 1),
            )
            .map_err(|_| CaptureVfsError::TooManyInstallations)?;
        // SAFETY: `allocation` is boxed and retained through process exit.
        let code = unsafe { ffi::sqlite3_vfs_register(&mut allocation.vfs, 0) };
        if code != ffi::SQLITE_OK {
            CAPTURE_VFS_INSTALLATIONS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            return Err(CaptureVfsError::RegisterFailed(code));
        }
        Ok(Self {
            allocation: Some(allocation),
        })
    }

    pub fn name(&self) -> &CStr {
        &self
            .allocation
            .as_ref()
            .expect("registered VFS retains its allocation")
            .name
    }
}

impl Drop for RegisteredCaptureVfs {
    fn drop(&mut self) {
        let Some(allocation) = self.allocation.take() else {
            return;
        };
        // SQLite retains the VFS name and raw pointer and may resolve/invoke it
        // later for ATTACH or temporary files. There is no Rust lifetime tying
        // those connections to this handle, so unregistering or freeing here
        // would make this safe API unsound or break a still-live connection.
        // The global installation cap bounds this deliberate process-lifetime
        // registration.
        let _ = Box::leak(allocation);
    }
}

#[repr(C)]
struct WrappedFile {
    base: ffi::sqlite3_file,
    capture: Option<FileCapture>,
    parent_file: ffi::sqlite3_file,
}

static WRAPPED_IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 3,
    xClose: Some(io_close),
    xRead: Some(io_read),
    xWrite: Some(io_write),
    xTruncate: Some(io_truncate),
    xSync: Some(io_sync),
    xFileSize: Some(io_file_size),
    xLock: Some(io_lock),
    xUnlock: Some(io_unlock),
    xCheckReservedLock: Some(io_check_reserved_lock),
    xFileControl: Some(io_file_control),
    xSectorSize: Some(io_sector_size),
    xDeviceCharacteristics: Some(io_device_characteristics),
    xShmMap: Some(io_shm_map),
    xShmLock: Some(io_shm_lock),
    xShmBarrier: Some(io_shm_barrier),
    xShmUnmap: Some(io_shm_unmap),
    xFetch: Some(io_fetch),
    xUnfetch: Some(io_unfetch),
};

fn parent_io_is_compatible(methods: &ffi::sqlite3_io_methods) -> bool {
    methods.iVersion >= 3
        && methods.xClose.is_some()
        && methods.xRead.is_some()
        && methods.xWrite.is_some()
        && methods.xTruncate.is_some()
        && methods.xSync.is_some()
        && methods.xFileSize.is_some()
        && methods.xLock.is_some()
        && methods.xUnlock.is_some()
        && methods.xCheckReservedLock.is_some()
        && methods.xFileControl.is_some()
        && methods.xSectorSize.is_some()
        && methods.xDeviceCharacteristics.is_some()
}

unsafe fn context(vfs: *mut ffi::sqlite3_vfs) -> &'static VfsContext {
    // SAFETY: every callback receives our registered VFS, whose pAppData is a
    // pointer to the VfsContext retained by RegisteredCaptureVfs.
    unsafe { &*((*vfs).pAppData.cast::<VfsContext>()) }
}

unsafe fn wrapped(file: *mut ffi::sqlite3_file) -> *mut WrappedFile {
    file.cast()
}

unsafe fn parent_file(file: *mut ffi::sqlite3_file) -> *mut ffi::sqlite3_file {
    // SAFETY: `file` points at our repr(C) prefix allocated using szOsFile.
    unsafe { ptr::addr_of_mut!((*wrapped(file)).parent_file) }
}

unsafe fn parent_methods(file: *mut ffi::sqlite3_file) -> *const ffi::sqlite3_io_methods {
    // SAFETY: after successful parent xOpen, SQLite requires pMethods to be
    // initialized. Missing methods are treated as SQLITE_NOTFOUND below.
    unsafe { (*parent_file(file)).pMethods }
}

unsafe fn parent_vfs(vfs: *mut ffi::sqlite3_vfs) -> *mut ffi::sqlite3_vfs {
    unsafe { context(vfs).parent }
}

unsafe extern "C" fn vfs_open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let parent = unsafe { parent_vfs(vfs) };
    let Some(open) = (unsafe { (*parent).xOpen }) else {
        return ffi::SQLITE_CANTOPEN;
    };
    let wrapper = unsafe { wrapped(file) };
    // SAFETY: SQLite supplied `szOsFile` bytes using our advertised size. The
    // parent gets the aligned tail reserved for its exact file structure.
    unsafe {
        ptr::write(
            wrapper,
            WrappedFile {
                base: ffi::sqlite3_file {
                    pMethods: ptr::null(),
                },
                capture: None,
                parent_file: ffi::sqlite3_file {
                    pMethods: ptr::null(),
                },
            },
        );
    }
    let code = unsafe { open(parent, name, parent_file(file), flags, out_flags) };
    if code != ffi::SQLITE_OK {
        return code;
    }
    let methods = unsafe { parent_methods(file) };
    if methods.is_null() || !parent_io_is_compatible(unsafe { &*methods }) {
        if !methods.is_null() {
            if let Some(close) = unsafe { (*methods).xClose } {
                // SQLite xClose is a final release even when it reports an I/O
                // error; the parent must dispose of its file-owned resources.
                let _ = unsafe { close(parent_file(file)) };
            }
        }
        return ffi::SQLITE_CANTOPEN;
    }
    let is_main = flags & ffi::SQLITE_OPEN_MAIN_DB != 0;
    let is_wal = flags & ffi::SQLITE_OPEN_WAL != 0;
    if (is_main || is_wal) && !name.is_null() {
        // Names are comparison data only. Invalid/non-UTF8 names remain valid
        // SQLite paths but simply receive no shadow capture.
        let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
        if bytes.len() <= MAX_CAPTURE_PATH_BYTES {
            unsafe {
                (*wrapper).capture = context(vfs).registry.attach(bytes, is_main, is_wal);
            }
        }
    }
    unsafe { (*wrapper).base.pMethods = &WRAPPED_IO_METHODS };
    ffi::SQLITE_OK
}

unsafe extern "C" fn vfs_delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    match unsafe { (*parent_vfs(vfs)).xDelete } {
        Some(callback) => unsafe { callback(parent_vfs(vfs), name, sync_dir) },
        None => ffi::SQLITE_NOTFOUND,
    }
}

unsafe extern "C" fn vfs_access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    result: *mut c_int,
) -> c_int {
    match unsafe { (*parent_vfs(vfs)).xAccess } {
        Some(callback) => unsafe { callback(parent_vfs(vfs), name, flags, result) },
        None => ffi::SQLITE_NOTFOUND,
    }
}

unsafe extern "C" fn vfs_full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    match unsafe { (*parent_vfs(vfs)).xFullPathname } {
        Some(callback) => unsafe { callback(parent_vfs(vfs), name, size, output) },
        None => ffi::SQLITE_NOTFOUND,
    }
}

unsafe extern "C" fn vfs_dl_open(vfs: *mut ffi::sqlite3_vfs, name: *const c_char) -> *mut c_void {
    unsafe {
        (*parent_vfs(vfs))
            .xDlOpen
            .map(|callback| callback(parent_vfs(vfs), name))
            .unwrap_or(ptr::null_mut())
    }
}
unsafe extern "C" fn vfs_dl_error(vfs: *mut ffi::sqlite3_vfs, size: c_int, output: *mut c_char) {
    if let Some(callback) = unsafe { (*parent_vfs(vfs)).xDlError } {
        unsafe { callback(parent_vfs(vfs), size, output) }
    }
}
unsafe extern "C" fn vfs_dl_sym(
    vfs: *mut ffi::sqlite3_vfs,
    handle: *mut c_void,
    name: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    unsafe {
        (*parent_vfs(vfs))
            .xDlSym
            .and_then(|callback| callback(parent_vfs(vfs), handle, name))
    }
}
unsafe extern "C" fn vfs_dl_close(vfs: *mut ffi::sqlite3_vfs, handle: *mut c_void) {
    if let Some(callback) = unsafe { (*parent_vfs(vfs)).xDlClose } {
        unsafe { callback(parent_vfs(vfs), handle) }
    }
}
unsafe extern "C" fn vfs_randomness(
    vfs: *mut ffi::sqlite3_vfs,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    unsafe {
        (*parent_vfs(vfs))
            .xRandomness
            .map(|callback| callback(parent_vfs(vfs), size, output))
            .unwrap_or(ffi::SQLITE_NOTFOUND)
    }
}
unsafe extern "C" fn vfs_sleep(vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    unsafe {
        (*parent_vfs(vfs))
            .xSleep
            .map(|callback| callback(parent_vfs(vfs), microseconds))
            .unwrap_or(ffi::SQLITE_NOTFOUND)
    }
}
unsafe extern "C" fn vfs_current_time(vfs: *mut ffi::sqlite3_vfs, output: *mut f64) -> c_int {
    unsafe {
        (*parent_vfs(vfs))
            .xCurrentTime
            .map(|callback| callback(parent_vfs(vfs), output))
            .unwrap_or(ffi::SQLITE_NOTFOUND)
    }
}
unsafe extern "C" fn vfs_get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    unsafe {
        (*parent_vfs(vfs))
            .xGetLastError
            .map(|callback| callback(parent_vfs(vfs), size, output))
            .unwrap_or(ffi::SQLITE_NOTFOUND)
    }
}
unsafe extern "C" fn vfs_current_time_int64(
    vfs: *mut ffi::sqlite3_vfs,
    output: *mut ffi::sqlite3_int64,
) -> c_int {
    unsafe {
        (*parent_vfs(vfs))
            .xCurrentTimeInt64
            .map(|callback| callback(parent_vfs(vfs), output))
            .unwrap_or(ffi::SQLITE_NOTFOUND)
    }
}
unsafe extern "C" fn vfs_set_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    syscall: ffi::sqlite3_syscall_ptr,
) -> c_int {
    unsafe {
        (*parent_vfs(vfs))
            .xSetSystemCall
            .map(|callback| callback(parent_vfs(vfs), name, syscall))
            .unwrap_or(ffi::SQLITE_NOTFOUND)
    }
}
unsafe extern "C" fn vfs_get_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> ffi::sqlite3_syscall_ptr {
    unsafe {
        (*parent_vfs(vfs))
            .xGetSystemCall
            .and_then(|callback| callback(parent_vfs(vfs), name))
    }
}
unsafe extern "C" fn vfs_next_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> *const c_char {
    unsafe {
        (*parent_vfs(vfs))
            .xNextSystemCall
            .map(|callback| callback(parent_vfs(vfs), name))
            .unwrap_or(ptr::null())
    }
}

macro_rules! delegate_io {
    ($file:expr, $method:ident $(, $arg:expr)*) => {{
        let methods = unsafe { parent_methods($file) };
        if methods.is_null() {
            ffi::SQLITE_NOTFOUND
        } else {
            unsafe { (*methods).$method.map(|callback| callback(parent_file($file) $(, $arg)*)).unwrap_or(ffi::SQLITE_NOTFOUND) }
        }
    }};
}

unsafe extern "C" fn io_close(file: *mut ffi::sqlite3_file) -> c_int {
    let code = delegate_io!(file, xClose);
    // SQLite's xClose is final: the parent releases file-owned resources even
    // when reporting an I/O error, and SQLite frees the sqlite3_file storage
    // after the callback. Drop capture exactly once and preserve that code.
    unsafe { ptr::drop_in_place(ptr::addr_of_mut!((*wrapped(file)).capture)) };
    unsafe { (*wrapped(file)).base.pMethods = ptr::null() };
    code
}
unsafe extern "C" fn io_read(
    file: *mut ffi::sqlite3_file,
    buffer: *mut c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    delegate_io!(file, xRead, buffer, amount, offset)
}
unsafe extern "C" fn io_write(
    file: *mut ffi::sqlite3_file,
    buffer: *const c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    let code = delegate_io!(file, xWrite, buffer, amount, offset);
    if code == ffi::SQLITE_OK && amount >= 0 && !buffer.is_null() {
        let capture = unsafe { &(*wrapped(file)).capture };
        if let Some(capture) = capture {
            let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), amount as usize) };
            capture.write(offset, bytes);
        }
    }
    code
}
unsafe extern "C" fn io_truncate(file: *mut ffi::sqlite3_file, size: ffi::sqlite3_int64) -> c_int {
    let code = delegate_io!(file, xTruncate, size);
    if code == ffi::SQLITE_OK {
        if let Some(capture) = unsafe { &(*wrapped(file)).capture } {
            capture.truncate(size);
        }
    }
    code
}
unsafe extern "C" fn io_sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    let code = delegate_io!(file, xSync, flags);
    if code == ffi::SQLITE_OK {
        if let Some(capture) = unsafe { &(*wrapped(file)).capture } {
            capture.sync();
        }
    }
    code
}
unsafe extern "C" fn io_file_size(
    file: *mut ffi::sqlite3_file,
    size: *mut ffi::sqlite3_int64,
) -> c_int {
    delegate_io!(file, xFileSize, size)
}
unsafe extern "C" fn io_lock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    delegate_io!(file, xLock, level)
}
unsafe extern "C" fn io_unlock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    delegate_io!(file, xUnlock, level)
}
unsafe extern "C" fn io_check_reserved_lock(
    file: *mut ffi::sqlite3_file,
    result: *mut c_int,
) -> c_int {
    delegate_io!(file, xCheckReservedLock, result)
}
unsafe extern "C" fn io_file_control(
    file: *mut ffi::sqlite3_file,
    op: c_int,
    arg: *mut c_void,
) -> c_int {
    delegate_io!(file, xFileControl, op, arg)
}
unsafe extern "C" fn io_sector_size(file: *mut ffi::sqlite3_file) -> c_int {
    delegate_io!(file, xSectorSize)
}
unsafe extern "C" fn io_device_characteristics(file: *mut ffi::sqlite3_file) -> c_int {
    delegate_io!(file, xDeviceCharacteristics)
}
unsafe extern "C" fn io_shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    page_size: c_int,
    extend: c_int,
    output: *mut *mut c_void,
) -> c_int {
    delegate_io!(file, xShmMap, page, page_size, extend, output)
}
unsafe extern "C" fn io_shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    delegate_io!(file, xShmLock, offset, count, flags)
}
unsafe extern "C" fn io_shm_barrier(file: *mut ffi::sqlite3_file) {
    let methods = unsafe { parent_methods(file) };
    if !methods.is_null() {
        if let Some(callback) = unsafe { (*methods).xShmBarrier } {
            unsafe { callback(parent_file(file)) }
        }
    }
}
unsafe extern "C" fn io_shm_unmap(file: *mut ffi::sqlite3_file, delete_flag: c_int) -> c_int {
    delegate_io!(file, xShmUnmap, delete_flag)
}
unsafe extern "C" fn io_fetch(
    file: *mut ffi::sqlite3_file,
    offset: ffi::sqlite3_int64,
    amount: c_int,
    output: *mut *mut c_void,
) -> c_int {
    let methods = unsafe { parent_methods(file) };
    if methods.is_null() {
        return ffi::SQLITE_NOTFOUND;
    }
    if let Some(callback) = unsafe { (*methods).xFetch } {
        unsafe { callback(parent_file(file), offset, amount, output) }
    } else {
        // SQLite specifies a successful null fetch as the signal to fall back
        // to xRead when the parent does not implement memory mapping.
        if !output.is_null() {
            unsafe { *output = ptr::null_mut() };
        }
        ffi::SQLITE_OK
    }
}
unsafe extern "C" fn io_unfetch(
    file: *mut ffi::sqlite3_file,
    offset: ffi::sqlite3_int64,
    pointer: *mut c_void,
) -> c_int {
    let methods = unsafe { parent_methods(file) };
    if methods.is_null() {
        return ffi::SQLITE_NOTFOUND;
    }
    unsafe {
        (*methods)
            .xUnfetch
            .map(|callback| callback(parent_file(file), offset, pointer))
            .unwrap_or(ffi::SQLITE_OK)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use rusqlite::{Connection, OpenFlags};
    use tempfile::TempDir;

    use super::*;

    static NEXT_VFS: AtomicU64 = AtomicU64::new(1);

    unsafe extern "C" fn failed_write(
        _file: *mut ffi::sqlite3_file,
        _buffer: *const c_void,
        _amount: c_int,
        _offset: ffi::sqlite3_int64,
    ) -> c_int {
        ffi::SQLITE_IOERR_WRITE
    }

    unsafe extern "C" fn failed_truncate(
        _file: *mut ffi::sqlite3_file,
        _size: ffi::sqlite3_int64,
    ) -> c_int {
        ffi::SQLITE_IOERR_TRUNCATE
    }

    unsafe extern "C" fn failed_sync(_file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
        ffi::SQLITE_IOERR_FSYNC
    }

    static FAILED_IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
        iVersion: 3,
        xClose: None,
        xRead: None,
        xWrite: Some(failed_write),
        xTruncate: Some(failed_truncate),
        xSync: Some(failed_sync),
        xFileSize: None,
        xLock: None,
        xUnlock: None,
        xCheckReservedLock: None,
        xFileControl: None,
        xSectorSize: None,
        xDeviceCharacteristics: None,
        xShmMap: None,
        xShmLock: None,
        xShmBarrier: None,
        xShmUnmap: None,
        xFetch: None,
        xUnfetch: None,
    };

    fn synthetic_failed_file() -> (WrappedFile, Arc<Mutex<RegisteredCaptureState>>) {
        let state = Arc::new(Mutex::new(RegisteredCaptureState::new()));
        let capture = FileCapture {
            registry: CaptureRegistry::new(),
            path: Vec::new(),
            token: 0,
            is_main: false,
            is_wal: true,
            state: Arc::clone(&state),
        };
        (
            WrappedFile {
                base: ffi::sqlite3_file {
                    pMethods: &WRAPPED_IO_METHODS,
                },
                capture: Some(capture),
                parent_file: ffi::sqlite3_file {
                    pMethods: &FAILED_IO_METHODS,
                },
            },
            state,
        )
    }

    fn setup() -> (
        TempDir,
        CString,
        CaptureRegistration,
        Arc<crate::store::StoreShadowCapture>,
    ) {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("capture.db");
        let c_path = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        let capture = crate::store::StoreShadowCapture::shared_for_test();
        let registration = capture.register_path_for_test(&path).unwrap();
        (directory, c_path, registration, capture)
    }

    fn setup_owned_vfs() -> (TempDir, CString, CaptureRegistration, RegisteredCaptureVfs) {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("capture.db");
        let c_path = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        let registry = CaptureRegistry::new();
        let registration = registry.register(&c_path).unwrap();
        let name = format!(
            "kioku-capture-test-{}",
            NEXT_VFS.fetch_add(1, Ordering::Relaxed)
        );
        let vfs = RegisteredCaptureVfs::install(&name, registry).unwrap();
        (directory, c_path, registration, vfs)
    }

    fn settle(registration: &CaptureRegistration, session: u8, attempt: u8) -> CapturedCommitBatch {
        registration
            .begin_drain(
                ShadowSessionId::from_bytes([session; 16]),
                ShadowAttemptId::from_bytes([attempt; 16]),
            )
            .unwrap()
            .commit()
            .unwrap()
    }

    fn open(path: &CStr, vfs_name: &CStr) -> Connection {
        Connection::open_with_flags_and_vfs(
            std::path::Path::new(std::str::from_utf8(path.to_bytes()).unwrap()),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            vfs_name,
        )
        .unwrap()
    }

    fn wal_setup(connection: &Connection) {
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=0; \
             CREATE TABLE events(value INTEGER); PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .unwrap();
    }

    #[test]
    fn sqlite_commit_is_captured_and_replays_against_a_checkpointed_oracle() {
        let (directory, c_path, registration, vfs) = setup();
        let connection = open(&c_path, vfs.vfs_name_for_test());
        assert_eq!(registration.attached_main_count(), 1);
        wal_setup(&connection);
        let replay = directory.path().join("replay.db");
        fs::copy(directory.path().join("capture.db"), &replay).unwrap();
        // The schema-creation commit predates this checkpoint and therefore
        // belongs to the prior base/generation. The future owner coordinates
        // checkpoint publication with this same drain boundary.
        let _ = settle(&registration, 1, 1);

        connection
            .execute("INSERT INTO events(value) VALUES (41)", [])
            .unwrap();
        connection
            .execute("INSERT INTO events(value) VALUES (42)", [])
            .unwrap();
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        let batch = settle(&registration, 1, 2);
        let commits = batch.commits();
        assert!(
            !commits.is_empty(),
            "a successful SQLite WAL commit must be observed"
        );
        for (index, commit) in commits.iter().enumerate() {
            commit.validate_segments(index as u64 + 1).unwrap();
        }

        // A checkpointed pre-transaction database plus exactly the captured
        // header/frames must recover the same SQLite-visible rows. This is an
        // oracle for this platform's default VFS, not a claim that arbitrary
        // SQLite WAL scheduling produces one xSync per SQL statement.
        let mut wal = commits[0].replay_header().to_vec();
        for commit in commits {
            wal.extend_from_slice(commit.replay_frames());
        }
        fs::write(replay.with_extension("db-wal"), wal).unwrap();
        let replayed = Connection::open(replay).unwrap();
        assert_eq!(
            replayed
                .query_row("SELECT count(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        drop(replayed);
        drop(connection);
    }

    #[test]
    fn rollback_does_not_publish_and_consecutive_transactions_remain_visible() {
        let (_directory, c_path, registration, vfs) = setup();
        let connection = open(&c_path, vfs.vfs_name_for_test());
        wal_setup(&connection);
        let _ = settle(&registration, 2, 1);
        connection
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO events VALUES (1); ROLLBACK;")
            .unwrap();
        assert!(settle(&registration, 2, 2).commits().is_empty());
        connection
            .execute("INSERT INTO events VALUES (2)", [])
            .unwrap();
        connection
            .execute("INSERT INTO events VALUES (3)", [])
            .unwrap();
        assert_eq!(
            connection
                .query_row("SELECT sum(value) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            5
        );
        let batch = settle(&registration, 2, 3);
        let commits = batch.commits();
        assert!(!commits.is_empty());
        assert!(commits
            .windows(2)
            .all(|pair| pair[0].first_frame_no() < pair[1].first_frame_no()));
        drop(connection);
    }

    #[test]
    fn drain_lease_is_exclusive_and_cancelled_lease_preserves_the_exact_prefix() {
        let session_id = ShadowSessionId::from_bytes([8; 16]);
        let first_attempt = ShadowAttemptId::from_bytes([9; 16]);
        let later_attempt = ShadowAttemptId::from_bytes([10; 16]);
        let (_directory, c_path, registration, vfs) = setup();
        let connection = open(&c_path, vfs.vfs_name_for_test());
        wal_setup(&connection);
        let _ = settle(&registration, 3, 1);
        connection
            .execute("INSERT INTO events VALUES (9)", [])
            .unwrap();
        let lease = registration.begin_drain(session_id, first_attempt).unwrap();
        let selected_count = registration
            .state
            .lock()
            .unwrap()
            .active_drain
            .unwrap()
            .commit_count;
        assert!(matches!(
            registration.begin_drain(session_id, later_attempt),
            Err(CaptureRegistryError::DrainActive)
        ));
        drop(lease);
        let lease = registration.begin_drain(session_id, later_attempt).unwrap();
        connection
            .execute("INSERT INTO events VALUES (10)", [])
            .unwrap();
        let batch = lease.commit().unwrap();
        assert_eq!(batch.session_id(), session_id);
        assert_eq!(batch.attempt_id(), later_attempt);
        assert_eq!(batch.stream_id(), registration.stream_id());
        assert_eq!(batch.commits().len(), selected_count);
        assert!(!settle(&registration, 8, 11).commits().is_empty());
        assert!(matches!(
            registration.begin_drain(session_id, later_attempt),
            Err(CaptureRegistryError::AttemptAlreadySettled)
        ));
        drop(connection);
    }

    #[test]
    fn owned_exact_drain_restores_front_on_drop_and_retirement_scrubs_it() {
        let session_id = ShadowSessionId::from_bytes([81; 16]);
        let first_attempt = ShadowAttemptId::from_bytes([82; 16]);
        let second_attempt = ShadowAttemptId::from_bytes([83; 16]);
        let (_directory, c_path, registration, vfs) = setup();
        let connection = open(&c_path, vfs.vfs_name_for_test());
        wal_setup(&connection);
        let _ = settle(&registration, 81, 1);
        connection
            .execute("INSERT INTO events VALUES (81)", [])
            .unwrap();
        assert_eq!(registration.completed_len(), 1);

        let owned = registration
            .begin_exact_one_drain(session_id, first_attempt)
            .unwrap()
            .take_for_publication()
            .unwrap();
        assert_eq!(registration.completed_len(), 0);
        assert!(matches!(
            registration.begin_exact_one_drain(session_id, second_attempt),
            Err(CaptureRegistryError::DrainActive)
        ));
        drop(owned);
        assert_eq!(registration.completed_len(), 1);

        let owned = registration
            .begin_exact_one_drain(session_id, second_attempt)
            .unwrap()
            .take_for_publication()
            .unwrap();
        let state = Arc::clone(&registration.state);
        drop(registration);
        assert!(state.lock().unwrap().capture.is_scrubbed_for_test());
        drop(owned);
        let state = state.lock().unwrap();
        assert!(state.retired);
        assert!(state.capture.is_scrubbed_for_test());
        assert!(state.active_drain.is_none());
        drop(state);
        drop(connection);
    }

    #[test]
    fn retiring_a_connection_stream_invalidates_its_lease_and_restart_is_fresh() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("restart.db");
        let c_path = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        let registry = CaptureRegistry::new();
        let first = registry
            .register_exact(CaptureStreamId::from_test_bytes([21; 16]), &c_path)
            .unwrap();
        let first_stream = first.stream_id();
        let lease = first
            .begin_drain(
                ShadowSessionId::from_bytes([22; 16]),
                ShadowAttemptId::from_bytes([23; 16]),
            )
            .unwrap();
        drop(first);
        assert!(matches!(lease.commit(), Err(CaptureRegistryError::Retired)));

        let restarted = registry
            .register_exact(CaptureStreamId::from_test_bytes([24; 16]), &c_path)
            .unwrap();
        assert_ne!(restarted.stream_id(), first_stream);
        assert!(restarted
            .begin_drain(
                ShadowSessionId::from_bytes([22; 16]),
                ShadowAttemptId::from_bytes([23; 16]),
            )
            .unwrap()
            .commit()
            .unwrap()
            .commits()
            .is_empty());
    }

    #[test]
    fn settlement_history_has_an_exact_1024_attempt_cap() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("settlement-cap.db");
        let c_path = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        let registry = CaptureRegistry::new();
        let registration = registry
            .register_exact(CaptureStreamId::from_test_bytes([61; 16]), &c_path)
            .unwrap();
        let session_id = ShadowSessionId::from_bytes([62; 16]);

        for ordinal in 1..=MAX_CAPTURE_DRAINS_PER_STREAM {
            let mut attempt = [0u8; 16];
            attempt[8..].copy_from_slice(&(ordinal as u64).to_be_bytes());
            let batch = registration
                .begin_drain(session_id, ShadowAttemptId::from_bytes(attempt))
                .unwrap()
                .commit()
                .unwrap();
            assert!(batch.commits().is_empty());
        }
        let mut overflow_attempt = [0u8; 16];
        overflow_attempt[8..]
            .copy_from_slice(&((MAX_CAPTURE_DRAINS_PER_STREAM + 1) as u64).to_be_bytes());
        assert!(matches!(
            registration.begin_drain(session_id, ShadowAttemptId::from_bytes(overflow_attempt)),
            Err(CaptureRegistryError::TooManyDrains)
        ));
        let state = registration.state.lock().unwrap();
        assert_eq!(state.settled_drains.len(), MAX_CAPTURE_DRAINS_PER_STREAM);
        assert!(state.active_drain.is_none());
    }

    #[test]
    fn drain_token_overflow_fails_without_claiming_the_queue() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("token-overflow.db");
        let c_path = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        let registry = CaptureRegistry::new();
        let registration = registry
            .register_exact(CaptureStreamId::from_test_bytes([71; 16]), &c_path)
            .unwrap();
        registration.state.lock().unwrap().next_drain_token = u64::MAX;
        assert!(matches!(
            registration.begin_drain(
                ShadowSessionId::from_bytes([72; 16]),
                ShadowAttemptId::from_bytes([73; 16]),
            ),
            Err(CaptureRegistryError::StateUnavailable)
        ));
        let state = registration.state.lock().unwrap();
        assert_eq!(state.next_drain_token, u64::MAX);
        assert!(state.active_drain.is_none());
        assert!(state.settled_drains.is_empty());
        assert!(state.capture.is_scrubbed_for_test());
    }

    #[test]
    fn sqlite_wal_restart_truncate_starts_a_new_capture_generation() {
        let (_directory, c_path, registration, vfs) = setup();
        let connection = open(&c_path, vfs.vfs_name_for_test());
        wal_setup(&connection);
        let _ = settle(&registration, 4, 1);
        connection
            .execute("INSERT INTO events VALUES (10)", [])
            .unwrap();
        let before_restart = settle(&registration, 4, 2);
        assert!(!before_restart.commits().is_empty());
        let old_generation = before_restart.commits().last().unwrap().wal_generation();

        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        connection
            .execute("INSERT INTO events VALUES (11)", [])
            .unwrap();
        let after_restart = settle(&registration, 4, 3);
        assert!(!after_restart.commits().is_empty());
        assert!(after_restart
            .commits()
            .iter()
            .all(|commit| commit.wal_generation() > old_generation));
        assert_eq!(
            connection
                .query_row("SELECT sum(value) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            21
        );
        drop(connection);
    }

    #[test]
    fn sqlite_process_restart_after_recovered_checkpoint_advances_wal_generation() {
        let (directory, c_path, registration, capture) = setup();
        let connection = open(&c_path, capture.vfs_name_for_test());
        wal_setup(&connection);
        let _ = settle(&registration, 44, 1);
        connection
            .execute("INSERT INTO events VALUES (10)", [])
            .unwrap();
        let before_restart = settle(&registration, 44, 2);
        let recovered_generation = before_restart
            .commits()
            .last()
            .expect("the archived predecessor has a captured WAL commit")
            .wal_generation();

        // Recovery checkpoints the authenticated archived WAL into the main
        // database and removes both sidecars before a fresh process opens it.
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(connection);
        drop(registration);

        let path = directory.path().join("capture.db");
        let restarted = capture
            .register_path_after_generation_for_test(&path, recovered_generation)
            .unwrap();
        let restarted_connection = open(&c_path, capture.vfs_name_for_test());
        restarted_connection
            .execute("INSERT INTO events VALUES (11)", [])
            .unwrap();
        let after_restart = settle(&restarted, 45, 1);
        assert!(!after_restart.commits().is_empty());
        assert!(after_restart.commits().iter().all(|commit| {
            commit.wal_generation()
                == recovered_generation
                    .checked_add(1)
                    .expect("test WAL generation remains in range")
        }));
        assert_eq!(
            restarted_connection
                .query_row("SELECT sum(value) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            21
        );
    }

    #[test]
    fn recovered_generation_overflow_refuses_registration_without_retaining_state() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("generation-overflow.db");
        let c_path = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        let registry = CaptureRegistry::new();

        assert!(matches!(
            registry.register_after_generation(&c_path, u64::MAX),
            Err(CaptureRegistryError::StateUnavailable)
        ));
        assert!(registry.is_empty_for_test());
    }

    #[test]
    fn registration_retirement_is_bounded_and_does_not_change_sqlite_results() {
        let (directory, c_path, registration, vfs) = setup();
        let connection = open(&c_path, vfs.vfs_name_for_test());
        wal_setup(&connection);
        drop(registration);
        connection
            .execute("INSERT INTO events VALUES (9)", [])
            .unwrap();
        assert_eq!(
            connection
                .query_row("SELECT value FROM events", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            9
        );
        drop(connection);
        assert!(directory.path().join("capture.db").exists());
    }

    #[test]
    fn retirement_scrubs_pending_capture_and_live_connection_cannot_repopulate_it() {
        let (_directory, c_path, registration, vfs) = setup();
        let connection = open(&c_path, vfs.vfs_name_for_test());
        wal_setup(&connection);
        let _ = settle(&registration, 51, 1);
        connection
            .execute("INSERT INTO events VALUES (51)", [])
            .unwrap();
        let state = Arc::clone(&registration.state);
        let lease = registration
            .begin_drain(
                ShadowSessionId::from_bytes([51; 16]),
                ShadowAttemptId::from_bytes([52; 16]),
            )
            .unwrap();
        {
            let state = state.lock().unwrap();
            assert!(!state.capture.is_scrubbed_for_test());
            assert!(state.active_drain.is_some());
        }

        // The connection and its FileCapture Arc remain live, as does the
        // outstanding lease. Registration retirement must nevertheless scrub
        // all WAL plaintext and invalidate both mutation paths atomically.
        drop(registration);
        {
            let state = state.lock().unwrap();
            assert!(state.retired);
            assert!(state.capture.is_scrubbed_for_test());
            assert!(state.active_drain.is_none());
            assert!(state.settled_drains.is_empty());
            assert_eq!(state.next_drain_token, 0);
        }
        assert!(matches!(lease.commit(), Err(CaptureRegistryError::Retired)));

        connection
            .execute("INSERT INTO events VALUES (52)", [])
            .unwrap();
        assert_eq!(
            connection
                .query_row("SELECT sum(value) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            103
        );
        let state = state.lock().unwrap();
        assert!(state.retired);
        assert!(state.capture.is_scrubbed_for_test());
        assert!(state.active_drain.is_none());
        assert!(state.settled_drains.is_empty());
    }

    #[test]
    fn dropping_vfs_handle_keeps_live_connection_callback_memory_safe() {
        let (directory, c_path, _registration, vfs) = setup_owned_vfs();
        let connection = open(&c_path, vfs.name());
        wal_setup(&connection);
        drop(vfs);

        let attached = directory.path().join("attached.db");
        connection
            .execute("ATTACH DATABASE ?1 AS later", [attached.to_string_lossy()])
            .unwrap();
        connection
            .execute_batch(
                "CREATE TABLE later.items(value INTEGER); INSERT INTO later.items VALUES (17);",
            )
            .unwrap();
        assert_eq!(
            connection
                .query_row("SELECT value FROM later.items", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            17
        );
    }

    #[test]
    fn parent_io_version_and_wal_callbacks_must_be_compatible() {
        assert!(parent_io_is_compatible(&WRAPPED_IO_METHODS));

        // SAFETY: sqlite3_io_methods contains only integers and function
        // pointers and has no destructor. These independent copies are used
        // only by this test.
        let mut older = unsafe { ptr::read(&WRAPPED_IO_METHODS) };
        older.iVersion = 2;
        assert!(!parent_io_is_compatible(&older));

        // SAFETY: same plain callback-table copy rationale as above.
        let mut missing_required_write = unsafe { ptr::read(&WRAPPED_IO_METHODS) };
        missing_required_write.xWrite = None;
        assert!(!parent_io_is_compatible(&missing_required_write));
    }

    #[test]
    fn failed_parent_wal_callbacks_preserve_exact_code_and_shadow_state() {
        let (mut write_file, write_state) = synthetic_failed_file();
        let byte = 7u8;
        let write_code = unsafe {
            io_write(
                ptr::addr_of_mut!(write_file.base),
                ptr::addr_of!(byte).cast(),
                1,
                crate::archive_v3_shadow::MAX_SHADOW_WAL_BYTES as i64,
            )
        };
        assert_eq!(write_code, ffi::SQLITE_IOERR_WRITE);
        assert_eq!(
            write_state.lock().unwrap().capture.metrics(),
            ShadowCaptureMetrics::default()
        );

        let (mut sync_file, sync_state) = synthetic_failed_file();
        sync_state
            .lock()
            .unwrap()
            .capture
            .observe_write(0, &[0; 32]);
        let sync_code = unsafe { io_sync(ptr::addr_of_mut!(sync_file.base), 0) };
        assert_eq!(sync_code, ffi::SQLITE_IOERR_FSYNC);
        assert_eq!(
            sync_state.lock().unwrap().capture.metrics(),
            ShadowCaptureMetrics::default()
        );

        let (mut truncate_file, truncate_state) = synthetic_failed_file();
        truncate_state
            .lock()
            .unwrap()
            .capture
            .observe_write(0, &[0; 32]);
        let truncate_code = unsafe { io_truncate(ptr::addr_of_mut!(truncate_file.base), 0) };
        assert_eq!(truncate_code, ffi::SQLITE_IOERR_TRUNCATE);
        assert_eq!(
            truncate_state.lock().unwrap().capture.observe_sync(true),
            crate::archive_v3_shadow::ShadowSyncOutcome::Dropped(
                crate::archive_v3_shadow::ShadowCaptureFault::MalformedWal
            )
        );
    }
}
