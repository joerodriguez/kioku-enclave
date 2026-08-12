#![allow(
    dead_code,
    reason = "inactive ADR-0022 shadow-parity verifier is compiled and fake-tested before any runtime authority wiring"
)]

//! Inactive ADR-0022 logical shadow-parity verification.
//!
//! This module compares two explicitly prepared, private SQLite staging copies.
//! It owns no [`crate::store::Store`], VFS, route, provider, credential,
//! scheduler, feature flag, publication, recovery, deletion, or cutover
//! authority. A parity match is advisory evidence only and never authorizes a
//! storage transition.
//!
//! Normal inspection uses independent `SQLITE_OPEN_READ_ONLY` connections.
//! SQLite exposes FTS5's no-op external-content integrity command only as an
//! `INSERT`, which read-only/query-only handles reject before FTS5 sees it.
//! Therefore the public seam accepts only [`PrivateStagedSqliteCopy`] values;
//! a private helper opens those disposable copies read-write solely for six
//! fixed FTS commands. It accepts no caller SQL and verifies the expected FTS5
//! virtual-table/source binding before each command. This inactive release has
//! no non-test constructor for the staging capability, so original/live paths
//! cannot reach the write path. Future recovery wiring must mint it only while
//! creating and owning a fresh private copy.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use rusqlite::{types::ValueRef, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::cp::sync::{
    canonical_logical_export_stream_digest_guarded, CANONICAL_LOGICAL_EXPORT_VERSION,
};

const MAX_STAGED_DATABASE_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_INTEGRITY_MESSAGES: usize = 16;
const MAX_INTEGRITY_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_SCHEMA_ENTRIES: u64 = 2_048;
const MAX_SCHEMA_NAME_BYTES: usize = 256;
const MAX_SCHEMA_SQL_BYTES: usize = 256 * 1024;
const MAX_SCHEMA_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOGICAL_TABLES: usize = 512;
const MAX_LOGICAL_COLUMNS: usize = 256;
const MAX_LOGICAL_ROWS_PER_TABLE: u64 = 2_000_000;
const MAX_LOGICAL_ROWS: u64 = 10_000_000;
const MAX_LOGICAL_FIELD_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOGICAL_ROW_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LOGICAL_TOTAL_BYTES: u64 = 40 * 1024 * 1024 * 1024;
const MAX_VECTOR_ROWS_PER_TABLE: u64 = 2_000_000;
const ENCODED_VECTOR_BYTES: usize = 384 * std::mem::size_of::<f32>();
const MAX_SELECTED_QUERY_ROWS: usize = 64;
const MAX_SELECTED_QUERY_VALUE_BYTES: usize = 64 * 1024;
const MAX_SELECTED_QUERY_DIGEST_BYTES: usize = 1024 * 1024;

const TABLE_COUNT_DOMAIN: &[u8] = b"kioku.adr0022.shadow-parity.table-counts\0";
const FULL_LOGICAL_DOMAIN: &[u8] = b"kioku.adr0022.shadow-parity.full-logical\0";
const VECTOR_DOMAIN: &[u8] = b"kioku.adr0022.shadow-parity.vectors\0";
const QUERY_DIGEST_DOMAIN: &[u8] = b"kioku.adr0022.shadow-parity.selected-queries\0";

/// Fixed diagnostic table-count order. The full logical gate below also
/// streams every ordinary live table and is the completeness authority.
const COUNTED_TABLES: &[&str] = &[
    "app_metadata",
    "audio_segments",
    "utterances",
    "screenshots",
    "screenshot_images",
    "episodes",
    "episode_final_briefs",
    "episode_members",
    "browser_snapshots",
    "browser_tabs",
    "screen_links",
    "screen_observation_jobs",
    "screen_observations",
    "episode_screen_interpretation_jobs",
    "episode_screen_interpretations",
    "capture_sessions",
    "capture_streams",
    "capture_events",
    "media_objects",
    "speaker_observations",
    "people",
    "voice_profiles",
    "voice_samples",
    "mcp_projection_jobs",
    "mcp_safe_utterances",
    "mcp_safe_screenshots",
    "mcp_safe_episodes",
    "vertex_usage_events",
    "vertex_usage_coverage",
    "webhook_deliveries",
    "email_deliveries",
    "push_deliveries",
    "device_watermarks",
    "vec_utterances",
    "vec_screenshots",
    "vec_episodes",
];

const FTS_TABLES: &[FtsSpec] = &[
    FtsSpec::required(
        "utterances_fts",
        "utterances",
        "usingfts5(text,content='utterances',content_rowid='id')",
    ),
    FtsSpec::required(
        "screenshots_fts",
        "screenshots",
        "usingfts5(ocr_text,content='screenshots',content_rowid='id')",
    ),
    FtsSpec::required(
        "episodes_fts",
        "episodes",
        "usingfts5(title,summary,minutes_text,content='episodes',content_rowid='id')",
    ),
    FtsSpec::optional(
        "mcp_utterances_fts",
        "mcp_safe_utterances",
        "usingfts5(sanitized_text,content='mcp_safe_utterances',content_rowid='id')",
    ),
    FtsSpec::optional(
        "mcp_screenshots_fts",
        "mcp_safe_screenshots",
        "usingfts5(sanitized_ocr,content='mcp_safe_screenshots',content_rowid='id')",
    ),
    FtsSpec::optional(
        "mcp_episodes_fts",
        "mcp_safe_episodes",
        "usingfts5(sanitized_title,sanitized_summary,content='mcp_safe_episodes',content_rowid='id')",
    ),
];

const VECTOR_TABLES: &[VectorSpec] = &[
    VectorSpec::new("vec_utterances", "utterances", "utterance_id"),
    VectorSpec::new("vec_screenshots", "screenshots", "screenshot_id"),
    VectorSpec::new("vec_episodes", "episodes", "episode_id"),
];

/// Fixed bounded probes are diagnostic only. Full parity is established by
/// `full_logical_database_digest`, which streams every ordinary table row.
const SELECTED_QUERIES: &[SelectedQuery] = &[
    SelectedQuery::new(
        "audio_segments",
        "SELECT id, started_at, ended_at, source_type FROM audio_segments ORDER BY id LIMIT ?1",
    ),
    SelectedQuery::new(
        "utterances",
        "SELECT id, audio_segment_id, start_offset_seconds, end_offset_seconds, text FROM utterances ORDER BY id LIMIT ?1",
    ),
    SelectedQuery::new(
        "screenshots",
        "SELECT id, captured_at, ocr_text FROM screenshots ORDER BY id LIMIT ?1",
    ),
    SelectedQuery::new(
        "episodes",
        "SELECT id, started_at, ended_at, title, summary FROM episodes ORDER BY id LIMIT ?1",
    ),
];

#[derive(Clone, Copy)]
struct FtsSpec {
    table: &'static str,
    source: &'static str,
    normalized_signature: &'static str,
    always_required: bool,
}

impl FtsSpec {
    const fn required(
        table: &'static str,
        source: &'static str,
        normalized_signature: &'static str,
    ) -> Self {
        Self {
            table,
            source,
            normalized_signature,
            always_required: true,
        }
    }

    const fn optional(
        table: &'static str,
        source: &'static str,
        normalized_signature: &'static str,
    ) -> Self {
        Self {
            table,
            source,
            normalized_signature,
            always_required: false,
        }
    }
}

#[derive(Clone, Copy)]
struct VectorSpec {
    table: &'static str,
    source: &'static str,
    key: &'static str,
}

impl VectorSpec {
    const fn new(table: &'static str, source: &'static str, key: &'static str) -> Self {
        Self { table, source, key }
    }
}

struct SelectedQuery {
    table: &'static str,
    sql: &'static str,
}

impl SelectedQuery {
    const fn new(table: &'static str, sql: &'static str) -> Self {
        Self { table, sql }
    }
}

/// Fixed check classes contain no path, archive identity, SQL, row id, or
/// plaintext and are safe for aggregate operator-visible rollout events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShadowParityCheck {
    DatabaseIntegrity,
    FtsIntegrity,
    VectorContents,
    TableCounts,
    LogicalExport,
    FullLogicalDatabase,
    SelectedQueries,
}

/// Typed and deliberately redacted verifier failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShadowParityError {
    InvalidStagedCopy,
    SameStagedCopy,
    DatabaseOpen,
    Cancelled,
    DeadlineExceeded,
    DatabaseRead(ShadowParityCheck),
}

impl fmt::Display for ShadowParityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStagedCopy => f.write_str("invalid private SQLite staging copy"),
            Self::SameStagedCopy => f.write_str("parity inputs are not independent copies"),
            Self::DatabaseOpen => f.write_str("shadow parity database unavailable"),
            Self::Cancelled => f.write_str("shadow parity cancelled"),
            Self::DeadlineExceeded => f.write_str("shadow parity deadline exceeded"),
            Self::DatabaseRead(check) => write!(f, "shadow parity check failed: {check:?}"),
        }
    }
}

impl std::error::Error for ShadowParityError {}

#[derive(Clone, Copy, PartialEq, Eq)]
struct StagedIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

/// Explicit capability for an owner-private, writable, disposable SQLite
/// staging copy. The caller must create it independently from the live Store
/// path and retain exclusive ownership for the complete comparison. The type
/// rejects symlinks, hard links, non-files, group/world permission bits,
/// oversized files, and later identity/size/mtime changes.
pub(crate) struct PrivateStagedSqliteCopy {
    path: PathBuf,
    identity: StagedIdentity,
}

impl PrivateStagedSqliteCopy {
    #[cfg(test)]
    pub(crate) fn new(path: PathBuf) -> Result<Self, ShadowParityError> {
        let identity = staged_identity(&path)?;
        Ok(Self { path, identity })
    }

    fn validate_unchanged(&self) -> Result<(), ShadowParityError> {
        if staged_identity(&self.path)? != self.identity {
            return Err(ShadowParityError::InvalidStagedCopy);
        }
        Ok(())
    }
}

impl fmt::Debug for PrivateStagedSqliteCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateStagedSqliteCopy(<redacted>)")
    }
}

#[cfg(unix)]
fn staged_identity(path: &Path) -> Result<StagedIdentity, ShadowParityError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ShadowParityError::InvalidStagedCopy)?;
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_STAGED_DATABASE_BYTES
        || metadata.nlink() != 1
        || mode & 0o077 != 0
        || mode & 0o200 == 0
    {
        return Err(ShadowParityError::InvalidStagedCopy);
    }
    Ok(StagedIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

#[cfg(not(unix))]
fn staged_identity(_path: &Path) -> Result<StagedIdentity, ShadowParityError> {
    // The attested image and supported developer environment are Unix. A new
    // platform must define an equivalent private-copy/file-identity proof.
    Err(ShadowParityError::InvalidStagedCopy)
}

/// Cancellation and deadline are explicit even though this seam is inactive.
/// Checks occur between tables/rows and immediately before and after SQLite's
/// synchronous `integrity_check`; SQLite does not expose a bounded-work pragma,
/// so a future runtime must run the verifier on a separately cancellable task.
pub(crate) struct ShadowParityRunControl<'a> {
    deadline: Instant,
    cancelled: &'a AtomicBool,
}

impl<'a> ShadowParityRunControl<'a> {
    pub(crate) const fn new(deadline: Instant, cancelled: &'a AtomicBool) -> Self {
        Self {
            deadline,
            cancelled,
        }
    }

    fn check(&self) -> Result<(), ShadowParityError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ShadowParityError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ShadowParityError::DeadlineExceeded);
        }
        Ok(())
    }

    fn active(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire) && Instant::now() < self.deadline
    }
}

/// Digest bytes remain comparable in-process but never render in diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpaqueParityDigest([u8; 32]);

impl fmt::Debug for OpaqueParityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueParityDigest(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShadowParityDigests {
    logical_export: OpaqueParityDigest,
    full_logical_database: OpaqueParityDigest,
    vectors: OpaqueParityDigest,
    table_counts: OpaqueParityDigest,
    selected_queries: OpaqueParityDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ShadowParityResult {
    Match(ShadowParityDigests),
    Mismatch(Vec<ShadowParityCheck>),
}

pub(crate) struct ShadowParityVerifier;

impl ShadowParityVerifier {
    pub(crate) fn compare_staged_copies(
        primary: &PrivateStagedSqliteCopy,
        shadow: &PrivateStagedSqliteCopy,
        control: &ShadowParityRunControl<'_>,
    ) -> Result<ShadowParityResult, ShadowParityError> {
        control.check()?;
        primary.validate_unchanged()?;
        shadow.validate_unchanged()?;
        if primary.identity.device == shadow.identity.device
            && primary.identity.inode == shadow.identity.inode
        {
            return Err(ShadowParityError::SameStagedCopy);
        }

        crate::store::init_vec_extension();
        let primary_conn = open_read_only(&primary.path)?;
        let shadow_conn = open_read_only(&shadow.path)?;
        let primary_snapshot = snapshot(&primary_conn, primary, control)?;
        let shadow_snapshot = snapshot(&shadow_conn, shadow, control)?;
        primary.validate_unchanged()?;
        shadow.validate_unchanged()?;

        let mut mismatches = Vec::new();
        compare_digest(
            primary_snapshot.table_counts,
            shadow_snapshot.table_counts,
            ShadowParityCheck::TableCounts,
            &mut mismatches,
        );
        compare_digest(
            primary_snapshot.vectors,
            shadow_snapshot.vectors,
            ShadowParityCheck::VectorContents,
            &mut mismatches,
        );
        compare_digest(
            primary_snapshot.logical_export,
            shadow_snapshot.logical_export,
            ShadowParityCheck::LogicalExport,
            &mut mismatches,
        );
        compare_digest(
            primary_snapshot.full_logical_database,
            shadow_snapshot.full_logical_database,
            ShadowParityCheck::FullLogicalDatabase,
            &mut mismatches,
        );
        compare_digest(
            primary_snapshot.selected_queries,
            shadow_snapshot.selected_queries,
            ShadowParityCheck::SelectedQueries,
            &mut mismatches,
        );

        if mismatches.is_empty() {
            Ok(ShadowParityResult::Match(ShadowParityDigests {
                logical_export: primary_snapshot.logical_export,
                full_logical_database: primary_snapshot.full_logical_database,
                vectors: primary_snapshot.vectors,
                table_counts: primary_snapshot.table_counts,
                selected_queries: primary_snapshot.selected_queries,
            }))
        } else {
            Ok(ShadowParityResult::Mismatch(mismatches))
        }
    }
}

fn compare_digest(
    primary: OpaqueParityDigest,
    shadow: OpaqueParityDigest,
    check: ShadowParityCheck,
    mismatches: &mut Vec<ShadowParityCheck>,
) {
    if primary != shadow {
        mismatches.push(check);
    }
}

struct Snapshot {
    table_counts: OpaqueParityDigest,
    logical_export: OpaqueParityDigest,
    full_logical_database: OpaqueParityDigest,
    vectors: OpaqueParityDigest,
    selected_queries: OpaqueParityDigest,
}

fn open_read_only(staged_path: &Path) -> Result<Connection, ShadowParityError> {
    let conn = Connection::open_with_flags(
        staged_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ShadowParityError::DatabaseOpen)?;
    conn.execute_batch("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;")
        .map_err(|_| ShadowParityError::DatabaseOpen)?;
    Ok(conn)
}

fn snapshot(
    conn: &Connection,
    staged: &PrivateStagedSqliteCopy,
    control: &ShadowParityRunControl<'_>,
) -> Result<Snapshot, ShadowParityError> {
    check_database_integrity(conn, control)?;
    check_fts_integrity(staged, control)?;
    let vectors = vector_contents_digest(conn, control)?;
    let table_counts = table_count_digest(conn, control)?;
    control.check()?;
    let logical_export_result =
        canonical_logical_export_stream_digest_guarded(conn, || control.active());
    let logical_export = OpaqueParityDigest(match logical_export_result {
        Ok(digest) => digest,
        Err(_) => {
            control.check()?;
            return Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::LogicalExport,
            ));
        }
    });
    control.check()?;
    let full_logical_database = full_logical_database_digest(conn, control)?;
    let selected_queries = selected_query_digest(conn, control)?;
    Ok(Snapshot {
        table_counts,
        logical_export,
        full_logical_database,
        vectors,
        selected_queries,
    })
}

fn check_database_integrity(
    conn: &Connection,
    control: &ShadowParityRunControl<'_>,
) -> Result<(), ShadowParityError> {
    control.check()?;
    let mut statement = conn
        .prepare("PRAGMA integrity_check(16)")
        .map_err(|_| ShadowParityError::DatabaseRead(ShadowParityCheck::DatabaseIntegrity))?;
    let mut rows = statement
        .query([])
        .map_err(|_| ShadowParityError::DatabaseRead(ShadowParityCheck::DatabaseIntegrity))?;
    let mut count = 0_usize;
    let mut saw_ok = false;
    while let Some(row) = rows
        .next()
        .map_err(|_| ShadowParityError::DatabaseRead(ShadowParityCheck::DatabaseIntegrity))?
    {
        control.check()?;
        count += 1;
        if count > MAX_INTEGRITY_MESSAGES {
            return Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::DatabaseIntegrity,
            ));
        }
        let ValueRef::Text(message) = row
            .get_ref(0)
            .map_err(|_| ShadowParityError::DatabaseRead(ShadowParityCheck::DatabaseIntegrity))?
        else {
            return Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::DatabaseIntegrity,
            ));
        };
        if message.len() > MAX_INTEGRITY_MESSAGE_BYTES || message != b"ok" || saw_ok {
            return Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::DatabaseIntegrity,
            ));
        }
        saw_ok = true;
    }
    control.check()?;
    if !saw_ok || count != 1 {
        return Err(ShadowParityError::DatabaseRead(
            ShadowParityCheck::DatabaseIntegrity,
        ));
    }
    Ok(())
}

fn check_fts_integrity(
    staged: &PrivateStagedSqliteCopy,
    control: &ShadowParityRunControl<'_>,
) -> Result<(), ShadowParityError> {
    staged.validate_unchanged()?;
    let conn = Connection::open_with_flags(
        &staged.path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ShadowParityError::DatabaseRead(ShadowParityCheck::FtsIntegrity))?;
    conn.execute_batch("PRAGMA trusted_schema = OFF;")
        .map_err(|_| ShadowParityError::DatabaseRead(ShadowParityCheck::FtsIntegrity))?;

    for spec in FTS_TABLES {
        control.check()?;
        let source_exists = table_exists(&conn, spec.source, ShadowParityCheck::FtsIntegrity)?;
        let expected = spec.always_required || source_exists;
        let schema = schema_entry(&conn, spec.table, ShadowParityCheck::FtsIntegrity)?;
        match (expected, schema) {
            (true, Some((entry_type, sql))) => {
                if !source_exists || !valid_external_fts_schema(&entry_type, &sql, *spec) {
                    return Err(ShadowParityError::DatabaseRead(
                        ShadowParityCheck::FtsIntegrity,
                    ));
                }
                let command = format!(
                    "INSERT INTO {}({}, rank) VALUES('integrity-check', 1)",
                    spec.table, spec.table
                );
                conn.execute(&command, []).map_err(|_| {
                    ShadowParityError::DatabaseRead(ShadowParityCheck::FtsIntegrity)
                })?;
            }
            (false, None) if !fts_shadow_present(&conn, *spec)? => {}
            _ => {
                return Err(ShadowParityError::DatabaseRead(
                    ShadowParityCheck::FtsIntegrity,
                ));
            }
        }
    }
    drop(conn);
    staged.validate_unchanged()?;
    Ok(())
}

fn valid_external_fts_schema(entry_type: &str, sql: &str, spec: FtsSpec) -> bool {
    if entry_type != "table" || sql.len() > MAX_SCHEMA_SQL_BYTES {
        return false;
    }
    let Some(normalized) = normalize_strict_virtual_table_sql(sql) else {
        return false;
    };
    normalized
        == format!(
            "createvirtualtable{}{}",
            spec.table, spec.normalized_signature
        )
        || normalized
            == format!(
                "createvirtualtableifnotexists{}{}",
                spec.table, spec.normalized_signature
            )
}

fn fts_shadow_present(conn: &Connection, spec: FtsSpec) -> Result<bool, ShadowParityError> {
    for suffix in ["data", "idx", "content", "docsize", "config"] {
        let name = format!("{}_{}", spec.table, suffix);
        if table_exists(conn, &name, ShadowParityCheck::FtsIntegrity)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn vector_contents_digest(
    conn: &Connection,
    control: &ShadowParityRunControl<'_>,
) -> Result<OpaqueParityDigest, ShadowParityError> {
    let check = ShadowParityCheck::VectorContents;
    let mut hasher = Sha256::new();
    hasher.update(VECTOR_DOMAIN);
    hasher.update(CANONICAL_LOGICAL_EXPORT_VERSION.to_be_bytes());
    for spec in VECTOR_TABLES {
        control.check()?;
        if !table_exists(conn, spec.source, check)? || !table_exists(conn, spec.table, check)? {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        let Some((entry_type, schema_sql)) = schema_entry(conn, spec.table, check)? else {
            return Err(ShadowParityError::DatabaseRead(check));
        };
        if entry_type != "table" || !valid_vector_schema(&schema_sql, *spec) {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        hash_len_prefixed(&mut hasher, spec.table.as_bytes());
        hash_len_prefixed(&mut hasher, schema_sql.as_bytes());
        hash_table_xinfo(conn, spec.table, &mut hasher, check)?;

        let count_sql = format!("SELECT count(*) FROM {}", spec.table);
        let source_count_sql = format!("SELECT count(*) FROM {}", spec.source);
        let count: i64 = conn
            .query_row(&count_sql, [], |row| row.get(0))
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let source_count: i64 = conn
            .query_row(&source_count_sql, [], |row| row.get(0))
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let orphan_sql = format!(
            "SELECT count(*) FROM {} AS vectors LEFT JOIN {} AS source \
             ON source.id = vectors.{} WHERE source.id IS NULL",
            spec.table, spec.source, spec.key
        );
        let orphans: i64 = conn
            .query_row(&orphan_sql, [], |row| row.get(0))
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        if count < 0
            || source_count < 0
            || orphans != 0
            || count > source_count
            || count as u64 > MAX_VECTOR_ROWS_PER_TABLE
        {
            return Err(ShadowParityError::DatabaseRead(check));
        }

        let query = format!(
            "SELECT {}, embedding FROM {} ORDER BY {}",
            spec.key, spec.table, spec.key
        );
        let mut statement = conn
            .prepare(&query)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let mut rows = statement
            .query([])
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let mut streamed = 0_u64;
        let mut previous_id = None;
        while let Some(row) = rows
            .next()
            .map_err(|_| ShadowParityError::DatabaseRead(check))?
        {
            control.check()?;
            streamed += 1;
            if streamed > MAX_VECTOR_ROWS_PER_TABLE {
                return Err(ShadowParityError::DatabaseRead(check));
            }
            let id: i64 = row
                .get(0)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?;
            if previous_id.is_some_and(|previous| id <= previous) {
                return Err(ShadowParityError::DatabaseRead(check));
            }
            previous_id = Some(id);
            let ValueRef::Blob(vector) = row
                .get_ref(1)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?
            else {
                return Err(ShadowParityError::DatabaseRead(check));
            };
            if vector.len() != ENCODED_VECTOR_BYTES {
                return Err(ShadowParityError::DatabaseRead(check));
            }
            hasher.update(id.to_be_bytes());
            hash_len_prefixed(&mut hasher, vector);
        }
        if streamed != count as u64 {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        hasher.update(streamed.to_be_bytes());
    }
    Ok(OpaqueParityDigest(hasher.finalize().into()))
}

fn valid_vector_schema(sql: &str, spec: VectorSpec) -> bool {
    if sql.len() > MAX_SCHEMA_SQL_BYTES {
        return false;
    }
    let Some(normalized) = normalize_strict_virtual_table_sql(sql) else {
        return false;
    };
    let body = format!(
        "{}usingvec0({}integerprimarykey,embeddingfloat[384]distance_metric=cosine)",
        spec.table, spec.key
    );
    normalized == format!("createvirtualtable{body}")
        || normalized == format!("createvirtualtableifnotexists{body}")
}

/// Canonicalize only the deliberately tiny virtual-table DDL grammar used by
/// Kioku. SQLite has already parsed the statement, but exact comparison still
/// rejects comments, quoted identifiers, escapes, trailing clauses, unknown
/// options, and any punctuation absent from the approved FTS5/vec0 forms.
fn normalize_strict_virtual_table_sql(sql: &str) -> Option<String> {
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    while let Some(character) = characters.next() {
        if character.is_ascii_whitespace() {
            continue;
        }
        if character.is_ascii_alphanumeric() || character == '_' {
            normalized.push(character.to_ascii_lowercase());
            continue;
        }
        if matches!(character, '(' | ')' | ',' | '=' | '[' | ']') {
            normalized.push(character);
            continue;
        }
        if character == '\'' {
            normalized.push(character);
            let mut closed = false;
            for quoted in characters.by_ref() {
                if quoted == '\'' {
                    closed = true;
                    normalized.push(quoted);
                    break;
                }
                if !(quoted.is_ascii_alphanumeric() || quoted == '_') {
                    return None;
                }
                normalized.push(quoted.to_ascii_lowercase());
            }
            if !closed {
                return None;
            }
            continue;
        }
        if character == ';' && characters.all(|remaining| remaining.is_ascii_whitespace()) {
            break;
        }
        return None;
    }
    (!normalized.is_empty()).then_some(normalized)
}

fn hash_table_xinfo(
    conn: &Connection,
    table: &str,
    hasher: &mut Sha256,
    check: ShadowParityCheck,
) -> Result<(), ShadowParityError> {
    let quoted = quote_identifier(table, check)?;
    let mut statement = conn
        .prepare(&format!("PRAGMA table_xinfo({quoted})"))
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut rows = statement
        .query([])
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut count = 0_usize;
    while let Some(row) = rows
        .next()
        .map_err(|_| ShadowParityError::DatabaseRead(check))?
    {
        count += 1;
        if count > MAX_LOGICAL_COLUMNS {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        for index in 0..7 {
            let value = row
                .get_ref(index)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?;
            hash_value(&mut *hasher, value, MAX_SCHEMA_SQL_BYTES, check)?;
        }
    }
    if count == 0 {
        return Err(ShadowParityError::DatabaseRead(check));
    }
    hasher.update((count as u64).to_be_bytes());
    Ok(())
}

fn table_count_digest(
    conn: &Connection,
    control: &ShadowParityRunControl<'_>,
) -> Result<OpaqueParityDigest, ShadowParityError> {
    let check = ShadowParityCheck::TableCounts;
    let mut hasher = Sha256::new();
    hasher.update(TABLE_COUNT_DOMAIN);
    hasher.update(CANONICAL_LOGICAL_EXPORT_VERSION.to_be_bytes());
    for table in COUNTED_TABLES {
        control.check()?;
        hash_len_prefixed(&mut hasher, table.as_bytes());
        let exists = table_exists(conn, table, check)?;
        hasher.update([u8::from(exists)]);
        if exists {
            let sql = format!("SELECT count(*) FROM {table}");
            let count: i64 = conn
                .query_row(&sql, [], |row| row.get(0))
                .map_err(|_| ShadowParityError::DatabaseRead(check))?;
            if count < 0 {
                return Err(ShadowParityError::DatabaseRead(check));
            }
            hasher.update((count as u64).to_be_bytes());
        }
    }
    Ok(OpaqueParityDigest(hasher.finalize().into()))
}

fn full_logical_database_digest(
    conn: &Connection,
    control: &ShadowParityRunControl<'_>,
) -> Result<OpaqueParityDigest, ShadowParityError> {
    let check = ShadowParityCheck::FullLogicalDatabase;
    let mut hasher = Sha256::new();
    hasher.update(FULL_LOGICAL_DOMAIN);
    hasher.update(CANONICAL_LOGICAL_EXPORT_VERSION.to_be_bytes());
    let mut schema_bytes = 0_u64;
    let mut schema_entries = 0_u64;
    let mut statement = conn
        .prepare(
            "SELECT type, name, COALESCE(sql, '') FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY type, name",
        )
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut rows = statement
        .query([])
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    while let Some(row) = rows
        .next()
        .map_err(|_| ShadowParityError::DatabaseRead(check))?
    {
        control.check()?;
        schema_entries += 1;
        if schema_entries > MAX_SCHEMA_ENTRIES {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        for index in 0..3 {
            let ValueRef::Text(value) = row
                .get_ref(index)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?
            else {
                return Err(ShadowParityError::DatabaseRead(check));
            };
            let limit = if index == 2 {
                MAX_SCHEMA_SQL_BYTES
            } else {
                MAX_SCHEMA_NAME_BYTES
            };
            if value.len() > limit {
                return Err(ShadowParityError::DatabaseRead(check));
            }
            schema_bytes = schema_bytes.saturating_add(value.len() as u64);
            if schema_bytes > MAX_SCHEMA_TOTAL_BYTES {
                return Err(ShadowParityError::DatabaseRead(check));
            }
            hash_len_prefixed(&mut hasher, value);
        }
    }
    hasher.update(schema_entries.to_be_bytes());
    drop(rows);
    drop(statement);

    let tables = ordinary_logical_tables(conn, control)?;
    let mut budget = LogicalBudget::default();
    for table in tables {
        control.check()?;
        stream_ordinary_table(conn, &table, &mut hasher, &mut budget, control)?;
    }
    Ok(OpaqueParityDigest(hasher.finalize().into()))
}

fn ordinary_logical_tables(
    conn: &Connection,
    control: &ShadowParityRunControl<'_>,
) -> Result<Vec<String>, ShadowParityError> {
    let check = ShadowParityCheck::FullLogicalDatabase;
    let mut statement = conn
        .prepare(
            "SELECT name, COALESCE(sql, '') FROM sqlite_schema WHERE type='table' ORDER BY name",
        )
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut rows = statement
        .query([])
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut tables = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| ShadowParityError::DatabaseRead(check))?
    {
        control.check()?;
        let name: String = row
            .get(0)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let sql: String = row
            .get(1)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        if name.len() > MAX_SCHEMA_NAME_BYTES || sql.len() > MAX_SCHEMA_SQL_BYTES {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        if name.starts_with("sqlite_") && name != "sqlite_sequence" {
            continue;
        }
        if is_known_virtual_table(&name) || is_known_virtual_shadow(&name) {
            continue;
        }
        if normalize_sql(&sql).starts_with("createvirtualtable") {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        tables.push(name);
        if tables.len() > MAX_LOGICAL_TABLES {
            return Err(ShadowParityError::DatabaseRead(check));
        }
    }
    Ok(tables)
}

fn is_known_virtual_table(name: &str) -> bool {
    FTS_TABLES.iter().any(|spec| spec.table == name)
        || VECTOR_TABLES.iter().any(|spec| spec.table == name)
}

fn is_known_virtual_shadow(name: &str) -> bool {
    FTS_TABLES.iter().any(|spec| {
        ["data", "idx", "content", "docsize", "config"]
            .iter()
            .any(|suffix| name == format!("{}_{}", spec.table, suffix))
    }) || VECTOR_TABLES.iter().any(|spec| {
        let Some(suffix) = name
            .strip_prefix(spec.table)
            .and_then(|value| value.strip_prefix('_'))
        else {
            return false;
        };
        matches!(suffix, "info" | "chunks" | "rowids")
            || suffix
                .strip_prefix("vector_chunks")
                .is_some_and(two_ascii_digits)
            || suffix
                .strip_prefix("metadatachunks")
                .is_some_and(two_ascii_digits)
    })
}

fn two_ascii_digits(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Default)]
struct LogicalBudget {
    rows: u64,
    bytes: u64,
}

#[derive(Clone)]
struct LogicalColumn {
    name: String,
    declaration: String,
    not_null: i64,
    default_value: Option<String>,
    primary_key: i64,
    hidden: i64,
}

fn stream_ordinary_table(
    conn: &Connection,
    table: &str,
    hasher: &mut Sha256,
    budget: &mut LogicalBudget,
    control: &ShadowParityRunControl<'_>,
) -> Result<(), ShadowParityError> {
    let check = ShadowParityCheck::FullLogicalDatabase;
    let columns = logical_columns(conn, table)?;
    if columns.is_empty() || columns.len() > MAX_LOGICAL_COLUMNS {
        return Err(ShadowParityError::DatabaseRead(check));
    }
    hash_len_prefixed(hasher, table.as_bytes());
    for column in &columns {
        hash_len_prefixed(hasher, column.name.as_bytes());
        hash_len_prefixed(hasher, column.declaration.as_bytes());
        hasher.update(column.not_null.to_be_bytes());
        match &column.default_value {
            Some(value) => {
                hasher.update([1]);
                hash_len_prefixed(hasher, value.as_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update(column.primary_key.to_be_bytes());
        hasher.update(column.hidden.to_be_bytes());
    }

    let selected: Vec<&LogicalColumn> =
        columns.iter().filter(|column| column.hidden != 1).collect();
    if selected.is_empty() {
        return Err(ShadowParityError::DatabaseRead(check));
    }
    let quoted_table = quote_identifier(table, check)?;
    let mut fields = selected
        .iter()
        .map(|column| quote_identifier(&column.name, check))
        .collect::<Result<Vec<_>, _>>()?;
    if columns.iter().any(|column| {
        matches!(
            column.name.to_ascii_lowercase().as_str(),
            "rowid" | "_rowid_" | "oid"
        )
    }) || !ordinary_table_has_rowid(conn, table)?
    {
        // Alias-bearing rowid and WITHOUT ROWID tables need a separately
        // reviewed index-backed traversal. Never fall back to a temp sort.
        return Err(ShadowParityError::DatabaseRead(check));
    }
    hasher.update([1]);
    fields.insert(0, "_rowid_".to_string());
    let field_list = fields.join(", ");
    // Rowid is unique and stored in B-tree order, so this is a streaming scan
    // rather than a database-sized temporary sort.
    let query = format!("SELECT {field_list} FROM {quoted_table} ORDER BY _rowid_");
    let mut statement = conn
        .prepare(&query)
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut rows = statement
        .query([])
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut table_rows = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|_| ShadowParityError::DatabaseRead(check))?
    {
        control.check()?;
        table_rows = table_rows.saturating_add(1);
        budget.rows = budget.rows.saturating_add(1);
        if table_rows > MAX_LOGICAL_ROWS_PER_TABLE || budget.rows > MAX_LOGICAL_ROWS {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        hasher.update(b"row\0");
        let mut row_bytes = 0_u64;
        for index in 0..fields.len() {
            let value = row
                .get_ref(index)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?;
            let value_bytes = hash_value(hasher, value, MAX_LOGICAL_FIELD_BYTES, check)? as u64;
            row_bytes = row_bytes.saturating_add(value_bytes);
            budget.bytes = budget.bytes.saturating_add(value_bytes);
            if row_bytes > MAX_LOGICAL_ROW_BYTES || budget.bytes > MAX_LOGICAL_TOTAL_BYTES {
                return Err(ShadowParityError::DatabaseRead(check));
            }
        }
    }
    hasher.update(table_rows.to_be_bytes());
    Ok(())
}

fn ordinary_table_has_rowid(conn: &Connection, table: &str) -> Result<bool, ShadowParityError> {
    let check = ShadowParityCheck::FullLogicalDatabase;
    let mut statement = conn
        .prepare("PRAGMA table_list")
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut rows = statement
        .query([])
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut visited = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|_| ShadowParityError::DatabaseRead(check))?
    {
        visited = visited.saturating_add(1);
        if visited > MAX_SCHEMA_ENTRIES {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        let schema: String = row
            .get(0)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let name: String = row
            .get(1)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        if schema == "main" && name == table {
            let entry_type: String = row
                .get(2)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?;
            let without_rowid: i64 = row
                .get(4)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?;
            return Ok(entry_type == "table" && without_rowid == 0);
        }
    }
    Err(ShadowParityError::DatabaseRead(check))
}

fn logical_columns(
    conn: &Connection,
    table: &str,
) -> Result<Vec<LogicalColumn>, ShadowParityError> {
    let check = ShadowParityCheck::FullLogicalDatabase;
    let quoted = quote_identifier(table, check)?;
    let mut statement = conn
        .prepare(&format!("PRAGMA table_xinfo({quoted})"))
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut rows = statement
        .query([])
        .map_err(|_| ShadowParityError::DatabaseRead(check))?;
    let mut columns = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| ShadowParityError::DatabaseRead(check))?
    {
        let name: String = row
            .get(1)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let declaration: String = row
            .get::<_, Option<String>>(2)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?
            .unwrap_or_default();
        let default_value: Option<String> = row
            .get(4)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        if name.len() > MAX_SCHEMA_NAME_BYTES
            || declaration.len() > MAX_SCHEMA_SQL_BYTES
            || default_value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_SCHEMA_SQL_BYTES)
        {
            return Err(ShadowParityError::DatabaseRead(check));
        }
        columns.push(LogicalColumn {
            name,
            declaration,
            not_null: row
                .get(3)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?,
            default_value,
            primary_key: row
                .get(5)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?,
            hidden: row
                .get(6)
                .map_err(|_| ShadowParityError::DatabaseRead(check))?,
        });
        if columns.len() > MAX_LOGICAL_COLUMNS {
            return Err(ShadowParityError::DatabaseRead(check));
        }
    }
    Ok(columns)
}

fn selected_query_digest(
    conn: &Connection,
    control: &ShadowParityRunControl<'_>,
) -> Result<OpaqueParityDigest, ShadowParityError> {
    let check = ShadowParityCheck::SelectedQueries;
    let mut hasher = Sha256::new();
    let mut hashed_bytes = 0_usize;
    hasher.update(QUERY_DIGEST_DOMAIN);
    hasher.update(CANONICAL_LOGICAL_EXPORT_VERSION.to_be_bytes());
    for selected in SELECTED_QUERIES {
        control.check()?;
        hash_len_prefixed(&mut hasher, selected.table.as_bytes());
        let exists = table_exists(conn, selected.table, check)?;
        hasher.update([u8::from(exists)]);
        if !exists {
            continue;
        }
        let mut statement = conn
            .prepare(selected.sql)
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let column_count = statement.column_count();
        let mut rows = statement
            .query([MAX_SELECTED_QUERY_ROWS as i64])
            .map_err(|_| ShadowParityError::DatabaseRead(check))?;
        let mut row_count = 0_u64;
        while let Some(row) = rows
            .next()
            .map_err(|_| ShadowParityError::DatabaseRead(check))?
        {
            control.check()?;
            row_count += 1;
            hasher.update(b"row\0");
            for index in 0..column_count {
                let value = row
                    .get_ref(index)
                    .map_err(|_| ShadowParityError::DatabaseRead(check))?;
                hashed_bytes = hashed_bytes.saturating_add(hash_value(
                    &mut hasher,
                    value,
                    MAX_SELECTED_QUERY_VALUE_BYTES,
                    check,
                )?);
                if hashed_bytes > MAX_SELECTED_QUERY_DIGEST_BYTES {
                    return Err(ShadowParityError::DatabaseRead(check));
                }
            }
        }
        hasher.update(row_count.to_be_bytes());
    }
    Ok(OpaqueParityDigest(hasher.finalize().into()))
}

fn table_exists(
    conn: &Connection,
    table: &str,
    check: ShadowParityCheck,
) -> Result<bool, ShadowParityError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type IN ('table', 'view') AND name=?1)",
        [table],
        |row| row.get::<_, i64>(0),
    )
    .map(|exists| exists != 0)
    .map_err(|_| ShadowParityError::DatabaseRead(check))
}

fn schema_entry(
    conn: &Connection,
    name: &str,
    check: ShadowParityCheck,
) -> Result<Option<(String, String)>, ShadowParityError> {
    conn.query_row(
        "SELECT type, COALESCE(sql, '') FROM sqlite_schema WHERE name=?1",
        [name],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(|_| ShadowParityError::DatabaseRead(check))
}

fn quote_identifier(value: &str, check: ShadowParityCheck) -> Result<String, ShadowParityError> {
    if value.is_empty() || value.len() > MAX_SCHEMA_NAME_BYTES || value.contains('\0') {
        return Err(ShadowParityError::DatabaseRead(check));
    }
    Ok(format!("\"{}\"", value.replace('"', "\"\"")))
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '"')
        .flat_map(char::to_lowercase)
        .collect()
}

fn hash_value(
    hasher: &mut Sha256,
    value: ValueRef<'_>,
    max_field_bytes: usize,
    check: ShadowParityCheck,
) -> Result<usize, ShadowParityError> {
    match value {
        ValueRef::Null => {
            hasher.update([0]);
            Ok(1)
        }
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
            Ok(9)
        }
        ValueRef::Real(value) => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
            Ok(9)
        }
        ValueRef::Text(value) => {
            if value.len() > max_field_bytes {
                return Err(ShadowParityError::DatabaseRead(check));
            }
            hasher.update([3]);
            hash_len_prefixed(hasher, value);
            Ok(9_usize.saturating_add(value.len()))
        }
        ValueRef::Blob(value) => {
            if value.len() > max_field_bytes {
                return Err(ShadowParityError::DatabaseRead(check));
            }
            hasher.update([4]);
            hash_len_prefixed(hasher, value);
            Ok(9_usize.saturating_add(value.len()))
        }
    }
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, sync::atomic::AtomicBool, time::Duration};

    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;
    use crate::cp::sync::{
        canonical_logical_export_stream_digest, canonical_logical_export_stream_digest_at_version,
    };

    struct Fixtures {
        _directory: TempDir,
        primary_path: PathBuf,
        shadow_path: PathBuf,
        primary: PrivateStagedSqliteCopy,
        shadow: PrivateStagedSqliteCopy,
    }

    impl Fixtures {
        fn new() -> Self {
            crate::store::init_vec_extension();
            let directory = tempfile::tempdir().unwrap();
            let primary_path = directory.path().join("primary-stage.db");
            let shadow_path = directory.path().join("shadow-stage.db");
            fixture(&primary_path);
            std::fs::copy(&primary_path, &shadow_path).unwrap();
            make_private(&primary_path);
            make_private(&shadow_path);
            let primary = PrivateStagedSqliteCopy::new(primary_path.clone()).unwrap();
            let shadow = PrivateStagedSqliteCopy::new(shadow_path.clone()).unwrap();
            Self {
                _directory: directory,
                primary_path,
                shadow_path,
                primary,
                shadow,
            }
        }

        fn refresh_shadow(&mut self) {
            self.shadow = PrivateStagedSqliteCopy::new(self.shadow_path.clone()).unwrap();
        }

        fn compare(&self) -> Result<ShadowParityResult, ShadowParityError> {
            let cancelled = AtomicBool::new(false);
            let control =
                ShadowParityRunControl::new(Instant::now() + Duration::from_secs(60), &cancelled);
            ShadowParityVerifier::compare_staged_copies(&self.primary, &self.shadow, &control)
        }
    }

    fn make_private(path: &Path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn fixture(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE audio_segments (id INTEGER PRIMARY KEY, started_at TEXT, ended_at TEXT, source_type TEXT);
            CREATE TABLE utterances (id INTEGER PRIMARY KEY, audio_segment_id INTEGER, start_offset_seconds REAL, end_offset_seconds REAL, text TEXT, source_key TEXT);
            CREATE TABLE screenshots (id INTEGER PRIMARY KEY, captured_at TEXT, active_app TEXT, ocr_text TEXT);
            CREATE TABLE episodes (id INTEGER PRIMARY KEY, started_at TEXT, ended_at TEXT, title TEXT, summary TEXT, minutes_text TEXT);
            CREATE TABLE app_metadata (key TEXT PRIMARY KEY, value TEXT);
            CREATE VIRTUAL TABLE utterances_fts USING fts5(text, content='utterances', content_rowid='id');
            CREATE VIRTUAL TABLE screenshots_fts USING fts5(ocr_text, content='screenshots', content_rowid='id');
            CREATE VIRTUAL TABLE episodes_fts USING fts5(title, summary, minutes_text, content='episodes', content_rowid='id');
            CREATE VIRTUAL TABLE vec_utterances USING vec0(utterance_id INTEGER PRIMARY KEY, embedding float[384] distance_metric=cosine);
            CREATE VIRTUAL TABLE vec_screenshots USING vec0(screenshot_id INTEGER PRIMARY KEY, embedding float[384] distance_metric=cosine);
            CREATE VIRTUAL TABLE vec_episodes USING vec0(episode_id INTEGER PRIMARY KEY, embedding float[384] distance_metric=cosine);
            INSERT INTO audio_segments VALUES (1, '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', 'mic');
            INSERT INTO utterances VALUES (1, 1, 0.0, 1.0, 'private transcript', 'source-1');
            INSERT INTO utterances VALUES (2, 1, 1.0, 2.0, 'second transcript', 'source-2');
            INSERT INTO screenshots VALUES (1, '2026-01-01T00:00:00Z', 'Kioku', 'private OCR');
            INSERT INTO episodes VALUES (1, '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', 'Private episode', 'Private summary', 'Private minute');
            INSERT INTO utterances_fts(rowid, text) VALUES (1, 'private transcript');
            INSERT INTO utterances_fts(rowid, text) VALUES (2, 'second transcript');
            INSERT INTO screenshots_fts(rowid, ocr_text) VALUES (1, 'private OCR');
            INSERT INTO episodes_fts(rowid, title, summary, minutes_text) VALUES (1, 'Private episode', 'Private summary', 'Private minute');
            INSERT INTO vec_utterances(utterance_id, embedding) VALUES (1, zeroblob(1536));
            INSERT INTO vec_screenshots(screenshot_id, embedding) VALUES (1, zeroblob(1536));
            INSERT INTO vec_episodes(episode_id, embedding) VALUES (1, zeroblob(1536));
            ",
        )
        .unwrap();
        for id in 2..=65_i64 {
            conn.execute(
                "INSERT INTO audio_segments VALUES (?1, '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', 'mic')",
                [id],
            )
            .unwrap();
        }
    }

    fn mutate(fixtures: &mut Fixtures, sql: &str) {
        let conn = Connection::open(&fixtures.shadow_path).unwrap();
        conn.execute_batch(sql).unwrap();
        drop(conn);
        fixtures.refresh_shadow();
    }

    fn mismatch(result: ShadowParityResult, expected: ShadowParityCheck) {
        match result {
            ShadowParityResult::Mismatch(checks) => assert!(checks.contains(&expected)),
            ShadowParityResult::Match(_) => panic!("expected mismatch"),
        }
    }

    #[test]
    fn matching_private_staged_copies_produce_only_opaque_digests() {
        let fixtures = Fixtures::new();
        assert!(matches!(
            fixtures.compare().unwrap(),
            ShadowParityResult::Match(_)
        ));
    }

    #[test]
    fn staging_type_rejects_non_private_files_and_same_inode() {
        let fixtures = Fixtures::new();
        std::fs::set_permissions(
            &fixtures.shadow_path,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            PrivateStagedSqliteCopy::new(fixtures.shadow_path.clone()),
            Err(ShadowParityError::InvalidStagedCopy)
        ));

        let cancelled = AtomicBool::new(false);
        let control =
            ShadowParityRunControl::new(Instant::now() + Duration::from_secs(60), &cancelled);
        assert_eq!(
            ShadowParityVerifier::compare_staged_copies(
                &fixtures.primary,
                &fixtures.primary,
                &control
            ),
            Err(ShadowParityError::SameStagedCopy)
        );
    }

    #[test]
    fn corruption_fails_closed() {
        let mut fixtures = Fixtures::new();
        std::fs::write(&fixtures.shadow_path, b"not a sqlite database").unwrap();
        make_private(&fixtures.shadow_path);
        fixtures.refresh_shadow();
        assert!(matches!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseOpen)
                | Err(ShadowParityError::DatabaseRead(
                    ShadowParityCheck::DatabaseIntegrity
                ))
        ));
    }

    #[test]
    fn stale_and_missing_core_fts_fail_closed() {
        let mut fixtures = Fixtures::new();
        mutate(&mut fixtures, "DELETE FROM utterances WHERE id=1");
        assert_eq!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::FtsIntegrity
            ))
        );

        let mut fixtures = Fixtures::new();
        mutate(&mut fixtures, "DROP TABLE utterances_fts");
        assert_eq!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::FtsIntegrity
            ))
        );
    }

    #[test]
    fn malformed_fts_and_missing_optional_mcp_fts_fail_closed() {
        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "DROP TABLE utterances_fts; CREATE TABLE utterances_fts(utterances_fts TEXT)",
        );
        assert_eq!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::FtsIntegrity
            ))
        );

        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "CREATE TABLE mcp_safe_utterances(id INTEGER PRIMARY KEY, sanitized_text TEXT)",
        );
        assert_eq!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::FtsIntegrity
            ))
        );
    }

    #[test]
    fn virtual_schema_validation_rejects_comment_spoofing_and_unknown_forms() {
        let fts = FTS_TABLES[0];
        assert!(valid_external_fts_schema(
            "table",
            "CREATE VIRTUAL TABLE utterances_fts USING fts5(\
                 text, content='utterances', content_rowid='id')",
            fts,
        ));
        assert!(!valid_external_fts_schema(
            "table",
            "CREATE VIRTUAL TABLE utterances_fts USING fts5(body /* \
                 usingfts5(text,content='utterances',content_rowid='id') */)",
            fts,
        ));
        assert!(!valid_external_fts_schema(
            "table",
            "CREATE VIRTUAL TABLE utterances_fts USING fts5(\
                 text, content='other', content_rowid='id')",
            fts,
        ));

        let vector = VECTOR_TABLES[0];
        assert!(valid_vector_schema(
            "CREATE VIRTUAL TABLE vec_utterances USING vec0(\
                 utterance_id INTEGER PRIMARY KEY, \
                 embedding float[384] distance_metric=cosine)",
            vector,
        ));
        assert!(!valid_vector_schema(
            "CREATE VIRTUAL TABLE vec_utterances USING fake(embedding /* \
                 usingvec0(utterance_idintegerprimarykey,\
                 embeddingfloat[384]distance_metric=cosine) */)",
            vector,
        ));
        assert!(!valid_vector_schema(
            "CREATE VIRTUAL TABLE vec_utterances USING vec0(\
                 utterance_id INTEGER PRIMARY KEY, \
                 embedding float[384] distance_metric=l2)",
            vector,
        ));
    }

    #[test]
    fn vector_orphan_missing_and_same_count_different_id_are_detected() {
        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "INSERT INTO vec_utterances(utterance_id, embedding) VALUES(99, zeroblob(1536))",
        );
        assert_eq!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::VectorContents
            ))
        );

        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "DELETE FROM vec_utterances WHERE utterance_id=1",
        );
        mismatch(
            fixtures.compare().unwrap(),
            ShadowParityCheck::VectorContents,
        );

        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "DELETE FROM vec_utterances WHERE utterance_id=1;
             INSERT INTO vec_utterances(utterance_id, embedding) VALUES(2, zeroblob(1536))",
        );
        mismatch(
            fixtures.compare().unwrap(),
            ShadowParityCheck::VectorContents,
        );
    }

    #[test]
    fn same_vector_id_with_different_exact_bytes_is_detected() {
        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "DELETE FROM vec_utterances WHERE utterance_id=1;
             INSERT INTO vec_utterances(utterance_id, embedding)
             VALUES(1, CAST(X'01000000' || zeroblob(1532) AS BLOB))",
        );
        mismatch(
            fixtures.compare().unwrap(),
            ShadowParityCheck::VectorContents,
        );
    }

    #[test]
    fn full_gate_detects_a_change_after_the_64_row_probe() {
        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "UPDATE audio_segments SET source_type='system' WHERE id=65",
        );
        let result = fixtures.compare().unwrap();
        mismatch(result.clone(), ShadowParityCheck::FullLogicalDatabase);
        if let ShadowParityResult::Mismatch(checks) = result {
            assert!(!checks.contains(&ShadowParityCheck::SelectedQueries));
        }
    }

    #[test]
    fn full_gate_rejects_unbounded_sort_and_rowid_alias_forms() {
        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "CREATE TABLE unsupported_without_rowid(\
                 key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
             INSERT INTO unsupported_without_rowid VALUES('key', 'value')",
        );
        assert_eq!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::FullLogicalDatabase
            ))
        );

        let mut fixtures = Fixtures::new();
        mutate(
            &mut fixtures,
            "CREATE TABLE unsupported_rowid_alias(\
                 rowid INTEGER PRIMARY KEY, value TEXT);
             INSERT INTO unsupported_rowid_alias VALUES(1, 'value')",
        );
        assert_eq!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::FullLogicalDatabase
            ))
        );
    }

    #[test]
    fn logical_export_digest_is_streamed_bounded_and_versioned() {
        let fixtures = Fixtures::new();
        let conn = open_read_only(&fixtures.primary_path).unwrap();
        let current = canonical_logical_export_stream_digest(&conn).unwrap();
        let next = canonical_logical_export_stream_digest_at_version(
            &conn,
            CANONICAL_LOGICAL_EXPORT_VERSION + 1,
        )
        .unwrap();
        assert_ne!(current, next);

        drop(conn);
        let mut fixtures = fixtures;
        mutate(
            &mut fixtures,
            "CREATE TABLE screenshot_images(id INTEGER PRIMARY KEY, payload TEXT);
             INSERT INTO screenshot_images VALUES(1, hex(zeroblob(2097153)))",
        );
        assert_eq!(
            fixtures.compare(),
            Err(ShadowParityError::DatabaseRead(
                ShadowParityCheck::LogicalExport
            ))
        );
    }

    #[test]
    fn cancellation_and_deadline_fail_before_work() {
        let fixtures = Fixtures::new();
        let cancelled = AtomicBool::new(true);
        let control =
            ShadowParityRunControl::new(Instant::now() + Duration::from_secs(60), &cancelled);
        assert_eq!(
            ShadowParityVerifier::compare_staged_copies(
                &fixtures.primary,
                &fixtures.shadow,
                &control
            ),
            Err(ShadowParityError::Cancelled)
        );

        let cancelled = AtomicBool::new(false);
        let expired = ShadowParityRunControl::new(Instant::now(), &cancelled);
        assert_eq!(
            ShadowParityVerifier::compare_staged_copies(
                &fixtures.primary,
                &fixtures.shadow,
                &expired
            ),
            Err(ShadowParityError::DeadlineExceeded)
        );
    }

    #[test]
    fn debug_output_redacts_paths_content_and_digests() {
        let fixtures = Fixtures::new();
        let result = fixtures.compare().unwrap();
        let rendered = format!(
            "{result:?} {:?} {:?}",
            fixtures.primary,
            ShadowParityError::DatabaseOpen
        );
        assert!(!rendered.contains("private transcript"));
        assert!(!rendered.contains("private OCR"));
        assert!(!rendered.contains(fixtures.primary_path.to_string_lossy().as_ref()));
        assert!(!rendered.contains(fixtures.shadow_path.to_string_lossy().as_ref()));
    }
}
