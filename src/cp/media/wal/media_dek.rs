#![allow(
    dead_code,
    reason = "inactive ADR-0022 media-DEK install boundary is reviewed before KMS, upload, launcher, or route ownership"
)]

//! Inactive first-writer-wins media-DEK installation boundary.
//!
//! A future KMS boundary must supply one wrapped DEK together with the exact
//! plaintext DEK that it wraps. This child retains no plaintext key: it derives
//! a keyed binding, atomically installs or exact-adopts the wrapped value in
//! `app_metadata`, and retains a bounded exact-replay receipt. It cannot call
//! KMS, read media, encrypt, invoke a provider or Store, launch work, allocate a
//! retry/clock/identity, acknowledge a request, or expose the wrapped value in
//! its result.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::archive_v3::MAX_WRAPPED_KEY_REGISTRY_BYTES;
use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};
use crate::crypto::Dek;

const REQUEST_V1: u16 = 1;
const REQUEST_MEDIA_DEK_INSTALL: u8 = 3;
const RESULT_V1: u16 = 1;
const RESULT_MEDIA_DEK_INSTALL: u8 = 3;
const OPERATION_SOURCE_DOMAIN: &[u8] = b"media-dek-install-v1\0";
const BINDING_DOMAIN: &[u8] = b"archive-v3-media-dek-install-binding-v1\0";
const MEDIA_DEK_METADATA_KEY: &str = "wrapped_media_dek";
const MAX_ACCOUNT_ID_BYTES: usize = 128;
const MAX_WRAPPED_DEK_B64_BYTES: usize = 24 * 1024;
const MAX_ENCODED_RESULT_BYTES: usize = 1024;
const SCHEMA_TABLE: &str = "archive_v3_wal_media_dek_install_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_dek_install_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_dek_install_state";
const MAX_ROWS: u32 = 1;
const MAX_RESULT_BYTES: u64 = 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type HmacSha256 = Hmac<Sha256>;
type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MediaDekInstallReceipt {
    wrapped_dek_commitment: [u8; 32],
    binding_commitment: [u8; 32],
}

impl MediaDekInstallReceipt {
    pub(in crate::cp) fn from_stored_commitments(
        wrapped_dek_commitment: [u8; 32],
        binding_commitment: [u8; 32],
    ) -> Result<Self> {
        if wrapped_dek_commitment == [0; 32] || binding_commitment == [0; 32] {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(Self {
            wrapped_dek_commitment,
            binding_commitment,
        })
    }

    pub(in crate::cp) const fn wrapped_dek_commitment(&self) -> [u8; 32] {
        self.wrapped_dek_commitment
    }

    pub(in crate::cp) const fn binding_commitment(&self) -> [u8; 32] {
        self.binding_commitment
    }

    pub(in crate::cp) fn validate_plaintext_dek(
        &self,
        account_id: &str,
        plaintext_dek: &Dek,
    ) -> Result<()> {
        let expected =
            derive_binding_commitment(plaintext_dek, account_id, &self.wrapped_dek_commitment)?;
        (expected == self.binding_commitment)
            .then_some(())
            .ok_or(WalIdempotencyError::Precondition)
    }
}

/// Exact local installation half of a future KMS media-DEK handoff. The
/// plaintext DEK is used only while deriving the binding and is never retained
/// by the plan, request, ledger, or replay result.
pub(crate) struct MediaDekInstallPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    wrapped_dek_b64: Zeroizing<String>,
    receipt: MediaDekInstallReceipt,
}

impl MediaDekInstallPlan {
    /// Visible to the owning route module only: `load_or_create_media_dek`
    /// is the single production constructor site.
    pub(crate) fn new(
        account_id: String,
        wrapped_dek_b64: String,
        plaintext_dek: &Dek,
    ) -> Result<Self> {
        Self::build(None, account_id, wrapped_dek_b64, plaintext_dek)
    }

    #[cfg(test)]
    pub(in crate::cp) fn new_for_cross_domain_test(
        account_id: String,
        wrapped_dek_b64: String,
        plaintext_dek: &Dek,
    ) -> Result<Self> {
        Self::build(None, account_id, wrapped_dek_b64, plaintext_dek)
    }

    fn build(
        operation_id: Option<WalLogicalOperationId>,
        account_id: String,
        wrapped_dek_b64: String,
        plaintext_dek: &Dek,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if account_id.len() > MAX_ACCOUNT_ID_BYTES {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_wrapped_dek(&wrapped_dek_b64)?;
        let wrapped_dek_commitment: [u8; 32] = Sha256::digest(wrapped_dek_b64.as_bytes()).into();
        if wrapped_dek_commitment == [0; 32] {
            return Err(WalIdempotencyError::Corrupt);
        }
        let binding_commitment =
            derive_binding_commitment(plaintext_dek, &account_id, &wrapped_dek_commitment)?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                let mut source = Vec::with_capacity(
                    OPERATION_SOURCE_DOMAIN
                        .len()
                        .saturating_add(account_id.len()),
                );
                source.extend_from_slice(OPERATION_SOURCE_DOMAIN);
                source.extend_from_slice(account_id.as_bytes());
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::MediaCaptureEvent,
                    &source,
                )?
            }
        };
        Ok(Self {
            operation_id,
            account_id,
            wrapped_dek_b64: Zeroizing::new(wrapped_dek_b64),
            receipt: MediaDekInstallReceipt {
                wrapped_dek_commitment,
                binding_commitment,
            },
        })
    }

    fn from_stored(
        account_id: String,
        wrapped_dek_b64: String,
        receipt: MediaDekInstallReceipt,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Corrupt)?;
        if account_id.len() > MAX_ACCOUNT_ID_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        validate_wrapped_dek(&wrapped_dek_b64).map_err(|_| WalIdempotencyError::Corrupt)?;
        let wrapped_dek_commitment: [u8; 32] = Sha256::digest(wrapped_dek_b64.as_bytes()).into();
        if wrapped_dek_commitment != receipt.wrapped_dek_commitment
            || receipt.binding_commitment == [0; 32]
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(Self {
            operation_id: derive_operation_id(&account_id)?,
            account_id,
            wrapped_dek_b64: Zeroizing::new(wrapped_dek_b64),
            receipt,
        })
    }

    #[cfg(test)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        account_id: String,
        wrapped_dek_b64: String,
        plaintext_dek: &Dek,
    ) -> Result<Self> {
        Self::build(
            Some(operation_id),
            account_id,
            wrapped_dek_b64,
            plaintext_dek,
        )
    }
}

/// Reauthenticates the one exact installed media-DEK receipt without exposing
/// the wrapped value or any KMS/decryption authority to a sibling domain.
pub(in crate::cp) fn authenticate_media_dek_install_receipt(
    connection: &Connection,
    account_id: &str,
    receipt: &MediaDekInstallReceipt,
) -> Result<()> {
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Err(WalIdempotencyError::Precondition);
    }
    validate_schema_marker(connection)?;
    let wrapped_dek_b64 = load_wrapped_dek(connection)?.ok_or(WalIdempotencyError::Precondition)?;
    let plan = MediaDekInstallPlan::from_stored(account_id.to_owned(), wrapped_dek_b64, *receipt)?;
    let prepared =
        PreparedLogicalMutation::prepare(plan).map_err(|_| WalIdempotencyError::Corrupt)?;
    MediaDekInstallLedger::lookup(connection, &prepared)?
        .map(|_| ())
        .ok_or(WalIdempotencyError::Corrupt)
}

impl Drop for MediaDekInstallPlan {
    fn drop(&mut self) {
        self.account_id.zeroize();
    }
}

pub(crate) struct MediaDekInstallLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for MediaDekInstallPlan {
    type Ledger = MediaDekInstallLedger;
    type Output = MediaDekInstallReceipt;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::MediaCaptureEvent
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(
            self.account_id
                .len()
                .saturating_add(self.wrapped_dek_b64.len())
                .saturating_add(80),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_MEDIA_DEK_INSTALL);
        append_string(&mut request, &self.account_id)?;
        append_string(&mut request, self.wrapped_dek_b64.as_str())?;
        request.extend_from_slice(&self.receipt.wrapped_dek_commitment);
        request.extend_from_slice(&self.receipt.binding_commitment);
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let existing = load_wrapped_dek(transaction)?;
        match existing {
            Some(value) if value == self.wrapped_dek_b64.as_str() => {}
            Some(_) => return Err(WalIdempotencyError::Precondition),
            None => {
                let changed = transaction
                    .execute(
                        "INSERT INTO app_metadata(key,value) VALUES (?1,?2)",
                        params![MEDIA_DEK_METADATA_KEY, self.wrapped_dek_b64.as_str()],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if changed != 1 {
                    return Err(WalIdempotencyError::Corrupt);
                }
            }
        }
        validate_installed_value(transaction, self)?;
        encode_receipt(&self.receipt)
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        (decode_receipt(result)? == self.receipt)
            .then_some(())
            .ok_or(WalIdempotencyError::Corrupt)
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        let receipt = decode_receipt(result)?;
        (receipt == self.receipt)
            .then_some(receipt)
            .ok_or(WalIdempotencyError::Corrupt)
    }
}

impl WalLogicalDomainLedger<MediaDekInstallPlan> for MediaDekInstallLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaDekInstallPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT operation_id,format_version,codec_version,request_fingerprint,
                        account_id,wrapped_dek_commitment,binding_commitment,
                        result_bytes,result_commitment
                 FROM archive_v3_wal_media_dek_install_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                StoredLedgerRow::from_row,
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let plan = prepared.plan_for_domain_ledger();
        if row.operation_id.len() != 16
            || row.request_fingerprint.len() != 32
            || row.wrapped_dek_commitment.len() != 32
            || row.binding_commitment.len() != 32
            || row.result_commitment.len() != 32
            || row.result_bytes.len() > MAX_ENCODED_RESULT_BYTES
            || row.format_version != i64::from(WalOperationKind::format_version())
            || row.codec_version != i64::from(WalOperationKind::MediaCaptureEvent.codec_version())
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        if row.request_fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        if !row.matches_plan(plan) {
            return Err(WalIdempotencyError::Corrupt);
        }
        let expected_operation = derive_operation_id(&row.account_id)?;
        if row.operation_id.as_slice() != expected_operation.as_bytes().as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        validate_installed_value(connection, plan)?;
        let result =
            WalReplayResult::decode(WalOperationKind::MediaCaptureEvent, &row.result_bytes)?;
        if row.result_commitment.as_slice()
            != result
                .commitment(WalOperationKind::MediaCaptureEvent)?
                .as_slice()
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        plan.validate_replay(&result)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<MediaDekInstallPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let plan = prepared.plan_for_domain_ledger();
        let expected = encode_receipt(&plan.receipt)?;
        let expected_encoded = expected.encode(WalOperationKind::MediaCaptureEvent)?;
        if expected_encoded.len() > MAX_ENCODED_RESULT_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, expected_encoded.len())?;
        let result = plan.apply(transaction)?;
        plan.validate_replay(&result)?;
        let encoded = result.encode(WalOperationKind::MediaCaptureEvent)?;
        if encoded != expected_encoded {
            return Err(WalIdempotencyError::Corrupt);
        }
        let result_commitment = result.commitment(WalOperationKind::MediaCaptureEvent)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_media_dek_install_operations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  account_id,wrapped_dek_commitment,binding_commitment,
                  result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(WalOperationKind::MediaCaptureEvent.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    plan.account_id,
                    plan.receipt.wrapped_dek_commitment.as_slice(),
                    plan.receipt.binding_commitment.as_slice(),
                    encoded.as_slice(),
                    result_commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_media_dek_install_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        let Some(stored) = Self::lookup(transaction, prepared)? else {
            return Err(WalIdempotencyError::Corrupt);
        };
        if stored != result {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

struct StoredLedgerRow {
    operation_id: Vec<u8>,
    format_version: i64,
    codec_version: i64,
    request_fingerprint: Vec<u8>,
    account_id: String,
    wrapped_dek_commitment: Vec<u8>,
    binding_commitment: Vec<u8>,
    result_bytes: Vec<u8>,
    result_commitment: Vec<u8>,
}

impl StoredLedgerRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            operation_id: row.get(0)?,
            format_version: row.get(1)?,
            codec_version: row.get(2)?,
            request_fingerprint: row.get(3)?,
            account_id: row.get(4)?,
            wrapped_dek_commitment: row.get(5)?,
            binding_commitment: row.get(6)?,
            result_bytes: row.get(7)?,
            result_commitment: row.get(8)?,
        })
    }

    fn matches_plan(&self, plan: &MediaDekInstallPlan) -> bool {
        self.operation_id.as_slice() == plan.operation_id.as_bytes().as_slice()
            && self.account_id == plan.account_id
            && self.wrapped_dek_commitment.as_slice()
                == plan.receipt.wrapped_dek_commitment.as_slice()
            && self.binding_commitment.as_slice() == plan.receipt.binding_commitment.as_slice()
    }
}

fn derive_operation_id(account_id: &str) -> Result<WalLogicalOperationId> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Corrupt)?;
    if account_id.len() > MAX_ACCOUNT_ID_BYTES {
        return Err(WalIdempotencyError::Corrupt);
    }
    let mut source = Vec::with_capacity(
        OPERATION_SOURCE_DOMAIN
            .len()
            .saturating_add(account_id.len()),
    );
    source.extend_from_slice(OPERATION_SOURCE_DOMAIN);
    source.extend_from_slice(account_id.as_bytes());
    WalLogicalOperationId::from_stable_source(WalOperationKind::MediaCaptureEvent, &source)
        .map_err(|_| WalIdempotencyError::Corrupt)
}

fn derive_binding_commitment(
    plaintext_dek: &Dek,
    account_id: &str,
    wrapped_dek_commitment: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut mac =
        HmacSha256::new_from_slice(&plaintext_dek.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    mac.update(BINDING_DOMAIN);
    mac.update(
        &u32::try_from(account_id.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    mac.update(account_id.as_bytes());
    mac.update(wrapped_dek_commitment);
    let commitment: [u8; 32] = mac.finalize().into_bytes().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn validate_wrapped_dek(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_WRAPPED_DEK_B64_BYTES {
        return Err(WalIdempotencyError::Malformed);
    }
    let decoded = Zeroizing::new(
        BASE64_STANDARD
            .decode(value.as_bytes())
            .map_err(|_| WalIdempotencyError::Malformed)?,
    );
    if decoded.is_empty()
        || decoded.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
        || BASE64_STANDARD.encode(decoded.as_slice()) != value
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn load_wrapped_dek(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT value FROM app_metadata WHERE key=?1",
            [MEDIA_DEK_METADATA_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn validate_installed_value(connection: &Connection, plan: &MediaDekInstallPlan) -> Result<()> {
    let installed = load_wrapped_dek(connection)?.ok_or(WalIdempotencyError::Corrupt)?;
    let commitment: [u8; 32] = Sha256::digest(installed.as_bytes()).into();
    if installed != plan.wrapped_dek_b64.as_str()
        || commitment != plan.receipt.wrapped_dek_commitment
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn append_string(destination: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_receipt(receipt: &MediaDekInstallReceipt) -> Result<WalReplayResult> {
    let mut bytes = Vec::with_capacity(67);
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_MEDIA_DEK_INSTALL);
    bytes.extend_from_slice(&receipt.wrapped_dek_commitment);
    bytes.extend_from_slice(&receipt.binding_commitment);
    WalReplayResult::canonical_response(WalOperationKind::MediaCaptureEvent, bytes)
}

fn decode_receipt(result: &WalReplayResult) -> Result<MediaDekInstallReceipt> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    if bytes.len() != 67
        || bytes[0..2] != RESULT_V1.to_be_bytes()
        || bytes[2] != RESULT_MEDIA_DEK_INSTALL
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let wrapped_dek_commitment: [u8; 32] = bytes[3..35]
        .try_into()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    let binding_commitment: [u8; 32] = bytes[35..67]
        .try_into()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if wrapped_dek_commitment == [0; 32] || binding_commitment == [0; 32] {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(MediaDekInstallReceipt {
        wrapped_dek_commitment,
        binding_commitment,
    })
}

fn require_kind(prepared: &PreparedLogicalMutation<MediaDekInstallPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::MediaCaptureEvent)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3)",
            params![SCHEMA_TABLE, LEDGER_TABLE, STATE_TABLE],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        3 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_media_dek_install_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_dek_install_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        account_id TEXT NOT NULL,
                        wrapped_dek_commitment BLOB NOT NULL,
                        binding_commitment BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(account_id) BETWEEN 1 AND 128),
                        CHECK(length(wrapped_dek_commitment)=32 AND wrapped_dek_commitment<>zeroblob(32)),
                        CHECK(length(binding_commitment)=32 AND binding_commitment<>zeroblob(32)),
                        CHECK(length(result_bytes) BETWEEN 76 AND 1024),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_media_dek_install_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 1024)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_dek_install_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_dek_install_state
                        (singleton,row_count,result_bytes) VALUES (1,0,0);",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            validate_schema_marker(transaction)
        }
    }
}

fn validate_schema_marker(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version
             FROM archive_v3_wal_media_dek_install_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::MediaCaptureEvent.codec_version()),
        ))
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let _ = load_ledger_state(connection)?;
    Ok(())
}

fn load_ledger_state(connection: &Connection) -> Result<(u32, u64)> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes
             FROM archive_v3_wal_media_dek_install_state WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let row_count = u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    let result_bytes = u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?;
    if row_count > MAX_ROWS || result_bytes > MAX_RESULT_BYTES {
        return Err(WalIdempotencyError::Corrupt);
    }
    let actual = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(result_bytes)),0)
             FROM archive_v3_wal_media_dek_install_operations",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if actual.0 != i64::from(row_count)
        || actual.1 != i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok((row_count, result_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };

    const ACCOUNT: &str = "account-1";

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE app_metadata(
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                 ) STRICT, WITHOUT ROWID;",
            )
            .unwrap();
        connection
    }

    fn wrapped(seed: u8) -> String {
        BASE64_STANDARD.encode([seed; 64])
    }

    fn plan(seed: u8) -> MediaDekInstallPlan {
        MediaDekInstallPlan::new(ACCOUNT.to_owned(), wrapped(seed), &Dek([seed; 32])).unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: MediaDekInstallPlan,
    ) -> std::result::Result<
        crate::archive_v3_wal_idempotency::ExecutedLogicalMutation<MediaDekInstallPlan>,
        WalIdempotencyError,
    > {
        execute_prepared_for_owner(connection, PreparedLogicalMutation::prepare(plan)?)
    }

    fn execute_error(
        connection: &mut Connection,
        plan: MediaDekInstallPlan,
    ) -> WalIdempotencyError {
        match execute(connection, plan) {
            Ok(_) => panic!("mutation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn exact_install_applies_reopens_and_replays_without_exposing_the_wrapper() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let path = temporary.path().to_owned();
        let mut connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE app_metadata(
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                 ) STRICT, WITHOUT ROWID;",
            )
            .unwrap();
        let first = plan(7);
        let replay = plan(7);
        let operation_id = first.operation_id();
        assert_ne!(
            operation_id,
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::MediaCaptureEvent,
                ACCOUNT.as_bytes(),
            )
            .unwrap()
        );
        let applied = execute(&mut connection, first).unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        let receipt = applied.into_validated_result().release().unwrap();
        assert_ne!(receipt.wrapped_dek_commitment(), [0; 32]);
        assert_ne!(receipt.binding_commitment(), [0; 32]);
        let stored: String = connection
            .query_row(
                "SELECT value FROM app_metadata WHERE key=?1",
                [MEDIA_DEK_METADATA_KEY],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, wrapped(7));
        let result_bytes: Vec<u8> = connection
            .query_row(
                "SELECT result_bytes FROM archive_v3_wal_media_dek_install_operations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!result_bytes
            .windows(stored.len())
            .any(|window| window == stored.as_bytes()));
        drop(connection);

        let mut reopened = Connection::open(&path).unwrap();
        let changes = reopened.total_changes();
        let replayed = execute(&mut reopened, replay).unwrap();
        assert_eq!(replayed.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replayed.operation_id(), operation_id);
        assert_eq!(replayed.into_validated_result().release().unwrap(), receipt);
        assert_eq!(reopened.total_changes(), changes);
    }

    #[test]
    fn exact_preexisting_wrapper_is_adopted_but_another_wrapper_is_rejected() {
        let mut adopted = connection();
        adopted
            .execute(
                "INSERT INTO app_metadata(key,value) VALUES (?1,?2)",
                params![MEDIA_DEK_METADATA_KEY, wrapped(7)],
            )
            .unwrap();
        assert_eq!(
            execute(&mut adopted, plan(7)).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );

        let mut rejected = connection();
        rejected
            .execute(
                "INSERT INTO app_metadata(key,value) VALUES (?1,?2)",
                params![MEDIA_DEK_METADATA_KEY, wrapped(8)],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut rejected, plan(7)),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            rejected
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name='archive_v3_wal_media_dek_install_operations'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn changed_same_account_conflicts_and_second_account_cannot_consume_capacity() {
        let mut connection = connection();
        execute(&mut connection, plan(7)).unwrap();
        assert_eq!(
            execute_error(&mut connection, plan(8)),
            WalIdempotencyError::FingerprintConflict
        );
        let second =
            MediaDekInstallPlan::new("account-2".to_owned(), wrapped(7), &Dek([7; 32])).unwrap();
        assert_eq!(
            execute_error(&mut connection, second),
            WalIdempotencyError::Limit
        );
        assert_eq!(load_ledger_state(&connection).unwrap().0, 1);
    }

    #[test]
    fn malformed_inputs_and_forced_identity_are_rejected_or_fail_closed() {
        assert!(
            MediaDekInstallPlan::new("../account".to_owned(), wrapped(7), &Dek([7; 32])).is_err()
        );
        assert!(MediaDekInstallPlan::new(
            ACCOUNT.to_owned(),
            "not base64".to_owned(),
            &Dek([7; 32])
        )
        .is_err());
        assert!(MediaDekInstallPlan::new(
            ACCOUNT.to_owned(),
            BASE64_STANDARD.encode(vec![7; MAX_WRAPPED_KEY_REGISTRY_BYTES + 1]),
            &Dek([7; 32])
        )
        .is_err());

        let mut connection = connection();
        let forced = MediaDekInstallPlan::with_operation_id(
            WalLogicalOperationId::from_bytes([9; 16]).unwrap(),
            ACCOUNT.to_owned(),
            wrapped(7),
            &Dek([7; 32]),
        )
        .unwrap();
        assert_eq!(
            execute_error(&mut connection, forced),
            WalIdempotencyError::Corrupt
        );
        assert!(load_wrapped_dek(&connection).unwrap().is_none());
    }

    #[test]
    fn app_metadata_or_ledger_tamper_fails_closed_on_replay() {
        let mut metadata = connection();
        execute(&mut metadata, plan(7)).unwrap();
        metadata
            .execute(
                "UPDATE app_metadata SET value=?1 WHERE key=?2",
                params![wrapped(8), MEDIA_DEK_METADATA_KEY],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut metadata, plan(7)),
            WalIdempotencyError::Corrupt
        );

        let mut ledger = connection();
        execute(&mut ledger, plan(7)).unwrap();
        ledger
            .execute(
                "UPDATE archive_v3_wal_media_dek_install_operations
                 SET binding_commitment=randomblob(32)",
                [],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut ledger, plan(7)),
            WalIdempotencyError::Corrupt
        );

        let mut counter = connection();
        execute(&mut counter, plan(7)).unwrap();
        counter
            .execute(
                "UPDATE archive_v3_wal_media_dek_install_state
                 SET result_bytes=result_bytes+1 WHERE singleton=1",
                [],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut counter, plan(7)),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn capacity_preserves_exact_state_and_partial_or_late_failures_install_nothing() {
        let mut capacity = connection();
        execute(&mut capacity, plan(7)).unwrap();
        let second =
            MediaDekInstallPlan::new("account-2".to_owned(), wrapped(7), &Dek([7; 32])).unwrap();
        assert_eq!(
            execute_error(&mut capacity, second),
            WalIdempotencyError::Limit
        );
        assert_eq!(load_wrapped_dek(&capacity).unwrap(), Some(wrapped(7)));
        assert_eq!(load_ledger_state(&capacity).unwrap().0, 1);

        let mut partial = connection();
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_media_dek_install_schema(
                    singleton INTEGER PRIMARY KEY,
                    format_version INTEGER NOT NULL,
                    codec_version INTEGER NOT NULL
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut partial, plan(7)),
            WalIdempotencyError::Corrupt
        );
        assert!(load_wrapped_dek(&partial).unwrap().is_none());

        let mut late_metadata = connection();
        late_metadata
            .execute_batch(
                "CREATE TRIGGER rewrite_installed_media_dek
                 AFTER INSERT ON app_metadata
                 WHEN NEW.key='wrapped_media_dek'
                 BEGIN
                   UPDATE app_metadata SET value='corrupt' WHERE key=NEW.key;
                 END;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut late_metadata, plan(7)),
            WalIdempotencyError::Corrupt
        );
        assert!(load_wrapped_dek(&late_metadata).unwrap().is_none());

        let mut late_ledger = connection();
        {
            let transaction = late_ledger.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        late_ledger
            .execute_batch(
                "CREATE TRIGGER rewrite_media_dek_ledger
                 AFTER INSERT ON archive_v3_wal_media_dek_install_operations
                 BEGIN
                   UPDATE archive_v3_wal_media_dek_install_operations
                   SET binding_commitment=randomblob(32)
                   WHERE operation_id=NEW.operation_id;
                 END;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut late_ledger, plan(7)),
            WalIdempotencyError::Corrupt
        );
        assert!(load_wrapped_dek(&late_ledger).unwrap().is_none());
        assert_eq!(load_ledger_state(&late_ledger).unwrap(), (0, 0));
    }
}
