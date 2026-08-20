#![allow(
    dead_code,
    reason = "inactive ADR-0022 email settlement is reviewed before launcher or worker ownership"
)]

//! Inactive provider-accepted email WAL domain.
//!
//! The existing delivery ID is the provider idempotency key and is durable
//! before any send. A future send boundary may construct this plan only after
//! receiving a definitive provider acceptance. This child can then settle the
//! exact local predecessor row and retain unit replay. It cannot send email,
//! allocate a delivery or retry, call Store, launch work, or acknowledge a
//! request.

pub(super) mod cancellation;
pub(super) mod settlement;
pub(in crate::cp) use cancellation::CancellableDelivery;
pub(crate) use cancellation::{EmailDeliveryCancellationLedger, EmailDeliveryCancellationPlan};
pub(in crate::cp) use settlement::EmailDeliveryPredecessor;
pub(crate) use settlement::{EmailDeliverySettlementLedger, EmailDeliverySettlementPlan};

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const STATE_PENDING: u8 = 1;
const STATE_RETRY: u8 = 2;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_DELIVERY_ID_BYTES: usize = 70;
const MAX_PROVIDER_MESSAGE_ID_BYTES: usize = 512;
const MAX_ERROR_CODE_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const SCHEMA_TABLE: &str = "archive_v3_wal_email_accepted_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_email_accepted_operations";
const STATE_TABLE: &str = "archive_v3_wal_email_accepted_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedState {
    Pending,
    Retry,
}

impl ExpectedState {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "retry" => Ok(Self::Retry),
            _ => Err(WalIdempotencyError::Malformed),
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Pending => STATE_PENDING,
            Self::Retry => STATE_RETRY,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Retry => "retry",
        }
    }
}

/// Exact local half of one definitive provider acceptance. The delivery ID
/// already exists and is also the provider idempotency key; every mutable
/// predecessor fact and every accepted result fact is fingerprinted before
/// actor admission.
pub(crate) struct EmailAcceptedPlan {
    operation_id: WalLogicalOperationId,
    delivery_id: String,
    episode_id: i64,
    delivery_version: i32,
    include_content: bool,
    expected_state: ExpectedState,
    expected_attempt_count: i32,
    expected_next_attempt_at: String,
    expected_response_status: Option<u16>,
    expected_error_code: Option<String>,
    created_at: String,
    expected_updated_at: String,
    provider_message_id: String,
    accepted_status: u16,
    accepted_at: String,
}

impl EmailAcceptedPlan {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        delivery_id: String,
        episode_id: i64,
        delivery_version: i32,
        include_content: bool,
        expected_state: String,
        expected_attempt_count: i32,
        expected_next_attempt_at: String,
        expected_response_status: Option<u16>,
        expected_error_code: Option<String>,
        created_at: String,
        expected_updated_at: String,
        provider_message_id: String,
        accepted_status: u16,
        accepted_at: String,
    ) -> Result<Self> {
        Self::build(
            None,
            delivery_id,
            episode_id,
            delivery_version,
            include_content,
            expected_state,
            expected_attempt_count,
            expected_next_attempt_at,
            expected_response_status,
            expected_error_code,
            created_at,
            expected_updated_at,
            provider_message_id,
            accepted_status,
            accepted_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        operation_id: Option<WalLogicalOperationId>,
        delivery_id: String,
        episode_id: i64,
        delivery_version: i32,
        include_content: bool,
        expected_state: String,
        expected_attempt_count: i32,
        expected_next_attempt_at: String,
        expected_response_status: Option<u16>,
        expected_error_code: Option<String>,
        created_at: String,
        expected_updated_at: String,
        provider_message_id: String,
        accepted_status: u16,
        accepted_at: String,
    ) -> Result<Self> {
        validate_delivery_id(&delivery_id)?;
        if episode_id <= 0
            || delivery_version <= 0
            || !(0..i32::MAX).contains(&expected_attempt_count)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let expected_state = ExpectedState::parse(&expected_state)?;
        validate_timestamp(&expected_next_attempt_at)?;
        validate_timestamp(&created_at)?;
        validate_timestamp(&expected_updated_at)?;
        validate_timestamp(&accepted_at)?;
        if timestamp_millis(&created_at)? > timestamp_millis(&expected_updated_at)?
            || timestamp_millis(&expected_updated_at)? > timestamp_millis(&accepted_at)?
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if expected_response_status.is_some_and(|status| !(100..=599).contains(&status))
            || !(200..=299).contains(&accepted_status)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if let Some(code) = &expected_error_code {
            validate_bounded_text(code, MAX_ERROR_CODE_BYTES)?;
        }
        validate_bounded_text(&provider_message_id, MAX_PROVIDER_MESSAGE_ID_BYTES)?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => WalLogicalOperationId::from_stable_source(
                WalOperationKind::EmailDelivery,
                delivery_id.as_bytes(),
            )?,
        };
        Ok(Self {
            operation_id,
            delivery_id,
            episode_id,
            delivery_version,
            include_content,
            expected_state,
            expected_attempt_count,
            expected_next_attempt_at,
            expected_response_status,
            expected_error_code,
            created_at,
            expected_updated_at,
            provider_message_id,
            accepted_status,
            accepted_at,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        delivery_id: &str,
        episode_id: i64,
        delivery_version: i32,
        include_content: bool,
        expected_state: &str,
        expected_attempt_count: i32,
        expected_next_attempt_at: &str,
        expected_response_status: Option<u16>,
        expected_error_code: Option<&str>,
        created_at: &str,
        expected_updated_at: &str,
        provider_message_id: &str,
        accepted_status: u16,
        accepted_at: &str,
    ) -> Result<Self> {
        Self::build(
            Some(operation_id),
            delivery_id.to_owned(),
            episode_id,
            delivery_version,
            include_content,
            expected_state.to_owned(),
            expected_attempt_count,
            expected_next_attempt_at.to_owned(),
            expected_response_status,
            expected_error_code.map(str::to_owned),
            created_at.to_owned(),
            expected_updated_at.to_owned(),
            provider_message_id.to_owned(),
            accepted_status,
            accepted_at.to_owned(),
        )
    }
}

pub(crate) struct EmailAcceptedLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for EmailAcceptedPlan {
    type Ledger = EmailAcceptedLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::EmailDelivery
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(1_024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_string(&mut request, &self.delivery_id)?;
        request.extend_from_slice(&self.episode_id.to_be_bytes());
        request.extend_from_slice(&self.delivery_version.to_be_bytes());
        request.push(u8::from(self.include_content));
        request.push(self.expected_state.tag());
        request.extend_from_slice(&self.expected_attempt_count.to_be_bytes());
        encode_string(&mut request, &self.expected_next_attempt_at)?;
        encode_optional_status(&mut request, self.expected_response_status);
        encode_optional_string(&mut request, self.expected_error_code.as_deref())?;
        encode_string(&mut request, &self.created_at)?;
        encode_string(&mut request, &self.expected_updated_at)?;
        encode_string(&mut request, &self.provider_message_id)?;
        request.extend_from_slice(&self.accepted_status.to_be_bytes());
        encode_string(&mut request, &self.accepted_at)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let Some(stored) = load_email_row(transaction, &self.delivery_id)? else {
            return Err(WalIdempotencyError::Precondition);
        };
        if stored.matches_terminal(self) {
            return Ok(WalReplayResult::unit());
        }
        if !stored.matches_pending(self) {
            return Err(WalIdempotencyError::Precondition);
        }
        let next_attempt_count = self
            .expected_attempt_count
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?;
        let changed = transaction
            .execute(
                "UPDATE email_deliveries
                 SET state='accepted',attempt_count=?1,provider_message_id=?2,
                     response_status=?3,error_code=NULL,updated_at=?4
                 WHERE delivery_id=?5 AND episode_id=?6 AND delivery_version=?7
                   AND include_content=?8 AND state=?9 AND attempt_count=?10
                   AND next_attempt_at=?11 AND provider_message_id IS NULL
                   AND response_status IS ?12 AND error_code IS ?13
                   AND created_at=?14 AND updated_at=?15",
                params![
                    next_attempt_count,
                    self.provider_message_id,
                    i64::from(self.accepted_status),
                    self.accepted_at,
                    self.delivery_id,
                    self.episode_id,
                    self.delivery_version,
                    i64::from(self.include_content),
                    self.expected_state.as_str(),
                    self.expected_attempt_count,
                    self.expected_next_attempt_at,
                    self.expected_response_status.map(i64::from),
                    self.expected_error_code,
                    self.created_at,
                    self.expected_updated_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        let settled =
            load_email_row(transaction, &self.delivery_id)?.ok_or(WalIdempotencyError::Corrupt)?;
        if !settled.matches_terminal(self) {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(WalReplayResult::unit())
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        match result {
            WalReplayResult::UnitApplied => Ok(()),
            WalReplayResult::CanonicalResponse(_) => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)
    }
}

impl WalLogicalDomainLedger<EmailAcceptedPlan> for EmailAcceptedLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<EmailAcceptedPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,
                        result_bytes,result_commitment
                 FROM archive_v3_wal_email_accepted_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some((format, codec, fingerprint, encoded, commitment)) = row else {
            return Ok(None);
        };
        let kind = WalOperationKind::EmailDelivery;
        if format != i64::from(WalOperationKind::format_version())
            || codec != i64::from(kind.codec_version())
            || fingerprint.len() != 32
            || commitment.len() != 32
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        if fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        let result = WalReplayResult::decode(kind, &encoded)?;
        if commitment.as_slice() != result.commitment(kind)?.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<EmailAcceptedPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::EmailDelivery;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_email_accepted_operations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let previous_result_bytes =
            i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_email_accepted_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    previous_result_bytes,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct StoredEmailRow {
    episode_id: i64,
    delivery_version: i32,
    include_content: bool,
    state: String,
    attempt_count: i32,
    next_attempt_at: String,
    provider_message_id: Option<String>,
    response_status: Option<u16>,
    error_code: Option<String>,
    created_at: String,
    updated_at: String,
}

impl StoredEmailRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let include_content = row.get::<_, i64>(2)?;
        let response_status = row
            .get::<_, Option<i64>>(7)?
            .map(|value| {
                u16::try_from(value).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })
            })
            .transpose()?;
        Ok(Self {
            episode_id: row.get(0)?,
            delivery_version: row.get(1)?,
            include_content: include_content != 0,
            state: row.get(3)?,
            attempt_count: row.get(4)?,
            next_attempt_at: row.get(5)?,
            provider_message_id: row.get(6)?,
            response_status,
            error_code: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
        })
    }

    fn matches_identity(&self, plan: &EmailAcceptedPlan) -> bool {
        self.episode_id == plan.episode_id
            && self.delivery_version == plan.delivery_version
            && self.include_content == plan.include_content
            && self.next_attempt_at == plan.expected_next_attempt_at
            && self.created_at == plan.created_at
    }

    fn matches_pending(&self, plan: &EmailAcceptedPlan) -> bool {
        self.matches_identity(plan)
            && self.state == plan.expected_state.as_str()
            && self.attempt_count == plan.expected_attempt_count
            && self.provider_message_id.is_none()
            && self.response_status == plan.expected_response_status
            && self.error_code == plan.expected_error_code
            && self.updated_at == plan.expected_updated_at
    }

    fn matches_terminal(&self, plan: &EmailAcceptedPlan) -> bool {
        self.matches_identity(plan)
            && self.state == "accepted"
            && self.attempt_count == plan.expected_attempt_count.saturating_add(1)
            && self.provider_message_id.as_deref() == Some(plan.provider_message_id.as_str())
            && self.response_status == Some(plan.accepted_status)
            && self.error_code.is_none()
            && self.updated_at == plan.accepted_at
    }
}

fn load_email_row(connection: &Connection, delivery_id: &str) -> Result<Option<StoredEmailRow>> {
    connection
        .query_row(
            "SELECT episode_id,delivery_version,include_content,state,attempt_count,
                    next_attempt_at,provider_message_id,response_status,error_code,
                    created_at,updated_at
             FROM email_deliveries WHERE delivery_id=?1",
            [delivery_id],
            StoredEmailRow::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn require_kind(prepared: &PreparedLogicalMutation<EmailAcceptedPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::EmailDelivery)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn validate_delivery_id(value: &str) -> Result<()> {
    let suffix = value.strip_prefix("deliv_");
    if value.len() != MAX_DELIVERY_ID_BYTES
        || suffix.is_none_or(|suffix| {
            suffix.len() != 64
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_bounded_text(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn timestamp_millis(value: &str) -> Result<i64> {
    super::super::isotime::parse_epoch_millis(value).ok_or(WalIdempotencyError::Malformed)
}

fn validate_timestamp(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TIMESTAMP_BYTES {
        return Err(WalIdempotencyError::Malformed);
    }
    let millis = timestamp_millis(value)?;
    if super::super::isotime::format_epoch_millis(millis) != value {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    if length == 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            encode_string(output, value)?;
        }
    }
    Ok(())
}

fn encode_optional_status(output: &mut Vec<u8>, value: Option<u16>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
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
                    "CREATE TABLE archive_v3_wal_email_accepted_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_email_accepted_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes)=9),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_email_accepted_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_email_accepted_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_email_accepted_state
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
             FROM archive_v3_wal_email_accepted_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::EmailDelivery.codec_version()),
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
             FROM archive_v3_wal_email_accepted_state WHERE singleton=1",
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
    Ok((row_count, result_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use tempfile::tempdir;

    const DELIVERY: &str = "deliv_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DELIVERY_TWO: &str =
        "deliv_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEXT_AT: &str = "2026-08-14T12:00:00.000Z";
    const CREATED_AT: &str = "2026-08-14T11:59:00.000Z";
    const UPDATED_AT: &str = "2026-08-14T12:00:00.000Z";
    const ACCEPTED_AT: &str = "2026-08-14T12:00:01.000Z";
    const PROVIDER_ID: &str = "resend-message-0001";

    fn install_domain_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE email_deliveries (
                    episode_id INTEGER NOT NULL,
                    delivery_version INTEGER NOT NULL,
                    delivery_id TEXT NOT NULL UNIQUE,
                    include_content INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL,
                    provider_message_id TEXT,
                    response_status INTEGER,
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (episode_id,delivery_version)
                 ) STRICT;",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

    fn insert_email(connection: &Connection, delivery_id: &str, episode_id: i64, state: &str) {
        connection
            .execute(
                "INSERT INTO email_deliveries
                 (episode_id,delivery_version,delivery_id,include_content,state,
                  attempt_count,next_attempt_at,provider_message_id,response_status,
                  error_code,created_at,updated_at)
                 VALUES (?1,3,?2,1,?3,2,?4,NULL,503,'http_503',?5,?6)",
                params![
                    episode_id,
                    delivery_id,
                    state,
                    NEXT_AT,
                    CREATED_AT,
                    UPDATED_AT
                ],
            )
            .unwrap();
    }

    fn plan_for(delivery_id: &str, episode_id: i64) -> EmailAcceptedPlan {
        EmailAcceptedPlan::new(
            delivery_id.into(),
            episode_id,
            3,
            true,
            "retry".into(),
            2,
            NEXT_AT.into(),
            Some(503),
            Some("http_503".into()),
            CREATED_AT.into(),
            UPDATED_AT.into(),
            PROVIDER_ID.into(),
            200,
            ACCEPTED_AT.into(),
        )
        .unwrap()
    }

    fn explicit_id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    #[test]
    fn stable_identity_is_kind_scoped_and_request_binds_predecessor_and_acceptance() {
        let first = plan_for(DELIVERY, 41);
        let replay = plan_for(DELIVERY, 41);
        assert_eq!(first.operation_id(), replay.operation_id());
        assert_eq!(
            first.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(
            first.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::WebhookDelivery,
                DELIVERY.as_bytes(),
            )
            .unwrap()
        );
        let changed = EmailAcceptedPlan::new(
            DELIVERY.into(),
            41,
            3,
            true,
            "retry".into(),
            2,
            NEXT_AT.into(),
            Some(503),
            Some("http_503".into()),
            CREATED_AT.into(),
            UPDATED_AT.into(),
            "another-provider-id".into(),
            200,
            ACCEPTED_AT.into(),
        )
        .unwrap();
        assert_ne!(
            first.canonical_request().unwrap(),
            changed.canonical_request().unwrap()
        );
        assert!(EmailAcceptedPlan::new(
            "deliv_not-hex".into(),
            41,
            3,
            true,
            "retry".into(),
            2,
            NEXT_AT.into(),
            None,
            None,
            CREATED_AT.into(),
            UPDATED_AT.into(),
            PROVIDER_ID.into(),
            200,
            ACCEPTED_AT.into(),
        )
        .is_err());
        assert!(EmailAcceptedPlan::new(
            DELIVERY.into(),
            41,
            3,
            true,
            "retry".into(),
            2,
            NEXT_AT.into(),
            None,
            None,
            CREATED_AT.into(),
            UPDATED_AT.into(),
            PROVIDER_ID.into(),
            500,
            ACCEPTED_AT.into(),
        )
        .is_err());
    }

    #[test]
    fn exact_retry_settlement_applies_once_and_replays_without_rewriting() {
        let mut connection = connection();
        insert_email(&connection, DELIVERY, 41, "retry");
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        applied.into_validated_result().release().unwrap();
        let stored = load_email_row(&connection, DELIVERY).unwrap().unwrap();
        assert_eq!(stored.state, "accepted");
        assert_eq!(stored.attempt_count, 3);
        assert_eq!(stored.provider_message_id.as_deref(), Some(PROVIDER_ID));
        assert_eq!(stored.response_status, Some(200));
        assert_eq!(stored.updated_at, ACCEPTED_AT);

        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(load_ledger_state(&connection).unwrap(), (1, 9));
    }

    #[test]
    fn pending_predecessor_is_supported_with_its_exact_null_outcome() {
        let mut connection = connection();
        insert_email(&connection, DELIVERY, 41, "pending");
        connection
            .execute(
                "UPDATE email_deliveries SET attempt_count=0,response_status=NULL,
                 error_code=NULL WHERE delivery_id=?1",
                [DELIVERY],
            )
            .unwrap();
        let pending = EmailAcceptedPlan::new(
            DELIVERY.into(),
            41,
            3,
            true,
            "pending".into(),
            0,
            NEXT_AT.into(),
            None,
            None,
            CREATED_AT.into(),
            UPDATED_AT.into(),
            PROVIDER_ID.into(),
            202,
            ACCEPTED_AT.into(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(pending).unwrap(),
        )
        .unwrap();
        let stored = load_email_row(&connection, DELIVERY).unwrap().unwrap();
        assert_eq!(stored.state, "accepted");
        assert_eq!(stored.attempt_count, 1);
        assert_eq!(stored.response_status, Some(202));
    }

    #[test]
    fn missing_precondition_rolls_back_lazy_schema_then_same_identity_applies() {
        let mut connection = connection();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name LIKE 'archive_v3_wal_email_accepted_%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        insert_email(&connection, DELIVERY, 41, "retry");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn every_substituted_row_fact_and_ineligible_state_fails_closed() {
        for mutation in [
            "UPDATE email_deliveries SET episode_id=42",
            "UPDATE email_deliveries SET delivery_version=4",
            "UPDATE email_deliveries SET include_content=0",
            "UPDATE email_deliveries SET state='failed'",
            "UPDATE email_deliveries SET attempt_count=3",
            "UPDATE email_deliveries SET next_attempt_at='2026-08-14T12:00:02.000Z'",
            "UPDATE email_deliveries SET provider_message_id='old'",
            "UPDATE email_deliveries SET response_status=502",
            "UPDATE email_deliveries SET error_code='http_502'",
            "UPDATE email_deliveries SET created_at='2026-08-14T11:58:00.000Z'",
            "UPDATE email_deliveries SET updated_at='2026-08-14T12:00:02.000Z'",
        ] {
            let mut connection = connection();
            insert_email(&connection, DELIVERY, 41, "retry");
            connection.execute(mutation, []).unwrap();
            assert_eq!(
                execute_prepared_for_owner(
                    &mut connection,
                    PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
                )
                .err()
                .unwrap(),
                WalIdempotencyError::Precondition,
                "mutation should fail: {mutation}"
            );
        }
    }

    #[test]
    fn exact_preexisting_terminal_is_adopted_but_alternate_acceptance_is_rejected() {
        let mut adopted = connection();
        insert_email(&adopted, DELIVERY, 41, "retry");
        adopted
            .execute(
                "UPDATE email_deliveries SET state='accepted',attempt_count=3,
                 provider_message_id=?1,response_status=200,error_code=NULL,updated_at=?2",
                params![PROVIDER_ID, ACCEPTED_AT],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut adopted,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Applied
        );

        let mut conflict = connection();
        insert_email(&conflict, DELIVERY, 41, "retry");
        conflict
            .execute(
                "UPDATE email_deliveries SET state='accepted',attempt_count=3,
                 provider_message_id='other',response_status=200,error_code=NULL,updated_at=?1",
                [ACCEPTED_AT],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut conflict,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn capacity_is_reserved_before_mutation_and_existing_replay_survives() {
        let mut connection = connection();
        insert_email(&connection, DELIVERY, 41, "retry");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_email_accepted_state SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        insert_email(&connection, DELIVERY_TWO, 42, "retry");
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY_TWO, 42)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            load_email_row(&connection, DELIVERY_TWO)
                .unwrap()
                .unwrap()
                .state,
            "retry"
        );
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_the_email_transition() {
        let mut connection = connection();
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_email_wal_insert
                 BEFORE INSERT ON archive_v3_wal_email_accepted_operations
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        insert_email(&connection, DELIVERY, 41, "retry");
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Unavailable
        );
        let stored = load_email_row(&connection, DELIVERY).unwrap().unwrap();
        assert_eq!(stored.state, "retry");
        assert_eq!(stored.attempt_count, 2);
        assert_eq!(load_ledger_state(&connection).unwrap(), (0, 0));
    }

    #[test]
    fn changed_same_delivery_conflicts_and_result_tamper_fails_closed() {
        let mut connection = connection();
        insert_email(&connection, DELIVERY, 41, "retry");
        let fixed = || {
            EmailAcceptedPlan::with_operation_id(
                explicit_id(9),
                DELIVERY,
                41,
                3,
                true,
                "retry",
                2,
                NEXT_AT,
                Some(503),
                Some("http_503"),
                CREATED_AT,
                UPDATED_AT,
                PROVIDER_ID,
                200,
                ACCEPTED_AT,
            )
            .unwrap()
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(fixed()).unwrap(),
        )
        .unwrap();
        let changed = EmailAcceptedPlan::with_operation_id(
            explicit_id(9),
            DELIVERY,
            41,
            3,
            true,
            "retry",
            2,
            NEXT_AT,
            Some(503),
            Some("http_503"),
            CREATED_AT,
            UPDATED_AT,
            "different-provider-id",
            200,
            ACCEPTED_AT,
        )
        .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(changed).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::FingerprintConflict
        );
        connection
            .execute(
                "UPDATE archive_v3_wal_email_accepted_operations
                 SET result_commitment=?1",
                [[7u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(fixed()).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn close_reopen_replays_exactly_and_admits_the_next_delivery() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("email.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            install_domain_schema(&connection);
            insert_email(&connection, DELIVERY, 41, "retry");
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
            )
            .unwrap();
        }
        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut reopened,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        insert_email(&reopened, DELIVERY_TWO, 42, "retry");
        assert_eq!(
            execute_prepared_for_owner(
                &mut reopened,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY_TWO, 42)).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(load_ledger_state(&reopened).unwrap(), (2, 18));
    }

    #[test]
    fn partial_schema_is_rejected() {
        let mut connection = connection();
        connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_email_accepted_schema (
                    singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        insert_email(&connection, DELIVERY, 41, "retry");
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan_for(DELIVERY, 41)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }
}
