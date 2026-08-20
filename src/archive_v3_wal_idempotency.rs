#![allow(
    dead_code,
    reason = "inactive ADR-0022 logical-write gate is compiled before production launcher or serving activation"
)]

//! Inactive, fail-closed logical-operation idempotency gate for archive-v3 WAL.
//!
//! Replay rows are permanent within their exact owning operation
//! domain. A caller cannot use a universal receipt table: it must hold a
//! module-sealed domain plan whose distinct, bounded ledger fixes the request
//! fingerprint, indexed resolver, and exact replay-result policy. A bounded
//! test exemplar plus separately reviewed capture-session-finish,
//! metadata-only screen-reference-batch, selected-screenshot receipt,
//! caller-stable finalization queue, exact finalization commit, screen-storyboard
//! result without person evidence, raw-media retention settlement,
//! provider-accepted delivery, Vertex usage, reviewer-fixture,
//! substance-backfill, and visual-evidence-backfill children implement that
//! contract; every other production domain remains unsealed.
//! This module performs only local SQLite transactions and derives opaque
//! identifiers. It has no Store connection, launcher, publisher construction,
//! capture, root, witness, provider, route, worker, or startup path.
//!
//! The private owner enforces this order once a future launcher supplies it a
//! sealed plan:
//! derive stable ID/fingerprint before actor admission; reconcile any pending
//! attempt; enter `BEGIN IMMEDIATE`; resolve-or-apply the domain mutation and
//! exact result atomically; capture the same ID/fingerprint; publish and exact-
//! read back immutable objects; CAS/reconcile the witness; settle publication;
//! only then expose the retained result. Cancellation after a local commit but
//! before settlement must poison that actor until durable reconciliation.

use rusqlite::{Connection, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{any::Any, fmt, sync::atomic::AtomicBool};
use thiserror::Error;
use zeroize::Zeroizing;

const WAL_IDEMPOTENCY_FORMAT_V1: u16 = 1;
const OPERATION_ID_DOMAIN: &[u8] = b"kioku/archive-v3/wal-logical-operation-id/v1\0";
const REQUEST_FINGERPRINT_DOMAIN: &[u8] = b"kioku/archive-v3/wal-logical-request-fingerprint/v1\0";
const REPLAY_RESULT_DOMAIN: &[u8] = b"kioku/archive-v3/wal-logical-replay-result/v1\0";
const MAX_CANONICAL_WAL_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_CANONICAL_REPLAY_RESULT_BYTES: usize = 4096;
pub(crate) const MAX_ENCODED_REPLAY_RESULT_BYTES: usize = MAX_CANONICAL_REPLAY_RESULT_BYTES + 9;
const RESULT_UNIT: u8 = 1;
const RESULT_CANONICAL_RESPONSE: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum WalIdempotencyError {
    #[error("WAL logical operation input is malformed")]
    Malformed,
    #[error("WAL logical operation exceeded a fixed bound")]
    Limit,
    #[error("WAL logical operation state is corrupt or unsupported")]
    Corrupt,
    #[error("WAL logical operation ID was reused for a different request")]
    FingerprintConflict,
    #[error("WAL logical operation domain rejected the replay result")]
    ResultUnsupported,
    #[error("WAL logical operation precondition is not satisfied")]
    Precondition,
    #[error("WAL logical operation transaction is unavailable")]
    Unavailable,
}

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// Stable portable domains approved for future conversion. Attempt counters,
/// wall-clock retry bookkeeping, auto-ID creation, arbitrary SQL, purge, and
/// account deletion deliberately have no variant and remain disabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum WalOperationKind {
    MediaCaptureEvent = 1,
    CaptureSessionFinish = 2,
    SelectedScreenshot = 3,
    FinalizationQueue = 4,
    FinalizationCommit = 5,
    DeterministicMediaWorkResult = 6,
    VertexUsage = 7,
    WebhookDelivery = 8,
    EmailDelivery = 9,
    PushDelivery = 10,
    Retention = 11,
    ReviewerBackfill = 12,
    /// One append-only product schema ladder step, applied under the owner's
    /// own lease and published as an ordinary settled WAL commit
    /// (`src/schema_ladder.rs`). The first ordinal added after the Phase-2
    /// deletion: no signing ceremony backed it, deliberately -- the
    /// compile-pinned mutation-set commitment is gone, and the reviewed-plan
    /// seal plus this enum are the whole admission story now.
    SchemaEpochAdvance = 13,
}

impl WalOperationKind {
    pub(crate) fn decode(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::MediaCaptureEvent),
            2 => Ok(Self::CaptureSessionFinish),
            3 => Ok(Self::SelectedScreenshot),
            4 => Ok(Self::FinalizationQueue),
            5 => Ok(Self::FinalizationCommit),
            6 => Ok(Self::DeterministicMediaWorkResult),
            7 => Ok(Self::VertexUsage),
            8 => Ok(Self::WebhookDelivery),
            9 => Ok(Self::EmailDelivery),
            10 => Ok(Self::PushDelivery),
            11 => Ok(Self::Retention),
            12 => Ok(Self::ReviewerBackfill),
            13 => Ok(Self::SchemaEpochAdvance),
            _ => Err(WalIdempotencyError::Corrupt),
        }
    }

    pub(crate) const fn codec_version(self) -> u16 {
        match self {
            Self::MediaCaptureEvent
            | Self::CaptureSessionFinish
            | Self::SelectedScreenshot
            | Self::FinalizationQueue
            | Self::FinalizationCommit
            | Self::DeterministicMediaWorkResult
            | Self::VertexUsage
            | Self::WebhookDelivery
            | Self::EmailDelivery
            | Self::PushDelivery
            | Self::Retention
            | Self::ReviewerBackfill
            | Self::SchemaEpochAdvance => 1,
        }
    }

    const fn permits_canonical_response(self) -> bool {
        matches!(
            self,
            Self::MediaCaptureEvent
                | Self::CaptureSessionFinish
                | Self::SelectedScreenshot
                | Self::VertexUsage
        )
    }

    pub(crate) const fn format_version() -> u16 {
        WAL_IDEMPOTENCY_FORMAT_V1
    }
}

/// Nonzero stable ID supplied by the portable domain, never allocated after a
/// mutation begins.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalLogicalOperationId([u8; 16]);

/// Length-prefixed framing for one canonical field.
///
/// Two distinct field vectors must never produce identical bytes by
/// concatenation: `("ab","c")` and `("a","bc")` differ only because each field
/// carries its own length. Every plan family authored after the ADR-0022
/// genesis-first replan frames its canonical request and its stable operation
/// source through this helper.
pub(crate) fn hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<()> {
    hasher.update(
        u32::try_from(value.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    hasher.update(value);
    Ok(())
}

/// Build a domain-separated, length-prefixed stable operation source.
///
/// Several plan families legitimately share one `WalOperationKind` ordinal
/// (adding an ordinal is a reviewed, signed act). The existing families derive
/// their operation id from a BARE durable id with no family prefix, and there
/// is no global operation index to catch a collision — so two families sharing
/// an ordinal and a natural key would silently collide on one ledger row.
/// Every family added from now on derives its id through this: the subtype is
/// framed first, then each field, so no combination of subtype and fields can
/// alias another family's source.
pub(crate) fn stable_operation_source(subtype: &[u8], fields: &[&[u8]]) -> Result<Vec<u8>> {
    if subtype.is_empty() {
        return Err(WalIdempotencyError::Malformed);
    }
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, subtype)?;
    for field in fields {
        hash_field(&mut hasher, field)?;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut source = Vec::with_capacity(1 + subtype.len() + 32);
    // The subtype stays in the clear so a durable id remains attributable to
    // its family during forensics; the digest binds every field exactly.
    source.extend_from_slice(subtype);
    source.push(0);
    source.extend_from_slice(&digest);
    Ok(source)
}

impl WalLogicalOperationId {
    pub(crate) fn from_bytes(value: [u8; 16]) -> Result<Self> {
        value
            .iter()
            .any(|byte| *byte != 0)
            .then_some(Self(value))
            .ok_or(WalIdempotencyError::Malformed)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Derives an opaque operation ID from an originating domain's already
    /// validated, caller-stable source identity. The source is fixed before
    /// actor admission; retries derive the same ID without a counter, clock,
    /// random allocation, or database lookup.
    pub(crate) fn from_stable_source(
        kind: WalOperationKind,
        canonical_source: &[u8],
    ) -> Result<Self> {
        if canonical_source.is_empty() || canonical_source.len() > MAX_CANONICAL_WAL_REQUEST_BYTES {
            return Err(if canonical_source.is_empty() {
                WalIdempotencyError::Malformed
            } else {
                WalIdempotencyError::Limit
            });
        }
        let source_length =
            u32::try_from(canonical_source.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let mut hasher = Sha256::new();
        hasher.update(OPERATION_ID_DOMAIN);
        hasher.update(WAL_IDEMPOTENCY_FORMAT_V1.to_be_bytes());
        hasher.update((kind as u16).to_be_bytes());
        hasher.update(kind.codec_version().to_be_bytes());
        hasher.update(source_length.to_be_bytes());
        hasher.update(canonical_source);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut value = [0u8; 16];
        value.copy_from_slice(&digest[..16]);
        if value == [0; 16] {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for WalLogicalOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalLogicalOperationId(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalRequestFingerprint([u8; 32]);

impl WalRequestFingerprint {
    fn derive(kind: WalOperationKind, canonical_request: &[u8]) -> Result<Self> {
        if canonical_request.is_empty() {
            return Err(WalIdempotencyError::Malformed);
        }
        if canonical_request.len() > MAX_CANONICAL_WAL_REQUEST_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_FINGERPRINT_DOMAIN);
        hasher.update(WAL_IDEMPOTENCY_FORMAT_V1.to_be_bytes());
        hasher.update((kind as u16).to_be_bytes());
        hasher.update(kind.codec_version().to_be_bytes());
        hasher.update((canonical_request.len() as u32).to_be_bytes());
        hasher.update(canonical_request);
        let fingerprint: [u8; 32] = hasher.finalize().into();
        if fingerprint == [0; 32] {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(Self(fingerprint))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_control_bytes(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        value: [u8; 32],
    ) -> Result<Self> {
        (value != [0; 32])
            .then_some(Self(value))
            .ok_or(WalIdempotencyError::Malformed)
    }

    #[cfg(test)]
    pub(crate) fn for_owner_test(value: [u8; 32]) -> Result<Self> {
        (value != [0; 32])
            .then_some(Self(value))
            .ok_or(WalIdempotencyError::Malformed)
    }
}

impl fmt::Debug for WalRequestFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalRequestFingerprint(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum WalReplayResult {
    UnitApplied,
    CanonicalResponse(Zeroizing<Vec<u8>>),
}

impl WalReplayResult {
    pub(crate) fn unit() -> Self {
        Self::UnitApplied
    }

    pub(crate) fn canonical_response(kind: WalOperationKind, bytes: Vec<u8>) -> Result<Self> {
        if !kind.permits_canonical_response() {
            return Err(WalIdempotencyError::ResultUnsupported);
        }
        if bytes.is_empty() {
            return Err(WalIdempotencyError::Malformed);
        }
        if bytes.len() > MAX_CANONICAL_REPLAY_RESULT_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        Ok(Self::CanonicalResponse(Zeroizing::new(bytes)))
    }

    pub(crate) fn encode(&self, kind: WalOperationKind) -> Result<Zeroizing<Vec<u8>>> {
        let mut encoded = Zeroizing::new(Vec::new());
        encoded.extend_from_slice(&WAL_IDEMPOTENCY_FORMAT_V1.to_be_bytes());
        encoded.extend_from_slice(&(kind as u16).to_be_bytes());
        match self {
            Self::UnitApplied => {
                encoded.push(RESULT_UNIT);
                encoded.extend_from_slice(&0u32.to_be_bytes());
            }
            Self::CanonicalResponse(bytes) => {
                if !kind.permits_canonical_response() || bytes.is_empty() {
                    return Err(WalIdempotencyError::ResultUnsupported);
                }
                if bytes.len() > MAX_CANONICAL_REPLAY_RESULT_BYTES {
                    return Err(WalIdempotencyError::Limit);
                }
                encoded.push(RESULT_CANONICAL_RESPONSE);
                encoded.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                encoded.extend_from_slice(bytes);
            }
        }
        Ok(encoded)
    }

    pub(crate) fn decode(kind: WalOperationKind, encoded: &[u8]) -> Result<Self> {
        if encoded.len() < 9 || encoded.len() > MAX_CANONICAL_REPLAY_RESULT_BYTES + 9 {
            return Err(WalIdempotencyError::Corrupt);
        }
        let version = u16::from_be_bytes([encoded[0], encoded[1]]);
        let stored_kind = u16::from_be_bytes([encoded[2], encoded[3]]);
        let length = u32::from_be_bytes([encoded[5], encoded[6], encoded[7], encoded[8]]) as usize;
        if version != WAL_IDEMPOTENCY_FORMAT_V1
            || stored_kind != kind as u16
            || encoded.len() != 9 + length
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        match encoded[4] {
            RESULT_UNIT if length == 0 => Ok(Self::UnitApplied),
            RESULT_CANONICAL_RESPONSE
                if kind.permits_canonical_response()
                    && (1..=MAX_CANONICAL_REPLAY_RESULT_BYTES).contains(&length) =>
            {
                Ok(Self::CanonicalResponse(Zeroizing::new(
                    encoded[9..].to_vec(),
                )))
            }
            _ => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    pub(crate) fn commitment(&self, kind: WalOperationKind) -> Result<[u8; 32]> {
        let encoded = self.encode(kind)?;
        let mut hasher = Sha256::new();
        hasher.update(REPLAY_RESULT_DOMAIN);
        hasher.update((encoded.len() as u32).to_be_bytes());
        hasher.update(encoded.as_slice());
        let commitment: [u8; 32] = hasher.finalize().into();
        Ok(commitment)
    }
}

impl fmt::Debug for WalReplayResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnitApplied => formatter.write_str("WalReplayResult::UnitApplied"),
            Self::CanonicalResponse(bytes) => formatter
                .debug_tuple("WalReplayResult::CanonicalResponse")
                .field(&format_args!("<redacted:{} bytes>", bytes.len()))
                .finish(),
        }
    }
}

#[cfg(not(test))]
mod sealed {
    pub(crate) trait DomainLedger {}
    pub(crate) trait DomainPlan {}
}

// Deterministic cross-module actor fixtures may exercise the boundary, but
// production siblings cannot implement either sealed contract.
#[cfg(test)]
pub(crate) mod sealed {
    pub(crate) trait DomainLedger {}
    pub(crate) trait DomainPlan {}
}

/// Each supported domain owns request canonicalization, mutation SQL, and
/// exact replay validation. No generic closure or arbitrary SQL reaches the
/// permanent ledger surface.
pub(crate) trait WalLogicalDomainPlan: sealed::DomainPlan + Send + Sized + 'static {
    type Ledger: WalLogicalDomainLedger<Self>;
    /// The originating logical domain is the only code allowed to decode its
    /// bounded durable replay result into a caller-visible value.
    type Output: Send + 'static;

    fn kind(&self) -> WalOperationKind;
    fn operation_id(&self) -> WalLogicalOperationId;
    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>>;
    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult>;
    fn validate_replay(&self, result: &WalReplayResult) -> Result<()>;
    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output>;
}

/// Every portable domain owns a distinct, permanently retained, bounded row
/// family and its exact indexed resolver. The shared gate deliberately has no
/// universal table or table-name selector.
pub(crate) trait WalLogicalDomainLedger<P: WalLogicalDomainPlan>:
    sealed::DomainLedger + Send
{
    /// Exact indexed replay lookup. It must authenticate the same bounded
    /// domain result as `resolve_or_apply` without applying caller work.
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<P>,
    ) -> Result<Option<WalReplayResult>>;

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<P>,
    ) -> Result<LogicalMutationResult>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainLedgerBounds {
    max_rows: u32,
    max_result_bytes: u64,
}

impl DomainLedgerBounds {
    pub(crate) const fn new(max_rows: u32, max_result_bytes: u64) -> Self {
        Self {
            max_rows,
            max_result_bytes,
        }
    }

    pub(crate) fn admit(
        self,
        rows: u32,
        result_bytes: u64,
        next_result_bytes: usize,
    ) -> Result<()> {
        let next_result_bytes =
            u64::try_from(next_result_bytes).map_err(|_| WalIdempotencyError::Limit)?;
        if self.max_rows == 0
            || self.max_result_bytes == 0
            || rows >= self.max_rows
            || result_bytes
                .checked_add(next_result_bytes)
                .is_none_or(|total| total > self.max_result_bytes)
        {
            return Err(WalIdempotencyError::Limit);
        }
        Ok(())
    }
}

impl sealed::DomainPlan for crate::cp::media::wal::CaptureSessionFinishPlan {}
impl sealed::DomainLedger for crate::cp::media::wal::CaptureSessionFinishLedger {}
impl sealed::DomainPlan for crate::cp::media::wal::CanonicalCaptureEventPlan {}
impl sealed::DomainLedger for crate::cp::media::wal::CanonicalCaptureEventLedger {}
impl sealed::DomainPlan for crate::cp::media::wal::MediaDekInstallPlan {}
impl sealed::DomainLedger for crate::cp::media::wal::MediaDekInstallLedger {}
impl sealed::DomainPlan for crate::cp::media::wal::MediaReferenceBatchPlan {}
impl sealed::DomainLedger for crate::cp::media::wal::MediaReferenceBatchLedger {}
impl sealed::DomainPlan for crate::cp::model_usage::wal::VertexIntentReconcilePlan {}
impl sealed::DomainLedger for crate::cp::model_usage::wal::VertexIntentReconcileLedger {}
impl sealed::DomainPlan for crate::cp::model_usage::wal::VertexCoverageLedgerPlan {}
impl sealed::DomainLedger for crate::cp::model_usage::wal::VertexCoverageLedgerLedger {}
impl sealed::DomainPlan for crate::cp::model_usage::wal::VertexUsageDeliveryPlan {}
impl sealed::DomainLedger for crate::cp::model_usage::wal::VertexUsageDeliveryLedger {}
impl sealed::DomainPlan for crate::cp::model_usage::wal::VertexInvocationBeginPlan {}
impl sealed::DomainLedger for crate::cp::model_usage::wal::VertexInvocationBeginLedger {}
impl sealed::DomainPlan for crate::cp::model_usage::wal::VertexUsageOutcomePlan {}
impl sealed::DomainLedger for crate::cp::model_usage::wal::VertexUsageOutcomeLedger {}
impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotPlan {}
impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotLedger {}
impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotAttemptPlan {}
impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotAttemptLedger {}
impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotUploadCandidatePlan {}
impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotUploadCandidateLedger {}
impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotSendStartedPlan {}
impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotSendStartedLedger {}
impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotTerminationPlan {}
impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotTerminationLedger {}
impl sealed::DomainPlan for crate::cp::query::wal::FinalizationQueuePlan {}
impl sealed::DomainLedger for crate::cp::query::wal::FinalizationQueueLedger {}
impl sealed::DomainPlan for crate::cp::finalizer::FinalizationLifecyclePlan {}
impl sealed::DomainLedger for crate::cp::finalizer::FinalizationLifecycleLedger {}
impl sealed::DomainPlan for crate::cp::finalizer::FinalizationCommitPlan {}
impl sealed::DomainLedger for crate::cp::finalizer::FinalizationCommitLedger {}
impl sealed::DomainPlan for crate::cp::summarizer::wal::EpisodeEmbeddingBatchPlan {}
impl sealed::DomainLedger for crate::cp::summarizer::wal::EpisodeEmbeddingBatchLedger {}
impl sealed::DomainPlan for crate::cp::media_worker::wal::MediaWorkReservationPlan {}
impl sealed::DomainLedger for crate::cp::media_worker::wal::MediaWorkReservationLedger {}
impl sealed::DomainPlan for crate::cp::media_worker::wal::ScreenStoryboardResultPlan {}
impl sealed::DomainLedger for crate::cp::media_worker::wal::ScreenStoryboardResultLedger {}
impl sealed::DomainPlan for crate::cp::media_worker::wal::ScreenStoryboardAttemptPlan {}
impl sealed::DomainLedger for crate::cp::media_worker::wal::ScreenStoryboardAttemptLedger {}
impl sealed::DomainPlan for crate::cp::media_worker::wal::RetentionSettlementPlan {}
impl sealed::DomainLedger for crate::cp::media_worker::wal::RetentionSettlementLedger {}
impl sealed::DomainPlan for crate::cp::email_worker::wal::EmailAcceptedPlan {}
impl sealed::DomainLedger for crate::cp::email_worker::wal::EmailAcceptedLedger {}
impl sealed::DomainPlan for crate::cp::push::wal::PushAcceptedPlan {}
impl sealed::DomainLedger for crate::cp::push::wal::PushAcceptedLedger {}
impl sealed::DomainPlan for crate::cp::webhook_worker::wal::WebhookSentPlan {}
impl sealed::DomainLedger for crate::cp::webhook_worker::wal::WebhookSentLedger {}
impl sealed::DomainPlan for crate::cp::reviewer::wal::ReviewerFixturePlan {}
impl sealed::DomainLedger for crate::cp::reviewer::wal::ReviewerFixtureLedger {}
impl sealed::DomainPlan for crate::cp::summarizer::wal::SubstanceBackfillBatchPlan {}
impl sealed::DomainLedger for crate::cp::summarizer::wal::SubstanceBackfillBatchLedger {}
impl sealed::DomainPlan for crate::cp::summarizer::wal::VisualEvidenceBackfillBatchPlan {}
impl sealed::DomainLedger for crate::cp::summarizer::wal::VisualEvidenceBackfillBatchLedger {}

/// Opaque plan produced before actor entry. Only the private WAL owner
/// may consume it; callers cannot obtain its ID, fingerprint, SQL, or result.
pub(crate) struct PreparedLogicalMutation<P: WalLogicalDomainPlan> {
    plan: P,
    operation_id: WalLogicalOperationId,
    request_fingerprint: WalRequestFingerprint,
}

impl<P: WalLogicalDomainPlan> PreparedLogicalMutation<P> {
    pub(crate) fn prepare(plan: P) -> Result<Self> {
        let operation_id = plan.operation_id();
        let canonical_request = plan.canonical_request()?;
        let request_fingerprint = WalRequestFingerprint::derive(plan.kind(), &canonical_request)?;
        Ok(Self {
            plan,
            operation_id,
            request_fingerprint,
        })
    }

    pub(crate) fn kind_for_owner(&self) -> WalOperationKind {
        self.plan.kind()
    }

    pub(crate) const fn operation_id_for_owner(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    pub(crate) const fn request_fingerprint_for_owner(&self) -> WalRequestFingerprint {
        self.request_fingerprint
    }

    pub(crate) const fn plan_for_domain_ledger(&self) -> &P {
        &self.plan
    }
}

impl<P: WalLogicalDomainPlan> fmt::Debug for PreparedLogicalMutation<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedLogicalMutation(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogicalMutationDisposition {
    Applied,
    Replayed,
}

/// Opaque exact result of one domain-ledger resolution. Both first apply and
/// replay retain the bounded canonical result; the WAL owner may inspect only
/// the disposition while the domain codec remains the sole result decoder.
pub(crate) enum LogicalMutationResult {
    Applied(WalReplayResult),
    Replayed(WalReplayResult),
}

impl LogicalMutationResult {
    const fn disposition(&self) -> LogicalMutationDisposition {
        match self {
            Self::Applied(_) => LogicalMutationDisposition::Applied,
            Self::Replayed(_) => LogicalMutationDisposition::Replayed,
        }
    }
}

/// Exact local result retained by the owner until publication settles. The
/// replay bytes have no getter: only the domain ledger can validate them and
/// only the WAL owner can carry the opaque value across its actor boundary.
pub(crate) struct ValidatedWalLogicalResult<P: WalLogicalDomainPlan> {
    plan: P,
    result: WalReplayResult,
}

impl<P: WalLogicalDomainPlan> ValidatedWalLogicalResult<P> {
    fn new(plan: P, result: WalReplayResult) -> Result<Self> {
        plan.validate_replay(&result)?;
        Ok(Self { plan, result })
    }

    /// This is deliberately consuming and remains the sole conversion from
    /// the opaque retained result to the logical domain's typed output.
    pub(crate) fn release(self) -> Result<P::Output> {
        self.plan.decode_output(&self.result)
    }
}

impl<P: WalLogicalDomainPlan> fmt::Debug for ValidatedWalLogicalResult<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedWalLogicalResult(<opaque>)")
    }
}

pub(crate) struct ExecutedLogicalMutation<P: WalLogicalDomainPlan> {
    kind: WalOperationKind,
    operation_id: WalLogicalOperationId,
    request_fingerprint: WalRequestFingerprint,
    disposition: LogicalMutationDisposition,
    result: ValidatedWalLogicalResult<P>,
}

impl<P: WalLogicalDomainPlan> ExecutedLogicalMutation<P> {
    pub(crate) const fn kind(&self) -> WalOperationKind {
        self.kind
    }

    pub(crate) const fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    pub(crate) const fn request_fingerprint(&self) -> WalRequestFingerprint {
        self.request_fingerprint
    }

    pub(crate) const fn disposition(&self) -> LogicalMutationDisposition {
        self.disposition
    }

    pub(crate) fn into_validated_result(self) -> ValidatedWalLogicalResult<P> {
        self.result
    }
}

pub(crate) fn execute_prepared_for_owner<P: WalLogicalDomainPlan>(
    connection: &mut Connection,
    prepared: PreparedLogicalMutation<P>,
) -> Result<ExecutedLogicalMutation<P>> {
    let kind = prepared.plan.kind();
    let operation_id = prepared.operation_id;
    let request_fingerprint = prepared.request_fingerprint;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let result = P::Ledger::resolve_or_apply(&transaction, &prepared)?;
    let disposition = result.disposition();
    let replay_result = match result {
        LogicalMutationResult::Applied(result) | LogicalMutationResult::Replayed(result) => result,
    };
    prepared.plan.validate_replay(&replay_result)?;
    transaction
        .commit()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(ExecutedLogicalMutation {
        kind,
        operation_id,
        request_fingerprint,
        disposition,
        result: ValidatedWalLogicalResult::new(prepared.plan, replay_result)?,
    })
}

pub(crate) fn lookup_prepared_for_owner<P: WalLogicalDomainPlan>(
    connection: &Connection,
    prepared: PreparedLogicalMutation<P>,
) -> Result<PreparedLookup<P>> {
    let result = P::Ledger::lookup(connection, &prepared)?;
    match result {
        Some(result) => Ok(PreparedLookup::Present(ValidatedWalLogicalResult::new(
            prepared.plan,
            result,
        )?)),
        None => Ok(PreparedLookup::Absent(prepared)),
    }
}

pub(crate) enum PreparedLookup<P: WalLogicalDomainPlan> {
    Absent(PreparedLogicalMutation<P>),
    Present(ValidatedWalLogicalResult<P>),
}

mod erased_sealed {
    pub(crate) trait PreparedMutation {}
    pub(crate) trait ValidatedResult {}
}

/// Object-safe owner boundary for the closed set of sealed logical plans.
///
/// Type erasure happens only after a domain has produced a fully prepared
/// mutation. It lets one archive actor serialize different reviewed domains
/// without exposing a generic SQL closure, ledger selector, or result codec.
pub(crate) trait ErasedPreparedLogicalMutation:
    erased_sealed::PreparedMutation + Send + 'static
{
    fn kind_for_owner(&self) -> WalOperationKind;
    fn operation_id_for_owner(&self) -> WalLogicalOperationId;
    fn request_fingerprint_for_owner(&self) -> WalRequestFingerprint;

    fn lookup_for_owner(self: Box<Self>, connection: &Connection) -> Result<ErasedPreparedLookup>;

    fn execute_for_owner(
        self: Box<Self>,
        connection: &mut Connection,
    ) -> Result<ErasedExecutedLogicalMutation>;
}

trait ErasedValidatedResult: erased_sealed::ValidatedResult + Send {
    fn release_boxed(self: Box<Self>) -> Result<Box<dyn Any + Send>>;
}

impl<P: WalLogicalDomainPlan> erased_sealed::ValidatedResult for ValidatedWalLogicalResult<P> {}

impl<P: WalLogicalDomainPlan> ErasedValidatedResult for ValidatedWalLogicalResult<P> {
    fn release_boxed(self: Box<Self>) -> Result<Box<dyn Any + Send>> {
        Ok(Box::new(ValidatedWalLogicalResult::release(*self)?))
    }
}

/// Opaque validated result whose originating plan retains sole decoding
/// authority. The launcher may only return it to the typed submitter.
pub(crate) struct ErasedValidatedWalLogicalResult {
    inner: Box<dyn ErasedValidatedResult>,
}

impl ErasedValidatedWalLogicalResult {
    fn new<P: WalLogicalDomainPlan>(result: ValidatedWalLogicalResult<P>) -> Self {
        Self {
            inner: Box::new(result),
        }
    }

    pub(crate) fn release(self) -> Result<Box<dyn Any + Send>> {
        self.inner.release_boxed()
    }
}

impl fmt::Debug for ErasedValidatedWalLogicalResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ErasedValidatedWalLogicalResult(<opaque>)")
    }
}

pub(crate) enum ErasedPreparedLookup {
    Absent(Box<dyn ErasedPreparedLogicalMutation>),
    Present(ErasedValidatedWalLogicalResult),
}

pub(crate) struct ErasedExecutedLogicalMutation {
    kind: WalOperationKind,
    operation_id: WalLogicalOperationId,
    request_fingerprint: WalRequestFingerprint,
    disposition: LogicalMutationDisposition,
    result: ErasedValidatedWalLogicalResult,
}

impl ErasedExecutedLogicalMutation {
    pub(crate) const fn kind(&self) -> WalOperationKind {
        self.kind
    }

    pub(crate) const fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    pub(crate) const fn request_fingerprint(&self) -> WalRequestFingerprint {
        self.request_fingerprint
    }

    pub(crate) const fn disposition(&self) -> LogicalMutationDisposition {
        self.disposition
    }

    pub(crate) fn into_validated_result(self) -> ErasedValidatedWalLogicalResult {
        self.result
    }
}

impl<P: WalLogicalDomainPlan> erased_sealed::PreparedMutation for PreparedLogicalMutation<P> {}

impl<P: WalLogicalDomainPlan> ErasedPreparedLogicalMutation for PreparedLogicalMutation<P> {
    fn kind_for_owner(&self) -> WalOperationKind {
        PreparedLogicalMutation::kind_for_owner(self)
    }

    fn operation_id_for_owner(&self) -> WalLogicalOperationId {
        PreparedLogicalMutation::operation_id_for_owner(self)
    }

    fn request_fingerprint_for_owner(&self) -> WalRequestFingerprint {
        PreparedLogicalMutation::request_fingerprint_for_owner(self)
    }

    fn lookup_for_owner(self: Box<Self>, connection: &Connection) -> Result<ErasedPreparedLookup> {
        match lookup_prepared_for_owner(connection, *self)? {
            PreparedLookup::Absent(prepared) => {
                Ok(ErasedPreparedLookup::Absent(Box::new(prepared)))
            }
            PreparedLookup::Present(result) => Ok(ErasedPreparedLookup::Present(
                ErasedValidatedWalLogicalResult::new(result),
            )),
        }
    }

    fn execute_for_owner(
        self: Box<Self>,
        connection: &mut Connection,
    ) -> Result<ErasedExecutedLogicalMutation> {
        let executed = execute_prepared_for_owner(connection, *self)?;
        let kind = executed.kind();
        let operation_id = executed.operation_id();
        let request_fingerprint = executed.request_fingerprint();
        let disposition = executed.disposition();
        let result = ErasedValidatedWalLogicalResult::new(executed.into_validated_result());
        Ok(ErasedExecutedLogicalMutation {
            kind,
            operation_id,
            request_fingerprint,
            disposition,
            result,
        })
    }
}

#[cfg(test)]
fn execute_prepared<P: WalLogicalDomainPlan>(
    connection: &mut Connection,
    prepared: PreparedLogicalMutation<P>,
) -> Result<LogicalMutationDisposition> {
    execute_prepared_for_owner(connection, prepared).map(|result| result.disposition())
}

/// Process-local cancellation guard for the future actor owner. Dropping a
/// pre-commit attempt is harmless; dropping after local commit and before
/// durable publication settlement poisons the actor. This has no publisher or
/// authority transition.
struct LocalMutationCancellationGuard<'a> {
    actor_poisoned: &'a AtomicBool,
    local_committed: bool,
    settled: bool,
}

impl<'a> LocalMutationCancellationGuard<'a> {
    fn new(actor_poisoned: &'a AtomicBool) -> Self {
        Self {
            actor_poisoned,
            local_committed: false,
            settled: false,
        }
    }

    fn mark_local_committed(&mut self) {
        self.local_committed = true;
    }

    fn mark_settled(&mut self) {
        self.settled = true;
    }
}

impl Drop for LocalMutationCancellationGuard<'_> {
    fn drop(&mut self) {
        if self.local_committed && !self.settled {
            self.actor_poisoned
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn stable_operation_sources_cannot_alias_across_families_or_fields() {
        use super::{stable_operation_source, WalLogicalOperationId, WalOperationKind};

        // The motivating hazard: two families that share one ordinal and one
        // natural key must not derive the same operation id, or they collide
        // on a single ledger row. Existing families derive from a BARE id, so
        // without a framed subtype this is a real collision.
        let a = stable_operation_source(b"family-a-v1", &[b"same-natural-key"]).unwrap();
        let b = stable_operation_source(b"family-b-v1", &[b"same-natural-key"]).unwrap();
        assert_ne!(a, b);
        assert_ne!(
            WalLogicalOperationId::from_stable_source(WalOperationKind::VertexUsage, &a).unwrap(),
            WalLogicalOperationId::from_stable_source(WalOperationKind::VertexUsage, &b).unwrap()
        );

        // Field framing: concatenation must not alias. Without per-field
        // length prefixes ("ab","c") and ("a","bc") produce identical bytes.
        assert_ne!(
            stable_operation_source(b"f", &[b"ab", b"c"]).unwrap(),
            stable_operation_source(b"f", &[b"a", b"bc"]).unwrap()
        );
        // The subtype is framed too, so it cannot absorb a leading field.
        assert_ne!(
            stable_operation_source(b"fa", &[b"b"]).unwrap(),
            stable_operation_source(b"f", &[b"ab"]).unwrap()
        );

        // Caller-stability: identical inputs derive an identical id, which is
        // what makes a client retry an exact replay rather than a second
        // mutation.
        assert_eq!(
            stable_operation_source(b"family-a-v1", &[b"k", b"v"]).unwrap(),
            stable_operation_source(b"family-a-v1", &[b"k", b"v"]).unwrap()
        );

        // The subtype stays in the clear so a durable id remains attributable
        // to its family during forensics.
        assert!(a.starts_with(b"family-a-v1"));
        // Fail closed on an unnamed family.
        assert!(stable_operation_source(b"", &[b"k"]).is_err());
    }
    use super::*;
    use rusqlite::{params, OptionalExtension};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    };
    use std::time::Duration;

    #[derive(Clone)]
    struct TestDomain {
        kind: WalOperationKind,
        id: WalLogicalOperationId,
        request: Vec<u8>,
        result: WalReplayResult,
        apply_count: Arc<AtomicUsize>,
        lookup_count: Arc<AtomicUsize>,
        fail_after_sql: bool,
    }

    struct TestMediaCaptureLedger;

    impl sealed::DomainPlan for TestDomain {}
    impl sealed::DomainLedger for TestMediaCaptureLedger {}

    const TEST_LEDGER_BOUNDS: DomainLedgerBounds =
        DomainLedgerBounds::new(64, (64 * MAX_ENCODED_REPLAY_RESULT_BYTES) as u64);

    impl WalLogicalDomainLedger<TestDomain> for TestMediaCaptureLedger {
        fn lookup(
            connection: &Connection,
            prepared: &PreparedLogicalMutation<TestDomain>,
        ) -> Result<Option<WalReplayResult>> {
            if prepared.plan.kind() != WalOperationKind::MediaCaptureEvent {
                return Err(WalIdempotencyError::ResultUnsupported);
            }
            prepared.plan.lookup_count.fetch_add(1, Ordering::SeqCst);
            let row = connection
                .query_row(
                    "SELECT format_version,codec_version,request_fingerprint,
                            result_bytes,result_commitment
                     FROM test_wal_media_capture_operations WHERE operation_id=?1",
                    [prepared.operation_id.as_bytes().as_slice()],
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
            if format != i64::from(WAL_IDEMPOTENCY_FORMAT_V1)
                || codec != i64::from(WalOperationKind::MediaCaptureEvent.codec_version())
                || fingerprint.len() != 32
                || commitment.len() != 32
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            if fingerprint.as_slice() != prepared.request_fingerprint.as_bytes() {
                return Err(WalIdempotencyError::FingerprintConflict);
            }
            let result = WalReplayResult::decode(WalOperationKind::MediaCaptureEvent, &encoded)?;
            if commitment.as_slice()
                != result
                    .commitment(WalOperationKind::MediaCaptureEvent)?
                    .as_slice()
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            prepared.plan.validate_replay(&result)?;
            Ok(Some(result))
        }

        fn resolve_or_apply(
            transaction: &Transaction<'_>,
            prepared: &PreparedLogicalMutation<TestDomain>,
        ) -> Result<LogicalMutationResult> {
            if let Some(result) = Self::lookup(transaction, prepared)? {
                return Ok(LogicalMutationResult::Replayed(result));
            }

            let (rows, result_bytes) = transaction
                .query_row(
                    "SELECT row_count,result_bytes
                     FROM test_wal_media_capture_ledger_state WHERE singleton=1",
                    [],
                    |row| Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(|_| WalIdempotencyError::Corrupt)?;
            let result_bytes =
                u64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
            // Reserve the domain codec's maximum encoded result before any
            // mutation SQL, so a full ledger cannot execute caller work and
            // then rely on rollback for safety.
            TEST_LEDGER_BOUNDS.admit(rows, result_bytes, MAX_ENCODED_REPLAY_RESULT_BYTES)?;
            let result = prepared.plan.apply(transaction)?;
            prepared.plan.validate_replay(&result)?;
            let encoded = result.encode(WalOperationKind::MediaCaptureEvent)?;
            let commitment = result.commitment(WalOperationKind::MediaCaptureEvent)?;
            transaction
                .execute(
                    "INSERT INTO test_wal_media_capture_operations
                     (operation_id,format_version,codec_version,request_fingerprint,
                      result_bytes,result_commitment)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        prepared.operation_id.as_bytes().as_slice(),
                        i64::from(WAL_IDEMPOTENCY_FORMAT_V1),
                        i64::from(WalOperationKind::MediaCaptureEvent.codec_version()),
                        prepared.request_fingerprint.as_bytes().as_slice(),
                        encoded.as_slice(),
                        commitment.as_slice(),
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            transaction
                .execute(
                    "UPDATE test_wal_media_capture_ledger_state
                     SET row_count=row_count+1,result_bytes=result_bytes+?1
                     WHERE singleton=1",
                    [i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            Ok(LogicalMutationResult::Applied(result))
        }
    }

    impl WalLogicalDomainPlan for TestDomain {
        type Ledger = TestMediaCaptureLedger;
        type Output = WalReplayResult;

        fn kind(&self) -> WalOperationKind {
            self.kind
        }

        fn operation_id(&self) -> WalLogicalOperationId {
            self.id
        }

        fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(self.request.clone()))
        }

        fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
            self.apply_count.fetch_add(1, Ordering::SeqCst);
            transaction
                .execute(
                    "INSERT INTO domain_values(value) VALUES (?1)",
                    [self.request.as_slice()],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if self.fail_after_sql {
                return Err(WalIdempotencyError::Unavailable);
            }
            Ok(self.result.clone())
        }

        fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
            if result == &self.result {
                Ok(())
            } else {
                Err(WalIdempotencyError::ResultUnsupported)
            }
        }

        fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
            self.validate_replay(result)?;
            Ok(result.clone())
        }
    }

    fn initialize_test_ledger(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE domain_values(value BLOB NOT NULL);
                 CREATE TABLE test_wal_media_capture_operations (
                    operation_id BLOB PRIMARY KEY NOT NULL,
                    format_version INTEGER NOT NULL,
                    codec_version INTEGER NOT NULL,
                    request_fingerprint BLOB NOT NULL,
                    result_bytes BLOB NOT NULL,
                    result_commitment BLOB NOT NULL,
                    CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                    CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                    CHECK(length(result_bytes) BETWEEN 9 AND 4105),
                    CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                 ) WITHOUT ROWID;
                 CREATE TABLE test_wal_media_capture_ledger_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 64),
                    result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 262720)
                 );
                 INSERT INTO test_wal_media_capture_ledger_state
                    (singleton,row_count,result_bytes) VALUES (1,0,0);",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        initialize_test_ledger(&connection);
        connection
    }

    fn domain(
        kind: WalOperationKind,
        id: u8,
        request: &[u8],
        result: WalReplayResult,
        count: Arc<AtomicUsize>,
    ) -> TestDomain {
        TestDomain {
            kind,
            id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            request: request.to_vec(),
            result,
            apply_count: count,
            lookup_count: Arc::new(AtomicUsize::new(0)),
            fail_after_sql: false,
        }
    }

    #[test]
    fn ids_fingerprints_domains_versions_and_bounds_are_strict() {
        assert!(WalLogicalOperationId::from_bytes([0; 16]).is_err());
        assert!(WalLogicalOperationId::from_stable_source(
            WalOperationKind::MediaCaptureEvent,
            &[]
        )
        .is_err());
        assert!(WalLogicalOperationId::from_stable_source(
            WalOperationKind::MediaCaptureEvent,
            &vec![1; MAX_CANONICAL_WAL_REQUEST_BYTES + 1]
        )
        .is_err());
        let id = WalLogicalOperationId::from_bytes([1; 16]).unwrap();
        assert_eq!(format!("{id:?}"), "WalLogicalOperationId(<opaque>)");
        assert!(WalRequestFingerprint::derive(WalOperationKind::MediaCaptureEvent, &[]).is_err());
        assert!(WalRequestFingerprint::derive(
            WalOperationKind::MediaCaptureEvent,
            &vec![1; MAX_CANONICAL_WAL_REQUEST_BYTES + 1]
        )
        .is_err());
        let one = WalRequestFingerprint::derive(WalOperationKind::MediaCaptureEvent, b"x").unwrap();
        let two =
            WalRequestFingerprint::derive(WalOperationKind::CaptureSessionFinish, b"x").unwrap();
        assert_ne!(one.as_bytes(), two.as_bytes());
        assert!(WalOperationKind::decode(0).is_err());
        // Ordinal 13 is SchemaEpochAdvance — the first ordinal added after
        // the Phase-2 deletion, with no signing ceremony behind it. It
        // returns nothing to any caller, so it stays out of
        // permits_canonical_response.
        assert_eq!(
            WalOperationKind::decode(13).unwrap(),
            WalOperationKind::SchemaEpochAdvance
        );
        assert_eq!(WalOperationKind::SchemaEpochAdvance.codec_version(), 1);
        assert!(
            WalReplayResult::canonical_response(WalOperationKind::SchemaEpochAdvance, vec![1])
                .is_err()
        );
        assert!(WalOperationKind::decode(14).is_err());
        assert!(
            WalReplayResult::canonical_response(WalOperationKind::FinalizationCommit, vec![1])
                .is_err()
        );
        assert!(
            WalReplayResult::canonical_response(WalOperationKind::VertexUsage, vec![1]).is_ok()
        );
        assert!(WalReplayResult::canonical_response(
            WalOperationKind::MediaCaptureEvent,
            vec![1; MAX_CANONICAL_REPLAY_RESULT_BYTES + 1]
        )
        .is_err());
    }

    #[test]
    fn exact_replay_does_not_reapply_domain_closure_or_write_rows() {
        let mut connection = connection();
        let count = Arc::new(AtomicUsize::new(0));
        let first = domain(
            WalOperationKind::MediaCaptureEvent,
            1,
            b"request",
            WalReplayResult::canonical_response(
                WalOperationKind::MediaCaptureEvent,
                b"response".to_vec(),
            )
            .unwrap(),
            count.clone(),
        );
        assert_eq!(
            execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(first).unwrap()
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        );
        let changes = connection.total_changes();
        let replay = domain(
            WalOperationKind::MediaCaptureEvent,
            1,
            b"request",
            WalReplayResult::canonical_response(
                WalOperationKind::MediaCaptureEvent,
                b"response".to_vec(),
            )
            .unwrap(),
            count.clone(),
        );
        assert_eq!(
            execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(replay).unwrap()
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(connection.total_changes(), changes);
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM domain_values", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn same_domain_and_id_with_different_fingerprint_conflicts() {
        let mut connection = connection();
        let count = Arc::new(AtomicUsize::new(0));
        let first = domain(
            WalOperationKind::MediaCaptureEvent,
            2,
            b"first",
            WalReplayResult::unit(),
            count.clone(),
        );
        execute_prepared(
            &mut connection,
            PreparedLogicalMutation::prepare(first).unwrap(),
        )
        .unwrap();
        let conflict = domain(
            WalOperationKind::MediaCaptureEvent,
            2,
            b"second",
            WalReplayResult::unit(),
            count,
        );
        assert_eq!(
            execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(conflict).unwrap()
            )
            .unwrap_err(),
            WalIdempotencyError::FingerprintConflict
        );
    }

    #[test]
    fn domain_sql_and_result_row_rollback_together() {
        let mut connection = connection();
        let count = Arc::new(AtomicUsize::new(0));
        let mut failing = domain(
            WalOperationKind::MediaCaptureEvent,
            3,
            b"rollback",
            WalReplayResult::unit(),
            count,
        );
        failing.fail_after_sql = true;
        assert!(execute_prepared(
            &mut connection,
            PreparedLogicalMutation::prepare(failing).unwrap()
        )
        .is_err());
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM domain_values", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM test_wal_media_capture_operations",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn result_tamper_unknown_version_and_codec_fail_closed() {
        for corruption in ["result", "version", "codec"] {
            let mut connection = connection();
            let count = Arc::new(AtomicUsize::new(0));
            let plan = domain(
                WalOperationKind::MediaCaptureEvent,
                4,
                b"request",
                WalReplayResult::canonical_response(
                    WalOperationKind::MediaCaptureEvent,
                    b"response".to_vec(),
                )
                .unwrap(),
                count.clone(),
            );
            execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .unwrap();
            match corruption {
                "result" => {
                    connection
                        .execute(
                            "UPDATE test_wal_media_capture_operations SET result_bytes=?1",
                            [vec![0xff; 9]],
                        )
                        .unwrap();
                }
                "version" => {
                    connection
                        .execute(
                            "UPDATE test_wal_media_capture_operations SET format_version=99",
                            [],
                        )
                        .unwrap();
                }
                "codec" => {
                    connection
                        .execute(
                            "UPDATE test_wal_media_capture_operations SET codec_version=99",
                            [],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let replay = domain(
                WalOperationKind::MediaCaptureEvent,
                4,
                b"request",
                WalReplayResult::canonical_response(
                    WalOperationKind::MediaCaptureEvent,
                    b"response".to_vec(),
                )
                .unwrap(),
                count,
            );
            assert!(execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(replay).unwrap()
            )
            .is_err());
        }
    }

    #[test]
    fn restart_distinguishes_absent_from_exact_committed_replay() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logical.db");
        let count = Arc::new(AtomicUsize::new(0));
        {
            let mut connection = Connection::open(&path).unwrap();
            initialize_test_ledger(&connection);
            let plan = domain(
                WalOperationKind::MediaCaptureEvent,
                5,
                b"commit",
                WalReplayResult::unit(),
                count.clone(),
            );
            assert_eq!(
                execute_prepared(
                    &mut connection,
                    PreparedLogicalMutation::prepare(plan).unwrap()
                )
                .unwrap(),
                LogicalMutationDisposition::Applied
            );
        }
        let mut reopened = Connection::open(&path).unwrap();
        let replay = domain(
            WalOperationKind::MediaCaptureEvent,
            5,
            b"commit",
            WalReplayResult::unit(),
            count.clone(),
        );
        assert_eq!(
            execute_prepared(
                &mut reopened,
                PreparedLogicalMutation::prepare(replay).unwrap()
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        let absent = domain(
            WalOperationKind::MediaCaptureEvent,
            6,
            b"new",
            WalReplayResult::unit(),
            count.clone(),
        );
        assert_eq!(
            execute_prepared(
                &mut reopened,
                PreparedLogicalMutation::prepare(absent).unwrap()
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_same_operation_serializes_to_one_apply_and_one_replay() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("serialized.db");
        {
            let connection = Connection::open(&path).unwrap();
            initialize_test_ledger(&connection);
        }
        let barrier = Arc::new(Barrier::new(2));
        let count = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let count = Arc::clone(&count);
            workers.push(std::thread::spawn(move || {
                let mut connection = Connection::open(path).unwrap();
                connection.busy_timeout(Duration::from_secs(5)).unwrap();
                barrier.wait();
                let plan = domain(
                    WalOperationKind::MediaCaptureEvent,
                    7,
                    b"same-request",
                    WalReplayResult::unit(),
                    count,
                );
                execute_prepared(
                    &mut connection,
                    PreparedLogicalMutation::prepare(plan).unwrap(),
                )
                .unwrap()
            }));
        }
        let mut dispositions = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        dispositions.sort_by_key(|disposition| match disposition {
            LogicalMutationDisposition::Applied => 0,
            LogicalMutationDisposition::Replayed => 1,
        });
        assert_eq!(
            dispositions,
            vec![
                LogicalMutationDisposition::Applied,
                LogicalMutationDisposition::Replayed,
            ]
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let connection = Connection::open(&path).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM domain_values", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn domain_row_and_byte_caps_reject_before_apply_and_lookup_work_is_constant() {
        let mut full_ledger = connection();
        let apply_count = Arc::new(AtomicUsize::new(0));
        for id in 1..=64 {
            let plan = domain(
                WalOperationKind::MediaCaptureEvent,
                id,
                &[id],
                WalReplayResult::unit(),
                Arc::clone(&apply_count),
            );
            let lookup_count = Arc::clone(&plan.lookup_count);
            assert_eq!(
                execute_prepared(
                    &mut full_ledger,
                    PreparedLogicalMutation::prepare(plan).unwrap(),
                )
                .unwrap(),
                LogicalMutationDisposition::Applied
            );
            assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
        }
        let over_row_cap = domain(
            WalOperationKind::MediaCaptureEvent,
            65,
            b"over-row-cap",
            WalReplayResult::unit(),
            Arc::clone(&apply_count),
        );
        assert_eq!(
            execute_prepared(
                &mut full_ledger,
                PreparedLogicalMutation::prepare(over_row_cap).unwrap(),
            )
            .unwrap_err(),
            WalIdempotencyError::Limit
        );
        assert_eq!(apply_count.load(Ordering::SeqCst), 64);

        let replay = domain(
            WalOperationKind::MediaCaptureEvent,
            32,
            &[32],
            WalReplayResult::unit(),
            Arc::clone(&apply_count),
        );
        let replay_lookup_count = Arc::clone(&replay.lookup_count);
        assert_eq!(
            execute_prepared(
                &mut full_ledger,
                PreparedLogicalMutation::prepare(replay).unwrap(),
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(replay_lookup_count.load(Ordering::SeqCst), 1);
        assert_eq!(apply_count.load(Ordering::SeqCst), 64);

        let mut byte_limited = connection();
        byte_limited
            .execute(
                "UPDATE test_wal_media_capture_ledger_state SET result_bytes=?1",
                [i64::try_from(TEST_LEDGER_BOUNDS.max_result_bytes - 8).unwrap()],
            )
            .unwrap();
        let byte_apply_count = Arc::new(AtomicUsize::new(0));
        let over_byte_cap = domain(
            WalOperationKind::MediaCaptureEvent,
            66,
            b"over-byte-cap",
            WalReplayResult::unit(),
            Arc::clone(&byte_apply_count),
        );
        assert_eq!(
            execute_prepared(
                &mut byte_limited,
                PreparedLogicalMutation::prepare(over_byte_cap).unwrap(),
            )
            .unwrap_err(),
            WalIdempotencyError::Limit
        );
        assert_eq!(byte_apply_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancellation_before_commit_is_safe_and_after_commit_poisons_until_settled() {
        let poisoned = AtomicBool::new(false);
        drop(LocalMutationCancellationGuard::new(&poisoned));
        assert!(!poisoned.load(Ordering::Acquire));
        {
            let mut guard = LocalMutationCancellationGuard::new(&poisoned);
            guard.mark_local_committed();
        }
        assert!(poisoned.load(Ordering::Acquire));
        poisoned.store(false, Ordering::Release);
        {
            let mut guard = LocalMutationCancellationGuard::new(&poisoned);
            guard.mark_local_committed();
            guard.mark_settled();
        }
        assert!(!poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn source_has_no_runtime_or_public_universal_receipt_surface() {
        let source = include_str!("archive_v3_wal_idempotency.rs");
        for forbidden in [
            concat!("crate::store::", "Store"),
            concat!("std::", "env"),
            concat!("Gcs", "Client"),
            concat!("Witness::", "advance"),
            concat!("tokio::", "spawn"),
            concat!("pub struct ", "PreparedLogicalMutation"),
            concat!("OperationKind::", "AccountDelete"),
            concat!("OperationKind::", "EpisodeDelete"),
            concat!("archive_v3_wal_", "logical_operations"),
            concat!("ORDER BY operation_", "kind"),
        ] {
            assert!(!source.contains(forbidden), "found forbidden {forbidden}");
        }
    }
}
