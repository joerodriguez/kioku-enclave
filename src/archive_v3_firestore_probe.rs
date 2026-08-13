#![allow(
    dead_code,
    reason = "ADR-0022 Firestore transport probe is merged inert before deployment wiring"
)]

//! Non-authoritative ADR-0022 Firestore transport probe.
//!
//! The probe owns one permanently reserved singleton document and never names
//! an archive, user, object, key, route, or content fact.  It exists only to
//! exercise the dedicated named-database transaction path before semantic
//! witness authority is eligible for activation.

use rand::{rngs::OsRng, RngCore};
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    archive_v3_firestore_auth::FirestoreWitnessAttestationBearer,
    archive_v3_firestore_http::FirestoreWitnessRestTransport,
    archive_v3_firestore_witness::{
        FirestoreTransportProbe, FirestoreWitnessConfig, FirestoreWitnessTransportError,
    },
    archive_v3_witness::WitnessError,
};

pub(crate) const PROBE_COLLECTION: &str = "archive_witness_transport_probe_v1";
pub(crate) const PROBE_DOCUMENT_ID: &str = "singleton";
pub(crate) const PROBE_RECORD_BYTES: usize = 64;
static PROBE_TASK_STARTED: AtomicBool = AtomicBool::new(false);
const PROBE_STARTUP_DEADLINE: Duration = Duration::from_secs(120);
const PROBE_MAGIC: &[u8; 16] = b"KIOKU-WIT-PROBE\0";
const PROBE_VERSION: u32 = 1;
const GENERATION_OFFSET: usize = 24;
const ATTEMPT_OFFSET: usize = 32;

/// Redacted process-aggregate result. These variants deliberately carry no
/// provider message, namespace, record, generation, or attempt identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FirestoreProbeOutcome {
    Confirmed,
    Stale,
    OutcomeUnknown,
    Failed,
    TimedOut,
}

impl FirestoreProbeOutcome {
    /// Fixed content-free marker used by the sole startup log. No provider
    /// error, namespace, attempt, record, or timing is exposed.
    pub(crate) const fn marker(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Stale => "stale",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
        }
    }
}

/// Image-baked startup selector. `Off` is the checked-in default; `ProbeV1`
/// may exercise only the reserved singleton transport record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum FirestoreProbeMode {
    #[default]
    Off,
    ProbeV1,
}

impl FirestoreProbeMode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "probe-v1" => Some(Self::ProbeV1),
            _ => None,
        }
    }
}

/// All probe settings are one image-baked unit. Off requires an empty
/// namespace; probe-v1 requires the complete exact named-database identity.
pub(crate) struct FirestoreProbeStartupConfig {
    mode: FirestoreProbeMode,
    witness: Option<FirestoreWitnessConfig>,
}

impl FirestoreProbeStartupConfig {
    pub(crate) fn from_values(
        mode: &str,
        project_id: &str,
        project_number: &str,
        database_id: &str,
    ) -> Result<Self, WitnessError> {
        let mode = FirestoreProbeMode::parse(mode).ok_or(WitnessError::Malformed)?;
        let all_empty =
            project_id.is_empty() && project_number.is_empty() && database_id.is_empty();
        let all_present =
            !project_id.is_empty() && !project_number.is_empty() && !database_id.is_empty();
        let witness = match mode {
            FirestoreProbeMode::Off if all_empty => None,
            FirestoreProbeMode::ProbeV1 if all_present => Some(FirestoreWitnessConfig::new(
                project_id,
                project_number,
                database_id,
            )?),
            _ => return Err(WitnessError::Malformed),
        };
        Ok(Self { mode, witness })
    }

    pub(crate) fn from_env() -> Result<Self, WitnessError> {
        let mode =
            std::env::var("ARCHIVE_WITNESS_SHADOW_MODE").unwrap_or_else(|_| "off".to_owned());
        let project_id = std::env::var("ARCHIVE_WITNESS_PROJECT_ID").unwrap_or_default();
        let project_number = std::env::var("ARCHIVE_WITNESS_PROJECT_NUMBER").unwrap_or_default();
        let database_id = std::env::var("ARCHIVE_WITNESS_DATABASE_ID").unwrap_or_default();
        Self::from_values(&mode, &project_id, &project_number, &database_id)
    }
}

impl fmt::Debug for FirestoreProbeStartupConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirestoreProbeStartupConfig(<redacted>)")
    }
}

/// Await the sole bounded one-shot probe before any application Store, KMS, or
/// GCS construction. Off returns without constructing credentials or transport.
/// The fixed marker is logged here and the outcome is not returned, so callers
/// cannot connect it to readiness, health, admission, or archive authority.
pub(crate) async fn run_startup_probe(
    config: FirestoreProbeStartupConfig,
) -> Result<(), WitnessError> {
    match (config.mode, config.witness) {
        (FirestoreProbeMode::Off, None) => Ok(()),
        (FirestoreProbeMode::ProbeV1, Some(config)) => {
            if PROBE_TASK_STARTED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(WitnessError::Synchronization);
            }
            let runner = FirestoreProbeRunner::new(config)?;
            let outcome = tokio::time::timeout(PROBE_STARTUP_DEADLINE, runner.run_once())
                .await
                .unwrap_or(FirestoreProbeOutcome::TimedOut);
            tracing::info!(
                outcome = outcome.marker(),
                "archive witness transport probe finished"
            );
            Ok(())
        }
        _ => Err(WitnessError::Malformed),
    }
}

/// Returns the sole legal document suffix. There is intentionally no caller
/// input, collection selector, or arbitrary document-name constructor.
pub(crate) const fn singleton_document_suffix() -> &'static str {
    "archive_witness_transport_probe_v1/singleton"
}

/// Fixed production composition for the probe. Construction performs no I/O;
/// the only operation is the redacted one-shot probe future.
pub(crate) struct FirestoreProbeRunner {
    inner: FirestoreTransportProbe,
}

impl FirestoreProbeRunner {
    pub(crate) fn new(config: FirestoreWitnessConfig) -> Result<Self, WitnessError> {
        let bearer = Arc::new(
            FirestoreWitnessAttestationBearer::new(config.provider_audience())
                .map_err(map_construction_error)?,
        );
        let transport = Arc::new(
            FirestoreWitnessRestTransport::new(config.namespace())
                .map_err(map_construction_error)?,
        );
        Ok(Self {
            inner: FirestoreTransportProbe::new(config, bearer, transport),
        })
    }

    pub(crate) async fn run_once(&self) -> FirestoreProbeOutcome {
        self.inner.run_once().await
    }
}

fn map_construction_error(error: FirestoreWitnessTransportError) -> WitnessError {
    match error {
        FirestoreWitnessTransportError::Protocol => WitnessError::Malformed,
        _ => WitnessError::Unavailable,
    }
}

impl fmt::Debug for FirestoreProbeRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirestoreProbeRunner(<redacted>)")
    }
}

/// Opaque identifier used to reconcile one ambiguous commit. It has no
/// serialization or display surface and its debug representation is redacted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FirestoreProbeAttemptId([u8; 32]);

impl FirestoreProbeAttemptId {
    pub(crate) fn random() -> Self {
        let mut value = [0; 32];
        while value == [0; 32] {
            OsRng.fill_bytes(&mut value);
        }
        Self(value)
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for FirestoreProbeAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirestoreProbeAttemptId(<opaque>)")
    }
}

/// Exact fixed-size singleton payload. Bytes outside the defined fields are
/// canonical zero padding and are rejected if a provider substitutes them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FirestoreProbeRecord {
    generation: u64,
    attempt_id: FirestoreProbeAttemptId,
}

impl FirestoreProbeRecord {
    pub(crate) fn first(attempt_id: FirestoreProbeAttemptId) -> Self {
        Self {
            generation: 1,
            attempt_id,
        }
    }

    pub(crate) fn next(self, attempt_id: FirestoreProbeAttemptId) -> Option<FirestoreProbeRecord> {
        self.generation.checked_add(1).map(|generation| Self {
            generation,
            attempt_id,
        })
    }

    pub(crate) fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) fn attempt_id(self) -> FirestoreProbeAttemptId {
        self.attempt_id
    }

    pub(crate) fn encode(self) -> [u8; PROBE_RECORD_BYTES] {
        let mut bytes = [0; PROBE_RECORD_BYTES];
        bytes[..PROBE_MAGIC.len()].copy_from_slice(PROBE_MAGIC);
        bytes[16..20].copy_from_slice(&PROBE_VERSION.to_be_bytes());
        bytes[GENERATION_OFFSET..GENERATION_OFFSET + 8]
            .copy_from_slice(&self.generation.to_be_bytes());
        bytes[ATTEMPT_OFFSET..].copy_from_slice(&self.attempt_id.0);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PROBE_RECORD_BYTES
            || bytes.get(..PROBE_MAGIC.len()) != Some(PROBE_MAGIC)
            || bytes.get(16..20) != Some(PROBE_VERSION.to_be_bytes().as_slice())
            || bytes.get(20..GENERATION_OFFSET) != Some([0; 4].as_slice())
        {
            return None;
        }
        let generation = u64::from_be_bytes(
            bytes
                .get(GENERATION_OFFSET..ATTEMPT_OFFSET)?
                .try_into()
                .ok()?,
        );
        let attempt_id = FirestoreProbeAttemptId(bytes.get(ATTEMPT_OFFSET..)?.try_into().ok()?);
        (generation != 0 && attempt_id.0 != [0; 32]).then_some(Self {
            generation,
            attempt_id,
        })
    }
}

impl fmt::Debug for FirestoreProbeRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirestoreProbeRecord(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(byte: u8) -> FirestoreProbeAttemptId {
        FirestoreProbeAttemptId::from_test_bytes([byte; 32])
    }

    #[test]
    fn exact_probe_record_round_trips_and_is_redacted() {
        let record = FirestoreProbeRecord::first(attempt(7));
        assert_eq!(FirestoreProbeRecord::decode(&record.encode()), Some(record));
        assert_eq!(record.generation(), 1);
        assert_eq!(format!("{record:?}"), "FirestoreProbeRecord(<redacted>)");
        assert_eq!(
            format!("{:?}", record.attempt_id()),
            "FirestoreProbeAttemptId(<opaque>)"
        );
    }

    #[test]
    fn codec_rejects_wrong_size_magic_version_padding_generation_and_attempt() {
        let canonical = FirestoreProbeRecord::first(attempt(9)).encode();
        assert!(FirestoreProbeRecord::decode(&canonical[..63]).is_none());
        for (offset, replacement) in [(0, 0xff), (19, 2), (20, 1), (31, 0), (32, 0)] {
            let mut mutated = canonical;
            mutated[offset] = replacement;
            if offset == 32 {
                mutated[ATTEMPT_OFFSET..].fill(0);
            } else if offset == 31 {
                mutated[GENERATION_OFFSET..ATTEMPT_OFFSET].fill(0);
            }
            assert!(
                FirestoreProbeRecord::decode(&mutated).is_none(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn generation_is_checked_and_cannot_wrap() {
        let record = FirestoreProbeRecord {
            generation: u64::MAX,
            attempt_id: attempt(1),
        };
        assert!(record.next(attempt(2)).is_none());
        assert_eq!(
            FirestoreProbeRecord::first(attempt(1))
                .next(attempt(2))
                .unwrap()
                .generation(),
            2
        );
    }

    #[test]
    fn mode_and_path_are_exact_and_have_no_arbitrary_name_surface() {
        assert_eq!(
            FirestoreProbeMode::parse("off"),
            Some(FirestoreProbeMode::Off)
        );
        assert_eq!(
            FirestoreProbeMode::parse("probe-v1"),
            Some(FirestoreProbeMode::ProbeV1)
        );
        for rejected in ["", "probe", "PROBE-V1", "probe-v2", "off "] {
            assert_eq!(FirestoreProbeMode::parse(rejected), None);
        }
        assert_eq!(
            singleton_document_suffix(),
            "archive_witness_transport_probe_v1/singleton"
        );
    }

    #[test]
    fn startup_config_is_all_or_nothing_and_off_has_empty_namespace() {
        let off = FirestoreProbeStartupConfig::from_values("off", "", "", "").unwrap();
        assert_eq!(off.mode, FirestoreProbeMode::Off);
        assert!(off.witness.is_none());
        assert!(FirestoreProbeStartupConfig::from_values(
            "probe-v1",
            "project-1",
            "123456789",
            "witness-db"
        )
        .is_ok());
        for values in [
            ("off", "project-1", "", ""),
            ("probe-v1", "", "123456789", "witness-db"),
            ("probe-v1", "project-1", "wrong", "witness-db"),
            ("probe-v1", "project-1", "123456789", "(default)"),
            ("wrong", "", "", ""),
        ] {
            assert!(FirestoreProbeStartupConfig::from_values(
                values.0, values.1, values.2, values.3
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn off_startup_probe_is_zero_io_and_has_no_result_authority() {
        let off = FirestoreProbeStartupConfig::from_values("off", "", "", "").unwrap();
        run_startup_probe(off).await.unwrap();
    }

    #[test]
    fn outcome_markers_are_fixed_and_content_free() {
        assert_eq!(FirestoreProbeOutcome::Confirmed.marker(), "confirmed");
        assert_eq!(FirestoreProbeOutcome::Stale.marker(), "stale");
        assert_eq!(
            FirestoreProbeOutcome::OutcomeUnknown.marker(),
            "outcome_unknown"
        );
        assert_eq!(FirestoreProbeOutcome::Failed.marker(), "failed");
        assert_eq!(FirestoreProbeOutcome::TimedOut.marker(), "timed_out");
    }
}
