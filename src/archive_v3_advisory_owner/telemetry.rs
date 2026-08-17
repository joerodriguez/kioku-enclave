//! Privacy-preserving, content-free asynchronous telemetry for Phase-1 advisory canary.
//!
//! Invariants:
//! - All identifiers and lifecycle facts are domain-separated SHA-256 commitments.
//! - Durations are mapped to discrete logarithmic buckets.
//! - Non-blocking emission (`try_send` on a bounded 256-entry channel) ensures that
//!   telemetry cannot block, delay, or fail the controller or durable transitions.
//! - Telemetry sinks run in an isolated background worker with panic protection (`catch_unwind`).
//! - No raw database plaintext, query text, user IDs, or encryption keys can ever leak.

use std::{
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use sha2::{Digest, Sha256};
use tokio::sync::mpsc::{channel, Sender};

const TELEMETRY_OP_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-telemetry/operation/v1\0";
const TELEMETRY_OWNER_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-telemetry/owner/v1\0";
const TELEMETRY_WINDOW_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-telemetry/window/v1\0";
const TELEMETRY_SCOPE_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-telemetry/scope/v1\0";
const TELEMETRY_FENCE_DOMAIN: &[u8] = b"kioku/archive-v3/phase1-telemetry/fence/v1\0";

/// Maximum capacity of the bounded asynchronous telemetry queue.
pub(super) const MAX_TELEMETRY_QUEUE_CAPACITY: usize = 256;

/// Hard cap on retained test events in the in-memory test sink.
pub(super) const MAX_TEST_EVENTS_CAPACITY: usize = 1024;

/// Coarse duration bucket for privacy-preserving telemetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DurationBucket {
    Under10Ms,
    Under50Ms,
    Under100Ms,
    Under500Ms,
    Under1S,
    Under5S,
    Under10S,
    Under30S,
    Over30S,
}

impl DurationBucket {
    pub(super) fn from_duration(d: Duration) -> Self {
        let ms = d.as_millis();
        if ms < 10 {
            Self::Under10Ms
        } else if ms < 50 {
            Self::Under50Ms
        } else if ms < 100 {
            Self::Under100Ms
        } else if ms < 500 {
            Self::Under500Ms
        } else if ms < 1_000 {
            Self::Under1S
        } else if ms < 5_000 {
            Self::Under5S
        } else if ms < 10_000 {
            Self::Under10S
        } else if ms < 30_000 {
            Self::Under30S
        } else {
            Self::Over30S
        }
    }
}

/// Content-free, commitment-only Phase-1 advisory canary lifecycle event.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum Phase1CanaryEvent {
    PreflightVerified {
        scope_commitment: [u8; 32],
        window_commitment: [u8; 32],
        operator_statement_commitment: [u8; 32],
        release_image_digest: [u8; 32],
    },
    MaintenanceImportCompleted {
        operation_commitment: [u8; 32],
        duration_bucket: DurationBucket,
    },
    AdvisoryOwnerBound {
        operation_commitment: [u8; 32],
        owner_commitment: [u8; 32],
        lease_ticks: u64,
    },
    LegacyFenceReleased {
        operation_commitment: [u8; 32],
        fence_commitment: [u8; 32],
    },
    LocalAdmissionResumed {
        operation_commitment: [u8; 32],
    },
    ComparisonSettled {
        operation_commitment: [u8; 32],
        duration_bucket: DurationBucket,
        evidence_commitment: [u8; 32],
    },
    CaptureRetired {
        operation_commitment: [u8; 32],
    },
    Aborted {
        operation_commitment: [u8; 32],
        locus: &'static str,
        reason: &'static str,
    },
}

impl std::fmt::Debug for Phase1CanaryEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreflightVerified { .. } => write!(f, "Phase1CanaryEvent::PreflightVerified"),
            Self::MaintenanceImportCompleted { .. } => {
                write!(f, "Phase1CanaryEvent::MaintenanceImportCompleted")
            }
            Self::AdvisoryOwnerBound { .. } => write!(f, "Phase1CanaryEvent::AdvisoryOwnerBound"),
            Self::LegacyFenceReleased { .. } => write!(f, "Phase1CanaryEvent::LegacyFenceReleased"),
            Self::LocalAdmissionResumed { .. } => {
                write!(f, "Phase1CanaryEvent::LocalAdmissionResumed")
            }
            Self::ComparisonSettled { .. } => write!(f, "Phase1CanaryEvent::ComparisonSettled"),
            Self::CaptureRetired { .. } => write!(f, "Phase1CanaryEvent::CaptureRetired"),
            Self::Aborted { locus, reason, .. } => {
                write!(f, "Phase1CanaryEvent::Aborted({locus}, {reason})")
            }
        }
    }
}

/// Helper function to derive domain-separated commitments.
fn commit_bytes(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    hasher.finalize().into()
}

/// Destination sink for Phase-1 canary telemetry events.
pub(super) trait Phase1CanaryTelemetrySink: Send + Sync {
    fn record_event(&self, event: Phase1CanaryEvent);
}

/// Bounded in-memory telemetry sink for testing and observation.
pub(super) struct InMemoryPhase1TelemetrySink {
    events: std::sync::Mutex<Vec<Phase1CanaryEvent>>,
}

impl InMemoryPhase1TelemetrySink {
    pub(super) fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    #[cfg(test)]
    pub(super) fn events(&self) -> Vec<Phase1CanaryEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl Phase1CanaryTelemetrySink for InMemoryPhase1TelemetrySink {
    fn record_event(&self, event: Phase1CanaryEvent) {
        let mut guard = self.events.lock().unwrap();
        if guard.len() < MAX_TEST_EVENTS_CAPACITY {
            guard.push(event);
        }
    }
}

/// Asynchronous, non-blocking telemetry emitter.
#[derive(Clone)]
pub(super) struct Phase1TelemetryRecorder {
    sender: Option<Sender<Phase1CanaryEvent>>,
    dropped_events: Arc<AtomicU64>,
}

impl Phase1TelemetryRecorder {
    pub(super) fn new(sink: Option<Arc<dyn Phase1CanaryTelemetrySink>>) -> Self {
        let dropped_events = Arc::new(AtomicU64::new(0));
        let sender = sink.map(|s| {
            let (tx, mut rx) = channel::<Phase1CanaryEvent>(MAX_TELEMETRY_QUEUE_CAPACITY);
            let dropped = Arc::clone(&dropped_events);
            tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    let sink_ref = Arc::clone(&s);
                    let res = std::panic::catch_unwind(AssertUnwindSafe(move || {
                        sink_ref.record_event(event);
                    }));
                    if res.is_err() {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            tx
        });

        Self {
            sender,
            dropped_events,
        }
    }

    #[cfg(test)]
    pub(super) fn dropped_count(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    fn emit(&self, event: Phase1CanaryEvent) {
        if let Some(tx) = &self.sender {
            if tx.try_send(event).is_err() {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn emit_preflight_verified(
        &self,
        scope_id: [u8; 16],
        maintenance_window_id: [u8; 16],
        operator_statement_commitment: [u8; 32],
        release_image_digest: [u8; 32],
    ) {
        self.emit(Phase1CanaryEvent::PreflightVerified {
            scope_commitment: commit_bytes(TELEMETRY_SCOPE_DOMAIN, &scope_id),
            window_commitment: commit_bytes(TELEMETRY_WINDOW_DOMAIN, &maintenance_window_id),
            operator_statement_commitment,
            release_image_digest,
        });
    }

    pub(super) fn emit_maintenance_import_completed(
        &self,
        operation_id: [u8; 16],
        duration: Duration,
    ) {
        self.emit(Phase1CanaryEvent::MaintenanceImportCompleted {
            operation_commitment: commit_bytes(TELEMETRY_OP_DOMAIN, &operation_id),
            duration_bucket: DurationBucket::from_duration(duration),
        });
    }

    pub(super) fn emit_advisory_owner_bound(
        &self,
        operation_id: [u8; 16],
        owner_id: [u8; 16],
        lease_ticks: u64,
    ) {
        self.emit(Phase1CanaryEvent::AdvisoryOwnerBound {
            operation_commitment: commit_bytes(TELEMETRY_OP_DOMAIN, &operation_id),
            owner_commitment: commit_bytes(TELEMETRY_OWNER_DOMAIN, &owner_id),
            lease_ticks,
        });
    }

    pub(super) fn emit_legacy_fence_released(
        &self,
        operation_id: [u8; 16],
        marker_generation: Option<u64>,
    ) {
        let fence_bytes = marker_generation.unwrap_or(0).to_be_bytes();
        self.emit(Phase1CanaryEvent::LegacyFenceReleased {
            operation_commitment: commit_bytes(TELEMETRY_OP_DOMAIN, &operation_id),
            fence_commitment: commit_bytes(TELEMETRY_FENCE_DOMAIN, &fence_bytes),
        });
    }

    pub(super) fn emit_local_admission_resumed(&self, operation_id: [u8; 16]) {
        self.emit(Phase1CanaryEvent::LocalAdmissionResumed {
            operation_commitment: commit_bytes(TELEMETRY_OP_DOMAIN, &operation_id),
        });
    }

    pub(super) fn emit_comparison_settled(
        &self,
        operation_id: [u8; 16],
        duration: Duration,
        evidence_commitment: [u8; 32],
    ) {
        self.emit(Phase1CanaryEvent::ComparisonSettled {
            operation_commitment: commit_bytes(TELEMETRY_OP_DOMAIN, &operation_id),
            duration_bucket: DurationBucket::from_duration(duration),
            evidence_commitment,
        });
    }

    pub(super) fn emit_capture_retired(&self, operation_id: [u8; 16]) {
        self.emit(Phase1CanaryEvent::CaptureRetired {
            operation_commitment: commit_bytes(TELEMETRY_OP_DOMAIN, &operation_id),
        });
    }

    pub(super) fn emit_aborted(
        &self,
        operation_id: [u8; 16],
        locus: &'static str,
        reason: &'static str,
    ) {
        self.emit(Phase1CanaryEvent::Aborted {
            operation_commitment: commit_bytes(TELEMETRY_OP_DOMAIN, &operation_id),
            locus,
            reason,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn test_duration_bucket_mapping() {
        assert_eq!(
            DurationBucket::from_duration(Duration::from_millis(5)),
            DurationBucket::Under10Ms
        );
        assert_eq!(
            DurationBucket::from_duration(Duration::from_millis(25)),
            DurationBucket::Under50Ms
        );
        assert_eq!(
            DurationBucket::from_duration(Duration::from_millis(75)),
            DurationBucket::Under100Ms
        );
        assert_eq!(
            DurationBucket::from_duration(Duration::from_millis(250)),
            DurationBucket::Under500Ms
        );
        assert_eq!(
            DurationBucket::from_duration(Duration::from_millis(750)),
            DurationBucket::Under1S
        );
        assert_eq!(
            DurationBucket::from_duration(Duration::from_secs(3)),
            DurationBucket::Under5S
        );
        assert_eq!(
            DurationBucket::from_duration(Duration::from_secs(8)),
            DurationBucket::Under10S
        );
        assert_eq!(
            DurationBucket::from_duration(Duration::from_secs(20)),
            DurationBucket::Under30S
        );
        assert_eq!(
            DurationBucket::from_duration(Duration::from_secs(45)),
            DurationBucket::Over30S
        );
    }

    struct PanickingSink {
        should_panic: AtomicBool,
    }

    impl Phase1CanaryTelemetrySink for PanickingSink {
        fn record_event(&self, _event: Phase1CanaryEvent) {
            if self.should_panic.load(Ordering::SeqCst) {
                panic!("simulated telemetry sink failure");
            }
        }
    }

    #[tokio::test]
    async fn test_telemetry_recorder_panic_isolation() {
        let sink = Arc::new(PanickingSink {
            should_panic: AtomicBool::new(true),
        });
        let recorder =
            Phase1TelemetryRecorder::new(Some(sink as Arc<dyn Phase1CanaryTelemetrySink>));

        // Emitting events into a panicking sink must not crash or bubble up
        recorder.emit_local_admission_resumed([0x12; 16]);
        recorder.emit_local_admission_resumed([0x34; 16]);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(recorder.dropped_count(), 2);
    }

    #[tokio::test]
    async fn test_in_memory_sink_bounded_capacity() {
        let sink = Arc::new(InMemoryPhase1TelemetrySink::new());
        let recorder = Phase1TelemetryRecorder::new(Some(
            Arc::clone(&sink) as Arc<dyn Phase1CanaryTelemetrySink>
        ));

        for i in 0..100 {
            recorder.emit_local_admission_resumed([i as u8; 16]);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(sink.events().len(), 100);
        assert_eq!(recorder.dropped_count(), 0);
    }
}
