//! Process-local, content-free observability for the legacy archive snapshot path.
//!
//! The service does not currently run a metrics exporter.  These counters and
//! fixed-bucket histograms are therefore periodically emitted through the
//! existing structured tracing pipeline.  They intentionally have no labels:
//! user/archive identifiers, object names, paths, timestamps tied to a user,
//! and database content must never enter this module's state or log event.

use std::sync::atomic::{AtomicU64, Ordering};

/// Inclusive histogram bounds for archive byte observations.
pub(crate) const BYTE_BUCKET_UPPER_BOUNDS: [u64; 10] = [
    64 * 1024,
    1024 * 1024,
    16 * 1024 * 1024,
    256 * 1024 * 1024,
    1024 * 1024 * 1024,
    4 * 1024 * 1024 * 1024,
    16 * 1024 * 1024 * 1024,
    32 * 1024 * 1024 * 1024,
    64 * 1024 * 1024 * 1024,
    u64::MAX,
];

/// Inclusive histogram bounds for end-to-end save latency, in microseconds.
pub(crate) const LATENCY_US_BUCKET_UPPER_BOUNDS: [u64; 10] = [
    10_000,
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
    30_000_000,
    u64::MAX,
];

/// Inclusive fixed-point ratio bounds.  One million parts-per-million is 1x.
pub(crate) const AMPLIFICATION_PPM_BUCKET_UPPER_BOUNDS: [u64; 10] = [
    1_000_000,
    1_010_000,
    1_100_000,
    2_000_000,
    4_000_000,
    16_000_000,
    64_000_000,
    256_000_000,
    1_024_000_000,
    u64::MAX,
];

struct AggregateHistogram<const N: usize> {
    count: AtomicU64,
    sum: AtomicU64,
    max: AtomicU64,
    cumulative_buckets: [AtomicU64; N],
}

impl<const N: usize> Default for AggregateHistogram<N> {
    fn default() -> Self {
        Self {
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            max: AtomicU64::new(0),
            cumulative_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl<const N: usize> AggregateHistogram<N> {
    fn observe(&self, value: u64, upper_bounds: &[u64; N]) {
        saturating_add(&self.count, 1);
        saturating_add(&self.sum, value);
        update_max(&self.max, value);
        for (bucket, upper_bound) in self.cumulative_buckets.iter().zip(upper_bounds) {
            if value <= *upper_bound {
                saturating_add(bucket, 1);
            }
        }
    }

    fn snapshot(&self) -> HistogramSnapshot<N> {
        HistogramSnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum: self.sum.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
            cumulative_buckets: std::array::from_fn(|index| {
                self.cumulative_buckets[index].load(Ordering::Relaxed)
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HistogramSnapshot<const N: usize> {
    pub(crate) count: u64,
    pub(crate) sum: u64,
    pub(crate) max: u64,
    pub(crate) cumulative_buckets: [u64; N],
}

/// One unlabeled, process-local snapshot of the archive metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StorageMetricsSnapshot {
    pub(crate) logical_db_bytes: HistogramSnapshot<10>,
    pub(crate) changed_wal_bytes_proxy: HistogramSnapshot<10>,
    pub(crate) encrypted_upload_bytes: HistogramSnapshot<10>,
    pub(crate) encrypted_download_bytes: HistogramSnapshot<10>,
    pub(crate) encrypted_upload_attempted_bytes_total: u64,
    pub(crate) save_attempts_total: u64,
    pub(crate) save_completed_total: u64,
    pub(crate) save_failed_total: u64,
    pub(crate) save_skipped_total: u64,
    pub(crate) save_latency_us: HistogramSnapshot<10>,
    pub(crate) write_amplification_ppm: HistogramSnapshot<10>,
}

/// Aggregate process counters.  There is deliberately no label map here.
#[derive(Default)]
pub(crate) struct StorageMetrics {
    logical_db_bytes: AggregateHistogram<10>,
    changed_wal_bytes_proxy: AggregateHistogram<10>,
    encrypted_upload_bytes: AggregateHistogram<10>,
    encrypted_download_bytes: AggregateHistogram<10>,
    encrypted_upload_attempted_bytes_total: AtomicU64,
    save_attempts_total: AtomicU64,
    save_completed_total: AtomicU64,
    save_failed_total: AtomicU64,
    save_skipped_total: AtomicU64,
    save_latency_us: AggregateHistogram<10>,
    write_amplification_ppm: AggregateHistogram<10>,
}

impl StorageMetrics {
    pub(crate) fn record_logical_db_bytes(&self, bytes: u64) {
        self.logical_db_bytes
            .observe(bytes, &BYTE_BUCKET_UPPER_BOUNDS);
    }

    pub(crate) fn record_encrypted_download(&self, bytes: u64) {
        self.encrypted_download_bytes
            .observe(bytes, &BYTE_BUCKET_UPPER_BOUNDS);
    }

    pub(crate) fn record_changed_wal_bytes_proxy(&self, bytes: u64) {
        self.changed_wal_bytes_proxy
            .observe(bytes, &BYTE_BUCKET_UPPER_BOUNDS);
    }

    pub(crate) fn record_save_attempt(&self) {
        saturating_add(&self.save_attempts_total, 1);
    }

    pub(crate) fn record_encrypted_upload_attempt(&self, bytes: u64) {
        saturating_add(&self.encrypted_upload_attempted_bytes_total, bytes);
    }

    /// Record a successful save outcome.
    ///
    /// `Some` is a durable whole-snapshot upload. The middle value is the
    /// pre-checkpoint WAL-file length: a changed-page proxy which includes WAL
    /// framing and can be affected by SQLite auto-checkpointing/reuse. `None`
    /// is reserved for a later, proven-clean dirty-save path: Phase 0 does not
    /// claim a skipped save unless a caller can actually observe that state.
    pub(crate) fn record_save_completed(
        &self,
        durable_snapshot: Option<(u64, u64, u64)>,
        latency_us: u64,
    ) {
        self.save_latency_us
            .observe(latency_us, &LATENCY_US_BUCKET_UPPER_BOUNDS);
        match durable_snapshot {
            Some((logical_db_bytes, changed_wal_bytes_proxy, encrypted_bytes)) => {
                saturating_add(&self.save_completed_total, 1);
                self.record_logical_db_bytes(logical_db_bytes);
                self.encrypted_upload_bytes
                    .observe(encrypted_bytes, &BYTE_BUCKET_UPPER_BOUNDS);
                let amplification_ppm = ratio_ppm(encrypted_bytes, changed_wal_bytes_proxy);
                self.write_amplification_ppm
                    .observe(amplification_ppm, &AMPLIFICATION_PPM_BUCKET_UPPER_BOUNDS);
            }
            None => saturating_add(&self.save_skipped_total, 1),
        }
    }

    pub(crate) fn record_save_failed(&self, latency_us: u64) {
        saturating_add(&self.save_failed_total, 1);
        self.save_latency_us
            .observe(latency_us, &LATENCY_US_BUCKET_UPPER_BOUNDS);
    }

    pub(crate) fn snapshot(&self) -> StorageMetricsSnapshot {
        StorageMetricsSnapshot {
            logical_db_bytes: self.logical_db_bytes.snapshot(),
            changed_wal_bytes_proxy: self.changed_wal_bytes_proxy.snapshot(),
            encrypted_upload_bytes: self.encrypted_upload_bytes.snapshot(),
            encrypted_download_bytes: self.encrypted_download_bytes.snapshot(),
            encrypted_upload_attempted_bytes_total: self
                .encrypted_upload_attempted_bytes_total
                .load(Ordering::Relaxed),
            save_attempts_total: self.save_attempts_total.load(Ordering::Relaxed),
            save_completed_total: self.save_completed_total.load(Ordering::Relaxed),
            save_failed_total: self.save_failed_total.load(Ordering::Relaxed),
            save_skipped_total: self.save_skipped_total.load(Ordering::Relaxed),
            save_latency_us: self.save_latency_us.snapshot(),
            write_amplification_ppm: self.write_amplification_ppm.snapshot(),
        }
    }
}

fn ratio_ppm(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let ratio = u128::from(numerator)
        .saturating_mul(1_000_000)
        .checked_div(u128::from(denominator))
        .unwrap_or(u128::from(u64::MAX));
    ratio.min(u128::from(u64::MAX)) as u64
}

fn saturating_add(target: &AtomicU64, amount: u64) {
    let _ = target.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
}

fn update_max(target: &AtomicU64, value: u64) {
    let _ = target.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (value > current).then_some(value)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histograms_are_cumulative_and_saturating() {
        let histogram = AggregateHistogram::<3>::default();
        let bounds = [10, 20, u64::MAX];
        histogram.observe(5, &bounds);
        histogram.observe(20, &bounds);
        histogram.observe(30, &bounds);

        let snapshot = histogram.snapshot();
        assert_eq!(snapshot.count, 3);
        assert_eq!(snapshot.sum, 55);
        assert_eq!(snapshot.max, 30);
        assert_eq!(snapshot.cumulative_buckets, [1, 2, 3]);
    }

    #[test]
    fn ratio_is_fixed_point_and_handles_zero() {
        assert_eq!(ratio_ppm(101, 100), 1_010_000);
        assert_eq!(ratio_ppm(1, 0), u64::MAX);
    }

    #[test]
    fn save_outcomes_remain_aggregate_and_mutually_exclusive() {
        let metrics = StorageMetrics::default();
        metrics.record_save_attempt();
        metrics.record_encrypted_upload_attempt(101);
        metrics.record_changed_wal_bytes_proxy(10);
        metrics.record_save_completed(Some((100, 10, 101)), 20_000);
        metrics.record_save_attempt();
        metrics.record_save_completed(None, 1_000);
        metrics.record_save_attempt();
        metrics.record_save_failed(50_000);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.save_attempts_total, 3);
        assert_eq!(snapshot.save_completed_total, 1);
        assert_eq!(snapshot.save_skipped_total, 1);
        assert_eq!(snapshot.save_failed_total, 1);
        assert_eq!(snapshot.encrypted_upload_attempted_bytes_total, 101);
        assert_eq!(snapshot.write_amplification_ppm.count, 1);
        assert_eq!(snapshot.changed_wal_bytes_proxy.sum, 10);
        assert_eq!(snapshot.write_amplification_ppm.sum, 10_100_000);
        assert_eq!(snapshot.save_latency_us.count, 3);
    }
}
