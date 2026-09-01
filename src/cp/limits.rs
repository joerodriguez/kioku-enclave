//! Fleet-wide quotas, rate limits, and concurrency admission.

use std::time::Duration;

use crate::error::Result;

use crate::persistence::{FleetAdmissionLease, RepositorySet};

pub(crate) use crate::persistence::VertexWorkClass;

/// Reviewed per-account UTC-calendar-day Vertex output ceiling baked into the
/// attested image. Class allocations remain non-borrowing 50/25/25 shares.
pub(crate) const REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY: i64 = 2_621_440;

/// Token-bucket rate limiter keyed by user id.
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
        }
    }

    /// Apply this limiter across the whole PostgreSQL fleet.
    pub async fn consume_scoped(
        &self,
        repositories: &RepositorySet,
        scope: &'static str,
        key: &str,
    ) -> bool {
        match repositories
            .admission()
            .consume_rate(scope, key, self.capacity, self.refill_per_sec)
            .await
        {
            Ok(allowed) => allowed,
            Err(error) => {
                tracing::error!(scope, error = %error, "fleet rate admission failed closed");
                false
            }
        }
    }
}

/// Canonical media and individual-reference admission must keep pace with the
/// 120 event credits granted by each recorded minute. The one-minute bucket
/// absorbs reconnect bursts while the two-event-per-second refill sustains the
/// maximum credited live production rate; durable event and byte credits remain
/// the account's ultimate admission bound.
pub fn capture_event_limiter() -> RateLimiter {
    RateLimiter::new(120.0, 2.0)
}

pub(crate) struct ConcurrencyPermit {
    _lease: FleetAdmissionLease,
}

/// Acquire a durable fleet lease. Storage errors are returned so callers can
/// distinguish service unavailability from ordinary saturation.
pub(crate) async fn try_acquire_concurrency(
    repositories: &RepositorySet,
    scope: &'static str,
    holder: &str,
    limit: u32,
    ttl: Duration,
) -> Result<Option<ConcurrencyPermit>> {
    let admission = repositories.admission_arc();
    if admission
        .acquire_concurrency(scope, holder, limit, ttl)
        .await?
    {
        Ok(Some(ConcurrencyPermit {
            _lease: FleetAdmissionLease::new(admission, scope, holder),
        }))
    } else {
        Ok(None)
    }
}

/// Returns true only for an existing active account. Unknown/deleted users are
/// denied so a stale access token cannot recreate content after deletion.
pub async fn account_active(repositories: &RepositorySet, user_id: &str) -> Result<bool> {
    repositories.entitlements().account_active(user_id).await
}

/// Atomically reserve a bounded Vertex output ceiling from both the global
/// daily hard cap and the work class's protected allocation. Class borrowing
/// is deliberately disabled until source-settled state can be proven; this is
/// the fail-closed policy that prevents screens from consuming audio capacity.
pub async fn reserve_vertex_output_tokens_for_class(
    repositories: &RepositorySet,
    user_id: &str,
    class: VertexWorkClass,
    requested: i64,
    daily_limit: i64,
) -> Result<bool> {
    repositories
        .entitlements()
        .reserve_vertex_output_tokens_for_class(user_id, class, requested, daily_limit)
        .await
}

#[cfg(test)]
mod tests {
    use super::{capture_event_limiter, REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY};
    use crate::persistence::{VertexWorkClass, CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS};

    #[test]
    fn capture_event_admission_matches_the_paid_minute_credit_rate() {
        let limiter = capture_event_limiter();
        assert_eq!(limiter.capacity, 120.0);
        assert_eq!(limiter.refill_per_sec, 2.0);
    }

    #[test]
    fn reviewed_vertex_quota_fits_the_conservative_active_daily_chain() {
        let audio = VertexWorkClass::Audio.protected_limit(REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY);
        let screen = VertexWorkClass::Screen.protected_limit(REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY);
        let derived =
            VertexWorkClass::DerivedText.protected_limit(REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY);
        assert_eq!(audio, 1_310_720);
        assert_eq!(screen, 655_360);
        assert_eq!(derived, 655_360);
        assert_eq!(
            audio / i64::from(super::super::vertex::MAX_MEDIA_OUTPUT_TOKENS),
            320
        );
        assert_eq!(
            screen / i64::from(super::super::vertex::MAX_SCREEN_OUTPUT_TOKENS),
            640
        );
        assert_eq!(
            derived / i64::from(CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS),
            80
        );

        // One same-day maximal settled cohort can consume 32 formation calls,
        // one reconciliation call, and up to 32 successor finalizations.
        // This intentionally counts the complete steady-state chain rather
        // than only the already-formed activation backlog.
        let formation_calls = super::super::reconciler::MAX_COHORT_DRAFTS;
        let reconciliation_calls = 1_i64;
        let finalizer_calls = super::super::reconciler::MAX_OUTPUTS as i64;
        let active_chain_calls = formation_calls + reconciliation_calls + finalizer_calls;
        assert_eq!(active_chain_calls, 65);
        let active_chain_tokens =
            active_chain_calls * i64::from(CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS);
        assert_eq!(active_chain_tokens, 532_480);
        assert!(active_chain_tokens <= derived);
        assert_eq!(
            super::super::reconciler::RECONCILIATION_OUTPUT_TOKENS,
            CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS
        );
        assert_eq!(
            super::super::finalizer::FINALIZER_MAX_OUTPUT_TOKENS,
            CAPTURE_FORMATION_PROVIDER_MAX_OUTPUT_TOKENS
        );
    }
}
