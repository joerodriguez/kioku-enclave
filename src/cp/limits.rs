//! Fleet-wide quotas, rate limits, and concurrency admission.

use std::time::Duration;

use crate::error::Result;

use crate::persistence::{FleetAdmissionLease, RepositorySet};

pub(crate) use crate::persistence::VertexWorkClass;

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
