//! Per-user quotas and rate limits. Rate limiters are in-memory token buckets,
//! which is correct for the single-instance enclave. Daily counters live in
//! the control DB (`usage_daily`).

use std::collections::HashMap;
use std::time::Instant;

use tokio::sync::Mutex;

use crate::error::Result;

use crate::persistence::RepositorySet;

pub(crate) use crate::persistence::VertexWorkClass;

/// Token-bucket rate limiter keyed by user id.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
    capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
        }
    }

    /// Try to consume one token. Returns `false` when rate-limited.
    pub async fn consume(&self, user_id: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        let entry = buckets
            .entry(user_id.to_string())
            .or_insert((self.capacity, now));
        // Refill proportional to elapsed time.
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * self.refill_per_sec).min(self.capacity);
        entry.1 = now;
        if entry.0 < 1.0 {
            return false;
        }
        entry.0 -= 1.0;
        true
    }
}

/// Returns true only for an existing active account. Unknown/deleted users are
/// denied so a stale access token cannot recreate content after deletion.
pub async fn account_active(repositories: &RepositorySet, user_id: &str) -> Result<bool> {
    repositories.entitlements().account_active(user_id).await
}

pub struct QuotaResult {
    pub allowed: bool,
    #[allow(dead_code)] // legacy ingest quota name; Vertex callers need only allowed
    pub quota: Option<String>,
}

#[cfg(test)]
fn vertex_reservation_allowed(current: i64, requested: i64, limit: i64) -> bool {
    requested > 0 && limit > 0 && current.saturating_add(requested) <= limit
}

/// Reserve the request's full output ceiling before calling Vertex. The
/// encrypted persistent counter survives VM restarts. A timeout retains its
/// reservation because the model may still have completed billable work.
#[cfg(test)]
pub async fn reserve_vertex_output_tokens(
    repositories: &RepositorySet,
    user_id: &str,
    requested: i64,
    daily_limit: i64,
) -> Result<QuotaResult> {
    let result = repositories
        .entitlements()
        .reserve_vertex_output_tokens(user_id, requested, daily_limit)
        .await?;
    Ok(QuotaResult {
        allowed: result.allowed,
        quota: result.quota,
    })
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
) -> Result<QuotaResult> {
    let result = repositories
        .entitlements()
        .reserve_vertex_output_tokens_for_class(user_id, class, requested, daily_limit)
        .await?;
    Ok(QuotaResult {
        allowed: result.allowed,
        quota: result.quota,
    })
}

/// Check-then-increment daily usage. Mildly racy under concurrency (acceptable —
/// a few items past the cap don't matter and the next call re-checks).
#[allow(dead_code)] // retained for old-index tooling after `/api/sync/batch` retirement
pub async fn daily_quota(
    repositories: &RepositorySet,
    user_id: &str,
    utterances: i64,
    screenshots: i64,
    mcp_calls: i64,
    limits: (i64, i64, i64),
) -> Result<QuotaResult> {
    let result = repositories
        .entitlements()
        .reserve_daily_usage(user_id, utterances, screenshots, mcp_calls, limits)
        .await?;
    Ok(QuotaResult {
        allowed: result.allowed,
        quota: result.quota,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::control_store::ControlStore;
    use crate::persistence::RepositorySet;
    use crate::store::tests::{FakeGcs, FakeKms};
    use std::sync::Arc;

    #[test]
    fn vertex_output_reservations_fail_closed_at_the_daily_limit() {
        assert!(vertex_reservation_allowed(0, 8_192, 524_288));
        assert!(vertex_reservation_allowed(516_096, 8_192, 524_288));
        assert!(!vertex_reservation_allowed(516_097, 8_192, 524_288));
        assert!(!vertex_reservation_allowed(0, 8_193, 8_192));
    }

    #[tokio::test]
    async fn vertex_output_reservations_are_persistent_and_atomic() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let user = control
            .upsert_user(
                "vertex-budget-user",
                "budget@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();

        let repositories = RepositorySet::legacy(Arc::clone(&control));
        let first = reserve_vertex_output_tokens(&repositories, &user.id, 8_192, 8_192)
            .await
            .unwrap();
        let second = reserve_vertex_output_tokens(&repositories, &user.id, 1, 8_192)
            .await
            .unwrap();
        assert!(first.allowed);
        assert!(!second.allowed);
        assert_eq!(
            second.quota.as_deref(),
            Some("vertex_output_tokens_per_day")
        );

        let user_id = user.id.clone();
        let persisted: (i64, i64) = control
            .read(move |conn| {
                conn.query_row(
                    "SELECT vertex_requests, vertex_output_tokens FROM usage_daily \
                     WHERE user_id = ?1",
                    [&user_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(persisted, (1, 8_192));
    }

    #[tokio::test]
    async fn vertex_work_classes_have_persistent_protected_budgets() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let user = control
            .upsert_user(
                "class-budget-user",
                "classes@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let daily_limit = 16_384;
        let repositories = RepositorySet::legacy(Arc::clone(&control));

        assert!(
            reserve_vertex_output_tokens_for_class(
                &repositories,
                &user.id,
                VertexWorkClass::Screen,
                4_096,
                daily_limit,
            )
            .await
            .unwrap()
            .allowed
        );
        let screen_over = reserve_vertex_output_tokens_for_class(
            &repositories,
            &user.id,
            VertexWorkClass::Screen,
            1,
            daily_limit,
        )
        .await
        .unwrap();
        assert!(!screen_over.allowed);
        assert_eq!(
            screen_over.quota.as_deref(),
            Some("vertex_screen_output_tokens_per_day")
        );

        assert!(
            reserve_vertex_output_tokens_for_class(
                &repositories,
                &user.id,
                VertexWorkClass::Audio,
                8_192,
                daily_limit,
            )
            .await
            .unwrap()
            .allowed
        );
        assert!(
            reserve_vertex_output_tokens_for_class(
                &repositories,
                &user.id,
                VertexWorkClass::DerivedText,
                4_096,
                daily_limit,
            )
            .await
            .unwrap()
            .allowed
        );

        let user_id = user.id.clone();
        let persisted: (i64, i64, i64, i64) = control
            .read(move |conn| {
                conn.query_row(
                    "SELECT vertex_output_tokens,vertex_audio_output_tokens,\
                            vertex_screen_output_tokens,vertex_derived_output_tokens \
                     FROM usage_daily WHERE user_id=?1",
                    [&user_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(persisted, (16_384, 8_192, 4_096, 4_096));
    }

    #[tokio::test]
    async fn every_billable_media_retry_consumes_a_distinct_output_ceiling() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let user = control
            .upsert_user(
                "media-retry-budget-user",
                "retries@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let repositories = RepositorySet::legacy(Arc::clone(&control));

        // Audio owns half of the 600-token daily ceiling. Three ambiguous or
        // invalid-output attempts may each have been billed and therefore
        // consume all 300 protected tokens; a fourth attempt must fail closed.
        for _ in 0..3 {
            assert!(
                reserve_vertex_output_tokens_for_class(
                    &repositories,
                    &user.id,
                    VertexWorkClass::Audio,
                    100,
                    600,
                )
                .await
                .unwrap()
                .allowed
            );
        }
        let fourth = reserve_vertex_output_tokens_for_class(
            &repositories,
            &user.id,
            VertexWorkClass::Audio,
            100,
            600,
        )
        .await
        .unwrap();
        assert!(!fourth.allowed);
        assert_eq!(
            fourth.quota.as_deref(),
            Some("vertex_audio_output_tokens_per_day")
        );

        let user_id = user.id.clone();
        let persisted: (i64, i64, i64) = control
            .read(move |conn| {
                conn.query_row(
                    "SELECT vertex_requests,vertex_output_tokens,vertex_audio_output_tokens \
                     FROM usage_daily WHERE user_id=?1",
                    [&user_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(persisted, (3, 300, 300));
    }
}
