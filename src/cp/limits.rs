//! Per-user quotas and rate limits. Rate limiters are in-memory token buckets,
//! which is correct for the single-instance enclave. Daily counters live in
//! the control DB (`usage_daily`).

use std::collections::HashMap;
use std::time::Instant;

use tokio::sync::Mutex;

use crate::error::Result;

use super::control_store::ControlStore;

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
pub async fn account_active(control: &ControlStore, user_id: &str) -> Result<bool> {
    Ok(control.user_status(user_id).await?.as_deref() == Some("active"))
}

pub struct QuotaResult {
    pub allowed: bool,
    pub quota: Option<String>,
}

fn vertex_reservation_allowed(current: i64, requested: i64, limit: i64) -> bool {
    requested > 0 && limit > 0 && current.saturating_add(requested) <= limit
}

/// Reserve the request's full output ceiling before calling Vertex. The
/// encrypted persistent counter survives VM restarts. A timeout retains its
/// reservation because the model may still have completed billable work.
pub async fn reserve_vertex_output_tokens(
    control: &ControlStore,
    user_id: &str,
    requested: i64,
    daily_limit: i64,
) -> Result<QuotaResult> {
    let user_id = user_id.to_string();
    control
        .write(move |conn| {
            let today: String =
                conn.query_row("SELECT strftime('%Y-%m-%d','now')", [], |row| row.get(0))?;
            let current: i64 = conn
                .query_row(
                    "SELECT vertex_output_tokens FROM usage_daily \
                     WHERE user_id = ?1 AND day = ?2",
                    rusqlite::params![user_id, today],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            if !vertex_reservation_allowed(current, requested, daily_limit) {
                return Ok(QuotaResult {
                    allowed: false,
                    quota: Some("vertex_output_tokens_per_day".into()),
                });
            }
            conn.execute(
                "INSERT INTO usage_daily \
                 (user_id, day, vertex_requests, vertex_output_tokens) \
                 VALUES (?1, ?2, 1, ?3) \
                 ON CONFLICT(user_id, day) DO UPDATE SET \
                   vertex_requests = vertex_requests + 1, \
                   vertex_output_tokens = vertex_output_tokens + excluded.vertex_output_tokens",
                rusqlite::params![user_id, today, requested],
            )?;
            Ok(QuotaResult {
                allowed: true,
                quota: None,
            })
        })
        .await
}

/// Check-then-increment daily usage. Mildly racy under concurrency (acceptable —
/// a few items past the cap don't matter and the next call re-checks).
pub async fn daily_quota(
    control: &ControlStore,
    user_id: &str,
    utterances: i64,
    screenshots: i64,
    mcp_calls: i64,
    limits: (i64, i64, i64),
) -> Result<QuotaResult> {
    if utterances == 0 && screenshots == 0 && mcp_calls == 0 {
        return Ok(QuotaResult {
            allowed: true,
            quota: None,
        });
    }
    let user_id = user_id.to_string();
    let (lim_utt, lim_scr, lim_mcp) = limits;
    control
        .write(move |conn| {
            let today: String =
                conn.query_row("SELECT strftime('%Y-%m-%d','now')", [], |r| r.get(0))?;
            let (cur_utt, cur_scr, cur_mcp): (i64, i64, i64) = conn
                .query_row(
                    "SELECT utterances, screenshots, mcp_calls FROM usage_daily \
                     WHERE user_id = ?1 AND day = ?2",
                    rusqlite::params![user_id, today],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap_or((0, 0, 0));

            if utterances > 0 && cur_utt + utterances > lim_utt {
                return Ok(QuotaResult {
                    allowed: false,
                    quota: Some("utterances_per_day".into()),
                });
            }
            if screenshots > 0 && cur_scr + screenshots > lim_scr {
                return Ok(QuotaResult {
                    allowed: false,
                    quota: Some("screenshots_per_day".into()),
                });
            }
            if mcp_calls > 0 && cur_mcp + mcp_calls > lim_mcp {
                return Ok(QuotaResult {
                    allowed: false,
                    quota: Some("mcp_calls_per_day".into()),
                });
            }

            conn.execute(
                "INSERT INTO usage_daily (user_id, day, utterances, screenshots, mcp_calls) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(user_id, day) DO UPDATE SET \
                   utterances  = utterances  + excluded.utterances, \
                   screenshots = screenshots + excluded.screenshots, \
                   mcp_calls   = mcp_calls   + excluded.mcp_calls",
                rusqlite::params![user_id, today, utterances, screenshots, mcp_calls],
            )?;
            Ok(QuotaResult {
                allowed: true,
                quota: None,
            })
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let control = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let user = control
            .upsert_user("vertex-budget-user", "budget@example.com")
            .await
            .unwrap();

        let first = reserve_vertex_output_tokens(&control, &user.id, 8_192, 8_192)
            .await
            .unwrap();
        let second = reserve_vertex_output_tokens(&control, &user.id, 1, 8_192)
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
}
