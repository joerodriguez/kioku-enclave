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

/// Insert query accounting without persisting the user's sensitive search text.
#[allow(dead_code)] // wired by the MCP/search routes in a later commit
pub async fn log_query(
    control: &ControlStore,
    user_id: &str,
    source: &str,
    tool: &str,
    _query_text: Option<String>,
    result_count: i64,
    duration_ms: i64,
) -> Result<()> {
    let (user_id, source, tool) = (user_id.to_string(), source.to_string(), tool.to_string());
    control
        .write(move |conn| {
            conn.execute(
                "INSERT INTO query_log (user_id, source, tool, query_text, result_count, duration_ms) \
                 VALUES (?1, ?2, ?3, NULL, ?4, ?5)",
                rusqlite::params![user_id, source, tool, result_count, duration_ms],
            )?;
            Ok(())
        })
        .await
}
