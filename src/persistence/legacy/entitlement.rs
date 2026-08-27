use std::sync::Arc;

use async_trait::async_trait;

use crate::cp::control_store::ControlStore;
use crate::error::Result;

use super::super::entitlement::{EntitlementRepository, QuotaResult, VertexWorkClass};

pub(crate) struct LegacyEntitlementRepository {
    control: Arc<ControlStore>,
}

impl LegacyEntitlementRepository {
    pub(crate) fn new(control: Arc<ControlStore>) -> Self {
        Self { control }
    }
}

fn reservation_allowed(current: i64, requested: i64, limit: i64) -> bool {
    requested > 0 && limit > 0 && current.saturating_add(requested) <= limit
}

#[async_trait]
impl EntitlementRepository for LegacyEntitlementRepository {
    async fn account_active(&self, account_id: &str) -> Result<bool> {
        Ok(self.control.user_status(account_id).await?.as_deref() == Some("active"))
    }

    async fn reserve_vertex_output_tokens(
        &self,
        account_id: &str,
        requested: i64,
        daily_limit: i64,
    ) -> Result<QuotaResult> {
        let account_id = account_id.to_string();
        self.control
            .write(move |connection| {
                let today: String =
                    connection
                        .query_row("SELECT strftime('%Y-%m-%d','now')", [], |row| row.get(0))?;
                let current: i64 = connection
                    .query_row(
                        "SELECT vertex_output_tokens FROM usage_daily \
                         WHERE user_id = ?1 AND day = ?2",
                        rusqlite::params![account_id, today],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);
                if !reservation_allowed(current, requested, daily_limit) {
                    return Ok(QuotaResult {
                        allowed: false,
                        quota: Some("vertex_output_tokens_per_day".into()),
                    });
                }
                connection.execute(
                    "INSERT INTO usage_daily \
                     (user_id, day, vertex_requests, vertex_output_tokens) \
                     VALUES (?1, ?2, 1, ?3) \
                     ON CONFLICT(user_id, day) DO UPDATE SET \
                       vertex_requests = vertex_requests + 1, \
                       vertex_output_tokens = vertex_output_tokens + excluded.vertex_output_tokens",
                    rusqlite::params![account_id, today, requested],
                )?;
                Ok(QuotaResult {
                    allowed: true,
                    quota: None,
                })
            })
            .await
    }

    async fn reserve_vertex_output_tokens_for_class(
        &self,
        account_id: &str,
        class: VertexWorkClass,
        requested: i64,
        daily_limit: i64,
    ) -> Result<QuotaResult> {
        let account_id = account_id.to_string();
        self.control
            .write(move |connection| {
                let today: String = connection.query_row(
                    "SELECT strftime('%Y-%m-%d','now')",
                    [],
                    |row| row.get(0),
                )?;
                let current: (i64, i64, i64, i64) = connection
                    .query_row(
                        "SELECT vertex_output_tokens,vertex_audio_output_tokens,\
                                vertex_screen_output_tokens,vertex_derived_output_tokens \
                         FROM usage_daily WHERE user_id=?1 AND day=?2",
                        rusqlite::params![account_id, today],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .unwrap_or((0, 0, 0, 0));
                let class_current = match class {
                    VertexWorkClass::Audio => current.1,
                    VertexWorkClass::Screen => current.2,
                    VertexWorkClass::DerivedText => current.3,
                };
                if !reservation_allowed(current.0, requested, daily_limit) {
                    return Ok(QuotaResult {
                        allowed: false,
                        quota: Some("vertex_output_tokens_per_day".into()),
                    });
                }
                if !reservation_allowed(
                    class_current,
                    requested,
                    class.protected_limit(daily_limit),
                ) {
                    return Ok(QuotaResult {
                        allowed: false,
                        quota: Some(class.quota_name().into()),
                    });
                }
                let (audio, screen, derived) = match class {
                    VertexWorkClass::Audio => (requested, 0, 0),
                    VertexWorkClass::Screen => (0, requested, 0),
                    VertexWorkClass::DerivedText => (0, 0, requested),
                };
                connection.execute(
                    "INSERT INTO usage_daily \
                     (user_id,day,vertex_requests,vertex_output_tokens,\
                      vertex_audio_output_tokens,vertex_screen_output_tokens,vertex_derived_output_tokens) \
                     VALUES (?1,?2,1,?3,?4,?5,?6) \
                     ON CONFLICT(user_id,day) DO UPDATE SET \
                       vertex_requests=vertex_requests+1,\
                       vertex_output_tokens=vertex_output_tokens+excluded.vertex_output_tokens,\
                       vertex_audio_output_tokens=vertex_audio_output_tokens+excluded.vertex_audio_output_tokens,\
                       vertex_screen_output_tokens=vertex_screen_output_tokens+excluded.vertex_screen_output_tokens,\
                       vertex_derived_output_tokens=vertex_derived_output_tokens+excluded.vertex_derived_output_tokens",
                    rusqlite::params![account_id, today, requested, audio, screen, derived],
                )?;
                Ok(QuotaResult { allowed: true, quota: None })
            })
            .await
    }

    async fn reserve_daily_usage(
        &self,
        account_id: &str,
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
        let account_id = account_id.to_string();
        let (utterance_limit, screenshot_limit, mcp_limit) = limits;
        self.control
            .write(move |connection| {
                let today: String =
                    connection
                        .query_row("SELECT strftime('%Y-%m-%d','now')", [], |row| row.get(0))?;
                let current: (i64, i64, i64) = connection
                    .query_row(
                        "SELECT utterances, screenshots, mcp_calls FROM usage_daily \
                         WHERE user_id = ?1 AND day = ?2",
                        rusqlite::params![account_id, today],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .unwrap_or((0, 0, 0));
                for (requested, used, limit, name) in [
                    (utterances, current.0, utterance_limit, "utterances_per_day"),
                    (
                        screenshots,
                        current.1,
                        screenshot_limit,
                        "screenshots_per_day",
                    ),
                    (mcp_calls, current.2, mcp_limit, "mcp_calls_per_day"),
                ] {
                    if requested > 0 && used.saturating_add(requested) > limit {
                        return Ok(QuotaResult {
                            allowed: false,
                            quota: Some(name.into()),
                        });
                    }
                }
                connection.execute(
                    "INSERT INTO usage_daily (user_id, day, utterances, screenshots, mcp_calls) \
                     VALUES (?1, ?2, ?3, ?4, ?5) \
                     ON CONFLICT(user_id, day) DO UPDATE SET \
                       utterances  = utterances  + excluded.utterances, \
                       screenshots = screenshots + excluded.screenshots, \
                       mcp_calls   = mcp_calls   + excluded.mcp_calls",
                    rusqlite::params![account_id, today, utterances, screenshots, mcp_calls],
                )?;
                Ok(QuotaResult {
                    allowed: true,
                    quota: None,
                })
            })
            .await
    }
}
