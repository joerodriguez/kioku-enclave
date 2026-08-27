use async_trait::async_trait;
use sqlx::Row;

use crate::error::Result;

use super::super::entitlement::{EntitlementRepository, QuotaResult, VertexWorkClass};
use super::{advisory_transaction_lock, PostgresPersistence};

fn reservation_allowed(current: i64, requested: i64, limit: i64) -> bool {
    requested > 0 && limit > 0 && current.saturating_add(requested) <= limit
}

#[async_trait]
impl EntitlementRepository for PostgresPersistence {
    async fn account_active(&self, account_id: &str) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1 AND status = 'active')",
        )
        .bind(account_id)
        .fetch_one(self.pool())
        .await?)
    }

    async fn reserve_vertex_output_tokens(
        &self,
        account_id: &str,
        requested: i64,
        daily_limit: i64,
    ) -> Result<QuotaResult> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "quota-daily", account_id).await?;
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT vertex_output_tokens FROM usage_daily \
              WHERE account_id = $1 AND day = CURRENT_DATE FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?
        .unwrap_or(0);
        if !reservation_allowed(current, requested, daily_limit) {
            return Ok(QuotaResult {
                allowed: false,
                quota: Some("vertex_output_tokens_per_day".into()),
            });
        }
        sqlx::query(
            "INSERT INTO usage_daily \
                (account_id, day, vertex_requests, vertex_output_tokens) \
             VALUES ($1, CURRENT_DATE, 1, $2) \
             ON CONFLICT (account_id, day) DO UPDATE SET \
               vertex_requests = usage_daily.vertex_requests + 1, \
               vertex_output_tokens = usage_daily.vertex_output_tokens + EXCLUDED.vertex_output_tokens, \
               updated_at = now()",
        )
        .bind(account_id)
        .bind(requested)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(QuotaResult {
            allowed: true,
            quota: None,
        })
    }

    async fn reserve_vertex_output_tokens_for_class(
        &self,
        account_id: &str,
        class: VertexWorkClass,
        requested: i64,
        daily_limit: i64,
    ) -> Result<QuotaResult> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "quota-daily", account_id).await?;
        let row = sqlx::query(
            "SELECT vertex_output_tokens, vertex_audio_output_tokens, \
                    vertex_screen_output_tokens, vertex_derived_output_tokens \
               FROM usage_daily WHERE account_id = $1 AND day = CURRENT_DATE FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let current = row
            .map(|row| {
                Ok::<_, sqlx::Error>((
                    row.try_get::<i64, _>("vertex_output_tokens")?,
                    row.try_get::<i64, _>("vertex_audio_output_tokens")?,
                    row.try_get::<i64, _>("vertex_screen_output_tokens")?,
                    row.try_get::<i64, _>("vertex_derived_output_tokens")?,
                ))
            })
            .transpose()?
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
        if !reservation_allowed(class_current, requested, class.protected_limit(daily_limit)) {
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
        sqlx::query(
            "INSERT INTO usage_daily \
                (account_id, day, vertex_requests, vertex_output_tokens, \
                 vertex_audio_output_tokens, vertex_screen_output_tokens, \
                 vertex_derived_output_tokens) \
             VALUES ($1, CURRENT_DATE, 1, $2, $3, $4, $5) \
             ON CONFLICT (account_id, day) DO UPDATE SET \
               vertex_requests = usage_daily.vertex_requests + 1, \
               vertex_output_tokens = usage_daily.vertex_output_tokens + EXCLUDED.vertex_output_tokens, \
               vertex_audio_output_tokens = usage_daily.vertex_audio_output_tokens + EXCLUDED.vertex_audio_output_tokens, \
               vertex_screen_output_tokens = usage_daily.vertex_screen_output_tokens + EXCLUDED.vertex_screen_output_tokens, \
               vertex_derived_output_tokens = usage_daily.vertex_derived_output_tokens + EXCLUDED.vertex_derived_output_tokens, \
               updated_at = now()",
        )
        .bind(account_id)
        .bind(requested)
        .bind(audio)
        .bind(screen)
        .bind(derived)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(QuotaResult {
            allowed: true,
            quota: None,
        })
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
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "quota-daily", account_id).await?;
        let row = sqlx::query(
            "SELECT utterances, screenshots, mcp_calls FROM usage_daily \
              WHERE account_id = $1 AND day = CURRENT_DATE FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let current = row
            .map(|row| {
                Ok::<_, sqlx::Error>((
                    row.try_get::<i64, _>("utterances")?,
                    row.try_get::<i64, _>("screenshots")?,
                    row.try_get::<i64, _>("mcp_calls")?,
                ))
            })
            .transpose()?
            .unwrap_or((0, 0, 0));
        for (requested, used, limit, name) in [
            (utterances, current.0, limits.0, "utterances_per_day"),
            (screenshots, current.1, limits.1, "screenshots_per_day"),
            (mcp_calls, current.2, limits.2, "mcp_calls_per_day"),
        ] {
            if requested > 0 && used.saturating_add(requested) > limit {
                return Ok(QuotaResult {
                    allowed: false,
                    quota: Some(name.into()),
                });
            }
        }
        sqlx::query(
            "INSERT INTO usage_daily \
                (account_id, day, utterances, screenshots, mcp_calls) \
             VALUES ($1, CURRENT_DATE, $2, $3, $4) \
             ON CONFLICT (account_id, day) DO UPDATE SET \
               utterances = usage_daily.utterances + EXCLUDED.utterances, \
               screenshots = usage_daily.screenshots + EXCLUDED.screenshots, \
               mcp_calls = usage_daily.mcp_calls + EXCLUDED.mcp_calls, \
               updated_at = now()",
        )
        .bind(account_id)
        .bind(utterances)
        .bind(screenshots)
        .bind(mcp_calls)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(QuotaResult {
            allowed: true,
            quota: None,
        })
    }
}
