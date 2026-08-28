use async_trait::async_trait;
use sqlx::Row;

use crate::error::Result;

use super::super::entitlement::{EntitlementRepository, VertexWorkClass};
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

    async fn reserve_vertex_output_tokens_for_class(
        &self,
        account_id: &str,
        class: VertexWorkClass,
        requested: i64,
        daily_limit: i64,
    ) -> Result<bool> {
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
            return Ok(false);
        }
        if !reservation_allowed(class_current, requested, class.protected_limit(daily_limit)) {
            return Ok(false);
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
        Ok(true)
    }
}
