use std::time::Duration;

use async_trait::async_trait;
use sqlx::Row;

use crate::{
    error::{EnclaveError, Result},
    persistence::AdmissionRepository,
};

use super::{advisory_transaction_lock, duration_seconds, PostgresPersistence};

fn validate_dimension(value: &str, name: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(EnclaveError::InvalidRequest(format!(
            "invalid fleet admission {name}"
        )));
    }
    Ok(())
}

#[async_trait]
impl AdmissionRepository for PostgresPersistence {
    async fn consume_rate(
        &self,
        scope: &str,
        key: &str,
        capacity: f64,
        refill_per_second: f64,
    ) -> Result<bool> {
        validate_dimension(scope, "scope")?;
        validate_dimension(key, "key")?;
        if !capacity.is_finite()
            || capacity < 1.0
            || !refill_per_second.is_finite()
            || refill_per_second <= 0.0
        {
            return Err(EnclaveError::Config(
                "invalid fleet rate-limit policy".into(),
            ));
        }

        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(
            &mut transaction,
            "fleet-rate-limit",
            &format!("{scope}\u{1f}{key}"),
        )
        .await?;
        let current = sqlx::query(
            "SELECT tokens, \
                    GREATEST(0,extract(epoch FROM (clock_timestamp()-updated_at)))::double precision \
               AS elapsed_seconds \
             FROM fleet_rate_limits WHERE scope=$1 AND admission_key=$2 FOR UPDATE",
        )
        .bind(scope)
        .bind(key)
        .fetch_optional(&mut *transaction)
        .await?;
        let available = match current {
            Some(row) => {
                let tokens: f64 = row.try_get("tokens")?;
                let elapsed: f64 = row.try_get("elapsed_seconds")?;
                (tokens + elapsed * refill_per_second).min(capacity)
            }
            None => capacity,
        };
        let allowed = available >= 1.0;
        let remaining = if allowed { available - 1.0 } else { available };
        sqlx::query(
            "INSERT INTO fleet_rate_limits(scope,admission_key,tokens,updated_at) \
             VALUES($1,$2,$3,clock_timestamp()) \
             ON CONFLICT(scope,admission_key) DO UPDATE \
             SET tokens=EXCLUDED.tokens,updated_at=EXCLUDED.updated_at",
        )
        .bind(scope)
        .bind(key)
        .bind(remaining)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(allowed)
    }

    async fn acquire_concurrency(
        &self,
        scope: &str,
        holder: &str,
        limit: u32,
        ttl: Duration,
    ) -> Result<bool> {
        validate_dimension(scope, "scope")?;
        validate_dimension(holder, "holder")?;
        if limit == 0 {
            return Err(EnclaveError::Config(
                "fleet concurrency limit must be positive".into(),
            ));
        }
        let ttl_seconds = duration_seconds(ttl)?;
        if !(1.0..=3_600.0).contains(&ttl_seconds) {
            return Err(EnclaveError::Config(
                "fleet concurrency lease TTL must be between 1 and 3600 seconds".into(),
            ));
        }

        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "fleet-concurrency", scope).await?;
        sqlx::query(
            "DELETE FROM fleet_concurrency_leases \
             WHERE scope=$1 AND expires_at<=clock_timestamp()",
        )
        .bind(scope)
        .execute(&mut *transaction)
        .await?;
        let already_held = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM fleet_concurrency_leases \
                           WHERE scope=$1 AND holder=$2)",
        )
        .bind(scope)
        .bind(holder)
        .fetch_one(&mut *transaction)
        .await?;
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM fleet_concurrency_leases WHERE scope=$1")
                .bind(scope)
                .fetch_one(&mut *transaction)
                .await?;
        let allowed = already_held || active < i64::from(limit);
        if allowed {
            sqlx::query(
                "INSERT INTO fleet_concurrency_leases(scope,holder,expires_at) \
                 VALUES($1,$2,clock_timestamp()+$3::double precision*interval '1 second') \
                 ON CONFLICT(scope,holder) DO UPDATE SET expires_at=EXCLUDED.expires_at",
            )
            .bind(scope)
            .bind(holder)
            .bind(ttl_seconds)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(allowed)
    }

    async fn release_concurrency(&self, scope: &str, holder: &str) -> Result<()> {
        validate_dimension(scope, "scope")?;
        validate_dimension(holder, "holder")?;
        sqlx::query("DELETE FROM fleet_concurrency_leases WHERE scope=$1 AND holder=$2")
            .bind(scope)
            .bind(holder)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}
