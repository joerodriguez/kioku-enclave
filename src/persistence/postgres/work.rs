use async_trait::async_trait;

use crate::{
    cp::isotime,
    error::{EnclaveError, Result},
    persistence::WorkRepository,
};

use super::PostgresPersistence;

fn parse_timestamp(value: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .filter(|millis| isotime::format_epoch_millis(*millis) == value)
        .ok_or_else(|| EnclaveError::Store("work cursor timestamp is invalid".into()))
}

#[async_trait]
impl WorkRepository for PostgresPersistence {
    async fn active_account_ids(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT id FROM accounts WHERE status='active' ORDER BY created_at,id",
        )
        .fetch_all(self.pool())
        .await?)
    }

    async fn summarized_until(&self, account_id: &str) -> Result<Option<String>> {
        let value = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT floor(extract(epoch FROM summarized_until) * 1000)::bigint \
             FROM accounts WHERE id=$1",
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?
        .flatten();
        Ok(value.map(isotime::format_epoch_millis))
    }

    async fn set_summarized_until(&self, account_id: &str, value: &str) -> Result<()> {
        let millis = parse_timestamp(value)?;
        sqlx::query(
            "UPDATE accounts SET summarized_until=to_timestamp($2::double precision/1000.0), \
                    updated_at=now() WHERE id=$1",
        )
        .bind(account_id)
        .bind(millis)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}
