use std::collections::HashSet;

use async_trait::async_trait;
use sqlx::Row;

use crate::cp::isotime;
use crate::error::{EnclaveError, Result};

use super::super::billing::{
    AccountDriverMetrics, BillingRepository, RecordingLeaseRequestRow, RetainedAccountMetrics,
    VertexCoverageAnchor,
};
use super::{advisory_transaction_lock, PostgresPersistence};

const RECORDING_LEASE_DURATION_MS: i64 = 60_000;
const RECORDING_DELIVERY_EVENTS_PER_MINUTE: i64 = 120;
const RECORDING_DELIVERY_BYTES_PER_MINUTE: i64 = 256 * 1024 * 1024;
const MAX_RECORDING_LEASE_DENIALS_PER_ACCOUNT: i64 = 100;
const MAX_PENDING_REFERENCE_BATCHES_PER_ACCOUNT: i64 = 256;

fn valid_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn settle_reference_batches(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE capture_reference_batch_receipts r SET state='completed',updated_at=now() \
          WHERE r.account_id=$1 AND r.state='reserved' AND NOT EXISTS ( \
            SELECT 1 FROM capture_reference_batch_events e \
            JOIN recording_delivery_reservations d ON d.account_id=e.account_id AND d.event_id=e.event_id \
            WHERE e.account_id=r.account_id AND e.batch_id=r.batch_id)",
    )
    .bind(account_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "DELETE FROM capture_reference_batch_receipts r WHERE r.account_id=$1 AND r.state='completed' \
          AND r.batch_id NOT IN (SELECT batch_id FROM capture_reference_batch_receipts \
            WHERE account_id=$1 AND state='completed' ORDER BY updated_at DESC,batch_id DESC LIMIT 256)",
    )
    .bind(account_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn valid_utc_month(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7
        && bytes[4] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..].iter().all(u8::is_ascii_digit)
        && (1..=12).contains(&((bytes[5] - b'0') * 10 + bytes[6] - b'0'))
}

fn checked_i64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| EnclaveError::Config(format!("{label} overflow")))
}

fn checked_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| EnclaveError::Config(format!("{label} overflow")))
}

fn required_millis(value: &str, label: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .ok_or_else(|| EnclaveError::Config(format!("invalid {label} timestamp")))
}

async fn account_status_for_update(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT status FROM accounts WHERE id=$1 FOR UPDATE")
            .bind(account_id)
            .fetch_optional(&mut **transaction)
            .await?,
    )
}

async fn grant_recording_delivery_minute(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO recording_delivery_balances (account_id,event_credits,byte_credits) \
         VALUES ($1,$2,$3) ON CONFLICT (account_id) DO UPDATE SET \
           event_credits=recording_delivery_balances.event_credits+EXCLUDED.event_credits, \
           byte_credits=recording_delivery_balances.byte_credits+EXCLUDED.byte_credits, \
           updated_at=now()",
    )
    .bind(account_id)
    .bind(RECORDING_DELIVERY_EVENTS_PER_MINUTE)
    .bind(RECORDING_DELIVERY_BYTES_PER_MINUTE)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn lease_row(row: &sqlx::postgres::PgRow, state: String) -> Result<RecordingLeaseRequestRow> {
    let summary = row
        .try_get::<Option<String>, _>("summary_json")?
        .map(|value| serde_json::from_str(&value))
        .transpose()?;
    Ok(RecordingLeaseRequestRow {
        requested_lease_id: row.try_get("requested_lease_id")?,
        issued_lease_id: row.try_get("issued_lease_id")?,
        expires_at: isotime::format_epoch_millis(row.try_get("expires_at_ms")?),
        state,
        summary,
        denial_code: row.try_get("denial_code")?,
    })
}

#[async_trait]
impl BillingRepository for PostgresPersistence {
    async fn existing_billing_account_id(&self, account_id: &str) -> Result<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT billing_account_id FROM billing_accounts WHERE account_id=$1",
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?)
    }

    async fn billing_account_id(&self, account_id: &str) -> Result<String> {
        let proposed = format!("acct_{}", crate::cp::tokens::random_token_hex());
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "billing-account", account_id).await?;
        if account_status_for_update(&mut transaction, account_id)
            .await?
            .as_deref()
            != Some("active")
        {
            return Err(EnclaveError::Auth("account inactive".into()));
        }
        sqlx::query(
            "INSERT INTO billing_accounts (account_id,billing_account_id) VALUES ($1,$2) \
             ON CONFLICT (account_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(&proposed)
        .execute(&mut *transaction)
        .await?;
        let billing_id = sqlx::query_scalar::<_, String>(
            "SELECT billing_account_id FROM billing_accounts WHERE account_id=$1",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(billing_id)
    }

    async fn billing_account_id_for_deletion(&self, account_id: &str) -> Result<String> {
        let proposed = format!("acct_{}", crate::cp::tokens::random_token_hex());
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "billing-account", account_id).await?;
        match account_status_for_update(&mut transaction, account_id)
            .await?
            .as_deref()
        {
            Some("active" | "deletion_requested") => {
                sqlx::query(
                    "INSERT INTO billing_accounts (account_id,billing_account_id) VALUES ($1,$2) \
                     ON CONFLICT (account_id) DO NOTHING",
                )
                .bind(account_id)
                .bind(&proposed)
                .execute(&mut *transaction)
                .await?;
            }
            Some("deleting") => {}
            _ => return Err(EnclaveError::Auth("account inactive".into())),
        }
        let billing_id = sqlx::query_scalar::<_, String>(
            "SELECT billing_account_id FROM billing_accounts WHERE account_id=$1",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| {
            EnclaveError::Conflict("deleting account has no durable billing mapping".into())
        })?;
        transaction.commit().await?;
        Ok(billing_id)
    }

    async fn active_identities_for_billing_accounts(
        &self,
        billing_account_ids: Vec<String>,
    ) -> Result<Vec<(String, String, String)>> {
        let mut transaction = self.pool().begin().await?;
        let mut identities = Vec::with_capacity(billing_account_ids.len());
        for billing_account_id in billing_account_ids {
            let Some(row) = sqlx::query(
                "SELECT a.id,a.email FROM billing_accounts b \
                 JOIN accounts a ON a.id=b.account_id \
                 WHERE b.billing_account_id=$1 AND a.status='active'",
            )
            .bind(&billing_account_id)
            .fetch_optional(&mut *transaction)
            .await?
            else {
                continue;
            };
            identities.push((
                row.try_get("id")?,
                row.try_get("email")?,
                billing_account_id,
            ));
        }
        transaction.commit().await?;
        Ok(identities)
    }

    async fn retained_active_account_metrics(
        &self,
        period: &str,
    ) -> Result<RetainedAccountMetrics> {
        if !valid_utc_month(period) {
            return Err(EnclaveError::InvalidRequest(
                "account metrics period must be YYYY-MM".into(),
            ));
        }
        let row = sqlx::query(
            "SELECT count(*)::bigint AS retained, \
                    count(*) FILTER (WHERE to_char(created_at AT TIME ZONE 'UTC','YYYY-MM')=$1)::bigint AS new_mtd \
             FROM accounts WHERE status='active'",
        )
        .bind(period)
        .fetch_one(self.pool())
        .await?;
        Ok(RetainedAccountMetrics {
            retained_active_accounts: checked_u64(row.try_get("retained")?, "active account")?,
            new_retained_active_accounts_mtd: checked_u64(
                row.try_get("new_mtd")?,
                "new active account",
            )?,
        })
    }

    async fn active_vertex_coverage_complete(&self, period: &str) -> Result<bool> {
        if !valid_utc_month(period) {
            return Err(EnclaveError::InvalidRequest(
                "Vertex coverage period must be YYYY-MM".into(),
            ));
        }
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM accounts a LEFT JOIN vertex_coverage_anchors v \
               ON v.account_id=a.id AND v.period=$1 \
             WHERE a.status='active' AND \
               (v.account_id IS NULL OR v.pending_events<>0 OR v.lost_events<>0)",
        )
        .bind(period)
        .fetch_one(self.pool())
        .await?
            == 0)
    }

    async fn reconcile_vertex_coverage(
        &self,
        account_id: &str,
        period: &str,
        sequence: u64,
        pending_events: u64,
        lost_events: u64,
        observed_at: &str,
    ) -> Result<VertexCoverageAnchor> {
        if !valid_utc_month(period) {
            return Err(EnclaveError::InvalidRequest(
                "Vertex coverage period must be YYYY-MM".into(),
            ));
        }
        let sequence = checked_i64(sequence, "coverage sequence")?;
        let pending_events = checked_i64(pending_events, "coverage pending count")?;
        let lost_events = checked_i64(lost_events, "coverage lost count")?;
        let observed_at_ms = required_millis(observed_at, "coverage observation")?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(
            &mut transaction,
            "vertex-coverage",
            &format!("{account_id}\u{1f}{period}"),
        )
        .await?;
        if !matches!(
            account_status_for_update(&mut transaction, account_id)
                .await?
                .as_deref(),
            Some("active" | "deletion_requested" | "deleting")
        ) {
            return Err(EnclaveError::Auth("account inactive".into()));
        }
        let existing = sqlx::query(
            "SELECT sequence,pending_events,lost_events, \
                    floor(extract(epoch FROM observed_at)*1000)::bigint AS observed_at_ms \
             FROM vertex_coverage_anchors WHERE account_id=$1 AND period=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(period)
        .fetch_optional(&mut *transaction)
        .await?;
        let (chosen_sequence, chosen_pending, chosen_lost, chosen_observed) = match existing {
            None => (sequence, pending_events, lost_events, observed_at_ms),
            Some(row) => {
                let current_sequence: i64 = row.try_get("sequence")?;
                let current_pending: i64 = row.try_get("pending_events")?;
                let current_lost: i64 = row.try_get("lost_events")?;
                let current_observed: i64 = row.try_get("observed_at_ms")?;
                if sequence > current_sequence {
                    (
                        sequence,
                        pending_events,
                        current_lost.max(lost_events),
                        observed_at_ms,
                    )
                } else if sequence == current_sequence
                    && pending_events == current_pending
                    && lost_events == current_lost
                    && observed_at_ms == current_observed
                {
                    (sequence, pending_events, lost_events, observed_at_ms)
                } else {
                    let next = current_sequence
                        .checked_add(1)
                        .ok_or_else(|| EnclaveError::Config("coverage sequence overflow".into()))?;
                    let now_ms = sqlx::query_scalar::<_, i64>(
                        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    )
                    .fetch_one(&mut *transaction)
                    .await?;
                    (
                        next,
                        pending_events,
                        current_lost.max(lost_events).max(1),
                        now_ms,
                    )
                }
            }
        };
        sqlx::query(
            "INSERT INTO vertex_coverage_anchors \
                (account_id,period,sequence,pending_events,lost_events,observed_at) \
             VALUES ($1,$2,$3,$4,$5,to_timestamp($6::double precision/1000.0)) \
             ON CONFLICT (account_id,period) DO UPDATE SET \
               sequence=EXCLUDED.sequence,pending_events=EXCLUDED.pending_events, \
               lost_events=EXCLUDED.lost_events,observed_at=EXCLUDED.observed_at,updated_at=now()",
        )
        .bind(account_id)
        .bind(period)
        .bind(chosen_sequence)
        .bind(chosen_pending)
        .bind(chosen_lost)
        .bind(chosen_observed)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(VertexCoverageAnchor {
            period: period.into(),
            sequence: checked_u64(chosen_sequence, "coverage sequence")?,
            pending_events: checked_u64(chosen_pending, "coverage pending count")?,
            lost_events: checked_u64(chosen_lost, "coverage lost count")?,
            observed_at: isotime::format_epoch_millis(chosen_observed),
        })
    }

    async fn vertex_coverage_anchor(
        &self,
        account_id: &str,
        period: &str,
    ) -> Result<Option<VertexCoverageAnchor>> {
        if !valid_utc_month(period) {
            return Err(EnclaveError::InvalidRequest(
                "Vertex coverage period must be YYYY-MM".into(),
            ));
        }
        let row = sqlx::query(
            "SELECT sequence,pending_events,lost_events, \
                    floor(extract(epoch FROM observed_at)*1000)::bigint AS observed_at_ms \
             FROM vertex_coverage_anchors WHERE account_id=$1 AND period=$2",
        )
        .bind(account_id)
        .bind(period)
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            Ok(VertexCoverageAnchor {
                period: period.into(),
                sequence: checked_u64(row.try_get("sequence")?, "coverage sequence")?,
                pending_events: checked_u64(
                    row.try_get("pending_events")?,
                    "coverage pending count",
                )?,
                lost_events: checked_u64(row.try_get("lost_events")?, "coverage lost count")?,
                observed_at: isotime::format_epoch_millis(row.try_get("observed_at_ms")?),
            })
        })
        .transpose()
    }

    async fn account_driver_metrics(
        &self,
        account_id: &str,
        period: &str,
    ) -> Result<AccountDriverMetrics> {
        if !valid_utc_month(period) {
            return Err(EnclaveError::InvalidRequest(
                "account metrics period must be YYYY-MM".into(),
            ));
        }
        let row = sqlx::query(
            "WITH tenant_rows(bytes) AS ( \
               SELECT COALESCE(sum(pg_column_size(r)),0)::bigint FROM capture_events r WHERE account_id=$1 \
               UNION ALL SELECT COALESCE(sum(pg_column_size(r)),0)::bigint FROM utterances r WHERE account_id=$1 \
               UNION ALL SELECT COALESCE(sum(pg_column_size(r)),0)::bigint FROM screenshots r WHERE account_id=$1 \
               UNION ALL SELECT COALESCE(sum(pg_column_size(r)),0)::bigint FROM episodes r WHERE account_id=$1 \
               UNION ALL SELECT COALESCE(sum(pg_column_size(r)),0)::bigint FROM episode_final_briefs r WHERE account_id=$1 \
               UNION ALL SELECT COALESCE(sum(pg_column_size(r)),0)::bigint FROM people r WHERE account_id=$1 \
               UNION ALL SELECT COALESCE(sum(pg_column_size(r)),0)::bigint FROM voice_samples r WHERE account_id=$1 \
               UNION ALL SELECT COALESCE(sum(byte_length),0)::bigint FROM media_objects WHERE account_id=$1 AND deleted_at IS NULL \
             ), coverage AS ( \
               SELECT sequence,pending_events,lost_events, \
                      floor(extract(epoch FROM updated_at)*1000)::bigint AS observed_at_ms \
               FROM vertex_usage_coverage WHERE account_id=$1 AND period=$2 \
             ) \
             SELECT (SELECT COALESCE(sum(bytes),0)::bigint FROM tenant_rows) AS storage_bytes, \
                    (SELECT count(*)::bigint FROM email_deliveries WHERE account_id=$1 \
                       AND state='delivered' \
                       AND updated_at >= to_date($2,'YYYY-MM') \
                       AND updated_at < to_date($2,'YYYY-MM') + interval '1 month') AS accepted_email_count, \
                    sequence,pending_events,lost_events,observed_at_ms \
             FROM (SELECT 1) one LEFT JOIN coverage ON true",
        )
        .bind(account_id)
        .bind(period)
        .fetch_one(self.pool())
        .await?;
        let vertex_coverage = row
            .try_get::<Option<i64>, _>("sequence")?
            .map(|sequence| {
                Ok::<VertexCoverageAnchor, EnclaveError>(VertexCoverageAnchor {
                    period: period.to_string(),
                    sequence: checked_u64(sequence, "coverage sequence")?,
                    pending_events: checked_u64(
                        row.try_get("pending_events")?,
                        "coverage pending count",
                    )?,
                    lost_events: checked_u64(row.try_get("lost_events")?, "coverage lost count")?,
                    observed_at: isotime::format_epoch_millis(row.try_get("observed_at_ms")?),
                })
            })
            .transpose()?;
        Ok(AccountDriverMetrics {
            storage_bytes: checked_u64(row.try_get("storage_bytes")?, "storage byte count")?,
            accepted_email_count: checked_u64(
                row.try_get("accepted_email_count")?,
                "email delivery count",
            )?,
            vertex_coverage,
        })
    }

    async fn pending_billing_detach_ids(&self, limit: i64) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT billing_account_id FROM billing_detach_outbox ORDER BY created_at LIMIT $1",
        )
        .bind(limit.clamp(1, 100))
        .fetch_all(self.pool())
        .await?)
    }

    async fn complete_billing_detach(&self, billing_account_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM billing_detach_outbox WHERE billing_account_id=$1")
            .bind(billing_account_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    async fn record_billing_detach_failure(&self, billing_account_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE billing_detach_outbox SET attempts=attempts+1,last_attempt_at=now() \
             WHERE billing_account_id=$1",
        )
        .bind(billing_account_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn offline_recording_usage_receipt(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM offline_recording_usage_receipts \
                           WHERE account_id=$1 AND request_id=$2)",
        )
        .bind(account_id)
        .bind(request_id)
        .fetch_one(self.pool())
        .await?)
    }

    async fn complete_offline_recording_usage(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-accounting", account_id).await?;
        let inserted = sqlx::query_scalar::<_, i64>(
            "INSERT INTO offline_recording_usage_receipts (account_id,request_id) \
             VALUES ($1,$2) ON CONFLICT (account_id,request_id) DO NOTHING RETURNING 1::bigint",
        )
        .bind(account_id)
        .bind(request_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if inserted {
            grant_recording_delivery_minute(&mut transaction, account_id).await?;
        }
        transaction.commit().await?;
        Ok(inserted)
    }

    async fn reserve_recording_delivery(
        &self,
        account_id: &str,
        event_id: &str,
        media_bytes: i64,
    ) -> Result<bool> {
        let media_bytes = media_bytes.max(0);
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-accounting", account_id).await?;
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT reserved_bytes FROM recording_delivery_reservations \
             WHERE account_id=$1 AND event_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(event_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let (event_cost, byte_cost) = match existing {
            Some(reserved) => (0, media_bytes.saturating_sub(reserved)),
            None => (1, media_bytes),
        };
        let balance = sqlx::query(
            "SELECT event_credits,byte_credits FROM recording_delivery_balances \
             WHERE account_id=$1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(balance) = balance else {
            return Ok(false);
        };
        if balance.try_get::<i64, _>("event_credits")? < event_cost
            || balance.try_get::<i64, _>("byte_credits")? < byte_cost
        {
            return Ok(false);
        }
        if event_cost != 0 || byte_cost != 0 {
            sqlx::query(
                "UPDATE recording_delivery_balances SET \
                   event_credits=event_credits-$2,byte_credits=byte_credits-$3,updated_at=now() \
                 WHERE account_id=$1",
            )
            .bind(account_id)
            .bind(event_cost)
            .bind(byte_cost)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO recording_delivery_reservations \
                    (account_id,event_id,reserved_bytes) VALUES ($1,$2,$3) \
                 ON CONFLICT (account_id,event_id) DO UPDATE SET \
                    reserved_bytes=GREATEST(recording_delivery_reservations.reserved_bytes, \
                                            EXCLUDED.reserved_bytes)",
            )
            .bind(account_id)
            .bind(event_id)
            .bind(media_bytes)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(true)
    }

    async fn reserve_recording_delivery_batch(
        &self,
        account_id: &str,
        batch_id: &str,
        manifest_digest: &str,
        stream_id: &str,
        first_sequence: i64,
        last_sequence: i64,
        event_ids: &[String],
        new_event_ids: &[String],
    ) -> Result<bool> {
        let event_set = event_ids.iter().collect::<HashSet<_>>();
        let new_set = new_event_ids.iter().collect::<HashSet<_>>();
        if !valid_hex_digest(batch_id)
            || !valid_hex_digest(manifest_digest)
            || stream_id.is_empty()
            || event_ids.is_empty()
            || event_ids.len() > 64
            || event_set.len() != event_ids.len()
            || new_set.len() != new_event_ids.len()
            || new_event_ids.iter().any(|event| !event_set.contains(event))
            || first_sequence < 0
            || last_sequence < first_sequence
            || last_sequence
                .checked_sub(first_sequence)
                .and_then(|span| span.checked_add(1))
                != i64::try_from(event_ids.len()).ok()
        {
            return Err(EnclaveError::InvalidRequest(
                "reference batch reservation is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-accounting", account_id).await?;
        let existing = sqlx::query(
            "SELECT manifest_digest,stream_id,first_sequence,last_sequence,event_count,state \
               FROM capture_reference_batch_receipts WHERE account_id=$1 AND batch_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(batch_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let state = if let Some(row) = existing {
            let stored_events = sqlx::query_scalar::<_, String>(
                "SELECT event_id FROM capture_reference_batch_events \
                  WHERE account_id=$1 AND batch_id=$2 ORDER BY ordinal",
            )
            .bind(account_id)
            .bind(batch_id)
            .fetch_all(&mut *transaction)
            .await?;
            if row.try_get::<String, _>("manifest_digest")? != manifest_digest
                || row.try_get::<String, _>("stream_id")? != stream_id
                || row.try_get::<i64, _>("first_sequence")? != first_sequence
                || row.try_get::<i64, _>("last_sequence")? != last_sequence
                || row.try_get::<i64, _>("event_count")?
                    != i64::try_from(event_ids.len()).unwrap_or(i64::MAX)
                || stored_events != event_ids
            {
                return Err(EnclaveError::Conflict(
                    "idempotency conflict for reference batch".into(),
                ));
            }
            row.try_get::<String, _>("state")?
        } else {
            let pending: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM capture_reference_batch_receipts \
                  WHERE account_id=$1 AND state<>'completed'",
            )
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await?;
            if pending >= MAX_PENDING_REFERENCE_BATCHES_PER_ACCOUNT {
                return Err(EnclaveError::Conflict(
                    "too many pending reference batches".into(),
                ));
            }
            sqlx::query(
                "INSERT INTO capture_reference_batch_receipts \
                 (account_id,batch_id,manifest_digest,stream_id,first_sequence,last_sequence,event_count,state) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,'awaiting_credit')",
            )
            .bind(account_id)
            .bind(batch_id)
            .bind(manifest_digest)
            .bind(stream_id)
            .bind(first_sequence)
            .bind(last_sequence)
            .bind(i64::try_from(event_ids.len()).unwrap_or(i64::MAX))
            .execute(&mut *transaction)
            .await?;
            for (ordinal, event_id) in event_ids.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO capture_reference_batch_events(account_id,batch_id,ordinal,event_id) \
                     VALUES($1,$2,$3,$4)",
                )
                .bind(account_id)
                .bind(batch_id)
                .bind(i64::try_from(ordinal).unwrap_or(i64::MAX))
                .bind(event_id)
                .execute(&mut *transaction)
                .await?;
            }
            "awaiting_credit".into()
        };
        if state == "completed" {
            if !new_event_ids.is_empty() {
                return Err(EnclaveError::Store(
                    "completed reference batch is absent from structured capture state".into(),
                ));
            }
            transaction.commit().await?;
            return Ok(true);
        }
        let mut unreserved = Vec::new();
        for event_id in new_event_ids {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM recording_delivery_reservations \
                  WHERE account_id=$1 AND event_id=$2)",
            )
            .bind(account_id)
            .bind(event_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !exists {
                unreserved.push(event_id);
            }
        }
        if !unreserved.is_empty() {
            let available = sqlx::query_scalar::<_, i64>(
                "SELECT event_credits FROM recording_delivery_balances WHERE account_id=$1 FOR UPDATE",
            )
            .bind(account_id)
            .fetch_optional(&mut *transaction)
            .await?;
            if available
                .is_none_or(|credits| credits < i64::try_from(unreserved.len()).unwrap_or(i64::MAX))
            {
                transaction.commit().await?;
                return Ok(false);
            }
            sqlx::query(
                "UPDATE recording_delivery_balances SET event_credits=event_credits-$2,updated_at=now() \
                  WHERE account_id=$1",
            )
            .bind(account_id)
            .bind(i64::try_from(unreserved.len()).unwrap_or(i64::MAX))
            .execute(&mut *transaction)
            .await?;
            for event_id in unreserved {
                sqlx::query(
                    "INSERT INTO recording_delivery_reservations(account_id,event_id,reserved_bytes) \
                     VALUES($1,$2,0) ON CONFLICT(account_id,event_id) DO NOTHING",
                )
                .bind(account_id)
                .bind(event_id)
                .execute(&mut *transaction)
                .await?;
            }
        }
        sqlx::query(
            "UPDATE capture_reference_batch_receipts SET state='reserved',updated_at=now() \
              WHERE account_id=$1 AND batch_id=$2 AND state<>'reserved'",
        )
        .bind(account_id)
        .bind(batch_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    async fn complete_recording_delivery_batch(
        &self,
        account_id: &str,
        batch_id: &str,
        manifest_digest: &str,
        event_ids: &[String],
    ) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-accounting", account_id).await?;
        let receipt = sqlx::query(
            "SELECT manifest_digest FROM capture_reference_batch_receipts \
              WHERE account_id=$1 AND batch_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(batch_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Store("reference batch receipt is missing".into()))?;
        let stored_events = sqlx::query_scalar::<_, String>(
            "SELECT event_id FROM capture_reference_batch_events \
              WHERE account_id=$1 AND batch_id=$2 ORDER BY ordinal",
        )
        .bind(account_id)
        .bind(batch_id)
        .fetch_all(&mut *transaction)
        .await?;
        if receipt.try_get::<String, _>("manifest_digest")? != manifest_digest
            || stored_events != event_ids
        {
            return Err(EnclaveError::Conflict(
                "idempotency conflict for reference batch completion".into(),
            ));
        }
        sqlx::query(
            "DELETE FROM recording_delivery_reservations WHERE account_id=$1 AND event_id=ANY($2)",
        )
        .bind(account_id)
        .bind(event_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE capture_reference_batch_receipts SET state='completed',updated_at=now() \
              WHERE account_id=$1 AND batch_id=$2",
        )
        .bind(account_id)
        .bind(batch_id)
        .execute(&mut *transaction)
        .await?;
        settle_reference_batches(&mut transaction, account_id).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn complete_recording_delivery(&self, account_id: &str, event_id: &str) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-accounting", account_id).await?;
        sqlx::query(
            "DELETE FROM recording_delivery_reservations WHERE account_id=$1 AND event_id=$2",
        )
        .bind(account_id)
        .bind(event_id)
        .execute(&mut *transaction)
        .await?;
        settle_reference_batches(&mut transaction, account_id).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn recording_lease_receipt(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<Option<RecordingLeaseRequestRow>> {
        let request = sqlx::query(
            "SELECT requested_lease_id,issued_lease_id, \
                    floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms, \
                    state,summary_json,NULL::text AS denial_code \
             FROM recording_lease_requests WHERE account_id=$1 AND request_id=$2",
        )
        .bind(account_id)
        .bind(request_id)
        .fetch_optional(self.pool())
        .await?;
        if let Some(row) = request {
            let state = row.try_get("state")?;
            return lease_row(&row, state).map(Some);
        }
        let denial = sqlx::query(
            "SELECT requested_lease_id,issued_lease_id, \
                    floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms, \
                    summary_json,denial_code \
             FROM recording_lease_denials WHERE account_id=$1 AND request_id=$2",
        )
        .bind(account_id)
        .bind(request_id)
        .fetch_optional(self.pool())
        .await?;
        denial
            .map(|row| lease_row(&row, "denied".into()))
            .transpose()
    }

    async fn active_recording_lease(&self, account_id: &str) -> Result<Option<(String, String)>> {
        let row = sqlx::query(
            "SELECT lease_id,floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms \
             FROM recording_leases WHERE account_id=$1",
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            Ok((
                row.try_get("lease_id")?,
                isotime::format_epoch_millis(row.try_get("expires_at_ms")?),
            ))
        })
        .transpose()
    }

    async fn pending_recording_lease_request(
        &self,
        account_id: &str,
    ) -> Result<Option<(String, RecordingLeaseRequestRow)>> {
        let row = sqlx::query(
            "SELECT request_id,requested_lease_id,issued_lease_id, \
                    floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms, \
                    NULL::text AS summary_json,NULL::text AS denial_code \
             FROM recording_lease_requests WHERE account_id=$1 AND state='pending' \
             ORDER BY created_at,request_id LIMIT 1",
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let request_id = row.try_get("request_id")?;
            Ok((request_id, lease_row(&row, "pending".into())?))
        })
        .transpose()
    }

    async fn begin_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
        requested_lease_id: Option<&str>,
        issued_lease_id: &str,
        expires_at: &str,
    ) -> Result<()> {
        let expires_at_ms = required_millis(expires_at, "recording lease expiry")?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-lease", account_id).await?;
        let pending = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM recording_lease_requests \
             WHERE account_id=$1 AND state='pending'",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        if pending >= 1 {
            return Err(EnclaveError::Conflict(
                "too many pending recording lease requests".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO recording_lease_requests \
                (account_id,request_id,requested_lease_id,issued_lease_id,expires_at,state) \
             VALUES ($1,$2,$3,$4,to_timestamp($5::double precision/1000.0),'pending')",
        )
        .bind(account_id)
        .bind(request_id)
        .bind(requested_lease_id)
        .bind(issued_lease_id)
        .bind(expires_at_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn deny_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
        denial_code: &str,
        summary: &serde_json::Value,
    ) -> Result<()> {
        let summary = serde_json::to_string(summary)?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-lease", account_id).await?;
        let pending = sqlx::query(
            "DELETE FROM recording_lease_requests \
             WHERE account_id=$1 AND request_id=$2 AND state='pending' \
             RETURNING requested_lease_id,issued_lease_id, \
                       floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms",
        )
        .bind(account_id)
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO recording_lease_denials \
                (account_id,request_id,requested_lease_id,issued_lease_id,expires_at, \
                 denial_code,summary_json) \
             VALUES ($1,$2,$3,$4,to_timestamp($5::double precision/1000.0),$6,$7)",
        )
        .bind(account_id)
        .bind(request_id)
        .bind(pending.try_get::<Option<String>, _>("requested_lease_id")?)
        .bind(pending.try_get::<String, _>("issued_lease_id")?)
        .bind(pending.try_get::<i64, _>("expires_at_ms")?)
        .bind(denial_code)
        .bind(summary)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM recording_lease_denials WHERE created_at < now()-interval '7 days'",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM recording_lease_denials WHERE (account_id,request_id) IN ( \
               SELECT account_id,request_id FROM recording_lease_denials WHERE account_id=$1 \
               ORDER BY created_at DESC,request_id DESC OFFSET $2)",
        )
        .bind(account_id)
        .bind(MAX_RECORDING_LEASE_DENIALS_PER_ACCOUNT)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn complete_recording_lease(
        &self,
        account_id: &str,
        request_id: &str,
        retry_now_ms: Option<i64>,
        summary: &serde_json::Value,
    ) -> Result<(String, String)> {
        let summary = serde_json::to_string(summary)?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-lease", account_id).await?;
        let pending = sqlx::query(
            "SELECT issued_lease_id, \
                    floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms \
             FROM recording_lease_requests \
             WHERE account_id=$1 AND request_id=$2 AND state='pending' FOR UPDATE",
        )
        .bind(account_id)
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await?;
        let lease_id: String = pending.try_get("issued_lease_id")?;
        let pending_expires_ms: i64 = pending.try_get("expires_at_ms")?;
        let active = sqlx::query(
            "SELECT lease_id,floor(extract(epoch FROM expires_at)*1000)::bigint AS expires_at_ms \
             FROM recording_leases WHERE account_id=$1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let active_expires_ms = match active {
            Some(row) => {
                let active_id: String = row.try_get("lease_id")?;
                let active_expires: i64 = row.try_get("expires_at_ms")?;
                if active_id != lease_id
                    && retry_now_ms.is_none_or(|now_ms| active_expires > now_ms)
                {
                    return Err(EnclaveError::Conflict(
                        "a different recording lease became active".into(),
                    ));
                }
                Some(active_expires)
            }
            None => None,
        };
        let expires_ms = match retry_now_ms {
            Some(now_ms) => now_ms
                .max(active_expires_ms.unwrap_or(i64::MIN))
                .saturating_add(RECORDING_LEASE_DURATION_MS)
                .max(pending_expires_ms),
            None => pending_expires_ms.max(active_expires_ms.unwrap_or(i64::MIN)),
        };
        sqlx::query(
            "UPDATE recording_lease_requests SET \
                expires_at=to_timestamp($3::double precision/1000.0),state='granted',summary_json=$4 \
             WHERE account_id=$1 AND request_id=$2 AND state='pending'",
        )
        .bind(account_id)
        .bind(request_id)
        .bind(expires_ms)
        .bind(summary)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO recording_leases (account_id,lease_id,expires_at) \
             VALUES ($1,$2,to_timestamp($3::double precision/1000.0)) \
             ON CONFLICT (account_id) DO UPDATE SET \
               lease_id=EXCLUDED.lease_id,expires_at=EXCLUDED.expires_at,updated_at=now()",
        )
        .bind(account_id)
        .bind(&lease_id)
        .bind(expires_ms)
        .execute(&mut *transaction)
        .await?;
        grant_recording_delivery_minute(&mut transaction, account_id).await?;
        sqlx::query(
            "DELETE FROM recording_lease_requests \
             WHERE state<>'pending' AND created_at < now()-interval '7 days'",
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok((lease_id, isotime::format_epoch_millis(expires_ms)))
    }

    async fn conflict_recording_lease_request(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE recording_lease_requests SET state='conflict' \
             WHERE account_id=$1 AND request_id=$2 AND state='pending'",
        )
        .bind(account_id)
        .bind(request_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}
