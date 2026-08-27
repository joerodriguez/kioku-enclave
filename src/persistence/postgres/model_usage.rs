use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    cp::{
        billing::{VertexCoverageSnapshot, VertexUsageEvent},
        isotime,
        model_usage::{normalized_billable_response, normalized_traffic_type, to_i64},
        vertex::{VertexMetadata, VertexOperation},
    },
    error::{EnclaveError, Result},
    persistence::{ClaimedVertexCoverage, ClaimedVertexUsageBatch, ModelUsageRepository},
};

use super::{advisory_transaction_lock, PostgresPersistence};

const OUTBOX_BATCH: i64 = 100;
const CLAIM_SECONDS: f64 = 120.0;

fn invocation_fingerprint(
    account_id: &str,
    operation: VertexOperation,
    requested_model: &str,
    location: &str,
    caller_anchor: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"kioku.vertex-invocation.v1\0");
    digest.update(account_id.as_bytes());
    digest.update([0]);
    digest.update(format!("{operation:?}").as_bytes());
    digest.update([0]);
    digest.update(requested_model.as_bytes());
    digest.update([0]);
    digest.update(location.as_bytes());
    digest.update([0]);
    digest.update(caller_anchor);
    digest.finalize().into()
}

fn event_id(fingerprint: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(68);
    value.push_str("vtx_");
    for byte in fingerprint {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

async fn refresh_coverage(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO vertex_usage_coverage
             (account_id,period,sequence,pending_events,lost_events,delivery_state)
         VALUES (
             $1,
             to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC','YYYY-MM'),
             1,
             (SELECT count(*) FROM vertex_usage_events
               WHERE account_id=$1 AND delivery_state='pending'
                 AND observed_at >= date_trunc('month',CURRENT_TIMESTAMP)),
             0,
             'pending'
         )
         ON CONFLICT(account_id,period) DO UPDATE SET
             sequence=vertex_usage_coverage.sequence+1,
             pending_events=excluded.pending_events,
             delivery_state='pending',
             delivery_claim_id=NULL,
             delivery_claim_expires_at=NULL,
             updated_at=CURRENT_TIMESTAMP",
    )
    .bind(account_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn event_from_row(
    row: &sqlx::postgres::PgRow,
    billing_account_id: &str,
) -> Result<VertexUsageEvent> {
    let status = row
        .try_get::<Option<i32>, _>("http_status")?
        .map(u16::try_from)
        .transpose()
        .map_err(|_| EnclaveError::Store("invalid Vertex HTTP status".into()))?;
    let token = |name: &str| -> Result<Option<u64>> {
        row.try_get::<Option<i64>, _>(name)?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| EnclaveError::Store(format!("invalid Vertex token count in {name}")))
    };
    let observed_at_ms: i64 = row.try_get("observed_at_ms")?;
    Ok(VertexUsageEvent {
        account_id: billing_account_id.to_owned(),
        event_id: row.try_get("event_id")?,
        operation: row.try_get("operation")?,
        requested_model: row.try_get("requested_model")?,
        returned_model: row.try_get("returned_model")?,
        location: row.try_get("location")?,
        traffic_type: row.try_get("traffic_type")?,
        outcome: row.try_get("outcome")?,
        http_status: status,
        prompt_tokens: token("prompt_tokens")?,
        input_text_tokens: token("input_text_tokens")?,
        input_audio_tokens: token("input_audio_tokens")?,
        input_image_tokens: token("input_image_tokens")?,
        cached_input_tokens: token("cached_input_tokens")?,
        cached_input_text_tokens: token("cached_input_text_tokens")?,
        cached_input_audio_tokens: token("cached_input_audio_tokens")?,
        cached_input_image_tokens: token("cached_input_image_tokens")?,
        output_text_tokens: token("output_text_tokens")?,
        thought_tokens: token("thought_tokens")?,
        total_tokens: token("total_tokens")?,
        observed_at: isotime::format_epoch_millis(observed_at_ms),
    })
}

fn event_models_are_safe(event: &VertexUsageEvent) -> bool {
    crate::cp::vertex_model_name_is_billing_safe(&event.requested_model)
        && event
            .returned_model
            .as_deref()
            .is_none_or(crate::cp::vertex_model_name_is_billing_safe)
        && (event.outcome != "metered" || event.returned_model.is_some())
}

async fn settle_simple_outcome(
    persistence: &PostgresPersistence,
    account_id: &str,
    event_id: &str,
    outcome: &str,
    delivery_state: &str,
    http_status: Option<u16>,
) -> Result<()> {
    let mut transaction = persistence.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE vertex_usage_events
            SET outcome=$3,delivery_state=$4,http_status=$5,updated_at=CURRENT_TIMESTAMP
          WHERE account_id=$1 AND event_id=$2 AND outcome='started'",
    )
    .bind(account_id)
    .bind(event_id)
    .bind(outcome)
    .bind(delivery_state)
    .bind(http_status.map(i32::from))
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed == 0 {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM vertex_usage_events WHERE account_id=$1 AND event_id=$2)",
        )
        .bind(account_id)
        .bind(event_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !exists {
            return Err(EnclaveError::Store(
                "Vertex invocation intent does not exist".into(),
            ));
        }
    }
    refresh_coverage(&mut transaction, account_id).await?;
    transaction.commit().await?;
    Ok(())
}

#[async_trait]
impl ModelUsageRepository for PostgresPersistence {
    async fn begin_invocation(
        &self,
        account_id: &str,
        operation: VertexOperation,
        requested_model: &str,
        location: &str,
        caller_anchor: &[u8; 32],
    ) -> Result<String> {
        let requested_model = requested_model.chars().take(256).collect::<String>();
        let location = location.chars().take(128).collect::<String>();
        let fingerprint = invocation_fingerprint(
            account_id,
            operation,
            &requested_model,
            &location,
            caller_anchor,
        );
        let event_id = event_id(&fingerprint);
        let mut transaction = self.pool.begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND status='active')",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !active {
            return Err(EnclaveError::Auth("account inactive".into()));
        }
        let inserted = sqlx::query(
            "INSERT INTO vertex_usage_events
                 (account_id,event_id,request_fingerprint,operation,requested_model,location,outcome)
             VALUES($1,$2,$3,$4,$5,$6,'started')
             ON CONFLICT(account_id,event_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(&event_id)
        .bind(fingerprint.as_slice())
        .bind(operation.as_str())
        .bind(&requested_model)
        .bind(&location)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted == 0 {
            let stored: Vec<u8> = sqlx::query_scalar(
                "SELECT request_fingerprint FROM vertex_usage_events
                  WHERE account_id=$1 AND event_id=$2 FOR UPDATE",
            )
            .bind(account_id)
            .bind(&event_id)
            .fetch_one(&mut *transaction)
            .await?;
            if stored.as_slice() != fingerprint {
                return Err(EnclaveError::Conflict(
                    "Vertex invocation id was reused with different input".into(),
                ));
            }
        } else {
            refresh_coverage(&mut transaction, account_id).await?;
        }
        transaction.commit().await?;
        Ok(event_id)
    }

    async fn settle_response(
        &self,
        account_id: &str,
        event_id: &str,
        metadata: &VertexMetadata,
    ) -> Result<()> {
        let (model, normalized) = normalized_billable_response(metadata);
        let outcome = if normalized.is_some() {
            "metered"
        } else {
            "usage_missing"
        };
        let usage = normalized.unwrap_or_default();
        let mut transaction = self.pool.begin().await?;
        let changed = sqlx::query(
            "UPDATE vertex_usage_events SET
                 returned_model=$3,traffic_type=$4,http_status=200,
                 prompt_tokens=$5,input_text_tokens=$6,input_audio_tokens=$7,input_image_tokens=$8,
                 cached_input_tokens=$9,cached_input_text_tokens=$10,cached_input_audio_tokens=$11,
                 cached_input_image_tokens=$12,output_text_tokens=$13,thought_tokens=$14,total_tokens=$15,
                 outcome=$16,updated_at=CURRENT_TIMESTAMP
              WHERE account_id=$1 AND event_id=$2 AND outcome='started'",
        )
        .bind(account_id)
        .bind(event_id)
        .bind(model)
        .bind(normalized_traffic_type(metadata.traffic_type.as_deref()))
        .bind(to_i64(usage.prompt_tokens))
        .bind(to_i64(usage.input_text_tokens))
        .bind(to_i64(usage.input_audio_tokens))
        .bind(to_i64(usage.input_image_tokens))
        .bind(to_i64(usage.cached_input_tokens))
        .bind(to_i64(usage.cached_input_text_tokens))
        .bind(to_i64(usage.cached_input_audio_tokens))
        .bind(to_i64(usage.cached_input_image_tokens))
        .bind(to_i64(usage.output_tokens))
        .bind(to_i64(usage.thought_tokens))
        .bind(to_i64(usage.total_tokens))
        .bind(outcome)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            let exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM vertex_usage_events WHERE account_id=$1 AND event_id=$2)",
            )
            .bind(account_id)
            .bind(event_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !exists {
                return Err(EnclaveError::Store(
                    "Vertex invocation intent does not exist".into(),
                ));
            }
        }
        refresh_coverage(&mut transaction, account_id).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_ambiguous(
        &self,
        account_id: &str,
        event_id: &str,
        http_status: Option<u16>,
    ) -> Result<()> {
        settle_simple_outcome(
            self,
            account_id,
            event_id,
            "ambiguous",
            "pending",
            http_status,
        )
        .await
    }

    async fn settle_not_billed(
        &self,
        account_id: &str,
        event_id: &str,
        http_status: u16,
    ) -> Result<()> {
        settle_simple_outcome(
            self,
            account_id,
            event_id,
            "not_billed",
            "delivered",
            Some(http_status),
        )
        .await
    }

    async fn pending_events(
        &self,
        account_id: &str,
        billing_account_id: &str,
        force_started_ambiguous: bool,
    ) -> Result<Option<ClaimedVertexUsageBatch>> {
        let mut transaction = self.pool.begin().await?;
        let mut coverage_dirty = if force_started_ambiguous {
            sqlx::query(
                "UPDATE vertex_usage_events SET outcome='ambiguous',updated_at=CURRENT_TIMESTAMP
                  WHERE account_id=$1 AND outcome='started'",
            )
            .bind(account_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
                != 0
        } else {
            sqlx::query(
                "UPDATE vertex_usage_events SET outcome='ambiguous',updated_at=CURRENT_TIMESTAMP
                  WHERE account_id=$1 AND outcome='started'
                    AND observed_at <= CURRENT_TIMESTAMP - interval '3 minutes'",
            )
            .bind(account_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
                != 0
        };

        loop {
            let rows = sqlx::query(
                "SELECT event_id,operation,requested_model,returned_model,location,traffic_type,
                        outcome,http_status,prompt_tokens,input_text_tokens,input_audio_tokens,input_image_tokens,
                        cached_input_tokens,cached_input_text_tokens,cached_input_audio_tokens,
                        cached_input_image_tokens,output_text_tokens,thought_tokens,total_tokens,
                        floor(extract(epoch FROM observed_at) * 1000)::bigint AS observed_at_ms
                   FROM vertex_usage_events
                  WHERE account_id=$1 AND delivery_state='pending' AND outcome!='started'
                    AND (delivery_claim_expires_at IS NULL OR delivery_claim_expires_at <= CURRENT_TIMESTAMP)
                  ORDER BY observed_at,event_id
                  LIMIT $2 FOR UPDATE SKIP LOCKED",
            )
            .bind(account_id)
            .bind(OUTBOX_BATCH)
            .fetch_all(&mut *transaction)
            .await?;
            if rows.is_empty() {
                if coverage_dirty {
                    refresh_coverage(&mut transaction, account_id).await?;
                }
                transaction.commit().await?;
                return Ok(None);
            }
            let events = rows
                .iter()
                .map(|row| event_from_row(row, billing_account_id))
                .collect::<Result<Vec<_>>>()?;
            let (deliverable, poison): (Vec<_>, Vec<_>) =
                events.into_iter().partition(event_models_are_safe);
            for event in poison {
                coverage_dirty = true;
                sqlx::query(
                    "UPDATE vertex_usage_events SET
                         returned_model=NULL,prompt_tokens=NULL,input_text_tokens=NULL,
                         input_audio_tokens=NULL,input_image_tokens=NULL,cached_input_tokens=NULL,
                         cached_input_text_tokens=NULL,cached_input_audio_tokens=NULL,
                         cached_input_image_tokens=NULL,output_text_tokens=NULL,thought_tokens=NULL,
                         total_tokens=NULL,outcome='usage_missing',delivery_state='delivered',
                         delivery_claim_id=NULL,delivery_claim_expires_at=NULL,updated_at=CURRENT_TIMESTAMP
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(account_id)
                .bind(event.event_id)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "UPDATE vertex_usage_coverage SET lost_events=lost_events+1,delivery_state='pending'
                      WHERE account_id=$1 AND period=to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC','YYYY-MM')",
                )
                .bind(account_id)
                .execute(&mut *transaction)
                .await?;
            }
            if deliverable.is_empty() {
                continue;
            }
            let claim_id = crate::cp::tokens::random_token_hex();
            for event in &deliverable {
                sqlx::query(
                    "UPDATE vertex_usage_events SET delivery_claim_id=$3,
                         delivery_claim_expires_at=CURRENT_TIMESTAMP + make_interval(secs => $4),
                         updated_at=CURRENT_TIMESTAMP
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(account_id)
                .bind(&event.event_id)
                .bind(&claim_id)
                .bind(CLAIM_SECONDS)
                .execute(&mut *transaction)
                .await?;
            }
            if coverage_dirty {
                refresh_coverage(&mut transaction, account_id).await?;
            }
            transaction.commit().await?;
            return Ok(Some(ClaimedVertexUsageBatch {
                claim_id,
                events: deliverable,
            }));
        }
    }

    async fn complete_delivery(
        &self,
        account_id: &str,
        claim_id: &str,
        event_ids: &[String],
    ) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        for event_id in event_ids {
            let changed = sqlx::query(
                "UPDATE vertex_usage_events SET delivery_state='delivered',delivery_claim_id=NULL,
                     delivery_claim_expires_at=NULL,updated_at=CURRENT_TIMESTAMP
                  WHERE account_id=$1 AND event_id=$2 AND delivery_claim_id=$3
                    AND delivery_state='pending'",
            )
            .bind(account_id)
            .bind(event_id)
            .bind(claim_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed == 0 {
                let delivered = sqlx::query_scalar::<_, bool>(
                    "SELECT delivery_state='delivered' FROM vertex_usage_events
                      WHERE account_id=$1 AND event_id=$2",
                )
                .bind(account_id)
                .bind(event_id)
                .fetch_optional(&mut *transaction)
                .await?
                .unwrap_or(false);
                if !delivered {
                    return Err(EnclaveError::Conflict(
                        "Vertex delivery claim is no longer authoritative".into(),
                    ));
                }
            }
        }
        refresh_coverage(&mut transaction, account_id).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn note_delivery_failure(
        &self,
        account_id: &str,
        claim_id: &str,
        event_ids: &[String],
    ) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        for event_id in event_ids {
            sqlx::query(
                "UPDATE vertex_usage_events SET delivery_attempt_count=delivery_attempt_count+1,
                     delivery_claim_id=NULL,delivery_claim_expires_at=NULL,updated_at=CURRENT_TIMESTAMP
                  WHERE account_id=$1 AND event_id=$2 AND delivery_claim_id=$3
                    AND delivery_state='pending'",
            )
            .bind(account_id)
            .bind(event_id)
            .bind(claim_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn pending_coverage(
        &self,
        account_id: &str,
        billing_account_id: &str,
    ) -> Result<Vec<ClaimedVertexCoverage>> {
        let mut transaction = self.pool.begin().await?;
        let period: String =
            sqlx::query_scalar("SELECT to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC','YYYY-MM')")
                .fetch_one(&mut *transaction)
                .await?;
        sqlx::query(
            "UPDATE vertex_usage_coverage SET pending_events=0,
                 lost_events=GREATEST(lost_events+pending_events,1),delivery_state='delivered',
                 delivery_claim_id=NULL,delivery_claim_expires_at=NULL,updated_at=CURRENT_TIMESTAMP
              WHERE account_id=$1 AND period < $2 AND delivery_state='pending'",
        )
        .bind(account_id)
        .bind(&period)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO vertex_usage_coverage
                 (account_id,period,sequence,pending_events,lost_events,delivery_state)
             VALUES($1,$2,1,
                 (SELECT count(*) FROM vertex_usage_events
                   WHERE account_id=$1 AND delivery_state='pending'
                     AND observed_at >= date_trunc('month',CURRENT_TIMESTAMP)),0,'pending')
             ON CONFLICT(account_id,period) DO NOTHING",
        )
        .bind(account_id)
        .bind(&period)
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query(
            "SELECT period,sequence,pending_events,lost_events,
                    floor(extract(epoch FROM updated_at) * 1000)::bigint AS updated_at_ms
               FROM vertex_usage_coverage
              WHERE account_id=$1 AND period=$2 AND delivery_state='pending'
                AND (delivery_claim_expires_at IS NULL OR delivery_claim_expires_at <= CURRENT_TIMESTAMP)
              FOR UPDATE SKIP LOCKED",
        )
        .bind(account_id)
        .bind(&period)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(Vec::new());
        };
        let claim_id = crate::cp::tokens::random_token_hex();
        sqlx::query(
            "UPDATE vertex_usage_coverage SET delivery_claim_id=$3,
                 delivery_claim_expires_at=CURRENT_TIMESTAMP + make_interval(secs => $4)
              WHERE account_id=$1 AND period=$2",
        )
        .bind(account_id)
        .bind(&period)
        .bind(&claim_id)
        .bind(CLAIM_SECONDS)
        .execute(&mut *transaction)
        .await?;
        let sequence = u64::try_from(row.try_get::<i64, _>("sequence")?)
            .map_err(|_| EnclaveError::Store("invalid Vertex coverage sequence".into()))?;
        let pending_events = u64::try_from(row.try_get::<i64, _>("pending_events")?)
            .map_err(|_| EnclaveError::Store("invalid Vertex pending count".into()))?;
        let lost_events = u64::try_from(row.try_get::<i64, _>("lost_events")?)
            .map_err(|_| EnclaveError::Store("invalid Vertex lost count".into()))?;
        let updated_at_ms: i64 = row.try_get("updated_at_ms")?;
        transaction.commit().await?;
        Ok(vec![ClaimedVertexCoverage {
            claim_id,
            snapshot: VertexCoverageSnapshot {
                account_id: billing_account_id.to_owned(),
                period,
                sequence,
                pending_events,
                lost_events,
                observed_at: isotime::format_epoch_millis(updated_at_ms),
            },
        }])
    }

    async fn persist_coverage_snapshot(
        &self,
        account_id: &str,
        claim_id: &str,
        predecessor: &VertexCoverageSnapshot,
        replacement: &VertexCoverageSnapshot,
    ) -> Result<()> {
        if predecessor.period != replacement.period {
            return Err(EnclaveError::Conflict(
                "coverage period changed during reconciliation".into(),
            ));
        }
        let observed_at = isotime::parse_epoch_millis(&replacement.observed_at)
            .ok_or_else(|| EnclaveError::Store("invalid coverage timestamp".into()))?;
        let changed =
            sqlx::query(
                "UPDATE vertex_usage_coverage SET sequence=$5,pending_events=$6,lost_events=$7,
                 delivery_state='pending',updated_at=to_timestamp($8::double precision/1000.0)
              WHERE account_id=$1 AND period=$2 AND delivery_claim_id=$3 AND sequence=$4",
            )
            .bind(account_id)
            .bind(&predecessor.period)
            .bind(claim_id)
            .bind(i64::try_from(predecessor.sequence).map_err(|_| {
                EnclaveError::Store("coverage predecessor sequence overflow".into())
            })?)
            .bind(
                i64::try_from(replacement.sequence)
                    .map_err(|_| EnclaveError::Store("coverage sequence overflow".into()))?,
            )
            .bind(
                i64::try_from(replacement.pending_events)
                    .map_err(|_| EnclaveError::Store("coverage pending overflow".into()))?,
            )
            .bind(
                i64::try_from(replacement.lost_events)
                    .map_err(|_| EnclaveError::Store("coverage lost overflow".into()))?,
            )
            .bind(observed_at)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "coverage predecessor changed during reconciliation".into(),
            ));
        }
        Ok(())
    }

    async fn complete_coverage(
        &self,
        account_id: &str,
        claim_id: &str,
        period: &str,
        sequence: u64,
    ) -> Result<()> {
        let sequence = i64::try_from(sequence)
            .map_err(|_| EnclaveError::Store("coverage sequence overflow".into()))?;
        let changed = sqlx::query(
            "UPDATE vertex_usage_coverage SET delivery_state='delivered',delivery_claim_id=NULL,
                 delivery_claim_expires_at=NULL,updated_at=CURRENT_TIMESTAMP
              WHERE account_id=$1 AND period=$2 AND sequence=$3 AND delivery_claim_id=$4
                AND delivery_state='pending'",
        )
        .bind(account_id)
        .bind(period)
        .bind(sequence)
        .bind(claim_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed == 0 {
            let delivered = sqlx::query_scalar::<_, bool>(
                "SELECT delivery_state='delivered' FROM vertex_usage_coverage
                  WHERE account_id=$1 AND period=$2 AND sequence=$3",
            )
            .bind(account_id)
            .bind(period)
            .bind(sequence)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(false);
            if !delivered {
                return Err(EnclaveError::Conflict(
                    "Vertex coverage claim is no longer authoritative".into(),
                ));
            }
        }
        Ok(())
    }

    async fn invalidate_stale_coverage(
        &self,
        account_id: &str,
        claim_id: &str,
        period: &str,
        sequence: u64,
    ) -> Result<()> {
        let sequence = i64::try_from(sequence)
            .map_err(|_| EnclaveError::Store("coverage sequence overflow".into()))?;
        sqlx::query(
            "UPDATE vertex_usage_coverage SET sequence=sequence+1,lost_events=GREATEST(lost_events,1),
                 delivery_state='pending',delivery_claim_id=NULL,delivery_claim_expires_at=NULL,
                 updated_at=CURRENT_TIMESTAMP
              WHERE account_id=$1 AND period=$2 AND sequence=$3 AND delivery_claim_id=$4",
        )
        .bind(account_id)
        .bind(period)
        .bind(sequence)
        .bind(claim_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
