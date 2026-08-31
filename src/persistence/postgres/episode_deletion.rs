use std::collections::BTreeSet;

use async_trait::async_trait;
use sqlx::Row;

use crate::{
    error::{EnclaveError, Result},
    persistence::{
        EpisodeDeletionPlan, EpisodeDeletionRepository, EpisodeDeletionStart, EpisodePurge,
    },
};

use super::{advisory_transaction_lock, PostgresPersistence};

fn event_id(source_key: &str) -> Option<&str> {
    let value = source_key.strip_prefix("cloud-v2:")?;
    value.split(':').next().filter(|value| !value.is_empty())
}

fn decode_plan(episode_id: i64, purge: String, media: String) -> Result<EpisodeDeletionPlan> {
    Ok(EpisodeDeletionPlan {
        episode_id,
        purge: serde_json::from_str(&purge)?,
        media_object_keys: serde_json::from_str(&media)?,
    })
}

#[async_trait]
impl EpisodeDeletionRepository for PostgresPersistence {
    async fn begin_episode_deletion(
        &self,
        account_id: &str,
        episode_id: i64,
    ) -> Result<EpisodeDeletionStart> {
        if episode_id <= 0 {
            return Err(EnclaveError::InvalidRequest(
                "episode id must be positive".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        // Serialize deletion with reconciliation claim admission. A live
        // processing lease is the durable fence proving that provider egress
        // may be in flight; deletion waits for the account lock, then refuses
        // until that bounded lease is released or expires. Conversely, once
        // deletion marks the episode, the claim-side snapshot revalidation
        // fails before any provider request can begin.
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        let reconciliation_in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memory_reconciliation_jobs \
              WHERE account_id=$1 AND state='processing' \
                AND claim_until>CURRENT_TIMESTAMP \
                AND predecessor_episode_ids @> ARRAY[$2]::bigint[])",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_one(&mut *transaction)
        .await?;
        if reconciliation_in_flight {
            return Err(EnclaveError::Conflict(
                "episode reconciliation is in flight".into(),
            ));
        }
        if let Some(row) = sqlx::query(
            "SELECT state,purge::text AS purge,media_object_keys::text AS media \
               FROM episode_deletions WHERE account_id=$1 AND episode_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let plan = decode_plan(episode_id, row.try_get("purge")?, row.try_get("media")?)?;
            let state: String = row.try_get("state")?;
            transaction.rollback().await?;
            return match state.as_str() {
                "pending" => Ok(EpisodeDeletionStart::Pending(plan)),
                "complete" => Ok(EpisodeDeletionStart::Complete(plan.purge)),
                _ => Err(EnclaveError::Store(
                    "episode deletion has an invalid state".into(),
                )),
            };
        }

        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM episodes WHERE account_id=$1 AND id=$2 FOR UPDATE)",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !exists {
            transaction.rollback().await?;
            return Ok(EpisodeDeletionStart::NotFound);
        }

        let utterances = sqlx::query(
            "SELECT u.id,u.source_key,u.audio_segment_id \
               FROM episode_members m JOIN utterances u \
                 ON u.account_id=m.account_id AND u.id=m.record_id \
              WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='utterance' \
              ORDER BY u.id",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(&mut *transaction)
        .await?;
        let screenshots = sqlx::query(
            "SELECT s.id,s.source_key FROM episode_members m JOIN screenshots s \
                 ON s.account_id=m.account_id AND s.id=m.record_id \
              WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='screenshot' \
              ORDER BY s.id",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(&mut *transaction)
        .await?;
        let utterance_ids = utterances
            .iter()
            .map(|row| row.try_get("id"))
            .collect::<std::result::Result<Vec<i64>, _>>()?;
        let screenshot_ids = screenshots
            .iter()
            .map(|row| row.try_get("id"))
            .collect::<std::result::Result<Vec<i64>, _>>()?;
        let utterance_source_keys = utterances
            .iter()
            .filter_map(|row| {
                row.try_get::<Option<String>, _>("source_key")
                    .ok()
                    .flatten()
            })
            .collect::<Vec<_>>();
        let screenshot_source_keys = screenshots
            .iter()
            .filter_map(|row| {
                row.try_get::<Option<String>, _>("source_key")
                    .ok()
                    .flatten()
            })
            .collect::<Vec<_>>();
        let segment_ids = utterances
            .iter()
            .map(|row| row.try_get("audio_segment_id"))
            .collect::<std::result::Result<Vec<i64>, _>>()?;

        let mut candidate_events = BTreeSet::new();
        for source in utterance_source_keys
            .iter()
            .chain(screenshot_source_keys.iter())
        {
            if let Some(event) = event_id(source) {
                candidate_events.insert(event.to_owned());
            }
        }
        let mut orphan_events = Vec::new();
        for event in candidate_events {
            let utterance_prefix = format!("cloud-v2:{event}:%");
            let screen_source = format!("cloud-v2:{event}");
            let survivors = sqlx::query_scalar::<_, i64>(
                "SELECT (SELECT count(*) FROM utterances WHERE account_id=$1 \
                            AND source_key LIKE $2 AND NOT (id=ANY($4))) + \
                        (SELECT count(*) FROM screenshots WHERE account_id=$1 \
                            AND source_key=$3 AND NOT (id=ANY($5)))",
            )
            .bind(account_id)
            .bind(&utterance_prefix)
            .bind(&screen_source)
            .bind(&utterance_ids)
            .bind(&screenshot_ids)
            .fetch_one(&mut *transaction)
            .await?;
            if survivors == 0 {
                orphan_events.push(event);
            }
        }

        let mut media_object_keys = sqlx::query_scalar::<_, String>(
            "SELECT object_key FROM screenshot_images WHERE account_id=$1 AND episode_id=$2 \
              ORDER BY object_key",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(&mut *transaction)
        .await?;
        if !orphan_events.is_empty() {
            media_object_keys.extend(
                sqlx::query_scalar::<_, String>(
                    "SELECT object_key FROM media_objects WHERE account_id=$1 \
                       AND event_id=ANY($2) AND deleted_at IS NULL ORDER BY object_key",
                )
                .bind(account_id)
                .bind(&orphan_events)
                .fetch_all(&mut *transaction)
                .await?,
            );
        }
        media_object_keys.sort();
        media_object_keys.dedup();

        let remaining_segments = if segment_ids.is_empty() {
            0
        } else {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM audio_segments s WHERE s.account_id=$1 AND s.id=ANY($2) \
                  AND NOT EXISTS (SELECT 1 FROM utterances u WHERE u.account_id=s.account_id \
                    AND u.audio_segment_id=s.id AND NOT (u.id=ANY($3)))",
            )
            .bind(account_id)
            .bind(&segment_ids)
            .bind(&utterance_ids)
            .fetch_one(&mut *transaction)
            .await?
        };
        let purge = EpisodePurge {
            deleted_utterances: utterance_ids.len(),
            deleted_screenshots: screenshot_ids.len(),
            deleted_segments: usize::try_from(remaining_segments)
                .map_err(|_| EnclaveError::Store("episode segment count overflow".into()))?,
            utterance_source_keys,
            screenshot_source_keys,
        };
        let purge_json = serde_json::to_string(&purge)?;
        let media_json = serde_json::to_string(&media_object_keys)?;
        let utterance_json = serde_json::to_string(&utterance_ids)?;
        let screenshot_json = serde_json::to_string(&screenshot_ids)?;
        let segment_json = serde_json::to_string(&segment_ids)?;
        let orphan_json = serde_json::to_string(&orphan_events)?;
        sqlx::query(
            "UPDATE episodes SET finalization_status='deleting',finalization_claim_token=NULL,\
                    finalization_claim_until=NULL,updated_at=now() WHERE account_id=$1 AND id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,\
                    utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) \
             VALUES($1,$2,'pending',$3::jsonb,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb)",
        )
        .bind(account_id)
        .bind(episode_id)
        .bind(&purge_json)
        .bind(&media_json)
        .bind(utterance_json)
        .bind(screenshot_json)
        .bind(segment_json)
        .bind(orphan_json)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(EpisodeDeletionStart::Pending(EpisodeDeletionPlan {
            episode_id,
            purge,
            media_object_keys,
        }))
    }

    async fn complete_episode_deletion(
        &self,
        account_id: &str,
        plan: &EpisodeDeletionPlan,
    ) -> Result<EpisodePurge> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT state,purge::text AS purge,media_object_keys::text AS media,\
                    utterance_ids::text AS utterances,screenshot_ids::text AS screenshots,\
                    segment_ids::text AS segments,orphan_event_ids::text AS events \
               FROM episode_deletions WHERE account_id=$1 AND episode_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(plan.episode_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("episode deletion was not prepared".into()))?;
        let persisted = decode_plan(
            plan.episode_id,
            row.try_get("purge")?,
            row.try_get("media")?,
        )?;
        if &persisted != plan {
            return Err(EnclaveError::Conflict(
                "episode deletion plan does not match durable authority".into(),
            ));
        }
        if row.try_get::<String, _>("state")? == "complete" {
            transaction.rollback().await?;
            return Ok(persisted.purge);
        }
        let utterance_ids: Vec<i64> =
            serde_json::from_str(&row.try_get::<String, _>("utterances")?)?;
        let screenshot_ids: Vec<i64> =
            serde_json::from_str(&row.try_get::<String, _>("screenshots")?)?;
        let segment_ids: Vec<i64> = serde_json::from_str(&row.try_get::<String, _>("segments")?)?;
        let orphan_events: Vec<String> =
            serde_json::from_str(&row.try_get::<String, _>("events")?)?;

        if !utterance_ids.is_empty() {
            sqlx::query(
                "DELETE FROM episode_members WHERE account_id=$1 AND record_type='utterance' \
                    AND record_id=ANY($2)",
            )
            .bind(account_id)
            .bind(&utterance_ids)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("DELETE FROM utterances WHERE account_id=$1 AND id=ANY($2)")
                .bind(account_id)
                .bind(&utterance_ids)
                .execute(&mut *transaction)
                .await?;
        }
        if !screenshot_ids.is_empty() {
            sqlx::query(
                "DELETE FROM episode_members WHERE account_id=$1 AND record_type='screenshot' \
                    AND record_id=ANY($2)",
            )
            .bind(account_id)
            .bind(&screenshot_ids)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("DELETE FROM screenshots WHERE account_id=$1 AND id=ANY($2)")
                .bind(account_id)
                .bind(&screenshot_ids)
                .execute(&mut *transaction)
                .await?;
        }
        if !segment_ids.is_empty() {
            sqlx::query(
                "DELETE FROM audio_segments s WHERE s.account_id=$1 AND s.id=ANY($2) \
                  AND NOT EXISTS (SELECT 1 FROM utterances u WHERE u.account_id=s.account_id \
                    AND u.audio_segment_id=s.id)",
            )
            .bind(account_id)
            .bind(&segment_ids)
            .execute(&mut *transaction)
            .await?;
        }
        if !orphan_events.is_empty() {
            sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id=ANY($2)")
                .bind(account_id)
                .bind(&orphan_events)
                .execute(&mut *transaction)
                .await?;
        }
        sqlx::query("DELETE FROM episodes WHERE account_id=$1 AND id=$2")
            .bind(account_id)
            .bind(plan.episode_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE episode_deletions SET state='complete',completed_at=now(),updated_at=now() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(plan.episode_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(persisted.purge)
    }

    async fn pending_episode_deletions(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, EpisodeDeletionPlan)>> {
        let limit = i64::try_from(limit.clamp(1, 256)).map_err(|_| {
            EnclaveError::InvalidRequest("episode deletion limit is invalid".into())
        })?;
        let rows = sqlx::query(
            "SELECT account_id,episode_id,purge::text AS purge,media_object_keys::text AS media \
               FROM episode_deletions WHERE state='pending' \
              ORDER BY updated_at,account_id,episode_id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| {
                let account_id = row.try_get("account_id")?;
                let episode_id = row.try_get("episode_id")?;
                let plan = decode_plan(episode_id, row.try_get("purge")?, row.try_get("media")?)?;
                Ok((account_id, plan))
            })
            .collect()
    }
}
