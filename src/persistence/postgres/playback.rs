use async_trait::async_trait;
use sqlx::Row;

use crate::{
    cp::{
        isotime,
        playback::{
            availability_from_counts, opaque_id, projection_revision, resolve_utterance_interval,
            DurableReadFence, PersonMemoriesPage, PersonMemorySummary, PlaybackDataset,
            SegmentAuthority, SourceAuthority, UtteranceAuthority, MAX_AUDIO_SEGMENT_BYTES,
        },
    },
    error::{EnclaveError, Result},
    persistence::PlaybackRepository,
};

use super::PostgresPersistence;

fn epoch_millis(row: &sqlx::postgres::PgRow, name: &str) -> Result<i64> {
    row.try_get(name).map_err(Into::into)
}

fn optional_epoch_string(row: &sqlx::postgres::PgRow, name: &str) -> Result<Option<String>> {
    Ok(row
        .try_get::<Option<i64>, _>(name)?
        .map(isotime::format_epoch_millis))
}

#[async_trait]
impl PlaybackRepository for PostgresPersistence {
    async fn dataset(
        &self,
        account_id: &str,
        memory_id: i64,
        durable_read: Option<&DurableReadFence>,
    ) -> Result<Option<PlaybackDataset>> {
        crate::gcs::validate_user_id(account_id)?;
        if memory_id <= 0 {
            return Ok(None);
        }
        let memory = sqlx::query(
            "SELECT floor(extract(epoch FROM started_at)*1000)::bigint started_at_ms, \
                    floor(extract(epoch FROM ended_at)*1000)::bigint ended_at_ms \
               FROM episodes WHERE account_id=$1 AND id=$2 AND substance<>'none'",
        )
        .bind(account_id)
        .bind(memory_id)
        .fetch_optional(self.pool())
        .await?;
        let Some(memory) = memory else {
            return Ok(None);
        };
        let started_ms = epoch_millis(&memory, "started_at_ms")?;
        let ended_ms = epoch_millis(&memory, "ended_at_ms")?;
        if ended_ms <= started_ms {
            return Err(EnclaveError::Store("memory interval is malformed".into()));
        }
        let started_at = isotime::format_epoch_millis(started_ms);
        let ended_at = isotime::format_epoch_millis(ended_ms);
        let fence_revision = durable_read.map(|fence| fence.policy_revision);
        let fence_epoch = durable_read.map(|fence| fence.policy_epoch.as_str());

        let segment_rows = sqlx::query(
            "SELECT DISTINCT e.capture_session_id,e.stream_id,e.stream_kind,e.event_id, \
                    floor(extract(epoch FROM e.started_at)*1000)::bigint event_started_ms, \
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint event_ended_ms, \
                    m.asset_id,m.object_key,m.object_generation,m.object_backend,m.mime_type,m.codec, \
                    m.byte_length,m.sha256,m.processing_state, \
                    floor(extract(epoch FROM m.deleted_at)*1000)::bigint deleted_at_ms, \
                    COALESCE(ra.retention_decision,'processing_window_30d') retention_decision, \
                    COALESCE(ra.storage_backend,'processing') storage_backend, \
                    ra.retention_policy_revision,ra.retention_policy_epoch,ra.recording_key_epoch, \
                    COALESCE(ra.recording_state,'processing_only') recording_state \
               FROM episode_members em \
               JOIN utterances u ON u.account_id=em.account_id AND em.record_type='utterance' AND u.id=em.record_id \
               JOIN speaker_observation_sources src ON src.account_id=u.account_id AND src.speaker_observation_id=u.speaker_observation_id \
               JOIN capture_events e ON e.account_id=src.account_id AND e.event_id=src.event_id \
               LEFT JOIN media_objects m ON m.account_id=e.account_id AND m.event_id=e.event_id \
               LEFT JOIN recording_media_authority ra ON ra.account_id=m.account_id AND ra.asset_id=m.asset_id \
              WHERE em.account_id=$1 AND em.episode_id=$2 \
                AND e.stream_kind IN ('mic','system_audio','ios_mic') \
              ORDER BY event_started_ms,e.stream_id,e.event_id",
        )
        .bind(account_id)
        .bind(memory_id)
        .fetch_all(self.pool())
        .await?;
        let mut segments = Vec::with_capacity(segment_rows.len());
        for row in segment_rows {
            let capture_session_id: String = row.try_get("capture_session_id")?;
            let stream_id: String = row.try_get("stream_id")?;
            let kind: String = row.try_get("stream_kind")?;
            let event_id: String = row.try_get("event_id")?;
            let retention_decision: String = row.try_get("retention_decision")?;
            let retention_policy_revision: Option<i64> =
                row.try_get("retention_policy_revision")?;
            let retention_policy_epoch: Option<String> = row.try_get("retention_policy_epoch")?;
            let durable_read_authorized = retention_decision == "until_deleted"
                && fence_revision == retention_policy_revision
                && fence_epoch == retention_policy_epoch.as_deref();
            segments.push(SegmentAuthority {
                recording_id: opaque_id("rec_", &[account_id, &capture_session_id]),
                segment_id: opaque_id("seg_", &[account_id, &event_id]),
                track_id: opaque_id("track_", &[account_id, &capture_session_id, &stream_id]),
                kind,
                capture_session_id,
                stream_id,
                event_id,
                asset_id: row.try_get("asset_id")?,
                object_key: row.try_get("object_key")?,
                generation: row.try_get("object_generation")?,
                object_backend: row.try_get("object_backend")?,
                stored_mime_type: row.try_get("mime_type")?,
                codec: row.try_get("codec")?,
                byte_length: row.try_get("byte_length")?,
                sha256: row.try_get("sha256")?,
                processing_state: row.try_get("processing_state")?,
                deleted_at: optional_epoch_string(&row, "deleted_at_ms")?,
                retention_decision,
                storage_backend: row.try_get("storage_backend")?,
                retention_policy_revision,
                retention_policy_epoch,
                recording_key_epoch: row.try_get("recording_key_epoch")?,
                recording_state: row.try_get("recording_state")?,
                durable_read_authorized,
                timeline_start_ms: epoch_millis(&row, "event_started_ms")?
                    .saturating_sub(started_ms),
                timeline_end_ms: epoch_millis(&row, "event_ended_ms")?.saturating_sub(started_ms),
            });
        }

        let utterance_rows = sqlx::query(
            "SELECT u.id,u.speaker_observation_id, \
                    floor(extract(epoch FROM o.started_at)*1000)::bigint observation_started_ms, \
                    floor(extract(epoch FROM o.ended_at)*1000)::bigint observation_ended_ms, \
                    floor(extract(epoch FROM s.started_at)*1000)::bigint segment_started_ms, \
                    u.start_offset_seconds,u.end_offset_seconds,u.text,u.speaker_label, \
                    COALESCE(o.overlap,false) overlap, \
                    CASE WHEN c.attribution_state='owner_transmit' THEN NULL ELSE p.id END AS person_id, \
                    p.display_name,c.attribution_state \
               FROM episode_members em \
               JOIN utterances u ON u.account_id=em.account_id AND em.record_type='utterance' AND u.id=em.record_id \
               JOIN audio_segments s ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
               LEFT JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id \
               LEFT JOIN speaker_clusters c ON c.account_id=o.account_id AND c.id=o.cluster_id \
               LEFT JOIN people p ON p.account_id=u.account_id AND p.id=COALESCE(o.person_id,c.person_id) AND p.status='identified' \
              WHERE em.account_id=$1 AND em.episode_id=$2 \
              ORDER BY COALESCE(o.started_at,s.started_at),u.id",
        )
        .bind(account_id)
        .bind(memory_id)
        .fetch_all(self.pool())
        .await?;
        let mut utterances = Vec::with_capacity(utterance_rows.len());
        for row in utterance_rows {
            let observation_start = optional_epoch_string(&row, "observation_started_ms")?;
            let observation_end = optional_epoch_string(&row, "observation_ended_ms")?;
            let segment_start =
                isotime::format_epoch_millis(epoch_millis(&row, "segment_started_ms")?);
            let (absolute_start_ms, absolute_end_ms) = resolve_utterance_interval(
                observation_start.as_deref(),
                observation_end.as_deref(),
                &segment_start,
                row.try_get("start_offset_seconds")?,
                row.try_get("end_offset_seconds")?,
            )
            .ok_or_else(|| EnclaveError::Store("utterance interval is malformed".into()))?;
            let person_id: Option<i64> = row.try_get("person_id")?;
            let attribution = row.try_get::<Option<String>, _>("attribution_state")?;
            utterances.push(UtteranceAuthority {
                utterance_id: row.try_get("id")?,
                observation_id: row.try_get("speaker_observation_id")?,
                timeline_start_ms: absolute_start_ms.saturating_sub(started_ms),
                timeline_end_ms: absolute_end_ms.saturating_sub(started_ms),
                text: row.try_get("text")?,
                fallback_label: row.try_get("speaker_label")?,
                overlap: row.try_get("overlap")?,
                person_id,
                display_name: row.try_get("display_name")?,
                attribution_state: if person_id.is_some() {
                    Some("direct_identity_evidence".into())
                } else {
                    attribution.map(|state| match state.as_str() {
                        "owner_transmit" => "owner_source_role".into(),
                        "anonymous_profile" => "verified_voice".into(),
                        "request_local" | "unsegmented" => "context_inferred".into(),
                        _ => "unavailable".into(),
                    })
                },
            });
        }

        let source_rows = sqlx::query(
            "SELECT DISTINCT src.speaker_observation_id,src.event_id,src.window_start_ms, \
                    src.window_end_ms,src.event_start_ms,src.event_end_ms \
               FROM episode_members em \
               JOIN utterances u ON u.account_id=em.account_id AND em.record_type='utterance' AND u.id=em.record_id \
               JOIN speaker_observation_sources src ON src.account_id=u.account_id AND src.speaker_observation_id=u.speaker_observation_id \
              WHERE em.account_id=$1 AND em.episode_id=$2 \
              ORDER BY src.speaker_observation_id,src.window_start_ms,src.event_id",
        )
        .bind(account_id)
        .bind(memory_id)
        .fetch_all(self.pool())
        .await?;
        let sources = source_rows
            .iter()
            .map(|row| {
                Ok(SourceAuthority {
                    observation_id: row.try_get("speaker_observation_id")?,
                    event_id: row.try_get("event_id")?,
                    window_start_ms: row.try_get("window_start_ms")?,
                    window_end_ms: row.try_get("window_end_ms")?,
                    event_start_ms: row.try_get("event_start_ms")?,
                    event_end_ms: row.try_get("event_end_ms")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let revision = projection_revision(
            memory_id,
            &started_at,
            &ended_at,
            &segments,
            &utterances,
            &sources,
        );
        Ok(Some(PlaybackDataset {
            owner_id: account_id.to_owned(),
            memory_id,
            started_at,
            ended_at,
            duration_ms: ended_ms.saturating_sub(started_ms),
            projection_revision: revision,
            segments,
            utterances,
            sources,
        }))
    }

    async fn person_memories(
        &self,
        account_id: &str,
        person_id: i64,
        before_id: Option<i64>,
        limit: usize,
        durable_read: Option<&DurableReadFence>,
    ) -> Result<PersonMemoriesPage> {
        crate::gcs::validate_user_id(account_id)?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM people WHERE account_id=$1 AND id=$2 AND status='identified')",
        )
        .bind(account_id)
        .bind(person_id)
        .fetch_one(self.pool())
        .await?;
        if !exists {
            return Err(EnclaveError::NotFound);
        }
        let fence_revision = durable_read.map(|fence| fence.policy_revision);
        let fence_epoch = durable_read.map(|fence| fence.policy_epoch.as_str());
        let rows = sqlx::query(
            "SELECT e.id,e.title,e.summary, \
                    floor(extract(epoch FROM e.started_at)*1000)::bigint started_at_ms, \
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint ended_at_ms, \
                    count(DISTINCT u.id) FILTER (WHERE o.person_id=$2) attributed_count, \
                    min(floor(extract(epoch FROM o.started_at)*1000)::bigint) FILTER (WHERE o.person_id=$2) first_attributed_ms, \
                    count(DISTINCT ce.capture_session_id) source_recordings, \
                    min(u.id) FILTER (WHERE o.person_id=$2) playback_utterance_id, \
                    count(DISTINCT src.event_id) source_count, \
                    count(DISTINCT src.event_id) FILTER (WHERE mo.processing_state='ready' AND mo.deleted_at IS NULL \
                      AND mo.object_backend='current' AND mo.object_generation>0 AND mo.mime_type IN ('audio/m4a','audio/mp4') \
                      AND mo.codec='aac' AND mo.byte_length BETWEEN 1 AND $5 AND mo.sha256 ~ '^[0-9a-fA-F]{64}$' \
                      AND ((COALESCE(ra.retention_decision,'processing_window_30d')='processing_window_30d' \
                            AND COALESCE(ra.storage_backend,'processing')='processing' AND COALESCE(ra.recording_state,'processing_only')='processing_only') \
                        OR (ra.retention_decision='until_deleted' AND ra.storage_backend='recordings' AND ra.recording_state='durable' \
                            AND $6::bigint IS NOT NULL AND ra.retention_policy_revision=$6 \
                            AND $7::text IS NOT NULL AND ra.retention_policy_epoch=$7))) ready_count, \
                    count(DISTINCT src.event_id) FILTER (WHERE mo.deleted_at IS NULL \
                      AND mo.processing_state IN ('queued','processing','retry_wait')) pending_count, \
                    count(DISTINCT src.event_id) FILTER (WHERE mo.deleted_at IS NOT NULL AND mo.processing_state<>'pruned') deleted_count, \
                    count(DISTINCT src.event_id) FILTER (WHERE mo.processing_state='pruned') pruned_count \
               FROM episodes e \
               JOIN episode_participants ep ON ep.account_id=e.account_id AND ep.episode_id=e.id \
               LEFT JOIN episode_members em ON em.account_id=e.account_id AND em.episode_id=e.id AND em.record_type='utterance' \
               LEFT JOIN utterances u ON u.account_id=em.account_id AND u.id=em.record_id \
               LEFT JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id \
               LEFT JOIN speaker_observation_sources src ON src.account_id=o.account_id AND src.speaker_observation_id=o.id \
               LEFT JOIN capture_events ce ON ce.account_id=src.account_id AND ce.event_id=src.event_id \
               LEFT JOIN media_objects mo ON mo.account_id=src.account_id AND mo.event_id=src.event_id \
               LEFT JOIN recording_media_authority ra ON ra.account_id=mo.account_id AND ra.asset_id=mo.asset_id \
              WHERE e.account_id=$1 AND ep.person_id=$2 AND ep.state='active' AND e.substance<>'none' \
                AND ($3::bigint IS NULL OR e.id<$3) \
              GROUP BY e.id,e.title,e.summary,e.started_at,e.ended_at ORDER BY e.id DESC LIMIT $4",
        )
        .bind(account_id)
        .bind(person_id)
        .bind(before_id)
        .bind(i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX))
        .bind(MAX_AUDIO_SEGMENT_BYTES)
        .bind(fence_revision)
        .bind(fence_epoch)
        .fetch_all(self.pool())
        .await?;
        let mut memories = Vec::with_capacity(rows.len());
        for row in rows {
            let started_ms = epoch_millis(&row, "started_at_ms")?;
            let first_attributed_ms: Option<i64> = row.try_get("first_attributed_ms")?;
            let source_count = row.try_get("source_count")?;
            let ready_count = row.try_get("ready_count")?;
            let pending_count = row.try_get("pending_count")?;
            let deleted_count = row.try_get("deleted_count")?;
            let pruned_count = row.try_get("pruned_count")?;
            memories.push(PersonMemorySummary {
                memory_id: row.try_get("id")?,
                title: row.try_get("title")?,
                summary: row.try_get("summary")?,
                started_at: isotime::format_epoch_millis(started_ms),
                ended_at: isotime::format_epoch_millis(epoch_millis(&row, "ended_at_ms")?),
                attributed_utterance_count: row.try_get("attributed_count")?,
                contributing_recording_count: row.try_get("source_recordings")?,
                audio_availability: availability_from_counts(
                    source_count,
                    ready_count,
                    pending_count,
                    deleted_count,
                    pruned_count,
                ),
                playback_start_ms: first_attributed_ms
                    .map(|first| first.saturating_sub(started_ms).max(0)),
                playback_utterance_id: row.try_get("playback_utterance_id")?,
            });
        }
        let next_cursor = (memories.len() > limit).then(|| memories[limit - 1].memory_id);
        memories.truncate(limit);
        Ok(PersonMemoriesPage {
            person_id,
            memories,
            next_cursor,
        })
    }
}
