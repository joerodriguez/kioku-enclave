-- Exact account/session selectors only. Returned identifiers remain inside the
-- attested migrator; its public result contains only counts and commitments.
WITH sessions AS MATERIALIZED (
    SELECT * FROM capture_sessions WHERE account_id=$1 AND id=ANY($2::text[])
), streams AS MATERIALIZED (
    SELECT * FROM capture_streams WHERE account_id=$1 AND capture_session_id=ANY($2::text[])
), events AS MATERIALIZED (
    SELECT * FROM capture_events WHERE account_id=$1 AND capture_session_id=ANY($2::text[])
), projection_events(kind,id,event_id) AS MATERIALIZED (
    SELECT 'utterance',id,split_part(substr(source_key,10),':',1) FROM utterances
     WHERE account_id=$1 AND source_key LIKE 'cloud-v2:%'
    UNION SELECT 'utterance',u.id,o.event_id FROM utterances u JOIN speaker_observations o
      ON o.account_id=u.account_id AND o.id=u.speaker_observation_id WHERE u.account_id=$1
    UNION SELECT 'utterance',u.id,o.event_id FROM utterances u JOIN speaker_observation_sources o
      ON o.account_id=u.account_id AND o.speaker_observation_id=u.speaker_observation_id WHERE u.account_id=$1
    UNION SELECT 'screenshot',id,substr(source_key,10) FROM screenshots
     WHERE account_id=$1 AND source_key LIKE 'cloud-v2:%'
    UNION SELECT 'screenshot',screenshot_id,event_id FROM visual_speaker_observations WHERE account_id=$1
), projections AS MATERIALIZED (
    SELECT DISTINCT p.kind,p.id FROM projection_events p JOIN events e ON e.event_id=p.event_id
), utterance_ids AS MATERIALIZED (SELECT id FROM projections WHERE kind='utterance'),
screenshot_ids AS MATERIALIZED (SELECT id FROM projections WHERE kind='screenshot'),
segments AS MATERIALIZED (
    SELECT DISTINCT audio_segment_id id FROM utterances WHERE account_id=$1 AND id IN (SELECT id FROM utterance_ids)
), observations AS MATERIALIZED (
    SELECT o.id FROM speaker_observations o WHERE o.account_id=$1 AND (
        o.event_id IN (SELECT event_id FROM events) OR EXISTS(SELECT 1 FROM speaker_observation_sources s
         WHERE s.account_id=$1 AND s.speaker_observation_id=o.id AND s.event_id IN (SELECT event_id FROM events)))
), works AS MATERIALIZED (
    SELECT DISTINCT work_unit_id id FROM media_work_members WHERE account_id=$1 AND event_id IN (SELECT event_id FROM events)
), clusters AS MATERIALIZED (
    SELECT id FROM speaker_clusters WHERE account_id=$1 AND work_unit_id IN (SELECT id FROM works)
), browser_states AS MATERIALIZED (
    SELECT DISTINCT state_key FROM browser_observations_v2 WHERE account_id=$1 AND event_id IN (SELECT event_id FROM events)
      AND state_key IS NOT NULL
), batches AS MATERIALIZED (
    SELECT batch_id FROM capture_reference_batch_receipts WHERE account_id=$1 AND stream_id IN (SELECT id FROM streams)
), violations AS (
    SELECT 'session_scope' reason WHERE (SELECT count(*) FROM sessions)<>cardinality($2::text[])
        OR cardinality($2::text[]) NOT BETWEEN 1 AND 4
        OR EXISTS(SELECT 1 FROM sessions WHERE ended_at IS NULL OR ended_at>clock_timestamp()-interval '7 days')
    UNION ALL SELECT 'stream_scope' WHERE (SELECT count(*) FROM streams) NOT BETWEEN 1 AND 16
        OR EXISTS(SELECT 1 FROM streams WHERE sealed_sequence IS NOT NULL OR committed_through_sequence<>-1)
        OR EXISTS(SELECT 1 FROM streams WHERE capture_formation_stream_contiguous_through(account_id,id)<>-2
            OR capture_formation_stream_accepted_max(account_id,id)<0)
    UNION ALL SELECT 'event_scope' WHERE (SELECT count(*) FROM events) NOT BETWEEN 1 AND 256
        OR EXISTS(SELECT 1 FROM events e LEFT JOIN streams s ON s.id=e.stream_id
                   WHERE s.id IS NULL OR s.capture_session_id<>e.capture_session_id)
    UNION ALL SELECT 'prior_deleted_sequence' WHERE EXISTS(SELECT 1 FROM capture_formation_deleted_sequences
        WHERE account_id=$1 AND capture_session_id=ANY($2::text[]))
    UNION ALL SELECT 'canonical_shape' WHERE EXISTS(SELECT 1 FROM events e WHERE e.media_disposition='canonical'
        AND num_nonnulls(e.canonical_event_id,e.canonical_asset_id,e.canonical_media_sha256,
            e.perceptual_hash,e.hamming_distance,e.pixel_change_ratio,e.context_fingerprint,e.dedupe_version)<>0)
    UNION ALL SELECT 'media_authority' WHERE EXISTS(
        SELECT 1 FROM events e LEFT JOIN media_objects m
          ON m.account_id=e.account_id AND m.event_id=e.event_id
        LEFT JOIN recording_media_authority a ON a.account_id=m.account_id AND a.asset_id=m.asset_id
        WHERE (e.media_disposition='canonical' AND (
          m.asset_id IS DISTINCT FROM e.asset_id OR a.asset_id IS DISTINCT FROM e.asset_id
          OR NOT coalesce((a.retention_decision='processing_window_30d' AND a.storage_backend='processing'
            AND a.recording_state='processing_only' AND a.recording_key_epoch IS NULL
            AND m.object_key='raw/'||e.account_id||'/'||e.asset_id||'.enc')
          OR (a.retention_decision='until_deleted' AND a.storage_backend='recordings'
            AND a.recording_state='durable' AND a.recording_key_epoch IS NOT NULL
            AND m.object_key='recordings/'||e.account_id||'/'||e.asset_id||'.enc'),false)))
          OR (e.media_disposition='reference' AND (m.asset_id IS NOT NULL OR EXISTS(
            SELECT 1 FROM recording_media_authority WHERE account_id=e.account_id AND asset_id=e.asset_id))))
    UNION ALL SELECT 'canonical_family' WHERE EXISTS(
        SELECT 1 FROM capture_events e WHERE e.account_id=$1 AND (
          (e.event_id IN (SELECT event_id FROM events) AND e.canonical_event_id IS NOT NULL
            AND e.canonical_event_id NOT IN (SELECT event_id FROM events))
          OR (e.event_id NOT IN (SELECT event_id FROM events)
            AND e.canonical_event_id IN (SELECT event_id FROM events))
          OR (e.event_id NOT IN (SELECT event_id FROM events)
            AND e.canonical_asset_id IN (SELECT asset_id FROM events))))
        OR EXISTS(SELECT 1 FROM events e LEFT JOIN capture_events root
          ON root.account_id=e.account_id AND root.event_id=e.canonical_event_id
          LEFT JOIN media_objects media ON media.account_id=root.account_id AND media.event_id=root.event_id
          WHERE e.media_disposition='reference' AND (root.media_disposition IS DISTINCT FROM 'canonical'
            OR e.canonical_asset_id IS DISTINCT FROM root.asset_id
            OR e.canonical_asset_id IS DISTINCT FROM media.asset_id
            OR e.canonical_media_sha256 IS DISTINCT FROM media.sha256))
    UNION ALL SELECT 'projection_scope' WHERE (SELECT count(*) FROM projections)>1024
        OR EXISTS(SELECT 1 FROM projection_events e JOIN projections p USING(kind,id)
                   WHERE e.event_id NOT IN (SELECT event_id FROM events))
    UNION ALL SELECT 'owned_projection' WHERE EXISTS(SELECT 1 FROM episode_members m JOIN projections p
        ON p.kind=m.record_type AND p.id=m.record_id WHERE m.account_id=$1)
        OR EXISTS(SELECT 1 FROM active_episode_members m JOIN projections p
        ON p.kind=m.record_type AND p.id=m.record_id WHERE m.account_id=$1)
        OR EXISTS(SELECT 1 FROM memory_reconciliation_sources m JOIN projections p
        ON p.kind=m.record_type AND p.id=m.record_id WHERE m.account_id=$1)
    UNION ALL SELECT 'prior_deletion_authority' WHERE EXISTS(SELECT 1 FROM episode_deletions d WHERE d.account_id=$1 AND (
        EXISTS(SELECT 1 FROM jsonb_array_elements_text(d.orphan_event_ids) e(id) WHERE id IN (SELECT event_id FROM events))
        OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d.utterance_ids) u(id) WHERE id::bigint IN (SELECT id FROM utterance_ids))
        OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d.screenshot_ids) s(id) WHERE id::bigint IN (SELECT id FROM screenshot_ids))
        OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d.segment_ids) s(id) WHERE id::bigint IN (SELECT id FROM segments))
        OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(d.media_object_keys) k(key) WHERE key IN (
          SELECT object_key FROM media_objects WHERE account_id=$1 AND event_id IN (SELECT event_id FROM events)))))
        OR EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_sessions WHERE account_id=$1 AND capture_session_id=ANY($2::text[]))
        OR EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_events WHERE account_id=$1 AND (
          capture_session_id=ANY($2::text[]) OR event_id IN (SELECT event_id FROM events) OR root_event_id IN (SELECT event_id FROM events)))
        OR EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_roots WHERE account_id=$1 AND root_event_id IN (SELECT event_id FROM events))
        OR EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_members m JOIN projections p
          ON p.kind=m.record_type AND p.id=m.record_id WHERE m.account_id=$1)
        OR EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_objects WHERE account_id=$1 AND object_key IN (
          SELECT object_key FROM media_objects WHERE account_id=$1 AND event_id IN (SELECT event_id FROM events)))
    UNION ALL SELECT 'episode_projection' WHERE EXISTS(SELECT 1 FROM screenshot_images
        WHERE account_id=$1 AND screenshot_id IN (SELECT id FROM screenshot_ids))
        OR EXISTS(SELECT 1 FROM episode_screen_interpretations WHERE account_id=$1
        AND screenshot_id IN (SELECT id FROM screenshot_ids))
    UNION ALL SELECT 'shared_segment' WHERE EXISTS(SELECT 1 FROM utterances WHERE account_id=$1
        AND audio_segment_id IN (SELECT id FROM segments) AND id NOT IN (SELECT id FROM utterance_ids))
    UNION ALL SELECT 'shared_screenshot' WHERE EXISTS(SELECT 1 FROM screenshots WHERE account_id=$1
        AND duplicate_of_id IN (SELECT id FROM screenshot_ids) AND id NOT IN (SELECT id FROM screenshot_ids))
    UNION ALL SELECT 'shared_work' WHERE EXISTS(SELECT 1 FROM media_work_members WHERE account_id=$1
        AND work_unit_id IN (SELECT id FROM works) AND event_id NOT IN (SELECT event_id FROM events))
    UNION ALL SELECT 'shared_observation' WHERE EXISTS(SELECT 1 FROM speaker_observations WHERE account_id=$1
        AND id IN (SELECT id FROM observations) AND event_id NOT IN (SELECT event_id FROM events))
        OR EXISTS(SELECT 1 FROM speaker_observation_sources WHERE account_id=$1
        AND speaker_observation_id IN (SELECT id FROM observations) AND event_id NOT IN (SELECT event_id FROM events))
        OR EXISTS(SELECT 1 FROM utterances WHERE account_id=$1 AND speaker_observation_id IN (SELECT id FROM observations)
        AND id NOT IN (SELECT id FROM utterance_ids))
        OR EXISTS(SELECT 1 FROM speaker_observations WHERE account_id=$1 AND cluster_id IN (SELECT id FROM clusters)
        AND id NOT IN (SELECT id FROM observations))
    -- Inferred person/profile lineage is deliberately unsupported, never partly erased.
    UNION ALL SELECT 'identity_lineage' WHERE EXISTS(SELECT 1 FROM speaker_observations WHERE account_id=$1
        AND id IN (SELECT id FROM observations) AND (person_id IS NOT NULL OR direct_evidence_id IS NOT NULL))
        OR EXISTS(SELECT 1 FROM speaker_clusters WHERE account_id=$1 AND id IN (SELECT id FROM clusters)
        AND (person_id IS NOT NULL OR voice_profile_id IS NOT NULL))
        OR EXISTS(SELECT 1 FROM episode_speaker_slots WHERE account_id=$1 AND speaker_cluster_id IN (SELECT id FROM clusters))
        OR EXISTS(SELECT 1 FROM voice_samples WHERE account_id=$1 AND speaker_observation_id IN (SELECT id FROM observations))
        OR EXISTS(SELECT 1 FROM person_name_claims WHERE account_id=$1 AND (source_event_id IN (SELECT event_id FROM events)
        OR speaker_observation_id IN (SELECT id FROM observations)))
        OR EXISTS(SELECT 1 FROM identity_evidence WHERE account_id=$1 AND (source_event_id IN (SELECT event_id FROM events)
        OR speaker_observation_id IN (SELECT id FROM observations)))
        OR EXISTS(SELECT 1 FROM person_facts WHERE account_id=$1 AND (source_event_id IN (SELECT event_id FROM events)
        OR speaker_observation_id IN (SELECT id FROM observations)))
    UNION ALL SELECT 'shared_browser' WHERE EXISTS(SELECT 1 FROM browser_observations_v2 WHERE account_id=$1
        AND state_key IN (SELECT state_key FROM browser_states) AND event_id NOT IN (SELECT event_id FROM events))
        OR EXISTS(SELECT 1 FROM screenshots WHERE account_id=$1 AND browser_snapshot_source_key IN (SELECT state_key FROM browser_states)
        AND id NOT IN (SELECT id FROM screenshot_ids))
    UNION ALL SELECT 'batch_scope' WHERE EXISTS(SELECT 1 FROM capture_reference_batch_events WHERE account_id=$1
        AND batch_id IN (SELECT batch_id FROM batches) AND event_id NOT IN (SELECT event_id FROM events))
        OR EXISTS(SELECT 1 FROM capture_reference_batch_events WHERE account_id=$1
        AND event_id IN (SELECT event_id FROM events) AND batch_id NOT IN (SELECT batch_id FROM batches))
    UNION ALL SELECT 'unknown_outbox' WHERE EXISTS(SELECT 1 FROM outbox_events WHERE account_id=$1
        AND aggregate_id IN (SELECT event_id FROM events) AND (event_kind<>'capture_media_queued'
          OR event_id<>'capture:'||aggregate_id OR payload->>'event_id' IS DISTINCT FROM aggregate_id))
)
SELECT (SELECT count(*) FROM violations)::bigint AS violations,
       jsonb_build_object(
         'sessions',(SELECT coalesce(jsonb_agg(id ORDER BY id),'[]') FROM sessions),
         'streams',(SELECT coalesce(jsonb_agg(id ORDER BY id),'[]') FROM streams),
         'events',(SELECT coalesce(jsonb_agg(event_id ORDER BY event_id),'[]') FROM events),
         'assets',(SELECT coalesce(jsonb_agg(asset_id ORDER BY asset_id),'[]') FROM events),
         'utterances',(SELECT coalesce(jsonb_agg(id::text ORDER BY id),'[]') FROM utterance_ids),
         'screenshots',(SELECT coalesce(jsonb_agg(id::text ORDER BY id),'[]') FROM screenshot_ids),
         'segments',(SELECT coalesce(jsonb_agg(id::text ORDER BY id),'[]') FROM segments),
         'observations',(SELECT coalesce(jsonb_agg(id::text ORDER BY id),'[]') FROM observations),
         'works',(SELECT coalesce(jsonb_agg(id ORDER BY id),'[]') FROM works),
         'clusters',(SELECT coalesce(jsonb_agg(id::text ORDER BY id),'[]') FROM clusters),
         'browser_states',(SELECT coalesce(jsonb_agg(state_key ORDER BY state_key),'[]') FROM browser_states),
         'batches',(SELECT coalesce(jsonb_agg(batch_id ORDER BY batch_id),'[]') FROM batches)
       )::text AS scope
