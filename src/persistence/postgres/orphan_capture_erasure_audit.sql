WITH operations AS MATERIALIZED (
    SELECT o.*,
      (SELECT count(*) FROM orphan_capture_erasure_sessions s
        WHERE s.account_id=o.account_id AND s.operation_id=o.operation_id) actual_sessions,
      (SELECT count(*) FROM orphan_capture_erasure_streams s
        WHERE s.account_id=o.account_id AND s.operation_id=o.operation_id) actual_streams,
      (SELECT count(*) FROM orphan_capture_erasure_events e
        WHERE e.account_id=o.account_id AND e.operation_id=o.operation_id) actual_events,
      (SELECT count(*) FROM orphan_capture_erasure_objects m
        WHERE m.account_id=o.account_id AND m.operation_id=o.operation_id) actual_objects
    FROM orphan_capture_erasure_operations o
), resurrected AS (
    SELECT e.account_id,e.operation_id FROM capture_sessions c JOIN orphan_capture_erasure_sessions e
      ON e.account_id=c.account_id AND e.capture_session_id=c.id
    UNION SELECT e.account_id,e.operation_id FROM capture_streams c JOIN orphan_capture_erasure_streams e
      ON e.account_id=c.account_id AND e.stream_id=c.id
    UNION SELECT e.account_id,e.operation_id FROM capture_events c JOIN orphan_capture_erasure_events e
      ON e.account_id=c.account_id AND (e.event_id=c.event_id OR e.asset_id=c.asset_id
        OR e.event_id=c.canonical_event_id OR e.asset_id=c.canonical_asset_id)
    UNION SELECT e.account_id,e.operation_id FROM media_objects m JOIN orphan_capture_erasure_events e
      ON e.account_id=m.account_id AND e.asset_id=m.asset_id
    UNION SELECT e.account_id,e.operation_id FROM utterances u JOIN orphan_capture_erasure_events e
      ON e.account_id=u.account_id AND e.event_id=split_part(substr(u.source_key,10),':',1)
      WHERE u.source_key LIKE 'cloud-v2:%'
    UNION SELECT e.account_id,e.operation_id FROM screenshots s JOIN orphan_capture_erasure_events e
      ON e.account_id=s.account_id AND e.event_id=substr(s.source_key,10)
      WHERE s.source_key LIKE 'cloud-v2:%'
)
SELECT count(*) FILTER(WHERE state IN ('preparing','provider_pending'))::bigint pending_operations,
       count(*) FILTER(WHERE state='provider_verified')::bigint provider_verified_operations,
       count(*) FILTER(WHERE state='complete' AND capture_upload_fenced)::bigint complete_fenced_operations,
       count(*) FILTER(WHERE state='complete' AND NOT capture_upload_fenced)::bigint released_operations,
       coalesce(sum(actual_objects),0)::bigint inventory_objects,
       count(*) FILTER(WHERE state='preparing' OR actual_sessions<>session_count
           OR actual_streams<>stream_count OR actual_events<>event_count
           OR (state='complete' AND actual_objects<>0)
           OR (state<>'complete' AND actual_objects<>object_count)
           OR EXISTS(SELECT 1 FROM resurrected r
             WHERE r.account_id=o.account_id AND r.operation_id=o.operation_id))::bigint coherence_violations
  FROM operations o;
