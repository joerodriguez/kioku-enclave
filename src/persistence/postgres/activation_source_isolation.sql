-- Owner-prelaunch eligibility, NOT source completion. Metadata never leaves this
-- read-only snapshot except as counts. Over-connection intentionally fails closed.
WITH unresolved AS MATERIALIZED (
    SELECT account_id,capture_session_id FROM capture_formation_receipts receipt
     WHERE source_revision<>completed_revision OR state<>'complete'
        OR (finish_requested_at IS NOT NULL AND seal_finalized_at IS NULL)
    UNION
    SELECT session.account_id,session.id FROM capture_sessions session
      LEFT JOIN capture_formation_receipts receipt
        ON receipt.account_id=session.account_id AND receipt.capture_session_id=session.id
     WHERE session.ended_at IS NOT NULL AND (
        receipt.account_id IS NULL OR receipt.state<>'complete'
        OR receipt.completed_revision<>receipt.source_revision
        OR receipt.finish_requested_at IS NULL OR receipt.seal_finalized_at IS NULL
        OR receipt.seal_generation<1
        OR NOT EXISTS(SELECT 1 FROM capture_formation_seal_events seal
            WHERE seal.account_id=receipt.account_id
              AND seal.capture_session_id=receipt.capture_session_id
              AND seal.seal_generation=receipt.seal_generation
              AND seal.source_revision=receipt.source_revision AND seal.event_kind='seal'
              AND seal.stream_maxima_sha256=capture_formation_stream_maxima_sha256(
                  receipt.account_id,receipt.capture_session_id))
        OR EXISTS(SELECT 1 FROM capture_formation_seal_events reopen
            WHERE reopen.account_id=receipt.account_id
              AND reopen.capture_session_id=receipt.capture_session_id
              AND reopen.seal_generation=receipt.seal_generation AND reopen.event_kind='reopen')
        OR NOT EXISTS(SELECT 1 FROM capture_streams stream
            WHERE stream.account_id=session.account_id AND stream.capture_session_id=session.id)
        OR EXISTS(SELECT 1 FROM capture_streams stream
            WHERE stream.account_id=session.account_id AND stream.capture_session_id=session.id
              AND (stream.sealed_sequence IS NULL
                OR stream.committed_through_sequence<>stream.sealed_sequence
                OR stream.committed_through_sequence IS DISTINCT FROM
                    capture_formation_stream_accepted_max(stream.account_id,stream.id)
                OR stream.committed_through_sequence IS DISTINCT FROM
                    capture_formation_stream_contiguous_through(stream.account_id,stream.id))))
),
-- Include all accounts, not just the incomplete account: empty/malformed drafts
-- elsewhere must not become a hidden liveness exception. No content columns.
projection_events(account_id,kind,id,event_id) AS MATERIALIZED (
    SELECT account_id,'utterance',id,split_part(substr(source_key,10),':',1)
      FROM utterances WHERE source_key LIKE 'cloud-v2:%'
    UNION SELECT u.account_id,'utterance',u.id,o.event_id FROM utterances u
      JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id
    UNION SELECT u.account_id,'utterance',u.id,o.event_id FROM utterances u
      JOIN speaker_observation_sources o
        ON o.account_id=u.account_id AND o.speaker_observation_id=u.speaker_observation_id
    UNION SELECT account_id,'screenshot',id,substr(source_key,10)
      FROM screenshots WHERE source_key LIKE 'cloud-v2:%'
    UNION SELECT account_id,'screenshot',screenshot_id,event_id FROM visual_speaker_observations
),
all_atoms AS MATERIALIZED (
    SELECT u.account_id,'u:'||u.id AS key,'utterance'::text AS kind,u.id,
           a.started_at+u.start_offset_seconds*interval '1 second' AS started_at,
           greatest(a.started_at+u.end_offset_seconds*interval '1 second',
                    a.started_at+u.start_offset_seconds*interval '1 second') AS ended_at
      FROM utterances u JOIN audio_segments a
        ON a.account_id=u.account_id AND a.id=u.audio_segment_id
    UNION ALL
    SELECT account_id,'s:'||id,'screenshot',id,captured_at,
           greatest(captured_at,visible_until)
      FROM screenshots
),
drafts AS MATERIALIZED (
    SELECT e.account_id,e.id,e.started_at,e.ended_at,
           e.finalization_status IN ('processing','deleting')
             OR e.finalization_claim_token IS NOT NULL
             OR EXISTS(SELECT 1 FROM episode_final_briefs b
                 WHERE b.account_id=e.account_id AND b.episode_id=e.id)
             OR EXISTS(SELECT 1 FROM webhook_deliveries d
                 WHERE d.account_id=e.account_id AND d.episode_id=e.id)
             OR EXISTS(SELECT 1 FROM email_deliveries d
                 WHERE d.account_id=e.account_id AND d.episode_id=e.id)
             OR EXISTS(SELECT 1 FROM push_deliveries d
                 WHERE d.account_id=e.account_id AND d.episode_id=e.id) AS row_conflict
      FROM episodes e JOIN memory_handles h
        ON h.account_id=e.account_id AND h.episode_id=e.id AND h.state='active'
      JOIN accounts a ON a.id=e.account_id AND a.status='active'
     WHERE e.structure_state='draft' AND e.finalized_at IS NULL
),
header_ordered AS (
    SELECT *,max(floor(extract(epoch FROM ended_at)*1000)) OVER (
        PARTITION BY account_id ORDER BY started_at,id
        ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS prior_end
      FROM drafts
),
headers AS MATERIALIZED (
    SELECT *,sum(CASE WHEN prior_end IS NULL
        OR floor(extract(epoch FROM started_at)*1000)>prior_end+14400000
        THEN 1 ELSE 0 END) OVER (PARTITION BY account_id ORDER BY started_at,id) AS header_component
      FROM header_ordered
),
atoms AS MATERIALIZED (
    SELECT atom.* FROM all_atoms atom
     WHERE NOT EXISTS(SELECT 1 FROM active_episode_members m WHERE m.account_id=atom.account_id
        AND m.record_type=atom.kind AND m.record_id=atom.id)
        OR EXISTS(SELECT 1 FROM active_episode_members m JOIN drafts d
            ON d.account_id=m.account_id AND d.id=m.episode_id
            WHERE m.account_id=atom.account_id AND m.record_type=atom.kind AND m.record_id=atom.id)
),
sessions AS MATERIALIZED (
    SELECT s.account_id,s.id,s.ended_at AS finish_at,
           least(s.started_at,min(e.started_at),min(atom.started_at)) AS started_at,
           greatest(s.last_event_at,s.ended_at,max(e.ended_at),max(atom.ended_at)) AS ended_at,
           greatest(s.created_at,s.ended_at,max(e.received_at),max(job.updated_at)) AS last_received_at
      FROM capture_sessions s LEFT JOIN capture_events e
        ON e.account_id=s.account_id AND e.capture_session_id=s.id
      LEFT JOIN projection_events projection
        ON projection.account_id=e.account_id AND projection.event_id=e.event_id
      LEFT JOIN atoms atom ON atom.account_id=projection.account_id
        AND atom.kind=projection.kind AND atom.id=projection.id
      LEFT JOIN media_processing_jobs job ON job.account_id=e.account_id AND job.event_id=e.event_id
     GROUP BY s.account_id,s.id
),
owners AS MATERIALIZED (
    -- Ownership is a non-temporal edge. Expand even when members lie outside
    -- the episode's declared interval. Other active owners are excluded by v24.
    SELECT e.account_id,e.id,least(e.started_at,min(atom.started_at)) AS started_at,
           greatest(e.ended_at,max(atom.ended_at)) AS ended_at,
           count(atom.id)::bigint AS atoms,count(m.record_id)::bigint AS members,
           h.header_component,h.row_conflict
      FROM episodes e JOIN memory_handles handle
        ON handle.account_id=e.account_id AND handle.episode_id=e.id AND handle.state='active'
      LEFT JOIN active_episode_members m ON m.account_id=e.account_id AND m.episode_id=e.id
      LEFT JOIN atoms atom ON atom.account_id=m.account_id
        AND atom.kind=m.record_type AND atom.id=m.record_id
      LEFT JOIN headers h ON h.account_id=e.account_id AND h.id=e.id
     WHERE h.id IS NOT NULL
     GROUP BY e.account_id,e.id,h.header_component,h.row_conflict
),
inventory AS MATERIALIZED (
    SELECT * FROM (
        SELECT account_id,'c:'||id AS key,started_at,ended_at FROM sessions
        UNION ALL SELECT account_id,key,started_at,ended_at FROM atoms
        UNION ALL SELECT account_id,'d:'||id,started_at,ended_at FROM owners
    ) all_vertices LIMIT 100001
),
ordered AS (
    SELECT *,max(ended_at) OVER (PARTITION BY account_id ORDER BY started_at,ended_at,key
        ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS prior_end FROM inventory
),
components AS MATERIALIZED (
    -- One extra millisecond conservatively covers v24's floor-to-ms boundary.
    SELECT *,sum(CASE WHEN prior_end IS NULL OR started_at>prior_end+interval '4 hours 1 millisecond'
        THEN 1 ELSE 0 END) OVER (PARTITION BY account_id ORDER BY started_at,ended_at,key) AS component
      FROM ordered
),
component_facts AS MATERIALIZED (
    SELECT c.account_id,c.component,count(o.header_component)::bigint AS drafts,
           count(DISTINCT o.header_component)::bigint AS header_components,
           count(o.id) FILTER (WHERE o.header_component IS NULL)::bigint AS outside_owners
      FROM components c LEFT JOIN owners o ON o.account_id=c.account_id AND c.key='d:'||o.id
     GROUP BY c.account_id,c.component
),
eligible AS MATERIALIZED (
    SELECT u.account_id,u.capture_session_id FROM unresolved u
      JOIN accounts account ON account.id=u.account_id AND account.status='active'
      JOIN sessions s ON s.account_id=u.account_id AND s.id=u.capture_session_id
      JOIN components c ON c.account_id=s.account_id AND c.key='c:'||s.id
      JOIN component_facts f ON f.account_id=c.account_id AND f.component=c.component
      JOIN capture_formation_receipts r
        ON r.account_id=s.account_id AND r.capture_session_id=s.id
     WHERE s.finish_at IS NOT NULL AND s.ended_at<transaction_timestamp()-interval '7 days'
       AND s.last_received_at<transaction_timestamp()-interval '7 days'
       AND r.source_revision>r.completed_revision AND r.state='pending'
       AND r.finish_requested_at IS NOT NULL AND r.seal_finalized_at IS NULL
       AND r.seal_generation=0 AND r.attempt_count=0 AND r.claim_token IS NULL
       AND f.drafts=0
       -- The narrow owner lane admits no cross-session canonical family at all
       -- for a held source. Do not convert a non-temporal link into a time hull.
       AND NOT EXISTS(SELECT 1 FROM capture_events child JOIN capture_events parent
            ON parent.account_id=child.account_id AND parent.event_id=child.canonical_event_id
            WHERE child.account_id=s.account_id
              AND child.capture_session_id<>parent.capture_session_id
              AND (child.capture_session_id=s.id OR parent.capture_session_id=s.id))
       AND EXISTS(SELECT 1 FROM capture_streams stream
            WHERE stream.account_id=s.account_id AND stream.capture_session_id=s.id
              AND capture_formation_stream_contiguous_through(stream.account_id,stream.id)
                  <capture_formation_stream_accepted_max(stream.account_id,stream.id))
       AND NOT EXISTS(SELECT 1 FROM capture_formation_pages p
            WHERE p.account_id=s.account_id AND p.capture_session_id=s.id)
       AND NOT EXISTS(SELECT 1 FROM capture_events e JOIN media_processing_jobs j
            ON j.account_id=e.account_id AND j.event_id=e.event_id
            WHERE e.account_id=s.account_id AND e.capture_session_id=s.id
              AND j.state NOT IN ('succeeded','canceled','failed_terminal'))
       AND NOT EXISTS(SELECT 1 FROM capture_events e JOIN media_objects m
            ON m.account_id=e.account_id AND m.event_id=e.event_id
            WHERE e.account_id=s.account_id AND e.capture_session_id=s.id
              AND m.deleted_at IS NULL AND m.processing_state IN ('queued','processing','retry_wait'))
),
facts AS (
    SELECT (SELECT count(*)::bigint FROM unresolved) AS unsettled_sessions,
           (SELECT count(DISTINCT account_id)::bigint FROM unresolved) AS unsettled_accounts,
           (SELECT count(*)::bigint FROM eligible) AS isolated_historical_sessions,
           (SELECT count(*)::bigint FROM inventory) AS inventory_rows,
           (SELECT count(*)<=100000 FROM inventory) AS inventory_bounded,
           (SELECT count(*)::bigint FROM owners WHERE header_component IS NOT NULL
               AND (atoms=0 OR atoms<>members OR row_conflict)) AS blocked_drafts,
           (SELECT count(*)::bigint FROM component_facts
               WHERE drafts>0 AND (header_components>1 OR outside_owners>0)) AS conflicting_components
)
SELECT to_jsonb(facts)::text AS payload FROM facts;
