-- Complete conservative source graph. $1 is a tenant, or NULL for the fixed
-- aggregate audit. No content columns. Never use a truncated inventory.
WITH projection_events(account_id,kind,id,event_id) AS MATERIALIZED (
    SELECT account_id,'utterance',id,split_part(substr(source_key,10),':',1)
      FROM utterances WHERE ($1::text IS NULL OR account_id=$1) AND source_key LIKE 'cloud-v2:%'
    UNION SELECT u.account_id,'utterance',u.id,o.event_id FROM utterances u
      JOIN speaker_observations o ON o.account_id=u.account_id AND o.id=u.speaker_observation_id
     WHERE ($1::text IS NULL OR u.account_id=$1)
    UNION SELECT u.account_id,'utterance',u.id,o.event_id FROM utterances u
      JOIN speaker_observation_sources o
        ON o.account_id=u.account_id AND o.speaker_observation_id=u.speaker_observation_id
     WHERE ($1::text IS NULL OR u.account_id=$1)
    UNION SELECT account_id,'screenshot',id,substr(source_key,10)
      FROM screenshots WHERE ($1::text IS NULL OR account_id=$1) AND source_key LIKE 'cloud-v2:%'
    UNION SELECT account_id,'screenshot',screenshot_id,event_id FROM visual_speaker_observations
     WHERE ($1::text IS NULL OR account_id=$1)
),
all_atoms AS MATERIALIZED (
    SELECT u.account_id,'u:'||u.id AS key,'utterance'::text AS kind,u.id,
           a.started_at+u.start_offset_seconds*interval '1 second' AS started_at,
           greatest(a.started_at+u.end_offset_seconds*interval '1 second',
                    a.started_at+u.start_offset_seconds*interval '1 second') AS ended_at
      FROM utterances u JOIN audio_segments a
        ON a.account_id=u.account_id AND a.id=u.audio_segment_id
     WHERE ($1::text IS NULL OR u.account_id=$1)
    UNION ALL
    SELECT account_id,'s:'||id,'screenshot',id,captured_at,
           greatest(captured_at,visible_until)
      FROM screenshots WHERE ($1::text IS NULL OR account_id=$1)
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
     WHERE ($1::text IS NULL OR e.account_id=$1)
       AND e.structure_state='draft' AND e.finalized_at IS NULL
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
     WHERE ($1::text IS NULL OR s.account_id=$1)
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
     WHERE ($1::text IS NULL OR e.account_id=$1) AND h.id IS NOT NULL
     GROUP BY e.account_id,e.id,h.header_component,h.row_conflict
),
canonical_bridges AS MATERIALIZED (
    SELECT child.account_id,'r:'||child.event_id AS key,
           least(child_session.started_at,parent_session.started_at) AS started_at,
           greatest(child_session.ended_at,parent_session.ended_at) AS ended_at
      FROM capture_events child JOIN capture_events parent
        ON parent.account_id=child.account_id AND parent.event_id=child.canonical_event_id
      JOIN sessions child_session
        ON child_session.account_id=child.account_id AND child_session.id=child.capture_session_id
      JOIN sessions parent_session
        ON parent_session.account_id=parent.account_id AND parent_session.id=parent.capture_session_id
     WHERE ($1::text IS NULL OR child.account_id=$1)
       AND child.capture_session_id<>parent.capture_session_id
),
inventory AS MATERIALIZED (
    SELECT * FROM (
        SELECT account_id,'c:'||id AS key,started_at,ended_at FROM sessions
        UNION ALL SELECT account_id,key,started_at,ended_at FROM atoms
        UNION ALL SELECT account_id,'d:'||id,started_at,ended_at FROM owners
        UNION ALL SELECT account_id,key,started_at,ended_at FROM canonical_bridges
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
candidate_components AS MATERIALIZED (
    SELECT c.account_id,c.component,
           min(c.started_at) AS started_at,max(c.ended_at) AS ended_at,
           array_agg(o.id ORDER BY o.id) FILTER (WHERE o.id IS NOT NULL) AS draft_ids,
           count(o.id)::bigint AS drafts,
           count(*) FILTER (WHERE c.key LIKE 'u:%' OR c.key LIKE 's:%')::bigint AS atoms,
           count(*) FILTER (WHERE c.key LIKE 'c:%')::bigint AS sessions,
           count(o.id) FILTER (WHERE o.atoms=0 OR o.atoms<>o.members OR o.row_conflict)::bigint AS blocked_drafts
      FROM components c LEFT JOIN owners o
        ON o.account_id=c.account_id AND c.key='d:'||o.id
     GROUP BY c.account_id,c.component
    HAVING count(o.id)>0
)
