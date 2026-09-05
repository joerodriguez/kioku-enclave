WITH
bounds AS MATERIALIZED (
    SELECT $1::text AS raw_since,
           $1::timestamptz AS since_at,
           transaction_timestamp() AS observed_at,
           current_setting('transaction_read_only')::boolean AS transaction_read_only
),
valid AS MATERIALIZED (
    SELECT raw_since,since_at,observed_at,transaction_read_only
      FROM bounds
     WHERE since_at >= observed_at - interval '48 hours'
       AND since_at <= observed_at
),
active_accounts AS MATERIALIZED (
    SELECT account.id
      FROM accounts account
      CROSS JOIN valid
     WHERE account.status='active'
),

latest_activation AS MATERIALIZED (
    SELECT event.phase,event.generation,event.rollout_basis_points,
           event.explicit_canary_account_ids,
           cardinality(event.explicit_canary_account_ids)::bigint AS explicit_canary_count,
           event.applied_at
      FROM persistence_feature_activation_events event
      CROSS JOIN valid
     WHERE event.feature='episode_topology_reconciliation'
     ORDER BY event.event_sequence DESC
     LIMIT 1
),
latest_draining_activation AS MATERIALIZED (
    SELECT event.generation
      FROM persistence_feature_activation_events event
      CROSS JOIN valid
     WHERE event.feature='episode_topology_reconciliation'
       AND event.phase='draining'
     ORDER BY event.event_sequence DESC
     LIMIT 1
),
activation_backfill AS MATERIALIZED (
    SELECT backfill.refresh_generation,backfill.complete,backfill.rows_scanned,
           backfill.rows_inserted,backfill.rows_reopened,backfill.updated_at,
           backfill.completed_at
      FROM persistence_feature_activation_backfills backfill
      CROSS JOIN valid
     WHERE backfill.feature='episode_topology_reconciliation'
       AND backfill.backfill_name='capture_formation_receipts'
),
activation_drain AS MATERIALIZED (
    SELECT drain.complete,drain.claims_scanned,drain.claims_revoked,
           drain.updated_at,drain.completed_at
      FROM persistence_feature_activation_drains drain
      JOIN latest_draining_activation activation
        ON drain.feature='episode_topology_reconciliation'
       AND drain.activation_generation=activation.generation
),
activation_facts AS MATERIALIZED (
    SELECT EXISTS(SELECT 1 FROM latest_activation) AS present,
           (SELECT CASE WHEN phase IN ('installed','draining','active','paused')
                        THEN phase END FROM latest_activation) AS phase,
           (SELECT generation FROM latest_activation) AS generation,
           (SELECT rollout_basis_points FROM latest_activation) AS rollout_basis_points,
           (SELECT explicit_canary_count FROM latest_activation) AS explicit_canary_count,
           (SELECT floor(extract(epoch FROM applied_at)*1000)::bigint
              FROM latest_activation) AS applied_at_ms,
           (SELECT count(*)::bigint FROM active_accounts) AS active_accounts,
           (SELECT count(*)::bigint
              FROM persistence_feature_activation_assignments assignment
             WHERE assignment.feature='episode_topology_reconciliation') AS assignments,
           (SELECT count(*)::bigint
              FROM active_accounts account
             WHERE NOT EXISTS (
                 SELECT 1
                   FROM persistence_feature_activation_assignments assignment
                  WHERE assignment.feature='episode_topology_reconciliation'
                    AND assignment.account_id=account.id
             )) AS unassigned_active_accounts,
           EXISTS(SELECT 1 FROM activation_backfill) AS backfill_present,
           (SELECT refresh_generation FROM activation_backfill) AS backfill_refresh_generation,
           (SELECT complete FROM activation_backfill) AS backfill_complete,
           (SELECT rows_scanned FROM activation_backfill) AS backfill_rows_scanned,
           (SELECT rows_inserted FROM activation_backfill) AS backfill_rows_inserted,
           (SELECT rows_reopened FROM activation_backfill) AS backfill_rows_reopened,
           (SELECT floor(extract(epoch FROM updated_at)*1000)::bigint
              FROM activation_backfill) AS backfill_updated_at_ms,
           (SELECT floor(extract(epoch FROM completed_at)*1000)::bigint
              FROM activation_backfill) AS backfill_completed_at_ms,
           EXISTS(SELECT 1 FROM activation_drain) AS drain_present,
           (SELECT complete FROM activation_drain) AS drain_complete,
           (SELECT claims_scanned FROM activation_drain) AS drain_claims_scanned,
           (SELECT claims_revoked FROM activation_drain) AS drain_claims_revoked,
           (SELECT floor(extract(epoch FROM updated_at)*1000)::bigint
              FROM activation_drain) AS drain_updated_at_ms,
           (SELECT floor(extract(epoch FROM completed_at)*1000)::bigint
              FROM activation_drain) AS drain_completed_at_ms,
           (SELECT count(*)::bigint FROM episode_deletions deletion
             WHERE deletion.state='pending') AS pending_episode_deletions,
           (SELECT count(*)::bigint
              FROM episode_deletions deletion
              LEFT JOIN persistence_feature_episode_deletion_progress progress
                ON progress.account_id=deletion.account_id
               AND progress.episode_id=deletion.episode_id
             WHERE ((SELECT phase='installed' FROM latest_activation)
                    AND deletion.state='pending')
                OR ((SELECT phase<>'installed' FROM latest_activation)
                    AND deletion.state='pending'
                    AND (progress.account_id IS NULL OR progress.phase='complete'))
                OR (deletion.state='complete' AND progress.account_id IS NOT NULL
                    AND progress.phase<>'complete'))
               AS episode_deletion_coherence_violations,
           (SELECT count(*)::bigint
              FROM episodes episode
             WHERE episode.structure_state='draft'
               AND episode.finalization_claim_token IS NOT NULL
               AND ((SELECT rollout_basis_points=10000 FROM latest_activation)
                    OR episode.account_id IN (
                        SELECT unnest(explicit_canary_account_ids) FROM latest_activation
                    ))) AS scoped_draft_finalization_claims,
           (SELECT count(*)::bigint
              FROM persistence_feature_activation_events event
             WHERE event.feature='episode_topology_reconciliation'
               AND event.phase NOT IN ('installed','draining','active','paused'))
               AS domain_violation_count
),

capture_scope AS MATERIALIZED (
    SELECT event.stream_kind,event.media_disposition,event.started_at,event.ended_at
      FROM capture_events event
      CROSS JOIN valid audit_window
     WHERE event.received_at >= audit_window.since_at
       AND event.received_at <= audit_window.observed_at
),
capture_categories(stream_kind,media_disposition,ordinal) AS (
    VALUES
      ('mic','canonical',1),('mic','reference',2),
      ('system_audio','canonical',3),('system_audio','reference',4),
      ('mac_screen','canonical',5),('mac_screen','reference',6),
      ('ios_mic','canonical',7),('ios_mic','reference',8),
      ('ios_imported_screenshot','canonical',9),('ios_imported_screenshot','reference',10),
      ('ios_shared_page','canonical',11),('ios_shared_page','reference',12)
),
capture_group_rows AS MATERIALIZED (
    SELECT category.stream_kind,category.media_disposition,category.ordinal,
           count(event.stream_kind)::bigint AS count,
           floor(extract(epoch FROM min(event.started_at))*1000)::bigint
               AS first_started_at_ms,
           floor(extract(epoch FROM max(event.ended_at))*1000)::bigint
               AS last_ended_at_ms
      FROM capture_categories category
      LEFT JOIN capture_scope event
        ON event.stream_kind=category.stream_kind
       AND event.media_disposition=category.media_disposition
     GROUP BY category.stream_kind,category.media_disposition,category.ordinal
),
capture_facts AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'stream_kind',stream_kind,
               'media_disposition',media_disposition,
               'count',count,
               'first_started_at_ms',first_started_at_ms,
               'last_ended_at_ms',last_ended_at_ms
           ) ORDER BY ordinal) AS groups,
           (SELECT count(*)::bigint FROM capture_scope
             WHERE stream_kind NOT IN (
                       'mic','system_audio','mac_screen','ios_mic',
                       'ios_imported_screenshot','ios_shared_page')
                OR media_disposition NOT IN ('canonical','reference'))
               AS domain_violation_count
      FROM capture_group_rows
),

media_work_since_scope AS MATERIALIZED (
    SELECT work.account_id,work.id,work.work_class,work.state,
           work.reservation_retained,work.attempt_count,
           work.reserved_output_tokens,work.claim_token,work.claim_until,
           work.error_code,work.updated_at
      FROM media_work_units work
      CROSS JOIN valid audit_window
     WHERE work.updated_at >= audit_window.since_at
       AND work.updated_at <= audit_window.observed_at
),
media_work_unfinished_scope AS MATERIALIZED (
    SELECT work.account_id,work.id,work.work_class,work.state,
           work.reservation_retained,work.attempt_count,
           work.reserved_output_tokens,work.claim_token,work.claim_until,
           work.error_code,work.updated_at
      FROM media_work_units work
      CROSS JOIN valid
     WHERE work.state NOT IN ('succeeded','failed_terminal')
),
media_work_categories(work_class,state,reservation_retained,ordinal) AS (
    VALUES
      ('audio','planned',false,1),('audio','planned',true,2),
      ('audio','processing',false,3),('audio','processing',true,4),
      ('audio','retry_wait',false,5),('audio','retry_wait',true,6),
      ('audio','succeeded',false,7),('audio','succeeded',true,8),
      ('audio','failed_terminal',false,9),('audio','failed_terminal',true,10),
      ('screen','planned',false,11),('screen','planned',true,12),
      ('screen','processing',false,13),('screen','processing',true,14),
      ('screen','retry_wait',false,15),('screen','retry_wait',true,16),
      ('screen','succeeded',false,17),('screen','succeeded',true,18),
      ('screen','failed_terminal',false,19),('screen','failed_terminal',true,20)
),
media_work_since_aggregates AS MATERIALIZED (
    SELECT work_class,state,reservation_retained,count(*)::bigint AS count,
           coalesce(sum(attempt_count),0)::bigint AS attempt_count,
           coalesce(sum(reserved_output_tokens),0)::bigint AS reserved_output_tokens
      FROM media_work_since_scope
     GROUP BY work_class,state,reservation_retained
),
media_work_unfinished_aggregates AS MATERIALIZED (
    SELECT work_class,state,reservation_retained,count(*)::bigint AS count,
           coalesce(sum(attempt_count),0)::bigint AS attempt_count,
           coalesce(sum(reserved_output_tokens),0)::bigint AS reserved_output_tokens
      FROM media_work_unfinished_scope
     GROUP BY work_class,state,reservation_retained
),
media_work_since_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'work_class',category.work_class,
               'state',category.state,
               'reservation_retained',category.reservation_retained,
               'count',coalesce(aggregate.count,0),
               'attempt_count',coalesce(aggregate.attempt_count,0),
               'reserved_output_tokens',coalesce(aggregate.reserved_output_tokens,0)
           ) ORDER BY category.ordinal) AS groups
      FROM media_work_categories category
      LEFT JOIN media_work_since_aggregates aggregate
        USING(work_class,state,reservation_retained)
),
media_work_unfinished_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'work_class',category.work_class,
               'state',category.state,
               'reservation_retained',category.reservation_retained,
               'count',coalesce(aggregate.count,0),
               'attempt_count',coalesce(aggregate.attempt_count,0),
               'reserved_output_tokens',coalesce(aggregate.reserved_output_tokens,0)
           ) ORDER BY category.ordinal) AS groups
      FROM media_work_categories category
      LEFT JOIN media_work_unfinished_aggregates aggregate
        USING(work_class,state,reservation_retained)
),
media_job_since_scope AS MATERIALIZED (
    SELECT job.account_id,job.id,job.job_kind,job.state,job.attempt_count,
           job.lease_owner,job.lease_token,job.lease_until,job.error_code,job.updated_at
      FROM media_processing_jobs job
      CROSS JOIN valid audit_window
     WHERE job.updated_at >= audit_window.since_at
       AND job.updated_at <= audit_window.observed_at
),
media_job_unfinished_scope AS MATERIALIZED (
    SELECT job.account_id,job.id,job.job_kind,job.state,job.attempt_count,
           job.lease_owner,job.lease_token,job.lease_until,job.error_code,job.updated_at
      FROM media_processing_jobs job
      CROSS JOIN valid
     WHERE job.state NOT IN ('succeeded','failed_terminal','canceled')
),
media_job_categories(job_kind,state,ordinal) AS (
    VALUES
      ('gemini_audio','pending',1),('gemini_audio','processing',2),
      ('gemini_audio','retry_wait',3),('gemini_audio','succeeded',4),
      ('gemini_audio','failed_terminal',5),('gemini_audio','canceled',6),
      ('gemini_screen','pending',7),('gemini_screen','processing',8),
      ('gemini_screen','retry_wait',9),('gemini_screen','succeeded',10),
      ('gemini_screen','failed_terminal',11),('gemini_screen','canceled',12)
),
media_job_since_aggregates AS MATERIALIZED (
    SELECT job_kind,state,count(*)::bigint AS count,
           coalesce(sum(attempt_count),0)::bigint AS attempt_count
      FROM media_job_since_scope
     GROUP BY job_kind,state
),
media_job_unfinished_aggregates AS MATERIALIZED (
    SELECT job_kind,state,count(*)::bigint AS count,
           coalesce(sum(attempt_count),0)::bigint AS attempt_count
      FROM media_job_unfinished_scope
     GROUP BY job_kind,state
),
media_job_since_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'job_kind',category.job_kind,'state',category.state,
               'count',coalesce(aggregate.count,0),
               'attempt_count',coalesce(aggregate.attempt_count,0)
           ) ORDER BY category.ordinal) AS groups
      FROM media_job_categories category
      LEFT JOIN media_job_since_aggregates aggregate USING(job_kind,state)
),
media_job_unfinished_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'job_kind',category.job_kind,'state',category.state,
               'count',coalesce(aggregate.count,0),
               'attempt_count',coalesce(aggregate.attempt_count,0)
           ) ORDER BY category.ordinal) AS groups
      FROM media_job_categories category
      LEFT JOIN media_job_unfinished_aggregates aggregate USING(job_kind,state)
),
media_budget_per_account AS MATERIALIZED (
    SELECT job.account_id,count(*)::bigint AS count
      FROM media_job_unfinished_scope job
     WHERE job.state='retry_wait' AND job.error_code='vertex_daily_budget'
     GROUP BY job.account_id
),
media_facts AS MATERIALIZED (
    SELECT (SELECT groups FROM media_work_since_groups) AS work_units_since,
           (SELECT groups FROM media_work_unfinished_groups) AS work_units_unfinished,
           (SELECT groups FROM media_job_since_groups) AS jobs_since,
           (SELECT groups FROM media_job_unfinished_groups) AS jobs_unfinished,
           (SELECT count(*)::bigint
              FROM media_work_units work CROSS JOIN valid audit_window
             WHERE (work.updated_at BETWEEN audit_window.since_at AND audit_window.observed_at
                       OR work.state NOT IN ('succeeded','failed_terminal'))
               AND (work.work_class NOT IN ('audio','screen')
                    OR work.state NOT IN (
                       'planned','processing','retry_wait','succeeded','failed_terminal')))
               AS work_domain_violation_count,
           (SELECT count(*)::bigint
              FROM media_processing_jobs job CROSS JOIN valid audit_window
             WHERE (job.updated_at BETWEEN audit_window.since_at AND audit_window.observed_at
                       OR job.state NOT IN ('succeeded','failed_terminal','canceled'))
               AND (job.job_kind NOT IN ('gemini_audio','gemini_screen')
                    OR job.state NOT IN (
                       'pending','processing','retry_wait','succeeded',
                       'failed_terminal','canceled')))
               AS job_domain_violation_count,
           (SELECT count(*)::bigint FROM media_job_unfinished_scope
             WHERE error_code='vertex_daily_budget') AS current_budget_jobs,
           (SELECT count(*)::bigint FROM media_work_unfinished_scope
             WHERE error_code='vertex_daily_budget') AS current_budget_work_units,
           (SELECT count(DISTINCT (member.account_id,member.work_unit_id))::bigint
              FROM media_job_unfinished_scope job
              JOIN media_work_members member
                ON member.account_id=job.account_id AND member.job_id=job.id
             WHERE job.error_code='vertex_daily_budget') AS current_budget_distinct_work_units,
           (SELECT count(*)::bigint FROM media_job_unfinished_scope job CROSS JOIN valid audit_window
             WHERE job.state='retry_wait' AND job.error_code='vertex_daily_budget'
               AND job.updated_at<=audit_window.observed_at) AS budget_retry_due_jobs,
           (SELECT count(*)::bigint FROM media_job_unfinished_scope job CROSS JOIN valid audit_window
             WHERE job.state='retry_wait' AND job.error_code='vertex_daily_budget'
               AND job.updated_at>audit_window.observed_at) AS budget_retry_future_jobs,
           (SELECT count(*)::bigint FROM media_job_unfinished_scope job CROSS JOIN valid audit_window
             WHERE job.state='retry_wait' AND job.error_code='vertex_daily_budget'
               AND job.updated_at<audit_window.observed_at) AS budget_retry_past_due_jobs,
           (SELECT floor(extract(epoch FROM min(job.updated_at))*1000)::bigint
              FROM media_job_unfinished_scope job
             WHERE job.state='retry_wait' AND job.error_code='vertex_daily_budget')
               AS budget_retry_earliest_next_attempt_at_ms,
           (SELECT floor(extract(epoch FROM max(job.updated_at))*1000)::bigint
              FROM media_job_unfinished_scope job
             WHERE job.state='retry_wait' AND job.error_code='vertex_daily_budget')
               AS budget_retry_latest_next_attempt_at_ms,
           coalesce((SELECT max(count) FROM media_budget_per_account),0)::bigint
               AS budget_retry_max_jobs_per_account,
           (SELECT count(*)::bigint FROM media_job_unfinished_scope job CROSS JOIN valid audit_window
             WHERE job.state='processing' AND job.lease_until<=audit_window.observed_at)
               AS expired_processing_jobs,
           (SELECT count(*)::bigint FROM media_work_unfinished_scope work CROSS JOIN valid audit_window
             WHERE work.state='processing' AND work.claim_until<=audit_window.observed_at)
               AS expired_processing_work_units,
           (SELECT count(*)::bigint FROM media_job_unfinished_scope job
             WHERE (job.state='processing') <>
                   (job.lease_owner IS NOT NULL AND job.lease_token IS NOT NULL
                    AND job.lease_until IS NOT NULL)) AS inconsistent_processing_jobs,
           (SELECT count(*)::bigint FROM media_work_unfinished_scope work
             WHERE (work.state='processing') <>
                   (work.claim_token IS NOT NULL AND work.claim_until IS NOT NULL))
               AS inconsistent_processing_work_units,
           (SELECT count(*)::bigint FROM media_work_unfinished_scope work
             WHERE NOT EXISTS (
                 SELECT 1 FROM media_work_members member
                  WHERE member.account_id=work.account_id AND member.work_unit_id=work.id
             )) AS unfinished_work_without_members
),

formation_receipt_since_scope AS MATERIALIZED (
    SELECT receipt.account_id,receipt.capture_session_id,receipt.state,
           receipt.source_revision,receipt.completed_revision,receipt.attempt_count,
           receipt.claim_until,receipt.next_attempt_at,receipt.finish_requested_at,
           receipt.seal_finalized_at,receipt.updated_at
      FROM capture_formation_receipts receipt
      CROSS JOIN valid audit_window
     WHERE receipt.updated_at >= audit_window.since_at
       AND receipt.updated_at <= audit_window.observed_at
),
formation_receipt_unfinished_scope AS MATERIALIZED (
    SELECT receipt.account_id,receipt.capture_session_id,receipt.state,
           receipt.source_revision,receipt.completed_revision,receipt.attempt_count,
           receipt.claim_until,receipt.next_attempt_at,receipt.finish_requested_at,
           receipt.seal_finalized_at,receipt.updated_at
      FROM capture_formation_receipts receipt
      CROSS JOIN valid
     WHERE receipt.source_revision>receipt.completed_revision
),
formation_receipt_categories(state,ordinal) AS (
    VALUES ('pending',1),('processing',2),('retry_wait',3),('complete',4)
),
formation_receipt_since_aggregates AS MATERIALIZED (
    SELECT state,count(*)::bigint AS count,
           coalesce(sum(attempt_count),0)::bigint AS attempt_count,
           coalesce(sum(source_revision-completed_revision),0)::bigint
               AS outstanding_revisions
      FROM formation_receipt_since_scope GROUP BY state
),
formation_receipt_unfinished_aggregates AS MATERIALIZED (
    SELECT state,count(*)::bigint AS count,
           coalesce(sum(attempt_count),0)::bigint AS attempt_count,
           coalesce(sum(source_revision-completed_revision),0)::bigint
               AS outstanding_revisions
      FROM formation_receipt_unfinished_scope GROUP BY state
),
formation_receipt_since_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'state',category.state,'count',coalesce(aggregate.count,0),
               'attempt_count',coalesce(aggregate.attempt_count,0),
               'outstanding_revisions',coalesce(aggregate.outstanding_revisions,0)
           ) ORDER BY category.ordinal) AS groups
      FROM formation_receipt_categories category
      LEFT JOIN formation_receipt_since_aggregates aggregate USING(state)
),
formation_receipt_unfinished_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'state',category.state,'count',coalesce(aggregate.count,0),
               'attempt_count',coalesce(aggregate.attempt_count,0),
               'outstanding_revisions',coalesce(aggregate.outstanding_revisions,0)
           ) ORDER BY category.ordinal) AS groups
      FROM formation_receipt_categories category
      LEFT JOIN formation_receipt_unfinished_aggregates aggregate USING(state)
),
formation_page_since_scope AS MATERIALIZED (
    SELECT page.account_id,page.capture_session_id,page.source_revision,page.state,
           page.claim_until,page.provider_attempt,page.covered_utterance_ids,
           page.covered_screenshot_ids,(page.staged_response IS NOT NULL) AS staged_response,
           page.updated_at
      FROM capture_formation_pages page
      CROSS JOIN valid audit_window
     WHERE page.updated_at >= audit_window.since_at
       AND page.updated_at <= audit_window.observed_at
),
formation_page_unfinished_scope AS MATERIALIZED (
    SELECT page.account_id,page.capture_session_id,page.source_revision,page.state,
           page.claim_until,page.provider_attempt,page.covered_utterance_ids,
           page.covered_screenshot_ids,(page.staged_response IS NOT NULL) AS staged_response,
           page.updated_at
      FROM capture_formation_pages page
      CROSS JOIN valid
     WHERE page.state NOT IN ('complete','invalidated')
),
formation_page_categories(state,ordinal) AS (
    VALUES ('processing',1),('retry_wait',2),('complete',3),('invalidated',4)
),
formation_page_since_aggregates AS MATERIALIZED (
    SELECT state,count(*)::bigint AS count,
           coalesce(sum(provider_attempt),0)::bigint AS provider_attempts,
           coalesce(sum(cardinality(covered_utterance_ids)),0)::bigint AS covered_utterances,
           coalesce(sum(cardinality(covered_screenshot_ids)),0)::bigint AS covered_screenshots,
           count(*) FILTER (WHERE staged_response)::bigint AS staged_responses
      FROM formation_page_since_scope GROUP BY state
),
formation_page_unfinished_aggregates AS MATERIALIZED (
    SELECT state,count(*)::bigint AS count,
           coalesce(sum(provider_attempt),0)::bigint AS provider_attempts,
           coalesce(sum(cardinality(covered_utterance_ids)),0)::bigint AS covered_utterances,
           coalesce(sum(cardinality(covered_screenshot_ids)),0)::bigint AS covered_screenshots,
           count(*) FILTER (WHERE staged_response)::bigint AS staged_responses
      FROM formation_page_unfinished_scope GROUP BY state
),
formation_page_since_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'state',category.state,'count',coalesce(aggregate.count,0),
               'provider_attempts',coalesce(aggregate.provider_attempts,0),
               'covered_utterances',coalesce(aggregate.covered_utterances,0),
               'covered_screenshots',coalesce(aggregate.covered_screenshots,0),
               'staged_responses',coalesce(aggregate.staged_responses,0)
           ) ORDER BY category.ordinal) AS groups
      FROM formation_page_categories category
      LEFT JOIN formation_page_since_aggregates aggregate USING(state)
),
formation_page_unfinished_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'state',category.state,'count',coalesce(aggregate.count,0),
               'provider_attempts',coalesce(aggregate.provider_attempts,0),
               'covered_utterances',coalesce(aggregate.covered_utterances,0),
               'covered_screenshots',coalesce(aggregate.covered_screenshots,0),
               'staged_responses',coalesce(aggregate.staged_responses,0)
           ) ORDER BY category.ordinal) AS groups
      FROM formation_page_categories category
      LEFT JOIN formation_page_unfinished_aggregates aggregate USING(state)
),
formation_facts AS MATERIALIZED (
    SELECT (SELECT groups FROM formation_receipt_since_groups) AS receipts_since,
           (SELECT groups FROM formation_receipt_unfinished_groups) AS receipts_unfinished,
           (SELECT groups FROM formation_page_since_groups) AS pages_since,
           (SELECT groups FROM formation_page_unfinished_groups) AS pages_unfinished,
           (SELECT count(*)::bigint
              FROM capture_formation_receipts receipt CROSS JOIN valid audit_window
             WHERE (receipt.updated_at BETWEEN audit_window.since_at AND audit_window.observed_at
                       OR receipt.source_revision>receipt.completed_revision)
               AND receipt.state NOT IN ('pending','processing','retry_wait','complete'))
               AS receipt_domain_violation_count,
           (SELECT count(*)::bigint
              FROM capture_formation_pages page CROSS JOIN valid audit_window
             WHERE (page.updated_at BETWEEN audit_window.since_at AND audit_window.observed_at
                       OR page.state NOT IN ('complete','invalidated'))
               AND page.state NOT IN ('processing','retry_wait','complete','invalidated'))
               AS page_domain_violation_count,
           (SELECT count(*)::bigint FROM formation_receipt_unfinished_scope
             WHERE finish_requested_at IS NOT NULL) AS finished_dirty_receipts,
           (SELECT count(*)::bigint
              FROM formation_receipt_unfinished_scope receipt
              JOIN capture_sessions session
                ON session.account_id=receipt.account_id
               AND session.id=receipt.capture_session_id
             WHERE session.ended_at IS NOT NULL AND receipt.finish_requested_at IS NULL)
               AS ended_without_finish_receipts,
           (SELECT count(*)::bigint FROM capture_formation_receipts
             WHERE finish_requested_at IS NOT NULL AND seal_finalized_at IS NULL)
               AS seal_pending_receipts,
           (SELECT count(DISTINCT account_id)::bigint FROM (
                SELECT receipt.account_id FROM capture_formation_receipts receipt
                 WHERE receipt.source_revision<>receipt.completed_revision
                    OR receipt.state<>'complete'
                    OR (receipt.finish_requested_at IS NOT NULL
                        AND receipt.seal_finalized_at IS NULL)
                UNION
                SELECT session.account_id FROM capture_sessions session
                 LEFT JOIN capture_formation_receipts receipt
                   ON receipt.account_id=session.account_id
                  AND receipt.capture_session_id=session.id
                 WHERE session.ended_at IS NOT NULL AND (
                       receipt.account_id IS NULL
                       OR receipt.state<>'complete'
                       OR receipt.completed_revision<>receipt.source_revision
                       OR receipt.finish_requested_at IS NULL
                       OR receipt.seal_finalized_at IS NULL
                       OR receipt.seal_generation<1
                       OR NOT EXISTS(
                           SELECT 1 FROM capture_formation_seal_events seal
                            WHERE seal.account_id=receipt.account_id
                              AND seal.capture_session_id=receipt.capture_session_id
                              AND seal.seal_generation=receipt.seal_generation
                              AND seal.source_revision=receipt.source_revision
                              AND seal.event_kind='seal'
                              AND seal.stream_maxima_sha256=
                                  capture_formation_stream_maxima_sha256(
                                      receipt.account_id,receipt.capture_session_id))
                       OR EXISTS(
                           SELECT 1 FROM capture_formation_seal_events reopen
                            WHERE reopen.account_id=receipt.account_id
                              AND reopen.capture_session_id=receipt.capture_session_id
                              AND reopen.seal_generation=receipt.seal_generation
                              AND reopen.event_kind='reopen')
                       OR NOT EXISTS(
                           SELECT 1 FROM capture_streams stream
                            WHERE stream.account_id=session.account_id
                              AND stream.capture_session_id=session.id)
                       OR EXISTS(
                           SELECT 1 FROM capture_streams stream
                            WHERE stream.account_id=session.account_id
                              AND stream.capture_session_id=session.id
                              AND (stream.sealed_sequence IS NULL
                                   OR stream.committed_through_sequence<>
                                      stream.sealed_sequence
                                   OR stream.committed_through_sequence IS DISTINCT FROM
                                      capture_formation_stream_accepted_max(
                                          stream.account_id,stream.id)
                                   OR stream.committed_through_sequence IS DISTINCT FROM
                                      capture_formation_stream_contiguous_through(
                                          stream.account_id,stream.id)))
                 )
           ) unresolved) AS unresolved_source_accounts,
           (SELECT count(*)::bigint FROM formation_receipt_unfinished_scope receipt
              CROSS JOIN valid audit_window
             WHERE receipt.state='retry_wait'
               AND receipt.next_attempt_at<=audit_window.observed_at) AS retry_due_receipts,
           (SELECT count(*)::bigint FROM formation_receipt_unfinished_scope receipt
              CROSS JOIN valid audit_window
             WHERE receipt.state='retry_wait'
               AND receipt.next_attempt_at>audit_window.observed_at) AS retry_future_receipts,
           (SELECT count(*)::bigint FROM formation_receipt_unfinished_scope receipt
              CROSS JOIN valid audit_window
             WHERE receipt.state='processing'
               AND receipt.claim_until<=audit_window.observed_at) AS expired_processing_receipts,
           (SELECT count(*)::bigint
              FROM formation_page_unfinished_scope page
              JOIN capture_formation_receipts receipt
                ON receipt.account_id=page.account_id
               AND receipt.capture_session_id=page.capture_session_id
               AND receipt.source_revision=page.source_revision
             WHERE receipt.finish_requested_at IS NOT NULL)
               AS nonterminal_pages_for_finished_receipts,
           (SELECT count(*)::bigint FROM capture_formation_pages
             WHERE staged_response IS NOT NULL) AS staged_response_pages,
           (SELECT count(*)::bigint FROM summary_window_claims
             WHERE state='processing') AS legacy_processing_claims,
           (SELECT count(*)::bigint FROM summary_window_claims claim CROSS JOIN valid audit_window
             WHERE claim.state='processing' AND claim.claim_until<=audit_window.observed_at)
               AS legacy_expired_claims,
           (SELECT count(*)::bigint FROM summary_window_claims
             WHERE state='retry_wait') AS legacy_retry_due_claims,
           0::bigint AS legacy_retry_future_claims,
           (SELECT count(*)::bigint FROM summary_window_claims
             WHERE state='retry_wait'
               AND error_code IN ('vertex_daily_budget','vertex_quota'))
               AS legacy_budget_error_claims
),

reconciliation_job_since_scope AS MATERIALIZED (
    SELECT job.account_id,job.source_fingerprint,job.state,job.attempt_count,
           job.model_attempt_count,job.predecessor_episode_ids,job.claim_until,
           job.next_attempt_at,job.updated_at
      FROM memory_reconciliation_jobs job
      CROSS JOIN valid audit_window
     WHERE job.updated_at >= audit_window.since_at
       AND job.updated_at <= audit_window.observed_at
),
reconciliation_job_unfinished_scope AS MATERIALIZED (
    SELECT job.account_id,job.source_fingerprint,job.state,job.attempt_count,
           job.model_attempt_count,job.predecessor_episode_ids,job.claim_until,
           job.next_attempt_at,job.updated_at
      FROM memory_reconciliation_jobs job
      CROSS JOIN valid
     WHERE job.state NOT IN ('complete','failed_terminal')
),
reconciliation_categories(state,ordinal) AS (
    VALUES ('pending',1),('processing',2),('retry_wait',3),('complete',4),('failed_terminal',5)
),
reconciliation_since_aggregates AS MATERIALIZED (
    SELECT state,count(*)::bigint AS count,
           coalesce(sum(attempt_count),0)::bigint AS attempt_count,
           coalesce(sum(model_attempt_count),0)::bigint AS model_attempt_count,
           coalesce(sum(cardinality(predecessor_episode_ids)),0)::bigint AS predecessor_count
      FROM reconciliation_job_since_scope GROUP BY state
),
reconciliation_unfinished_aggregates AS MATERIALIZED (
    SELECT state,count(*)::bigint AS count,
           coalesce(sum(attempt_count),0)::bigint AS attempt_count,
           coalesce(sum(model_attempt_count),0)::bigint AS model_attempt_count,
           coalesce(sum(cardinality(predecessor_episode_ids)),0)::bigint AS predecessor_count
      FROM reconciliation_job_unfinished_scope GROUP BY state
),
reconciliation_since_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'state',category.state,'count',coalesce(aggregate.count,0),
               'attempt_count',coalesce(aggregate.attempt_count,0),
               'model_attempt_count',coalesce(aggregate.model_attempt_count,0),
               'predecessor_count',coalesce(aggregate.predecessor_count,0)
           ) ORDER BY category.ordinal) AS groups
      FROM reconciliation_categories category
      LEFT JOIN reconciliation_since_aggregates aggregate USING(state)
),
reconciliation_unfinished_groups AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'state',category.state,'count',coalesce(aggregate.count,0),
               'attempt_count',coalesce(aggregate.attempt_count,0),
               'model_attempt_count',coalesce(aggregate.model_attempt_count,0),
               'predecessor_count',coalesce(aggregate.predecessor_count,0)
           ) ORDER BY category.ordinal) AS groups
      FROM reconciliation_categories category
      LEFT JOIN reconciliation_unfinished_aggregates aggregate USING(state)
),
candidate_draft_rows AS MATERIALIZED (
    SELECT episode.account_id,episode.started_at,episode.ended_at,
           max(episode.ended_at) OVER (
               PARTITION BY episode.account_id
               ORDER BY episode.started_at,episode.ended_at
               ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
           ) AS prior_max_ended_at
      FROM episodes episode
      JOIN memory_handles handle
        ON handle.account_id=episode.account_id AND handle.episode_id=episode.id
       AND handle.state='active'
      JOIN active_accounts account ON account.id=episode.account_id
     WHERE episode.structure_state='draft' AND episode.substance!='none'
),
candidate_draft_marked AS MATERIALIZED (
    SELECT account_id,started_at,ended_at,
           CASE WHEN prior_max_ended_at IS NULL
                       OR started_at>prior_max_ended_at+interval '4 hours'
                  THEN 1 ELSE 0 END AS new_component
      FROM candidate_draft_rows
),
candidate_draft_components AS MATERIALIZED (
    SELECT account_id,started_at,ended_at,
           sum(new_component) OVER (
               PARTITION BY account_id ORDER BY started_at,ended_at
               ROWS UNBOUNDED PRECEDING
           ) AS component
      FROM candidate_draft_marked
),
candidate_component_sizes AS MATERIALIZED (
    SELECT account_id,component,count(*)::bigint AS drafts
      FROM candidate_draft_components
     GROUP BY account_id,component
),
reconciliation_facts AS MATERIALIZED (
    SELECT (SELECT groups FROM reconciliation_since_groups) AS jobs_since,
           (SELECT groups FROM reconciliation_unfinished_groups) AS jobs_unfinished,
           (SELECT count(*)::bigint
              FROM memory_reconciliation_jobs job CROSS JOIN valid audit_window
             WHERE (job.updated_at BETWEEN audit_window.since_at AND audit_window.observed_at
                       OR job.state NOT IN ('complete','failed_terminal'))
               AND job.state NOT IN (
                   'pending','processing','retry_wait','complete','failed_terminal'))
               AS job_domain_violation_count,
           (SELECT count(*)::bigint FROM reconciliation_job_unfinished_scope job
              CROSS JOIN valid audit_window
             WHERE job.state='retry_wait' AND job.next_attempt_at<=audit_window.observed_at)
               AS retry_due_jobs,
           (SELECT count(*)::bigint FROM reconciliation_job_unfinished_scope job
              CROSS JOIN valid audit_window
             WHERE job.state='retry_wait' AND job.next_attempt_at>audit_window.observed_at)
               AS retry_future_jobs,
           (SELECT count(*)::bigint FROM reconciliation_job_unfinished_scope job
              CROSS JOIN valid audit_window
             WHERE job.state='processing' AND job.claim_until<=audit_window.observed_at)
               AS expired_processing_jobs,
           (SELECT count(*)::bigint FROM memory_reconciliation_stages) AS staged_rows,
           (SELECT count(*)::bigint
              FROM memory_reconciliation_stages stage
              LEFT JOIN memory_reconciliation_jobs job
                ON job.account_id=stage.account_id
               AND job.source_fingerprint=stage.source_fingerprint
             WHERE job.source_fingerprint IS NULL OR job.state<>'processing')
               AS stage_without_authoritative_job,
           (SELECT count(*)::bigint FROM candidate_draft_rows) AS candidate_drafts,
           (SELECT count(*)::bigint FROM candidate_component_sizes) AS candidate_components,
           coalesce((SELECT max(drafts) FROM candidate_component_sizes),0)::bigint
               AS max_drafts_per_component,
           (SELECT count(*)::bigint FROM candidate_component_sizes WHERE drafts>32)
               AS components_over_32
),

topology_categories(relation,ordinal) AS (
    VALUES ('merge',1),('split',2),('repartition',3)
),
topology_scope AS MATERIALIZED (
    SELECT handle.origin_relation,handle.account_id,handle.reconciliation_id
      FROM memory_handles handle
      JOIN memory_reconciliations reconciliation
        ON reconciliation.account_id=handle.account_id
       AND reconciliation.id=handle.reconciliation_id
      CROSS JOIN valid audit_window
     WHERE reconciliation.committed_at >= audit_window.since_at
       AND reconciliation.committed_at <= audit_window.observed_at
),
topology_aggregates AS MATERIALIZED (
    SELECT origin_relation,
           count(DISTINCT (account_id,reconciliation_id))::bigint AS count
      FROM topology_scope GROUP BY origin_relation
),
topology_facts AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'relation',category.relation,'count',coalesce(aggregate.count,0)
           ) ORDER BY category.ordinal) AS groups,
           (SELECT count(*)::bigint FROM topology_scope
             WHERE origin_relation NOT IN ('merge','split','repartition'))
               AS domain_violation_count
      FROM topology_categories category
      LEFT JOIN topology_aggregates aggregate
        ON aggregate.origin_relation=category.relation
),

vertex_scope AS MATERIALIZED (
    SELECT event.operation,event.outcome,event.output_text_tokens,
           event.thought_tokens,event.total_tokens
      FROM vertex_usage_events event
      CROSS JOIN valid audit_window
     WHERE event.observed_at >= audit_window.since_at
       AND event.observed_at <= audit_window.observed_at
),
vertex_categories(operation,outcome,ordinal) AS (
    VALUES
      ('audio_understanding','started',1),('audio_understanding','metered',2),
      ('audio_understanding','usage_missing',3),('audio_understanding','ambiguous',4),
      ('audio_understanding','not_billed',5),
      ('screen_understanding','started',6),('screen_understanding','metered',7),
      ('screen_understanding','usage_missing',8),('screen_understanding','ambiguous',9),
      ('screen_understanding','not_billed',10),
      ('episode_summarization','started',11),('episode_summarization','metered',12),
      ('episode_summarization','usage_missing',13),('episode_summarization','ambiguous',14),
      ('episode_summarization','not_billed',15),
      ('episode_finalization','started',16),('episode_finalization','metered',17),
      ('episode_finalization','usage_missing',18),('episode_finalization','ambiguous',19),
      ('episode_finalization','not_billed',20),
      ('episode_reconciliation','started',21),('episode_reconciliation','metered',22),
      ('episode_reconciliation','usage_missing',23),('episode_reconciliation','ambiguous',24),
      ('episode_reconciliation','not_billed',25)
),
vertex_aggregates AS MATERIALIZED (
    SELECT operation,outcome,count(*)::bigint AS count,
           coalesce(sum(output_text_tokens),0)::bigint AS output_text_tokens,
           coalesce(sum(thought_tokens),0)::bigint AS thought_tokens,
           coalesce(sum(total_tokens),0)::bigint AS total_tokens
      FROM vertex_scope GROUP BY operation,outcome
),
vertex_facts AS MATERIALIZED (
    SELECT jsonb_agg(jsonb_build_object(
               'operation',category.operation,'outcome',category.outcome,
               'count',coalesce(aggregate.count,0),
               'output_text_tokens',coalesce(aggregate.output_text_tokens,0),
               'thought_tokens',coalesce(aggregate.thought_tokens,0),
               'total_tokens',coalesce(aggregate.total_tokens,0)
           ) ORDER BY category.ordinal) AS groups,
           (SELECT count(*)::bigint FROM vertex_scope
             WHERE operation NOT IN (
                       'audio_understanding','screen_understanding',
                       'episode_summarization','episode_finalization',
                       'episode_reconciliation')
                OR outcome NOT IN (
                       'started','metered','usage_missing','ambiguous','not_billed'))
               AS domain_violation_count
      FROM vertex_categories category
      LEFT JOIN vertex_aggregates aggregate USING(operation,outcome)
),

-- Model-provider authority is not a calendar-day quota projection. A debit
-- can precede failed admission or a deduplicated attempt; never refund it or
-- synthesize a provider outcome to infer quiescence. Count raw authority even
-- for inactive accounts, expired leases, or terminal-looking residual claims.
provider_activity_facts AS MATERIALIZED (
    SELECT (SELECT count(*)::bigint FROM vertex_usage_events
             WHERE outcome='started') AS started_intents,
           (SELECT count(*)::bigint FROM media_work_units
             WHERE state='processing' OR claim_token IS NOT NULL OR claim_until IS NOT NULL)
               AS media_work_claims,
           (SELECT count(*)::bigint FROM media_processing_jobs
             WHERE state='processing' OR lease_token IS NOT NULL
                OR lease_owner IS NOT NULL OR lease_until IS NOT NULL) AS media_job_claims,
           (SELECT count(*)::bigint FROM summary_window_claims
             WHERE state='processing' OR claim_token IS NOT NULL OR claim_until IS NOT NULL)
               AS summary_claims,
           (SELECT count(*)::bigint FROM capture_formation_receipts
             WHERE state='processing' OR claim_token IS NOT NULL OR claim_until IS NOT NULL
                OR claimed_revision IS NOT NULL OR claimed_source_fingerprint IS NOT NULL)
               AS formation_receipt_claims,
           (SELECT count(*)::bigint FROM capture_formation_pages
             WHERE state='processing' OR claim_token IS NOT NULL OR claim_until IS NOT NULL)
               AS formation_page_claims,
           (SELECT count(*)::bigint FROM memory_reconciliation_jobs
             WHERE state='processing' OR claim_token IS NOT NULL OR claim_until IS NOT NULL)
               AS reconciliation_claims,
           (SELECT count(*)::bigint FROM episodes
             WHERE finalization_status='processing' OR finalization_claim_token IS NOT NULL
                OR finalization_claim_until IS NOT NULL) AS finalization_claims
      FROM valid
),

usage_scope AS MATERIALIZED (
    SELECT usage.account_id,usage.vertex_requests,usage.vertex_output_tokens,
           usage.vertex_audio_output_tokens,usage.vertex_screen_output_tokens,
           usage.vertex_derived_output_tokens
      FROM usage_daily usage
      CROSS JOIN valid audit_window
     WHERE usage.day=(audit_window.since_at AT TIME ZONE 'UTC')::date
),
active_usage AS MATERIALIZED (
    SELECT account.id AS account_id,
           coalesce(usage.vertex_requests,0)::bigint AS vertex_requests,
           coalesce(usage.vertex_output_tokens,0)::bigint AS vertex_output_tokens,
           coalesce(usage.vertex_audio_output_tokens,0)::bigint AS audio_tokens,
           coalesce(usage.vertex_screen_output_tokens,0)::bigint AS screen_tokens,
           coalesce(usage.vertex_derived_output_tokens,0)::bigint AS derived_tokens
      FROM active_accounts account
      LEFT JOIN usage_scope usage ON usage.account_id=account.id
),
provider_day AS MATERIALIZED (
    SELECT event.account_id,
           CASE WHEN event.operation='audio_understanding' THEN 'audio'
                WHEN event.operation='screen_understanding' THEN 'screen'
                WHEN event.operation IN (
                    'episode_summarization','episode_finalization','episode_reconciliation')
                THEN 'derived' END AS class,
           count(*)::bigint AS admitted,
           count(*) FILTER (WHERE event.outcome<>'started')::bigint AS terminal,
           count(*) FILTER (WHERE event.outcome='started')::bigint AS pending_started,
           count(*) FILTER (WHERE event.outcome IN (
               'metered','usage_missing','ambiguous'))::bigint AS possible_billed
      FROM vertex_usage_events event
      CROSS JOIN valid audit_window
     WHERE event.observed_at >= date_trunc('day',audit_window.since_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
       AND event.observed_at < (date_trunc('day',audit_window.since_at AT TIME ZONE 'UTC')
                                + interval '1 day') AT TIME ZONE 'UTC'
       AND event.observed_at <= audit_window.observed_at
       AND event.operation IN (
           'audio_understanding','screen_understanding','episode_summarization',
           'episode_finalization','episode_reconciliation')
     GROUP BY event.account_id,class
),
usage_categories(class,token_limit,quantum,ordinal) AS (
    VALUES ('audio',1310720::bigint,4096::bigint,1),
           ('screen',655360::bigint,1024::bigint,2),
           ('derived',655360::bigint,8192::bigint,3)
),
usage_class_account AS MATERIALIZED (
    SELECT category.class,category.token_limit,category.quantum,category.ordinal,
           usage.account_id,
           CASE category.class WHEN 'audio' THEN usage.audio_tokens
                               WHEN 'screen' THEN usage.screen_tokens
                               ELSE usage.derived_tokens END::bigint AS used_tokens,
           coalesce(provider.admitted,0)::bigint AS admitted,
           coalesce(provider.terminal,0)::bigint AS terminal,
           coalesce(provider.pending_started,0)::bigint AS pending_started,
           coalesce(provider.possible_billed,0)::bigint AS possible_billed
      FROM usage_categories category
      CROSS JOIN active_usage usage
      LEFT JOIN provider_day provider
        ON provider.account_id=usage.account_id AND provider.class=category.class
),
usage_class_aggregates AS MATERIALIZED (
    SELECT category.class,category.token_limit,category.quantum,category.ordinal,
           coalesce((SELECT sum(CASE category.class
                                  WHEN 'audio' THEN usage.vertex_audio_output_tokens
                                  WHEN 'screen' THEN usage.vertex_screen_output_tokens
                                  ELSE usage.vertex_derived_output_tokens END)::bigint
                       FROM usage_scope usage),0)::bigint AS used_tokens,
           coalesce((SELECT sum(account.used_tokens/category.quantum)::bigint
                       FROM usage_class_account account
                      WHERE account.class=category.class),0)::bigint AS reservation_slots,
           coalesce((SELECT max(account.used_tokens)::bigint
                       FROM usage_class_account account
                      WHERE account.class=category.class),0)::bigint
               AS max_used_tokens_per_active_account,
           coalesce((SELECT min(greatest(category.token_limit-account.used_tokens,0))::bigint
                       FROM usage_class_account account
                      WHERE account.class=category.class),category.token_limit)::bigint
               AS minimum_remaining_tokens_per_active_account,
           coalesce((SELECT min(greatest(category.token_limit-account.used_tokens,0)/category.quantum)::bigint
                       FROM usage_class_account account
                      WHERE account.class=category.class),category.token_limit/category.quantum)::bigint
               AS minimum_remaining_slots_per_active_account,
           (SELECT count(*)::bigint FROM usage_class_account account
             WHERE account.class=category.class AND account.used_tokens>=category.token_limit)
               AS accounts_at_or_over_limit,
           (SELECT count(*)::bigint FROM usage_scope usage
             WHERE (CASE category.class
                      WHEN 'audio' THEN usage.vertex_audio_output_tokens
                      WHEN 'screen' THEN usage.vertex_screen_output_tokens
                      ELSE usage.vertex_derived_output_tokens END)%category.quantum<>0)
               AS nondivisible_rows,
           coalesce((SELECT sum(account.admitted)::bigint FROM usage_class_account account
                       WHERE account.class=category.class),0)::bigint AS admitted_event_rows,
           coalesce((SELECT sum(account.terminal)::bigint FROM usage_class_account account
                       WHERE account.class=category.class),0)::bigint AS terminal_event_rows,
           coalesce((SELECT sum(account.pending_started)::bigint FROM usage_class_account account
                       WHERE account.class=category.class),0)::bigint AS pending_started_rows,
           coalesce((SELECT sum(account.possible_billed)::bigint FROM usage_class_account account
                       WHERE account.class=category.class),0)::bigint AS possible_billed_rows,
           coalesce((SELECT sum(greatest(account.used_tokens/category.quantum-account.admitted,0))::bigint
                       FROM usage_class_account account
                      WHERE account.class=category.class),0)::bigint AS unmatched_reservations,
           coalesce((SELECT sum(greatest(account.admitted-account.used_tokens/category.quantum,0))::bigint
                       FROM usage_class_account account
                      WHERE account.class=category.class),0)::bigint AS event_overhang,
           (SELECT count(*)::bigint FROM usage_class_account account
             WHERE account.class=category.class
               AND account.used_tokens/category.quantum>account.admitted)
               AS accounts_with_unmatched_reservations,
           coalesce((SELECT max(greatest(account.used_tokens/category.quantum-account.admitted,0))::bigint
                       FROM usage_class_account account
                      WHERE account.class=category.class),0)::bigint
               AS max_unmatched_reservations_per_account
      FROM usage_categories category
),
usage_facts AS MATERIALIZED (
    SELECT (SELECT count(*)::bigint FROM active_accounts) AS active_accounts,
           (SELECT count(*)::bigint FROM usage_scope) AS usage_rows,
           coalesce((SELECT sum(vertex_requests)::bigint FROM usage_scope),0)::bigint
               AS vertex_requests,
           coalesce((SELECT sum(vertex_output_tokens)::bigint FROM usage_scope),0)::bigint
               AS vertex_output_tokens,
           coalesce((SELECT sum(vertex_audio_output_tokens+vertex_screen_output_tokens+
                               vertex_derived_output_tokens)::bigint FROM usage_scope),0)::bigint
               AS class_output_tokens,
           (SELECT count(*)::bigint FROM usage_scope
             WHERE vertex_output_tokens<>
                   vertex_audio_output_tokens+vertex_screen_output_tokens+
                   vertex_derived_output_tokens) AS total_mismatch_rows,
           (SELECT count(*)::bigint FROM usage_scope
             WHERE vertex_requests<>
                   vertex_audio_output_tokens/4096+
                   vertex_screen_output_tokens/1024+
                   vertex_derived_output_tokens/8192) AS request_slot_mismatch_rows,
           jsonb_agg(jsonb_build_object(
               'class',class,'token_limit',token_limit,'quantum',quantum,
               'slot_limit',token_limit/quantum,'used_tokens',used_tokens,
               'reservation_slots',reservation_slots,
               'max_used_tokens_per_active_account',max_used_tokens_per_active_account,
               'minimum_remaining_tokens_per_active_account',minimum_remaining_tokens_per_active_account,
               'minimum_remaining_slots_per_active_account',minimum_remaining_slots_per_active_account,
               'accounts_at_or_over_limit',accounts_at_or_over_limit,
               'nondivisible_rows',nondivisible_rows,
               'admitted_event_rows',admitted_event_rows,
               'terminal_event_rows',terminal_event_rows,
               'pending_started_rows',pending_started_rows,
               'possible_billed_rows',possible_billed_rows,
               'unmatched_reservations',unmatched_reservations,
               'event_overhang',event_overhang,
               'accounts_with_unmatched_reservations',accounts_with_unmatched_reservations,
               'max_unmatched_reservations_per_account',max_unmatched_reservations_per_account
           ) ORDER BY ordinal) AS classes
      FROM usage_class_aggregates
),

finalization_scope AS MATERIALIZED (
    SELECT episode.account_id,episode.structure_state,episode.substance,
           episode.finalized_at,episode.finalization_version,
           episode.finalization_status,episode.finalization_attempt_count,
           episode.finalization_next_attempt_at,episode.finalization_claim_token,
           episode.finalization_claim_until,episode.identity_revision,
           episode.finalized_identity_revision
      FROM episodes episode
      JOIN memory_handles handle
        ON handle.account_id=episode.account_id AND handle.episode_id=episode.id
       AND handle.state='active'
      JOIN active_accounts account ON account.id=episode.account_id
),
finalization_facts AS MATERIALIZED (
    SELECT count(finalization.account_id)::bigint AS active_handle_episodes,
           count(*) FILTER (WHERE structure_state='draft')::bigint AS draft_episodes,
           count(*) FILTER (WHERE structure_state='reconciled')::bigint AS reconciled_episodes,
           count(*) FILTER (WHERE substance!='none' AND (
               finalized_at IS NULL OR coalesce(finalization_version,0)<5
               OR finalized_identity_revision<identity_revision))::bigint AS needs_finalization,
           count(*) FILTER (WHERE structure_state='reconciled' AND substance!='none' AND (
               finalized_at IS NULL OR coalesce(finalization_version,0)<5
               OR finalized_identity_revision<identity_revision))::bigint
               AS reconciled_needs_finalization,
           count(*) FILTER (WHERE finalization_status='processing'
                            OR finalization_claim_token IS NOT NULL)::bigint
               AS processing_claims,
           count(*) FILTER (WHERE finalization_claim_token IS NOT NULL
                            AND finalization_claim_until<=audit_window.observed_at)::bigint
               AS expired_processing_claims,
           count(*) FILTER (WHERE finalization_status IN ('retry_wait','budget_wait')
                            AND finalization_next_attempt_at<=audit_window.observed_at)::bigint
               AS due_waits,
           count(*) FILTER (WHERE finalization_status IN ('retry_wait','budget_wait')
                            AND finalization_next_attempt_at>audit_window.observed_at)::bigint
               AS future_waits,
           count(*) FILTER (WHERE finalization_status='budget_wait')::bigint AS budget_waits,
           count(*) FILTER (WHERE finalization_status='failed_terminal')::bigint
               AS failed_terminal,
           floor(extract(epoch FROM min(finalization_next_attempt_at)
                 FILTER (WHERE finalization_status IN ('retry_wait','budget_wait')))*1000)::bigint
               AS oldest_wait_at_ms,
           floor(extract(epoch FROM max(finalization_next_attempt_at)
                 FILTER (WHERE finalization_status IN ('retry_wait','budget_wait')))*1000)::bigint
               AS latest_wait_at_ms,
           count(*) FILTER (WHERE structure_state NOT IN ('draft','reconciled')
                            OR finalization_status NOT IN (
               'pending_horizon','pending_identity','pending_watermark','queued','processing',
               'retry_wait','budget_wait','failed_terminal','complete','finalized','deleting'))::bigint
               AS domain_violation_count
      FROM finalization_scope finalization RIGHT JOIN valid audit_window ON true
     GROUP BY audit_window.observed_at
),

account_component_counts AS MATERIALIZED (
    SELECT account.id AS account_id,coalesce(component.count,0)::bigint AS components,
           coalesce(component.successor_finalizers,0)::bigint AS successor_finalizers
      FROM active_accounts account
      LEFT JOIN (
          SELECT account_id,count(*)::bigint AS count,
                 (count(*)*32)::bigint AS successor_finalizers
            FROM candidate_component_sizes GROUP BY account_id
      ) component ON component.account_id=account.id
),
account_finalization_needs AS MATERIALIZED (
    SELECT account.id AS account_id,count(scope.account_id)::bigint AS reconciled_needs
      FROM active_accounts account
      LEFT JOIN finalization_scope scope ON scope.account_id=account.id
           AND scope.structure_state='reconciled' AND scope.substance!='none'
           AND (scope.finalized_at IS NULL OR coalesce(scope.finalization_version,0)<5
                OR scope.finalized_identity_revision<scope.identity_revision)
     GROUP BY account.id
),
account_capacity AS MATERIALIZED (
    SELECT account.id AS account_id,
           greatest(1310720-usage.audio_tokens,0)/4096 AS audio_remaining_slots,
           greatest(655360-usage.screen_tokens,0)/1024 AS screen_remaining_slots,
           greatest(655360-usage.derived_tokens,0)/8192 AS derived_remaining_slots,
           component.components,component.successor_finalizers,
           (component.components+component.successor_finalizers+
              finalization.reconciled_needs)::bigint AS projected_required_slots
      FROM active_accounts account
      JOIN active_usage usage ON usage.account_id=account.id
      JOIN account_component_counts component ON component.account_id=account.id
      JOIN account_finalization_needs finalization ON finalization.account_id=account.id
),
capacity_facts AS MATERIALIZED (
    SELECT coalesce(sum(components),0)::bigint AS projected_components,
           coalesce(sum(successor_finalizers),0)::bigint AS projected_successor_finalizers,
           greatest(65,coalesce(max(projected_required_slots),0))::bigint
               AS max_required_derived_slots,
           count(*) FILTER (WHERE derived_remaining_slots<greatest(65,projected_required_slots))::bigint
               AS accounts_insufficient_derived,
           coalesce(min(derived_remaining_slots-greatest(65,projected_required_slots)),80)::bigint
               AS minimum_derived_headroom_slots,
           count(*) FILTER (WHERE audio_remaining_slots<96)::bigint
               AS accounts_below_audio_96_slots,
           coalesce(min(audio_remaining_slots),320)::bigint AS minimum_audio_remaining_slots,
           count(*) FILTER (WHERE screen_remaining_slots<=0)::bigint AS accounts_at_screen_cap,
           count(*) FILTER (WHERE audio_remaining_slots<96)=0 AS audio_remaining_at_least_96,
           count(*) FILTER (WHERE derived_remaining_slots<greatest(65,projected_required_slots))=0
               AS derived_remaining_covers_backlog,
           count(*) FILTER (WHERE screen_remaining_slots<=0)=0 AS screen_remaining_nonzero,
           (SELECT count(*)=0 FROM candidate_component_sizes WHERE drafts>32)
               AS no_oversized_components
      FROM account_capacity
),

domain_gate AS MATERIALIZED (
    SELECT activation.domain_violation_count+capture.domain_violation_count+
           media.work_domain_violation_count+media.job_domain_violation_count+
           formation.receipt_domain_violation_count+formation.page_domain_violation_count+
           reconciliation.job_domain_violation_count+topology.domain_violation_count+
           vertex.domain_violation_count+finalization.domain_violation_count=0 AS domain_clean
      FROM activation_facts activation,capture_facts capture,media_facts media,
           formation_facts formation,reconciliation_facts reconciliation,
           topology_facts topology,vertex_facts vertex,finalization_facts finalization
),
gate_facts AS MATERIALIZED (
    SELECT domain.domain_clean,
           usage.total_mismatch_rows=0 AND usage.request_slot_mismatch_rows=0
             AND NOT EXISTS (SELECT 1 FROM usage_class_aggregates
                              WHERE nondivisible_rows<>0 OR accounts_at_or_over_limit<>0)
             AS quota_invariants_hold,
           provider.started_intents=0 AND provider.media_work_claims=0
             AND provider.media_job_claims=0 AND provider.summary_claims=0
             AND provider.formation_receipt_claims=0 AND provider.formation_page_claims=0
             AND provider.reconciliation_claims=0 AND provider.finalization_claims=0
             AS provider_quiescent,
           media.current_budget_jobs=0 AND media.current_budget_work_units=0
             AS media_budget_drained,
           media.expired_processing_jobs=0 AND media.expired_processing_work_units=0
             AND media.inconsistent_processing_jobs=0
             AND media.inconsistent_processing_work_units=0
             AND media.unfinished_work_without_members=0
             AND formation.expired_processing_receipts=0
             AND reconciliation.expired_processing_jobs=0
             AND finalization.expired_processing_claims=0 AS leases_unexpired,
           formation.finished_dirty_receipts=0
             AND formation.ended_without_finish_receipts=0
             AND formation.seal_pending_receipts=0
             AND formation.unresolved_source_accounts=0
             AND formation.nonterminal_pages_for_finished_receipts=0
             AND formation.legacy_processing_claims=0
             AND formation.legacy_expired_claims=0
             AND formation.legacy_retry_due_claims=0
             AND formation.retry_due_receipts=0 AS formation_quiescent,
           NOT EXISTS (SELECT 1 FROM reconciliation_job_unfinished_scope)
             AND reconciliation.staged_rows=0 AS reconciliation_quiescent,
           finalization.processing_claims=0 AS finalization_claims_quiescent,
           coalesce(activation.present AND activation.phase='installed'
             AND activation.generation=0 AND activation.rollout_basis_points=0
             AND activation.explicit_canary_count=0
             AND activation.backfill_present AND activation.backfill_complete
             AND activation.backfill_refresh_generation=activation.generation
             AND activation.episode_deletion_coherence_violations=0,false)
             AS activation_ready_for_drain,
           coalesce(activation.present AND activation.phase='draining'
             AND activation.rollout_basis_points=10000
             AND activation.explicit_canary_count=0
             AND activation.unassigned_active_accounts=0
             AND activation.backfill_present AND activation.backfill_complete
             AND activation.backfill_refresh_generation=activation.generation
             AND activation.drain_present AND activation.drain_complete,false)
             AND activation.scoped_draft_finalization_claims=0
             AS activation_ready_for_active,
           capacity.audio_remaining_at_least_96
             AND capacity.derived_remaining_covers_backlog
             AND capacity.screen_remaining_nonzero
             AND capacity.no_oversized_components AS capacity_sufficient
      FROM domain_gate domain,usage_facts usage,media_facts media,
           formation_facts formation,reconciliation_facts reconciliation,
           finalization_facts finalization,activation_facts activation,
           capacity_facts capacity,provider_activity_facts provider
),
gate_results AS MATERIALIZED (
    SELECT domain_clean,quota_invariants_hold,provider_quiescent,
           media_budget_drained,leases_unexpired,formation_quiescent,
           reconciliation_quiescent,finalization_claims_quiescent,
           activation_ready_for_drain,activation_ready_for_active,
           capacity_sufficient,
           -- Historical finish import and the first immutable capture seal are
           -- deliberately forbidden until signed Draining proves the predecessor
           -- fleet is gone. Keep their independently reported formation gate for
           -- Active, but do not make that post-drain repair a cyclic precondition
           -- of the transition which authorizes it.
           domain_clean AND quota_invariants_hold AND provider_quiescent
             AND media_budget_drained AND leases_unexpired
             AND reconciliation_quiescent AND finalization_claims_quiescent
             AND activation_ready_for_drain AND capacity_sufficient AS ready_for_drain,
           domain_clean AND quota_invariants_hold AND provider_quiescent
             AND media_budget_drained AND leases_unexpired AND formation_quiescent
             AND reconciliation_quiescent AND finalization_claims_quiescent
             AND activation_ready_for_active AND capacity_sufficient AS ready_for_active
      FROM gate_facts
)
SELECT jsonb_build_object(
    'contract','kioku.postdeploy.aggregate-audit.v2',
    'schema_version',2,
    'observed_at',to_char(audit_window.observed_at AT TIME ZONE 'UTC',
                          'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'since',audit_window.raw_since,
    'usage_day',to_char(audit_window.since_at AT TIME ZONE 'UTC','YYYY-MM-DD'),
    'transaction_read_only',audit_window.transaction_read_only,
    'provider_activity',(SELECT to_jsonb(provider) FROM provider_activity_facts provider),
    'activation',to_jsonb(activation),
    'capture_events',to_jsonb(capture),
    'media',to_jsonb(media),
    'formation',to_jsonb(formation),
    'reconciliation',to_jsonb(reconciliation),
    'topology',to_jsonb(topology),
    'vertex_usage',to_jsonb(vertex),
    'usage_daily',to_jsonb(usage),
    'finalization',to_jsonb(finalization),
    'capacity',to_jsonb(capacity),
    'gates',to_jsonb(gates)
)::text AS payload
  FROM valid audit_window,activation_facts activation,capture_facts capture,
       media_facts media,formation_facts formation,reconciliation_facts reconciliation,
       topology_facts topology,vertex_facts vertex,usage_facts usage,
       finalization_facts finalization,capacity_facts capacity,gate_results gates;
