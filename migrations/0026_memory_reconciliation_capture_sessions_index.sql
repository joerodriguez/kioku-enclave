CREATE INDEX CONCURRENTLY capture_sessions_reconciliation_horizon_idx
    ON capture_sessions (
        account_id,
        (greatest(last_event_at,coalesce(ended_at,last_event_at))),
        started_at,
        id
    );
