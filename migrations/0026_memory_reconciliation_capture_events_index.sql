CREATE INDEX CONCURRENTLY capture_events_reconciliation_horizon_idx
    ON capture_events(account_id,ended_at,started_at,capture_session_id);
