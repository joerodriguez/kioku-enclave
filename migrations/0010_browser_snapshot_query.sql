-- Legacy browser snapshot representation retained for older capture clients.
-- Cloud Capture v2 writes browser_states_v2/browser_observations_v2 instead.

CREATE TABLE browser_snapshots (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    source_key text NOT NULL,
    captured_at timestamptz NOT NULL,
    browser_bundle_id text NOT NULL,
    browser_name text NOT NULL,
    permission_status text NOT NULL,
    active_window_index bigint,
    active_tab_index bigint,
    reported_tab_count bigint NOT NULL DEFAULT 0 CHECK (reported_tab_count >= 0),
    truncated boolean NOT NULL DEFAULT false,
    content_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, source_key)
);

CREATE TABLE browser_tabs (
    account_id text NOT NULL,
    browser_snapshot_id bigint NOT NULL,
    window_index bigint NOT NULL,
    tab_index bigint NOT NULL,
    title text,
    url text,
    url_scheme text,
    is_active boolean NOT NULL,
    is_loading boolean,
    PRIMARY KEY (account_id, browser_snapshot_id, window_index, tab_index),
    FOREIGN KEY (account_id, browser_snapshot_id)
        REFERENCES browser_snapshots(account_id, id) ON DELETE CASCADE
);

-- Version 8 initially left this edge restrictive. Account deletion removes
-- the event and state in one transaction, so the derived observation must
-- cascade from either parent instead of depending on cascade trigger order.
ALTER TABLE browser_observations_v2
    DROP CONSTRAINT browser_observations_v2_account_id_state_key_fkey;
ALTER TABLE browser_observations_v2
    ADD CONSTRAINT browser_observations_v2_account_id_state_key_fkey
    FOREIGN KEY (account_id, state_key)
    REFERENCES browser_states_v2(account_id, state_key) ON DELETE CASCADE;

UPDATE persistence_schema SET version = 10, updated_at = now() WHERE singleton = true;
