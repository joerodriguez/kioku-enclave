-- Atomic capture receipts, media metadata, browser evidence, and work outbox.

CREATE TABLE capture_sessions (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id text NOT NULL,
    device_id text NOT NULL,
    install_id text NOT NULL,
    started_at timestamptz NOT NULL,
    last_event_at timestamptz NOT NULL,
    ended_at timestamptz,
    schema_version bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id)
);

CREATE TABLE capture_streams (
    account_id text NOT NULL,
    id text NOT NULL,
    capture_session_id text NOT NULL,
    device_id text NOT NULL,
    stream_kind text NOT NULL CHECK (stream_kind IN (
        'mic','system_audio','mac_screen','ios_mic','ios_imported_screenshot','ios_shared_page'
    )),
    committed_through_sequence bigint NOT NULL DEFAULT -1,
    sealed_sequence bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, capture_session_id)
        REFERENCES capture_sessions(account_id, id) ON DELETE CASCADE
);

CREATE TABLE capture_events (
    account_id text NOT NULL,
    event_id text NOT NULL,
    device_id text NOT NULL,
    install_id text NOT NULL,
    capture_session_id text NOT NULL,
    stream_id text NOT NULL,
    stream_kind text NOT NULL,
    sequence bigint NOT NULL,
    source_wall_at timestamptz NOT NULL,
    source_monotonic_ns text NOT NULL,
    started_at timestamptz NOT NULL,
    ended_at timestamptz NOT NULL,
    timezone_id text NOT NULL,
    utc_offset_minutes bigint NOT NULL,
    clock_uncertainty_ms bigint NOT NULL,
    asset_id text NOT NULL,
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    context_json jsonb,
    media_disposition text NOT NULL CHECK (media_disposition IN ('canonical','reference')),
    canonical_event_id text,
    canonical_asset_id text,
    canonical_media_sha256 text,
    perceptual_hash text,
    hamming_distance bigint,
    pixel_change_ratio double precision,
    context_fingerprint text,
    dedupe_version bigint,
    audio_role text,
    audio_route text,
    route_epoch bigint,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, event_id),
    UNIQUE (account_id, asset_id),
    UNIQUE (account_id, device_id, stream_id, sequence),
    FOREIGN KEY (account_id, capture_session_id)
        REFERENCES capture_sessions(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, stream_id)
        REFERENCES capture_streams(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, canonical_event_id)
        REFERENCES capture_events(account_id, event_id) ON DELETE CASCADE,
    CHECK (
        (media_disposition='canonical' AND canonical_event_id IS NULL)
        OR
        (media_disposition='reference' AND canonical_event_id IS NOT NULL)
    )
);
CREATE INDEX capture_events_time_idx
    ON capture_events (account_id, started_at, event_id);
CREATE INDEX capture_events_session_idx
    ON capture_events (account_id, capture_session_id);

CREATE TABLE media_objects (
    account_id text NOT NULL,
    asset_id text NOT NULL,
    event_id text NOT NULL,
    object_key text NOT NULL,
    object_generation bigint,
    object_backend text CHECK (object_backend IN ('current')),
    mime_type text NOT NULL,
    codec text NOT NULL,
    byte_length bigint NOT NULL CHECK (byte_length >= 0),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    sample_rate bigint,
    channels bigint,
    frame_count bigint,
    width bigint,
    height bigint,
    scale double precision,
    orientation text,
    processing_state text NOT NULL DEFAULT 'queued' CHECK (
        processing_state IN ('queued','processing','ready','retry_wait','failed','pruned')
    ),
    retain_until timestamptz,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, asset_id),
    UNIQUE (account_id, event_id),
    UNIQUE (account_id, object_key),
    FOREIGN KEY (account_id, event_id)
        REFERENCES capture_events(account_id, event_id) ON DELETE CASCADE
);

CREATE TABLE recording_media_authority (
    account_id text NOT NULL,
    asset_id text NOT NULL,
    capture_policy_revision bigint NOT NULL CHECK (capture_policy_revision >= 0),
    retention_policy_revision bigint NOT NULL CHECK (retention_policy_revision >= 0),
    retention_policy_epoch text,
    retention_decision text NOT NULL CHECK (
        retention_decision IN ('processing_window_30d','until_deleted')
    ),
    storage_backend text NOT NULL CHECK (storage_backend IN ('processing','recordings')),
    recording_key_epoch bigint,
    recording_state text NOT NULL CHECK (recording_state IN ('processing_only','durable')),
    decision_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (account_id, asset_id),
    FOREIGN KEY (account_id, asset_id)
        REFERENCES media_objects(account_id, asset_id) ON DELETE CASCADE
);

CREATE TABLE browser_states_v2 (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    state_key text NOT NULL,
    browser_bundle_id text NOT NULL,
    browser_name text NOT NULL,
    permission_status text NOT NULL,
    content_hash text NOT NULL,
    tabs_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, state_key)
);

CREATE TABLE browser_observations_v2 (
    account_id text NOT NULL,
    observation_id text NOT NULL,
    event_id text NOT NULL,
    observed_at timestamptz NOT NULL,
    state_key text,
    context_status text NOT NULL,
    active_url text,
    active_title text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, observation_id),
    UNIQUE (account_id, event_id),
    FOREIGN KEY (account_id, event_id)
        REFERENCES capture_events(account_id, event_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, state_key)
        REFERENCES browser_states_v2(account_id, state_key)
);

CREATE TABLE media_processing_jobs (
    account_id text NOT NULL,
    id bigserial NOT NULL,
    event_id text NOT NULL,
    job_kind text NOT NULL CHECK (job_kind IN ('gemini_audio','gemini_screen')),
    input_revision text NOT NULL,
    processor_version bigint NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (
        state IN ('pending','processing','retry_wait','succeeded','failed_terminal','canceled')
    ),
    attempt_count bigint NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_owner text,
    lease_token text,
    lease_until timestamptz,
    error_code text,
    model_id text,
    prompt_version bigint,
    schema_version bigint,
    usage_json jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, job_kind, input_revision, processor_version),
    FOREIGN KEY (account_id, event_id)
        REFERENCES capture_events(account_id, event_id) ON DELETE CASCADE
);
CREATE INDEX media_processing_jobs_claim_idx
    ON media_processing_jobs (state, updated_at, account_id, id);

CREATE TABLE outbox_events (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    event_id text NOT NULL,
    event_kind text NOT NULL,
    aggregate_id text NOT NULL,
    payload jsonb NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','publishing','published','dead')),
    attempt_count bigint NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    claim_owner text,
    claim_token text,
    claim_until timestamptz,
    available_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, event_id)
);
CREATE INDEX outbox_events_claim_idx
    ON outbox_events (state, available_at, account_id, event_id);

UPDATE persistence_schema SET version = 8, updated_at = now() WHERE singleton = true;
