-- Fleet-safe media processing claims and PostgreSQL-native result projections.

CREATE TABLE media_work_units (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id text NOT NULL,
    work_class text NOT NULL CHECK (work_class IN ('audio','screen')),
    processor_version bigint NOT NULL,
    state text NOT NULL CHECK (
        state IN ('planned','processing','retry_wait','succeeded','failed_terminal')
    ),
    started_at timestamptz NOT NULL,
    ended_at timestamptz NOT NULL,
    reserved_output_tokens bigint NOT NULL CHECK (reserved_output_tokens >= 0),
    reservation_retained boolean NOT NULL DEFAULT false,
    attempt_count bigint NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    claim_token text,
    claim_until timestamptz,
    error_code text,
    usage_json jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,id),
    CHECK ((claim_token IS NULL) = (claim_until IS NULL))
);

CREATE TABLE media_work_members (
    account_id text NOT NULL,
    work_unit_id text NOT NULL,
    event_id text NOT NULL,
    job_id bigint NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal >= 0),
    window_start_ms bigint NOT NULL,
    window_end_ms bigint NOT NULL,
    PRIMARY KEY (account_id,work_unit_id,event_id),
    UNIQUE (account_id,work_unit_id,ordinal),
    UNIQUE (account_id,job_id),
    FOREIGN KEY (account_id,work_unit_id)
        REFERENCES media_work_units(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,event_id)
        REFERENCES capture_events(account_id,event_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,job_id)
        REFERENCES media_processing_jobs(account_id,id) ON DELETE CASCADE
);

CREATE INDEX media_work_units_claim_idx
    ON media_work_units(state,claim_until,account_id,updated_at);

CREATE TABLE speaker_clusters (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    work_unit_id text NOT NULL,
    speaker_local_id text NOT NULL,
    voice_profile_id bigint,
    person_id bigint,
    attribution_state text NOT NULL CHECK (attribution_state IN (
        'owner_transmit','person_bound','anonymous_profile','request_local','unsegmented'
    )),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,id),
    UNIQUE (account_id,work_unit_id,speaker_local_id),
    FOREIGN KEY (account_id,work_unit_id)
        REFERENCES media_work_units(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,voice_profile_id)
        REFERENCES voice_profiles(account_id,id) ON DELETE SET NULL (voice_profile_id),
    FOREIGN KEY (account_id,person_id)
        REFERENCES people(account_id,id) ON DELETE SET NULL (person_id)
);

ALTER TABLE speaker_observations
    ADD COLUMN cluster_id bigint,
    ADD COLUMN direct_evidence_id bigint,
    ADD COLUMN embedding_status text NOT NULL DEFAULT 'pending'
        CHECK (embedding_status IN ('pending','processing','ready','failed','raw_media_expired')),
    ADD CONSTRAINT speaker_observations_cluster_fk
        FOREIGN KEY (account_id,cluster_id)
        REFERENCES speaker_clusters(account_id,id) ON DELETE SET NULL (cluster_id);

CREATE TABLE speaker_observation_sources (
    account_id text NOT NULL,
    speaker_observation_id bigint NOT NULL,
    event_id text NOT NULL,
    window_start_ms bigint NOT NULL,
    window_end_ms bigint NOT NULL,
    event_start_ms bigint NOT NULL,
    event_end_ms bigint NOT NULL,
    PRIMARY KEY (account_id,speaker_observation_id,event_id,window_start_ms),
    FOREIGN KEY (account_id,speaker_observation_id)
        REFERENCES speaker_observations(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,event_id)
        REFERENCES capture_events(account_id,event_id) ON DELETE CASCADE
);

CREATE TABLE visual_speaker_observations (
    account_id text NOT NULL,
    id bigint NOT NULL,
    event_id text NOT NULL,
    screenshot_id bigint NOT NULL,
    observed_at timestamptz NOT NULL,
    platform text NOT NULL,
    displayed_name text NOT NULL,
    normalized_name text NOT NULL,
    highlight_state text NOT NULL CHECK (
        highlight_state IN ('active_speaker_box','audio_waveform','roster_indicator','none')
    ),
    bounding_box jsonb,
    model_version bigint NOT NULL DEFAULT 1,
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,id),
    FOREIGN KEY (account_id,event_id)
        REFERENCES capture_events(account_id,event_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,screenshot_id)
        REFERENCES screenshots(account_id,id) ON DELETE CASCADE
);

CREATE INDEX visual_speaker_observations_time_idx
    ON visual_speaker_observations(account_id,observed_at,normalized_name);

CREATE TABLE voice_embedding_jobs (
    account_id text NOT NULL,
    id bigint NOT NULL,
    speaker_observation_id bigint NOT NULL,
    embedding_space text NOT NULL,
    processor_version bigint NOT NULL DEFAULT 1,
    quality_version bigint NOT NULL DEFAULT 1,
    scorer_version bigint NOT NULL DEFAULT 2,
    state text NOT NULL CHECK (
        state IN ('pending','processing','retry_wait','failed','ready','raw_media_expired')
    ),
    lease_owner text,
    lease_token text,
    lease_until timestamptz,
    attempt_count bigint NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz,
    error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,id),
    UNIQUE (account_id,speaker_observation_id,embedding_space,processor_version,quality_version,scorer_version),
    FOREIGN KEY (account_id,speaker_observation_id)
        REFERENCES speaker_observations(account_id,id) ON DELETE CASCADE,
    CHECK ((lease_owner IS NULL) = (lease_token IS NULL)),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);

CREATE INDEX voice_embedding_jobs_claim_idx
    ON voice_embedding_jobs(state,next_attempt_at,lease_until,account_id,id);

UPDATE persistence_schema SET version = 14, updated_at = now()
WHERE singleton = true AND version = 13;
