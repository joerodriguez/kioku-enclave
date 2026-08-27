-- Tenant-qualified structured memory and PostgreSQL-native search foundation.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE content_id_counters (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    entity_kind text NOT NULL,
    next_id bigint NOT NULL CHECK (next_id > 0),
    PRIMARY KEY (account_id, entity_kind)
);

CREATE TABLE audio_segments (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    started_at timestamptz NOT NULL,
    ended_at timestamptz NOT NULL,
    duration_seconds double precision NOT NULL CHECK (duration_seconds >= 0),
    source_type text NOT NULL CHECK (source_type IN ('mic', 'system')),
    audio_format text NOT NULL DEFAULT 'm4a',
    file_size_bytes bigint,
    speech_percentage double precision,
    detected_language text,
    transcription_status text NOT NULL DEFAULT 'pending',
    processing_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id)
);

CREATE TABLE utterances (
    account_id text NOT NULL,
    id bigint NOT NULL,
    audio_segment_id bigint NOT NULL,
    start_offset_seconds double precision NOT NULL,
    end_offset_seconds double precision NOT NULL,
    text text NOT NULL,
    language text,
    confidence double precision,
    speaker_label text NOT NULL,
    source_key text,
    speaker_observation_id bigint,
    embedding vector(384),
    search_document tsvector GENERATED ALWAYS AS
        (to_tsvector('simple', coalesce(text, ''))) STORED,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, audio_segment_id)
        REFERENCES audio_segments(account_id, id) ON DELETE CASCADE,
    UNIQUE (account_id, source_key)
);
CREATE INDEX utterances_time_idx
    ON utterances (account_id, audio_segment_id, id);
CREATE INDEX utterances_search_idx
    ON utterances USING gin (search_document);
CREATE INDEX utterances_embedding_idx
    ON utterances USING hnsw (embedding vector_cosine_ops);

CREATE TABLE screenshots (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    captured_at timestamptz NOT NULL,
    active_app text,
    window_title text,
    ocr_text text,
    salient_ocr_text text,
    url text,
    ocr_status text NOT NULL DEFAULT 'done',
    image_hash text,
    is_duplicate boolean NOT NULL DEFAULT false,
    source_key text,
    display_id bigint,
    capture_context_version bigint,
    capture_status text,
    primary_bundle_id text,
    primary_window_id bigint,
    capture_group_id text,
    visible_windows jsonb,
    visible_windows_truncated boolean NOT NULL DEFAULT false,
    visual_signals jsonb,
    semantic_context_hash text,
    browser_snapshot_source_key text,
    duplicate_of_id bigint,
    visible_until timestamptz,
    dedupe_version bigint NOT NULL DEFAULT 1,
    embedding vector(384),
    search_document tsvector GENERATED ALWAYS AS
        (to_tsvector('simple', coalesce(ocr_text, ''))) STORED,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, duplicate_of_id)
        REFERENCES screenshots(account_id, id),
    UNIQUE (account_id, source_key)
);
CREATE INDEX screenshots_time_idx ON screenshots (account_id, captured_at DESC, id DESC);
CREATE INDEX screenshots_search_idx ON screenshots USING gin (search_document);
CREATE INDEX screenshots_embedding_idx
    ON screenshots USING hnsw (embedding vector_cosine_ops);

CREATE TABLE screen_observations (
    account_id text NOT NULL,
    screenshot_id bigint NOT NULL,
    input_revision text NOT NULL,
    observation_version bigint NOT NULL,
    status text NOT NULL CHECK (status IN ('ready', 'fallback')),
    generation_method text NOT NULL,
    literal_description text NOT NULL,
    screen_state text NOT NULL,
    content_type text NOT NULL,
    visible_text_summary text,
    notable_items jsonb NOT NULL DEFAULT '[]'::jsonb,
    model_name text,
    prompt_version bigint NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, screenshot_id),
    FOREIGN KEY (account_id, screenshot_id)
        REFERENCES screenshots(account_id, id) ON DELETE CASCADE
);

CREATE TABLE episodes (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    started_at timestamptz NOT NULL,
    ended_at timestamptz NOT NULL,
    type text,
    title text,
    summary text,
    participants jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(participants) = 'array'),
    languages jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(languages) = 'array'),
    action_items jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(action_items) = 'array'),
    model text,
    topics jsonb,
    people jsonb,
    minute_summaries jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(minute_summaries) = 'array'),
    minutes_text text,
    substance text NOT NULL DEFAULT 'normal'
        CHECK (substance IN ('none', 'low', 'normal')),
    visual_evidence text NOT NULL DEFAULT 'none'
        CHECK (visual_evidence IN ('none', 'useful')),
    finalized_at timestamptz,
    finalization_version bigint,
    finalization_status text NOT NULL DEFAULT 'pending_horizon',
    finalization_error text,
    finalization_attempted_at timestamptz,
    finalization_attempt_count bigint NOT NULL DEFAULT 0,
    finalization_next_attempt_at timestamptz,
    identity_revision bigint NOT NULL DEFAULT 0,
    finalized_identity_revision bigint NOT NULL DEFAULT 0,
    identity_refresh_status text
        CHECK (identity_refresh_status IN ('queued', 'processing', 'ready', 'failed')),
    speaker_processing_status text NOT NULL DEFAULT 'ready'
        CHECK (speaker_processing_status IN ('ready', 'pending', 'degraded')),
    embedding vector(384),
    search_document tsvector GENERATED ALWAYS AS
        (to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(summary, '') || ' ' || coalesce(minutes_text, ''))) STORED,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz,
    PRIMARY KEY (account_id, id)
);
CREATE INDEX episodes_time_idx ON episodes (account_id, started_at DESC, id DESC);
CREATE INDEX episodes_search_idx ON episodes USING gin (search_document);
CREATE INDEX episodes_embedding_idx ON episodes USING hnsw (embedding vector_cosine_ops);

CREATE TABLE episode_members (
    account_id text NOT NULL,
    episode_id bigint NOT NULL,
    record_type text NOT NULL CHECK (record_type IN ('utterance', 'screenshot')),
    record_id bigint NOT NULL,
    PRIMARY KEY (account_id, episode_id, record_type, record_id),
    FOREIGN KEY (account_id, episode_id)
        REFERENCES episodes(account_id, id) ON DELETE CASCADE
);
CREATE INDEX episode_members_record_idx
    ON episode_members (account_id, record_type, record_id);

UPDATE persistence_schema SET version = 7, updated_at = now() WHERE singleton = true;
