-- Rich episode evidence projections. All identifiers are tenant-qualified so
-- colliding per-user legacy ids cannot cross an account boundary.

CREATE TABLE screenshot_images (
    account_id text NOT NULL,
    id text NOT NULL,
    screenshot_id bigint NOT NULL,
    episode_id bigint NOT NULL,
    source_key text NOT NULL,
    captured_at timestamptz NOT NULL,
    object_key text NOT NULL,
    mime_type text NOT NULL CHECK (mime_type = 'image/jpeg'),
    width bigint NOT NULL CHECK (width > 0),
    height bigint NOT NULL CHECK (height > 0),
    byte_length bigint NOT NULL CHECK (byte_length BETWEEN 0 AND 153600),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, source_key),
    UNIQUE (account_id, object_key),
    FOREIGN KEY (account_id, screenshot_id)
        REFERENCES screenshots(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, episode_id)
        REFERENCES episodes(account_id, id) ON DELETE CASCADE
);
CREATE INDEX screenshot_images_episode_idx ON screenshot_images(account_id, episode_id);

CREATE TABLE episode_screen_interpretations (
    account_id text NOT NULL,
    episode_id bigint NOT NULL,
    screenshot_id bigint NOT NULL,
    episode_revision text NOT NULL,
    interpretation_version bigint NOT NULL,
    status text NOT NULL CHECK (status IN ('ready','fallback')),
    activity_summary text,
    relevance_level bigint NOT NULL CHECK (relevance_level BETWEEN 0 AND 3),
    relevance_reason text,
    milestone_type text NOT NULL DEFAULT 'none',
    base_score bigint NOT NULL DEFAULT 0,
    key_rank bigint,
    is_key_screen boolean NOT NULL DEFAULT false,
    semantic_group text,
    model_name text,
    prompt_version bigint NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, episode_id, screenshot_id),
    FOREIGN KEY (account_id, episode_id)
        REFERENCES episodes(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, screenshot_id)
        REFERENCES screenshots(account_id, id) ON DELETE CASCADE
);

CREATE TABLE people (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    display_name text,
    normalized_name text,
    status text NOT NULL DEFAULT 'unknown'
        CHECK (status IN ('unknown','identified','quarantined')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id)
);

CREATE TABLE episode_speaker_slots (
    account_id text NOT NULL,
    id bigint NOT NULL,
    episode_id bigint NOT NULL,
    voice_profile_id bigint,
    speaker_cluster_id bigint,
    slot_ordinal bigint NOT NULL CHECK (slot_ordinal >= 0),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','superseded')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, episode_id, slot_ordinal),
    FOREIGN KEY (account_id, episode_id)
        REFERENCES episodes(account_id, id) ON DELETE CASCADE,
    CHECK (
        (status='active' AND ((voice_profile_id IS NULL) <> (speaker_cluster_id IS NULL)))
        OR status='superseded'
    )
);

CREATE TABLE episode_participants (
    account_id text NOT NULL,
    id bigint NOT NULL,
    episode_id bigint NOT NULL,
    participant_key text NOT NULL,
    person_id bigint,
    source_claimed_name text,
    speaker_slot_id bigint,
    attribution_kind text NOT NULL CHECK (attribution_kind IN (
        'owner','owner_presentation','owner_source_role','verified_voice',
        'direct_identity_evidence','context_inferred'
    )),
    state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active','superseded','quarantined')),
    derivation_version bigint NOT NULL DEFAULT 1,
    confidence double precision NOT NULL DEFAULT 1.0,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, episode_id, participant_key),
    FOREIGN KEY (account_id, episode_id)
        REFERENCES episodes(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, person_id)
        REFERENCES people(account_id, id) ON DELETE SET NULL (person_id),
    FOREIGN KEY (account_id, speaker_slot_id)
        REFERENCES episode_speaker_slots(account_id, id) ON DELETE SET NULL (speaker_slot_id)
);
CREATE INDEX episode_participants_episode_idx
    ON episode_participants(account_id, episode_id, state, id);

UPDATE persistence_schema SET version = 11, updated_at = now() WHERE singleton = true;
