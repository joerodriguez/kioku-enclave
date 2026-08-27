-- Durable two-step episode deletion: freeze DB authority, erase GCS media,
-- then atomically purge structured state with a replayable receipt.

CREATE TABLE episode_deletions (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','complete')),
    purge jsonb NOT NULL CHECK (jsonb_typeof(purge)='object'),
    media_object_keys jsonb NOT NULL CHECK (jsonb_typeof(media_object_keys)='array'),
    utterance_ids jsonb NOT NULL CHECK (jsonb_typeof(utterance_ids)='array'),
    screenshot_ids jsonb NOT NULL CHECK (jsonb_typeof(screenshot_ids)='array'),
    segment_ids jsonb NOT NULL CHECK (jsonb_typeof(segment_ids)='array'),
    orphan_event_ids jsonb NOT NULL CHECK (jsonb_typeof(orphan_event_ids)='array'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    PRIMARY KEY (account_id,episode_id)
);
CREATE INDEX episode_deletions_pending_idx
    ON episode_deletions(state,updated_at,account_id,episode_id);

UPDATE persistence_schema SET version = 20, updated_at = now()
WHERE singleton = true AND version = 19;
