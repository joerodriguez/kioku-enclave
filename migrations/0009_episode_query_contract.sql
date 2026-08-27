-- Structured final briefs used by episode list/detail and delivery surfaces.

CREATE TABLE episode_final_briefs (
    account_id text NOT NULL,
    episode_id bigint NOT NULL,
    overview text NOT NULL,
    decisions jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(decisions) = 'array'),
    action_items jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(action_items) = 'array'),
    important_links jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(important_links) = 'array'),
    open_questions jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(open_questions) = 'array'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, episode_id),
    FOREIGN KEY (account_id, episode_id)
        REFERENCES episodes(account_id, id) ON DELETE CASCADE
);

UPDATE persistence_schema SET version = 9, updated_at = now() WHERE singleton = true;
