-- ADR-0048 Phase 5: presentation metadata, never an archive/topology revision.
ALTER TABLE episodes ADD COLUMN identity_refinalized_at timestamptz;

CREATE TABLE episode_identity_presentations (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    semantic_initialized boolean NOT NULL DEFAULT false,
    -- Every refresh compares against the immutable transaction-entry baseline.
    semantic_transaction_xid xid8,
    semantic_transaction_baseline jsonb
        CHECK (jsonb_typeof(semantic_transaction_baseline)='object'),
    CHECK ((semantic_transaction_xid IS NULL)=(semantic_transaction_baseline IS NULL)),
    semantic_state jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(semantic_state)='array'),
    timeline_labels jsonb NOT NULL DEFAULT '{"labels":[]}'::jsonb
        CHECK (jsonb_typeof(timeline_labels)='object'),
    minute_labels jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(minute_labels)='object'),
    action_labels jsonb NOT NULL DEFAULT '{"labels":[]}'::jsonb
        CHECK (jsonb_typeof(action_labels)='object'),
    brief_labels jsonb NOT NULL DEFAULT '{"labels":[]}'::jsonb
        CHECK (jsonb_typeof(brief_labels)='object'),
    PRIMARY KEY(account_id,episode_id),
    FOREIGN KEY(account_id,episode_id) REFERENCES episodes(account_id,id) ON DELETE CASCADE
);

CREATE TABLE identity_presentation_schema (
    singleton boolean PRIMARY KEY CHECK(singleton),
    version bigint NOT NULL CHECK(version=34),
    contract_sha256 text NOT NULL CHECK(contract_sha256 ~ '^[0-9a-f]{64}$'),
    catalog_sha256 text NOT NULL CHECK(catalog_sha256 ~ '^[0-9a-f]{64}$'),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
