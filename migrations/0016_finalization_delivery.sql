-- Fleet-owned finalization and tenant-qualified outbound delivery outboxes.

ALTER TABLE episodes
    ADD COLUMN finalization_claim_token text,
    ADD COLUMN finalization_claim_until timestamptz,
    ADD COLUMN finalization_completed_claim_token text,
    ADD COLUMN finalization_vertex_event_id text,
    ADD COLUMN finalization_analysis_revision text,
    ADD CONSTRAINT episodes_finalization_claim_pair CHECK (
        (finalization_claim_token IS NULL) = (finalization_claim_until IS NULL)
    ),
    ADD CONSTRAINT episodes_finalization_vertex_event_fk FOREIGN KEY (
        account_id,finalization_vertex_event_id
    ) REFERENCES vertex_usage_events(account_id,event_id);

CREATE INDEX episodes_finalization_claim_idx
    ON episodes(account_id,finalization_status,finalization_next_attempt_at,ended_at,id);

CREATE TABLE webhook_deliveries (
    account_id text NOT NULL,
    episode_id bigint NOT NULL,
    subscription_id text NOT NULL,
    delivery_version bigint NOT NULL,
    event_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','processing','retry_wait','delivered','failed','cancelled','ambiguous')),
    attempt_count bigint NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    claim_token text,
    claim_until timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(account_id,episode_id,subscription_id,delivery_version),
    UNIQUE(account_id,event_id),
    FOREIGN KEY(account_id,episode_id) REFERENCES episodes(account_id,id) ON DELETE CASCADE,
    CHECK ((claim_token IS NULL) = (claim_until IS NULL))
);

CREATE TABLE email_deliveries (
    account_id text NOT NULL,
    episode_id bigint NOT NULL,
    delivery_version bigint NOT NULL,
    delivery_id text NOT NULL,
    include_content boolean NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','processing','retry_wait','delivered','failed','cancelled','ambiguous')),
    attempt_count bigint NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    claim_token text,
    claim_until timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(account_id,episode_id,delivery_version),
    UNIQUE(account_id,delivery_id),
    FOREIGN KEY(account_id,episode_id) REFERENCES episodes(account_id,id) ON DELETE CASCADE,
    CHECK ((claim_token IS NULL) = (claim_until IS NULL))
);

CREATE TABLE push_deliveries (
    account_id text NOT NULL,
    episode_id bigint NOT NULL,
    installation_binding text NOT NULL,
    delivery_version bigint NOT NULL,
    delivery_id text NOT NULL,
    handoff_handle text NOT NULL,
    collapse_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','processing','retry_wait','delivered','failed','cancelled','ambiguous')),
    attempt_count bigint NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    claim_token text,
    claim_until timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(account_id,episode_id,installation_binding,delivery_version),
    UNIQUE(account_id,delivery_id),
    FOREIGN KEY(account_id,episode_id) REFERENCES episodes(account_id,id) ON DELETE CASCADE,
    CHECK ((claim_token IS NULL) = (claim_until IS NULL))
);

CREATE INDEX webhook_deliveries_claim_idx ON webhook_deliveries(state,next_attempt_at,claim_until,account_id);
CREATE INDEX email_deliveries_claim_idx ON email_deliveries(state,next_attempt_at,claim_until,account_id);
CREATE INDEX push_deliveries_claim_idx ON push_deliveries(state,next_attempt_at,claim_until,account_id);

UPDATE persistence_schema SET version = 16, updated_at = now()
WHERE singleton = true AND version = 15;
