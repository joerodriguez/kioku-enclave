-- Fleet-wide summarizer claims. Episode data already lives in the
-- tenant-qualified tables introduced by migration 0007.

CREATE TABLE summary_window_claims (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    window_from timestamptz NOT NULL,
    window_to timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('processing','retry_wait','succeeded')),
    claim_token text,
    claim_until timestamptz,
    attempt_count bigint NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    error_code text,
    completed_claim_token text,
    completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((claim_token IS NULL) = (claim_until IS NULL)),
    CHECK (window_to > window_from)
);

CREATE INDEX summary_window_claims_reclaim_idx
    ON summary_window_claims(state,claim_until,updated_at);

CREATE TABLE summary_window_results (
    account_id text NOT NULL,
    window_from timestamptz NOT NULL,
    window_to timestamptz NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal >= 0),
    episode_id bigint NOT NULL,
    PRIMARY KEY (account_id,window_from,window_to,ordinal),
    FOREIGN KEY (account_id,episode_id)
        REFERENCES episodes(account_id,id) ON DELETE CASCADE
);

UPDATE persistence_schema SET version = 15, updated_at = now()
WHERE singleton = true AND version = 14;
