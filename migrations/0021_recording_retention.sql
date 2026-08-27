-- Fleet-wide recording-retention policy, preview/CAS receipts, and key epochs.

CREATE TABLE recording_retention_preferences (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    policy text NOT NULL CHECK (policy IN ('processing_window_30d','until_deleted')),
    consent_version bigint NOT NULL CHECK (consent_version >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    policy_epoch text,
    effective_at timestamptz NOT NULL,
    revocation_cutoff timestamptz,
    updated_at timestamptz NOT NULL,
    CHECK ((policy='until_deleted') = (policy_epoch IS NOT NULL)),
    CHECK (policy!='until_deleted' OR revocation_cutoff IS NULL)
);

CREATE TABLE recording_retention_history (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    revision bigint NOT NULL,
    policy text NOT NULL CHECK (policy IN ('processing_window_30d','until_deleted')),
    consent_version bigint NOT NULL,
    policy_epoch text,
    effective_at timestamptz NOT NULL,
    revocation_cutoff timestamptz,
    operation_id text NOT NULL,
    request_fingerprint text NOT NULL,
    PRIMARY KEY(account_id,revision)
);

CREATE TABLE recording_key_epochs (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key_epoch bigint NOT NULL CHECK (key_epoch > 0),
    policy_epoch text NOT NULL,
    wrapped_dek text NOT NULL,
    state text NOT NULL CHECK (state IN ('active','retired','erased')),
    created_at timestamptz NOT NULL DEFAULT now(),
    erased_at timestamptz,
    PRIMARY KEY(account_id,key_epoch),
    UNIQUE(account_id,policy_epoch),
    CHECK ((state='erased') = (wrapped_dek=''))
);

CREATE TABLE recording_retention_previews (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    preview_id text NOT NULL,
    expected_revision bigint NOT NULL,
    target_policy text NOT NULL CHECK (target_policy IN ('processing_window_30d','until_deleted')),
    consent_version bigint NOT NULL,
    promote_existing boolean NOT NULL,
    inventory_fingerprint text NOT NULL,
    object_count bigint NOT NULL,
    byte_count bigint NOT NULL,
    recording_count bigint NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(account_id,preview_id)
);

CREATE TABLE recording_retention_changes (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    idempotency_key_hash text NOT NULL,
    request_fingerprint text NOT NULL,
    preview_id text NOT NULL,
    operation_id text NOT NULL,
    resulting_revision bigint NOT NULL,
    resulting_policy text NOT NULL CHECK (resulting_policy IN ('processing_window_30d','until_deleted')),
    state text NOT NULL CHECK (state IN ('settled','delete_pending','physical_complete')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY(account_id,operation_id),
    UNIQUE(account_id,idempotency_key_hash)
);
CREATE INDEX recording_retention_changes_pending_idx
    ON recording_retention_changes(state,updated_at,account_id,operation_id);

UPDATE persistence_schema SET version = 21, updated_at = now()
WHERE singleton = true AND version = 20;
