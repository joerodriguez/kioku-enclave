-- Fleet-wide admission for GCS media uploads and the account processing key.

CREATE TABLE account_media_keys (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    wrapped_dek text NOT NULL CHECK (wrapped_dek <> ''),
    installed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE capture_upload_intents (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    event_id text NOT NULL,
    token text NOT NULL CHECK (token <> ''),
    asset_id text NOT NULL,
    object_key text NOT NULL,
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, event_id),
    UNIQUE (token)
);
CREATE INDEX capture_upload_intents_expiry_idx
    ON capture_upload_intents (expires_at, account_id);

UPDATE persistence_schema SET version = 18, updated_at = now() WHERE singleton = true;
