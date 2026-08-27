-- Fleet-wide reference-batch credit reservations and replay receipts.

CREATE TABLE capture_reference_batch_receipts (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    batch_id text NOT NULL CHECK (batch_id ~ '^[0-9a-fA-F]{64}$'),
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[0-9a-fA-F]{64}$'),
    stream_id text NOT NULL,
    first_sequence bigint NOT NULL CHECK (first_sequence >= 0),
    last_sequence bigint NOT NULL CHECK (last_sequence >= first_sequence),
    event_count bigint NOT NULL CHECK (event_count BETWEEN 1 AND 64),
    state text NOT NULL CHECK (state IN ('awaiting_credit','reserved','completed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(account_id,batch_id)
);
CREATE INDEX capture_reference_batch_pending_idx
    ON capture_reference_batch_receipts(account_id,state,updated_at);

CREATE TABLE capture_reference_batch_events (
    account_id text NOT NULL,
    batch_id text NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 0 AND 63),
    event_id text NOT NULL,
    PRIMARY KEY(account_id,batch_id,ordinal),
    UNIQUE(account_id,batch_id,event_id),
    FOREIGN KEY(account_id,batch_id)
        REFERENCES capture_reference_batch_receipts(account_id,batch_id) ON DELETE CASCADE
);

UPDATE persistence_schema SET version = 22, updated_at = now()
WHERE singleton = true AND version = 21;
