-- Billing pseudonyms, recording authorization receipts, and fleet-wide
-- usage/delivery authority.

CREATE TABLE billing_accounts (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    billing_account_id text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE billing_detach_outbox (
    billing_account_id text PRIMARY KEY,
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_attempt_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vertex_coverage_anchors (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    period text NOT NULL CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    sequence bigint NOT NULL CHECK (sequence > 0),
    pending_events bigint NOT NULL CHECK (pending_events >= 0),
    lost_events bigint NOT NULL CHECK (lost_events >= 0),
    observed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, period)
);

CREATE TABLE recording_leases (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    lease_id text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE recording_lease_requests (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    request_id text NOT NULL,
    requested_lease_id text,
    issued_lease_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('pending', 'granted', 'conflict')),
    summary_json text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, request_id)
);

CREATE INDEX recording_lease_requests_pending_idx
    ON recording_lease_requests (account_id, created_at, request_id)
    WHERE state = 'pending';

CREATE TABLE recording_lease_denials (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    request_id text NOT NULL,
    requested_lease_id text,
    issued_lease_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    denial_code text NOT NULL,
    summary_json text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, request_id)
);

CREATE INDEX recording_lease_denials_retention_idx
    ON recording_lease_denials (account_id, created_at DESC, request_id DESC);

CREATE TABLE recording_delivery_balances (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    event_credits bigint NOT NULL CHECK (event_credits >= 0),
    byte_credits bigint NOT NULL CHECK (byte_credits >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE recording_delivery_reservations (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    event_id text NOT NULL,
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, event_id)
);

CREATE TABLE offline_recording_usage_receipts (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    request_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, request_id)
);

UPDATE persistence_schema SET version = 4, updated_at = now() WHERE singleton = true;
