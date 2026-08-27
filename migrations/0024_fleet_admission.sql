-- Fleet-wide token buckets and crash-recoverable concurrency leases.

CREATE TABLE fleet_rate_limits (
    scope text NOT NULL CHECK (length(scope) BETWEEN 1 AND 256),
    admission_key text NOT NULL CHECK (length(admission_key) BETWEEN 1 AND 256),
    tokens double precision NOT NULL
        CHECK (tokens >= 0 AND tokens < 'Infinity'::double precision),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope, admission_key)
);

CREATE TABLE fleet_concurrency_leases (
    scope text NOT NULL CHECK (length(scope) BETWEEN 1 AND 256),
    holder text NOT NULL CHECK (length(holder) BETWEEN 1 AND 256),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (scope, holder)
);

CREATE INDEX fleet_concurrency_leases_expiry_idx
    ON fleet_concurrency_leases (scope, expires_at);

UPDATE persistence_schema SET version = 24, updated_at = now()
WHERE singleton = true AND version = 23;
