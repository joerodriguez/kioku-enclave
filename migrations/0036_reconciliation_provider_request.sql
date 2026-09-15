-- The organizer's exact provider request is frozen by the first try of a
-- durable attempt and replayed byte-for-byte by every later try of the same
-- attempt identity, as capture formation freezes its page request. Speaker
-- identity changes presentation, never the source, so without this freeze a
-- label change between two tries of one attempt re-rendered a different body
-- under the same attempt id, which the usage ledger refuses for as long as
-- that attempt is retried. Presentation working state, never an archive or
-- topology revision: it leaves with its job, at attempt advance, at terminal
-- failure and at publication. Named outside the reserved memory_% family the
-- base cold_objects release step digests.
CREATE TABLE reconciliation_provider_requests (
    account_id text NOT NULL,
    source_fingerprint bytea NOT NULL CHECK (octet_length(source_fingerprint)=32),
    provider_attempt_identity bytea NOT NULL CHECK (octet_length(provider_attempt_identity)=32),
    provider_request text NOT NULL CHECK (octet_length(provider_request) BETWEEN 1 AND 4194304),
    provider_request_sha256 bytea NOT NULL CHECK (octet_length(provider_request_sha256)=32),
    frozen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id,source_fingerprint),
    CONSTRAINT reconciliation_provider_requests_job_fkey
        FOREIGN KEY (account_id,source_fingerprint)
        REFERENCES memory_reconciliation_jobs(account_id,source_fingerprint) ON DELETE CASCADE
);

CREATE TABLE reconciliation_provider_request_schema (
    singleton boolean PRIMARY KEY CHECK(singleton),
    version bigint NOT NULL CHECK(version=36),
    contract_sha256 text NOT NULL CHECK(contract_sha256 ~ '^[0-9a-f]{64}$'),
    catalog_sha256 text NOT NULL CHECK(catalog_sha256 ~ '^[0-9a-f]{64}$'),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
