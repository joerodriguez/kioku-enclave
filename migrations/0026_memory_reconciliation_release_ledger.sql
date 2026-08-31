-- Bootstrap for the durable online release ledger. The runner executes this
-- only after proving that every v26 catalog name is absent. All statements and
-- the first release row commit atomically; a retry accepts an existing ledger
-- only when its stored bootstrap/catalog hashes and complete definition match.

ALTER TABLE persistence_schema
    ADD COLUMN expanded_through_version bigint;

ALTER TABLE persistence_schema
    ADD CONSTRAINT persistence_schema_expand_monotonic_v26
    CHECK (expanded_through_version IS NULL OR expanded_through_version >= version)
    NOT VALID;

CREATE TABLE persistence_schema_releases (
    release_version bigint PRIMARY KEY,
    predecessor_version bigint NOT NULL,
    protocol_version bigint NOT NULL CHECK (protocol_version > 0),
    contract_sha256 bytea NOT NULL CHECK (octet_length(contract_sha256)=32),
    bootstrap_catalog_sha256 bytea NOT NULL
        CHECK (octet_length(bootstrap_catalog_sha256)=32),
    phase text NOT NULL CHECK (phase IN ('installing','backfilling','expanded','finalized')),
    accounts_cursor text,
    accounts_complete boolean NOT NULL DEFAULT false,
    episodes_cursor_account_id text,
    episodes_cursor_id bigint,
    episodes_complete boolean NOT NULL DEFAULT false,
    members_cursor_account_id text,
    members_cursor_episode_id bigint,
    members_cursor_record_type text,
    members_cursor_record_id bigint,
    members_complete boolean NOT NULL DEFAULT false,
    accounts_scanned bigint NOT NULL DEFAULT 0 CHECK (accounts_scanned >= 0),
    episodes_scanned bigint NOT NULL DEFAULT 0 CHECK (episodes_scanned >= 0),
    members_scanned bigint NOT NULL DEFAULT 0 CHECK (members_scanned >= 0),
    expanded_at timestamptz,
    finalization_receipt jsonb,
    finalization_receipt_sha256 bytea,
    finalization_receipt_signature bytea,
    finalization_receipt_key_sha256 bytea,
    finalized_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((episodes_cursor_account_id IS NULL) = (episodes_cursor_id IS NULL)),
    CHECK ((members_cursor_account_id IS NULL) = (members_cursor_episode_id IS NULL)
       AND (members_cursor_account_id IS NULL) = (members_cursor_record_type IS NULL)
       AND (members_cursor_account_id IS NULL) = (members_cursor_record_id IS NULL)),
    CHECK (phase NOT IN ('expanded','finalized') OR expanded_at IS NOT NULL),
    CHECK (phase <> 'finalized' OR (
        finalization_receipt IS NOT NULL
        AND finalization_receipt_sha256 IS NOT NULL
        AND octet_length(finalization_receipt_sha256)=32
        AND finalization_receipt_signature IS NOT NULL
        AND octet_length(finalization_receipt_signature)=64
        AND finalization_receipt_key_sha256 IS NOT NULL
        AND octet_length(finalization_receipt_key_sha256)=32
        AND finalized_at IS NOT NULL
    ))
);

CREATE TABLE persistence_schema_release_steps (
    release_version bigint NOT NULL,
    step_name text NOT NULL CHECK (length(step_name) BETWEEN 1 AND 64),
    ddl_sha256 bytea NOT NULL CHECK (octet_length(ddl_sha256)=32),
    catalog_sha256 bytea NOT NULL CHECK (octet_length(catalog_sha256)=32),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (release_version,step_name),
    FOREIGN KEY (release_version)
        REFERENCES persistence_schema_releases(release_version) ON DELETE CASCADE
);
