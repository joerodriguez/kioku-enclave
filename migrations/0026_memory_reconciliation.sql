-- Source-settled memory topology reconciliation cold objects.
--
-- The release runner executes this file in one bounded transaction before any
-- data backfill. Every table and ordinary index below is new in schema 26, so
-- this transaction does not take an AccessExclusiveLock on a populated product
-- table. Existing-table changes, compatibility triggers, concurrent indexes,
-- bounded backfills, and durable receipts are separate release steps.

CREATE TABLE memory_archive_state (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- A handle deliberately contains no title, summary, transcript, or other
-- content. Superseded ids therefore remain resolvable without becoming a
-- second content store.
CREATE TABLE memory_handles (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('active','superseded','retired')),
    origin_relation text CHECK (origin_relation IN ('merge','split','repartition','non_memory')),
    reconciliation_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    PRIMARY KEY (account_id,episode_id),
    CHECK (
        (state='active' AND origin_relation IS NULL AND retired_at IS NULL)
        OR (state='superseded' AND origin_relation IN ('merge','split','repartition') AND retired_at IS NOT NULL)
        OR (state='retired' AND origin_relation='non_memory' AND retired_at IS NOT NULL)
    )
);

-- This is the only mutable topology projection. The concurrently installed
-- legacy source guard and this unique key prevent two active owners.
CREATE TABLE active_episode_members (
    account_id text NOT NULL,
    episode_id bigint NOT NULL,
    record_type text NOT NULL CHECK (record_type IN ('utterance','screenshot')),
    record_id bigint NOT NULL CHECK (record_id > 0),
    PRIMARY KEY (account_id,episode_id,record_type,record_id),
    UNIQUE (account_id,record_type,record_id),
    FOREIGN KEY (account_id,episode_id)
        REFERENCES episodes(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,episode_id)
        REFERENCES memory_handles(account_id,episode_id) ON DELETE CASCADE
);
CREATE INDEX active_episode_members_episode_idx
    ON active_episode_members(account_id,episode_id,record_type,record_id);

CREATE TABLE memory_reconciliations (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id text NOT NULL CHECK (length(id) BETWEEN 5 AND 128),
    reconciliation_version bigint NOT NULL CHECK (reconciliation_version > 0),
    model text NOT NULL,
    prompt_version bigint NOT NULL CHECK (prompt_version > 0),
    vertex_event_id text,
    cohort_started_at timestamptz NOT NULL,
    cohort_ended_at timestamptz NOT NULL,
    source_fingerprint bytea NOT NULL CHECK (octet_length(source_fingerprint)=32),
    topology_fingerprint bytea NOT NULL CHECK (octet_length(topology_fingerprint)=32),
    result_commitment bytea NOT NULL CHECK (octet_length(result_commitment)=32),
    archive_revision bigint NOT NULL CHECK (archive_revision > 0),
    committed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,id),
    UNIQUE (account_id,source_fingerprint),
    FOREIGN KEY (account_id,vertex_event_id)
        REFERENCES vertex_usage_events(account_id,event_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE memory_reconciliation_jobs (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    source_fingerprint bytea NOT NULL CHECK (octet_length(source_fingerprint)=32),
    topology_fingerprint bytea NOT NULL CHECK (octet_length(topology_fingerprint)=32),
    predecessor_episode_ids bigint[] NOT NULL CHECK (cardinality(predecessor_episode_ids) BETWEEN 1 AND 32),
    cohort_started_at timestamptz NOT NULL,
    cohort_ended_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','processing','retry_wait','complete','failed_terminal')),
    attempt_count bigint NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    model_attempt_count bigint NOT NULL DEFAULT 0 CHECK (model_attempt_count >= 0),
    claim_token text,
    claim_until timestamptz,
    next_attempt_at timestamptz,
    last_error_code text,
    reconciliation_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,source_fingerprint),
    UNIQUE (account_id,reconciliation_id),
    FOREIGN KEY (account_id,reconciliation_id)
        REFERENCES memory_reconciliations(account_id,id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((claim_token IS NULL) = (claim_until IS NULL)),
    CHECK ((state='processing') = (claim_token IS NOT NULL)),
    CHECK ((state='retry_wait') = (next_attempt_at IS NOT NULL)),
    CHECK ((state='complete') = (reconciliation_id IS NOT NULL)),
    CHECK (cohort_ended_at >= cohort_started_at)
);
CREATE INDEX memory_reconciliation_jobs_due_idx
    ON memory_reconciliation_jobs(state,next_attempt_at,claim_until,updated_at);
CREATE INDEX memory_reconciliation_jobs_predecessors_idx
    ON memory_reconciliation_jobs USING gin(predecessor_episode_ids);

-- The paid provider result is durable JSONB before any topology mutation.
-- Publication consumes the plaintext stage while retaining only content-free
-- commitments and provider provenance.
CREATE TABLE memory_reconciliation_stages (
    account_id text NOT NULL,
    source_fingerprint bytea NOT NULL CHECK (octet_length(source_fingerprint)=32),
    topology_fingerprint bytea NOT NULL CHECK (octet_length(topology_fingerprint)=32),
    predecessor_episode_ids bigint[] NOT NULL CHECK (cardinality(predecessor_episode_ids) BETWEEN 1 AND 32),
    normalized_partition jsonb NOT NULL CHECK (jsonb_typeof(normalized_partition)='object'),
    result_commitment bytea NOT NULL CHECK (octet_length(result_commitment)=32),
    planned_outputs jsonb NOT NULL CHECK (jsonb_typeof(planned_outputs)='array'),
    planned_outputs_commitment bytea NOT NULL CHECK (octet_length(planned_outputs_commitment)=32),
    model text NOT NULL,
    vertex_event_id text,
    reconciliation_version bigint NOT NULL CHECK (reconciliation_version > 0),
    prompt_version bigint NOT NULL CHECK (prompt_version > 0),
    partition_schema_version bigint NOT NULL CHECK (partition_schema_version > 0),
    validator_version bigint NOT NULL CHECK (validator_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,source_fingerprint),
    FOREIGN KEY (account_id,source_fingerprint)
        REFERENCES memory_reconciliation_jobs(account_id,source_fingerprint) ON DELETE CASCADE,
    FOREIGN KEY (account_id,vertex_event_id)
        REFERENCES vertex_usage_events(account_id,event_id)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX memory_reconciliation_stages_predecessors_idx
    ON memory_reconciliation_stages USING gin(predecessor_episode_ids);

CREATE TABLE memory_lineage_edges (
    account_id text NOT NULL,
    reconciliation_id text NOT NULL,
    predecessor_episode_id bigint NOT NULL,
    successor_episode_id bigint NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (account_id,predecessor_episode_id,ordinal),
    UNIQUE (account_id,predecessor_episode_id,successor_episode_id),
    FOREIGN KEY (account_id,reconciliation_id)
        REFERENCES memory_reconciliations(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,predecessor_episode_id)
        REFERENCES memory_handles(account_id,episode_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (account_id,successor_episode_id)
        REFERENCES memory_handles(account_id,episode_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (predecessor_episode_id <> successor_episode_id)
);
CREATE INDEX memory_lineage_successor_idx
    ON memory_lineage_edges(account_id,successor_episode_id,predecessor_episode_id);

CREATE TABLE memory_reconciliation_sources (
    account_id text NOT NULL,
    reconciliation_id text NOT NULL,
    record_type text NOT NULL CHECK (record_type IN ('utterance','screenshot')),
    record_id bigint NOT NULL CHECK (record_id > 0),
    successor_episode_id bigint NOT NULL,
    PRIMARY KEY (account_id,reconciliation_id,record_type,record_id),
    FOREIGN KEY (account_id,reconciliation_id)
        REFERENCES memory_reconciliations(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,successor_episode_id)
        REFERENCES memory_handles(account_id,episode_id)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX memory_reconciliation_sources_successor_idx
    ON memory_reconciliation_sources(account_id,successor_episode_id);

ALTER TABLE memory_handles
    ADD CONSTRAINT memory_handles_reconciliation_fk
    FOREIGN KEY (account_id,reconciliation_id)
    REFERENCES memory_reconciliations(account_id,id)
    DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX memory_handles_reconciliation_idx
    ON memory_handles(account_id,reconciliation_id)
    WHERE reconciliation_id IS NOT NULL;

-- Functions are installed before their triggers. Trigger creation is split
-- into bounded existing-table transactions by the release runner.
CREATE FUNCTION install_memory_archive_for_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO memory_archive_state(account_id,revision)
    VALUES(NEW.id,0) ON CONFLICT(account_id) DO NOTHING;
    RETURN NEW;
END
$$;

CREATE FUNCTION install_active_memory_handle() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO memory_archive_state(account_id,revision)
    VALUES(NEW.account_id,0) ON CONFLICT(account_id) DO NOTHING;
    INSERT INTO memory_handles(account_id,episode_id,state)
    VALUES(NEW.account_id,NEW.id,'active')
    ON CONFLICT(account_id,episode_id) DO NOTHING;
    RETURN NEW;
END
$$;

CREATE FUNCTION maintain_episode_structure_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.finalized_at IS NOT NULL THEN
        NEW.structure_state := 'reconciled';
    ELSIF NEW.structure_state IS NULL THEN
        NEW.structure_state := 'draft';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION project_active_episode_member() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('DELETE','UPDATE') THEN
        DELETE FROM active_episode_members
         WHERE account_id=OLD.account_id AND episode_id=OLD.episode_id
           AND record_type=OLD.record_type AND record_id=OLD.record_id;
        IF TG_OP='DELETE' THEN
            RETURN OLD;
        END IF;
    END IF;
    IF EXISTS(SELECT 1 FROM memory_handles
               WHERE account_id=NEW.account_id AND episode_id=NEW.episode_id
                 AND state='active') THEN
        INSERT INTO active_episode_members(account_id,episode_id,record_type,record_id)
        VALUES(NEW.account_id,NEW.episode_id,NEW.record_type,NEW.record_id)
        ON CONFLICT (account_id,episode_id,record_type,record_id) DO NOTHING;
    END IF;
    RETURN NEW;
END
$$;

-- Episode deletion remains authoritative. Pending paid-result content for a
-- cohort containing the episode is removed, and its durable handle becomes a
-- content-free retired tombstone. Completed reconciliation history remains.
CREATE FUNCTION retire_deleted_memory() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM memory_handles WHERE account_id=OLD.account_id
              AND episode_id=OLD.id AND state='active') THEN
        DELETE FROM memory_reconciliation_stages
         WHERE account_id=OLD.account_id
           AND predecessor_episode_ids @> ARRAY[OLD.id]::bigint[];
        DELETE FROM memory_reconciliation_jobs
         WHERE account_id=OLD.account_id
           AND predecessor_episode_ids @> ARRAY[OLD.id]::bigint[]
           AND state<>'complete';
        UPDATE memory_handles
           SET state='retired',origin_relation='non_memory',reconciliation_id=NULL,
               retired_at=now()
         WHERE account_id=OLD.account_id AND episode_id=OLD.id AND state='active';
    END IF;
    RETURN OLD;
END
$$;
