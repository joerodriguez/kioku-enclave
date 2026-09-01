-- Append-only activation authority for PostgreSQL memory reconciliation.
--
-- Every object uses a name family ignored by the frozen v0.9.16 schema-26
-- verifier.  The schema marker deliberately remains 26/26 while this contract
-- is installed or draining.  Only a separately signed `active` event advances
-- it to 27/27, which makes every v0.9.16 process fail readiness.

-- Installation cannot guess whether an older pending deletion already
-- crossed provider egress. Resolve it under the v26 binary first. A completed
-- v26 deletion is eligible only when it has no orphan event IDs; otherwise
-- the deleted capture sequence coordinates cannot be reconstructed exactly.
SET LOCAL lock_timeout = '30s';
LOCK TABLE episode_deletions IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS(SELECT 1 FROM episode_deletions WHERE state='pending') THEN
        RAISE EXCEPTION 'v27 install refused: pending episode deletion requires v26 resolution'
            USING ERRCODE='check_violation';
    END IF;
    IF EXISTS(
        SELECT 1 FROM episode_deletions
         WHERE state='complete'
           AND jsonb_typeof(orphan_event_ids)='array'
           AND jsonb_array_length(orphan_event_ids)>0
    ) THEN
        RAISE EXCEPTION 'v27 install refused: completed v26 deletion lacks capture sequence coordinates'
            USING ERRCODE='check_violation';
    END IF;
END
$$;

CREATE TABLE persistence_feature_activation_contracts (
    feature text PRIMARY KEY CHECK (feature='episode_topology_reconciliation'),
    protocol_version bigint NOT NULL CHECK (protocol_version=1),
    base_schema_version bigint NOT NULL CHECK (base_schema_version=26),
    target_schema_version bigint NOT NULL CHECK (target_schema_version=27),
    contract_sha256 bytea NOT NULL CHECK (octet_length(contract_sha256)=32),
    catalog_sha256 bytea NOT NULL CHECK (octet_length(catalog_sha256)=32),
    base_finalization_receipt_sha256 bytea NOT NULL
        CHECK (octet_length(base_finalization_receipt_sha256)=32),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE persistence_feature_activation_events (
    event_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    feature text NOT NULL REFERENCES persistence_feature_activation_contracts(feature),
    generation bigint NOT NULL CHECK (generation>=0),
    previous_phase text NOT NULL CHECK (previous_phase IN (
        'preactive','installed','draining','active','paused'
    )),
    phase text NOT NULL CHECK (phase IN ('installed','draining','active','paused')),
    rollout_basis_points bigint NOT NULL CHECK (rollout_basis_points IN (0,10000)),
    rollout_seed text NOT NULL CHECK (
        rollout_seed ~ '^sha256:[0-9a-f]{64}$'
    ),
    explicit_canary_account_ids text[] NOT NULL DEFAULT '{}',
    candidate_fleet_image_digest text CHECK (
        candidate_fleet_image_digest IS NULL
        OR candidate_fleet_image_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    reconciliation_producer_contract_sha256 text CHECK (
        reconciliation_producer_contract_sha256 IS NULL
        OR reconciliation_producer_contract_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    reconciliation_model text,
    vertex_location text,
    receipt jsonb,
    receipt_sha256 bytea,
    receipt_signature bytea,
    receipt_key_sha256 bytea,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(feature,generation),
    CHECK (cardinality(explicit_canary_account_ids)<=128),
    CHECK (
        (phase='installed' AND generation=0 AND previous_phase='preactive'
            AND rollout_basis_points=0
            AND cardinality(explicit_canary_account_ids)=0
            AND candidate_fleet_image_digest IS NULL
            AND reconciliation_producer_contract_sha256 IS NULL
            AND reconciliation_model IS NULL AND vertex_location IS NULL
            AND receipt IS NULL AND receipt_sha256 IS NULL
            AND receipt_signature IS NULL AND receipt_key_sha256 IS NULL)
        OR
        (phase<>'installed' AND generation>0
            AND receipt IS NOT NULL
            AND candidate_fleet_image_digest IS NOT NULL
            AND reconciliation_producer_contract_sha256 IS NOT NULL
            AND reconciliation_model IS NOT NULL AND vertex_location IS NOT NULL
            AND receipt_sha256 IS NOT NULL AND octet_length(receipt_sha256)=32
            AND receipt_signature IS NOT NULL AND octet_length(receipt_signature)=64
            AND receipt_key_sha256 IS NOT NULL AND octet_length(receipt_key_sha256)=32)
    ),
    CHECK (receipt IS NULL OR (
        (receipt->>'generation')::bigint=generation
        AND receipt->>'previous_phase'=previous_phase
        AND receipt->>'requested_phase'=phase
        AND (receipt->>'rollout_basis_points')::bigint=rollout_basis_points
        AND receipt->>'rollout_seed'=rollout_seed
        AND receipt->'explicit_canary_account_ids'=to_jsonb(explicit_canary_account_ids)
        AND receipt->>'candidate_fleet_image_digest'=candidate_fleet_image_digest
        AND receipt->>'reconciliation_producer_contract_sha256'=
            reconciliation_producer_contract_sha256
        AND receipt->>'reconciliation_model'=reconciliation_model
        AND receipt->>'vertex_location'=vertex_location
    ))
);

CREATE TABLE persistence_feature_activation_assignments (
    feature text NOT NULL,
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    activation_generation bigint NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(feature,account_id),
    FOREIGN KEY(feature,activation_generation)
        REFERENCES persistence_feature_activation_events(feature,generation)
);
CREATE INDEX persistence_feature_activation_assignments_generation_idx
    ON persistence_feature_activation_assignments(feature,activation_generation,account_id);

-- Provenance companion for the v26 stage relation. Keeping this under the
-- v27-safe persistence_feature prefix preserves v0.9.16's exact memory_%
-- catalog receipt throughout dark install and draining.
CREATE TABLE persistence_feature_reconciliation_stage_contracts (
    feature text NOT NULL DEFAULT 'episode_topology_reconciliation'
        CHECK (feature='episode_topology_reconciliation'),
    account_id text NOT NULL,
    source_fingerprint bytea NOT NULL CHECK (octet_length(source_fingerprint)=32),
    activation_generation bigint NOT NULL,
    producer_contract_sha256 bytea NOT NULL CHECK (octet_length(producer_contract_sha256)=32),
    reconciliation_model text NOT NULL,
    vertex_location text NOT NULL,
    provider_attempt_identity bytea CHECK (
        provider_attempt_identity IS NULL OR octet_length(provider_attempt_identity)=32
    ),
    provider_invocation_fingerprint bytea CHECK (
        provider_invocation_fingerprint IS NULL
        OR octet_length(provider_invocation_fingerprint)=32
    ),
    reconciliation_id text,
    staged_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    committed_at timestamptz,
    PRIMARY KEY(account_id,source_fingerprint),
    UNIQUE(account_id,reconciliation_id),
    FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY(feature,activation_generation)
        REFERENCES persistence_feature_activation_events(feature,generation),
    FOREIGN KEY(account_id,reconciliation_id)
        REFERENCES memory_reconciliations(account_id,id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((reconciliation_id IS NULL)=(committed_at IS NULL)),
    CHECK ((provider_attempt_identity IS NULL)=
           (provider_invocation_fingerprint IS NULL))
);

-- Bounded, resumable formation-receipt coverage. Generation zero is the
-- online install pass. Entering `draining` resets this row to that signed
-- generation after predecessor_instances=0; `active` is refused until the
-- post-predecessor pass has reached an exact end-of-keyspace receipt.
CREATE TABLE persistence_feature_activation_backfills (
    feature text NOT NULL,
    backfill_name text NOT NULL CHECK (
        backfill_name='capture_formation_receipts'
    ),
    refresh_generation bigint NOT NULL CHECK (refresh_generation>=0),
    last_account_id text,
    last_capture_session_id text,
    complete boolean NOT NULL DEFAULT false,
    rows_scanned bigint NOT NULL DEFAULT 0 CHECK (rows_scanned>=0),
    rows_inserted bigint NOT NULL DEFAULT 0 CHECK (rows_inserted>=0),
    rows_reopened bigint NOT NULL DEFAULT 0 CHECK (rows_reopened>=0),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY(feature,backfill_name),
    FOREIGN KEY(feature,refresh_generation)
        REFERENCES persistence_feature_activation_events(feature,generation),
    CHECK (
        (last_account_id IS NULL)=(last_capture_session_id IS NULL)
    ),
    CHECK (complete=(completed_at IS NOT NULL))
);

-- Draft-claim draining is also keyset bounded. A row is created for every
-- signed draining generation and retained as non-content operational proof.
CREATE TABLE persistence_feature_activation_drains (
    feature text NOT NULL,
    activation_generation bigint NOT NULL,
    last_account_id text,
    last_episode_id bigint,
    complete boolean NOT NULL DEFAULT false,
    claims_scanned bigint NOT NULL DEFAULT 0 CHECK (claims_scanned>=0),
    claims_revoked bigint NOT NULL DEFAULT 0 CHECK (claims_revoked>=0),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY(feature,activation_generation),
    FOREIGN KEY(feature,activation_generation)
        REFERENCES persistence_feature_activation_events(feature,generation),
    CHECK ((last_account_id IS NULL)=(last_episode_id IS NULL)),
    CHECK (complete=(completed_at IS NOT NULL))
);

-- Large episode deletion is a durable, bounded state machine. The v20
-- episode_deletions row remains the externally visible freeze/receipt; these
-- content-free companions hold exact coordinates and progress without
-- changing the frozen v26 relation. The application may create companions
-- only after the signed Draining guard transition has made v0.9.16 unready.
CREATE TABLE persistence_feature_episode_deletion_progress (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    phase text NOT NULL CHECK (phase IN (
        'inventory_members','inventory_projection_events',
        'inventory_episode_objects','classify_roots','inventory_family_sessions',
        'inventory_family_events','provider_delete','purge_members',
        'tombstone_events','purge_events','refresh_sessions','finalize','complete'
    )),
    member_record_type_cursor text,
    member_record_id_cursor bigint,
    projection_record_type_cursor text,
    projection_record_id_cursor bigint,
    projection_event_id_cursor text,
    episode_object_key_cursor text,
    root_event_id_cursor text,
    session_root_event_id_cursor text,
    session_event_id_cursor text,
    family_root_event_id_cursor text,
    family_event_id_cursor text,
    coordinate_sha256 bytea NOT NULL CHECK (octet_length(coordinate_sha256)=32),
    member_count bigint NOT NULL DEFAULT 0 CHECK (member_count>=0),
    utterance_count bigint NOT NULL DEFAULT 0 CHECK (utterance_count>=0),
    screenshot_count bigint NOT NULL DEFAULT 0 CHECK (screenshot_count>=0),
    segment_count bigint NOT NULL DEFAULT 0 CHECK (segment_count>=0),
    root_count bigint NOT NULL DEFAULT 0 CHECK (root_count>=0),
    event_count bigint NOT NULL DEFAULT 0 CHECK (event_count>=0),
    object_count bigint NOT NULL DEFAULT 0 CHECK (object_count>=0),
    session_count bigint NOT NULL DEFAULT 0 CHECK (session_count>=0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY(account_id,episode_id),
    FOREIGN KEY(account_id,episode_id)
        REFERENCES episode_deletions(account_id,episode_id) ON DELETE CASCADE,
    CHECK ((member_record_type_cursor IS NULL)=(member_record_id_cursor IS NULL)),
    CHECK ((projection_record_type_cursor IS NULL)=
           (projection_record_id_cursor IS NULL)),
    CHECK ((session_root_event_id_cursor IS NULL)=
           (session_event_id_cursor IS NULL)),
    CHECK ((family_root_event_id_cursor IS NULL)=
           (family_event_id_cursor IS NULL)),
    CHECK ((phase='complete')=(completed_at IS NOT NULL))
);

CREATE TABLE persistence_feature_episode_deletion_members (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    record_type text NOT NULL CHECK (record_type IN ('utterance','screenshot')),
    record_id bigint NOT NULL,
    source_key text,
    audio_segment_id bigint,
    coordinate_sha256 bytea NOT NULL CHECK (octet_length(coordinate_sha256)=32),
    purged_at timestamptz,
    PRIMARY KEY(account_id,episode_id,record_type,record_id),
    FOREIGN KEY(account_id,episode_id)
        REFERENCES episode_deletions(account_id,episode_id) ON DELETE CASCADE,
    CHECK ((record_type='screenshot')=(audio_segment_id IS NULL))
);
CREATE INDEX persistence_feature_episode_deletion_members_pending_idx
    ON persistence_feature_episode_deletion_members(account_id,episode_id,record_type,record_id)
    WHERE purged_at IS NULL;

CREATE TABLE persistence_feature_episode_deletion_roots (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    root_event_id text NOT NULL,
    disposition text NOT NULL DEFAULT 'pending'
        CHECK (disposition IN ('pending','survivor','orphan')),
    coordinate_sha256 bytea NOT NULL CHECK (octet_length(coordinate_sha256)=32),
    classified_at timestamptz,
    PRIMARY KEY(account_id,episode_id,root_event_id),
    FOREIGN KEY(account_id,episode_id)
        REFERENCES episode_deletions(account_id,episode_id) ON DELETE CASCADE,
    CHECK ((disposition='pending')=(classified_at IS NULL))
);
CREATE INDEX persistence_feature_episode_deletion_roots_pending_idx
    ON persistence_feature_episode_deletion_roots(account_id,episode_id,root_event_id)
    WHERE disposition='pending';

CREATE TABLE persistence_feature_episode_deletion_events (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    root_event_id text NOT NULL,
    event_id text NOT NULL,
    capture_session_id text NOT NULL,
    stream_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence>=0),
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    coordinate_sha256 bytea NOT NULL CHECK (octet_length(coordinate_sha256)=32),
    tombstoned_at timestamptz,
    purged_at timestamptz,
    PRIMARY KEY(account_id,episode_id,event_id),
    UNIQUE(account_id,event_id),
    FOREIGN KEY(account_id,episode_id)
        REFERENCES episode_deletions(account_id,episode_id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,episode_id,root_event_id)
        REFERENCES persistence_feature_episode_deletion_roots(
            account_id,episode_id,root_event_id
        ) ON DELETE CASCADE
);
CREATE INDEX persistence_feature_episode_deletion_events_pending_idx
    ON persistence_feature_episode_deletion_events(
        account_id,episode_id,root_event_id,(event_id=root_event_id),event_id
    )
    WHERE purged_at IS NULL;
CREATE INDEX persistence_feature_episode_deletion_events_tombstone_idx
    ON persistence_feature_episode_deletion_events(account_id,episode_id,event_id)
    WHERE tombstoned_at IS NULL;

CREATE TABLE persistence_feature_episode_deletion_objects (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    object_key text NOT NULL,
    object_kind text NOT NULL CHECK (object_kind IN ('screenshot_image','media_object')),
    object_key_sha256 bytea NOT NULL CHECK (octet_length(object_key_sha256)=32),
    provider_deleted_at timestamptz,
    PRIMARY KEY(account_id,episode_id,object_key),
    FOREIGN KEY(account_id,episode_id)
        REFERENCES episode_deletions(account_id,episode_id) ON DELETE CASCADE
);
CREATE INDEX persistence_feature_episode_deletion_objects_pending_idx
    ON persistence_feature_episode_deletion_objects(account_id,episode_id,object_key)
    WHERE provider_deleted_at IS NULL;

CREATE TABLE persistence_feature_episode_deletion_sessions (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    episode_id bigint NOT NULL,
    capture_session_id text NOT NULL,
    coordinate_sha256 bytea NOT NULL CHECK (octet_length(coordinate_sha256)=32),
    refreshed_at timestamptz,
    PRIMARY KEY(account_id,episode_id,capture_session_id),
    FOREIGN KEY(account_id,episode_id)
        REFERENCES episode_deletions(account_id,episode_id) ON DELETE CASCADE
);
CREATE INDEX persistence_feature_episode_deletion_sessions_pending_idx
    ON persistence_feature_episode_deletion_sessions(account_id,episode_id,capture_session_id)
    WHERE refreshed_at IS NULL;

-- These functions are installed dark. Their four triggers are attached and
-- definition-verified atomically by the signed Installed->Draining transition.
CREATE FUNCTION guard_persistence_feature_episode_deletion_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    guarded_phase text;
BEGIN
    IF TG_TABLE_NAME='episodes' THEN
        IF TG_OP<>'DELETE' THEN
            RAISE EXCEPTION 'paged episode deletion guard attached to an invalid episode operation'
                USING ERRCODE='55000';
        END IF;
        IF NOT EXISTS(SELECT 1 FROM accounts WHERE id=OLD.account_id) THEN
            RETURN OLD;
        END IF;
        SELECT progress.phase INTO guarded_phase
          FROM persistence_feature_episode_deletion_progress progress
         WHERE progress.account_id=OLD.account_id
           AND progress.episode_id=OLD.id;
        IF NOT FOUND THEN
            RETURN OLD;
        END IF;
        IF guarded_phase NOT IN ('finalize','complete') THEN
            RAISE EXCEPTION 'paged episode deletion refuses an unauthorised episode removal'
                USING ERRCODE='55000';
        END IF;
        RETURN OLD;
    ELSIF TG_TABLE_NAME<>'episode_members' THEN
        RAISE EXCEPTION 'paged episode deletion guard attached to an invalid relation'
            USING ERRCODE='55000';
    END IF;

    IF TG_OP='DELETE' AND NOT EXISTS(
        SELECT 1 FROM accounts WHERE id=OLD.account_id
    ) THEN
        RETURN OLD;
    END IF;
    IF TG_OP IN ('DELETE','UPDATE') THEN
        SELECT progress.phase INTO guarded_phase
          FROM persistence_feature_episode_deletion_progress progress
         WHERE progress.account_id=OLD.account_id
           AND progress.episode_id=OLD.episode_id;
        IF FOUND AND NOT (TG_OP='DELETE' AND guarded_phase IN ('purge_members','finalize')) THEN
            RAISE EXCEPTION 'paged episode deletion freezes its exact member inventory'
                USING ERRCODE='55000';
        END IF;
    END IF;
    IF TG_OP IN ('INSERT','UPDATE') AND EXISTS(
        SELECT 1 FROM persistence_feature_episode_deletion_progress progress
         WHERE progress.account_id=NEW.account_id
           AND progress.episode_id=NEW.episode_id
           AND progress.phase<>'complete'
    ) THEN
        RAISE EXCEPTION 'paged episode deletion refuses a new target member'
            USING ERRCODE='55000';
    END IF;
    RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$$;

CREATE FUNCTION guard_persistence_feature_episode_deletion_media_work()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state='processing' AND NEW.claim_token IS NOT NULL
       AND NEW.claim_until>clock_timestamp() AND EXISTS(
        SELECT 1
          FROM media_work_members member
          JOIN capture_events event
            ON event.account_id=member.account_id AND event.event_id=member.event_id
          JOIN persistence_feature_episode_deletion_roots root
            ON root.account_id=event.account_id
           AND root.root_event_id=coalesce(event.canonical_event_id,event.event_id)
           AND root.disposition<>'pending'
          JOIN persistence_feature_episode_deletion_progress progress
            ON progress.account_id=root.account_id
           AND progress.episode_id=root.episode_id
           AND progress.phase<>'complete'
         WHERE member.account_id=NEW.account_id
           AND member.work_unit_id=NEW.id
    ) THEN
        RAISE EXCEPTION 'paged episode deletion refuses media provider egress'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION guard_persistence_feature_episode_deletion_formation_claim()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state='processing' AND NEW.claim_token IS NOT NULL
       AND NEW.claim_until>clock_timestamp() AND EXISTS(
        SELECT 1 FROM persistence_feature_episode_deletion_sessions session
          JOIN persistence_feature_episode_deletion_progress progress
            ON progress.account_id=session.account_id
           AND progress.episode_id=session.episode_id
           AND progress.phase<>'complete'
         WHERE session.account_id=NEW.account_id
           AND session.capture_session_id=NEW.capture_session_id
    ) THEN
        RAISE EXCEPTION 'paged episode deletion refuses formation provider egress'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;

-- Content-free accepted-sequence authority for evidence erased by an episode
-- deletion. Capture acknowledgements remain contiguous after the source row is
-- removed, while the event identity and manifest commitment can never be
-- replayed as live evidence. `deletion_episode_id` is immutable provenance,
-- not an FK: account/session erasure owns this row's cascade independently of
-- the durable deletion receipt.
CREATE TABLE capture_formation_deleted_sequences (
    account_id text NOT NULL,
    capture_session_id text NOT NULL,
    stream_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence>=0),
    event_id text NOT NULL,
    original_manifest_digest text NOT NULL CHECK (
        original_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    deletion_episode_id bigint NOT NULL,
    deleted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    provenance text NOT NULL CHECK (provenance='episode_deletion_v1'),
    PRIMARY KEY(account_id,stream_id,sequence),
    UNIQUE(account_id,event_id),
    FOREIGN KEY(account_id,capture_session_id)
        REFERENCES capture_sessions(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,stream_id)
        REFERENCES capture_streams(account_id,id) ON DELETE CASCADE
);
CREATE INDEX capture_formation_deleted_sequences_session_idx
    ON capture_formation_deleted_sequences(
        account_id,capture_session_id,stream_id,sequence
    );

CREATE FUNCTION deny_persistence_feature_activation_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'feature activation authority is append-only'
        USING ERRCODE='55000';
END
$$;

CREATE FUNCTION guard_persistence_feature_activation_assignment_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' AND NOT EXISTS(
        SELECT 1 FROM accounts WHERE id=OLD.account_id
    ) THEN
        -- Account deletion owns this FK cascade. Standalone assignment removal
        -- remains impossible, so an admitted live account can never regress.
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'feature activation assignment is immutable for a live account'
        USING ERRCODE='55000';
END
$$;

CREATE FUNCTION append_persistence_feature_activation_event()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    prior_generation bigint;
    prior_phase text;
    prior_rollout_basis_points bigint;
    prior_rollout_seed text;
    prior_explicit_canary_account_ids text[];
    prior_candidate_fleet_image_digest text;
    prior_producer_contract_sha256 text;
    prior_reconciliation_model text;
    prior_vertex_location text;
BEGIN
    -- This singleton row is the fleet-wide transaction fence. Application
    -- boundaries take KEY SHARE; a signed transition takes UPDATE.
    PERFORM 1 FROM persistence_feature_activation_contracts
     WHERE feature=NEW.feature FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'feature activation contract is missing'
            USING ERRCODE='55000';
    END IF;

    SELECT generation,phase,rollout_basis_points,rollout_seed,
           explicit_canary_account_ids,candidate_fleet_image_digest,
           reconciliation_producer_contract_sha256,
           reconciliation_model,vertex_location
      INTO prior_generation,prior_phase,prior_rollout_basis_points,prior_rollout_seed,
           prior_explicit_canary_account_ids,prior_candidate_fleet_image_digest,
           prior_producer_contract_sha256,
           prior_reconciliation_model,prior_vertex_location
      FROM persistence_feature_activation_events
     WHERE feature=NEW.feature ORDER BY generation DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.generation<>0 OR NEW.previous_phase<>'preactive' OR NEW.phase<>'installed' THEN
            RAISE EXCEPTION 'first feature activation event must install generation zero'
                USING ERRCODE='55000';
        END IF;
    ELSIF NEW.generation<>prior_generation+1 OR NEW.previous_phase<>prior_phase THEN
        RAISE EXCEPTION 'feature activation generation is stale or non-contiguous'
            USING ERRCODE='55000';
    ELSIF NOT (
        (prior_phase='installed' AND NEW.phase='draining')
        OR (prior_phase='draining' AND NEW.phase='active')
        OR (prior_phase='active' AND NEW.phase='paused')
        OR (prior_phase='paused' AND NEW.phase='draining')
        OR (prior_phase='paused' AND NEW.phase='active')
    ) THEN
        RAISE EXCEPTION 'feature activation phase transition is invalid'
            USING ERRCODE='55000';
    ELSIF NEW.phase IN ('active','paused')
       AND (
            NEW.rollout_basis_points IS DISTINCT FROM prior_rollout_basis_points
            OR NEW.rollout_seed IS DISTINCT FROM prior_rollout_seed
            OR NEW.explicit_canary_account_ids IS DISTINCT FROM
               prior_explicit_canary_account_ids
            OR NEW.candidate_fleet_image_digest IS DISTINCT FROM
               prior_candidate_fleet_image_digest
            OR NEW.reconciliation_producer_contract_sha256 IS DISTINCT FROM
               prior_producer_contract_sha256
            OR NEW.reconciliation_model IS DISTINCT FROM prior_reconciliation_model
            OR NEW.vertex_location IS DISTINCT FROM prior_vertex_location
       ) THEN
        RAISE EXCEPTION 'active and paused transitions must preserve fleet, rollout, and producer scope'
            USING ERRCODE='55000';
    ELSIF prior_phase='paused' AND NEW.phase='draining'
       AND (
            (prior_rollout_basis_points=10000 AND NEW.rollout_basis_points<>10000)
            OR (
                NEW.rollout_basis_points<>10000
                AND NOT (prior_explicit_canary_account_ids <@
                         NEW.explicit_canary_account_ids)
            )
       ) THEN
        RAISE EXCEPTION 'a later draining scope cannot remove activated accounts'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION capture_formation_stream_accepted_max(
    requested_account_id text,
    requested_stream_id text
)
RETURNS bigint LANGUAGE sql STABLE STRICT AS $$
    SELECT coalesce(max(accepted.sequence),-1)
      FROM (
            SELECT event.sequence
              FROM capture_events event
             WHERE event.account_id=requested_account_id
               AND event.stream_id=requested_stream_id
            UNION
            SELECT deleted.sequence
              FROM capture_formation_deleted_sequences deleted
             WHERE deleted.account_id=requested_account_id
               AND deleted.stream_id=requested_stream_id
      ) accepted
$$;

-- -1 is the exact empty prefix; -2 means the accepted set has a gap. Capture
-- sequences start at zero, so count/min/max prove contiguity without an
-- unbounded generate_series scan.
CREATE FUNCTION capture_formation_stream_contiguous_through(
    requested_account_id text,
    requested_stream_id text
)
RETURNS bigint LANGUAGE sql STABLE STRICT AS $$
    WITH accepted(sequence) AS (
        SELECT event.sequence
          FROM capture_events event
         WHERE event.account_id=requested_account_id
           AND event.stream_id=requested_stream_id
        UNION
        SELECT deleted.sequence
          FROM capture_formation_deleted_sequences deleted
         WHERE deleted.account_id=requested_account_id
           AND deleted.stream_id=requested_stream_id
    ), stats AS (
        SELECT count(*)::bigint AS accepted_count,min(sequence) AS minimum_sequence,
               max(sequence) AS maximum_sequence
          FROM accepted
    )
    SELECT CASE
        WHEN accepted_count=0 THEN -1
        WHEN minimum_sequence=0 AND maximum_sequence=accepted_count-1
            THEN maximum_sequence
        ELSE -2
    END
      FROM stats
$$;

CREATE FUNCTION capture_formation_stream_maxima_sha256(
    requested_account_id text,
    requested_capture_session_id text
)
RETURNS bytea LANGUAGE sql STABLE STRICT AS $$
    SELECT sha256(convert_to(
        coalesce(jsonb_agg(jsonb_build_array(
            stream.id,
            stream.committed_through_sequence,
            capture_formation_stream_accepted_max(stream.account_id,stream.id),
            stream.sealed_sequence,
            (SELECT coalesce(jsonb_agg(jsonb_build_array(
                        deleted.sequence,deleted.event_id,
                        deleted.original_manifest_digest,
                        deleted.deletion_episode_id,deleted.provenance
                    ) ORDER BY deleted.sequence),'[]'::jsonb)
               FROM capture_formation_deleted_sequences deleted
              WHERE deleted.account_id=stream.account_id
                AND deleted.stream_id=stream.id)
        ) ORDER BY stream.id),'[]'::jsonb)::text,
        'UTF8'
    ))
      FROM capture_streams stream
     WHERE stream.account_id=requested_account_id
       AND stream.capture_session_id=requested_capture_session_id
$$;

CREATE FUNCTION append_capture_formation_deleted_sequence()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    live_session_id text;
    live_stream_id text;
    live_sequence bigint;
    live_manifest_digest text;
BEGIN
    SELECT event.capture_session_id,event.stream_id,event.sequence,event.manifest_digest
      INTO live_session_id,live_stream_id,live_sequence,live_manifest_digest
      FROM capture_events event
     WHERE event.account_id=NEW.account_id AND event.event_id=NEW.event_id
     FOR KEY SHARE;
    IF NOT FOUND
       OR NEW.capture_session_id IS DISTINCT FROM live_session_id
       OR NEW.stream_id IS DISTINCT FROM live_stream_id
       OR NEW.sequence IS DISTINCT FROM live_sequence
       OR NEW.original_manifest_digest IS DISTINCT FROM live_manifest_digest THEN
        RAISE EXCEPTION 'capture deletion tombstone must bind an exact live event'
            USING ERRCODE='55000';
    END IF;
    PERFORM 1 FROM episode_deletions deletion
     WHERE deletion.account_id=NEW.account_id
       AND deletion.episode_id=NEW.deletion_episode_id
       AND deletion.state='pending'
       AND deletion.orphan_event_ids ? NEW.event_id
     FOR KEY SHARE;
    IF NOT FOUND THEN
        PERFORM 1
          FROM persistence_feature_episode_deletion_events planned
          JOIN persistence_feature_episode_deletion_progress progress
            ON progress.account_id=planned.account_id
           AND progress.episode_id=planned.episode_id
           AND progress.phase='tombstone_events'
         WHERE planned.account_id=NEW.account_id
           AND planned.episode_id=NEW.deletion_episode_id
           AND planned.event_id=NEW.event_id
           AND planned.capture_session_id=NEW.capture_session_id
           AND planned.stream_id=NEW.stream_id
           AND planned.sequence=NEW.sequence
           AND planned.manifest_digest=NEW.original_manifest_digest
           AND planned.purged_at IS NULL
         FOR KEY SHARE OF planned,progress;
    END IF;
    IF NOT FOUND OR NEW.provenance<>'episode_deletion_v1' THEN
        RAISE EXCEPTION 'capture deletion tombstone lacks a pending deletion receipt'
            USING ERRCODE='55000';
    END IF;
    NEW.deleted_at:=clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION guard_capture_formation_deleted_sequence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' AND (
        NOT EXISTS(SELECT 1 FROM capture_sessions session
                    WHERE session.account_id=OLD.account_id
                      AND session.id=OLD.capture_session_id)
        OR NOT EXISTS(SELECT 1 FROM capture_streams stream
                       WHERE stream.account_id=OLD.account_id
                         AND stream.id=OLD.stream_id)
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'capture deletion sequence history is append-only'
        USING ERRCODE='55000';
END
$$;

CREATE FUNCTION reject_deleted_capture_sequence()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(
        SELECT 1 FROM capture_formation_deleted_sequences deleted
         WHERE deleted.account_id=NEW.account_id
           AND (deleted.event_id=NEW.event_id
                OR (deleted.stream_id=NEW.stream_id
                    AND deleted.sequence=NEW.sequence))
    ) OR EXISTS(
        SELECT 1 FROM episode_deletions deletion
         WHERE deletion.account_id=NEW.account_id
           AND deletion.state='pending'
           AND (deletion.orphan_event_ids ? NEW.event_id
                OR deletion.orphan_event_ids ? NEW.canonical_event_id)
    ) OR EXISTS(
        SELECT 1
          FROM persistence_feature_episode_deletion_roots root
          JOIN persistence_feature_episode_deletion_progress progress
            ON progress.account_id=root.account_id
           AND progress.episode_id=root.episode_id
           AND progress.phase<>'complete'
         WHERE root.account_id=NEW.account_id
           AND root.disposition<>'pending'
           AND root.root_event_id IN (NEW.event_id,NEW.canonical_event_id)
    ) THEN
        RAISE EXCEPTION 'deleted or pending-deletion capture evidence cannot be admitted'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_pending_deleted_capture_projection()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    source_event_id text;
BEGIN
    IF TG_TABLE_NAME='utterances' THEN
        source_event_id:=split_part(substr(NEW.source_key,10),':',1);
    ELSIF TG_TABLE_NAME='screenshots' THEN
        source_event_id:=substr(NEW.source_key,10);
    ELSE
        RAISE EXCEPTION 'pending-deletion projection guard attached to an invalid relation'
            USING ERRCODE='55000';
    END IF;
    IF NEW.source_key LIKE 'cloud-v2:%'
       AND source_event_id<>''
       AND EXISTS(
            SELECT 1 FROM episode_deletions deletion
             WHERE deletion.account_id=NEW.account_id
               AND deletion.state='pending'
               AND deletion.orphan_event_ids ? source_event_id
            UNION ALL
            SELECT 1
              FROM capture_events event
              JOIN persistence_feature_episode_deletion_roots root
                ON root.account_id=event.account_id
               AND root.root_event_id=coalesce(event.canonical_event_id,event.event_id)
               AND root.disposition<>'pending'
              JOIN persistence_feature_episode_deletion_progress progress
                ON progress.account_id=root.account_id
               AND progress.episode_id=root.episode_id
               AND progress.phase<>'complete'
             WHERE event.account_id=NEW.account_id
               AND event.event_id=source_event_id
       ) THEN
        RAISE EXCEPTION 'pending episode deletion refuses a new source projection'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_pending_deleted_episode_member()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(
        WITH projection_event_ids(event_id) AS (
            SELECT split_part(substr(utterance.source_key,10),':',1)
              FROM utterances utterance
             WHERE NEW.record_type='utterance'
               AND utterance.account_id=NEW.account_id
               AND utterance.id=NEW.record_id
               AND utterance.source_key LIKE 'cloud-v2:%'
            UNION
            SELECT observation.event_id
              FROM utterances utterance
              JOIN speaker_observations observation
                ON observation.account_id=utterance.account_id
               AND observation.id=utterance.speaker_observation_id
             WHERE NEW.record_type='utterance'
               AND utterance.account_id=NEW.account_id
               AND utterance.id=NEW.record_id
            UNION
            SELECT source.event_id
              FROM utterances utterance
              JOIN speaker_observation_sources source
                ON source.account_id=utterance.account_id
               AND source.speaker_observation_id=utterance.speaker_observation_id
             WHERE NEW.record_type='utterance'
               AND utterance.account_id=NEW.account_id
               AND utterance.id=NEW.record_id
            UNION
            SELECT substr(screenshot.source_key,10)
              FROM screenshots screenshot
             WHERE NEW.record_type='screenshot'
               AND screenshot.account_id=NEW.account_id
               AND screenshot.id=NEW.record_id
               AND screenshot.source_key LIKE 'cloud-v2:%'
            UNION
            SELECT observation.event_id
              FROM visual_speaker_observations observation
             WHERE NEW.record_type='screenshot'
               AND observation.account_id=NEW.account_id
               AND observation.screenshot_id=NEW.record_id
        ), family_ids(event_id) AS (
            SELECT event.event_id FROM capture_events event
              JOIN projection_event_ids source ON source.event_id=event.event_id
             WHERE event.account_id=NEW.account_id
            UNION
            SELECT coalesce(event.canonical_event_id,event.event_id)
              FROM capture_events event
              JOIN projection_event_ids source ON source.event_id=event.event_id
             WHERE event.account_id=NEW.account_id
        )
        SELECT 1 FROM episode_deletions deletion
          JOIN family_ids family
            ON deletion.orphan_event_ids ? family.event_id
         WHERE deletion.account_id=NEW.account_id
           AND deletion.state='pending'
        UNION ALL
        SELECT 1
          FROM family_ids family
          JOIN capture_events event
            ON event.account_id=NEW.account_id AND event.event_id=family.event_id
          JOIN persistence_feature_episode_deletion_roots root
            ON root.account_id=event.account_id
           AND root.root_event_id=coalesce(event.canonical_event_id,event.event_id)
           AND root.disposition<>'pending'
          JOIN persistence_feature_episode_deletion_progress progress
            ON progress.account_id=root.account_id
           AND progress.episode_id=root.episode_id
           AND progress.phase<>'complete'
    ) THEN
        RAISE EXCEPTION 'pending episode deletion refuses a new episode source owner'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION require_capture_event_deletion_tombstone()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Account/session erasure owns its normal FK cascade. A live-session event
    -- may only be removed after the episode-deletion transaction has appended
    -- the exact accepted-sequence tombstone, including reference rows deleted
    -- by capture_events' canonical-event cascade.
    IF NOT EXISTS(
        SELECT 1 FROM capture_sessions session
         WHERE session.account_id=OLD.account_id
           AND session.id=OLD.capture_session_id
    ) OR EXISTS(
        SELECT 1 FROM capture_formation_deleted_sequences deleted
         WHERE deleted.account_id=OLD.account_id
           AND deleted.capture_session_id=OLD.capture_session_id
           AND deleted.stream_id=OLD.stream_id
           AND deleted.sequence=OLD.sequence
           AND deleted.event_id=OLD.event_id
           AND deleted.original_manifest_digest=OLD.manifest_digest
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'live-session capture deletion requires an exact sequence tombstone'
        USING ERRCODE='55000';
END
$$;

CREATE FUNCTION append_capture_formation_seal_event()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    receipt_revision bigint;
    receipt_generation bigint;
    receipt_finish_requested_at timestamptz;
    receipt_seal_finalized_at timestamptz;
    prior_seal_generation bigint;
BEGIN
    SELECT source_revision,seal_generation,finish_requested_at,seal_finalized_at
      INTO receipt_revision,receipt_generation,receipt_finish_requested_at,
           receipt_seal_finalized_at
      FROM capture_formation_receipts
     WHERE account_id=NEW.account_id
       AND capture_session_id=NEW.capture_session_id
     FOR UPDATE;
    IF NOT FOUND OR NEW.source_revision<>receipt_revision THEN
        RAISE EXCEPTION 'capture seal event source revision is stale'
            USING ERRCODE='55000';
    END IF;
    SELECT coalesce(max(seal_generation),0) INTO prior_seal_generation
      FROM capture_formation_seal_events
     WHERE account_id=NEW.account_id
       AND capture_session_id=NEW.capture_session_id
       AND event_kind='seal';
    IF NEW.event_kind='seal' THEN
        IF NEW.trigger_event_id IS NOT NULL
           OR receipt_finish_requested_at IS NULL
           OR receipt_seal_finalized_at IS NOT NULL
           OR receipt_generation<>prior_seal_generation
           OR NEW.seal_generation<>prior_seal_generation+1
           OR NEW.provenance NOT IN (
                'quiet_contiguous_v1','legacy_quiet_contiguous_v1','topology_rebind_v1'
           )
           OR NOT EXISTS(
                SELECT 1 FROM capture_streams stream
                 WHERE stream.account_id=NEW.account_id
                   AND stream.capture_session_id=NEW.capture_session_id
           )
           OR EXISTS(
                SELECT 1 FROM capture_streams stream
                 WHERE stream.account_id=NEW.account_id
                   AND stream.capture_session_id=NEW.capture_session_id
                   AND (stream.committed_through_sequence IS DISTINCT FROM
                           capture_formation_stream_accepted_max(
                               stream.account_id,stream.id)
                        OR stream.committed_through_sequence IS DISTINCT FROM
                           capture_formation_stream_contiguous_through(
                               stream.account_id,stream.id)
                        OR stream.sealed_sequence IS DISTINCT FROM
                           stream.committed_through_sequence)
           ) THEN
            RAISE EXCEPTION 'capture seal event is not the next exact contiguous seal'
                USING ERRCODE='55000';
        END IF;
    ELSIF NEW.event_kind='reopen' THEN
        IF NEW.trigger_event_id IS NULL
           OR receipt_seal_finalized_at IS NULL
           OR NEW.seal_generation<>receipt_generation
           OR NEW.seal_generation<>prior_seal_generation
           OR NEW.provenance<>'late_source_reopen_v1'
           OR NOT EXISTS(
                SELECT 1 FROM capture_formation_seal_events prior
                 WHERE prior.account_id=NEW.account_id
                   AND prior.capture_session_id=NEW.capture_session_id
                   AND prior.seal_generation=NEW.seal_generation
                   AND prior.event_kind='seal'
           ) THEN
            RAISE EXCEPTION 'capture seal reopen does not identify the current finalized generation'
                USING ERRCODE='55000';
        END IF;
        PERFORM 1 FROM capture_events event
         WHERE event.account_id=NEW.account_id
           AND event.event_id=NEW.trigger_event_id
           AND event.capture_session_id=NEW.capture_session_id
         FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'capture seal reopen trigger event is not live in this session'
                USING ERRCODE='55000';
        END IF;
    END IF;
    IF NEW.stream_maxima_sha256 IS DISTINCT FROM
       capture_formation_stream_maxima_sha256(NEW.account_id,NEW.capture_session_id) THEN
        RAISE EXCEPTION 'capture seal stream-maxima commitment is not canonical'
            USING ERRCODE='55000';
    END IF;
    NEW.recorded_at:=clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION guard_capture_formation_seal_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' AND NOT EXISTS(
        SELECT 1 FROM capture_sessions session
         WHERE session.account_id=OLD.account_id
           AND session.id=OLD.capture_session_id
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'capture formation seal history is append-only'
        USING ERRCODE='55000';
END
$$;

-- Installed while v26 remains live, but attached to `episodes` only in the
-- signed draining transaction. The guard catches even lingering v0.9.16
-- settlement code before the bounded claim drain begins and refuses a
-- draft->finalized transition for every account selected by immutable
-- draining/active history.
CREATE FUNCTION enforce_assigned_episode_finalization()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    is_assigned boolean;
    was_selected_for_reconciliation boolean;
BEGIN
    -- Revocation/cleanup is always permitted. Any scoped draft which would
    -- leave this row carrying a claim or a finalization is a legacy lane and
    -- is refused, including claim acquisition after a completed drain cursor.
    IF NEW.structure_state<>'draft'
       OR (NEW.finalized_at IS NULL AND NEW.finalization_claim_token IS NULL) THEN
        RETURN NEW;
    END IF;

    SELECT EXISTS(
        SELECT 1 FROM persistence_feature_activation_assignments assignment
         WHERE assignment.feature='episode_topology_reconciliation'
           AND assignment.account_id=NEW.account_id
    ) INTO is_assigned;

    -- Derive stickiness from immutable draining/active event history, not an
    -- INSERT in this transaction: raising below rolls the old settlement back.
    -- Thus the drain itself and every later pause remain permanently fenced.
    SELECT EXISTS(
        SELECT 1 FROM persistence_feature_activation_events event
         WHERE event.feature='episode_topology_reconciliation'
           AND event.phase IN ('draining','active')
           AND (
                NEW.account_id=ANY(event.explicit_canary_account_ids)
                OR event.rollout_basis_points=10000
           )
    ) INTO was_selected_for_reconciliation;

    IF is_assigned OR was_selected_for_reconciliation THEN
        RAISE EXCEPTION 'assigned account draft claims and finalization require reconciliation'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER persistence_feature_activation_contracts_immutable
BEFORE UPDATE OR DELETE ON persistence_feature_activation_contracts
FOR EACH ROW EXECUTE FUNCTION deny_persistence_feature_activation_mutation();

CREATE TRIGGER persistence_feature_activation_events_append
BEFORE INSERT ON persistence_feature_activation_events
FOR EACH ROW EXECUTE FUNCTION append_persistence_feature_activation_event();

CREATE TRIGGER persistence_feature_activation_events_immutable
BEFORE UPDATE OR DELETE ON persistence_feature_activation_events
FOR EACH ROW EXECUTE FUNCTION deny_persistence_feature_activation_mutation();

CREATE TRIGGER persistence_feature_activation_assignments_immutable
BEFORE UPDATE OR DELETE ON persistence_feature_activation_assignments
FOR EACH ROW EXECUTE FUNCTION guard_persistence_feature_activation_assignment_mutation();

-- A source revision is dirty until the formation worker settles that exact
-- revision, including an explicit no-memory outcome. New evidence increments
-- source_revision and invalidates any older claim atomically.
CREATE TABLE capture_formation_receipts (
    account_id text NOT NULL,
    capture_session_id text NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision>=1),
    completed_revision bigint NOT NULL DEFAULT 0
        CHECK (completed_revision>=0 AND completed_revision<=source_revision),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','processing','retry_wait','complete')),
    claimed_revision bigint,
    claim_token text,
    claim_until timestamptz,
    next_attempt_at timestamptz,
    attempt_count bigint NOT NULL DEFAULT 0 CHECK (attempt_count>=0),
    completed_outcome text CHECK (completed_outcome IN ('memories','no_memory','accounted')),
    completed_claim_token text,
    claimed_source_fingerprint bytea CHECK (
        claimed_source_fingerprint IS NULL OR octet_length(claimed_source_fingerprint)=32
    ),
    completed_source_fingerprint bytea CHECK (
        completed_source_fingerprint IS NULL OR octet_length(completed_source_fingerprint)=32
    ),
    completed_at timestamptz,
    finish_requested_at timestamptz,
    finish_request_provenance text CHECK (
        finish_request_provenance IS NULL OR finish_request_provenance IN (
            'event_finish_v1','finish_endpoint_v1','legacy_client_refinish_v1',
            'legacy_ended_v1'
        )
    ),
    seal_finalized_at timestamptz,
    seal_generation bigint NOT NULL DEFAULT 0 CHECK (seal_generation>=0),
    seal_finalization_provenance text CHECK (
        seal_finalization_provenance IS NULL OR seal_finalization_provenance IN (
            'quiet_contiguous_v1','legacy_quiet_contiguous_v1','topology_rebind_v1'
        )
    ),
    last_error_code text,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,capture_session_id),
    FOREIGN KEY(account_id,capture_session_id)
        REFERENCES capture_sessions(account_id,id) ON DELETE CASCADE,
    CHECK (
        (state='processing') =
        (claim_token IS NOT NULL AND claim_until IS NOT NULL AND claimed_revision IS NOT NULL
            AND claimed_source_fingerprint IS NOT NULL)
    ),
    CHECK (claimed_revision IS NULL OR claimed_revision<=source_revision),
    CHECK ((state='complete')=(completed_revision=source_revision)),
    CHECK (
        (state='complete') =
        (completed_outcome IS NOT NULL AND completed_claim_token IS NOT NULL
            AND completed_source_fingerprint IS NOT NULL AND completed_at IS NOT NULL)
    ),
    CHECK ((state='complete')=(completed_claim_token IS NOT NULL)),
    CHECK ((state='complete')=(completed_source_fingerprint IS NOT NULL)),
    CHECK ((state='complete')=(completed_outcome IS NOT NULL)),
    CHECK ((state='complete')=(completed_at IS NOT NULL)),
    CHECK (
        (finish_requested_at IS NULL)=(finish_request_provenance IS NULL)
    ),
    CHECK (
        (seal_finalized_at IS NULL)=(seal_finalization_provenance IS NULL)
    ),
    CHECK (
        seal_finalized_at IS NULL OR (
            finish_requested_at IS NOT NULL AND seal_generation>=1
        )
    )
);
CREATE INDEX capture_formation_receipts_pending_idx
    ON capture_formation_receipts(updated_at,account_id,capture_session_id)
    WHERE source_revision>completed_revision;
CREATE INDEX capture_formation_receipts_seal_pending_idx
    ON capture_formation_receipts(account_id,finish_requested_at,capture_session_id)
    WHERE finish_requested_at IS NOT NULL AND seal_finalized_at IS NULL;

-- Exact-session formation is page-accounted rather than truncated at the
-- model input ceiling.  The covered arrays name every source in a bounded
-- page; the provider arrays are the exact unowned subset visible to the
-- model.  A response is staged as an ephemeral JSONB string before parsing so
-- claim loss can replay settlement without another provider request.  It is
-- cleared atomically at terminal page settlement or revision invalidation.
CREATE TABLE capture_formation_pages (
    account_id text NOT NULL,
    capture_session_id text NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision>=1),
    page_index bigint NOT NULL CHECK (page_index>=0),
    source_fingerprint bytea NOT NULL CHECK (octet_length(source_fingerprint)=32),
    page_source_commitment bytea NOT NULL CHECK (octet_length(page_source_commitment)=32),
    covered_utterance_ids bigint[] NOT NULL DEFAULT '{}',
    covered_screenshot_ids bigint[] NOT NULL DEFAULT '{}',
    provider_utterance_ids bigint[] NOT NULL DEFAULT '{}',
    provider_screenshot_ids bigint[] NOT NULL DEFAULT '{}',
    has_more boolean NOT NULL,
    state text NOT NULL CHECK (state IN ('processing','retry_wait','complete','invalidated')),
    claim_token text,
    claim_until timestamptz,
    provider_attempt bigint NOT NULL DEFAULT 1 CHECK (provider_attempt>=1),
    provider_request jsonb,
    provider_request_sha256 bytea CHECK (
        provider_request_sha256 IS NULL OR octet_length(provider_request_sha256)=32
    ),
    staged_response jsonb,
    staged_response_sha256 bytea CHECK (
        staged_response_sha256 IS NULL OR octet_length(staged_response_sha256)=32
    ),
    staged_vertex_event_id text,
    completed_outcome text CHECK (completed_outcome IN ('memories','no_memory','accounted')),
    successor_episode_ids bigint[],
    completed_claim_token text,
    completed_at timestamptz,
    last_error_code text,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,capture_session_id,source_revision,page_index),
    UNIQUE(account_id,capture_session_id,source_revision,page_source_commitment),
    FOREIGN KEY(account_id,capture_session_id)
        REFERENCES capture_sessions(account_id,id) ON DELETE CASCADE,
    CHECK (cardinality(covered_utterance_ids)<=4000),
    CHECK (cardinality(covered_screenshot_ids)<=2000),
    CHECK (provider_utterance_ids<@covered_utterance_ids),
    CHECK (provider_screenshot_ids<@covered_screenshot_ids),
    CHECK ((state='processing')=(claim_token IS NOT NULL AND claim_until IS NOT NULL)),
    CHECK ((provider_request IS NULL)=(provider_request_sha256 IS NULL)),
    CHECK (provider_request IS NULL OR
           octet_length(provider_request #>> '{}')<=16777216),
    CHECK ((staged_response IS NULL)=(staged_response_sha256 IS NULL)),
    CHECK (staged_response IS NULL OR
           octet_length(staged_response #>> '{}')<=2097152),
    CHECK ((staged_response IS NULL)=(staged_vertex_event_id IS NULL)),
    CHECK (staged_response IS NULL OR provider_request IS NOT NULL),
    CHECK ((state='complete')=(completed_outcome IS NOT NULL AND successor_episode_ids IS NOT NULL
                               AND completed_claim_token IS NOT NULL AND completed_at IS NOT NULL)),
    CHECK (state<>'complete' OR (provider_request IS NULL AND staged_response IS NULL))
);
CREATE INDEX capture_formation_pages_resume_idx
    ON capture_formation_pages(account_id,capture_session_id,source_revision,page_index)
    WHERE state<>'complete' AND state<>'invalidated';

-- Providerless reconciliation proves arbitrarily large capture-session
-- neighborhoods in bounded pages. Discovery is repeated after every envelope
-- expansion, then a second full verification generation must reproduce the
-- exact ordered commitment and count. Only `ready` may authorize KEEP.
CREATE TABLE persistence_feature_reconciliation_neighborhood_scans (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    component_seed_sha256 bytea NOT NULL CHECK (octet_length(component_seed_sha256)=32),
    predecessor_episode_ids bigint[] NOT NULL,
    phase text NOT NULL CHECK (phase IN ('discovery','verification','ready')),
    closure_generation bigint NOT NULL DEFAULT 1 CHECK (closure_generation>=1),
    closure_started_ms bigint NOT NULL,
    closure_ended_ms bigint NOT NULL CHECK (closure_ended_ms>=closure_started_ms),
    pass_started_ms bigint NOT NULL,
    pass_ended_ms bigint NOT NULL CHECK (pass_ended_ms>=pass_started_ms),
    cursor_session_id text,
    rolling_commitment bytea NOT NULL CHECK (octet_length(rolling_commitment)=32),
    rolling_count bigint NOT NULL DEFAULT 0 CHECK (rolling_count>=0),
    discovery_commitment bytea CHECK (
        discovery_commitment IS NULL OR octet_length(discovery_commitment)=32
    ),
    discovery_count bigint CHECK (discovery_count IS NULL OR discovery_count>=0),
    verification_generation bigint NOT NULL DEFAULT 0 CHECK (verification_generation>=0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(account_id,component_seed_sha256,closure_generation),
    CHECK (cardinality(predecessor_episode_ids)>0),
    CHECK ((discovery_commitment IS NULL)=(discovery_count IS NULL)),
    CHECK ((phase='discovery')=(discovery_commitment IS NULL AND discovery_count IS NULL)),
    CHECK (phase<>'ready' OR (
        verification_generation>=1 AND cursor_session_id IS NULL
        AND discovery_commitment IS NOT NULL AND discovery_count IS NOT NULL
        AND rolling_commitment=discovery_commitment
        AND rolling_count=discovery_count
    ))
);

CREATE TABLE persistence_feature_reconciliation_neighborhood_members (
    account_id text NOT NULL,
    component_seed_sha256 bytea NOT NULL CHECK (octet_length(component_seed_sha256)=32),
    closure_generation bigint NOT NULL CHECK (closure_generation>=1),
    session_id text NOT NULL,
    started_ms bigint NOT NULL,
    ended_ms bigint NOT NULL CHECK (ended_ms>=started_ms),
    guard_commitment bytea NOT NULL CHECK (octet_length(guard_commitment)=32),
    settled boolean NOT NULL,
    PRIMARY KEY(account_id,session_id),
    FOREIGN KEY(account_id,component_seed_sha256,closure_generation)
        REFERENCES persistence_feature_reconciliation_neighborhood_scans(
            account_id,component_seed_sha256,closure_generation
        )
        ON DELETE CASCADE
);
CREATE INDEX persistence_feature_reconciliation_neighborhood_members_generation_idx
    ON persistence_feature_reconciliation_neighborhood_members(
        account_id,closure_generation,session_id
    );

CREATE TABLE capture_formation_seal_events (
    account_id text NOT NULL,
    capture_session_id text NOT NULL,
    seal_generation bigint NOT NULL CHECK (seal_generation>=1),
    source_revision bigint NOT NULL CHECK (source_revision>=1),
    event_kind text NOT NULL CHECK (event_kind IN ('seal','reopen')),
    trigger_event_id text,
    stream_maxima_sha256 bytea NOT NULL CHECK (octet_length(stream_maxima_sha256)=32),
    provenance text NOT NULL CHECK (provenance IN (
        'quiet_contiguous_v1','legacy_quiet_contiguous_v1','topology_rebind_v1',
        'late_source_reopen_v1'
    )),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,capture_session_id,seal_generation,event_kind),
    FOREIGN KEY(account_id,capture_session_id)
        REFERENCES capture_sessions(account_id,id) ON DELETE CASCADE,
    CHECK (
        (event_kind='seal' AND provenance IN (
            'quiet_contiguous_v1','legacy_quiet_contiguous_v1','topology_rebind_v1'
        )) OR (event_kind='reopen' AND provenance='late_source_reopen_v1')
    ),
    CHECK ((event_kind='seal')=(trigger_event_id IS NULL))
);
CREATE TRIGGER capture_formation_seal_events_append
BEFORE INSERT ON capture_formation_seal_events
FOR EACH ROW EXECUTE FUNCTION append_capture_formation_seal_event();
CREATE TRIGGER capture_formation_seal_events_immutable
BEFORE UPDATE OR DELETE ON capture_formation_seal_events
FOR EACH ROW EXECUTE FUNCTION guard_capture_formation_seal_event_mutation();

CREATE TRIGGER capture_formation_deleted_sequences_append
BEFORE INSERT ON capture_formation_deleted_sequences
FOR EACH ROW EXECUTE FUNCTION append_capture_formation_deleted_sequence();
CREATE TRIGGER capture_formation_deleted_sequences_immutable
BEFORE UPDATE OR DELETE ON capture_formation_deleted_sequences
FOR EACH ROW EXECUTE FUNCTION guard_capture_formation_deleted_sequence_mutation();
CREATE TRIGGER capture_events_00_reject_deleted_sequence
BEFORE INSERT ON capture_events
FOR EACH ROW EXECUTE FUNCTION reject_deleted_capture_sequence();
CREATE TRIGGER capture_events_01_require_deleted_sequence
BEFORE DELETE ON capture_events
FOR EACH ROW EXECUTE FUNCTION require_capture_event_deletion_tombstone();
CREATE TRIGGER utterances_00_reject_pending_deleted_capture_projection
BEFORE INSERT OR UPDATE OF source_key ON utterances
FOR EACH ROW EXECUTE FUNCTION reject_pending_deleted_capture_projection();
CREATE TRIGGER screenshots_00_reject_pending_deleted_capture_projection
BEFORE INSERT OR UPDATE OF source_key ON screenshots
FOR EACH ROW EXECUTE FUNCTION reject_pending_deleted_capture_projection();
