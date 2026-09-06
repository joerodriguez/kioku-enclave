-- Independent, additive orphan-erasure authority. This does not change the
-- immutable v27 activation catalog, schema marker, accepted-sequence history,
-- or any activation/formation function. Only the signed migrator installs it.

CREATE TABLE orphan_capture_erasure_contract (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    ddl_sha256 bytea NOT NULL CHECK (octet_length(ddl_sha256)=32),
    catalog_sha256 bytea NOT NULL CHECK (octet_length(catalog_sha256)=32),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE orphan_capture_erasure_operations (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    operation_id text NOT NULL CHECK (operation_id ~ '^[a-zA-Z0-9_-]{1,128}$'),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256)=32),
    request_signature bytea NOT NULL CHECK (octet_length(request_signature)=64),
    request_key_sha256 bytea NOT NULL CHECK (octet_length(request_key_sha256)=32),
    scope_sha256 bytea NOT NULL CHECK (octet_length(scope_sha256)=32),
    object_inventory_sha256 bytea NOT NULL CHECK (octet_length(object_inventory_sha256)=32),
    provider_names_sha256 bytea NOT NULL CHECK (octet_length(provider_names_sha256)=32),
    provider_name_count bigint NOT NULL CHECK (provider_name_count BETWEEN 0 AND 512),
    account_provider_names_sha256 bytea NOT NULL CHECK (octet_length(account_provider_names_sha256)=32),
    survivor_sha256 bytea NOT NULL CHECK (octet_length(survivor_sha256)=32),
    activation_generation bigint NOT NULL CHECK (activation_generation>0),
    candidate_image_digest text NOT NULL CHECK (candidate_image_digest ~ '^sha256:[0-9a-f]{64}$'),
    activation_contract_sha256 bytea NOT NULL CHECK (octet_length(activation_contract_sha256)=32),
    activation_catalog_sha256 bytea NOT NULL CHECK (octet_length(activation_catalog_sha256)=32),
    activation_receipt_sha256 bytea NOT NULL CHECK (octet_length(activation_receipt_sha256)=32),
    provider_authority_sha256 bytea NOT NULL CHECK (octet_length(provider_authority_sha256)=32),
    protected_control_proof_sha256 bytea NOT NULL CHECK (octet_length(protected_control_proof_sha256)=32),
    session_count bigint NOT NULL CHECK (session_count BETWEEN 1 AND 4),
    stream_count bigint NOT NULL CHECK (stream_count BETWEEN 1 AND 16),
    event_count bigint NOT NULL CHECK (event_count BETWEEN 1 AND 256),
    object_count bigint NOT NULL CHECK (object_count BETWEEN 0 AND 256),
    CHECK (provider_name_count=2*object_count),
    projection_count bigint NOT NULL CHECK (projection_count BETWEEN 0 AND 1024),
    capture_upload_fenced boolean NOT NULL DEFAULT true,
    state text NOT NULL DEFAULT 'preparing'
        CHECK (state IN ('preparing','provider_pending','provider_verified','complete')),
    prepared_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    sealed_at timestamptz,
    provider_verified_at timestamptz,
    provider_ack_request_sha256 bytea CHECK (octet_length(provider_ack_request_sha256)=32),
    provider_ack_signature bytea CHECK (octet_length(provider_ack_signature)=64),
    completed_at timestamptz,
    provider_receipt_sha256 bytea CHECK (octet_length(provider_receipt_sha256)=32),
    completion_request_sha256 bytea CHECK (octet_length(completion_request_sha256)=32),
    completion_signature bytea CHECK (octet_length(completion_signature)=64),
    fence_release_request_sha256 bytea CHECK (octet_length(fence_release_request_sha256)=32),
    fence_release_signature bytea CHECK (octet_length(fence_release_signature)=64),
    fence_release_generation bigint CHECK (fence_release_generation>activation_generation),
    fence_release_candidate_image_digest text CHECK (
        fence_release_candidate_image_digest ~ '^sha256:[0-9a-f]{64}$'
        AND fence_release_candidate_image_digest<>candidate_image_digest),
    fence_release_activation_receipt_sha256 bytea CHECK (octet_length(fence_release_activation_receipt_sha256)=32),
    fence_release_fleet_evidence_sha256 bytea CHECK (octet_length(fence_release_fleet_evidence_sha256)=32),
    fence_release_protected_canary_sha256 bytea CHECK (octet_length(fence_release_protected_canary_sha256)=32),
    fence_release_admission_contract_sha256 bytea CHECK (octet_length(fence_release_admission_contract_sha256)=32),
    fence_released_at timestamptz,
    PRIMARY KEY(account_id,operation_id),
    CHECK ((state='preparing')=(sealed_at IS NULL)),
    CHECK ((state IN ('provider_verified','complete'))=(provider_verified_at IS NOT NULL)),
    CHECK ((state IN ('provider_verified','complete'))=(provider_ack_request_sha256 IS NOT NULL)),
    CHECK ((state IN ('provider_verified','complete'))=(provider_ack_signature IS NOT NULL)),
    CHECK ((state='complete')=(completed_at IS NOT NULL)),
    CHECK ((state IN ('provider_verified','complete'))=(provider_receipt_sha256 IS NOT NULL)),
    CHECK ((state='complete')=(completion_request_sha256 IS NOT NULL)),
    CHECK ((state='complete')=(completion_signature IS NOT NULL)),
    CHECK (capture_upload_fenced=(fence_released_at IS NULL)),
    CHECK (capture_upload_fenced=(fence_release_request_sha256 IS NULL)),
    CHECK (capture_upload_fenced=(fence_release_signature IS NULL)),
    CHECK (capture_upload_fenced=(fence_release_generation IS NULL)),
    CHECK (capture_upload_fenced=(fence_release_candidate_image_digest IS NULL)),
    CHECK (capture_upload_fenced=(fence_release_activation_receipt_sha256 IS NULL)),
    CHECK (capture_upload_fenced=(fence_release_fleet_evidence_sha256 IS NULL)),
    CHECK (capture_upload_fenced=(fence_release_protected_canary_sha256 IS NULL)),
    CHECK (capture_upload_fenced=(fence_release_admission_contract_sha256 IS NULL)),
    CHECK (capture_upload_fenced OR state='complete')
);
CREATE INDEX orphan_capture_erasure_operations_pending_idx
    ON orphan_capture_erasure_operations(state,account_id,operation_id);
CREATE UNIQUE INDEX orphan_capture_erasure_operations_one_fence_idx
    ON orphan_capture_erasure_operations(account_id) WHERE capture_upload_fenced;

-- Tombstones deliberately do not reference the erased session/stream/event.
-- Their only cascade is whole-account erasure, never accepted-sequence repair.
CREATE TABLE orphan_capture_erasure_sessions (
    account_id text NOT NULL,
    capture_session_id text NOT NULL,
    operation_id text NOT NULL,
    PRIMARY KEY(account_id,capture_session_id),
    UNIQUE(account_id,capture_session_id,operation_id),
    FOREIGN KEY(account_id,operation_id)
        REFERENCES orphan_capture_erasure_operations(account_id,operation_id) ON DELETE CASCADE
);
CREATE TABLE orphan_capture_erasure_streams (
    account_id text NOT NULL,
    stream_id text NOT NULL,
    capture_session_id text NOT NULL,
    operation_id text NOT NULL,
    PRIMARY KEY(account_id,stream_id),
    UNIQUE(account_id,stream_id,capture_session_id,operation_id),
    FOREIGN KEY(account_id,capture_session_id,operation_id)
        REFERENCES orphan_capture_erasure_sessions(account_id,capture_session_id,operation_id)
        ON DELETE CASCADE
);
CREATE TABLE orphan_capture_erasure_events (
    account_id text NOT NULL,
    event_id text NOT NULL,
    asset_id text NOT NULL,
    stream_id text NOT NULL,
    capture_session_id text NOT NULL,
    operation_id text NOT NULL,
    PRIMARY KEY(account_id,event_id),
    UNIQUE(account_id,asset_id),
    UNIQUE(account_id,event_id,asset_id,operation_id),
    FOREIGN KEY(account_id,stream_id,capture_session_id,operation_id)
        REFERENCES orphan_capture_erasure_streams(account_id,stream_id,capture_session_id,operation_id)
        ON DELETE CASCADE
);
CREATE TABLE orphan_capture_erasure_objects (
    account_id text NOT NULL,
    operation_id text NOT NULL,
    object_key text NOT NULL,
    object_generation bigint NOT NULL CHECK (object_generation>0),
    event_id text NOT NULL,
    asset_id text NOT NULL,
    byte_length bigint NOT NULL CHECK (byte_length>=0),
    original_sha256 text NOT NULL CHECK (original_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY(account_id,operation_id,object_key),
    UNIQUE(account_id,object_key),
    FOREIGN KEY(account_id,event_id,asset_id,operation_id)
        REFERENCES orphan_capture_erasure_events(account_id,event_id,asset_id,operation_id)
        ON DELETE CASCADE,
    CHECK (account_id ~ '^[a-zA-Z0-9_-]{1,128}$'),
    CHECK (asset_id ~ '^[a-zA-Z0-9_-]{1,128}$'),
    CHECK (event_id ~ '^[a-zA-Z0-9_-]{1,128}$'),
    CHECK (object_key IN ('raw/'||account_id||'/'||asset_id||'.enc',
                         'recordings/'||account_id||'/'||asset_id||'.enc'))
);

CREATE FUNCTION orphan_capture_erasure_guard_inventory_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM orphan_capture_erasure_operations operation
     WHERE operation.account_id=NEW.account_id AND operation.operation_id=NEW.operation_id
       AND operation.state='preparing' FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'orphan erasure inventory is sealed' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER orphan_capture_erasure_sessions_insert
    BEFORE INSERT ON orphan_capture_erasure_sessions
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_inventory_insert();
CREATE TRIGGER orphan_capture_erasure_streams_insert
    BEFORE INSERT ON orphan_capture_erasure_streams
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_inventory_insert();
CREATE TRIGGER orphan_capture_erasure_events_insert
    BEFORE INSERT ON orphan_capture_erasure_events
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_inventory_insert();
CREATE TRIGGER orphan_capture_erasure_objects_insert
    BEFORE INSERT ON orphan_capture_erasure_objects
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_inventory_insert();

CREATE FUNCTION orphan_capture_erasure_require_sealed_commit()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    account_key text:=CASE WHEN TG_OP='DELETE' THEN OLD.account_id ELSE NEW.account_id END;
    operation_key text:=CASE WHEN TG_OP='DELETE' THEN OLD.operation_id ELSE NEW.operation_id END;
    operation_state text;
    expected_objects bigint;
    actual_objects bigint;
BEGIN
    SELECT state,object_count INTO operation_state,expected_objects
      FROM orphan_capture_erasure_operations
     WHERE account_id=account_key AND operation_id=operation_key;
    IF NOT FOUND THEN
        RETURN NULL; -- Whole-account deletion also owns the journal cascade.
    END IF;
    IF operation_state='preparing' THEN
        RAISE EXCEPTION 'unsealed orphan erasure cannot commit' USING ERRCODE='55000';
    END IF;
    SELECT count(*) INTO actual_objects FROM orphan_capture_erasure_objects
     WHERE account_id=account_key AND operation_id=operation_key;
    IF (operation_state='complete' AND actual_objects<>0)
       OR (operation_state<>'complete' AND actual_objects<>expected_objects) THEN
        RAISE EXCEPTION 'orphan erasure completion and inventory scrub must be atomic'
            USING ERRCODE='55000';
    END IF;
    RETURN NULL;
END
$$;
CREATE CONSTRAINT TRIGGER orphan_capture_erasure_sealed_commit
    AFTER INSERT OR UPDATE ON orphan_capture_erasure_operations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION orphan_capture_erasure_require_sealed_commit();
CREATE CONSTRAINT TRIGGER orphan_capture_erasure_inventory_commit
    AFTER INSERT OR DELETE ON orphan_capture_erasure_objects
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION orphan_capture_erasure_require_sealed_commit();

CREATE FUNCTION orphan_capture_erasure_guard_history()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' AND TG_TABLE_NAME<>'orphan_capture_erasure_contract' THEN
        IF NOT EXISTS(SELECT 1 FROM accounts WHERE id=OLD.account_id) THEN
            RETURN OLD;
        END IF;
        IF TG_TABLE_NAME='orphan_capture_erasure_objects' THEN
            IF EXISTS(SELECT 1 FROM orphan_capture_erasure_operations operation
                       WHERE operation.account_id=OLD.account_id
                         AND operation.operation_id=OLD.operation_id
                         AND operation.state='provider_verified') THEN
                RETURN OLD;
            END IF;
        END IF;
    END IF;
    RAISE EXCEPTION 'orphan capture erasure history is immutable' USING ERRCODE='55000';
END
$$;
CREATE TRIGGER orphan_capture_erasure_contract_immutable
    BEFORE UPDATE OR DELETE ON orphan_capture_erasure_contract
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_history();
CREATE TRIGGER orphan_capture_erasure_sessions_immutable
    BEFORE UPDATE OR DELETE ON orphan_capture_erasure_sessions
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_history();
CREATE TRIGGER orphan_capture_erasure_streams_immutable
    BEFORE UPDATE OR DELETE ON orphan_capture_erasure_streams
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_history();
CREATE TRIGGER orphan_capture_erasure_events_immutable
    BEFORE UPDATE OR DELETE ON orphan_capture_erasure_events
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_history();
CREATE TRIGGER orphan_capture_erasure_objects_immutable
    BEFORE UPDATE OR DELETE ON orphan_capture_erasure_objects
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_history();

CREATE FUNCTION orphan_capture_erasure_guard_operation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    changed jsonb;
    object_root bytea;
    provider_names_root bytea;
BEGIN
    IF TG_OP='INSERT' THEN
        PERFORM 1 FROM accounts WHERE id=NEW.account_id FOR UPDATE;
        IF NEW.state<>'preparing' OR NOT NEW.capture_upload_fenced THEN
            RAISE EXCEPTION 'orphan erasure must begin with an uncommitted preparing state'
                USING ERRCODE='55000';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' THEN
        IF NOT EXISTS(SELECT 1 FROM accounts WHERE id=OLD.account_id) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'orphan erasure operation cannot be deleted' USING ERRCODE='55000';
    END IF;
    IF (to_jsonb(NEW)-ARRAY['state','sealed_at','provider_verified_at','provider_ack_request_sha256',
          'provider_ack_signature','completed_at','provider_receipt_sha256',
          'completion_request_sha256','completion_signature','capture_upload_fenced',
          'fence_release_request_sha256','fence_release_signature','fence_released_at',
          'fence_release_generation','fence_release_candidate_image_digest','fence_release_activation_receipt_sha256',
          'fence_release_fleet_evidence_sha256','fence_release_protected_canary_sha256','fence_release_admission_contract_sha256'])
       IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['state','sealed_at','provider_verified_at','provider_ack_request_sha256',
          'provider_ack_signature','completed_at','provider_receipt_sha256',
          'completion_request_sha256','completion_signature','capture_upload_fenced',
          'fence_release_request_sha256','fence_release_signature','fence_released_at',
          'fence_release_generation','fence_release_candidate_image_digest','fence_release_activation_receipt_sha256',
          'fence_release_fleet_evidence_sha256','fence_release_protected_canary_sha256','fence_release_admission_contract_sha256']) THEN
        RAISE EXCEPTION 'orphan erasure identity cannot change' USING ERRCODE='55000';
    END IF;
    SELECT jsonb_object_agg(new_value.key,new_value.value) INTO changed
      FROM jsonb_each(to_jsonb(NEW)) new_value
     WHERE new_value.value IS DISTINCT FROM to_jsonb(OLD)->new_value.key;
    IF OLD.state='preparing' AND NEW.state='provider_pending'
       AND (changed-ARRAY['state','sealed_at'])='{}'::jsonb THEN
        IF (SELECT count(*) FROM orphan_capture_erasure_sessions
             WHERE account_id=NEW.account_id AND operation_id=NEW.operation_id)<>NEW.session_count
           OR (SELECT count(*) FROM orphan_capture_erasure_streams
                WHERE account_id=NEW.account_id AND operation_id=NEW.operation_id)<>NEW.stream_count
           OR (SELECT count(*) FROM orphan_capture_erasure_events
                WHERE account_id=NEW.account_id AND operation_id=NEW.operation_id)<>NEW.event_count
           OR (SELECT count(*) FROM orphan_capture_erasure_objects
                WHERE account_id=NEW.account_id AND operation_id=NEW.operation_id)<>NEW.object_count THEN
            RAISE EXCEPTION 'orphan erasure inventory count differs from authority' USING ERRCODE='55000';
        END IF;
        SELECT sha256(convert_to('kioku.orphan-capture-objects.v1'||E'\n'||coalesce(
            string_agg(object_key||E'\t'||object_generation::text||E'\t'||event_id||E'\t'||asset_id||
                       E'\t'||byte_length::text||E'\t'||original_sha256||E'\n','' ORDER BY object_key),''),
            'UTF8')) INTO object_root
          FROM orphan_capture_erasure_objects
         WHERE account_id=NEW.account_id AND operation_id=NEW.operation_id;
        IF object_root<>NEW.object_inventory_sha256 THEN
            RAISE EXCEPTION 'orphan erasure object root differs from authority' USING ERRCODE='55000';
        END IF;
        SELECT sha256(convert_to('kioku.orphan-capture-provider-names.v1'||E'\n'||coalesce(
            string_agg(prefix||'/'||account_id||'/'||asset_id||'.enc'||E'\n',''
              ORDER BY prefix||'/'||account_id||'/'||asset_id||'.enc'),''),'UTF8'))
          INTO provider_names_root FROM orphan_capture_erasure_objects
          CROSS JOIN (VALUES ('raw'),('recordings')) names(prefix)
         WHERE account_id=NEW.account_id AND operation_id=NEW.operation_id;
        IF provider_names_root<>NEW.provider_names_sha256 THEN
            RAISE EXCEPTION 'orphan erasure provider names differ from authority' USING ERRCODE='55000';
        END IF;
        NEW.sealed_at:=clock_timestamp();
        RETURN NEW;
    END IF;
    IF OLD.state='provider_pending' AND NEW.state='provider_verified'
       AND (changed-ARRAY['state','provider_verified_at','provider_ack_request_sha256',
                         'provider_ack_signature','provider_receipt_sha256'])='{}'::jsonb THEN
        NEW.provider_verified_at:=clock_timestamp();
        RETURN NEW;
    END IF;
    IF OLD.state='provider_verified' AND NEW.state='complete'
       AND (changed-ARRAY['state','completed_at','completion_request_sha256',
                         'completion_signature'])='{}'::jsonb THEN
        IF EXISTS(SELECT 1 FROM orphan_capture_erasure_objects
                   WHERE account_id=NEW.account_id AND operation_id=NEW.operation_id) THEN
            RAISE EXCEPTION 'orphan erasure completion requires an atomic inventory scrub'
                USING ERRCODE='55000';
        END IF;
        NEW.completed_at:=clock_timestamp();
        RETURN NEW;
    END IF;
    IF OLD.state='complete' AND NEW.state='complete'
       AND OLD.capture_upload_fenced AND NOT NEW.capture_upload_fenced
       AND (to_jsonb(NEW)-ARRAY['capture_upload_fenced','fence_release_request_sha256',
          'fence_release_signature','fence_released_at','fence_release_generation','fence_release_candidate_image_digest',
          'fence_release_activation_receipt_sha256','fence_release_fleet_evidence_sha256',
          'fence_release_protected_canary_sha256','fence_release_admission_contract_sha256'])
           =(to_jsonb(OLD)-ARRAY['capture_upload_fenced','fence_release_request_sha256',
          'fence_release_signature','fence_released_at','fence_release_generation','fence_release_candidate_image_digest',
          'fence_release_activation_receipt_sha256','fence_release_fleet_evidence_sha256',
          'fence_release_protected_canary_sha256','fence_release_admission_contract_sha256']) THEN
        NEW.fence_released_at:=clock_timestamp();
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'orphan erasure permits only forward completion and fence release'
        USING ERRCODE='55000';
END
$$;
CREATE TRIGGER orphan_capture_erasure_operations_forward
    BEFORE INSERT OR UPDATE OR DELETE ON orphan_capture_erasure_operations
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_operation();

CREATE FUNCTION orphan_capture_erasure_guard_upload()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    row_value jsonb:=to_jsonb(NEW);
BEGIN
    -- The serving predecessor already obtains this account row lock before
    -- reserving. Repeat it here to serialize every insert with preparation.
    PERFORM 1 FROM accounts WHERE id=NEW.account_id FOR UPDATE;
    IF TG_TABLE_NAME='capture_upload_intents' AND (
        NEW.account_id !~ '^[a-zA-Z0-9_-]{1,128}$'
        OR row_value->>'asset_id' !~ '^[a-zA-Z0-9_-]{1,128}$'
        OR row_value->>'object_key' NOT IN (
          'raw/'||NEW.account_id||'/'||(row_value->>'asset_id')||'.enc',
          'recordings/'||NEW.account_id||'/'||(row_value->>'asset_id')||'.enc')) THEN
        RAISE EXCEPTION 'capture upload key does not match its exact identity' USING ERRCODE='55000';
    END IF;
    IF EXISTS(SELECT 1 FROM orphan_capture_erasure_operations operation
               WHERE operation.account_id=NEW.account_id AND operation.capture_upload_fenced)
       OR EXISTS(SELECT 1 FROM orphan_capture_erasure_events erased
                   WHERE erased.account_id=NEW.account_id
                     AND (erased.event_id=row_value->>'event_id'
                          OR erased.asset_id=row_value->>'asset_id'))
       OR EXISTS(SELECT 1 FROM orphan_capture_erasure_streams erased
                   WHERE erased.account_id=NEW.account_id
                     AND erased.stream_id=row_value->>'stream_id') THEN
        RAISE EXCEPTION 'capture upload is fenced by owner-authorized erasure'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER orphan_capture_erasure_upload_admission
    BEFORE INSERT OR UPDATE ON capture_upload_intents
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_upload();
CREATE TRIGGER orphan_capture_erasure_delivery_admission
    BEFORE INSERT OR UPDATE ON recording_delivery_reservations
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_upload();
CREATE TRIGGER orphan_capture_erasure_reference_admission
    BEFORE INSERT OR UPDATE ON capture_reference_batch_receipts
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_upload();
CREATE TRIGGER orphan_capture_erasure_reference_event_admission
    BEFORE INSERT OR UPDATE ON capture_reference_batch_events
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_upload();

CREATE FUNCTION orphan_capture_erasure_guard_capture()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    row_value jsonb:=to_jsonb(NEW);
    session_key text;
    stream_key text;
BEGIN
    session_key:=CASE WHEN TG_TABLE_NAME='capture_sessions' THEN row_value->>'id'
                      ELSE row_value->>'capture_session_id' END;
    stream_key:=CASE WHEN TG_TABLE_NAME='capture_streams' THEN row_value->>'id'
                     ELSE row_value->>'stream_id' END;
    PERFORM 1 FROM accounts WHERE id=NEW.account_id FOR UPDATE;
    IF EXISTS(SELECT 1 FROM orphan_capture_erasure_operations operation
               WHERE operation.account_id=NEW.account_id AND operation.capture_upload_fenced)
       OR EXISTS(SELECT 1 FROM orphan_capture_erasure_sessions erased
               WHERE erased.account_id=NEW.account_id AND erased.capture_session_id=session_key)
       OR EXISTS(SELECT 1 FROM orphan_capture_erasure_streams erased
                   WHERE erased.account_id=NEW.account_id AND erased.stream_id=stream_key)
       OR EXISTS(SELECT 1 FROM orphan_capture_erasure_events erased
                   WHERE erased.account_id=NEW.account_id AND (
                       erased.event_id=row_value->>'event_id'
                       OR erased.event_id=row_value->>'canonical_event_id'
                       OR erased.asset_id=row_value->>'asset_id'
                       OR erased.asset_id=row_value->>'canonical_asset_id')) THEN
        RAISE EXCEPTION 'erased capture identity cannot be reused' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER orphan_capture_erasure_sessions_admission
    BEFORE INSERT OR UPDATE ON capture_sessions
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_capture();
CREATE TRIGGER orphan_capture_erasure_streams_admission
    BEFORE INSERT OR UPDATE ON capture_streams
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_capture();
CREATE TRIGGER orphan_capture_erasure_events_admission
    BEFORE INSERT OR UPDATE ON capture_events
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_capture();

-- Projections have no event FK. A late result must not recreate erased content
-- after the source cascade removed the old episode-deletion lookup authority.
CREATE FUNCTION orphan_capture_erasure_guard_projection()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    source_event text;
BEGIN
    -- Serialize with prepare before checking its committed fence. Do not
    -- upgrade an account FK lock already held by a predecessor projector.
    PERFORM pg_advisory_xact_lock_shared(hashtextextended(
        'kioku:postgres-memory-reconciliation-activation:v27',0));
    source_event:=CASE WHEN TG_TABLE_NAME='utterances'
        THEN split_part(substr(NEW.source_key,10),':',1) ELSE substr(NEW.source_key,10) END;
    IF EXISTS(SELECT 1 FROM orphan_capture_erasure_operations operation
               WHERE operation.account_id=NEW.account_id AND operation.capture_upload_fenced)
       OR (NEW.source_key LIKE 'cloud-v2:%' AND EXISTS(
            SELECT 1 FROM orphan_capture_erasure_events erased
             WHERE erased.account_id=NEW.account_id AND erased.event_id=source_event)) THEN
        RAISE EXCEPTION 'erased capture projection cannot be recreated' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER orphan_capture_erasure_utterance_admission
    BEFORE INSERT OR UPDATE ON utterances
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_projection();
CREATE TRIGGER orphan_capture_erasure_screenshot_admission
    BEFORE INSERT OR UPDATE ON screenshots
    FOR EACH ROW EXECUTE FUNCTION orphan_capture_erasure_guard_projection();
