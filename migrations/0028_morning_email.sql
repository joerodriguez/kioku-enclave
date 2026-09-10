-- ADR-0045: native email is a calendar-scheduled digest. Install only with
-- outbound workers quiescent. Historical receipts remain in email_deliveries;
-- old binaries cannot claim per-memory email after this transactional cutover.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM email_deliveries WHERE state='processing')
       OR EXISTS (SELECT 1 FROM email_send_fences) THEN
        RAISE EXCEPTION 'morning email cutover requires quiescent email delivery';
    END IF;
END $$;

CREATE TABLE morning_email_schedules (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    timezone text,
    next_due_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((timezone IS NULL) = (next_due_at IS NULL))
);

CREATE TABLE morning_email_deliveries (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    delivery_date date NOT NULL,
    delivery_id text NOT NULL,
    timezone text NOT NULL,
    consent_revision text NOT NULL,
    recipient_email text NOT NULL,
    include_content boolean NOT NULL,
    state text NOT NULL CHECK(state IN ('assembling','pending','processing','retry_wait','delivered','ambiguous','failed','cancelled','empty')),
    snapshot jsonb NOT NULL,
    frozen_request jsonb,
    attempt_count bigint NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 10),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    claim_token text,
    claim_until timestamptz,
    completed_claim_token text,
    first_send_at timestamptz,
    provider_message_id text,
    response_status bigint,
    error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(account_id,delivery_date),
    UNIQUE(account_id,delivery_id),
    CHECK ((claim_token IS NULL)=(claim_until IS NULL))
);
CREATE INDEX morning_email_deliveries_due_idx
    ON morning_email_deliveries(account_id,state,next_attempt_at);

-- Evidence identity survives topology replacement; origin_episode_id is an
-- audit coordinate, deliberately not a cascading FK to a mutable memory.
-- withheld_update explicitly tracks new evidence in a previously sent memory:
-- no automatic update-email stream is authorized by ADR-0045.
CREATE TABLE morning_email_sources (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    record_type text NOT NULL CHECK(record_type IN ('utterance','screenshot')),
    record_id bigint NOT NULL CHECK(record_id>0),
    origin_episode_id bigint NOT NULL,
    last_considered_delivery_id text,
    include_content boolean NOT NULL,
    state text NOT NULL CHECK(state IN ('pending','delivered','ambiguous','withheld_update','cancelled','failed')),
    delivery_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(account_id,record_type,record_id)
);
CREATE INDEX morning_email_sources_delivery_idx
    ON morning_email_sources(account_id,delivery_id);

INSERT INTO morning_email_schedules(account_id)
SELECT account_id FROM episode_email_preferences;

-- Only previously queued coverage is transferred. Attempts with a possible
-- prior submission are conservatively covered, never rebuilt into a digest.
INSERT INTO morning_email_sources(account_id,record_type,record_id,origin_episode_id,include_content,state,delivery_id)
SELECT DISTINCT ON(d.account_id,m.record_type,m.record_id)
    d.account_id,m.record_type,m.record_id,d.episode_id,d.include_content,
    CASE WHEN d.state='delivered' THEN 'delivered'
         WHEN d.state='ambiguous' OR d.attempt_count>0 THEN 'ambiguous'
         WHEN NOT EXISTS(SELECT 1 FROM episode_email_preferences p WHERE p.account_id=d.account_id AND p.enabled) THEN 'cancelled'
         ELSE 'pending' END,
    CASE WHEN d.state IN ('delivered','ambiguous') OR d.attempt_count>0 THEN d.delivery_id ELSE NULL END
FROM email_deliveries d JOIN episode_members m ON m.account_id=d.account_id AND m.episode_id=d.episode_id
WHERE d.state IN ('pending','retry_wait','delivered','ambiguous')
ORDER BY d.account_id,m.record_type,m.record_id,
    CASE WHEN d.state='delivered' THEN 0 WHEN d.state='ambiguous' OR d.attempt_count>0 THEN 1 ELSE 2 END,d.created_at;

UPDATE email_deliveries SET state='cancelled',last_error='morning_digest_cutover',error_code='morning_digest_cutover',updated_at=now()
WHERE state IN ('pending','retry_wait');

CREATE FUNCTION kioku_morning_email_legacy_fence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state='processing' THEN
        RAISE EXCEPTION 'per-memory native email has been replaced by morning delivery';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER kioku_morning_email_legacy_fence BEFORE INSERT OR UPDATE ON email_deliveries
FOR EACH ROW EXECUTE FUNCTION kioku_morning_email_legacy_fence();

-- Compatible older finalizers can enqueue while the delivery worker cutover is
-- installed. The native sender is fenced above, and eligibility transfers here.
CREATE FUNCTION kioku_morning_email_legacy_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state='pending' THEN
        INSERT INTO morning_email_sources(account_id,record_type,record_id,origin_episode_id,include_content,state)
        SELECT NEW.account_id,m.record_type,m.record_id,NEW.episode_id,NEW.include_content,'pending'
        FROM episode_members m JOIN episode_email_preferences p ON p.account_id=m.account_id AND p.enabled
        WHERE m.account_id=NEW.account_id AND m.episode_id=NEW.episode_id
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER kioku_morning_email_legacy_enqueue AFTER INSERT ON email_deliveries
FOR EACH ROW EXECUTE FUNCTION kioku_morning_email_legacy_enqueue();

-- Individual memory deletion erases cached plaintext too. Retain only the
-- content-free date/transport receipt so deletion cannot reopen a sent day.
CREATE FUNCTION kioku_morning_email_memory_delete() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE affected text[];
BEGIN
    IF TG_OP='UPDATE' AND (NEW.finalization_status IS DISTINCT FROM 'deleting' OR OLD.finalization_status='deleting') THEN
        RETURN NEW;
    END IF;
    SELECT array_agg(d.delivery_id) INTO affected FROM morning_email_deliveries d
    WHERE d.account_id=OLD.account_id AND EXISTS(
        SELECT 1 FROM jsonb_array_elements(coalesce(d.snapshot->'episodes','[]'::jsonb)) e
        WHERE (e->>'episode_id')::bigint=OLD.id);
    IF EXISTS(SELECT 1 FROM morning_email_deliveries d WHERE d.account_id=OLD.account_id
        AND d.delivery_id=ANY(affected) AND d.state='processing') THEN
        RAISE EXCEPTION 'memory has an in-flight morning email';
    END IF;
    UPDATE morning_email_sources s SET delivery_id=NULL,updated_at=clock_timestamp()
    WHERE s.account_id=OLD.account_id AND s.delivery_id=ANY(affected) AND s.state='pending';
    UPDATE morning_email_deliveries SET snapshot='{}',frozen_request=NULL,
        state=CASE WHEN state IN ('assembling','pending','retry_wait') THEN 'cancelled' ELSE state END,
        error_code=CASE WHEN state IN ('assembling','pending','retry_wait') THEN 'memory_deleted' ELSE error_code END,
        updated_at=clock_timestamp()
    WHERE account_id=OLD.account_id AND delivery_id=ANY(affected);
    DELETE FROM morning_email_sources s USING episode_members m
    WHERE m.account_id=OLD.account_id AND m.episode_id=OLD.id AND s.account_id=m.account_id
      AND s.record_type=m.record_type AND s.record_id=m.record_id;
    IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE TRIGGER kioku_morning_email_memory_delete BEFORE DELETE OR UPDATE OF finalization_status ON episodes
FOR EACH ROW EXECUTE FUNCTION kioku_morning_email_memory_delete();

-- Canonical identity refresh may change the verified recipient independently
-- of notification settings. Daily claims hold a share lock on the account row
-- through publishing their send fence; this trigger therefore cannot race the
-- final recipient check. Do not authorize a different destination implicitly.
CREATE FUNCTION kioku_morning_email_recipient_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.email IS NOT DISTINCT FROM OLD.email THEN RETURN NEW; END IF;
    IF EXISTS(SELECT 1 FROM email_send_fences WHERE account_id=OLD.id) THEN
        RAISE EXCEPTION 'account recipient has an in-flight morning email';
    END IF;
    UPDATE morning_email_sources s SET delivery_id=NULL,updated_at=clock_timestamp()
    WHERE s.account_id=OLD.id AND s.state='pending' AND EXISTS(
        SELECT 1 FROM morning_email_deliveries d WHERE d.account_id=s.account_id AND d.delivery_id=s.delivery_id
          AND d.state IN ('assembling','pending','retry_wait'));
    UPDATE morning_email_deliveries SET state='cancelled',snapshot='{}',frozen_request=NULL,
        error_code='recipient_changed',updated_at=clock_timestamp()
    WHERE account_id=OLD.id AND state IN ('assembling','pending','retry_wait');
    RETURN NEW;
END $$;
CREATE TRIGGER kioku_morning_email_recipient_change BEFORE UPDATE OF email ON accounts
FOR EACH ROW EXECUTE FUNCTION kioku_morning_email_recipient_change();
