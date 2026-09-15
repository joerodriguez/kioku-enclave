-- ADR-0049: the recording device's reading language, stamped per capture event
-- by the companion and resolved at authoring time. Presentation input only:
-- never transcript evidence, never an archive/topology revision. NULL is the
-- pre-companion manifest; the base schema and every earlier receipt are untouched.
ALTER TABLE capture_events ADD COLUMN locale_id text;
ALTER TABLE capture_events ADD CONSTRAINT capture_events_locale_id_bcp47
    CHECK (locale_id IS NULL
           OR (octet_length(locale_id)<=35
               AND locale_id ~ '^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$'));
-- The resolver reads the newest stamped event; without this partial index an
-- account whose history predates the stamp would walk every event on each
-- authoring call. Named outside the base release's reserved
-- capture_events_reconciliation_% family.
CREATE INDEX capture_events_locale_idx
    ON capture_events (account_id, started_at DESC, event_id DESC)
    WHERE locale_id IS NOT NULL;

CREATE TABLE authoring_language_schema (
    singleton boolean PRIMARY KEY CHECK(singleton),
    version bigint NOT NULL CHECK(version=35),
    contract_sha256 text NOT NULL CHECK(contract_sha256 ~ '^[0-9a-f]{64}$'),
    catalog_sha256 text NOT NULL CHECK(catalog_sha256 ~ '^[0-9a-f]{64}$'),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
