-- ADR-0049: the recording device's reading language, stamped per capture event
-- by the companion and resolved at authoring time. Presentation input only:
-- never transcript evidence, never an archive/topology revision. NULL is the
-- pre-companion manifest; the base schema and every earlier receipt are untouched.
ALTER TABLE capture_events ADD COLUMN locale_id text;
ALTER TABLE capture_events ADD CONSTRAINT capture_events_locale_id_bcp47
    CHECK (locale_id IS NULL OR locale_id ~ '^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$');

CREATE TABLE authoring_language_schema (
    singleton boolean PRIMARY KEY CHECK(singleton),
    version bigint NOT NULL CHECK(version=35),
    contract_sha256 text NOT NULL CHECK(contract_sha256 ~ '^[0-9a-f]{64}$'),
    catalog_sha256 text NOT NULL CHECK(catalog_sha256 ~ '^[0-9a-f]{64}$'),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
