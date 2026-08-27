-- Idempotent marker for the synthetic plugin-review account fixture.

CREATE TABLE reviewer_fixtures (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    fixture_version bigint NOT NULL CHECK (fixture_version = 1),
    seeded_at timestamptz NOT NULL DEFAULT now()
);

UPDATE persistence_schema SET version = 23, updated_at = now()
WHERE singleton = true AND version = 22;
