-- ADR-0048 Phase 1: operator state only. No account content, base schema
-- marker, activation receipt, or source trigger is changed by this companion.
CREATE TABLE voice_identity_controls (
    singleton boolean PRIMARY KEY CHECK (singleton),
    cohort text NOT NULL DEFAULT 'none' CHECK (cohort IN ('none','explicit','all')),
    explicit_account_ids text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(explicit_account_ids) <= 1024),
    paused boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO voice_identity_controls(singleton) VALUES (true);

CREATE UNIQUE INDEX voice_samples_observation_version_key
    ON voice_samples(account_id, speaker_observation_id, embedding_space, quality_version, scorer_version);
CREATE INDEX voice_embedding_jobs_account_claim_idx
    ON voice_embedding_jobs(account_id, state, next_attempt_at, id);
