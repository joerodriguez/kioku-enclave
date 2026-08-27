-- Tenant-qualified people, speaker evidence, and voice lineage records.

CREATE TABLE speaker_observations (
    account_id text NOT NULL,
    id bigint NOT NULL,
    person_id bigint,
    event_id text NOT NULL,
    turn_id text NOT NULL,
    speaker_local_id text NOT NULL,
    started_at timestamptz NOT NULL,
    ended_at timestamptz NOT NULL,
    transcript_text text NOT NULL,
    language text,
    overlap boolean NOT NULL DEFAULT false,
    voice_eligibility text,
    voice_diagnostics jsonb,
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, event_id, turn_id),
    FOREIGN KEY (account_id, person_id)
        REFERENCES people(account_id, id) ON DELETE SET NULL (person_id),
    FOREIGN KEY (account_id, event_id)
        REFERENCES capture_events(account_id, event_id) ON DELETE CASCADE
);
CREATE INDEX speaker_observations_person_idx
    ON speaker_observations(account_id, person_id, id DESC);

CREATE TABLE voice_profiles (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    person_id bigint,
    label text NOT NULL,
    embedding_space text NOT NULL,
    channel_domain text NOT NULL,
    centroid bytea NOT NULL,
    sample_count bigint NOT NULL DEFAULT 0 CHECK (sample_count >= 0),
    scorer_version bigint NOT NULL DEFAULT 2,
    representative_kind text NOT NULL DEFAULT 'medoid_trimmed_centroid',
    medoid_sample_id bigint,
    status text NOT NULL DEFAULT 'tentative'
        CHECK (status IN ('tentative','stable','quarantined')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, label),
    FOREIGN KEY (account_id, person_id)
        REFERENCES people(account_id, id) ON DELETE SET NULL (person_id)
);
CREATE INDEX voice_profiles_person_idx ON voice_profiles(account_id, person_id, id);

CREATE TABLE voice_samples (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    speaker_observation_id bigint NOT NULL,
    voice_profile_id bigint,
    embedding_space text NOT NULL,
    channel_domain text NOT NULL,
    embedding bytea NOT NULL,
    quality_score double precision NOT NULL,
    diagnostics jsonb NOT NULL DEFAULT '{}'::jsonb,
    quality_version bigint NOT NULL DEFAULT 1,
    scorer_version bigint NOT NULL DEFAULT 2,
    eligibility text NOT NULL DEFAULT 'enroll',
    duration_ms bigint NOT NULL DEFAULT 0,
    speech_ratio double precision NOT NULL DEFAULT 0,
    snr_proxy_db double precision NOT NULL DEFAULT 0,
    clipping_ratio double precision NOT NULL DEFAULT 0,
    silence_ratio double precision NOT NULL DEFAULT 0,
    embedding_norm double precision NOT NULL DEFAULT 1,
    outlier boolean NOT NULL DEFAULT false,
    similarity double precision,
    decision_margin double precision,
    accepted boolean NOT NULL DEFAULT false,
    embedding_job_id bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, speaker_observation_id)
        REFERENCES speaker_observations(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, voice_profile_id)
        REFERENCES voice_profiles(account_id, id) ON DELETE SET NULL (voice_profile_id)
);

CREATE TABLE voice_profile_revisions (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    profile_id bigint NOT NULL,
    status text NOT NULL
        CHECK (status IN ('tentative','stable','quarantined','superseded','split')),
    derivation_version bigint NOT NULL,
    scorer_version bigint NOT NULL,
    representative_kind text NOT NULL,
    centroid bytea NOT NULL,
    sample_count bigint NOT NULL CHECK (sample_count >= 0),
    medoid_sample_id bigint,
    person_id bigint,
    proposal_id bigint,
    predecessor_revision_id bigint,
    reason_code text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, profile_id)
        REFERENCES voice_profiles(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, medoid_sample_id)
        REFERENCES voice_samples(account_id, id) ON DELETE SET NULL (medoid_sample_id),
    FOREIGN KEY (account_id, person_id)
        REFERENCES people(account_id, id) ON DELETE SET NULL (person_id),
    FOREIGN KEY (account_id, predecessor_revision_id)
        REFERENCES voice_profile_revisions(account_id, id) ON DELETE SET NULL (predecessor_revision_id)
);
CREATE UNIQUE INDEX voice_profile_revisions_active_idx
    ON voice_profile_revisions(account_id, profile_id) WHERE active;

CREATE TABLE voice_sample_profile_assignments (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    sample_id bigint NOT NULL,
    profile_id bigint NOT NULL,
    proposal_id bigint,
    predecessor_assignment_id bigint,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, sample_id)
        REFERENCES voice_samples(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, profile_id)
        REFERENCES voice_profiles(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, predecessor_assignment_id)
        REFERENCES voice_sample_profile_assignments(account_id, id)
        ON DELETE SET NULL (predecessor_assignment_id)
);
CREATE UNIQUE INDEX voice_sample_profile_assignments_active_idx
    ON voice_sample_profile_assignments(account_id, sample_id) WHERE active;
CREATE INDEX voice_sample_profile_assignments_profile_idx
    ON voice_sample_profile_assignments(account_id, profile_id, active, sample_id);

CREATE TABLE person_name_claims (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    person_id bigint,
    name text NOT NULL,
    normalized_name text NOT NULL,
    normalized_email text,
    source_event_id text,
    speaker_observation_id bigint,
    observed_at timestamptz NOT NULL,
    evidence_kind text NOT NULL,
    evidence jsonb NOT NULL,
    confidence double precision NOT NULL,
    status text NOT NULL CHECK (
        status IN ('proposed','probationary','accepted','conflicted','superseded','rejected')
    ),
    supersedes_id bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, person_id)
        REFERENCES people(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, source_event_id)
        REFERENCES capture_events(account_id, event_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, speaker_observation_id)
        REFERENCES speaker_observations(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, supersedes_id)
        REFERENCES person_name_claims(account_id, id) ON DELETE SET NULL (supersedes_id)
);
CREATE INDEX person_name_claims_name_idx
    ON person_name_claims(account_id, normalized_name, observed_at DESC);
CREATE INDEX person_name_claims_person_idx
    ON person_name_claims(account_id, person_id, status, observed_at DESC);

CREATE TABLE identity_evidence (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    person_id bigint,
    voice_profile_id bigint,
    source_event_id text,
    observed_at timestamptz,
    speaker_observation_id bigint,
    kind text NOT NULL,
    claimed_name text,
    evidence jsonb NOT NULL,
    score double precision,
    status text NOT NULL CHECK (status IN ('proposed','accepted','rejected','quarantined')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, person_id)
        REFERENCES people(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, voice_profile_id)
        REFERENCES voice_profiles(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, source_event_id)
        REFERENCES capture_events(account_id, event_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, speaker_observation_id)
        REFERENCES speaker_observations(account_id, id) ON DELETE CASCADE
);
CREATE INDEX identity_evidence_person_idx
    ON identity_evidence(account_id, person_id, id DESC);

CREATE TABLE person_facts (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    person_id bigint NOT NULL,
    predicate text NOT NULL,
    value text NOT NULL,
    evidence jsonb NOT NULL,
    derivation_version bigint NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','superseded','conflicted')),
    supersedes_id bigint,
    source_event_id text,
    speaker_observation_id bigint,
    observed_at timestamptz,
    literal_evidence text,
    confidence double precision NOT NULL DEFAULT 0,
    conflicts_with_id bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    FOREIGN KEY (account_id, person_id)
        REFERENCES people(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, supersedes_id)
        REFERENCES person_facts(account_id, id) ON DELETE SET NULL (supersedes_id),
    FOREIGN KEY (account_id, conflicts_with_id)
        REFERENCES person_facts(account_id, id) ON DELETE SET NULL (conflicts_with_id),
    FOREIGN KEY (account_id, source_event_id)
        REFERENCES capture_events(account_id, event_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, speaker_observation_id)
        REFERENCES speaker_observations(account_id, id) ON DELETE CASCADE
);
CREATE INDEX person_facts_person_idx
    ON person_facts(account_id, person_id, status, observed_at DESC, id DESC);

UPDATE persistence_schema SET version = 12, updated_at = now() WHERE singleton = true;
