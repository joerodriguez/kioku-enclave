-- Remaining user-visible voice-lineage records required by the export and
-- identity contracts.

CREATE TABLE voice_profile_representatives (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    profile_id bigint NOT NULL,
    channel_domain text NOT NULL,
    centroid bytea NOT NULL,
    sample_count bigint NOT NULL DEFAULT 0 CHECK (sample_count >= 0),
    medoid_sample_id bigint,
    scorer_version bigint NOT NULL DEFAULT 2,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,id),
    UNIQUE (account_id,profile_id,channel_domain),
    FOREIGN KEY (account_id,profile_id)
        REFERENCES voice_profiles(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,medoid_sample_id)
        REFERENCES voice_samples(account_id,id) ON DELETE SET NULL (medoid_sample_id)
);
CREATE INDEX voice_profile_representatives_domain_idx
    ON voice_profile_representatives(account_id,channel_domain);

CREATE TABLE profile_identity_bindings (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    voice_profile_id bigint NOT NULL,
    person_id bigint NOT NULL,
    evidence_count bigint NOT NULL DEFAULT 1 CHECK (evidence_count > 0),
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    state text NOT NULL CHECK (
        state IN ('probationary','accepted','conflicted','superseded','rejected')
    ),
    derivation_version bigint NOT NULL,
    evidence jsonb NOT NULL,
    supersedes_id bigint,
    active boolean NOT NULL DEFAULT false,
    operation_id text,
    conflicts_with_id bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,id),
    FOREIGN KEY (account_id,voice_profile_id)
        REFERENCES voice_profiles(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,person_id)
        REFERENCES people(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,supersedes_id)
        REFERENCES profile_identity_bindings(account_id,id) ON DELETE SET NULL (supersedes_id),
    FOREIGN KEY (account_id,conflicts_with_id)
        REFERENCES profile_identity_bindings(account_id,id) ON DELETE SET NULL (conflicts_with_id)
);
CREATE UNIQUE INDEX profile_identity_bindings_active_idx
    ON profile_identity_bindings(account_id,voice_profile_id)
    WHERE active AND state='accepted';
CREATE UNIQUE INDEX profile_identity_bindings_operation_idx
    ON profile_identity_bindings(account_id,voice_profile_id,operation_id)
    WHERE operation_id IS NOT NULL;

UPDATE persistence_schema SET version = 19, updated_at = now() WHERE singleton = true;
