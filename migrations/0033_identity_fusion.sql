-- Source-backed name/fact reduction. No source transcript or media is rewritten.
CREATE TABLE identity_name_inputs (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    evidence_id bigint NOT NULL,
    kind text NOT NULL CHECK(kind IN ('self_introduction','screen','vocative','context','mention')),
    source_observation_id bigint,
    subject_observation_id bigint,
    visual_observation_id bigint,
    extraction_version bigint NOT NULL CHECK(extraction_version > 0),
    PRIMARY KEY(account_id,evidence_id),
    FOREIGN KEY(account_id,evidence_id) REFERENCES identity_evidence(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,source_observation_id) REFERENCES speaker_observations(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,subject_observation_id) REFERENCES speaker_observations(account_id,id) ON DELETE SET NULL(subject_observation_id),
    FOREIGN KEY(account_id,visual_observation_id) REFERENCES visual_speaker_observations(account_id,id) ON DELETE CASCADE,
    CHECK((kind IN ('screen','context') AND visual_observation_id IS NOT NULL AND source_observation_id IS NULL)
       OR (kind IN ('self_introduction','vocative','mention') AND source_observation_id IS NOT NULL AND visual_observation_id IS NULL))
);
CREATE INDEX identity_name_inputs_subject_idx ON identity_name_inputs(account_id,subject_observation_id,evidence_id);

CREATE TABLE profile_name_bindings (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    profile_id bigint NOT NULL,
    person_id bigint,
    current_claim_id bigint,
    conflict_peers bigint[] NOT NULL DEFAULT '{}' CHECK(cardinality(conflict_peers)<=64),
    status text NOT NULL CHECK(status IN ('unbound','accepted','quarantined')),
    policy_version bigint NOT NULL CHECK(policy_version > 0),
    input_sha256 text NOT NULL CHECK(input_sha256 ~ '^[0-9a-f]{64}$'),
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(account_id,profile_id),
    FOREIGN KEY(account_id,profile_id) REFERENCES voice_profiles(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,person_id) REFERENCES people(account_id,id) ON DELETE SET NULL(person_id),
    FOREIGN KEY(account_id,current_claim_id) REFERENCES person_name_claims(account_id,id) ON DELETE SET NULL(current_claim_id)
);
CREATE INDEX profile_name_bindings_evaluation_idx ON profile_name_bindings(account_id,evaluated_at,profile_id);

CREATE TABLE profile_name_claims (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    profile_id bigint NOT NULL,
    claim_id bigint NOT NULL,
    policy_version bigint NOT NULL CHECK(policy_version > 0),
    input_sha256 text NOT NULL CHECK(input_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY(account_id,claim_id),
    FOREIGN KEY(account_id,profile_id) REFERENCES voice_profiles(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,claim_id) REFERENCES person_name_claims(account_id,id) ON DELETE CASCADE
);
CREATE INDEX profile_name_claims_profile_idx ON profile_name_claims(account_id,profile_id,claim_id);

CREATE TABLE person_fact_candidates (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    source_event_id text NOT NULL,
    speaker_observation_id bigint NOT NULL,
    ordinal bigint NOT NULL CHECK(ordinal >= 0),
    predicate text NOT NULL CHECK(predicate IN ('role','organization','relationship','preference','responsibility','contact','location','other')),
    value text NOT NULL,
    value_key text NOT NULL,
    literal_evidence text NOT NULL,
    confidence double precision NOT NULL CHECK(confidence BETWEEN 0 AND 1),
    replacement_of text,
    replacement_key text,
    CHECK((replacement_of IS NULL)=(replacement_key IS NULL)),
    observed_at timestamptz NOT NULL,
    extraction_version bigint NOT NULL CHECK(extraction_version > 0),
    derived_fact_id bigint,
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(account_id,id),
    UNIQUE(account_id,speaker_observation_id,ordinal),
    FOREIGN KEY(account_id,source_event_id) REFERENCES capture_events(account_id,event_id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,speaker_observation_id) REFERENCES speaker_observations(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,derived_fact_id) REFERENCES person_facts(account_id,id) ON DELETE SET NULL(derived_fact_id)
);
CREATE INDEX person_fact_candidates_evaluation_idx ON person_fact_candidates(account_id,evaluated_at,id);
CREATE INDEX person_fact_candidates_source_idx ON person_fact_candidates(account_id,speaker_observation_id,id);

CREATE TABLE identity_fusion_schema (
    singleton boolean PRIMARY KEY CHECK(singleton),
    version bigint NOT NULL CHECK(version=33),
    contract_sha256 text NOT NULL CHECK(contract_sha256 ~ '^[0-9a-f]{64}$'),
    catalog_sha256 text NOT NULL CHECK(catalog_sha256 ~ '^[0-9a-f]{64}$'),
    installed_at timestamptz NOT NULL DEFAULT now()
);
