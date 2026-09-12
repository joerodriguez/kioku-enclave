-- ADR-0048 direct voice-reconciliation companion. Existing voice and person
-- tables remain authoritative; these rows commit exact append-only lineage.
CREATE TABLE voice_profile_proposals (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id bigint NOT NULL,
    kind text NOT NULL CHECK (kind='merge'),
    policy_version bigint NOT NULL CHECK (policy_version>0),
    embedding_space text NOT NULL,
    scorer_version bigint NOT NULL CHECK (scorer_version>0),
    channel_domain text NOT NULL,
    left_profile_id bigint NOT NULL,
    right_profile_id bigint NOT NULL,
    left_revision_id bigint NOT NULL,
    right_revision_id bigint NOT NULL,
    left_member_count bigint NOT NULL CHECK (left_member_count>0),
    right_member_count bigint NOT NULL CHECK (right_member_count>0),
    left_members_sha256 text NOT NULL CHECK (left_members_sha256 ~ '^[0-9a-f]{64}$'),
    right_members_sha256 text NOT NULL CHECK (right_members_sha256 ~ '^[0-9a-f]{64}$'),
    left_person_id bigint,
    right_person_id bigint,
    source_person_state jsonb NOT NULL CHECK (jsonb_typeof(source_person_state)='object'),
    left_superseded_revision_id bigint,
    right_superseded_revision_id bigint,
    slot_count bigint NOT NULL DEFAULT 0 CHECK(slot_count>=0),
    slots_sha256 text CHECK(slots_sha256 ~ '^[0-9a-f]{64}$'),
    applied_person_state jsonb CHECK(jsonb_typeof(applied_person_state)='object'),
    result_profile_id bigint,
    result_revision_id bigint,
    result_members_sha256 text CHECK (result_members_sha256 ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('proposed','applied','reversed','quarantined','rejected')),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 80),
    decision jsonb NOT NULL CHECK (jsonb_typeof(decision)='object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,id),
    UNIQUE (account_id,left_profile_id,right_profile_id,left_revision_id,right_revision_id,policy_version),
    CHECK (left_profile_id<right_profile_id),
    FOREIGN KEY (account_id,left_profile_id) REFERENCES voice_profiles(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,right_profile_id) REFERENCES voice_profiles(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,left_revision_id) REFERENCES voice_profile_revisions(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,right_revision_id) REFERENCES voice_profile_revisions(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,left_superseded_revision_id) REFERENCES voice_profile_revisions(account_id,id) ON DELETE SET NULL (left_superseded_revision_id),
    FOREIGN KEY (account_id,right_superseded_revision_id) REFERENCES voice_profile_revisions(account_id,id) ON DELETE SET NULL (right_superseded_revision_id),
    FOREIGN KEY (account_id,result_profile_id) REFERENCES voice_profiles(account_id,id) ON DELETE SET NULL (result_profile_id),
    FOREIGN KEY (account_id,result_revision_id) REFERENCES voice_profile_revisions(account_id,id) ON DELETE SET NULL (result_revision_id),
    FOREIGN KEY (account_id,left_person_id) REFERENCES people(account_id,id) ON DELETE SET NULL (left_person_id),
    FOREIGN KEY (account_id,right_person_id) REFERENCES people(account_id,id) ON DELETE SET NULL (right_person_id)
);
CREATE INDEX voice_profile_proposals_state_idx ON voice_profile_proposals(account_id,state,id);
CREATE TABLE voice_profile_proposal_samples (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    proposal_id bigint NOT NULL,
    source_profile_id bigint NOT NULL,
    sample_id bigint NOT NULL,
    source_assignment_id bigint NOT NULL,
    PRIMARY KEY (account_id,proposal_id,sample_id),
    FOREIGN KEY (account_id,proposal_id) REFERENCES voice_profile_proposals(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,source_profile_id) REFERENCES voice_profiles(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,sample_id) REFERENCES voice_samples(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,source_assignment_id) REFERENCES voice_sample_profile_assignments(account_id,id) ON DELETE CASCADE
);
-- Slots retain their original ordinal and ID. A proposal snapshots only metadata
-- needed to reverse its own derived reservation transfer, never source turns.
CREATE TABLE voice_profile_proposal_slots (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    proposal_id bigint NOT NULL,
    slot_id bigint NOT NULL,
    episode_id bigint NOT NULL,
    source_profile_id bigint,
    source_cluster_id bigint,
    slot_ordinal bigint NOT NULL CHECK(slot_ordinal>=0),
    source_status text NOT NULL CHECK(source_status IN ('active','superseded')),
    applied_status text CHECK(applied_status IN ('active','superseded')),
    PRIMARY KEY(account_id,proposal_id,slot_id),
    FOREIGN KEY(account_id,proposal_id) REFERENCES voice_profile_proposals(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,slot_id) REFERENCES episode_speaker_slots(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,episode_id) REFERENCES episodes(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,source_profile_id) REFERENCES voice_profiles(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,source_cluster_id) REFERENCES speaker_clusters(account_id,id) ON DELETE CASCADE
);
ALTER TABLE voice_profile_revisions ADD CONSTRAINT voice_profile_revisions_proposal_fk
    FOREIGN KEY(account_id,proposal_id) REFERENCES voice_profile_proposals(account_id,id) ON DELETE SET NULL (proposal_id);
ALTER TABLE voice_sample_profile_assignments ADD CONSTRAINT voice_sample_assignments_proposal_fk
    FOREIGN KEY(account_id,proposal_id) REFERENCES voice_profile_proposals(account_id,id) ON DELETE SET NULL (proposal_id);
CREATE TABLE voice_recurrence_schema (
    singleton boolean PRIMARY KEY CHECK(singleton),
    version bigint NOT NULL CHECK(version=32),
    contract_sha256 text NOT NULL CHECK(contract_sha256 ~ '^[0-9a-f]{64}$'),
    catalog_sha256 text NOT NULL CHECK(catalog_sha256 ~ '^[0-9a-f]{64}$'),
    installed_at timestamptz NOT NULL DEFAULT now()
);
