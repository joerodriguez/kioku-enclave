-- ADR-0048 owner enrollment, withdrawal fencing and per-observation ownership.
ALTER TABLE accounts ADD COLUMN enrollment_revision bigint NOT NULL DEFAULT 0
    CHECK (enrollment_revision >= 0);

ALTER TABLE people DROP CONSTRAINT people_status_check;
ALTER TABLE people ADD CONSTRAINT people_status_check
    CHECK (status IN ('unknown','identified','quarantined','owner','recurring'));
CREATE UNIQUE INDEX people_owner_account_key ON people(account_id) WHERE status='owner';

ALTER TABLE episode_participants DROP CONSTRAINT episode_participants_attribution_kind_check;
ALTER TABLE episode_participants ADD CONSTRAINT episode_participants_attribution_kind_check
    CHECK (attribution_kind IN ('owner','owner_presentation','owner_source_role','owner_voice',
        'verified_voice','direct_identity_evidence','context_inferred'));

ALTER TABLE speaker_clusters
    ADD COLUMN owner boolean NOT NULL DEFAULT false,
    ADD COLUMN profile_updates_quarantined boolean NOT NULL DEFAULT false,
    ADD COLUMN channel_domain text;

ALTER TABLE speaker_observations
    ADD COLUMN voice_profile_id bigint,
    ADD COLUMN voice_sample_id bigint,
    ADD COLUMN owner_evidence_id bigint,
    ADD CONSTRAINT speaker_observations_voice_profile_fk
        FOREIGN KEY (account_id,voice_profile_id) REFERENCES voice_profiles(account_id,id)
        ON DELETE SET NULL (voice_profile_id),
    ADD CONSTRAINT speaker_observations_voice_sample_fk
        FOREIGN KEY (account_id,voice_sample_id) REFERENCES voice_samples(account_id,id)
        ON DELETE SET NULL (voice_sample_id),
    ADD CONSTRAINT speaker_observations_owner_evidence_fk
        FOREIGN KEY (account_id,owner_evidence_id) REFERENCES identity_evidence(account_id,id)
        ON DELETE SET NULL (owner_evidence_id);
CREATE INDEX speaker_observations_voice_profile_idx
    ON speaker_observations(account_id,voice_profile_id,id);

CREATE TABLE voice_enrollment_sessions (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    capture_session_id text NOT NULL,
    designated boolean NOT NULL,
    enrollment_revision bigint NOT NULL,
    first_event_id text,
    device_id text NOT NULL,
    install_id text NOT NULL,
    stream_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('recording','processing','enrolled','inconclusive','expired')),
    reason text CHECK (reason IN (
        'marker_missing','marker_after_ordinary_start','unsupported_stream','multiple_streams',
        'multiple_devices','route_changed','enrollment_revoked','no_speech','no_eligible_sample',
        'no_dominant_voice','overlapping_speech','raw_media_expired','source_deleted','forgotten',
        'processing_failed','source_changed')),
    channel_domain text,
    timeline_started_at timestamptz,
    timeline_cutoff_at timestamptz,
    source_revision bigint CHECK (source_revision >= 0),
    seal_generation bigint CHECK (seal_generation >= 0),
    dominant_share double precision CHECK (dominant_share >= 0 AND dominant_share <= 1),
    accepted_sample_count bigint NOT NULL DEFAULT 0 CHECK (accepted_sample_count >= 0),
    voice_profile_id bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,capture_session_id),
    FOREIGN KEY (account_id,capture_session_id)
        REFERENCES capture_sessions(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,first_event_id)
        REFERENCES capture_events(account_id,event_id) ON DELETE SET NULL (first_event_id),
    FOREIGN KEY (account_id,voice_profile_id)
        REFERENCES voice_profiles(account_id,id) ON DELETE SET NULL (voice_profile_id),
    CHECK ((timeline_started_at IS NULL) = (timeline_cutoff_at IS NULL)),
    CHECK (timeline_cutoff_at > timeline_started_at
        AND timeline_cutoff_at <= timeline_started_at + interval '180 seconds'),
    CHECK (designated OR state IN ('inconclusive','expired'))
);
CREATE INDEX voice_enrollment_sessions_pending_idx
    ON voice_enrollment_sessions(account_id,state,created_at,capture_session_id);
