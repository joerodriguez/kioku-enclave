LEFT JOIN LATERAL (
    WITH RECURSIVE basis AS (
        SELECT o.id AS observation_id,c.id AS speaker_cluster_id,vp.id AS voice_profile_id,
               (owner_match.valid OR (coalesce(c.attribution_state='owner_transmit',false)
                   AND NOT owner_domain.recognized)) AS owner_source,
               owner_match.valid AS owner_voice,
               op.id AS observation_person_id,cp.id AS cluster_person_id,
               pp.id AS profile_person_id,op.display_name AS observation_name,
               cp.display_name AS cluster_name,pp.display_name AS profile_name,
               coalesce(op.id IS NOT NULL AND cp.id IS NOT NULL AND op.id<>cp.id,false)
                   AS identity_conflict,
               __MEMORY__ AS episode_id
          FROM (SELECT 1) anchor
          LEFT JOIN speaker_observations o
            ON o.account_id=__UTTERANCE__.account_id AND o.id=__UTTERANCE__.speaker_observation_id
          LEFT JOIN speaker_clusters c ON c.account_id=o.account_id AND c.id=o.cluster_id
          LEFT JOIN voice_profiles vp ON vp.account_id=o.account_id
            AND vp.id=coalesce(o.voice_profile_id,CASE WHEN NOT coalesce(c.profile_updates_quarantined,false)
                AND NOT coalesce(c.owner,false) THEN c.voice_profile_id END)
          LEFT JOIN people op ON op.account_id=o.account_id AND op.id=o.person_id
            AND op.status='identified' AND nullif(btrim(op.display_name),'') IS NOT NULL
          LEFT JOIN people cp ON cp.account_id=c.account_id AND cp.id=c.person_id
            AND NOT coalesce(c.profile_updates_quarantined,false)
            AND cp.status='identified' AND nullif(btrim(cp.display_name),'') IS NOT NULL
          LEFT JOIN people pp ON pp.account_id=vp.account_id AND pp.id=vp.person_id
            AND vp.status<>'quarantined' AND pp.status='identified'
            AND nullif(btrim(pp.display_name),'') IS NOT NULL
          CROSS JOIN LATERAL (
              SELECT EXISTS(SELECT 1 FROM voice_profiles owner_profile
                  JOIN people owner ON owner.account_id=owner_profile.account_id
                    AND owner.id=owner_profile.person_id AND owner.status='owner'
                  WHERE owner_profile.account_id=o.account_id
                    AND owner_profile.channel_domain=c.channel_domain
                    AND owner_profile.embedding_space='__EMBEDDING_SPACE__'
                    AND owner_profile.scorer_version=__SCORER_VERSION__
                    AND owner_profile.status<>'quarantined' AND owner_profile.sample_count>0) recognized
          ) owner_domain
          CROSS JOIN LATERAL (
              SELECT EXISTS(SELECT 1 FROM identity_evidence evidence
                  JOIN people owner ON owner.account_id=evidence.account_id
                    AND owner.id=evidence.person_id AND owner.status='owner'
                  JOIN voice_samples sample ON sample.account_id=evidence.account_id
                    AND sample.id=o.voice_sample_id AND sample.speaker_observation_id=o.id
                    AND sample.voice_profile_id=vp.id AND sample.accepted
                  WHERE evidence.account_id=o.account_id AND evidence.id=o.owner_evidence_id
                    AND evidence.speaker_observation_id=o.id AND evidence.person_id=o.person_id
                    AND evidence.voice_profile_id=vp.id AND vp.person_id=owner.id
                    AND evidence.kind IN ('owner_enrollment','owner_voice') AND evidence.status='accepted'
                    AND evidence.evidence->>'voice_sample_id'=sample.id::text
                    AND vp.status<>'quarantined' AND vp.sample_count>0
                    AND vp.embedding_space='__EMBEDDING_SPACE__' AND vp.scorer_version=__SCORER_VERSION__
                    AND sample.embedding_space=vp.embedding_space AND sample.scorer_version=vp.scorer_version
                    AND sample.channel_domain=vp.channel_domain) valid
          ) owner_match
    ), resolved AS (
        -- Direct evidence is independently authoritative. A propagated profile
        -- person cannot override it; conflicting direct sources abstain.
        SELECT basis.*,
               CASE WHEN owner_source OR identity_conflict THEN NULL
                    ELSE coalesce(observation_person_id,cluster_person_id,profile_person_id) END AS person_id,
               CASE WHEN owner_source OR identity_conflict THEN NULL
                    ELSE coalesce(observation_name,cluster_name,profile_name) END AS person_name,
               CASE WHEN owner_voice THEN 'owner_voice' WHEN owner_source THEN 'owner_source_role'
                    WHEN NOT identity_conflict AND coalesce(observation_person_id,cluster_person_id) IS NOT NULL
                        THEN 'direct_identity_evidence'
                    WHEN voice_profile_id IS NOT NULL THEN 'verified_voice'
                    WHEN observation_id IS NOT NULL THEN 'context_inferred'
                    ELSE NULL END AS attribution_kind
          FROM basis
    ), slotted AS (
        SELECT resolved.*,slot.slot_ordinal
          FROM resolved
          LEFT JOIN LATERAL (
              SELECT s.slot_ordinal FROM episode_speaker_slots s
                LEFT JOIN speaker_clusters alias_cluster
                  ON alias_cluster.account_id=s.account_id AND alias_cluster.id=s.speaker_cluster_id
               WHERE s.account_id=__UTTERANCE__.account_id AND s.episode_id=resolved.episode_id
                 AND s.status='active' AND (
                    (resolved.voice_profile_id IS NOT NULL AND
                        (s.voice_profile_id=resolved.voice_profile_id OR alias_cluster.voice_profile_id=resolved.voice_profile_id))
                    OR (resolved.voice_profile_id IS NULL AND s.speaker_cluster_id=resolved.speaker_cluster_id))
               ORDER BY s.slot_ordinal,s.id LIMIT 1
          ) slot ON TRUE
    ), letters(n,label) AS (
        SELECT slot_ordinal/26-1,chr(65+(slot_ordinal%26)::int) FROM slotted
         WHERE slot_ordinal IS NOT NULL
        UNION ALL
        SELECT n/26-1,chr(65+(n%26)::int)||label FROM letters WHERE n>=0
    ), presented AS (
        SELECT slotted.*,
            CASE WHEN owner_source THEN 'Me'
                 WHEN person_name IS NOT NULL THEN person_name
                 WHEN slot_ordinal IS NOT NULL THEN 'Speaker '||(SELECT label FROM letters WHERE n<0)
                 WHEN observation_id IS NULL THEN coalesce(nullif(btrim(__UTTERANCE__.speaker_label),''),'Speaker')
                 ELSE 'Speaker' END AS speaker_label,
            CASE WHEN owner_source THEN 'owner'
                 WHEN person_id IS NOT NULL THEN 'person:'||person_id
                 WHEN voice_profile_id IS NOT NULL THEN 'voice_profile:'||voice_profile_id
                 WHEN speaker_cluster_id IS NOT NULL THEN 'speaker_cluster:'||speaker_cluster_id
                 ELSE NULL END AS participant_key
        FROM slotted
    )
    SELECT speaker_label,speaker_label AS display_name,person_id,attribution_kind,episode_id,
           voice_profile_id,speaker_cluster_id,slot_ordinal,participant_key,owner_source,
           identity_conflict,observation_id
      FROM presented
) AS speaker_identity ON TRUE
