-- Signed one-time dormant v1 -> v2 activation-contract upgrade.
-- Never edit the v27 installer or its immutable contract/event history.
CREATE TABLE reconciliation_activation_epoch_contract (
    feature text PRIMARY KEY REFERENCES persistence_feature_activation_contracts(feature)
        CHECK(feature='episode_topology_reconciliation'),
    generation bigint NOT NULL CHECK(generation=2),
    prior_append_definition text NOT NULL CHECK(length(prior_append_definition) BETWEEN 1 AND 65536),
    receipt jsonb NOT NULL,
    receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
    receipt_signature bytea NOT NULL CHECK(octet_length(receipt_signature)=64),
    receipt_key_sha256 bytea NOT NULL CHECK(octet_length(receipt_key_sha256)=32),
    FOREIGN KEY(feature,generation) REFERENCES persistence_feature_activation_events(feature,generation)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK(coalesce(receipt->>'contract_version'='2' AND receipt->>'generation'='2'
          AND receipt->>'previous_phase'='draining' AND receipt->>'requested_phase'='draining'
          AND jsonb_typeof(receipt->'epoch_upgrade')='object',false))
);

CREATE FUNCTION reconciliation_activation_epoch_insert_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    prior persistence_feature_activation_events%ROWTYPE;
BEGIN
    PERFORM 1 FROM persistence_feature_activation_contracts WHERE feature=NEW.feature FOR UPDATE;
    SELECT * INTO prior FROM persistence_feature_activation_events
     WHERE feature=NEW.feature ORDER BY generation DESC LIMIT 1;
    IF NOT FOUND OR prior.generation<>1 OR prior.phase<>'draining'
       OR NEW.receipt->'epoch_upgrade'->>'prior_receipt_sha256' IS DISTINCT FROM
            'sha256:'||encode(prior.receipt_sha256,'hex')
       OR NEW.receipt->'epoch_upgrade'->>'prior_candidate_fleet_image_digest' IS DISTINCT FROM
            prior.candidate_fleet_image_digest
       OR NEW.receipt->>'rollout_basis_points' IS DISTINCT FROM prior.rollout_basis_points::text
       OR NEW.receipt->>'rollout_seed' IS DISTINCT FROM prior.rollout_seed
       OR NEW.receipt->'explicit_canary_account_ids' IS DISTINCT FROM to_jsonb(prior.explicit_canary_account_ids)
       OR NEW.receipt->>'reconciliation_producer_contract_sha256' IS DISTINCT FROM prior.reconciliation_producer_contract_sha256
       OR NEW.receipt->>'reconciliation_model' IS DISTINCT FROM prior.reconciliation_model
       OR NEW.receipt->>'vertex_location' IS DISTINCT FROM prior.vertex_location
    THEN
        RAISE EXCEPTION 'activation epoch does not extend the exact dormant predecessor'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER reconciliation_activation_epoch_insert
BEFORE INSERT ON reconciliation_activation_epoch_contract
FOR EACH ROW EXECUTE FUNCTION reconciliation_activation_epoch_insert_guard();
CREATE TRIGGER reconciliation_activation_epoch_immutable
BEFORE UPDATE OR DELETE ON reconciliation_activation_epoch_contract
FOR EACH ROW EXECUTE FUNCTION deny_persistence_feature_activation_mutation();

CREATE OR REPLACE FUNCTION append_persistence_feature_activation_event()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    prior_generation bigint;
    prior_phase text;
    prior_rollout_basis_points bigint;
    prior_rollout_seed text;
    prior_explicit_canary_account_ids text[];
    prior_candidate_fleet_image_digest text;
    prior_producer_contract_sha256 text;
    prior_reconciliation_model text;
    prior_vertex_location text;
BEGIN
    -- This singleton row is the fleet-wide transaction fence. Application
    -- boundaries take KEY SHARE; a signed transition takes UPDATE.
    PERFORM 1 FROM persistence_feature_activation_contracts
     WHERE feature=NEW.feature FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'feature activation contract is missing'
            USING ERRCODE='55000';
    END IF;

    SELECT generation,phase,rollout_basis_points,rollout_seed,
           explicit_canary_account_ids,candidate_fleet_image_digest,
           reconciliation_producer_contract_sha256,
           reconciliation_model,vertex_location
      INTO prior_generation,prior_phase,prior_rollout_basis_points,prior_rollout_seed,
           prior_explicit_canary_account_ids,prior_candidate_fleet_image_digest,
           prior_producer_contract_sha256,
           prior_reconciliation_model,prior_vertex_location
      FROM persistence_feature_activation_events
     WHERE feature=NEW.feature ORDER BY generation DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.generation<>0 OR NEW.previous_phase<>'preactive' OR NEW.phase<>'installed' THEN
            RAISE EXCEPTION 'first feature activation event must install generation zero'
                USING ERRCODE='55000';
        END IF;
    ELSIF NEW.generation<>prior_generation+1 OR NEW.previous_phase<>prior_phase THEN
        RAISE EXCEPTION 'feature activation generation is stale or non-contiguous'
            USING ERRCODE='55000';
    ELSIF NOT (
        (prior_phase='installed' AND NEW.phase='draining')
        OR (prior_phase='draining' AND NEW.phase='active')
        OR (prior_phase='active' AND NEW.phase='paused')
        OR (prior_phase='paused' AND NEW.phase='draining')
        OR (prior_phase='paused' AND NEW.phase='active')
        OR EXISTS(SELECT 1 FROM reconciliation_activation_epoch_contract epoch
             WHERE epoch.feature=NEW.feature AND epoch.generation=NEW.generation
               AND prior_generation=1 AND prior_phase='draining'
               AND NEW.generation=2 AND NEW.phase='draining'
               AND epoch.receipt=NEW.receipt AND epoch.receipt_sha256=NEW.receipt_sha256
               AND epoch.receipt_signature=NEW.receipt_signature
               AND epoch.receipt_key_sha256=NEW.receipt_key_sha256
               AND NEW.rollout_basis_points=prior_rollout_basis_points
               AND NEW.rollout_seed=prior_rollout_seed
               AND NEW.explicit_canary_account_ids=prior_explicit_canary_account_ids
               AND NEW.reconciliation_producer_contract_sha256=prior_producer_contract_sha256
               AND NEW.reconciliation_model=prior_reconciliation_model
               AND NEW.vertex_location=prior_vertex_location)
    ) THEN
        RAISE EXCEPTION 'feature activation phase transition is invalid'
            USING ERRCODE='55000';
    ELSIF NEW.phase IN ('active','paused')
       AND (
            NEW.rollout_basis_points IS DISTINCT FROM prior_rollout_basis_points
            OR NEW.rollout_seed IS DISTINCT FROM prior_rollout_seed
            OR NEW.explicit_canary_account_ids IS DISTINCT FROM
               prior_explicit_canary_account_ids
            OR NEW.candidate_fleet_image_digest IS DISTINCT FROM
               prior_candidate_fleet_image_digest
            OR NEW.reconciliation_producer_contract_sha256 IS DISTINCT FROM
               prior_producer_contract_sha256
            OR NEW.reconciliation_model IS DISTINCT FROM prior_reconciliation_model
            OR NEW.vertex_location IS DISTINCT FROM prior_vertex_location
       ) THEN
        RAISE EXCEPTION 'active and paused transitions must preserve fleet, rollout, and producer scope'
            USING ERRCODE='55000';
    ELSIF prior_phase='paused' AND NEW.phase='draining'
       AND (
            (prior_rollout_basis_points=10000 AND NEW.rollout_basis_points<>10000)
            OR (
                NEW.rollout_basis_points<>10000
                AND NOT (prior_explicit_canary_account_ids <@
                         NEW.explicit_canary_account_ids)
            )
       ) THEN
        RAISE EXCEPTION 'a later draining scope cannot remove activated accounts'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END
$$;
