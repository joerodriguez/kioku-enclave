-- Binds: $1 canonical strict fleet-receipt JSON, $2 its SHA-256, $3 the
-- detached Ed25519 signature, $4 the baked public-key DER SHA-256, and $5 the
-- exact embedded expand-contract SHA-256. No DDL or backfill occurs here.
WITH accepted_release AS (
    UPDATE persistence_schema_releases
       SET phase='finalized',
           finalization_receipt=$1::jsonb,
           finalization_receipt_sha256=$2,
           finalization_receipt_signature=$3,
           finalization_receipt_key_sha256=$4,
           finalized_at=clock_timestamp(),
           updated_at=clock_timestamp()
     WHERE release_version=26
       AND predecessor_version=24
       AND protocol_version=1
       AND contract_sha256=$5
       AND phase='expanded'
       AND accounts_complete
       AND episodes_complete
       AND members_complete
       AND finalization_receipt IS NULL
       AND finalization_receipt_signature IS NULL
       AND finalization_receipt_key_sha256 IS NULL
       AND ($1::jsonb->>'observed_at')::timestamptz <= clock_timestamp()
       AND ($1::jsonb->>'expires_at')::timestamptz
             >= clock_timestamp()+interval '60 seconds'
     RETURNING release_version
)
UPDATE persistence_schema
   SET version=26,updated_at=clock_timestamp()
 WHERE singleton=true
   AND version=24
   AND expanded_through_version=26
   AND EXISTS(SELECT 1 FROM accepted_release)
RETURNING version,expanded_through_version;
