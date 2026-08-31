-- Bind $1 is the exact embedded schema-contract SHA-256. The release row and
-- compatibility marker advance together only after catalog/data verification.
WITH accepted_release AS (
    UPDATE persistence_schema_releases
       SET phase='expanded',expanded_at=coalesce(expanded_at,clock_timestamp()),
           updated_at=clock_timestamp()
     WHERE release_version=26
       AND predecessor_version=25
       AND protocol_version=1
       AND contract_sha256=$1
       AND phase='backfilling'
       AND accounts_complete
       AND episodes_complete
       AND members_complete
       AND (SELECT count(*) FROM persistence_schema_release_steps
             WHERE release_version=26)=8
     RETURNING release_version
)
UPDATE persistence_schema
   SET expanded_through_version=26,updated_at=clock_timestamp()
 WHERE singleton=true
   AND version=25
   AND expanded_through_version IS NULL
   AND EXISTS(SELECT 1 FROM accepted_release)
RETURNING version,expanded_through_version;
