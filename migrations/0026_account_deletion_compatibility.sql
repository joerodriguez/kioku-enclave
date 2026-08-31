-- Install the additive account-deletion request value without advancing the
-- schema marker. Production still serves the strict schema-24 predecessor
-- during the v26 expand, so the marker remains 24 until fleet finalization.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid='accounts'::regclass
           AND conname='accounts_status_check'
           AND convalidated
           AND pg_get_constraintdef(oid) =
               'CHECK ((status = ANY (ARRAY[''active''::text, ''deleting''::text, ''deleted''::text, ''unavailable''::text])))'
    ) THEN
        RAISE EXCEPTION 'schema-24 account status constraint is not the validated predecessor contract'
            USING ERRCODE='55000';
    END IF;
    ALTER TABLE accounts DROP CONSTRAINT accounts_status_check;
    ALTER TABLE accounts ADD CONSTRAINT accounts_status_check
        CHECK (status IN (
            'active','deletion_requested','deleting','deleted','unavailable'
        ));
END
$$;
