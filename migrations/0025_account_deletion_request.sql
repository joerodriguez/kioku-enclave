-- Add a durable pre-fence account-deletion request state. This state closes
-- account admission before usage settlement and the remote billing fence,
-- while preserving identity/content until that fence is acknowledged.

ALTER TABLE accounts DROP CONSTRAINT accounts_status_check;
ALTER TABLE accounts ADD CONSTRAINT accounts_status_check
    CHECK (status IN ('active', 'deletion_requested', 'deleting', 'deleted', 'unavailable'));

UPDATE persistence_schema SET version = 25, updated_at = now()
WHERE singleton = true AND version = 24;
