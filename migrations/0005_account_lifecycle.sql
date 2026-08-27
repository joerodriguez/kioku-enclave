-- Content-free account deletion state. The operation and tombstones remain
-- after the account row and every tenant-owned row are physically removed.

CREATE TABLE account_deletion_operations (
    account_id text PRIMARY KEY,
    operation_id text NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('pending', 'failed_retryable', 'physical_complete')),
    reason text NOT NULL,
    retry_after_seconds bigint CHECK (retry_after_seconds IS NULL OR retry_after_seconds >= 0),
    hard_delete_time timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX account_deletion_pending_idx
    ON account_deletion_operations (updated_at, account_id)
    WHERE status = 'pending';

UPDATE persistence_schema SET version = 5, updated_at = now() WHERE singleton = true;
