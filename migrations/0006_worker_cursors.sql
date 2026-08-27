-- Fleet-wide scheduler enumeration and the durable memory-formation cursor.

ALTER TABLE accounts ADD COLUMN summarized_until timestamptz;

CREATE INDEX accounts_active_sweep_idx
    ON accounts (created_at, id)
    WHERE status = 'active';

UPDATE persistence_schema SET version = 6, updated_at = now() WHERE singleton = true;
