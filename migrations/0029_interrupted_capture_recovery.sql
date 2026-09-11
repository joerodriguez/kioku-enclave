-- Additive, independently receipted recovery provenance. The dedicated
-- migrator verifies the exact predecessor before this change; serving runs
-- no DDL and does not rewrite the signed v27 activation history.
ALTER TABLE capture_formation_receipts
    DROP CONSTRAINT capture_formation_receipts_finish_request_provenance_check;
ALTER TABLE capture_formation_receipts
    ADD CONSTRAINT capture_formation_receipts_finish_request_provenance_check CHECK (
        finish_request_provenance IS NULL OR finish_request_provenance IN (
            'event_finish_v1','finish_endpoint_v1','legacy_client_refinish_v1',
            'legacy_ended_v1','server_inactivity_v1'
        )
    );

CREATE TABLE interrupted_capture_schema (
    singleton boolean PRIMARY KEY CHECK (singleton),
    version bigint NOT NULL CHECK (version=29),
    contract_sha256 text NOT NULL,
    catalog_sha256 text NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
