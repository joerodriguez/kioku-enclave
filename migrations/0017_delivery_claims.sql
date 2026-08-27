-- Fleet-wide provider admission and durable frozen outbound requests.

CREATE TABLE provider_send_lanes (
    provider text PRIMARY KEY CHECK (provider IN ('email','webhook','push')),
    owner_token text,
    lease_until timestamptz,
    next_send_at timestamptz NOT NULL DEFAULT now(),
    circuit_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((owner_token IS NULL) = (lease_until IS NULL))
);

INSERT INTO provider_send_lanes(provider) VALUES ('email'),('webhook'),('push');

ALTER TABLE email_deliveries
    ADD COLUMN completed_claim_token text,
    ADD COLUMN frozen_recipient_email text,
    ADD COLUMN frozen_include_content boolean,
    ADD COLUMN frozen_subject text,
    ADD COLUMN frozen_text_body text,
    ADD COLUMN frozen_html_body text,
    ADD COLUMN send_started_at timestamptz,
    ADD COLUMN provider_message_id text,
    ADD COLUMN response_status bigint,
    ADD COLUMN error_code text;

ALTER TABLE webhook_deliveries
    ADD COLUMN completed_claim_token text,
    ADD COLUMN frozen_endpoint_url text,
    ADD COLUMN frozen_signing_secret text,
    ADD COLUMN frozen_include_content boolean,
    ADD COLUMN frozen_event_body text,
    ADD COLUMN send_started_at timestamptz,
    ADD COLUMN response_status bigint,
    ADD COLUMN error_code text;

ALTER TABLE push_deliveries
    ADD COLUMN completed_claim_token text,
    ADD COLUMN frozen_topic text,
    ADD COLUMN frozen_environment text,
    ADD COLUMN frozen_device_token text,
    ADD COLUMN frozen_token_generation bigint,
    ADD COLUMN send_started_at timestamptz,
    ADD COLUMN response_status bigint,
    ADD COLUMN error_code text;

UPDATE persistence_schema SET version = 17, updated_at = now()
WHERE singleton = true AND version = 16;
