-- User notification destinations and the short-lived provider-send fences
-- that serialize destination changes with in-flight disclosures.

CREATE TABLE webhook_subscriptions (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id text NOT NULL,
    name text NOT NULL,
    endpoint_url text NOT NULL,
    signing_secret text NOT NULL,
    include_content boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id)
);

CREATE INDEX webhook_subscriptions_account_idx
    ON webhook_subscriptions (account_id, created_at, id);

CREATE TABLE webhook_send_fences (
    account_id text NOT NULL,
    event_id text NOT NULL,
    subscription_id text NOT NULL,
    claim_id text NOT NULL UNIQUE,
    lease_expires_at timestamptz NOT NULL,
    endpoint_url text NOT NULL,
    signing_secret text NOT NULL,
    include_content boolean NOT NULL,
    outcome_kind text CHECK (outcome_kind IN (
        'sent', 'retry', 'ambiguous', 'failed',
        'cancel_account_inactive', 'cancel_subscription_missing',
        'cancel_subscription_disabled', 'cancel_destination_changed'
    )),
    provider_status bigint,
    provider_error text,
    retry_at timestamptz,
    outcome_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, event_id)
);

CREATE INDEX webhook_send_fences_subscription_idx
    ON webhook_send_fences (account_id, subscription_id, event_id);

CREATE TABLE episode_email_preferences (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    include_content boolean NOT NULL DEFAULT false,
    consented_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (enabled OR NOT include_content)
);

CREATE TABLE email_send_fences (
    account_id text NOT NULL,
    delivery_id text NOT NULL,
    claim_id text NOT NULL UNIQUE,
    lease_expires_at timestamptz NOT NULL,
    recipient_email text NOT NULL,
    include_content boolean NOT NULL,
    outcome_kind text CHECK (outcome_kind IN (
        'accepted', 'retry', 'ambiguous', 'failed',
        'cancel_account_inactive', 'cancel_preference_disabled',
        'cancel_recipient_changed', 'cancel_content_consent_changed'
    )),
    provider_status bigint,
    provider_message_id text,
    provider_error text,
    retry_at timestamptz,
    outcome_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, delivery_id)
);

CREATE INDEX email_send_fences_account_idx ON email_send_fences (account_id);

CREATE SEQUENCE push_token_generation_seq AS bigint START WITH 1;

CREATE TABLE push_installations (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id text NOT NULL,
    platform text NOT NULL CHECK (platform IN ('ios', 'macos')),
    topic text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    device_token text NOT NULL,
    token_generation bigint NOT NULL DEFAULT nextval('push_token_generation_seq')
        CHECK (token_generation > 0),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    UNIQUE (topic, environment, device_token)
);

CREATE INDEX push_installations_account_idx
    ON push_installations (account_id, enabled, last_seen_at, id);

CREATE TABLE push_send_fences (
    account_id text NOT NULL,
    installation_id text NOT NULL,
    token_generation bigint NOT NULL CHECK (token_generation > 0),
    claim_id text NOT NULL UNIQUE,
    lease_expires_at timestamptz NOT NULL,
    outcome_kind text CHECK (outcome_kind IN (
        'accepted', 'retry', 'ambiguous', 'failed', 'token_terminal',
        'cancel_account_inactive', 'cancel_installation_missing',
        'cancel_installation_disabled', 'cancel_token_generation_changed'
    )),
    provider_status bigint,
    provider_error text,
    retry_at timestamptz,
    outcome_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, installation_id)
);

CREATE INDEX push_send_fences_account_idx ON push_send_fences (account_id);

UPDATE persistence_schema SET version = 3, updated_at = now() WHERE singleton = true;
