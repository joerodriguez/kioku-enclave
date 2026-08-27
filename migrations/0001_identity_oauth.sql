-- ADR-0040 PostgreSQL foundation: accounts, identities, credentials, and OAuth.
-- Serving processes never run this file; the release migrator applies it once.

CREATE TABLE persistence_schema (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version bigint NOT NULL CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO persistence_schema (singleton, version) VALUES (true, 1);

CREATE TABLE accounts (
    id text PRIMARY KEY,
    email text NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deleting', 'deleted', 'unavailable')),
    primary_provider text NOT NULL,
    primary_subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (primary_provider, primary_subject)
);

CREATE TABLE deleted_accounts (
    account_id text PRIMARY KEY,
    deleted_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE deleted_identities (
    provider text NOT NULL,
    subject text NOT NULL,
    deleted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);

CREATE TABLE auth_identities (
    provider text NOT NULL,
    subject text NOT NULL,
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject),
    UNIQUE (account_id, provider)
);

CREATE INDEX auth_identities_account_idx
    ON auth_identities (account_id, provider);

CREATE TABLE signup_daily (
    day date PRIMARY KEY,
    accounts bigint NOT NULL CHECK (accounts >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE apple_credentials (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    client_id text NOT NULL,
    refresh_token text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_validated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (account_id, client_id)
);

CREATE TABLE oauth_clients (
    client_id text PRIMARY KEY,
    client_name text,
    redirect_uris text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oauth_clients_redirect_uris_idx
    ON oauth_clients USING gin (redirect_uris);

CREATE TABLE oauth_consents (
    consent_hash text PRIMARY KEY,
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX oauth_consents_expiry_idx ON oauth_consents (expires_at);

CREATE TABLE oauth_authorization_codes (
    code_hash text PRIMARY KEY,
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);

CREATE INDEX oauth_authorization_codes_expiry_idx
    ON oauth_authorization_codes (expires_at);

CREATE TABLE refresh_tokens (
    token_hash text PRIMARY KEY,
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_active_account_idx
    ON refresh_tokens (account_id, client_id, expires_at)
    WHERE revoked_at IS NULL;
