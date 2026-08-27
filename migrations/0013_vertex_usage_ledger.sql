-- Fleet-wide Vertex invocation accounting and billing delivery claims.

CREATE TABLE vertex_usage_events (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    event_id text NOT NULL,
    request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    operation text NOT NULL CHECK (operation IN (
        'audio_understanding','screen_understanding','episode_summarization',
        'episode_finalization'
    )),
    requested_model text NOT NULL,
    returned_model text,
    location text NOT NULL,
    traffic_type text NOT NULL DEFAULT 'on_demand' CHECK (traffic_type IN (
        'on_demand','batch','provisioned_throughput'
    )),
    http_status integer CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    prompt_tokens bigint CHECK (prompt_tokens IS NULL OR prompt_tokens >= 0),
    input_text_tokens bigint CHECK (input_text_tokens IS NULL OR input_text_tokens >= 0),
    input_audio_tokens bigint CHECK (input_audio_tokens IS NULL OR input_audio_tokens >= 0),
    input_image_tokens bigint CHECK (input_image_tokens IS NULL OR input_image_tokens >= 0),
    cached_input_tokens bigint CHECK (cached_input_tokens IS NULL OR cached_input_tokens >= 0),
    cached_input_text_tokens bigint CHECK (cached_input_text_tokens IS NULL OR cached_input_text_tokens >= 0),
    cached_input_audio_tokens bigint CHECK (cached_input_audio_tokens IS NULL OR cached_input_audio_tokens >= 0),
    cached_input_image_tokens bigint CHECK (cached_input_image_tokens IS NULL OR cached_input_image_tokens >= 0),
    output_text_tokens bigint CHECK (output_text_tokens IS NULL OR output_text_tokens >= 0),
    thought_tokens bigint CHECK (thought_tokens IS NULL OR thought_tokens >= 0),
    total_tokens bigint CHECK (total_tokens IS NULL OR total_tokens >= 0),
    outcome text NOT NULL CHECK (outcome IN (
        'started','metered','usage_missing','ambiguous','not_billed'
    )),
    delivery_state text NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','delivered')),
    delivery_attempt_count bigint NOT NULL DEFAULT 0 CHECK (delivery_attempt_count >= 0),
    delivery_claim_id text,
    delivery_claim_expires_at timestamptz,
    observed_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, event_id),
    CHECK ((delivery_claim_id IS NULL) = (delivery_claim_expires_at IS NULL))
);
CREATE INDEX vertex_usage_events_outbox_idx
    ON vertex_usage_events(delivery_state, delivery_claim_expires_at, observed_at);

CREATE TABLE vertex_usage_coverage (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    period text NOT NULL CHECK (period ~ '^[0-9]{4}-[0-9]{2}$'),
    sequence bigint NOT NULL CHECK (sequence > 0),
    pending_events bigint NOT NULL CHECK (pending_events >= 0),
    lost_events bigint NOT NULL DEFAULT 0 CHECK (lost_events >= 0),
    delivery_state text NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','delivered')),
    delivery_claim_id text,
    delivery_claim_expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, period),
    CHECK ((delivery_claim_id IS NULL) = (delivery_claim_expires_at IS NULL))
);

UPDATE persistence_schema SET version = 13 WHERE singleton = true AND version = 12;
