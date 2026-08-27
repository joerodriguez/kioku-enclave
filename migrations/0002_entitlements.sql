-- Fleet-wide usage and quota counters.

CREATE TABLE usage_daily (
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    day date NOT NULL,
    utterances bigint NOT NULL DEFAULT 0 CHECK (utterances >= 0),
    screenshots bigint NOT NULL DEFAULT 0 CHECK (screenshots >= 0),
    mcp_calls bigint NOT NULL DEFAULT 0 CHECK (mcp_calls >= 0),
    vertex_requests bigint NOT NULL DEFAULT 0 CHECK (vertex_requests >= 0),
    vertex_output_tokens bigint NOT NULL DEFAULT 0 CHECK (vertex_output_tokens >= 0),
    vertex_audio_output_tokens bigint NOT NULL DEFAULT 0
        CHECK (vertex_audio_output_tokens >= 0),
    vertex_screen_output_tokens bigint NOT NULL DEFAULT 0
        CHECK (vertex_screen_output_tokens >= 0),
    vertex_derived_output_tokens bigint NOT NULL DEFAULT 0
        CHECK (vertex_derived_output_tokens >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, day)
);

UPDATE persistence_schema SET version = 2, updated_at = now() WHERE singleton = true;
