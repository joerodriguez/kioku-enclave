# PostgreSQL migrations

Reviewed, append-only schema migrations for the ADR-0040 structured-state
backend. A dedicated release operation applies these files under SQLx's
migration lock; serving instances only verify `persistence_schema.version`.

- `0001_identity_oauth.sql` creates the account, identity, Apple credential,
  signup-budget, OAuth client/consent/code, and refresh-token foundation.
