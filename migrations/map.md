# PostgreSQL migrations

Reviewed, append-only schema migrations for the ADR-0040 structured-state
backend. A dedicated release operation applies these files under SQLx's
migration lock; serving instances only verify `persistence_schema.version`.

- `0001_identity_oauth.sql` creates the account, identity, Apple credential,
  signup-budget, OAuth client/consent/code, and refresh-token foundation.
- `0002_entitlements.sql` adds tenant-scoped, fleet-wide daily quota and Vertex
  reservation counters.
- `0003_notification_configuration.sql` adds webhook destinations, email
  consent, the bounded push registry, and provider-send fence tables that
  serialize configuration changes with in-flight disclosures.
- `0004_billing_recording.sql` adds billing pseudonyms, coverage anchors,
  recording lease/idempotency receipts, and fleet-wide delivery credits.
