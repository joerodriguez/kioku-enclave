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
- `0005_account_lifecycle.sql` adds durable account-deletion operations and
  no-resurrection tombstones.
- `0006_worker_cursors.sql` adds fleet-wide scheduler enumeration and the
  durable summarizer cursor.
- `0007_content_search.sql` adds tenant-qualified structured memories plus
  PostgreSQL full-text and pgvector indexes.
- `0008_capture_ingestion.sql` adds atomic capture receipts, media metadata,
  browser evidence, processing jobs, and the transactional work outbox.
- `0009_episode_query_contract.sql` adds tenant-scoped final briefs consumed by
  the episode list/detail and delivery surfaces.
