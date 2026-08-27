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
- `0010_browser_snapshot_query.sql` preserves the legacy and Cloud Capture v2
  browser-evidence query contract.
- `0011_episode_evidence_query.sql` adds tenant-qualified screenshot images,
  screen interpretations, people, speaker slots, and participants.
- `0012_people_voice_queries.sql` adds the people, identity-evidence,
  speaker-observation, and voice-lineage records used by public memory queries.
- `0013_vertex_usage_ledger.sql` adds fleet-wide paid-model invocation intents,
  billing delivery claims, and coverage reconciliation.
- `0014_media_processing.sql` adds fleet-wide media work-unit claims and
  tenant-qualified transcript, screen, speaker, and voice-job projections.
- `0015_memory_formation.sql` adds fleet-wide summarizer window claims and
  atomic episode/cursor settlement.
- `0016_finalization_delivery.sql` adds fleet-owned finalization claims and
  tenant-qualified webhook, email, and push delivery outboxes.
