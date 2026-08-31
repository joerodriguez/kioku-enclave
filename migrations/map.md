# PostgreSQL migrations

Reviewed, append-only schema migrations for the ADR-0040/ADR-0042 PostgreSQL-only
structured-state authority. A dedicated release operation applies these files under the
PostgreSQL schema advisory lock; serving instances only verify a finalized version or an exact
receipted expand declared compatible by the candidate.

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
- `0010_browser_snapshot_query.sql` adds the Cloud Capture v2 browser-evidence query contract.
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
- `0017_delivery_claims.sql` adds fleet-wide provider lanes and durable frozen
  outbound request evidence for crash-safe multi-process delivery.
- `0018_capture_upload_admission.sql` adds fleet-wide GCS upload admission and
  the single installed processing-media key for each account.
- `0019_voice_lineage_export.sql` adds the remaining voice representative and
  identity-binding records exposed by the user export contract.
- `0020_episode_deletion.sql` adds a durable freeze/provider-purge/database-
  purge state machine and replayable receipt for user-requested episode deletion.
- `0021_recording_retention.sql` adds fleet-wide recording-retention policy,
  preview/CAS receipts, durable key epochs, and downgrade reconciliation state.
- `0022_reference_batch_billing.sql` adds durable reference-batch credit
  reservations, ordered event fingerprints, replay, and completion receipts.
- `0023_reviewer_fixture.sql` records the idempotent synthetic plugin-review
  fixture in PostgreSQL.
- `0024_fleet_admission.sql` adds fleet-wide token buckets and
  crash-recoverable concurrency leases so replica count cannot multiply
  request budgets.
- `0025_account_deletion_request.sql` adds the durable `deletion_requested`
  admission fence used while final usage and the one-way billing deletion
  fence are reconciled, before identity/content deletion begins.
- `0026_memory_reconciliation_episode_members_unique_index.sql` installs the
  mandatory legacy source-owner guard with `CREATE UNIQUE INDEX CONCURRENTLY`.
  Ambiguous ownership fails before any other v26 object; interrupted invalid
  builds are removed by the runner before a repaired retry.
- `0026_memory_reconciliation_release_ledger.sql` adds the one-row compatibility
  marker field plus exact-contract phase/cursor/fleet-authorization and
  per-step DDL/catalog-hash ledgers in one collision-refusing bounded metadata
  transaction.
- `0026_memory_reconciliation.sql` adds only new tenant-qualified source-settled
  reconciliation tables, functions, and indexes: leases, JSONB staged results,
  active-only membership, content-free handles and lineage, archive revisions,
  and atomic publication. It contains no backfill or index on a populated table.
- `0026_memory_reconciliation_capture_sessions_index.sql` and
  `0026_memory_reconciliation_capture_events_index.sql` install the two
  populated capture-horizon indexes concurrently and outside a transaction.
- `0026_memory_reconciliation_expand_receipt.sql` atomically records the exact
  completed contract as `expanded_through_version=26` and phase `expanded` while
  deliberately leaving version 25 for predecessor readiness.
- `0026_memory_reconciliation_finalize.sql` performs no DDL or backfill. It
  requires a 60-second database-time margin, atomically persists canonical
  strict fleet evidence, its SHA-256, detached Ed25519 signature, baked-key
  fingerprint, and `clock_timestamp()` receipt, then flips only
  `persistence_schema.version` to 26. A confirmation literal alone cannot
  finalize.
