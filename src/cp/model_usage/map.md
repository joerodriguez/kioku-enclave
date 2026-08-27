# Vertex usage WAL child map

| Path | Responsibility |
| --- | --- |
| `wal.rs` | Active ADR-0022 model-usage WAL family registry and deterministic terminal-outcome ledger. It seals the invocation, reconciliation, delivery, and coverage children into the generic WAL owner and keeps each subtype's operation identity and replay result bounded. |
| `wal/invocation.rs` | Durable pre-egress Vertex invocation allocation. It derives an opaque event from the caller anchor and lane sequence, applies or adopts the exact `started` row, and refreshes producer coverage in the same witnessed transaction so a paid request cannot leave first. |
| `wal/reconcile.rs` | Crash-stale intent and unsafe-model reconciliation. Stale intents become deliverable `ambiguous` events; only explicitly enumerated poison rows are quarantined and increase `lost_events`, with predecessor-bound absolute accounting that cannot double-count on replay. |
| `wal/delivery.rs` | Usage outbox attempt and terminal-delivery transitions. It carries exact event predecessors, advances attempts or marks delivery once, and refreshes coverage atomically without repeating provider work. |
| `wal/coverage.rs` | Coverage rollover, control-anchored snapshot persistence, delivery completion, and stale invalidation. Full predecessor CAS and stable logical identities make captured-before-publication recovery reapply the same marker exactly once; conservative rollback loss is never cleared or incremented by replay. |
