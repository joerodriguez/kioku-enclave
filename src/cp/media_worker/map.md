# map.md — `src/cp/media_worker/`

Private children of the raw-media worker. Nothing in this directory is a
launcher, route, provider adapter, task, or production Store-policy selector.

| File | Role |
|---|---|
| `wal.rs` | **Inactive ADR-0022 retention A-domain:** derives one account/event-scoped opaque operation from a caller-stable capture event, fingerprints the exact account-bound object key, bucket-local generation/provenance, plaintext hash, retention deadline, eligible predecessor state, and fixed terminal timestamp, then atomically marks only that exact row pruned or adopts an identical pre-existing terminal row. Its distinct 1,048,576-row/32-MiB ledger reserves capacity before domain SQL and exact-replays after restart. A future boundary must authenticate and settle provider deletion before constructing the plan; this child cannot call Store, list/read/delete provider objects, launch work, or acknowledge completion. |
