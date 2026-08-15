# map.md — `src/cp/query/wal/`

Private inactive ADR-0022 query mutation children. They cannot call Store,
allocate attempts or clocks, launch work, schedule retries, invoke providers,
or acknowledge routes.

| File | Role |
|---|---|
| `finalization_queue.rs` | Closed caller-stable finalization-queue codec and distinct bounded permanent unit-replay ledger. It fingerprints the complete eligible episode predecessor plus a fixed request identity and canonical queue timestamp, then full-tuple transitions only that exact row to `queued`. |
