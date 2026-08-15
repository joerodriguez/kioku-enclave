# map.md — `src/cp/finalizer/`

Private inactive ADR-0022 finalization mutation child. It cannot call Store,
allocate attempts, delivery identities, handoffs, destinations, or clocks,
invoke a model/provider, launch work, schedule retries, send, or acknowledge.

| File | Role |
|---|---|
| `wal.rs` | Closed exact finalization-commit codec and distinct bounded permanent unit-replay ledger. It derives identity from a pre-existing terminal Vertex event, authenticates that event's exact provider-result commitment plus the full episode/membership/prior-product predecessor, and atomically commits the complete normalized brief/screen product plus only already-fixed initial outbox rows. |
