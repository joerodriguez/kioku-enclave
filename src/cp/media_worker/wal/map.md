# map.md — `src/cp/media_worker/wal/`

Private, inactive ADR-0022 logical-result children. Nothing in this directory
is a launcher, worker, provider adapter, Store policy, route, task, retry loop,
or acknowledgement path.

| File | Role |
|---|---|
| `result.rs` | **Inactive screen-storyboard result A-domain:** derives one opaque operation from an already durable terminal Vertex attempt, authenticates that exact attempt plus the complete leased screen-work predecessor, and atomically inserts only caller-ID-fixed screenshots and screen observations while full-tuple settling their jobs, media rows, and work unit. Its distinct 1,048,576-row/32-MiB ledger reserves capacity before domain SQL and exact-replays after restart. The subtype accepts no person evidence and cannot create audio, identity, person, or voice rows. A future B boundary must bind the Vertex attempt to the work before constructing the plan; provider calls, media reads, clocks, automatic IDs, Store, launching, retries, and acknowledgement remain absent. |
