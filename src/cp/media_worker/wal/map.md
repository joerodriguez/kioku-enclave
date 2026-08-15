# map.md — `src/cp/media_worker/wal/`

Private, inactive ADR-0022 logical-result children. Nothing in this directory
is a launcher, worker, provider adapter, Store policy, route, task, retry loop,
or acknowledgement path.

| File | Role |
|---|---|
| `attempt.rs` | **Inactive screen-storyboard Vertex-begin B boundary:** authenticates one complete reserved screen-work attempt with at least the fixed two-minute provider window, binds both its exact predecessor and post-usage-stable attempt identity, derives the event ID from account/work/attempt identity, and atomically records the exact started billing event, deterministic full-tuple monthly coverage advance, complete work binding, and bounded typed receipt. Same-attempt replay is exact while a renewed lease/counter topology yields a new identity. It has no provider/media read, clock/random ID, Store, worker, launcher, task, retry, or acknowledgement authority. |
| `result.rs` | **Inactive screen-storyboard result A-domain:** its production-facing v2 request derives a subtype-separated opaque operation from an already durable terminal Vertex attempt, reauthenticates the sibling B ledger and typed receipt, compares that binding's stable attempt commitment to the current leased terminal work, and authenticates the complete exact predecessor. It atomically inserts only caller-ID-fixed screenshots and screen observations while full-tuple settling their jobs, media rows, and work unit, then exact-reads its distinct 1,048,576-row/32-MiB ledger before commit. Replay reauthenticates the permanent attempt binding. Historical v1 identity/encoding remains test-covered behind a test-only constructor. The subtype accepts no person evidence and cannot create audio, identity, person, or voice rows. Provider calls, media reads, clocks, automatic IDs, Store, launching, retries, and acknowledgement remain absent. |
