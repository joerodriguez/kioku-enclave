# Vertex usage WAL child map

| Path | Responsibility |
| --- | --- |
| wal.rs | Inactive ADR-0022 production A-domain for deterministic terminal outcomes of a pre-existing Vertex usage event. It derives one opaque operation ID from the exact durable event ID, canonicalizes the terminal response/ambiguous/not-billed facts, applies or exactly adopts the terminal row, refreshes coverage only on the first transition from started, and retains unit replay in its own hard-bounded permanent ledger. The B-domain invocation allocator remains outside this child. There is no Store, worker, launcher, provider, delivery, task, acknowledgement, list/delete, startup, route, or policy connection. |
