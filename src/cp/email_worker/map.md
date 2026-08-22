# Email-worker WAL child map

| Path | Responsibility |
| --- | --- |
| `wal.rs` | Active ADR-0022 email boundary and the only exported surface of its sealed children. It exposes typed claim, recovery, request-freeze, authority-check, and exact-settlement operations; it cannot call Store, Control, Resend, launch tasks, or choose policy. |
| `wal/claim.rs` | Persists the complete due-row predecessor and a leased random send capability before provider I/O. One bounded frozen-request row owns the exact recipient, rendered text/HTML, content-consent decision, and 24-hour idempotency key; claims retain only its SHA-256 commitment. A 65,536-row/1-GiB request budget, 16 provider-free deferrals per attempt, ten-attempt cap, one-live-claim index, deletion guard, replay ledger, and cascade accounting fail closed without provider spend. Live claims are never recovered by competitors; only expired claims may become ambiguous. |
| `wal/exact.rs` | Settles cancel, defer, retry, accepted, failed, or ambiguous from the complete carried predecessor and optional exact claim. It re-reads and full-row-CASes every immutable and nullable mutable field, checks attempts/timestamps/transitions, settles the claim in the same SQLite transaction, and adopts only an identical terminal target. Claimless cancellation refuses while a live claim exists. |
