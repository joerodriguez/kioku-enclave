# Email-worker WAL child map

| Path | Responsibility |
| --- | --- |
| `wal.rs` | **Inactive ADR-0022 only:** exact local settlement of a provider-accepted email whose durable delivery identity and predecessor row already exist. Owns a distinct bounded replay ledger; cannot send email, allocate or retry attempts, call Store, launch work, acknowledge a request, or activate WAL persistence. |
