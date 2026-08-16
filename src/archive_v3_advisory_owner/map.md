# Advisory owner private children

| File | Responsibility |
|---|---|
| `comparison.rs` | Inactive Phase-1 owner-private exact-R1 recovery, bounded captured-prefix replay, independent pinned-legacy backup/full-parity comparison, atomic exact-live prefix restoration before evidence, repeated source/release/witness authentication, and a one-shot content-free Control settlement bound to the exact released owner. Exact retained-row loading reconciles lost Control responses before new local work. Only after durability, the owner invokes Store's cancellation-owned exact selector/registration retirement; it scrubs the restored queue, exact-reconciles already-retired state, and leaves the legacy connection authoritative. It has no drain publication settlement, acknowledgement, launcher, route, task, provider mutation/list/delete, or serving authority. |
