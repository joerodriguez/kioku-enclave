# map.md — src/persistence/

Backend-neutral, typed application persistence ports and their composition root.
Product handlers and workers depend on these use-case interfaces rather than database
connections, SQL callbacks, or whole-file persistence behavior.

| File | Role |
|---|---|
| `mod.rs` | `RepositorySet` composition root. It currently constructs the behavior-preserving legacy identity adapter; PostgreSQL and further domain ports are added as vertical slices. |
| `identity.rs` | Account lifecycle lookup and Google-account upsert port, plus the private adapter over the existing encrypted `ControlStore`. |

The legacy adapter remains authoritative while interfaces are extracted. It is not a
production dual-write or fallback mechanism. A future PostgreSQL repository set will be
selected once at startup and must implement the same behavioral contracts.
