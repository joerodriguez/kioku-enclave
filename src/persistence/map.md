# map.md — src/persistence/

Backend-neutral, typed application persistence ports and their composition root.
Product handlers and workers depend on these use-case interfaces rather than database
connections, SQL callbacks, or whole-file persistence behavior.

| File | Role |
|---|---|
| `mod.rs` | `RepositorySet` composition root. It currently constructs the behavior-preserving legacy identity adapter; PostgreSQL and further domain ports are added as vertical slices. |
| `identity.rs` | Backend-neutral account/session and Apple-credential contract. |
| `oauth.rs` | Backend-neutral OAuth client, consent, authorization-code, and refresh-token transaction contract. |
| [`legacy/`](legacy/map.md) | Private behavior-preserving adapters over the current encrypted SQLite/GCS stores. |

The legacy adapter remains authoritative while interfaces are extracted. It is not a
production dual-write or fallback mechanism. A future PostgreSQL repository set will be
selected once at startup and must implement the same behavioral contracts.
