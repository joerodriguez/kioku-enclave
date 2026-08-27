# Legacy persistence adapter map

| File | Responsibility |
|---|---|
| `mod.rs` | Private composition boundary for the current encrypted SQLite/GCS implementation. |
| `entitlement.rs` | Behavior-preserving active-account checks and atomic daily quota/Vertex reservations backed by `ControlStore`. |
| `identity.rs` | Behavior-preserving account, identity, Apple credential, and session operations backed by `ControlStore`. |
| `oauth.rs` | Behavior-preserving OAuth registry, grant, code, and refresh-token operations backed by `ControlStore`. |

Application handlers and workers depend on the typed ports in the parent
`persistence` module, never on these concrete adapters.
