# Legacy persistence adapter map

| File | Responsibility |
|---|---|
| `mod.rs` | Private composition boundary for the current encrypted SQLite/GCS implementation. |
| `billing.rs` | Behavior-preserving billing pseudonym, recording lease/credit, coverage, and detach operations backed by `ControlStore`. |
| `entitlement.rs` | Behavior-preserving active-account checks and atomic daily quota/Vertex reservations backed by `ControlStore`. |
| `identity.rs` | Behavior-preserving account, identity, Apple credential, and session operations backed by `ControlStore`. |
| `notification.rs` | Behavior-preserving webhook, email preference, and push installation operations backed by `ControlStore`. |
| `oauth.rs` | Behavior-preserving OAuth registry, grant, code, and refresh-token operations backed by `ControlStore`. |

Application handlers and workers depend on the typed ports in the parent
`persistence` module, never on these concrete adapters.
