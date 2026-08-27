# PostgreSQL persistence

The production-target implementations of the backend-neutral persistence
ports. They share one bounded SQLx pool and PostgreSQL transaction authority.
The module is compiled and contract-tested during extraction, but startup must
not select it until every active domain has moved off the legacy stores.

| File | Role |
|---|---|
| `mod.rs` | Pool construction, UTC/timeout policy, explicit migrator, schema verification, and shared transaction helpers. |
| `identity.rs` | PostgreSQL accounts, identities, signup budget, Apple credentials, and coherent session reads. |
| `oauth.rs` | PostgreSQL OAuth client registration, consent/code consumption, and refresh-token rotation. |
