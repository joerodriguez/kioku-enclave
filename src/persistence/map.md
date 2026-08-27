# map.md — src/persistence/

Backend-neutral, typed application persistence ports and their composition root.
Product handlers and workers depend on these use-case interfaces rather than database
connections, SQL callbacks, or whole-file persistence behavior.

| File | Role |
|---|---|
| `mod.rs` | `RepositorySet` composition root for the legacy and PostgreSQL implementations. Startup selects exactly one complete repository set without request-time fallback or dual authority. |
| `admission.rs` | Backend-neutral fleet token-bucket and crash-recoverable concurrency-lease contract. |
| `billing.rs` | Backend-neutral billing pseudonym, recording authorization/credit, coverage, and detach-outbox contract. |
| `identity.rs` | Backend-neutral account/session and Apple-credential contract. |
| `lifecycle.rs` | Backend-neutral account tombstone, deletion progress, Apple-revocation, and final identity cleanup contract. |
| `oauth.rs` | Backend-neutral OAuth client, consent, authorization-code, and refresh-token transaction contract. |
| `playback.rs` | Backend-neutral recording playback dataset and person-memory projection contract. |
| `query.rs` | Backend-neutral tenant-scoped structured-memory search, episode pagination/detail projection, merged feed, and capture-freshness contract. |
| `entitlement.rs` | Backend-neutral active-account, daily usage, and Vertex reservation contract. |
| `episode_deletion.rs` | Backend-neutral two-step episode freeze, provider cleanup inventory, and durable purge receipt. |
| `notification.rs` | Backend-neutral webhook, email-consent, and push-installation configuration contract with redacted secret-bearing types. |
| `recording_retention.rs` | Backend-neutral preview/CAS policy, durable recording-key epoch, inventory, and downgrade-completion contract. |
| `work.rs` | Backend-neutral fleet account enumeration, summarizer cursor, and durable email, webhook, and push disclosure-fence contracts; provider I/O occurs outside the repository transaction. |
| [`legacy/`](legacy/map.md) | Private behavior-preserving adapters over the current encrypted SQLite/GCS stores. |
| [`postgres/`](postgres/map.md) | Bounded SQLx pool plus PostgreSQL implementations of the extracted ports. |
| `media_object.rs` / `gcs_media.rs` | Encrypted GCS object contract and provider implementation, including exact account and durable-recording purge. |
| `disabled_legacy.rs` | Fail-closed GCS implementation installed behind unavoidable compatibility structs in PostgreSQL mode so an accidentally missed legacy call cannot read or mutate the retired SQLite authority. |

`PERSISTENCE_BACKEND` selects the legacy or PostgreSQL repository set once at startup.
The legacy adapter remains a reference/development implementation, not a dual-write or
fallback mechanism. PostgreSQL mode verifies the reviewed schema and uses encrypted GCS
only through `MediaObjectStore` for large media bytes.
