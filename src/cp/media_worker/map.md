# map.md — `src/cp/media_worker/`

Private children of the raw-media worker. Nothing in this directory is a
launcher, route, provider adapter, task, or production Store-policy selector.

| File | Role |
|---|---|
| [`wal.rs`](wal/map.md) | **Inactive ADR-0022 media-worker A-domains:** owns the raw-media retention settlement plus a private first deterministic-result subtype. Retention derives one account/event-scoped opaque operation from a caller-stable capture event, fingerprints exact object/provenance/deadline/predecessor facts, and can only mark that row pruned after a future deletion boundary settles the provider object. The private child accepts one already terminal, durably identified Vertex screen attempt and the complete exact leased-work predecessor; it inserts only caller-ID-fixed screenshots/observations and full-tuple settles the corresponding jobs, media rows, and work unit. Both use distinct 1,048,576-row/32-MiB exact-replay ledgers. Screen person evidence and every audio/person/identity/voice result remain unsupported. Neither path can call Store/providers, read media, allocate clocks/IDs, launch work, retry, or acknowledge completion. |
