# map.md — `src/cp/media_worker/`

Private children of the raw-media worker. Nothing in this directory is a
launcher, route, provider adapter, task, or production Store-policy selector.

| File | Role |
|---|---|
| [`wal.rs`](wal/map.md) | **Inactive ADR-0022 media-worker domains:** owns raw-media retention and the first deterministic screen-result A subtype plus a private screen Vertex-begin B identity boundary. The B child authenticates one exact reserved topology with at least a two-minute live lease window, binds both its exact predecessor and post-usage-stable identity, derives a deterministic event ID, and atomically commits the started billing event, monthly coverage, complete work binding, and bounded receipt. The production-facing result v2 reauthenticates that exact permanent binding and stable work-attempt identity before it inserts only caller-ID-fixed screenshots/observations and full-tuple settles jobs, media, and work; historical v1 remains test-only. Screen person evidence and every audio/person/identity/voice result remain unsupported. These paths cannot call Store/providers, read media, allocate clocks/random IDs, launch work, retry, or acknowledge completion. |
