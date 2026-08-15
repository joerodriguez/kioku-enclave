# map.md — src/cp/media/wal/

Private inactive ADR-0022 logical-operation children. They do not define routes
or obtain Store, provider, task, acknowledgement, or launcher authority.

| File | Role |
|---|---|
| `capture_event.rs` | Closed local canonical-capture receipt codec and distinct bounded permanent exact-replay ledger. It derives a subtype-separated operation identity from the stable caller event ID, fingerprints the complete normalized manifest plus exact account-bound object key and positive provider generation, rejects adoption without its ledger, authenticates any existing session/stream binding, and atomically commits the event, media, browser, processing-job, session, stream-acknowledgement, bounded response, and ledger. A future B boundary must encrypt/upload the exact media and mint that immutable receipt; DEK, media bytes, provider, billing, Store, launcher, task, and acknowledgement authority remain absent. |
| `reference_batch.rs` | Closed metadata-only Mac screen-reference batch codec and distinct bounded permanent exact-replay ledger. It derives a subtype-separated operation identity from the existing deterministic batch ID, fingerprints the complete normalized ordered manifests under the fixed 1-MiB bound, and commits exact reference validation, new/duplicate rows, stream acknowledgement, response, and ledger atomically. Canonical media upload and the B-domain media-DEK/provider handoff remain unsupported. |
