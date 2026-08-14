# map.md — src/cp/media/wal/

Private inactive ADR-0022 logical-operation children. They do not define routes
or obtain Store, provider, task, acknowledgement, or launcher authority.

| File | Role |
|---|---|
| `reference_batch.rs` | Closed metadata-only Mac screen-reference batch codec and distinct bounded permanent exact-replay ledger. It derives a subtype-separated operation identity from the existing deterministic batch ID, fingerprints the complete normalized ordered manifests under the fixed 1-MiB bound, and commits exact reference validation, new/duplicate rows, stream acknowledgement, response, and ledger atomically. Canonical media upload and the B-domain media-DEK/provider handoff remain unsupported. |
