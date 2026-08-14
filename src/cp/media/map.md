# map.md — src/cp/media/

Private Cloud Capture implementation children. They do not define routes on
their own; route ownership remains in the parent `src/cp/media.rs` module.

| File | Role |
|---|---|
| `wal.rs` / `wal/reference_batch.rs` | **Inactive ADR-0022 only:** closed capture-session-finish and metadata-only screen-reference-batch request/result codecs with distinct bounded permanent replay ledgers. Stable identities derive from the validated caller session ID or subtype-separated cross-language batch ID before actor admission. Each ledger lazily creates only its own authenticated schema inside the same logical mutation transaction, reserves capacity before domain SQL, and exact-index replays an authenticated result. The reference batch atomically covers its complete normalized manifest vector, exact reference preconditions, event rows, stream acknowledgement, and bounded response; canonical media's B-domain DEK/provider handoff is not admitted. There is no Store, launcher, route, provider, task, acknowledgement, or runtime-policy wiring. |
