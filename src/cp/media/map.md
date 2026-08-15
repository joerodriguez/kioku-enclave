# map.md — src/cp/media/

Private Cloud Capture implementation children. They do not define routes on
their own; route ownership remains in the parent `src/cp/media.rs` module.

| File | Role |
|---|---|
| `wal.rs` / `wal/capture_event.rs` / `wal/reference_batch.rs` | **Inactive ADR-0022 only:** closed capture-session-finish, local canonical-capture receipt, and metadata-only screen-reference-batch request/result codecs with distinct bounded permanent replay ledgers. Stable identities derive from the validated caller session ID, subtype-separated caller event ID, or subtype-separated cross-language batch ID before actor admission. Each ledger lazily creates only its own authenticated schema inside the same logical mutation transaction, reserves capacity before domain SQL, and exact-index replays an authenticated result. The canonical child accepts only a complete normalized manifest plus exact account-bound object key and positive provider generation already fixed by a future B upload boundary, rejects unledgered adoption, authenticates existing session/stream bindings, and atomically covers all local event/media/browser/job/session/stream-ack rows and its bounded response. The reference batch covers its complete normalized manifest vector, exact reference preconditions, event rows, stream acknowledgement, and bounded response. DEK allocation, encryption/upload, Store, launcher, route, provider, billing, task, acknowledgement, and runtime-policy wiring remain absent. |
