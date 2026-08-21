# map.md — src/cp/media/

Private Cloud Capture implementation children. They do not define routes on
their own; route ownership remains in the parent `src/cp/media.rs` module.

The parent manifest now caps device-supplied `started_at` and `ended_at` at the
same 64-byte bound enforced by every media settle family, preventing a newly
ingested event from being claimed and paid for when neither success nor failure
could ever settle it.

| File | Role |
|---|---|
| `wal.rs` / `wal/capture_event.rs` / `wal/reference_batch.rs` / `wal/reference_event.rs` | **ADR-0022; the capture-event and reference codecs are now route-owned, the capture-session-finish and media-DEK ones remain as they were:** closed capture-session-finish, local canonical-capture receipt, and metadata-only screen-reference-batch request/result codecs with distinct bounded permanent replay ledgers. Stable identities derive from the validated caller session ID, subtype-separated caller event ID, or subtype-separated cross-language batch ID before actor admission. Each ledger lazily creates only its own authenticated schema inside the same logical mutation transaction, reserves capacity before domain SQL, and exact-index replays an authenticated result. The canonical child accepts only a complete normalized manifest plus exact account-bound object key and positive provider generation already fixed by a future B upload boundary, rejects unledgered adoption, authenticates existing session/stream bindings, and atomically covers all local event/media/browser/job/session/stream-ack rows and its bounded response. The reference batch covers its complete normalized manifest vector, exact reference preconditions, event rows, stream acknowledgement, and bounded response. The single-event reference child mirrors the batch under its own subtype and ledger, treats a duplicate as a first-class outcome, and carries a rebase-required refusal to the route out of band. `upload_capture_event` owns the canonical and single-event reference children behind `is_wal_authoritative`, after a routed preflight read; the legacy write+save pair is byte-intact on the unselected branch. DEK allocation, encryption/upload and provider wiring stay on the route as they were. |
