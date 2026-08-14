# map.md — src/cp/media/

Private Cloud Capture implementation children. They do not define routes on
their own; route ownership remains in the parent `src/cp/media.rs` module.

| File | Role |
|---|---|
| `wal.rs` | **Inactive ADR-0022 only:** closed capture-session-finish request/result codec and its distinct bounded permanent replay ledger. Stable identity is derived from the validated caller session ID before actor admission. The ledger lazily creates only its own authenticated schema inside the same logical mutation transaction, reserves capacity before domain SQL, and exact-index replays an authenticated result. It has no Store, launcher, route, provider, task, acknowledgement, or runtime-policy wiring. |
