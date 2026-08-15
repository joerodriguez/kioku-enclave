# map.md — `src/cp/query/wal/`

Private inactive ADR-0022 query mutation children. They cannot call Store,
allocate attempts or clocks, launch work, schedule retries, invoke providers,
or acknowledge routes.

| File | Role |
|---|---|
| `finalization_queue.rs` | Closed caller-stable finalization-queue codec and distinct bounded permanent unit-replay ledger. It fingerprints the complete eligible episode predecessor plus a fixed request identity and canonical queue timestamp, then full-tuple transitions only that exact row to `queued`. |
| `selected_screenshot_attempt.rs` | Inactive pre-provider B boundary that consumes one caller-fixed opaque attempt ID, reauthenticates the complete eligible screenshot predecessor and exact numeric screenshot ID, derives the account-bound object key, atomically reserves pending episode count/bytes, and retains the full binding plus typed receipt. Exact local consumption avoids double-counting; absent/inexact consumption remains reserved. It has no random/clock/DEK/media/provider/Store/launcher/retry/rejection-release/cleanup/acknowledgement authority. |
