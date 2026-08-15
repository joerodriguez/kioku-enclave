# map.md — `src/cp/query/wal/`

Private inactive ADR-0022 query mutation children. They cannot call Store,
allocate attempts or clocks, launch work, schedule retries, invoke providers,
or acknowledge routes.

The parent selected-screenshot A codec consumes the exact attempt child's
permanent binding in its production-facing v2 request and on replay; historical
unbound v1 construction is test-only. A second child authenticates that attempt
and the installed media-DEK receipt before retaining one exact context-bound
ciphertext candidate. A third child consumes only the exact-name,
DEK-authenticated candidate and durably records one deterministic `SendStarted`
request identity before any future provider call; provider settlement remains
absent.

| File | Role |
|---|---|
| `finalization_queue.rs` | Closed caller-stable finalization-queue codec and distinct bounded permanent unit-replay ledger. It fingerprints the complete eligible episode predecessor plus a fixed request identity and canonical queue timestamp, then full-tuple transitions only that exact row to `queued`. |
| `selected_screenshot_attempt.rs` | Inactive pre-provider B boundary that consumes one caller-fixed opaque attempt ID, reauthenticates the complete eligible screenshot predecessor and exact numeric screenshot ID, derives the account-bound object key, atomically reserves pending episode count/bytes, and retains the full binding plus typed receipt. Exact local consumption avoids double-counting; absent/inexact consumption remains reserved. It has no random/clock/DEK/media/provider/Store/launcher/retry/rejection-release/cleanup/acknowledgement authority. |
| `selected_screenshot_send.rs` | Inactive `SendStarted` continuation. Its plan can be built only from the WAL-private exact-name candidate loader, derives a deterministic 256-bit send request ID and complete send binding, requires the exact candidate plus an unconsumed B attempt on first apply, and atomically inserts a separate bounded marker before any future provider I/O. Replay may survive later exact A settlement. The parent can obtain only an opaque plan from a WAL-owned factory; only its post-marker exact-name loader crosses that boundary, requiring account, image, and borrowed DEK before returning the original ciphertext plus a non-cloneable typed marker receipt. It has no enumeration, KMS/provider client, network I/O, clock/randomness, retry, outcome classification, A/C settlement, Store, route, launcher, delete/list, or acknowledgement authority. |
| `selected_screenshot_upload.rs` | Inactive `CandidateReady` continuation of the exact selected-screenshot attempt. Construction borrows the validated JPEG and media DEK, authenticates the installed-DEK receipt, exact-decrypts the supplied context-bound ciphertext, and retains only that ciphertext plus keyed commitments in a 512-MiB-capped permanent ledger. Apply requires the exact unconsumed attempt; replay reauthenticates both predecessors. Its private exact-name restart loader preflights lengths and requires the account, attempt, and borrowed DEK before returning only that authenticated ciphertext/receipt. It has no enumeration, KMS, provider, send-start, outcome, Store, route, launcher, retry, delete/list, or acknowledgement authority. |
