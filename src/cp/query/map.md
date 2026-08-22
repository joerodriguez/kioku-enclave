# map.md — `src/cp/query/`

Private inactive ADR-0022 logical-operation children. They do not define routes
or obtain Store, provider, task, acknowledgement, or launcher authority.

The production parent `query.rs` also contains the separately gated browser
snapshot reader. Its browser-v2 arm follows a live episode member through the
screen result's `capture-v2-browser:<event_id>` reference, exact-matches the
capture context, observation, persisted state envelope, and recomputed
cross-language commitment, and fails closed on malformed evidence. The legacy
arm remains strict and likewise requires a live episode association. This
reader does not activate the child WAL family below, and its selected route
stays gated until the episode-deletion/browser-GC lifecycle is sealed.

| File | Role |
|---|---|
| [`wal.rs`](wal/map.md) | Closed, inactive selected-screenshot receipt codec plus private selected-screenshot-attempt, ciphertext-candidate, send-start, provider-proof, definitive-no-object termination, and finalization-queue children. The obsolete selected multipart route is now a Genesis `410 Gone` tombstone, so this family has no production route owner. The B attempt child consumes a caller-fixed opaque identity, reauthenticates the exact eligible screenshot ID, derives the account-bound object key, and atomically reserves pending episode count/bytes. The candidate child authenticates that exact unconsumed attempt and the installed media-DEK receipt, verifies the context-bound ciphertext against the borrowed validated JPEG/DEK, and durably retains ciphertext plus keyed commitments before any future send. The send child can consume only that exact-name authenticated candidate, derives one deterministic send request ID, and commits `SendStarted` before any future provider call. The provider-neutral child durably admits only one execution request, grants an injected seam one conditional create plus one bounded exact-name readback, and returns only a non-cloneable exact success or definitive-no-object proof. The C child consumes only the exact rejection proof and execution claim, reauthenticates the complete chain, releases budget for another target, and permanently fences the original target and future provider preparation. The A-v3 codec can consume the accepted proof and atomically retain a local screenshot in tests; historical unbound v1 and B-only v2 are also test-only. The queue child accepts only a caller-stable request and exact predecessor. None is Store/route/provider/launcher wired. |
