# map.md — `src/cp/query/`

Private inactive ADR-0022 logical-operation children. They do not define routes
or obtain Store, provider, task, acknowledgement, or launcher authority.

| File | Role |
|---|---|
| [`wal.rs`](wal/map.md) | Closed selected-screenshot receipt codec plus private selected-screenshot-attempt, ciphertext-candidate, and finalization-queue children, each with a distinct bounded permanent exact-replay ledger. The B attempt child consumes a caller-fixed opaque identity, reauthenticates the exact eligible screenshot ID, derives the account-bound object key, and atomically reserves pending episode count/bytes. The candidate child authenticates that exact unconsumed attempt and the installed media-DEK receipt, verifies the context-bound ciphertext against the borrowed validated JPEG/DEK, and durably retains ciphertext plus keyed commitments before any future send. The production-facing A v2 request reconstructs and consumes the attempt binding before local settlement and on replay; historical unbound v1 is test-only. Send-start, provider receipt, and C rejection release remain absent. The queue child accepts only a caller-stable request and exact predecessor. None is route/launcher wired. |
