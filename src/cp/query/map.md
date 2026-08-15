# map.md — `src/cp/query/`

Private inactive ADR-0022 logical-operation children. They do not define routes
or obtain Store, provider, task, acknowledgement, or launcher authority.

| File | Role |
|---|---|
| [`wal.rs`](wal/map.md) | Closed selected-screenshot receipt codec plus private selected-screenshot-attempt and finalization-queue children, each with a distinct bounded permanent exact-replay ledger. The B attempt child consumes a caller-fixed opaque identity, reauthenticates the exact eligible screenshot ID, derives the account-bound object key, and atomically reserves pending episode count/bytes before any future provider I/O. The production-facing A v2 request reconstructs and consumes that exact binding before local settlement and on replay; historical unbound v1 is test-only. Provider receipt/DEK/upload and C rejection release remain absent. The queue child accepts only a caller-stable request and exact predecessor. None is route/launcher wired. |
