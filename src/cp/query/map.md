# map.md — `src/cp/query/`

Private inactive ADR-0022 logical-operation children. They do not define routes
or obtain Store, provider, task, acknowledgement, or launcher authority.

| File | Role |
|---|---|
| [`wal.rs`](wal/map.md) | Closed selected-screenshot receipt codec and private finalization-queue child, each with a distinct bounded permanent exact-replay ledger. A future B boundary must durably choose the opaque screenshot upload attempt before provider I/O. The queue child accepts only a caller-stable request and exact predecessor; neither is route/launcher wired. |
