# `cp/summarizer/`

Private inactive ADR-0022 logical-operation children. They do not obtain Store,
Vertex, task, launcher, route, or acknowledgement authority.

| File | Responsibility |
|---|---|
| `wal.rs` | Closed ADR-0009 substance-backfill batch codec and distinct bounded permanent replay ledger. It authenticates the exact ordered next episode-input prefix, applies classifications and advances a private cursor atomically, and writes the historical completion marker only for an exact empty tail. A pre-existing exact marker may be adopted. |
| `wal/visual_evidence.rs` | Closed ADR-0010 visual-evidence-backfill batch codec and separate bounded permanent replay ledger. It reconstructs and binds each eligible episode's exact bounded text-only evidence from deterministically ordered nonduplicate member screens, full-tuple updates only the exact next cursor prefix, and completes only at an exact empty tail. Sixteen maximum inputs fit the shared one-MiB request cap. It cannot load pixels, reserve or invoke inference, call Store, launch work, or acknowledge completion. |
