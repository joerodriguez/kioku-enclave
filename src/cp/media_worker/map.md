# map.md — `src/cp/media_worker/`

Private children of the raw-media worker. Nothing in this directory is a
launcher, route, provider adapter, task, or production Store-policy selector.

The WAL family also owns the claim boundary's fail-closed refusal path: legacy
rows that violate settle bounds, deterministic planner heads that fit no
window, duplicate-event topology, and malformed/future/topology-mismatched stored work units are
named before payment. The quarantine child preflights complete exact row/unit
evidence before writing, advances only attributable jobs onto the bounded
retry/terminal/resurrection ladder, and updates shared media once per event.
Global clock/account/code failures remain non-charging. Repaired evidence
invalidates a stale quarantine plan.

| File | Role |
|---|---|
| [`wal.rs`](wal/map.md) | **ADR-0022 media-worker domains:** owns raw-media retention; the screen and audio attempt/result families; and the active selected voice-embedding plus provider-free voice-profile/person boundary. Selected transcript v3 atomically creates one fixed-id pending job per turn and only an unbound proposal whose high-confidence name and fact evidence are exact substrings of that same turn; a sealed backfill repairs eligible observations permanently settled by v1 without jobs. The embedding owner exact-reads bounded source/current-generation topology, durably claims before GCS/KMS/model work, and exact-settles a caller-ID-fixed pending sample or typed provider-free result. The profile owner repairs historical revisions/assignments, makes bounded deterministic sample assignments, reconciles or quarantines representatives, refuses imported lineage actions, and settles episode speaker readiness. Once an observation has one exact accepted active profile, the same provider-free family full-row commits its transcript/source/sample/profile/identity/person closure and four additional allocator pins before atomically accepting the person, name, bounded facts, active profile binding, observation and cluster. Repeated literal evidence supersedes exactly one active binding; conflict and corruption reject without partial public state. Clock rollback defers without mutation. The sealed plans cannot call Store/providers, read media, allocate clocks/random IDs, launch work, retry, or acknowledge completion. |
