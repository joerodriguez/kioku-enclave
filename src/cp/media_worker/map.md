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
| [`wal.rs`](wal/map.md) | **Inactive ADR-0022 media-worker domains:** owns raw-media retention, the deterministic screen-result A subtype plus its private screen Vertex-begin B identity boundary, and (slice 11) the audio-window pair — an audio Vertex-begin B clone under distinct identity domains and a bound-only audio transcript A subtype. Each B child authenticates one exact reserved topology with at least a two-minute live lease window, binds both its exact predecessor and post-usage-stable identity, derives a deterministic event ID, and atomically commits the started billing event, monthly coverage, complete work binding, and bounded receipt. Each production-facing result reauthenticates its exact permanent binding and stable work-attempt identity before caller-ID-fixed inserts (screenshots/observations for screen; pin-derived segment/cluster/observation/utterance rows for audio, silent windows legal) and full-tuple settles jobs, media, and work; historical screen v1 remains test-only. Screen person evidence and every person/identity/voice result remain unsupported — the audio transcript subtype structurally cannot create identity, person, or voice rows. The audio family's sequence gate (T24) now opens on the sealed epoch-0 baseline because `audio_segments`/`utterances` are `AUTOINCREMENT`; it remains as a fail-closed residual defence against a legacy pre-re-baseline archive shape. These paths cannot call Store/providers, read media, allocate clocks/random IDs, launch work, retry, or acknowledge completion. |
