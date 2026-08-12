# map.md — `legacy_gcm/extent_candidate/`

Private inactive bridge from a pinned/authenticated historical SQLite blob to
non-authoritative archive-v3 extent candidates. `coordinator.rs` is a child of
the sealed legacy-GCM source so it can consume provisional bytes and the
one-shot completion without exposing either capability. It injects an async
read-only witness, exact range reader, resolved archive cipher, immutable
backend, and ledger connection; it authenticates the exact witness-nominated
base root before a caller-retained durable attempt is prepared. It can persist
only after a no-write, zeroizing-buffer SQLite preflight reaches exact EOF,
finishes source authentication, and rejects schema rollback. Restart family
discovery and reconciliation use only bounded fully validated ledger rows and
require exclusive future caller ownership; they accept no current witness or
source. The coordinator can persist only `CandidateReady`, never witness CAS/publication, storage listing,
deletion, GC, Store/VFS, route, flag, provider, or runtime authority.
