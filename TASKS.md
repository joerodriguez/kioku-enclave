# ADR-0029 ready-notification delivery

- [x] Persist authenticated, per-installation APNs registrations with account-switch and token-generation fencing.
- [x] Commit first-finalization push deliveries atomically with the final memory result; regeneration does not replay them.
- [x] Send privacy-safe per-device handoff handles through separate production and sandbox APNs transports.
- [x] Resolve notification handoffs only for the authenticated owner and canonical browser memory route.
- [x] Treat APNs delivery as non-blocking to finalization while failing production startup/release closed on missing provider configuration.
- [x] Verify the complete Rust suite, lint, formatting, release-selection, and release-preflight contracts.
- [ ] Publish signed production release v0.8.14. The signed v0.8.13 image is
  non-deployable: its attested manifest omitted the selected production profile,
  and the release wrapper correctly rejected it before rollout.

# ADR-0022 task evidence

## Capacity fixture and local gate

- [x] Versioned deterministic, numeric-only 12-month fixtures for 40, 80, and 100
  recording hours per month, with exact derived distributions.
- [x] Declared and validated the 32-GiB SQLite ceiling and a sparse near-ceiling extent
  profile without committing generated data.
- [x] Added a separate, opt-in production-shaped local gate with profile-derived disk
  preflight, bounded streaming batches, exact per-kind distribution checks, SQLite
  DB/WAL/checkpoint observations over materialized content-free payload/vector-shape BLOBs,
  and content-free reports.
- [x] Kept Phase-0a smoke tests fast and permanently non-evidence; the long gate is not
  executed in CI contract tests.
- [x] Defined an inactive, offline, restricted-JCS preauthorization schema and policy
  template, exact workload-by-result/environment/metric/formula verifier, explicit untrusted-wrapper activation
  blockers, and adversarial test contract. The checked-in template has intentionally invalid
  anchors; no current input authenticates time/challenge/provenance or consumes a replay nonce.
- [ ] Populate a separately controlled release policy with real trust anchors, collect
  signed production evidence, and exercise archive-v3 VFS, backend, witness, fault,
  lifecycle, cache, and concurrency paths before any authority transition.

The checked items do not authorize archive-v3 persistence or deployment. See
[`eval/capacity/README.md`](eval/capacity/README.md) for the reproducible operator command
and the local gate's explicit limitations.
