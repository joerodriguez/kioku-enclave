# ADR-0022 amendment: solo-operator activation policy

Status: accepted by the repository owner/operator on 2026-08-18 ("go with the
simplified plan"; sole user; downtime acceptable; internal refactor). This amendment
rescopes the *operational ceremony* of
[`0022-production-activation-runbook.md`](0022-production-activation-runbook.md) for
the current deployment reality: **one operator who is also the only user and the
reviewer**. It does not weaken any data-safety property, cryptographic boundary, or
fail-closed default in the code, and it changes nothing about how future users sign
up (per-archive data keys remain automatic and enclave-internal).

## What is retained unchanged (the data-safety core)

- Backup of all legacy snapshot objects before any migration step.
- The full shadow import with independent parity comparison (SQLite integrity,
  FTS/vector integrity, table counts, logical export, full logical contents) before
  any authority change.
- The durable one-shot controller with restart-safe staged Control rows, exact
  lost-response reconciliation, and fail-closed aborts.
- The Firestore witness anti-rollback chain and its exact-readback CAS discipline.
- The three-root `VerifiedAdvisoryCanaryAuthorization` verifier, the empty Phase-1
  mutation set, and every sealed constructor — the *code* is unchanged.
- Acknowledgement semantics: no acknowledgement changes until the reviewed
  authority-transition slice; after cutover, acknowledgement requires immutable WAL
  plus witness settlement, never a local SQLite commit alone.
- Legacy snapshots retained frozen for a 30-day rollback window after cutover.
- The 4-GiB tmpfs size policy (the sole archive measures ≈0.6 GiB).

## What is rescoped, and why it is safe here

| Runbook requirement | Solo-operator form | Why safe |
|---|---|---|
| Three pairwise-distinct roots with independent custodians | Three distinct Ed25519 keypairs minted and held by the one operator, in three separate local key files outside the repository; only public roots are pinned in this open-source tree | The multi-custodian split defends users against a rogue or compromised operator. Here the operator is the only user; the split would have one person check themselves three times. Distinct keys are kept so the verifier code, formats, and future re-split remain unchanged. |
| Live deployment-observer service with signed zero-serving observations | The operator stops serving themselves and signs window observations locally with the deployment-observer key via the reviewed signer tool | "Zero serving replicas" is trivially true and directly observed by the person who stopped the service; downtime is accepted. |
| Multi-week advisory observation before any authority change | One offline rehearsal on a copy of the archive, then advisory import + full parity + cutover inside a single approved downtime window | The observation window builds confidence without downtime for live users. With downtime accepted and one user, full parity comparison is a stronger, direct check. |
| Canary subject consent apparatus, cohorts, Phase-5 scale, per-cohort rollback | The canary is the operator's own archive; cohorts collapse to one; scale-out deferred until there is a fleet | No other user exists to protect or schedule. |
| Signed exact-image drill receipts | The full locked test suite (fault-injection families) plus the offline rehearsal receipt, recorded in the deployment record | Drill semantics are already executably specified by the test suite; the rehearsal exercises the real flow end to end. |
| Formal monitoring commitment with named on-call rotation | Monitoring/rollback policy bytes are still produced and bound (canonical formats), naming the operator; alerting is the operator's own observation plus the client sync check | The commitment binding stays real; the staffing apparatus has one candidate. |

## Custody record

- `operator` root: private key at the operator's local
  `~/.local/state/kioku/adr0022-roots/operator.key` (mode 0600).
- `image-attestation` root: `~/.local/state/kioku/adr0022-roots/image.key`.
- `deployment-observer` root: `~/.local/state/kioku/adr0022-roots/deploy.key`.
- None of these files, nor any private material, may ever enter this repository or
  any bucket. Rotation = mint replacement keys, land a reviewed root-pinning PR,
  re-sign. Revocation = land a reviewed PR zeroing the pinned root (restores the
  fail-closed state).

## Revised activation procedure

1. Land the reviewed prerequisites: pinned public roots, observation-signer tool,
   policy-byte values naming the operator, provisioning of the witness database and
   least-privilege WIF/bucket resources per
   [`0022-phase1-resource-provisioning-plan.md`](0022-phase1-resource-provisioning-plan.md)
   (executed with its non-mutating emitter's approved transcript).
2. Land the reviewed activation wiring: checked-in runtime coordinates, the
   controller entry path, and the Phase-2 acquisition/acknowledgement transition —
   each through the normal PR + local-verification gate.
3. Rehearse offline against a copy of the archive; record the receipt.
4. Downtime window: stop serving → backup check → one-shot controller run (import →
   parity → settle) → reviewed cutover to WAL-authoritative → restart → client sync
   verification.
5. Rollback at any failure: legacy remains untouched and authoritative; restart on
   the prior image; the frozen snapshots are the recovery path for 30 days.
6. New-user default flip to archive-v3-native genesis is a separate later PR;
   signup UX is unchanged in all cases.

## Explicitly unchanged no-go signals

Acknowledge-before-witness-settlement, ambiguous-retry-under-new-identity,
absence-inferred rejection, enumeration/deletion through the WAL runtime,
older-root selection after acknowledgement, second owner/runtime, and
image/config-binding bypass all remain permanent stop conditions.
