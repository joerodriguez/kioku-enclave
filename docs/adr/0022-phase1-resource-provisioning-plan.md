# ADR-0022 Phase-1 resource provisioning plan

> **SUPERSEDED (2026-08-20) — historical record, not executable as written.** The
> genesis-first replan deleted the Phase-1 advisory canary this plan provisions for:
> `#288` (`61ae996`) and `#289` (`9b2f87e`) removed the advisory-owner family, the Phase-2
> admission, and the eight phase1/phase2 signer/provision scripts. **The companion emitter
> named below, `scripts/phase1_provision_archive_resources.py`, and its contract test are
> among the deleted files**, so the numbered `gcloud` transcript, the `--emit-shell` C4
> gate, and the `--plan-digest` signed-approval artifact can no longer be produced from
> this repository, and the `REQUIRED_DECISION_*` approval ceremony no longer has a tool
> that enforces it.
>
> The *resource shapes* below are not obsolete in the same way: the archive-GCS,
> archive-witness Firestore, and registry-KMS boundaries they describe survive in
> `src/archive_v3_gcs_auth.rs`, `src/archive_v3_firestore_auth.rs`,
> `src/archive_v3_firestore_witness.rs`, and `src/archive_v3_registry_kms.rs`, and a
> genesis-first archive still needs a bucket, a named non-`(default)` witness database, a
> pinned KMS version, and image-digest-pinned WIF providers. Read this document as an
> input to a future provisioning plan, not as one — any successor must re-derive the
> least-privilege grants against the surviving code and must not assume the Phase-1
> canary, its window/zero-serving observation, or its three-root approval exist.

Status: **PROPOSED — awaiting operator C4 approval. This document grants no permission and
claims no decision.** It exists to close one hard stop recorded in
[`0022-production-activation-runbook.md`](0022-production-activation-runbook.md): "this checkout
contains no reviewed archive GCS/registry-KMS/authoritative-witness provisioning, adoption,
backup, or restore plan." It proposes the exact resources, names, commands, and least-privilege
IAM for the Phase-1 advisory canary, and it stops there. Every operator-owned value appears as an
explicit `REQUIRED_DECISION_*` placeholder; the companion tool refuses to fill any of them.

The plan covers only the runbook's "Controller and resources" and "Runtime coordinates" evidence
rows. It does not authorize or perform image publication, deployment rolls, runtime-profile
activation, monitoring deployment, canary execution, Store policy change, or any Phase-2+ work.

## Operator decisions (all REQUIRED, none made here)

The provisioning tool (`scripts/phase1_provision_archive_resources.py`) requires each value as an
explicit CLI flag and exits nonzero naming every missing `REQUIRED_DECISION_*`, so the open
C-decisions stay machine-checkable. Proposed values are proposals, nothing more.

| Placeholder | Meaning | Proposed value (for approval, not assumed) |
|---|---|---|
| `REQUIRED_DECISION_ARCHIVE_PROJECT` | Project ID owning the archive bucket, archive WIF pool, and the existing production KEK | `kioku-joerodriguez` |
| `REQUIRED_DECISION_ARCHIVE_PROJECT_NUMBER` | Numeric project number the code derives the archive GCS STS audience from | operator supplies |
| `REQUIRED_DECISION_WITNESS_PROJECT` | Project ID owning the witness database, witness WIF pool, and backups bucket | see tradeoff below |
| `REQUIRED_DECISION_WITNESS_PROJECT_NUMBER` | Numeric project number the code derives the witness STS audience from | operator supplies |
| `REQUIRED_DECISION_WITNESS_DATABASE` | Named Firestore witness database; `(default)` is refused everywhere | `archive-v3-witness` |
| `REQUIRED_DECISION_ARCHIVE_BUCKET` | Archive object bucket | `kioku-archive-v3-prod` |
| `REQUIRED_DECISION_BACKUPS_BUCKET` | Separate witness-export backups bucket | `kioku-archive-v3-backups` |
| `REQUIRED_DECISION_IMAGE_DIGEST` | Approved release image digest every `principalSet` member is pinned to | from the signed release subject |
| `REQUIRED_DECISION_KMS_LOCATION` / `_KEY_RING` / `_KEY` | Coordinates of the existing production KEK (no new key) | deploy history: `us-central1` / existing ring / `kioku-kek` |
| `REQUIRED_DECISION_REGISTRY_KMS_VERSION` | Exact numeric enabled version beneath the existing key that the registry adapter pins | operator selects from `versions list` |

**Witness project tradeoff (operator decision).** Same project (`kioku-joerodriguez`): one
billing/IAM surface, simplest audit, and the conditional database-scoped binding below still
isolates the grant; blast radius is shared with the rest of the project, and a future project-level
administrator can reach witness IAM the same way they can reach everything else there. Dedicated
witness project: control-plane blast-radius separation and an independent IAM audit boundary for
the acknowledgement-critical ledger, at the cost of a second project to number, monitor, and pay
for. **Recommendation (labeled as such, not a decision): start in `kioku-joerodriguez` for
operational simplicity; move to a dedicated project before Phase 2 authority if the operator wants
blast-radius separation.** The plan's commands work unchanged for either choice.

## Identity: two dedicated WIF pools, digest-pinned members

The code pins both audiences; provisioning must match them byte for byte:

- `src/archive_v3_gcs_auth.rs` accepts only
  `//iam.googleapis.com/projects/REQUIRED_DECISION_ARCHIVE_PROJECT_NUMBER/locations/global/workloadIdentityPools/archive-gcs-attest/providers/archive-gcs`
  and exchanges a no-nonce Confidential Space token at Google STS for the fixed
  `devstorage.read_write` scope.
- `src/archive_v3_firestore_witness.rs` / `src/archive_v3_firestore_auth.rs` accept only
  `//iam.googleapis.com/projects/REQUIRED_DECISION_WITNESS_PROJECT_NUMBER/locations/global/workloadIdentityPools/archive-witness-attest/providers/archive-witness`
  with the fixed `cloud-platform` STS scope.

Pool and provider IDs (`archive-gcs-attest/archive-gcs`, `archive-witness-attest/archive-witness`)
are literal constants in the source, not placeholders; only the project numbers are operator
decisions. The plan creates both pools and OIDC providers against the Confidential Space issuer
with `attribute.image_digest = assertion.submods.container.image_digest` and the same attribute
condition the existing KEK binding documents (`assertion.swname == "CONFIDENTIAL_SPACE"` and
`"STABLE"` support attribute; README "Confidential Space and KMS"). Each provider's
`--allowed-audiences` is set to the exact code-pinned audience string. A read-only describe step
verifies the provider resource names equal the audiences the enclave derives; the operator should
also diff the attribute mapping/condition against the existing production KEK provider before
approval.

Every enclave-facing IAM member in this plan is
`principalSet://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/attribute.image_digest/REQUIRED_DECISION_IMAGE_DIGEST`
— mirroring the existing kioku-kek binding pattern, so only the attested approved image can use
the grants. Scopes do not grant authority; the custom roles below are the entire authority.

## Archive object bucket

Proposed `gs://kioku-archive-v3-prod` (`REQUIRED_DECISION_ARCHIVE_BUCKET`), `us-central1`,
uniform bucket-level access on, public access prevention **enforced**, object versioning **on**
(immutable-object accidental-overwrite forensics; the runtime's create-if-absent already uses
`ifGenerationMatch=0` generation preconditions, `src/archive_v3_gcs.rs`), default soft-delete
policy retained unchanged.

Deliberately absent, matching the runbook's permanent no-go list and execution step 3:

- **No lifecycle deletion rules.** Deletion authority is Phase-6 work with its own reviewed plan
  and identity; an unattended lifecycle rule would be an unreviewed deleter.
- **No retention lock.** A locked retention policy is irreversible and would permanently block the
  reviewed Phase-6 deletion path; revisit at Phase 6 with its own review. (Reversible protections —
  versioning, soft delete, enforced PAP — are used instead.)

Access is one custom role, `kiokuArchiveV3ObjectWriter`, granting **only**
`storage.objects.create` and `storage.objects.get` — explicitly no list, no delete, no update, no
predefined role — bound at bucket level to the digest-pinned `principalSet` from
`archive-gcs-attest`. This matches the reviewed publisher boundary ("retains only exact-name
immutable create/get authority", `0022-activation-readiness.md`) and keeps "enumerate or delete
archive objects through the WAL runtime" impossible at the IAM layer as well as in code.

## Registry KMS: pin an existing version, create nothing, grant nothing

`src/archive_v3_registry_kms.rs` accepts one exact numeric `cryptoKeyVersions/N` **beneath the
already-selected legacy production key** and revalidates it as `ENABLED`
`GOOGLE_SYMMETRIC_ENCRYPTION` at `SOFTWARE` protection on every wrap/unwrap, binding the version
coordinate into the AAD. Accordingly this plan:

- creates **no** key, key ring, or key version, and adds **no** KMS IAM. The per-digest KEK
  binding continues to flow only through the existing reviewed deploy path
  (`gcloud kms keys add-iam-policy-binding` for each approved digest, per the deployment runbook);
- emits read-only verification only: `versions describe` must report the decided
  `REQUIRED_DECISION_REGISTRY_KMS_VERSION` as `ENABLED GOOGLE_SYMMETRIC_ENCRYPTION SOFTWARE`, and
  `get-iam-policy` must show only digest-gated `principalSet` decrypt members and no standing
  human decrypt;
- flags one coverage check for review: the adapter's per-operation revalidation performs a
  metadata `GET` on the version, which requires `cloudkms.cryptoKeyVersions.get`. If the role used
  by the existing digest-binding flow does not include it, that is a separately reviewed
  deploy-flow amendment — not a new standing grant added here.

## Authoritative witness database

Proposed named Firestore database `archive-v3-witness` (`REQUIRED_DECISION_WITNESS_DATABASE`) in
`REQUIRED_DECISION_WITNESS_PROJECT`, `us-central1`, Firestore native mode, delete protection on
(reversible), PITR on. The witness is **never** `(default)`: the adapter addresses only an
explicitly named database, and both the provisioning tool and its tests refuse `(default)`
everywhere. Documents live only at `archive_witness_v3/{archive_id_lowerhex}` with the single
bytes field `r` — opaque commitment bytes, content-free.

Access is one custom role, `kiokuArchiveV3WitnessWriter`, granting **only** the real Firestore
IAM permissions the transaction boundary needs — `datastore.databases.get` (transaction
begin/rollback) plus `datastore.entities.create`, `datastore.entities.get`,
`datastore.entities.update` — no delete, no query enumeration, no index or rule authority. The
binding is **conditional**, scoped to the one database resource:

```text
resource.name == "projects/<witness project>/databases/archive-v3-witness"
  || resource.name.startsWith("projects/<witness project>/databases/archive-v3-witness/")
```

so the grant cannot reach `(default)`, any sibling database, or a prefix-colliding name. The
member is the digest-pinned `principalSet` from `archive-witness-attest`. The operator should
verify the condition's evaluation against current Firestore IAM-condition documentation during
review; a condition that fails closed is acceptable, one that fails open is not.

## Backup and restore

- **PITR** on the witness database is the primary point-in-time basis.
- **Scheduled export** goes to the separate proposed `gs://kioku-archive-v3-backups`
  (`REQUIRED_DECISION_BACKUPS_BUCKET`; enforced PAP, uniform access) — never to the archive
  bucket. The only non-`principalSet` member in this plan is the Google-managed Firestore service
  agent (`service-<witness number>@gcp-sa-firestore.iam.gserviceaccount.com`), bound on the
  backups bucket alone with the custom export-only role `kiokuArchiveV3BackupExportWriter`
  (`storage.buckets.get`, `storage.objects.create`, `storage.objects.get`). If the first
  supervised export drill proves the managed exporter needs one more permission, that exact
  permission arrives by reviewed amendment naming the drill error — never a broad role.
- **GCS object versioning** on the archive bucket is the object-level protection for archive
  contents themselves.
- **Restore drills** are exercised and receipted through the activation tracker's B4 drill
  harness (the runbook's "Phase-1 drills" row); an export that has never been restore-drilled is
  not restore evidence. Recurrence cadence is operator policy recorded with the C4 approval; this
  plan deliberately creates no standing scheduler identity.
- **Backup infrastructure has no read access to plaintext.** Everything at rest is
  enclave-encrypted ciphertext (archive objects, wrapped DEKs) or content-free witness
  commitments; exports and PITR reproduce ciphertext and commitments only, and no backup-side
  role in this plan carries any decrypt permission.

## Adoption

Adoption of the provisioned resources maps to the `src/archive_v3_genesis.rs` flow and nothing
else: production construction accepts only a durable lifecycle reservation; every registry, root,
and witness request obtains a fresh create admission through the encrypted-control ledger; and the
witness genesis document is created **only through the sealed commit-start-aware Firestore
creator**, with ambiguity held on the same ID/bytes/admission until exact readback reconciles it.
**No manual witness document write is ever performed** — not to seed, not to repair, not to test.
A pre-ledger existing document fails closed and is an incident, not a starting point.

## Provisioning tool

`scripts/phase1_provision_archive_resources.py` is strictly non-mutating and has **no apply mode
at all**. Default output is the numbered exact-command plan (plain `gcloud`, no Terraform), each
step carrying its runbook justification and read-only/mutating label. `--emit-shell PATH`
additionally writes a reviewable transcript with `set -euo pipefail`, every command commented with
its justification, and a fail-closed guard: the transcript refuses to execute unless
`KIOKU_PHASE1_PLAN_APPROVAL_DIGEST` holds the C4-approved plan digest. Every `REQUIRED_DECISION_*`
is a mandatory flag; missing or placeholder-literal values exit nonzero naming each missing
decision. `scripts/test_phase1_provision_archive_resources.py` pins the emitted-command
invariants: digest-pinned `principalSet` members only (plus the one listed backup service agent),
no banned role/permission substrings, named non-default witness database, enforced bucket flags,
audiences equal to the source constants, and digest stability.

## Approval artifact (C4)

The C4 decision this plan awaits is a signed operator approval that binds, at minimum:

1. every `REQUIRED_DECISION_*` value, written out exactly;
2. the plan digest from
   `python3 scripts/phase1_provision_archive_resources.py --plan-digest <all decision flags>` —
   the SHA-256 of the canonicalized emitted plan, which changes if any decision or command
   changes;
3. the approving operator's named account (the plan's first verification step records it), the
   approval window/expiry, and the explicit statement that execution authority covers exactly the
   mutating steps of this plan for Phase 1 and nothing else.

The GO packet for the runbook's "Controller and resources" and "Cloud authority" rows carries that
signed artifact; the emitted shell transcript executes only when the operator supplies the same
approved digest in the environment. Substituted decisions, a stale digest, or an expired window
make the approval void and the state `NO-GO`.

**This plan grants no permission.** It performs no cloud mutation, names no authority, and
approves nothing — including its own proposals. Until a C4 approval artifact signs this plan's
exact digest and decision values, every resource above remains unprovisioned, the runbook's
hard stop remains open, and any attempt to treat this document (or its tool's output) as
authorization is itself a `NO-GO` signal.
