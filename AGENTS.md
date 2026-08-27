# Working in this repo (agent guide)

`kioku-enclave` is the **entire Kioku application backend**. It terminates TLS and serves OAuth, sync, the MCP server,
account export/delete, quotas, and the episode summarizer (`src/cp/`), alongside the
data-plane query/storage code. It runs inside a GCP Confidential Space VM (AMD SEV) and is
open source so the running instance can be attested against this exact code. Private
Cloud SQL PostgreSQL is the structured-state plaintext boundary; large GCS media remains
application-encrypted per user. Treat every change as security-sensitive by default.

## `map.md` files — read them first, keep them current

Every meaningful directory has a **`map.md`** describing what it's for and how it fits
the whole service. Start at the root [map.md](map.md) for the architecture, then read a
directory's `map.md` before working in it.

**Standing rule:** when you add/remove/rename files or change what a module is
responsible for, update that directory's `map.md` in the **same change**; new directories
get a `map.md` linked from their parent. Treat a stale `map.md` like stale docs.

## Start here

- [map.md](map.md) — architecture + directory tour (read this first).
- `README.md` — what the enclave does, the attestation/privacy claim, build instructions.
- `SECURITY.md` — full threat model and known gaps. Read before changing anything in
  auth, crypto, attestation, or key handling.
- `CONTRIBUTING.md` — contribution + PR rules (summarized below).
- **Product + security ground truth: `README.md` and `SECURITY.md` in this repo.** Preserve
  the security invariants they document: bounded raw media follows the authenticated
  Cloud Capture path by default; large persistent media objects are encrypted per user;
  structured plaintext is limited to the attested application, private Cloud SQL, and
  the documented Vertex boundary; media-key access is bound to the attested digest; no undocumented plaintext sink is
  introduced; and export/delete remain complete.
  A change that weakens an invariant is wrong by default.
- Client applications, capture pipelines, and deployment automation are downstream
  consumers of the public interfaces documented in this repository. Coordinate breaking
  compatibility changes without relying on an unpublished repository layout.

## Verification

The local verification pipeline is the exhaustive, authoritative merge gate.
GitHub Actions is disabled for this repository. Before requesting merge, run the
reviewed local verification stage and attach its non-secret evidence summary to
the PR; a remote status check is no longer expected.

For normal local work, start with the quick verification and run a focused test
for the code you changed:

```bash
./scripts/agent-verify.sh quick
./scripts/agent-verify.sh focused -- module::tests::affected_case
```

Run the local full suite when a change is broad, security-sensitive, touches
shared behavior, or CI diagnosis needs local reproduction:

```bash
./scripts/agent-verify.sh full
```

The helper uses locked Cargo compilation/test invocations, refuses a heavy build
when the worktree's disk has less than its 15-GiB default free-space floor, holds
a crash-safe per-worktree artifact lock for the entire Cargo sequence, and uses
a 10-GiB-bounded `sccache` only when it is already installed. A separate
`cargo build` is not required: `cargo check`, tests, and Clippy compile the
code they need. See `./scripts/agent-verify.sh --help` for modes and options.
Use this helper for agent-run Cargo validation rather than launching raw Cargo:
its crash-safe lock prevents a completed worktree's generated artifacts from
being retired during compilation.

The Docker image targets `x86_64-unknown-linux-musl` for the Confidential Space VM
(see `Dockerfile` / `README.md`). Keep build inputs pinned and provenance auditable.
Do not claim bit-for-bit reproducibility until the remaining crates.io, apt-snapshot,
and independent-rebuild gaps documented in `README.md` are closed.

## Logging progress

This repo has no `PROGRESS.md`. When an enclave change is deployed, record the commit SHA
**and** resulting image digest in the operator's deployment record so source, image, and
rollout remain traceable.

## Commits & PRs

Match git history: short scoped subjects like `feat(episodes): …`, `ci: …`, `Docs: …`.
Per CONTRIBUTING.md: include a clear description of what changed and why, and for
security-sensitive changes (auth, crypto, attestation) explain the **threat-model
impact**. Run the appropriate local verification above before opening a PR; the
local signed evidence is the exhaustive merge/release gate.

Only commit/push when the user asks. Default branch is `main`.

**STRICT PR RULE: NEVER PUSH DIRECTLY TO `main`**. All changes — including features, bug fixes, documentation, and version bumps — MUST be committed on a branch and submitted via Pull Request. Never push directly to `main`.

- **Zero-Click PR & Auto-Merge Queue Workflow**: To land changes cleanly without manual UI clicking, agents create PRs and enable CLI auto-merge:
  ```bash
  git checkout -b feat/feature-name
  git commit -m "feat(scope): detailed description"
  git push -u origin HEAD
  gh pr create --fill --base main
  gh pr merge --rebase
  ```
  Do not merge until a reviewer has checked the local verification evidence.
  Continue to avoid `--admin`; disabling hosted checks does not authorize bypassing
  branch, review, or signed-commit protections.

## Release & GCP Deployment Checklist

When releasing a new version or deploying changes to production, follow these steps to guarantee code completeness and live VM state agreement:

1. **Version Bump & Staging Completeness**:
   - Always run `git status` before running `./scripts/bump_version.sh <version>`.
   - `./scripts/bump_version.sh` executes `git add -A` to ensure all source code changes, migrations, tests, and documentation are committed together with `Cargo.toml` and `Cargo.lock`. Never commit version files in isolation while source modifications remain unstaged.

2. **GCP Confidential Space Fleet Roll**:
   - A tag does not trigger a hosted build. Run `scripts/local_image_pipeline.py`
     on the reviewed Linux/amd64 builder, then sign and verify its evidence locally.
   - Roll only through the monorepo's explicit staged Terraform deployment flow. It
     drains and scales the old fleet to zero, proves no old instances remain, changes the
     one KMS-authorized digest and instance-template version, then restores at least two
     homogeneous members behind the passthrough load balancer. Do not substitute an
     in-place metadata edit or ad hoc instance reset.
   - Verify every MIG member reports `kioku-enclave starting version X.Y.Z`, PostgreSQL
     schema readiness, and the shared static TLS generation before reopening admission.

3. **Timezone & Query Type-Affinity Rules**:
   - Database timestamps are stored in UTC ISO 8601 strings (`2026-07-26T23:51:39.450Z`).
   - SQLite `strftime('%s', ...)` returns a `TEXT` string. Comparing `strftime` outputs to numeric integer offsets (e.g. `+ 14400`) causes SQLite type-affinity failures where `TEXT > INTEGER` evaluates to `FALSE`.
   - Always wrap `strftime('%s', ...)` expressions in `CAST(strftime('%s', ...) AS INTEGER)`.
   - Ensure timestamp queries evaluate exact UTC bounds **and** US local timezone offsets (+4h EDT, +5h EST/CDT, +7h PDT) so wall-clock time queries from assistant callers match UTC database records.

## Security reminders specific to this repo

- Structured plaintext is intentionally queryable in private Cloud SQL; application
  memory and legacy/reference SQLite use SEV memory/tmpfs, and large media remains
  encrypted in GCS. Never write plaintext to VM persistent disk or logs.
- Don't weaken the ID-token / attestation path or log decrypted content.
- Report vulnerabilities privately (see CONTRIBUTING.md / SECURITY.md) — never in a
  public issue.
