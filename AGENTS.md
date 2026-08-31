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
  introduced; export documents its current structured-row/media-metadata coverage and byte-export
  blocker honestly; and deletion remains complete.
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
export KIOKU_TEST_POSTGRES_URL='postgresql://...'
./scripts/agent-verify.sh full
```

Full verification requires an explicitly provisioned disposable PostgreSQL 17 database,
sets `KIOKU_REQUIRE_POSTGRES_CONTRACT=1`, and fails closed instead of silently skipping
the real database contracts. It does not assume Docker is installed and does not start a
database container on the operator's behalf. The helper uses locked Cargo
compilation/test invocations, refuses a heavy build
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

### Delivery ownership

For a user request that authorizes implementation changes, the default definition of
done is a merged pull request, not uncommitted code in a worktree. Unless the user
explicitly narrows the request (for example, analysis only, no commit, or stop before
merge), the implementing session owns the complete delivery loop:

1. Use the task's existing authoritative branch/worktree. Otherwise refresh the
   canonical repository with `git fetch origin`, then create a unique guarded
   implementation worktree from current `origin/main`; never mix in, stash, discard, or
   rewrite unrelated dirty changes.
2. Implement the change and run the strongest relevant local verification above.
   Required gates must pass. Record the exact commands, outcomes, and any boundary that
   cannot be exercised locally.
3. Review the complete diff. For non-trivial, cross-boundary, or security-sensitive
   work, obtain a fresh independent review from another agent or human, record the
   findings/resolution in the PR without representing it as a GitHub approval, and
   resolve its findings before merge.
4. Commit only task-owned changes, push the branch, open a PR with a clear summary,
   threat-model/release impact where relevant, and non-secret verification evidence.
5. Stay with the PR through conflicts, review feedback, and gate failures; merge through
   the normal rebase path, confirm the PR is merged, and report its URL and merge SHA.

Implementation authorization includes commit, push, PR creation, and merge; do not pause
to ask again for those routine delivery steps. If credentials, permissions, or a required
human approval make merge impossible, leave a recoverable branch/PR and report the exact
blocker instead of silently stopping at local edits.

Merging is not releasing. Do not perform a release-only version bump, create a tag,
build or publish an image/release, run a schema migration or fleet roll, mutate GCP, or
deploy production unless the user explicitly asks for release or deployment in that
session. After merge, hand the reviewed source refs and verification evidence to the
separately authorized release session. Required source version changes may remain part
of the implementation PR; they do not authorize publication.

Default branch is `main`.

**STRICT PR RULE: NEVER PUSH DIRECTLY TO `main`**. All changes — including features, bug fixes, documentation, and version bumps — MUST be committed on a branch and submitted via Pull Request. Never push directly to `main`.

- **Zero-click reviewed PR workflow**: To land changes cleanly without manual UI clicking, agents create and merge PRs with the CLI:
  ```bash
  git checkout -b feat/feature-name
  git commit -m "feat(scope): detailed description"
  git push -u origin HEAD
  gh pr create --fill --base main
  gh pr merge --rebase
  ```
  Do not merge until the required local verification passes and the independent review
  requirement above is satisfied.
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
   - Roll only through the monorepo's explicit staged Terraform deployment flow. For a
     schema/API-compatible release, ADR-0041 separately preauthorizes exactly the reviewed
     predecessor/candidate pair, rolls the regional MIG with zero unavailable members,
     retires the predecessor, and restores steady one-digest authority. Incompatible
     releases retain the scale-to-zero maintenance lane. Do not substitute an in-place
     metadata edit or ad hoc instance reset.
   - Verify every MIG member reports `kioku-enclave starting version X.Y.Z`, PostgreSQL
     schema readiness, and the shared static TLS generation before reopening admission.

3. **Timezone & Query Type-Affinity Rules**:
   - PostgreSQL stores database timestamps as `timestamptz`; normalize API values to UTC
     RFC 3339 (`2026-07-26T23:51:39.450Z`) at the boundary.
   - Keep wall-clock query behavior explicit about the caller's IANA timezone and daylight-saving
     transition. Test exact UTC bounds plus representative US offsets (+4h EDT, +5h EST/CDT,
     +7h PDT) so assistant wall-clock queries match stored instants.
   - Do not replace typed timestamp comparisons with text casts or process-local timezone state.

## Security reminders specific to this repo

- Structured plaintext is intentionally queryable only in private Cloud SQL and application
  memory; large media remains encrypted in GCS. Never write plaintext to VM persistent disk
  or logs, and never add a second structured-state authority or fallback.
- Don't weaken the ID-token / attestation path or log decrypted content.
- Report vulnerabilities privately (see CONTRIBUTING.md / SECURITY.md) — never in a
  public issue.
