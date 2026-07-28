# Working in this repo (agent guide)

`kioku-enclave` is the **entire Kioku backend** — the only process that
ever holds user plaintext. It terminates TLS and serves OAuth, sync, the MCP server,
account export/delete, quotas, and the episode summarizer (`src/cp/`), alongside the
data-plane query/storage code. It runs inside a GCP Confidential Space VM (AMD SEV) and is
open source so the running instance can be attested against this exact code. Treat every
change as security-sensitive by default.

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
  the security invariants they document: raw media stays local by default; plaintext only
  enters this attested process; data is encrypted per user; key access is bound to the
  attested digest; no new plaintext sink is introduced; and export/delete remain complete.
  A change that weakens an invariant is wrong by default.
- Client applications, capture pipelines, and deployment automation are downstream
  consumers of the public interfaces documented in this repository. Coordinate breaking
  compatibility changes without relying on an unpublished repository layout.

## Before you commit — all four must pass

```bash
cargo build --locked                              # native build for local testing
cargo test --locked                               # no network; in-memory fakes for KMS/GCS
cargo clippy --locked --all-targets -- -D warnings # warnings are errors
cargo fmt --all -- --check                        # must be clean
```

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
impact**. Run the four checks above first.

Only commit/push when the user asks. Default branch is `main`.

**STRICT PR RULE: NEVER PUSH DIRECTLY TO `main`**. All changes — including features, bug fixes, documentation, and version bumps — MUST be committed on a branch and submitted via Pull Request. Never push directly to `main`.

- **Zero-Click PR & Auto-Merge Queue Workflow**: To land changes cleanly without manual UI clicking, agents create PRs and enable auto-merge rebase via CLI:
  ```bash
  git checkout -b feat/feature-name
  git commit -m "feat(scope): detailed description"
  git push -u origin HEAD
  gh pr create --fill --base main
  gh pr merge --auto --rebase
  ```
  This automatically queues the PR for merge once CI passes, rebasing it onto `main` as a single clean commit with the full PR description.

## Release & GCP Deployment Checklist

When releasing a new version or deploying changes to production, follow these steps to guarantee code completeness and live VM state agreement:

1. **Version Bump & Staging Completeness**:
   - Always run `git status` before running `./scripts/bump_version.sh <version>`.
   - `./scripts/bump_version.sh` executes `git add -A` to ensure all source code changes, migrations, tests, and documentation are committed together with `Cargo.toml` and `Cargo.lock`. Never commit version files in isolation while source modifications remain unstaged.

2. **GCP Confidential Space Live VM Roll**:
   - Pushing a release tag `vX.Y.Z` triggers the enclave image build on GitHub Actions.
   - The monorepo deployment watcher (`deploy.yml` in `joerodriguez/kioku`) updates `infra/terraform.tfvars` with the new pinned digest.
   - **CRITICAL**: GCP Confidential Space TEE VMs do **not** automatically reload container images in-place. After Terraform updates the instance metadata, force the VM to boot the new image digest by running:
     ```bash
     gcloud compute instances reset kioku-enclave --project=kioku-joerodriguez --zone=us-central1-b
     ```
   - Verify boot and version startup by inspecting serial console logs:
     ```bash
     gcloud compute instances get-serial-port-output kioku-enclave --project=kioku-joerodriguez --zone=us-central1-b | tail -n 30
     ```
     Confirm `kioku-enclave starting version X.Y.Z` and ACME TLS certificate initialization.

3. **Timezone & Query Type-Affinity Rules**:
   - Database timestamps are stored in UTC ISO 8601 strings (`2026-07-26T23:51:39.450Z`).
   - SQLite `strftime('%s', ...)` returns a `TEXT` string. Comparing `strftime` outputs to numeric integer offsets (e.g. `+ 14400`) causes SQLite type-affinity failures where `TEXT > INTEGER` evaluates to `FALSE`.
   - Always wrap `strftime('%s', ...)` expressions in `CAST(strftime('%s', ...) AS INTEGER)`.
   - Ensure timestamp queries evaluate exact UTC bounds **and** US local timezone offsets (+4h EDT, +5h EST/CDT, +7h PDT) so wall-clock time queries from assistant callers match UTC database records.

## Security reminders specific to this repo

- Plaintext lives only in this process and SEV-encrypted tmpfs (`/tmp`); never write it
  to persistent disk.
- Don't weaken the ID-token / attestation path or log decrypted content.
- Report vulnerabilities privately (see CONTRIBUTING.md / SECURITY.md) — never in a
  public issue.
