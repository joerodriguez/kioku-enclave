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

## Security reminders specific to this repo

- Plaintext lives only in this process and SEV-encrypted tmpfs (`/tmp`); never write it
  to persistent disk.
- Don't weaken the ID-token / attestation path or log decrypted content.
- Report vulnerabilities privately (see CONTRIBUTING.md / SECURITY.md) — never in a
  public issue.
