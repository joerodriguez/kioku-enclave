# Working in this repo (agent guide)

`kioku-enclave` is the **entire Kioku backend** (as of ADR-0001) — the only process that
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
- **Product + security ground truth: `docs/PRODUCT-SPEC.md` in the sibling
  `kioku-monorepo` repo.** It states what Kioku is for and the **security invariants** that
  govern this repo above all (raw media never leaves the Mac; plaintext only in this
  attested process; per-user encryption; key access bound to the attested digest; no new
  plaintext sink; export/delete always complete). Resolve decisions in its favor; a change
  that weakens an invariant is wrong by default.
- The Mac app, capture pipeline, and infra live in the **separate `kioku-monorepo` repo**;
  interface contracts are in its `docs/CONTRACTS.md` and `docs/CLOUD.md`.

## Before you commit — all three must pass

```bash
cargo build                       # native build for local testing
cargo test                        # no network; in-memory fakes for KMS/GCS
cargo clippy -- -D warnings       # warnings are errors
cargo fmt                         # must be clean
```

The Docker image targets `x86_64-unknown-linux-musl` for the Confidential Space VM
(see `Dockerfile` / `README.md`). The build must stay **reproducible** — the attestation
story depends on a release-tagged build of this source producing the published digest.

## Logging progress

This repo has no `PROGRESS.md`. Enclave work is logged in the **monorepo's**
`PROGRESS.md` as an `**Enclave (kioku-enclave <sha>, digest sha256:…)**` bullet inside
the relevant dated entry. When you ship an enclave change that gets deployed, record the
commit SHA **and** the resulting image digest there so cross-repo work stays traceable.

## Commits & PRs

Match git history: short scoped subjects like `feat(episodes): …`, `ci: …`, `Docs: …`.
Per CONTRIBUTING.md: include a clear description of what changed and why, and for
security-sensitive changes (auth, crypto, attestation) explain the **threat-model
impact**. Run the three checks above first.

Only commit/push when the user asks. Default branch is `main`.

## Security reminders specific to this repo

- Plaintext lives only in this process and SEV-encrypted tmpfs (`/tmp`); never write it
  to persistent disk.
- Don't weaken the ID-token / attestation path or log decrypted content.
- Report vulnerabilities privately (see CONTRIBUTING.md / SECURITY.md) — never in a
  public issue.
