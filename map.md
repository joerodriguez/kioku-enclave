# map.md — kioku-enclave (root)

> **What `map.md` files are:** one per directory, describing what it's for and how it
> fits the whole, so agents can orient quickly. **Keep them current** when you add/
> remove/rename files or change a directory's role. See [CLAUDE.md](CLAUDE.md).

## What this repo is

The **Kioku data plane** — the only process that ever holds user plaintext. A Rust
service that runs inside a GCP Confidential Space VM (AMD SEV) and is published open
source so the running instance can be **attested** against this exact code. The
control plane and macOS app live in the separate **`kioku-monorepo`** repo.

## Where it sits

```
kioku-monorepo control plane (Cloud Run)
        │  ID-token-attested HTTPS calls to /v1/*
        ▼
   THIS SERVICE (Confidential Space VM, SEV)
        │  AES-256-GCM encrypted per-user SQLite blobs
        ▼
   GCS  (ciphertext only; keys gated by Cloud KMS attestation)
```

The control plane never receives user keys or plaintext. Plaintext lives **only** in
this process and in SEV-encrypted tmpfs (`/tmp`) — never on persistent disk.

## Layout

| Path | What it is |
|---|---|
| [src/](src/map.md) | The Rust service: HTTP API, crypto, attestation, storage, search, episodes |
| [ci/](ci/map.md) | CI build-and-roll pipeline template |
| `Dockerfile` | Reproducible `x86_64-unknown-linux-musl` image for the VM (attestation depends on reproducibility) |
| `Cargo.toml` / `Cargo.lock` | Crate manifest |
| `README.md` | What the enclave does + the attestation/privacy claim |
| `SECURITY.md` | **Threat model + known gaps — read before touching crypto/auth/attestation** |
| `CONTRIBUTING.md` | PR rules; the three pre-commit checks |
| `rust-toolchain.toml` | Pinned toolchain |

## Working here

- Pre-commit, all must pass: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt`.
- Treat every change as security-sensitive; explain threat-model impact for auth/crypto/
  attestation changes.
- The `/v1/*` API contract mirrors `kioku-monorepo`'s `docs/CONTRACTS.md` /
  `cloud/src/enclave.js` — keep them in sync.
- Progress is logged in the **monorepo's** `PROGRESS.md` (this repo has none); record the
  enclave commit SHA + deployed image digest there.
