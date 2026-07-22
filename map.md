# map.md — kioku-enclave (root)

> **What `map.md` files are:** one per directory, describing what it's for and how it
> fits the whole, so agents can orient quickly. **Keep them current** when you add/
> remove/rename files or change a directory's role. See [CLAUDE.md](CLAUDE.md).

## What this repo is

The **attested Kioku backend** — the only Kioku-operated server process that handles user
plaintext. This Rust service runs inside a GCP Confidential Space VM (AMD SEV) and is
published so a running image can be audited against signed source and build provenance.
It includes TLS, OAuth, sync, MCP/REST queries, account operations, summarisation, and
encrypted persistence; client applications and deployment automation are downstream
consumers.

## Where it sits

```
OAuth clients and legacy service-identity integrations
        │  authenticated HTTPS
        ▼
   THIS SERVICE (Confidential Space VM, SEV)
        ├── context-bound AES-256-GCM blobs ──► GCS (ciphertext only)
        ├── attestation-derived credentials ─► Cloud KMS
        └── documented plaintext egress ─────► Vertex / opt-in Gmail delivery
```

The control plane is part of this process. Plaintext databases live only in process memory
and SEV-protected tmpfs (`/tmp`), never on persistent disk. Selected summarisation text
and opt-in final-brief email cross the TEE boundary as documented in `SECURITY.md`.

## Layout

| Path | What it is |
|---|---|
| [src/](src/map.md) | The Rust backend: TLS, OAuth/API, crypto, attestation, storage, search, episodes |
| `.github/workflows/` | CI, CodeQL/dependency checks, image build/scan, provenance, and SBOM attestations |
| `Dockerfile` | Digest-pinned builder/model definition for the static `x86_64-unknown-linux-musl` image; remaining rebuild limits are documented in `SECURITY.md` |
| `Cargo.toml` / `Cargo.lock` | Crate manifest |
| `README.md` | What the enclave does + the attestation/privacy claim |
| `SECURITY.md` | **Threat model + residual risks — read before touching crypto/auth/attestation** |
| `CONTRIBUTING.md` | PR rules; the three pre-commit checks |
| `rust-toolchain.toml` | Pinned toolchain |

## Working here

- Pre-commit, all must pass: `cargo test --locked`,
  `cargo clippy --locked --all-targets -- -D warnings`, `cargo fmt --all -- --check`.
- Treat every change as security-sensitive; explain threat-model impact for auth/crypto/
  attestation changes.
- The `/v1/*` API is a public compatibility boundary; keep handler behavior and public
  documentation in sync, and coordinate breaking changes with downstream clients.
- Record the enclave commit SHA + deployed image digest in the operator's deployment
  record.
