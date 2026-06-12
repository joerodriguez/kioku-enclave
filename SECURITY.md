# Security

## Scope

This document covers the threat model for `kioku-enclave` — the production
data plane and the only process that holds Kioku user plaintext. It is a
living document; the "Known gaps" section records what is not yet fully
implemented, so an auditor has an honest picture of the current state.

---

## What is in scope

- Confidentiality of user transcripts, OCR text, and episode summaries at rest
  (AES-256-GCM blobs in GCS) and in transit (TLS to GCS/KMS from the enclave;
  VPC-private path from the control plane)
- Integrity of the DEK hierarchy (KEK in KMS, per-user DEK wrapped at rest)
- Isolation between users (per-user DEKs; separate encrypted SQLite blobs)
- Attestation: the claim that KMS releases keys only to this exact code

## What is out of scope

- OAuth token security (control plane)
- Billing and quota bypass (control plane)
- The macOS client (separate binary, separate threat model)
- Side-channel attacks on AMD SEV from a co-tenant hypervisor (Confidential
  Space provides VM-level memory encryption, not CPU-level side-channel
  hardening)
- **Vertex Gemini inference confidentiality:** episode summarisation sends text
  **outside the enclave** to Vertex Gemini under Google's no-retention API
  terms. The privacy claim is explicitly _"attested enclave + Google
  no-retention terms"_, not enclave-only processing. This is a documented
  design choice, not a gap.

---

## Key hierarchy

```
Cloud KMS (KEK, 90-day rotation)
│  Attestation path: WIF pool attribute_condition requires
│    assertion.swname == 'CONFIDENTIAL_SPACE' AND
│    'STABLE' in submods.confidential_space.support_attributes AND
│    attribute.image_digest == <published release digest>
│
│  No service-account or human key path exists. The KMS key's only
│  IAM principal is the attestation-gated principalSet. A project
│  owner cannot decrypt without modifying the image (which changes
│  the digest and voids the attestation condition).
│
└─► per-user DEK (32 random bytes, AES-256 key)
    │  Wrapped by KMS; ciphertext stored in GCS object metadata.
    │  Plaintext DEK lives only in enclave memory (/tmp tmpfs) during
    │  a request.
    │
    └─► AES-256-GCM encrypted SQLite blob (per user)
        │  Format: [ nonce: 12 B ][ ciphertext ‖ tag ]
        │  Stored at GCS: indexes/{user_id}.db.enc
        │  Decrypted to /tmp tmpfs; re-encrypted on save.
        │  /tmp is a tee-mount tmpfs — SEV-encrypted VM memory,
        │  never written to the persistent disk.
```

---

## Threat actors and mitigations

### T1 — Malicious operator / insider

**Threat:** Operator with GCP IAM owner role attempts to read user data.

**Mitigation:** KMS decrypt IAM grants exist **only** for the attestation-gated
`principalSet`. There is no service-account and no human principal with KMS
decrypt permission. An operator cannot obtain a KMS token that satisfies the
attestation condition without running an image that carries this exact code and
produces this exact digest — and if they modify the code, the digest changes
and the condition fails.

**Verification:** `gcloud kms keys get-iam-policy` should list no
`serviceAccount:`, `user:`, or `group:` member with
`roles/cloudkms.cryptoKeyEncrypterDecrypter`. Only a `principalSet://…` entry
for the WIF pool should be present.

### T2 — Compromised control plane

**Threat:** Attacker gains code execution in the Cloud Run control plane and
issues malicious requests to the enclave.

**Mitigation:** The control plane never receives DEKs or decryption key
material. A compromised control plane can inject false data via `/v1/ingest` or
read search results via `/v1/search`, but cannot access raw encrypted blobs or
the KMS key directly.

**Authentication:** The enclave verifies every request carries a Google-signed
ID token proving the caller is the designated control-plane service account.
This is the only authentication path — there is no shared-secret fallback and
no flag to disable it. The expected service account email and the token
audience are baked into the image at build time — an operator cannot point the
enclave at a different caller by changing launch metadata.

**Input validation:** The `user_id` the control plane supplies is restricted to
`[A-Za-z0-9_-]{1,128}` at every endpoint (and re-checked in the store) before
it is used to derive the decrypted database's temp-file path or the GCS object
name, so a compromised control plane cannot use path metacharacters to steer
plaintext to an attacker-chosen location.

### T3 — GCS compromise

**Threat:** Attacker reads GCS bucket contents.

**Mitigation:** All blobs are AES-256-GCM encrypted with per-user DEKs. GCS
access without KMS access yields only ciphertext. The wrapped DEK stored in GCS
object metadata is itself KMS-encrypted; decrypting it requires KMS access,
which is attestation-gated.

### T4 — Side-channel / memory inspection in TEE

**Threat:** Co-tenant or hypervisor reads enclave memory.

**Mitigation:** GCP Confidential Space uses AMD SEV to encrypt VM memory at the
hardware level. The hypervisor cannot read plaintext guest memory.

**Residual risk:** CPU-level microarchitectural side-channels (Spectre-class)
are not fully mitigated by AMD SEV. Enclave code does not process secret
material in timing-sensitive loops; bearer-token authentication is RS256
signature verification, not a secret comparison.

### T5 — Supply chain / build tampering

**Threat:** Attacker modifies source or build pipeline to exfiltrate keys.

**Mitigation:** Any change to the image changes its digest, which voids the KMS
attestation condition. This source is published and tagged per release so the
build is independently reproducible.

**Partial:** `cargo vendor` in CI is not yet implemented — the build fetches
from crates.io at build time. A supply-chain attacker who compromises a
dependency before the build runs could modify the binary. Cosign/SLSA
provenance is also not yet published. See Known gaps below.

---

## Known gaps

These are documented interim states with a clear remediation path. The threat
model is honest about them.

### Gap 1 — Control-plane to enclave transport is plain HTTP

The VPC path between the control plane (Cloud Run) and the enclave uses plain
HTTP at the application layer over Google's (host-level encrypted) VPC fabric.
The enclave validates the caller's ID token on every request, but the channel
itself is not mutually authenticated at the TLS layer.

**Impact:** A network-adjacent attacker on the VPC (e.g. a future misconfigured
VPC peering) could observe plaintext in flight. The firewall currently restricts
enclave port 8080 to the VPC connector subnet only. Note that the enclave's
HTTP listener binds `0.0.0.0` and performs no network-level access control of
its own — the network boundary is this VPC firewall plus the per-request
ID-token verification, not the listener.

**Resolution:** Attested mTLS between the control plane and the enclave, with
the enclave's certificate bound to its attested workload identity. This is
planned future work.

### Gap 2 — Reproducible builds and provenance not yet hardened

The build does not yet vendor dependencies (`cargo vendor`), the builder image
is pinned by tag not digest, and no cosign/SLSA provenance attestation is
published. A verifier must trust the CI system (GitHub Actions) as well as the
published image digest.

**Resolution:** `cargo vendor` in CI, digest-pinned builder image, and
published cosign/SLSA provenance so the digest-to-source link is independently
verifiable.

### Gap 3 — Vertex summarisation leaks plaintext outside the TEE

Episode summarisation sends user plaintext to Google Vertex Gemini via the
control plane. This is out of scope by design (see "What is out of scope"
above) but is repeated here for completeness because it is the most
significant limitation of the "sealed hardware" claim for users.

---

## Reporting

To report a security vulnerability:

- **Email:** joerodriguez@gmail.com
- Do not open a public GitHub issue for vulnerabilities.
- We target a 90-day disclosure timeline for coordinated disclosure.
