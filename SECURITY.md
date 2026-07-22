# Security

## Scope

`kioku-enclave` is the production Kioku backend, not only a storage data plane. The
same attested Rust process terminates TLS and implements Google OAuth, token issuance,
device sync, MCP and REST queries, account export/deletion, quotas, summarisation, and
encrypted persistence. This threat model therefore includes those control-plane
surfaces.

### In scope

- Confidentiality and integrity of transcripts, OCR text, opted-in screenshot evidence,
  episode data, identity state, and OAuth credentials handled by this service.
- TLS transport to public clients and to Google APIs.
- OAuth, bearer-token, and legacy service-identity authentication and authorization.
- Per-user isolation, export, deletion, quotas, and abuse controls.
- The KMS/DEK hierarchy and encrypted GCS objects.
- Confidential Space attestation, image-digest authorization, and the public release
  evidence used to audit a running image.
- The repository's CI, dependency scanning, image scanning, provenance, and release
  process.

### Out of scope or accepted external trust

- The macOS client, which is a separate binary with its own threat model.
- Payment processing; no billing provider is implemented here.
- CPU-level microarchitectural side channels. Confidential Space provides VM memory
  encryption, not complete Spectre-class protection.
- **Vertex Gemini inference confidentiality.** Summarisation sends selected text from
  this process to Vertex under Google's no-data-retention API terms. The privacy claim is
  “attested enclave + Google no-data-retention terms,” not enclave-only inference.
- **Opt-in Gmail delivery.** When enabled by a user, final-brief MIME content leaves the
  TEE for Gmail under that user's OAuth grant.

## Security invariants

- Production never serves the application over plaintext HTTP. The production image
  requires `ENCLAVE_ACME=1`; boot waits for a usable certificate, and a non-debug build
  without TLS refuses to start. Plain HTTP is available only in a debug binary with
  `ENCLAVE_TEST_MODE=1`.
- The Confidential Space launch policy permits only `PORT` to be changed at launch.
  KMS, GCS, caller identity, OAuth, TLS, attestation, and migration settings are baked
  into the image and therefore covered by its digest.
- KMS encrypt/decrypt uses an attestation token exchanged through the configured WIF
  provider. There is no VM-service-account credential fallback for KMS.
- A token returned by the public `/v1/attestation` endpoint uses the HTTPS verifier URL
  `${BASE_URL}/v1/attestation` as its audience. It never uses
  `ATTEST_STS_AUDIENCE`: a WIF-audience token is an STS bearer credential and must not
  leave the enclave.
- Decrypted databases exist only in the `/tmp` Confidential Space tmpfs and in process
  memory. User content and key material must never be logged.
- Legacy encrypted blobs are rejected unless a reviewed migration image explicitly
  bakes in `ENCLAVE_ALLOW_LEGACY_BLOBS=1`.

## Key hierarchy and encrypted objects

```text
Cloud KMS KEK
│  KMS IAM grants decrypt only to an attestation-gated WIF principalSet:
│    assertion.swname == "CONFIDENTIAL_SPACE"
│    "STABLE" in submods.confidential_space.support_attributes
│    attribute.image_digest == <approved release digest>
│
└─► KMS-wrapped DEK
    │  The wrapped DEK is stored with the corresponding GCS object.
    │  Plaintext DEKs exist only in enclave memory.
    │
    └─► context-bound AES-256-GCM blob (v2)
        [ "KIOKU-BLOB" || 0x02 ][ 12-byte nonce ][ ciphertext || tag ]
```

Version 2 uses AES-GCM Additional Authenticated Data containing a domain separator and
the object's logical identity. User databases are bound to their exact
`indexes/{user_id}.db.enc` name, screenshot evidence is bound to both the authenticated
user and exact media object key, and control/ACME state uses fixed, distinct contexts.
Moving ciphertext and its wrapped DEK to another object or user therefore fails
authentication.

User databases, the control database, ACME state, and screenshot evidence are rewritten
to v2 immediately when successfully opened by an explicitly enabled migration image.
Strict images default to `ENCLAVE_ALLOW_LEGACY_BLOBS=0`. The migration is one-way; see
[`RELEASING.md`](RELEASING.md#one-time-legacy-blob-migration) before upgrading a
deployment that contains pre-v2 objects.

## Attestation and TLS

The KMS credential path and public verification path deliberately use different
Confidential Space tokens:

1. Internally, `ATTEST_STS_AUDIENCE` is the WIF provider resource. Its token is exchanged
   at Google STS for a short-lived KMS access token and is never exposed by an HTTP
   endpoint.
2. Publicly, `/v1/attestation` returns a non-credential OIDC token whose audience is that
   HTTPS verifier endpoint. The request to the launcher includes the lowercase hex
   SHA-256 fingerprint of the active leaf certificate DER as a nonce. Certificate and
   fingerprint renew together; a request that straddles renewal can mismatch and must be
   retried over a fresh connection. A verifier must validate Google's signature, issuer,
   expiry, audience, nonce, relevant Confidential Space claims, and image digest rather
   than merely decoding the JWT.

TLS terminates inside the attested binary, so no external reverse proxy receives request
plaintext. ACME generates the private key inside the TEE and persists account,
certificate, and key state only as a KMS-wrapped, context-bound encrypted blob. Port 80
serves only the ACME HTTP-01 challenge router; the application is served over TLS on the
configured `PORT`.

## Threat actors and mitigations

### T1 — Malicious operator or cloud-project insider

**Threat:** An operator with broad GCP IAM access attempts to decrypt user data or boot
the approved image with weaker settings.

**Mitigation:** The KEK's decrypt grant is limited to the attestation-gated
`principalSet`; no human or service-account principal should hold that role. Changing
code or baked configuration changes the image digest and invalidates the KMS condition.
The launch policy permits only `PORT`, so an operator cannot replace KMS coordinates,
trusted callers, auth policy, TLS policy, or the legacy-blob gate through VM metadata.

**Operator verification:** inspect the KMS IAM policy and confirm that
`roles/cloudkms.cryptoKeyEncrypterDecrypter` has only the expected attestation-gated
principal set—no `user:`, `group:`, or `serviceAccount:` member.

### T2 — Compromised client token or legacy caller

**Threat:** An attacker steals a Kioku bearer token, a Google identity token, or the
identity of the service account trusted by legacy `/v1/*` routes.

**Mitigation:** Public OAuth validates configured Google audiences and the account
allow-list. Authenticated routes derive the user from the Kioku token rather than trusting
a caller-supplied identity. OAuth uses PKCE and persisted, single-use authorization-code
state. Legacy routes accept only Google-signed ID tokens with the baked audience and
service-account email; there is no shared-secret or auth-disable fallback. User IDs are
validated before use in paths or object names.

**Residual risk:** A valid legacy caller identity is highly privileged and can select a
user ID on compatibility routes. Remove legacy integrations when downstream clients no
longer require them, and protect that service account accordingly.

### T3 — Remote exploit in the attested service

**Threat:** A malformed request exploits a bug in the exact approved binary.

**Mitigation:** Authentication middleware, bounded request bodies, input validation,
rate limits, quotas, memory-safe Rust, tests, clippy, CodeQL, dependency review, and
vulnerability scans reduce this risk. Attestation proves which code is running; it does
not prove that code is bug-free. Report suspected vulnerabilities privately as described
below.

### T4 — GCS compromise or object substitution

**Threat:** An attacker reads, replaces, or relocates GCS objects.

**Mitigation:** GCS contains ciphertext and KMS-wrapped DEKs. KMS access is separately
attestation-gated. AES-GCM authenticates contents, GCS generation preconditions reject
lost-update races, and v2 AAD binds each blob to its intended logical object and user.

### T5 — Hypervisor or memory inspection

**Threat:** A co-tenant or hypervisor reads plaintext guest memory or persistent disk.

**Mitigation:** Confidential Space uses AMD SEV memory encryption, and decrypted SQLite
files are created only on the required `/tmp` tmpfs. No plaintext is intentionally
written to persistent disk.

**Residual risk:** CPU-level microarchitectural side channels are not fully mitigated by
AMD SEV.

### T6 — Source, dependency, or build-pipeline tampering

**Threat:** An attacker modifies source, dependencies, Actions, or build inputs so the
published image differs from the reviewed release.

**Mitigation:** Release tags are signed and verified; the release script refuses to
overwrite an existing public release. Third-party Actions and the Rust builder image are
pinned by full digest/SHA. The embedding model is pinned to a repository revision and
verified by SHA-256. CI runs formatting, locked tests, clippy, RustSec audit (with a
documented RSA-verification-only exception for `RUSTSEC-2023-0071`), CodeQL, dependency
review, and an SBOM-based image scan. Cargo-auditable metadata makes statically linked
Rust crates visible in that image SBOM, and CI fails if representative core/native
packages are absent. The credentialed build job accepts only main or `v*` tag refs; the
GCP OIDC provider must additionally constrain immutable repository/owner IDs and the
expected workflow identity. A tagged build publishes GitHub-signed image
provenance, an SPDX SBOM, and a signed SBOM attestation; the release script verifies the
expected repository, workflow, source ref, commit, image repository, digest, and
attestations before publishing or rolling. Verifiers must also authenticate the tag's
signing-key fingerprint against a separately published trusted anchor; signature validity
alone does not establish signer identity.

## Residual risks and limitations

### Source-to-image rebuilds are not yet independently reproducible

The builder image and model are pinned, but Cargo sources are fetched from crates.io
rather than vendored, Debian packages are installed from mutable apt repositories without
snapshot/version pins, and the workflow does not yet demonstrate a bit-for-bit rebuild.
GitHub-signed provenance proves which GitHub workflow claims to have produced an image;
it does not eliminate trust in GitHub Actions or mutable dependency delivery.

Release notes must say “publicly auditable with signed build provenance,” not
“independently reproducible.” Closing this limitation requires vendored Rust sources,
snapshot-pinned OS packages, deterministic build inputs/timestamps, network-disabled
compilation, and independent rebuild comparison.

### Vertex and opt-in Gmail delivery cross the TEE boundary

Episode summarisation and evidence verification send selected text to Google Vertex
Gemini from this process. Google's no-data-retention terms apply, but the data is outside
the Confidential Space boundary while Vertex processes it. When enabled, episode-email
delivery similarly sends final-brief content to Gmail using the connected user's OAuth
grant.

### Stable user identifiers are linkable

User IDs are deterministically derived from the Google subject identifier. Anyone who
already knows that subject can derive the corresponding `indexes/{user_id}.db.enc` name.
This is an accepted availability trade-off, not an encryption bypass.

## Reporting vulnerabilities

Report security vulnerabilities privately:

- Use the repository's [private vulnerability reporting
  form](https://github.com/joerodriguez/kioku-enclave/security/advisories/new).
- Do **not** open a public GitHub issue or include exploit details in public logs.
- The target coordinated-disclosure timeline is 90 days.
