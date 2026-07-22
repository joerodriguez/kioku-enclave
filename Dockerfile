# ── kioku-enclave container ───────────────────────────────────────────────────
#
# Reproducibility notes
# ---------------------
# To make builds more repeatable and auditable (not yet bit-for-bit reproducible):
#   1. The builder image and model revision are pinned below.
#   2. Pass the source commit timestamp to BuildKit:
#        --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
#   3. Build with --locked so Cargo.lock is authoritative.
#   4. Consider vendoring deps (cargo vendor) so the build is fully offline
#      and the source tree is the complete input — a remaining hardening item.
#   5. Record the image digest after push and publish it in the release notes;
#      this is the value verifiers check against the attestation token.
#
# Cross-compilation note
# ----------------------
# The musl static target (x86_64-unknown-linux-musl) is the correct target for
# a FROM-scratch image and for GCP Confidential Space (which runs Linux/x86-64).
# On macOS arm64 you need a cross-linker; the CI pipeline (Linux x86-64 runner)
# compiles natively with:
#   rustup target add x86_64-unknown-linux-musl
#   cargo build --release --locked --target x86_64-unknown-linux-musl
# The local `cargo build` (darwin) is for development only; the Dockerfile
# assumes it runs on a Linux x86-64 builder (GitHub Actions Ubuntu 24.04).
#
# Operator build instructions
# ---------------------------
# Each operator MUST supply their own deployment values at build time.
# Security-relevant config is baked into the image so it is covered by the
# attested image digest — an operator cannot change it at launch time.
#
# Required build args (no safe defaults — build will fail if unset):
#   KMS_PROJECT          GCP project that owns the KMS key ring
#   KMS_LOCATION         Location of the key ring (e.g. us-central1)
#   KMS_KEY_RING         KMS key ring name
#   KMS_KEY              KMS crypto key name
#   GCS_BUCKET           GCS bucket holding encrypted index blobs
#   RUN_SA_EMAIL         Service account email the control plane presents in its
#                        Google ID token (format: name@project.iam.gserviceaccount.com)
#   ENCLAVE_AUDIENCE     The enclave's own URL, used to validate the 'aud' claim
#                        in the control-plane's ID token (an HTTPS origin)
#   ATTEST_STS_AUDIENCE  Full WIF provider resource name for the attestation STS
#                        exchange (format:
#                        //iam.googleapis.com/projects/<NUM>/locations/global/
#                        workloadIdentityPools/<POOL>/providers/<PROVIDER>)
#   GOOGLE_DESKTOP_CLIENT_ID / GOOGLE_WEB_CLIENT_ID  Google OAuth audiences
#   ALLOWED_EMAILS       Comma-separated account allow-list
#   BASE_URL / WEB_ORIGIN  Public API issuer and browser application origin
#   VERTEX_PROJECT / VERTEX_LOCATION / VERTEX_MODEL  Summarizer configuration
#   ENCLAVE_ACME         Set to 1 for production in-enclave TLS
#   ENCLAVE_ACME_DIRECTORY / ENCLAVE_ACME_CONTACT  ACME endpoint and contact
#
# Example build command:
#   docker build \
#     --build-arg SOURCE_DATE_EPOCH=<source-commit-unix-timestamp> \
#     --build-arg KMS_PROJECT=my-project \
#     --build-arg KMS_LOCATION=us-central1 \
#     --build-arg KMS_KEY_RING=my-keyring \
#     --build-arg KMS_KEY=my-kek \
#     --build-arg GCS_BUCKET=my-enclave-indexes \
#     --build-arg RUN_SA_EMAIL=control-plane@my-project.iam.gserviceaccount.com \
#     --build-arg ENCLAVE_AUDIENCE=https://api.example.com \
#     --build-arg ATTEST_STS_AUDIENCE=//iam.googleapis.com/projects/123.../... \
#     --build-arg GOOGLE_DESKTOP_CLIENT_ID=...apps.googleusercontent.com \
#     --build-arg GOOGLE_WEB_CLIENT_ID=...apps.googleusercontent.com \
#     --build-arg ALLOWED_EMAILS=owner@example.com \
#     --build-arg BASE_URL=https://api.example.com \
#     --build-arg WEB_ORIGIN=https://app.example.com \
#     --build-arg VERTEX_PROJECT=my-project \
#     --build-arg VERTEX_LOCATION=us-central1 \
#     --build-arg VERTEX_MODEL=gemini-2.5-flash \
#     --build-arg ENCLAVE_ACME=1 \
#     --build-arg ENCLAVE_ACME_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory \
#     --build-arg ENCLAVE_ACME_CONTACT=mailto:operator@example.com \
#     -t kioku-enclave:local .

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM rust:1.96.0-slim@sha256:c37af730be4fd8104cbf9aedbd6ab259e51ca2d5437817a0f8680edf66ac6c28 AS builder

ARG SOURCE_DATE_EPOCH
WORKDIR /build

# Declare and validate production configuration in a runnable stage. A bare
# ARG/ENV assignment accepts empty strings, so validation must be explicit.
ARG KMS_PROJECT
ARG KMS_LOCATION
ARG KMS_KEY_RING
ARG KMS_KEY
ARG GCS_BUCKET
ARG RUN_SA_EMAIL
ARG ENCLAVE_AUDIENCE
ARG ATTEST_STS_AUDIENCE
ARG GOOGLE_DESKTOP_CLIENT_ID
ARG GOOGLE_WEB_CLIENT_ID
ARG ALLOWED_EMAILS
ARG BASE_URL
ARG WEB_ORIGIN
ARG VERTEX_PROJECT
ARG VERTEX_LOCATION
ARG VERTEX_MODEL
ARG ENCLAVE_ACME
ARG ENCLAVE_ACME_DIRECTORY
ARG ENCLAVE_ACME_CONTACT
ARG ENCLAVE_ALLOW_LEGACY_BLOBS=0
RUN set -eu \
    && case "${SOURCE_DATE_EPOCH}" in ''|*[!0-9]*) false;; *) true;; esac \
    && for value in \
        "${KMS_PROJECT}" "${KMS_LOCATION}" "${KMS_KEY_RING}" "${KMS_KEY}" \
        "${GCS_BUCKET}" "${RUN_SA_EMAIL}" "${ENCLAVE_AUDIENCE}" \
        "${ATTEST_STS_AUDIENCE}" "${GOOGLE_DESKTOP_CLIENT_ID}" \
        "${GOOGLE_WEB_CLIENT_ID}" "${ALLOWED_EMAILS}" "${BASE_URL}" "${WEB_ORIGIN}" \
        "${VERTEX_PROJECT}" "${VERTEX_LOCATION}" "${VERTEX_MODEL}" \
        "${ENCLAVE_ACME_DIRECTORY}" "${ENCLAVE_ACME_CONTACT}"; \
       do [ -n "${value}" ]; done \
    && [ "${ENCLAVE_ACME}" = "1" ] \
    && [ "${ALLOWED_EMAILS}" != "*" ] \
    && [ "${ENCLAVE_ALLOW_LEGACY_BLOBS}" = "0" -o "${ENCLAVE_ALLOW_LEGACY_BLOBS}" = "1" ] \
    && case "${ENCLAVE_AUDIENCE}" in https://*) true;; *) false;; esac \
    && case "${BASE_URL}" in https://*) true;; *) false;; esac \
    && case "${WEB_ORIGIN}" in https://*) true;; *) false;; esac \
    && case "${ATTEST_STS_AUDIENCE}" in //iam.googleapis.com/*/workloadIdentityPools/*/providers/*) true;; *) false;; esac

# Install musl toolchain (+ curl for the embedding-model download below)
RUN rustup target add x86_64-unknown-linux-musl \
    && apt-get update -qq \
    && apt-get install -y --no-install-recommends musl-tools curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Embed the exact Cargo dependency graph in the stripped production binary so
# image scanners can recover statically linked Rust crates. Version and the
# tool's own lockfile are pinned; this is build tooling, not runtime content.
RUN cargo install cargo-auditable --version 0.7.4 --locked

# ── Embedding model (hybrid search) ────────────────────────────────────────────
#
# paraphrase-multilingual-MiniLM-L12-v2 — the pinned query/document embedding
# model (see src/embedding.rs MODEL_ID; the Mac client MUST ship the same
# files). Downloaded here with pinned SHA-256 hashes so the model content is
# a deterministic build input: the weights are baked into the image and are
# therefore covered by the attested digest, same as the binary. ~470 MB.
#
# Bumping the model = new hashes here + MODEL_ID bump in src/embedding.rs on
# BOTH sides (enclave + its companion client) + a vec-table migration.
# The repository identifies this model as Apache-2.0; the pinned model card is
# included in the image as attribution and is hash-verified with the artifacts.
ARG MODEL_REVISION=e8f8c211226b894fcb81acc59f3b34ba3efd5f42
RUN mkdir -p /models \
    && curl -fsSL -o /models/config.json \
       "https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/${MODEL_REVISION}/config.json" \
    && curl -fsSL -o /models/tokenizer.json \
       "https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/${MODEL_REVISION}/tokenizer.json" \
    && curl -fsSL -o /models/model.safetensors \
       "https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/${MODEL_REVISION}/model.safetensors" \
    && curl -fsSL -o /models/MODEL_CARD.md \
       "https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/raw/${MODEL_REVISION}/README.md" \
    && echo "6300193cb75e01cf80c96decef7187dfb33094d97cc1490b7ead6ff134476e4e  /models/config.json" | sha256sum -c - \
    && echo "2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8  /models/tokenizer.json" | sha256sum -c - \
    && echo "eaa086f0ffee582aeb45b36e34cdd1fe2d6de2bef61f8a559a1bbc9bd955917b  /models/model.safetensors" | sha256sum -c - \
    && echo "1e98ea05b0de579fcaad3d625b62ea55647142ed674d5f5ebf1440e4bbbb6f23  /models/MODEL_CARD.md" | sha256sum -c -

# musl does not define the BSD-style u_int*_t aliases that sqlite-vec.c's
# bundled C uses (typedef u_int8_t uint8_t; ...). glibc/macOS provide them, musl
# does not — so on musl those typedefs fail and uint8_t silently degrades to
# `int`, cascading into every vec0 pointer-type error. Map the BSD names onto
# the standard C99 types for the C compilation; `typedef uint8_t uint8_t;` is
# a legal redundant typedef in C11. Only sqlite-vec.c references these names;
# rusqlite's bundled sqlite3.c uses the standard types and is unaffected.
ENV CFLAGS="-Du_int8_t=uint8_t -Du_int16_t=uint16_t -Du_int32_t=uint32_t -Du_int64_t=uint64_t"
ENV CFLAGS_x86_64_unknown_linux_musl="-Du_int8_t=uint8_t -Du_int16_t=uint16_t -Du_int32_t=uint32_t -Du_int64_t=uint64_t"

# Cache dependency compilation separately from source
COPY Cargo.toml Cargo.lock ./
# Create a dummy main so cargo can compile deps
RUN mkdir src && echo 'fn main(){}' > src/main.rs \
    && cargo auditable build --release --locked --target x86_64-unknown-linux-musl \
    && rm -rf src

# Build the real binary
COPY src ./src
# Touch main.rs so cargo detects the change
RUN touch src/main.rs \
    && cargo auditable build --release --locked --target x86_64-unknown-linux-musl

# ── Stage 2: minimal runtime ──────────────────────────────────────────────────
FROM scratch

# No CA certificate file needed: reqwest is built with rustls-tls-webpki-roots
# which compiles the Mozilla root CA bundle directly into the binary.  A
# FROM-scratch image therefore has no filesystem dependency for TLS.

# Confidential Space launch policy: tee-env-* VM metadata may only set env
# vars the image explicitly allow-lists here — the launcher refuses to boot
# otherwise. ONLY PORT is operator-overridable. EVERYTHING that
# affects security is baked into the image below, so it is part of the attested
# digest and an operator CANNOT change it at launch:
#   - ENCLAVE_KMS_VIA_ATTESTATION can't be flipped off
#   - RUN_SA_EMAIL (whose ID token is trusted) can't be pointed at an attacker SA
#   - KMS_*/GCS_BUCKET/ATTEST_STS_AUDIENCE/ENCLAVE_AUDIENCE can't be substituted
# Invariant: a malicious operator cannot boot the attested image with weakened
# auth or pointed at different infrastructure. Caller authentication is
# ID-token verification only — there is no shared-secret path in the binary.
LABEL "tee.launch_policy.allow_env_override"="PORT"

# Allow container stdout/stderr redirection to Cloud Logging on HARDENED
# Confidential Space images (default is debug-only, and the launcher kills
# the workload if the operator requests redirection the image doesn't allow).
# Operational logs are required to run this in production; the corresponding
# SECURITY.md rule is that log lines must never contain user content —
# tracing here logs operational identifiers, counts, and statuses—not content.
LABEL "tee.launch_policy.log_redirect"="always"

# Allow the operator to mount a tmpfs at /tmp (tee-mount VM metadata).
# This is REQUIRED twice over: (1) FROM scratch has no /tmp at all, so SQLite
# temp-file creation fails without it; (2) decrypted per-user SQLite databases
# are materialized under /tmp while in use — they must live in tmpfs (encrypted
# VM memory under SEV), never on the VM disk, where a snapshot could expose
# plaintext and void the confidentiality claim.
LABEL "tee.launch_policy.allow_mount_destinations"="/tmp"

# ── Deployment-specific build args ─────────────────────────────────────────────
#
# These values are BAKED INTO THE IMAGE at docker build time (not overridable at
# launch). Changing any value changes the image digest, which changes what the
# KMS attestation condition accepts — exactly the audit trail we want.
#
# Each operator sets these for their own GCP project and infrastructure.
# See the build instructions at the top of this file.
ARG KMS_PROJECT
ARG KMS_LOCATION
ARG KMS_KEY_RING
ARG KMS_KEY
ARG GCS_BUCKET
ARG RUN_SA_EMAIL
ARG ENCLAVE_AUDIENCE
ARG ATTEST_STS_AUDIENCE

# ── Baked configuration (part of the attested digest) ─────────────────────────
#
# All security-relevant config lives here, not in operator-controlled tee-env,
# so it is fixed by the image digest the attestation binds to. Changing any of
# these values means a new image + new digest + a new KMS binding — exactly the
# audit trail we want.
ENV KMS_PROJECT=${KMS_PROJECT} \
    KMS_LOCATION=${KMS_LOCATION} \
    KMS_KEY_RING=${KMS_KEY_RING} \
    KMS_KEY=${KMS_KEY} \
    GCS_BUCKET=${GCS_BUCKET} \
    RUN_SA_EMAIL=${RUN_SA_EMAIL} \
    ENCLAVE_AUDIENCE=${ENCLAVE_AUDIENCE} \
    ATTEST_STS_AUDIENCE=${ATTEST_STS_AUDIENCE}

# ── Control-plane config (ADR-0001) — baked into the attested digest ──────────
#
# The enclave is now the whole backend (OAuth/sync/MCP/summarizer + TLS). These
# are security-relevant (trusted OAuth audiences and the public base URL that
# is the access-token issuer) so they are baked, not
# operator-overridable — same rationale as the KMS config above.
# Secret values are not build args: the web client secret is fetched from Secret
# Manager and JWT secrets live in the KMS-protected control store.
#
# TLS (ADR-0003): the certificate is NOT baked. ENCLAVE_ACME=1 makes the enclave
# obtain + renew it from Let's Encrypt itself (HTTP-01 on :80), generating the
# private key inside the TEE and persisting it only KMS-encrypted in GCS. This
# keeps the TLS key out of the container env — Confidential Space publishes the
# env in the attestation token (serial console / Cloud Logging), which is how
# the old baked ENCLAVE_TLS_*_PEM_B64 args leaked the key to operator-visible
# logs. Those env vars remain honored at runtime only as a bootstrap fallback
# and for local testing; do not reintroduce them as build args.
ARG GOOGLE_DESKTOP_CLIENT_ID
ARG GOOGLE_WEB_CLIENT_ID
ARG ALLOWED_EMAILS
ARG BASE_URL
ARG WEB_ORIGIN
ARG VERTEX_PROJECT
ARG VERTEX_LOCATION
ARG VERTEX_MODEL
ARG ENCLAVE_ACME
ARG ENCLAVE_ACME_DIRECTORY
ARG ENCLAVE_ACME_CONTACT
ARG ENCLAVE_ALLOW_LEGACY_BLOBS=0
ENV GOOGLE_DESKTOP_CLIENT_ID=${GOOGLE_DESKTOP_CLIENT_ID} \
    GOOGLE_WEB_CLIENT_ID=${GOOGLE_WEB_CLIENT_ID} \
    ALLOWED_EMAILS=${ALLOWED_EMAILS} \
    BASE_URL=${BASE_URL} \
    WEB_ORIGIN=${WEB_ORIGIN} \
    VERTEX_PROJECT=${VERTEX_PROJECT} \
    VERTEX_LOCATION=${VERTEX_LOCATION} \
    VERTEX_MODEL=${VERTEX_MODEL} \
    ENCLAVE_ACME=${ENCLAVE_ACME} \
    ENCLAVE_ACME_DIRECTORY=${ENCLAVE_ACME_DIRECTORY} \
    ENCLAVE_ACME_CONTACT=${ENCLAVE_ACME_CONTACT} \
    ENCLAVE_ALLOW_LEGACY_BLOBS=${ENCLAVE_ALLOW_LEGACY_BLOBS}

# ── Security flags — hardcoded, not operator-supplied ─────────────────────────
#
# These are NOT deployment-specific; they are the hardened-by-default security
# posture of this image. Every operator deployment gets these baked in.
# ENCLAVE_KMS_VIA_ATTESTATION=1 — obtain KMS credentials via the attestation
#                               STS exchange, not the VM metadata SA token.
# (ID-token caller authentication needs no flag: it is unconditional in the
# binary and cannot be disabled.)
ENV ENCLAVE_KMS_VIA_ATTESTATION=1

# Copy the static binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/kioku-enclave /kioku-enclave

# Embedding model for in-enclave query embedding (hybrid search). Baked into
# the image → covered by the attested digest. EMBED_MODEL_DIR is read at boot;
# if the model fails to load the enclave serves FTS-only (never fatal).
COPY --from=builder /models /models
ENV EMBED_MODEL_DIR=/models

# Root, deliberately: the Confidential Space launcher mounts the /tmp tmpfs
# root-owned with no mode/uid knobs in the tee-mount spec, and a FROM-scratch
# image has no shell to chown it at startup — a non-root UID gets EACCES on
# every SQLite temp file. The usual argument for non-root barely applies here:
# single static binary, no shell, no package manager, hardened TEE, and the
# data the process touches is the data it owns.

# Confidential Space publishes ONLY the EXPOSEd container ports to the host
# (observed: the launcher logs "Exposed Ports: map[...]" and forwards just those).
# The enclave now terminates TLS on 443 (ADR-0001), so 443 MUST be exposed or the
# port is unreachable from the VM's external interface. 80 is the ACME HTTP-01
# challenge listener (ADR-0003) — without it Let's Encrypt cannot validate and
# issuance/renewal fails. 8080 is also exposed because it remains the default
# application `PORT`; production traffic on that port is still TLS.
EXPOSE 443
EXPOSE 80
EXPOSE 8080

ENTRYPOINT ["/kioku-enclave"]
