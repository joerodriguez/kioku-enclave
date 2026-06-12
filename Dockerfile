# ── kioku-enclave container ───────────────────────────────────────────────────
#
# Reproducibility notes
# ---------------------
# To build reproducibly:
#   1. Pin the builder image to a digest, not just a tag.
#   2. Set SOURCE_DATE_EPOCH before building:
#        export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
#   3. Build with --locked so Cargo.lock is authoritative.
#   4. Consider vendoring deps (cargo vendor) so the build is fully offline
#      and the source tree is the complete input — a TODO for CI hardening.
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
# assumes it runs on a Linux x86-64 builder (GitHub Actions ubuntu-latest).
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
#                        in the control-plane's ID token (e.g. http://10.x.x.x:8080)
#   ATTEST_STS_AUDIENCE  Full WIF provider resource name for the attestation STS
#                        exchange (format:
#                        //iam.googleapis.com/projects/<NUM>/locations/global/
#                        workloadIdentityPools/<POOL>/providers/<PROVIDER>)
#
# Example build command:
#   docker build \
#     --build-arg KMS_PROJECT=my-project \
#     --build-arg KMS_LOCATION=us-central1 \
#     --build-arg KMS_KEY_RING=my-keyring \
#     --build-arg KMS_KEY=my-kek \
#     --build-arg GCS_BUCKET=my-enclave-indexes \
#     --build-arg RUN_SA_EMAIL=control-plane@my-project.iam.gserviceaccount.com \
#     --build-arg ENCLAVE_AUDIENCE=http://10.0.0.5:8080 \
#     --build-arg ATTEST_STS_AUDIENCE=//iam.googleapis.com/projects/123.../... \
#     -t kioku-enclave:local .

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM rust:1.96.0-slim AS builder

WORKDIR /build

# Install musl toolchain
RUN rustup target add x86_64-unknown-linux-musl \
    && apt-get update -qq \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

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
    && cargo build --release --locked --target x86_64-unknown-linux-musl \
    && rm -rf src

# Build the real binary
COPY src ./src
# Touch main.rs so cargo detects the change
RUN touch src/main.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl

# ── Stage 2: minimal runtime ──────────────────────────────────────────────────
FROM scratch

# No CA certificate file needed: reqwest is built with rustls-tls-webpki-roots
# which compiles the Mozilla root CA bundle directly into the binary.  A
# FROM-scratch image therefore has no filesystem dependency for TLS.

# Confidential Space launch policy: tee-env-* VM metadata may only set env
# vars the image explicitly allow-lists here — the launcher refuses to boot
# otherwise. ONLY PORT and RUST_LOG are operator-overridable. EVERYTHING that
# affects security is baked into the image below, so it is part of the attested
# digest and an operator CANNOT change it at launch:
#   - ENCLAVE_KMS_VIA_ATTESTATION can't be flipped off
#   - RUN_SA_EMAIL (whose ID token is trusted) can't be pointed at an attacker SA
#   - KMS_*/GCS_BUCKET/ATTEST_STS_AUDIENCE/ENCLAVE_AUDIENCE can't be substituted
# Invariant: a malicious operator cannot boot the attested image with weakened
# auth or pointed at different infrastructure. Caller authentication is
# ID-token verification only — there is no shared-secret path in the binary.
LABEL "tee.launch_policy.allow_env_override"="PORT,RUST_LOG"

# Allow container stdout/stderr redirection to Cloud Logging on HARDENED
# Confidential Space images (default is debug-only, and the launcher kills
# the workload if the operator requests redirection the image doesn't allow).
# Operational logs are required to run this in production; the corresponding
# SECURITY.md rule is that log lines must never contain user content —
# tracing here logs user ids and counts only.
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

# Root, deliberately: the Confidential Space launcher mounts the /tmp tmpfs
# root-owned with no mode/uid knobs in the tee-mount spec, and a FROM-scratch
# image has no shell to chown it at startup — a non-root UID gets EACCES on
# every SQLite temp file. The usual argument for non-root barely applies here:
# single static binary, no shell, no package manager, hardened TEE, and the
# data the process touches is the data it owns.

EXPOSE 8080

ENTRYPOINT ["/kioku-enclave"]
