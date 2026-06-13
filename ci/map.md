# map.md — ci/

CI pipeline for building and rolling the enclave onto its Confidential Space VM.

- `build-and-roll.yml.template` — template for the build → push image → roll-VM pipeline.
  Builds the reproducible `x86_64-unknown-linux-musl` image, pushes it, and rolls the VM
  (impersonating the push-only `kioku-enclave-ci` service account, not the deployer).

Because the attestation claim depends on a reproducible build, the image digest produced
here is what gets bound in KMS and recorded in the monorepo `PROGRESS.md`.

> Keep this `map.md` current if the CI flow changes.
