# map.md — ci/

Optional operator template for a combined build-and-roll pipeline.

- `build-and-roll.yml.template` — inert example for operators who own both their image
  registry and deployment Terraform. The canonical Kioku project intentionally keeps
  these privileges split: this public repo's `.github/workflows/build.yml` uses the
  push-only `kioku-enclave-ci` identity, while the deployment repository performs the
  separately requested VM roll.

The canonical release command and public digest record are documented in
[`RELEASING.md`](../RELEASING.md). The build is locked but not yet bit-for-bit
reproducible; do not describe it as reproducible until the `SECURITY.md` gap is closed.

> Keep this `map.md` current if the CI flow changes.
