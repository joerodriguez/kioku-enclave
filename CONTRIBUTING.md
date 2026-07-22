# Contributing

## Security vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Use the repository's [private vulnerability reporting
form](https://github.com/joerodriguez/kioku-enclave/security/advisories/new) with
a description of the issue and steps to reproduce. We target a 90-day
coordinated disclosure timeline.

See SECURITY.md for the full threat model and known gaps.

## Bug reports and feature requests

Open a GitHub issue. Include:

- What you expected to happen.
- What actually happened.
- Relevant log output (with any sensitive data redacted).
- Rust toolchain version (`rustup show`).

## Pull requests

1. Fork the repository and create a branch for your change.
2. Run the locked tests, clippy across all targets with warnings denied, and
   the formatting check before submitting. All three must pass.
3. Include a clear description of what the change does and why.
4. Security-sensitive changes (auth, crypto, attestation) require extra
   scrutiny. Explain the threat model impact of your change.

## Development build

```sh
cargo build --locked                              # native development build
cargo test --locked                               # in-memory KMS/GCS fakes
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

The Docker build targets `x86_64-unknown-linux-musl` for the Confidential
Space VM. See README.md for the full build instructions.
