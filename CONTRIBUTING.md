# Contributing

## Security vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, email joerodriguez@gmail.com with a description of the
issue and steps to reproduce. We target a 90-day coordinated disclosure
timeline.

See SECURITY.md for the full threat model and known gaps.

## Bug reports and feature requests

Open a GitHub issue. Include:

- What you expected to happen.
- What actually happened.
- Relevant log output (with any sensitive data redacted).
- Rust toolchain version (`rustup show`).

## Pull requests

1. Fork the repository and create a branch for your change.
2. Run `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt` before
   submitting. All three must pass.
3. Include a clear description of what the change does and why.
4. Security-sensitive changes (auth, crypto, attestation) require extra
   scrutiny. Explain the threat model impact of your change.

## Development build

```sh
cargo build       # native build for local testing
cargo test        # no network required; uses in-memory fakes for KMS/GCS
cargo clippy -- -D warnings
cargo fmt
```

The Docker build targets `x86_64-unknown-linux-musl` for the Confidential
Space VM. See README.md for the full build instructions.
