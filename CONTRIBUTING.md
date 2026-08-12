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
2. Run the quick local verification and focused tests for the code changed.
   Run the full local suite when the change is broad, security-sensitive, or
   you need to reproduce CI. Required GitHub CI is the exhaustive,
   authoritative merge gate; it must pass before merge.
3. Include a clear description of what the change does and why.
4. Security-sensitive changes (auth, crypto, attestation) require extra
   scrutiny. Explain the threat model impact of your change.

## Development build

```sh
# Default local feedback: formatting plus a locked type-check.
./scripts/agent-verify.sh quick

# Add the smallest relevant test selection while developing.
./scripts/agent-verify.sh focused -- module::tests::affected_case

# Available for broad or security-sensitive changes and CI diagnosis.
./scripts/agent-verify.sh full
```

The helper uses locked Cargo compilation/test invocations. It checks free disk
space before invoking Cargo, coordinates builds and artifact retirement with a
crash-safe per-worktree lock, and, when `sccache` is already installed, enables it with a
10-GiB cache limit. The default disk-space floor is 15 GiB. `sccache` is optional.
A separate `cargo build` is not needed because the other commands compile the
required code. In shared agent worktrees, use this helper instead of racing
artifact retirement with a raw Cargo command.

The Docker build targets `x86_64-unknown-linux-musl` for the Confidential
Space VM. See README.md for the full build instructions.
