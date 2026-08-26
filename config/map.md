# `config/` map

Checked-in, reviewable configuration that changes the attested image. These files contain
no secrets and are parsed fail-closed by the build and release tooling; repository variables
and manual-dispatch inputs cannot override them.

| Path | Responsibility |
|---|---|
| `archive-witness-probe.json` | Exact default-off ADR-0022 Firestore transport-probe profile. `probe-v1` requires a complete named-database namespace and is eligible only for an exact `vX.Y.Z-witness-probe.N` prerelease. |
| `archive-v3-shadow-runtime.json` | Sole schema-2 ADR-0022 single-archive WAL runtime profile. This BOOTSTRAP source line is exact `off` with every deployment fragment empty, so it cannot construct archive-v3 credentials, relaunch an owner, or arm Genesis. A later separately reviewed FINAL source line may replace it with the complete fresh-production `single-archive-wal-v1` tuple and one-way commitment; active selection remains limited to an exact `vX.Y.Z-archive-v3-wal.N` production tag with no operator/environment/dispatch override. |
| `adr0022-fresh-generation-intent.json` | Canonical provider-free `adr0022-v1` namespace intent. Its exact 1,551 bytes hash to `7ece5ba9…3727`; every fixed schema-10 fresh release coordinate refuses any content or byte-encoding drift. |
| `adr0022-fresh-schema10-bootstrap-fixture.json` | Synthetic cross-repository schema-10 BOOTSTRAP metadata fixture in exact producer order and compact-LF encoding. Its 3,094 bytes hash to `40ce2530…e2a9`; synthetic commit/image/canary values grant no release or provider authority. |
