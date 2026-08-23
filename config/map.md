# `config/` map

Checked-in, reviewable configuration that changes the attested image. These files contain
no secrets and are parsed fail-closed by the build and release tooling; repository variables
and manual-dispatch inputs cannot override them.

| Path | Responsibility |
|---|---|
| `archive-witness-probe.json` | Exact default-off ADR-0022 Firestore transport-probe profile. `probe-v1` requires a complete named-database namespace and is eligible only for an exact `vX.Y.Z-witness-probe.N` prerelease. |
| `archive-v3-shadow-runtime.json` | Sole schema-2 ADR-0022 single-archive WAL runtime profile. The checked file remains exact `off` with all seven fragments empty. A complete canonical `single-archive-wal-v1` form is image-evidence eligible only on an exact `vX.Y.Z-archive-v3-wal.N` production tag; it has no operator/environment/dispatch override. Under that signed profile startup relaunches durable selected owners and the Genesis sign-in trigger is armed only when the separately baked `GENESIS_WAL_NATIVE=on` agrees. |
