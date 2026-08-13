# `config/` map

Checked-in, reviewable configuration that changes the attested image. These files contain
no secrets and are parsed fail-closed by the build and release tooling; repository variables
and manual-dispatch inputs cannot override them.

| Path | Responsibility |
|---|---|
| `archive-witness-probe.json` | Exact default-off ADR-0022 Firestore transport-probe profile. `probe-v1` requires a complete named-database namespace and is eligible only for an exact `vX.Y.Z-witness-probe.N` prerelease. |
| `archive-v3-shadow-runtime.json` | Sole construction-only ADR-0022 runtime profile. Its only accepted form is exact `off` with all six provider fragments empty; no active mode exists in this slice. |
