# docs

Proposed and accepted architecture decision records for cross-boundary behavior that must
remain stable across the enclave, client applications, and the external billing service.

| Path | Purpose |
|---|---|
| [adr/](adr/map.md) | Proposed and accepted architecture decisions and their operational consequences |
| [postgresql-schema-releases.md](postgresql-schema-releases.md) | Receipt-bound PostgreSQL expand/finalize ordering, exact morning-email/interrupted-capture/voice-identity/owner-enrollment/profile-proposal/name-evidence companions, voice cohort/pause operator phases, compatibility windows, and writer-activation boundaries |
| [orphan-capture-erasure.md](orphan-capture-erasure.md) | Bounded owner-authorized orphan-capture erasure, durable media inventory/replay barriers, and compatibility/verification requirements; source implemented and under review, provider/operator delivery and production enablement pending |
