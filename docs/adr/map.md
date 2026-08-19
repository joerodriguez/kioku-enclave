# Architecture decisions

| ADR | Decision |
|---|---|
| [ADR-0017](0017-entitlement-admission-port.md) | Provider-neutral allowance admission and wall-clock recording meter |
| [ADR-0018](0018-entitlement-boundary-and-flow.md) | Enclave/external-control-plane boundary and rejection flow |
| [ADR-0019](0019-privacy-preserving-vertex-cost-attribution.md) | Durable, content-free Vertex usage attribution |
| [ADR-0020](0020-owner-economics-facade.md) | Owner-only opaque economics join and local coverage measurement |
| [ADR-0021](0021-external-service-ports.md) | Provider-neutral external-service ports and deploy-time adapters |
| [ADR-0022 activation readiness](0022-activation-readiness.md) | Inactive enclave boundary closure, explicit no-go findings, and ordered production authorization/evidence requirements for scalable encrypted archive persistence |
| [ADR-0022 production activation runbook](0022-production-activation-runbook.md) | Separate Phase-1 advisory and Phase-2 authority decisions, exact evidence inputs, execution order, permanent stop conditions, and operator authority handoff |
| [`0022-solo-operator-activation.md`](0022-solo-operator-activation.md) | Accepted amendment rescoping the activation runbook's multi-party ceremony for the single-operator/single-user deployment: retains the full data-safety core (backup, shadow parity, durable one-shot controller, witness anti-rollback, sealed verifiers, acknowledgement-after-settlement, rollback window) while collapsing custodial/observation ceremony to the one real operator, with custody, rotation, and revocation recorded. |
| [ADR-0030](0030-in-enclave-silence-compaction-and-source-clock-restoration.md) | Proposed in-enclave speech-time compaction with exact source-clock restoration and measured cost gates |
