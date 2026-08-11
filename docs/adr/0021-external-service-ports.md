# ADR-0021: External-service ports and deploy-time adapters

- Status: Accepted direction; inference migration staged
- Date: 2026-08-11

## Context

The attested open-source core must remain auditable and useful without embedding Kioku's
private commercial choices. It also needs external identity, entitlement, generative
inference, email, and user-selected webhook capabilities. Dynamically linking closed code
into the enclave image would make the deployed digest impossible to audit from this
repository, while proxying user plaintext through a closed control plane would violate the
documented content boundary.

## Decision

Use ports-and-adapters with network adapters selected by image-baked configuration:

1. **Entitlement admission:** the enclave's port knows only account pseudonym, meter,
   bounded quantity, deterministic request identity, decision, and usage snapshot. The
   closed control plane implements commerce and policy.
2. **Generative inference:** converge on a provider-neutral inference port whose request
   vocabulary is the OpenAI-compatible Chat Completions shape for text, images, audio,
   tools, and JSON-schema responses. Provider-specific authentication and endpoint
   selection are deploy-time adapters. Google documents an OpenAI-compatible endpoint for
   both hosted models and self-deployed Model Garden models, so this boundary preserves a
   path from the current deployment to an open GPU model without changing domain logic.
3. **Inference telemetry:** name core token counters and operation attributes after the
   OpenTelemetry GenAI semantic conventions. Provider-only counters live in an optional
   adapter extension and never determine authorization as an implicit zero.
4. **Identity:** use standard OIDC/OAuth claims at the port; provider client IDs and
   credentials remain configuration.
5. **Outbound user automation:** retain signed CloudEvents/Standard Webhooks over the
   user-selected HTTPS boundary.

An adapter is an external HTTPS service or an open-source module built from this
repository. A closed binary or library is never loaded into the attested process. Any
adapter receiving user content remains an explicit security/privacy egress and the exact
production provider remains disclosed to users even though domain code is provider
neutral.

OpenFeature is useful precedent for provider resolution, but its evaluation contract does
not provide atomic, prospective, idempotent consumption. Kioku therefore keeps the small
reservation protocol defined by ADR-0017 instead of presenting quota as a feature flag.

## Migration

- The entitlement port is effective immediately; merchant names, host lists, catalog
  values, and financial schemas are removed from enclave source.
- Existing `/api/billing` names remain only as a shipped-client compatibility facade and
  may be replaced by `/api/entitlements` after all supported clients migrate.
- The current generative provider calls remain an explicitly documented egress until the
  OpenAI-compatible port reproduces the strict media, schema, token-limit, retry, and
  deletion-fence tests. The migration must not weaken those gates merely to gain provider
  interchangeability.

## Consequences

- Commercial implementation can remain closed without weakening source-to-image audit of
  the plaintext data plane.
- Switching hosted inference or moving to an open GPU model becomes an adapter/config
  change after the compatibility gate passes.
- Provider neutrality does not hide privacy reality: exact production egress is still
  disclosed in the threat model and release metadata.

## References

- [OpenFeature provider specification](https://openfeature.dev/specification/sections/providers/)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
- [Google Cloud OpenAI-compatible inference endpoint](https://cloud.google.com/vertex-ai/generative-ai/docs/multimodal/call-vertex-using-openai-library)
