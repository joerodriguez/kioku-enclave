//! Strict private operator requests. These are not activation authorizations and
//! are never logged or stored as raw JSON in the permanent erasure journal.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    cp::isotime,
    error::{EnclaveError, Result},
};

const REQUEST_CONTRACT: &str = "kioku.postgresql.orphan-capture-erasure.v1";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_VALIDITY_MS: i64 = 15 * 60 * 1000;
const EXECUTION_MARGIN_MS: i64 = 60 * 1000;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OrphanErasureRequest {
    pub(super) contract: String,
    pub(super) erasure_contract_sha256: String,
    pub(super) account_id: String,
    pub(super) operation_id: String,
    pub(super) activation: ErasureActivationBinding,
    pub(super) action: ErasureAction,
    pub(super) observed_at: String,
    pub(super) expires_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErasureActivationBinding {
    pub(super) generation: i64,
    pub(super) phase: String,
    pub(super) candidate_image_digest: String,
    pub(super) contract_sha256: String,
    pub(super) catalog_sha256: String,
    pub(super) receipt_sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum ErasureAction {
    InstallSchema,
    Inspect(ErasureTargets),
    Prepare(ErasurePrepare),
    AcknowledgeProvider(ErasureProviderAcknowledgement),
    Finalize(ErasureFinalize),
    ReleaseFence(ErasureFenceRelease),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErasureTargets {
    pub(super) capture_session_ids: Vec<String>,
    pub(super) protected_episode_id: i64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ErasureCounts {
    pub(super) sessions: i64,
    pub(super) streams: i64,
    pub(super) events: i64,
    pub(super) objects: i64,
    pub(super) projections: i64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErasurePrepare {
    pub(super) targets: ErasureTargets,
    pub(super) scope_sha256: String,
    pub(super) object_inventory_sha256: String,
    pub(super) provider_names_sha256: String,
    pub(super) provider_name_count: i64,
    pub(super) account_provider_names_sha256: String,
    pub(super) provider_unclassified_objects: u32,
    pub(super) survivor_sha256: String,
    pub(super) protected_control_proof_sha256: String,
    pub(super) provider_authority_sha256: String,
    pub(super) provider_retention_clear: bool,
    pub(super) counts: ErasureCounts,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErasureOperationBinding {
    pub(super) prepare_request_sha256: String,
    pub(super) scope_sha256: String,
    pub(super) object_inventory_sha256: String,
    pub(super) provider_names_sha256: String,
    pub(super) account_provider_names_sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErasureProviderAcknowledgement {
    pub(super) operation: ErasureOperationBinding,
    pub(super) provider_receipt_sha256: String,
    pub(super) all_generations_absent: bool,
    pub(super) retention_clear: bool,
    pub(super) provider_unclassified_objects: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErasureFinalize {
    pub(super) operation: ErasureOperationBinding,
    pub(super) provider_ack_request_sha256: String,
    pub(super) protected_episode_id: i64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErasureFenceRelease {
    pub(super) operation: ErasureOperationBinding,
    pub(super) completion_request_sha256: String,
    pub(super) admission_contract_sha256: String,
    pub(super) fleet_evidence_sha256: String,
    pub(super) protected_canary_evidence_sha256: String,
    pub(super) candidate_instances: u32,
    pub(super) predecessor_instances: u32,
    pub(super) unavailable_instances: u32,
}

// No Debug: raw account/source identities must not reach diagnostics by accident.
pub(crate) struct VerifiedOrphanErasureRequest {
    pub(super) request: OrphanErasureRequest,
    pub(super) request_sha256: Vec<u8>,
    pub(super) signature: Vec<u8>,
    pub(super) key_sha256: Vec<u8>,
    observed_at_ms: i64,
    expires_at_ms: i64,
}

pub(super) fn sha256_label(bytes: &[u8]) -> String {
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

pub(super) fn digest_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("sha256:").ok_or_else(invalid_request)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(invalid_request());
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |value: u8| {
                if value <= b'9' {
                    value - b'0'
                } else {
                    value - b'a' + 10
                }
            };
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect())
}

fn invalid_request() -> EnclaveError {
    EnclaveError::Config(
        "orphan erasure request is invalid or does not bind the reviewed contract".into(),
    )
}

pub(super) fn valid_identity(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || v == b'_' || v == b'-')
}

fn validate_targets(targets: &ErasureTargets) -> Result<()> {
    if !(1..=4).contains(&targets.capture_session_ids.len())
        || targets.protected_episode_id <= 0
        || !targets
            .capture_session_ids
            .iter()
            .all(|v| valid_identity(v))
        || !targets.capture_session_ids.windows(2).all(|v| v[0] < v[1])
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn validate_operation(operation: &ErasureOperationBinding) -> Result<()> {
    for digest in [
        &operation.prepare_request_sha256,
        &operation.scope_sha256,
        &operation.object_inventory_sha256,
        &operation.provider_names_sha256,
        &operation.account_provider_names_sha256,
    ] {
        digest_bytes(digest)?;
    }
    Ok(())
}

fn validate_shape(request: &OrphanErasureRequest) -> Result<(i64, i64)> {
    if request.contract != REQUEST_CONTRACT
        || request.erasure_contract_sha256
            != sha256_label(&super::orphan_capture_erasure::contract_digest())
        || !valid_identity(&request.account_id)
        || !valid_identity(&request.operation_id)
        || request.activation.generation <= 0
    {
        return Err(invalid_request());
    }
    let release = matches!(request.action, ErasureAction::ReleaseFence(_));
    if request.activation.phase != if release { "active" } else { "draining" } {
        return Err(invalid_request());
    }
    for digest in [
        &request.activation.candidate_image_digest,
        &request.activation.contract_sha256,
        &request.activation.catalog_sha256,
        &request.activation.receipt_sha256,
    ] {
        digest_bytes(digest)?;
    }
    match &request.action {
        ErasureAction::InstallSchema => {
            if request.account_id != "schema" || request.operation_id != "install" {
                return Err(invalid_request());
            }
        }
        ErasureAction::Inspect(targets) => validate_targets(targets)?,
        ErasureAction::Prepare(prepare) => {
            validate_targets(&prepare.targets)?;
            for digest in [
                &prepare.scope_sha256,
                &prepare.object_inventory_sha256,
                &prepare.provider_names_sha256,
                &prepare.account_provider_names_sha256,
                &prepare.survivor_sha256,
                &prepare.protected_control_proof_sha256,
                &prepare.provider_authority_sha256,
            ] {
                digest_bytes(digest)?;
            }
            let count = &prepare.counts;
            if !prepare.provider_retention_clear
                || prepare.provider_unclassified_objects != 0
                || count.sessions != prepare.targets.capture_session_ids.len() as i64
                || !(1..=16).contains(&count.streams)
                || !(1..=256).contains(&count.events)
                || !(0..=256).contains(&count.objects)
                || prepare.provider_name_count != count.objects * 2
                || !(0..=1024).contains(&count.projections)
            {
                return Err(invalid_request());
            }
        }
        ErasureAction::AcknowledgeProvider(ack) => {
            validate_operation(&ack.operation)?;
            digest_bytes(&ack.provider_receipt_sha256)?;
            if !ack.all_generations_absent
                || !ack.retention_clear
                || ack.provider_unclassified_objects != 0
            {
                return Err(invalid_request());
            }
        }
        ErasureAction::Finalize(finalize) => {
            validate_operation(&finalize.operation)?;
            digest_bytes(&finalize.provider_ack_request_sha256)?;
            if finalize.protected_episode_id <= 0 {
                return Err(invalid_request());
            }
        }
        ErasureAction::ReleaseFence(release) => {
            validate_operation(&release.operation)?;
            for digest in [
                &release.completion_request_sha256,
                &release.admission_contract_sha256,
                &release.fleet_evidence_sha256,
                &release.protected_canary_evidence_sha256,
            ] {
                digest_bytes(digest)?;
            }
            if release.admission_contract_sha256 != admission_contract_sha256()
                || release.candidate_instances == 0
                || release.predecessor_instances != 0
                || release.unavailable_instances != 0
            {
                return Err(invalid_request());
            }
        }
    }
    let observed = isotime::parse_epoch_millis(&request.observed_at).ok_or_else(invalid_request)?;
    let expires = isotime::parse_epoch_millis(&request.expires_at).ok_or_else(invalid_request)?;
    if isotime::format_epoch_millis(observed) != request.observed_at
        || isotime::format_epoch_millis(expires) != request.expires_at
        || expires <= observed
        || expires.saturating_sub(observed) > MAX_VALIDITY_MS
    {
        return Err(invalid_request());
    }
    Ok((observed, expires))
}

pub(super) fn admission_contract_sha256() -> String {
    sha256_label(&Sha256::digest(b"kioku.orphan-capture-admission.v1\0session-stream-event-asset-canonical-reference\0preflight-before-credit\0account-locked-reservation-before-provider-put\0"))
}

/// Canonical transport is recursively key-sorted compact JSON with one newline.
/// Parsing into strict structs first rejects duplicate/unknown fields before
/// canonicalization; no unsigned transport variant is accepted.
fn canonical_bytes(request: &OrphanErasureRequest) -> Result<Vec<u8>> {
    fn sorted(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(object) => serde_json::Value::Object(
                object
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(sorted).collect())
            }
            value => value,
        }
    }
    let value = sorted(serde_json::to_value(request)?);
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn test_verified_request(
    request: OrphanErasureRequest,
) -> Result<VerifiedOrphanErasureRequest> {
    let canonical = canonical_bytes(&request)?;
    let signature = STANDARD.encode(super::schema_release::test_sign_operator_request(
        &canonical,
    ));
    verify_orphan_erasure_request(
        std::str::from_utf8(&canonical).expect("JSON is UTF8"),
        &signature,
    )
}

pub(crate) fn verify_orphan_erasure_request(
    raw_request: &str,
    raw_signature: &str,
) -> Result<VerifiedOrphanErasureRequest> {
    if raw_request.len() > MAX_REQUEST_BYTES || raw_signature.len() != 88 {
        return Err(invalid_request());
    }
    let request: OrphanErasureRequest =
        serde_json::from_str(raw_request).map_err(|_| invalid_request())?;
    let (observed_at_ms, expires_at_ms) = validate_shape(&request)?;
    let canonical = canonical_bytes(&request)?;
    if canonical != raw_request.as_bytes() {
        return Err(invalid_request());
    }
    let signature = STANDARD
        .decode(raw_signature)
        .map_err(|_| invalid_request())?;
    if signature.len() != 64 || STANDARD.encode(&signature) != raw_signature {
        return Err(invalid_request());
    }
    let key_sha256 =
        super::schema_release::verify_operator_request_signature(&canonical, &signature)?;
    Ok(VerifiedOrphanErasureRequest {
        request,
        request_sha256: Sha256::digest(&canonical).to_vec(),
        signature,
        key_sha256,
        observed_at_ms,
        expires_at_ms,
    })
}

impl VerifiedOrphanErasureRequest {
    pub(super) async fn require_fresh(&self, connection: &mut sqlx::PgConnection) -> Result<()> {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(connection)
                .await?;
        if now < self.observed_at_ms || now > self.expires_at_ms.saturating_sub(EXECUTION_MARGIN_MS)
        {
            return Err(EnclaveError::Conflict(
                "orphan erasure authorization is not currently executable".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn inspect_fixture() -> OrphanErasureRequest {
        OrphanErasureRequest {
            contract: REQUEST_CONTRACT.into(),
            erasure_contract_sha256: sha256_label(
                &super::super::orphan_capture_erasure::contract_digest(),
            ),
            account_id: "fixture-account".into(),
            operation_id: "fixture-operation".into(),
            activation: ErasureActivationBinding {
                generation: 1,
                phase: "draining".into(),
                candidate_image_digest: sha256_label(&[1; 32]),
                contract_sha256: sha256_label(&[2; 32]),
                catalog_sha256: sha256_label(&[3; 32]),
                receipt_sha256: sha256_label(&[4; 32]),
            },
            action: ErasureAction::Inspect(ErasureTargets {
                capture_session_ids: vec!["a".into(), "b".into()],
                protected_episode_id: 1,
            }),
            observed_at: "2026-09-06T12:00:00.000Z".into(),
            expires_at: "2026-09-06T12:15:00.000Z".into(),
        }
    }

    #[test]
    fn orphan_erasure_request_binds_exact_bytes_domain_and_targets() {
        let request = inspect_fixture();
        let bytes = canonical_bytes(&request).unwrap();
        let raw = String::from_utf8(bytes.clone()).unwrap();
        let signature = STANDARD.encode(super::super::schema_release::test_sign_operator_request(
            &bytes,
        ));
        assert!(verify_orphan_erasure_request(&raw, &signature).is_ok());
        assert!(verify_orphan_erasure_request(raw.trim(), &signature).is_err());
        assert!(verify_orphan_erasure_request(
            &raw.replace("fixture-account", "other-account"),
            &signature
        )
        .is_err());
        assert!(verify_orphan_erasure_request(
            &raw.replace(REQUEST_CONTRACT, "kioku.postgresql.schema-finalization"),
            &signature
        )
        .is_err());
        assert!(verify_orphan_erasure_request(
            &raw.replacen('{', "{\"unknown\":true,", 1),
            &signature
        )
        .is_err());
        assert!(verify_orphan_erasure_request(
            &raw.replacen('{', "{\"contract\":\"duplicate\",", 1),
            &signature
        )
        .is_err());
        let mut changed = request.clone();
        changed.action = ErasureAction::Inspect(ErasureTargets {
            capture_session_ids: vec!["b".into(), "a".into()],
            protected_episode_id: 1,
        });
        assert!(validate_shape(&changed).is_err());
        changed.action = ErasureAction::Inspect(ErasureTargets {
            capture_session_ids: vec!["a".into(), "a".into()],
            protected_episode_id: 1,
        });
        assert!(validate_shape(&changed).is_err());
        changed.action = ErasureAction::Inspect(ErasureTargets {
            capture_session_ids: vec!["a/../b".into()],
            protected_episode_id: 1,
        });
        assert!(validate_shape(&changed).is_err());
        changed = request;
        changed.expires_at = "2026-09-06T12:15:00.001Z".into();
        assert!(validate_shape(&changed).is_err());
    }
}
