//! Reviewed solo-operator entry for the one-shot Phase-1 advisory canary run.
//!
//! This is the only production path that constructs the sealed shadow runtime and
//! drives [`SingleArchivePhase1AdvisoryController`]; it is reachable exclusively
//! from the pre-serving `--run-archive-v3-phase1-canary` argv branch, so serving
//! replicas can never carry it (the process exits before the server binds).
//!
//! Every input is explicit and fail-closed:
//! - The runtime deployment comes only from the baked image configuration
//!   (`from_baked_env`); a serving-shaped image (mode `off`) refuses to run.
//! - The archive binding comes only from the durable Control ledger for the one
//!   named user; the sealed `bind_once` recomputes and compares the image-baked
//!   binding commitment.
//! - The three-root authorization is read from operator-supplied evidence files
//!   and verified against the pinned public roots before anything else runs.
//! - The window observer consumes operator-signed observations from a local feed
//!   file; the trusted memory measurement reads the SEV guest's /proc/meminfo.
//! - Outputs are content-free: the terminal stage name and commitments only.

use std::sync::Arc;

use super::{
    controller::{ProcMeminfoVmMemoryProvider, SingleArchivePhase1AdvisoryController},
    live_window_observer::{FileSignedWindowObservationSource, LiveDeploymentWindowObserver},
    window::HeldPhase1Window,
    AdvisoryOwnerError,
};
use crate::archive_v3_shadow_runtime::{
    ArchiveV3ShadowRuntimeDeployment, DurableSingleArchiveBinding, PendingSingleArchiveWalRuntime,
};
use crate::cp::control_store::ControlStore;
use crate::crypto::GcpKmsClient;
use crate::store::Store;

/// Parsed, validated solo-canary invocation. Constructed only by `parse_args`.
pub(crate) struct SoloCanaryInvocation {
    user_id: String,
    run_id: [u8; 16],
    window_id: [u8; 16],
    deployment_target_commitment: [u8; 32],
    deployment_revision_commitment: [u8; 32],
    challenge_commitment: [u8; 32],
    monitoring_policy_commitment: [u8; 32],
    rollback_policy_commitment: [u8; 32],
    zero_replica_digest: [u8; 32],
    window_start_ticks: u64,
    window_end_ticks: u64,
    observations_file: std::path::PathBuf,
    operator_statement: Vec<u8>,
    operator_signature: Vec<u8>,
    image_attestation: Vec<u8>,
    image_attestation_signature: Vec<u8>,
    runtime_admission: Vec<u8>,
    runtime_admission_signature: Vec<u8>,
}

impl std::fmt::Debug for SoloCanaryInvocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SoloCanaryInvocation(<opaque>)")
    }
}

fn fixed_hex<const N: usize>(name: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{name}: expected {} hex chars", N * 2));
    }
    let mut out = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| format!("{name}: invalid hex"))?;
        out[index] = u8::from_str_radix(text, 16).map_err(|_| format!("{name}: invalid hex"))?;
    }
    if out == [0u8; N] {
        return Err(format!("{name}: zero value is refused"));
    }
    Ok(out)
}

impl SoloCanaryInvocation {
    /// Parse `--flag value` pairs. Every flag is mandatory; unknown flags refuse.
    pub(crate) fn parse_args(args: &[String]) -> Result<Self, String> {
        let mut values = std::collections::HashMap::new();
        let mut cursor = args.iter();
        while let Some(flag) = cursor.next() {
            let value = cursor
                .next()
                .ok_or_else(|| format!("{flag}: missing value"))?;
            if values.insert(flag.clone(), value.clone()).is_some() {
                return Err(format!("{flag}: duplicated"));
            }
        }
        let take = |name: &str| -> Result<String, String> {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| format!("{name}: required"))
        };
        let evidence = |name: &str| -> Result<Vec<u8>, String> {
            let path = take(name)?;
            let bytes =
                std::fs::read(&path).map_err(|_| format!("{name}: unreadable evidence file"))?;
            if bytes.is_empty() {
                return Err(format!("{name}: empty evidence file"));
            }
            Ok(bytes)
        };

        let known = [
            "--user-id",
            "--run-id",
            "--window-id",
            "--deployment-target-commitment",
            "--deployment-revision-commitment",
            "--challenge-commitment",
            "--monitoring-policy-commitment",
            "--rollback-policy-commitment",
            "--zero-replica-digest",
            "--window-start-ticks",
            "--window-end-ticks",
            "--observations-file",
            "--operator-statement-file",
            "--operator-signature-file",
            "--image-attestation-file",
            "--image-attestation-signature-file",
            "--runtime-admission-file",
            "--runtime-admission-signature-file",
        ];
        for flag in values.keys() {
            if !known.contains(&flag.as_str()) {
                return Err(format!("{flag}: unknown flag"));
            }
        }

        let ticks = |name: &str| -> Result<u64, String> {
            take(name)?
                .parse::<u64>()
                .map_err(|_| format!("{name}: invalid u64"))
        };

        Ok(Self {
            user_id: take("--user-id")?,
            run_id: fixed_hex::<16>("--run-id", &take("--run-id")?)?,
            window_id: fixed_hex::<16>("--window-id", &take("--window-id")?)?,
            deployment_target_commitment: fixed_hex::<32>(
                "--deployment-target-commitment",
                &take("--deployment-target-commitment")?,
            )?,
            deployment_revision_commitment: fixed_hex::<32>(
                "--deployment-revision-commitment",
                &take("--deployment-revision-commitment")?,
            )?,
            challenge_commitment: fixed_hex::<32>(
                "--challenge-commitment",
                &take("--challenge-commitment")?,
            )?,
            monitoring_policy_commitment: fixed_hex::<32>(
                "--monitoring-policy-commitment",
                &take("--monitoring-policy-commitment")?,
            )?,
            rollback_policy_commitment: fixed_hex::<32>(
                "--rollback-policy-commitment",
                &take("--rollback-policy-commitment")?,
            )?,
            zero_replica_digest: fixed_hex::<32>(
                "--zero-replica-digest",
                &take("--zero-replica-digest")?,
            )?,
            window_start_ticks: ticks("--window-start-ticks")?,
            window_end_ticks: ticks("--window-end-ticks")?,
            observations_file: std::path::PathBuf::from(take("--observations-file")?),
            operator_statement: evidence("--operator-statement-file")?,
            operator_signature: evidence("--operator-signature-file")?,
            image_attestation: evidence("--image-attestation-file")?,
            image_attestation_signature: evidence("--image-attestation-signature-file")?,
            runtime_admission: evidence("--runtime-admission-file")?,
            runtime_admission_signature: evidence("--runtime-admission-signature-file")?,
        })
    }
}

/// Run the one-shot solo Phase-1 advisory canary. Returns the process exit code;
/// stdout receives only content-free stage names and hex commitments.
pub(crate) async fn run_solo_phase1_canary(
    invocation: SoloCanaryInvocation,
    control: Arc<ControlStore>,
    store: Arc<Store>,
    concrete_kms: Arc<GcpKmsClient>,
) -> i32 {
    // 1. The image must be activation-shaped: baked coordinates present and valid.
    let deployment = match ArchiveV3ShadowRuntimeDeployment::from_baked_env() {
        Ok(Some(deployment)) => deployment,
        Ok(None) => {
            eprintln!("refusing: image is serving-shaped (archive-v3 runtime mode is off)");
            return 2;
        }
        Err(_) => {
            eprintln!("refusing: baked archive-v3 runtime coordinates are invalid");
            return 2;
        }
    };

    // 2. Three-root authorization verifies before any provider construction.
    let authorization = match super::canary_trust::verify_pinned_advisory_canary_authorization(
        &invocation.operator_statement,
        &invocation.operator_signature,
        &invocation.image_attestation,
        &invocation.image_attestation_signature,
        &invocation.runtime_admission,
        &invocation.runtime_admission_signature,
    ) {
        Ok(authorization) => authorization,
        Err(_) => {
            eprintln!("refusing: three-root canary authorization failed verification");
            return 2;
        }
    };

    // 3. Live held window from the operator-approved coordinates.
    let window = match HeldPhase1Window::new(
        invocation.window_id,
        invocation.deployment_target_commitment,
        invocation.deployment_revision_commitment,
        invocation.challenge_commitment,
        invocation.monitoring_policy_commitment,
        invocation.rollback_policy_commitment,
        invocation.zero_replica_digest,
        invocation.window_start_ticks,
        invocation.window_end_ticks,
    ) {
        Ok(window) => window,
        Err(_) => {
            eprintln!("refusing: window coordinates are invalid");
            return 2;
        }
    };

    // 4. Durable archive binding for the one named user; sealed bind-once.
    let binding = match control.active_archive_binding(&invocation.user_id).await {
        Ok(binding) => binding,
        Err(_) => {
            eprintln!("refusing: no active legacy archive binding for the named user");
            return 2;
        }
    };
    let durable = DurableSingleArchiveBinding::from_control_store(binding);
    let runtime = match PendingSingleArchiveWalRuntime::new(deployment, concrete_kms)
        .and_then(|pending| pending.bind_once(durable))
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("refusing: sealed runtime binding failed (image/archive commitment)");
            return 2;
        }
    };

    // 5. Operator observation feed + pinned-root observer + trusted memory.
    let observer = match LiveDeploymentWindowObserver::from_pinned_root(Arc::new(
        FileSignedWindowObservationSource::new(invocation.observations_file.clone()),
    )) {
        Ok(observer) => observer,
        Err(_) => {
            eprintln!("refusing: pinned deployment-observer root is unavailable");
            return 2;
        }
    };

    let controller = Arc::new(SingleArchivePhase1AdvisoryController::new(
        Arc::clone(&control),
        Arc::clone(&store),
        Arc::new(observer),
        Arc::new(ProcMeminfoVmMemoryProvider),
        None,
    ));

    match controller
        .execute_canary_run(
            invocation.run_id,
            &invocation.user_id,
            runtime,
            window,
            Some(authorization),
        )
        .await
    {
        Ok(record) => {
            let commitment_hex: String = record
                .commitment
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            println!("phase1_canary_stage={:?}", record.stage);
            println!("phase1_canary_run_commitment={commitment_hex}");
            0
        }
        Err(AdvisoryOwnerError::Conflict) => {
            eprintln!("phase1_canary_stage=conflict");
            3
        }
        Err(_) => {
            eprintln!("phase1_canary_stage=failed");
            3
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args(dir: &std::path::Path) -> Vec<String> {
        let mut args = Vec::new();
        let mut push = |flag: &str, value: String| {
            args.push(flag.to_string());
            args.push(value);
        };
        for name in [
            "statement",
            "operator-sig",
            "attestation",
            "attestation-sig",
            "admission",
            "admission-sig",
            "observations",
        ] {
            std::fs::write(dir.join(name), b"nonempty").unwrap();
        }
        push(
            "--user-id",
            "11111111-1111-4111-8111-111111111111".to_string(),
        );
        push("--run-id", "11".repeat(16));
        push("--window-id", "22".repeat(16));
        push("--deployment-target-commitment", "33".repeat(32));
        push("--deployment-revision-commitment", "44".repeat(32));
        push("--challenge-commitment", "55".repeat(32));
        push("--monitoring-policy-commitment", "66".repeat(32));
        push("--rollback-policy-commitment", "77".repeat(32));
        push("--zero-replica-digest", "88".repeat(32));
        push("--window-start-ticks", "1000".to_string());
        push("--window-end-ticks", "2000".to_string());
        push(
            "--observations-file",
            dir.join("observations").display().to_string(),
        );
        push(
            "--operator-statement-file",
            dir.join("statement").display().to_string(),
        );
        push(
            "--operator-signature-file",
            dir.join("operator-sig").display().to_string(),
        );
        push(
            "--image-attestation-file",
            dir.join("attestation").display().to_string(),
        );
        push(
            "--image-attestation-signature-file",
            dir.join("attestation-sig").display().to_string(),
        );
        push(
            "--runtime-admission-file",
            dir.join("admission").display().to_string(),
        );
        push(
            "--runtime-admission-signature-file",
            dir.join("admission-sig").display().to_string(),
        );
        args
    }

    #[test]
    fn parse_args_requires_every_flag_and_refuses_zero_or_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let args = valid_args(dir.path());
        assert!(SoloCanaryInvocation::parse_args(&args).is_ok());

        // Dropping any one flag pair refuses with its name.
        for index in (0..args.len()).step_by(2) {
            let mut missing = args.clone();
            missing.drain(index..index + 2);
            let err = SoloCanaryInvocation::parse_args(&missing).unwrap_err();
            assert!(err.contains("required") || err.contains("missing"), "{err}");
        }

        // Zero commitments, bad hex, unknown flags, duplicates all refuse.
        let mutate = |flag: &str, value: &str| {
            let mut mutated = args.clone();
            let index = mutated.iter().position(|a| a == flag).unwrap();
            mutated[index + 1] = value.to_string();
            SoloCanaryInvocation::parse_args(&mutated)
        };
        assert!(mutate("--window-id", &"00".repeat(16)).is_err());
        assert!(mutate("--challenge-commitment", &"zz".repeat(32)).is_err());
        assert!(mutate("--run-id", "1234").is_err());
        assert!(mutate("--window-start-ticks", "not-a-number").is_err());

        let mut unknown = args.clone();
        unknown.push("--surprise".into());
        unknown.push("x".into());
        assert!(SoloCanaryInvocation::parse_args(&unknown)
            .unwrap_err()
            .contains("unknown"));

        let mut duplicated = args.clone();
        duplicated.push("--run-id".into());
        duplicated.push("11".repeat(16));
        assert!(SoloCanaryInvocation::parse_args(&duplicated)
            .unwrap_err()
            .contains("duplicated"));

        // Missing evidence file refuses.
        let mut absent = args.clone();
        let index = absent
            .iter()
            .position(|a| a == "--operator-statement-file")
            .unwrap();
        absent[index + 1] = dir.path().join("absent").display().to_string();
        assert!(SoloCanaryInvocation::parse_args(&absent)
            .unwrap_err()
            .contains("unreadable"));
    }
}
