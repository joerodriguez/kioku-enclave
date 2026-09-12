//! Bounded, cohort-gated WeSpeaker serving worker. No provider receives voiceprints.
use super::{
    media_worker::load_retained_media,
    voice_identity::{channel_domain, guarded_samples},
    voice_memory::{decode_mono_16khz, VoiceEngine, MAX_TURN_SAMPLES},
    voice_quality::{self, SampleDecision},
    CpState,
};
use crate::{
    error::{EnclaveError, Result},
    persistence::{
        RepositorySet, VoiceCohort, VoiceEmbeddingClaim, VoiceEmbeddingOutcome,
        VoiceEmbeddingSource,
    },
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};

const SWEEP_SECONDS: u64 = 20;
const MAX_ACCOUNTS: usize = 4;
const BATCH_SECONDS: u64 = 180;
// A timed-out blocking inference may finish after its async caller. Holding
// this permit inside the closure keeps those stragglers inside the CPU bound.
static CPU_SLOTS: Semaphore = Semaphore::const_new(MAX_ACCOUNTS);
pub(crate) type DecodedCache = HashMap<String, Arc<Vec<f32>>>;

fn metric(cohort: VoiceCohort, outcome: &'static str, count: u64, latency: &'static str) {
    tracing::info!(target: "kioku::voice", metric_schema="voice_identity_v1",
        cohort=cohort.as_str(), outcome, count, latency_bucket=latency,
        "voice identity outcome");
}
fn latency_bucket(elapsed: Duration) -> &'static str {
    match elapsed.as_millis() {
        0..=999 => "lt_1s",
        1000..=4999 => "1_5s",
        5000..=29999 => "5_30s",
        _ => "ge_30s",
    }
}
fn media_expired(error: &EnclaveError) -> bool {
    matches!(error, EnclaveError::NotFound)
        || matches!(error, EnclaveError::Gcs(message) if message == "GCS returned an unexpected object generation")
}
fn source_domain(source: &VoiceEmbeddingSource) -> String {
    channel_domain(
        &source.stream_kind,
        source.audio_role.as_deref(),
        source.audio_route.as_deref(),
    )
}

pub(crate) trait VoiceInference: Send + Sync {
    fn embed(&self, samples: &[f32]) -> Result<Vec<f32>>;
}
impl VoiceInference for VoiceEngine {
    fn embed(&self, samples: &[f32]) -> Result<Vec<f32>> {
        self.embed_samples(samples)
    }
}

pub(crate) async fn infer_claim(
    repositories: &RepositorySet,
    kms: &dyn crate::crypto::KmsClient,
    engine: Arc<dyn VoiceInference>,
    claim: &VoiceEmbeddingClaim,
    cache: &mut DecodedCache,
) -> Result<VoiceEmbeddingOutcome> {
    let Some(first) = claim.sources.first() else {
        return Ok(VoiceEmbeddingOutcome::RawMediaExpired);
    };
    let domain = source_domain(first);
    if claim.sources.iter().any(|source| {
        source_domain(source) != domain || source.capture_session_id != first.capture_session_id
    }) {
        return Err(EnclaveError::Embedding(
            "voice source domain mismatch".into(),
        ));
    }
    let mut encoded = HashMap::new();
    for source in &claim.sources {
        if !cache.contains_key(&source.event_id) && !encoded.contains_key(&source.event_id) {
            let bytes = match load_retained_media(
                repositories.media_objects(),
                kms,
                &claim.account_id,
                &source.object_name,
                source.object_generation,
                source.byte_length,
                &source.sha256,
            )
            .await
            {
                Ok(bytes) => bytes,
                Err(error) if media_expired(&error) => {
                    return Ok(VoiceEmbeddingOutcome::RawMediaExpired)
                }
                Err(error) => return Err(error),
            };
            encoded.insert(source.event_id.clone(), (bytes, source.mime_type.clone()));
        }
    }
    let permit = CPU_SLOTS
        .try_acquire()
        .map_err(|_| EnclaveError::Embedding("voice CPU capacity busy".into()))?;
    let mut decoded = cache.clone();
    let mut sources = claim.sources.clone();
    let overlap = claim.overlap;
    let (decoded, outcome) = tokio::task::spawn_blocking(move || -> Result<_> {
        let _permit = permit;
        for (event_id, (bytes, mime)) in encoded {
            decoded.insert(event_id, Arc::new(decode_mono_16khz(&bytes, &mime)?));
        }
        sources.sort_by_key(|source| (source.window_start_ms, source.event_id.clone()));
        let mut chunks = Vec::new();
        for source in &sources {
            let samples = decoded
                .get(&source.event_id)
                .ok_or_else(|| EnclaveError::Embedding("voice decoded source missing".into()))?;
            chunks.push((
                source.window_start_ms,
                guarded_samples(samples, source.event_start_ms, source.event_end_ms)?,
            ));
        }
        let chunk = reconstruct_timeline(&chunks)?;
        let diagnostics = voice_quality::diagnose(&chunk, overlap, &[]);
        let outcome = if diagnostics.decision == SampleDecision::NoEmbedding {
            VoiceEmbeddingOutcome::NoEmbedding { diagnostics }
        } else {
            let embedding = engine.embed(&chunk)?;
            VoiceEmbeddingOutcome::Sample {
                embedding,
                diagnostics,
                channel_domain: domain,
            }
        };
        Ok((decoded, outcome))
    })
    .await
    .map_err(|_| EnclaveError::Embedding("voice inference task failed".into()))??;
    *cache = decoded;
    Ok(outcome)
}

/// Projected event spans can overlap or have gaps. Use their original window
/// coordinates, as Gemini window assembly does: never concatenate duplicate
/// acoustic time into artificial enrollment evidence.
fn reconstruct_timeline(chunks: &[(i64, &[f32])]) -> Result<Vec<f32>> {
    let Some(start) = chunks.iter().map(|(start, _)| *start).min() else {
        return Ok(Vec::new());
    };
    if start < 0 {
        return Err(EnclaveError::Embedding(
            "voice timeline offset is negative".into(),
        ));
    }
    let mut spans = Vec::new();
    let mut length = 0;
    for (at, samples) in chunks {
        let offset = usize::try_from(at - start)
            .ok()
            .and_then(|v| v.checked_mul(16))
            .ok_or_else(|| EnclaveError::Embedding("voice timeline offset is invalid".into()))?;
        let end = offset
            .checked_add(samples.len())
            .ok_or_else(|| EnclaveError::Embedding("voice timeline span is invalid".into()))?;
        length = length.max(end.min(MAX_TURN_SAMPLES));
        spans.push((offset, *samples));
    }
    let mut sums = vec![0.0_f64; length];
    let mut counts = vec![0_u32; length];
    for (offset, samples) in spans {
        for (index, sample) in samples
            .iter()
            .take(length.saturating_sub(offset))
            .enumerate()
        {
            sums[offset + index] += f64::from(*sample);
            counts[offset + index] += 1;
        }
    }
    Ok(sums
        .into_iter()
        .zip(counts)
        .map(|(sum, count)| {
            if count == 0 {
                0.0
            } else {
                (sum / f64::from(count)) as f32
            }
        })
        .collect())
}

async fn process_account(state: &CpState, account_id: &str, cohort: VoiceCohort) {
    let Some(engine) = &state.voice else {
        return;
    };
    let engine: Arc<dyn VoiceInference> = engine.clone();
    let owner = super::tokens::random_token_hex();
    let repository = state.repositories.voice_identity();
    let batch = match repository.claim_voice_embeddings(account_id, &owner).await {
        Ok(batch) => batch,
        Err(_) => {
            metric(cohort, "claim_failed", 1, "none");
            return;
        }
    };
    metric(cohort, "raw_media_expired", batch.expired_count, "none");
    metric(cohort, "attempts_exhausted", batch.exhausted_count, "none");
    let deadline = Instant::now() + Duration::from_secs(BATCH_SECONDS);
    let mut cache = DecodedCache::new();
    for claim in batch.claims {
        let started = Instant::now();
        let outcome = if Instant::now() >= deadline {
            VoiceEmbeddingOutcome::Retry
        } else {
            match tokio::time::timeout_at(
                deadline,
                infer_claim(
                    &state.repositories,
                    state.kms.as_ref(),
                    Arc::clone(&engine),
                    &claim,
                    &mut cache,
                ),
            )
            .await
            {
                Ok(Ok(outcome)) => outcome,
                _ => VoiceEmbeddingOutcome::Retry,
            }
        };
        let label = match &outcome {
            VoiceEmbeddingOutcome::Sample { diagnostics, .. } => match diagnostics.decision {
                SampleDecision::Enroll => "enroll_sample",
                SampleDecision::MatchOnly => "match_only_sample",
                SampleDecision::Quarantine => "quarantined_sample",
                SampleDecision::NoEmbedding => "no_embedding",
            },
            VoiceEmbeddingOutcome::NoEmbedding { .. } => "no_embedding",
            VoiceEmbeddingOutcome::RawMediaExpired => "raw_media_expired",
            VoiceEmbeddingOutcome::Retry => "retry",
        };
        match repository.settle_voice_embedding(&claim, outcome).await {
            Ok(true) => metric(cohort, label, 1, latency_bucket(started.elapsed())),
            Ok(false) => metric(cohort, "lease_lost", 1, "none"),
            Err(_) => metric(cohort, "settlement_failed", 1, "none"),
        }
    }
}

async fn sweep(state: &Arc<CpState>) {
    let controls = match state
        .repositories
        .voice_identity()
        .voice_identity_controls()
        .await
    {
        Ok(controls) => controls,
        Err(_) => {
            metric(VoiceCohort::None, "controls_unavailable", 1, "none");
            return;
        }
    };
    let accounts = match state.repositories.work().active_account_ids().await {
        Ok(accounts) => accounts,
        Err(_) => {
            metric(controls.cohort, "accounts_unavailable", 1, "none");
            return;
        }
    };
    let mut tasks = JoinSet::new();
    for account_id in accounts {
        if tasks.len() >= MAX_ACCOUNTS {
            let _ = tasks.join_next().await;
        }
        let state = Arc::clone(state);
        let cohort = controls.cohort;
        let infer = controls.admits(&account_id) && state.voice.is_some();
        tasks.spawn(async move {
            if state
                .repositories
                .voice_identity()
                .maintain_owner_voice_enrollment(&account_id)
                .await
                .is_err()
            {
                metric(cohort, "enrollment_maintenance_failed", 1, "none");
            }
            if state
                .repositories
                .voice_identity()
                .maintain_voice_profiles(&account_id)
                .await
                .is_err()
            {
                metric(cohort, "profile_maintenance_failed", 1, "none");
            }
            if infer {
                process_account(&state, &account_id, cohort).await;
                if state
                    .repositories
                    .voice_identity()
                    .maintain_owner_voice_enrollment(&account_id)
                    .await
                    .is_err()
                {
                    metric(cohort, "enrollment_maintenance_failed", 1, "none");
                }
                if state
                    .repositories
                    .voice_identity()
                    .maintain_voice_profiles(&account_id)
                    .await
                    .is_err()
                {
                    metric(cohort, "profile_maintenance_failed", 1, "none");
                }
            }
        });
    }
    while tasks.join_next().await.is_some() {}
}

pub fn spawn_scheduler(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(SWEEP_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            sweep(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlapping_sources_cannot_manufacture_enrollment_duration() {
        let first = vec![0.1; 32000];
        let second = vec![0.3; 32000];
        let chunk = reconstruct_timeline(&[(1000, &first), (1000, &second)]).unwrap();
        assert_eq!(
            chunk.len(),
            32000,
            "overlapping voice sources must preserve real acoustic duration"
        );
        assert!(
            (chunk[100] - 0.2).abs() < 0.00001,
            "overlapping voice source samples must be averaged"
        );
        assert_eq!(
            voice_quality::diagnose(&chunk, false, &[]).decision,
            SampleDecision::MatchOnly,
            "overlap must never promote match-only evidence to enrollment"
        );
    }
    #[test]
    fn source_gaps_remain_silence_and_long_spans_are_bounded() {
        let source = vec![0.2; 16000];
        let chunk = reconstruct_timeline(&[(0, &source), (4000, &source)]).unwrap();
        assert_eq!(
            chunk.len(),
            80000,
            "voice timeline must preserve gaps between sources"
        );
        assert!(
            chunk[16000..64000].iter().all(|v| *v == 0.0),
            "missing source time must remain silence"
        );
        assert_eq!(
            voice_quality::diagnose(&chunk, false, &[]).decision,
            SampleDecision::Quarantine,
            "a sparse timeline must not be treated as clean continuous speech"
        );
        assert_eq!(
            reconstruct_timeline(&[(0, &source), (31000, &source)])
                .unwrap()
                .len(),
            MAX_TURN_SAMPLES
        );
    }
    #[test]
    fn content_free_latency_has_fixed_buckets() {
        assert_eq!(latency_bucket(Duration::from_millis(999)), "lt_1s");
        assert_eq!(latency_bucket(Duration::from_secs(1)), "1_5s");
        assert_eq!(latency_bucket(Duration::from_secs(5)), "5_30s");
        assert_eq!(latency_bucket(Duration::from_secs(30)), "ge_30s");
    }
}
