//! Real PostgreSQL + encrypted fake-GCS exercise of the serving inference boundary.
use super::{voice_identity::tests::seed_voice_observation, PostgresPersistence};
use crate::{
    cp::{
        voice_memory::encode_mono_16khz_wav,
        voice_worker::{infer_claim, DecodedCache, VoiceInference},
    },
    crypto::{encrypt_bound_blob, Dek, FakeKms, KmsClient},
    error::Result,
    gcs::{media_blob_context, FakeGcs, GcsClient},
    persistence::{
        GcsMediaObjectStore, RepositorySet, VoiceCohort, VoiceEmbeddingOutcome,
        VoiceIdentityRepository,
    },
};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct SyntheticVoice(AtomicUsize);
impl VoiceInference for SyntheticVoice {
    fn embed(&self, samples: &[f32]) -> Result<Vec<f32>> {
        assert_eq!(
            samples.len(),
            64000,
            "worker must decode and slice the four-second source"
        );
        self.0.fetch_add(1, Ordering::SeqCst);
        let mut embedding = vec![0.; 256];
        embedding[0] = 1.;
        Ok(embedding)
    }
}

#[tokio::test]
async fn voice_worker_decrypts_once_and_settles_without_provider_embedding_egress() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = Arc::new(PostgresPersistence::with_pool(
        fixture.persistence.pool().clone(),
    ));
    let account = "voice-worker-contract";
    seed_voice_observation(&repo, account, "session", "one", 1, 1).await;
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    let kms = FakeKms::new();
    let gcs = Arc::new(FakeGcs::new());
    let samples = (0..64000)
        .map(|i| (i as f32 / 17.).sin() * 0.2)
        .collect::<Vec<_>>();
    let wav = encode_mono_16khz_wav(&samples).unwrap();
    let object = format!("raw/{account}/one.enc");
    let dek = Dek::generate();
    let wrapped = kms.wrap_dek(&dek.0).await.unwrap();
    let encrypted = encrypt_bound_blob(&dek, &wav, &media_blob_context(account, &object)).unwrap();
    let generation = gcs
        .put_object(&object, &encrypted, &wrapped, 0)
        .await
        .unwrap();
    sqlx::query("UPDATE media_objects SET byte_length=$2,sha256=$3,object_generation=$4 WHERE account_id=$1")
        .bind(account).bind(wav.len() as i64).bind(format!("{:x}",Sha256::digest(&wav))).bind(generation).execute(repo.pool()).await.unwrap();
    let repositories = RepositorySet::postgres(
        Arc::clone(&repo),
        Arc::new(GcsMediaObjectStore::new(gcs.clone())),
    );
    let claim = repo
        .claim_voice_embeddings(account, "test-worker")
        .await
        .unwrap()
        .claims
        .remove(0);
    let engine = Arc::new(SyntheticVoice(AtomicUsize::new(0)));
    let mut cache = DecodedCache::new();
    let outcome = infer_claim(&repositories, &kms, engine.clone(), &claim, &mut cache)
        .await
        .unwrap();
    assert!(
        matches!(&outcome, VoiceEmbeddingOutcome::Sample { .. }),
        "worker must produce a sample from retained encrypted audio"
    );
    assert!(repo.settle_voice_embedding(&claim, outcome).await.unwrap());
    assert_eq!(engine.0.load(Ordering::SeqCst), 1);
    // Prove a second turn uses decoded cache rather than reopening the media.
    gcs.delete_object_generation(&object, generation)
        .await
        .unwrap();
    let outcome = infer_claim(&repositories, &kms, engine.clone(), &claim, &mut cache)
        .await
        .unwrap();
    assert!(
        matches!(outcome, VoiceEmbeddingOutcome::Sample { .. }),
        "batch must reuse decoded source after its first exact-generation load"
    );
    cache.clear();
    let outcome = infer_claim(&repositories, &kms, engine, &claim, &mut cache)
        .await
        .unwrap();
    assert!(
        matches!(outcome, VoiceEmbeddingOutcome::RawMediaExpired),
        "missing exact-generation media must expire without inference"
    );
    let row: (i64,String)=sqlx::query_as("SELECT p.sample_count,j.state FROM voice_profiles p JOIN voice_embedding_jobs j ON j.account_id=p.account_id WHERE p.account_id=$1").bind(account).fetch_one(repo.pool()).await.unwrap();
    assert_eq!(
        row,
        (1, "ready".into()),
        "worker output must reach durable profile settlement"
    );
    repo.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
}

struct WindowProbe {
    calls: AtomicUsize,
    received: std::sync::Mutex<Vec<usize>>,
}
impl VoiceInference for WindowProbe {
    fn embed(&self, samples: &[f32]) -> Result<Vec<f32>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.received.lock().unwrap().push(samples.len());
        assert!(
            samples.iter().any(|sample| sample.abs() > 0.05),
            "the embedded window must be the spoken half, not the quiet opening"
        );
        let mut embedding = vec![0.; 256];
        embedding[1] = 1.;
        Ok(embedding)
    }
}

#[tokio::test]
async fn voice_worker_embeds_the_spoken_window_of_a_long_turn_and_records_the_span() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = Arc::new(PostgresPersistence::with_pool(
        fixture.persistence.pool().clone(),
    ));
    let account = "voice-worker-long-turn";
    seed_voice_observation(&repo, account, "session", "long", 1, 1).await;
    repo.set_voice_identity_cohort(VoiceCohort::All, &[])
        .await
        .unwrap();
    // One sixty-second turn: a near-silent opening, then speech-like bursts
    // with pauses at a quiet-room level. The first thirty seconds alone would
    // have quarantined; the worker must find the spoken half.
    let rate = 16_000_usize;
    let samples = (0..60 * rate)
        .map(|i| {
            if i < 30 * rate {
                (i as f32 / 17.).sin() * 0.0005
            } else if (i / (rate / 4)) % 3 != 2 {
                (i as f32 / 17.).sin() * 0.2
            } else {
                (i as f32 / 23.).sin() * 0.001
            }
        })
        .collect::<Vec<_>>();
    let wav = encode_mono_16khz_wav(&samples).unwrap();
    let kms = FakeKms::new();
    let gcs = Arc::new(FakeGcs::new());
    let object = format!("raw/{account}/long.enc");
    let dek = Dek::generate();
    let wrapped = kms.wrap_dek(&dek.0).await.unwrap();
    let encrypted = encrypt_bound_blob(&dek, &wav, &media_blob_context(account, &object)).unwrap();
    let generation = gcs
        .put_object(&object, &encrypted, &wrapped, 0)
        .await
        .unwrap();
    sqlx::query("UPDATE media_objects SET byte_length=$2,sha256=$3,object_generation=$4 WHERE account_id=$1")
        .bind(account).bind(wav.len() as i64).bind(format!("{:x}",Sha256::digest(&wav))).bind(generation).execute(repo.pool()).await.unwrap();
    sqlx::query(
        "UPDATE capture_events SET ended_at=started_at+interval '60 seconds' WHERE account_id=$1",
    )
    .bind(account)
    .execute(repo.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE speaker_observations SET ended_at=started_at+interval '60 seconds' WHERE account_id=$1")
        .bind(account).execute(repo.pool()).await.unwrap();
    sqlx::query("UPDATE speaker_observation_sources SET window_end_ms=60000,event_end_ms=60000 WHERE account_id=$1")
        .bind(account).execute(repo.pool()).await.unwrap();
    let repositories = RepositorySet::postgres(
        Arc::clone(&repo),
        Arc::new(GcsMediaObjectStore::new(gcs.clone())),
    );
    let claim = repo
        .claim_voice_embeddings(account, "test-worker")
        .await
        .unwrap()
        .claims
        .remove(0);
    let engine = Arc::new(WindowProbe {
        calls: AtomicUsize::new(0),
        received: std::sync::Mutex::new(Vec::new()),
    });
    let mut cache = DecodedCache::new();
    let outcome = infer_claim(&repositories, &kms, engine.clone(), &claim, &mut cache)
        .await
        .unwrap();
    match &outcome {
        VoiceEmbeddingOutcome::Sample { diagnostics, .. } => {
            assert_eq!(
                diagnostics.decision,
                crate::cp::voice_quality::SampleDecision::Enroll
            );
            assert_eq!(diagnostics.span_offset_ms, 30_000);
            assert_eq!(diagnostics.turn_duration_ms, 60_000);
            assert_eq!(diagnostics.duration_ms, 30_000);
            assert_eq!(
                diagnostics.detector_version,
                crate::cp::voice_quality::DETECTOR_VERSION
            );
        }
        VoiceEmbeddingOutcome::NoEmbedding { .. } => panic!("long turn must yield a sample"),
        VoiceEmbeddingOutcome::RawMediaExpired | VoiceEmbeddingOutcome::Retry => {
            panic!("long turn media is retained and inference must not be deferred")
        }
    }
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *engine.received.lock().unwrap(),
        vec![30 * rate],
        "the model receives exactly the thirty-second bound"
    );
    assert!(repo.settle_voice_embedding(&claim, outcome).await.unwrap());
    let stored: (i64, i64, i64, bool) = sqlx::query_as(
        "SELECT (diagnostics->>'span_offset_ms')::bigint,(diagnostics->>'turn_duration_ms')::bigint, \
                (diagnostics->>'detector_version')::bigint,accepted \
           FROM voice_samples WHERE account_id=$1",
    )
    .bind(account)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    assert_eq!(
        stored,
        (
            30_000,
            60_000,
            crate::cp::voice_quality::DETECTOR_VERSION,
            true
        ),
        "the chosen span and detector are durable diagnostics"
    );
    repo.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
}
