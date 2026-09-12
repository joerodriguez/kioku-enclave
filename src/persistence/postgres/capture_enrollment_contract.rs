//! Real accepted-capture contracts; no provider or embedding model required.
use super::PostgresPersistence;
use crate::cp::media::{
    manifest_digest, CaptureEnrollmentKind, CaptureEventManifest, RecordingMediaAuthorityDecision,
    StreamKind,
};
use crate::error::Result;
use crate::persistence::{
    CaptureCommit, CaptureCommitResult, CapturePreflight, CaptureRepository, CaptureUploadIdentity,
    ReferenceBatchCommit, VoiceEnrollmentReason, VoiceEnrollmentState,
};
use sqlx::Row;

fn manifest(session: &str, event: &str, sequence: i64, marked: bool) -> CaptureEventManifest {
    let mut value: CaptureEventManifest = serde_json::from_value(serde_json::json!({
        "schema_version":2,"event_id":event,"device_id":"device","install_id":"install","capture_session_id":session,"stream_id":format!("stream-{session}"),"stream_kind":"mic","sequence":sequence,
        "source_wall_at":"2026-09-01T12:00:00Z","source_monotonic_ns":0,"started_at":"2026-09-01T12:00:00Z","ended_at":"2026-09-01T12:00:04Z","timezone_id":"UTC","utc_offset_minutes":0,"clock_uncertainty_ms":0,
        "media":{"asset_id":event,"mime_type":"audio/wav","codec":"pcm","byte_length":128044,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sample_rate":16000,"channels":1,"frame_count":64000},"context":null,"audio_role":"ambient","audio_route":"builtin_mic"
    })).unwrap();
    value.enrollment = marked.then_some(CaptureEnrollmentKind::OwnerVoice);
    value.enrollment_revision = marked.then_some(0);
    value
}

async fn account(repo: &PostgresPersistence, id: &str) {
    sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,'synthetic@example.test','google',$1)").bind(id).execute(repo.pool()).await.unwrap();
}
async fn commit(
    repo: &PostgresPersistence,
    account: &str,
    manifest: &CaptureEventManifest,
) -> Result<CaptureCommitResult> {
    let digest = manifest_digest(manifest)?;
    let asset = &manifest.media.as_ref().unwrap().asset_id;
    let key = crate::gcs::canonical_capture_media_object_key(account, asset)?;
    let token = repo
        .reserve_media_upload(
            account,
            CaptureUploadIdentity {
                capture_session_id: &manifest.capture_session_id,
                stream_id: &manifest.stream_id,
                event_id: &manifest.event_id,
                asset_id: asset,
            },
            &key,
            &digest,
        )
        .await?;
    repo.commit_event(CaptureCommit {
        account_id: account.into(),
        manifest: manifest.clone(),
        manifest_digest: digest,
        object_key: Some(key),
        object_generation: Some(1),
        upload_token: token,
        media_authority: Some(RecordingMediaAuthorityDecision::ProcessingWindow30d {
            capture_policy_revision: 0,
            decision_at: "2026-09-01T12:00:05Z".into(),
        }),
        committed_at: "2026-09-01T12:00:05Z".into(),
    })
    .await
}
async fn enrollment(
    repo: &PostgresPersistence,
    account: &str,
    session: &str,
) -> Option<(bool, String, Option<String>)> {
    sqlx::query_as("SELECT designated,state,reason FROM voice_enrollment_sessions WHERE account_id=$1 AND capture_session_id=$2").bind(account).bind(session).fetch_optional(repo.pool()).await.unwrap()
}

#[tokio::test]
async fn enrollment_capture_first_acceptance_beats_sequence_and_preflight_and_replay() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let a = "enrollment-first";
    account(repo, a).await;
    let marked = manifest("session", "marked", 0, true);
    assert_eq!(
        repo.preflight_event(a, &marked, &manifest_digest(&marked).unwrap(), None)
            .await
            .unwrap(),
        CapturePreflight::New
    );
    assert!(
        enrollment(repo, a, "session").await.is_none(),
        "preflight must not designate an unaccepted enrollment"
    );
    let ordinary = manifest("session", "ordinary", 1, false);
    assert_eq!(
        commit(repo, a, &ordinary)
            .await
            .unwrap()
            .committed_through_sequence,
        -1
    );
    assert_eq!(
        commit(repo, a, &marked)
            .await
            .unwrap()
            .committed_through_sequence,
        1
    );
    assert_eq!(
        enrollment(repo, a, "session").await,
        Some((
            false,
            "inconclusive".into(),
            Some("marker_after_ordinary_start".into())
        )),
        "the first accepted event fixes designation even when a lower sequence arrives later"
    );
    let before: String = sqlx::query_scalar(
        "SELECT to_jsonb(s)::text FROM voice_enrollment_sessions s WHERE account_id=$1",
    )
    .bind(a)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    assert!(commit(repo, a, &marked).await.unwrap().duplicate);
    let after: String = sqlx::query_scalar(
        "SELECT to_jsonb(s)::text FROM voice_enrollment_sessions s WHERE account_id=$1",
    )
    .bind(a)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    assert_eq!(
        before, after,
        "exact capture replay must not mutate enrollment metadata"
    );
    let mut changed = marked.clone();
    changed.enrollment_revision = Some(1);
    assert!(
        commit(repo, a, &changed).await.is_err(),
        "an accepted event cannot change enrollment revision on replay"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn enrollment_capture_withdrawal_fences_offline_missing_stale_and_expired_inputs() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let a = "enrollment-revision";
    account(repo, a).await;
    sqlx::query("UPDATE accounts SET enrollment_revision=1 WHERE id=$1")
        .bind(a)
        .execute(repo.pool())
        .await
        .unwrap();
    for (session, revision) in [
        ("missing", None),
        ("stale", Some(0)),
        ("negative", Some(-1)),
    ] {
        let mut event = manifest(session, session, 0, true);
        event.enrollment_revision = revision;
        assert_eq!(
            commit(repo, a, &event)
                .await
                .unwrap()
                .committed_through_sequence,
            0
        );
        assert_eq!(
            enrollment(repo, a, session).await.unwrap().2.as_deref(),
            Some("enrollment_revoked"),
            "an offline first upload cannot cross the account withdrawal revision"
        );
    }
    let mut current = manifest("current", "current", 0, true);
    current.enrollment_revision = Some(1);
    commit(repo, a, &current).await.unwrap();
    assert_eq!(enrollment(repo, a, "current").await.unwrap().1, "recording");
    sqlx::query("UPDATE voice_enrollment_sessions SET state='expired',reason='forgotten' WHERE account_id=$1 AND capture_session_id='current'").bind(a).execute(repo.pool()).await.unwrap();
    let mut queued = manifest("current", "queued", 1, true);
    queued.enrollment_revision = Some(1);
    commit(repo, a, &queued).await.unwrap();
    assert_eq!(
        enrollment(repo, a, "current").await.unwrap().1,
        "expired",
        "queued events cannot revive an expired accepted enrollment session"
    );
    assert!(repo
        .session_status("another-account", "current", None)
        .await
        .unwrap()
        .is_none());
    let status = repo
        .session_status(a, "current", None)
        .await
        .unwrap()
        .unwrap();
    let detail = status.enrollment.unwrap();
    assert_eq!(detail.state, VoiceEnrollmentState::Expired);
    assert_eq!(detail.reason, Some(VoiceEnrollmentReason::Forgotten));
    let json = serde_json::to_value(detail).unwrap();
    assert_eq!(
        json.as_object().unwrap().len(),
        3,
        "session enrollment exposes only state, reason and domain"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn enrollment_capture_violations_keep_audio_and_preserve_stream_identity() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let a = "enrollment-violations";
    account(repo, a).await;
    for (session, reason) in [
        ("marker", "marker_missing"),
        ("stream", "multiple_streams"),
        ("device", "multiple_devices"),
        ("route", "route_changed"),
    ] {
        let first = manifest(session, &format!("{session}-first"), 0, true);
        commit(repo, a, &first).await.unwrap();
        let mut next = manifest(session, &format!("{session}-next"), 1, true);
        match session {
            "marker" => {
                next.enrollment = None;
                next.enrollment_revision = None;
            }
            "stream" => {
                next.stream_id = "other-stream".into();
                next.sequence = 0;
            }
            "device" => {
                next.device_id = "other-device".into();
                next.install_id = "other-install".into();
                next.stream_id = "other-device-stream".into();
                next.sequence = 0;
            }
            _ => next.audio_route = Some("wired_headset".into()),
        }
        assert!(
            !commit(repo, a, &next).await.unwrap().duplicate,
            "enrollment violations must still accept otherwise valid ordinary audio"
        );
        assert_eq!(
            enrollment(repo, a, session).await.unwrap().2.as_deref(),
            Some(reason),
            "accepted violation must permanently make that enrollment inconclusive"
        );
        let mut further = manifest(session, &format!("{session}-further"), 2, true);
        assert!(commit(repo, a, &further).await.is_ok());
        assert_eq!(
            enrollment(repo, a, session).await.unwrap().2.as_deref(),
            Some(reason),
            "later marked audio must not heal a session violation"
        );
        further.event_id = format!("{session}-wrong-device");
        further.media.as_mut().unwrap().asset_id = further.event_id.clone();
        further.device_id = "third-device".into();
        further.sequence = 3;
        assert!(
            commit(repo, a, &further).await.is_err(),
            "the enrollment exception must not reuse an existing stream across devices"
        );
    }
    let mut unsupported = manifest("unsupported", "unsupported", 0, true);
    unsupported.stream_kind = StreamKind::SystemAudio;
    commit(repo, a, &unsupported).await.unwrap();
    assert_eq!(
        enrollment(repo, a, "unsupported")
            .await
            .unwrap()
            .2
            .as_deref(),
        Some("unsupported_stream")
    );
    let ordinary = manifest("ordinary", "ordinary", 0, false);
    commit(repo, a, &ordinary).await.unwrap();
    let mut wrong = manifest("ordinary", "ordinary-wrong", 0, false);
    wrong.stream_id = "wrong-stream".into();
    wrong.device_id = "wrong-device".into();
    assert!(
        commit(repo, a, &wrong).await.is_err(),
        "ordinary sessions keep their existing device scope"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn enrollment_capture_late_earlier_source_rebases_one_window_and_invalidates_decision() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let a = "enrollment-timeline";
    account(repo, a).await;
    let mut late = manifest("session", "later", 1, true);
    late.started_at = "2026-09-01T12:01:00Z".into();
    late.ended_at = "2026-09-01T12:01:04Z".into();
    commit(repo, a, &late).await.unwrap();
    sqlx::query("UPDATE voice_enrollment_sessions SET state='enrolled',source_revision=7,seal_generation=0,dominant_share=1,accepted_sample_count=1 WHERE account_id=$1").bind(a).execute(repo.pool()).await.unwrap();
    let earlier = manifest("session", "earlier", 0, true);
    commit(repo, a, &earlier).await.unwrap();
    let row=sqlx::query("SELECT state,source_revision,dominant_share,accepted_sample_count,extract(epoch FROM (timeline_cutoff_at-timeline_started_at))::bigint AS duration,timeline_started_at='2026-09-01T12:00:00Z'::timestamptz AS correct_start FROM voice_enrollment_sessions WHERE account_id=$1").bind(a).fetch_one(repo.pool()).await.unwrap();
    assert!(row.get::<bool, _>("correct_start"));
    assert_eq!(
        row.get::<i64, _>("duration"),
        180,
        "late earlier input must rebase one 180-second enrollment window"
    );
    assert_eq!(
        row.get::<String, _>("state"),
        "recording",
        "new accepted source invalidates enrollment even before final seal"
    );
    assert!(row.get::<Option<i64>, _>("source_revision").is_none());
    assert!(row.get::<Option<f64>, _>("dominant_share").is_none());
    assert_eq!(row.get::<i64, _>("accepted_sample_count"), 0);
    cleanup(fixture).await;
}

#[tokio::test]
async fn enrollment_capture_reference_batch_rechecks_designation_inside_commit() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let a = "enrollment-batch";
    account(repo, a).await;
    repo.preflight_reference_batch_enrollment(a, "session")
        .await
        .unwrap();
    let event = manifest("session", "audio", 0, true);
    commit(repo, a, &event).await.unwrap();
    assert!(
        repo.preflight_reference_batch_enrollment(a, "session")
            .await
            .is_err(),
        "batch preflight must refuse an already-designated enrollment session"
    );
    // Simulate designation winning between the HTTP preflight and atomic commit.
    let mut reference = event.clone();
    reference.event_id = "screen".into();
    reference.stream_id = "screen-stream".into();
    reference.stream_kind = StreamKind::MacScreen;
    reference.enrollment = None;
    reference.enrollment_revision = None;
    let error = repo
        .commit_reference_batch(ReferenceBatchCommit {
            account_id: a.into(),
            events: vec![reference.clone()],
            manifest_digests: vec![manifest_digest(&reference).unwrap()],
            committed_at: "2026-09-01T12:00:06Z".into(),
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("do not admit voice enrollment sessions"),
        "atomic batch commit must recheck enrollment before inserting any item"
    );
    assert!(repo.event_status(a, "screen").await.unwrap().is_none());
    assert_eq!(
        repo.stream_ack(a, &event.stream_id).await.unwrap(),
        0,
        "batch refusal must preserve the audio acknowledgement"
    );
    assert_eq!(enrollment(repo, a, "session").await.unwrap().1, "recording");
    cleanup(fixture).await;
}

#[tokio::test]
async fn enrollment_capture_concurrent_first_events_and_deleted_replay_keep_one_designation() {
    let Some(fixture) = super::tests::test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    let a = "enrollment-concurrent";
    account(repo, a).await;
    repo.install_memory_reconciliation_activation_schema()
        .await
        .unwrap();
    let marked = manifest("session", "marked", 0, true);
    let ordinary = manifest("session", "ordinary", 1, false);
    let (one, two) = tokio::join!(commit(repo, a, &marked), commit(repo, a, &ordinary));
    one.unwrap();
    two.unwrap();
    let state = enrollment(repo, a, "session").await.unwrap();
    assert!(matches!((state.0,state.2.as_deref()),(true,Some("marker_missing")) | (false,Some("marker_after_ordinary_start"))),"racing first events must serialize into one immutable designation with a truthful violation");
    assert_eq!(repo.stream_ack(a, &marked.stream_id).await.unwrap(), 1);
    sqlx::query("INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) VALUES($1,1,'pending','{}','[]','[]','[]','[]','[\"marked\"]')")
        .bind(a).execute(repo.pool()).await.unwrap();
    sqlx::query("INSERT INTO capture_formation_deleted_sequences(account_id,capture_session_id,stream_id,sequence,event_id,original_manifest_digest,deletion_episode_id,provenance) VALUES($1,'session',$2,0,'marked',$3,1,'episode_deletion_v1')")
        .bind(a).bind(&marked.stream_id).bind(manifest_digest(&marked).unwrap()).execute(repo.pool()).await.unwrap();
    sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id='marked'")
        .bind(a)
        .execute(repo.pool())
        .await
        .unwrap();
    let before: String = sqlx::query_scalar(
        "SELECT to_jsonb(s)::text FROM voice_enrollment_sessions s WHERE account_id=$1",
    )
    .bind(a)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    assert!(commit(repo, a, &marked).await.unwrap().duplicate);
    let after: String = sqlx::query_scalar(
        "SELECT to_jsonb(s)::text FROM voice_enrollment_sessions s WHERE account_id=$1",
    )
    .bind(a)
    .fetch_one(repo.pool())
    .await
    .unwrap();
    assert_eq!(
        before, after,
        "deleted-event replay must leave the durable enrollment decision unchanged"
    );
    assert!(
        repo.event_status(a, "marked").await.unwrap().is_none(),
        "deleted enrollment media must not be recreated by exact replay"
    );
    cleanup(fixture).await;
}

async fn cleanup(fixture: super::tests::ControlPlaneContractFixture) {
    fixture.persistence.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA {} CASCADE",
        fixture.schema
    )))
    .execute(fixture.base.pool())
    .await
    .unwrap();
    fixture.base.pool().close().await;
}
