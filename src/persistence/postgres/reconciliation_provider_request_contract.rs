//! Real PostgreSQL contract for the organizer's frozen provider request.
//!
//! Speaker identity changes presentation, never the source, so a name accepted
//! between two tries of one durable attempt re-renders a different model input
//! under an unchanged source fingerprint and attempt identity. The usage
//! ledger keys its row by that attempt identity and refuses different request
//! bytes forever; the reconciler used to treat that refusal as a same-attempt
//! retry, so the account's lane wedged. The first try now freezes the exact
//! request and every later try of the attempt replays it.
use super::{
    speaker_writer_contract::{cleanup, form_capture},
    tests::test_persistence,
    PostgresPersistence,
};
use crate::cp::reconciler::{
    test_reconciliation_provider_commitments_for_input, test_render_model_input,
};
use crate::cp::vertex::VertexOperation;
use crate::error::EnclaveError;
use crate::persistence::{
    identity_presentation::AuthoredLabelMap, vertex_attempt_event_id,
    FrozenReconciliationProviderRequest, MemoryReconciliationRepository, ModelUsageRepository,
    ReconciliationClaim, ReconciliationProviderRequest, ReconciliationPublish,
    ReconciliationPublishResult, ReconciliationSnapshot, VertexInvocationAdmission,
    RECONCILIATION_PROVIDER_REQUEST_CONTRACT_VERSION, RECONCILIATION_PROVIDER_REQUEST_MAX_BYTES,
};

const QUIET_HORIZON_SECONDS: i64 = 4 * 60 * 60;

fn request(
    user_message: String,
    authored_labels: AuthoredLabelMap,
) -> ReconciliationProviderRequest {
    ReconciliationProviderRequest {
        contract_version: RECONCILIATION_PROVIDER_REQUEST_CONTRACT_VERSION,
        authored_labels,
        user_message,
    }
}

async fn seed_account(repo: &PostgresPersistence, account: &str) {
    sqlx::query("INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES($1,'synthetic@example.test','google',$1)")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    super::activation::test_activate_speaker_writer_account(repo, account)
        .await
        .unwrap();
    form_capture(repo, account, 1).await;
}

async fn cohort(repo: &PostgresPersistence, account: &str) -> ReconciliationSnapshot {
    repo.next_source_settled_cohort(account, QUIET_HORIZON_SECONDS, None, 32, 1000)
        .await
        .unwrap()
        .expect("synthetic reconciliation source-settled cohort")
}

async fn claim(
    repo: &PostgresPersistence,
    snapshot: &ReconciliationSnapshot,
) -> ReconciliationClaim {
    repo.claim_reconciliation(snapshot, 900)
        .await
        .unwrap()
        .expect("synthetic reconciliation claim")
}

async fn freeze(
    repo: &PostgresPersistence,
    claim: &ReconciliationClaim,
    current: Option<&ReconciliationProviderRequest>,
) -> FrozenReconciliationProviderRequest {
    repo.freeze_reconciliation_provider_request(claim, current)
        .await
        .unwrap()
        .expect("a frozen request")
}

/// An accepted person name: presentation advances while the raw source,
/// its fingerprint and the topology commitment stay exactly where they were.
async fn name_the_speaker(repo: &PostgresPersistence, account: &str) {
    sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,1,'Synthetic Name','identified')")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE speaker_clusters SET person_id=1,attribution_state='person_bound' WHERE account_id=$1 AND id=1")
        .bind(account)
        .execute(repo.pool())
        .await
        .unwrap();
}

async fn frozen_row(repo: &PostgresPersistence, account: &str) -> Option<(Vec<u8>, String)> {
    sqlx::query_as(
        "SELECT provider_attempt_identity,provider_request FROM reconciliation_provider_requests \
          WHERE account_id=$1",
    )
    .bind(account)
    .fetch_optional(repo.pool())
    .await
    .unwrap()
}

async fn usage_outcome(repo: &PostgresPersistence, account: &str, event_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT outcome FROM vertex_usage_events WHERE account_id=$1 AND event_id=$2",
    )
    .bind(account)
    .bind(event_id)
    .fetch_one(repo.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn reconciliation_provider_request_is_frozen_by_the_first_try_and_replayed_after_a_label_change(
) {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "provider-request-freeze";
    seed_account(repo, ACCOUNT).await;

    let before = cohort(repo, ACCOUNT).await;
    assert!(
        before.atoms[0].context.starts_with("[Speaker A]"),
        "the anonymous voice renders with its lettered slot: {}",
        before.atoms[0].context
    );
    let first_claim = claim(repo, &before).await;
    let first_input = test_render_model_input(&before).unwrap();
    let (attempt, first_anchor, first_fingerprint) =
        test_reconciliation_provider_commitments_for_input(&first_input, &first_claim).unwrap();
    assert!(
        repo.freeze_reconciliation_provider_request(&first_claim, None)
            .await
            .unwrap()
            .is_none(),
        "nothing is frozen before the first try renders"
    );

    // Try 1: freeze the rendering, then let the ledger admit the attempt with
    // exactly those bytes. Ownership is then lost (crash, lost egress guard,
    // failed stage) before the request reaches the provider.
    let frozen = freeze(
        repo,
        &first_claim,
        Some(&request(
            first_input.clone(),
            before.authored_labels.clone(),
        )),
    )
    .await;
    assert!(
        !frozen.replayed,
        "the first try of an attempt freezes its own rendering"
    );
    assert_eq!(frozen.request.user_message, first_input);
    assert_eq!(frozen.request.authored_labels, before.authored_labels);
    let admitted = repo
        .begin_invocation_attempt(
            ACCOUNT,
            VertexOperation::EpisodeReconciliation,
            &first_claim.reconciliation_model,
            &first_claim.vertex_location,
            &first_anchor,
            &attempt,
        )
        .await
        .unwrap();
    assert_eq!(admitted.admission, VertexInvocationAdmission::Send);
    assert_eq!(admitted.event_id, vertex_attempt_event_id(&attempt));
    assert_eq!(
        usage_outcome(repo, ACCOUNT, &admitted.event_id).await,
        "started"
    );

    // Between the tries a person is named. Presentation moves; the source
    // fingerprint, the topology commitment, the job and therefore the attempt
    // identity do not, so the retry is a second try of the same attempt.
    name_the_speaker(repo, ACCOUNT).await;
    let after = cohort(repo, ACCOUNT).await;
    assert_eq!(after.source_fingerprint, before.source_fingerprint);
    assert_eq!(after.topology_fingerprint, before.topology_fingerprint);
    assert!(
        after.atoms[0].context.starts_with("[Synthetic Name]"),
        "the accepted name is now the presented label: {}",
        after.atoms[0].context
    );
    let second_input = test_render_model_input(&after).unwrap();
    assert_ne!(second_input, first_input, "the re-rendered body differs");
    let (second_attempt, second_anchor, _) =
        test_reconciliation_provider_commitments_for_input(&second_input, &first_claim).unwrap();
    assert_eq!(
        second_attempt, attempt,
        "a presentation-only change must not move the durable attempt identity"
    );
    assert_ne!(second_anchor, first_anchor);

    // The hazard: the re-rendered body under the unchanged attempt identity is
    // refused by the ledger, and would be refused again on every later try.
    // A build that re-rendered on retry mapped this to a same-attempt retry
    // and wedged the account's reconciliation lane.
    let refused = repo
        .begin_invocation_attempt(
            ACCOUNT,
            VertexOperation::EpisodeReconciliation,
            &first_claim.reconciliation_model,
            &first_claim.vertex_location,
            &second_anchor,
            &attempt,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&refused, EnclaveError::Conflict(message)
            if message.contains("reused with different input")),
        "the ledger must refuse a different body under an admitted attempt: {refused}"
    );
    // Re-entry of a started attempt means its owner was lost, whatever bytes
    // the re-entrant carries; the stored attempt stays reachable by identity
    // so an owner can settle against it without recovering the body.
    assert_eq!(
        usage_outcome(repo, ACCOUNT, &admitted.event_id).await,
        "ambiguous"
    );
    let stored = repo
        .durable_attempt_provenance(ACCOUNT, &attempt)
        .await
        .unwrap()
        .expect("the admitted attempt is reported");
    assert_eq!(stored.event_id, admitted.event_id);
    assert_eq!(stored.request_fingerprint, first_fingerprint);
    assert_eq!(stored.outcome, "ambiguous");
    assert!(
        repo.durable_attempt_provenance(ACCOUNT, &[0x5b; 32])
            .await
            .unwrap()
            .is_none(),
        "an identity the ledger never admitted has no provenance"
    );

    // The fix: the retry re-claims the same job (lease lost, same model
    // attempt) and receives the frozen bytes instead of its own rendering.
    repo.release_reconciliation(&first_claim, Some(0), "provider_preflight", false, false)
        .await
        .unwrap();
    assert!(
        frozen_row(repo, ACCOUNT).await.is_some(),
        "a same-attempt release keeps the frozen request for the retry"
    );
    let second_claim = claim(repo, &after).await;
    assert_eq!(
        second_claim.model_attempt_count,
        first_claim.model_attempt_count
    );
    assert_eq!(second_claim.attempt_count, first_claim.attempt_count + 1);
    let replay = freeze(
        repo,
        &second_claim,
        Some(&request(
            second_input.clone(),
            after.authored_labels.clone(),
        )),
    )
    .await;
    assert!(
        replay.replayed,
        "a later try of the same attempt replays the frozen request"
    );
    assert_eq!(replay.request.user_message, first_input);
    assert_eq!(
        replay.request.authored_labels, before.authored_labels,
        "the namespace the model was shown travels with the frozen request"
    );
    assert_eq!(
        freeze(repo, &second_claim, None).await,
        replay,
        "a try whose own rendering is refused still replays the frozen request"
    );
    let (replay_attempt, replay_anchor, replay_fingerprint) =
        test_reconciliation_provider_commitments_for_input(
            &replay.request.user_message,
            &second_claim,
        )
        .unwrap();
    assert_eq!(replay_attempt, attempt);
    assert_eq!(replay_anchor, first_anchor);
    assert_eq!(replay_fingerprint, first_fingerprint);
    let replayed = repo
        .begin_invocation_attempt(
            ACCOUNT,
            VertexOperation::EpisodeReconciliation,
            &second_claim.reconciliation_model,
            &second_claim.vertex_location,
            &replay_anchor,
            &attempt,
        )
        .await
        .unwrap();
    assert_eq!(
        replayed.admission,
        VertexInvocationAdmission::AmbiguousTerminal,
        "the ledger's own replay rule applies: a started attempt whose owner was lost is terminal"
    );

    // That terminal outcome stages the conservative-ambiguity result with the
    // stored attempt's provenance and publishes; the frozen plaintext leaves
    // with the completed job.
    let stored_fingerprint: [u8; 32] = stored
        .request_fingerprint
        .as_slice()
        .try_into()
        .expect("stored fingerprint is a digest");
    let guard = repo
        .acquire_provider_egress_guard(&second_claim)
        .await
        .unwrap()
        .expect("signed reconciliation egress guard");
    let staged = guard
        .stage_and_release(
            super::memory_reconciliation::test_provider_stage_write_with_provenance(
                &after,
                "frozen-request",
                "conservative-ambiguity-v1",
                &stored.event_id,
                &attempt,
                &stored_fingerprint,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let published = repo
        .publish_reconciliation(ReconciliationPublish {
            claim: second_claim,
            reconciliation_id: format!("frozen-request-{ACCOUNT}"),
            cohort_started_at: after.cohort_started_at.clone(),
            cohort_ended_at: after.cohort_ended_at.clone(),
            result_commitment: staged.result_commitment,
        })
        .await
        .unwrap();
    assert!(matches!(
        published,
        ReconciliationPublishResult::Published { .. }
    ));
    assert!(
        frozen_row(repo, ACCOUNT).await.is_none(),
        "completed reconciliation history keeps no frozen model input"
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn reconciliation_provider_request_follows_the_attempt_identity_and_the_claim() {
    let Some(fixture) = test_persistence().await else {
        return;
    };
    let repo = &fixture.persistence;
    const ACCOUNT: &str = "provider-request-attempts";
    seed_account(repo, ACCOUNT).await;
    let snapshot = cohort(repo, ACCOUNT).await;
    let input = test_render_model_input(&snapshot).unwrap();
    let first_claim = claim(repo, &snapshot).await;

    // Bounds and contract are checked before anything is written.
    let oversized = request(
        "x".repeat(RECONCILIATION_PROVIDER_REQUEST_MAX_BYTES),
        Default::default(),
    );
    assert!(matches!(
        repo.freeze_reconciliation_provider_request(&first_claim, Some(&oversized))
            .await
            .unwrap_err(),
        EnclaveError::InvalidRequest(_)
    ));
    let mut wrong_contract = request(input.clone(), Default::default());
    wrong_contract.contract_version = 0;
    assert!(matches!(
        repo.freeze_reconciliation_provider_request(&first_claim, Some(&wrong_contract))
            .await
            .unwrap_err(),
        EnclaveError::InvalidRequest(_)
    ));
    assert!(frozen_row(repo, ACCOUNT).await.is_none());

    // Only the live claim may freeze or replay.
    let mut foreign = first_claim.clone();
    foreign.claim_token = "not-the-claim".into();
    for current in [
        Some(request(input.clone(), snapshot.authored_labels.clone())),
        None,
    ] {
        assert!(matches!(
            repo.freeze_reconciliation_provider_request(&foreign, current.as_ref())
                .await
                .unwrap_err(),
            EnclaveError::Conflict(_)
        ));
    }
    assert!(frozen_row(repo, ACCOUNT).await.is_none());

    let frozen = freeze(
        repo,
        &first_claim,
        Some(&request(input.clone(), snapshot.authored_labels.clone())),
    )
    .await;
    assert!(!frozen.replayed);
    let (first_attempt, _, _) =
        test_reconciliation_provider_commitments_for_input(&input, &first_claim).unwrap();
    let stored = frozen_row(repo, ACCOUNT).await.expect("frozen request row");
    assert_eq!(
        stored.0, first_attempt,
        "the row is bound to the claim's attempt identity"
    );

    // Tampered stored bytes fail closed instead of being replayed.
    sqlx::query("UPDATE reconciliation_provider_requests SET provider_request=provider_request||' ' WHERE account_id=$1")
        .bind(ACCOUNT)
        .execute(repo.pool())
        .await
        .unwrap();
    for current in [
        Some(request(input.clone(), snapshot.authored_labels.clone())),
        None,
    ] {
        assert!(matches!(
            repo.freeze_reconciliation_provider_request(&first_claim, current.as_ref())
                .await
                .unwrap_err(),
            EnclaveError::Store(_)
        ));
    }
    sqlx::query(
        "UPDATE reconciliation_provider_requests SET provider_request=$2 WHERE account_id=$1",
    )
    .bind(ACCOUNT)
    .bind(&stored.1)
    .execute(repo.pool())
    .await
    .unwrap();

    // A consumed model attempt discards the frozen request: the next attempt
    // identity has no ledger row, so it renders and freezes afresh.
    repo.release_reconciliation(&first_claim, Some(0), "provider_not_billed", false, true)
        .await
        .unwrap();
    assert!(
        frozen_row(repo, ACCOUNT).await.is_none(),
        "advancing the model attempt must discard the frozen request"
    );
    let second_claim = claim(repo, &snapshot).await;
    assert_eq!(
        second_claim.model_attempt_count,
        first_claim.model_attempt_count + 1
    );
    let renewed_input = format!("{input} ");
    let renewed = freeze(
        repo,
        &second_claim,
        Some(&request(
            renewed_input.clone(),
            snapshot.authored_labels.clone(),
        )),
    )
    .await;
    assert!(!renewed.replayed);
    assert_eq!(renewed.request.user_message, renewed_input);
    let (second_attempt, _, _) =
        test_reconciliation_provider_commitments_for_input(&renewed_input, &second_claim).unwrap();
    assert_ne!(second_attempt, first_attempt);
    assert_eq!(frozen_row(repo, ACCOUNT).await.unwrap().0, second_attempt);

    // A stored request for a stale attempt identity is never replayed: it is
    // replaced by the next rendering, and a try without one gets nothing.
    sqlx::query("UPDATE reconciliation_provider_requests SET provider_attempt_identity=$2 WHERE account_id=$1")
        .bind(ACCOUNT)
        .bind(first_attempt.as_slice())
        .execute(repo.pool())
        .await
        .unwrap();
    assert!(repo
        .freeze_reconciliation_provider_request(&second_claim, None)
        .await
        .unwrap()
        .is_none());
    let replaced = freeze(
        repo,
        &second_claim,
        Some(&request(input.clone(), snapshot.authored_labels.clone())),
    )
    .await;
    assert!(!replaced.replayed);
    assert_eq!(replaced.request.user_message, input);
    assert_eq!(frozen_row(repo, ACCOUNT).await.unwrap().0, second_attempt);

    // An intact row under a request contract this build cannot read is
    // replaced (never refused on every try) once a rendering exists; a try
    // without one gets nothing rather than an unreadable request.
    let unreadable = r#"{"contract_version":0,"user_message":"superseded"}"#;
    sqlx::query("UPDATE reconciliation_provider_requests SET provider_request=$2,provider_request_sha256=sha256(convert_to($2,'UTF8')) WHERE account_id=$1")
        .bind(ACCOUNT)
        .bind(unreadable)
        .execute(repo.pool())
        .await
        .unwrap();
    assert!(repo
        .freeze_reconciliation_provider_request(&second_claim, None)
        .await
        .unwrap()
        .is_none());
    let readable = freeze(
        repo,
        &second_claim,
        Some(&request(
            renewed_input.clone(),
            snapshot.authored_labels.clone(),
        )),
    )
    .await;
    assert!(!readable.replayed);
    assert_eq!(readable.request.user_message, renewed_input);
    assert!(
        freeze(
            repo,
            &second_claim,
            Some(&request(input.clone(), snapshot.authored_labels.clone())),
        )
        .await
        .replayed,
        "the replacement is the frozen request from now on"
    );

    // A claim whose model attempt the job has moved past can neither freeze
    // nor replay.
    sqlx::query("UPDATE memory_reconciliation_jobs SET model_attempt_count=model_attempt_count+1 WHERE account_id=$1")
        .bind(ACCOUNT)
        .execute(repo.pool())
        .await
        .unwrap();
    for current in [
        Some(request(input.clone(), snapshot.authored_labels.clone())),
        None,
    ] {
        assert!(matches!(
            repo.freeze_reconciliation_provider_request(&second_claim, current.as_ref())
                .await
                .unwrap_err(),
            EnclaveError::Conflict(_)
        ));
    }
    sqlx::query("UPDATE memory_reconciliation_jobs SET model_attempt_count=model_attempt_count-1 WHERE account_id=$1")
        .bind(ACCOUNT)
        .execute(repo.pool())
        .await
        .unwrap();

    // A terminal release keeps no plaintext working state either.
    repo.release_reconciliation(&second_claim, None, "terminal", true, false)
        .await
        .unwrap();
    assert!(frozen_row(repo, ACCOUNT).await.is_none());
    cleanup(fixture).await;
}
