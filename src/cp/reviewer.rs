//! Idempotent, synthetic archive for the single plugin-review identity.
//!
//! The fixture is created only after Google Identity Platform verifies the
//! exact image-baked reviewer UID and email. It lives in the same encrypted,
//! per-user SQLite blob as ordinary Kioku data and contains no real user data.

pub(crate) mod wal;

use std::sync::Arc;

use crate::{error::Result, store::Store};

const FIXTURE_MARKER: &str = "openai-review-fixture-v1";

pub async fn ensure_demo_archive(store: &Arc<Store>, user_id: &str) -> Result<bool> {
    if store.is_wal_authoritative(user_id) {
        // ADR-0022: the synthetic fixture settles as the sealed
        // ReviewerFixturePlan (which writes the same marker); the probe uses
        // the routed read lane and the settle replays exactly on retry.
        let already_seeded = store
            .wal_authoritative_read(user_id, |conn| {
                Ok(conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM app_metadata WHERE key = ?1)",
                    [FIXTURE_MARKER],
                    |row| row.get::<_, bool>(0),
                )?)
            })
            .await?;
        if already_seeded {
            return Ok(false);
        }
        let prepared = wal::ReviewerFixturePlan::new(user_id.to_owned())
            .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare)
            .map_err(|_| {
                crate::error::EnclaveError::Store(
                    "reviewer fixture plan construction failed".into(),
                )
            })?;
        store.wal_authoritative_submit(user_id, prepared).await?;
        return Ok(true);
    }
    let changed = store
        .with_user(user_id, |conn| {
            let already_seeded: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM app_metadata WHERE key = ?1)",
                [FIXTURE_MARKER],
                |row| row.get(0),
            )?;
            if already_seeded {
                return Ok(false);
            }

            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                r#"
                INSERT OR IGNORE INTO audio_segments
                    (id, started_at, ended_at, duration_seconds, source_type, transcription_status)
                VALUES
                    (910001, '2026-07-22T09:00:00Z', '2026-07-22T09:35:00Z', 2100, 'mic', 'done'),
                    (910002, '2026-07-22T10:15:00Z', '2026-07-22T10:50:00Z', 2100, 'system', 'done'),
                    (910003, '2026-07-22T14:00:00Z', '2026-07-22T15:00:00Z', 3600, 'mic', 'done');

                INSERT OR IGNORE INTO utterances
                    (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text,
                     language, confidence, speaker_label, source_key)
                VALUES
                    (920001, 910001, 90, 104,
                     'We agreed to move the Kioku launch from August 12 to August 19 so QA can finish the release checks.',
                     'en', 0.99, 'Maya', 'review:launch:decision'),
                    (920002, 910001, 118, 134,
                     'Alex owns the launch checklist and will confirm the migration rehearsal by Friday.',
                     'en', 0.99, 'Maya', 'review:launch:action'),
                    (920003, 910002, 240, 263,
                     'The stale dashboard came from a cache invalidation bug: the episode detail key was not cleared after an update.',
                     'en', 0.99, 'Me', 'review:cache:diagnosis'),
                    (920004, 910002, 284, 302,
                     'The fix is to invalidate both the episode list and episode detail cache keys after a successful write.',
                     'en', 0.99, 'Me', 'review:cache:fix'),
                    (920005, 910003, 300, 326,
                     'Use depuis for an action that began in the past and continues now; depuis is followed by the starting point or duration.',
                     'en', 0.99, 'Camille', 'review:french:depuis'),
                    (920006, 910003, 690, 714,
                     'Use pendant for a completed duration. Practice contrasting depuis deux ans with pendant deux ans.',
                     'en', 0.99, 'Camille', 'review:french:pendant');

                INSERT OR IGNORE INTO screenshots
                    (id, captured_at, active_app, window_title, ocr_text, salient_ocr_text,
                     url, image_hash, is_duplicate, source_key)
                VALUES
                    (930001, '2026-07-22T11:20:00Z', 'Google Chrome',
                     'Vendor renewal checklist',
                     'Renewal checklist: review the synthetic agreement at https://example.com/renewal before August 1.',
                     'Renewal checklist at example.com/renewal',
                     'https://example.com/renewal', 'review-synthetic-renewal', 0,
                     'review:screen:renewal');

                INSERT OR IGNORE INTO episodes
                    (id, started_at, ended_at, type, title, summary, participants, languages,
                     action_items, model, minute_summaries, minutes_text, substance,
                     visual_evidence, finalized_at, finalization_version, finalization_status)
                VALUES
                    (940001, '2026-07-22T09:00:00Z', '2026-07-22T09:35:00Z', 'meeting',
                     'Launch planning and QA decision',
                     'The team moved the Kioku launch from August 12 to August 19 so QA could complete release checks. Alex owns the launch checklist.',
                     '["Maya","Alex","Me"]', '["en"]',
                     '["Alex: confirm the migration rehearsal by Friday","Complete the launch checklist before August 19"]',
                     'synthetic-review',
                     '[{"start":"2026-07-22T09:00:00Z","gist":"Reviewed QA readiness."},{"start":"2026-07-22T09:15:00Z","gist":"Moved launch to August 19."},{"start":"2026-07-22T09:30:00Z","gist":"Assigned the checklist to Alex."}]',
                     'Reviewed QA readiness. Moved launch to August 19. Assigned the checklist to Alex.',
                     'normal', 'none', '2026-07-22T16:00:00Z', 3, 'complete'),
                    (940002, '2026-07-22T10:15:00Z', '2026-07-22T10:50:00Z', 'coding',
                     'Dashboard cache invalidation fix',
                     'Diagnosed stale episode details as an invalidation bug and updated the write path to clear list and detail cache keys.',
                     '["Me"]', '["en"]',
                     '["Add a regression test for episode detail invalidation"]',
                     'synthetic-review',
                     '[{"start":"2026-07-22T10:15:00Z","gist":"Reproduced stale dashboard state."},{"start":"2026-07-22T10:30:00Z","gist":"Found the missing detail-key invalidation."},{"start":"2026-07-22T10:45:00Z","gist":"Implemented the fix and planned a regression test."}]',
                     'Reproduced stale dashboard state. Found the missing detail-key invalidation. Implemented the cache fix.',
                     'normal', 'none', '2026-07-22T16:00:00Z', 3, 'complete'),
                    (940003, '2026-07-22T11:18:00Z', '2026-07-22T11:24:00Z', 'browsing',
                     'Vendor renewal page',
                     'Reviewed a synthetic vendor renewal checklist and its example.com renewal link.',
                     '["Me"]', '["en"]', '["Review the renewal checklist before August 1"]',
                     'synthetic-review',
                     '[{"start":"2026-07-22T11:18:00Z","gist":"Opened the vendor renewal checklist."}]',
                     'Opened the vendor renewal checklist at example.com/renewal.',
                     'normal', 'useful', '2026-07-22T16:00:00Z', 3, 'complete'),
                    (940004, '2026-07-22T14:00:00Z', '2026-07-22T15:00:00Z', 'lesson',
                     'French lesson: depuis and pendant',
                     'Practiced the difference between depuis for continuing situations and pendant for completed durations.',
                     '["Camille","Me"]', '["fr","en"]',
                     '["Practice five sentence pairs contrasting depuis and pendant"]',
                     'synthetic-review',
                     '[{"start":"2026-07-22T14:00:00Z","gist":"Reviewed depuis for continuing actions."},{"start":"2026-07-22T14:30:00Z","gist":"Contrasted depuis with pendant."},{"start":"2026-07-22T14:50:00Z","gist":"Assigned five practice sentence pairs."}]',
                     'Reviewed depuis for continuing actions. Contrasted depuis with pendant. Assigned practice.',
                     'normal', 'none', '2026-07-22T16:00:00Z', 3, 'complete');

                INSERT OR IGNORE INTO episode_members (episode_id, record_type, record_id)
                VALUES
                    (940001, 'utterance', 920001),
                    (940001, 'utterance', 920002),
                    (940002, 'utterance', 920003),
                    (940002, 'utterance', 920004),
                    (940003, 'screenshot', 930001),
                    (940004, 'utterance', 920005),
                    (940004, 'utterance', 920006);

                INSERT OR IGNORE INTO episode_final_briefs
                    (episode_id, overview, decisions, action_items, important_links, open_questions)
                VALUES
                    (940001,
                     'The team delayed the Kioku launch by one week to finish QA.',
                     '["Move the launch from August 12 to August 19"]',
                     '[{"owner":"Alex","task":"Confirm the migration rehearsal by Friday"},{"task":"Complete the launch checklist before August 19"}]',
                     '[]',
                     '[]'),
                    (940002,
                     'The stale dashboard was traced to incomplete cache invalidation.',
                     '["Invalidate both episode list and detail keys after writes"]',
                     '[{"owner":"Me","task":"Add a regression test for episode detail invalidation"}]',
                     '[]',
                     '[]'),
                    (940003,
                     'Reviewed the synthetic vendor renewal checklist.',
                     '[]',
                     '[{"owner":"Me","task":"Review the renewal checklist before August 1"}]',
                     '[{"url":"https://example.com/renewal","label":"Synthetic renewal checklist"}]',
                     '[]'),
                    (940004,
                     'Practiced choosing depuis for continuing situations and pendant for completed durations.',
                     '[]',
                     '[{"owner":"Me","task":"Write five sentence pairs contrasting depuis and pendant"}]',
                     '[]',
                     '[]');

                INSERT OR REPLACE INTO device_watermarks (device_id, modality, watermark_at)
                VALUES
                    ('synthetic-review-device', 'audio', '2026-07-22T15:00:00Z'),
                    ('synthetic-review-device', 'screen', '2026-07-22T15:00:00Z');
                "#,
            )?;
            tx.execute(
                "INSERT INTO app_metadata (key, value) VALUES (?1, 'seeded')",
                [FIXTURE_MARKER],
            )?;
            tx.commit()?;
            Ok(true)
        })
        .await?;
    if changed {
        store.save_user(user_id).await?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{FakeGcs, FakeKms};

    /// The G10 gate's user. It never signs in through Google, but its archive
    /// binding is minted by the same `create_active_archive_binding_conn` the
    /// sign-in transaction runs, which is the durable precondition genesis
    /// hangs off.
    const SMOKE_USER: &str = "22222222-2222-4222-8222-222222222222";

    /// Every fixture fact the serving lane can be asked for, read through the
    /// routed WAL-authoritative read path and rendered as exact text.
    ///
    /// The six `created_at`/`updated_at` columns are deliberately IN this
    /// comparison. `ReviewerFixturePlan` omits all six from its INSERTs and
    /// each carries `DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))`, so a
    /// wall clock runs inside `apply`. Excluding them would build a test that
    /// cannot fail on the one axis it exists to check; including them turns
    /// the before/after equality below into a real proof that the clock ran
    /// exactly once and its answer was carried durably, rather than being
    /// re-derived by whatever rebuilt the archive.
    async fn fixture_facts_through_serving_lane(store: &Arc<Store>, user_id: &str) -> Vec<String> {
        store
            .wal_authoritative_read(user_id, |conn| {
                let mut facts = Vec::new();
                for sql in [
                    "SELECT id || '|' || transcription_status || '|' || created_at
                     FROM audio_segments ORDER BY id",
                    "SELECT id || '|' || text || '|' || speaker_label || '|' || created_at
                     FROM utterances ORDER BY id",
                    "SELECT id || '|' || url || '|' || created_at
                     FROM screenshots ORDER BY id",
                    "SELECT id || '|' || title || '|' || finalization_status || '|' || created_at
                     FROM episodes ORDER BY id",
                    "SELECT episode_id || '|' || record_type || '|' || record_id
                     FROM episode_members ORDER BY episode_id, record_type, record_id",
                    "SELECT episode_id || '|' || overview || '|' || created_at
                     FROM episode_final_briefs ORDER BY episode_id",
                    "SELECT device_id || '|' || modality || '|' || watermark_at || '|' || updated_at
                     FROM device_watermarks ORDER BY modality",
                    "SELECT key || '|' || value || '|' || updated_at
                     FROM app_metadata ORDER BY key",
                    // The FTS shadow tables are maintained by triggers on
                    // `utterances`, so a matching row here proves the WAL
                    // capture carried the trigger-written shadow pages too,
                    // not just the base table.
                    "SELECT 'fts-depuis|' || COUNT(*) FROM utterances_fts
                     WHERE utterances_fts MATCH 'depuis'",
                    "SELECT 'fts-invalidation|' || COUNT(*) FROM utterances_fts
                     WHERE utterances_fts MATCH 'invalidation'",
                ] {
                    let mut statement = conn.prepare(sql)?;
                    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
                    for row in rows {
                        facts.push(row?);
                    }
                }
                Ok(facts)
            })
            .await
            .expect("the routed serving read must answer")
    }

    #[tokio::test]
    async fn reviewer_fixture_is_idempotent_and_contains_expected_evidence() {
        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(kms, gcs));
        let user_id = "33333333-3333-4333-8333-333333333333";

        assert!(ensure_demo_archive(&store, user_id).await.unwrap());
        assert!(!ensure_demo_archive(&store, user_id).await.unwrap());

        store
            .with_user(user_id, |conn| {
                let episodes: i64 =
                    conn.query_row("SELECT count(*) FROM episodes", [], |row| row.get(0))?;
                let launch: String =
                    conn.query_row("SELECT text FROM utterances WHERE id = 920001", [], |row| {
                        row.get(0)
                    })?;
                let renewal: String =
                    conn.query_row("SELECT url FROM screenshots WHERE id = 930001", [], |row| {
                        row.get(0)
                    })?;
                assert_eq!(episodes, 4);
                assert!(launch.contains("August 19"));
                assert_eq!(renewal, "https://example.com/renewal");
                assert!(wal::fixture_is_exact(conn));
                Ok(())
            })
            .await
            .unwrap();
    }

    /// **G10 — the genesis spine's end-to-end gate.**
    ///
    /// Create a user, converge genesis, launch the owner, submit
    /// `ReviewerFixturePlan`, kill the process, relaunch, and read the
    /// fixture back through the routed serving lane.
    ///
    /// Until this test existed, `run_durable_genesis` and `install_and_launch`
    /// had never been executed by anything: both reach a live bucket, a live
    /// KMS key version and a live Firestore database on their first
    /// statement, so G9 could only compile-check and structurally pin them.
    /// This runs the composition itself, over in-memory providers behind the
    /// module's `#[cfg(test)]` runtime source.
    ///
    /// What "kill the process" means here, precisely: every in-memory handle
    /// is dropped — the control store, the user store, the launched serving
    /// authority and its publisher lane, the WAL owner's private staged
    /// SQLite copy, the provider clients — and process two is rebuilt from
    /// the durable substrate alone (the encrypted control object, the
    /// archive's immutable objects, the wrapped-registry CAS and the witness
    /// database). It is not a real `fork`/`SIGKILL`: the harness shares one
    /// address space, so it cannot prove that nothing survives in a static,
    /// a leaked thread, or the allocator. It does prove that nothing the
    /// serving lane needs is reconstructed from anything but durable state.
    #[tokio::test]
    async fn genesis_launch_submit_kill_relaunch_and_read_the_fixture_back() {
        use crate::archive_v3_genesis_trigger::{
            tests::{converge_for_smoke, GenesisSmokeSubstrate},
            GenesisConvergence,
        };
        use crate::cp::control_store::WalGenesisStage;
        use crate::cp::wal_gate_test_support::capture_events;

        let substrate = GenesisSmokeSubstrate::new();
        let (captured, capture_guard) = capture_events();

        // ---- process one: create the user, converge genesis, serve ----
        let first = substrate.boot();
        let binding = first
            .control
            .create_genesis_test_binding(SMOKE_USER)
            .await
            .unwrap();
        let archive_id = binding.archive_id();
        assert!(
            !first.store.is_wal_authoritative(SMOKE_USER),
            "a freshly bound user is on the ordinary legacy path"
        );

        let outcome = converge_for_smoke(
            &substrate.runtime(),
            &first.control,
            &first.store,
            SMOKE_USER,
        )
        .await
        .expect("genesis convergence must reach the durable terminal");
        assert_eq!(outcome, GenesisConvergence::Converged);
        let birth_metric = r#""metric":"archive_v3_genesis_birth_witness""#;
        assert_eq!(captured.text().matches(birth_metric).count(), 1);

        // The terminal contract, from the durable ledger rather than from the
        // pass that wrote it. `is_exact_unleased_wal_authoritative_terminal`
        // is the tree's own conjunction of the four facts the spine promises
        // — valid, `Active`, `WalAuthoritative`, no owner, lease tick zero —
        // and it is the exact `expected`-side conjunct set that
        // `exact_wal_owner_acquire_from` demands. That function is not
        // edited, and the launch below runs it for real.
        let terminal = first
            .control
            .wal_genesis_authoritative_terminal_for_archive(archive_id)
            .await
            .unwrap()
            .expect("the genesis ledger must hold the released terminal");
        assert!(terminal.is_exact_unleased_wal_authoritative_terminal());
        assert_eq!(
            terminal.root().root().sequence(),
            2,
            "Variant B publishes exactly two ladder roots, satisfying \
             archive_v3_wal_owners.root_seq CHECK (root_seq > 0)"
        );
        assert_eq!(
            first
                .control
                .wal_genesis_ledger_stage(archive_id)
                .await
                .unwrap(),
            Some(WalGenesisStage::WalAuthoritative)
        );
        assert!(first.store.is_wal_authoritative(SMOKE_USER));
        assert!(first.store.has_wal_serving_authority(SMOKE_USER));

        // ---- submit the probe through its real entry point ----
        assert!(
            ensure_demo_archive(&first.store, SMOKE_USER).await.unwrap(),
            "the first settle must submit the plan"
        );
        assert!(
            !ensure_demo_archive(&first.store, SMOKE_USER).await.unwrap(),
            "the routed probe must see its own settled write"
        );
        let before_kill = fixture_facts_through_serving_lane(&first.store, SMOKE_USER).await;
        assert!(
            before_kill
                .iter()
                .any(|fact| fact == "fts-depuis|2" || fact == "fts-depuis|1"),
            "the FTS shadow tables must have been populated by the triggers: {before_kill:?}"
        );

        // Guard against the equality below being vacuous. The plan supplies
        // `app_metadata.updated_at` explicitly, and omits the six other
        // timestamp columns, which therefore carry whatever
        // `DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))` returned inside
        // `apply`. Contrasting the two proves the compared timestamps are a
        // live clock reading rather than another constant — without pinning
        // the test to the machine's actual date.
        let marker_fact = before_kill
            .iter()
            .find(|fact| fact.starts_with("openai-review-fixture-v1|seeded|"))
            .expect("the plan's own explicit marker timestamp")
            .clone();
        assert!(
            marker_fact.ends_with("|2026-07-22T16:00:00.000Z"),
            "the plan sets this one itself: {marker_fact}"
        );
        let clock_written: Vec<&String> = before_kill
            .iter()
            .filter(|fact| fact.starts_with("910001|") || fact.starts_with("920001|"))
            .collect();
        assert_eq!(clock_written.len(), 2);
        for fact in clock_written {
            assert!(
                !fact.ends_with("|2026-07-22T16:00:00.000Z"),
                "a column the plan omits must carry the default clock, not a \
                 constant, or the survival check below proves nothing: {fact}"
            );
        }

        // ---- kill ----
        drop(first);

        // A crashed owner leaves its own WAL-owner lease standing in the
        // witness, and the restart cannot tell "I crashed" from "I am a
        // zombie": `exact_wal_owner_renewal_from` cannot apply (the live
        // record and the durable binding are the same bytes, so no tick
        // advanced in the record), so the only remaining arm is the provider
        // reacquire, which `exact_wal_owner_reacquire_from` admits only once
        // trusted time is past the dead lease's expiry. That is the designed
        // fencing cost of a restart, and it is real in production too: such a
        // user is `unavailable` until the lease lapses, and converges on the
        // next sign-in or token refresh. The harness's witness clock is
        // frozen, so it has to be moved for the restart to be able to happen
        // at all; no predicate is relaxed to get there.
        substrate.advance_witness_clock("2026-01-02T03:20:05.123Z");

        // ---- process two: rebuild from durable state alone ----
        let second = substrate.boot();
        assert!(
            !second.store.is_wal_authoritative(SMOKE_USER),
            "a fresh process starts with no selection installed"
        );
        assert!(!second.store.has_wal_serving_authority(SMOKE_USER));

        // This is the production resumption point: `cp/oauth.rs` runs exactly
        // this on the next sign-in or token refresh. It observes the durable
        // terminal stage, skips the whole durable half, re-adopts the same
        // owner reservation and relaunches the serving authority.
        let outcome = converge_for_smoke(
            &substrate.runtime(),
            &second.control,
            &second.store,
            SMOKE_USER,
        )
        .await
        .expect("the relaunch must reconstruct the serving authority");
        assert_eq!(outcome, GenesisConvergence::AlreadyTerminal);
        assert_eq!(
            captured.text().matches(birth_metric).count(),
            1,
            "an already-terminal relaunch must not claim a new birth"
        );
        drop(capture_guard);
        assert!(second.store.has_wal_serving_authority(SMOKE_USER));

        // ---- read the fixture back through the serving read path ----
        // `ensure_demo_archive` answering `false` is itself the readback: the
        // reviewer probe routes through `wal_authoritative_read`, so a `false`
        // means the relaunched lane served the settled marker.
        assert!(
            !ensure_demo_archive(&second.store, SMOKE_USER)
                .await
                .unwrap(),
            "the relaunched serving lane must already hold the fixture"
        );
        let after_relaunch = fixture_facts_through_serving_lane(&second.store, SMOKE_USER).await;
        assert_eq!(
            before_kill, after_relaunch,
            "every fixture fact, including the six default-clock timestamp \
             columns the plan omits, must survive the kill byte-identically"
        );
        assert!(
            after_relaunch.len() > 20,
            "the readback must be the whole fixture, not an empty agreement"
        );

        // The ledger is unchanged by a relaunch: no third root, no second
        // witness, no second genesis.
        let relaunched_terminal = second
            .control
            .wal_genesis_authoritative_terminal_for_archive(archive_id)
            .await
            .unwrap()
            .expect("the terminal must survive the kill");
        assert_eq!(relaunched_terminal.encode(), terminal.encode());
        assert_eq!(relaunched_terminal.root().root().sequence(), 2);
    }
}
