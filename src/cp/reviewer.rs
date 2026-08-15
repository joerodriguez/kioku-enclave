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
}
