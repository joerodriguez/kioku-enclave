#![allow(
    dead_code,
    reason = "inactive ADR-0022 reviewer fixture is reviewed before launcher or route ownership"
)]

//! Inactive exact reviewer-fixture WAL domain.
//!
//! The image-baked reviewer identity and fixture version already provide a
//! stable operation identity. This child can seed or exactly adopt only the
//! complete fixed synthetic archive and its marker. It cannot authenticate a
//! reviewer, call Store, save, launch work, invoke a route, or acknowledge a
//! request.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const FIXTURE_MARKER: &str = "openai-review-fixture-v1";
const FIXTURE_MARKER_VALUE: &str = "seeded";
const FIXTURE_TIME: &str = "2026-07-22T16:00:00.000Z";
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_UUID_BYTES: usize = 36;
const SCHEMA_TABLE: &str = "archive_v3_wal_reviewer_fixture_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_reviewer_fixture_operations";
const STATE_TABLE: &str = "archive_v3_wal_reviewer_fixture_state";
const MAX_ROWS: u32 = 64;
const MAX_RESULT_BYTES: u64 = 64 * ENCODED_UNIT_RESULT_BYTES as u64;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// One exact synthetic reviewer archive, bound to the already authenticated
/// stable reviewer account before actor admission.
pub(crate) struct ReviewerFixturePlan {
    operation_id: WalLogicalOperationId,
    user_id: String,
}

impl ReviewerFixturePlan {
    pub(super) fn new(user_id: String) -> Result<Self> {
        Self::build(None, user_id)
    }

    fn build(operation_id: Option<WalLogicalOperationId>, user_id: String) -> Result<Self> {
        validate_uuid(&user_id)?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                let mut source = Vec::with_capacity(FIXTURE_MARKER.len() + 1 + user_id.len());
                source.extend_from_slice(FIXTURE_MARKER.as_bytes());
                source.push(0);
                source.extend_from_slice(user_id.as_bytes());
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::ReviewerBackfill,
                    &source,
                )?
            }
        };
        Ok(Self {
            operation_id,
            user_id,
        })
    }

    #[cfg(test)]
    fn with_operation_id(operation_id: WalLogicalOperationId, user_id: &str) -> Result<Self> {
        Self::build(Some(operation_id), user_id.to_owned())
    }
}

pub(crate) struct ReviewerFixtureLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for ReviewerFixturePlan {
    type Ledger = ReviewerFixtureLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::ReviewerBackfill
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(128));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_string(&mut request, FIXTURE_MARKER)?;
        encode_string(&mut request, &self.user_id)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        match load_fixture_marker(transaction)? {
            Some(value) if value == FIXTURE_MARKER_VALUE => {
                validate_fixture(transaction)?;
                return Ok(WalReplayResult::unit());
            }
            Some(_) => return Err(WalIdempotencyError::Precondition),
            None => {}
        }

        insert_fixture_rows(transaction)?;
        validate_fixture(transaction)?;
        transaction
            .execute(
                "INSERT INTO app_metadata(key,value,updated_at) VALUES (?1,?2,?3)",
                params![FIXTURE_MARKER, FIXTURE_MARKER_VALUE, FIXTURE_TIME],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if load_fixture_marker(transaction)?.as_deref() != Some(FIXTURE_MARKER_VALUE) {
            return Err(WalIdempotencyError::Corrupt);
        }
        validate_fixture(transaction)?;
        Ok(WalReplayResult::unit())
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        match result {
            WalReplayResult::UnitApplied => Ok(()),
            WalReplayResult::CanonicalResponse(_) => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)
    }
}

impl WalLogicalDomainLedger<ReviewerFixturePlan> for ReviewerFixtureLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<ReviewerFixturePlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,
                        result_bytes,result_commitment
                 FROM archive_v3_wal_reviewer_fixture_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some((format, codec, fingerprint, encoded, commitment)) = row else {
            return Ok(None);
        };
        let kind = WalOperationKind::ReviewerBackfill;
        if format != i64::from(WalOperationKind::format_version())
            || codec != i64::from(kind.codec_version())
            || fingerprint.len() != 32
            || commitment.len() != 32
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        if fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        let result = WalReplayResult::decode(kind, &encoded)?;
        if commitment.as_slice() != result.commitment(kind)?.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<ReviewerFixturePlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::ReviewerBackfill;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_reviewer_fixture_operations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let previous_result_bytes =
            i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_reviewer_fixture_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    previous_result_bytes,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

fn load_fixture_marker(connection: &Connection) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT value FROM app_metadata WHERE key=?1",
            [FIXTURE_MARKER],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn insert_fixture_rows(transaction: &Transaction<'_>) -> Result<()> {
    transaction
        .execute_batch(
            r#"
            INSERT OR IGNORE INTO audio_segments
                (id,started_at,ended_at,duration_seconds,source_type,transcription_status)
            VALUES
                (910001,'2026-07-22T09:00:00Z','2026-07-22T09:35:00Z',2100,'mic','done'),
                (910002,'2026-07-22T10:15:00Z','2026-07-22T10:50:00Z',2100,'system','done'),
                (910003,'2026-07-22T14:00:00Z','2026-07-22T15:00:00Z',3600,'mic','done');

            INSERT OR IGNORE INTO utterances
                (id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,
                 language,confidence,speaker_label,source_key)
            VALUES
                (920001,910001,90,104,
                 'We agreed to move the Kioku launch from August 12 to August 19 so QA can finish the release checks.',
                 'en',0.99,'Maya','review:launch:decision'),
                (920002,910001,118,134,
                 'Alex owns the launch checklist and will confirm the migration rehearsal by Friday.',
                 'en',0.99,'Maya','review:launch:action'),
                (920003,910002,240,263,
                 'The stale dashboard came from a cache invalidation bug: the episode detail key was not cleared after an update.',
                 'en',0.99,'Me','review:cache:diagnosis'),
                (920004,910002,284,302,
                 'The fix is to invalidate both the episode list and episode detail cache keys after a successful write.',
                 'en',0.99,'Me','review:cache:fix'),
                (920005,910003,300,326,
                 'Use depuis for an action that began in the past and continues now; depuis is followed by the starting point or duration.',
                 'en',0.99,'Camille','review:french:depuis'),
                (920006,910003,690,714,
                 'Use pendant for a completed duration. Practice contrasting depuis deux ans with pendant deux ans.',
                 'en',0.99,'Camille','review:french:pendant');

            INSERT OR IGNORE INTO screenshots
                (id,captured_at,active_app,window_title,ocr_text,salient_ocr_text,
                 url,image_hash,is_duplicate,source_key)
            VALUES
                (930001,'2026-07-22T11:20:00Z','Google Chrome','Vendor renewal checklist',
                 'Renewal checklist: review the synthetic agreement at https://example.com/renewal before August 1.',
                 'Renewal checklist at example.com/renewal','https://example.com/renewal',
                 'review-synthetic-renewal',0,'review:screen:renewal');

            INSERT OR IGNORE INTO episodes
                (id,started_at,ended_at,type,title,summary,participants,languages,
                 action_items,model,minute_summaries,minutes_text,substance,
                 visual_evidence,finalized_at,finalization_version,finalization_status)
            VALUES
                (940001,'2026-07-22T09:00:00Z','2026-07-22T09:35:00Z','meeting',
                 'Launch planning and QA decision',
                 'The team moved the Kioku launch from August 12 to August 19 so QA could complete release checks. Alex owns the launch checklist.',
                 '["Maya","Alex","Me"]','["en"]',
                 '["Alex: confirm the migration rehearsal by Friday","Complete the launch checklist before August 19"]',
                 'synthetic-review',
                 '[{"start":"2026-07-22T09:00:00Z","gist":"Reviewed QA readiness."},{"start":"2026-07-22T09:15:00Z","gist":"Moved launch to August 19."},{"start":"2026-07-22T09:30:00Z","gist":"Assigned the checklist to Alex."}]',
                 'Reviewed QA readiness. Moved launch to August 19. Assigned the checklist to Alex.',
                 'normal','none','2026-07-22T16:00:00Z',3,'complete'),
                (940002,'2026-07-22T10:15:00Z','2026-07-22T10:50:00Z','coding',
                 'Dashboard cache invalidation fix',
                 'Diagnosed stale episode details as an invalidation bug and updated the write path to clear list and detail cache keys.',
                 '["Me"]','["en"]','["Add a regression test for episode detail invalidation"]',
                 'synthetic-review',
                 '[{"start":"2026-07-22T10:15:00Z","gist":"Reproduced stale dashboard state."},{"start":"2026-07-22T10:30:00Z","gist":"Found the missing detail-key invalidation."},{"start":"2026-07-22T10:45:00Z","gist":"Implemented the fix and planned a regression test."}]',
                 'Reproduced stale dashboard state. Found the missing detail-key invalidation. Implemented the cache fix.',
                 'normal','none','2026-07-22T16:00:00Z',3,'complete'),
                (940003,'2026-07-22T11:18:00Z','2026-07-22T11:24:00Z','browsing',
                 'Vendor renewal page',
                 'Reviewed a synthetic vendor renewal checklist and its example.com renewal link.',
                 '["Me"]','["en"]','["Review the renewal checklist before August 1"]',
                 'synthetic-review',
                 '[{"start":"2026-07-22T11:18:00Z","gist":"Opened the vendor renewal checklist."}]',
                 'Opened the vendor renewal checklist at example.com/renewal.',
                 'normal','useful','2026-07-22T16:00:00Z',3,'complete'),
                (940004,'2026-07-22T14:00:00Z','2026-07-22T15:00:00Z','lesson',
                 'French lesson: depuis and pendant',
                 'Practiced the difference between depuis for continuing situations and pendant for completed durations.',
                 '["Camille","Me"]','["fr","en"]',
                 '["Practice five sentence pairs contrasting depuis and pendant"]',
                 'synthetic-review',
                 '[{"start":"2026-07-22T14:00:00Z","gist":"Reviewed depuis for continuing actions."},{"start":"2026-07-22T14:30:00Z","gist":"Contrasted depuis with pendant."},{"start":"2026-07-22T14:50:00Z","gist":"Assigned five practice sentence pairs."}]',
                 'Reviewed depuis for continuing actions. Contrasted depuis with pendant. Assigned practice.',
                 'normal','none','2026-07-22T16:00:00Z',3,'complete');

            INSERT OR IGNORE INTO episode_members(episode_id,record_type,record_id)
            VALUES
                (940001,'utterance',920001),(940001,'utterance',920002),
                (940002,'utterance',920003),(940002,'utterance',920004),
                (940003,'screenshot',930001),
                (940004,'utterance',920005),(940004,'utterance',920006);

            INSERT OR IGNORE INTO episode_final_briefs
                (episode_id,overview,decisions,action_items,important_links,open_questions)
            VALUES
                (940001,'The team delayed the Kioku launch by one week to finish QA.',
                 '["Move the launch from August 12 to August 19"]',
                 '[{"owner":"Alex","task":"Confirm the migration rehearsal by Friday"},{"task":"Complete the launch checklist before August 19"}]','[]','[]'),
                (940002,'The stale dashboard was traced to incomplete cache invalidation.',
                 '["Invalidate both episode list and detail keys after writes"]',
                 '[{"owner":"Me","task":"Add a regression test for episode detail invalidation"}]','[]','[]'),
                (940003,'Reviewed the synthetic vendor renewal checklist.','[]',
                 '[{"owner":"Me","task":"Review the renewal checklist before August 1"}]',
                 '[{"url":"https://example.com/renewal","label":"Synthetic renewal checklist"}]','[]'),
                (940004,'Practiced choosing depuis for continuing situations and pendant for completed durations.','[]',
                 '[{"owner":"Me","task":"Write five sentence pairs contrasting depuis and pendant"}]','[]','[]');

            INSERT OR IGNORE INTO device_watermarks(device_id,modality,watermark_at)
            VALUES
                ('synthetic-review-device','audio','2026-07-22T15:00:00Z'),
                ('synthetic-review-device','screen','2026-07-22T15:00:00Z');
            "#,
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn exact_count(connection: &Connection, sql: &str) -> Result<i64> {
    connection
        .query_row(sql, [], |row| row.get(0))
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn validate_fixture(connection: &Connection) -> Result<()> {
    let checks = [
        (
            3,
            "SELECT COUNT(*) FROM audio_segments WHERE
             (id=910001 AND started_at='2026-07-22T09:00:00Z' AND ended_at='2026-07-22T09:35:00Z' AND duration_seconds=2100 AND source_type='mic' AND audio_format='m4a' AND file_size_bytes IS NULL AND speech_percentage IS NULL AND detected_language IS NULL AND transcription_status='done' AND processing_error IS NULL) OR
             (id=910002 AND started_at='2026-07-22T10:15:00Z' AND ended_at='2026-07-22T10:50:00Z' AND duration_seconds=2100 AND source_type='system' AND audio_format='m4a' AND file_size_bytes IS NULL AND speech_percentage IS NULL AND detected_language IS NULL AND transcription_status='done' AND processing_error IS NULL) OR
             (id=910003 AND started_at='2026-07-22T14:00:00Z' AND ended_at='2026-07-22T15:00:00Z' AND duration_seconds=3600 AND source_type='mic' AND audio_format='m4a' AND file_size_bytes IS NULL AND speech_percentage IS NULL AND detected_language IS NULL AND transcription_status='done' AND processing_error IS NULL)",
        ),
        (
            6,
            "SELECT COUNT(*) FROM utterances WHERE
             (id=920001 AND audio_segment_id=910001 AND start_offset_seconds=90 AND end_offset_seconds=104 AND text='We agreed to move the Kioku launch from August 12 to August 19 so QA can finish the release checks.' AND language='en' AND confidence=0.99 AND speaker_label='Maya' AND source_key='review:launch:decision') OR
             (id=920002 AND audio_segment_id=910001 AND start_offset_seconds=118 AND end_offset_seconds=134 AND text='Alex owns the launch checklist and will confirm the migration rehearsal by Friday.' AND language='en' AND confidence=0.99 AND speaker_label='Maya' AND source_key='review:launch:action') OR
             (id=920003 AND audio_segment_id=910002 AND start_offset_seconds=240 AND end_offset_seconds=263 AND text='The stale dashboard came from a cache invalidation bug: the episode detail key was not cleared after an update.' AND language='en' AND confidence=0.99 AND speaker_label='Me' AND source_key='review:cache:diagnosis') OR
             (id=920004 AND audio_segment_id=910002 AND start_offset_seconds=284 AND end_offset_seconds=302 AND text='The fix is to invalidate both the episode list and episode detail cache keys after a successful write.' AND language='en' AND confidence=0.99 AND speaker_label='Me' AND source_key='review:cache:fix') OR
             (id=920005 AND audio_segment_id=910003 AND start_offset_seconds=300 AND end_offset_seconds=326 AND text='Use depuis for an action that began in the past and continues now; depuis is followed by the starting point or duration.' AND language='en' AND confidence=0.99 AND speaker_label='Camille' AND source_key='review:french:depuis') OR
             (id=920006 AND audio_segment_id=910003 AND start_offset_seconds=690 AND end_offset_seconds=714 AND text='Use pendant for a completed duration. Practice contrasting depuis deux ans with pendant deux ans.' AND language='en' AND confidence=0.99 AND speaker_label='Camille' AND source_key='review:french:pendant')",
        ),
        (
            1,
            "SELECT COUNT(*) FROM screenshots WHERE id=930001 AND captured_at='2026-07-22T11:20:00Z' AND active_app='Google Chrome' AND window_title='Vendor renewal checklist' AND ocr_text='Renewal checklist: review the synthetic agreement at https://example.com/renewal before August 1.' AND salient_ocr_text='Renewal checklist at example.com/renewal' AND url='https://example.com/renewal' AND ocr_status='done' AND image_hash='review-synthetic-renewal' AND is_duplicate=0 AND source_key='review:screen:renewal' AND display_id IS NULL AND capture_context_version IS NULL AND capture_status IS NULL AND primary_bundle_id IS NULL AND primary_window_id IS NULL AND capture_group_id IS NULL AND visible_windows_json IS NULL AND visible_windows_truncated=0 AND visual_signals_json IS NULL AND semantic_context_hash IS NULL AND browser_snapshot_source_key IS NULL AND duplicate_of_id IS NULL AND visible_until IS NULL AND dedupe_version=1",
        ),
        (
            4,
            "SELECT COUNT(*) FROM episodes WHERE
             (id=940001 AND started_at='2026-07-22T09:00:00Z' AND ended_at='2026-07-22T09:35:00Z' AND type='meeting' AND title='Launch planning and QA decision' AND summary='The team moved the Kioku launch from August 12 to August 19 so QA could complete release checks. Alex owns the launch checklist.' AND participants='[\"Maya\",\"Alex\",\"Me\"]' AND languages='[\"en\"]' AND action_items='[\"Alex: confirm the migration rehearsal by Friday\",\"Complete the launch checklist before August 19\"]' AND model='synthetic-review' AND topics IS NULL AND people IS NULL AND minute_summaries='[{\"start\":\"2026-07-22T09:00:00Z\",\"gist\":\"Reviewed QA readiness.\"},{\"start\":\"2026-07-22T09:15:00Z\",\"gist\":\"Moved launch to August 19.\"},{\"start\":\"2026-07-22T09:30:00Z\",\"gist\":\"Assigned the checklist to Alex.\"}]' AND minutes_text='Reviewed QA readiness. Moved launch to August 19. Assigned the checklist to Alex.' AND substance='normal' AND visual_evidence='none' AND updated_at IS NULL AND finalized_at='2026-07-22T16:00:00Z' AND finalization_version=3 AND finalization_status='complete' AND finalization_error IS NULL AND finalization_attempted_at IS NULL AND finalization_attempt_count=0 AND finalization_next_attempt_at IS NULL) OR
             (id=940002 AND started_at='2026-07-22T10:15:00Z' AND ended_at='2026-07-22T10:50:00Z' AND type='coding' AND title='Dashboard cache invalidation fix' AND summary='Diagnosed stale episode details as an invalidation bug and updated the write path to clear list and detail cache keys.' AND participants='[\"Me\"]' AND languages='[\"en\"]' AND action_items='[\"Add a regression test for episode detail invalidation\"]' AND model='synthetic-review' AND topics IS NULL AND people IS NULL AND minute_summaries='[{\"start\":\"2026-07-22T10:15:00Z\",\"gist\":\"Reproduced stale dashboard state.\"},{\"start\":\"2026-07-22T10:30:00Z\",\"gist\":\"Found the missing detail-key invalidation.\"},{\"start\":\"2026-07-22T10:45:00Z\",\"gist\":\"Implemented the fix and planned a regression test.\"}]' AND minutes_text='Reproduced stale dashboard state. Found the missing detail-key invalidation. Implemented the cache fix.' AND substance='normal' AND visual_evidence='none' AND updated_at IS NULL AND finalized_at='2026-07-22T16:00:00Z' AND finalization_version=3 AND finalization_status='complete' AND finalization_error IS NULL AND finalization_attempted_at IS NULL AND finalization_attempt_count=0 AND finalization_next_attempt_at IS NULL) OR
             (id=940003 AND started_at='2026-07-22T11:18:00Z' AND ended_at='2026-07-22T11:24:00Z' AND type='browsing' AND title='Vendor renewal page' AND summary='Reviewed a synthetic vendor renewal checklist and its example.com renewal link.' AND participants='[\"Me\"]' AND languages='[\"en\"]' AND action_items='[\"Review the renewal checklist before August 1\"]' AND model='synthetic-review' AND topics IS NULL AND people IS NULL AND minute_summaries='[{\"start\":\"2026-07-22T11:18:00Z\",\"gist\":\"Opened the vendor renewal checklist.\"}]' AND minutes_text='Opened the vendor renewal checklist at example.com/renewal.' AND substance='normal' AND visual_evidence='useful' AND updated_at IS NULL AND finalized_at='2026-07-22T16:00:00Z' AND finalization_version=3 AND finalization_status='complete' AND finalization_error IS NULL AND finalization_attempted_at IS NULL AND finalization_attempt_count=0 AND finalization_next_attempt_at IS NULL) OR
             (id=940004 AND started_at='2026-07-22T14:00:00Z' AND ended_at='2026-07-22T15:00:00Z' AND type='lesson' AND title='French lesson: depuis and pendant' AND summary='Practiced the difference between depuis for continuing situations and pendant for completed durations.' AND participants='[\"Camille\",\"Me\"]' AND languages='[\"fr\",\"en\"]' AND action_items='[\"Practice five sentence pairs contrasting depuis and pendant\"]' AND model='synthetic-review' AND topics IS NULL AND people IS NULL AND minute_summaries='[{\"start\":\"2026-07-22T14:00:00Z\",\"gist\":\"Reviewed depuis for continuing actions.\"},{\"start\":\"2026-07-22T14:30:00Z\",\"gist\":\"Contrasted depuis with pendant.\"},{\"start\":\"2026-07-22T14:50:00Z\",\"gist\":\"Assigned five practice sentence pairs.\"}]' AND minutes_text='Reviewed depuis for continuing actions. Contrasted depuis with pendant. Assigned practice.' AND substance='normal' AND visual_evidence='none' AND updated_at IS NULL AND finalized_at='2026-07-22T16:00:00Z' AND finalization_version=3 AND finalization_status='complete' AND finalization_error IS NULL AND finalization_attempted_at IS NULL AND finalization_attempt_count=0 AND finalization_next_attempt_at IS NULL)",
        ),
        (
            7,
            "SELECT COUNT(*) FROM episode_members WHERE
             (episode_id=940001 AND record_type='utterance' AND record_id IN (920001,920002)) OR
             (episode_id=940002 AND record_type='utterance' AND record_id IN (920003,920004)) OR
             (episode_id=940003 AND record_type='screenshot' AND record_id=930001) OR
             (episode_id=940004 AND record_type='utterance' AND record_id IN (920005,920006))",
        ),
        (
            4,
            "SELECT COUNT(*) FROM episode_final_briefs WHERE
             (episode_id=940001 AND overview='The team delayed the Kioku launch by one week to finish QA.' AND decisions='[\"Move the launch from August 12 to August 19\"]' AND action_items='[{\"owner\":\"Alex\",\"task\":\"Confirm the migration rehearsal by Friday\"},{\"task\":\"Complete the launch checklist before August 19\"}]' AND important_links='[]' AND open_questions='[]') OR
             (episode_id=940002 AND overview='The stale dashboard was traced to incomplete cache invalidation.' AND decisions='[\"Invalidate both episode list and detail keys after writes\"]' AND action_items='[{\"owner\":\"Me\",\"task\":\"Add a regression test for episode detail invalidation\"}]' AND important_links='[]' AND open_questions='[]') OR
             (episode_id=940003 AND overview='Reviewed the synthetic vendor renewal checklist.' AND decisions='[]' AND action_items='[{\"owner\":\"Me\",\"task\":\"Review the renewal checklist before August 1\"}]' AND important_links='[{\"url\":\"https://example.com/renewal\",\"label\":\"Synthetic renewal checklist\"}]' AND open_questions='[]') OR
             (episode_id=940004 AND overview='Practiced choosing depuis for continuing situations and pendant for completed durations.' AND decisions='[]' AND action_items='[{\"owner\":\"Me\",\"task\":\"Write five sentence pairs contrasting depuis and pendant\"}]' AND important_links='[]' AND open_questions='[]')",
        ),
        (
            2,
            "SELECT COUNT(*) FROM device_watermarks WHERE device_id='synthetic-review-device' AND ((modality='audio' AND watermark_at='2026-07-22T15:00:00Z') OR (modality='screen' AND watermark_at='2026-07-22T15:00:00Z'))",
        ),
    ];
    for (expected, sql) in checks {
        if exact_count(connection, sql)? != expected {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    if exact_count(
        connection,
        "SELECT COUNT(*) FROM episode_members WHERE episode_id BETWEEN 940001 AND 940004",
    )? != 7
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture_is_exact(connection: &Connection) -> bool {
    load_fixture_marker(connection).ok().flatten().as_deref() == Some(FIXTURE_MARKER_VALUE)
        && validate_fixture(connection).is_ok()
}

fn require_kind(prepared: &PreparedLogicalMutation<ReviewerFixturePlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::ReviewerBackfill)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn validate_uuid(value: &str) -> Result<()> {
    if value.len() != MAX_UUID_BYTES
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    if length == 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3)",
            params![SCHEMA_TABLE, LEDGER_TABLE, STATE_TABLE],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        3 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_reviewer_fixture_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_reviewer_fixture_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes)=9),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_reviewer_fixture_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 64),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 576)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_reviewer_fixture_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_reviewer_fixture_state
                        (singleton,row_count,result_bytes) VALUES (1,0,0);",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            validate_schema_marker(transaction)
        }
    }
}

fn validate_schema_marker(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version
             FROM archive_v3_wal_reviewer_fixture_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::ReviewerBackfill.codec_version()),
        ))
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let _ = load_ledger_state(connection)?;
    Ok(())
}

fn load_ledger_state(connection: &Connection) -> Result<(u32, u64)> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes
             FROM archive_v3_wal_reviewer_fixture_state WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let row_count = u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    let result_bytes = u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?;
    if row_count > MAX_ROWS || result_bytes > MAX_RESULT_BYTES {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok((row_count, result_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use tempfile::tempdir;

    const USER: &str = "11111111-1111-4111-8111-111111111111";
    const USER_TWO: &str = "22222222-2222-4222-8222-222222222222";

    fn install_domain_schema(connection: &Connection) {
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE audio_segments(
                    id INTEGER PRIMARY KEY,started_at TEXT NOT NULL,ended_at TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,source_type TEXT NOT NULL,
                    audio_format TEXT NOT NULL DEFAULT 'm4a',file_size_bytes INTEGER,
                    speech_percentage REAL,detected_language TEXT,
                    transcription_status TEXT NOT NULL,processing_error TEXT
                 ) STRICT;
                 CREATE TABLE utterances(
                    id INTEGER PRIMARY KEY,audio_segment_id INTEGER NOT NULL REFERENCES audio_segments(id),
                    start_offset_seconds REAL NOT NULL,end_offset_seconds REAL NOT NULL,
                    text TEXT NOT NULL,language TEXT,confidence REAL,speaker_label TEXT NOT NULL,
                    source_key TEXT
                 ) STRICT;
                 CREATE TABLE screenshots(
                    id INTEGER PRIMARY KEY,captured_at TEXT NOT NULL,active_app TEXT,
                    window_title TEXT,ocr_text TEXT,salient_ocr_text TEXT,url TEXT,
                    ocr_status TEXT NOT NULL DEFAULT 'done',image_hash TEXT,
                    is_duplicate INTEGER NOT NULL,source_key TEXT,display_id INTEGER,
                    capture_context_version INTEGER,capture_status TEXT,primary_bundle_id TEXT,
                    primary_window_id INTEGER,capture_group_id TEXT,visible_windows_json TEXT,
                    visible_windows_truncated INTEGER NOT NULL DEFAULT 0,visual_signals_json TEXT,
                    semantic_context_hash TEXT,browser_snapshot_source_key TEXT,
                    duplicate_of_id INTEGER,visible_until TEXT,dedupe_version INTEGER NOT NULL DEFAULT 1
                 ) STRICT;
                 CREATE TABLE episodes(
                    id INTEGER PRIMARY KEY,started_at TEXT NOT NULL,ended_at TEXT NOT NULL,
                    type TEXT,title TEXT,summary TEXT,participants TEXT,languages TEXT,
                    action_items TEXT,model TEXT,topics TEXT,people TEXT,minute_summaries TEXT,
                    minutes_text TEXT,substance TEXT NOT NULL,visual_evidence TEXT NOT NULL,
                    updated_at TEXT,finalized_at TEXT,finalization_version INTEGER,
                    finalization_status TEXT NOT NULL,finalization_error TEXT,
                    finalization_attempted_at TEXT,finalization_attempt_count INTEGER NOT NULL DEFAULT 0,
                    finalization_next_attempt_at TEXT
                 ) STRICT;
                 CREATE TABLE episode_members(
                    episode_id INTEGER NOT NULL REFERENCES episodes(id),record_type TEXT NOT NULL,
                    record_id INTEGER NOT NULL,PRIMARY KEY(episode_id,record_type,record_id)
                 ) STRICT;
                 CREATE TABLE episode_final_briefs(
                    episode_id INTEGER PRIMARY KEY REFERENCES episodes(id),overview TEXT NOT NULL,
                    decisions TEXT NOT NULL,action_items TEXT NOT NULL,important_links TEXT NOT NULL,
                    open_questions TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE device_watermarks(
                    device_id TEXT NOT NULL,modality TEXT NOT NULL,watermark_at TEXT NOT NULL,
                    PRIMARY KEY(device_id,modality)
                 ) STRICT;
                 CREATE TABLE app_metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT NOT NULL
                 ) STRICT;",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

    fn plan(user: &str) -> ReviewerFixturePlan {
        ReviewerFixturePlan::new(user.to_owned()).unwrap()
    }

    fn explicit_id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    fn seed_rows_without_marker(connection: &mut Connection) {
        let transaction = connection.transaction().unwrap();
        insert_fixture_rows(&transaction).unwrap();
        transaction.commit().unwrap();
    }

    fn insert_marker(connection: &Connection, value: &str) {
        connection
            .execute(
                "INSERT INTO app_metadata(key,value,updated_at) VALUES (?1,?2,?3)",
                params![FIXTURE_MARKER, value, FIXTURE_TIME],
            )
            .unwrap();
    }

    fn fixture_table_rows(connection: &Connection) -> i64 {
        [
            "audio_segments",
            "utterances",
            "screenshots",
            "episodes",
            "episode_members",
            "episode_final_briefs",
            "device_watermarks",
            "app_metadata",
        ]
        .into_iter()
        .map(|table| {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        })
        .sum()
    }

    #[test]
    fn stable_identity_is_kind_scoped_and_user_bound() {
        let first = plan(USER);
        let replay = plan(USER);
        assert_eq!(first.operation_id(), replay.operation_id());
        assert_eq!(
            first.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(first.operation_id(), plan(USER_TWO).operation_id());
        assert_ne!(
            first.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::Retention,
                USER.as_bytes(),
            )
            .unwrap()
        );
        assert!(ReviewerFixturePlan::new("not-a-uuid".into()).is_err());
        assert!(ReviewerFixturePlan::new("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".into()).is_err());
    }

    #[test]
    fn complete_fixture_applies_once_and_replays_without_rewriting() {
        let mut connection = connection();
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        applied.into_validated_result().release().unwrap();
        validate_fixture(&connection).unwrap();
        assert_eq!(
            load_fixture_marker(&connection).unwrap().as_deref(),
            Some(FIXTURE_MARKER_VALUE)
        );
        let before = fixture_table_rows(&connection);
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(fixture_table_rows(&connection), before);
        assert_eq!(load_ledger_state(&connection).unwrap(), (1, 9));
    }

    #[test]
    fn exact_preexisting_rows_without_marker_are_adopted_atomically() {
        let mut connection = connection();
        seed_rows_without_marker(&mut connection);
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
        )
        .unwrap();
        validate_fixture(&connection).unwrap();
        assert_eq!(
            load_fixture_marker(&connection).unwrap().as_deref(),
            Some(FIXTURE_MARKER_VALUE)
        );
    }

    #[test]
    fn exact_preexisting_marker_and_fixture_are_adopted_without_row_changes() {
        let mut connection = connection();
        seed_rows_without_marker(&mut connection);
        insert_marker(&connection, FIXTURE_MARKER_VALUE);
        let before = fixture_table_rows(&connection);
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(fixture_table_rows(&connection), before);
    }

    #[test]
    fn every_fixture_family_is_authenticated_before_marker_or_ledger_commit() {
        for mutation in [
            "UPDATE audio_segments SET ended_at='2026-07-22T09:34:00Z' WHERE id=910001",
            "UPDATE audio_segments SET audio_format='wav' WHERE id=910001",
            "UPDATE utterances SET text='changed' WHERE id=920001",
            "UPDATE screenshots SET url='https://example.net/' WHERE id=930001",
            "UPDATE screenshots SET ocr_status='pending' WHERE id=930001",
            "UPDATE episodes SET title='changed' WHERE id=940001",
            "UPDATE episodes SET finalization_error='changed' WHERE id=940001",
            "INSERT INTO episode_members VALUES (940001,'utterance',920003)",
            "UPDATE episode_final_briefs SET overview='changed' WHERE episode_id=940001",
            "UPDATE device_watermarks SET watermark_at='2026-07-22T14:59:00Z' WHERE modality='audio'",
        ] {
            let mut connection = connection();
            seed_rows_without_marker(&mut connection);
            connection.execute(mutation, []).unwrap();
            assert_eq!(
                execute_prepared_for_owner(
                    &mut connection,
                    PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
                )
                .err()
                .unwrap(),
                WalIdempotencyError::Precondition,
                "mutation should fail: {mutation}"
            );
            assert_eq!(load_fixture_marker(&connection).unwrap(), None);
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE name LIKE 'archive_v3_wal_reviewer_fixture_%'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn conflicting_marker_fails_closed_before_any_fixture_write() {
        let mut connection = connection();
        insert_marker(&connection, "different");
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(fixture_table_rows(&connection), 1);
    }

    #[test]
    fn capacity_is_reserved_before_fixture_mutation_and_replay_survives() {
        let mut connection = connection();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_reviewer_fixture_state SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(USER_TWO)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Limit
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_the_complete_fixture() {
        let mut connection = connection();
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_reviewer_wal_insert
                 BEFORE INSERT ON archive_v3_wal_reviewer_fixture_operations
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Unavailable
        );
        assert_eq!(fixture_table_rows(&connection), 0);
        assert_eq!(load_ledger_state(&connection).unwrap(), (0, 0));
    }

    #[test]
    fn changed_same_operation_conflicts_and_result_tamper_fails_closed() {
        let mut connection = connection();
        let fixed = || ReviewerFixturePlan::with_operation_id(explicit_id(10), USER).unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(fixed()).unwrap(),
        )
        .unwrap();
        let changed = ReviewerFixturePlan::with_operation_id(explicit_id(10), USER_TWO).unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(changed).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::FingerprintConflict
        );
        connection
            .execute(
                "UPDATE archive_v3_wal_reviewer_fixture_operations SET result_commitment=?1",
                [[7u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(fixed()).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn close_reopen_replays_the_exact_fixture() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("reviewer.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            install_domain_schema(&connection);
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
            )
            .unwrap();
        }
        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut reopened,
                PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        validate_fixture(&reopened).unwrap();
        assert_eq!(load_ledger_state(&reopened).unwrap(), (1, 9));
    }

    #[test]
    fn partial_ledger_schema_is_rejected() {
        let mut connection = connection();
        connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_reviewer_fixture_schema(
                    singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(USER)).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
        assert_eq!(fixture_table_rows(&connection), 0);
    }
}
