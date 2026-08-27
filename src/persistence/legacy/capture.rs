use std::sync::Arc;

use async_trait::async_trait;
use rusqlite::OptionalExtension;

use crate::{
    archive_v3_wal_idempotency::PreparedLogicalMutation,
    cp::media::{self, wal, MediaDisposition, PreflightOutcome, RecordOutcome},
    error::{EnclaveError, Result},
    persistence::{
        CaptureCommit, CaptureCommitResult, CaptureEventStatus, CapturePreflight,
        CaptureRepository, CaptureSessionStatus, ReferenceBatchCommit, ReferenceBatchCommitResult,
    },
    store::Store,
};

pub(crate) struct LegacyCaptureRepository {
    store: Arc<Store>,
}

impl LegacyCaptureRepository {
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl CaptureRepository for LegacyCaptureRepository {
    async fn preflight_event(
        &self,
        account_id: &str,
        manifest: &media::CaptureEventManifest,
        manifest_digest: &str,
        allowed_object_keys: Option<&[String]>,
    ) -> Result<CapturePreflight> {
        let manifest = manifest.clone();
        let manifest_digest = manifest_digest.to_owned();
        let allowed_object_keys = allowed_object_keys.map(ToOwned::to_owned);
        let wal_authoritative = self.store.is_wal_authoritative(account_id);
        let outcome = self
            .store
            .wal_authoritative_read(account_id, move |connection| {
                media::preflight_source_event(
                    connection,
                    &manifest,
                    &manifest_digest,
                    allowed_object_keys.as_deref(),
                )
            })
            .await?;
        if !wal_authoritative && matches!(outcome, PreflightOutcome::Duplicate { .. }) {
            // Preserve the legacy route's lost-save reconciliation: an
            // earlier in-memory SQLite commit whose GCS flush failed must be
            // flushed before its retry is acknowledged as a duplicate.
            self.store.save_user(account_id).await?;
        }
        Ok(match outcome {
            PreflightOutcome::New => CapturePreflight::New,
            PreflightOutcome::Duplicate {
                committed_through_sequence,
            } => CapturePreflight::Duplicate {
                committed_through_sequence,
            },
        })
    }

    async fn reserve_media_upload(
        &self,
        _account_id: &str,
        _event_id: &str,
        _asset_id: &str,
        _object_key: &str,
        _manifest_digest: &str,
    ) -> Result<Option<String>> {
        Ok(None)
    }

    async fn media_dek_wrapped(&self, account_id: &str) -> Result<Option<String>> {
        self.store
            .wal_authoritative_read(account_id, |connection| {
                Ok(connection
                    .query_row(
                        "SELECT value FROM app_metadata WHERE key='wrapped_media_dek'",
                        [],
                        |row| row.get(0),
                    )
                    .optional()?)
            })
            .await
    }

    async fn install_media_dek(
        &self,
        account_id: &str,
        candidate_wrapped: &str,
        candidate_dek: &crate::crypto::Dek,
    ) -> Result<String> {
        if self.store.is_wal_authoritative(account_id) {
            let plan = wal::MediaDekInstallPlan::new(
                account_id.to_owned(),
                candidate_wrapped.to_owned(),
                candidate_dek,
            )
            .map_err(|_| {
                EnclaveError::Store("media DEK install plan construction failed".into())
            })?;
            let prepared = PreparedLogicalMutation::prepare(plan).map_err(|_| {
                EnclaveError::Store("media DEK install plan construction failed".into())
            })?;
            match self
                .store
                .wal_authoritative_submit(account_id, prepared)
                .await
            {
                Ok(_) => return Ok(candidate_wrapped.to_owned()),
                Err(EnclaveError::Conflict(_)) => {
                    return self.media_dek_wrapped(account_id).await?.ok_or_else(|| {
                        EnclaveError::Store("media DEK install lost a race to no winner".into())
                    });
                }
                Err(error) => return Err(error),
            }
        }
        let candidate = candidate_wrapped.to_owned();
        let winner = self
            .store
            .with_user(account_id, move |connection| {
                connection.execute(
                    "INSERT INTO app_metadata (key,value) VALUES ('wrapped_media_dek',?1) \
                     ON CONFLICT(key) DO NOTHING",
                    [&candidate],
                )?;
                Ok(connection.query_row(
                    "SELECT value FROM app_metadata WHERE key='wrapped_media_dek'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await?;
        self.store.save_user(account_id).await?;
        Ok(winner)
    }

    async fn commit_event(&self, command: CaptureCommit) -> Result<CaptureCommitResult> {
        let CaptureCommit {
            account_id,
            manifest,
            manifest_digest,
            object_key,
            object_generation,
            upload_token: _,
            media_authority,
            committed_at,
        } = command;

        if self.store.is_wal_authoritative(&account_id) {
            return match manifest.media_disposition {
                MediaDisposition::Canonical => {
                    let object_key = object_key.ok_or_else(|| {
                        EnclaveError::InvalidRequest(
                            "canonical capture object key is required".into(),
                        )
                    })?;
                    let generation =
                        object_generation
                            .filter(|value| *value > 0)
                            .ok_or_else(|| {
                                EnclaveError::InvalidRequest(
                                    "canonical capture generation must be positive".into(),
                                )
                            })?;
                    let authority = media_authority.ok_or_else(|| {
                        EnclaveError::InvalidRequest(
                            "canonical capture media authority is required".into(),
                        )
                    })?;
                    let prepared = media::prepare_canonical_capture_event(
                        account_id.clone(),
                        manifest,
                        object_key,
                        generation,
                        authority,
                        committed_at,
                    )?;
                    let outcome = self
                        .store
                        .wal_authoritative_submit(&account_id, prepared)
                        .await?;
                    Ok(CaptureCommitResult {
                        duplicate: false,
                        committed_through_sequence: outcome.committed_through_sequence(),
                    })
                }
                MediaDisposition::Reference => {
                    let plan = wal::MediaReferenceEventPlan::new(
                        account_id.clone(),
                        manifest,
                        committed_at,
                    )
                    .map_err(|_| {
                        EnclaveError::Store("reference capture plan construction failed".into())
                    })?;
                    let refusal = plan.refusal_sink();
                    let prepared = PreparedLogicalMutation::prepare(plan).map_err(|_| {
                        EnclaveError::Store("reference capture plan construction failed".into())
                    })?;
                    match self
                        .store
                        .wal_authoritative_submit(&account_id, prepared)
                        .await
                    {
                        Ok(outcome) => Ok(CaptureCommitResult {
                            duplicate: outcome.duplicate(),
                            committed_through_sequence: outcome.committed_through_sequence(),
                        }),
                        Err(error) => Err(refusal.observed().unwrap_or(error)),
                    }
                }
            };
        }

        let account_for_write = account_id.clone();
        let outcome = self
            .store
            .with_user(&account_id, move |connection| {
                let outcome = match manifest.media_disposition {
                    MediaDisposition::Canonical => media::record_source_event_with_generation(
                        connection,
                        &account_for_write,
                        &manifest,
                        &manifest_digest,
                        object_key.as_deref().ok_or_else(|| {
                            EnclaveError::InvalidRequest(
                                "canonical capture object key is required".into(),
                            )
                        })?,
                        object_generation,
                        media_authority.as_ref(),
                    )?,
                    MediaDisposition::Reference => media::record_reference_event(
                        connection,
                        &account_for_write,
                        &manifest,
                        &manifest_digest,
                    )?,
                };
                Ok(CaptureCommitResult {
                    duplicate: outcome == RecordOutcome::Duplicate,
                    committed_through_sequence: media::committed_through_sequence(
                        connection,
                        &manifest.stream_id,
                    )?,
                })
            })
            .await?;
        self.store.save_user(&account_id).await?;
        Ok(outcome)
    }

    async fn commit_reference_batch(
        &self,
        command: ReferenceBatchCommit,
    ) -> Result<ReferenceBatchCommitResult> {
        let ReferenceBatchCommit {
            account_id,
            batch_id,
            events,
            manifest_digests,
            committed_at,
        } = command;
        if self.store.is_wal_authoritative(&account_id) {
            let plan = wal::MediaReferenceBatchPlan::new(
                account_id.clone(),
                batch_id,
                events,
                committed_at,
            )
            .map_err(|_| EnclaveError::Store("reference batch plan construction failed".into()))?;
            let refusal = plan.refusal_sink();
            let prepared = PreparedLogicalMutation::prepare(plan).map_err(|_| {
                EnclaveError::Store("reference batch plan construction failed".into())
            })?;
            return match self
                .store
                .wal_authoritative_submit(&account_id, prepared)
                .await
            {
                Ok(outcome) => Ok(ReferenceBatchCommitResult {
                    new_count: usize::from(outcome.new_count()),
                    duplicate_count: usize::from(outcome.duplicate_count()),
                    committed_through_sequence: outcome.committed_through_sequence(),
                }),
                Err(error) => Err(refusal.observed().unwrap_or(error)),
            };
        }

        let account_for_write = account_id.clone();
        let recorded = self
            .store
            .with_user(&account_id, move |connection| {
                media::record_reference_batch(
                    connection,
                    &account_for_write,
                    &events,
                    &manifest_digests,
                )
            })
            .await?;
        self.store.save_user(&account_id).await?;
        Ok(ReferenceBatchCommitResult {
            new_count: recorded.new_count,
            duplicate_count: recorded.duplicate_count,
            committed_through_sequence: recorded.committed_through_sequence,
        })
    }

    async fn stream_ack(&self, account_id: &str, stream_id: &str) -> Result<i64> {
        let stream_id = stream_id.to_owned();
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                media::committed_through_sequence(connection, &stream_id)
            })
            .await
    }

    async fn event_status(
        &self,
        account_id: &str,
        event_id: &str,
    ) -> Result<Option<CaptureEventStatus>> {
        let event_id = event_id.to_owned();
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                media::load_capture_status(connection, &event_id)
            })
            .await
    }

    async fn session_status(
        &self,
        account_id: &str,
        capture_session_id: &str,
        summarized_until_ms: Option<i64>,
    ) -> Result<Option<CaptureSessionStatus>> {
        let capture_session_id = capture_session_id.to_owned();
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                media::load_capture_session_status(
                    connection,
                    &capture_session_id,
                    summarized_until_ms,
                )
            })
            .await
    }

    async fn recent_sessions(
        &self,
        account_id: &str,
        window_hours: i64,
        max_sessions: i64,
        summarized_until_ms: Option<i64>,
    ) -> Result<Vec<CaptureSessionStatus>> {
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                let ids =
                    media::load_recent_capture_session_ids(connection, window_hours, max_sessions)?;
                ids.into_iter()
                    .map(|id| {
                        media::load_capture_session_status(connection, &id, summarized_until_ms)?
                            .ok_or_else(|| {
                                EnclaveError::Store(
                                    "capture session disappeared during listing".into(),
                                )
                            })
                    })
                    .collect()
            })
            .await
    }

    async fn finish_session(
        &self,
        account_id: &str,
        capture_session_id: &str,
    ) -> Result<Option<CaptureSessionStatus>> {
        if self.store.is_wal_authoritative(account_id) {
            let probe_id = capture_session_id.to_owned();
            let exists = self
                .store
                .wal_authoritative_read(account_id, move |connection| {
                    Ok(connection
                        .query_row(
                            "SELECT 1 FROM capture_sessions WHERE id=?1",
                            [&probe_id],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some())
                })
                .await?;
            if !exists {
                return Ok(None);
            }
            let plan = wal::CaptureSessionFinishPlan::new(capture_session_id.to_owned()).map_err(
                |_| EnclaveError::Store("capture-session finish plan construction failed".into()),
            )?;
            let prepared = PreparedLogicalMutation::prepare(plan).map_err(|_| {
                EnclaveError::Store("capture-session finish plan construction failed".into())
            })?;
            self.store
                .wal_authoritative_submit(account_id, prepared)
                .await?;
            return self
                .session_status(account_id, capture_session_id, None)
                .await;
        }

        let capture_session_id = capture_session_id.to_owned();
        let status = self
            .store
            .with_user(account_id, move |connection| {
                let updated = connection.execute(
                    "UPDATE capture_sessions SET ended_at=COALESCE(ended_at, \
                     strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id=?1",
                    [&capture_session_id],
                )?;
                if updated == 0 {
                    return Ok(None);
                }
                media::load_capture_session_status(connection, &capture_session_id, None)
            })
            .await?;
        if status.is_some() {
            self.store.save_user(account_id).await?;
        }
        Ok(status)
    }
}
