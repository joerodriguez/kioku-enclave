use std::collections::BTreeSet;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    cp::{
        control_store::{
            recording_retention_preview_fingerprint, recording_retention_request_fingerprint,
            valid_retention_idempotency_key, RecordingKeyEpoch, RecordingRetentionChange,
            RecordingRetentionInventory, RecordingRetentionPolicy, RecordingRetentionPreference,
            RecordingRetentionPreview, RECORDING_RETENTION_CONSENT_VERSION,
        },
        isotime,
    },
    error::{EnclaveError, Result},
    persistence::{RecordingRetentionChangeRequest, RecordingRetentionRepository},
};

use super::{advisory_transaction_lock, PostgresPersistence};

fn timestamp(row: &sqlx::postgres::PgRow, name: &str) -> Result<String> {
    Ok(isotime::format_epoch_millis(row.try_get::<i64, _>(name)?))
}

fn optional_timestamp(row: &sqlx::postgres::PgRow, name: &str) -> Result<Option<String>> {
    Ok(row
        .try_get::<Option<i64>, _>(name)?
        .map(isotime::format_epoch_millis))
}

fn preference_from_row(row: &sqlx::postgres::PgRow) -> Result<RecordingRetentionPreference> {
    let status: String = row.try_get("status")?;
    if status != "active" {
        return Err(EnclaveError::Auth("account inactive or deleting".into()));
    }
    let policy = row.try_get::<Option<String>, _>("policy")?;
    let operation_id = row.try_get("active_operation_id")?;
    let operation_state = row.try_get("operation_state")?;
    let Some(policy) = policy else {
        return Ok(RecordingRetentionPreference {
            policy: RecordingRetentionPolicy::ProcessingWindow30d,
            consent_version: 0,
            revision: 0,
            policy_epoch: None,
            effective_at: timestamp(row, "created_at_ms")?,
            revocation_cutoff: None,
            active_operation_id: operation_id,
            operation_state,
        });
    };
    let policy = RecordingRetentionPolicy::from_db(&policy)?;
    let consent_version = row.try_get("consent_version")?;
    let revision = row.try_get("revision")?;
    let policy_epoch: Option<String> = row.try_get("policy_epoch")?;
    let revocation_cutoff = optional_timestamp(row, "revocation_cutoff_ms")?;
    if revision <= 0
        || consent_version < 0
        || (policy == RecordingRetentionPolicy::UntilDeleted
            && (consent_version != RECORDING_RETENTION_CONSENT_VERSION
                || policy_epoch
                    .as_deref()
                    .is_none_or(|epoch| !valid_policy_epoch(epoch))
                || revocation_cutoff.is_some()))
        || (policy == RecordingRetentionPolicy::ProcessingWindow30d && policy_epoch.is_some())
    {
        return Err(EnclaveError::Store(
            "recording retention preference is malformed".into(),
        ));
    }
    Ok(RecordingRetentionPreference {
        policy,
        consent_version,
        revision,
        policy_epoch,
        effective_at: timestamp(row, "effective_at_ms")?,
        revocation_cutoff,
        active_operation_id: operation_id,
        operation_state,
    })
}

fn valid_policy_epoch(value: &str) -> bool {
    value.starts_with("rpe_") && value.len() == 68
}

fn valid_operation_id(value: &str) -> bool {
    value.starts_with("rrc_") && value.len() == 68
}

async fn load_preference(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    account_id: &str,
) -> Result<RecordingRetentionPreference> {
    let row = sqlx::query(
        "SELECT a.status, floor(extract(epoch FROM a.created_at)*1000)::bigint created_at_ms, \
                p.policy,p.consent_version,p.revision,p.policy_epoch, \
                floor(extract(epoch FROM p.effective_at)*1000)::bigint effective_at_ms, \
                floor(extract(epoch FROM p.revocation_cutoff)*1000)::bigint revocation_cutoff_ms, \
                active.operation_id active_operation_id,active.state operation_state \
           FROM accounts a \
           LEFT JOIN recording_retention_preferences p ON p.account_id=a.id \
           LEFT JOIN LATERAL ( \
             SELECT operation_id,state FROM recording_retention_changes \
              WHERE account_id=a.id AND state='delete_pending' \
              ORDER BY resulting_revision DESC LIMIT 1 \
           ) active ON true \
          WHERE a.id=$1",
    )
    .bind(account_id)
    .fetch_optional(executor)
    .await?
    .ok_or_else(|| EnclaveError::Auth("unknown user".into()))?;
    preference_from_row(&row)
}

fn change_from_row(
    row: &sqlx::postgres::PgRow,
    operation_id: String,
) -> Result<RecordingRetentionChange> {
    Ok(RecordingRetentionChange {
        operation_id,
        policy: RecordingRetentionPolicy::from_db(&row.try_get::<String, _>("policy")?)?,
        revision: row.try_get("revision")?,
        state: row.try_get("state")?,
        updated_at: timestamp(row, "updated_at_ms")?,
    })
}

#[async_trait]
impl RecordingRetentionRepository for PostgresPersistence {
    async fn preference(&self, account_id: &str) -> Result<RecordingRetentionPreference> {
        crate::store::validate_user_id(account_id)?;
        load_preference(self.pool(), account_id).await
    }

    async fn inventory(
        &self,
        account_id: &str,
        preference: &RecordingRetentionPreference,
    ) -> Result<RecordingRetentionInventory> {
        crate::store::validate_user_id(account_id)?;
        let (revision, epoch) = match preference.policy {
            RecordingRetentionPolicy::UntilDeleted => (
                Some(preference.revision),
                Some(preference.policy_epoch.as_deref().ok_or_else(|| {
                    EnclaveError::Store("durable recording policy lost its epoch".into())
                })?),
            ),
            RecordingRetentionPolicy::ProcessingWindow30d
                if preference.operation_state.is_some() =>
            {
                (None, None)
            }
            RecordingRetentionPolicy::ProcessingWindow30d => {
                return Ok(crate::cp::retention::empty_recording_inventory());
            }
        };
        let rows = sqlx::query(
            "SELECT m.asset_id,m.object_key,COALESCE(m.object_generation,0) generation, \
                    m.byte_length,m.sha256,e.capture_session_id,m.processing_state, \
                    floor(extract(epoch FROM m.deleted_at)*1000)::bigint deleted_at_ms, \
                    ra.retention_policy_revision,ra.retention_policy_epoch,ra.recording_state \
               FROM media_objects m \
               JOIN capture_events e ON e.account_id=m.account_id AND e.event_id=m.event_id \
               JOIN recording_media_authority ra ON ra.account_id=m.account_id AND ra.asset_id=m.asset_id \
              WHERE m.account_id=$1 AND m.object_key LIKE ('recordings/' || $1 || '/%') \
                AND ra.retention_decision='until_deleted' AND ra.storage_backend='recordings' \
                AND ($2::bigint IS NULL OR (ra.retention_policy_revision=$2 AND ra.retention_policy_epoch=$3)) \
              ORDER BY m.asset_id,m.object_key",
        )
        .bind(account_id)
        .bind(revision)
        .bind(epoch)
        .fetch_all(self.pool())
        .await?;
        let mut digest = Sha256::new();
        digest.update(b"kioku.recording-retention-inventory.v1\0");
        let mut object_count = 0_i64;
        let mut byte_count = 0_i64;
        let mut recordings = BTreeSet::new();
        for row in rows {
            let asset_id: String = row.try_get("asset_id")?;
            let object_key: String = row.try_get("object_key")?;
            let generation: i64 = row.try_get("generation")?;
            let bytes: i64 = row.try_get("byte_length")?;
            let sha256: String = row.try_get("sha256")?;
            let recording_id: String = row.try_get("capture_session_id")?;
            let state: String = row.try_get("processing_state")?;
            let deleted_at = row
                .try_get::<Option<i64>, _>("deleted_at_ms")?
                .map(isotime::format_epoch_millis)
                .unwrap_or_default();
            let authority_revision: i64 = row.try_get("retention_policy_revision")?;
            let authority_epoch: String = row.try_get("retention_policy_epoch")?;
            let authority_state: String = row.try_get("recording_state")?;
            for value in [
                asset_id.as_bytes(),
                object_key.as_bytes(),
                &generation.to_be_bytes(),
                &bytes.to_be_bytes(),
                sha256.as_bytes(),
                recording_id.as_bytes(),
                state.as_bytes(),
                deleted_at.as_bytes(),
                &authority_revision.to_be_bytes(),
                authority_epoch.as_bytes(),
                authority_state.as_bytes(),
            ] {
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value);
            }
            if generation > 0 && bytes > 0 && deleted_at.is_empty() && state != "pruned" {
                object_count = object_count.saturating_add(1);
                byte_count = byte_count.saturating_add(bytes);
                recordings.insert(recording_id);
            }
        }
        Ok(RecordingRetentionInventory {
            inventory_fingerprint: format!("{:x}", digest.finalize()),
            object_count,
            byte_count,
            recording_count: i64::try_from(recordings.len()).unwrap_or(i64::MAX),
        })
    }

    async fn create_preview(
        &self,
        account_id: &str,
        policy: RecordingRetentionPolicy,
        expected_revision: i64,
        consent_version: i64,
        promote_existing: bool,
        inventory: RecordingRetentionInventory,
    ) -> Result<RecordingRetentionPreview> {
        crate::store::validate_user_id(account_id)?;
        inventory.validate()?;
        if expected_revision < 0
            || consent_version != RECORDING_RETENTION_CONSENT_VERSION
            || promote_existing
        {
            return Err(EnclaveError::InvalidRequest(
                "invalid recording retention preview".into(),
            ));
        }
        let preview_id = format!("rrp_{}", crate::cp::tokens::random_token_hex());
        let request_fingerprint = recording_retention_preview_fingerprint(
            policy,
            expected_revision,
            consent_version,
            promote_existing,
            &inventory.inventory_fingerprint,
        );
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-retention", account_id).await?;
        let current = load_preference(&mut *transaction, account_id).await?;
        if current.revision != expected_revision || current.operation_state.is_some() {
            return Err(EnclaveError::Conflict(
                "recording retention revision is stale".into(),
            ));
        }
        if current.policy == policy {
            return Err(EnclaveError::Conflict(
                "recording retention policy is already selected".into(),
            ));
        }
        sqlx::query(
            "DELETE FROM recording_retention_previews WHERE account_id=$1 AND expires_at<=now()",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        let expires_at_ms: i64 = sqlx::query_scalar(
            "INSERT INTO recording_retention_previews \
             (account_id,preview_id,expected_revision,target_policy,consent_version,promote_existing, \
              inventory_fingerprint,object_count,byte_count,recording_count,created_at,expires_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now(),now()+interval '15 minutes') \
             RETURNING floor(extract(epoch FROM expires_at)*1000)::bigint",
        )
        .bind(account_id)
        .bind(&preview_id)
        .bind(expected_revision)
        .bind(policy.as_str())
        .bind(consent_version)
        .bind(promote_existing)
        .bind(&inventory.inventory_fingerprint)
        .bind(inventory.object_count)
        .bind(inventory.byte_count)
        .bind(inventory.recording_count)
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(RecordingRetentionPreview {
            preview_id,
            target_policy: policy,
            expected_revision,
            consent_version,
            promote_existing,
            inventory,
            request_fingerprint,
            expires_at: isotime::format_epoch_millis(expires_at_ms),
        })
    }

    async fn change_policy(
        &self,
        account_id: &str,
        request: RecordingRetentionChangeRequest<'_>,
    ) -> Result<RecordingRetentionChange> {
        crate::store::validate_user_id(account_id)?;
        request.inventory.validate()?;
        if request.expected_revision < 0
            || request.consent_version != RECORDING_RETENTION_CONSENT_VERSION
            || request.promote_existing
            || !request.preview_id.starts_with("rrp_")
            || request.preview_id.len() != 68
            || !valid_retention_idempotency_key(request.idempotency_key)
        {
            return Err(EnclaveError::InvalidRequest(
                "invalid recording retention change".into(),
            ));
        }
        let request_fingerprint = recording_retention_request_fingerprint(
            request.policy,
            request.expected_revision,
            request.consent_version,
            request.promote_existing,
            request.preview_id,
            &request.inventory.inventory_fingerprint,
        );
        let idempotency_key_hash = format!("{:x}", Sha256::digest(request.idempotency_key));
        let operation_id = format!("rrc_{}", crate::cp::tokens::random_token_hex());
        let proposed_epoch = format!("rpe_{}", crate::cp::tokens::random_token_hex());
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-retention", account_id).await?;
        if let Some(row) = sqlx::query(
            "SELECT request_fingerprint,operation_id,resulting_policy policy,resulting_revision revision,state, \
                    floor(extract(epoch FROM updated_at)*1000)::bigint updated_at_ms \
               FROM recording_retention_changes WHERE account_id=$1 AND idempotency_key_hash=$2",
        )
        .bind(account_id)
        .bind(&idempotency_key_hash)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if row.try_get::<String, _>("request_fingerprint")? != request_fingerprint {
                return Err(EnclaveError::Conflict(
                    "recording retention idempotency key was reused".into(),
                ));
            }
            return change_from_row(&row, row.try_get("operation_id")?);
        }
        let current = load_preference(&mut *transaction, account_id).await?;
        if current.revision != request.expected_revision || current.operation_state.is_some() {
            return Err(EnclaveError::Conflict(
                "recording retention revision is stale".into(),
            ));
        }
        if current.policy == request.policy {
            return Err(EnclaveError::Conflict(
                "recording retention policy is already selected".into(),
            ));
        }
        let preview = sqlx::query(
            "SELECT expected_revision,target_policy,consent_version,promote_existing, \
                    inventory_fingerprint,object_count,byte_count,recording_count,expires_at>now() fresh \
               FROM recording_retention_previews WHERE account_id=$1 AND preview_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(request.preview_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("recording retention preview is stale".into()))?;
        if preview.try_get::<i64, _>("expected_revision")? != request.expected_revision
            || preview.try_get::<String, _>("target_policy")? != request.policy.as_str()
            || preview.try_get::<i64, _>("consent_version")? != request.consent_version
            || preview.try_get::<bool, _>("promote_existing")? != request.promote_existing
            || preview.try_get::<String, _>("inventory_fingerprint")?
                != request.inventory.inventory_fingerprint
            || preview.try_get::<i64, _>("object_count")? != request.inventory.object_count
            || preview.try_get::<i64, _>("byte_count")? != request.inventory.byte_count
            || preview.try_get::<i64, _>("recording_count")? != request.inventory.recording_count
            || !preview.try_get::<bool, _>("fresh")?
        {
            return Err(EnclaveError::Conflict(
                "recording retention preview is stale".into(),
            ));
        }
        let revision = current
            .revision
            .checked_add(1)
            .ok_or_else(|| EnclaveError::Store("retention revision exhausted".into()))?;
        if current.policy == RecordingRetentionPolicy::UntilDeleted {
            sqlx::query(
                "UPDATE recording_retention_history SET revocation_cutoff=now() \
                  WHERE account_id=$1 AND revision=$2 AND revocation_cutoff IS NULL",
            )
            .bind(account_id)
            .bind(current.revision)
            .execute(&mut *transaction)
            .await?;
        }
        let key_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM recording_key_epochs WHERE account_id=$1 AND state<>'erased'",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        let policy_epoch = (request.policy == RecordingRetentionPolicy::UntilDeleted)
            .then_some(proposed_epoch.as_str());
        let state = match request.policy {
            RecordingRetentionPolicy::UntilDeleted => "settled",
            RecordingRetentionPolicy::ProcessingWindow30d if key_count > 0 => "delete_pending",
            RecordingRetentionPolicy::ProcessingWindow30d => "physical_complete",
        };
        sqlx::query(
            "INSERT INTO recording_retention_preferences \
             (account_id,policy,consent_version,revision,policy_epoch,effective_at,revocation_cutoff,updated_at) \
             VALUES($1,$2,$3,$4,$5,now(),CASE WHEN $2='processing_window_30d' THEN now() END,now()) \
             ON CONFLICT(account_id) DO UPDATE SET policy=excluded.policy,consent_version=excluded.consent_version, \
               revision=excluded.revision,policy_epoch=excluded.policy_epoch,effective_at=excluded.effective_at, \
               revocation_cutoff=excluded.revocation_cutoff,updated_at=excluded.updated_at",
        )
        .bind(account_id)
        .bind(request.policy.as_str())
        .bind(request.consent_version)
        .bind(revision)
        .bind(policy_epoch)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO recording_retention_history \
             (account_id,revision,policy,consent_version,policy_epoch,effective_at,revocation_cutoff,operation_id,request_fingerprint) \
             VALUES($1,$2,$3,$4,$5,now(),CASE WHEN $3='processing_window_30d' THEN now() END,$6,$7)",
        )
        .bind(account_id)
        .bind(revision)
        .bind(request.policy.as_str())
        .bind(request.consent_version)
        .bind(policy_epoch)
        .bind(&operation_id)
        .bind(&request_fingerprint)
        .execute(&mut *transaction)
        .await?;
        if request.policy == RecordingRetentionPolicy::ProcessingWindow30d {
            sqlx::query("UPDATE recording_key_epochs SET state='retired' WHERE account_id=$1 AND state='active'")
                .bind(account_id)
                .execute(&mut *transaction)
                .await?;
        }
        let row = sqlx::query(
            "INSERT INTO recording_retention_changes \
             (account_id,idempotency_key_hash,request_fingerprint,preview_id,operation_id,resulting_revision, \
              resulting_policy,state,created_at,updated_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,now(),now()) \
             RETURNING resulting_policy policy,resulting_revision revision,state, \
                       floor(extract(epoch FROM updated_at)*1000)::bigint updated_at_ms",
        )
        .bind(account_id)
        .bind(&idempotency_key_hash)
        .bind(&request_fingerprint)
        .bind(request.preview_id)
        .bind(&operation_id)
        .bind(revision)
        .bind(request.policy.as_str())
        .bind(state)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM recording_retention_previews WHERE account_id=$1")
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
        let result = change_from_row(&row, operation_id)?;
        transaction.commit().await?;
        Ok(result)
    }

    async fn change(
        &self,
        account_id: &str,
        operation_id: &str,
    ) -> Result<Option<RecordingRetentionChange>> {
        crate::store::validate_user_id(account_id)?;
        if !valid_operation_id(operation_id) {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT resulting_policy policy,resulting_revision revision,state, \
                    floor(extract(epoch FROM updated_at)*1000)::bigint updated_at_ms \
               FROM recording_retention_changes WHERE account_id=$1 AND operation_id=$2",
        )
        .bind(account_id)
        .bind(operation_id)
        .fetch_optional(self.pool())
        .await?;
        row.as_ref()
            .map(|row| change_from_row(row, operation_id.to_owned()))
            .transpose()
    }

    async fn pending_changes(&self, limit: usize) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT account_id,operation_id FROM recording_retention_changes \
              WHERE state='delete_pending' ORDER BY updated_at,operation_id LIMIT $1",
        )
        .bind(i64::try_from(limit.clamp(1, 256)).unwrap_or(256))
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|row| Ok((row.try_get("account_id")?, row.try_get("operation_id")?)))
            .collect()
    }

    async fn complete_downgrade(
        &self,
        account_id: &str,
        operation_id: &str,
    ) -> Result<RecordingRetentionChange> {
        crate::store::validate_user_id(account_id)?;
        if !valid_operation_id(operation_id) {
            return Err(EnclaveError::NotFound);
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-retention", account_id).await?;
        let row = sqlx::query(
            "SELECT resulting_policy policy,resulting_revision revision,state, \
                    floor(extract(epoch FROM updated_at)*1000)::bigint updated_at_ms \
               FROM recording_retention_changes WHERE account_id=$1 AND operation_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(operation_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(EnclaveError::NotFound)?;
        let current = change_from_row(&row, operation_id.to_owned())?;
        if current.state == "physical_complete" {
            transaction.commit().await?;
            return Ok(current);
        }
        if current.policy != RecordingRetentionPolicy::ProcessingWindow30d
            || current.state != "delete_pending"
        {
            return Err(EnclaveError::Conflict(
                "recording retention deletion state changed".into(),
            ));
        }
        let preference = load_preference(&mut *transaction, account_id).await?;
        if preference.policy != RecordingRetentionPolicy::ProcessingWindow30d
            || preference.revision != current.revision
        {
            return Err(EnclaveError::Conflict(
                "recording retention deletion fence changed".into(),
            ));
        }
        sqlx::query(
            "UPDATE media_objects m SET processing_state='pruned',object_generation=NULL,deleted_at=now() \
              WHERE m.account_id=$1 AND EXISTS (SELECT 1 FROM recording_media_authority ra \
                WHERE ra.account_id=m.account_id AND ra.asset_id=m.asset_id AND ra.storage_backend='recordings')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM recording_media_authority WHERE account_id=$1 AND storage_backend='recordings'")
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE recording_key_epochs SET wrapped_dek='',state='erased',erased_at=now() \
              WHERE account_id=$1 AND state<>'erased'",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query(
            "UPDATE recording_retention_changes SET state='physical_complete',updated_at=now() \
              WHERE account_id=$1 AND operation_id=$2 AND state='delete_pending' \
              RETURNING resulting_policy policy,resulting_revision revision,state, \
                        floor(extract(epoch FROM updated_at)*1000)::bigint updated_at_ms",
        )
        .bind(account_id)
        .bind(operation_id)
        .fetch_one(&mut *transaction)
        .await?;
        let result = change_from_row(&row, operation_id.to_owned())?;
        transaction.commit().await?;
        Ok(result)
    }

    async fn install_key_epoch(
        &self,
        account_id: &str,
        policy_revision: i64,
        policy_epoch: &str,
        candidate_wrapped_dek: &str,
    ) -> Result<RecordingKeyEpoch> {
        crate::store::validate_user_id(account_id)?;
        if policy_revision <= 0
            || !valid_policy_epoch(policy_epoch)
            || candidate_wrapped_dek.is_empty()
        {
            return Err(EnclaveError::InvalidRequest(
                "invalid recording key authority".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "recording-retention", account_id).await?;
        let preference = load_preference(&mut *transaction, account_id).await?;
        if preference.policy != RecordingRetentionPolicy::UntilDeleted
            || preference.revision != policy_revision
            || preference.policy_epoch.as_deref() != Some(policy_epoch)
            || preference.operation_state.is_some()
        {
            return Err(EnclaveError::Conflict(
                "recording key policy authority changed".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO recording_key_epochs(account_id,key_epoch,policy_epoch,wrapped_dek,state) \
             VALUES($1,$2,$3,$4,'active') ON CONFLICT(account_id,policy_epoch) DO NOTHING",
        )
        .bind(account_id)
        .bind(policy_revision)
        .bind(policy_epoch)
        .bind(candidate_wrapped_dek)
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query(
            "SELECT key_epoch,policy_epoch,wrapped_dek,state FROM recording_key_epochs \
              WHERE account_id=$1 AND policy_epoch=$2",
        )
        .bind(account_id)
        .bind(policy_epoch)
        .fetch_one(&mut *transaction)
        .await?;
        let key_epoch: i64 = row.try_get("key_epoch")?;
        let state: String = row.try_get("state")?;
        let wrapped_dek_b64: String = row.try_get("wrapped_dek")?;
        if key_epoch != policy_revision || state != "active" || wrapped_dek_b64.is_empty() {
            return Err(EnclaveError::Store(
                "recording key epoch is malformed".into(),
            ));
        }
        let result = RecordingKeyEpoch {
            key_epoch,
            policy_epoch: row.try_get("policy_epoch")?,
            wrapped_dek_b64,
        };
        transaction.commit().await?;
        Ok(result)
    }

    async fn key_epoch(
        &self,
        account_id: &str,
        key_epoch: i64,
        policy_epoch: &str,
    ) -> Result<Option<RecordingKeyEpoch>> {
        crate::store::validate_user_id(account_id)?;
        if key_epoch <= 0 || !valid_policy_epoch(policy_epoch) {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT key_epoch,policy_epoch,wrapped_dek,state FROM recording_key_epochs \
              WHERE account_id=$1 AND key_epoch=$2 AND policy_epoch=$3",
        )
        .bind(account_id)
        .bind(key_epoch)
        .bind(policy_epoch)
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else { return Ok(None) };
        let state: String = row.try_get("state")?;
        let wrapped_dek_b64: String = row.try_get("wrapped_dek")?;
        if !matches!(state.as_str(), "active" | "retired") || wrapped_dek_b64.is_empty() {
            return Ok(None);
        }
        Ok(Some(RecordingKeyEpoch {
            key_epoch: row.try_get("key_epoch")?,
            policy_epoch: row.try_get("policy_epoch")?,
            wrapped_dek_b64,
        }))
    }
}
