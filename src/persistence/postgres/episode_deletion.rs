use std::collections::BTreeSet;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    error::{EnclaveError, Result},
    persistence::{
        EpisodeDeletionPlan, EpisodeDeletionRepository, EpisodeDeletionStart, EpisodePurge,
    },
};

use super::{
    activation::lock_activation_contract_key_share_if_installed, advisory_transaction_lock,
    PostgresPersistence,
};

const MAX_AFFECTED_CAPTURE_SESSIONS: usize = 256;
const MAX_DELETED_CAPTURE_EVENTS: usize = 4_096;
const PAGED_DELETION_PAGE: usize = 512;
const PAGED_PROVIDER_OBJECT_PAGE: usize = 64;
const PAGED_SOURCE_KEY_PAGE: usize = 128;

fn empty_purge() -> EpisodePurge {
    EpisodePurge {
        source_key_delivery_complete: false,
        ..EpisodePurge::default()
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn coordinate_sha256(values: &[&[u8]]) -> Vec<u8> {
    let mut digest = Sha256::new();
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.finalize().to_vec()
}

fn advance_coordinate_sha256(
    prior: &[u8],
    coordinates: impl IntoIterator<Item = Vec<u8>>,
) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"kioku.episode-deletion.coordinates.v1\0");
    digest.update(prior);
    for coordinate in coordinates {
        digest.update((coordinate.len() as u64).to_be_bytes());
        digest.update(coordinate);
    }
    digest.finalize().to_vec()
}

async fn paged_episode_deletion_enabled(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    activation_installed: bool,
) -> Result<bool> {
    if !activation_installed {
        return Ok(false);
    }
    sqlx::query_scalar::<_, bool>(
        "SELECT coalesce((SELECT phase IN ('draining','active','paused') \
           FROM persistence_feature_activation_events \
          WHERE feature='episode_topology_reconciliation' \
          ORDER BY generation DESC LIMIT 1),false)",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn paged_episode_deletion_exists(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
) -> Result<bool> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_progress \
          WHERE account_id=$1 AND episode_id=$2)",
    )
    .bind(account_id)
    .bind(episode_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn paged_pending_plan(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
) -> Result<EpisodeDeletionPlan> {
    let phase = sqlx::query_scalar::<_, String>(
        "SELECT phase FROM persistence_feature_episode_deletion_progress \
          WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .fetch_one(&mut **transaction)
    .await?;
    let media_object_keys = if phase == "provider_delete" {
        let limit = i64::try_from(PAGED_PROVIDER_OBJECT_PAGE)
            .map_err(|_| EnclaveError::Store("episode deletion provider page overflow".into()))?;
        sqlx::query_scalar::<_, String>(
            "SELECT object_key FROM persistence_feature_episode_deletion_objects \
              WHERE account_id=$1 AND episode_id=$2 AND provider_deleted_at IS NULL \
              ORDER BY object_key LIMIT $3",
        )
        .bind(account_id)
        .bind(episode_id)
        .bind(limit)
        .fetch_all(&mut **transaction)
        .await?
    } else {
        Vec::new()
    };
    let purge = if phase == "finalize" {
        paged_source_key_delivery(transaction, account_id, episode_id)
            .await?
            .purge
    } else {
        empty_purge()
    };
    Ok(EpisodeDeletionPlan {
        episode_id,
        purge,
        media_object_keys,
    })
}

#[derive(Debug)]
struct PagedSourceKeyDelivery {
    purge: EpisodePurge,
    last_coordinate: Option<(String, i64)>,
    acknowledged_cursor: Option<String>,
}

fn source_key_cursor_commitment(
    account_id: &str,
    episode_id: i64,
    revision: &[u8],
    record_type: &str,
    record_id: i64,
) -> String {
    let digest = coordinate_sha256(&[
        b"kioku.episode-deletion.source-key-page.v1\0",
        account_id.as_bytes(),
        &episode_id.to_be_bytes(),
        revision,
        record_type.as_bytes(),
        &record_id.to_be_bytes(),
    ]);
    format!("sha256:{}", lowercase_hex(&digest))
}

async fn paged_source_key_delivery(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
) -> Result<PagedSourceKeyDelivery> {
    let row = sqlx::query(
        "SELECT utterance_count,screenshot_count,segment_count,coordinate_sha256, \
                member_record_type_cursor,member_record_id_cursor \
           FROM persistence_feature_episode_deletion_progress \
          WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .fetch_one(&mut **transaction)
    .await?;
    let revision: Vec<u8> = row.try_get("coordinate_sha256")?;
    let acknowledged_type: Option<String> = row.try_get("member_record_type_cursor")?;
    let acknowledged_id: Option<i64> = row.try_get("member_record_id_cursor")?;
    let limit = i64::try_from(PAGED_SOURCE_KEY_PAGE)
        .map_err(|_| EnclaveError::Store("episode deletion source-key page overflow".into()))?;
    let rows = sqlx::query(
        "SELECT record_type,record_id,source_key \
           FROM persistence_feature_episode_deletion_members \
          WHERE account_id=$1 AND episode_id=$2 AND source_key IS NOT NULL \
            AND ($3::text IS NULL OR (record_type,record_id)>($3,$4::bigint)) \
          ORDER BY record_type,record_id LIMIT $5 FOR KEY SHARE",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(acknowledged_type.as_deref())
    .bind(acknowledged_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    let mut utterance_source_keys = Vec::new();
    let mut screenshot_source_keys = Vec::new();
    for source in &rows {
        let source_key: String = source.try_get("source_key")?;
        match source.try_get::<String, _>("record_type")?.as_str() {
            "utterance" => utterance_source_keys.push(source_key),
            "screenshot" => screenshot_source_keys.push(source_key),
            _ => {
                return Err(EnclaveError::Store(
                    "episode deletion source-key record type is invalid".into(),
                ))
            }
        }
    }
    let last_coordinate: Option<(String, i64)> = rows
        .last()
        .map(|row| -> Result<(String, i64)> {
            Ok((
                row.try_get::<String, _>("record_type")?,
                row.try_get::<i64, _>("record_id")?,
            ))
        })
        .transpose()?;
    let source_key_cursor = last_coordinate.as_ref().map(|(record_type, record_id)| {
        source_key_cursor_commitment(account_id, episode_id, &revision, record_type, *record_id)
    });
    let acknowledged_cursor =
        acknowledged_type
            .as_deref()
            .zip(acknowledged_id)
            .map(|(record_type, record_id)| {
                source_key_cursor_commitment(
                    account_id,
                    episode_id,
                    &revision,
                    record_type,
                    record_id,
                )
            });
    let count = |column: &str| -> Result<usize> {
        usize::try_from(row.try_get::<i64, _>(column)?)
            .map_err(|_| EnclaveError::Store("episode deletion count overflow".into()))
    };
    Ok(PagedSourceKeyDelivery {
        purge: EpisodePurge {
            deleted_utterances: count("utterance_count")?,
            deleted_screenshots: count("screenshot_count")?,
            deleted_segments: count("segment_count")?,
            utterance_source_keys,
            screenshot_source_keys,
            source_key_cursor,
            source_key_delivery_complete: rows.is_empty(),
        },
        last_coordinate,
        acknowledged_cursor,
    })
}

async fn inventory_paged_members(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    prior_digest: &[u8],
) -> Result<()> {
    let limit = i64::try_from(PAGED_DELETION_PAGE + 1)
        .map_err(|_| EnclaveError::Store("episode deletion member page overflow".into()))?;
    let rows = sqlx::query(
        "SELECT member.record_type,member.record_id, \
                CASE WHEN member.record_type='utterance' THEN utterance.source_key \
                     ELSE screenshot.source_key END AS source_key, \
                utterance.audio_segment_id \
           FROM episode_members member \
           LEFT JOIN utterances utterance ON member.record_type='utterance' \
            AND utterance.account_id=member.account_id AND utterance.id=member.record_id \
           LEFT JOIN screenshots screenshot ON member.record_type='screenshot' \
            AND screenshot.account_id=member.account_id AND screenshot.id=member.record_id \
           JOIN persistence_feature_episode_deletion_progress progress \
             ON progress.account_id=member.account_id AND progress.episode_id=member.episode_id \
          WHERE member.account_id=$1 AND member.episode_id=$2 \
            AND (progress.member_record_type_cursor IS NULL OR \
                 (member.record_type,member.record_id)> \
                 (progress.member_record_type_cursor,progress.member_record_id_cursor)) \
            AND ((member.record_type='utterance' AND utterance.id IS NOT NULL) OR \
                 (member.record_type='screenshot' AND screenshot.id IS NOT NULL)) \
          ORDER BY member.record_type,member.record_id LIMIT $3 FOR KEY SHARE OF member",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    let has_more = rows.len() > PAGED_DELETION_PAGE;
    let rows = rows.iter().take(PAGED_DELETION_PAGE).collect::<Vec<_>>();
    if rows.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress \
                SET phase='inventory_projection_events',member_record_type_cursor=NULL, \
                    member_record_id_cursor=NULL,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }

    let mut record_types = Vec::with_capacity(rows.len());
    let mut record_ids = Vec::with_capacity(rows.len());
    let mut source_keys = Vec::with_capacity(rows.len());
    let mut segment_ids = Vec::with_capacity(rows.len());
    let mut coordinates = Vec::with_capacity(rows.len());
    for row in &rows {
        let record_type: String = row.try_get("record_type")?;
        let record_id: i64 = row.try_get("record_id")?;
        let source_key: Option<String> = row.try_get("source_key")?;
        let segment_id: Option<i64> = row.try_get("audio_segment_id")?;
        let coordinate = coordinate_sha256(&[
            record_type.as_bytes(),
            &record_id.to_be_bytes(),
            source_key.as_deref().unwrap_or("").as_bytes(),
            &segment_id.unwrap_or_default().to_be_bytes(),
        ]);
        record_types.push(record_type);
        record_ids.push(record_id);
        source_keys.push(source_key);
        segment_ids.push(segment_id);
        coordinates.push(coordinate);
    }
    sqlx::query(
        "INSERT INTO persistence_feature_episode_deletion_members( \
             account_id,episode_id,record_type,record_id,source_key,audio_segment_id, \
             coordinate_sha256) \
         SELECT $1,$2,page.record_type,page.record_id,page.source_key,page.audio_segment_id, \
                page.coordinate_sha256 \
           FROM unnest($3::text[],$4::bigint[],$5::text[],$6::bigint[],$7::bytea[]) \
                AS page(record_type,record_id,source_key,audio_segment_id,coordinate_sha256)",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&record_types)
    .bind(&record_ids)
    .bind(&source_keys)
    .bind(&segment_ids)
    .bind(&coordinates)
    .execute(&mut **transaction)
    .await?;
    let last = rows.last().expect("nonempty bounded page");
    let last_type: String = last.try_get("record_type")?;
    let last_id: i64 = last.try_get("record_id")?;
    let utterances = i64::try_from(
        record_types
            .iter()
            .filter(|value| *value == "utterance")
            .count(),
    )
    .map_err(|_| EnclaveError::Store("episode deletion utterance count overflow".into()))?;
    let screenshots = i64::try_from(
        record_types
            .iter()
            .filter(|value| *value == "screenshot")
            .count(),
    )
    .map_err(|_| EnclaveError::Store("episode deletion screenshot count overflow".into()))?;
    let next_digest = advance_coordinate_sha256(prior_digest, coordinates);
    sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             phase=CASE WHEN $8 THEN phase ELSE 'inventory_projection_events' END, \
             member_record_type_cursor=CASE WHEN $8 THEN $3 ELSE NULL END, \
             member_record_id_cursor=CASE WHEN $8 THEN $4 ELSE NULL END, \
             coordinate_sha256=$5,member_count=member_count+$6, \
             utterance_count=utterance_count+$7,screenshot_count=screenshot_count+$9, \
             updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(last_type)
    .bind(last_id)
    .bind(next_digest)
    .bind(
        i64::try_from(rows.len())
            .map_err(|_| EnclaveError::Store("episode deletion member count overflow".into()))?,
    )
    .bind(utterances)
    .bind(has_more)
    .bind(screenshots)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn inventory_paged_projection_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    prior_digest: &[u8],
) -> Result<()> {
    let limit = i64::try_from(PAGED_DELETION_PAGE + 1)
        .map_err(|_| EnclaveError::Store("episode deletion projection page overflow".into()))?;
    let rows = sqlx::query(
        "WITH projection_events(record_type,record_id,event_id) AS ( \
             SELECT member.record_type,member.record_id, \
                    split_part(substr(utterance.source_key,10),':',1) \
               FROM persistence_feature_episode_deletion_members member \
               JOIN utterances utterance ON member.record_type='utterance' \
                AND utterance.account_id=member.account_id AND utterance.id=member.record_id \
              WHERE member.account_id=$1 AND member.episode_id=$2 \
                AND utterance.source_key LIKE 'cloud-v2:%' \
             UNION \
             SELECT member.record_type,member.record_id,observation.event_id \
               FROM persistence_feature_episode_deletion_members member \
               JOIN utterances utterance ON member.record_type='utterance' \
                AND utterance.account_id=member.account_id AND utterance.id=member.record_id \
               JOIN speaker_observations observation \
                 ON observation.account_id=utterance.account_id \
                AND observation.id=utterance.speaker_observation_id \
              WHERE member.account_id=$1 AND member.episode_id=$2 \
             UNION \
             SELECT member.record_type,member.record_id,source.event_id \
               FROM persistence_feature_episode_deletion_members member \
               JOIN utterances utterance ON member.record_type='utterance' \
                AND utterance.account_id=member.account_id AND utterance.id=member.record_id \
               JOIN speaker_observation_sources source \
                 ON source.account_id=utterance.account_id \
                AND source.speaker_observation_id=utterance.speaker_observation_id \
              WHERE member.account_id=$1 AND member.episode_id=$2 \
             UNION \
             SELECT member.record_type,member.record_id,substr(screenshot.source_key,10) \
               FROM persistence_feature_episode_deletion_members member \
               JOIN screenshots screenshot ON member.record_type='screenshot' \
                AND screenshot.account_id=member.account_id AND screenshot.id=member.record_id \
              WHERE member.account_id=$1 AND member.episode_id=$2 \
                AND screenshot.source_key LIKE 'cloud-v2:%' \
             UNION \
             SELECT member.record_type,member.record_id,observation.event_id \
               FROM persistence_feature_episode_deletion_members member \
               JOIN visual_speaker_observations observation \
                 ON member.record_type='screenshot' \
                AND observation.account_id=member.account_id \
                AND observation.screenshot_id=member.record_id \
              WHERE member.account_id=$1 AND member.episode_id=$2 \
         ) \
         SELECT projection.record_type,projection.record_id,projection.event_id, \
                coalesce(event.canonical_event_id,event.event_id) AS root_event_id \
           FROM projection_events projection \
           JOIN capture_events event ON event.account_id=$1 \
            AND event.event_id=projection.event_id \
           JOIN persistence_feature_episode_deletion_progress progress \
             ON progress.account_id=$1 AND progress.episode_id=$2 \
          WHERE projection.event_id<>'' AND ( \
                progress.projection_record_type_cursor IS NULL OR \
                (projection.record_type,projection.record_id,projection.event_id)> \
                (progress.projection_record_type_cursor, \
                 progress.projection_record_id_cursor,progress.projection_event_id_cursor)) \
          ORDER BY projection.record_type,projection.record_id,projection.event_id \
          LIMIT $3 FOR KEY SHARE OF event",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    let has_more = rows.len() > PAGED_DELETION_PAGE;
    let rows = rows.iter().take(PAGED_DELETION_PAGE).collect::<Vec<_>>();
    if rows.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='inventory_episode_objects',projection_record_type_cursor=NULL, \
                 projection_record_id_cursor=NULL,projection_event_id_cursor=NULL, \
                 updated_at=clock_timestamp() WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let mut roots = rows
        .iter()
        .map(|row| row.try_get::<String, _>("root_event_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    roots.sort();
    roots.dedup();
    let root_coordinates = roots
        .iter()
        .map(|root| coordinate_sha256(&[root.as_bytes()]))
        .collect::<Vec<_>>();
    let inserted = sqlx::query(
        "INSERT INTO persistence_feature_episode_deletion_roots( \
             account_id,episode_id,root_event_id,coordinate_sha256) \
         SELECT $1,$2,page.root_event_id,page.coordinate_sha256 \
           FROM unnest($3::text[],$4::bytea[]) AS page(root_event_id,coordinate_sha256) \
         ON CONFLICT(account_id,episode_id,root_event_id) DO NOTHING",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&roots)
    .bind(&root_coordinates)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let last = rows.last().expect("nonempty bounded page");
    let last_type: String = last.try_get("record_type")?;
    let last_id: i64 = last.try_get("record_id")?;
    let last_event: String = last.try_get("event_id")?;
    let next_digest = advance_coordinate_sha256(prior_digest, root_coordinates);
    sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             phase=CASE WHEN $7 THEN phase ELSE 'inventory_episode_objects' END, \
             projection_record_type_cursor=CASE WHEN $7 THEN $3 ELSE NULL END, \
             projection_record_id_cursor=CASE WHEN $7 THEN $4 ELSE NULL END, \
             projection_event_id_cursor=CASE WHEN $7 THEN $5 ELSE NULL END, \
             coordinate_sha256=$6,root_count=root_count+$8,updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(last_type)
    .bind(last_id)
    .bind(last_event)
    .bind(next_digest)
    .bind(has_more)
    .bind(
        i64::try_from(inserted)
            .map_err(|_| EnclaveError::Store("episode deletion root count overflow".into()))?,
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn inventory_paged_episode_objects(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    prior_digest: &[u8],
) -> Result<()> {
    let limit = i64::try_from(PAGED_DELETION_PAGE + 1)
        .map_err(|_| EnclaveError::Store("episode deletion object page overflow".into()))?;
    let rows = sqlx::query(
        "SELECT image.object_key FROM screenshot_images image \
           JOIN persistence_feature_episode_deletion_progress progress \
             ON progress.account_id=image.account_id AND progress.episode_id=image.episode_id \
          WHERE image.account_id=$1 AND image.episode_id=$2 \
            AND (progress.episode_object_key_cursor IS NULL OR \
                 image.object_key>progress.episode_object_key_cursor) \
          ORDER BY image.object_key LIMIT $3 FOR KEY SHARE OF image",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    let has_more = rows.len() > PAGED_DELETION_PAGE;
    let keys = rows
        .iter()
        .take(PAGED_DELETION_PAGE)
        .map(|row| row.try_get::<String, _>("object_key"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='classify_roots',episode_object_key_cursor=NULL, \
                 updated_at=clock_timestamp() WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let coordinates = keys
        .iter()
        .map(|key| coordinate_sha256(&[key.as_bytes()]))
        .collect::<Vec<_>>();
    let inserted = sqlx::query(
        "INSERT INTO persistence_feature_episode_deletion_objects( \
             account_id,episode_id,object_key,object_kind,object_key_sha256) \
         SELECT $1,$2,page.object_key,'screenshot_image',page.coordinate_sha256 \
           FROM unnest($3::text[],$4::bytea[]) AS page(object_key,coordinate_sha256) \
         ON CONFLICT(account_id,episode_id,object_key) DO NOTHING",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&keys)
    .bind(&coordinates)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let next_digest = advance_coordinate_sha256(prior_digest, coordinates);
    sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             phase=CASE WHEN $5 THEN phase ELSE 'classify_roots' END, \
             episode_object_key_cursor=CASE WHEN $5 THEN $3 ELSE NULL END, \
             coordinate_sha256=$4,object_count=object_count+$6,updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(keys.last().expect("nonempty bounded page"))
    .bind(next_digest)
    .bind(has_more)
    .bind(
        i64::try_from(inserted)
            .map_err(|_| EnclaveError::Store("episode deletion object count overflow".into()))?,
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn classify_paged_roots(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    prior_digest: &[u8],
) -> Result<()> {
    let limit = i64::try_from(PAGED_PROVIDER_OBJECT_PAGE + 1)
        .map_err(|_| EnclaveError::Store("episode deletion root page overflow".into()))?;
    let roots = sqlx::query_scalar::<_, String>(
        "SELECT root_event_id FROM persistence_feature_episode_deletion_roots \
          WHERE account_id=$1 AND episode_id=$2 AND disposition='pending' \
          ORDER BY root_event_id LIMIT $3 FOR UPDATE",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    let has_more = roots.len() > PAGED_PROVIDER_OBJECT_PAGE;
    let roots = roots
        .into_iter()
        .take(PAGED_PROVIDER_OBJECT_PAGE)
        .collect::<Vec<_>>();
    if roots.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='inventory_family_sessions',root_event_id_cursor=NULL, \
                 updated_at=clock_timestamp() WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let exact_roots = sqlx::query_scalar::<_, String>(
        "SELECT event.event_id FROM capture_events event \
          WHERE event.account_id=$1 AND event.event_id=ANY($2::text[]) \
            AND event.canonical_event_id IS NULL \
          ORDER BY event.event_id FOR KEY SHARE",
    )
    .bind(account_id)
    .bind(&roots)
    .fetch_all(&mut **transaction)
    .await?;
    if exact_roots != roots {
        return Err(EnclaveError::Conflict(
            "paged episode deletion found a non-canonical or missing capture root".into(),
        ));
    }
    let survivor_roots = sqlx::query_scalar::<_, String>(
        "WITH outside_projection_events(event_id) AS ( \
             SELECT split_part(substr(utterance.source_key,10),':',1) \
               FROM utterances utterance \
              WHERE utterance.account_id=$1 AND utterance.source_key LIKE 'cloud-v2:%' \
                AND NOT EXISTS(SELECT 1 \
                      FROM persistence_feature_episode_deletion_members member \
                     WHERE member.account_id=$1 AND member.episode_id=$2 \
                       AND member.record_type='utterance' AND member.record_id=utterance.id) \
             UNION \
             SELECT observation.event_id FROM utterances utterance \
               JOIN speaker_observations observation \
                 ON observation.account_id=utterance.account_id \
                AND observation.id=utterance.speaker_observation_id \
              WHERE utterance.account_id=$1 AND NOT EXISTS(SELECT 1 \
                      FROM persistence_feature_episode_deletion_members member \
                     WHERE member.account_id=$1 AND member.episode_id=$2 \
                       AND member.record_type='utterance' AND member.record_id=utterance.id) \
             UNION \
             SELECT source.event_id FROM utterances utterance \
               JOIN speaker_observation_sources source \
                 ON source.account_id=utterance.account_id \
                AND source.speaker_observation_id=utterance.speaker_observation_id \
              WHERE utterance.account_id=$1 AND NOT EXISTS(SELECT 1 \
                      FROM persistence_feature_episode_deletion_members member \
                     WHERE member.account_id=$1 AND member.episode_id=$2 \
                       AND member.record_type='utterance' AND member.record_id=utterance.id) \
             UNION \
             SELECT substr(screenshot.source_key,10) FROM screenshots screenshot \
              WHERE screenshot.account_id=$1 AND screenshot.source_key LIKE 'cloud-v2:%' \
                AND NOT EXISTS(SELECT 1 \
                      FROM persistence_feature_episode_deletion_members member \
                     WHERE member.account_id=$1 AND member.episode_id=$2 \
                       AND member.record_type='screenshot' AND member.record_id=screenshot.id) \
             UNION \
             SELECT observation.event_id FROM visual_speaker_observations observation \
               JOIN screenshots screenshot ON screenshot.account_id=observation.account_id \
                AND screenshot.id=observation.screenshot_id \
              WHERE screenshot.account_id=$1 AND NOT EXISTS(SELECT 1 \
                      FROM persistence_feature_episode_deletion_members member \
                     WHERE member.account_id=$1 AND member.episode_id=$2 \
                       AND member.record_type='screenshot' AND member.record_id=screenshot.id) \
         ), outside_roots(root_event_id) AS ( \
             SELECT DISTINCT coalesce(event.canonical_event_id,event.event_id) \
               FROM capture_events event JOIN outside_projection_events projection \
                 ON projection.event_id=event.event_id \
              WHERE event.account_id=$1 \
         ) \
         SELECT candidate.root_event_id FROM unnest($3::text[]) candidate(root_event_id) \
          WHERE candidate.root_event_id IN (SELECT root_event_id FROM outside_roots) \
          ORDER BY candidate.root_event_id",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&roots)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let orphan_roots = roots
        .iter()
        .filter(|root| !survivor_roots.contains(*root))
        .cloned()
        .collect::<Vec<_>>();
    if !roots.is_empty() {
        let provider_in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS( \
                SELECT 1 FROM media_processing_jobs job \
                  JOIN capture_events event ON event.account_id=job.account_id \
                   AND event.event_id=job.event_id \
                 WHERE job.account_id=$1 AND job.state='processing' \
                   AND job.lease_token IS NOT NULL AND job.lease_until>clock_timestamp() \
                   AND coalesce(event.canonical_event_id,event.event_id)=ANY($2::text[]) \
                UNION ALL \
                SELECT 1 FROM media_work_units work \
                  JOIN media_work_members member ON member.account_id=work.account_id \
                   AND member.work_unit_id=work.id \
                  JOIN capture_events event ON event.account_id=member.account_id \
                   AND event.event_id=member.event_id \
                 WHERE work.account_id=$1 AND work.state='processing' \
                   AND work.claim_token IS NOT NULL AND work.claim_until>clock_timestamp() \
                   AND coalesce(event.canonical_event_id,event.event_id)=ANY($2::text[]) \
                UNION ALL \
                SELECT 1 FROM capture_formation_receipts receipt \
                 WHERE receipt.account_id=$1 AND receipt.state='processing' \
                   AND receipt.claim_until>clock_timestamp() \
                   AND receipt.capture_session_id IN ( \
                       SELECT DISTINCT event.capture_session_id FROM capture_events event \
                        WHERE event.account_id=$1 \
                          AND coalesce(event.canonical_event_id,event.event_id)=ANY($2::text[])) \
            )",
        )
        .bind(account_id)
        .bind(&roots)
        .fetch_one(&mut **transaction)
        .await?;
        if provider_in_flight {
            return Err(EnclaveError::Conflict(
                "paged episode deletion source provider work is in flight".into(),
            ));
        }
    }
    let survivor_roots = survivor_roots.into_iter().collect::<Vec<_>>();
    if !survivor_roots.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_roots SET \
                 disposition='survivor',classified_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2 AND root_event_id=ANY($3::text[]) \
                AND disposition='pending'",
        )
        .bind(account_id)
        .bind(episode_id)
        .bind(&survivor_roots)
        .execute(&mut **transaction)
        .await?;
    }
    if !orphan_roots.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_roots SET \
                 disposition='orphan',classified_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2 AND root_event_id=ANY($3::text[]) \
                AND disposition='pending'",
        )
        .bind(account_id)
        .bind(episode_id)
        .bind(&orphan_roots)
        .execute(&mut **transaction)
        .await?;
    }
    let coordinates = roots
        .iter()
        .map(|root| {
            let disposition = if survivor_roots.contains(root) {
                b"survivor".as_slice()
            } else {
                b"orphan".as_slice()
            };
            coordinate_sha256(&[root.as_bytes(), disposition])
        })
        .collect::<Vec<_>>();
    let next_digest = advance_coordinate_sha256(prior_digest, coordinates);
    sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             phase=CASE WHEN $4 THEN phase ELSE 'inventory_family_sessions' END, \
             root_event_id_cursor=CASE WHEN $4 THEN $3 ELSE NULL END, \
             coordinate_sha256=$5,updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(roots.last().expect("nonempty bounded root page"))
    .bind(has_more)
    .bind(next_digest)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn inventory_paged_family_sessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    prior_digest: &[u8],
) -> Result<()> {
    let limit = i64::try_from(PAGED_DELETION_PAGE + 1)
        .map_err(|_| EnclaveError::Store("episode deletion session inventory overflow".into()))?;
    let rows = sqlx::query(
        "SELECT root.root_event_id,event.event_id,event.capture_session_id \
           FROM persistence_feature_episode_deletion_roots root \
           JOIN capture_events event ON event.account_id=root.account_id \
            AND coalesce(event.canonical_event_id,event.event_id)=root.root_event_id \
           JOIN persistence_feature_episode_deletion_progress progress \
             ON progress.account_id=root.account_id AND progress.episode_id=root.episode_id \
          WHERE root.account_id=$1 AND root.episode_id=$2 AND root.disposition<>'pending' \
            AND (progress.session_root_event_id_cursor IS NULL OR \
                 (root.root_event_id,event.event_id)> \
                 (progress.session_root_event_id_cursor,progress.session_event_id_cursor)) \
          ORDER BY root.root_event_id,event.event_id LIMIT $3 FOR KEY SHARE OF event",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    let has_more = rows.len() > PAGED_DELETION_PAGE;
    let rows = rows.iter().take(PAGED_DELETION_PAGE).collect::<Vec<_>>();
    if rows.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='inventory_family_events',session_root_event_id_cursor=NULL, \
                 session_event_id_cursor=NULL,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let mut session_ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("capture_session_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    session_ids.sort();
    session_ids.dedup();
    let formation_in_flight = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM capture_formation_receipts receipt \
          WHERE receipt.account_id=$1 AND receipt.capture_session_id=ANY($2::text[]) \
            AND receipt.state='processing' AND receipt.claim_until>clock_timestamp())",
    )
    .bind(account_id)
    .bind(&session_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if formation_in_flight {
        return Err(EnclaveError::Conflict(
            "capture formation provider work is in flight".into(),
        ));
    }
    let session_coordinates = session_ids
        .iter()
        .map(|session| coordinate_sha256(&[session.as_bytes()]))
        .collect::<Vec<_>>();
    let inserted = sqlx::query(
        "INSERT INTO persistence_feature_episode_deletion_sessions( \
             account_id,episode_id,capture_session_id,coordinate_sha256) \
         SELECT $1,$2,page.capture_session_id,page.coordinate_sha256 \
           FROM unnest($3::text[],$4::bytea[]) \
                AS page(capture_session_id,coordinate_sha256) \
         ON CONFLICT(account_id,episode_id,capture_session_id) DO NOTHING",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&session_ids)
    .bind(&session_coordinates)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let page_coordinates = rows
        .iter()
        .map(|row| {
            let root: String = row.get("root_event_id");
            let event: String = row.get("event_id");
            let session: String = row.get("capture_session_id");
            coordinate_sha256(&[root.as_bytes(), event.as_bytes(), session.as_bytes()])
        })
        .collect::<Vec<_>>();
    let next_digest = advance_coordinate_sha256(prior_digest, page_coordinates);
    let last = rows.last().expect("nonempty bounded session page");
    let last_root: String = last.try_get("root_event_id")?;
    let last_event: String = last.try_get("event_id")?;
    sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             phase=CASE WHEN $6 THEN phase ELSE 'inventory_family_events' END, \
             session_root_event_id_cursor=CASE WHEN $6 THEN $3 ELSE NULL END, \
             session_event_id_cursor=CASE WHEN $6 THEN $4 ELSE NULL END, \
             coordinate_sha256=$5,session_count=session_count+$7, \
             updated_at=clock_timestamp() WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(last_root)
    .bind(last_event)
    .bind(next_digest)
    .bind(has_more)
    .bind(
        i64::try_from(inserted)
            .map_err(|_| EnclaveError::Store("episode deletion session count overflow".into()))?,
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn inventory_paged_family_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    prior_digest: &[u8],
) -> Result<()> {
    let limit = i64::try_from(PAGED_DELETION_PAGE + 1)
        .map_err(|_| EnclaveError::Store("episode deletion event page overflow".into()))?;
    let rows = sqlx::query(
        "SELECT root.root_event_id,event.event_id,event.capture_session_id,event.stream_id, \
                event.sequence,event.manifest_digest \
           FROM persistence_feature_episode_deletion_roots root \
           JOIN capture_events event ON event.account_id=root.account_id \
            AND coalesce(event.canonical_event_id,event.event_id)=root.root_event_id \
           JOIN persistence_feature_episode_deletion_progress progress \
             ON progress.account_id=root.account_id AND progress.episode_id=root.episode_id \
          WHERE root.account_id=$1 AND root.episode_id=$2 AND root.disposition='orphan' \
            AND (progress.family_root_event_id_cursor IS NULL OR \
                 (root.root_event_id,event.event_id)> \
                 (progress.family_root_event_id_cursor,progress.family_event_id_cursor)) \
          ORDER BY root.root_event_id,event.event_id LIMIT $3 FOR KEY SHARE OF event",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    let has_more = rows.len() > PAGED_DELETION_PAGE;
    let rows = rows.iter().take(PAGED_DELETION_PAGE).collect::<Vec<_>>();
    if rows.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='provider_delete',family_root_event_id_cursor=NULL, \
                 family_event_id_cursor=NULL,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let event_ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("event_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let provider_in_flight = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS( \
            SELECT 1 FROM media_processing_jobs job \
             WHERE job.account_id=$1 AND job.event_id=ANY($2::text[]) \
               AND job.state='processing' AND job.lease_token IS NOT NULL \
               AND job.lease_until>clock_timestamp() \
            UNION ALL \
            SELECT 1 FROM media_work_units work \
              JOIN media_work_members member ON member.account_id=work.account_id \
               AND member.work_unit_id=work.id \
             WHERE member.account_id=$1 AND member.event_id=ANY($2::text[]) \
               AND work.state='processing' AND work.claim_token IS NOT NULL \
               AND work.claim_until>clock_timestamp() \
            UNION ALL \
            SELECT 1 FROM capture_formation_receipts receipt \
             WHERE receipt.account_id=$1 AND receipt.state='processing' \
               AND receipt.claim_until>clock_timestamp() \
               AND receipt.capture_session_id=ANY($3::text[]) \
        )",
    )
    .bind(account_id)
    .bind(&event_ids)
    .bind(
        rows.iter()
            .map(|row| row.try_get::<String, _>("capture_session_id"))
            .collect::<std::result::Result<Vec<_>, _>>()?,
    )
    .fetch_one(&mut **transaction)
    .await?;
    if provider_in_flight {
        return Err(EnclaveError::Conflict(
            "paged episode deletion source provider work is in flight".into(),
        ));
    }

    let root_ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("root_event_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let session_ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("capture_session_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let stream_ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("stream_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let sequences = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("sequence"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let manifests = rows
        .iter()
        .map(|row| row.try_get::<String, _>("manifest_digest"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let coordinates = (0..rows.len())
        .map(|index| {
            coordinate_sha256(&[
                root_ids[index].as_bytes(),
                event_ids[index].as_bytes(),
                session_ids[index].as_bytes(),
                stream_ids[index].as_bytes(),
                &sequences[index].to_be_bytes(),
                manifests[index].as_bytes(),
            ])
        })
        .collect::<Vec<_>>();
    let inserted_events = sqlx::query(
        "INSERT INTO persistence_feature_episode_deletion_events( \
             account_id,episode_id,root_event_id,event_id,capture_session_id,stream_id, \
             sequence,manifest_digest,coordinate_sha256) \
         SELECT $1,$2,page.root_event_id,page.event_id,page.capture_session_id,page.stream_id, \
                page.sequence,page.manifest_digest,page.coordinate_sha256 \
           FROM unnest($3::text[],$4::text[],$5::text[],$6::text[],$7::bigint[], \
                       $8::text[],$9::bytea[]) \
                AS page(root_event_id,event_id,capture_session_id,stream_id,sequence, \
                        manifest_digest,coordinate_sha256)",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&root_ids)
    .bind(&event_ids)
    .bind(&session_ids)
    .bind(&stream_ids)
    .bind(&sequences)
    .bind(&manifests)
    .bind(&coordinates)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let media_rows = sqlx::query(
        "SELECT object.object_key FROM media_objects object \
          WHERE object.account_id=$1 AND object.event_id=ANY($2::text[]) \
            AND object.deleted_at IS NULL ORDER BY object.object_key FOR KEY SHARE",
    )
    .bind(account_id)
    .bind(&event_ids)
    .fetch_all(&mut **transaction)
    .await?;
    let media_keys = media_rows
        .iter()
        .map(|row| row.try_get::<String, _>("object_key"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let media_coordinates = media_keys
        .iter()
        .map(|key| coordinate_sha256(&[key.as_bytes()]))
        .collect::<Vec<_>>();
    let inserted_objects = if media_keys.is_empty() {
        0
    } else {
        sqlx::query(
            "INSERT INTO persistence_feature_episode_deletion_objects( \
                 account_id,episode_id,object_key,object_kind,object_key_sha256) \
             SELECT $1,$2,page.object_key,'media_object',page.coordinate_sha256 \
               FROM unnest($3::text[],$4::bytea[]) \
                    AS page(object_key,coordinate_sha256) \
             ON CONFLICT(account_id,episode_id,object_key) DO NOTHING",
        )
        .bind(account_id)
        .bind(episode_id)
        .bind(&media_keys)
        .bind(&media_coordinates)
        .execute(&mut **transaction)
        .await?
        .rows_affected()
    };
    let next_digest = advance_coordinate_sha256(prior_digest, coordinates);
    let last = rows.last().expect("nonempty bounded event page");
    let last_root: String = last.try_get("root_event_id")?;
    let last_event: String = last.try_get("event_id")?;
    sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             phase=CASE WHEN $6 THEN phase ELSE 'provider_delete' END, \
             family_root_event_id_cursor=CASE WHEN $6 THEN $3 ELSE NULL END, \
             family_event_id_cursor=CASE WHEN $6 THEN $4 ELSE NULL END, \
             coordinate_sha256=$5,event_count=event_count+$7, \
             object_count=object_count+$8, \
             updated_at=clock_timestamp() WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(last_root)
    .bind(last_event)
    .bind(next_digest)
    .bind(has_more)
    .bind(
        i64::try_from(inserted_events)
            .map_err(|_| EnclaveError::Store("episode deletion event count overflow".into()))?,
    )
    .bind(
        i64::try_from(inserted_objects)
            .map_err(|_| EnclaveError::Store("episode deletion object count overflow".into()))?,
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn acknowledge_paged_provider_objects(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    acknowledged_keys: &[String],
) -> Result<()> {
    if !acknowledged_keys.is_empty() {
        let acknowledged = sqlx::query(
            "UPDATE persistence_feature_episode_deletion_objects SET \
                 provider_deleted_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2 \
                AND object_key=ANY($3::text[]) AND provider_deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(episode_id)
        .bind(acknowledged_keys)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if usize::try_from(acknowledged).ok() != Some(acknowledged_keys.len()) {
            return Err(EnclaveError::Conflict(
                "episode deletion provider acknowledgement is stale".into(),
            ));
        }
    }
    let remaining = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_objects \
          WHERE account_id=$1 AND episode_id=$2 AND provider_deleted_at IS NULL)",
    )
    .bind(account_id)
    .bind(episode_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !remaining {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='purge_members',updated_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn purge_paged_members(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
) -> Result<()> {
    let limit = i64::try_from(PAGED_DELETION_PAGE)
        .map_err(|_| EnclaveError::Store("episode deletion purge page overflow".into()))?;
    let rows = sqlx::query(
        "SELECT record_type,record_id,audio_segment_id \
           FROM persistence_feature_episode_deletion_members \
          WHERE account_id=$1 AND episode_id=$2 AND purged_at IS NULL \
          ORDER BY record_type,record_id LIMIT $3 FOR UPDATE",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='tombstone_events',updated_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let record_types = rows
        .iter()
        .map(|row| row.try_get::<String, _>("record_type"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let record_ids = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("record_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let deleted_members = sqlx::query(
        "DELETE FROM episode_members member USING \
             unnest($3::text[],$4::bigint[]) page(record_type,record_id) \
          WHERE member.account_id=$1 AND member.episode_id=$2 \
            AND member.record_type=page.record_type AND member.record_id=page.record_id",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&record_types)
    .bind(&record_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if usize::try_from(deleted_members).ok() != Some(rows.len()) {
        return Err(EnclaveError::Conflict(
            "episode deletion member inventory changed before purge".into(),
        ));
    }
    let utterance_ids = record_types
        .iter()
        .zip(&record_ids)
        .filter_map(|(kind, id)| (kind == "utterance").then_some(*id))
        .collect::<Vec<_>>();
    let screenshot_ids = record_types
        .iter()
        .zip(&record_ids)
        .filter_map(|(kind, id)| (kind == "screenshot").then_some(*id))
        .collect::<Vec<_>>();
    if !utterance_ids.is_empty() {
        let deleted = sqlx::query("DELETE FROM utterances WHERE account_id=$1 AND id=ANY($2)")
            .bind(account_id)
            .bind(&utterance_ids)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        if usize::try_from(deleted).ok() != Some(utterance_ids.len()) {
            return Err(EnclaveError::Conflict(
                "episode deletion utterance inventory changed before purge".into(),
            ));
        }
    }
    if !screenshot_ids.is_empty() {
        let deleted = sqlx::query("DELETE FROM screenshots WHERE account_id=$1 AND id=ANY($2)")
            .bind(account_id)
            .bind(&screenshot_ids)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        if usize::try_from(deleted).ok() != Some(screenshot_ids.len()) {
            return Err(EnclaveError::Conflict(
                "episode deletion screenshot inventory changed before purge".into(),
            ));
        }
    }
    let mut segment_ids = rows
        .iter()
        .filter_map(|row| {
            row.try_get::<Option<i64>, _>("audio_segment_id")
                .ok()
                .flatten()
        })
        .collect::<Vec<_>>();
    segment_ids.sort_unstable();
    segment_ids.dedup();
    let deleted_segments = if segment_ids.is_empty() {
        0
    } else {
        sqlx::query(
            "DELETE FROM audio_segments segment WHERE segment.account_id=$1 \
              AND segment.id=ANY($2::bigint[]) AND NOT EXISTS( \
                  SELECT 1 FROM utterances utterance \
                   WHERE utterance.account_id=segment.account_id \
                     AND utterance.audio_segment_id=segment.id)",
        )
        .bind(account_id)
        .bind(&segment_ids)
        .execute(&mut **transaction)
        .await?
        .rows_affected()
    };
    let marked = sqlx::query(
        "UPDATE persistence_feature_episode_deletion_members member SET \
             purged_at=clock_timestamp() FROM \
             unnest($3::text[],$4::bigint[]) page(record_type,record_id) \
          WHERE member.account_id=$1 AND member.episode_id=$2 \
            AND member.record_type=page.record_type AND member.record_id=page.record_id \
            AND member.purged_at IS NULL",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&record_types)
    .bind(&record_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if usize::try_from(marked).ok() != Some(rows.len()) {
        return Err(EnclaveError::Conflict(
            "episode deletion member progress changed concurrently".into(),
        ));
    }
    sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             segment_count=segment_count+$3,updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(
        i64::try_from(deleted_segments)
            .map_err(|_| EnclaveError::Store("episode deletion segment count overflow".into()))?,
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn tombstone_paged_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
) -> Result<()> {
    let limit = i64::try_from(PAGED_DELETION_PAGE)
        .map_err(|_| EnclaveError::Store("episode deletion tombstone page overflow".into()))?;
    let event_ids = sqlx::query_scalar::<_, String>(
        "SELECT event_id FROM persistence_feature_episode_deletion_events \
          WHERE account_id=$1 AND episode_id=$2 AND tombstoned_at IS NULL \
          ORDER BY event_id LIMIT $3 FOR UPDATE",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    if event_ids.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='purge_events',updated_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let inserted = sqlx::query(
        "INSERT INTO capture_formation_deleted_sequences( \
             account_id,capture_session_id,stream_id,sequence,event_id, \
             original_manifest_digest,deletion_episode_id,provenance) \
         SELECT planned.account_id,planned.capture_session_id,planned.stream_id, \
                planned.sequence,planned.event_id,planned.manifest_digest,planned.episode_id, \
                'episode_deletion_v1' \
           FROM persistence_feature_episode_deletion_events planned \
           JOIN capture_events event ON event.account_id=planned.account_id \
            AND event.event_id=planned.event_id \
            AND event.capture_session_id=planned.capture_session_id \
            AND event.stream_id=planned.stream_id AND event.sequence=planned.sequence \
            AND event.manifest_digest=planned.manifest_digest \
          WHERE planned.account_id=$1 AND planned.episode_id=$2 \
            AND planned.event_id=ANY($3::text[]) AND planned.tombstoned_at IS NULL \
          ORDER BY planned.event_id",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&event_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if usize::try_from(inserted).ok() != Some(event_ids.len()) {
        return Err(EnclaveError::Conflict(
            "episode deletion could not tombstone its exact paged capture family".into(),
        ));
    }
    let marked = sqlx::query(
        "UPDATE persistence_feature_episode_deletion_events SET \
             tombstoned_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2 AND event_id=ANY($3::text[]) \
            AND tombstoned_at IS NULL",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&event_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if usize::try_from(marked).ok() != Some(event_ids.len()) {
        return Err(EnclaveError::Conflict(
            "episode deletion tombstone progress changed concurrently".into(),
        ));
    }
    Ok(())
}

async fn purge_paged_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
) -> Result<()> {
    let limit = i64::try_from(PAGED_DELETION_PAGE)
        .map_err(|_| EnclaveError::Store("episode deletion event purge page overflow".into()))?;
    let event_ids = sqlx::query_scalar::<_, String>(
        "SELECT event_id FROM persistence_feature_episode_deletion_events \
          WHERE account_id=$1 AND episode_id=$2 AND tombstoned_at IS NOT NULL \
            AND purged_at IS NULL \
          ORDER BY root_event_id,(event_id=root_event_id),event_id LIMIT $3 FOR UPDATE",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    if event_ids.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='refresh_sessions',updated_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    let exact_events = sqlx::query_scalar::<_, String>(
        "SELECT event.event_id FROM capture_events event \
          JOIN persistence_feature_episode_deletion_events planned \
            ON planned.account_id=event.account_id AND planned.event_id=event.event_id \
           AND planned.capture_session_id=event.capture_session_id \
           AND planned.stream_id=event.stream_id AND planned.sequence=event.sequence \
           AND planned.manifest_digest=event.manifest_digest \
          WHERE planned.account_id=$1 AND planned.episode_id=$2 \
            AND planned.event_id=ANY($3::text[]) ORDER BY planned.event_id FOR UPDATE OF event",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&event_ids)
    .fetch_all(&mut **transaction)
    .await?;
    let mut sorted_event_ids = event_ids.clone();
    sorted_event_ids.sort();
    if exact_events != sorted_event_ids {
        return Err(EnclaveError::Conflict(
            "episode deletion capture family changed before paged purge".into(),
        ));
    }

    let affected_work_ids = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT member.work_unit_id FROM media_work_members member \
          WHERE member.account_id=$1 AND member.event_id=ANY($2::text[]) \
          ORDER BY member.work_unit_id",
    )
    .bind(account_id)
    .bind(&event_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if !affected_work_ids.is_empty() {
        let affected_work = sqlx::query(
            "SELECT id,state,claim_token IS NOT NULL \
                    AND claim_until>clock_timestamp() AS claim_live \
               FROM media_work_units WHERE account_id=$1 AND id=ANY($2::text[]) \
              ORDER BY id FOR UPDATE",
        )
        .bind(account_id)
        .bind(&affected_work_ids)
        .fetch_all(&mut **transaction)
        .await?;
        if affected_work.len() != affected_work_ids.len()
            || affected_work
                .iter()
                .any(|row| row.try_get::<bool, _>("claim_live").unwrap_or(false))
        {
            return Err(EnclaveError::Conflict(
                "episode media processing aggregate changed or is in flight".into(),
            ));
        }
        let affected_jobs = sqlx::query(
            "SELECT member.work_unit_id,member.event_id,job.id, \
                    job.lease_token IS NOT NULL AND job.lease_until>clock_timestamp() \
                        AS lease_live, \
                    job.state='processing' OR (job.state='retry_wait' \
                        AND job.updated_at<=clock_timestamp()) AS restart_due, \
                    NOT EXISTS(SELECT 1 \
                        FROM persistence_feature_episode_deletion_events planned \
                       WHERE planned.account_id=member.account_id \
                         AND planned.episode_id=$3 AND planned.event_id=member.event_id) \
                        AS survives_deletion \
               FROM media_work_members member \
               JOIN media_processing_jobs job ON job.account_id=member.account_id \
                AND job.id=member.job_id \
              WHERE member.account_id=$1 AND member.work_unit_id=ANY($2::text[]) \
              ORDER BY member.work_unit_id,member.ordinal FOR UPDATE OF job",
        )
        .bind(account_id)
        .bind(&affected_work_ids)
        .bind(episode_id)
        .fetch_all(&mut **transaction)
        .await?;
        if affected_jobs
            .iter()
            .any(|row| row.try_get::<bool, _>("lease_live").unwrap_or(false))
        {
            return Err(EnclaveError::Conflict(
                "episode media processing job is in flight".into(),
            ));
        }
        let nonterminal_work_ids = affected_work
            .iter()
            .filter_map(|row| {
                let state = row.try_get::<String, _>("state").ok()?;
                matches!(state.as_str(), "planned" | "processing" | "retry_wait")
                    .then(|| row.get::<String, _>("id"))
            })
            .collect::<Vec<_>>();
        let surviving_jobs = affected_jobs
            .iter()
            .filter_map(|row| {
                let work_id = row.try_get::<String, _>("work_unit_id").ok()?;
                (nonterminal_work_ids.contains(&work_id)
                    && row.try_get::<bool, _>("survives_deletion").ok()?)
                .then(|| {
                    Ok::<_, sqlx::Error>((
                        row.try_get::<i64, _>("id")?,
                        row.try_get::<String, _>("event_id")?,
                        row.try_get::<bool, _>("restart_due")?,
                    ))
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !nonterminal_work_ids.is_empty() {
            sqlx::query("DELETE FROM media_work_units WHERE account_id=$1 AND id=ANY($2::text[])")
                .bind(account_id)
                .bind(&nonterminal_work_ids)
                .execute(&mut **transaction)
                .await?;
        }
        let restart_job_ids = surviving_jobs
            .iter()
            .filter_map(|(job_id, _, due)| due.then_some(*job_id))
            .collect::<Vec<_>>();
        let delayed_job_ids = surviving_jobs
            .iter()
            .filter_map(|(job_id, _, due)| (!due).then_some(*job_id))
            .collect::<Vec<_>>();
        if !restart_job_ids.is_empty() {
            sqlx::query(
                "UPDATE media_processing_jobs SET state='pending',lease_owner=NULL, \
                     lease_token=NULL,lease_until=NULL,error_code=NULL,usage_json=NULL, \
                     updated_at=clock_timestamp() \
                  WHERE account_id=$1 AND id=ANY($2::bigint[])",
            )
            .bind(account_id)
            .bind(&restart_job_ids)
            .execute(&mut **transaction)
            .await?;
        }
        if !delayed_job_ids.is_empty() {
            sqlx::query(
                "UPDATE media_processing_jobs SET lease_owner=NULL,lease_token=NULL, \
                     lease_until=NULL,usage_json=NULL \
                  WHERE account_id=$1 AND id=ANY($2::bigint[])",
            )
            .bind(account_id)
            .bind(&delayed_job_ids)
            .execute(&mut **transaction)
            .await?;
        }
        if !surviving_jobs.is_empty() {
            sqlx::query(
                "UPDATE media_objects object SET processing_state= \
                    CASE WHEN job.state='pending' THEN 'queued' ELSE 'retry_wait' END \
                   FROM media_processing_jobs job \
                  WHERE object.account_id=$1 AND object.event_id=job.event_id \
                    AND job.id=ANY($2::bigint[])",
            )
            .bind(account_id)
            .bind(
                surviving_jobs
                    .iter()
                    .map(|(job_id, _, _)| *job_id)
                    .collect::<Vec<_>>(),
            )
            .execute(&mut **transaction)
            .await?;
        }
    }

    let deleted =
        sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id=ANY($2::text[])")
            .bind(account_id)
            .bind(&event_ids)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
    if usize::try_from(deleted).ok() != Some(event_ids.len()) {
        return Err(EnclaveError::Conflict(
            "episode deletion capture purge was not exact".into(),
        ));
    }
    if !affected_work_ids.is_empty() {
        sqlx::query(
            "DELETE FROM media_work_units work WHERE work.account_id=$1 \
                AND work.id=ANY($2::text[]) \
                AND NOT EXISTS(SELECT 1 FROM media_work_members member \
                     WHERE member.account_id=work.account_id AND member.work_unit_id=work.id)",
        )
        .bind(account_id)
        .bind(&affected_work_ids)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "UPDATE media_work_units work SET usage_json=CASE \
                WHEN jsonb_typeof(work.usage_json->'provider_attempts')='array' THEN \
                  jsonb_set(work.usage_json,'{provider_attempts}',coalesce(( \
                    SELECT jsonb_agg(entry.value || '{\"response_b64\":null}'::jsonb \
                                     ORDER BY entry.ordinal) \
                      FROM jsonb_array_elements(work.usage_json->'provider_attempts') \
                           WITH ORDINALITY AS entry(value,ordinal)), '[]'::jsonb)) \
                ELSE work.usage_json END,updated_at=clock_timestamp() \
              WHERE work.account_id=$1 AND work.id=ANY($2::text[])",
        )
        .bind(account_id)
        .bind(&affected_work_ids)
        .execute(&mut **transaction)
        .await?;
        let raw_remains = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM media_work_units work \
              CROSS JOIN LATERAL jsonb_array_elements( \
                CASE WHEN jsonb_typeof(work.usage_json->'provider_attempts')='array' \
                     THEN work.usage_json->'provider_attempts' ELSE '[]'::jsonb END) entry \
             WHERE work.account_id=$1 AND work.id=ANY($2::text[]) \
               AND entry->>'response_b64' IS NOT NULL)",
        )
        .bind(account_id)
        .bind(&affected_work_ids)
        .fetch_one(&mut **transaction)
        .await?;
        if raw_remains {
            return Err(EnclaveError::Store(
                "episode deletion retained raw media provider response bytes".into(),
            ));
        }
    }
    let marked = sqlx::query(
        "UPDATE persistence_feature_episode_deletion_events SET \
             purged_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2 AND event_id=ANY($3::text[]) \
            AND purged_at IS NULL",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&event_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if usize::try_from(marked).ok() != Some(event_ids.len()) {
        return Err(EnclaveError::Conflict(
            "episode deletion capture progress changed concurrently".into(),
        ));
    }
    Ok(())
}

async fn refresh_paged_sessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
) -> Result<()> {
    let limit = i64::try_from(PAGED_PROVIDER_OBJECT_PAGE)
        .map_err(|_| EnclaveError::Store("episode deletion session page overflow".into()))?;
    let session_ids = sqlx::query_scalar::<_, String>(
        "SELECT capture_session_id FROM persistence_feature_episode_deletion_sessions \
          WHERE account_id=$1 AND episode_id=$2 AND refreshed_at IS NULL \
          ORDER BY capture_session_id LIMIT $3 FOR UPDATE",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    if session_ids.is_empty() {
        sqlx::query(
            "UPDATE persistence_feature_episode_deletion_progress SET \
                 phase='finalize',updated_at=clock_timestamp() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    for capture_session_id in &session_ids {
        super::memory_formation::refresh_capture_formation_receipt(
            transaction,
            account_id,
            capture_session_id,
        )
        .await?;
    }
    let marked = sqlx::query(
        "UPDATE persistence_feature_episode_deletion_sessions SET \
             refreshed_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2 \
            AND capture_session_id=ANY($3::text[]) AND refreshed_at IS NULL",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(&session_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if usize::try_from(marked).ok() != Some(session_ids.len()) {
        return Err(EnclaveError::Conflict(
            "episode deletion session refresh changed concurrently".into(),
        ));
    }
    Ok(())
}

async fn finalize_paged_deletion(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
) -> Result<EpisodePurge> {
    let incomplete = sqlx::query_scalar::<_, bool>(
        "SELECT \
           EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_roots \
                   WHERE account_id=$1 AND episode_id=$2 AND disposition='pending') OR \
           EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_objects \
                   WHERE account_id=$1 AND episode_id=$2 AND provider_deleted_at IS NULL) OR \
           EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_members \
                   WHERE account_id=$1 AND episode_id=$2 AND purged_at IS NULL) OR \
           EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_events \
                   WHERE account_id=$1 AND episode_id=$2 \
                     AND (tombstoned_at IS NULL OR purged_at IS NULL)) OR \
           EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_sessions \
                   WHERE account_id=$1 AND episode_id=$2 AND refreshed_at IS NULL) OR \
           EXISTS(SELECT 1 FROM episode_members \
                   WHERE account_id=$1 AND episode_id=$2)",
    )
    .bind(account_id)
    .bind(episode_id)
    .fetch_one(&mut **transaction)
    .await?;
    if incomplete {
        return Err(EnclaveError::Conflict(
            "episode deletion cannot finalize before exact paged closure".into(),
        ));
    }
    let delivery = paged_source_key_delivery(transaction, account_id, episode_id).await?;
    if !delivery.purge.source_key_delivery_complete {
        // Local source authority must acknowledge this exact bounded page
        // before the durable episode and terminal receipt can disappear.
        return Ok(delivery.purge);
    }
    let purge = delivery.purge;
    let purge_json = serde_json::to_string(&purge)?;
    let deleted = sqlx::query("DELETE FROM episodes WHERE account_id=$1 AND id=$2")
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    if deleted != 1 {
        return Err(EnclaveError::Conflict(
            "episode deletion target changed before finalization".into(),
        ));
    }
    sqlx::query(
        "UPDATE episode_deletions SET state='complete',purge=$3::jsonb, \
             media_object_keys='[]'::jsonb,utterance_ids='[]'::jsonb, \
             screenshot_ids='[]'::jsonb,segment_ids='[]'::jsonb, \
             orphan_event_ids='[]'::jsonb,completed_at=clock_timestamp(), \
             updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2 AND state='pending'",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(purge_json)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             phase='complete',completed_at=clock_timestamp(),updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2 AND phase='finalize'",
    )
    .bind(account_id)
    .bind(episode_id)
    .execute(&mut **transaction)
    .await?;
    Ok(purge)
}

async fn acknowledge_paged_source_key_delivery(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    source_key_cursor: &str,
) -> Result<EpisodePurge> {
    let progress = sqlx::query(
        "SELECT phase,member_record_type_cursor,member_record_id_cursor \
           FROM persistence_feature_episode_deletion_progress \
          WHERE account_id=$1 AND episode_id=$2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(episode_id)
    .fetch_one(&mut **transaction)
    .await?;
    let phase: String = progress.try_get("phase")?;
    if !matches!(phase.as_str(), "finalize" | "complete") {
        return Err(EnclaveError::Conflict(
            "episode deletion source keys are not ready for acknowledgement".into(),
        ));
    }
    let acknowledged_type: Option<String> = progress.try_get("member_record_type_cursor")?;
    let acknowledged_id: Option<i64> = progress.try_get("member_record_id_cursor")?;
    let delivery = paged_source_key_delivery(transaction, account_id, episode_id).await?;

    // An ACK response may be lost after its transaction commits. The token for
    // the persisted position therefore replays the current next page exactly;
    // anything older than that single step is stale and cannot skip forward.
    if delivery.acknowledged_cursor.as_deref() == Some(source_key_cursor) {
        return Ok(delivery.purge);
    }
    if phase != "finalize" || delivery.purge.source_key_cursor.as_deref() != Some(source_key_cursor)
    {
        return Err(EnclaveError::Conflict(
            "episode deletion source-key cursor is wrong or stale".into(),
        ));
    }
    let (record_type, record_id) = delivery.last_coordinate.ok_or_else(|| {
        EnclaveError::Conflict("episode deletion source-key cursor has no page".into())
    })?;
    let advanced = sqlx::query(
        "UPDATE persistence_feature_episode_deletion_progress SET \
             member_record_type_cursor=$3,member_record_id_cursor=$4, \
             updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2 AND phase='finalize' \
            AND member_record_type_cursor IS NOT DISTINCT FROM $5::text \
            AND member_record_id_cursor IS NOT DISTINCT FROM $6::bigint",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(record_type)
    .bind(record_id)
    .bind(acknowledged_type.as_deref())
    .bind(acknowledged_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if advanced != 1 {
        return Err(EnclaveError::Conflict(
            "episode deletion source-key acknowledgement changed concurrently".into(),
        ));
    }
    let next = paged_source_key_delivery(transaction, account_id, episode_id).await?;
    if next.purge.source_key_delivery_complete {
        finalize_paged_deletion(transaction, account_id, episode_id).await
    } else {
        Ok(next.purge)
    }
}

async fn advance_paged_deletion(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    plan: &EpisodeDeletionPlan,
) -> Result<Option<EpisodePurge>> {
    let row = sqlx::query(
        "SELECT phase,coordinate_sha256 FROM persistence_feature_episode_deletion_progress \
          WHERE account_id=$1 AND episode_id=$2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(plan.episode_id)
    .fetch_one(&mut **transaction)
    .await?;
    let phase: String = row.try_get("phase")?;
    let digest: Vec<u8> = row.try_get("coordinate_sha256")?;
    match phase.as_str() {
        "inventory_members" => {
            inventory_paged_members(transaction, account_id, plan.episode_id, &digest).await?
        }
        "inventory_projection_events" => {
            inventory_paged_projection_events(transaction, account_id, plan.episode_id, &digest)
                .await?
        }
        "inventory_episode_objects" => {
            inventory_paged_episode_objects(transaction, account_id, plan.episode_id, &digest)
                .await?
        }
        "classify_roots" => {
            classify_paged_roots(transaction, account_id, plan.episode_id, &digest).await?
        }
        "inventory_family_sessions" => {
            inventory_paged_family_sessions(transaction, account_id, plan.episode_id, &digest)
                .await?
        }
        "inventory_family_events" => {
            inventory_paged_family_events(transaction, account_id, plan.episode_id, &digest).await?
        }
        "provider_delete" => {
            acknowledge_paged_provider_objects(
                transaction,
                account_id,
                plan.episode_id,
                &plan.media_object_keys,
            )
            .await?
        }
        "purge_members" => purge_paged_members(transaction, account_id, plan.episode_id).await?,
        "tombstone_events" => {
            tombstone_paged_events(transaction, account_id, plan.episode_id).await?
        }
        "purge_events" => purge_paged_events(transaction, account_id, plan.episode_id).await?,
        "refresh_sessions" => {
            refresh_paged_sessions(transaction, account_id, plan.episode_id).await?
        }
        "finalize" => {
            return finalize_paged_deletion(transaction, account_id, plan.episode_id)
                .await
                .map(Some)
        }
        "complete" => {
            return paged_source_key_delivery(transaction, account_id, plan.episode_id)
                .await
                .map(|delivery| Some(delivery.purge))
        }
        _ => {
            return Err(EnclaveError::Store(
                "episode deletion has an invalid paged phase".into(),
            ))
        }
    }
    sqlx::query(
        "UPDATE episode_deletions SET updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=$2 AND state='pending'",
    )
    .bind(account_id)
    .bind(plan.episode_id)
    .execute(&mut **transaction)
    .await?;
    Ok(None)
}

async fn affected_capture_sessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    utterance_ids: &[i64],
    screenshot_ids: &[i64],
) -> Result<Vec<String>> {
    let limit = i64::try_from(MAX_AFFECTED_CAPTURE_SESSIONS + 1)
        .map_err(|_| EnclaveError::Store("episode deletion session bound overflow".into()))?;
    let sessions = sqlx::query_scalar::<_, String>(
        "WITH projection_events(event_id) AS ( \
             SELECT DISTINCT split_part(substr(utterance.source_key,10),':',1) \
               FROM utterances utterance \
              WHERE utterance.account_id=$1 AND utterance.id=ANY($2::bigint[]) \
                AND utterance.source_key LIKE 'cloud-v2:%' \
             UNION \
             SELECT DISTINCT substr(screenshot.source_key,10) \
               FROM screenshots screenshot \
              WHERE screenshot.account_id=$1 AND screenshot.id=ANY($3::bigint[]) \
                AND screenshot.source_key LIKE 'cloud-v2:%' \
             UNION \
             SELECT DISTINCT observation.event_id \
               FROM utterances utterance \
               JOIN speaker_observations observation \
                 ON observation.account_id=utterance.account_id \
                AND observation.id=utterance.speaker_observation_id \
              WHERE utterance.account_id=$1 AND utterance.id=ANY($2::bigint[]) \
             UNION \
             SELECT DISTINCT source.event_id \
               FROM utterances utterance \
               JOIN speaker_observation_sources source \
                 ON source.account_id=utterance.account_id \
                AND source.speaker_observation_id=utterance.speaker_observation_id \
              WHERE utterance.account_id=$1 AND utterance.id=ANY($2::bigint[]) \
         ), canonical_events(event_id) AS ( \
             SELECT DISTINCT coalesce(event.canonical_event_id,event.event_id) \
               FROM capture_events event \
              WHERE event.account_id=$1 AND ( \
                    event.event_id IN (SELECT event_id FROM projection_events) \
                    OR event.canonical_event_id IN (SELECT event_id FROM projection_events)) \
         ) \
         SELECT DISTINCT event.capture_session_id \
           FROM capture_events event \
          WHERE event.account_id=$1 \
            AND coalesce(event.canonical_event_id,event.event_id) IN ( \
                SELECT event_id FROM canonical_events) \
          ORDER BY event.capture_session_id LIMIT $4",
    )
    .bind(account_id)
    .bind(utterance_ids)
    .bind(screenshot_ids)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    if sessions.len() > MAX_AFFECTED_CAPTURE_SESSIONS {
        return Err(EnclaveError::Conflict(
            "episode deletion affects too many capture sessions for one atomic operation".into(),
        ));
    }
    Ok(sessions)
}

/// Resolve and lock the complete canonical/reference families touched by the
/// projections being deleted. A family is eligible only when no projection
/// outside this deletion still refers to any member. Locking every existing
/// member also fences a concurrent reference insert through the canonical FK.
async fn deletable_capture_event_family(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    candidate_event_ids: &[String],
    utterance_ids: &[i64],
    screenshot_ids: &[i64],
) -> Result<Vec<String>> {
    if candidate_event_ids.is_empty() {
        return Ok(Vec::new());
    }
    let roots = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT coalesce(event.canonical_event_id,event.event_id) \
           FROM capture_events event \
          WHERE event.account_id=$1 AND event.event_id=ANY($2::text[]) \
          ORDER BY coalesce(event.canonical_event_id,event.event_id)",
    )
    .bind(account_id)
    .bind(candidate_event_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let invalid_roots = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM capture_events root \
          WHERE root.account_id=$1 AND root.event_id=ANY($2::text[]) \
            AND root.canonical_event_id IS NOT NULL",
    )
    .bind(account_id)
    .bind(&roots)
    .fetch_one(&mut **transaction)
    .await?;
    if invalid_roots != 0 {
        return Err(EnclaveError::Conflict(
            "episode deletion found a non-canonical capture reference chain".into(),
        ));
    }
    let family_rows = sqlx::query(
        "SELECT event.event_id,coalesce(event.canonical_event_id,event.event_id) AS root_event_id \
           FROM capture_events event \
          WHERE event.account_id=$1 \
            AND coalesce(event.canonical_event_id,event.event_id)=ANY($2::text[]) \
          ORDER BY event.event_id FOR UPDATE",
    )
    .bind(account_id)
    .bind(&roots)
    .fetch_all(&mut **transaction)
    .await?;
    if family_rows.len() > MAX_DELETED_CAPTURE_EVENTS {
        return Err(EnclaveError::Conflict(
            "episode deletion capture-event family exceeds its atomic bound".into(),
        ));
    }
    let survivor_roots = sqlx::query_scalar::<_, String>(
        "WITH outside_owned_projection_events(event_id) AS ( \
             SELECT split_part(substr(utterance.source_key,10),':',1) \
              FROM active_episode_members owner JOIN utterances utterance \
                 ON owner.record_type='utterance' AND utterance.account_id=owner.account_id \
                AND utterance.id=owner.record_id \
              WHERE owner.account_id=$1 AND owner.episode_id<>$5 \
                AND utterance.source_key LIKE 'cloud-v2:%' \
             UNION \
             SELECT observation.event_id \
               FROM active_episode_members owner JOIN utterances utterance \
                 ON owner.record_type='utterance' AND utterance.account_id=owner.account_id \
                AND utterance.id=owner.record_id \
               JOIN speaker_observations observation \
                 ON observation.account_id=utterance.account_id \
                AND observation.id=utterance.speaker_observation_id \
              WHERE owner.account_id=$1 AND owner.episode_id<>$5 \
             UNION \
             SELECT source.event_id \
               FROM active_episode_members owner JOIN utterances utterance \
                 ON owner.record_type='utterance' AND utterance.account_id=owner.account_id \
                AND utterance.id=owner.record_id \
               JOIN speaker_observation_sources source \
                 ON source.account_id=utterance.account_id \
                AND source.speaker_observation_id=utterance.speaker_observation_id \
              WHERE owner.account_id=$1 AND owner.episode_id<>$5 \
             UNION \
             SELECT substr(screenshot.source_key,10) \
               FROM active_episode_members owner JOIN screenshots screenshot \
                 ON owner.record_type='screenshot' AND screenshot.account_id=owner.account_id \
                AND screenshot.id=owner.record_id \
              WHERE owner.account_id=$1 AND owner.episode_id<>$5 \
                AND screenshot.source_key LIKE 'cloud-v2:%' \
             UNION \
             SELECT observation.event_id \
               FROM active_episode_members owner JOIN screenshots screenshot \
                 ON owner.record_type='screenshot' AND screenshot.account_id=owner.account_id \
                AND screenshot.id=owner.record_id \
               JOIN visual_speaker_observations observation \
                 ON observation.account_id=screenshot.account_id \
                AND observation.screenshot_id=screenshot.id \
              WHERE owner.account_id=$1 AND owner.episode_id<>$5 \
         ), outside_owned_roots(root_event_id) AS ( \
             SELECT DISTINCT coalesce(source.canonical_event_id,source.event_id) \
               FROM capture_events source \
              WHERE source.account_id=$1 AND ( \
                    source.event_id IN (SELECT event_id FROM outside_owned_projection_events) \
                    OR source.canonical_event_id IN ( \
                        SELECT event_id FROM outside_owned_projection_events)) \
         ) \
         SELECT DISTINCT coalesce(event.canonical_event_id,event.event_id) \
           FROM capture_events event \
          WHERE event.account_id=$1 \
            AND coalesce(event.canonical_event_id,event.event_id)=ANY($2::text[]) \
            AND ( \
                EXISTS(SELECT 1 FROM utterances utterance \
                        WHERE utterance.account_id=$1 \
                          AND NOT (utterance.id=ANY($3::bigint[])) \
                          AND utterance.source_key LIKE 'cloud-v2:%' \
                          AND split_part(substr(utterance.source_key,10),':',1)=event.event_id) \
                OR EXISTS(SELECT 1 FROM screenshots screenshot \
                          WHERE screenshot.account_id=$1 \
                            AND NOT (screenshot.id=ANY($4::bigint[])) \
                            AND screenshot.source_key='cloud-v2:'||event.event_id) \
                OR EXISTS(SELECT 1 FROM utterances utterance \
                          JOIN speaker_observations observation \
                            ON observation.account_id=utterance.account_id \
                           AND observation.id=utterance.speaker_observation_id \
                         WHERE utterance.account_id=$1 \
                           AND NOT (utterance.id=ANY($3::bigint[])) \
                           AND observation.event_id=event.event_id) \
                OR EXISTS(SELECT 1 FROM utterances utterance \
                          JOIN speaker_observation_sources source \
                            ON source.account_id=utterance.account_id \
                           AND source.speaker_observation_id=utterance.speaker_observation_id \
                         WHERE utterance.account_id=$1 \
                           AND NOT (utterance.id=ANY($3::bigint[])) \
                           AND source.event_id=event.event_id) \
                OR EXISTS(SELECT 1 FROM visual_speaker_observations observation \
                          WHERE observation.account_id=$1 \
                            AND observation.event_id=event.event_id \
                            AND NOT (observation.screenshot_id=ANY($4::bigint[]))) \
                OR coalesce(event.canonical_event_id,event.event_id) IN ( \
                    SELECT root_event_id FROM outside_owned_roots) \
            ) \
          ORDER BY coalesce(event.canonical_event_id,event.event_id)",
    )
    .bind(account_id)
    .bind(&roots)
    .bind(utterance_ids)
    .bind(screenshot_ids)
    .bind(episode_id)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut deletable = Vec::with_capacity(family_rows.len());
    for row in family_rows {
        let root: String = row.try_get("root_event_id")?;
        if !survivor_roots.contains(&root) {
            deletable.push(row.try_get("event_id")?);
        }
    }
    Ok(deletable)
}

fn event_id(source_key: &str) -> Option<&str> {
    let value = source_key.strip_prefix("cloud-v2:")?;
    value.split(':').next().filter(|value| !value.is_empty())
}

fn decode_plan(episode_id: i64, purge: String, media: String) -> Result<EpisodeDeletionPlan> {
    Ok(EpisodeDeletionPlan {
        episode_id,
        purge: serde_json::from_str(&purge)?,
        media_object_keys: serde_json::from_str(&media)?,
    })
}

#[async_trait]
impl EpisodeDeletionRepository for PostgresPersistence {
    async fn begin_episode_deletion(
        &self,
        account_id: &str,
        episode_id: i64,
    ) -> Result<EpisodeDeletionStart> {
        if episode_id <= 0 {
            return Err(EnclaveError::InvalidRequest(
                "episode id must be positive".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let activation_installed =
            lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        // Serialize deletion with reconciliation claim admission. A live
        // processing lease is the durable fence proving that provider egress
        // may be in flight; deletion waits for the account lock, then refuses
        // until that bounded lease is released or expires. Conversely, once
        // deletion marks the episode, the claim-side snapshot revalidation
        // fails before any provider request can begin.
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        if let Some(row) = sqlx::query(
            "SELECT state,purge::text AS purge,media_object_keys::text AS media \
               FROM episode_deletions WHERE account_id=$1 AND episode_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let state: String = row.try_get("state")?;
            let paged = activation_installed
                && paged_episode_deletion_exists(&mut transaction, account_id, episode_id).await?;
            let plan = if paged && state == "pending" {
                paged_pending_plan(&mut transaction, account_id, episode_id).await?
            } else if paged && state == "complete" {
                EpisodeDeletionPlan {
                    episode_id,
                    purge: paged_source_key_delivery(&mut transaction, account_id, episode_id)
                        .await?
                        .purge,
                    media_object_keys: Vec::new(),
                }
            } else {
                decode_plan(episode_id, row.try_get("purge")?, row.try_get("media")?)?
            };
            transaction.rollback().await?;
            return match state.as_str() {
                "pending" => Ok(EpisodeDeletionStart::Pending(plan)),
                "complete" => Ok(EpisodeDeletionStart::Complete(plan.purge)),
                _ => Err(EnclaveError::Store(
                    "episode deletion has an invalid state".into(),
                )),
            };
        }
        let reconciliation_in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memory_reconciliation_jobs \
              WHERE account_id=$1 AND state='processing' \
                AND claim_until>clock_timestamp() \
                AND predecessor_episode_ids @> ARRAY[$2]::bigint[])",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_one(&mut *transaction)
        .await?;
        if reconciliation_in_flight {
            return Err(EnclaveError::Conflict(
                "episode reconciliation is in flight".into(),
            ));
        }
        let summary_in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM summary_window_claims \
              WHERE account_id=$1 AND state='processing' \
                AND claim_until>clock_timestamp())",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        if summary_in_flight {
            return Err(EnclaveError::Conflict(
                "episode summarization provider work is in flight".into(),
            ));
        }
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM episodes WHERE account_id=$1 AND id=$2 FOR UPDATE)",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !exists {
            transaction.rollback().await?;
            return Ok(EpisodeDeletionStart::NotFound);
        }
        let finalization_in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT finalization_claim_token IS NOT NULL \
                    AND finalization_claim_until>clock_timestamp() \
               FROM episodes WHERE account_id=$1 AND id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_one(&mut *transaction)
        .await?;
        if finalization_in_flight {
            return Err(EnclaveError::Conflict(
                "episode finalization provider work is in flight".into(),
            ));
        }

        if paged_episode_deletion_enabled(&mut transaction, activation_installed).await? {
            let other_pending_episode = sqlx::query_scalar::<_, i64>(
                "SELECT deletion.episode_id FROM episode_deletions deletion \
                   JOIN persistence_feature_episode_deletion_progress progress \
                     ON progress.account_id=deletion.account_id \
                    AND progress.episode_id=deletion.episode_id \
                  WHERE deletion.account_id=$1 AND deletion.state='pending' \
                  ORDER BY deletion.episode_id LIMIT 1 FOR UPDATE OF deletion",
            )
            .bind(account_id)
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(other_episode_id) = other_pending_episode {
                return Err(EnclaveError::Conflict(format!(
                    "episode {other_episode_id} is already pending deletion for this account"
                )));
            }
            let purge = empty_purge();
            let purge_json = serde_json::to_string(&purge)?;
            sqlx::query(
                "UPDATE episodes SET finalization_status='deleting', \
                     finalization_claim_token=NULL,finalization_claim_until=NULL, \
                     updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",
            )
            .bind(account_id)
            .bind(episode_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO episode_deletions(account_id,episode_id,state,purge, \
                     media_object_keys,utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) \
                 VALUES($1,$2,'pending',$3::jsonb,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb, \
                        '[]'::jsonb,'[]'::jsonb)",
            )
            .bind(account_id)
            .bind(episode_id)
            .bind(purge_json)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO persistence_feature_episode_deletion_progress( \
                     account_id,episode_id,phase,coordinate_sha256) \
                 VALUES($1,$2,'inventory_members',$3)",
            )
            .bind(account_id)
            .bind(episode_id)
            .bind(Sha256::digest(b"kioku.episode-deletion.coordinates.empty.v1\0").to_vec())
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(EpisodeDeletionStart::Pending(EpisodeDeletionPlan {
                episode_id,
                purge,
                media_object_keys: Vec::new(),
            }));
        }

        let utterances = sqlx::query(
            "SELECT u.id,u.source_key,u.audio_segment_id \
               FROM episode_members m JOIN utterances u \
                 ON u.account_id=m.account_id AND u.id=m.record_id \
              WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='utterance' \
              ORDER BY u.id",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(&mut *transaction)
        .await?;
        let screenshots = sqlx::query(
            "SELECT s.id,s.source_key FROM episode_members m JOIN screenshots s \
                 ON s.account_id=m.account_id AND s.id=m.record_id \
              WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='screenshot' \
              ORDER BY s.id",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(&mut *transaction)
        .await?;
        let utterance_ids = utterances
            .iter()
            .map(|row| row.try_get("id"))
            .collect::<std::result::Result<Vec<i64>, _>>()?;
        let screenshot_ids = screenshots
            .iter()
            .map(|row| row.try_get("id"))
            .collect::<std::result::Result<Vec<i64>, _>>()?;
        if activation_installed {
            let affected_sessions = affected_capture_sessions(
                &mut transaction,
                account_id,
                &utterance_ids,
                &screenshot_ids,
            )
            .await?;
            let formation_in_flight = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM capture_formation_receipts \
                  WHERE account_id=$1 AND capture_session_id=ANY($2::text[]) \
                    AND state='processing' AND claim_until>clock_timestamp())",
            )
            .bind(account_id)
            .bind(&affected_sessions)
            .fetch_one(&mut *transaction)
            .await?;
            if formation_in_flight {
                return Err(EnclaveError::Conflict(
                    "capture formation provider work is in flight".into(),
                ));
            }
        }
        let utterance_source_keys = utterances
            .iter()
            .filter_map(|row| {
                row.try_get::<Option<String>, _>("source_key")
                    .ok()
                    .flatten()
            })
            .collect::<Vec<_>>();
        let screenshot_source_keys = screenshots
            .iter()
            .filter_map(|row| {
                row.try_get::<Option<String>, _>("source_key")
                    .ok()
                    .flatten()
            })
            .collect::<Vec<_>>();
        let segment_ids = utterances
            .iter()
            .map(|row| row.try_get("audio_segment_id"))
            .collect::<std::result::Result<Vec<i64>, _>>()?;

        let mut candidate_events = BTreeSet::new();
        for source in utterance_source_keys
            .iter()
            .chain(screenshot_source_keys.iter())
        {
            if let Some(event) = event_id(source) {
                candidate_events.insert(event.to_owned());
            }
        }
        candidate_events.extend(
            sqlx::query_scalar::<_, String>(
                "SELECT DISTINCT event_id FROM ( \
                     SELECT observation.event_id \
                       FROM utterances utterance \
                       JOIN speaker_observations observation \
                         ON observation.account_id=utterance.account_id \
                        AND observation.id=utterance.speaker_observation_id \
                      WHERE utterance.account_id=$1 AND utterance.id=ANY($2::bigint[]) \
                     UNION \
                     SELECT source.event_id \
                       FROM utterances utterance \
                       JOIN speaker_observation_sources source \
                         ON source.account_id=utterance.account_id \
                        AND source.speaker_observation_id=utterance.speaker_observation_id \
                      WHERE utterance.account_id=$1 AND utterance.id=ANY($2::bigint[]) \
                     UNION \
                     SELECT observation.event_id \
                       FROM visual_speaker_observations observation \
                      WHERE observation.account_id=$1 \
                        AND observation.screenshot_id=ANY($3::bigint[]) \
                ) projection_events ORDER BY event_id",
            )
            .bind(account_id)
            .bind(&utterance_ids)
            .bind(&screenshot_ids)
            .fetch_all(&mut *transaction)
            .await?,
        );
        let candidate_events = candidate_events.into_iter().collect::<Vec<_>>();
        let orphan_events = deletable_capture_event_family(
            &mut transaction,
            account_id,
            episode_id,
            &candidate_events,
            &utterance_ids,
            &screenshot_ids,
        )
        .await?;

        // A provider-authorized media claim is a bounded disclosure fence.
        // Reservation authorization renews both the exact jobs and aggregate
        // work under this same activation/account lock order, so either side
        // wins atomically: deletion-first persists its family before egress,
        // while claim-first makes deletion retry after settlement/expiry.
        if !orphan_events.is_empty() {
            let media_provider_in_flight = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS( \
                    SELECT 1 FROM media_processing_jobs job \
                    JOIN capture_events event \
                      ON event.account_id=job.account_id AND event.event_id=job.event_id \
                    WHERE job.account_id=$1 AND job.state='processing' \
                      AND job.lease_token IS NOT NULL \
                      AND job.lease_until>clock_timestamp() \
                      AND (event.event_id=ANY($2::text[]) OR \
                           coalesce(event.canonical_event_id,event.event_id)=ANY($2::text[])) \
                    UNION ALL \
                    SELECT 1 FROM media_work_units work \
                    JOIN media_work_members member \
                      ON member.account_id=work.account_id \
                     AND member.work_unit_id=work.id \
                    JOIN capture_events event \
                      ON event.account_id=member.account_id \
                     AND event.event_id=member.event_id \
                    WHERE work.account_id=$1 AND work.state='processing' \
                      AND work.claim_token IS NOT NULL \
                      AND work.claim_until>clock_timestamp() \
                      AND (event.event_id=ANY($2::text[]) OR \
                           coalesce(event.canonical_event_id,event.event_id)=ANY($2::text[])) \
                )",
            )
            .bind(account_id)
            .bind(&orphan_events)
            .fetch_one(&mut *transaction)
            .await?;
            if media_provider_in_flight {
                return Err(EnclaveError::Conflict(
                    "episode media processing provider work is in flight".into(),
                ));
            }
        }

        let mut media_object_keys = sqlx::query_scalar::<_, String>(
            "SELECT object_key FROM screenshot_images WHERE account_id=$1 AND episode_id=$2 \
              ORDER BY object_key",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(&mut *transaction)
        .await?;
        if !orphan_events.is_empty() {
            media_object_keys.extend(
                sqlx::query_scalar::<_, String>(
                    "SELECT object_key FROM media_objects WHERE account_id=$1 \
                       AND event_id=ANY($2) AND deleted_at IS NULL ORDER BY object_key",
                )
                .bind(account_id)
                .bind(&orphan_events)
                .fetch_all(&mut *transaction)
                .await?,
            );
        }
        media_object_keys.sort();
        media_object_keys.dedup();

        let remaining_segments = if segment_ids.is_empty() {
            0
        } else {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM audio_segments s WHERE s.account_id=$1 AND s.id=ANY($2) \
                  AND NOT EXISTS (SELECT 1 FROM utterances u WHERE u.account_id=s.account_id \
                    AND u.audio_segment_id=s.id AND NOT (u.id=ANY($3)))",
            )
            .bind(account_id)
            .bind(&segment_ids)
            .bind(&utterance_ids)
            .fetch_one(&mut *transaction)
            .await?
        };
        let purge = EpisodePurge {
            deleted_utterances: utterance_ids.len(),
            deleted_screenshots: screenshot_ids.len(),
            deleted_segments: usize::try_from(remaining_segments)
                .map_err(|_| EnclaveError::Store("episode segment count overflow".into()))?,
            utterance_source_keys,
            screenshot_source_keys,
            source_key_cursor: None,
            source_key_delivery_complete: true,
        };
        let purge_json = serde_json::to_string(&purge)?;
        let media_json = serde_json::to_string(&media_object_keys)?;
        let utterance_json = serde_json::to_string(&utterance_ids)?;
        let screenshot_json = serde_json::to_string(&screenshot_ids)?;
        let segment_json = serde_json::to_string(&segment_ids)?;
        let orphan_json = serde_json::to_string(&orphan_events)?;
        sqlx::query(
            "UPDATE episodes SET finalization_status='deleting',finalization_claim_token=NULL,\
                    finalization_claim_until=NULL,updated_at=now() WHERE account_id=$1 AND id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO episode_deletions(account_id,episode_id,state,purge,media_object_keys,\
                    utterance_ids,screenshot_ids,segment_ids,orphan_event_ids) \
             VALUES($1,$2,'pending',$3::jsonb,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb)",
        )
        .bind(account_id)
        .bind(episode_id)
        .bind(&purge_json)
        .bind(&media_json)
        .bind(utterance_json)
        .bind(screenshot_json)
        .bind(segment_json)
        .bind(orphan_json)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(EpisodeDeletionStart::Pending(EpisodeDeletionPlan {
            episode_id,
            purge,
            media_object_keys,
        }))
    }

    async fn complete_episode_deletion(
        &self,
        account_id: &str,
        plan: &EpisodeDeletionPlan,
    ) -> Result<EpisodePurge> {
        let mut transaction = self.pool().begin().await?;
        let activation_installed =
            lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        let row = sqlx::query(
            "SELECT state,purge::text AS purge,media_object_keys::text AS media,\
                    utterance_ids::text AS utterances,screenshot_ids::text AS screenshots,\
                    segment_ids::text AS segments,orphan_event_ids::text AS events \
               FROM episode_deletions WHERE account_id=$1 AND episode_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(plan.episode_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("episode deletion was not prepared".into()))?;
        let state: String = row.try_get("state")?;
        let paged = activation_installed
            && paged_episode_deletion_exists(&mut transaction, account_id, plan.episode_id).await?;
        if paged {
            if state == "complete" {
                let completed =
                    paged_source_key_delivery(&mut transaction, account_id, plan.episode_id)
                        .await?
                        .purge;
                transaction.rollback().await?;
                return Ok(completed);
            }
            if !paged_episode_deletion_enabled(&mut transaction, activation_installed).await? {
                return Err(EnclaveError::Conflict(
                    "paged episode deletion is not enabled by the signed activation phase".into(),
                ));
            }
            let current = paged_pending_plan(&mut transaction, account_id, plan.episode_id).await?;
            if &current != plan {
                return Err(EnclaveError::Conflict(
                    "episode deletion page does not match durable authority".into(),
                ));
            }
            let completed = advance_paged_deletion(&mut transaction, account_id, plan).await?;
            transaction.commit().await?;
            return completed.ok_or_else(|| {
                EnclaveError::Conflict("episode deletion is still progressing".into())
            });
        }
        let persisted = decode_plan(
            plan.episode_id,
            row.try_get("purge")?,
            row.try_get("media")?,
        )?;
        if &persisted != plan {
            return Err(EnclaveError::Conflict(
                "episode deletion plan does not match durable authority".into(),
            ));
        }
        if state == "complete" {
            transaction.rollback().await?;
            return Ok(persisted.purge);
        }
        let utterance_ids: Vec<i64> =
            serde_json::from_str(&row.try_get::<String, _>("utterances")?)?;
        let screenshot_ids: Vec<i64> =
            serde_json::from_str(&row.try_get::<String, _>("screenshots")?)?;
        let segment_ids: Vec<i64> = serde_json::from_str(&row.try_get::<String, _>("segments")?)?;
        let mut orphan_events: Vec<String> =
            serde_json::from_str(&row.try_get::<String, _>("events")?)?;
        orphan_events.sort();
        orphan_events.dedup();
        if activation_installed && !orphan_events.is_empty() {
            let current_family = deletable_capture_event_family(
                &mut transaction,
                account_id,
                plan.episode_id,
                &orphan_events,
                &utterance_ids,
                &screenshot_ids,
            )
            .await?;
            if current_family != orphan_events {
                return Err(EnclaveError::Conflict(
                    "episode deletion capture family changed after its durable plan".into(),
                ));
            }
        }
        let affected_sessions = if activation_installed {
            affected_capture_sessions(
                &mut transaction,
                account_id,
                &utterance_ids,
                &screenshot_ids,
            )
            .await?
        } else {
            Vec::new()
        };
        // Capture and lock aggregate media work before orphan source rows
        // cascade its members/jobs. The lock order remains activation,
        // account, aggregate work, then exact jobs. Pending deletion already
        // fences new claims; this defensive live check rejects any stale
        // caller that violated that boundary.
        let affected_work_ids = if orphan_events.is_empty() {
            Vec::new()
        } else {
            sqlx::query_scalar::<_, String>(
                "SELECT DISTINCT member.work_unit_id FROM media_work_members member \
                  WHERE member.account_id=$1 AND member.event_id=ANY($2::text[]) \
                  ORDER BY member.work_unit_id",
            )
            .bind(account_id)
            .bind(&orphan_events)
            .fetch_all(&mut *transaction)
            .await?
        };
        let affected_work = if affected_work_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query(
                "SELECT id,state,claim_token IS NOT NULL \
                        AND claim_until>clock_timestamp() AS claim_live \
                   FROM media_work_units WHERE account_id=$1 AND id=ANY($2::text[]) \
                  ORDER BY id FOR UPDATE",
            )
            .bind(account_id)
            .bind(&affected_work_ids)
            .fetch_all(&mut *transaction)
            .await?
        };
        if affected_work.len() != affected_work_ids.len()
            || affected_work
                .iter()
                .any(|row| row.try_get::<bool, _>("claim_live").unwrap_or(false))
        {
            return Err(EnclaveError::Conflict(
                "episode media processing aggregate changed or is in flight".into(),
            ));
        }
        let affected_job_rows = if affected_work_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query(
                "SELECT member.work_unit_id,member.event_id,job.id,work.state AS work_state, \
                        job.state AS job_state,job.lease_token IS NOT NULL \
                        AND job.lease_until>clock_timestamp() AS lease_live, \
                        job.state='processing' OR (job.state='retry_wait' \
                            AND job.updated_at<=clock_timestamp()) AS restart_due \
                   FROM media_work_members member \
                   JOIN media_work_units work ON work.account_id=member.account_id \
                    AND work.id=member.work_unit_id \
                   JOIN media_processing_jobs job ON job.account_id=member.account_id \
                    AND job.id=member.job_id \
                  WHERE member.account_id=$1 AND member.work_unit_id=ANY($2::text[]) \
                  ORDER BY member.work_unit_id,member.ordinal FOR UPDATE OF job",
            )
            .bind(account_id)
            .bind(&affected_work_ids)
            .fetch_all(&mut *transaction)
            .await?
        };
        if affected_job_rows
            .iter()
            .any(|row| row.try_get::<bool, _>("lease_live").unwrap_or(false))
        {
            return Err(EnclaveError::Conflict(
                "episode media processing job is in flight".into(),
            ));
        }
        let nonterminal_work_ids = affected_work
            .iter()
            .filter_map(|row| {
                let state = row.try_get::<String, _>("state").ok()?;
                matches!(state.as_str(), "planned" | "processing" | "retry_wait")
                    .then(|| row.get::<String, _>("id"))
            })
            .collect::<Vec<_>>();
        let surviving_nonterminal_jobs = affected_job_rows
            .iter()
            .filter_map(|row| {
                let work_id = row.try_get::<String, _>("work_unit_id").ok()?;
                let event_id = row.try_get::<String, _>("event_id").ok()?;
                (nonterminal_work_ids.contains(&work_id) && !orphan_events.contains(&event_id))
                    .then(|| {
                        Ok::<_, sqlx::Error>((
                            row.try_get::<i64, _>("id")?,
                            event_id,
                            row.try_get::<bool, _>("restart_due")?,
                        ))
                    })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if !utterance_ids.is_empty() {
            sqlx::query(
                "DELETE FROM episode_members WHERE account_id=$1 AND record_type='utterance' \
                    AND record_id=ANY($2)",
            )
            .bind(account_id)
            .bind(&utterance_ids)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("DELETE FROM utterances WHERE account_id=$1 AND id=ANY($2)")
                .bind(account_id)
                .bind(&utterance_ids)
                .execute(&mut *transaction)
                .await?;
        }
        if !screenshot_ids.is_empty() {
            sqlx::query(
                "DELETE FROM episode_members WHERE account_id=$1 AND record_type='screenshot' \
                    AND record_id=ANY($2)",
            )
            .bind(account_id)
            .bind(&screenshot_ids)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("DELETE FROM screenshots WHERE account_id=$1 AND id=ANY($2)")
                .bind(account_id)
                .bind(&screenshot_ids)
                .execute(&mut *transaction)
                .await?;
        }
        if !segment_ids.is_empty() {
            sqlx::query(
                "DELETE FROM audio_segments s WHERE s.account_id=$1 AND s.id=ANY($2) \
                  AND NOT EXISTS (SELECT 1 FROM utterances u WHERE u.account_id=s.account_id \
                    AND u.audio_segment_id=s.id)",
            )
            .bind(account_id)
            .bind(&segment_ids)
            .execute(&mut *transaction)
            .await?;
        }
        if !orphan_events.is_empty() {
            if activation_installed {
                let tombstones = sqlx::query(
                    "INSERT INTO capture_formation_deleted_sequences( \
                         account_id,capture_session_id,stream_id,sequence,event_id, \
                         original_manifest_digest,deletion_episode_id,provenance) \
                     SELECT event.account_id,event.capture_session_id,event.stream_id, \
                            event.sequence,event.event_id,event.manifest_digest,$3, \
                            'episode_deletion_v1' \
                       FROM capture_events event \
                      WHERE event.account_id=$1 AND event.event_id=ANY($2::text[]) \
                      ORDER BY event.event_id",
                )
                .bind(account_id)
                .bind(&orphan_events)
                .bind(plan.episode_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if usize::try_from(tombstones).ok() != Some(orphan_events.len()) {
                    return Err(EnclaveError::Conflict(
                        "episode deletion could not tombstone its exact capture family".into(),
                    ));
                }
            }
            sqlx::query("DELETE FROM capture_events WHERE account_id=$1 AND event_id=ANY($2)")
                .bind(account_id)
                .bind(&orphan_events)
                .execute(&mut *transaction)
                .await?;
        }
        if !affected_work_ids.is_empty() {
            // A nonterminal aggregate is no longer an exact provider input
            // once any member is deleted. Delete it (which clears any staged
            // raw response and releases the UNIQUE job membership), then
            // make only due/expired survivors immediately replannable. A
            // future retry_wait remains delayed but has no aggregate owner.
            if !nonterminal_work_ids.is_empty() {
                sqlx::query(
                    "DELETE FROM media_work_units WHERE account_id=$1 AND id=ANY($2::text[])",
                )
                .bind(account_id)
                .bind(&nonterminal_work_ids)
                .execute(&mut *transaction)
                .await?;
            }
            let restart_job_ids = surviving_nonterminal_jobs
                .iter()
                .filter_map(|(job_id, _, due)| due.then_some(*job_id))
                .collect::<Vec<_>>();
            let delayed_job_ids = surviving_nonterminal_jobs
                .iter()
                .filter_map(|(job_id, _, due)| (!due).then_some(*job_id))
                .collect::<Vec<_>>();
            if !restart_job_ids.is_empty() {
                let restarted = sqlx::query(
                    "UPDATE media_processing_jobs SET state='pending',lease_owner=NULL, \
                            lease_token=NULL,lease_until=NULL,error_code=NULL,usage_json=NULL, \
                            updated_at=clock_timestamp() \
                      WHERE account_id=$1 AND id=ANY($2::bigint[])",
                )
                .bind(account_id)
                .bind(&restart_job_ids)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if usize::try_from(restarted).ok() != Some(restart_job_ids.len()) {
                    return Err(EnclaveError::Conflict(
                        "episode deletion could not restart exact surviving media jobs".into(),
                    ));
                }
            }
            if !delayed_job_ids.is_empty() {
                let cleared = sqlx::query(
                    "UPDATE media_processing_jobs SET lease_owner=NULL,lease_token=NULL, \
                            lease_until=NULL,usage_json=NULL \
                      WHERE account_id=$1 AND id=ANY($2::bigint[])",
                )
                .bind(account_id)
                .bind(&delayed_job_ids)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if usize::try_from(cleared).ok() != Some(delayed_job_ids.len()) {
                    return Err(EnclaveError::Conflict(
                        "episode deletion could not release delayed surviving media jobs".into(),
                    ));
                }
            }
            let surviving_event_ids = surviving_nonterminal_jobs
                .iter()
                .map(|(_, event_id, _)| event_id.as_str())
                .collect::<Vec<_>>();
            if !surviving_event_ids.is_empty() {
                sqlx::query(
                    "UPDATE media_objects object SET processing_state= \
                        CASE WHEN job.state='pending' THEN 'queued' ELSE 'retry_wait' END \
                       FROM media_processing_jobs job \
                      WHERE object.account_id=$1 AND object.event_id=job.event_id \
                        AND job.id=ANY($2::bigint[]) AND object.event_id=ANY($3::text[])",
                )
                .bind(account_id)
                .bind(
                    surviving_nonterminal_jobs
                        .iter()
                        .map(|(job_id, _, _)| *job_id)
                        .collect::<Vec<_>>(),
                )
                .bind(&surviving_event_ids)
                .execute(&mut *transaction)
                .await?;
            }
            // Zero-member terminal/succeeded aggregates carry no useful
            // authority. Remaining content-free historical aggregates may
            // stay, but raw staged bytes are defensively removed.
            sqlx::query(
                "DELETE FROM media_work_units work WHERE work.account_id=$1 \
                    AND work.id=ANY($2::text[]) \
                    AND NOT EXISTS(SELECT 1 FROM media_work_members member \
                         WHERE member.account_id=work.account_id \
                           AND member.work_unit_id=work.id)",
            )
            .bind(account_id)
            .bind(&affected_work_ids)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE media_work_units work SET usage_json=CASE \
                    WHEN jsonb_typeof(work.usage_json->'provider_attempts')='array' THEN \
                      jsonb_set(work.usage_json,'{provider_attempts}',coalesce(( \
                        SELECT jsonb_agg(entry.value || '{\"response_b64\":null}'::jsonb \
                                         ORDER BY entry.ordinal) \
                          FROM jsonb_array_elements(work.usage_json->'provider_attempts') \
                               WITH ORDINALITY AS entry(value,ordinal)), '[]'::jsonb)) \
                    ELSE work.usage_json END,updated_at=clock_timestamp() \
                  WHERE work.account_id=$1 AND work.id=ANY($2::text[])",
            )
            .bind(account_id)
            .bind(&affected_work_ids)
            .execute(&mut *transaction)
            .await?;
            let raw_response_remains = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM media_work_units work \
                  CROSS JOIN LATERAL jsonb_array_elements( \
                    CASE WHEN jsonb_typeof(work.usage_json->'provider_attempts')='array' \
                         THEN work.usage_json->'provider_attempts' ELSE '[]'::jsonb END) entry \
                 WHERE work.account_id=$1 AND work.id=ANY($2::text[]) \
                   AND entry->>'response_b64' IS NOT NULL)",
            )
            .bind(account_id)
            .bind(&affected_work_ids)
            .fetch_one(&mut *transaction)
            .await?;
            if raw_response_remains {
                return Err(EnclaveError::Store(
                    "episode deletion retained raw media provider response bytes".into(),
                ));
            }
        }
        for capture_session_id in &affected_sessions {
            super::memory_formation::refresh_capture_formation_receipt(
                &mut transaction,
                account_id,
                capture_session_id,
            )
            .await?;
        }
        sqlx::query("DELETE FROM episodes WHERE account_id=$1 AND id=$2")
            .bind(account_id)
            .bind(plan.episode_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE episode_deletions SET state='complete',completed_at=now(),updated_at=now() \
              WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(account_id)
        .bind(plan.episode_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(persisted.purge)
    }

    async fn acknowledge_episode_deletion_source_keys(
        &self,
        account_id: &str,
        episode_id: i64,
        source_key_cursor: &str,
    ) -> Result<EpisodePurge> {
        if episode_id <= 0 {
            return Err(EnclaveError::InvalidRequest(
                "episode id must be positive".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let activation_installed =
            lock_activation_contract_key_share_if_installed(&mut transaction).await?;
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        let state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM episode_deletions \
              WHERE account_id=$1 AND episode_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("episode deletion was not prepared".into()))?;
        if !matches!(state.as_str(), "pending" | "complete") {
            return Err(EnclaveError::Store(
                "episode deletion has an invalid state".into(),
            ));
        }
        if !activation_installed
            || !paged_episode_deletion_exists(&mut transaction, account_id, episode_id).await?
            || !paged_episode_deletion_enabled(&mut transaction, activation_installed).await?
        {
            return Err(EnclaveError::Conflict(
                "bounded episode deletion source-key delivery is not enabled".into(),
            ));
        }
        let purge = acknowledge_paged_source_key_delivery(
            &mut transaction,
            account_id,
            episode_id,
            source_key_cursor,
        )
        .await?;
        transaction.commit().await?;
        Ok(purge)
    }

    async fn pending_episode_deletions(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, EpisodeDeletionPlan)>> {
        let limit = i64::try_from(limit.clamp(1, 256)).map_err(|_| {
            EnclaveError::InvalidRequest("episode deletion limit is invalid".into())
        })?;
        let mut transaction = self.pool().begin().await?;
        let paged_schema = sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('persistence_feature_episode_deletion_progress') IS NOT NULL",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let rows = sqlx::query(
            "SELECT account_id,episode_id,purge::text AS purge,media_object_keys::text AS media \
               FROM episode_deletions WHERE state='pending' \
              ORDER BY updated_at,account_id,episode_id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await?;
        let mut pending = Vec::with_capacity(rows.len());
        for row in rows {
            let account_id: String = row.try_get("account_id")?;
            let episode_id: i64 = row.try_get("episode_id")?;
            let paged = paged_schema
                && paged_episode_deletion_exists(&mut transaction, &account_id, episode_id).await?;
            let plan = if paged {
                paged_pending_plan(&mut transaction, &account_id, episode_id).await?
            } else {
                decode_plan(episode_id, row.try_get("purge")?, row.try_get("media")?)?
            };
            pending.push((account_id, plan));
        }
        transaction.commit().await?;
        Ok(pending)
    }
}

#[cfg(test)]
pub(super) async fn test_real_pg_paged_episode_deletion_contract(
    persistence: &PostgresPersistence,
) -> Result<()> {
    const ACCOUNT: &str = "activation-paged-deletion-contract";
    const EPISODE_ID: i64 = 910_001;
    const OUTSIDE_EPISODE_ID: i64 = 910_002;
    const EVENT_COUNT: i64 = 4_097;
    const SESSION_COUNT: i64 = 257;
    const EXTRA_SOURCE_KEY_COUNT: i64 = (PAGED_SOURCE_KEY_PAGE as i64) * 2 + 17;

    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES($1,'paged-delete@example.invalid','test','paged-delete')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO screenshots(account_id,id,captured_at,source_key) \
         SELECT $1,1000+n,clock_timestamp()-interval '8 hours', \
                format('local-paged-delete-%s',n) \
           FROM generate_series(1,$2) n",
    )
    .bind(ACCOUNT)
    .bind(EXTRA_SOURCE_KEY_COUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         SELECT $1,format('paged-session-%s',n),'paged-device','paged-install', \
                clock_timestamp()-interval '8 hours',clock_timestamp()-interval '7 hours', \
                clock_timestamp()-interval '7 hours',1 \
           FROM generate_series(1,$2) n",
    )
    .bind(ACCOUNT)
    .bind(SESSION_COUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence) \
         SELECT $1,format('paged-stream-%s',n),format('paged-session-%s',n), \
                'paged-device','mic',-1 FROM generate_series(1,$2) n",
    )
    .bind(ACCOUNT)
    .bind(SESSION_COUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
         VALUES($1,'paged-event-1','paged-device','paged-install','paged-session-1', \
                'paged-stream-1','mic',0,clock_timestamp()-interval '8 hours','1', \
                clock_timestamp()-interval '8 hours',clock_timestamp()-interval '8 hours', \
                'UTC',0,0,'paged-asset-1',repeat('a',64),'canonical')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition, \
             canonical_event_id,canonical_asset_id) \
         SELECT $1,format('paged-event-%s',n),'paged-device','paged-install', \
                'paged-session-1','paged-stream-1','mic',n-1, \
                clock_timestamp()-interval '8 hours',n::text, \
                clock_timestamp()-interval '8 hours',clock_timestamp()-interval '8 hours', \
                'UTC',0,0,format('paged-asset-%s',n),repeat('a',64),'reference', \
                'paged-event-1','paged-asset-1' \
           FROM generate_series(2,$2) n",
    )
    .bind(ACCOUNT)
    .bind(EVENT_COUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
         VALUES($1,'survivor-event-1','paged-device','paged-install','paged-session-1', \
                'paged-stream-1','mic',$2,clock_timestamp()-interval '8 hours', \
                'survivor-1',clock_timestamp()-interval '8 hours', \
                clock_timestamp()-interval '8 hours','UTC',0,0,'survivor-asset-1', \
                repeat('d',64),'canonical')",
    )
    .bind(ACCOUNT)
    .bind(EVENT_COUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition, \
             canonical_event_id,canonical_asset_id) \
         SELECT $1,format('survivor-event-%s',n),'paged-device','paged-install', \
                format('paged-session-%s',n),format('paged-stream-%s',n),'mic', \
                0,clock_timestamp()-interval '8 hours',format('survivor-%s',n), \
                clock_timestamp()-interval '8 hours',clock_timestamp()-interval '8 hours', \
                'UTC',0,0,format('survivor-asset-%s',n),repeat('d',64),'reference', \
                'survivor-event-1','survivor-asset-1' \
           FROM generate_series(2,$3) n",
    )
    .bind(ACCOUNT)
    .bind(EVENT_COUNT)
    .bind(SESSION_COUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO media_objects( \
             account_id,asset_id,event_id,object_key,mime_type,codec,byte_length,sha256, \
             processing_state) \
         VALUES($1,'paged-asset-1','paged-event-1','paged-provider-object', \
                'audio/mp4','aac',1,repeat('c',64),'ready')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE capture_streams stream SET committed_through_sequence=source.maximum \
           FROM (SELECT stream_id,max(sequence) AS maximum FROM capture_events \
                  WHERE account_id=$1 GROUP BY stream_id) source \
          WHERE stream.account_id=$1 AND stream.id=source.stream_id",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO episodes(account_id,id,started_at,ended_at,title,summary) VALUES \
             ($1,$2,clock_timestamp()-interval '8 hours',clock_timestamp()-interval '7 hours', \
              'paged delete target','bounded source contract'), \
             ($1,$3,clock_timestamp()-interval '6 hours',clock_timestamp()-interval '5 hours', \
              'outside target','ownership mutation fixture')",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .bind(OUTSIDE_EPISODE_ID)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
         SELECT $1,$2,'screenshot',1000+n FROM generate_series(1,$3) n",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .bind(EXTRA_SOURCE_KEY_COUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO audio_segments( \
             account_id,id,started_at,ended_at,duration_seconds,source_type) \
         VALUES($1,1,clock_timestamp()-interval '8 hours', \
                clock_timestamp()-interval '7 hours',3600,'mic')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO utterances( \
             account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text, \
             speaker_label,speaker_observation_id) \
         VALUES($1,1,1,0,1,'paged deletion evidence','speaker',1)",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO screenshots(account_id,id,captured_at,source_key) VALUES \
             ($1,1,clock_timestamp()-interval '8 hours','cloud-v2:survivor-event-1'), \
             ($1,2,clock_timestamp()-interval '8 hours','cloud-v2:survivor-event-2')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
         VALUES($1,$2,'utterance',1)",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES \
             ($1,$2,'screenshot',1),($1,$3,'screenshot',2)",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .bind(OUTSIDE_EPISODE_ID)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO speaker_observations( \
             account_id,id,event_id,turn_id,speaker_local_id,started_at,ended_at, \
             transcript_text,embedding_status) \
         VALUES($1,1,'paged-event-1','paged-turn','speaker', \
                clock_timestamp()-interval '8 hours',clock_timestamp()-interval '8 hours', \
                'paged deletion evidence','ready')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO speaker_observation_sources( \
             account_id,speaker_observation_id,event_id,window_start_ms,window_end_ms, \
             event_start_ms,event_end_ms) \
         SELECT $1,1,format('paged-event-%s',n),n,n+1,n,n+1 \
           FROM generate_series(1,$2) n",
    )
    .bind(ACCOUNT)
    .bind(EVENT_COUNT)
    .execute(persistence.pool())
    .await?;

    let mut plan = match persistence
        .begin_episode_deletion(ACCOUNT, EPISODE_ID)
        .await?
    {
        EpisodeDeletionStart::Pending(plan) => plan,
        other => {
            return Err(EnclaveError::Store(format!(
                "paged deletion fixture did not start pending: {other:?}"
            )))
        }
    };
    let overlapping = persistence
        .begin_episode_deletion(ACCOUNT, OUTSIDE_EPISODE_ID)
        .await
        .expect_err("a shared-root deletion must serialize behind the pending account receipt");
    if !matches!(overlapping, EnclaveError::Conflict(ref error)
        if error.contains("already pending deletion for this account"))
    {
        return Err(EnclaveError::Store(format!(
            "overlapping shared-root deletion was not refused exactly: {overlapping}"
        )));
    }
    let legacy_delete = sqlx::query(
        "DELETE FROM episode_members \
          WHERE account_id=$1 AND episode_id=$2 AND record_type='utterance' AND record_id=1",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .execute(persistence.pool())
    .await;
    if legacy_delete.is_ok() {
        return Err(EnclaveError::Store(
            "frozen legacy worker could mutate a paged deletion receipt".into(),
        ));
    }
    let legacy_episode_delete = sqlx::query("DELETE FROM episodes WHERE account_id=$1 AND id=$2")
        .bind(ACCOUNT)
        .bind(EPISODE_ID)
        .execute(persistence.pool())
        .await;
    if legacy_episode_delete.is_ok() {
        return Err(EnclaveError::Store(
            "frozen legacy worker could complete a paged deletion receipt".into(),
        ));
    }

    let mut mutation_fences_verified = false;
    let mut provider_order_verified = false;
    let mut completed = None;
    for iteration in 0..512 {
        if !plan.media_object_keys.is_empty() {
            let structured_source_exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM capture_events \
                  WHERE account_id=$1 AND event_id='paged-event-1')",
            )
            .bind(ACCOUNT)
            .fetch_one(persistence.pool())
            .await?;
            if plan.media_object_keys != ["paged-provider-object"] || !structured_source_exists {
                return Err(EnclaveError::Store(
                    "paged deletion exposed an inexact provider batch or purged its key first"
                        .into(),
                ));
            }
            provider_order_verified = true;
        }
        match persistence.complete_episode_deletion(ACCOUNT, &plan).await {
            Ok(purge) => {
                completed = Some(purge);
                break;
            }
            Err(EnclaveError::Conflict(_)) => {}
            Err(error) => return Err(error),
        }
        if !mutation_fences_verified {
            let orphan_ready = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM persistence_feature_episode_deletion_roots \
                  WHERE account_id=$1 AND episode_id=$2 AND disposition='orphan')",
            )
            .bind(ACCOUNT)
            .bind(EPISODE_ID)
            .fetch_one(persistence.pool())
            .await?;
            if orphan_ready {
                let reference = sqlx::query(
                    "INSERT INTO capture_events( \
                         account_id,event_id,device_id,install_id,capture_session_id,stream_id, \
                         stream_kind,sequence,source_wall_at,source_monotonic_ns,started_at, \
                         ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id, \
                         manifest_digest,media_disposition,canonical_event_id) \
                     VALUES($1,'paged-late-reference','paged-device','paged-install', \
                            'paged-session-1','paged-stream-1','mic',999999,clock_timestamp(), \
                            'late',clock_timestamp(),clock_timestamp(),'UTC',0,0, \
                            'paged-late-asset',repeat('b',64),'reference','paged-event-1')",
                )
                .bind(ACCOUNT)
                .execute(persistence.pool())
                .await;
                if reference.is_ok() {
                    return Err(EnclaveError::Store(
                        "paged deletion admitted a late canonical reference".into(),
                    ));
                }
                let survivor_reference = sqlx::query(
                    "INSERT INTO capture_events( \
                         account_id,event_id,device_id,install_id,capture_session_id,stream_id, \
                         stream_kind,sequence,source_wall_at,source_monotonic_ns,started_at, \
                         ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id, \
                         manifest_digest,media_disposition,canonical_event_id) \
                     VALUES($1,'survivor-late-reference','paged-device','paged-install', \
                            'paged-session-2','paged-stream-2','mic',1,clock_timestamp(), \
                            'survivor-late',clock_timestamp(),clock_timestamp(),'UTC',0,0, \
                            'survivor-late-asset',repeat('e',64),'reference','survivor-event-1')",
                )
                .bind(ACCOUNT)
                .execute(persistence.pool())
                .await;
                if survivor_reference.is_ok() {
                    return Err(EnclaveError::Store(
                        "paged deletion admitted a late survivor-family reference".into(),
                    ));
                }
                let survivor_projection = sqlx::query(
                    "INSERT INTO screenshots(account_id,id,captured_at,source_key) \
                     VALUES($1,3,clock_timestamp(),'cloud-v2:survivor-event-3')",
                )
                .bind(ACCOUNT)
                .execute(persistence.pool())
                .await;
                if survivor_projection.is_ok() {
                    return Err(EnclaveError::Store(
                        "paged deletion admitted a late survivor-family projection".into(),
                    ));
                }
                let outside_owner = sqlx::query(
                    "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                     VALUES($1,$2,'utterance',1)",
                )
                .bind(ACCOUNT)
                .bind(OUTSIDE_EPISODE_ID)
                .execute(persistence.pool())
                .await;
                if outside_owner.is_ok() {
                    return Err(EnclaveError::Store(
                        "paged deletion admitted a late outside source owner".into(),
                    ));
                }
                mutation_fences_verified = true;
            }
        }
        plan = match persistence
            .begin_episode_deletion(ACCOUNT, EPISODE_ID)
            .await?
        {
            EpisodeDeletionStart::Pending(plan) => plan,
            EpisodeDeletionStart::Complete(purge) => {
                completed = Some(purge);
                break;
            }
            EpisodeDeletionStart::NotFound => {
                return Err(EnclaveError::Store(
                    "paged deletion lost its durable receipt".into(),
                ))
            }
        };
        if iteration == 511 {
            return Err(EnclaveError::Store(
                "paged deletion did not converge within its bounded fixture".into(),
            ));
        }
    }
    let mut page = completed.ok_or_else(|| {
        EnclaveError::Store("paged deletion fixture did not produce a source-key page".into())
    })?;
    if page.source_key_delivery_complete || page.source_key_cursor.is_none() {
        return Err(EnclaveError::Store(
            "paged deletion skipped its durable source-key delivery barrier".into(),
        ));
    }
    let first_cursor = page
        .source_key_cursor
        .clone()
        .expect("incomplete source-key delivery has a cursor");
    match persistence
        .begin_episode_deletion(ACCOUNT, EPISODE_ID)
        .await?
    {
        EpisodeDeletionStart::Pending(replayed) if replayed.purge == page => {}
        _ => {
            return Err(EnclaveError::Store(
                "unacknowledged source-key page did not replay byte-identically".into(),
            ))
        }
    }
    let replacement = if first_cursor.ends_with('0') {
        '1'
    } else {
        '0'
    };
    let wrong_cursor = format!("{}{replacement}", &first_cursor[..first_cursor.len() - 1]);
    let wrong = persistence
        .acknowledge_episode_deletion_source_keys(ACCOUNT, EPISODE_ID, &wrong_cursor)
        .await
        .expect_err("a commitment-mismatched source-key cursor must be refused");
    if !matches!(wrong, EnclaveError::Conflict(ref error)
        if error.contains("wrong or stale"))
    {
        return Err(EnclaveError::Store(format!(
            "wrong source-key cursor was not refused exactly: {wrong}"
        )));
    }
    let pending_before_ack = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM episodes WHERE account_id=$1 AND id=$2) \
              AND (SELECT state='pending' FROM episode_deletions \
                    WHERE account_id=$1 AND episode_id=$2)",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .fetch_one(persistence.pool())
    .await?;
    if !pending_before_ack {
        return Err(EnclaveError::Store(
            "episode deletion became terminal before local source-key ACK".into(),
        ));
    }

    let mut delivered_source_keys = BTreeSet::new();
    let mut delivery_pages = 0usize;
    let purge = loop {
        let page_len = page.utterance_source_keys.len() + page.screenshot_source_keys.len();
        if page_len > PAGED_SOURCE_KEY_PAGE {
            return Err(EnclaveError::Store(
                "episode deletion exceeded its source-key per-call bound".into(),
            ));
        }
        delivered_source_keys.extend(page.utterance_source_keys.iter().cloned());
        delivered_source_keys.extend(page.screenshot_source_keys.iter().cloned());
        if page.source_key_delivery_complete {
            break page;
        }
        delivery_pages += 1;
        let cursor = page
            .source_key_cursor
            .clone()
            .ok_or_else(|| EnclaveError::Store("source-key page lost its ACK cursor".into()))?;
        let next = persistence
            .acknowledge_episode_deletion_source_keys(ACCOUNT, EPISODE_ID, &cursor)
            .await?;
        let lost_response_replay = persistence
            .acknowledge_episode_deletion_source_keys(ACCOUNT, EPISODE_ID, &cursor)
            .await?;
        if lost_response_replay != next {
            return Err(EnclaveError::Store(
                "a lost source-key ACK response did not replay byte-identically".into(),
            ));
        }
        match persistence
            .begin_episode_deletion(ACCOUNT, EPISODE_ID)
            .await?
        {
            EpisodeDeletionStart::Pending(replayed) if !next.source_key_delivery_complete => {
                if replayed.purge != next {
                    return Err(EnclaveError::Store(
                        "restarted source-key delivery changed its current page".into(),
                    ));
                }
            }
            EpisodeDeletionStart::Complete(replayed) if next.source_key_delivery_complete => {
                if replayed != next {
                    return Err(EnclaveError::Store(
                        "restarted terminal source-key delivery changed its receipt".into(),
                    ));
                }
            }
            _ => {
                return Err(EnclaveError::Store(
                    "restarted source-key delivery returned an invalid state".into(),
                ))
            }
        }
        page = next;
    };
    if delivery_pages < 3 {
        return Err(EnclaveError::Store(
            "source-key fixture did not cross more than one bounded page".into(),
        ));
    }
    let stale = persistence
        .acknowledge_episode_deletion_source_keys(ACCOUNT, EPISODE_ID, &first_cursor)
        .await
        .expect_err("an ACK older than the immediately committed page must be stale");
    if !matches!(stale, EnclaveError::Conflict(ref error)
        if error.contains("wrong or stale"))
    {
        return Err(EnclaveError::Store(format!(
            "stale source-key cursor was not refused exactly: {stale}"
        )));
    }
    let mut expected_source_keys = BTreeSet::from(["cloud-v2:survivor-event-1".to_owned()]);
    expected_source_keys
        .extend((1..=EXTRA_SOURCE_KEY_COUNT).map(|index| format!("local-paged-delete-{index}")));
    if delivered_source_keys != expected_source_keys {
        return Err(EnclaveError::Store(
            "paged source-key delivery was not the exact restart-safe union".into(),
        ));
    }
    if !mutation_fences_verified
        || !provider_order_verified
        || purge.deleted_utterances != 1
        || purge.deleted_segments != 1
        || purge.deleted_screenshots
            != usize::try_from(EXTRA_SOURCE_KEY_COUNT + 1)
                .map_err(|_| EnclaveError::Store("source-key fixture count overflow".into()))?
        || !purge.source_key_delivery_complete
        || purge.source_key_cursor.is_some()
        || !purge.utterance_source_keys.is_empty()
        || !purge.screenshot_source_keys.is_empty()
    {
        return Err(EnclaveError::Store(
            "paged deletion terminal purge did not match exact source authority".into(),
        ));
    }
    let receipt = sqlx::query(
        "SELECT progress.phase,progress.event_count,progress.session_count, \
                (SELECT count(*) FROM capture_formation_deleted_sequences deleted \
                  WHERE deleted.account_id=progress.account_id \
                    AND deleted.deletion_episode_id=progress.episode_id) AS tombstones, \
                (SELECT count(*) FROM persistence_feature_episode_deletion_sessions session \
                  WHERE session.account_id=progress.account_id \
                    AND session.episode_id=progress.episode_id \
                    AND session.refreshed_at IS NOT NULL) AS refreshed_sessions \
           FROM persistence_feature_episode_deletion_progress progress \
          WHERE progress.account_id=$1 AND progress.episode_id=$2",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .fetch_one(persistence.pool())
    .await?;
    if receipt.try_get::<String, _>("phase")? != "complete"
        || receipt.try_get::<i64, _>("event_count")? != EVENT_COUNT
        || receipt.try_get::<i64, _>("session_count")? != SESSION_COUNT
        || receipt.try_get::<i64, _>("tombstones")? != EVENT_COUNT
        || receipt.try_get::<i64, _>("refreshed_sessions")? != SESSION_COUNT
    {
        return Err(EnclaveError::Store(
            "paged deletion did not retain exact event/session closure".into(),
        ));
    }
    let survivor_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM capture_events \
          WHERE account_id=$1 AND event_id LIKE 'survivor-event-%'",
    )
    .bind(ACCOUNT)
    .fetch_one(persistence.pool())
    .await?;
    if survivor_events != SESSION_COUNT {
        return Err(EnclaveError::Store(
            "paged deletion purged a survivor canonical family".into(),
        ));
    }
    match persistence
        .begin_episode_deletion(ACCOUNT, EPISODE_ID)
        .await?
    {
        EpisodeDeletionStart::Complete(replayed) if replayed == purge => {}
        _ => {
            return Err(EnclaveError::Store(
                "paged deletion terminal replay was not idempotent".into(),
            ))
        }
    }
    let shared_root_disposition = sqlx::query_scalar::<_, String>(
        "SELECT disposition FROM persistence_feature_episode_deletion_roots \
          WHERE account_id=$1 AND episode_id=$2 AND root_event_id='survivor-event-1'",
    )
    .bind(ACCOUNT)
    .bind(EPISODE_ID)
    .fetch_one(persistence.pool())
    .await?;
    if shared_root_disposition != "survivor" {
        return Err(EnclaveError::Store(
            "serialized first deletion did not preserve the shared capture root".into(),
        ));
    }
    if !matches!(
        persistence
            .begin_episode_deletion(ACCOUNT, OUTSIDE_EPISODE_ID)
            .await?,
        EpisodeDeletionStart::Pending(_)
    ) {
        return Err(EnclaveError::Store(
            "shared-root successor deletion did not start after terminal ACK".into(),
        ));
    }
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    let companion_rows = sqlx::query_scalar::<_, i64>(
        "SELECT \
           (SELECT count(*) FROM persistence_feature_episode_deletion_progress WHERE account_id=$1)+ \
           (SELECT count(*) FROM persistence_feature_episode_deletion_members WHERE account_id=$1)+ \
           (SELECT count(*) FROM persistence_feature_episode_deletion_roots WHERE account_id=$1)+ \
           (SELECT count(*) FROM persistence_feature_episode_deletion_events WHERE account_id=$1)+ \
           (SELECT count(*) FROM persistence_feature_episode_deletion_objects WHERE account_id=$1)+ \
           (SELECT count(*) FROM persistence_feature_episode_deletion_sessions WHERE account_id=$1)",
    )
    .bind(ACCOUNT)
    .fetch_one(persistence.pool())
    .await?;
    if companion_rows != 0 {
        return Err(EnclaveError::Store(
            "paged deletion companions did not follow account cascade".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn canonical_family_survivors_are_correlated_by_root() {
        let source = include_str!("episode_deletion.rs");
        let family = source
            .split("async fn deletable_capture_event_family(")
            .nth(1)
            .unwrap()
            .split("fn event_id(")
            .next()
            .unwrap();
        assert!(family.contains("outside_owned_roots(root_event_id)"));
        assert!(family.contains(
            "coalesce(event.canonical_event_id,event.event_id) IN ( \\\n                    SELECT root_event_id FROM outside_owned_roots)"
        ));
        assert!(!family.contains("owner.record_id=ANY($3::bigint[])"));
        assert!(!family.contains("owner.record_id=ANY($4::bigint[])"));
    }

    #[test]
    fn deletion_refuses_exact_family_media_provider_leases() {
        let source = include_str!("episode_deletion.rs");
        let begin = source
            .split("async fn begin_episode_deletion(")
            .nth(1)
            .unwrap()
            .split("async fn complete_episode_deletion(")
            .next()
            .unwrap();
        let activation = begin
            .find("lock_activation_contract_key_share_if_installed")
            .unwrap();
        let account = begin.find("advisory_transaction_lock").unwrap();
        let family = begin.find("deletable_capture_event_family(").unwrap();
        let media = begin.find("media_provider_in_flight").unwrap();
        let receipt = begin.rfind("INSERT INTO episode_deletions").unwrap();
        assert!(activation < account);
        assert!(account < family);
        assert!(family < media);
        assert!(media < receipt);
        assert!(begin.contains("FROM media_processing_jobs job"));
        assert!(begin.contains("FROM media_work_units work"));
        assert!(begin.contains("job.lease_until>clock_timestamp()"));
        assert!(begin.contains("work.claim_until>clock_timestamp()"));
        assert_eq!(
            begin
                .matches("coalesce(event.canonical_event_id,event.event_id)=ANY")
                .count(),
            2
        );
    }

    #[test]
    fn paged_deletion_has_no_permanent_source_cap_and_preserves_provider_ordering() {
        let source = include_str!("episode_deletion.rs");
        let paged = source
            .split("async fn inventory_paged_members(")
            .nth(1)
            .unwrap()
            .split("async fn affected_capture_sessions(")
            .next()
            .unwrap();
        assert!(paged.contains("PAGED_DELETION_PAGE"));
        assert!(paged.contains("PAGED_PROVIDER_OBJECT_PAGE"));
        assert!(!paged.contains("MAX_AFFECTED_CAPTURE_SESSIONS"));
        assert!(!paged.contains("MAX_DELETED_CAPTURE_EVENTS"));
        let provider = paged.find("\"provider_delete\"").unwrap();
        let members = paged.find("\"purge_members\"").unwrap();
        let tombstones = paged.find("\"tombstone_events\"").unwrap();
        let events = paged.find("\"purge_events\"").unwrap();
        assert!(provider < members && members < tombstones && tombstones < events);
        assert!(source.contains("(event_id=root_event_id),event_id"));
    }

    #[test]
    fn paged_deletion_requires_signed_post_installed_phase() {
        let source = include_str!("episode_deletion.rs");
        let gate = source
            .split("async fn paged_episode_deletion_enabled(")
            .nth(1)
            .unwrap()
            .split("async fn paged_episode_deletion_exists(")
            .next()
            .unwrap();
        assert!(gate.contains("phase IN ('draining','active','paused')"));
        assert!(!gate.contains("'installed'"));
        assert!(source.contains("episode deletion is still progressing"));
    }
}
