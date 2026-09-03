//! Append-only PostgreSQL activation authority for memory reconciliation.

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Postgres, Row};

use crate::{
    error::{EnclaveError, Result},
    persistence::{
        ActiveReconciliationAuthority, MemoryReconciliationActivationPhase,
        MemoryReconciliationActivationRepository, MemoryReconciliationActivationStatus,
    },
};

use super::{
    schema_release::{
        verify_finalized_v26_release, MemoryReconciliationActivationSignature,
        VerifiedMemoryReconciliationActivationReceipt,
    },
    PostgresPersistence, EXPECTED_SCHEMA_VERSION, MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION,
};

#[cfg(test)]
use crate::cp::isotime;

const FEATURE: &str = "episode_topology_reconciliation";
const RELEASE_LOCK: &str = "kioku:postgres-memory-reconciliation-activation:v27";
const INSTALL_SQL: &str =
    include_str!("../../../migrations/0027_memory_reconciliation_activation.sql");
const FORMATION_BACKFILL_NAME: &str = "capture_formation_receipts";
const FORMATION_BACKFILL_BATCH_SIZE: i64 = 256;
const FINALIZATION_CLAIM_DRAIN_BATCH_SIZE: i64 = 256;
const FORMATION_BACKFILL_SELECT_SQL: &str = "SELECT account_id,id FROM capture_sessions \
      WHERE ($1::text IS NULL OR (account_id,id)>($1,$2)) \
      ORDER BY account_id,id LIMIT $3";
const ACTIVE_GUARD_TRIGGER: &str = "episodes_00_enforce_assigned_reconciliation_finalization";
const ACTIVE_GUARD_DDL: &str =
    "CREATE TRIGGER episodes_00_enforce_assigned_reconciliation_finalization \
     BEFORE INSERT OR UPDATE ON episodes FOR EACH ROW \
     EXECUTE FUNCTION enforce_assigned_episode_finalization()";
const PENDING_DELETION_MEMBER_GUARD_TRIGGER: &str =
    "episode_members_00_reject_pending_deleted_source";
const PENDING_DELETION_MEMBER_GUARD_DDL: &str =
    "CREATE TRIGGER episode_members_00_reject_pending_deleted_source \
     BEFORE INSERT OR UPDATE OF episode_id, record_type, record_id ON episode_members \
     FOR EACH ROW EXECUTE FUNCTION reject_pending_deleted_episode_member()";
const PAGED_DELETION_MEMBER_GUARD_TRIGGER: &str = "episode_members_01_guard_paged_deletion";
const PAGED_DELETION_MEMBER_GUARD_DDL: &str =
    "CREATE TRIGGER episode_members_01_guard_paged_deletion \
     BEFORE INSERT OR DELETE OR UPDATE ON episode_members FOR EACH ROW \
     EXECUTE FUNCTION guard_persistence_feature_episode_deletion_mutation()";
const PAGED_DELETION_EPISODE_GUARD_TRIGGER: &str = "episodes_01_guard_paged_deletion";
const PAGED_DELETION_EPISODE_GUARD_DDL: &str =
    "CREATE TRIGGER episodes_01_guard_paged_deletion BEFORE DELETE ON episodes \
     FOR EACH ROW EXECUTE FUNCTION guard_persistence_feature_episode_deletion_mutation()";
const PAGED_DELETION_MEDIA_GUARD_TRIGGER: &str = "media_work_units_00_guard_paged_deletion";
const PAGED_DELETION_MEDIA_GUARD_DDL: &str =
    "CREATE TRIGGER media_work_units_00_guard_paged_deletion \
     BEFORE INSERT OR UPDATE ON media_work_units FOR EACH ROW \
     EXECUTE FUNCTION guard_persistence_feature_episode_deletion_media_work()";
const PAGED_DELETION_FORMATION_GUARD_TRIGGER: &str =
    "capture_formation_receipts_00_guard_paged_deletion";
const PAGED_DELETION_FORMATION_GUARD_DDL: &str =
    "CREATE TRIGGER capture_formation_receipts_00_guard_paged_deletion \
     BEFORE INSERT OR UPDATE ON capture_formation_receipts FOR EACH ROW \
     EXECUTE FUNCTION guard_persistence_feature_episode_deletion_formation_claim()";
const CONTRACT_MANIFEST: &str =
    "kioku-postgresql-memory-reconciliation-activation-v27-append-only-v1";

const RESERVED_RELATION_TABLES: &[&str] = &[
    "capture_formation_deleted_sequences",
    "capture_formation_pages",
    "capture_formation_receipts",
    "capture_formation_seal_events",
    "persistence_feature_activation_assignments",
    "persistence_feature_activation_backfills",
    "persistence_feature_activation_contracts",
    "persistence_feature_activation_drains",
    "persistence_feature_activation_events",
    "persistence_feature_episode_deletion_events",
    "persistence_feature_episode_deletion_members",
    "persistence_feature_episode_deletion_objects",
    "persistence_feature_episode_deletion_progress",
    "persistence_feature_episode_deletion_roots",
    "persistence_feature_episode_deletion_sessions",
    "persistence_feature_reconciliation_neighborhood_members",
    "persistence_feature_reconciliation_neighborhood_scans",
    "persistence_feature_reconciliation_stage_contracts",
];
const RESERVED_RELATION_SEQUENCES: &[&str] =
    &["persistence_feature_activation_events_event_sequence_seq"];
const RESERVED_RELATION_INDEXES: &[&str] = &[
    "capture_formation_deleted_sequences_account_id_event_id_key",
    "capture_formation_deleted_sequences_session_idx",
    "capture_formation_pages_account_id_capture_session_id_sourc_key",
    "capture_formation_pages_resume_idx",
    "capture_formation_receipts_pending_idx",
    "capture_formation_receipts_seal_pending_idx",
    "persistence_feature_activation_assignments_generation_idx",
    "persistence_feature_activation_events_feature_generation_key",
    "persistence_feature_episode_deletion_ev_account_id_event_id_key",
    "persistence_feature_episode_deletion_events_pending_idx",
    "persistence_feature_episode_deletion_events_tombstone_idx",
    "persistence_feature_episode_deletion_members_pending_idx",
    "persistence_feature_episode_deletion_objects_pending_idx",
    "persistence_feature_episode_deletion_roots_pending_idx",
    "persistence_feature_episode_deletion_sessions_pending_idx",
    "persistence_feature_reconcilia_account_id_reconciliation_id_key",
    "persistence_feature_reconcili_account_id_component_seed_sha_key",
    // PostgreSQL truncates the reviewed migration identifier to NAMEDATALEN-1.
    "persistence_feature_reconciliation_neighborhood_members_generat",
];
const RESERVED_FUNCTION_SIGNATURES: &[&str] = &[
    "f:append_capture_formation_deleted_sequence()",
    "f:append_capture_formation_seal_event()",
    "f:append_persistence_feature_activation_event()",
    "f:capture_formation_stream_accepted_max(text, text)",
    "f:capture_formation_stream_contiguous_through(text, text)",
    "f:capture_formation_stream_maxima_sha256(text, text)",
    "f:deny_persistence_feature_activation_mutation()",
    "f:enforce_assigned_episode_finalization()",
    "f:guard_capture_formation_deleted_sequence_mutation()",
    "f:guard_capture_formation_seal_event_mutation()",
    "f:guard_persistence_feature_activation_assignment_mutation()",
    "f:guard_persistence_feature_episode_deletion_formation_claim()",
    "f:guard_persistence_feature_episode_deletion_media_work()",
    "f:guard_persistence_feature_episode_deletion_mutation()",
    "f:reject_deleted_capture_sequence()",
    "f:reject_pending_deleted_capture_projection()",
    "f:reject_pending_deleted_episode_member()",
    "f:require_capture_event_deletion_tombstone()",
];
const RESERVED_BASE_TRIGGER_IDENTITIES: &[&str] = &[
    "capture_events.capture_events_00_reject_deleted_sequence",
    "capture_events.capture_events_01_require_deleted_sequence",
    "capture_formation_deleted_sequences.capture_formation_deleted_sequences_append",
    "capture_formation_deleted_sequences.capture_formation_deleted_sequences_immutable",
    "capture_formation_seal_events.capture_formation_seal_events_append",
    "capture_formation_seal_events.capture_formation_seal_events_immutable",
    "persistence_feature_activation_assignments.persistence_feature_activation_assignments_immutable",
    "persistence_feature_activation_contracts.persistence_feature_activation_contracts_immutable",
    "persistence_feature_activation_events.persistence_feature_activation_events_append",
    "persistence_feature_activation_events.persistence_feature_activation_events_immutable",
    "screenshots.screenshots_00_reject_pending_deleted_capture_projection",
    "utterances.utterances_00_reject_pending_deleted_capture_projection",
];
// These exact trigger identities are installed only by the signed Draining
// transition. Their presence/absence and definitions are verified separately
// for each activation phase, but no other trigger in their namespace is valid.
const RESERVED_DRAINING_TRIGGER_IDENTITIES: &[&str] = &[
    "capture_formation_receipts.capture_formation_receipts_00_guard_paged_deletion",
    "episode_members.episode_members_00_reject_pending_deleted_source",
    "episode_members.episode_members_01_guard_paged_deletion",
    "episodes.episodes_00_enforce_assigned_reconciliation_finalization",
    "episodes.episodes_01_guard_paged_deletion",
    "media_work_units.media_work_units_00_guard_paged_deletion",
];
const RESERVED_CATALOG_MANIFEST_SQL: &str = r#"
WITH actual_relations(signature) AS (
    SELECT relation.relkind::text||':'||relation.relname
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname=current_schema()
       AND (relation.relname LIKE 'persistence_feature\_%' ESCAPE '\'
            OR relation.relname LIKE 'capture_formation\_%' ESCAPE '\'
            OR (relation.relkind IN ('i','I') AND EXISTS(
                SELECT 1 FROM pg_index index_link
                JOIN pg_class table_state ON table_state.oid=index_link.indrelid
                JOIN pg_namespace table_namespace
                  ON table_namespace.oid=table_state.relnamespace
                 WHERE index_link.indexrelid=relation.oid
                   AND table_namespace.nspname=current_schema()
                   AND (table_state.relname LIKE 'persistence_feature\_%' ESCAPE '\'
                        OR table_state.relname LIKE 'capture_formation\_%' ESCAPE '\')
            )))
), actual_functions(signature) AS (
    SELECT function_state.prokind::text||':'||function_state.proname||'('||
           oidvectortypes(function_state.proargtypes)||')'
      FROM pg_proc function_state
      JOIN pg_namespace namespace ON namespace.oid=function_state.pronamespace
     WHERE namespace.nspname=current_schema()
       AND (function_state.proname LIKE 'persistence_feature\_%' ESCAPE '\'
            OR function_state.proname LIKE 'capture_formation\_%' ESCAPE '\'
            OR function_state.proname=ANY($3::text[]))
), actual_triggers(object_name) AS (
    SELECT table_state.relname||'.'||trigger_state.tgname
      FROM pg_trigger trigger_state
      JOIN pg_class table_state ON table_state.oid=trigger_state.tgrelid
      JOIN pg_namespace namespace ON namespace.oid=table_state.relnamespace
     WHERE namespace.nspname=current_schema() AND NOT trigger_state.tgisinternal
       AND (trigger_state.tgname LIKE 'persistence_feature\_%' ESCAPE '\'
            OR trigger_state.tgname LIKE 'capture_formation\_%' ESCAPE '\'
            OR table_state.relname LIKE 'persistence_feature\_%' ESCAPE '\'
            OR table_state.relname LIKE 'capture_formation\_%' ESCAPE '\'
            OR trigger_state.tgname=ANY($5::text[]))
), actual_types(signature) AS (
    SELECT type_state.typtype::text||':'||type_state.typname
      FROM pg_type type_state
      JOIN pg_namespace namespace ON namespace.oid=type_state.typnamespace
      LEFT JOIN pg_class relation ON relation.oid=type_state.typrelid
     WHERE namespace.nspname=current_schema()
       AND (type_state.typname LIKE 'persistence_feature\_%' ESCAPE '\'
            OR type_state.typname LIKE 'capture_formation\_%' ESCAPE '\'
            OR type_state.typname LIKE '\_persistence\_feature\_%' ESCAPE '\'
            OR type_state.typname LIKE '\_capture\_formation\_%' ESCAPE '\'
            OR relation.relname LIKE 'persistence_feature\_%' ESCAPE '\'
            OR relation.relname LIKE 'capture_formation\_%' ESCAPE '\')
), deviations(description) AS (
    SELECT 'unexpected relation '||signature FROM actual_relations
     WHERE NOT (signature=ANY($1::text[]))
    UNION ALL
    SELECT 'missing relation '||expected.signature
      FROM unnest($1::text[]) expected(signature)
     WHERE NOT EXISTS(SELECT 1 FROM actual_relations actual
                       WHERE actual.signature=expected.signature)
    UNION ALL
    SELECT 'unexpected function '||signature FROM actual_functions
     WHERE NOT (signature=ANY($2::text[]))
    UNION ALL
    SELECT 'missing function '||expected.signature
      FROM unnest($2::text[]) expected(signature)
     WHERE NOT EXISTS(SELECT 1 FROM actual_functions actual
                       WHERE actual.signature=expected.signature)
    UNION ALL
    SELECT 'unexpected trigger '||object_name FROM actual_triggers
     WHERE NOT (object_name=ANY($4::text[]))
    UNION ALL
    SELECT 'missing trigger '||expected.object_name
      FROM unnest($7::text[]) expected(object_name)
     WHERE NOT EXISTS(SELECT 1 FROM actual_triggers actual
                       WHERE actual.object_name=expected.object_name)
    UNION ALL
    SELECT 'unexpected type '||signature FROM actual_types
     WHERE NOT (signature=ANY($6::text[]))
    UNION ALL
    SELECT 'missing type '||expected.signature
      FROM unnest($6::text[]) expected(signature)
     WHERE NOT EXISTS(SELECT 1 FROM actual_types actual
                       WHERE actual.signature=expected.signature)
)
SELECT coalesce(array_agg(description ORDER BY description),'{}'::text[])
  FROM deviations
"#;

// The draining guards are intentionally excluded: they are attached only in
// the signed draining transaction and verified separately.
const CATALOG_EVIDENCE_SQL: &str = r#"
WITH relation_targets AS (
    SELECT relation.oid,relation.relname,relation.relkind,relation.relpersistence,
           relation.relrowsecurity,relation.relforcerowsecurity,relation.relreplident,
           relation.relam
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname=current_schema()
       AND relation.relkind IN ('r','p')
       AND relation.relname IN (
           'capture_formation_deleted_sequences',
           'capture_formation_pages',
           'capture_formation_receipts',
           'capture_formation_seal_events',
           'persistence_feature_activation_assignments',
           'persistence_feature_activation_backfills',
           'persistence_feature_activation_contracts',
           'persistence_feature_activation_drains',
           'persistence_feature_activation_events',
           'persistence_feature_episode_deletion_events',
           'persistence_feature_episode_deletion_members',
           'persistence_feature_episode_deletion_objects',
           'persistence_feature_episode_deletion_progress',
           'persistence_feature_episode_deletion_roots',
           'persistence_feature_episode_deletion_sessions',
           'persistence_feature_reconciliation_neighborhood_members',
           'persistence_feature_reconciliation_neighborhood_scans',
           'persistence_feature_reconciliation_stage_contracts'
       )
), evidence(kind,name,definition) AS (
    SELECT 'relation',target.relname,
           concat_ws('|',target.relkind::text,target.relpersistence::text,
                     target.relrowsecurity::text,target.relforcerowsecurity::text,
                     target.relreplident::text,target.relam::text)
      FROM relation_targets target
    UNION ALL
    SELECT 'column',target.relname||'.'||attribute.attnum::text||'.'||attribute.attname,
           concat_ws('|',format_type(attribute.atttypid,attribute.atttypmod),
                     attribute.attnotnull::text,attribute.attidentity::text,
                     attribute.attgenerated::text,
                     coalesce(pg_get_expr(default_value.adbin,default_value.adrelid),''),
                     attribute.attcollation::text)
      FROM relation_targets target
      JOIN pg_attribute attribute ON attribute.attrelid=target.oid
       AND attribute.attnum>0 AND NOT attribute.attisdropped
      LEFT JOIN pg_attrdef default_value ON default_value.adrelid=target.oid
       AND default_value.adnum=attribute.attnum
    UNION ALL
    SELECT 'constraint',target.relname||'.'||constraint_state.conname,
           concat_ws('|',constraint_state.contype::text,
                     constraint_state.convalidated::text,
                     constraint_state.condeferrable::text,
                     constraint_state.condeferred::text,
                     pg_get_constraintdef(constraint_state.oid,true))
      FROM relation_targets target
      JOIN pg_constraint constraint_state ON constraint_state.conrelid=target.oid
    UNION ALL
    SELECT 'index',index_state.relname,pg_get_indexdef(index_state.oid)
      FROM pg_index index_link
      JOIN pg_class index_state ON index_state.oid=index_link.indexrelid
      JOIN relation_targets target ON target.oid=index_link.indrelid
    UNION ALL
    SELECT 'sequence',sequence_state.relname,
           concat_ws('|',sequence_catalog.seqstart::text,
                     sequence_catalog.seqincrement::text,
                     sequence_catalog.seqmax::text,sequence_catalog.seqmin::text,
                     sequence_catalog.seqcache::text,sequence_catalog.seqcycle::text)
      FROM pg_class sequence_state
      JOIN pg_namespace namespace ON namespace.oid=sequence_state.relnamespace
      JOIN pg_sequence sequence_catalog ON sequence_catalog.seqrelid=sequence_state.oid
     WHERE namespace.nspname=current_schema() AND sequence_state.relkind='S'
       AND sequence_state.relname=
           'persistence_feature_activation_events_event_sequence_seq'
    UNION ALL
    SELECT 'trigger',table_state.relname||'.'||trigger_state.tgname,
           concat_ws('|',trigger_state.tgenabled::text,
                     pg_get_triggerdef(trigger_state.oid,true),function_state.proname)
     FROM pg_trigger trigger_state
     JOIN relation_targets table_state ON table_state.oid=trigger_state.tgrelid
     JOIN pg_proc function_state ON function_state.oid=trigger_state.tgfoid
     WHERE NOT trigger_state.tgisinternal
       AND NOT (table_state.relname='capture_formation_receipts'
                AND trigger_state.tgname=
                    'capture_formation_receipts_00_guard_paged_deletion')
    UNION ALL
    SELECT 'trigger',table_state.relname||'.'||trigger_state.tgname,
           concat_ws('|',trigger_state.tgenabled::text,
                     pg_get_triggerdef(trigger_state.oid,true),function_state.proname)
      FROM pg_trigger trigger_state
      JOIN pg_class table_state ON table_state.oid=trigger_state.tgrelid
      JOIN pg_namespace namespace ON namespace.oid=table_state.relnamespace
      JOIN pg_proc function_state ON function_state.oid=trigger_state.tgfoid
     WHERE namespace.nspname=current_schema() AND NOT trigger_state.tgisinternal
       AND ((table_state.relname='capture_events'
             AND trigger_state.tgname IN (
                 'capture_events_00_reject_deleted_sequence',
                 'capture_events_01_require_deleted_sequence'))
         OR (table_state.relname='utterances'
             AND trigger_state.tgname=
                 'utterances_00_reject_pending_deleted_capture_projection')
         OR (table_state.relname='screenshots'
             AND trigger_state.tgname=
                 'screenshots_00_reject_pending_deleted_capture_projection'))
    UNION ALL
    SELECT 'function',function_state.proname||'.'||pg_get_function_identity_arguments(function_state.oid),
           pg_get_functiondef(function_state.oid)
      FROM pg_proc function_state
      JOIN pg_namespace namespace ON namespace.oid=function_state.pronamespace
     WHERE namespace.nspname=current_schema()
       AND function_state.proname IN (
           'deny_persistence_feature_activation_mutation',
           'guard_persistence_feature_activation_assignment_mutation',
           'append_persistence_feature_activation_event',
           'capture_formation_stream_accepted_max',
           'capture_formation_stream_contiguous_through',
           'capture_formation_stream_maxima_sha256',
           'append_capture_formation_deleted_sequence',
           'guard_capture_formation_deleted_sequence_mutation',
           'reject_deleted_capture_sequence',
           'reject_pending_deleted_capture_projection',
           'reject_pending_deleted_episode_member',
           'require_capture_event_deletion_tombstone',
           'append_capture_formation_seal_event',
           'guard_capture_formation_seal_event_mutation',
           'guard_persistence_feature_episode_deletion_mutation',
           'guard_persistence_feature_episode_deletion_media_work',
           'guard_persistence_feature_episode_deletion_formation_claim',
           'enforce_assigned_episode_finalization')
)
SELECT coalesce(jsonb_agg(jsonb_build_array(kind,name,definition)
                          ORDER BY kind,name,definition),'[]'::jsonb)::text
  FROM evidence
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemoryReconciliationActivationReleaseStatus {
    Installed,
    AlreadyInstalled,
    BackfillInProgress,
    BackfillComplete,
    Draining,
    Active,
    Paused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct MemoryReconciliationActivationReleaseResult {
    pub(crate) status: MemoryReconciliationActivationReleaseStatus,
    pub(crate) phase: String,
    pub(crate) generation: i64,
    pub(crate) schema_version: i64,
    pub(crate) expanded_through_version: Option<i64>,
    pub(crate) rollout_basis_points: i64,
    pub(crate) explicit_canary_accounts: usize,
    pub(crate) assigned_accounts: i64,
    pub(crate) unresolved_source_accounts: i64,
    pub(crate) formation_backfill_generation: i64,
    pub(crate) formation_backfill_complete: bool,
    pub(crate) formation_backfill_rows_scanned: i64,
    pub(crate) formation_backfill_rows_inserted: i64,
    pub(crate) formation_backfill_rows_reopened: i64,
    pub(crate) finalization_claim_drain_complete: bool,
    pub(crate) finalization_claims_scanned: i64,
    pub(crate) finalization_claims_revoked: i64,
    pub(crate) contract_sha256: String,
    pub(crate) catalog_sha256: String,
    pub(crate) base_finalization_receipt_sha256: String,
    pub(crate) receipt_sha256: Option<String>,
}

#[derive(Clone, Debug)]
struct ActivationState {
    phase: MemoryReconciliationActivationPhase,
    generation: i64,
    latest_draining_generation: Option<i64>,
    rollout_basis_points: i64,
    rollout_seed: String,
    explicit_canary_account_ids: Vec<String>,
    candidate_fleet_image_digest: Option<String>,
    receipt_sha256: Option<Vec<u8>>,
    reconciliation_producer_contract_sha256: Option<String>,
    reconciliation_model: Option<String>,
    vertex_location: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct FormationBackfillState {
    refresh_generation: i64,
    complete: bool,
    rows_scanned: i64,
    rows_inserted: i64,
    rows_reopened: i64,
}

#[derive(Clone, Copy, Debug, Default)]
struct FinalizationClaimDrainState {
    present: bool,
    complete: bool,
    claims_scanned: i64,
    claims_revoked: i64,
}

fn phase(value: &str) -> Result<MemoryReconciliationActivationPhase> {
    match value {
        "preactive" => Ok(MemoryReconciliationActivationPhase::Preactive),
        "installed" => Ok(MemoryReconciliationActivationPhase::Installed),
        "draining" => Ok(MemoryReconciliationActivationPhase::Draining),
        "active" => Ok(MemoryReconciliationActivationPhase::Active),
        "paused" => Ok(MemoryReconciliationActivationPhase::Paused),
        _ => Err(EnclaveError::Config(
            "persisted memory reconciliation activation phase is invalid".into(),
        )),
    }
}

fn transition_preserves_activation_identity(
    current: MemoryReconciliationActivationPhase,
    requested: MemoryReconciliationActivationPhase,
) -> bool {
    matches!(
        (current, requested),
        (
            MemoryReconciliationActivationPhase::Draining,
            MemoryReconciliationActivationPhase::Active
        ) | (
            MemoryReconciliationActivationPhase::Active,
            MemoryReconciliationActivationPhase::Paused
        ) | (
            MemoryReconciliationActivationPhase::Paused,
            MemoryReconciliationActivationPhase::Active
        )
    )
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

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", lowercase_hex(bytes))
}

fn sha256_label_bytes(value: &str) -> Result<Vec<u8>> {
    let hex = value.strip_prefix("sha256:").ok_or_else(|| {
        EnclaveError::Config("activation producer contract digest is invalid".into())
    })?;
    if hex.len() != 64
        || hex
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(EnclaveError::Config(
            "activation producer contract digest is invalid".into(),
        ));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!("validated digest nibble"),
            };
            Ok((nibble(pair[0]) << 4) | nibble(pair[1]))
        })
        .collect()
}

fn reserved_relation_signatures() -> Vec<String> {
    RESERVED_RELATION_TABLES
        .iter()
        .map(|name| format!("r:{name}"))
        .chain(
            RESERVED_RELATION_SEQUENCES
                .iter()
                .map(|name| format!("S:{name}")),
        )
        .chain(
            RESERVED_RELATION_TABLES
                .iter()
                .map(|name| format!("i:{name}_pkey")),
        )
        .chain(
            RESERVED_RELATION_INDEXES
                .iter()
                .map(|name| format!("i:{name}")),
        )
        .collect()
}

fn reserved_function_names() -> Vec<String> {
    RESERVED_FUNCTION_SIGNATURES
        .iter()
        .map(|signature| {
            signature
                .strip_prefix("f:")
                .and_then(|value| value.split_once('('))
                .map(|(name, _)| name.to_owned())
                .expect("reserved function signature is canonical")
        })
        .collect()
}

fn reserved_trigger_identities() -> Vec<String> {
    RESERVED_BASE_TRIGGER_IDENTITIES
        .iter()
        .chain(RESERVED_DRAINING_TRIGGER_IDENTITIES)
        .map(|identity| (*identity).to_owned())
        .collect()
}

fn reserved_trigger_names() -> Vec<String> {
    reserved_trigger_identities()
        .into_iter()
        .map(|identity| {
            identity
                .split_once('.')
                .map(|(_, name)| name.to_owned())
                .expect("reserved trigger identity is canonical")
        })
        .collect()
}

fn reserved_type_signatures() -> Vec<String> {
    RESERVED_RELATION_TABLES
        .iter()
        .map(|name| format!("c:{name}"))
        .chain(
            RESERVED_RELATION_TABLES
                .iter()
                .map(|name| format!("b:_{name}")),
        )
        .collect()
}

async fn reserved_catalog_deviations(
    connection: &mut PgConnection,
    expect_installed: bool,
) -> Result<Vec<String>> {
    let relation_signatures = if expect_installed {
        reserved_relation_signatures()
    } else {
        Vec::new()
    };
    let function_signatures = if expect_installed {
        RESERVED_FUNCTION_SIGNATURES
            .iter()
            .map(|signature| (*signature).to_owned())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let trigger_identities = if expect_installed {
        reserved_trigger_identities()
    } else {
        Vec::new()
    };
    let required_trigger_identities = if expect_installed {
        RESERVED_BASE_TRIGGER_IDENTITIES
            .iter()
            .map(|identity| (*identity).to_owned())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let type_signatures = if expect_installed {
        reserved_type_signatures()
    } else {
        Vec::new()
    };
    Ok(sqlx::query_scalar(RESERVED_CATALOG_MANIFEST_SQL)
        .bind(relation_signatures)
        .bind(function_signatures)
        .bind(reserved_function_names())
        .bind(trigger_identities)
        .bind(reserved_trigger_names())
        .bind(type_signatures)
        .bind(required_trigger_identities)
        .fetch_one(connection)
        .await?)
}

fn activation_contract_digest() -> Vec<u8> {
    let mut digest = Sha256::new();
    for part in [
        CONTRACT_MANIFEST,
        INSTALL_SQL,
        FORMATION_BACKFILL_SELECT_SQL,
        ACTIVE_GUARD_DDL,
        PENDING_DELETION_MEMBER_GUARD_DDL,
        PAGED_DELETION_MEMBER_GUARD_DDL,
        PAGED_DELETION_EPISODE_GUARD_DDL,
        PAGED_DELETION_MEDIA_GUARD_DDL,
        PAGED_DELETION_FORMATION_GUARD_DDL,
        CATALOG_EVIDENCE_SQL,
        RESERVED_CATALOG_MANIFEST_SQL,
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    for signature in reserved_relation_signatures()
        .into_iter()
        .chain(
            RESERVED_FUNCTION_SIGNATURES
                .iter()
                .map(|signature| (*signature).to_owned()),
        )
        .chain(reserved_trigger_identities())
        .chain(reserved_type_signatures())
    {
        digest.update((signature.len() as u64).to_be_bytes());
        digest.update(signature.as_bytes());
    }
    digest.finalize().to_vec()
}

async fn ensure_reserved_catalog_manifest(connection: &mut PgConnection) -> Result<()> {
    let deviations = reserved_catalog_deviations(connection, true).await?;
    if !deviations.is_empty() {
        return Err(EnclaveError::Config(format!(
            "v27 reserved catalog namespace contains unreviewed objects: {}",
            deviations.join(",")
        )));
    }
    Ok(())
}

async fn ensure_pristine_reserved_catalog_namespace(connection: &mut PgConnection) -> Result<()> {
    let deviations = reserved_catalog_deviations(connection, false).await?;
    if !deviations.is_empty() {
        return Err(EnclaveError::Config(format!(
            "v27 reserved catalog namespace is not pristine before install: {}",
            deviations.join(",")
        )));
    }
    Ok(())
}

async fn catalog_digest(connection: &mut PgConnection) -> Result<Vec<u8>> {
    ensure_reserved_catalog_manifest(connection).await?;
    let evidence: String = sqlx::query_scalar(CATALOG_EVIDENCE_SQL)
        .fetch_one(connection)
        .await?;
    Ok(Sha256::digest(evidence.as_bytes()).to_vec())
}

async fn activation_contract_exists(connection: &mut PgConnection) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass('persistence_feature_activation_contracts') IS NOT NULL",
    )
    .fetch_one(connection)
    .await?)
}

async fn schema_marker(connection: &mut PgConnection) -> Result<(i64, Option<i64>)> {
    sqlx::query_as(
        "SELECT version,(to_jsonb(schema_marker)->>'expanded_through_version')::bigint \
           FROM persistence_schema schema_marker WHERE singleton=true",
    )
    .fetch_optional(connection)
    .await?
    .ok_or_else(|| EnclaveError::Config("PostgreSQL persistence schema marker is missing".into()))
}

async fn verify_exact_guard(
    connection: &mut PgConnection,
    table_name: &str,
    trigger_name: &str,
    function_name: &str,
    ddl: &str,
    trigger_type: i16,
) -> Result<()> {
    let exact = sqlx::query_scalar::<_, bool>(
        "SELECT count(*)=1 AND bool_and( \
             trigger_state.tgenabled='O' AND trigger_state.tgtype=$5 \
             AND function_state.proname=$3 \
             AND function_namespace.nspname=current_schema() \
             AND regexp_replace(btrim(pg_get_triggerdef(trigger_state.oid,true)), \
                                '\\s+',' ','g') = \
                 regexp_replace(btrim($4),'\\s+',' ','g')) \
           FROM pg_trigger trigger_state \
           JOIN pg_class table_state ON table_state.oid=trigger_state.tgrelid \
           JOIN pg_namespace table_namespace ON table_namespace.oid=table_state.relnamespace \
           JOIN pg_proc function_state ON function_state.oid=trigger_state.tgfoid \
           JOIN pg_namespace function_namespace ON function_namespace.oid=function_state.pronamespace \
          WHERE NOT trigger_state.tgisinternal \
            AND table_namespace.nspname=current_schema() AND table_state.relname=$1 \
            AND trigger_state.tgname=$2",
    )
    .bind(table_name)
    .bind(trigger_name)
    .bind(function_name)
    .bind(ddl)
    .bind(trigger_type)
    .fetch_one(connection)
    .await?;
    if !exact {
        return Err(EnclaveError::Config(format!(
            "reconciliation activation guard {trigger_name} is missing or changed"
        )));
    }
    Ok(())
}

async fn verify_activation_guards(connection: &mut PgConnection) -> Result<()> {
    verify_exact_guard(
        connection,
        "episodes",
        ACTIVE_GUARD_TRIGGER,
        "enforce_assigned_episode_finalization",
        ACTIVE_GUARD_DDL,
        23,
    )
    .await?;
    verify_exact_guard(
        connection,
        "episode_members",
        PENDING_DELETION_MEMBER_GUARD_TRIGGER,
        "reject_pending_deleted_episode_member",
        PENDING_DELETION_MEMBER_GUARD_DDL,
        23,
    )
    .await?;
    verify_exact_guard(
        connection,
        "episode_members",
        PAGED_DELETION_MEMBER_GUARD_TRIGGER,
        "guard_persistence_feature_episode_deletion_mutation",
        PAGED_DELETION_MEMBER_GUARD_DDL,
        31,
    )
    .await?;
    verify_exact_guard(
        connection,
        "episodes",
        PAGED_DELETION_EPISODE_GUARD_TRIGGER,
        "guard_persistence_feature_episode_deletion_mutation",
        PAGED_DELETION_EPISODE_GUARD_DDL,
        11,
    )
    .await?;
    verify_exact_guard(
        connection,
        "media_work_units",
        PAGED_DELETION_MEDIA_GUARD_TRIGGER,
        "guard_persistence_feature_episode_deletion_media_work",
        PAGED_DELETION_MEDIA_GUARD_DDL,
        23,
    )
    .await?;
    verify_exact_guard(
        connection,
        "capture_formation_receipts",
        PAGED_DELETION_FORMATION_GUARD_TRIGGER,
        "guard_persistence_feature_episode_deletion_formation_claim",
        PAGED_DELETION_FORMATION_GUARD_DDL,
        23,
    )
    .await
}

async fn verify_activation_guards_absent(connection: &mut PgConnection) -> Result<()> {
    let present = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM pg_trigger trigger_state \
          JOIN pg_class table_state ON table_state.oid=trigger_state.tgrelid \
          JOIN pg_namespace namespace ON namespace.oid=table_state.relnamespace \
         WHERE namespace.nspname=current_schema() AND NOT trigger_state.tgisinternal \
           AND (table_state.relname,trigger_state.tgname) IN ( \
             ('episodes','episodes_00_enforce_assigned_reconciliation_finalization'), \
             ('episode_members','episode_members_00_reject_pending_deleted_source'), \
             ('episode_members','episode_members_01_guard_paged_deletion'), \
             ('episodes','episodes_01_guard_paged_deletion'), \
             ('media_work_units','media_work_units_00_guard_paged_deletion'), \
             ('capture_formation_receipts', \
                'capture_formation_receipts_00_guard_paged_deletion')))",
    )
    .fetch_one(connection)
    .await?;
    if present {
        return Err(EnclaveError::Config(
            "reconciliation activation guards were attached before signed Draining".into(),
        ));
    }
    Ok(())
}

async fn verify_contract_and_events(
    connection: &mut PgConnection,
    base_receipt_sha256: &[u8],
) -> Result<ActivationState> {
    let expected_contract = activation_contract_digest();
    let expected_catalog = catalog_digest(connection).await?;
    let contract = sqlx::query(
        "SELECT protocol_version,base_schema_version,target_schema_version,contract_sha256, \
                catalog_sha256,base_finalization_receipt_sha256 \
           FROM persistence_feature_activation_contracts WHERE feature=$1",
    )
    .bind(FEATURE)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| EnclaveError::Config("v27 activation contract row is missing".into()))?;
    if contract.try_get::<i64, _>("protocol_version")? != 1
        || contract.try_get::<i64, _>("base_schema_version")? != EXPECTED_SCHEMA_VERSION
        || contract.try_get::<i64, _>("target_schema_version")?
            != MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION
        || contract.try_get::<Vec<u8>, _>("contract_sha256")? != expected_contract
        || contract.try_get::<Vec<u8>, _>("catalog_sha256")? != expected_catalog
        || contract.try_get::<Vec<u8>, _>("base_finalization_receipt_sha256")?
            != base_receipt_sha256
    {
        return Err(EnclaveError::Config(
            "v27 activation contract or catalog commitment changed".into(),
        ));
    }

    let rows = sqlx::query(
        "SELECT generation,previous_phase,phase,rollout_basis_points,rollout_seed, \
                explicit_canary_account_ids,candidate_fleet_image_digest, \
                reconciliation_producer_contract_sha256, \
                reconciliation_model,vertex_location,receipt::text AS receipt_json, \
                receipt_sha256,receipt_signature,receipt_key_sha256 \
           FROM persistence_feature_activation_events WHERE feature=$1 ORDER BY generation",
    )
    .bind(FEATURE)
    .fetch_all(&mut *connection)
    .await?;
    if rows.is_empty() {
        return Err(EnclaveError::Config(
            "v27 activation event chain is missing".into(),
        ));
    }
    let mut prior_phase = "preactive".to_owned();
    let mut state = None;
    let mut latest_draining_generation = None;
    for (ordinal, row) in rows.into_iter().enumerate() {
        let generation: i64 = row.try_get("generation")?;
        let previous_phase: String = row.try_get("previous_phase")?;
        let next_phase: String = row.try_get("phase")?;
        let candidate_fleet_image_digest: Option<String> =
            row.try_get("candidate_fleet_image_digest")?;
        if generation != ordinal as i64 || previous_phase != prior_phase {
            return Err(EnclaveError::Config(
                "v27 activation event chain is non-contiguous".into(),
            ));
        }
        let receipt_sha256: Option<Vec<u8>> = row.try_get("receipt_sha256")?;
        if generation == 0 {
            if next_phase != "installed"
                || row.try_get::<Option<String>, _>("receipt_json")?.is_some()
                || receipt_sha256.is_some()
                || candidate_fleet_image_digest.is_some()
            {
                return Err(EnclaveError::Config(
                    "v27 installation event is not the exact generation-zero contract".into(),
                ));
            }
        } else {
            let receipt_json: String = row.try_get("receipt_json")?;
            let receipt = serde_json::from_str(&receipt_json)?;
            let signature = MemoryReconciliationActivationSignature::from_bytes(
                row.try_get("receipt_signature")?,
            )?;
            let verified =
                super::schema_release::verify_memory_reconciliation_activation_authorization(
                    receipt, signature,
                )?;
            let signed = verified.receipt();
            let computed_digest = Sha256::digest(verified.canonical_bytes()).to_vec();
            if signed.generation != generation
                || signed.previous_phase != previous_phase
                || signed.requested_phase != next_phase
                || signed.activation_contract_sha256 != sha256_label(&expected_contract)
                || signed.activation_catalog_sha256 != sha256_label(&expected_catalog)
                || signed.base_finalization_receipt_sha256 != sha256_label(base_receipt_sha256)
                || receipt_sha256.as_deref() != Some(computed_digest.as_slice())
                || row.try_get::<Vec<u8>, _>("receipt_key_sha256")? != verified.key_sha256()
                || row.try_get::<i64, _>("rollout_basis_points")? != signed.rollout_basis_points
                || row.try_get::<String, _>("rollout_seed")? != signed.rollout_seed
                || row.try_get::<Vec<String>, _>("explicit_canary_account_ids")?
                    != signed.explicit_canary_account_ids
                || candidate_fleet_image_digest.as_deref()
                    != Some(signed.candidate_fleet_image_digest.as_str())
                || row
                    .try_get::<Option<String>, _>("reconciliation_producer_contract_sha256")?
                    .as_deref()
                    != Some(signed.reconciliation_producer_contract_sha256.as_str())
                || row
                    .try_get::<Option<String>, _>("reconciliation_model")?
                    .as_deref()
                    != Some(signed.reconciliation_model.as_str())
                || row
                    .try_get::<Option<String>, _>("vertex_location")?
                    .as_deref()
                    != Some(signed.vertex_location.as_str())
            {
                return Err(EnclaveError::Config(
                    "persisted v27 activation receipt does not verify exactly".into(),
                ));
            }
        }
        prior_phase = next_phase.clone();
        let verified_phase = phase(&next_phase)?;
        if transition_preserves_activation_identity(phase(&previous_phase)?, verified_phase)
            && state
                .as_ref()
                .and_then(|prior: &ActivationState| prior.candidate_fleet_image_digest.as_deref())
                != candidate_fleet_image_digest.as_deref()
        {
            return Err(EnclaveError::Config(
                "persisted active or paused activation changed candidate fleet identity".into(),
            ));
        }
        if verified_phase == MemoryReconciliationActivationPhase::Draining {
            latest_draining_generation = Some(generation);
        }
        state = Some(ActivationState {
            phase: verified_phase,
            generation,
            latest_draining_generation,
            rollout_basis_points: row.try_get("rollout_basis_points")?,
            rollout_seed: row.try_get("rollout_seed")?,
            explicit_canary_account_ids: row.try_get("explicit_canary_account_ids")?,
            candidate_fleet_image_digest,
            receipt_sha256,
            reconciliation_producer_contract_sha256: row
                .try_get("reconciliation_producer_contract_sha256")?,
            reconciliation_model: row.try_get("reconciliation_model")?,
            vertex_location: row.try_get("vertex_location")?,
        });
    }
    let state = state.expect("non-empty activation rows produced a state");
    let marker = schema_marker(connection).await?;
    match state.phase {
        MemoryReconciliationActivationPhase::Installed
            if marker == (EXPECTED_SCHEMA_VERSION, Some(EXPECTED_SCHEMA_VERSION)) =>
        {
            verify_activation_guards_absent(connection).await?;
        }
        MemoryReconciliationActivationPhase::Draining
            if marker == (EXPECTED_SCHEMA_VERSION, Some(EXPECTED_SCHEMA_VERSION)) =>
        {
            verify_activation_guards(connection).await?;
        }
        MemoryReconciliationActivationPhase::Draining
            if marker
                == (
                    MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION,
                    Some(MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION),
                ) =>
        {
            verify_activation_guards(connection).await?;
        }
        MemoryReconciliationActivationPhase::Active
        | MemoryReconciliationActivationPhase::Paused
            if marker
                == (
                    MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION,
                    Some(MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION),
                ) =>
        {
            verify_activation_guards(connection).await?;
        }
        _ => {
            return Err(EnclaveError::Config(
                "activation phase and PostgreSQL schema marker disagree".into(),
            ));
        }
    }
    Ok(state)
}

async fn assigned_count(connection: &mut PgConnection) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM persistence_feature_activation_assignments WHERE feature=$1",
    )
    .bind(FEATURE)
    .fetch_one(connection)
    .await?)
}

async fn formation_backfill_state(connection: &mut PgConnection) -> Result<FormationBackfillState> {
    let row = sqlx::query(
        "SELECT refresh_generation,complete,rows_scanned,rows_inserted,rows_reopened \
           FROM persistence_feature_activation_backfills \
          WHERE feature=$1 AND backfill_name=$2",
    )
    .bind(FEATURE)
    .bind(FORMATION_BACKFILL_NAME)
    .fetch_optional(connection)
    .await?
    .ok_or_else(|| EnclaveError::Config("v27 formation backfill ledger is missing".into()))?;
    Ok(FormationBackfillState {
        refresh_generation: row.try_get("refresh_generation")?,
        complete: row.try_get("complete")?,
        rows_scanned: row.try_get("rows_scanned")?,
        rows_inserted: row.try_get("rows_inserted")?,
        rows_reopened: row.try_get("rows_reopened")?,
    })
}

async fn finalization_claim_drain_state(
    connection: &mut PgConnection,
    generation: Option<i64>,
) -> Result<FinalizationClaimDrainState> {
    let Some(generation) = generation else {
        return Ok(FinalizationClaimDrainState::default());
    };
    let row = sqlx::query(
        "SELECT complete,claims_scanned,claims_revoked \
           FROM persistence_feature_activation_drains \
          WHERE feature=$1 AND activation_generation=$2",
    )
    .bind(FEATURE)
    .bind(generation)
    .fetch_optional(connection)
    .await?;
    Ok(match row {
        Some(row) => FinalizationClaimDrainState {
            present: true,
            complete: row.try_get("complete")?,
            claims_scanned: row.try_get("claims_scanned")?,
            claims_revoked: row.try_get("claims_revoked")?,
        },
        None => FinalizationClaimDrainState::default(),
    })
}

async fn unresolved_source_accounts(connection: &mut PgConnection) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(DISTINCT account_id) FROM ( \
             SELECT receipt.account_id FROM capture_formation_receipts receipt \
              WHERE receipt.source_revision<>receipt.completed_revision \
                 OR receipt.state<>'complete' \
                 OR (receipt.finish_requested_at IS NOT NULL \
                     AND receipt.seal_finalized_at IS NULL) \
             UNION \
             SELECT session.account_id FROM capture_sessions session \
              LEFT JOIN capture_formation_receipts receipt \
                ON receipt.account_id=session.account_id \
               AND receipt.capture_session_id=session.id \
              WHERE session.ended_at IS NOT NULL AND ( \
                    receipt.account_id IS NULL \
                    OR receipt.state<>'complete' \
                    OR receipt.completed_revision<>receipt.source_revision \
                    OR receipt.finish_requested_at IS NULL \
                    OR receipt.seal_finalized_at IS NULL \
                    OR receipt.seal_generation<1 \
                    OR NOT EXISTS( \
                        SELECT 1 FROM capture_formation_seal_events seal \
                         WHERE seal.account_id=receipt.account_id \
                           AND seal.capture_session_id=receipt.capture_session_id \
                           AND seal.seal_generation=receipt.seal_generation \
                           AND seal.source_revision=receipt.source_revision \
                           AND seal.event_kind='seal' \
                           AND seal.stream_maxima_sha256= \
                               capture_formation_stream_maxima_sha256( \
                                   receipt.account_id,receipt.capture_session_id)) \
                    OR EXISTS( \
                        SELECT 1 FROM capture_formation_seal_events reopen \
                         WHERE reopen.account_id=receipt.account_id \
                           AND reopen.capture_session_id=receipt.capture_session_id \
                           AND reopen.seal_generation=receipt.seal_generation \
                           AND reopen.event_kind='reopen') \
                    OR NOT EXISTS( \
                        SELECT 1 FROM capture_streams stream \
                         WHERE stream.account_id=session.account_id \
                           AND stream.capture_session_id=session.id) \
                    OR EXISTS( \
                        SELECT 1 FROM capture_streams stream \
                         WHERE stream.account_id=session.account_id \
                           AND stream.capture_session_id=session.id \
                           AND (stream.sealed_sequence IS NULL \
                                OR stream.committed_through_sequence<> \
                                   stream.sealed_sequence \
                                OR stream.committed_through_sequence IS DISTINCT FROM \
                                   capture_formation_stream_accepted_max( \
                                       stream.account_id,stream.id) \
                                OR stream.committed_through_sequence IS DISTINCT FROM \
                                   capture_formation_stream_contiguous_through( \
                                       stream.account_id,stream.id))) \
              ) \
         ) unresolved",
    )
    .fetch_one(connection)
    .await?)
}

async fn verify_activation_and_base_release(
    connection: &mut PgConnection,
) -> Result<(Vec<u8>, ActivationState)> {
    // The activation event chain binds the canonical v26 receipt digest. Read
    // that content-free digest first so the chain can determine whether the
    // two exact draining guards are authorized additions to the frozen v26
    // catalog. The full signed v26 receipt and every catalog byte are then
    // verified with that narrowly derived mode before this function returns.
    let stored_base = sqlx::query_scalar::<_, Option<Vec<u8>>>(
        "SELECT finalization_receipt_sha256 FROM persistence_schema_releases \
          WHERE release_version=$1",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_optional(&mut *connection)
    .await?
    .flatten()
    .ok_or_else(|| EnclaveError::Config("v26 finalization receipt digest is missing".into()))?;
    let state = verify_contract_and_events(connection, &stored_base).await?;
    let allow_draining_guards = matches!(
        state.phase,
        MemoryReconciliationActivationPhase::Draining
            | MemoryReconciliationActivationPhase::Active
            | MemoryReconciliationActivationPhase::Paused
    );
    let verified_base = verify_finalized_v26_release(connection, allow_draining_guards).await?;
    if verified_base != stored_base {
        return Err(EnclaveError::Config(
            "activation chain does not bind the verified v26 finalization receipt".into(),
        ));
    }
    Ok((verified_base, state))
}

async fn verified_status(
    connection: &mut PgConnection,
) -> Result<MemoryReconciliationActivationStatus> {
    let marker = schema_marker(connection).await?;
    if !activation_contract_exists(connection).await? {
        if marker != (EXPECTED_SCHEMA_VERSION, Some(EXPECTED_SCHEMA_VERSION)) {
            return Err(EnclaveError::Config(
                "v27 marker or activation contract is missing".into(),
            ));
        }
        verify_finalized_v26_release(connection, false).await?;
        return Ok(MemoryReconciliationActivationStatus {
            phase: MemoryReconciliationActivationPhase::Preactive,
            generation: 0,
            rollout_basis_points: 0,
            explicit_canary_accounts: 0,
            assigned_accounts: 0,
            formation_backfill_generation: None,
            formation_backfill_complete: false,
            finalization_claim_drain_complete: false,
            receipt_sha256: None,
            reconciliation_producer_contract_sha256: None,
            reconciliation_model: None,
            vertex_location: None,
        });
    }
    let (_, state) = verify_activation_and_base_release(connection).await?;
    let backfill = formation_backfill_state(connection).await?;
    let drain =
        finalization_claim_drain_state(connection, state.latest_draining_generation).await?;
    let expected_backfill_generation = state.latest_draining_generation.unwrap_or(0);
    if backfill.refresh_generation != expected_backfill_generation
        || (state.phase != MemoryReconciliationActivationPhase::Installed && !drain.present)
    {
        return Err(EnclaveError::Config(
            "reconciliation activation rollout ledgers do not match the signed draining generation"
                .into(),
        ));
    }
    if matches!(
        state.phase,
        MemoryReconciliationActivationPhase::Active | MemoryReconciliationActivationPhase::Paused
    ) && (!backfill.complete || !drain.complete)
    {
        return Err(EnclaveError::Config(
            "active or paused reconciliation activation has incomplete rollout ledgers".into(),
        ));
    }
    Ok(MemoryReconciliationActivationStatus {
        phase: state.phase,
        generation: state.generation,
        rollout_basis_points: state.rollout_basis_points,
        explicit_canary_accounts: state.explicit_canary_account_ids.len(),
        assigned_accounts: assigned_count(connection).await?,
        formation_backfill_generation: Some(backfill.refresh_generation),
        formation_backfill_complete: backfill.complete,
        finalization_claim_drain_complete: drain.complete,
        receipt_sha256: state.receipt_sha256.as_deref().map(sha256_label),
        reconciliation_producer_contract_sha256: state.reconciliation_producer_contract_sha256,
        reconciliation_model: state.reconciliation_model,
        vertex_location: state.vertex_location,
    })
}

pub(super) async fn verify_serving_activation_schema(
    connection: &mut PgConnection,
) -> Result<MemoryReconciliationActivationStatus> {
    verified_status(connection).await
}

/// Serialize a v27-capable source writer with signed activation transitions.
/// Absence is an intentional no-op during the binary-first dark rollout.
pub(super) async fn lock_activation_contract_key_share_if_installed(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<bool> {
    // This shared lock must precede even the existence probe. During the
    // binary-first schema-26 rollout, a writer may otherwise cache "absent",
    // let the exclusive installer commit v27, and only then perform legacy
    // DML without the new tombstone/finalization fences. Install and every
    // signed transition hold the exclusive counterpart through commit.
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
        .bind(RELEASE_LOCK)
        .execute(&mut **transaction)
        .await?;
    if !sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass('persistence_feature_activation_contracts') IS NOT NULL",
    )
    .fetch_one(&mut **transaction)
    .await?
    {
        return Ok(false);
    }
    sqlx::query(
        "SELECT feature FROM persistence_feature_activation_contracts \
         WHERE feature=$1 FOR KEY SHARE",
    )
    .bind(FEATURE)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(true)
}

async fn lock_contract_key_share(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<Option<ActivationState>> {
    if !lock_activation_contract_key_share_if_installed(transaction).await? {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT generation,phase,rollout_basis_points,rollout_seed, \
                explicit_canary_account_ids,candidate_fleet_image_digest,receipt_sha256, \
                reconciliation_producer_contract_sha256,reconciliation_model,vertex_location, \
                (SELECT max(prior.generation) \
                   FROM persistence_feature_activation_events prior \
                  WHERE prior.feature=$1 AND prior.phase='draining') \
                    AS latest_draining_generation \
           FROM persistence_feature_activation_events WHERE feature=$1 \
           ORDER BY generation DESC LIMIT 1",
    )
    .bind(FEATURE)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(Some(ActivationState {
        phase: phase(&row.try_get::<String, _>("phase")?)?,
        generation: row.try_get("generation")?,
        latest_draining_generation: row.try_get("latest_draining_generation")?,
        rollout_basis_points: row.try_get("rollout_basis_points")?,
        rollout_seed: row.try_get("rollout_seed")?,
        explicit_canary_account_ids: row.try_get("explicit_canary_account_ids")?,
        candidate_fleet_image_digest: row.try_get("candidate_fleet_image_digest")?,
        receipt_sha256: row.try_get("receipt_sha256")?,
        reconciliation_producer_contract_sha256: row
            .try_get("reconciliation_producer_contract_sha256")?,
        reconciliation_model: row.try_get("reconciliation_model")?,
        vertex_location: row.try_get("vertex_location")?,
    }))
}

async fn assigned(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    account_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM persistence_feature_activation_assignments \
          WHERE feature=$1 AND account_id=$2)",
    )
    .bind(FEATURE)
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn account_was_selected(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    account_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM persistence_feature_activation_events event \
          WHERE event.feature=$1 AND event.phase='active' \
            AND (event.rollout_basis_points=10000 \
                 OR $2=ANY(event.explicit_canary_account_ids)))",
    )
    .bind(FEATURE)
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?)
}

fn in_current_scope(state: &ActivationState, account_id: &str) -> bool {
    state.rollout_basis_points == 10_000
        || state
            .explicit_canary_account_ids
            .binary_search_by(|value| value.as_str().cmp(account_id))
            .is_ok()
}

/// Locks the fleet activation fence before every finalization boundary. An
/// immutable prior active scope remains authoritative during pause.
pub(super) async fn finalization_requires_reconciled(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    account_id: &str,
) -> Result<bool> {
    let Some(state) = lock_contract_key_share(transaction).await? else {
        return Ok(false);
    };
    let selected_now = matches!(
        state.phase,
        MemoryReconciliationActivationPhase::Draining | MemoryReconciliationActivationPhase::Active
    ) && in_current_scope(&state, account_id);
    if assigned(transaction, account_id).await?
        || account_was_selected(transaction, account_id).await?
        || selected_now
    {
        if selected_now {
            sqlx::query(
                "INSERT INTO persistence_feature_activation_assignments( \
                     feature,account_id,activation_generation) VALUES($1,$2,$3) \
                 ON CONFLICT(feature,account_id) DO NOTHING",
            )
            .bind(FEATURE)
            .bind(account_id)
            .bind(state.generation)
            .execute(&mut **transaction)
            .await?;
        }
        return Ok(true);
    }
    Ok(false)
}

/// Returns the exact signed active producer only after atomically assigning an
/// eligible account. Claim, provider attempt, stage, and publish bind all fields.
pub(super) async fn active_reconciliation_authority(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    account_id: &str,
) -> Result<Option<ActiveReconciliationAuthority>> {
    let Some(state) = lock_contract_key_share(transaction).await? else {
        return Ok(None);
    };
    if state.phase != MemoryReconciliationActivationPhase::Active {
        return Ok(None);
    }
    let is_assigned = assigned(transaction, account_id).await?;
    if !is_assigned && !in_current_scope(&state, account_id) {
        return Ok(None);
    }
    if !is_assigned {
        sqlx::query(
            "INSERT INTO persistence_feature_activation_assignments( \
                 feature,account_id,activation_generation) VALUES($1,$2,$3) \
             ON CONFLICT(feature,account_id) DO NOTHING",
        )
        .bind(FEATURE)
        .bind(account_id)
        .bind(state.generation)
        .execute(&mut **transaction)
        .await?;
    }
    let producer_label = state
        .reconciliation_producer_contract_sha256
        .ok_or_else(|| EnclaveError::Config("active producer commitment is missing".into()))?;
    Ok(Some(ActiveReconciliationAuthority {
        generation: state.generation,
        producer_contract_sha256: sha256_label_bytes(&producer_label)?,
        reconciliation_model: state
            .reconciliation_model
            .ok_or_else(|| EnclaveError::Config("active reconciliation model is missing".into()))?,
        vertex_location: state
            .vertex_location
            .ok_or_else(|| EnclaveError::Config("active Vertex location is missing".into()))?,
    }))
}

async fn insert_scope_assignments(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    generation: i64,
    explicit_accounts: &[String],
) -> Result<()> {
    if explicit_accounts.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO persistence_feature_activation_assignments( \
             feature,account_id,activation_generation) \
         SELECT $1,account.id,$2 FROM accounts account \
          WHERE account.id=ANY($3::text[]) \
         ON CONFLICT(feature,account_id) DO NOTHING",
    )
    .bind(FEATURE)
    .bind(generation)
    .bind(explicit_accounts)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn require_formation_backfill_complete(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    generation: Option<i64>,
) -> Result<()> {
    let complete = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM persistence_feature_activation_backfills \
          WHERE feature=$1 AND backfill_name=$2 \
            AND ($3::bigint IS NULL OR refresh_generation=$3) \
            AND complete=true)",
    )
    .bind(FEATURE)
    .bind(FORMATION_BACKFILL_NAME)
    .bind(generation)
    .fetch_one(&mut **transaction)
    .await?;
    if !complete {
        return Err(EnclaveError::Conflict(format!(
            "formation receipt backfill{} is incomplete",
            generation.map_or_else(String::new, |value| format!(" generation {value}"))
        )));
    }
    Ok(())
}

async fn reset_formation_backfill(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    generation: i64,
) -> Result<()> {
    let changed = sqlx::query(
        "UPDATE persistence_feature_activation_backfills \
            SET refresh_generation=$3,last_account_id=NULL,last_capture_session_id=NULL, \
                complete=false,rows_scanned=0,rows_inserted=0,rows_reopened=0, \
                started_at=clock_timestamp(),updated_at=clock_timestamp(),completed_at=NULL \
          WHERE feature=$1 AND backfill_name=$2",
    )
    .bind(FEATURE)
    .bind(FORMATION_BACKFILL_NAME)
    .bind(generation)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(EnclaveError::Config(
            "v27 formation backfill ledger is missing".into(),
        ));
    }
    Ok(())
}

async fn initialize_finalization_claim_drain(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    generation: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO persistence_feature_activation_drains( \
             feature,activation_generation) VALUES($1,$2)",
    )
    .bind(FEATURE)
    .bind(generation)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn require_finalization_claim_drain_complete(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    generation: Option<i64>,
) -> Result<()> {
    let complete = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM persistence_feature_activation_drains \
          WHERE feature=$1 AND ($2::bigint IS NULL OR activation_generation=$2) \
            AND complete=true)",
    )
    .bind(FEATURE)
    .bind(generation)
    .fetch_one(&mut **transaction)
    .await?;
    if !complete {
        return Err(EnclaveError::Conflict(format!(
            "draft finalization claim drain{} is incomplete",
            generation.map_or_else(String::new, |value| format!(" generation {value}"))
        )));
    }
    Ok(())
}

async fn require_zero_scoped_draft_claims(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    state: &ActivationState,
) -> Result<()> {
    let claims = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM episodes episode \
          WHERE episode.structure_state='draft' \
            AND episode.finalization_claim_token IS NOT NULL \
            AND ($1=10000 OR episode.account_id=ANY($2::text[]))",
    )
    .bind(state.rollout_basis_points)
    .bind(&state.explicit_canary_account_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if claims != 0 {
        return Err(EnclaveError::Conflict(
            "active transition found a scoped legacy draft claim after drain completion".into(),
        ));
    }
    Ok(())
}

async fn advance_finalization_claim_drain_batch(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    generation: i64,
) -> Result<bool> {
    let ledger = sqlx::query(
        "SELECT last_account_id,last_episode_id,complete \
           FROM persistence_feature_activation_drains \
          WHERE feature=$1 AND activation_generation=$2 FOR UPDATE",
    )
    .bind(FEATURE)
    .bind(generation)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| EnclaveError::Config("draft finalization claim drain is missing".into()))?;
    if ledger.try_get::<bool, _>("complete")? {
        return Ok(true);
    }
    let after_account_id: Option<String> = ledger.try_get("last_account_id")?;
    let after_episode_id: Option<i64> = ledger.try_get("last_episode_id")?;
    let rows = sqlx::query(
        "SELECT episode.account_id,episode.id \
           FROM episodes episode \
           JOIN persistence_feature_activation_events event \
             ON event.feature=$1 AND event.generation=$2 \
          WHERE episode.structure_state='draft' \
            AND episode.finalization_claim_token IS NOT NULL \
            AND (event.rollout_basis_points=10000 \
                 OR episode.account_id=ANY(event.explicit_canary_account_ids)) \
            AND ($3::text IS NULL OR (episode.account_id,episode.id)>($3,$4)) \
          ORDER BY episode.account_id,episode.id LIMIT $5 FOR UPDATE OF episode",
    )
    .bind(FEATURE)
    .bind(generation)
    .bind(after_account_id.as_deref())
    .bind(after_episode_id)
    .bind(FINALIZATION_CLAIM_DRAIN_BATCH_SIZE)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.is_empty() {
        let remaining = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM episodes episode \
              JOIN persistence_feature_activation_events event \
                ON event.feature=$1 AND event.generation=$2 \
             WHERE episode.structure_state='draft' \
               AND episode.finalization_claim_token IS NOT NULL \
               AND (event.rollout_basis_points=10000 \
                    OR episode.account_id=ANY(event.explicit_canary_account_ids)))",
        )
        .bind(FEATURE)
        .bind(generation)
        .fetch_one(&mut **transaction)
        .await?;
        if remaining {
            sqlx::query(
                "UPDATE persistence_feature_activation_drains \
                    SET last_account_id=NULL,last_episode_id=NULL,updated_at=clock_timestamp() \
                  WHERE feature=$1 AND activation_generation=$2 AND complete=false",
            )
            .bind(FEATURE)
            .bind(generation)
            .execute(&mut **transaction)
            .await?;
            return Ok(false);
        }
        let changed = sqlx::query(
            "UPDATE persistence_feature_activation_drains \
                SET complete=true,completed_at=clock_timestamp(),updated_at=clock_timestamp() \
              WHERE feature=$1 AND activation_generation=$2 AND complete=false",
        )
        .bind(FEATURE)
        .bind(generation)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "draft finalization claim drain lost its ledger claim".into(),
            ));
        }
        return Ok(true);
    }
    let account_ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("account_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let episode_ids = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let revoked = sqlx::query(
        "UPDATE episodes episode SET finalization_claim_token=NULL, \
             finalization_claim_until=NULL,finalization_status='pending_watermark', \
             finalization_error='awaiting_memory_reconciliation',updated_at=clock_timestamp() \
          FROM unnest($1::text[],$2::bigint[]) target(account_id,episode_id) \
         WHERE episode.account_id=target.account_id AND episode.id=target.episode_id \
           AND episode.structure_state='draft' \
           AND episode.finalization_claim_token IS NOT NULL",
    )
    .bind(&account_ids)
    .bind(&episode_ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let last = account_ids.len() - 1;
    let changed = sqlx::query(
        "UPDATE persistence_feature_activation_drains \
            SET last_account_id=$3,last_episode_id=$4, \
                claims_scanned=claims_scanned+$5,claims_revoked=claims_revoked+$6, \
                updated_at=clock_timestamp() \
          WHERE feature=$1 AND activation_generation=$2 AND complete=false",
    )
    .bind(FEATURE)
    .bind(generation)
    .bind(&account_ids[last])
    .bind(episode_ids[last])
    .bind(i64::try_from(rows.len()).map_err(|_| {
        EnclaveError::Store("finalization claim drain batch length overflowed".into())
    })?)
    .bind(
        i64::try_from(revoked)
            .map_err(|_| EnclaveError::Store("finalization claim drain count overflowed".into()))?,
    )
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(EnclaveError::Conflict(
            "draft finalization claim drain lost its ledger claim".into(),
        ));
    }
    Ok(false)
}

async fn advance_formation_backfill_batch(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    expected_generation: i64,
) -> Result<bool> {
    let ledger = sqlx::query(
        "SELECT refresh_generation,last_account_id,last_capture_session_id,complete \
           FROM persistence_feature_activation_backfills \
          WHERE feature=$1 AND backfill_name=$2 FOR UPDATE",
    )
    .bind(FEATURE)
    .bind(FORMATION_BACKFILL_NAME)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| EnclaveError::Config("v27 formation backfill ledger is missing".into()))?;
    let generation: i64 = ledger.try_get("refresh_generation")?;
    if generation != expected_generation {
        return Err(EnclaveError::Conflict(format!(
            "formation receipt backfill generation {generation} does not match activation generation {expected_generation}"
        )));
    }
    if ledger.try_get::<bool, _>("complete")? {
        return Ok(true);
    }
    let after_account_id: Option<String> = ledger.try_get("last_account_id")?;
    let after_session_id: Option<String> = ledger.try_get("last_capture_session_id")?;
    let rows = sqlx::query(FORMATION_BACKFILL_SELECT_SQL)
        .bind(after_account_id.as_deref())
        .bind(after_session_id.as_deref())
        .bind(FORMATION_BACKFILL_BATCH_SIZE)
        .fetch_all(&mut **transaction)
        .await?;
    if rows.is_empty() {
        // Candidate writers insert/dirty their own receipt under the contract
        // key-share fence. A missing row here can only be a lower key written by
        // a predecessor before the signed drain, so restart the bounded pass.
        let missing = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM capture_sessions session \
              LEFT JOIN capture_formation_receipts receipt \
                ON receipt.account_id=session.account_id \
               AND receipt.capture_session_id=session.id \
              WHERE receipt.capture_session_id IS NULL)",
        )
        .fetch_one(&mut **transaction)
        .await?;
        if missing {
            sqlx::query(
                "UPDATE persistence_feature_activation_backfills \
                    SET last_account_id=NULL,last_capture_session_id=NULL, \
                        updated_at=clock_timestamp() \
                  WHERE feature=$1 AND backfill_name=$2 AND refresh_generation=$3",
            )
            .bind(FEATURE)
            .bind(FORMATION_BACKFILL_NAME)
            .bind(generation)
            .execute(&mut **transaction)
            .await?;
            return Ok(false);
        }
        let changed = sqlx::query(
            "UPDATE persistence_feature_activation_backfills \
                SET complete=true,completed_at=clock_timestamp(),updated_at=clock_timestamp() \
              WHERE feature=$1 AND backfill_name=$2 AND refresh_generation=$3 \
                AND complete=false",
        )
        .bind(FEATURE)
        .bind(FORMATION_BACKFILL_NAME)
        .bind(generation)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "formation receipt backfill completion lost its ledger claim".into(),
            ));
        }
        return Ok(true);
    }

    let mut inserted = 0_i64;
    let mut reopened = 0_i64;
    for row in &rows {
        let account_id: String = row.try_get("account_id")?;
        let capture_session_id: String = row.try_get("id")?;
        let existed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM capture_formation_receipts \
              WHERE account_id=$1 AND capture_session_id=$2)",
        )
        .bind(&account_id)
        .bind(&capture_session_id)
        .fetch_one(&mut **transaction)
        .await?;
        if super::memory_formation::refresh_capture_formation_receipt(
            transaction,
            &account_id,
            &capture_session_id,
        )
        .await?
        {
            if existed {
                reopened += 1;
            } else {
                inserted += 1;
            }
        }
    }
    let last = rows
        .last()
        .expect("non-empty formation backfill batch has a last row");
    let last_account_id: String = last.try_get("account_id")?;
    let last_capture_session_id: String = last.try_get("id")?;
    let changed =
        sqlx::query(
            "UPDATE persistence_feature_activation_backfills \
            SET last_account_id=$4,last_capture_session_id=$5, \
                rows_scanned=rows_scanned+$6,rows_inserted=rows_inserted+$7, \
                rows_reopened=rows_reopened+$8,updated_at=clock_timestamp() \
          WHERE feature=$1 AND backfill_name=$2 AND refresh_generation=$3 \
            AND complete=false",
        )
        .bind(FEATURE)
        .bind(FORMATION_BACKFILL_NAME)
        .bind(generation)
        .bind(last_account_id)
        .bind(last_capture_session_id)
        .bind(i64::try_from(rows.len()).map_err(|_| {
            EnclaveError::Store("formation backfill batch length overflowed".into())
        })?)
        .bind(inserted)
        .bind(reopened)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    if changed != 1 {
        return Err(EnclaveError::Conflict(
            "formation receipt backfill lost its ledger claim".into(),
        ));
    }
    Ok(false)
}

async fn install_activation_guards(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<()> {
    for (table_name, trigger_name, ddl) in [
        ("episodes", ACTIVE_GUARD_TRIGGER, ACTIVE_GUARD_DDL),
        (
            "episode_members",
            PENDING_DELETION_MEMBER_GUARD_TRIGGER,
            PENDING_DELETION_MEMBER_GUARD_DDL,
        ),
        (
            "episode_members",
            PAGED_DELETION_MEMBER_GUARD_TRIGGER,
            PAGED_DELETION_MEMBER_GUARD_DDL,
        ),
        (
            "episodes",
            PAGED_DELETION_EPISODE_GUARD_TRIGGER,
            PAGED_DELETION_EPISODE_GUARD_DDL,
        ),
        (
            "media_work_units",
            PAGED_DELETION_MEDIA_GUARD_TRIGGER,
            PAGED_DELETION_MEDIA_GUARD_DDL,
        ),
        (
            "capture_formation_receipts",
            PAGED_DELETION_FORMATION_GUARD_TRIGGER,
            PAGED_DELETION_FORMATION_GUARD_DDL,
        ),
    ] {
        if !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pg_trigger trigger_state \
              JOIN pg_class table_state ON table_state.oid=trigger_state.tgrelid \
              JOIN pg_namespace namespace ON namespace.oid=table_state.relnamespace \
              WHERE NOT trigger_state.tgisinternal \
                AND namespace.nspname=current_schema() AND table_state.relname=$1 \
                AND trigger_state.tgname=$2)",
        )
        .bind(table_name)
        .bind(trigger_name)
        .fetch_one(&mut **transaction)
        .await?
        {
            sqlx::query(ddl).execute(&mut **transaction).await?;
        }
    }
    verify_activation_guards(transaction).await
}

async fn require_paged_or_complete_episode_deletions(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    current_phase: MemoryReconciliationActivationPhase,
) -> Result<()> {
    // Block direct legacy DML as well as cooperating writers while the signed
    // Draining transition proves that every unfinished deletion has the exact
    // paged companion required by the guards it is about to attach.
    sqlx::query("LOCK TABLE episode_deletions IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut **transaction)
        .await?;
    let incoherent = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS( \
             SELECT 1 FROM episode_deletions deletion \
             LEFT JOIN persistence_feature_episode_deletion_progress progress \
               ON progress.account_id=deletion.account_id \
              AND progress.episode_id=deletion.episode_id \
            WHERE ($1 AND deletion.state='pending') \
               OR (NOT $1 AND deletion.state='pending' \
                    AND (progress.account_id IS NULL OR progress.phase='complete')) \
               OR (deletion.state='complete' AND progress.account_id IS NOT NULL \
                    AND progress.phase<>'complete'))",
    )
    .bind(current_phase == MemoryReconciliationActivationPhase::Installed)
    .fetch_one(&mut **transaction)
    .await?;
    if incoherent {
        return Err(EnclaveError::Conflict(
            if current_phase == MemoryReconciliationActivationPhase::Installed {
                "signed Installed-to-Draining requires zero pending legacy episode deletions".into()
            } else {
                "signed Draining requires every pending episode deletion to have exact paged progress"
                    .into()
            },
        ));
    }
    Ok(())
}

fn release_status(
    phase: MemoryReconciliationActivationPhase,
) -> MemoryReconciliationActivationReleaseStatus {
    match phase {
        MemoryReconciliationActivationPhase::Installed => {
            MemoryReconciliationActivationReleaseStatus::AlreadyInstalled
        }
        MemoryReconciliationActivationPhase::Draining => {
            MemoryReconciliationActivationReleaseStatus::Draining
        }
        MemoryReconciliationActivationPhase::Active => {
            MemoryReconciliationActivationReleaseStatus::Active
        }
        MemoryReconciliationActivationPhase::Paused => {
            MemoryReconciliationActivationReleaseStatus::Paused
        }
        MemoryReconciliationActivationPhase::Preactive => unreachable!(),
    }
}

async fn release_result(
    connection: &mut PgConnection,
    status: MemoryReconciliationActivationReleaseStatus,
) -> Result<MemoryReconciliationActivationReleaseResult> {
    let activation = verified_status(connection).await?;
    let (schema_version, expanded_through_version) = schema_marker(connection).await?;
    let base = verify_finalized_v26_release(
        connection,
        matches!(
            activation.phase,
            MemoryReconciliationActivationPhase::Draining
                | MemoryReconciliationActivationPhase::Active
                | MemoryReconciliationActivationPhase::Paused
        ),
    )
    .await?;
    let backfill = formation_backfill_state(connection).await?;
    let drain_generation: Option<i64> = sqlx::query_scalar(
        "SELECT max(generation) FROM persistence_feature_activation_events \
          WHERE feature=$1 AND phase='draining'",
    )
    .bind(FEATURE)
    .fetch_one(&mut *connection)
    .await?;
    let drain = finalization_claim_drain_state(connection, drain_generation).await?;
    Ok(MemoryReconciliationActivationReleaseResult {
        status,
        phase: activation.phase.as_str().into(),
        generation: activation.generation,
        schema_version,
        expanded_through_version,
        rollout_basis_points: activation.rollout_basis_points,
        explicit_canary_accounts: activation.explicit_canary_accounts,
        assigned_accounts: activation.assigned_accounts,
        unresolved_source_accounts: unresolved_source_accounts(connection).await?,
        formation_backfill_generation: backfill.refresh_generation,
        formation_backfill_complete: backfill.complete,
        formation_backfill_rows_scanned: backfill.rows_scanned,
        formation_backfill_rows_inserted: backfill.rows_inserted,
        formation_backfill_rows_reopened: backfill.rows_reopened,
        finalization_claim_drain_complete: drain.complete,
        finalization_claims_scanned: drain.claims_scanned,
        finalization_claims_revoked: drain.claims_revoked,
        contract_sha256: sha256_label(&activation_contract_digest()),
        catalog_sha256: sha256_label(&catalog_digest(connection).await?),
        base_finalization_receipt_sha256: sha256_label(&base),
        receipt_sha256: activation.receipt_sha256,
    })
}

impl PostgresPersistence {
    pub(crate) async fn install_memory_reconciliation_activation_schema(
        &self,
    ) -> Result<MemoryReconciliationActivationReleaseResult> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(RELEASE_LOCK)
            .execute(&mut *transaction)
            .await?;
        let marker = schema_marker(&mut transaction).await?;
        let existed = activation_contract_exists(&mut transaction).await?;
        if existed {
            let (_, state) = verify_activation_and_base_release(&mut transaction).await?;
            transaction.commit().await?;
            let mut connection = self.pool().acquire().await?;
            return release_result(&mut connection, release_status(state.phase)).await;
        }
        if marker != (EXPECTED_SCHEMA_VERSION, Some(EXPECTED_SCHEMA_VERSION)) {
            return Err(EnclaveError::Config(
                "v27 activation install requires finalized 26/26 schema".into(),
            ));
        }
        let base = verify_finalized_v26_release(&mut transaction, false).await?;
        ensure_pristine_reserved_catalog_namespace(&mut transaction).await?;
        sqlx::raw_sql(INSTALL_SQL)
            .execute(&mut *transaction)
            .await?;
        let contract = activation_contract_digest();
        let catalog = catalog_digest(&mut transaction).await?;
        sqlx::query(
            "INSERT INTO persistence_feature_activation_contracts( \
                 feature,protocol_version,base_schema_version,target_schema_version, \
                 contract_sha256,catalog_sha256,base_finalization_receipt_sha256) \
             VALUES($1,1,$2,$3,$4,$5,$6)",
        )
        .bind(FEATURE)
        .bind(EXPECTED_SCHEMA_VERSION)
        .bind(MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION)
        .bind(&contract)
        .bind(&catalog)
        .bind(&base)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO persistence_feature_activation_events( \
                 feature,generation,previous_phase,phase,rollout_basis_points,rollout_seed) \
             VALUES($1,0,'preactive','installed',0,$2)",
        )
        .bind(FEATURE)
        .bind(format!("sha256:{}", "0".repeat(64)))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO persistence_feature_activation_backfills( \
                 feature,backfill_name,refresh_generation) VALUES($1,$2,0)",
        )
        .bind(FEATURE)
        .bind(FORMATION_BACKFILL_NAME)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let mut connection = self.pool().acquire().await?;
        release_result(
            &mut connection,
            MemoryReconciliationActivationReleaseStatus::Installed,
        )
        .await
    }

    /// Advances at most one bounded keyset batch. Operators repeat this
    /// resumable step until `formation_backfill_complete` is true; install and
    /// signed transitions never scan the populated capture corpus inline.
    pub(crate) async fn advance_memory_reconciliation_activation_backfill(
        &self,
    ) -> Result<MemoryReconciliationActivationReleaseResult> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(RELEASE_LOCK)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT feature FROM persistence_feature_activation_contracts \
             WHERE feature=$1 FOR KEY SHARE",
        )
        .bind(FEATURE)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Config("v27 activation is not installed".into()))?;
        let (_, state) = verify_activation_and_base_release(&mut transaction).await?;
        let expected_generation = match state.phase {
            MemoryReconciliationActivationPhase::Installed => 0,
            MemoryReconciliationActivationPhase::Draining => state.generation,
            MemoryReconciliationActivationPhase::Active
            | MemoryReconciliationActivationPhase::Paused => {
                require_formation_backfill_complete(&mut transaction, None).await?;
                require_finalization_claim_drain_complete(&mut transaction, None).await?;
                transaction.commit().await?;
                let mut connection = self.pool().acquire().await?;
                return release_result(
                    &mut connection,
                    MemoryReconciliationActivationReleaseStatus::BackfillComplete,
                )
                .await;
            }
            MemoryReconciliationActivationPhase::Preactive => unreachable!(),
        };
        let formation_complete = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM persistence_feature_activation_backfills \
              WHERE feature=$1 AND backfill_name=$2 AND refresh_generation=$3 \
                AND complete=true)",
        )
        .bind(FEATURE)
        .bind(FORMATION_BACKFILL_NAME)
        .bind(expected_generation)
        .fetch_one(&mut *transaction)
        .await?;
        let complete = if !formation_complete {
            let formation_now_complete =
                advance_formation_backfill_batch(&mut transaction, expected_generation).await?;
            formation_now_complete && state.phase == MemoryReconciliationActivationPhase::Installed
        } else if state.phase == MemoryReconciliationActivationPhase::Draining {
            advance_finalization_claim_drain_batch(&mut transaction, state.generation).await?
        } else {
            true
        };
        transaction.commit().await?;
        let mut connection = self.pool().acquire().await?;
        release_result(
            &mut connection,
            if complete {
                MemoryReconciliationActivationReleaseStatus::BackfillComplete
            } else {
                MemoryReconciliationActivationReleaseStatus::BackfillInProgress
            },
        )
        .await
    }

    pub(crate) async fn transition_memory_reconciliation_activation(
        &self,
        authorization: &VerifiedMemoryReconciliationActivationReceipt,
    ) -> Result<MemoryReconciliationActivationReleaseResult> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(RELEASE_LOCK)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT feature FROM persistence_feature_activation_contracts \
             WHERE feature=$1 FOR UPDATE",
        )
        .bind(FEATURE)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Config("v27 activation is not installed".into()))?;

        let (base, current) = verify_activation_and_base_release(&mut transaction).await?;
        let signed = authorization.receipt();
        let requested = phase(&signed.requested_phase)?;
        let expected_contract = activation_contract_digest();
        let expected_catalog = catalog_digest(&mut transaction).await?;
        if signed.generation != current.generation + 1
            || signed.previous_phase != current.phase.as_str()
            || signed.activation_contract_sha256 != sha256_label(&expected_contract)
            || signed.activation_catalog_sha256 != sha256_label(&expected_catalog)
            || signed.base_finalization_receipt_sha256 != sha256_label(&base)
        {
            return Err(EnclaveError::Conflict(
                "signed activation generation or contract is stale".into(),
            ));
        }
        let must_preserve_scope_and_producer =
            transition_preserves_activation_identity(current.phase, requested);
        if must_preserve_scope_and_producer
            && (signed.rollout_basis_points != current.rollout_basis_points
                || signed.rollout_seed != current.rollout_seed
                || signed.explicit_canary_account_ids != current.explicit_canary_account_ids
                || current.candidate_fleet_image_digest.as_deref()
                    != Some(signed.candidate_fleet_image_digest.as_str())
                || current.reconciliation_producer_contract_sha256.as_deref()
                    != Some(signed.reconciliation_producer_contract_sha256.as_str())
                || current.reconciliation_model.as_deref()
                    != Some(signed.reconciliation_model.as_str())
                || current.vertex_location.as_deref() != Some(signed.vertex_location.as_str()))
        {
            return Err(EnclaveError::Conflict(
                "active and paused transitions must preserve signed fleet, scope, and producer"
                    .into(),
            ));
        }
        if current.phase == MemoryReconciliationActivationPhase::Paused
            && requested == MemoryReconciliationActivationPhase::Draining
            && signed.rollout_basis_points != 10_000
            && (current.rollout_basis_points == 10_000
                || current
                    .explicit_canary_account_ids
                    .iter()
                    .any(|account_id| !signed.explicit_canary_account_ids.contains(account_id)))
        {
            return Err(EnclaveError::Conflict(
                "a later draining scope cannot remove previously activated accounts".into(),
            ));
        }
        let fresh = sqlx::query_scalar::<_, bool>(
            "SELECT to_timestamp($1::double precision/1000.0)<=clock_timestamp() \
                AND to_timestamp($2::double precision/1000.0) \
                    >=clock_timestamp()+CASE WHEN $3 THEN interval '0 seconds' \
                                             ELSE interval '60 seconds' END",
        )
        .bind(authorization.observed_at())
        .bind(authorization.expires_at())
        .bind(requested == MemoryReconciliationActivationPhase::Paused)
        .fetch_one(&mut *transaction)
        .await?;
        if !fresh {
            return Err(EnclaveError::Config(
                "activation receipt is not fresh according to PostgreSQL time".into(),
            ));
        }
        match requested {
            MemoryReconciliationActivationPhase::Draining => {
                require_paged_or_complete_episode_deletions(&mut transaction, current.phase)
                    .await?;
                if current.phase == MemoryReconciliationActivationPhase::Installed {
                    require_formation_backfill_complete(&mut transaction, Some(0)).await?;
                } else {
                    require_formation_backfill_complete(&mut transaction, None).await?;
                    require_finalization_claim_drain_complete(&mut transaction, None).await?;
                }
            }
            MemoryReconciliationActivationPhase::Active
                if current.phase == MemoryReconciliationActivationPhase::Draining =>
            {
                require_formation_backfill_complete(&mut transaction, Some(current.generation))
                    .await?;
                require_finalization_claim_drain_complete(
                    &mut transaction,
                    Some(current.generation),
                )
                .await?;
            }
            MemoryReconciliationActivationPhase::Active
            | MemoryReconciliationActivationPhase::Paused => {
                require_formation_backfill_complete(&mut transaction, None).await?;
                require_finalization_claim_drain_complete(&mut transaction, None).await?;
            }
            MemoryReconciliationActivationPhase::Installed
            | MemoryReconciliationActivationPhase::Preactive => unreachable!(),
        }
        if requested == MemoryReconciliationActivationPhase::Active {
            require_zero_scoped_draft_claims(&mut transaction, &current).await?;
        }
        let receipt_digest = Sha256::digest(authorization.canonical_bytes()).to_vec();
        let receipt_json = std::str::from_utf8(authorization.canonical_bytes())
            .map_err(|_| EnclaveError::Config("activation receipt is not UTF-8".into()))?;
        sqlx::query(
            "INSERT INTO persistence_feature_activation_events( \
                 feature,generation,previous_phase,phase,rollout_basis_points,rollout_seed, \
                 explicit_canary_account_ids,candidate_fleet_image_digest, \
                 reconciliation_producer_contract_sha256,reconciliation_model,vertex_location, \
                 receipt,receipt_sha256,receipt_signature,receipt_key_sha256) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15)",
        )
        .bind(FEATURE)
        .bind(signed.generation)
        .bind(&signed.previous_phase)
        .bind(&signed.requested_phase)
        .bind(signed.rollout_basis_points)
        .bind(&signed.rollout_seed)
        .bind(&signed.explicit_canary_account_ids)
        .bind(&signed.candidate_fleet_image_digest)
        .bind(&signed.reconciliation_producer_contract_sha256)
        .bind(&signed.reconciliation_model)
        .bind(&signed.vertex_location)
        .bind(receipt_json)
        .bind(&receipt_digest)
        .bind(authorization.signature_bytes())
        .bind(authorization.key_sha256())
        .execute(&mut *transaction)
        .await?;

        match requested {
            MemoryReconciliationActivationPhase::Draining => {
                install_activation_guards(&mut transaction).await?;
                insert_scope_assignments(
                    &mut transaction,
                    signed.generation,
                    &signed.explicit_canary_account_ids,
                )
                .await?;
                // The signed draining event proves predecessor_instances=0.
                // Re-scan every source key after that proof to repair any last
                // dark-fleet write which v0.9.16 could not mark dirty.
                reset_formation_backfill(&mut transaction, signed.generation).await?;
                initialize_finalization_claim_drain(&mut transaction, signed.generation).await?;
            }
            MemoryReconciliationActivationPhase::Active => {
                insert_scope_assignments(
                    &mut transaction,
                    signed.generation,
                    &signed.explicit_canary_account_ids,
                )
                .await?;
                install_activation_guards(&mut transaction).await?;
                let changed = sqlx::query(
                    "UPDATE persistence_schema SET version=$1,expanded_through_version=$1, \
                         updated_at=clock_timestamp() WHERE singleton=true AND ( \
                           (version=$2 AND expanded_through_version=$2) \
                           OR (version=$1 AND expanded_through_version=$1))",
                )
                .bind(MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION)
                .bind(EXPECTED_SCHEMA_VERSION)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if changed != 1 {
                    return Err(EnclaveError::Conflict(
                        "schema marker changed before activation".into(),
                    ));
                }
            }
            MemoryReconciliationActivationPhase::Paused => {
                install_activation_guards(&mut transaction).await?;
            }
            MemoryReconciliationActivationPhase::Installed
            | MemoryReconciliationActivationPhase::Preactive => unreachable!(),
        }
        transaction.commit().await?;
        let mut connection = self.pool().acquire().await?;
        release_result(&mut connection, release_status(requested)).await
    }
}

#[async_trait]
impl MemoryReconciliationActivationRepository for PostgresPersistence {
    async fn memory_reconciliation_activation_status(
        &self,
    ) -> Result<MemoryReconciliationActivationStatus> {
        let mut connection = self.pool().acquire().await?;
        verified_status(&mut connection).await
    }
}

#[cfg(test)]
#[test]
fn candidate_fleet_identity_changes_only_on_a_fresh_draining_cycle() {
    use MemoryReconciliationActivationPhase::{Active, Draining, Installed, Paused};

    assert!(!transition_preserves_activation_identity(
        Installed, Draining
    ));
    assert!(transition_preserves_activation_identity(Draining, Active));
    assert!(transition_preserves_activation_identity(Active, Paused));
    assert!(transition_preserves_activation_identity(Paused, Active));
    assert!(!transition_preserves_activation_identity(Paused, Draining));
}

#[cfg(test)]
#[test]
fn nested_activation_contract_future_stays_heap_pinned() {
    let source = include_str!("activation.rs");
    assert!(source.contains("Box::pin(test_real_pg_activation_contract_inner(&persistence)).await"));
}

#[cfg(test)]
struct TestFleetEvidence<'a> {
    outage_pause: bool,
    candidate_fleet_image_digest: &'a str,
}

#[cfg(test)]
async fn test_transition_authorization(
    persistence: &PostgresPersistence,
    generation: i64,
    previous_phase: &str,
    requested_phase: &str,
    rollout_basis_points: i64,
    explicit_canary_account_ids: Vec<String>,
    outage_pause: bool,
) -> Result<VerifiedMemoryReconciliationActivationReceipt> {
    let candidate_fleet_image_digest = format!("sha256:{}", "b".repeat(64));
    test_transition_authorization_with_candidate_digest(
        persistence,
        generation,
        previous_phase,
        requested_phase,
        rollout_basis_points,
        explicit_canary_account_ids,
        TestFleetEvidence {
            outage_pause,
            candidate_fleet_image_digest: &candidate_fleet_image_digest,
        },
    )
    .await
}

#[cfg(test)]
async fn test_transition_authorization_with_candidate_digest(
    persistence: &PostgresPersistence,
    generation: i64,
    previous_phase: &str,
    requested_phase: &str,
    rollout_basis_points: i64,
    explicit_canary_account_ids: Vec<String>,
    fleet_evidence: TestFleetEvidence<'_>,
) -> Result<VerifiedMemoryReconciliationActivationReceipt> {
    let mut connection = persistence.pool().acquire().await?;
    let (base, _) = verify_activation_and_base_release(&mut connection).await?;
    let producer_contract = crate::cp::reconciler::producer_contract_commitment(
        "gemini-reconciliation-v1",
        "us-central1",
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock must follow the Unix epoch")
        .as_millis() as i64;
    let receipt = super::schema_release::MemoryReconciliationActivationReceipt {
        contract: "kioku.postgresql.memory-reconciliation-activation".into(),
        contract_version: 1,
        generation,
        previous_phase: previous_phase.into(),
        requested_phase: requested_phase.into(),
        base_schema_version: EXPECTED_SCHEMA_VERSION,
        target_schema_version: MEMORY_RECONCILIATION_ACTIVATION_SCHEMA_VERSION,
        activation_contract_sha256: sha256_label(&activation_contract_digest()),
        activation_catalog_sha256: sha256_label(&catalog_digest(&mut connection).await?),
        base_finalization_receipt_sha256: sha256_label(&base),
        reconciliation_producer_contract_sha256: sha256_label(&producer_contract),
        reconciliation_model: "gemini-reconciliation-v1".into(),
        vertex_location: "us-central1".into(),
        rollout_basis_points,
        rollout_seed: format!("sha256:{}", "a".repeat(64)),
        explicit_canary_account_ids,
        candidate_fleet_image_digest: fleet_evidence.candidate_fleet_image_digest.into(),
        fleet_evidence_sha256: format!("sha256:{}", "c".repeat(64)),
        client_evidence_sha256: format!("sha256:{}", "d".repeat(64)),
        observed_at: isotime::format_epoch_millis(now - 1_000),
        expires_at: isotime::format_epoch_millis(now + 10 * 60 * 1_000),
        candidate_instances: if fleet_evidence.outage_pause { 0 } else { 2 },
        predecessor_instances: if fleet_evidence.outage_pause { 3 } else { 0 },
        unavailable_instances: if fleet_evidence.outage_pause { 4 } else { 0 },
        web_client_ready: !fleet_evidence.outage_pause,
        macos_client_ready: !fleet_evidence.outage_pause,
        ios_client_ready: !fleet_evidence.outage_pause,
    };
    super::schema_release::test_verify_activation_receipt(receipt)
}

#[cfg(test)]
async fn test_insert_transition_event_directly(
    persistence: &PostgresPersistence,
    authorization: &VerifiedMemoryReconciliationActivationReceipt,
) -> Result<()> {
    let signed = authorization.receipt();
    let receipt_json = std::str::from_utf8(authorization.canonical_bytes())
        .map_err(|_| EnclaveError::Config("test activation receipt is not UTF-8".into()))?;
    sqlx::query(
        "INSERT INTO persistence_feature_activation_events( \
             feature,generation,previous_phase,phase,rollout_basis_points,rollout_seed, \
             explicit_canary_account_ids,candidate_fleet_image_digest, \
             reconciliation_producer_contract_sha256,reconciliation_model,vertex_location, \
             receipt,receipt_sha256,receipt_signature,receipt_key_sha256) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15)",
    )
    .bind(FEATURE)
    .bind(signed.generation)
    .bind(&signed.previous_phase)
    .bind(&signed.requested_phase)
    .bind(signed.rollout_basis_points)
    .bind(&signed.rollout_seed)
    .bind(&signed.explicit_canary_account_ids)
    .bind(&signed.candidate_fleet_image_digest)
    .bind(&signed.reconciliation_producer_contract_sha256)
    .bind(&signed.reconciliation_model)
    .bind(&signed.vertex_location)
    .bind(receipt_json)
    .bind(Sha256::digest(authorization.canonical_bytes()).to_vec())
    .bind(authorization.signature_bytes())
    .bind(authorization.key_sha256())
    .execute(persistence.pool())
    .await?;
    Ok(())
}

#[cfg(test)]
async fn test_advance_activation_until_complete(
    persistence: &PostgresPersistence,
    require_claim_drain: bool,
) -> Result<()> {
    for _ in 0..128 {
        let result = persistence
            .advance_memory_reconciliation_activation_backfill()
            .await?;
        if result.formation_backfill_complete
            && (!require_claim_drain || result.finalization_claim_drain_complete)
        {
            return Ok(());
        }
    }
    Err(EnclaveError::Store(
        "test activation backfill did not converge within its bounded budget".into(),
    ))
}

#[cfg(test)]
async fn test_real_pg_seal_and_tombstone_contract(persistence: &PostgresPersistence) -> Result<()> {
    use crate::persistence::{CaptureRepository as _, EpisodeDeletionRepository as _};

    const GAP_ACCOUNT: &str = "activation-gap-contract";
    const LIFECYCLE_ACCOUNT: &str = "activation-seal-contract";
    const SESSION_CASCADE_ACCOUNT: &str = "activation-session-cascade";
    let late_reference: crate::cp::media::CaptureEventManifest = serde_json::from_value(
        serde_json::json!({
            "schema_version": 2,
            "event_id": "seal-event-1",
            "device_id": "seal-device",
            "install_id": "seal-install",
            "capture_session_id": "seal-session",
            "stream_id": "seal-stream",
            "stream_kind": "mac_screen",
            "sequence": 1,
            "source_wall_at": "2026-08-31T09:00:01.000Z",
            "source_monotonic_ns": 1_u64,
            "started_at": "2026-08-31T09:00:01.000Z",
            "ended_at": "2026-08-31T09:00:02.000Z",
            "timezone_id": "UTC",
            "utc_offset_minutes": 0,
            "clock_uncertainty_ms": 0,
            "media_disposition": "reference",
            "reference": {
                "canonical_event_id": "seal-event-0",
                "canonical_asset_id": "seal-asset-0",
                "canonical_media_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "perceptual_hash": "0123456789abcdef",
                "hamming_distance": 1,
                "pixel_change_ratio": 0.001,
                "context_fingerprint": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "dedupe_version": 1
            },
            "context": {
                "capture_status": "stable"
            }
        }),
    )?;
    late_reference.validate()?;
    let late_reference_digest = crate::cp::media::manifest_digest(&late_reference)?;
    sqlx::raw_sql(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) VALUES \
             ('activation-gap-contract','activation-gap@example.com','google','activation-gap'), \
             ('activation-seal-contract','activation-seal@example.com','google','activation-seal'); \
         INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES \
             ('activation-gap-contract','gap-session','gap-device','gap-install', \
              '2026-08-31T08:00:00Z','2026-08-31T08:00:03Z','2026-08-31T08:00:03Z',2), \
             ('activation-seal-contract','seal-session','seal-device','seal-install', \
              '2026-08-31T09:00:00Z','2026-08-31T09:00:01Z','2026-08-31T09:00:01Z',2); \
         INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind, \
             committed_through_sequence,sealed_sequence) \
         VALUES \
             ('activation-gap-contract','gap-stream','gap-session','gap-device','mac_screen',2,2), \
             ('activation-seal-contract','seal-stream','seal-session','seal-device','mac_screen',0,0); \
         INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
         VALUES \
             ('activation-gap-contract','gap-event-0','gap-device','gap-install','gap-session', \
              'gap-stream','mac_screen',0,'2026-08-31T08:00:00Z','0', \
              '2026-08-31T08:00:00Z','2026-08-31T08:00:01Z','UTC',0,0,'gap-asset-0', \
              repeat('a',64),'canonical'), \
             ('activation-gap-contract','gap-event-2','gap-device','gap-install','gap-session', \
              'gap-stream','mac_screen',2,'2026-08-31T08:00:02Z','2', \
              '2026-08-31T08:00:02Z','2026-08-31T08:00:03Z','UTC',0,0,'gap-asset-2', \
              repeat('b',64),'canonical'), \
             ('activation-seal-contract','seal-event-0','seal-device','seal-install','seal-session', \
              'seal-stream','mac_screen',0,'2026-08-31T09:00:00Z','0', \
              '2026-08-31T09:00:00Z','2026-08-31T09:00:01Z','UTC',0,0,'seal-asset-0', \
              repeat('c',64),'canonical'); \
         INSERT INTO capture_formation_receipts( \
             account_id,capture_session_id,source_revision,finish_requested_at, \
             finish_request_provenance) \
         VALUES \
             ('activation-gap-contract','gap-session',1,clock_timestamp(),'finish_endpoint_v1'), \
             ('activation-seal-contract','seal-session',1,clock_timestamp(),'finish_endpoint_v1');",
    )
    .execute(persistence.pool())
    .await?;

    assert!(sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance) \
         VALUES($1,'gap-session',1,1,'seal', \
                capture_formation_stream_maxima_sha256($1,'gap-session'),'quiet_contiguous_v1')",
    )
    .bind(GAP_ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());

    sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance) \
         VALUES($1,'seal-session',1,1,'seal', \
                capture_formation_stream_maxima_sha256($1,'seal-session'),'quiet_contiguous_v1')",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE capture_formation_receipts \
            SET seal_generation=1,seal_finalized_at=clock_timestamp(), \
                seal_finalization_provenance='quiet_contiguous_v1' \
          WHERE account_id=$1 AND capture_session_id='seal-session'",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,context_json, \
             media_disposition,canonical_event_id,canonical_asset_id,canonical_media_sha256, \
             perceptual_hash,hamming_distance,pixel_change_ratio,context_fingerprint,dedupe_version) \
         VALUES($1,$2,$3,$4,$5,$6,'mac_screen',1,'2026-08-31T09:00:01Z','1', \
                '2026-08-31T09:00:01Z','2026-08-31T09:00:02Z','UTC',0,0, \
                'reference-seal-event-1',$7,$8::jsonb,'reference','seal-event-0','seal-asset-0', \
                repeat('c',64),'0123456789abcdef',1,0.001,repeat('d',64),1)",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .bind(&late_reference.event_id)
    .bind(&late_reference.device_id)
    .bind(&late_reference.install_id)
    .bind(&late_reference.capture_session_id)
    .bind(&late_reference.stream_id)
    .bind(&late_reference_digest)
    .bind(serde_json::to_string(&late_reference.context)?)
    .execute(persistence.pool())
    .await?;
    sqlx::raw_sql(
        "UPDATE capture_streams SET committed_through_sequence=1 \
          WHERE account_id='activation-seal-contract' AND id='seal-stream'; \
         UPDATE capture_formation_receipts SET source_revision=2,updated_at=clock_timestamp() \
          WHERE account_id='activation-seal-contract' AND capture_session_id='seal-session';",
    )
    .execute(persistence.pool())
    .await?;
    assert!(sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance,trigger_event_id) \
         VALUES($1,'seal-session',1,2,'reopen', \
                capture_formation_stream_maxima_sha256($1,'seal-session'), \
                'late_source_reopen_v1','missing-trigger')",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());
    sqlx::query(
        "INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance,trigger_event_id) \
         VALUES($1,'seal-session',1,2,'reopen', \
                capture_formation_stream_maxima_sha256($1,'seal-session'), \
                'late_source_reopen_v1','seal-event-1')",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::raw_sql(
        "UPDATE capture_streams SET sealed_sequence=NULL \
          WHERE account_id='activation-seal-contract' AND id='seal-stream'; \
         UPDATE capture_formation_receipts \
            SET seal_finalized_at=NULL,seal_finalization_provenance=NULL \
          WHERE account_id='activation-seal-contract' AND capture_session_id='seal-session'; \
         UPDATE capture_streams SET sealed_sequence=1 \
          WHERE account_id='activation-seal-contract' AND id='seal-stream'; \
         INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance) \
         VALUES('activation-seal-contract','seal-session',2,2,'seal', \
                capture_formation_stream_maxima_sha256( \
                    'activation-seal-contract','seal-session'),'quiet_contiguous_v1'); \
         UPDATE capture_formation_receipts \
            SET seal_generation=2,seal_finalized_at=clock_timestamp(), \
                seal_finalization_provenance='quiet_contiguous_v1' \
          WHERE account_id='activation-seal-contract' AND capture_session_id='seal-session'; \
         INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary,updated_at) \
         VALUES('activation-seal-contract',10,'2026-08-31T09:00:01Z', \
                '2026-08-31T09:00:02Z','work','Deletion audit','Delete late source',clock_timestamp()); \
         INSERT INTO screenshots(account_id,id,captured_at,source_key) \
         VALUES('activation-seal-contract',10,'2026-08-31T09:00:01Z','cloud-v2:seal-event-1'); \
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
         VALUES('activation-seal-contract',10,'screenshot',10);",
    )
    .execute(persistence.pool())
    .await?;
    use crate::persistence::EpisodeDeletionStart;
    sqlx::query(
        "INSERT INTO summary_window_claims( \
             account_id,window_from,window_to,state,claim_token,claim_until) \
         VALUES($1,'2026-08-31T08:00:00Z','2026-08-31T10:00:00Z', \
                'processing','summary-provider-fence',clock_timestamp()+interval '15 minutes')",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .begin_episode_deletion(LIFECYCLE_ACCOUNT, 10)
        .await
        .is_err());
    sqlx::query("DELETE FROM summary_window_claims WHERE account_id=$1")
        .bind(LIFECYCLE_ACCOUNT)
        .execute(persistence.pool())
        .await?;
    sqlx::query(
        "UPDATE episodes SET finalization_claim_token='finalizer-provider-fence', \
                finalization_claim_until=clock_timestamp()+interval '15 minutes' \
          WHERE account_id=$1 AND id=10",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .begin_episode_deletion(LIFECYCLE_ACCOUNT, 10)
        .await
        .is_err());
    sqlx::query(
        "UPDATE episodes SET finalization_claim_token=NULL,finalization_claim_until=NULL \
          WHERE account_id=$1 AND id=10",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE capture_formation_receipts \
            SET state='processing',claimed_revision=source_revision, \
                claim_token='formation-provider-fence', \
                claim_until=clock_timestamp()+interval '15 minutes', \
                claimed_source_fingerprint=decode(repeat('e',64),'hex') \
          WHERE account_id=$1 AND capture_session_id='seal-session'",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .begin_episode_deletion(LIFECYCLE_ACCOUNT, 10)
        .await
        .is_err());
    sqlx::query(
        "UPDATE capture_formation_receipts \
            SET state='pending',claimed_revision=NULL,claim_token=NULL,claim_until=NULL, \
                claimed_source_fingerprint=NULL \
          WHERE account_id=$1 AND capture_session_id='seal-session'",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    let deletion_plan = match persistence
        .begin_episode_deletion(LIFECYCLE_ACCOUNT, 10)
        .await?
    {
        EpisodeDeletionStart::Pending(plan) => plan,
        other => {
            return Err(EnclaveError::Store(format!(
                "activation deletion fixture expected a pending plan, got {other:?}"
            )));
        }
    };
    sqlx::query(
        "INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary,updated_at) \
         VALUES($1,11,'2026-08-31T09:00:01Z','2026-08-31T09:00:02Z', \
                'work','Late owner','Must be refused',clock_timestamp())",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert!(sqlx::query(
        "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
         VALUES($1,11,'screenshot',10)",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());
    persistence
        .complete_episode_deletion(LIFECYCLE_ACCOUNT, &deletion_plan)
        .await?;
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT capture_formation_stream_accepted_max($1,'seal-stream'), \
                    capture_formation_stream_contiguous_through($1,'seal-stream'), \
                    count(*)::bigint FROM capture_formation_seal_events \
              WHERE account_id=$1 AND capture_session_id='seal-session'",
        )
        .bind(LIFECYCLE_ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        (1, 1, 4),
    );
    let replay = persistence
        .commit_event(crate::persistence::CaptureCommit {
            account_id: LIFECYCLE_ACCOUNT.into(),
            manifest: late_reference.clone(),
            manifest_digest: late_reference_digest.clone(),
            object_key: None,
            object_generation: None,
            upload_token: None,
            media_authority: None,
            committed_at: "2026-08-31T09:10:00.000Z".into(),
        })
        .await?;
    assert!(replay.duplicate);
    assert_eq!(replay.committed_through_sequence, 1);
    let batch_replay = persistence
        .commit_reference_batch(crate::persistence::ReferenceBatchCommit {
            account_id: LIFECYCLE_ACCOUNT.into(),
            events: vec![late_reference.clone()],
            manifest_digests: vec![late_reference_digest.clone()],
            committed_at: "2026-08-31T09:10:01.000Z".into(),
        })
        .await?;
    assert_eq!(batch_replay.new_count, 0);
    assert_eq!(batch_replay.duplicate_count, 1);
    assert_eq!(batch_replay.committed_through_sequence, 1);

    let mismatched_digest = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    assert!(persistence
        .commit_event(crate::persistence::CaptureCommit {
            account_id: LIFECYCLE_ACCOUNT.into(),
            manifest: late_reference.clone(),
            manifest_digest: mismatched_digest.into(),
            object_key: None,
            object_generation: None,
            upload_token: None,
            media_authority: None,
            committed_at: "2026-08-31T09:10:02.000Z".into(),
        })
        .await
        .is_err());
    assert!(persistence
        .commit_reference_batch(crate::persistence::ReferenceBatchCommit {
            account_id: LIFECYCLE_ACCOUNT.into(),
            events: vec![late_reference.clone()],
            manifest_digests: vec![mismatched_digest.into()],
            committed_at: "2026-08-31T09:10:03.000Z".into(),
        })
        .await
        .is_err());

    let mut coordinate_reuse = late_reference.clone();
    coordinate_reuse.event_id = "seal-event-replacement".into();
    let coordinate_reuse_digest = crate::cp::media::manifest_digest(&coordinate_reuse)?;
    assert!(persistence
        .commit_event(crate::persistence::CaptureCommit {
            account_id: LIFECYCLE_ACCOUNT.into(),
            manifest: coordinate_reuse.clone(),
            manifest_digest: coordinate_reuse_digest.clone(),
            object_key: None,
            object_generation: None,
            upload_token: None,
            media_authority: None,
            committed_at: "2026-08-31T09:10:04.000Z".into(),
        })
        .await
        .is_err());
    assert!(persistence
        .commit_reference_batch(crate::persistence::ReferenceBatchCommit {
            account_id: LIFECYCLE_ACCOUNT.into(),
            events: vec![coordinate_reuse],
            manifest_digests: vec![coordinate_reuse_digest],
            committed_at: "2026-08-31T09:10:05.000Z".into(),
        })
        .await
        .is_err());
    assert!(sqlx::query(
        "DELETE FROM capture_formation_seal_events \
          WHERE account_id=$1 AND capture_session_id='seal-session' AND event_kind='reopen'",
    )
    .bind(LIFECYCLE_ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());
    assert!(sqlx::raw_sql(
        "INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
         VALUES('activation-seal-contract','seal-event-1','seal-device','seal-install', \
                'seal-session','seal-stream','mac_screen',1,'2026-08-31T09:00:01Z','1', \
                '2026-08-31T09:00:01Z','2026-08-31T09:00:02Z','UTC',0,0,'seal-asset-replay', \
                repeat('d',64),'canonical')",
    )
    .execute(persistence.pool())
    .await
    .is_err());
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, String)>(
            "SELECT source_revision,seal_generation,seal_finalization_provenance \
               FROM capture_formation_receipts \
              WHERE account_id=$1 AND capture_session_id='seal-session'",
        )
        .bind(LIFECYCLE_ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        (3, 3, "topology_rebind_v1".into()),
    );
    sqlx::raw_sql(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES('activation-session-cascade','activation-session-cascade@example.com', \
                'google','activation-session-cascade'); \
         INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES('activation-session-cascade','cascade-session','cascade-device','cascade-install', \
                '2026-08-31T11:00:00Z','2026-08-31T11:00:01Z','2026-08-31T11:00:01Z',2); \
         INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind, \
             committed_through_sequence,sealed_sequence) \
         VALUES('activation-session-cascade','cascade-stream','cascade-session', \
                'cascade-device','mac_screen',0,0); \
         INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
         VALUES('activation-session-cascade','cascade-event-0','cascade-device','cascade-install', \
                'cascade-session','cascade-stream','mac_screen',0,'2026-08-31T11:00:00Z','0', \
                '2026-08-31T11:00:00Z','2026-08-31T11:00:01Z','UTC',0,0, \
                'cascade-asset-0',repeat('f',64),'canonical'); \
         INSERT INTO capture_formation_receipts( \
             account_id,capture_session_id,source_revision,finish_requested_at, \
             finish_request_provenance) \
         VALUES('activation-session-cascade','cascade-session',1,clock_timestamp(), \
                'finish_endpoint_v1'); \
         INSERT INTO capture_formation_seal_events( \
             account_id,capture_session_id,seal_generation,source_revision,event_kind, \
             stream_maxima_sha256,provenance) \
         VALUES('activation-session-cascade','cascade-session',1,1,'seal', \
                capture_formation_stream_maxima_sha256( \
                    'activation-session-cascade','cascade-session'),'quiet_contiguous_v1'); \
         UPDATE capture_formation_receipts \
            SET seal_generation=1,seal_finalized_at=clock_timestamp(), \
                seal_finalization_provenance='quiet_contiguous_v1' \
          WHERE account_id='activation-session-cascade' \
            AND capture_session_id='cascade-session'; \
         INSERT INTO episode_deletions( \
             account_id,episode_id,state,purge,media_object_keys,utterance_ids, \
             screenshot_ids,segment_ids,orphan_event_ids) \
         VALUES('activation-session-cascade',20,'pending','{}'::jsonb,'[]'::jsonb, \
                '[]'::jsonb,'[]'::jsonb,'[]'::jsonb,'[\"cascade-event-0\"]'::jsonb); \
         INSERT INTO capture_formation_deleted_sequences( \
             account_id,capture_session_id,stream_id,sequence,event_id, \
             original_manifest_digest,deletion_episode_id,provenance) \
         VALUES('activation-session-cascade','cascade-session','cascade-stream',0, \
                'cascade-event-0',repeat('f',64),20,'episode_deletion_v1'); \
         DELETE FROM capture_sessions \
          WHERE account_id='activation-session-cascade' AND id='cascade-session';",
    )
    .execute(persistence.pool())
    .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT \
                (SELECT count(*) FROM capture_events WHERE account_id=$1) + \
                (SELECT count(*) FROM capture_formation_deleted_sequences WHERE account_id=$1) + \
                (SELECT count(*) FROM capture_formation_receipts WHERE account_id=$1) + \
                (SELECT count(*) FROM capture_formation_seal_events WHERE account_id=$1)",
        )
        .bind(SESSION_CASCADE_ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        0,
    );
    sqlx::query("DELETE FROM accounts WHERE id=ANY($1::text[])")
        .bind(vec![
            GAP_ACCOUNT,
            LIFECYCLE_ACCOUNT,
            SESSION_CASCADE_ACCOUNT,
        ])
        .execute(persistence.pool())
        .await?;
    Ok(())
}

#[cfg(test)]
async fn wait_for_exclusive_release_lock(persistence: &PostgresPersistence) -> Result<()> {
    let mut observer = persistence.pool().acquire().await?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let acquired: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_lock_shared(hashtextextended($1,0))")
                    .bind(RELEASE_LOCK)
                    .fetch_one(&mut *observer)
                    .await?;
            if !acquired {
                return Ok::<(), EnclaveError>(());
            }
            let released: bool =
                sqlx::query_scalar("SELECT pg_advisory_unlock_shared(hashtextextended($1,0))")
                    .bind(RELEASE_LOCK)
                    .fetch_one(&mut *observer)
                    .await?;
            if !released {
                return Err(EnclaveError::Store(
                    "activation release-lock observer lost its shared lock".into(),
                ));
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| EnclaveError::Store("activation installer did not take its release lock".into()))?
}

#[cfg(test)]
async fn test_real_pg_v27_install_refuses_pending_deletion(
    persistence: &PostgresPersistence,
) -> Result<()> {
    const ACCOUNT: &str = "activation-install-pending-deletion";
    for (description, setup, cleanup) in [
        (
            "relation",
            "CREATE TABLE persistence_feature_unreviewed_preinstall(id bigint)",
            "DROP TABLE persistence_feature_unreviewed_preinstall",
        ),
        (
            "function",
            "CREATE FUNCTION persistence_feature_unreviewed_preinstall() \
             RETURNS bigint LANGUAGE sql IMMUTABLE AS 'SELECT 1::bigint'",
            "DROP FUNCTION persistence_feature_unreviewed_preinstall()",
        ),
        (
            "reviewed-function overload",
            "CREATE FUNCTION capture_formation_stream_accepted_max(text,text,text) \
             RETURNS bigint LANGUAGE sql IMMUTABLE AS 'SELECT -1::bigint'",
            "DROP FUNCTION capture_formation_stream_accepted_max(text,text,text)",
        ),
        (
            "trigger",
            "CREATE FUNCTION activation_test_passthrough_trigger() RETURNS trigger \
                 LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'; \
             CREATE TRIGGER persistence_feature_unreviewed_preinstall \
                 BEFORE UPDATE ON capture_events FOR EACH ROW \
                 EXECUTE FUNCTION activation_test_passthrough_trigger()",
            "DROP TRIGGER persistence_feature_unreviewed_preinstall ON capture_events; \
             DROP FUNCTION activation_test_passthrough_trigger()",
        ),
        (
            "type",
            "CREATE TYPE capture_formation_unreviewed_preinstall AS ENUM ('unexpected')",
            "DROP TYPE capture_formation_unreviewed_preinstall",
        ),
    ] {
        sqlx::raw_sql(setup).execute(persistence.pool()).await?;
        let error = persistence
            .install_memory_reconciliation_activation_schema()
            .await
            .expect_err("v27 install must refuse an occupied reserved catalog namespace");
        assert!(
            error
                .to_string()
                .contains("reserved catalog namespace is not pristine"),
            "unexpected reserved-catalog {description} install refusal: {error}"
        );
        let mut connection = persistence.pool().acquire().await?;
        assert!(
            !activation_contract_exists(&mut connection).await?,
            "reserved-catalog {description} refusal published an activation contract"
        );
        sqlx::raw_sql(cleanup).execute(persistence.pool()).await?;
    }
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES($1,'activation-install-pending@example.com','google', \
                'activation-install-pending')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    // Writer-first: the v17/schema-26 writer takes the shared release lock
    // before it observes the activation table as absent. The installer must
    // wait through that writer's legacy-safe DML, then see and refuse it.
    let mut legacy_writer = persistence.pool().begin().await?;
    assert!(!lock_activation_contract_key_share_if_installed(&mut legacy_writer).await?);
    let install_persistence = persistence.clone();
    let mut install_task = tokio::spawn(async move {
        install_persistence
            .install_memory_reconciliation_activation_schema()
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut install_task)
            .await
            .is_err(),
        "v27 install must wait behind a schema-26 writer's shared release lock"
    );
    sqlx::query(
        "INSERT INTO episode_deletions( \
             account_id,episode_id,state,purge,media_object_keys,utterance_ids, \
             screenshot_ids,segment_ids,orphan_event_ids) \
         VALUES($1,1,'pending','{}'::jsonb,'[]'::jsonb,'[]'::jsonb, \
                '[]'::jsonb,'[]'::jsonb,'[]'::jsonb)",
    )
    .bind(ACCOUNT)
    .execute(&mut *legacy_writer)
    .await?;
    legacy_writer.commit().await?;
    let error = install_task
        .await
        .map_err(|error| EnclaveError::Store(format!("v27 install task failed: {error}")))?
        .expect_err("v27 install must refuse unresolved v26 deletion receipts");
    assert!(
        error
            .to_string()
            .contains("pending episode deletion requires v26 resolution"),
        "unexpected v27 install refusal: {error}"
    );
    let contract_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass(format('%I.%I',current_schema(), \
                'persistence_feature_activation_contracts')) IS NOT NULL",
    )
    .fetch_one(persistence.pool())
    .await?;
    assert!(
        !contract_exists,
        "failed v27 install must roll back every activation object"
    );

    sqlx::query(
        "UPDATE episode_deletions SET state='complete',completed_at=clock_timestamp(), \
                orphan_event_ids='[\"lost-v26-event\"]'::jsonb \
          WHERE account_id=$1 AND episode_id=1",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    let error = persistence
        .install_memory_reconciliation_activation_schema()
        .await
        .expect_err("v27 install must refuse completed v26 deletions with lost coordinates");
    assert!(
        error
            .to_string()
            .contains("completed v26 deletion lacks capture sequence coordinates"),
        "unexpected completed-deletion install refusal: {error}"
    );
    let contract_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass(format('%I.%I',current_schema(), \
                'persistence_feature_activation_contracts')) IS NOT NULL",
    )
    .fetch_one(persistence.pool())
    .await?;
    assert!(
        !contract_exists,
        "completed-deletion refusal must roll back every activation object"
    );

    sqlx::query(
        "UPDATE episode_deletions SET orphan_event_ids='[]'::jsonb \
          WHERE account_id=$1 AND episode_id=1",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;

    sqlx::raw_sql(
        "INSERT INTO capture_sessions( \
             account_id,id,device_id,install_id,started_at,last_event_at,ended_at,schema_version) \
         VALUES('activation-install-pending-deletion','install-race-session', \
                'install-race-device','install-race-install','2026-08-31T08:00:00Z', \
                '2026-08-31T08:00:01Z','2026-08-31T08:00:01Z',2); \
         INSERT INTO capture_streams( \
             account_id,id,capture_session_id,device_id,stream_kind,committed_through_sequence) \
         VALUES('activation-install-pending-deletion','install-race-stream', \
                'install-race-session','install-race-device','mac_screen',0); \
         INSERT INTO capture_events( \
             account_id,event_id,device_id,install_id,capture_session_id,stream_id,stream_kind, \
             sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id, \
             utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition) \
         VALUES('activation-install-pending-deletion','install-race-event', \
                'install-race-device','install-race-install','install-race-session', \
                'install-race-stream','mac_screen',0,'2026-08-31T08:00:00Z','0', \
                '2026-08-31T08:00:00Z','2026-08-31T08:00:01Z','UTC',0,0, \
                'install-race-asset',repeat('a',64),'canonical')",
    )
    .execute(persistence.pool())
    .await?;

    // Installer-first: hold its table-lock acquisition point after it owns
    // the exclusive release lock. A new writer must wait, then observe the
    // committed contract and take the v27 tombstone path.
    let mut table_blocker = persistence.pool().begin().await?;
    sqlx::query("LOCK TABLE episode_deletions IN ROW EXCLUSIVE MODE")
        .execute(&mut *table_blocker)
        .await?;
    let install_persistence = persistence.clone();
    let mut install_task = tokio::spawn(async move {
        install_persistence
            .install_memory_reconciliation_activation_schema()
            .await
    });
    wait_for_exclusive_release_lock(persistence).await?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut install_task)
            .await
            .is_err(),
        "installer must remain behind the conflicting table lock"
    );
    let writer_persistence = persistence.clone();
    let mut exact_writer = tokio::spawn(async move {
        let mut transaction = writer_persistence.pool().begin().await?;
        if !lock_activation_contract_key_share_if_installed(&mut transaction).await? {
            return Err(EnclaveError::Store(
                "writer resumed without the installed activation contract".into(),
            ));
        }
        sqlx::raw_sql(
            "INSERT INTO episode_deletions( \
                 account_id,episode_id,state,purge,media_object_keys,utterance_ids, \
                 screenshot_ids,segment_ids,orphan_event_ids) \
             VALUES('activation-install-pending-deletion',2,'pending','{}'::jsonb, \
                    '[]'::jsonb,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb, \
                    '[\"install-race-event\"]'::jsonb); \
             INSERT INTO capture_formation_deleted_sequences( \
                 account_id,capture_session_id,stream_id,sequence,event_id, \
                 original_manifest_digest,deletion_episode_id,provenance) \
             VALUES('activation-install-pending-deletion','install-race-session', \
                    'install-race-stream',0,'install-race-event',repeat('a',64),2, \
                    'episode_deletion_v1'); \
             DELETE FROM capture_events \
              WHERE account_id='activation-install-pending-deletion' \
                AND event_id='install-race-event'; \
             UPDATE episode_deletions SET state='complete',completed_at=clock_timestamp() \
              WHERE account_id='activation-install-pending-deletion' AND episode_id=2",
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok::<(), EnclaveError>(())
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut exact_writer)
            .await
            .is_err(),
        "schema-26 writer must wait behind the installer's exclusive release lock"
    );
    table_blocker.commit().await?;
    install_task
        .await
        .map_err(|error| EnclaveError::Store(format!("v27 install task failed: {error}")))??;
    exact_writer
        .await
        .map_err(|error| EnclaveError::Store(format!("v27 writer task failed: {error}")))??;
    assert_eq!(
        sqlx::query_as::<_, (bool, bool, String)>(
            "SELECT \
                 NOT EXISTS(SELECT 1 FROM capture_events \
                     WHERE account_id=$1 AND event_id='install-race-event'), \
                 EXISTS(SELECT 1 FROM capture_formation_deleted_sequences \
                     WHERE account_id=$1 AND event_id='install-race-event'), \
                 (SELECT state FROM episode_deletions \
                     WHERE account_id=$1 AND episode_id=2)",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        (true, true, "complete".into()),
    );
    let malformed_ready = sqlx::query(
        "INSERT INTO persistence_feature_reconciliation_neighborhood_scans( \
             account_id,component_seed_sha256,predecessor_episode_ids,phase, \
             closure_started_ms,closure_ended_ms,pass_started_ms,pass_ended_ms, \
             rolling_commitment,rolling_count,verification_generation) \
         VALUES($1,$2,ARRAY[2::bigint],'ready',0,1,0,1,$3,1,1)",
    )
    .bind(ACCOUNT)
    .bind(vec![0x11_u8; 32])
    .bind(vec![0x22_u8; 32])
    .execute(persistence.pool())
    .await
    .expect_err("ready scan without paired discovery proof must be rejected");
    assert!(
        malformed_ready.to_string().contains("check constraint"),
        "unexpected malformed ready-scan result: {malformed_ready}"
    );
    sqlx::query("DELETE FROM accounts WHERE id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    Ok(())
}

#[cfg(test)]
async fn test_real_pg_activation_contract_inner(persistence: &PostgresPersistence) -> Result<()> {
    use crate::persistence::{
        EpisodeDeletionRepository as _, FinalizationClaimRequest, FinalizationRepository as _,
        FinalizationSettlement, MemoryReconciliationActivationRepository as _,
        MemoryReconciliationRepository as _, ModelUsageRepository as _, VertexInvocationAdmission,
    };

    const ACCOUNT: &str = "activation-contract-account";
    test_real_pg_v27_install_refuses_pending_deletion(persistence).await?;
    persistence
        .install_memory_reconciliation_activation_schema()
        .await?;
    for (description, setup, cleanup) in [
        (
            "relation",
            "CREATE TABLE capture_formation_unreviewed_postinstall(id bigint)",
            "DROP TABLE capture_formation_unreviewed_postinstall",
        ),
        (
            "index on a reserved relation",
            "CREATE INDEX activation_test_unreviewed_index \
                 ON capture_formation_pages(account_id)",
            "DROP INDEX activation_test_unreviewed_index",
        ),
        (
            "function",
            "CREATE FUNCTION persistence_feature_unreviewed_postinstall() \
             RETURNS bigint LANGUAGE sql IMMUTABLE AS 'SELECT 1::bigint'",
            "DROP FUNCTION persistence_feature_unreviewed_postinstall()",
        ),
        (
            "reviewed-function overload",
            "CREATE FUNCTION capture_formation_stream_accepted_max(text,text,text) \
             RETURNS bigint LANGUAGE sql IMMUTABLE AS 'SELECT -1::bigint'",
            "DROP FUNCTION capture_formation_stream_accepted_max(text,text,text)",
        ),
        (
            "trigger",
            "CREATE FUNCTION activation_test_passthrough_trigger() RETURNS trigger \
                 LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'; \
             CREATE TRIGGER persistence_feature_unreviewed_postinstall \
                 BEFORE UPDATE ON capture_events FOR EACH ROW \
                 EXECUTE FUNCTION activation_test_passthrough_trigger()",
            "DROP TRIGGER persistence_feature_unreviewed_postinstall ON capture_events; \
             DROP FUNCTION activation_test_passthrough_trigger()",
        ),
        (
            "type",
            "CREATE TYPE capture_formation_unreviewed_postinstall AS ENUM ('unexpected')",
            "DROP TYPE capture_formation_unreviewed_postinstall",
        ),
    ] {
        sqlx::raw_sql(setup).execute(persistence.pool()).await?;
        assert!(
            persistence.verify_schema().await.is_err(),
            "serving verification must reject an unreviewed reserved-prefix {description}"
        );
        sqlx::raw_sql(cleanup).execute(persistence.pool()).await?;
    }
    persistence.verify_schema().await?;
    persistence.verify_schema().await?;
    super::media_processing::test_real_pg_media_provider_deletion_contract(persistence).await?;
    test_real_pg_seal_and_tombstone_contract(persistence).await?;
    let producer_contract = crate::cp::reconciler::producer_contract_commitment(
        "gemini-reconciliation-v1",
        "us-central1",
    )?;
    persistence
        .verify_reconciliation_runtime_schema(
            Some("gemini-reconciliation-v1"),
            "us-central1",
            Some(&producer_contract),
        )
        .await?;
    assert!(persistence
        .verify_reconciliation_runtime_schema(None, "us-central1", None,)
        .await
        .is_err());
    {
        let mut connection = persistence.pool().acquire().await?;
        super::schema_release::test_frozen_v0_9_16_verify_schema(&mut connection).await?;
    }
    sqlx::query(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject) \
         VALUES($1,'activation-contract@example.com','google','activation-contract-subject')",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO content_id_counters(account_id,entity_kind,next_id) \
         VALUES($1,'episodes',5)",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary,updated_at) \
         VALUES \
            ($1,1,'2026-08-31T10:00:00Z','2026-08-31T10:01:00Z', \
             'work','Activation fence','Draft must remain fenced',clock_timestamp()), \
            ($1,3,'2026-08-31T10:04:00Z','2026-08-31T10:05:00Z', \
             'work','Raw legacy fence','Direct finalization must fail',clock_timestamp()), \
            ($1,4,'2026-08-31T10:06:00Z','2026-08-31T10:07:00Z', \
             'work','Pre-drain settlement','In-flight settlement wins before drain',clock_timestamp()), \
            ($1,90,clock_timestamp()-interval '5 hours 30 minutes', \
             clock_timestamp()-interval '5 hours','work','Provider drain fence', \
             'Provider usage must settle before draining',clock_timestamp()), \
            ($1,92,'2026-08-31T10:08:00Z','2026-08-31T10:09:00Z', \
             'work','Legacy deletion drain fence', \
             'Pending legacy deletion must block signed draining',clock_timestamp())",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query("UPDATE accounts SET summarized_until=clock_timestamp() WHERE id=$1")
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?;
    sqlx::query(
        "UPDATE episodes SET finalization_status='processing', \
                finalization_claim_token='pre-drain-v16-claim', \
                finalization_claim_until=clock_timestamp()+interval '15 minutes' \
          WHERE account_id=$1 AND id=1",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;

    test_advance_activation_until_complete(persistence, false).await?;
    let draining = test_transition_authorization(
        persistence,
        1,
        "installed",
        "draining",
        0,
        vec![ACCOUNT.into()],
        false,
    )
    .await?;
    sqlx::query(
        "INSERT INTO episode_deletions( \
             account_id,episode_id,state,purge,media_object_keys,utterance_ids, \
             screenshot_ids,segment_ids,orphan_event_ids) \
         VALUES($1,92,'pending','{}'::jsonb,'[]'::jsonb,'[]'::jsonb, \
                '[]'::jsonb,'[]'::jsonb,'[]'::jsonb)",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    let pending_deletion_error = persistence
        .transition_memory_reconciliation_activation(&draining)
        .await
        .expect_err("a pending legacy deletion must block signed Draining");
    assert!(pending_deletion_error
        .to_string()
        .contains("zero pending legacy episode deletions"));
    persistence.verify_schema().await?;
    assert_eq!(
        persistence
            .memory_reconciliation_activation_status()
            .await?
            .phase,
        MemoryReconciliationActivationPhase::Installed,
        "a rejected Draining transition must roll back its event and all six guards"
    );
    sqlx::query(
        "INSERT INTO persistence_feature_episode_deletion_progress( \
             account_id,episode_id,phase,coordinate_sha256) \
         VALUES($1,92,'inventory_members',decode(repeat('0',64),'hex'))",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert!(persistence
        .transition_memory_reconciliation_activation(&draining)
        .await
        .expect_err("manual paged progress must not convert an Installed legacy deletion")
        .to_string()
        .contains("zero pending legacy episode deletions"));
    sqlx::query(
        "DELETE FROM persistence_feature_episode_deletion_progress \
          WHERE account_id=$1 AND episode_id=92",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    sqlx::query(
        "UPDATE episode_deletions \
            SET state='complete',completed_at=clock_timestamp(),updated_at=clock_timestamp() \
          WHERE account_id=$1 AND episode_id=92",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    let finalization = persistence
        .claim_finalization(FinalizationClaimRequest {
            account_id: ACCOUNT,
            target_episode_id: Some(90),
            quiet_horizon_seconds: 4 * 60 * 60,
            finalization_version: 5,
            lease_seconds: 900,
        })
        .await?
        .ok_or_else(|| EnclaveError::Store("pre-drain finalization claim is missing".into()))?;
    let finalizer_attempt_identity = [0x91_u8; 32];
    let finalizer_caller_anchor = [0x92_u8; 32];
    let finalizer_usage = persistence
        .begin_invocation_attempt(
            ACCOUNT,
            crate::cp::vertex::VertexOperation::FinalEpisodeAnalysis,
            "contract-model",
            "us-central1",
            &finalizer_caller_anchor,
            &finalizer_attempt_identity,
        )
        .await?;
    assert_eq!(finalizer_usage.admission, VertexInvocationAdmission::Send);
    let finalizer_guard = persistence
        .acquire_finalization_egress_guard(&finalization)
        .await?
        .ok_or_else(|| EnclaveError::Store("pre-drain finalization guard is missing".into()))?;
    let mut legacy_settlement = persistence.pool().begin().await?;
    sqlx::query(
        "UPDATE episodes SET finalization_status='finalized',finalized_at=clock_timestamp() \
          WHERE account_id=$1 AND id=4",
    )
    .bind(ACCOUNT)
    .execute(&mut *legacy_settlement)
    .await?;
    let deletion_persistence = persistence.clone();
    let mut deletion_task = tokio::spawn(async move {
        deletion_persistence
            .begin_episode_deletion(ACCOUNT, 90)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut deletion_task)
            .await
            .is_err(),
        "episode deletion must wait behind a live finalization egress guard"
    );
    let transition_persistence = persistence.clone();
    let mut draining_task = tokio::spawn(async move {
        transition_persistence
            .transition_memory_reconciliation_activation(&draining)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut draining_task)
            .await
            .is_err()
    );
    legacy_settlement.commit().await?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut draining_task)
            .await
            .is_err(),
        "draining must still wait for terminal provider usage and guard release"
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        persistence.settle_response(
            ACCOUNT,
            &finalizer_usage.event_id,
            &crate::cp::vertex::VertexMetadata {
                model_version: Some("contract-model".into()),
                ..Default::default()
            },
        ),
    )
    .await
    .map_err(|_| {
        EnclaveError::Store(
            "finalizer terminal usage settlement deadlocked behind its egress guard".into(),
        )
    })??;
    finalizer_guard.release().await?;
    let deletion_error = deletion_task
        .await
        .map_err(|error| EnclaveError::Store(format!("deletion task failed: {error}")))?
        .expect_err("live guarded finalization must refuse deletion planning");
    assert!(deletion_error
        .to_string()
        .contains("finalization provider work is in flight"));
    draining_task.await.map_err(|error| {
        EnclaveError::Store(format!("draining transition task failed: {error}"))
    })??;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT candidate_fleet_image_digest \
               FROM persistence_feature_activation_events WHERE feature=$1 \
               ORDER BY generation",
        )
        .bind(FEATURE)
        .fetch_all(persistence.pool())
        .await?,
        vec![None, Some(format!("sha256:{}", "b".repeat(64)))],
        "Installed must remain unbound and signed Draining must persist the fleet digest"
    );
    super::episode_deletion::test_real_pg_paged_episode_deletion_contract(persistence).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT outcome FROM vertex_usage_events WHERE account_id=$1 AND event_id=$2",
        )
        .bind(ACCOUNT)
        .bind(&finalizer_usage.event_id)
        .fetch_one(persistence.pool())
        .await?,
        "usage_missing"
    );
    assert!(persistence
        .acquire_finalization_egress_guard(&finalization)
        .await?
        .is_none());
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT finalized_at IS NOT NULL FROM episodes WHERE account_id=$1 AND id=4",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?
    );
    assert!(persistence
        .verify_reconciliation_runtime_schema(None, "us-central1", None,)
        .await
        .is_err());
    persistence
        .verify_reconciliation_runtime_schema(
            Some("gemini-reconciliation-v1"),
            "us-central1",
            Some(&producer_contract),
        )
        .await?;
    {
        let mut connection = persistence.pool().acquire().await?;
        assert!(
            super::schema_release::test_frozen_v0_9_16_verify_schema(&mut connection)
                .await
                .is_err()
        );
    }
    assert!(sqlx::query(
        "UPDATE episodes SET finalization_status='finalized', \
                finalized_at=clock_timestamp(),finalization_claim_token=NULL, \
                finalization_claim_until=NULL \
          WHERE account_id=$1 AND id=1 \
            AND finalization_claim_token='pre-drain-v16-claim'",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());
    assert!(sqlx::query(
        "UPDATE episodes SET finalization_status='finalized',finalized_at=clock_timestamp() \
          WHERE account_id=$1 AND id=3",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());
    test_advance_activation_until_complete(persistence, true).await?;
    assert!(sqlx::query_scalar::<_, Option<String>>(
        "SELECT finalization_claim_token FROM episodes WHERE account_id=$1 AND id=90",
    )
    .bind(ACCOUNT)
    .fetch_one(persistence.pool())
    .await?
    .is_none());
    let stale_settlement = FinalizationSettlement {
        claim: finalization.clone(),
        vertex_event_id: finalizer_usage.event_id.clone(),
        model_name: "contract-model".into(),
        analysis_revision: "a".repeat(64),
        title: "Stale finalization".into(),
        summary: "A signed draining transition revoked this claim.".into(),
        minute_summaries_json: "[]".into(),
        minutes_text: "stale".into(),
        action_items_json: "[]".into(),
        overview: "stale".into(),
        decisions_json: "[]".into(),
        important_links_json: "[]".into(),
        open_questions_json: "[]".into(),
        ranked_screens: Vec::new(),
        webhook_destinations: Vec::new(),
        email_preference_include_content: None,
        push_destinations: Vec::new(),
        finalization_version: 5,
        observation_version: 1,
        observation_prompt_version: 1,
        interpretation_version: 1,
        interpretation_prompt_version: 1,
    };
    assert!(
        persistence
            .settle_finalization(stale_settlement)
            .await
            .is_err(),
        "Draining may discard a terminal provider result, but a revoked claim must never settle"
    );
    assert!(
        persistence
            .claim_finalization(FinalizationClaimRequest {
                account_id: ACCOUNT,
                target_episode_id: Some(90),
                quiet_horizon_seconds: 4 * 60 * 60,
                finalization_version: 5,
                lease_seconds: 900,
            })
            .await?
            .is_none(),
        "the assigned draft must not obtain another legacy finalizer send after Draining"
    );
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT finalized_at IS NOT NULL FROM episodes WHERE account_id=$1 AND id=90",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?
    );
    assert!(sqlx::query(
        "UPDATE episodes SET finalization_status='processing', \
                finalization_claim_token='late-v16-claim', \
                finalization_claim_until=clock_timestamp()+interval '15 minutes' \
          WHERE account_id=$1 AND id=3",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM episodes WHERE account_id=$1 \
              AND structure_state='draft' AND finalization_claim_token IS NOT NULL",
        )
        .bind(ACCOUNT)
        .fetch_one(persistence.pool())
        .await?,
        0,
    );
    sqlx::query(
        "UPDATE persistence_schema SET version=27,expanded_through_version=27 \
          WHERE singleton=true",
    )
    .execute(persistence.pool())
    .await?;
    assert!(persistence.verify_schema().await.is_err());
    sqlx::query(
        "UPDATE persistence_schema SET version=26,expanded_through_version=26 \
          WHERE singleton=true",
    )
    .execute(persistence.pool())
    .await?;
    persistence.verify_schema().await?;
    let mismatched_candidate_digest = format!("sha256:{}", "e".repeat(64));
    let mismatched_active = test_transition_authorization_with_candidate_digest(
        persistence,
        2,
        "draining",
        "active",
        0,
        vec![ACCOUNT.into()],
        TestFleetEvidence {
            outage_pause: false,
            candidate_fleet_image_digest: &mismatched_candidate_digest,
        },
    )
    .await?;
    assert!(persistence
        .transition_memory_reconciliation_activation(&mismatched_active)
        .await
        .is_err());
    assert!(
        test_insert_transition_event_directly(persistence, &mismatched_active)
            .await
            .expect_err("PostgreSQL must independently reject a fleet-changing Active event")
            .to_string()
            .contains("must preserve fleet, rollout, and producer scope")
    );
    assert_eq!(
        persistence
            .memory_reconciliation_activation_status()
            .await?
            .phase,
        MemoryReconciliationActivationPhase::Draining
    );
    let active = test_transition_authorization(
        persistence,
        2,
        "draining",
        "active",
        0,
        vec![ACCOUNT.into()],
        false,
    )
    .await?;
    persistence
        .transition_memory_reconciliation_activation(&active)
        .await?;
    {
        let mut connection = persistence.pool().acquire().await?;
        assert!(
            super::schema_release::test_frozen_v0_9_16_verify_schema(&mut connection)
                .await
                .is_err()
        );
    }
    persistence.verify_schema().await?;
    assert!(persistence
        .verify_reconciliation_runtime_schema(None, "us-central1", None,)
        .await
        .is_err());
    persistence
        .verify_reconciliation_runtime_schema(
            Some("gemini-reconciliation-v1"),
            "us-central1",
            Some(&producer_contract),
        )
        .await?;

    sqlx::raw_sql(
        "INSERT INTO screenshots(account_id,id,captured_at,active_app,ocr_text,source_key) \
         VALUES('activation-contract-account',100,'2026-08-31T10:00:30Z', \
                'Notes','provider lock order','activation-lock-source'); \
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
         VALUES('activation-contract-account',1,'screenshot',100);",
    )
    .execute(persistence.pool())
    .await?;
    let snapshot = persistence
        .next_source_settled_cohort(ACCOUNT, 4 * 60 * 60, None, 32, 4_000)
        .await?
        .ok_or_else(|| EnclaveError::Store("provider lock-order cohort is missing".into()))?;
    let claim = persistence
        .claim_reconciliation(&snapshot, 900)
        .await?
        .ok_or_else(|| EnclaveError::Store("provider lock-order claim is missing".into()))?;

    let (attempt_identity, caller_anchor, invocation_fingerprint) =
        crate::cp::reconciler::test_reconciliation_provider_commitments(&snapshot, &claim)?;
    let attempt = persistence
        .begin_invocation_attempt(
            ACCOUNT,
            crate::cp::vertex::VertexOperation::EpisodeReconciliation,
            &claim.reconciliation_model,
            &claim.vertex_location,
            &caller_anchor,
            &attempt_identity,
        )
        .await?;
    assert_eq!(attempt.admission, VertexInvocationAdmission::Send);
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT request_fingerprint FROM vertex_usage_events \
              WHERE account_id=$1 AND event_id=$2",
        )
        .bind(ACCOUNT)
        .bind(&attempt.event_id)
        .fetch_one(persistence.pool())
        .await?,
        invocation_fingerprint,
    );

    // A durable intent is not a terminal response and cannot authorize a
    // stage. Every persisted usage coordinate is checked independently.
    assert!(persistence
        .stage_reconciliation(
            &claim,
            super::memory_reconciliation::test_provider_stage_write_with_provenance(
                &snapshot,
                "started",
                &claim.reconciliation_model,
                &attempt.event_id,
                &attempt_identity,
                &invocation_fingerprint,
            )?,
        )
        .await
        .is_err());
    let wrong_attempt_identity = [0x7c_u8; 32];
    assert_ne!(wrong_attempt_identity, attempt_identity);
    assert!(persistence
        .stage_reconciliation(
            &claim,
            super::memory_reconciliation::test_provider_stage_write_with_provenance(
                &snapshot,
                "wrong-attempt",
                &claim.reconciliation_model,
                &attempt.event_id,
                &wrong_attempt_identity,
                &invocation_fingerprint,
            )?,
        )
        .await
        .is_err());
    persistence
        .settle_response(
            ACCOUNT,
            &attempt.event_id,
            &crate::cp::vertex::VertexMetadata::default(),
        )
        .await?;

    let wrong_fingerprint = [0x5a_u8; 32];
    assert_ne!(wrong_fingerprint, invocation_fingerprint);
    assert!(persistence
        .stage_reconciliation(
            &claim,
            super::memory_reconciliation::test_provider_stage_write_with_provenance(
                &snapshot,
                "wrong-fingerprint",
                &claim.reconciliation_model,
                &attempt.event_id,
                &attempt_identity,
                &wrong_fingerprint,
            )?,
        )
        .await
        .is_err());
    assert!(persistence
        .stage_reconciliation(
            &claim,
            super::memory_reconciliation::test_provider_stage_write_with_provenance(
                &snapshot,
                "wrong-stage-model",
                "different-model",
                &attempt.event_id,
                &attempt_identity,
                &invocation_fingerprint,
            )?,
        )
        .await
        .is_err());
    for (column, invalid, restore) in [
        (
            "requested_model",
            "different-model",
            claim.reconciliation_model.as_str(),
        ),
        ("location", "europe-west1", claim.vertex_location.as_str()),
        (
            "operation",
            "screen_understanding",
            crate::cp::vertex::VertexOperation::EpisodeReconciliation.as_str(),
        ),
    ] {
        let update = format!(
            "UPDATE vertex_usage_events SET {column}=$3 WHERE account_id=$1 AND event_id=$2"
        );
        sqlx::query(sqlx::AssertSqlSafe(update.clone()))
            .bind(ACCOUNT)
            .bind(&attempt.event_id)
            .bind(invalid)
            .execute(persistence.pool())
            .await?;
        assert!(persistence
            .stage_reconciliation(
                &claim,
                super::memory_reconciliation::test_provider_stage_write_with_provenance(
                    &snapshot,
                    "wrong-usage-coordinate",
                    &claim.reconciliation_model,
                    &attempt.event_id,
                    &attempt_identity,
                    &invocation_fingerprint,
                )?,
            )
            .await
            .is_err());
        sqlx::query(sqlx::AssertSqlSafe(update))
            .bind(ACCOUNT)
            .bind(&attempt.event_id)
            .bind(restore)
            .execute(persistence.pool())
            .await?;
    }
    for (outcome, status) in [("not_billed", 400_i32), ("usage_missing", 503_i32)] {
        sqlx::query(
            "UPDATE vertex_usage_events SET outcome=$3,http_status=$4 \
              WHERE account_id=$1 AND event_id=$2",
        )
        .bind(ACCOUNT)
        .bind(&attempt.event_id)
        .bind(outcome)
        .bind(status)
        .execute(persistence.pool())
        .await?;
        assert!(persistence
            .stage_reconciliation(
                &claim,
                super::memory_reconciliation::test_provider_stage_write_with_provenance(
                    &snapshot,
                    "wrong-terminal-usage",
                    &claim.reconciliation_model,
                    &attempt.event_id,
                    &attempt_identity,
                    &invocation_fingerprint,
                )?,
            )
            .await
            .is_err());
    }
    sqlx::query(
        "UPDATE vertex_usage_events SET outcome='usage_missing',http_status=200 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&attempt.event_id)
    .execute(persistence.pool())
    .await?;

    let normal_guard = persistence
        .acquire_provider_egress_guard(&claim)
        .await?
        .ok_or_else(|| EnclaveError::Store("normal provider provenance guard is missing".into()))?;
    let normal_staged = normal_guard
        .stage_and_release(
            super::memory_reconciliation::test_provider_stage_write_with_provenance(
                &snapshot,
                "normal-provider",
                &claim.reconciliation_model,
                &attempt.event_id,
                &attempt_identity,
                &invocation_fingerprint,
            )?,
        )
        .await?;

    sqlx::query(
        "UPDATE vertex_usage_events SET outcome='metered',http_status=200 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&attempt.event_id)
    .execute(persistence.pool())
    .await?;
    let normal_metered = persistence
        .stage_reconciliation(
            &claim,
            super::memory_reconciliation::test_provider_stage_write_with_provenance(
                &snapshot,
                "normal-provider",
                &claim.reconciliation_model,
                &attempt.event_id,
                &attempt_identity,
                &invocation_fingerprint,
            )?,
        )
        .await?;
    assert_eq!(normal_metered, normal_staged);
    sqlx::query(
        "UPDATE vertex_usage_events SET outcome='usage_missing',http_status=200 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&attempt.event_id)
    .execute(persistence.pool())
    .await?;

    sqlx::query(
        "UPDATE vertex_usage_events SET request_fingerprint=$3 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&attempt.event_id)
    .bind(wrong_fingerprint.as_slice())
    .execute(persistence.pool())
    .await?;
    assert!(persistence.staged_result(&claim).await.is_err());
    assert!(persistence
        .publish_reconciliation(crate::persistence::ReconciliationPublish {
            claim: claim.clone(),
            reconciliation_id: "rec_corrupt_provider_provenance".into(),
            cohort_started_at: snapshot.cohort_started_at.clone(),
            cohort_ended_at: snapshot.cohort_ended_at.clone(),
            result_commitment: normal_staged.result_commitment.clone(),
        })
        .await
        .is_err());
    sqlx::query(
        "UPDATE vertex_usage_events SET request_fingerprint=$3 \
          WHERE account_id=$1 AND event_id=$2",
    )
    .bind(ACCOUNT)
    .bind(&attempt.event_id)
    .bind(invocation_fingerprint.as_slice())
    .execute(persistence.pool())
    .await?;
    assert!(persistence.staged_result(&claim).await?.is_some());

    let ambiguity_stage = super::memory_reconciliation::test_provider_stage_write_with_provenance(
        &snapshot,
        "ambiguity-provider",
        "conservative-ambiguity-v1",
        &attempt.event_id,
        &attempt_identity,
        &invocation_fingerprint,
    )?;
    for (outcome, status) in [
        ("ambiguous", 504_i32),
        ("metered", 200_i32),
        ("usage_missing", 200_i32),
    ] {
        sqlx::query(
            "UPDATE vertex_usage_events SET outcome=$3,http_status=$4 \
              WHERE account_id=$1 AND event_id=$2",
        )
        .bind(ACCOUNT)
        .bind(&attempt.event_id)
        .bind(outcome)
        .bind(status)
        .execute(persistence.pool())
        .await?;
        persistence
            .stage_reconciliation(&claim, ambiguity_stage.clone())
            .await?;
    }

    let stage = super::memory_reconciliation::test_provider_stage_write(&snapshot, "initial")?;

    // A source transaction which already follows KEY SHARE -> account lock
    // makes guard acquisition wait before it can take any episode row lock.
    let mut source_first = persistence.pool().begin().await?;
    assert!(active_reconciliation_authority(&mut source_first, ACCOUNT)
        .await?
        .is_some());
    super::advisory_transaction_lock(&mut source_first, "memory-reconciliation", ACCOUNT).await?;
    let guard_persistence = persistence.clone();
    let guard_claim = claim.clone();
    let mut guard_task = tokio::spawn(async move {
        guard_persistence
            .acquire_provider_egress_guard(&guard_claim)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut guard_task)
            .await
            .is_err(),
        "provider guard must wait behind an earlier account mutation lock"
    );
    source_first.commit().await?;
    let guard = guard_task
        .await
        .map_err(|error| EnclaveError::Store(format!("provider guard task failed: {error}")))??
        .ok_or_else(|| EnclaveError::Store("provider egress guard was not acquired".into()))?;

    // Once the guard owns account and episode locks, a later source mutation
    // waits at the advisory boundary while the same guard transaction stages
    // and commits without opening a lock-inverted second transaction.
    let mutation_persistence = persistence.clone();
    let predecessor_ids = snapshot.predecessor_episode_ids.clone();
    let (mutation_ready_tx, mutation_ready_rx) = tokio::sync::oneshot::channel();
    let mut mutation_task = tokio::spawn(async move {
        let mut transaction = mutation_persistence.pool().begin().await?;
        let authority = active_reconciliation_authority(&mut transaction, ACCOUNT).await?;
        mutation_ready_tx.send(()).map_err(|_| {
            EnclaveError::Store("provider mutation barrier receiver disappeared".into())
        })?;
        if authority.is_none() {
            return Err(EnclaveError::Conflict(
                "provider mutation lost activation authority".into(),
            ));
        }
        super::advisory_transaction_lock(&mut transaction, "memory-reconciliation", ACCOUNT)
            .await?;
        sqlx::query(
            "UPDATE episodes SET updated_at=updated_at \
              WHERE account_id=$1 AND id=ANY($2)",
        )
        .bind(ACCOUNT)
        .bind(&predecessor_ids)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok::<(), EnclaveError>(())
    });
    mutation_ready_rx.await.map_err(|_| {
        EnclaveError::Store("provider mutation did not reach its advisory boundary".into())
    })?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut mutation_task)
            .await
            .is_err(),
        "source mutation must wait while provider authority is fenced"
    );
    let staged = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        guard.stage_and_release(stage),
    )
    .await
    .map_err(|_| EnclaveError::Store("guarded provider stage deadlocked".into()))??;
    assert_eq!(staged.account_id, ACCOUNT);
    mutation_task.await.map_err(|error| {
        EnclaveError::Store(format!("provider mutation task failed: {error}"))
    })??;

    let model_attempts_before_replay = sqlx::query_scalar::<_, i64>(
        "SELECT model_attempt_count FROM memory_reconciliation_jobs \
          WHERE account_id=$1 AND source_fingerprint=$2",
    )
    .bind(ACCOUNT)
    .bind(&claim.source_fingerprint)
    .fetch_one(persistence.pool())
    .await?;
    let replay_guard = persistence
        .acquire_provider_egress_guard(&claim)
        .await?
        .ok_or_else(|| EnclaveError::Store("provider replay guard is missing".into()))?;
    let replayed = replay_guard
        .stage_and_release(super::memory_reconciliation::test_provider_stage_write(
            &snapshot, "initial",
        )?)
        .await?;
    assert_eq!(replayed, staged);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT model_attempt_count FROM memory_reconciliation_jobs \
              WHERE account_id=$1 AND source_fingerprint=$2",
        )
        .bind(ACCOUNT)
        .bind(&claim.source_fingerprint)
        .fetch_one(persistence.pool())
        .await?,
        model_attempts_before_replay,
    );

    assert!(persistence
        .verify_reconciliation_runtime_schema(
            Some("different-model"),
            "us-central1",
            Some(&producer_contract),
        )
        .await
        .is_err());
    assert!(sqlx::query(
        "UPDATE episodes SET finalized_at=clock_timestamp() \
          WHERE account_id=$1 AND id=1",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());
    sqlx::query(
        "INSERT INTO episodes( \
             account_id,id,started_at,ended_at,type,title,summary,structure_state,updated_at) \
         VALUES($1,2,'2026-08-31T10:02:00Z','2026-08-31T10:03:00Z', \
                'work','Reconciled activation fence','Allowed finalization', \
                'reconciled',clock_timestamp())",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert_eq!(
        sqlx::query(
            "UPDATE episodes SET finalized_at=clock_timestamp() \
              WHERE account_id=$1 AND id=2",
        )
        .bind(ACCOUNT)
        .execute(persistence.pool())
        .await?
        .rows_affected(),
        1
    );

    sqlx::query(
        "INSERT INTO episodes( \
             account_id,id,started_at,ended_at,type,title,summary,structure_state,updated_at) \
         VALUES($1,91,clock_timestamp()-interval '5 hours 30 minutes', \
                clock_timestamp()-interval '5 hours','work','Deletion wins fence', \
                'A stale claim must not disclose after deletion','reconciled',clock_timestamp())",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    let deletion_first_claim = persistence
        .claim_finalization(FinalizationClaimRequest {
            account_id: ACCOUNT,
            target_episode_id: Some(91),
            quiet_horizon_seconds: 4 * 60 * 60,
            finalization_version: 5,
            lease_seconds: 900,
        })
        .await?
        .ok_or_else(|| {
            EnclaveError::Store("deletion-first finalization claim is missing".into())
        })?;
    let deletion_first_attempt = persistence
        .begin_invocation_attempt(
            ACCOUNT,
            crate::cp::vertex::VertexOperation::FinalEpisodeAnalysis,
            "contract-model",
            "us-central1",
            &[0x93_u8; 32],
            &[0x94_u8; 32],
        )
        .await?;
    assert_eq!(
        deletion_first_attempt.admission,
        VertexInvocationAdmission::Send
    );
    sqlx::query(
        "UPDATE episodes SET finalization_claim_until=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND id=91",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await?;
    assert!(matches!(
        persistence.begin_episode_deletion(ACCOUNT, 91).await?,
        crate::persistence::EpisodeDeletionStart::Pending(_)
    ));
    assert!(persistence
        .acquire_finalization_egress_guard(&deletion_first_claim)
        .await?
        .is_none());
    persistence
        .settle_pre_egress_not_billed(ACCOUNT, &deletion_first_attempt.event_id)
        .await?;

    sqlx::query(
        "UPDATE persistence_feature_activation_backfills \
            SET complete=false,completed_at=NULL WHERE feature=$1",
    )
    .bind(FEATURE)
    .execute(persistence.pool())
    .await?;
    assert!(persistence.verify_schema().await.is_err());
    sqlx::query(
        "UPDATE persistence_feature_activation_backfills \
            SET complete=true,completed_at=clock_timestamp() WHERE feature=$1",
    )
    .bind(FEATURE)
    .execute(persistence.pool())
    .await?;
    persistence.verify_schema().await?;

    let mismatched_pause = test_transition_authorization_with_candidate_digest(
        persistence,
        3,
        "active",
        "paused",
        0,
        vec![ACCOUNT.into()],
        TestFleetEvidence {
            outage_pause: true,
            candidate_fleet_image_digest: &mismatched_candidate_digest,
        },
    )
    .await?;
    assert!(persistence
        .transition_memory_reconciliation_activation(&mismatched_pause)
        .await
        .is_err());
    let pause = test_transition_authorization(
        persistence,
        3,
        "active",
        "paused",
        0,
        vec![ACCOUNT.into()],
        true,
    )
    .await?;
    let mut provider_guard = persistence.pool().begin().await?;
    assert!(
        active_reconciliation_authority(&mut provider_guard, ACCOUNT)
            .await?
            .is_some()
    );
    let transition_persistence = persistence.clone();
    let mut pause_task = tokio::spawn(async move {
        transition_persistence
            .transition_memory_reconciliation_activation(&pause)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut pause_task)
            .await
            .is_err()
    );
    provider_guard.commit().await?;
    let paused_result = pause_task
        .await
        .map_err(|error| EnclaveError::Store(format!("pause transition task failed: {error}")))??;
    let audit_since = sqlx::query_scalar::<_, String>(
        "SELECT to_char(clock_timestamp()-interval '1 hour', \
                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
    )
    .fetch_one(persistence.pool())
    .await?;
    let paused_audit = persistence
        .aggregate_audit(&audit_since)
        .await
        .expect("Paused aggregate audit must retain the latest Draining ledger");
    assert_eq!(paused_audit.activation.phase.as_deref(), Some("paused"));
    assert_eq!(
        paused_audit.activation.generation,
        Some(paused_result.generation)
    );
    assert!(paused_audit.activation.drain_present);
    assert_eq!(
        paused_audit.activation.drain_complete,
        Some(paused_result.finalization_claim_drain_complete)
    );
    assert_eq!(
        paused_audit.activation.drain_claims_scanned,
        Some(paused_result.finalization_claims_scanned)
    );
    assert_eq!(
        paused_audit.activation.drain_claims_revoked,
        Some(paused_result.finalization_claims_revoked)
    );
    persistence.verify_schema().await?;
    let mut paused_egress = persistence.pool().begin().await?;
    assert!(active_reconciliation_authority(&mut paused_egress, ACCOUNT)
        .await?
        .is_none());
    paused_egress.rollback().await?;
    assert!(persistence
        .verify_reconciliation_runtime_schema(None, "us-central1", None,)
        .await
        .is_err());
    persistence
        .verify_reconciliation_runtime_schema(
            Some("gemini-reconciliation-v1"),
            "us-central1",
            Some(&producer_contract),
        )
        .await?;
    assert!(sqlx::query(
        "UPDATE episodes SET finalized_at=clock_timestamp() \
          WHERE account_id=$1 AND id=1",
    )
    .bind(ACCOUNT)
    .execute(persistence.pool())
    .await
    .is_err());

    let mismatched_resume = test_transition_authorization_with_candidate_digest(
        persistence,
        4,
        "paused",
        "active",
        0,
        vec![ACCOUNT.into()],
        TestFleetEvidence {
            outage_pause: false,
            candidate_fleet_image_digest: &mismatched_candidate_digest,
        },
    )
    .await?;
    assert!(persistence
        .transition_memory_reconciliation_activation(&mismatched_resume)
        .await
        .is_err());
    let resume = test_transition_authorization(
        persistence,
        4,
        "paused",
        "active",
        0,
        vec![ACCOUNT.into()],
        false,
    )
    .await?;
    persistence
        .transition_memory_reconciliation_activation(&resume)
        .await?;

    // The generation-2 stage was paid for but never published before pause.
    // Reclaim the exact cohort under generation 4 and prove a different
    // result with identical producer/model versions can stage and publish;
    // the generation-bound source fingerprint also prevents replaying the
    // old staged row as current authority.
    sqlx::query(
        "UPDATE memory_reconciliation_jobs \
            SET claim_until=clock_timestamp()-interval '1 second' \
          WHERE account_id=$1 AND source_fingerprint=$2",
    )
    .bind(ACCOUNT)
    .bind(&snapshot.source_fingerprint)
    .execute(persistence.pool())
    .await?;
    let resumed_snapshot = persistence
        .next_source_settled_cohort(ACCOUNT, 4 * 60 * 60, None, 32, 4_000)
        .await?
        .ok_or_else(|| EnclaveError::Store("resumed reconciliation cohort is missing".into()))?;
    assert_ne!(
        resumed_snapshot.source_fingerprint,
        snapshot.source_fingerprint
    );
    let resumed_claim = persistence
        .claim_reconciliation(&resumed_snapshot, 900)
        .await?
        .ok_or_else(|| EnclaveError::Store("resumed reconciliation claim is missing".into()))?;
    assert_eq!(resumed_claim.activation_generation, 4);
    assert!(persistence.staged_result(&resumed_claim).await?.is_none());
    let resumed_guard = persistence
        .acquire_provider_egress_guard(&resumed_claim)
        .await?
        .ok_or_else(|| EnclaveError::Store("resumed provider guard is missing".into()))?;
    let resumed_stage_write =
        super::memory_reconciliation::test_provider_stage_write(&resumed_snapshot, "resumed")?;
    let resumed_stage = resumed_guard.stage_and_release(resumed_stage_write).await?;
    assert_ne!(resumed_stage.result_commitment, staged.result_commitment);
    assert_eq!(resumed_stage.activation_generation, 4);
    let mut reconciliation_digest = Sha256::new();
    reconciliation_digest.update(b"kioku:postgres-memory-reconciliation:v1\0");
    reconciliation_digest.update(&resumed_snapshot.source_fingerprint);
    reconciliation_digest.update(&resumed_stage.result_commitment);
    let reconciliation_id = format!("rec_{:x}", reconciliation_digest.finalize());
    let published = persistence
        .publish_reconciliation(crate::persistence::ReconciliationPublish {
            claim: resumed_claim,
            reconciliation_id,
            cohort_started_at: resumed_snapshot.cohort_started_at.clone(),
            cohort_ended_at: resumed_snapshot.cohort_ended_at.clone(),
            result_commitment: resumed_stage.result_commitment,
        })
        .await?;
    assert!(matches!(
        published,
        crate::persistence::ReconciliationPublishResult::Published { .. }
    ));

    let pause_again = test_transition_authorization(
        persistence,
        5,
        "active",
        "paused",
        0,
        vec![ACCOUNT.into()],
        false,
    )
    .await?;
    persistence
        .transition_memory_reconciliation_activation(&pause_again)
        .await?;
    let shrinking_scope = test_transition_authorization(
        persistence,
        6,
        "paused",
        "draining",
        0,
        vec!["different-canary".into()],
        false,
    )
    .await?;
    assert!(persistence
        .transition_memory_reconciliation_activation(&shrinking_scope)
        .await
        .is_err());
    let rotated_candidate_digest = format!("sha256:{}", "e".repeat(64));
    let global_drain = test_transition_authorization_with_candidate_digest(
        persistence,
        6,
        "paused",
        "draining",
        10_000,
        Vec::new(),
        TestFleetEvidence {
            outage_pause: false,
            candidate_fleet_image_digest: &rotated_candidate_digest,
        },
    )
    .await?;
    persistence
        .transition_memory_reconciliation_activation(&global_drain)
        .await?;
    test_advance_activation_until_complete(persistence, true).await?;
    let stale_fleet_active = test_transition_authorization(
        persistence,
        7,
        "draining",
        "active",
        10_000,
        Vec::new(),
        false,
    )
    .await?;
    assert!(persistence
        .transition_memory_reconciliation_activation(&stale_fleet_active)
        .await
        .is_err());
    let global_active = test_transition_authorization_with_candidate_digest(
        persistence,
        7,
        "draining",
        "active",
        10_000,
        Vec::new(),
        TestFleetEvidence {
            outage_pause: false,
            candidate_fleet_image_digest: &rotated_candidate_digest,
        },
    )
    .await?;
    let global_active_result = persistence
        .transition_memory_reconciliation_activation(&global_active)
        .await?;
    let global_active_audit = persistence
        .aggregate_audit(&audit_since)
        .await
        .expect("Active aggregate audit must select the latest of multiple Draining ledgers");
    assert_eq!(
        global_active_audit.activation.phase.as_deref(),
        Some("active")
    );
    assert_eq!(
        global_active_audit.activation.generation,
        Some(global_active_result.generation)
    );
    assert!(global_active_audit.activation.drain_present);
    assert_eq!(
        global_active_audit.activation.drain_complete,
        Some(global_active_result.finalization_claim_drain_complete)
    );
    assert_eq!(
        global_active_audit.activation.drain_claims_scanned,
        Some(global_active_result.finalization_claims_scanned)
    );
    assert_eq!(
        global_active_audit.activation.drain_claims_revoked,
        Some(global_active_result.finalization_claims_revoked)
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT candidate_fleet_image_digest \
               FROM persistence_feature_activation_events \
              WHERE feature=$1 AND generation IN (6,7) ORDER BY generation",
        )
        .bind(FEATURE)
        .fetch_all(persistence.pool())
        .await?,
        vec![
            Some(rotated_candidate_digest.clone()),
            Some(rotated_candidate_digest)
        ],
        "a fresh Paused-to-Draining proof may rotate the fleet, then Active must preserve it"
    );
    super::memory_formation::test_real_pg_oversized_formation_and_neighborhood(persistence).await?;
    let status = persistence
        .memory_reconciliation_activation_status()
        .await?;
    assert_eq!(status.phase, MemoryReconciliationActivationPhase::Active);
    assert_eq!(status.rollout_basis_points, 10_000);
    Ok(())
}

/// Executes v27 against an isolated real-PostgreSQL schema so the frozen v26
/// contract and the append-only marker transition are exercised without
/// making the main reusable contract database irreversible.
#[cfg(test)]
pub(super) async fn test_real_pg_activation_contract(base: &PostgresPersistence) {
    use std::{str::FromStr as _, time::Duration};

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    let _release_contract_guard = super::POSTGRES_RELEASE_CONTRACT_MUTEX.lock().await;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock must follow the Unix epoch")
        .as_nanos();
    let schema = format!("kioku_activation_{}_{}", std::process::id(), unique);
    assert!(schema
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(base.pool())
        .await
        .expect("create isolated activation schema");
    let database_url = std::env::var("KIOKU_TEST_POSTGRES_URL")
        .expect("real PostgreSQL activation contract requires its configured URL");
    let options = PgConnectOptions::from_str(&database_url)
        .expect("parse real PostgreSQL activation URL")
        .options([("search_path", format!("{schema},public"))]);
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .expect("connect isolated activation schema");
    let persistence = PostgresPersistence { pool };
    let outcome = async {
        persistence.migrate().await?;
        // This broad contract is also nested inside the exhaustive control-plane
        // future. Keep its state off that test thread's bounded stack.
        Box::pin(test_real_pg_activation_contract_inner(&persistence)).await
    }
    .await;
    persistence.pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(base.pool())
        .await
        .expect("drop isolated activation schema");
    outcome.expect("real PostgreSQL v27 activation contract");
}

/// Independently runnable activation contract. Keeping this separate from the
/// monolithic PostgreSQL repository contract makes migration, transition, and
/// tamper failures directly attributable and permits parallel isolated-schema
/// execution.
#[cfg(test)]
#[tokio::test]
async fn postgres_memory_reconciliation_activation_contract() {
    use std::time::Duration;

    let required = std::env::var("KIOKU_REQUIRE_POSTGRES_CONTRACT").as_deref() == Ok("1");
    let database_url = match std::env::var("KIOKU_TEST_POSTGRES_URL") {
        Ok(value) => value,
        Err(_) => {
            assert!(
                !required,
                "KIOKU_TEST_POSTGRES_URL is required by the real PostgreSQL activation contract"
            );
            eprintln!("KIOKU_TEST_POSTGRES_URL is unset; skipping v27 activation contract");
            return;
        }
    };
    let base = PostgresPersistence::connect(super::PostgresPoolConfig {
        database_url,
        root_ca_pem: None,
        max_connections: 8,
        acquire_timeout: Duration::from_secs(5),
        statement_timeout: Duration::from_secs(30),
    })
    .await
    .expect("connect real PostgreSQL activation contract");
    test_real_pg_activation_contract(&base).await;
    base.pool.close().await;
}
