//! Online, resumable PostgreSQL schema-26 release protocol.
//!
//! The production v24 predecessor reads only `persistence_schema.version`, so
//! every additive step—including the schema-25 account-status expansion—leaves
//! that value at 24. A v26 reader accepts the schema only after the exact
//! embedded contract is durably receipted as 24/26. The writer
//! additionally requires a strict, persisted zero-unavailable fleet receipt
//! and the finalized 26/26 marker.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::pool::PoolConnection;
use sqlx::{Acquire, PgConnection, Postgres, Row};

use crate::cp::isotime;
use crate::error::{EnclaveError, Result};

use super::{
    classify_serving_schema, installed_schema_state_from_row, transaction_schema_state,
    InstalledSchemaState, PostgresPersistence, ServingSchemaState, EXPECTED_SCHEMA_VERSION,
    MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
};

const RELEASE_PROTOCOL_VERSION: i64 = 1;
const BACKFILL_BATCH_SIZE: i64 = 250;
const MAX_BACKFILL_BATCHES_PER_RUN: usize = 100;
const FLEET_RECEIPT_MAX_VALIDITY_MILLIS: i64 = 15 * 60 * 1_000;
const FLEET_RECEIPT_MIN_REMAINING_MILLIS: i64 = 60 * 1_000;
const RELEASE_ADVISORY_LOCK: &str = "kioku:postgres-schema-release:v26";
const SCHEMA_FINALIZATION_PUBLIC_KEY_ENV: &str = "SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64";
const SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256_ENV: &str = "SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

const RELEASE_LEDGER_SQL: &str =
    include_str!("../../../migrations/0026_memory_reconciliation_release_ledger.sql");
const COLD_OBJECTS_SQL: &str = include_str!("../../../migrations/0026_memory_reconciliation.sql");
const EXPAND_RECEIPT_SQL: &str =
    include_str!("../../../migrations/0026_memory_reconciliation_expand_receipt.sql");
const FINALIZE_SQL: &str =
    include_str!("../../../migrations/0026_memory_reconciliation_finalize.sql");
const LEGACY_MEMBERSHIP_INDEX_SQL: &str =
    include_str!("../../../migrations/0026_memory_reconciliation_episode_members_unique_index.sql");
const CAPTURE_SESSIONS_INDEX_SQL: &str =
    include_str!("../../../migrations/0026_memory_reconciliation_capture_sessions_index.sql");
const CAPTURE_EVENTS_INDEX_SQL: &str =
    include_str!("../../../migrations/0026_memory_reconciliation_capture_events_index.sql");
const ACCOUNT_DELETION_COMPATIBILITY_SQL: &str =
    include_str!("../../../migrations/0026_account_deletion_compatibility.sql");

// Each populated-table DDL statement is executed and committed independently
// with a short lock timeout. NOT VALID checks protect all new writes without a
// table scan; the receipting invariant proves the bounded backfill covered old
// rows.
const EPISODES_ADD_STRUCTURE_STATE_SQL: &str =
    "ALTER TABLE episodes ADD COLUMN structure_state text";
const EPISODES_STRUCTURE_DEFAULT_SQL: &str =
    "ALTER TABLE episodes ALTER COLUMN structure_state SET DEFAULT 'draft'";
const EPISODES_STRUCTURE_VALUES_SQL: &str = r#"
ALTER TABLE episodes
    ADD CONSTRAINT episodes_structure_state_values_v26
    CHECK (structure_state IN ('draft','reconciled')) NOT VALID;
"#;
const EPISODES_STRUCTURE_REQUIRED_SQL: &str = r#"
ALTER TABLE episodes
    ADD CONSTRAINT episodes_structure_state_required_v26
    CHECK (structure_state IS NOT NULL) NOT VALID;
"#;

const ACCOUNTS_ARCHIVE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER accounts_install_memory_archive
AFTER INSERT ON accounts FOR EACH ROW
EXECUTE FUNCTION install_memory_archive_for_account();
"#;
const EPISODES_STRUCTURE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER episodes_maintain_structure_state
BEFORE INSERT OR UPDATE ON episodes FOR EACH ROW
EXECUTE FUNCTION maintain_episode_structure_state();
"#;
const EPISODES_HANDLE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER episodes_install_active_memory_handle
AFTER INSERT ON episodes FOR EACH ROW
EXECUTE FUNCTION install_active_memory_handle();
"#;
const EPISODES_DELETE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER episodes_retire_deleted_memory
BEFORE DELETE ON episodes FOR EACH ROW
EXECUTE FUNCTION retire_deleted_memory();
"#;
const EPISODE_MEMBERS_TRIGGER_SQL: &str = r#"
CREATE TRIGGER episode_members_project_active
AFTER INSERT OR UPDATE OR DELETE ON episode_members FOR EACH ROW
EXECUTE FUNCTION project_active_episode_member();
"#;

const VERTEX_ADD_EXPANDED_CHECK_SQL: &str = r#"
ALTER TABLE vertex_usage_events
    ADD CONSTRAINT vertex_usage_events_operation_check_v26
    CHECK (operation IN (
        'audio_understanding','screen_understanding','episode_summarization',
        'episode_finalization','episode_reconciliation'
    )) NOT VALID;
"#;
const VERTEX_SWAP_EXPANDED_CHECK_SQL: &str = r#"
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid='vertex_usage_events'::regclass
           AND conname='vertex_usage_events_operation_check'
           AND convalidated
           AND pg_get_constraintdef(oid) =
               'CHECK ((operation = ANY (ARRAY[''audio_understanding''::text, ''screen_understanding''::text, ''episode_summarization''::text, ''episode_finalization''::text])))'
    ) THEN
        RAISE EXCEPTION 'schema-24 Vertex operation constraint is not the validated predecessor contract'
            USING ERRCODE='55000';
    END IF;
    ALTER TABLE vertex_usage_events
        DROP CONSTRAINT vertex_usage_events_operation_check;
    ALTER TABLE vertex_usage_events
        RENAME CONSTRAINT vertex_usage_events_operation_check_v26
        TO vertex_usage_events_operation_check;
END
$$;
"#;

const STEP_LEGACY_MEMBERSHIP_GUARD: &str = "legacy_membership_guard";
const STEP_ACCOUNT_DELETION_COMPATIBILITY: &str = "account_deletion_compatibility";
const STEP_COLD_OBJECTS: &str = "cold_objects";
const STEP_ACCOUNTS_COMPATIBILITY: &str = "accounts_compatibility";
const STEP_EPISODES_COMPATIBILITY: &str = "episodes_compatibility";
const STEP_MEMBERS_COMPATIBILITY: &str = "members_compatibility";
const STEP_VERTEX_OPERATION: &str = "vertex_operation";
const STEP_CAPTURE_SESSIONS_INDEX: &str = "capture_sessions_index";
const STEP_CAPTURE_EVENTS_INDEX: &str = "capture_events_index";
const RELEASE_STEP_MANIFEST: &str = "account_deletion_compatibility\nlegacy_membership_guard\ncold_objects\naccounts_compatibility\nepisodes_compatibility\nmembers_compatibility\nvertex_operation\ncapture_sessions_index\ncapture_events_index\n";
const RELEASE_STEP_NAMES: &[&str] = &[
    STEP_ACCOUNT_DELETION_COMPATIBILITY,
    STEP_LEGACY_MEMBERSHIP_GUARD,
    STEP_COLD_OBJECTS,
    STEP_ACCOUNTS_COMPATIBILITY,
    STEP_EPISODES_COMPATIBILITY,
    STEP_MEMBERS_COMPATIBILITY,
    STEP_VERTEX_OPERATION,
    STEP_CAPTURE_SESSIONS_INDEX,
    STEP_CAPTURE_EVENTS_INDEX,
];
const ACCOUNT_DELETION_COMPATIBILITY_DDL: &[&str] = &[ACCOUNT_DELETION_COMPATIBILITY_SQL];
const LEGACY_MEMBERSHIP_GUARD_DDL: &[&str] = &[LEGACY_MEMBERSHIP_INDEX_SQL];
const COLD_OBJECTS_DDL: &[&str] = &[COLD_OBJECTS_SQL];
const ACCOUNTS_COMPATIBILITY_DDL: &[&str] = &[ACCOUNTS_ARCHIVE_TRIGGER_SQL];
const EPISODES_COMPATIBILITY_DDL: &[&str] = &[
    EPISODES_ADD_STRUCTURE_STATE_SQL,
    EPISODES_STRUCTURE_DEFAULT_SQL,
    EPISODES_STRUCTURE_VALUES_SQL,
    EPISODES_STRUCTURE_REQUIRED_SQL,
    EPISODES_STRUCTURE_TRIGGER_SQL,
    EPISODES_HANDLE_TRIGGER_SQL,
    EPISODES_DELETE_TRIGGER_SQL,
];
const MEMBERS_COMPATIBILITY_DDL: &[&str] = &[EPISODE_MEMBERS_TRIGGER_SQL];
const VERTEX_OPERATION_DDL: &[&str] = &[
    VERTEX_ADD_EXPANDED_CHECK_SQL,
    VERTEX_SWAP_EXPANDED_CHECK_SQL,
];
const CAPTURE_SESSIONS_INDEX_DDL: &[&str] = &[CAPTURE_SESSIONS_INDEX_SQL];
const CAPTURE_EVENTS_INDEX_DDL: &[&str] = &[CAPTURE_EVENTS_INDEX_SQL];

// A step receipt binds both the exact embedded DDL and a deterministic
// PostgreSQL catalog projection captured in the same transaction. The
// projection includes columns/defaults/nullability, every constraint and
// index on new relations, function bodies, trigger identities, and rejects
// extra objects in the reserved v26 name families.
const STEP_CATALOG_EVIDENCE_SQL: &str = r#"
WITH relation_targets AS (
    SELECT relation.oid,relation.relname,relation.relkind,relation.relpersistence,
           relation.relrowsecurity,relation.relforcerowsecurity,relation.relreplident,
           relation.relam
     FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname=current_schema()
       AND (
            ($1='cold_objects' AND (
                relation.relname LIKE 'memory\_%' ESCAPE '\'
                OR relation.relname LIKE 'active\_episode\_members%' ESCAPE '\'))
         OR ($1 IN ('account_deletion_compatibility','accounts_compatibility')
             AND relation.relname='accounts')
         OR ($1='episodes_compatibility' AND relation.relname='episodes')
         OR ($1='members_compatibility' AND relation.relname='episode_members')
         OR ($1='vertex_operation' AND relation.relname='vertex_usage_events')
       )
), evidence(kind,name,definition) AS (
    SELECT 'relation',target.relname,
           concat_ws('|',target.relkind::text,target.relpersistence::text,
                     target.relrowsecurity::text,target.relforcerowsecurity::text,
                     target.relreplident::text,target.relam::text,
                     CASE WHEN target.relkind='p'
                          THEN coalesce(pg_get_partkeydef(target.oid),'') ELSE '' END)
      FROM relation_targets target
     WHERE $1='cold_objects'
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
     WHERE $1='cold_objects'
        OR ($1='episodes_compatibility' AND attribute.attname='structure_state')
    UNION ALL
    SELECT 'constraint',target.relname||'.'||constraint_state.conname,
           concat_ws('|',constraint_state.contype::text,
                     constraint_state.convalidated::text,
                     constraint_state.condeferrable::text,
                     constraint_state.condeferred::text,
                     pg_get_constraintdef(constraint_state.oid,true))
      FROM relation_targets target
     JOIN pg_constraint constraint_state ON constraint_state.conrelid=target.oid
     WHERE $1='cold_objects'
        OR ($1='account_deletion_compatibility'
            AND constraint_state.conname='accounts_status_check')
        OR ($1='episodes_compatibility'
            AND constraint_state.conname LIKE 'episodes_structure_state_%')
        OR ($1='vertex_operation'
            AND constraint_state.conname LIKE 'vertex_usage_events_operation_check%')
    UNION ALL
    SELECT 'index',table_state.relname||'.'||index_state.relname,
           concat_ws('|',catalog_index.indisunique::text,catalog_index.indisprimary::text,
                     catalog_index.indisexclusion::text,catalog_index.indimmediate::text,
                     catalog_index.indisvalid::text,catalog_index.indisready::text,
                     catalog_index.indislive::text,pg_get_indexdef(index_state.oid))
      FROM pg_index catalog_index
      JOIN pg_class index_state ON index_state.oid=catalog_index.indexrelid
      JOIN pg_class table_state ON table_state.oid=catalog_index.indrelid
      JOIN pg_namespace namespace ON namespace.oid=table_state.relnamespace
     WHERE namespace.nspname=current_schema()
       AND (
            ($1='cold_objects' AND (
                table_state.relname LIKE 'memory\_%' ESCAPE '\'
                OR table_state.relname LIKE 'active\_episode\_members%' ESCAPE '\'))
         OR ($1='legacy_membership_guard'
             AND index_state.relname LIKE 'episode_members_memory_source_%')
         OR ($1='capture_sessions_index'
             AND index_state.relname LIKE 'capture_sessions_reconciliation_%')
         OR ($1='capture_events_index'
             AND index_state.relname LIKE 'capture_events_reconciliation_%')
       )
    UNION ALL
    SELECT 'trigger',table_state.relname||'.'||trigger_state.tgname,
           concat_ws('|',trigger_state.tgenabled::text,
                     pg_get_triggerdef(trigger_state.oid,true),
                     function_state.proname)
      FROM pg_trigger trigger_state
      JOIN pg_class table_state ON table_state.oid=trigger_state.tgrelid
      JOIN pg_namespace namespace ON namespace.oid=table_state.relnamespace
      JOIN pg_proc function_state ON function_state.oid=trigger_state.tgfoid
     WHERE namespace.nspname=current_schema() AND NOT trigger_state.tgisinternal
       AND (($1='accounts_compatibility' AND table_state.relname='accounts')
         OR ($1='episodes_compatibility' AND table_state.relname='episodes')
         OR ($1='members_compatibility' AND table_state.relname='episode_members'))
    UNION ALL
    SELECT 'function',function_state.proname||'.'||pg_get_function_identity_arguments(function_state.oid),
           pg_get_functiondef(function_state.oid)
      FROM pg_proc function_state
      JOIN pg_namespace namespace ON namespace.oid=function_state.pronamespace
     WHERE $1='cold_objects' AND namespace.nspname=current_schema()
       AND function_state.proname IN (
            'install_memory_archive_for_account','install_active_memory_handle',
            'maintain_episode_structure_state','project_active_episode_member',
            'retire_deleted_memory')
)
SELECT coalesce(jsonb_agg(jsonb_build_array(kind,name,definition)
                          ORDER BY kind,name,definition),'[]'::jsonb)::text
  FROM evidence
"#;

const LEDGER_CATALOG_EVIDENCE_SQL: &str = r#"
WITH target_relations AS (
    SELECT relation.oid,relation.relname,relation.relkind,relation.relpersistence,
           relation.relrowsecurity,relation.relforcerowsecurity,relation.relreplident,
           relation.relam
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname=current_schema()
       AND relation.relname IN ('persistence_schema_releases',
                                'persistence_schema_release_steps')
), evidence(kind,name,definition) AS (
    SELECT 'relation',target.relname,
           concat_ws('|',target.relkind::text,target.relpersistence::text,
                     target.relrowsecurity::text,target.relforcerowsecurity::text,
                     target.relreplident::text,target.relam::text)
      FROM target_relations target
    UNION ALL
    SELECT 'column',target.relname||'.'||attribute.attnum::text||'.'||attribute.attname,
           concat_ws('|',format_type(attribute.atttypid,attribute.atttypmod),
                     attribute.attnotnull::text,attribute.attidentity::text,
                     attribute.attgenerated::text,
                     coalesce(pg_get_expr(default_value.adbin,default_value.adrelid),''),
                     attribute.attcollation::text)
      FROM target_relations target
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
      FROM target_relations target
      JOIN pg_constraint constraint_state ON constraint_state.conrelid=target.oid
    UNION ALL
    SELECT 'index',table_state.relname||'.'||index_state.relname,
           concat_ws('|',catalog_index.indisunique::text,catalog_index.indisprimary::text,
                     catalog_index.indisexclusion::text,catalog_index.indimmediate::text,
                     catalog_index.indisvalid::text,catalog_index.indisready::text,
                     catalog_index.indislive::text,pg_get_indexdef(index_state.oid))
      FROM pg_index catalog_index
      JOIN pg_class index_state ON index_state.oid=catalog_index.indexrelid
      JOIN target_relations table_state ON table_state.oid=catalog_index.indrelid
    UNION ALL
    SELECT 'column','persistence_schema.expanded_through_version',
           concat_ws('|',format_type(attribute.atttypid,attribute.atttypmod),
                     attribute.attnotnull::text,
                     coalesce(pg_get_expr(default_value.adbin,default_value.adrelid),''))
      FROM pg_attribute attribute
      LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid
       AND default_value.adnum=attribute.attnum
     WHERE attribute.attrelid='persistence_schema'::regclass
       AND attribute.attname='expanded_through_version' AND NOT attribute.attisdropped
    UNION ALL
    SELECT 'constraint','persistence_schema.'||constraint_state.conname,
           concat_ws('|',constraint_state.convalidated::text,
                     pg_get_constraintdef(constraint_state.oid,true))
      FROM pg_constraint constraint_state
     WHERE constraint_state.conrelid='persistence_schema'::regclass
       AND constraint_state.conname='persistence_schema_expand_monotonic_v26'
)
SELECT coalesce(jsonb_agg(jsonb_build_array(kind,name,definition)
                          ORDER BY kind,name,definition),'[]'::jsonb)::text
  FROM evidence
"#;

const PRISTINE_V26_PREFLIGHT_SQL: &str = r#"
SELECT
    NOT EXISTS(SELECT 1 FROM information_schema.columns
                WHERE table_schema=current_schema()
                  AND table_name='persistence_schema'
                  AND column_name='expanded_through_version')
AND to_regclass('public.persistence_schema_releases') IS NULL
AND to_regclass('public.persistence_schema_release_steps') IS NULL
AND NOT EXISTS(
    SELECT 1 FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname=current_schema()
      AND (relation.relname LIKE 'memory\_%' ESCAPE '\'
        OR relation.relname LIKE 'active\_episode\_members%' ESCAPE '\'
        OR relation.relname LIKE 'episode_members_memory_source_%'
        OR relation.relname LIKE 'capture_sessions_reconciliation_%'
        OR relation.relname LIKE 'capture_events_reconciliation_%'))
AND NOT EXISTS(
    SELECT 1 FROM information_schema.columns
     WHERE table_schema=current_schema() AND table_name='episodes'
       AND column_name='structure_state')
AND NOT EXISTS(
    SELECT 1 FROM pg_constraint constraint_state
     WHERE (constraint_state.conrelid='episodes'::regclass
            AND constraint_state.conname LIKE 'episodes_structure_state_%')
        OR (constraint_state.conrelid='vertex_usage_events'::regclass
            AND constraint_state.conname='vertex_usage_events_operation_check_v26'))
AND NOT EXISTS(
    SELECT 1 FROM pg_trigger trigger_state
     WHERE NOT trigger_state.tgisinternal
       AND trigger_state.tgname IN (
            'accounts_install_memory_archive','episodes_maintain_structure_state',
            'episodes_install_active_memory_handle','episodes_retire_deleted_memory',
            'episode_members_project_active'))
AND NOT EXISTS(
    SELECT 1 FROM pg_proc function_state
    JOIN pg_namespace namespace ON namespace.oid=function_state.pronamespace
    WHERE namespace.nspname=current_schema()
      AND function_state.proname IN (
            'install_memory_archive_for_account','install_active_memory_handle',
            'maintain_episode_structure_state','project_active_episode_member',
            'retire_deleted_memory'))
"#;

const CONTRACT_MANIFEST_VERSION: &str = "kioku-postgresql-memory-reconciliation-v26-online-v3";
const CONTRACT_PARTS: &[&str] = &[
    CONTRACT_MANIFEST_VERSION,
    RELEASE_LEDGER_SQL,
    ACCOUNT_DELETION_COMPATIBILITY_SQL,
    COLD_OBJECTS_SQL,
    EPISODES_ADD_STRUCTURE_STATE_SQL,
    EPISODES_STRUCTURE_DEFAULT_SQL,
    EPISODES_STRUCTURE_VALUES_SQL,
    EPISODES_STRUCTURE_REQUIRED_SQL,
    ACCOUNTS_ARCHIVE_TRIGGER_SQL,
    EPISODES_STRUCTURE_TRIGGER_SQL,
    EPISODES_HANDLE_TRIGGER_SQL,
    EPISODES_DELETE_TRIGGER_SQL,
    EPISODE_MEMBERS_TRIGGER_SQL,
    VERTEX_ADD_EXPANDED_CHECK_SQL,
    VERTEX_SWAP_EXPANDED_CHECK_SQL,
    LEGACY_MEMBERSHIP_INDEX_SQL,
    CAPTURE_SESSIONS_INDEX_SQL,
    CAPTURE_EVENTS_INDEX_SQL,
    EXPAND_RECEIPT_SQL,
    FINALIZE_SQL,
    STEP_CATALOG_EVIDENCE_SQL,
    LEDGER_CATALOG_EVIDENCE_SQL,
    PRISTINE_V26_PREFLIGHT_SQL,
    RELEASE_STEP_MANIFEST,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SchemaReleaseStatus {
    ExpandInProgress,
    Expanded,
    AlreadyExpanded,
    Finalized,
    AlreadyFinalized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SchemaReleaseResult {
    pub(crate) status: SchemaReleaseStatus,
    pub(crate) release_version: i64,
    pub(crate) schema_version: i64,
    pub(crate) expanded_through_version: Option<i64>,
    pub(crate) contract_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) finalization_receipt_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchemaFinalizationReceipt {
    pub(crate) contract: String,
    pub(crate) contract_version: u32,
    pub(crate) release_version: i64,
    pub(crate) expand_contract_sha256: String,
    pub(crate) candidate_image_digest: String,
    pub(crate) fleet_evidence_sha256: String,
    pub(crate) observed_at: String,
    pub(crate) expires_at: String,
    pub(crate) candidate_instances: u32,
    pub(crate) predecessor_instances: u32,
    pub(crate) unavailable_instances: u32,
    pub(crate) writer_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SchemaFinalizationSignature(Vec<u8>);

impl SchemaFinalizationSignature {
    pub(crate) fn from_base64(value: &str) -> Result<Self> {
        let bytes = BASE64_STANDARD.decode(value).map_err(|_| {
            EnclaveError::Config(
                "schema finalization signature must be canonical standard base64".into(),
            )
        })?;
        if bytes.len() != 64 || BASE64_STANDARD.encode(&bytes) != value {
            return Err(EnclaveError::Config(
                "schema finalization signature must be canonical standard base64 for 64 bytes"
                    .into(),
            ));
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedSchemaFinalizationReceipt {
    canonical_bytes: Vec<u8>,
    signature: SchemaFinalizationSignature,
    key_sha256: Vec<u8>,
    observed_at: i64,
    expires_at: i64,
}

impl VerifiedSchemaFinalizationReceipt {
    pub(crate) fn has_exact_canonical_transport(&self, supplied: &str) -> bool {
        supplied.as_bytes() == self.canonical_bytes
    }
}

#[derive(Clone, Debug)]
struct SchemaFinalizationTrustAnchor {
    public_key: [u8; 32],
    der_sha256: Vec<u8>,
}

#[derive(Debug)]
struct ReleaseProgress {
    phase: String,
    accounts_complete: bool,
    episodes_complete: bool,
    members_complete: bool,
}

#[derive(Debug)]
struct IndexState {
    valid: bool,
    ready: bool,
    unique: bool,
    definition: String,
}

fn contract_digest() -> Vec<u8> {
    let mut digest = Sha256::new();
    for part in CONTRACT_PARTS {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    digest.finalize().to_vec()
}

fn step_sql_parts(step_name: &str) -> Option<&'static [&'static str]> {
    match step_name {
        STEP_ACCOUNT_DELETION_COMPATIBILITY => Some(ACCOUNT_DELETION_COMPATIBILITY_DDL),
        STEP_LEGACY_MEMBERSHIP_GUARD => Some(LEGACY_MEMBERSHIP_GUARD_DDL),
        STEP_COLD_OBJECTS => Some(COLD_OBJECTS_DDL),
        STEP_ACCOUNTS_COMPATIBILITY => Some(ACCOUNTS_COMPATIBILITY_DDL),
        STEP_EPISODES_COMPATIBILITY => Some(EPISODES_COMPATIBILITY_DDL),
        STEP_MEMBERS_COMPATIBILITY => Some(MEMBERS_COMPATIBILITY_DDL),
        STEP_VERTEX_OPERATION => Some(VERTEX_OPERATION_DDL),
        STEP_CAPTURE_SESSIONS_INDEX => Some(CAPTURE_SESSIONS_INDEX_DDL),
        STEP_CAPTURE_EVENTS_INDEX => Some(CAPTURE_EVENTS_INDEX_DDL),
        _ => None,
    }
}

fn step_ddl_digest(step_name: &str) -> Result<Vec<u8>> {
    let parts = step_sql_parts(step_name)
        .ok_or_else(|| EnclaveError::Config(format!("unknown schema-release step {step_name}")))?;
    let mut digest = Sha256::new();
    digest.update((step_name.len() as u64).to_be_bytes());
    digest.update(step_name.as_bytes());
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    Ok(digest.finalize().to_vec())
}

fn evidence_digest(evidence: &str) -> Vec<u8> {
    Sha256::digest(evidence.as_bytes()).to_vec()
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

fn parse_lowercase_sha256(value: &str, field: &str) -> Result<Vec<u8>> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(EnclaveError::Config(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )));
    }
    let mut decoded = Vec::with_capacity(32);
    for pair in value.as_bytes().chunks_exact(2) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => unreachable!("validated lowercase hexadecimal byte"),
        };
        decoded.push((nibble(pair[0]) << 4) | nibble(pair[1]));
    }
    Ok(decoded)
}

fn schema_finalization_trust_anchor_from_values(
    public_key_der_base64: &str,
    expected_der_sha256: &str,
) -> Result<SchemaFinalizationTrustAnchor> {
    let der = BASE64_STANDARD.decode(public_key_der_base64).map_err(|_| {
        EnclaveError::Config(format!(
            "{SCHEMA_FINALIZATION_PUBLIC_KEY_ENV} must be canonical standard base64"
        ))
    })?;
    if BASE64_STANDARD.encode(&der) != public_key_der_base64
        || der.len() != ED25519_SPKI_PREFIX.len() + 32
        || !der.starts_with(ED25519_SPKI_PREFIX)
    {
        return Err(EnclaveError::Config(format!(
            "{SCHEMA_FINALIZATION_PUBLIC_KEY_ENV} must encode one Ed25519 SPKI DER public key"
        )));
    }
    let configured_sha256 = parse_lowercase_sha256(
        expected_der_sha256,
        SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256_ENV,
    )?;
    let actual_sha256 = Sha256::digest(&der).to_vec();
    if actual_sha256 != configured_sha256 {
        return Err(EnclaveError::Config(
            "schema finalization public key does not match its baked SHA-256 fingerprint".into(),
        ));
    }
    let public_key: [u8; 32] = der[ED25519_SPKI_PREFIX.len()..]
        .try_into()
        .map_err(|_| EnclaveError::Config("Ed25519 public key has invalid length".into()))?;
    Ok(SchemaFinalizationTrustAnchor {
        public_key,
        der_sha256: actual_sha256,
    })
}

fn configured_schema_finalization_trust_anchor() -> Result<SchemaFinalizationTrustAnchor> {
    let public_key = std::env::var(SCHEMA_FINALIZATION_PUBLIC_KEY_ENV).ok();
    let fingerprint = std::env::var(SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256_ENV).ok();
    #[cfg(test)]
    if public_key.is_none() && fingerprint.is_none() {
        return test_schema_finalization_trust_anchor();
    }
    let public_key = public_key.ok_or_else(|| {
        EnclaveError::Config(format!(
            "{SCHEMA_FINALIZATION_PUBLIC_KEY_ENV} must come from baked image configuration"
        ))
    })?;
    let fingerprint = fingerprint.ok_or_else(|| {
        EnclaveError::Config(format!(
            "{SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256_ENV} must come from baked image configuration"
        ))
    })?;
    schema_finalization_trust_anchor_from_values(&public_key, &fingerprint)
}

fn is_sha256_label(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn canonical_receipt_bytes(receipt: &SchemaFinalizationReceipt) -> Result<Vec<u8>> {
    let value = serde_json::to_value(receipt)?;
    let object = value.as_object().ok_or_else(|| {
        EnclaveError::Store("schema finalization receipt did not serialize as an object".into())
    })?;
    let sorted = object
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    let mut canonical = serde_json::to_vec(&sorted)?;
    canonical.push(b'\n');
    Ok(canonical)
}

fn validate_finalization_receipt_shape(
    receipt: &SchemaFinalizationReceipt,
    expected_contract: &[u8],
) -> Result<(i64, i64)> {
    if receipt.contract != "kioku.postgresql.schema-finalization"
        || receipt.contract_version != 1
        || receipt.release_version != EXPECTED_SCHEMA_VERSION
        || receipt.expand_contract_sha256 != sha256_label(expected_contract)
    {
        return Err(EnclaveError::Config(
            "schema finalization receipt does not bind the exact v26 expand contract".into(),
        ));
    }
    if !is_sha256_label(&receipt.candidate_image_digest)
        || !is_sha256_label(&receipt.fleet_evidence_sha256)
    {
        return Err(EnclaveError::Config(
            "schema finalization receipt digests must be lowercase sha256 labels".into(),
        ));
    }
    if receipt.candidate_instances == 0
        || receipt.predecessor_instances != 0
        || receipt.unavailable_instances != 0
        || receipt.writer_enabled
    {
        return Err(EnclaveError::Config(
            "schema finalization receipt must prove a writer-dark homogeneous available candidate fleet"
                .into(),
        ));
    }
    let observed_at = isotime::parse_epoch_millis(&receipt.observed_at).ok_or_else(|| {
        EnclaveError::Config("schema finalization observed_at is not RFC3339".into())
    })?;
    let expires_at = isotime::parse_epoch_millis(&receipt.expires_at).ok_or_else(|| {
        EnclaveError::Config("schema finalization expires_at is not RFC3339".into())
    })?;
    if isotime::format_epoch_millis(observed_at) != receipt.observed_at
        || isotime::format_epoch_millis(expires_at) != receipt.expires_at
        || expires_at <= observed_at
        || expires_at - observed_at > FLEET_RECEIPT_MAX_VALIDITY_MILLIS
    {
        return Err(EnclaveError::Config(
            "schema finalization receipt timestamps must be canonical UTC and valid for at most 15 minutes"
                .into(),
        ));
    }
    Ok((observed_at, expires_at))
}

fn verify_finalization_signature(
    receipt: SchemaFinalizationReceipt,
    signature: SchemaFinalizationSignature,
) -> Result<VerifiedSchemaFinalizationReceipt> {
    let anchor = configured_schema_finalization_trust_anchor()?;
    verify_finalization_signature_with_anchor(receipt, signature, anchor)
}

fn verify_finalization_signature_with_anchor(
    receipt: SchemaFinalizationReceipt,
    signature: SchemaFinalizationSignature,
    anchor: SchemaFinalizationTrustAnchor,
) -> Result<VerifiedSchemaFinalizationReceipt> {
    let expected_contract = contract_digest();
    let (observed_at, expires_at) =
        validate_finalization_receipt_shape(&receipt, &expected_contract)?;
    let canonical_bytes = canonical_receipt_bytes(&receipt)?;
    UnparsedPublicKey::new(&ED25519, &anchor.public_key)
        .verify(&canonical_bytes, signature.as_bytes())
        .map_err(|_| {
            EnclaveError::Config(
                "schema finalization receipt signature does not match the baked trust anchor"
                    .into(),
            )
        })?;
    Ok(VerifiedSchemaFinalizationReceipt {
        canonical_bytes,
        signature,
        key_sha256: anchor.der_sha256,
        observed_at,
        expires_at,
    })
}

pub(crate) fn verify_schema_finalization_authorization(
    receipt: SchemaFinalizationReceipt,
    signature: SchemaFinalizationSignature,
) -> Result<VerifiedSchemaFinalizationReceipt> {
    verify_finalization_signature(receipt, signature)
}

async fn acquire_release_connection(
    persistence: &PostgresPersistence,
) -> Result<PoolConnection<Postgres>> {
    let mut connection = persistence.pool.acquire().await?;
    let acquired =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock(hashtextextended($1,0))")
            .bind(RELEASE_ADVISORY_LOCK)
            .fetch_one(&mut *connection)
            .await?;
    if !acquired {
        return Err(EnclaveError::Conflict(
            "another PostgreSQL schema release runner owns the v26 session lock".into(),
        ));
    }
    Ok(connection)
}

async fn release_connection<T>(
    mut connection: PoolConnection<Postgres>,
    result: Result<T>,
) -> Result<T> {
    let unlocked =
        sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock(hashtextextended($1,0))")
            .bind(RELEASE_ADVISORY_LOCK)
            .fetch_one(&mut *connection)
            .await;
    match unlocked {
        Ok(true) => result,
        Ok(false) => {
            let _ = connection.close().await;
            match result {
                Err(error) => Err(error),
                Ok(_) => Err(EnclaveError::Store(
                    "PostgreSQL schema release session lock was not owned at release".into(),
                )),
            }
        }
        Err(unlock_error) => {
            let _ = connection.close().await;
            match result {
                Err(error) => Err(error),
                Ok(_) => Err(unlock_error.into()),
            }
        }
    }
}

async fn connection_schema_state(connection: &mut PgConnection) -> Result<InstalledSchemaState> {
    let row = sqlx::query(
        "SELECT version, \
                (to_jsonb(schema_marker)->>'expanded_through_version')::bigint \
                    AS expanded_through_version \
           FROM persistence_schema schema_marker WHERE singleton=true",
    )
    .fetch_optional(connection)
    .await?;
    row.as_ref()
        .map(installed_schema_state_from_row)
        .transpose()?
        .ok_or_else(|| {
            EnclaveError::Config("PostgreSQL persistence schema marker is missing".into())
        })
}

async fn step_catalog_evidence(connection: &mut PgConnection, step_name: &str) -> Result<String> {
    if !RELEASE_STEP_NAMES.contains(&step_name) {
        return Err(EnclaveError::Config(format!(
            "unknown schema-release step {step_name}"
        )));
    }
    Ok(sqlx::query_scalar::<_, String>(STEP_CATALOG_EVIDENCE_SQL)
        .bind(step_name)
        .fetch_one(connection)
        .await?)
}

async fn ledger_catalog_evidence(connection: &mut PgConnection) -> Result<String> {
    Ok(sqlx::query_scalar::<_, String>(LEDGER_CATALOG_EVIDENCE_SQL)
        .fetch_one(connection)
        .await?)
}

async fn verified_release_steps(
    connection: &mut PgConnection,
    require_complete: bool,
) -> Result<BTreeSet<String>> {
    let rows = sqlx::query(
        "SELECT release_version,step_name,ddl_sha256,catalog_sha256 \
           FROM persistence_schema_release_steps ORDER BY release_version,step_name",
    )
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() > RELEASE_STEP_NAMES.len() {
        return Err(EnclaveError::Config(
            "schema-release ledger contains extra step receipts".into(),
        ));
    }
    let mut completed = BTreeSet::new();
    for row in rows {
        let release_version: i64 = row.try_get("release_version")?;
        let step_name: String = row.try_get("step_name")?;
        if release_version != EXPECTED_SCHEMA_VERSION
            || !RELEASE_STEP_NAMES.contains(&step_name.as_str())
            || !completed.insert(step_name.clone())
        {
            return Err(EnclaveError::Config(format!(
                "schema-release ledger contains unknown or duplicate step {step_name}"
            )));
        }
        let stored_ddl: Vec<u8> = row.try_get("ddl_sha256")?;
        if stored_ddl != step_ddl_digest(&step_name)? {
            return Err(EnclaveError::Config(format!(
                "schema-release step {step_name} does not match embedded DDL"
            )));
        }
        let stored_catalog: Vec<u8> = row.try_get("catalog_sha256")?;
        let evidence = step_catalog_evidence(connection, &step_name).await?;
        if stored_catalog != evidence_digest(&evidence) {
            return Err(EnclaveError::Config(format!(
                "schema-release step {step_name} catalog evidence changed"
            )));
        }
    }
    if require_complete
        && (completed.len() != RELEASE_STEP_NAMES.len()
            || RELEASE_STEP_NAMES
                .iter()
                .any(|step| !completed.contains(*step)))
    {
        return Err(EnclaveError::Config(
            "schema-release ledger does not contain the complete exact step manifest".into(),
        ));
    }
    Ok(completed)
}

async fn verify_existing_release_ledger(
    connection: &mut PgConnection,
    expected_contract: &[u8],
) -> Result<ReleaseProgress> {
    let row = sqlx::query(
        "SELECT predecessor_version,protocol_version,contract_sha256, \
                bootstrap_catalog_sha256,phase,accounts_complete,episodes_complete, \
                members_complete, \
                (SELECT count(*) FROM persistence_schema_releases) AS release_row_count \
           FROM persistence_schema_releases WHERE release_version=$1",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_one(&mut *connection)
    .await?;
    let predecessor: i64 = row.try_get("predecessor_version")?;
    let protocol: i64 = row.try_get("protocol_version")?;
    let installed_contract: Vec<u8> = row.try_get("contract_sha256")?;
    let bootstrap_catalog: Vec<u8> = row.try_get("bootstrap_catalog_sha256")?;
    let release_row_count: i64 = row.try_get("release_row_count")?;
    let evidence = ledger_catalog_evidence(connection).await?;
    if release_row_count != 1
        || predecessor != MEMORY_RECONCILIATION_EXPAND_FROM_VERSION
        || protocol != RELEASE_PROTOCOL_VERSION
        || installed_contract != expected_contract
        || bootstrap_catalog != evidence_digest(&evidence)
    {
        return Err(EnclaveError::Config(
            "schema-release ledger does not match the embedded v26 bootstrap contract".into(),
        ));
    }
    verified_release_steps(connection, false).await?;
    Ok(ReleaseProgress {
        phase: row.try_get("phase")?,
        accounts_complete: row.try_get("accounts_complete")?,
        episodes_complete: row.try_get("episodes_complete")?,
        members_complete: row.try_get("members_complete")?,
    })
}

async fn bootstrap_or_verify_release_ledger(
    connection: &mut PgConnection,
    expected_contract: &[u8],
) -> Result<ReleaseProgress> {
    let state = sqlx::query_as::<_, (bool, bool, bool)>(
        "SELECT \
            EXISTS(SELECT 1 FROM information_schema.columns \
                    WHERE table_schema=current_schema() \
                      AND table_name='persistence_schema' \
                      AND column_name='expanded_through_version'), \
            to_regclass('public.persistence_schema_releases') IS NOT NULL, \
            to_regclass('public.persistence_schema_release_steps') IS NOT NULL",
    )
    .fetch_one(&mut *connection)
    .await?;
    if state == (false, false, false) {
        let pristine = sqlx::query_scalar::<_, bool>(PRISTINE_V26_PREFLIGHT_SQL)
            .fetch_one(&mut *connection)
            .await?;
        if !pristine {
            return Err(EnclaveError::Config(
                "v26 catalog names are not pristine before release-ledger bootstrap".into(),
            ));
        }
        let mut transaction = connection.begin().await?;
        sqlx::raw_sql(
            "SET LOCAL lock_timeout='2s'; \
             SET LOCAL statement_timeout='10s'; \
             SET LOCAL idle_in_transaction_session_timeout='15s';",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::raw_sql(RELEASE_LEDGER_SQL)
            .execute(&mut *transaction)
            .await?;
        let evidence = ledger_catalog_evidence(&mut transaction).await?;
        sqlx::query(
            "INSERT INTO persistence_schema_releases( \
                 release_version,predecessor_version,protocol_version,contract_sha256, \
                 bootstrap_catalog_sha256,phase) \
             VALUES($1,$2,$3,$4,$5,'installing')",
        )
        .bind(EXPECTED_SCHEMA_VERSION)
        .bind(MEMORY_RECONCILIATION_EXPAND_FROM_VERSION)
        .bind(RELEASE_PROTOCOL_VERSION)
        .bind(expected_contract)
        .bind(evidence_digest(&evidence))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
    } else if state != (true, true, true) {
        return Err(EnclaveError::Config(
            "v26 release-ledger bootstrap is partial or collides with an existing object".into(),
        ));
    }

    verify_existing_release_ledger(connection, expected_contract).await
}

async fn execute_receipted_ddl(
    connection: &mut PgConnection,
    step_name: &'static str,
) -> Result<()> {
    if verified_release_steps(connection, false)
        .await?
        .contains(step_name)
    {
        return Ok(());
    }
    let sql_parts = step_sql_parts(step_name)
        .ok_or_else(|| EnclaveError::Config(format!("unknown schema-release step {step_name}")))?;
    let mut transaction = connection.begin().await?;
    sqlx::raw_sql(
        "SET LOCAL lock_timeout='2s'; \
         SET LOCAL statement_timeout='10s'; \
         SET LOCAL idle_in_transaction_session_timeout='20s';",
    )
    .execute(&mut *transaction)
    .await?;
    let phase = sqlx::query_scalar::<_, String>(
        "SELECT phase FROM persistence_schema_releases \
          WHERE release_version=$1 FOR UPDATE",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_one(&mut *transaction)
    .await?;
    if phase != "installing" {
        return Err(EnclaveError::Config(format!(
            "cannot install schema-release step {step_name} during phase {phase}"
        )));
    }
    for sql in sql_parts {
        sqlx::raw_sql(*sql).execute(&mut *transaction).await?;
    }
    let evidence = step_catalog_evidence(&mut transaction, step_name).await?;
    if evidence == "[]" {
        return Err(EnclaveError::Store(format!(
            "schema-release step {step_name} produced no catalog evidence"
        )));
    }
    sqlx::query(
        "INSERT INTO persistence_schema_release_steps( \
             release_version,step_name,ddl_sha256,catalog_sha256) \
         VALUES($1,$2,$3,$4)",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .bind(step_name)
    .bind(step_ddl_digest(step_name)?)
    .bind(evidence_digest(&evidence))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    verified_release_steps(connection, false).await?;
    Ok(())
}

async fn execute_concurrent_index_statement(
    connection: &mut PgConnection,
    sql: &'static str,
) -> Result<()> {
    let previous = sqlx::query_as::<_, (String, String)>(
        "SELECT current_setting('lock_timeout'),current_setting('statement_timeout')",
    )
    .fetch_one(&mut *connection)
    .await?;
    sqlx::query(
        "SELECT set_config('lock_timeout','2s',false), \
                set_config('statement_timeout','15min',false)",
    )
    .execute(&mut *connection)
    .await?;
    let statement_result = sqlx::raw_sql(sql).execute(&mut *connection).await;
    let reset_result = sqlx::query(
        "SELECT set_config('lock_timeout',$1,false), \
                set_config('statement_timeout',$2,false)",
    )
    .bind(previous.0)
    .bind(previous.1)
    .execute(&mut *connection)
    .await;
    match (statement_result, reset_result) {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(error), _) => Err(error.into()),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

async fn index_state(
    connection: &mut PgConnection,
    index_name: &str,
) -> Result<Option<IndexState>> {
    let row = sqlx::query(
        "SELECT index_state.indisvalid,index_state.indisready,index_state.indisunique, \
                pg_get_indexdef(index_state.indexrelid) AS definition \
           FROM pg_index index_state \
           JOIN pg_class index_class ON index_class.oid=index_state.indexrelid \
           JOIN pg_namespace namespace ON namespace.oid=index_class.relnamespace \
          WHERE namespace.nspname=current_schema() AND index_class.relname=$1",
    )
    .bind(index_name)
    .fetch_optional(connection)
    .await?;
    row.map(|row| {
        Ok(IndexState {
            valid: row.try_get("indisvalid")?,
            ready: row.try_get("indisready")?,
            unique: row.try_get("indisunique")?,
            definition: row.try_get("definition")?,
        })
    })
    .transpose()
}

async fn drop_concurrent_index(connection: &mut PgConnection, index_name: &str) -> Result<()> {
    let sql = match index_name {
        "episode_members_memory_source_unique_idx" => {
            "DROP INDEX CONCURRENTLY IF EXISTS episode_members_memory_source_unique_idx"
        }
        "capture_sessions_reconciliation_horizon_idx" => {
            "DROP INDEX CONCURRENTLY IF EXISTS capture_sessions_reconciliation_horizon_idx"
        }
        "capture_events_reconciliation_horizon_idx" => {
            "DROP INDEX CONCURRENTLY IF EXISTS capture_events_reconciliation_horizon_idx"
        }
        _ => {
            return Err(EnclaveError::Config(format!(
                "refusing to drop unrecognized schema-release index {index_name}"
            )))
        }
    };
    execute_concurrent_index_statement(connection, sql).await
}

async fn ensure_concurrent_index(
    connection: &mut PgConnection,
    index_name: &str,
    sql: &'static str,
) -> Result<()> {
    let (unique, expected_definition) = expected_index_definition(index_name)?;
    if let Some(state) = index_state(connection, index_name).await? {
        if state.unique != unique
            || normalize_index_definition(&state.definition) != expected_definition
        {
            return Err(EnclaveError::Config(format!(
                "schema-release index {index_name} exists with an unexpected definition"
            )));
        }
        if !state.valid || !state.ready {
            drop_concurrent_index(connection, index_name).await?;
        } else {
            return Ok(());
        }
    }

    if let Err(error) = execute_concurrent_index_statement(connection, sql).await {
        if let Some(state) = index_state(connection, index_name).await? {
            if state.unique != unique
                || normalize_index_definition(&state.definition) != expected_definition
            {
                return Err(EnclaveError::Config(format!(
                    "schema-release index {index_name} was left with an unexpected definition: {error}"
                )));
            }
            if !state.valid || !state.ready {
                drop_concurrent_index(connection, index_name).await?;
            }
        }
        let duplicate_source = matches!(
            &error,
            EnclaveError::Postgres(postgres_error)
                if postgres_error
                    .as_database_error()
                    .and_then(|database_error| database_error.code())
                    .as_deref()
                    == Some("23505")
        );
        let detail = if unique && duplicate_source {
            "repair any source assigned to more than one legacy episode, then retry"
        } else {
            "the interrupted concurrent index was removed; retry the release"
        };
        return Err(EnclaveError::Config(format!(
            "could not install production-safe index {index_name}: {error}; {detail}"
        )));
    }

    let state = index_state(connection, index_name)
        .await?
        .ok_or_else(|| EnclaveError::Store(format!("index {index_name} was not installed")))?;
    let definition = normalize_index_definition(&state.definition);
    if !state.valid || !state.ready || state.unique != unique || definition != expected_definition {
        return Err(EnclaveError::Store(format!(
            "index {index_name} did not match the reviewed online contract"
        )));
    }
    Ok(())
}

fn normalize_index_definition(definition: &str) -> String {
    definition
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
        .replace("public.", "")
}

fn expected_index_definition(index_name: &str) -> Result<(bool, String)> {
    let (unique, definition) = match index_name {
        "episode_members_memory_source_unique_idx" => (
            true,
            "CREATE UNIQUE INDEX episode_members_memory_source_unique_idx ON episode_members USING btree (account_id, record_type, record_id)",
        ),
        "capture_sessions_reconciliation_horizon_idx" => (
            false,
            "CREATE INDEX capture_sessions_reconciliation_horizon_idx ON capture_sessions USING btree (account_id, GREATEST(last_event_at, COALESCE(ended_at, last_event_at)), started_at, id)",
        ),
        "capture_events_reconciliation_horizon_idx" => (
            false,
            "CREATE INDEX capture_events_reconciliation_horizon_idx ON capture_events USING btree (account_id, ended_at, started_at, capture_session_id)",
        ),
        _ => {
            return Err(EnclaveError::Config(format!(
                "unknown schema-release index {index_name}"
            )))
        }
    };
    Ok((unique, normalize_index_definition(definition)))
}

async fn execute_receipted_concurrent_index(
    connection: &mut PgConnection,
    step_name: &'static str,
    index_name: &'static str,
    sql: &'static str,
) -> Result<()> {
    if verified_release_steps(connection, false)
        .await?
        .contains(step_name)
    {
        ensure_concurrent_index(connection, index_name, sql).await?;
        return Ok(());
    }
    ensure_concurrent_index(connection, index_name, sql).await?;
    let mut transaction = connection.begin().await?;
    sqlx::raw_sql(
        "SET LOCAL lock_timeout='2s'; \
         SET LOCAL statement_timeout='10s'; \
         SET LOCAL idle_in_transaction_session_timeout='15s';",
    )
    .execute(&mut *transaction)
    .await?;
    let phase = sqlx::query_scalar::<_, String>(
        "SELECT phase FROM persistence_schema_releases \
          WHERE release_version=$1 FOR UPDATE",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_one(&mut *transaction)
    .await?;
    if phase != "installing" {
        return Err(EnclaveError::Config(
            "cannot receipt a concurrent index outside the installing phase".into(),
        ));
    }
    let evidence = step_catalog_evidence(&mut transaction, step_name).await?;
    sqlx::query(
        "INSERT INTO persistence_schema_release_steps( \
             release_version,step_name,ddl_sha256,catalog_sha256) \
         VALUES($1,$2,$3,$4)",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .bind(step_name)
    .bind(step_ddl_digest(step_name)?)
    .bind(evidence_digest(&evidence))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    verified_release_steps(connection, false).await?;
    Ok(())
}

async fn load_release_progress(connection: &mut PgConnection) -> Result<ReleaseProgress> {
    let row = sqlx::query(
        "SELECT phase,accounts_complete,episodes_complete,members_complete \
           FROM persistence_schema_releases WHERE release_version=$1",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_one(connection)
    .await?;
    Ok(ReleaseProgress {
        phase: row.try_get("phase")?,
        accounts_complete: row.try_get("accounts_complete")?,
        episodes_complete: row.try_get("episodes_complete")?,
        members_complete: row.try_get("members_complete")?,
    })
}

async fn mark_backfill_started(connection: &mut PgConnection) -> Result<()> {
    verified_release_steps(connection, true).await?;
    let mut transaction = connection.begin().await?;
    sqlx::raw_sql(
        "SET LOCAL lock_timeout='2s'; \
         SET LOCAL statement_timeout='10s'; \
         SET LOCAL idle_in_transaction_session_timeout='15s';",
    )
    .execute(&mut *transaction)
    .await?;
    let affected = sqlx::query(
        "UPDATE persistence_schema_releases \
            SET phase='backfilling',updated_at=now() \
          WHERE release_version=$1 AND phase IN ('installing','backfilling')",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if affected != 1 {
        return Err(EnclaveError::Config(
            "schema release cannot enter backfill from its current phase".into(),
        ));
    }
    transaction.commit().await?;
    Ok(())
}

async fn backfill_accounts_batch(connection: &mut PgConnection) -> Result<()> {
    let mut transaction = connection.begin().await?;
    sqlx::raw_sql(
        "SET LOCAL lock_timeout='2s'; \
         SET LOCAL statement_timeout='5s'; \
         SET LOCAL idle_in_transaction_session_timeout='10s';",
    )
    .execute(&mut *transaction)
    .await?;
    let cursor = sqlx::query_scalar::<_, Option<String>>(
        "SELECT accounts_cursor FROM persistence_schema_releases \
          WHERE release_version=$1 AND phase='backfilling' FOR UPDATE",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_one(&mut *transaction)
    .await?;
    let rows = sqlx::query(
        "SELECT id FROM accounts \
          WHERE ($1::text IS NULL OR id>$1) \
          ORDER BY id LIMIT $2 FOR KEY SHARE",
    )
    .bind(cursor.as_deref())
    .bind(BACKFILL_BATCH_SIZE)
    .fetch_all(&mut *transaction)
    .await?;
    if rows.is_empty() {
        sqlx::query(
            "UPDATE persistence_schema_releases \
                SET accounts_complete=true,updated_at=now() \
              WHERE release_version=$1 AND phase='backfilling'",
        )
        .bind(EXPECTED_SCHEMA_VERSION)
        .execute(&mut *transaction)
        .await?;
    } else {
        let account_ids = rows
            .iter()
            .map(|row| row.try_get::<String, _>("id"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        sqlx::query(
            "INSERT INTO memory_archive_state(account_id,revision) \
             SELECT account_id,0 FROM unnest($1::text[]) account_id \
             ON CONFLICT(account_id) DO NOTHING",
        )
        .bind(&account_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE persistence_schema_releases \
                SET accounts_cursor=$2,accounts_scanned=accounts_scanned+$3,updated_at=now() \
              WHERE release_version=$1 AND phase='backfilling'",
        )
        .bind(EXPECTED_SCHEMA_VERSION)
        .bind(account_ids.last().expect("nonempty account batch"))
        .bind(account_ids.len() as i64)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn backfill_episodes_batch(connection: &mut PgConnection) -> Result<()> {
    let mut transaction = connection.begin().await?;
    sqlx::raw_sql(
        "SET LOCAL lock_timeout='2s'; \
         SET LOCAL statement_timeout='5s'; \
         SET LOCAL idle_in_transaction_session_timeout='10s';",
    )
    .execute(&mut *transaction)
    .await?;
    let cursor = sqlx::query(
        "SELECT episodes_cursor_account_id,episodes_cursor_id \
           FROM persistence_schema_releases \
          WHERE release_version=$1 AND phase='backfilling' FOR UPDATE",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_one(&mut *transaction)
    .await?;
    let cursor_account: Option<String> = cursor.try_get("episodes_cursor_account_id")?;
    let cursor_id: Option<i64> = cursor.try_get("episodes_cursor_id")?;
    let rows = sqlx::query(
        "SELECT account_id,id FROM episodes \
          WHERE ($1::text IS NULL OR (account_id,id)>($1,$2::bigint)) \
          ORDER BY account_id,id LIMIT $3 FOR NO KEY UPDATE",
    )
    .bind(cursor_account.as_deref())
    .bind(cursor_id)
    .bind(BACKFILL_BATCH_SIZE)
    .fetch_all(&mut *transaction)
    .await?;
    if rows.is_empty() {
        sqlx::query(
            "UPDATE persistence_schema_releases \
                SET episodes_complete=true,updated_at=now() \
              WHERE release_version=$1 AND phase='backfilling'",
        )
        .bind(EXPECTED_SCHEMA_VERSION)
        .execute(&mut *transaction)
        .await?;
    } else {
        let account_ids = rows
            .iter()
            .map(|row| row.try_get::<String, _>("account_id"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let episode_ids = rows
            .iter()
            .map(|row| row.try_get::<i64, _>("id"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        sqlx::query(
            "INSERT INTO memory_handles(account_id,episode_id,state) \
             SELECT account_id,episode_id,'active' \
               FROM unnest($1::text[],$2::bigint[]) pair(account_id,episode_id) \
             ON CONFLICT(account_id,episode_id) DO NOTHING",
        )
        .bind(&account_ids)
        .bind(&episode_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE episodes episode \
                SET structure_state=CASE WHEN episode.finalized_at IS NULL \
                                         THEN 'draft' ELSE 'reconciled' END \
               FROM unnest($1::text[],$2::bigint[]) pair(account_id,episode_id) \
              WHERE episode.account_id=pair.account_id AND episode.id=pair.episode_id",
        )
        .bind(&account_ids)
        .bind(&episode_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE persistence_schema_releases \
                SET episodes_cursor_account_id=$2,episodes_cursor_id=$3, \
                    episodes_scanned=episodes_scanned+$4,updated_at=now() \
              WHERE release_version=$1 AND phase='backfilling'",
        )
        .bind(EXPECTED_SCHEMA_VERSION)
        .bind(account_ids.last().expect("nonempty episode batch"))
        .bind(episode_ids.last().expect("nonempty episode batch"))
        .bind(account_ids.len() as i64)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn backfill_members_batch(connection: &mut PgConnection) -> Result<()> {
    let mut transaction = connection.begin().await?;
    sqlx::raw_sql(
        "SET LOCAL lock_timeout='2s'; \
         SET LOCAL statement_timeout='5s'; \
         SET LOCAL idle_in_transaction_session_timeout='10s';",
    )
    .execute(&mut *transaction)
    .await?;
    let cursor = sqlx::query(
        "SELECT members_cursor_account_id,members_cursor_episode_id, \
                members_cursor_record_type,members_cursor_record_id \
           FROM persistence_schema_releases \
          WHERE release_version=$1 AND phase='backfilling' FOR UPDATE",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_one(&mut *transaction)
    .await?;
    let cursor_account: Option<String> = cursor.try_get("members_cursor_account_id")?;
    let cursor_episode: Option<i64> = cursor.try_get("members_cursor_episode_id")?;
    let cursor_type: Option<String> = cursor.try_get("members_cursor_record_type")?;
    let cursor_record: Option<i64> = cursor.try_get("members_cursor_record_id")?;
    let rows = sqlx::query(
        "SELECT account_id,episode_id,record_type,record_id FROM episode_members \
          WHERE ($1::text IS NULL OR (account_id,episode_id,record_type,record_id) \
                >($1,$2::bigint,$3::text,$4::bigint)) \
          ORDER BY account_id,episode_id,record_type,record_id \
          LIMIT $5 FOR KEY SHARE",
    )
    .bind(cursor_account.as_deref())
    .bind(cursor_episode)
    .bind(cursor_type.as_deref())
    .bind(cursor_record)
    .bind(BACKFILL_BATCH_SIZE)
    .fetch_all(&mut *transaction)
    .await?;
    if rows.is_empty() {
        sqlx::query(
            "UPDATE persistence_schema_releases \
                SET members_complete=true,updated_at=now() \
              WHERE release_version=$1 AND phase='backfilling'",
        )
        .bind(EXPECTED_SCHEMA_VERSION)
        .execute(&mut *transaction)
        .await?;
    } else {
        let account_ids = rows
            .iter()
            .map(|row| row.try_get::<String, _>("account_id"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let episode_ids = rows
            .iter()
            .map(|row| row.try_get::<i64, _>("episode_id"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let record_types = rows
            .iter()
            .map(|row| row.try_get::<String, _>("record_type"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let record_ids = rows
            .iter()
            .map(|row| row.try_get::<i64, _>("record_id"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        sqlx::query(
            "INSERT INTO active_episode_members(account_id,episode_id,record_type,record_id) \
             SELECT account_id,episode_id,record_type,record_id \
               FROM unnest($1::text[],$2::bigint[],$3::text[],$4::bigint[]) \
                    member(account_id,episode_id,record_type,record_id) \
             ON CONFLICT(account_id,episode_id,record_type,record_id) DO NOTHING",
        )
        .bind(&account_ids)
        .bind(&episode_ids)
        .bind(&record_types)
        .bind(&record_ids)
        .execute(&mut *transaction)
        .await?;
        let last = account_ids.len() - 1;
        sqlx::query(
            "UPDATE persistence_schema_releases \
                SET members_cursor_account_id=$2,members_cursor_episode_id=$3, \
                    members_cursor_record_type=$4,members_cursor_record_id=$5, \
                    members_scanned=members_scanned+$6,updated_at=now() \
              WHERE release_version=$1 AND phase='backfilling'",
        )
        .bind(EXPECTED_SCHEMA_VERSION)
        .bind(&account_ids[last])
        .bind(episode_ids[last])
        .bind(&record_types[last])
        .bind(record_ids[last])
        .bind(account_ids.len() as i64)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn run_backfill_budget(connection: &mut PgConnection, max_batches: usize) -> Result<bool> {
    for _ in 0..max_batches {
        let progress = load_release_progress(connection).await?;
        if progress.phase != "backfilling" {
            return Err(EnclaveError::Config(format!(
                "schema release has unexpected backfill phase {}",
                progress.phase
            )));
        }
        if !progress.accounts_complete {
            backfill_accounts_batch(connection).await?;
        } else if !progress.episodes_complete {
            backfill_episodes_batch(connection).await?;
        } else if !progress.members_complete {
            backfill_members_batch(connection).await?;
        } else {
            return Ok(true);
        }
    }
    let progress = load_release_progress(connection).await?;
    Ok(progress.accounts_complete && progress.episodes_complete && progress.members_complete)
}

async fn verify_installation_barrier(connection: &mut PgConnection) -> Result<()> {
    verified_release_steps(connection, true).await?;
    Ok(())
}

async fn verify_catalog_contract(connection: &mut PgConnection) -> Result<()> {
    verify_installation_barrier(connection).await
}

async fn verify_backfill_invariants(connection: &mut PgConnection) -> Result<()> {
    let invariants_hold = sqlx::query_scalar::<_, bool>(
        "SELECT \
            NOT EXISTS( \
                SELECT 1 FROM accounts account \
                LEFT JOIN memory_archive_state archive ON archive.account_id=account.id \
                WHERE archive.account_id IS NULL) \
        AND NOT EXISTS( \
                SELECT 1 FROM episodes episode \
                LEFT JOIN memory_handles handle \
                  ON handle.account_id=episode.account_id AND handle.episode_id=episode.id \
                WHERE handle.episode_id IS NULL OR handle.state<>'active' \
                   OR episode.structure_state IS NULL \
                   OR (episode.finalized_at IS NOT NULL AND episode.structure_state<>'reconciled')) \
        AND NOT EXISTS( \
                SELECT 1 FROM episode_members member \
                LEFT JOIN active_episode_members active \
                  ON active.account_id=member.account_id \
                 AND active.episode_id=member.episode_id \
                 AND active.record_type=member.record_type \
                 AND active.record_id=member.record_id \
                WHERE active.record_id IS NULL) \
        AND NOT EXISTS( \
                SELECT 1 FROM active_episode_members active \
                LEFT JOIN episode_members member \
                  ON member.account_id=active.account_id \
                 AND member.episode_id=active.episode_id \
                 AND member.record_type=active.record_type \
                 AND member.record_id=active.record_id \
                WHERE member.record_id IS NULL) \
        AND NOT EXISTS( \
                SELECT 1 FROM memory_handles handle \
                LEFT JOIN episodes episode \
                  ON episode.account_id=handle.account_id AND episode.id=handle.episode_id \
                WHERE handle.state='active' AND episode.id IS NULL)",
    )
    .fetch_one(connection)
    .await?;
    if !invariants_hold {
        return Err(EnclaveError::Store(
            "v26 backfill invariant changed before expand receipt; retry repairs the projection"
                .into(),
        ));
    }
    Ok(())
}

fn release_result(
    status: SchemaReleaseStatus,
    state: InstalledSchemaState,
    finalization_receipt_sha256: Option<Vec<u8>>,
) -> SchemaReleaseResult {
    SchemaReleaseResult {
        status,
        release_version: EXPECTED_SCHEMA_VERSION,
        schema_version: state.version,
        expanded_through_version: state.expanded_through_version,
        contract_sha256: sha256_label(&contract_digest()),
        finalization_receipt_sha256: finalization_receipt_sha256.as_deref().map(sha256_label),
    }
}

async fn verify_release_row(
    connection: &mut PgConnection,
    serving_state: ServingSchemaState,
) -> Result<Option<Vec<u8>>> {
    let expected_contract = contract_digest();
    verify_existing_release_ledger(connection, &expected_contract).await?;
    let row = sqlx::query(
        "SELECT predecessor_version,protocol_version,contract_sha256,phase, \
                accounts_complete,episodes_complete,members_complete, \
                finalization_receipt::text AS finalization_receipt_json, \
                finalization_receipt_sha256,finalization_receipt_signature, \
                finalization_receipt_key_sha256 \
           FROM persistence_schema_releases WHERE release_version=$1",
    )
    .bind(EXPECTED_SCHEMA_VERSION)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| EnclaveError::Config("v26 schema release receipt is missing".into()))?;
    let predecessor: i64 = row.try_get("predecessor_version")?;
    let protocol: i64 = row.try_get("protocol_version")?;
    let installed_contract: Vec<u8> = row.try_get("contract_sha256")?;
    let phase: String = row.try_get("phase")?;
    let all_backfills_complete = row.try_get::<bool, _>("accounts_complete")?
        && row.try_get::<bool, _>("episodes_complete")?
        && row.try_get::<bool, _>("members_complete")?;
    if predecessor != MEMORY_RECONCILIATION_EXPAND_FROM_VERSION
        || protocol != RELEASE_PROTOCOL_VERSION
        || installed_contract != expected_contract
        || !all_backfills_complete
    {
        return Err(EnclaveError::Config(
            "v26 schema release receipt does not match the embedded contract".into(),
        ));
    }
    verify_catalog_contract(connection).await?;

    match serving_state {
        ServingSchemaState::ExpandedTransition if phase == "expanded" => {
            let receipt: Option<String> = row.try_get("finalization_receipt_json")?;
            let digest: Option<Vec<u8>> = row.try_get("finalization_receipt_sha256")?;
            let signature: Option<Vec<u8>> = row.try_get("finalization_receipt_signature")?;
            let key_sha256: Option<Vec<u8>> = row.try_get("finalization_receipt_key_sha256")?;
            if receipt.is_some() || digest.is_some() || signature.is_some() || key_sha256.is_some()
            {
                return Err(EnclaveError::Config(
                    "expanded schema unexpectedly contains finalization authorization".into(),
                ));
            }
            Ok(None)
        }
        ServingSchemaState::Finalized if phase == "finalized" => {
            let receipt_json: String = row.try_get("finalization_receipt_json")?;
            let stored_digest: Vec<u8> = row.try_get("finalization_receipt_sha256")?;
            let stored_signature: Vec<u8> = row.try_get("finalization_receipt_signature")?;
            let stored_key_sha256: Vec<u8> = row.try_get("finalization_receipt_key_sha256")?;
            let receipt: SchemaFinalizationReceipt = serde_json::from_str(&receipt_json)?;
            let verified = verify_finalization_signature(
                receipt,
                SchemaFinalizationSignature(stored_signature),
            )?;
            let computed_digest = Sha256::digest(&verified.canonical_bytes).to_vec();
            if stored_digest != computed_digest || stored_key_sha256 != verified.key_sha256 {
                return Err(EnclaveError::Config(
                    "durable schema finalization authorization does not verify".into(),
                ));
            }
            Ok(Some(stored_digest))
        }
        _ => Err(EnclaveError::Config(format!(
            "schema marker and durable release phase disagree: {serving_state:?}/{phase}"
        ))),
    }
}

impl PostgresPersistence {
    /// Install or resume the complete v26 expand while leaving the predecessor
    /// marker at 24. Each invocation has a fixed batch budget; `ExpandInProgress`
    /// is a successful durable checkpoint and the same command resumes it.
    pub(crate) async fn expand_memory_reconciliation_release_schema(
        &self,
    ) -> Result<SchemaReleaseResult> {
        let mut connection = acquire_release_connection(self).await?;
        let result = self
            .expand_memory_reconciliation_release_schema_locked(
                &mut connection,
                MAX_BACKFILL_BATCHES_PER_RUN,
            )
            .await;
        release_connection(connection, result).await
    }

    #[cfg(test)]
    pub(super) async fn expand_memory_reconciliation_release_schema_with_batch_budget(
        &self,
        max_backfill_batches: usize,
    ) -> Result<SchemaReleaseResult> {
        let mut connection = acquire_release_connection(self).await?;
        let result = self
            .expand_memory_reconciliation_release_schema_locked(
                &mut connection,
                max_backfill_batches,
            )
            .await;
        release_connection(connection, result).await
    }

    async fn expand_memory_reconciliation_release_schema_locked(
        &self,
        connection: &mut PgConnection,
        max_backfill_batches: usize,
    ) -> Result<SchemaReleaseResult> {
        let initial = connection_schema_state(connection).await?;
        match initial {
            InstalledSchemaState {
                version: EXPECTED_SCHEMA_VERSION,
                expanded_through_version: Some(EXPECTED_SCHEMA_VERSION),
            } => {
                let receipt_digest =
                    verify_release_row(connection, ServingSchemaState::Finalized).await?;
                return Ok(release_result(
                    SchemaReleaseStatus::AlreadyFinalized,
                    initial,
                    receipt_digest,
                ));
            }
            InstalledSchemaState {
                version: MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
                expanded_through_version: Some(EXPECTED_SCHEMA_VERSION),
            } => {
                verify_release_row(connection, ServingSchemaState::ExpandedTransition).await?;
                return Ok(release_result(
                    SchemaReleaseStatus::AlreadyExpanded,
                    initial,
                    None,
                ));
            }
            InstalledSchemaState {
                version: MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
                expanded_through_version: None,
            } => {}
            state => {
                return Err(EnclaveError::Config(format!(
                    "memory reconciliation expand requires pristine or receipted schema 24; found {}/{}",
                    state.version,
                    state
                        .expanded_through_version
                        .map(|version| version.to_string())
                        .unwrap_or_else(|| "none".into()),
                )))
            }
        }

        let expected_contract = contract_digest();
        let progress = bootstrap_or_verify_release_ledger(connection, &expected_contract).await?;
        if !matches!(progress.phase.as_str(), "installing" | "backfilling") {
            return Err(EnclaveError::Config(format!(
                "unreceipted schema marker has impossible release phase {}",
                progress.phase
            )));
        }

        // Install the additive schema-25 account status value as part of this
        // receipted expand without advancing the marker that the live v24
        // predecessor checks. The step first proves the exact v24 constraint.
        execute_receipted_ddl(connection, STEP_ACCOUNT_DELETION_COMPATIBILITY).await?;

        // The next product-table action is the legacy uniqueness guard. Its
        // concurrent build is followed by an exact catalog snapshot and a
        // durable step receipt; an interrupted valid build is receipted only
        // after its entire normalized definition matches this binary.
        execute_receipted_concurrent_index(
            connection,
            STEP_LEGACY_MEMBERSHIP_GUARD,
            "episode_members_memory_source_unique_idx",
            LEGACY_MEMBERSHIP_INDEX_SQL,
        )
        .await?;

        // New relations, indexes, and trigger functions are collision-refusing
        // and commit atomically with their exact catalog receipt. Populated
        // relation changes remain in separate short bounded transactions.
        execute_receipted_ddl(connection, STEP_COLD_OBJECTS).await?;
        execute_receipted_ddl(connection, STEP_ACCOUNTS_COMPATIBILITY).await?;
        execute_receipted_ddl(connection, STEP_EPISODES_COMPATIBILITY).await?;
        execute_receipted_ddl(connection, STEP_MEMBERS_COMPATIBILITY).await?;

        // The v24 check proves every existing operation belongs to the v26
        // superset. Adding the successor NOT VALID check protects new writes;
        // the old validated constraint is then swapped in one bounded metadata
        // transaction without a validation scan.
        execute_receipted_ddl(connection, STEP_VERTEX_OPERATION).await?;

        execute_receipted_concurrent_index(
            connection,
            STEP_CAPTURE_SESSIONS_INDEX,
            "capture_sessions_reconciliation_horizon_idx",
            CAPTURE_SESSIONS_INDEX_SQL,
        )
        .await?;
        execute_receipted_concurrent_index(
            connection,
            STEP_CAPTURE_EVENTS_INDEX,
            "capture_events_reconciliation_horizon_idx",
            CAPTURE_EVENTS_INDEX_SQL,
        )
        .await?;

        verify_installation_barrier(connection).await?;
        mark_backfill_started(connection).await?;
        if !run_backfill_budget(connection, max_backfill_batches).await? {
            let state = connection_schema_state(connection).await?;
            if state != initial {
                return Err(EnclaveError::Store(
                    "in-progress v26 backfill changed the predecessor schema marker".into(),
                ));
            }
            return Ok(release_result(
                SchemaReleaseStatus::ExpandInProgress,
                state,
                None,
            ));
        }

        verify_catalog_contract(connection).await?;
        verify_backfill_invariants(connection).await?;
        let mut transaction = connection.begin().await?;
        sqlx::raw_sql(
            "SET LOCAL lock_timeout='2s'; \
             SET LOCAL statement_timeout='15s'; \
             SET LOCAL idle_in_transaction_session_timeout='20s';",
        )
        .execute(&mut *transaction)
        .await?;
        verify_catalog_contract(&mut transaction).await?;
        let receipted = sqlx::query(EXPAND_RECEIPT_SQL)
            .bind(&expected_contract)
            .fetch_optional(&mut *transaction)
            .await?;
        if receipted.is_none() {
            return Err(EnclaveError::Conflict(
                "v26 expand receipt preconditions changed before marker publication".into(),
            ));
        }
        transaction.commit().await?;

        let expanded = connection_schema_state(connection).await?;
        let serving_state = classify_serving_schema(expanded)?;
        if serving_state != ServingSchemaState::ExpandedTransition {
            return Err(EnclaveError::Store(
                "v26 expand did not publish the 24/26 compatibility marker".into(),
            ));
        }
        verify_release_row(connection, serving_state).await?;
        Ok(release_result(
            SchemaReleaseStatus::Expanded,
            expanded,
            None,
        ))
    }

    /// Finalize only when the caller supplies a fresh strict ADR-0041 fleet
    /// receipt. The receipt and marker flip commit atomically; a literal phase
    /// confirmation without this evidence can never advance schema 24.
    pub(crate) async fn finalize_memory_reconciliation_release_schema(
        &self,
        authorization: &VerifiedSchemaFinalizationReceipt,
    ) -> Result<SchemaReleaseResult> {
        let mut connection = acquire_release_connection(self).await?;
        let result = self
            .finalize_memory_reconciliation_release_schema_locked(&mut connection, authorization)
            .await;
        release_connection(connection, result).await
    }

    async fn finalize_memory_reconciliation_release_schema_locked(
        &self,
        connection: &mut PgConnection,
        authorization: &VerifiedSchemaFinalizationReceipt,
    ) -> Result<SchemaReleaseResult> {
        let expected_contract = contract_digest();
        let receipt_digest = Sha256::digest(&authorization.canonical_bytes).to_vec();
        let canonical_receipt_json = String::from_utf8(authorization.canonical_bytes.clone())
            .map_err(|error| {
                EnclaveError::Store(format!(
                    "canonical schema finalization receipt is not UTF-8: {error}"
                ))
            })?;
        let initial = connection_schema_state(connection).await?;
        if initial
            == (InstalledSchemaState {
                version: EXPECTED_SCHEMA_VERSION,
                expanded_through_version: Some(EXPECTED_SCHEMA_VERSION),
            })
        {
            let installed_digest = verify_release_row(connection, ServingSchemaState::Finalized)
                .await?
                .ok_or_else(|| {
                    EnclaveError::Store("finalized schema receipt hash is missing".into())
                })?;
            if installed_digest != receipt_digest {
                return Err(EnclaveError::Config(
                    "schema is already finalized with a different fleet receipt".into(),
                ));
            }
            return Ok(release_result(
                SchemaReleaseStatus::AlreadyFinalized,
                initial,
                Some(installed_digest),
            ));
        }
        if initial
            != (InstalledSchemaState {
                version: MEMORY_RECONCILIATION_EXPAND_FROM_VERSION,
                expanded_through_version: Some(EXPECTED_SCHEMA_VERSION),
            })
        {
            return Err(EnclaveError::Config(format!(
                "memory reconciliation finalize requires receipted 24/26 expand; found {}/{}",
                initial.version,
                initial
                    .expanded_through_version
                    .map(|version| version.to_string())
                    .unwrap_or_else(|| "none".into()),
            )));
        }
        verify_release_row(connection, ServingSchemaState::ExpandedTransition).await?;
        verify_backfill_invariants(connection).await?;
        let database_now = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        )
        .fetch_one(&mut *connection)
        .await?;
        if authorization.observed_at > database_now
            || authorization.expires_at
                < database_now.saturating_add(FLEET_RECEIPT_MIN_REMAINING_MILLIS)
        {
            return Err(EnclaveError::Config(
                "schema finalization fleet receipt lacks the required 60-second commit margin"
                    .into(),
            ));
        }

        let mut transaction = connection.begin().await?;
        sqlx::raw_sql(
            "SET LOCAL lock_timeout='2s'; \
             SET LOCAL statement_timeout='15s'; \
             SET LOCAL idle_in_transaction_session_timeout='20s';",
        )
        .execute(&mut *transaction)
        .await?;
        if transaction_schema_state(&mut transaction).await? != initial {
            return Err(EnclaveError::Conflict(
                "schema marker changed before finalization receipt publication".into(),
            ));
        }
        verify_catalog_contract(&mut transaction).await?;
        let finalized = sqlx::query(FINALIZE_SQL)
            .bind(canonical_receipt_json)
            .bind(&receipt_digest)
            .bind(authorization.signature.as_bytes())
            .bind(&authorization.key_sha256)
            .bind(&expected_contract)
            .fetch_optional(&mut *transaction)
            .await?;
        if finalized.is_none() {
            return Err(EnclaveError::Conflict(
                "schema finalization receipt preconditions changed before publication".into(),
            ));
        }
        transaction.commit().await?;

        let state = connection_schema_state(connection).await?;
        if classify_serving_schema(state)? != ServingSchemaState::Finalized {
            return Err(EnclaveError::Store(
                "v26 finalization did not publish the 26/26 marker".into(),
            ));
        }
        let installed_digest = verify_release_row(connection, ServingSchemaState::Finalized)
            .await?
            .ok_or_else(|| EnclaveError::Store("finalization receipt did not persist".into()))?;
        Ok(release_result(
            SchemaReleaseStatus::Finalized,
            state,
            Some(installed_digest),
        ))
    }

    pub(crate) async fn verify_schema(&self) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        let state = connection_schema_state(&mut connection).await?;
        let serving_state = classify_serving_schema(state)?;
        verify_release_row(&mut connection, serving_state).await?;
        Ok(())
    }

    /// A receipted 24/26 expand is reader-compatible with a live v24 fleet but
    /// can never authorize topology publication. The writer requires a 26/26
    /// marker and a strict persisted fleet receipt whose canonical hash verifies.
    pub(crate) async fn verify_reconciliation_writer_schema(&self) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        let state = connection_schema_state(&mut connection).await?;
        if classify_serving_schema(state)? != ServingSchemaState::Finalized {
            return Err(EnclaveError::Config(format!(
                "memory reconciliation writer requires finalized PostgreSQL schema version {EXPECTED_SCHEMA_VERSION}"
            )));
        }
        if verify_release_row(&mut connection, ServingSchemaState::Finalized)
            .await?
            .is_none()
        {
            return Err(EnclaveError::Config(
                "memory reconciliation writer requires a persisted fleet finalization receipt"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn test_finalization_receipt() -> SchemaFinalizationReceipt {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock must follow the Unix epoch")
        .as_millis() as i64;
    SchemaFinalizationReceipt {
        contract: "kioku.postgresql.schema-finalization".into(),
        contract_version: 1,
        release_version: EXPECTED_SCHEMA_VERSION,
        expand_contract_sha256: sha256_label(&contract_digest()),
        candidate_image_digest: format!("sha256:{}", "1".repeat(64)),
        fleet_evidence_sha256: format!("sha256:{}", "2".repeat(64)),
        observed_at: isotime::format_epoch_millis(now - 1_000),
        expires_at: isotime::format_epoch_millis(now + 10 * 60 * 1_000),
        candidate_instances: 2,
        predecessor_instances: 0,
        unavailable_instances: 0,
        writer_enabled: false,
    }
}

#[cfg(test)]
fn test_schema_finalization_key_pair() -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ])
    .expect("RFC 8032 Ed25519 seed must be valid")
}

#[cfg(test)]
fn test_schema_finalization_trust_anchor() -> Result<SchemaFinalizationTrustAnchor> {
    use ring::signature::KeyPair as _;

    let key_pair = test_schema_finalization_key_pair();
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(key_pair.public_key().as_ref());
    schema_finalization_trust_anchor_from_values(
        &BASE64_STANDARD.encode(&der),
        &lowercase_hex(&Sha256::digest(&der)),
    )
}

#[cfg(test)]
pub(super) fn test_finalization_authorization() -> VerifiedSchemaFinalizationReceipt {
    let receipt = test_finalization_receipt();
    test_verify_finalization_receipt(receipt).expect("test receipt signature must verify")
}

#[cfg(test)]
pub(super) fn test_verify_finalization_receipt(
    receipt: SchemaFinalizationReceipt,
) -> Result<VerifiedSchemaFinalizationReceipt> {
    let signature = test_schema_finalization_key_pair()
        .sign(&canonical_receipt_bytes(&receipt).expect("test receipt must canonicalize"));
    verify_finalization_signature_with_anchor(
        receipt,
        SchemaFinalizationSignature(signature.as_ref().to_vec()),
        test_schema_finalization_trust_anchor()?,
    )
}

#[cfg(test)]
pub(super) fn test_reject_tampered_finalization_signature(
    receipt: SchemaFinalizationReceipt,
) -> Result<VerifiedSchemaFinalizationReceipt> {
    let mut signature = test_schema_finalization_key_pair()
        .sign(&canonical_receipt_bytes(&receipt).expect("test receipt must canonicalize"))
        .as_ref()
        .to_vec();
    signature[0] ^= 1;
    verify_finalization_signature_with_anchor(
        receipt,
        SchemaFinalizationSignature(signature),
        test_schema_finalization_trust_anchor()?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_contract_hash_binds_every_release_fragment() {
        assert_eq!(contract_digest().len(), 32);
        assert!(CONTRACT_PARTS.contains(&LEGACY_MEMBERSHIP_INDEX_SQL));
        assert!(CONTRACT_PARTS.contains(&CAPTURE_SESSIONS_INDEX_SQL));
        assert!(CONTRACT_PARTS.contains(&EXPAND_RECEIPT_SQL));
        assert!(CONTRACT_PARTS.contains(&FINALIZE_SQL));
        assert!(CONTRACT_PARTS.contains(&STEP_CATALOG_EVIDENCE_SQL));
        assert!(CONTRACT_PARTS.contains(&LEDGER_CATALOG_EVIDENCE_SQL));
        assert!(CONTRACT_PARTS.contains(&PRISTINE_V26_PREFLIGHT_SQL));
        assert!(CONTRACT_PARTS.contains(&RELEASE_STEP_MANIFEST));
    }

    #[test]
    fn fleet_receipt_is_strict_writer_dark_and_short_lived() {
        let contract = contract_digest();
        let receipt = test_finalization_receipt();
        assert!(validate_finalization_receipt_shape(&receipt, &contract).is_ok());

        let mut predecessor_present = receipt.clone();
        predecessor_present.predecessor_instances = 1;
        assert!(validate_finalization_receipt_shape(&predecessor_present, &contract).is_err());

        let mut writer_enabled = receipt.clone();
        writer_enabled.writer_enabled = true;
        assert!(validate_finalization_receipt_shape(&writer_enabled, &contract).is_err());

        let mut stale = receipt;
        let observed = isotime::parse_epoch_millis(&stale.observed_at).unwrap();
        stale.expires_at =
            isotime::format_epoch_millis(observed + FLEET_RECEIPT_MAX_VALIDITY_MILLIS + 1);
        assert!(validate_finalization_receipt_shape(&stale, &contract).is_err());
    }

    #[test]
    fn fleet_receipt_signature_binds_exact_canonical_bytes_and_baked_anchor() {
        let authorization = test_finalization_authorization();
        assert_eq!(authorization.signature.as_bytes().len(), 64);
        assert_eq!(authorization.key_sha256.len(), 32);
        assert_eq!(authorization.canonical_bytes.last(), Some(&b'\n'));
        assert!(authorization.has_exact_canonical_transport(
            std::str::from_utf8(&authorization.canonical_bytes).unwrap()
        ));
        assert!(!authorization.has_exact_canonical_transport("{}"));

        let mut changed = test_finalization_receipt();
        changed.candidate_instances += 1;
        assert!(verify_finalization_signature_with_anchor(
            changed,
            authorization.signature.clone(),
            test_schema_finalization_trust_anchor().unwrap()
        )
        .is_err());
        let mut wrong_der = ED25519_SPKI_PREFIX.to_vec();
        wrong_der.extend_from_slice(&[0x42; 32]);
        let wrong_anchor = schema_finalization_trust_anchor_from_values(
            &BASE64_STANDARD.encode(&wrong_der),
            &lowercase_hex(&Sha256::digest(&wrong_der)),
        )
        .unwrap();
        let wrong_anchor_receipt = test_finalization_receipt();
        let wrong_anchor_signature = test_schema_finalization_key_pair()
            .sign(&canonical_receipt_bytes(&wrong_anchor_receipt).unwrap());
        assert!(verify_finalization_signature_with_anchor(
            wrong_anchor_receipt,
            SchemaFinalizationSignature(wrong_anchor_signature.as_ref().to_vec()),
            wrong_anchor
        )
        .is_err());
        assert!(SchemaFinalizationSignature::from_base64("not-base64").is_err());
        let noncanonical = BASE64_STANDARD
            .encode([0_u8; 64])
            .trim_end_matches('=')
            .to_owned();
        assert!(SchemaFinalizationSignature::from_base64(&noncanonical).is_err());
        assert!(schema_finalization_trust_anchor_from_values(
            &BASE64_STANDARD.encode([0_u8; 44]),
            &"0".repeat(64)
        )
        .is_err());
        let mut valid_der = ED25519_SPKI_PREFIX.to_vec();
        valid_der.extend_from_slice(&[0x42; 32]);
        assert!(schema_finalization_trust_anchor_from_values(
            &BASE64_STANDARD.encode(valid_der),
            &"0".repeat(64)
        )
        .is_err());
    }

    #[test]
    fn expand_contract_has_no_blocking_backfill_or_nonconcurrent_hot_index() {
        let cold_objects = COLD_OBJECTS_SQL
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!cold_objects.contains("UPDATE episodes"));
        assert!(!cold_objects
            .contains("INSERT INTO memory_handles(account_id,episode_id,state) SELECT"));
        assert!(
            !cold_objects.contains("INSERT INTO memory_archive_state(account_id,revision) SELECT")
        );
        assert!(!cold_objects.contains(
            "INSERT INTO active_episode_members(account_id,episode_id,record_type,record_id) SELECT"
        ));
        assert!(LEGACY_MEMBERSHIP_INDEX_SQL.contains("CREATE UNIQUE INDEX CONCURRENTLY"));
        assert!(CAPTURE_SESSIONS_INDEX_SQL.contains("CREATE INDEX CONCURRENTLY"));
        assert!(CAPTURE_EVENTS_INDEX_SQL.contains("CREATE INDEX CONCURRENTLY"));
        assert!(!EXPAND_RECEIPT_SQL.contains("SET version=26"));
        assert!(FINALIZE_SQL.contains("finalization_receipt=$1::jsonb"));
        assert!(FINALIZE_SQL.contains("finalization_receipt_signature=$3"));
        assert!(FINALIZE_SQL.contains("clock_timestamp()+interval '60 seconds'"));
        assert!(FINALIZE_SQL.contains("SET version=26"));
    }
}
