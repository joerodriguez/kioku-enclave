//! v6 qualification for the source-closed runtime, not a claim of source completion.
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

use super::{
    aggregate_audit::FormationAudit, memory_reconciliation::MAX_SOURCE_COMPONENTS_PER_SWEEP,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceGraphAudit {
    pub(crate) inventory_rows: i64,
    pub(crate) inventory_bounded: bool,
    pub(crate) candidate_drafts: i64,
    pub(crate) candidate_components: i64,
    pub(crate) max_components_per_account: i64,
    pub(crate) blocked_components: i64,
    pub(crate) oversized_components: i64,
    pub(crate) sweep_component_limit: i64,
}

impl SourceGraphAudit {
    pub(super) fn valid(&self) -> bool {
        [
            self.inventory_rows,
            self.candidate_drafts,
            self.candidate_components,
            self.max_components_per_account,
            self.blocked_components,
            self.oversized_components,
        ]
        .into_iter()
        .all(|count| count >= 0)
            && self.inventory_rows <= 100_001
            && self.inventory_bounded == (self.inventory_rows <= 100_000)
            && self.candidate_drafts <= self.inventory_rows
            && self.candidate_components <= self.candidate_drafts
            && (self.candidate_components == 0) == (self.candidate_drafts == 0)
            && (self.max_components_per_account == 0) == (self.candidate_components == 0)
            && self.max_components_per_account <= self.candidate_components
            && self.blocked_components <= self.candidate_components
            && self.oversized_components <= self.candidate_components
            && self.sweep_component_limit == MAX_SOURCE_COMPONENTS_PER_SWEEP as i64
    }

    pub(super) fn formation_eligible(&self, formation: &FormationAudit) -> bool {
        self.valid()
            && self.inventory_bounded
            && self.blocked_components == 0
            && self.oversized_components == 0
            && self.max_components_per_account <= self.sweep_component_limit
            && [
                formation.nonterminal_pages_for_finished_receipts,
                formation.staged_response_pages,
                formation.legacy_processing_claims,
                formation.legacy_expired_claims,
                formation.legacy_retry_due_claims,
                formation.legacy_retry_future_claims,
                formation.retry_due_receipts,
                formation.retry_future_receipts,
                formation.expired_processing_receipts,
            ]
            .into_iter()
            .all(|count| count == 0)
    }
}

pub(super) async fn snapshot(
    connection: &mut PgConnection,
) -> crate::error::Result<SourceGraphAudit> {
    let payload: String = sqlx::query_scalar(concat!(
        include_str!("reconciliation_source_components.sql"),
        "SELECT jsonb_build_object(
            'inventory_rows',(SELECT count(*) FROM inventory),
            'inventory_bounded',(SELECT count(*)<=100000 FROM inventory),
            'candidate_drafts',coalesce(sum(fresh_drafts),0),
            'candidate_components',count(*),
            'max_components_per_account',coalesce((SELECT max(n) FROM (
                SELECT count(*) n FROM candidate_components GROUP BY account_id) accounts),0),
            'blocked_components',count(*) FILTER(WHERE blocked_drafts>0 OR atoms=0),
            'oversized_components',count(*) FILTER(WHERE drafts>32 OR atoms>4000 OR sessions>256),
            'sweep_component_limit',$2::bigint)::text FROM candidate_components"
    ))
    .bind(Option::<&str>::None)
    .bind(MAX_SOURCE_COMPONENTS_PER_SWEEP as i64)
    .fetch_one(connection)
    .await?;
    Ok(serde_json::from_str(&payload)?)
}

/// Private SQL-to-SQL capacity input, never part of the content-free public
/// audit report. Each owner belongs to one complete component, so context
/// sources are counted once even when several fresh drafts share that context.
pub(super) async fn context_finalizer_bounds(
    connection: &mut PgConnection,
) -> crate::error::Result<String> {
    Ok(sqlx::query_scalar(concat!(
        include_str!("reconciliation_source_components.sql"),
        "SELECT coalesce(jsonb_agg(jsonb_build_object('account_id',account_id,'atoms',atoms)), '[]'::jsonb)::text
           FROM (SELECT component.account_id,sum(owner.atoms)::bigint AS atoms
                   FROM candidate_components component JOIN owners owner
                     ON owner.account_id=component.account_id AND owner.id=ANY(component.draft_ids)
                  WHERE NOT owner.needs_organization
                  GROUP BY component.account_id) context"
    ))
    .bind(Option::<&str>::None)
    .fetch_one(connection)
    .await?)
}
