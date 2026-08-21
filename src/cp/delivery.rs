//! Typed canonical finalized-episode delivery data and database loader.
//!
//! Shared by outbound channels (webhooks and native email) to load
//! finalized episode details safely from the per-user encrypted store.

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::cp::CpState;
use crate::error::{wal_domain, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionDetail {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionItemDetail {
    pub text: String,
    pub owner: String,
    pub due_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkDetail {
    pub url: String,
    pub label: String,
    pub why_it_matters: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedEpisode {
    pub episode_id: i64,
    pub title: String,
    pub started_at: String,
    pub ended_at: String,
    pub finalized_at: String,
    pub episode_type: Option<String>,
    pub participants: Vec<String>,
    pub overview: String,
    pub decisions: Vec<DecisionDetail>,
    pub action_items: Vec<ActionItemDetail>,
    pub important_links: Vec<LinkDetail>,
    pub open_questions: Vec<String>,
}

pub fn parse_string_list(raw: Option<String>) -> Vec<String> {
    raw.and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default()
}

pub async fn load_finalized_episode(
    state: &CpState,
    user_id: &str,
    episode_id: i64,
) -> Result<Option<FinalizedEpisode>> {
    // ADR-0022 D4: the brief join is not migrated. Every outbound channel
    // gates its own sweep before reaching here, so this is the backstop —
    // and it must REFUSE, never answer `Ok(None)`: the webhook worker reads
    // `None` as `event_data_missing` and terminalises the delivery, so a
    // silent empty here would destroy the outbox instead of deferring it.
    if let Some(error) = state.wal_domain_refusal(user_id, wal_domain::DELIVERY_FINALIZED_EPISODE) {
        return Err(error);
    }
    let user = user_id.to_string();
    state
        .store
        .with_user(&user, move |conn| {
            let row = conn
                .query_row(
                    "SELECT e.title, e.started_at, e.ended_at, e.finalized_at, e.type,
                            e.participants, b.overview, b.decisions, b.action_items,
                            b.important_links, b.open_questions
                     FROM episodes e
                     JOIN episode_final_briefs b ON b.episode_id = e.id
                     WHERE e.id = ?1",
                    [episode_id],
                    |r| {
                        Ok(FinalizedEpisode {
                            episode_id,
                            title: r.get(0)?,
                            started_at: r.get(1)?,
                            ended_at: r.get(2)?,
                            finalized_at: r.get(3)?,
                            episode_type: r.get(4)?,
                            participants: parse_string_list(r.get(5)?),
                            overview: r.get(6)?,
                            decisions: serde_json::from_str(&r.get::<_, String>(7)?)
                                .unwrap_or_default(),
                            action_items: serde_json::from_str(&r.get::<_, String>(8)?)
                                .unwrap_or_default(),
                            important_links: serde_json::from_str(&r.get::<_, String>(9)?)
                                .unwrap_or_default(),
                            open_questions: parse_string_list(r.get(10)?),
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_string_list_roundtrip() {
        assert_eq!(parse_string_list(None), Vec::<String>::new());
        assert_eq!(
            parse_string_list(Some("[\"Alice\",\"Bob\"]".to_string())),
            vec!["Alice".to_string(), "Bob".to_string()]
        );
        assert_eq!(
            parse_string_list(Some("invalid".to_string())),
            Vec::<String>::new()
        );
    }

    /// ADR-0022 D4. The finalized-brief loader is deferred, and it must REFUSE
    /// rather than answer `Ok(None)`: the webhook worker reads `None` as
    /// `event_data_missing` and terminalises the delivery, so a silent empty
    /// would destroy the outbox instead of deferring it.
    #[tokio::test]
    async fn a_deferred_brief_load_refuses_instead_of_reporting_no_brief() {
        use crate::cp::wal_gate_test_support::{select_wal_authoritative, state};
        use crate::error::{wal_domain, EnclaveError};

        let state = state();
        let user_id = "delivery-deferred-user";
        select_wal_authoritative(&state.store, user_id);

        match load_finalized_episode(&state, user_id, 1).await {
            Err(EnclaveError::WalDomainUnmigrated(domain)) => {
                assert_eq!(domain, wal_domain::DELIVERY_FINALIZED_EPISODE);
            }
            Ok(None) => panic!("a deferred brief must never be reported as absent"),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
}
