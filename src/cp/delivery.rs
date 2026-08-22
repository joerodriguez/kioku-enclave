//! Typed canonical finalized-episode delivery data and database loader.
//!
//! Shared by outbound channels (webhooks and native email) to load
//! finalized episode details safely from the per-user encrypted store.

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::cp::CpState;
use crate::error::Result;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizedEpisodeLoad {
    Missing,
    Malformed(&'static str),
    Present(Box<FinalizedEpisode>),
}

pub async fn load_finalized_episode(
    state: &CpState,
    user_id: &str,
    episode_id: i64,
) -> Result<FinalizedEpisodeLoad> {
    state
        .store
        .wal_authoritative_read(user_id, move |conn| {
            let row = conn
                .query_row(
                    "SELECT e.title, e.started_at, e.ended_at, e.finalized_at, e.type,
                            e.participants, b.overview, b.decisions, b.action_items,
                            b.important_links, b.open_questions
                     FROM episodes e
                     JOIN episode_final_briefs b ON b.episode_id = e.id
                     WHERE e.id = ?1 AND e.finalization_status = 'complete'
                       AND e.finalized_at IS NOT NULL",
                    [episode_id],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, Option<String>>(4)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, String>(6)?,
                            r.get::<_, String>(7)?,
                            r.get::<_, String>(8)?,
                            r.get::<_, String>(9)?,
                            r.get::<_, String>(10)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                title,
                started_at,
                ended_at,
                finalized_at,
                episode_type,
                participants,
                overview,
                decisions,
                action_items,
                important_links,
                open_questions,
            )) = row
            else {
                return Ok(FinalizedEpisodeLoad::Missing);
            };
            let malformed = FinalizedEpisodeLoad::Malformed;
            Ok(FinalizedEpisodeLoad::Present(Box::new(FinalizedEpisode {
                episode_id,
                title,
                started_at,
                ended_at,
                finalized_at,
                episode_type,
                participants: match participants {
                    Some(raw) => match serde_json::from_str(&raw) {
                        Ok(value) => value,
                        Err(_) => return Ok(malformed("participants")),
                    },
                    None => Vec::new(),
                },
                overview,
                decisions: match serde_json::from_str(&decisions) {
                    Ok(value) => value,
                    Err(_) => return Ok(malformed("decisions")),
                },
                action_items: match serde_json::from_str(&action_items) {
                    Ok(value) => value,
                    Err(_) => return Ok(malformed("action_items")),
                },
                important_links: match serde_json::from_str(&important_links) {
                    Ok(value) => value,
                    Err(_) => return Ok(malformed("important_links")),
                },
                open_questions: match serde_json::from_str(&open_questions) {
                    Ok(value) => value,
                    Err(_) => return Ok(malformed("open_questions")),
                },
            })))
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A selected archive without its serving authority must still refuse;
    /// genuine absence alone is `Ok(Missing)`. This distinction prevents an
    /// authority outage from being mistaken for a terminal missing brief.
    #[tokio::test]
    async fn unavailable_selected_brief_authority_refuses_instead_of_reporting_absence() {
        use crate::cp::wal_gate_test_support::{select_wal_authoritative, state};
        use crate::error::EnclaveError;

        let state = state();
        let user_id = "delivery-deferred-user";
        select_wal_authoritative(&state.store, user_id);

        match load_finalized_episode(&state, user_id, 1).await {
            Err(EnclaveError::Store(message)) => {
                assert!(message.contains("serving authority"), "{message}");
            }
            Ok(FinalizedEpisodeLoad::Missing) => {
                panic!("an unavailable brief must never be reported as absent")
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn genuine_absence_is_none_but_malformed_finalized_json_fails_closed() {
        use crate::cp::wal_gate_test_support::state;

        let state = state();
        let user_id = "legacy-delivery-loader";
        assert_eq!(
            load_finalized_episode(&state, user_id, 1).await.unwrap(),
            FinalizedEpisodeLoad::Missing
        );
        state
            .store
            .with_user(user_id, |connection| {
                connection.execute_batch(
                    "INSERT INTO episodes
                       (id,started_at,ended_at,finalized_at,title,substance,finalization_status)
                     VALUES
                       (1,'2026-08-20T19:00:00.000Z','2026-08-20T19:30:00.000Z',
                        '2026-08-20T19:31:00.000Z','Malformed brief','normal','complete');
                     INSERT INTO episode_final_briefs
                       (episode_id,overview,decisions,action_items,important_links,open_questions)
                     VALUES (1,'overview','not-json','[]','[]','[]');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            load_finalized_episode(&state, user_id, 1).await,
            Ok(FinalizedEpisodeLoad::Malformed("decisions"))
        ));
    }
}
