//! Typed canonical finalized-episode delivery data shared by outbound channels.
//!
//! PostgreSQL delivery claims carry a fully decoded immutable episode snapshot,
//! so provider workers never perform an unfenced content read.

use serde::{Deserialize, Serialize};

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
