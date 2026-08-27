use async_trait::async_trait;

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuotaResult {
    pub(crate) allowed: bool,
    pub(crate) quota: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VertexWorkClass {
    Audio,
    Screen,
    DerivedText,
}

impl VertexWorkClass {
    pub(crate) fn quota_name(self) -> &'static str {
        match self {
            Self::Audio => "vertex_audio_output_tokens_per_day",
            Self::Screen => "vertex_screen_output_tokens_per_day",
            Self::DerivedText => "vertex_derived_output_tokens_per_day",
        }
    }

    pub(crate) fn protected_limit(self, daily_limit: i64) -> i64 {
        let percent = match self {
            Self::Audio => 50,
            Self::Screen | Self::DerivedText => 25,
        };
        daily_limit.saturating_mul(percent) / 100
    }
}

#[async_trait]
pub(crate) trait EntitlementRepository: Send + Sync {
    async fn account_active(&self, account_id: &str) -> Result<bool>;

    #[allow(dead_code)] // retained for the aggregate reservation contract fixture
    async fn reserve_vertex_output_tokens(
        &self,
        account_id: &str,
        requested: i64,
        daily_limit: i64,
    ) -> Result<QuotaResult>;

    async fn reserve_vertex_output_tokens_for_class(
        &self,
        account_id: &str,
        class: VertexWorkClass,
        requested: i64,
        daily_limit: i64,
    ) -> Result<QuotaResult>;

    async fn reserve_daily_usage(
        &self,
        account_id: &str,
        utterances: i64,
        screenshots: i64,
        mcp_calls: i64,
        limits: (i64, i64, i64),
    ) -> Result<QuotaResult>;
}
