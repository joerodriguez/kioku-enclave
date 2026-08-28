use async_trait::async_trait;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VertexWorkClass {
    Audio,
    Screen,
    DerivedText,
}

impl VertexWorkClass {
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

    async fn reserve_vertex_output_tokens_for_class(
        &self,
        account_id: &str,
        class: VertexWorkClass,
        requested: i64,
        daily_limit: i64,
    ) -> Result<bool>;
}
