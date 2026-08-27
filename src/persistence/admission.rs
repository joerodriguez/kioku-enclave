//! Fleet-wide request admission contracts.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;

use crate::error::Result;

/// Durable admission primitives used when more than one process can serve.
#[async_trait]
pub(crate) trait AdmissionRepository: Send + Sync {
    async fn consume_rate(
        &self,
        scope: &str,
        key: &str,
        capacity: f64,
        refill_per_second: f64,
    ) -> Result<bool>;

    async fn acquire_concurrency(
        &self,
        scope: &str,
        holder: &str,
        limit: u32,
        ttl: Duration,
    ) -> Result<bool>;

    async fn release_concurrency(&self, scope: &str, holder: &str) -> Result<()>;
}

/// A fleet concurrency lease. Dropping it releases promptly; the durable TTL
/// is the crash-recovery backstop.
pub(crate) struct FleetAdmissionLease {
    repository: Arc<dyn AdmissionRepository>,
    scope: String,
    holder: String,
}

impl FleetAdmissionLease {
    pub(crate) fn new(repository: Arc<dyn AdmissionRepository>, scope: &str, holder: &str) -> Self {
        Self {
            repository,
            scope: scope.to_owned(),
            holder: holder.to_owned(),
        }
    }
}

impl Drop for FleetAdmissionLease {
    fn drop(&mut self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let repository = Arc::clone(&self.repository);
        let scope = self.scope.clone();
        let holder = self.holder.clone();
        runtime.spawn(async move {
            if let Err(error) = repository.release_concurrency(&scope, &holder).await {
                tracing::warn!(scope = %scope, error = %error, "fleet admission lease release failed");
            }
        });
    }
}
