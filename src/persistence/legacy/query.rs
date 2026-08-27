use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::persistence::MemoryQueryRepository;
use crate::search::{search_all, SearchHit, SearchRequest};
use crate::store::Store;

pub(crate) struct LegacyMemoryQueryRepository {
    store: Arc<Store>,
}

impl LegacyMemoryQueryRepository {
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl MemoryQueryRepository for LegacyMemoryQueryRepository {
    async fn search(&self, account_id: &str, request: &SearchRequest) -> Result<Vec<SearchHit>> {
        let request = request.clone();
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                search_all(connection, &request)
            })
            .await
    }
}
