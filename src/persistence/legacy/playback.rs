use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    cp::playback::{DurableReadFence, PersonMemoriesPage, PlaybackDataset},
    error::Result,
    persistence::PlaybackRepository,
    store::Store,
};

pub(crate) struct LegacyPlaybackRepository {
    store: Arc<Store>,
}

impl LegacyPlaybackRepository {
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl PlaybackRepository for LegacyPlaybackRepository {
    async fn dataset(
        &self,
        account_id: &str,
        memory_id: i64,
        durable_read: Option<&DurableReadFence>,
    ) -> Result<Option<PlaybackDataset>> {
        let account_id = account_id.to_owned();
        let durable_read = durable_read.cloned();
        self.store
            .wal_authoritative_read(&account_id.clone(), move |connection| {
                crate::cp::playback::load_playback_dataset(
                    connection,
                    &account_id,
                    memory_id,
                    durable_read.as_ref(),
                )
            })
            .await
    }

    async fn person_memories(
        &self,
        account_id: &str,
        person_id: i64,
        before_id: Option<i64>,
        limit: usize,
        durable_read: Option<&DurableReadFence>,
    ) -> Result<PersonMemoriesPage> {
        let durable_read = durable_read.cloned();
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                let exists: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM people WHERE id=?1 AND status='identified')",
                    [person_id],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Err(crate::error::EnclaveError::NotFound);
                }
                crate::cp::playback::load_person_memories(
                    connection,
                    person_id,
                    before_id,
                    limit,
                    durable_read.as_ref(),
                )
            })
            .await
    }
}
