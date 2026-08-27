use async_trait::async_trait;

use crate::{
    cp::playback::{DurableReadFence, PersonMemoriesPage, PlaybackDataset},
    error::Result,
};

#[async_trait]
pub(crate) trait PlaybackRepository: Send + Sync {
    async fn dataset(
        &self,
        account_id: &str,
        memory_id: i64,
        durable_read: Option<&DurableReadFence>,
    ) -> Result<Option<PlaybackDataset>>;

    async fn person_memories(
        &self,
        account_id: &str,
        person_id: i64,
        before_id: Option<i64>,
        limit: usize,
        durable_read: Option<&DurableReadFence>,
    ) -> Result<PersonMemoriesPage>;
}
