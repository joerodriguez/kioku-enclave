//! Backend-neutral application persistence boundaries.
//!
//! Product code depends on the typed ports exposed here, never on a database
//! connection or SQL callback. The legacy adapter delegates to the existing
//! SQLite/GCS stores while the PostgreSQL implementation is built vertically.

mod identity;

use std::sync::Arc;

pub(crate) use identity::{AccountStatus, IdentitySessionRepository};

use self::identity::LegacyIdentitySessionRepository;
use crate::cp::control_store::ControlStore;

/// The persistence dependencies injected into application code.
///
/// This starts with authentication because it is the first vertical slice.
/// Additional ports join this set as their handlers and workers are extracted.
#[derive(Clone)]
pub(crate) struct RepositorySet {
    identity_sessions: Arc<dyn IdentitySessionRepository>,
}

impl RepositorySet {
    pub(crate) fn legacy(control: Arc<ControlStore>) -> Self {
        Self {
            identity_sessions: Arc::new(LegacyIdentitySessionRepository::new(control)),
        }
    }

    pub(crate) fn identity_sessions(&self) -> &dyn IdentitySessionRepository {
        self.identity_sessions.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{AccountStatus, RepositorySet};
    use crate::cp::control_store::{ControlStore, TEST_SIGNUP_LIMIT};
    use crate::store::tests::{FakeGcs, FakeKms};

    #[tokio::test]
    async fn legacy_identity_port_preserves_signup_and_status_behavior() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let repositories = RepositorySet::legacy(control);

        let account = repositories
            .identity_sessions()
            .upsert_subject_account(
                "postgres-interface-subject",
                "owner@example.com",
                TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();

        assert_eq!(account.email, "owner@example.com");
        assert_eq!(
            repositories
                .identity_sessions()
                .account_status(&account.id)
                .await
                .unwrap(),
            Some(AccountStatus::Active)
        );
    }
}
