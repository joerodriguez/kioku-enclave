//! Adapters over the current encrypted SQLite/GCS implementation.
//!
//! This module is the only serving boundary allowed to depend on the concrete
//! legacy stores while application callers move to typed persistence ports.

mod identity;
mod oauth;

pub(super) use identity::LegacyIdentitySessionRepository;
pub(super) use oauth::LegacyOAuthRepository;
