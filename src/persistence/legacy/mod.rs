//! Adapters over the current encrypted SQLite/GCS implementation.
//!
//! This module is the only serving boundary allowed to depend on the concrete
//! legacy stores while application callers move to typed persistence ports.

mod billing;
mod entitlement;
mod identity;
mod notification;
mod oauth;

pub(super) use billing::LegacyBillingRepository;
pub(super) use entitlement::LegacyEntitlementRepository;
pub(super) use identity::LegacyIdentitySessionRepository;
pub(super) use notification::LegacyNotificationRepository;
pub(super) use oauth::LegacyOAuthRepository;
