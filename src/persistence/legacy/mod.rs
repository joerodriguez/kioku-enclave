//! Adapters over the current encrypted SQLite/GCS implementation.
//!
//! This module is the only serving boundary allowed to depend on the concrete
//! legacy stores while application callers move to typed persistence ports.

mod billing;
mod capture;
mod entitlement;
mod identity;
mod lifecycle;
mod model_usage;
mod notification;
mod oauth;
mod query;
mod work;

pub(super) use billing::LegacyBillingRepository;
pub(super) use capture::LegacyCaptureRepository;
pub(super) use entitlement::LegacyEntitlementRepository;
pub(super) use identity::LegacyIdentitySessionRepository;
pub(super) use lifecycle::LegacyAccountLifecycleRepository;
pub(super) use model_usage::LegacyModelUsageRepository;
pub(super) use notification::LegacyNotificationRepository;
pub(super) use oauth::LegacyOAuthRepository;
pub(super) use query::LegacyMemoryQueryRepository;
pub(super) use work::LegacyWorkRepository;
