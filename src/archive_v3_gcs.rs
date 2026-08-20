#![allow(
    dead_code,
    reason = "inactive ADR-0022 transport boundary is compiled and unit-tested before runtime wiring"
)]

//! Inactive ADR-0022 GCS adapter boundary.
//!
//! This module has production-safe *semantics* and test fakes. Its concrete
//! sibling HTTP transport is also compiled and tested, but neither is wired to
//! Store, routes, the VFS, the witness, authority, Terraform, or deployment.

use crate::{
    archive_v3::{
        ArchivePrefix, ArchiveV3Error, CiphertextEnvelope, CreateIfAbsent,
        ExactKeyRegistryProvider, ImmutableObjectBackend, KeyRegistryContext, ObjectContext,
        ObjectId, ObjectKey, ObjectRole, Result, KEY_REGISTRY_PLAINTEXT_BYTES,
        MAX_ENCODED_ENVELOPE_BYTES, MAX_WRAPPED_KEY_REGISTRY_BYTES,
    },
    archive_v3_witness::{ExactRootProvider, WitnessError},
};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use zeroize::Zeroize;

pub(crate) const MAX_CANONICAL_OBJECT_KEY_BYTES: usize = 512;
pub(crate) const MAX_ENUMERATION_PAGE_BYTES: usize =
    (crate::archive_v3::MAX_ENUMERATION_PAGE + 1) * MAX_CANONICAL_OBJECT_KEY_BYTES;

/// Redacted transport status. Implementations must not include GCS paths,
/// archive IDs, ciphertext hashes, or continuation tokens in errors/logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GcsArchiveV3TransportError {
    /// Provider availability failure. The adapter reconciles this category too,
    /// even though concrete transports should prefer `OutcomeUnknown` whenever
    /// a mutating request may have been submitted.
    Unavailable,
    /// The conditional request may have reached GCS. This category is always
    /// reconciled by an exact read; Protocol is reserved for pre-submit faults.
    OutcomeUnknown,
    NotFound,
    PreconditionFailed,
    TooLarge,
    Protocol,
}

/// Result of GCS `ifGenerationMatch=0` creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GcsArchiveV3CreateResult {
    Created,
    PreconditionFailed,
}

/// Archive-scoped object IDs are claimed before any data-object create.  A
/// claim survives ordinary object GC/deletion so a version ID can never be
/// reused at another logical location under the same archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GcsArchiveV3ClaimResult {
    Reserved,
    AlreadyReserved,
    AlreadyMaterialized,
    Conflict,
}

/// Exact all-generation deletion outcome. A real transport must delete every
/// generation for the exact object name, not merely the live generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GcsArchiveV3DeleteResult {
    DeletedAllGenerations,
    Absent,
}

/// One bounded, key-based transport page. `names` must be ordered strictly by
/// bytewise object name and only contain names below the requested prefix.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GcsArchiveV3Page {
    pub names: Vec<String>,
}

impl fmt::Debug for GcsArchiveV3Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GcsArchiveV3Page(<redacted>)")
    }
}

/// Provider-neutral asynchronous transport shaped around GCS's conditional
/// generation semantics. The future concrete HTTP client belongs only here;
/// callers never receive provider paths, generations, or raw KMS metadata.
#[async_trait::async_trait]
pub(crate) trait ArchiveV3GcsTransport: Send + Sync {
    /// Atomically create or reconcile the archive-scoped immutable-ID claim.
    /// A concrete GCS transport stores a content-free claim object committed
    /// to the canonical key. Claims are included in final account-deletion
    /// inventory but are never removed by ordinary object GC.
    async fn claim_object_id(
        &self,
        canonical_archive_prefix: &str,
        object_id: ObjectId,
        canonical_key: &str,
        ciphertext_hash: [u8; 32],
    ) -> std::result::Result<GcsArchiveV3ClaimResult, GcsArchiveV3TransportError>;

    /// Permanently consume a matching reservation after exact read-back. This
    /// transition is idempotent. A materialized claim remains after ordinary
    /// object deletion and therefore prevents recreation under the same ID.
    async fn mark_object_id_materialized(
        &self,
        canonical_archive_prefix: &str,
        object_id: ObjectId,
        canonical_key: &str,
        ciphertext_hash: [u8; 32],
    ) -> std::result::Result<(), GcsArchiveV3TransportError>;

    async fn create_if_absent(
        &self,
        canonical_key: &str,
        bytes: &[u8],
    ) -> std::result::Result<GcsArchiveV3CreateResult, GcsArchiveV3TransportError>;

    /// Read exactly one current object while enforcing `max_bytes` on declared
    /// length and accumulated body bytes. The HTTP/TLS implementation must use
    /// bounded internal buffers. `None` is definitive absence, not an empty object.
    async fn read_exact(
        &self,
        canonical_key: &str,
        max_bytes: usize,
    ) -> std::result::Result<Option<Vec<u8>>, GcsArchiveV3TransportError>;

    /// Return at most `limit` names strictly greater than `after` (when set).
    /// The transport must enforce both [`MAX_CANONICAL_OBJECT_KEY_BYTES`] per
    /// name and [`MAX_ENUMERATION_PAGE_BYTES`] over the page while streaming
    /// the provider response. Pagination is key-based, never a raw token.
    async fn list_after(
        &self,
        canonical_prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> std::result::Result<GcsArchiveV3Page, GcsArchiveV3TransportError>;

    async fn delete_all_generations_exact(
        &self,
        canonical_key: &str,
    ) -> std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError>;

    /// Read/list one exact canonical object and prove that neither live,
    /// noncurrent, nor soft-deleted generations remain. This is used only to
    /// reconcile an ambiguous delete response; it must not issue a mutation.
    async fn verify_all_generations_absent_exact(
        &self,
        _canonical_key: &str,
    ) -> std::result::Result<bool, GcsArchiveV3TransportError> {
        Err(GcsArchiveV3TransportError::Protocol)
    }

    /// Remove the permanent claim for one already-authenticated immutable
    /// object ID.  Callers supply an archive prefix and opaque ID rather than
    /// a claim path, so account deletion cannot manufacture a provider key.
    /// The default deliberately fails closed until a concrete transport has
    /// implemented the same all-generation/soft-delete proof as content.
    async fn delete_claim_all_generations_exact(
        &self,
        _canonical_archive_prefix: &str,
        _object_id: ObjectId,
    ) -> std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError> {
        Err(GcsArchiveV3TransportError::Protocol)
    }

    /// Claim counterpart to [`Self::verify_all_generations_absent_exact`].
    async fn verify_claim_all_generations_absent_exact(
        &self,
        _canonical_archive_prefix: &str,
        _object_id: ObjectId,
    ) -> std::result::Result<bool, GcsArchiveV3TransportError> {
        Err(GcsArchiveV3TransportError::Protocol)
    }
}

/// Bounded registry KMS boundary. The adapter receives the typed registry
/// context and derives its canonical, zeroizing KMS AAD internally; no raw DEK
/// is exposed and no legacy per-object wrapped-DEK metadata is used. Every
/// method must zero the full destination before validation or its first await,
/// and may publish bytes only on success.
#[async_trait::async_trait]
pub(crate) trait ArchiveV3RegistryKms: Send + Sync {
    async fn wrap_registry(
        &self,
        context: &KeyRegistryContext,
        registry_plaintext: &[u8],
        destination: &mut [u8],
    ) -> std::result::Result<usize, GcsArchiveV3TransportError>;

    async fn unwrap_registry(
        &self,
        context: &KeyRegistryContext,
        wrapped_registry_ciphertext: &[u8],
        destination: &mut [u8],
    ) -> std::result::Result<usize, GcsArchiveV3TransportError>;
}

/// Immutable archive adapter retaining create/read/delete semantics even when
/// a create response is lost after GCS has committed the object.
pub(crate) struct GcsArchiveV3Backend {
    transport: Arc<dyn ArchiveV3GcsTransport>,
}

impl GcsArchiveV3Backend {
    pub(crate) fn new(transport: Arc<dyn ArchiveV3GcsTransport>) -> Self {
        Self { transport }
    }

    fn valid_key(key: &ObjectKey) -> bool {
        canonical_object_id(key.as_str()).is_some_and(|id| id == key.object_id())
    }

    async fn read_encoded_envelope(
        &self,
        key: &ObjectKey,
    ) -> Result<Option<(Vec<u8>, CiphertextEnvelope)>> {
        if !Self::valid_key(key) {
            return Err(ArchiveV3Error::InvalidContext);
        }
        let bytes = self
            .transport
            .read_exact(key.as_str(), MAX_ENCODED_ENVELOPE_BYTES)
            .await
            .map_err(map_transport)?;
        let Some(bytes) = bytes else { return Ok(None) };
        if bytes.len() > MAX_ENCODED_ENVELOPE_BYTES {
            return Err(ArchiveV3Error::TooLarge("transport object"));
        }
        let envelope = CiphertextEnvelope::decode(&bytes)?;
        Ok(Some((bytes, envelope)))
    }

    async fn read_envelope(&self, key: &ObjectKey) -> Result<Option<CiphertextEnvelope>> {
        Ok(self
            .read_encoded_envelope(key)
            .await?
            .map(|(_, envelope)| envelope))
    }
}

async fn create_raw_immutable(
    transport: &dyn ArchiveV3GcsTransport,
    key: &ObjectKey,
    encoded: &[u8],
    max_bytes: usize,
) -> Result<CreateIfAbsent> {
    if encoded.is_empty() || canonical_object_id(key.as_str()) != Some(key.object_id()) {
        return Err(ArchiveV3Error::InvalidContext);
    }
    if encoded.len() > max_bytes {
        return Err(ArchiveV3Error::TooLarge("transport object"));
    }
    let archive_prefix = key_archive_prefix(key.as_str())?;
    let ciphertext_hash: [u8; 32] = Sha256::digest(encoded).into();
    let claim = transport
        .claim_object_id(
            archive_prefix,
            key.object_id(),
            key.as_str(),
            ciphertext_hash,
        )
        .await
        .map_err(map_transport)?;
    if claim == GcsArchiveV3ClaimResult::Conflict {
        return Err(ArchiveV3Error::Conflict);
    }

    let reconcile = || async {
        match transport
            .read_exact(key.as_str(), max_bytes)
            .await
            .map_err(map_transport)?
        {
            Some(stored) if stored == encoded => Ok(true),
            Some(_) => Err(ArchiveV3Error::Conflict),
            None => Ok(false),
        }
    };
    if claim == GcsArchiveV3ClaimResult::AlreadyMaterialized {
        return if reconcile().await? {
            Ok(CreateIfAbsent::AlreadyPresentIdentical)
        } else {
            // A materialized-but-absent object was deleted. Its permanent
            // claim forbids recreating that object ID, even at the same key.
            Err(ArchiveV3Error::Conflict)
        };
    }
    if claim == GcsArchiveV3ClaimResult::AlreadyReserved {
        if !reconcile().await? {
            // A reservation is one-way. If its original object is absent, the
            // ID is burned rather than recreated after an unobserved delete.
            return Err(ArchiveV3Error::Conflict);
        }
        transport
            .mark_object_id_materialized(
                archive_prefix,
                key.object_id(),
                key.as_str(),
                ciphertext_hash,
            )
            .await
            .map_err(map_transport)?;
        return Ok(CreateIfAbsent::AlreadyPresentIdentical);
    }
    debug_assert_eq!(claim, GcsArchiveV3ClaimResult::Reserved);

    let outcome = match transport.create_if_absent(key.as_str(), encoded).await {
        Ok(GcsArchiveV3CreateResult::Created) => {
            if reconcile().await? {
                CreateIfAbsent::Created
            } else {
                return Err(ArchiveV3Error::Unavailable);
            }
        }
        Ok(GcsArchiveV3CreateResult::PreconditionFailed) => {
            if reconcile().await? {
                CreateIfAbsent::AlreadyPresentIdentical
            } else {
                return Err(ArchiveV3Error::Unavailable);
            }
        }
        Err(
            GcsArchiveV3TransportError::OutcomeUnknown | GcsArchiveV3TransportError::Unavailable,
        ) => {
            if reconcile().await? {
                CreateIfAbsent::Created
            } else {
                return Err(ArchiveV3Error::Unavailable);
            }
        }
        Err(error) => return Err(map_transport(error)),
    };
    transport
        .mark_object_id_materialized(
            archive_prefix,
            key.object_id(),
            key.as_str(),
            ciphertext_hash,
        )
        .await
        .map_err(map_transport)?;
    Ok(outcome)
}

#[async_trait::async_trait]
impl ImmutableObjectBackend for GcsArchiveV3Backend {
    async fn create_if_absent(
        &self,
        key: ObjectKey,
        value: CiphertextEnvelope,
    ) -> Result<CreateIfAbsent> {
        if !Self::valid_key(&key) {
            return Err(ArchiveV3Error::InvalidContext);
        }
        let encoded = value.encode();
        create_raw_immutable(
            self.transport.as_ref(),
            &key,
            &encoded,
            MAX_ENCODED_ENVELOPE_BYTES,
        )
        .await
    }

    async fn get(&self, key: &ObjectKey) -> Result<Option<CiphertextEnvelope>> {
        self.read_envelope(key).await
    }

    async fn enumerate(
        &self,
        prefix: &ArchivePrefix,
        cursor: Option<&crate::archive_v3::EnumerationCursor>,
        limit: crate::archive_v3::EnumerationLimit,
    ) -> Result<crate::archive_v3::EnumerationPage> {
        if !valid_archive_prefix(prefix.as_str())
            || cursor.is_some_and(|cursor| cursor.prefix != *prefix)
        {
            return Err(ArchiveV3Error::InvalidContext);
        }
        let after = cursor.map(|cursor| cursor.after.as_str());
        let page = self
            .transport
            .list_after(prefix.as_str(), after, limit.get() + 1)
            .await
            .map_err(map_transport)?;
        if page.names.len() > limit.get() + 1 {
            return Err(ArchiveV3Error::TooLarge("transport page"));
        }
        let mut page_bytes = 0usize;
        for name in &page.names {
            page_bytes = page_bytes
                .checked_add(name.len())
                .ok_or(ArchiveV3Error::TooLarge("transport page"))?;
            if name.len() > MAX_CANONICAL_OBJECT_KEY_BYTES
                || page_bytes > MAX_ENUMERATION_PAGE_BYTES
            {
                return Err(ArchiveV3Error::TooLarge("transport page"));
            }
        }
        let mut objects = Vec::with_capacity(page.names.len());
        let mut previous = after.map(str::to_owned);
        for name in page.names {
            if !name.starts_with(prefix.as_str())
                || previous
                    .as_deref()
                    .is_some_and(|prior| name.as_str() <= prior)
            {
                return Err(ArchiveV3Error::InvalidContext);
            }
            let id = canonical_object_id(&name).ok_or(ArchiveV3Error::InvalidContext)?;
            previous = Some(name.clone());
            objects.push(ObjectKey::from_validated_canonical(name, id));
        }
        let next_cursor = if objects.len() > limit.get() {
            objects.truncate(limit.get());
            Some(crate::archive_v3::EnumerationCursor {
                prefix: prefix.clone(),
                after: objects.last().expect("non-zero bounded limit").clone(),
            })
        } else {
            None
        };
        Ok(crate::archive_v3::EnumerationPage {
            objects,
            next_cursor,
        })
    }

    async fn delete_exact(&self, key: &ObjectKey) -> Result<bool> {
        if !Self::valid_key(key) {
            return Err(ArchiveV3Error::InvalidContext);
        }
        match self
            .transport
            .delete_all_generations_exact(key.as_str())
            .await
        {
            Ok(GcsArchiveV3DeleteResult::DeletedAllGenerations) => Ok(true),
            Ok(GcsArchiveV3DeleteResult::Absent) => Ok(false),
            Err(error) => Err(map_transport(error)),
        }
    }
}

/// Exact immutable root reader for the witness boundary.
pub(crate) struct GcsArchiveV3RootProvider {
    backend: GcsArchiveV3Backend,
}

impl GcsArchiveV3RootProvider {
    pub(crate) fn new(transport: Arc<dyn ArchiveV3GcsTransport>) -> Self {
        Self {
            backend: GcsArchiveV3Backend::new(transport),
        }
    }
}

#[async_trait::async_trait]
impl ExactRootProvider for GcsArchiveV3RootProvider {
    async fn read_exact(
        &self,
        context: &ObjectContext,
    ) -> std::result::Result<CiphertextEnvelope, WitnessError> {
        if context.role() != crate::archive_v3::ObjectRole::RootV3 {
            return Err(WitnessError::Malformed);
        }
        match self.backend.get(&context.object_key()).await {
            Ok(Some(envelope)) => Ok(envelope),
            Ok(None) => Err(WitnessError::MissingRootObject),
            Err(ArchiveV3Error::Unavailable) => Err(WitnessError::Unavailable),
            Err(_) => Err(WitnessError::Malformed),
        }
    }
}

/// Exact wrapped-registry and bounded KMS adapter. It uses the registry's
/// canonical storage key directly because registry ciphertext is KMS material,
/// not an archive envelope encrypted by the DEK it contains.
pub(crate) struct GcsArchiveV3RegistryProvider {
    transport: Arc<dyn ArchiveV3GcsTransport>,
    kms: Arc<dyn ArchiveV3RegistryKms>,
}

impl GcsArchiveV3RegistryProvider {
    pub(crate) fn new(
        transport: Arc<dyn ArchiveV3GcsTransport>,
        kms: Arc<dyn ArchiveV3RegistryKms>,
    ) -> Self {
        Self { transport, kms }
    }

    /// Wrap one exact registry plaintext under the typed context. The KMS
    /// implementation, not this caller, derives the canonical AAD. The
    /// capability is token-gated because it does not survive the runtime
    /// bundle's `Arc<dyn ExactKeyRegistryProvider>` erasure: only the
    /// reviewed genesis backend composition (which alone can mint the token)
    /// may reach it on a released concrete provider.
    pub(crate) async fn wrap_registry(
        &self,
        _token: &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext,
        context: &KeyRegistryContext,
        registry_plaintext: &[u8],
        destination: &mut [u8],
    ) -> Result<usize> {
        destination.zeroize();
        let result = self
            .kms
            .wrap_registry(context, registry_plaintext, destination)
            .await;
        match result {
            Ok(len)
                if (1..=MAX_WRAPPED_KEY_REGISTRY_BYTES).contains(&len)
                    && len <= destination.len() =>
            {
                Ok(len)
            }
            Ok(0) => {
                destination.zeroize();
                Err(ArchiveV3Error::InvalidContext)
            }
            Ok(_) => {
                destination.zeroize();
                Err(ArchiveV3Error::TooLarge("wrapped key registry"))
            }
            Err(error) => {
                destination.zeroize();
                Err(map_transport(error))
            }
        }
    }

    /// Create a wrapped registry object under the same archive-wide ID claim
    /// namespace as envelopes. This is the only permitted registry write seam.
    pub(crate) async fn create_wrapped_if_absent(
        &self,
        context: &KeyRegistryContext,
        object_id: ObjectId,
        wrapped_registry_ciphertext: &[u8],
    ) -> Result<CreateIfAbsent> {
        let key = context.object_key(object_id);
        create_raw_immutable(
            self.transport.as_ref(),
            &key,
            wrapped_registry_ciphertext,
            MAX_WRAPPED_KEY_REGISTRY_BYTES,
        )
        .await
    }
}

#[async_trait::async_trait]
impl ExactKeyRegistryProvider for GcsArchiveV3RegistryProvider {
    async fn read_exact_wrapped(
        &self,
        context: &KeyRegistryContext,
        object_id: ObjectId,
        destination: &mut [u8],
    ) -> Result<usize> {
        if destination.len() < MAX_WRAPPED_KEY_REGISTRY_BYTES {
            return Err(ArchiveV3Error::TooLarge("registry destination"));
        }
        let key = context.object_key(object_id);
        let bytes = self
            .transport
            .read_exact(key.as_str(), MAX_WRAPPED_KEY_REGISTRY_BYTES)
            .await
            .map_err(map_transport)?
            .ok_or(ArchiveV3Error::InvalidContext)?;
        if bytes.is_empty() || bytes.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES {
            return Err(ArchiveV3Error::TooLarge("wrapped key registry"));
        }
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    async fn kms_unwrap_exact(
        &self,
        context: &KeyRegistryContext,
        wrapped_registry_ciphertext: &[u8],
        destination: &mut [u8],
    ) -> Result<usize> {
        destination.zeroize();
        if wrapped_registry_ciphertext.is_empty()
            || wrapped_registry_ciphertext.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
        {
            return Err(ArchiveV3Error::TooLarge("wrapped key registry"));
        }
        if destination.len() < KEY_REGISTRY_PLAINTEXT_BYTES {
            return Err(ArchiveV3Error::TooLarge("key registry plaintext"));
        }
        let result = self
            .kms
            .unwrap_registry(context, wrapped_registry_ciphertext, destination)
            .await;
        match result {
            Ok(KEY_REGISTRY_PLAINTEXT_BYTES) => Ok(KEY_REGISTRY_PLAINTEXT_BYTES),
            Ok(len) if len > destination.len() || len > KEY_REGISTRY_PLAINTEXT_BYTES => {
                destination.zeroize();
                Err(ArchiveV3Error::TooLarge("key registry plaintext"))
            }
            Ok(_) => {
                destination.zeroize();
                Err(ArchiveV3Error::InvalidContext)
            }
            Err(error) => {
                destination.zeroize();
                Err(map_transport(error))
            }
        }
    }
}

fn map_transport(error: GcsArchiveV3TransportError) -> ArchiveV3Error {
    match error {
        GcsArchiveV3TransportError::Unavailable
        | GcsArchiveV3TransportError::OutcomeUnknown
        | GcsArchiveV3TransportError::NotFound => ArchiveV3Error::Unavailable,
        GcsArchiveV3TransportError::PreconditionFailed => ArchiveV3Error::Conflict,
        GcsArchiveV3TransportError::TooLarge => ArchiveV3Error::TooLarge("transport object"),
        GcsArchiveV3TransportError::Protocol => ArchiveV3Error::InvalidContext,
    }
}

fn key_archive_prefix(key: &str) -> Result<&str> {
    let Some(remainder) = key.strip_prefix("archive/v3/") else {
        return Err(ArchiveV3Error::InvalidContext);
    };
    let Some(separator) = remainder.find('/') else {
        return Err(ArchiveV3Error::InvalidContext);
    };
    let prefix_len = "archive/v3/".len() + separator + 1;
    let prefix = &key[..prefix_len];
    valid_archive_prefix(prefix)
        .then_some(prefix)
        .ok_or(ArchiveV3Error::InvalidContext)
}

pub(super) fn valid_archive_prefix(prefix: &str) -> bool {
    let Some(id) = prefix.strip_prefix("archive/v3/") else {
        return false;
    };
    id.len() == 33 && id.ends_with('/') && is_lower_hex(&id[..32])
}

/// Validate every canonical form emitted by `ObjectContext::object_key` and
/// recover the unique immutable ID from its terminal component.
pub(crate) fn canonical_object_id(key: &str) -> Option<ObjectId> {
    canonical_object_identity(key).map(|(object_id, _)| object_id)
}

pub(crate) fn canonical_object_identity(key: &str) -> Option<(ObjectId, ObjectRole)> {
    if key.len() > MAX_CANONICAL_OBJECT_KEY_BYTES
        || !key.starts_with("archive/v3/")
        || key.contains("//")
        || key.contains("..")
    {
        return None;
    }
    let mut components = key.split('/');
    if components.next() != Some("archive")
        || components.next() != Some("v3")
        || !components
            .next()
            .is_some_and(|archive| is_lower_hex_len(archive, 32))
    {
        return None;
    }
    let role = components.next()?;
    let (id_hex, object_role) = match role {
        "extents" => {
            let (epoch, extent, terminal) =
                (components.next()?, components.next()?, components.next()?);
            (
                (is_lower_hex_len(epoch, 32)
                    && canonical_decimal(extent)
                    && components.next().is_none())
                .then(|| terminal_id(terminal, ".extx"))
                .flatten(),
                ObjectRole::ExtentV3,
            )
        }
        "wal" => {
            let (epoch, terminal) = (components.next()?, components.next()?);
            (
                (is_lower_hex_len(epoch, 32) && components.next().is_none())
                    .then(|| hyphenated_terminal_id(terminal, ".walx"))
                    .flatten(),
                ObjectRole::WalSegmentV3,
            )
        }
        "wal-commits" => {
            let (epoch, terminal) = (components.next()?, components.next()?);
            (
                (is_lower_hex_len(epoch, 32) && components.next().is_none())
                    .then(|| hyphenated_terminal_id(terminal, ".wcdx"))
                    .flatten(),
                ObjectRole::WalCommitDescriptorV3,
            )
        }
        "nodes" => {
            let (epoch, level, terminal) =
                (components.next()?, components.next()?, components.next()?);
            (
                (is_lower_hex_len(epoch, 32)
                    && canonical_decimal(level)
                    && components.next().is_none())
                .then(|| terminal_id(terminal, ".nodex"))
                .flatten(),
                ObjectRole::MerkleNodeV3,
            )
        }
        "root-candidates" => {
            let (epoch, terminal) = (components.next()?, components.next()?);
            (
                (is_lower_hex_len(epoch, 32) && components.next().is_none())
                    .then(|| hyphenated_terminal_id(terminal, ".rootx"))
                    .flatten(),
                ObjectRole::RootV3,
            )
        }
        "keys" => {
            let (kind, epoch, terminal) =
                (components.next()?, components.next()?, components.next()?);
            (
                (matches!(kind, "archive" | "media")
                    && is_lower_hex_len(epoch, 32)
                    && components.next().is_none())
                .then(|| terminal_id(terminal, ".keyx"))
                .flatten(),
                ObjectRole::KeyRegistryV3,
            )
        }
        "staging" => {
            let (operation, terminal) = (components.next()?, components.next()?);
            (
                (is_lower_hex_len(operation, 32) && components.next().is_none())
                    .then(|| terminal_id(terminal, ""))
                    .flatten(),
                ObjectRole::StagingV3,
            )
        }
        "checkpoints" => {
            let (epoch, checkpoint, kind, terminal) = (
                components.next()?,
                components.next()?,
                components.next()?,
                components.next()?,
            );
            if !is_lower_hex_len(epoch, 32)
                || !is_lower_hex_len(checkpoint, 32)
                || components.next().is_some()
            {
                (None, ObjectRole::CheckpointChunkV3)
            } else {
                match kind {
                    "chunks" => (
                        hyphenated_terminal_id(terminal, ".chkx"),
                        ObjectRole::CheckpointChunkV3,
                    ),
                    "manifest" => (
                        manifest_terminal_id(terminal),
                        ObjectRole::CheckpointManifestV3,
                    ),
                    _ => (None, ObjectRole::CheckpointChunkV3),
                }
            }
        }
        _ => (None, ObjectRole::CheckpointChunkV3),
    };
    let id_hex = id_hex?;
    if !is_lower_hex_len(id_hex, 32) {
        return None;
    }
    let mut raw = [0u8; 16];
    for (index, pair) in id_hex.as_bytes().chunks_exact(2).enumerate() {
        raw[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some((ObjectId::from_bytes(raw), object_role))
}

fn terminal_id<'a>(terminal: &'a str, suffix: &str) -> Option<&'a str> {
    let stem = terminal.strip_suffix(suffix)?;
    is_lower_hex_len(stem, 32).then_some(stem)
}
fn hyphenated_terminal_id<'a>(terminal: &'a str, suffix: &str) -> Option<&'a str> {
    let stem = terminal.strip_suffix(suffix)?;
    let (prefix, id) = stem.rsplit_once('-')?;
    canonical_decimal(prefix)
        .then_some(id)
        .filter(|id| is_lower_hex_len(id, 32))
}
fn manifest_terminal_id(terminal: &str) -> Option<&str> {
    let stem = terminal.strip_suffix(".cmfx")?;
    let mut fields = stem.split('-');
    let (level, start, end, id) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
    );
    (fields.next().is_none()
        && canonical_decimal(level)
        && canonical_decimal(start)
        && canonical_decimal(end)
        && is_lower_hex_len(id, 32))
    .then_some(id)
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value
            .parse::<u64>()
            .is_ok_and(|parsed| parsed.to_string() == value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn is_lower_hex_len(value: &str, length: usize) -> bool {
    value.len() == length && is_lower_hex(value)
}
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for GcsArchiveV3Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GcsArchiveV3Backend(<redacted>)")
    }
}
impl fmt::Debug for GcsArchiveV3RootProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GcsArchiveV3RootProvider(<redacted>)")
    }
}
impl fmt::Debug for GcsArchiveV3RegistryProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GcsArchiveV3RegistryProvider(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{
        ArchiveCipher, ArchiveDek, ArchiveId, DatabaseEpoch, KeyEpoch, KeyKind,
        KeyRegistryPlaintext, LogicalLocation, ObjectRole,
    };
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Clone, Copy)]
    enum NextCreate {
        Normal,
        LostSuccess,
        LostSuccessUnavailable,
        Precondition,
    }
    #[derive(Clone, PartialEq, Eq)]
    struct FakeClaim {
        key: String,
        ciphertext_hash: [u8; 32],
        materialized: bool,
    }
    struct FakeTransport {
        objects: Mutex<BTreeMap<String, Vec<Vec<u8>>>>,
        claims: Mutex<BTreeMap<(String, ObjectId), FakeClaim>>,
        next: Mutex<NextCreate>,
        fail_next_materialize: Mutex<bool>,
        deleted: Mutex<Vec<String>>,
        deleted_generation_counts: Mutex<Vec<usize>>,
    }
    impl FakeTransport {
        fn new() -> Self {
            Self {
                objects: Mutex::new(BTreeMap::new()),
                claims: Mutex::new(BTreeMap::new()),
                next: Mutex::new(NextCreate::Normal),
                fail_next_materialize: Mutex::new(false),
                deleted: Mutex::new(Vec::new()),
                deleted_generation_counts: Mutex::new(Vec::new()),
            }
        }
    }
    struct FakeRegistryKms {
        expected_context: KeyRegistryContext,
        expected_wrapped: Vec<u8>,
        plaintext: Vec<u8>,
    }
    #[async_trait::async_trait]
    impl ArchiveV3RegistryKms for FakeRegistryKms {
        async fn wrap_registry(
            &self,
            context: &KeyRegistryContext,
            registry_plaintext: &[u8],
            destination: &mut [u8],
        ) -> std::result::Result<usize, GcsArchiveV3TransportError> {
            destination.zeroize();
            if context != &self.expected_context
                || registry_plaintext != self.plaintext
                || self.expected_wrapped.len() > destination.len()
            {
                return Err(GcsArchiveV3TransportError::Protocol);
            }
            destination[..self.expected_wrapped.len()].copy_from_slice(&self.expected_wrapped);
            Ok(self.expected_wrapped.len())
        }

        async fn unwrap_registry(
            &self,
            context: &KeyRegistryContext,
            wrapped_registry_ciphertext: &[u8],
            destination: &mut [u8],
        ) -> std::result::Result<usize, GcsArchiveV3TransportError> {
            destination.zeroize();
            if context != &self.expected_context
                || wrapped_registry_ciphertext != self.expected_wrapped
                || self.plaintext.len() > destination.len()
            {
                return Err(GcsArchiveV3TransportError::Protocol);
            }
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }

    #[derive(Clone, Copy)]
    enum FaultyRegistryKmsMode {
        PartialWriteThenError,
        PartialWriteThenOversizedLength,
    }

    struct FaultyRegistryKms {
        mode: FaultyRegistryKmsMode,
    }

    impl FaultyRegistryKms {
        fn result(
            &self,
            destination: &mut [u8],
        ) -> std::result::Result<usize, GcsArchiveV3TransportError> {
            let partial = destination.len().min(4);
            destination[..partial].fill(0x5a);
            match self.mode {
                FaultyRegistryKmsMode::PartialWriteThenError => {
                    Err(GcsArchiveV3TransportError::Protocol)
                }
                FaultyRegistryKmsMode::PartialWriteThenOversizedLength => {
                    Ok(destination.len().saturating_add(1))
                }
            }
        }
    }

    #[async_trait::async_trait]
    impl ArchiveV3RegistryKms for FaultyRegistryKms {
        async fn wrap_registry(
            &self,
            _context: &KeyRegistryContext,
            _registry_plaintext: &[u8],
            destination: &mut [u8],
        ) -> std::result::Result<usize, GcsArchiveV3TransportError> {
            self.result(destination)
        }

        async fn unwrap_registry(
            &self,
            _context: &KeyRegistryContext,
            _wrapped_registry_ciphertext: &[u8],
            destination: &mut [u8],
        ) -> std::result::Result<usize, GcsArchiveV3TransportError> {
            self.result(destination)
        }
    }
    #[async_trait::async_trait]
    impl ArchiveV3GcsTransport for FakeTransport {
        async fn claim_object_id(
            &self,
            archive_prefix: &str,
            object_id: ObjectId,
            key: &str,
            ciphertext_hash: [u8; 32],
        ) -> std::result::Result<GcsArchiveV3ClaimResult, GcsArchiveV3TransportError> {
            let mut claims = self.claims.lock().unwrap();
            let claim_key = (archive_prefix.to_owned(), object_id);
            Ok(match claims.get(&claim_key) {
                Some(existing)
                    if existing.key == key && existing.ciphertext_hash == ciphertext_hash =>
                {
                    if existing.materialized {
                        GcsArchiveV3ClaimResult::AlreadyMaterialized
                    } else {
                        GcsArchiveV3ClaimResult::AlreadyReserved
                    }
                }
                Some(_) => GcsArchiveV3ClaimResult::Conflict,
                None => {
                    claims.insert(
                        claim_key,
                        FakeClaim {
                            key: key.to_owned(),
                            ciphertext_hash,
                            materialized: false,
                        },
                    );
                    GcsArchiveV3ClaimResult::Reserved
                }
            })
        }

        async fn mark_object_id_materialized(
            &self,
            archive_prefix: &str,
            object_id: ObjectId,
            key: &str,
            ciphertext_hash: [u8; 32],
        ) -> std::result::Result<(), GcsArchiveV3TransportError> {
            let mut fail = self.fail_next_materialize.lock().unwrap();
            if *fail {
                *fail = false;
                return Err(GcsArchiveV3TransportError::Unavailable);
            }
            drop(fail);
            let mut claims = self.claims.lock().unwrap();
            let claim = claims
                .get_mut(&(archive_prefix.to_owned(), object_id))
                .ok_or(GcsArchiveV3TransportError::Protocol)?;
            if claim.key != key || claim.ciphertext_hash != ciphertext_hash {
                return Err(GcsArchiveV3TransportError::Protocol);
            }
            claim.materialized = true;
            Ok(())
        }

        async fn create_if_absent(
            &self,
            key: &str,
            bytes: &[u8],
        ) -> std::result::Result<GcsArchiveV3CreateResult, GcsArchiveV3TransportError> {
            let next = *self.next.lock().unwrap();
            let mut objects = self.objects.lock().unwrap();
            if matches!(next, NextCreate::Precondition)
                || objects
                    .get(key)
                    .is_some_and(|versions| !versions.is_empty())
            {
                return Ok(GcsArchiveV3CreateResult::PreconditionFailed);
            }
            objects.insert(key.to_owned(), vec![bytes.to_vec()]);
            if matches!(next, NextCreate::LostSuccess) {
                Err(GcsArchiveV3TransportError::OutcomeUnknown)
            } else if matches!(next, NextCreate::LostSuccessUnavailable) {
                Err(GcsArchiveV3TransportError::Unavailable)
            } else {
                Ok(GcsArchiveV3CreateResult::Created)
            }
        }
        async fn read_exact(
            &self,
            key: &str,
            max: usize,
        ) -> std::result::Result<Option<Vec<u8>>, GcsArchiveV3TransportError> {
            match self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .and_then(|versions| versions.last())
                .cloned()
            {
                Some(bytes) if bytes.len() > max => Err(GcsArchiveV3TransportError::TooLarge),
                value => Ok(value),
            }
        }
        async fn list_after(
            &self,
            prefix: &str,
            after: Option<&str>,
            limit: usize,
        ) -> std::result::Result<GcsArchiveV3Page, GcsArchiveV3TransportError> {
            let objects = self.objects.lock().unwrap();
            Ok(GcsArchiveV3Page {
                names: objects
                    .iter()
                    .filter(|(key, versions)| {
                        !versions.is_empty()
                            && key.starts_with(prefix)
                            && after.is_none_or(|after| key.as_str() > after)
                    })
                    .take(limit)
                    .map(|(key, _)| key.clone())
                    .collect(),
            })
        }
        async fn delete_all_generations_exact(
            &self,
            key: &str,
        ) -> std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError> {
            self.deleted.lock().unwrap().push(key.to_owned());
            let removed = self.objects.lock().unwrap().remove(key);
            self.deleted_generation_counts
                .lock()
                .unwrap()
                .push(removed.as_ref().map_or(0, Vec::len));
            Ok(if removed.is_some_and(|versions| !versions.is_empty()) {
                GcsArchiveV3DeleteResult::DeletedAllGenerations
            } else {
                GcsArchiveV3DeleteResult::Absent
            })
        }
    }
    fn context(object: u8) -> ObjectContext {
        ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: u64::from(object),
                byte_len: 4096,
            },
            ObjectId::from_bytes([object; 16]),
            None,
        )
        .unwrap()
    }
    fn envelope(context: &ObjectContext, byte: u8) -> CiphertextEnvelope {
        ArchiveCipher::new(ArchiveDek::from_bytes([9; 32]))
            .seal(context, &vec![byte; 4096])
            .unwrap()
    }

    #[test]
    fn wal_commit_descriptor_keys_are_exact_and_noncanonical_forms_fail_closed() {
        let object_id = ObjectId::from_bytes([0x0a; 16]);
        let context = ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::WalCommitDescriptorV3,
            LogicalLocation::WalCommitDescriptor { root_seq: 17 },
            object_id,
            None,
        )
        .unwrap();
        let key = context.object_key();
        assert_eq!(canonical_object_id(key.as_str()), Some(object_id));
        assert_eq!(
            canonical_object_id(&key.as_str().replace("/17-", "/017-")),
            None
        );
        assert_eq!(
            canonical_object_id(&key.as_str().replace("0a0a", "0A0A")),
            None
        );
    }

    #[tokio::test]
    async fn create_handles_412_lost_success_and_all_generation_delete() {
        let transport = Arc::new(FakeTransport::new());
        let backend = GcsArchiveV3Backend::new(transport.clone());
        let context = context(4);
        let value = envelope(&context, 7);
        let key = context.object_key();
        *transport.next.lock().unwrap() = NextCreate::LostSuccess;
        assert_eq!(
            backend
                .create_if_absent(key.clone(), value.clone())
                .await
                .unwrap(),
            CreateIfAbsent::Created
        );
        *transport.next.lock().unwrap() = NextCreate::Precondition;
        assert_eq!(
            backend
                .create_if_absent(key.clone(), value.clone())
                .await
                .unwrap(),
            CreateIfAbsent::AlreadyPresentIdentical
        );
        transport
            .objects
            .lock()
            .unwrap()
            .get_mut(key.as_str())
            .unwrap()
            .push(value.encode());
        assert!(backend.delete_exact(&key).await.unwrap());
        assert_eq!(transport.deleted_generation_counts.lock().unwrap()[0], 2);
        assert_eq!(
            backend.create_if_absent(key.clone(), value).await,
            Err(ArchiveV3Error::Conflict),
            "a materialized ID remains consumed after exact object deletion"
        );
        assert!(!backend.delete_exact(&key).await.unwrap());
        assert_eq!(transport.deleted.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn reservation_is_never_recreated_after_materialize_failure_and_delete() {
        let transport = Arc::new(FakeTransport::new());
        let backend = GcsArchiveV3Backend::new(transport.clone());
        let context = context(6);
        let value = envelope(&context, 8);
        let key = context.object_key();
        *transport.next.lock().unwrap() = NextCreate::LostSuccessUnavailable;
        *transport.fail_next_materialize.lock().unwrap() = true;

        assert_eq!(
            backend.create_if_absent(key.clone(), value.clone()).await,
            Err(ArchiveV3Error::Unavailable),
            "the object exists but its durable claim was not finalized"
        );
        assert!(transport.objects.lock().unwrap().contains_key(key.as_str()));
        assert!(backend.delete_exact(&key).await.unwrap());
        assert_eq!(
            backend.create_if_absent(key.clone(), value).await,
            Err(ArchiveV3Error::Conflict),
            "an existing one-way reservation burns the absent object ID"
        );
        assert!(!transport.objects.lock().unwrap().contains_key(key.as_str()));
    }

    #[tokio::test]
    async fn conflict_and_canonical_key_pagination_are_strict() {
        let transport = Arc::new(FakeTransport::new());
        let backend = GcsArchiveV3Backend::new(transport.clone());
        let first = context(4);
        let second = context(5);
        let first_value = envelope(&first, 1);
        let second_value = envelope(&second, 2);
        backend
            .create_if_absent(first.object_key(), first_value.clone())
            .await
            .unwrap();
        assert_eq!(
            backend
                .create_if_absent(first.object_key(), second_value)
                .await,
            Err(ArchiveV3Error::Conflict)
        );
        let cross_location_same_id = ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 999,
                byte_len: 4096,
            },
            first.object_id(),
            None,
        )
        .unwrap();
        assert_eq!(
            backend
                .create_if_absent(
                    cross_location_same_id.object_key(),
                    envelope(&cross_location_same_id, 9),
                )
                .await,
            Err(ArchiveV3Error::Conflict),
            "an archive-scoped object ID cannot be reused at another logical location"
        );
        backend
            .create_if_absent(second.object_key(), envelope(&second, 3))
            .await
            .unwrap();
        let prefix = ArchivePrefix::for_archive(ArchiveId::from_bytes([1; 16]));
        let page = backend
            .enumerate(
                &prefix,
                None,
                crate::archive_v3::EnumerationLimit::new(1).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.objects.len(), 1);
        assert!(page.next_cursor.is_some());
        transport.objects.lock().unwrap().insert(
            "archive/v3/01010101010101010101010101010101/not-a-canonical-key".into(),
            vec![vec![1]],
        );
        assert_eq!(
            backend
                .enumerate(
                    &prefix,
                    None,
                    crate::archive_v3::EnumerationLimit::new(9).unwrap()
                )
                .await,
            Err(ArchiveV3Error::InvalidContext)
        );
    }

    #[tokio::test]
    async fn registry_provider_binds_canonical_kms_aad_without_dek_metadata() {
        let transport = Arc::new(FakeTransport::new());
        let context = KeyRegistryContext::with_rotation_generation(
            ArchiveId::from_bytes([1; 16]),
            KeyKind::Archive,
            KeyEpoch::from_bytes([3; 16]),
            7,
        );
        let object_id = ObjectId::from_bytes([8; 16]);
        let wrapped = b"bounded-wrapped-registry".to_vec();
        transport.objects.lock().unwrap().insert(
            context.object_key(object_id).as_str().to_owned(),
            vec![wrapped.clone()],
        );
        let plaintext =
            KeyRegistryPlaintext::encode_archive(&context, &ArchiveDek::from_bytes([9; 32]))
                .unwrap()
                .to_vec();
        let kms = Arc::new(FakeRegistryKms {
            expected_context: context,
            expected_wrapped: wrapped.clone(),
            plaintext: plaintext.clone(),
        });
        let provider = GcsArchiveV3RegistryProvider::new(transport, kms);
        let mut wrapped_output = [0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        let wrapped_length = provider
            .wrap_registry(
                &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext::for_test(),
                &context,
                &plaintext,
                &mut wrapped_output,
            )
            .await
            .unwrap();
        assert_eq!(&wrapped_output[..wrapped_length], wrapped.as_slice());
        let mut read = [0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        let length = provider
            .read_exact_wrapped(&context, object_id, &mut read)
            .await
            .unwrap();
        assert_eq!(&read[..length], wrapped.as_slice());
        let mut unwrapped = vec![0u8; plaintext.len()];
        let length = provider
            .kms_unwrap_exact(&context, &read[..length], &mut unwrapped)
            .await
            .unwrap();
        assert_eq!(&unwrapped[..length], plaintext.as_slice());

        let wrong_context = KeyRegistryContext::with_rotation_generation(
            ArchiveId::from_bytes([2; 16]),
            KeyKind::Archive,
            KeyEpoch::from_bytes([3; 16]),
            7,
        );
        let mut rejected_wrap = [0x91; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        assert_eq!(
            provider
                .wrap_registry(
                    &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext::for_test(),
                    &wrong_context,
                    &plaintext,
                    &mut rejected_wrap
                )
                .await,
            Err(ArchiveV3Error::InvalidContext)
        );
        assert!(rejected_wrap.iter().all(|byte| *byte == 0));

        let mut rejected_unwrap = vec![0x92; plaintext.len()];
        assert_eq!(
            provider
                .kms_unwrap_exact(&context, &[], &mut rejected_unwrap)
                .await,
            Err(ArchiveV3Error::TooLarge("wrapped key registry"))
        );
        assert!(rejected_unwrap.iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn registry_provider_scrubs_faulty_delegate_errors_and_invalid_lengths() {
        let context = KeyRegistryContext::with_rotation_generation(
            ArchiveId::from_bytes([1; 16]),
            KeyKind::Archive,
            KeyEpoch::from_bytes([3; 16]),
            7,
        );
        let plaintext =
            KeyRegistryPlaintext::encode_archive(&context, &ArchiveDek::from_bytes([9; 32]))
                .unwrap();
        for mode in [
            FaultyRegistryKmsMode::PartialWriteThenError,
            FaultyRegistryKmsMode::PartialWriteThenOversizedLength,
        ] {
            let provider = GcsArchiveV3RegistryProvider::new(
                Arc::new(FakeTransport::new()),
                Arc::new(FaultyRegistryKms { mode }),
            );
            let mut wrapped = [0xa1; MAX_WRAPPED_KEY_REGISTRY_BYTES];
            let wrap_result = provider
                .wrap_registry(
                    &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext::for_test(),
                    &context,
                    &plaintext,
                    &mut wrapped,
                )
                .await;
            assert_eq!(
                wrap_result,
                match mode {
                    FaultyRegistryKmsMode::PartialWriteThenError => {
                        Err(ArchiveV3Error::InvalidContext)
                    }
                    FaultyRegistryKmsMode::PartialWriteThenOversizedLength => {
                        Err(ArchiveV3Error::TooLarge("wrapped key registry"))
                    }
                }
            );
            assert!(wrapped.iter().all(|byte| *byte == 0));

            let mut unwrapped = [0xa2; KEY_REGISTRY_PLAINTEXT_BYTES];
            let unwrap_result = provider
                .kms_unwrap_exact(&context, b"wrapped", &mut unwrapped)
                .await;
            assert_eq!(
                unwrap_result,
                match mode {
                    FaultyRegistryKmsMode::PartialWriteThenError => {
                        Err(ArchiveV3Error::InvalidContext)
                    }
                    FaultyRegistryKmsMode::PartialWriteThenOversizedLength => {
                        Err(ArchiveV3Error::TooLarge("key registry plaintext"))
                    }
                }
            );
            assert!(unwrapped.iter().all(|byte| *byte == 0));
        }
    }

    #[tokio::test]
    async fn registry_create_uses_the_archive_wide_permanent_id_claim() {
        let transport = Arc::new(FakeTransport::new());
        let registry_context = KeyRegistryContext::new(
            ArchiveId::from_bytes([1; 16]),
            KeyKind::Archive,
            KeyEpoch::from_bytes([3; 16]),
        );
        let object_id = ObjectId::from_bytes([4; 16]);
        let kms = Arc::new(FakeRegistryKms {
            expected_context: registry_context,
            expected_wrapped: Vec::new(),
            plaintext: Vec::new(),
        });
        let provider = GcsArchiveV3RegistryProvider::new(transport.clone(), kms);
        assert_eq!(
            provider
                .create_wrapped_if_absent(&registry_context, object_id, b"wrapped")
                .await
                .unwrap(),
            CreateIfAbsent::Created
        );
        let conflicting_extent = context(4);
        let backend = GcsArchiveV3Backend::new(transport);
        assert_eq!(
            backend
                .create_if_absent(
                    conflicting_extent.object_key(),
                    envelope(&conflicting_extent, 8),
                )
                .await,
            Err(ArchiveV3Error::Conflict)
        );
    }

    #[tokio::test]
    async fn bounded_reads_root_roles_and_debug_output_fail_closed() {
        let transport = Arc::new(FakeTransport::new());
        let backend = GcsArchiveV3Backend::new(transport.clone());
        let extent = context(4);
        transport.objects.lock().unwrap().insert(
            extent.object_key().as_str().to_owned(),
            vec![vec![0; MAX_ENCODED_ENVELOPE_BYTES + 1]],
        );
        assert_eq!(
            backend.get(&extent.object_key()).await,
            Err(ArchiveV3Error::TooLarge("transport object"))
        );

        let root_provider = GcsArchiveV3RootProvider::new(transport);
        assert_eq!(
            root_provider.read_exact(&extent).await,
            Err(WitnessError::Malformed)
        );
        assert_eq!(
            format!(
                "{:?}",
                GcsArchiveV3Page {
                    names: vec![extent.object_key().as_str().to_owned()]
                }
            ),
            "GcsArchiveV3Page(<redacted>)"
        );
        assert_eq!(format!("{backend:?}"), "GcsArchiveV3Backend(<redacted>)");

        let prefix = ArchivePrefix::for_archive(ArchiveId::from_bytes([1; 16]));
        let oversized_name = format!(
            "{}{}",
            prefix.as_str(),
            "x".repeat(MAX_CANONICAL_OBJECT_KEY_BYTES)
        );
        let oversized_transport = Arc::new(FakeTransport::new());
        oversized_transport
            .objects
            .lock()
            .unwrap()
            .insert(oversized_name, vec![vec![1]]);
        let oversized_backend = GcsArchiveV3Backend::new(oversized_transport);
        assert_eq!(
            oversized_backend
                .enumerate(
                    &prefix,
                    None,
                    crate::archive_v3::EnumerationLimit::new(1).unwrap(),
                )
                .await,
            Err(ArchiveV3Error::TooLarge("transport page"))
        );
    }
}
