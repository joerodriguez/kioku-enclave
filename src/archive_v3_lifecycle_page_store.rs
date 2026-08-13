#![allow(
    dead_code,
    reason = "inactive ADR-0022 encrypted lifecycle page store is compiled and fake-tested before runtime wiring"
)]

//! Inactive encrypted external storage for ADR-0022 lifecycle inventory pages.
//!
//! This module can create, authenticate, and eventually erase only exact
//! immutable lifecycle-page object names. It has no list operation, provider
//! implementation, credential/config source, runtime constructor, walker, or
//! deletion coordinator. Production key construction requires proof that the
//! control-store DEK came from a validated encrypted-control generation.

use crate::{
    archive_v3::{ArchiveId, ObjectId},
    archive_v3_lifecycle::{
        validate_cleanup_page_chain, ArchiveLifecyclePageStore, DurableInventoryPage,
        DurablePhysicalCompletion, ErasedInventoryPages, InventoryPage, InventoryPageReference,
        LifecycleError, MAX_LIFECYCLE_PAGES, MAX_LIFECYCLE_PAGE_BYTES,
    },
    cp::control_store::LifecyclePersistenceContext,
};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use async_trait::async_trait;
use hkdf::Hkdf;
use sha2::Sha256;
use std::{fmt, fmt::Write as _, sync::Arc};
use zeroize::Zeroizing;

const PAGE_OBJECT_MAGIC: &[u8; 4] = b"KILC";
const PAGE_OBJECT_VERSION: u16 = 1;
const PAGE_OBJECT_HEADER_BYTES: usize = PAGE_OBJECT_MAGIC.len() + 2 + 12;
const PAGE_OBJECT_TAG_BYTES: usize = 16;
const MAX_PAGE_OBJECT_BYTES: usize =
    PAGE_OBJECT_HEADER_BYTES + MAX_LIFECYCLE_PAGE_BYTES + PAGE_OBJECT_TAG_BYTES;
const PAGE_KEY_SALT: &[u8] = b"kioku/archive-v3/lifecycle-page-control-key/v1\0";
const PAGE_KEY_DOMAIN: &[u8] = b"kioku/archive-v3/lifecycle-page-derived-key/v1\0";
const PAGE_NONCE_DOMAIN: &[u8] = b"kioku/archive-v3/lifecycle-page-derived-nonce/v1\0";
const PAGE_AAD_DOMAIN: &[u8] = b"kioku/archive-v3/lifecycle-page-object-aad/v1\0";
const PAGE_OBJECT_PREFIX: &str = "control/archive-v3/lifecycle-pages";

/// Redacted transport failures. Any mutating-response uncertainty is always
/// reconciled through an exact read or exact all-generation absence check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecyclePageTransportError {
    OutcomeUnknown,
    Unavailable,
    TooLarge,
    Protocol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecyclePageCreateResult {
    Created,
    PreconditionFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecyclePageDeleteResult {
    DeletedAllGenerations,
    Absent,
}

/// Narrow exact-name transport. It deliberately exposes no prefix list,
/// overwrite, metadata patch, bucket, token, or provider-generation API.
#[async_trait]
pub(crate) trait LifecyclePageTransport: Send + Sync {
    async fn create_if_absent(
        &self,
        exact_name: &str,
        ciphertext: &[u8],
    ) -> Result<LifecyclePageCreateResult, LifecyclePageTransportError>;

    /// Implementations must enforce `max_bytes` on both declared and streamed
    /// response lengths. `None` is definitive exact-name absence.
    async fn read_exact(
        &self,
        exact_name: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, LifecyclePageTransportError>;

    async fn delete_all_generations_exact(
        &self,
        exact_name: &str,
    ) -> Result<LifecyclePageDeleteResult, LifecyclePageTransportError>;

    /// Proves that live, noncurrent, and soft-deleted generations of this one
    /// exact name are all absent.
    async fn verify_all_generations_absent_exact(
        &self,
        exact_name: &str,
    ) -> Result<bool, LifecyclePageTransportError>;

    /// After durable admission has frozen, prove that no previously submitted
    /// create for any supplied exact name can still settle. A production
    /// adapter must own requests through terminal provider response or use an
    /// independently authenticated provider/trusted-time drain; a delay or
    /// configuration boolean is not evidence.
    async fn frozen_create_requests_drained(
        &self,
        exact_names: &[&str],
    ) -> Result<bool, LifecyclePageTransportError>;
}

/// Root secret for deriving one independent key per exact lifecycle page.
/// Only the encrypted control-store producer can construct it in production.
pub(crate) struct LifecyclePageControlKey {
    control_dek: Zeroizing<[u8; 32]>,
}

impl LifecyclePageControlKey {
    pub(crate) fn from_loaded_control_generation(
        _producer: &LifecyclePersistenceContext,
        control_dek: Zeroizing<[u8; 32]>,
    ) -> Result<Self, LifecycleError> {
        Self::validated(control_dek)
    }

    fn validated(control_dek: Zeroizing<[u8; 32]>) -> Result<Self, LifecycleError> {
        if control_dek.iter().all(|byte| *byte == 0) {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self { control_dek })
    }

    #[cfg(test)]
    fn for_test(control_dek: [u8; 32]) -> Self {
        Self::validated(Zeroizing::new(control_dek)).unwrap()
    }
}

impl fmt::Debug for LifecyclePageControlKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LifecyclePageControlKey(<opaque>)")
    }
}

/// Unforgeable outside this producer module. The lifecycle receipt factory
/// accepts it only after exact AEAD readback and canonical page validation.
pub(crate) struct AuthenticatedPageReadback(());

impl AuthenticatedPageReadback {
    fn validated() -> Self {
        Self(())
    }
}

/// Unforgeable outside this producer module. It is minted only after exact
/// all-generation and soft-delete absence for the complete sealed page chain.
pub(crate) struct AuthenticatedPageAbsence(());

impl AuthenticatedPageAbsence {
    fn validated() -> Self {
        Self(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageCreateDisposition {
    /// A request may already have been submitted; retry only the same exact
    /// deterministic name and ciphertext, then authenticate exact readback.
    OutcomeUnknown,
    /// Durable control already records authenticated exact readback. Do not
    /// submit another create; authenticate the exact object again.
    Created,
}

/// Durable control-owned permission for exactly one lifecycle-page create.
/// The row is persisted as outcome-unknown before this receipt can escape the
/// control transaction, so cancellation and process loss remain drain work.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurablePageCreateAdmission {
    deletion_fence: ObjectId,
    reference: InventoryPageReference,
    disposition: PageCreateDisposition,
}

impl DurablePageCreateAdmission {
    pub(crate) fn from_persisted(
        _producer: &LifecyclePersistenceContext,
        deletion_fence: ObjectId,
        reference: InventoryPageReference,
        disposition: PageCreateDisposition,
    ) -> Result<Self, LifecycleError> {
        validate_reference(deletion_fence, reference)?;
        Ok(Self {
            deletion_fence,
            reference,
            disposition,
        })
    }

    fn matches(self, deletion_fence: ObjectId, reference: InventoryPageReference) -> bool {
        self.deletion_fence == deletion_fence && self.reference == reference
    }

    const fn disposition(self) -> PageCreateDisposition {
        self.disposition
    }

    pub(crate) const fn deletion_fence(self) -> ObjectId {
        self.deletion_fence
    }

    pub(crate) const fn reference(self) -> InventoryPageReference {
        self.reference
    }
}

impl fmt::Debug for DurablePageCreateAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurablePageCreateAdmission(<opaque>)")
    }
}

/// Producer-sealed proof that the durable control anchor is physical-complete,
/// its page-create admission set is frozen, every row was exact-readback
/// created before sealing, and the references still match that same seal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrozenPageCreateSet {
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    inventory_commitment: [u8; 32],
    page_count: u32,
    terminal_page_hash: [u8; 32],
}

impl FrozenPageCreateSet {
    pub(crate) fn from_persisted(
        _producer: &LifecyclePersistenceContext,
        completion: DurablePhysicalCompletion,
        references: &[InventoryPageReference],
    ) -> Result<Self, LifecycleError> {
        validate_cleanup_page_chain(&completion, references)?;
        let seal = completion.physical_receipt().seal();
        Ok(Self {
            archive_id: seal.archive_id(),
            deletion_fence: seal.deletion_fence(),
            inventory_commitment: seal.inventory_commitment(),
            page_count: seal.page_count(),
            terminal_page_hash: seal.terminal_page_hash(),
        })
    }

    fn matches(
        self,
        completion: DurablePhysicalCompletion,
        references: &[InventoryPageReference],
    ) -> bool {
        if validate_cleanup_page_chain(&completion, references).is_err() {
            return false;
        }
        let seal = completion.physical_receipt().seal();
        self.archive_id == seal.archive_id()
            && self.deletion_fence == seal.deletion_fence()
            && self.inventory_commitment == seal.inventory_commitment()
            && self.page_count == seal.page_count()
            && self.terminal_page_hash == seal.terminal_page_hash()
    }

    pub(crate) const fn archive_id(self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn deletion_fence(self) -> ObjectId {
        self.deletion_fence
    }
}

impl fmt::Debug for FrozenPageCreateSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenPageCreateSet(<opaque>)")
    }
}

/// Exact durable page split recovered from encrypted control after restart.
/// Created pages retain only authenticated external-read references; at most
/// one unresolved page retains its original canonical bytes for exact retry.
pub(crate) struct RecoveredPageCreatePlan {
    created: Vec<InventoryPageReference>,
    outcome_unknown: Option<InventoryPage>,
}

impl RecoveredPageCreatePlan {
    pub(crate) fn from_persisted(
        _producer: &LifecyclePersistenceContext,
        archive_id: ArchiveId,
        created: Vec<InventoryPageReference>,
        outcome_unknown: Option<InventoryPage>,
    ) -> Result<Self, LifecycleError> {
        Self::validated(archive_id, created, outcome_unknown)
    }

    fn validated(
        archive_id: ArchiveId,
        created: Vec<InventoryPageReference>,
        outcome_unknown: Option<InventoryPage>,
    ) -> Result<Self, LifecycleError> {
        let unresolved_count = if outcome_unknown.is_some() { 1 } else { 0 };
        if created.len() + unresolved_count > MAX_LIFECYCLE_PAGES {
            return Err(LifecycleError::Limit);
        }
        let mut previous = [0; 32];
        for (ordinal, reference) in created.iter().enumerate() {
            if reference.archive_id() != archive_id
                || usize::try_from(reference.page_ordinal()).ok() != Some(ordinal)
                || reference.previous_hash() != previous
            {
                return Err(LifecycleError::ChainMismatch);
            }
            previous = reference.page_hash();
        }
        if let Some(page) = &outcome_unknown {
            let reference = page.reference();
            if reference.archive_id() != archive_id
                || usize::try_from(reference.page_ordinal()).ok() != Some(created.len())
                || reference.previous_hash() != previous
                || InventoryPage::decode(archive_id, page.encoded())? != *page
            {
                return Err(LifecycleError::ChainMismatch);
            }
        }
        Ok(Self {
            created,
            outcome_unknown,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        archive_id: ArchiveId,
        created: Vec<InventoryPageReference>,
        outcome_unknown: Option<InventoryPage>,
    ) -> Result<Self, LifecycleError> {
        Self::validated(archive_id, created, outcome_unknown)
    }

    pub(crate) fn created(&self) -> &[InventoryPageReference] {
        &self.created
    }

    pub(crate) fn outcome_unknown(&self) -> Option<&InventoryPage> {
        self.outcome_unknown.as_ref()
    }
}

impl fmt::Debug for RecoveredPageCreatePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveredPageCreatePlan(<opaque>)")
    }
}

/// Durable control boundary for page creates. Production implementation lives
/// in the encrypted control store; this module cannot mint its receipts.
#[async_trait]
pub(crate) trait LifecyclePageAdmissionLedger: Send + Sync {
    async fn admit_page_create(
        &self,
        deletion_fence: ObjectId,
        page: &InventoryPage,
    ) -> Result<DurablePageCreateAdmission, LifecycleError>;

    /// Recover the sole unresolved exact page bytes retained by encrypted
    /// control. Created rows retain only references, so the global control
    /// blob never accumulates the complete external inventory.
    async fn recover_page_create_plan(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<RecoveredPageCreatePlan, LifecycleError>;

    async fn reconcile_page_created(
        &self,
        admission: DurablePageCreateAdmission,
        durable: &DurableInventoryPage,
    ) -> Result<(), LifecycleError>;

    async fn authorize_page_cleanup(
        &self,
        completion: DurablePhysicalCompletion,
        references: &[InventoryPageReference],
    ) -> Result<FrozenPageCreateSet, LifecycleError>;
}

struct LifecyclePageObjectName(String);

impl LifecyclePageObjectName {
    fn derive(
        deletion_fence: ObjectId,
        reference: InventoryPageReference,
    ) -> Result<Self, LifecycleError> {
        validate_reference(deletion_fence, reference)?;
        let mut value =
            String::with_capacity(PAGE_OBJECT_PREFIX.len() + 1 + 32 + 1 + 32 + 1 + 8 + 1 + 64 + 4);
        value.push_str(PAGE_OBJECT_PREFIX);
        value.push('/');
        push_hex(&mut value, reference.archive_id().as_bytes());
        value.push('/');
        push_hex(&mut value, deletion_fence.as_bytes());
        value.push('/');
        let _ = write!(&mut value, "{:08x}-", reference.page_ordinal());
        push_hex(&mut value, &reference.page_hash());
        value.push_str(".enc");
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LifecyclePageObjectName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LifecyclePageObjectName(<opaque>)")
    }
}

/// Concrete crypto/reconciliation producer over an injected narrow transport.
/// It is intentionally non-cloneable and exposes no provider or key getter.
pub(crate) struct EncryptedLifecyclePageStore {
    control_key: LifecyclePageControlKey,
    transport: Arc<dyn LifecyclePageTransport>,
    admissions: Arc<dyn LifecyclePageAdmissionLedger>,
}

impl EncryptedLifecyclePageStore {
    pub(crate) fn new(
        control_key: LifecyclePageControlKey,
        transport: Arc<dyn LifecyclePageTransport>,
        admissions: Arc<dyn LifecyclePageAdmissionLedger>,
    ) -> Self {
        Self {
            control_key,
            transport,
            admissions,
        }
    }

    fn encrypt_page(
        &self,
        deletion_fence: ObjectId,
        page: &InventoryPage,
    ) -> Result<Vec<u8>, LifecycleError> {
        let reference = page.reference();
        validate_reference(deletion_fence, reference)?;
        if InventoryPage::decode(reference.archive_id(), page.encoded())? != *page {
            return Err(LifecycleError::ChainMismatch);
        }
        let name = LifecyclePageObjectName::derive(deletion_fence, reference)?;
        let context = page_context(deletion_fence, reference, &name)?;
        let key = self.derive_page_key(&context)?;
        let nonce = self.derive_page_nonce(&context)?;
        let aad = page_aad(&context);
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| LifecycleError::Corrupt)?;
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: page.encoded(),
                    aad: &aad,
                },
            )
            .map_err(|_| LifecycleError::Corrupt)?;
        let mut encoded = Vec::with_capacity(PAGE_OBJECT_HEADER_BYTES + ciphertext.len());
        encoded.extend_from_slice(PAGE_OBJECT_MAGIC);
        encoded.extend_from_slice(&PAGE_OBJECT_VERSION.to_be_bytes());
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        if encoded.len() > MAX_PAGE_OBJECT_BYTES {
            return Err(LifecycleError::Limit);
        }
        Ok(encoded)
    }

    fn derive_page_key(&self, context: &[u8]) -> Result<Zeroizing<[u8; 32]>, LifecycleError> {
        let hkdf = Hkdf::<Sha256>::new(Some(PAGE_KEY_SALT), &self.control_key.control_dek[..]);
        let mut info = Zeroizing::new(Vec::with_capacity(PAGE_KEY_DOMAIN.len() + context.len()));
        info.extend_from_slice(PAGE_KEY_DOMAIN);
        info.extend_from_slice(context);
        let mut key = Zeroizing::new([0; 32]);
        hkdf.expand(&info[..], &mut key[..])
            .map_err(|_| LifecycleError::Corrupt)?;
        Ok(key)
    }

    fn derive_page_nonce(&self, context: &[u8]) -> Result<[u8; 12], LifecycleError> {
        let hkdf = Hkdf::<Sha256>::new(Some(PAGE_KEY_SALT), &self.control_key.control_dek[..]);
        let mut info = Zeroizing::new(Vec::with_capacity(PAGE_NONCE_DOMAIN.len() + context.len()));
        info.extend_from_slice(PAGE_NONCE_DOMAIN);
        info.extend_from_slice(context);
        let mut nonce = [0; 12];
        hkdf.expand(&info[..], &mut nonce)
            .map_err(|_| LifecycleError::Corrupt)?;
        Ok(nonce)
    }

    async fn authenticated_read(
        &self,
        deletion_fence: ObjectId,
        reference: InventoryPageReference,
        missing: LifecycleError,
    ) -> Result<DurableInventoryPage, LifecycleError> {
        let name = LifecyclePageObjectName::derive(deletion_fence, reference)?;
        let exact_len = page_object_len(reference)?;
        let encoded = self
            .transport
            .read_exact(name.as_str(), exact_len)
            .await
            .map_err(map_transport_error)?
            .ok_or(missing)?;
        if encoded.len() != exact_len || encoded.len() > MAX_PAGE_OBJECT_BYTES {
            return Err(LifecycleError::Limit);
        }
        let page = self.decrypt_page(deletion_fence, reference, &name, &encoded)?;
        DurableInventoryPage::from_authenticated_external_readback(
            &AuthenticatedPageReadback::validated(),
            reference,
            page,
        )
    }

    fn decrypt_page(
        &self,
        deletion_fence: ObjectId,
        reference: InventoryPageReference,
        name: &LifecyclePageObjectName,
        encoded: &[u8],
    ) -> Result<InventoryPage, LifecycleError> {
        if encoded.len() != page_object_len(reference)?
            || encoded.get(..PAGE_OBJECT_MAGIC.len()) != Some(PAGE_OBJECT_MAGIC)
            || encoded.get(PAGE_OBJECT_MAGIC.len()..PAGE_OBJECT_MAGIC.len() + 2)
                != Some(PAGE_OBJECT_VERSION.to_be_bytes().as_slice())
        {
            return Err(LifecycleError::Corrupt);
        }
        let nonce_start = PAGE_OBJECT_MAGIC.len() + 2;
        let ciphertext_start = nonce_start + 12;
        let nonce: &[u8; 12] = encoded
            .get(nonce_start..ciphertext_start)
            .ok_or(LifecycleError::Corrupt)?
            .try_into()
            .map_err(|_| LifecycleError::Corrupt)?;
        let ciphertext = encoded
            .get(ciphertext_start..)
            .ok_or(LifecycleError::Corrupt)?;
        let context = page_context(deletion_fence, reference, name)?;
        let key = self.derive_page_key(&context)?;
        let expected_nonce = self.derive_page_nonce(&context)?;
        if nonce != &expected_nonce {
            return Err(LifecycleError::Corrupt);
        }
        let aad = page_aad(&context);
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| LifecycleError::Corrupt)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    (&expected_nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| LifecycleError::Corrupt)?,
        );
        if plaintext.len()
            != usize::try_from(reference.encoded_len()).map_err(|_| LifecycleError::Limit)?
        {
            return Err(LifecycleError::ChainMismatch);
        }
        let page = InventoryPage::decode(reference.archive_id(), &plaintext)?;
        if page.reference() != reference {
            return Err(LifecycleError::ChainMismatch);
        }
        Ok(page)
    }

    async fn reconcile_after_create(
        &self,
        deletion_fence: ObjectId,
        reference: InventoryPageReference,
    ) -> Result<DurableInventoryPage, LifecycleError> {
        self.authenticated_read(deletion_fence, reference, LifecycleError::Unavailable)
            .await
    }

    async fn erase_one_exact_name(
        &self,
        name: &LifecyclePageObjectName,
    ) -> Result<(), LifecycleError> {
        let _delete_result = self
            .transport
            .delete_all_generations_exact(name.as_str())
            .await;
        match self
            .transport
            .verify_all_generations_absent_exact(name.as_str())
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(LifecycleError::InvalidState),
            Err(error) => Err(map_transport_error(error)),
        }
    }
}

impl fmt::Debug for EncryptedLifecyclePageStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedLifecyclePageStore(<opaque>)")
    }
}

#[async_trait]
impl ArchiveLifecyclePageStore for EncryptedLifecyclePageStore {
    async fn create_exact_page(
        &self,
        deletion_fence: ObjectId,
        page: &InventoryPage,
    ) -> Result<DurableInventoryPage, LifecycleError> {
        let reference = page.reference();
        let name = LifecyclePageObjectName::derive(deletion_fence, reference)?;
        let ciphertext = self.encrypt_page(deletion_fence, page)?;
        let admission = self
            .admissions
            .admit_page_create(deletion_fence, page)
            .await?;
        if !admission.matches(deletion_fence, reference) {
            return Err(LifecycleError::Corrupt);
        }
        if admission.disposition() == PageCreateDisposition::Created {
            return self
                .authenticated_read(deletion_fence, reference, LifecycleError::InvalidState)
                .await;
        }
        match self
            .transport
            .create_if_absent(name.as_str(), &ciphertext)
            .await
        {
            Ok(
                LifecyclePageCreateResult::Created | LifecyclePageCreateResult::PreconditionFailed,
            )
            | Err(LifecyclePageTransportError::OutcomeUnknown)
            | Err(LifecyclePageTransportError::Unavailable) => {
                let durable = self
                    .reconcile_after_create(deletion_fence, reference)
                    .await?;
                self.admissions
                    .reconcile_page_created(admission, &durable)
                    .await?;
                Ok(durable)
            }
            Err(error) => Err(map_transport_error(error)),
        }
    }

    async fn read_exact_page(
        &self,
        deletion_fence: ObjectId,
        reference: InventoryPageReference,
    ) -> Result<DurableInventoryPage, LifecycleError> {
        self.authenticated_read(deletion_fence, reference, LifecycleError::InvalidState)
            .await
    }

    async fn erase_exact_pages_after_physical_completion(
        &self,
        completion: &DurablePhysicalCompletion,
        references: &[InventoryPageReference],
    ) -> Result<ErasedInventoryPages, LifecycleError> {
        validate_cleanup_page_chain(completion, references)?;
        let seal = completion.physical_receipt().seal();
        // Resolve and structurally validate every exact target before the first
        // destructive request. A corrupt later reference must not permit a
        // valid earlier page to be removed.
        let names = references
            .iter()
            .map(|reference| LifecyclePageObjectName::derive(seal.deletion_fence(), *reference))
            .collect::<Result<Vec<_>, _>>()?;
        let frozen = self
            .admissions
            .authorize_page_cleanup(*completion, references)
            .await?;
        if !frozen.matches(*completion, references) {
            return Err(LifecycleError::Corrupt);
        }
        let exact_names = names
            .iter()
            .map(LifecyclePageObjectName::as_str)
            .collect::<Vec<_>>();
        if !self
            .transport
            .frozen_create_requests_drained(&exact_names)
            .await
            .map_err(map_transport_error)?
        {
            return Err(LifecycleError::InvalidState);
        }
        for name in &names {
            self.erase_one_exact_name(name).await?;
        }
        ErasedInventoryPages::from_authenticated_external_absence(
            &AuthenticatedPageAbsence::validated(),
            completion,
            references,
        )
    }
}

impl EncryptedLifecyclePageStore {
    /// Resume the one exact unresolved page after process loss. The encrypted
    /// control row supplies the original canonical bytes/partition; the normal
    /// create path reuses its durable admission and deterministic ciphertext.
    pub(crate) async fn resume_outcome_unknown_page(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<Option<DurableInventoryPage>, LifecycleError> {
        let plan = self
            .admissions
            .recover_page_create_plan(archive_id, deletion_fence)
            .await?;
        let Some(page) = plan.outcome_unknown() else {
            return Ok(None);
        };
        self.create_exact_page(deletion_fence, page).await.map(Some)
    }
}

fn validate_reference(
    deletion_fence: ObjectId,
    reference: InventoryPageReference,
) -> Result<(), LifecycleError> {
    let hash = reference.page_hash();
    let mut expected_page_id = [0; 16];
    expected_page_id.copy_from_slice(&hash[..16]);
    if deletion_fence.as_bytes().iter().all(|byte| *byte == 0)
        || reference
            .archive_id()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || hash.iter().all(|byte| *byte == 0)
        || expected_page_id.as_slice() != reference.page_id().as_bytes()
        || reference.encoded_len() == 0
        || usize::try_from(reference.page_ordinal())
            .map_or(true, |ordinal| ordinal >= MAX_LIFECYCLE_PAGES)
        || usize::try_from(reference.encoded_len())
            .map_or(true, |length| length > MAX_LIFECYCLE_PAGE_BYTES)
        || (reference.page_ordinal() == 0) != (reference.previous_hash() == [0; 32])
    {
        return Err(LifecycleError::Corrupt);
    }
    Ok(())
}

fn page_object_len(reference: InventoryPageReference) -> Result<usize, LifecycleError> {
    PAGE_OBJECT_HEADER_BYTES
        .checked_add(usize::try_from(reference.encoded_len()).map_err(|_| LifecycleError::Limit)?)
        .and_then(|length| length.checked_add(PAGE_OBJECT_TAG_BYTES))
        .filter(|length| *length <= MAX_PAGE_OBJECT_BYTES)
        .ok_or(LifecycleError::Limit)
}

fn page_context(
    deletion_fence: ObjectId,
    reference: InventoryPageReference,
    name: &LifecyclePageObjectName,
) -> Result<Zeroizing<Vec<u8>>, LifecycleError> {
    validate_reference(deletion_fence, reference)?;
    let name_len = u16::try_from(name.as_str().len()).map_err(|_| LifecycleError::Limit)?;
    let mut context = Zeroizing::new(Vec::with_capacity(
        2 + name.as_str().len() + 16 + 16 + 4 + 16 + 32 + 32 + 4,
    ));
    context.extend_from_slice(&name_len.to_be_bytes());
    context.extend_from_slice(name.as_str().as_bytes());
    context.extend_from_slice(reference.archive_id().as_bytes());
    context.extend_from_slice(deletion_fence.as_bytes());
    context.extend_from_slice(&reference.page_ordinal().to_be_bytes());
    context.extend_from_slice(reference.page_id().as_bytes());
    context.extend_from_slice(&reference.previous_hash());
    context.extend_from_slice(&reference.page_hash());
    context.extend_from_slice(&reference.encoded_len().to_be_bytes());
    Ok(context)
}

fn page_aad(context: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut aad = Zeroizing::new(Vec::with_capacity(PAGE_AAD_DOMAIN.len() + context.len()));
    aad.extend_from_slice(PAGE_AAD_DOMAIN);
    aad.extend_from_slice(context);
    aad
}

fn push_hex(target: &mut String, bytes: &[u8]) {
    for byte in bytes {
        let _ = write!(target, "{byte:02x}");
    }
}

fn map_transport_error(error: LifecyclePageTransportError) -> LifecycleError {
    match error {
        LifecyclePageTransportError::OutcomeUnknown | LifecyclePageTransportError::Unavailable => {
            LifecycleError::Unavailable
        }
        LifecyclePageTransportError::TooLarge => LifecycleError::Limit,
        LifecyclePageTransportError::Protocol => LifecycleError::Corrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{DatabaseEpoch, KeyEpoch, LogicalLocation, ObjectContext, ObjectRole},
        archive_v3_lifecycle::{
            ArtifactCreateState, BootstrapAttemptId, DeletionInventorySeal,
            PhysicalDeletionReceipt, PlannedArtifact,
        },
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
    };
    use tokio::sync::Notify;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CreateAction {
        Normal,
        CreatedWithoutStore,
        OutcomeUnknownAfterStore,
        OutcomeUnknownWithoutStore,
        UnavailableAfterStore,
        BlockAfterStore,
        TooLarge,
        Protocol,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DeleteAction {
        Normal,
        OutcomeUnknownAfterDelete,
        LeaveSoftDeleted,
    }

    #[derive(Default)]
    struct FakeState {
        objects: BTreeMap<String, Vec<Vec<u8>>>,
        create_payloads: Vec<Vec<u8>>,
        soft_deleted: BTreeSet<String>,
        create_calls: usize,
        read_calls: usize,
        delete_calls: usize,
        verify_calls: usize,
        max_read: Option<usize>,
        create_action: Option<CreateAction>,
        delete_action: Option<DeleteAction>,
        fail_delete_call: Option<usize>,
        read_override: Option<Result<Option<Vec<u8>>, LifecyclePageTransportError>>,
        create_drain: Option<Result<bool, LifecyclePageTransportError>>,
    }

    #[derive(Default)]
    struct FakeTransport {
        state: Mutex<FakeState>,
        committed_before_block: AtomicBool,
        committed_notify: Notify,
        release_create: Notify,
    }

    impl FakeTransport {
        fn set_create_action(&self, action: CreateAction) {
            self.state.lock().unwrap().create_action = Some(action);
        }

        fn set_delete_action(&self, action: DeleteAction) {
            self.state.lock().unwrap().delete_action = Some(action);
        }

        fn set_fail_delete_call(&self, call: usize) {
            self.state.lock().unwrap().fail_delete_call = Some(call);
        }

        fn set_read_override(&self, value: Result<Option<Vec<u8>>, LifecyclePageTransportError>) {
            self.state.lock().unwrap().read_override = Some(value);
        }

        fn only_object(&self) -> (String, Vec<u8>) {
            let state = self.state.lock().unwrap();
            assert_eq!(state.objects.len(), 1);
            let (name, generations) = state.objects.iter().next().unwrap();
            (name.clone(), generations.last().unwrap().clone())
        }

        fn replace_object(&self, name: String, bytes: Vec<u8>) {
            self.state.lock().unwrap().objects.insert(name, vec![bytes]);
        }

        fn copy_object_to(&self, source: &str, destination: String) {
            let mut state = self.state.lock().unwrap();
            let bytes = state.objects[source].last().unwrap().clone();
            state.objects.insert(destination, vec![bytes]);
        }

        fn add_generation(&self, name: &str) {
            let mut state = self.state.lock().unwrap();
            let bytes = state.objects[name].last().unwrap().clone();
            state.objects.get_mut(name).unwrap().push(bytes);
        }

        fn mark_soft_deleted(&self, name: &str) {
            self.state
                .lock()
                .unwrap()
                .soft_deleted
                .insert(name.to_owned());
        }

        fn counts(&self) -> (usize, usize, usize, usize) {
            let state = self.state.lock().unwrap();
            (
                state.create_calls,
                state.read_calls,
                state.delete_calls,
                state.verify_calls,
            )
        }

        fn object_count(&self) -> usize {
            self.state.lock().unwrap().objects.len()
        }

        fn create_payloads(&self) -> Vec<Vec<u8>> {
            self.state.lock().unwrap().create_payloads.clone()
        }

        fn max_read(&self) -> Option<usize> {
            self.state.lock().unwrap().max_read
        }

        async fn wait_until_committed(&self) {
            loop {
                if self.committed_before_block.load(Ordering::SeqCst) {
                    return;
                }
                self.committed_notify.notified().await;
            }
        }
    }

    #[async_trait]
    impl LifecyclePageTransport for FakeTransport {
        async fn create_if_absent(
            &self,
            exact_name: &str,
            ciphertext: &[u8],
        ) -> Result<LifecyclePageCreateResult, LifecyclePageTransportError> {
            let action = {
                let mut state = self.state.lock().unwrap();
                state.create_calls += 1;
                state.create_payloads.push(ciphertext.to_vec());
                state.create_action.take().unwrap_or(CreateAction::Normal)
            };
            match action {
                CreateAction::CreatedWithoutStore => Ok(LifecyclePageCreateResult::Created),
                CreateAction::OutcomeUnknownWithoutStore => {
                    Err(LifecyclePageTransportError::OutcomeUnknown)
                }
                CreateAction::TooLarge => Err(LifecyclePageTransportError::TooLarge),
                CreateAction::Protocol => Err(LifecyclePageTransportError::Protocol),
                CreateAction::Normal
                | CreateAction::OutcomeUnknownAfterStore
                | CreateAction::UnavailableAfterStore
                | CreateAction::BlockAfterStore => {
                    let result = {
                        let mut state = self.state.lock().unwrap();
                        if state.objects.contains_key(exact_name) {
                            LifecyclePageCreateResult::PreconditionFailed
                        } else {
                            state
                                .objects
                                .insert(exact_name.to_owned(), vec![ciphertext.to_vec()]);
                            LifecyclePageCreateResult::Created
                        }
                    };
                    match action {
                        CreateAction::OutcomeUnknownAfterStore => {
                            Err(LifecyclePageTransportError::OutcomeUnknown)
                        }
                        CreateAction::UnavailableAfterStore => {
                            Err(LifecyclePageTransportError::Unavailable)
                        }
                        CreateAction::BlockAfterStore => {
                            self.committed_before_block.store(true, Ordering::SeqCst);
                            self.committed_notify.notify_waiters();
                            self.release_create.notified().await;
                            Ok(result)
                        }
                        _ => Ok(result),
                    }
                }
            }
        }

        async fn read_exact(
            &self,
            exact_name: &str,
            max_bytes: usize,
        ) -> Result<Option<Vec<u8>>, LifecyclePageTransportError> {
            let mut state = self.state.lock().unwrap();
            state.read_calls += 1;
            state.max_read = Some(max_bytes);
            if let Some(value) = state.read_override.take() {
                return value;
            }
            Ok(state
                .objects
                .get(exact_name)
                .and_then(|generations| generations.last().cloned()))
        }

        async fn delete_all_generations_exact(
            &self,
            exact_name: &str,
        ) -> Result<LifecyclePageDeleteResult, LifecyclePageTransportError> {
            let mut state = self.state.lock().unwrap();
            state.delete_calls += 1;
            let call = state.delete_calls;
            if state.fail_delete_call == Some(call) {
                return Err(LifecyclePageTransportError::OutcomeUnknown);
            }
            let action = state.delete_action.take().unwrap_or(DeleteAction::Normal);
            let existed = state.objects.remove(exact_name).is_some();
            match action {
                DeleteAction::Normal => {
                    state.soft_deleted.remove(exact_name);
                    Ok(if existed {
                        LifecyclePageDeleteResult::DeletedAllGenerations
                    } else {
                        LifecyclePageDeleteResult::Absent
                    })
                }
                DeleteAction::OutcomeUnknownAfterDelete => {
                    state.soft_deleted.remove(exact_name);
                    Err(LifecyclePageTransportError::OutcomeUnknown)
                }
                DeleteAction::LeaveSoftDeleted => {
                    state.soft_deleted.insert(exact_name.to_owned());
                    Ok(LifecyclePageDeleteResult::DeletedAllGenerations)
                }
            }
        }

        async fn verify_all_generations_absent_exact(
            &self,
            exact_name: &str,
        ) -> Result<bool, LifecyclePageTransportError> {
            let mut state = self.state.lock().unwrap();
            state.verify_calls += 1;
            Ok(!state.objects.contains_key(exact_name) && !state.soft_deleted.contains(exact_name))
        }

        async fn frozen_create_requests_drained(
            &self,
            _exact_names: &[&str],
        ) -> Result<bool, LifecyclePageTransportError> {
            self.state
                .lock()
                .unwrap()
                .create_drain
                .take()
                .unwrap_or(Ok(true))
        }
    }

    #[derive(Default)]
    struct FakeAdmissionState {
        pages: BTreeMap<(ArchiveId, u32), (ObjectId, InventoryPage, PageCreateDisposition)>,
        frozen: bool,
    }

    #[derive(Default)]
    struct FakeAdmissionLedger {
        state: Mutex<FakeAdmissionState>,
    }

    #[async_trait]
    impl LifecyclePageAdmissionLedger for FakeAdmissionLedger {
        async fn admit_page_create(
            &self,
            deletion_fence: ObjectId,
            page: &InventoryPage,
        ) -> Result<DurablePageCreateAdmission, LifecycleError> {
            let mut state = self.state.lock().unwrap();
            if state.frozen {
                return Err(LifecycleError::InvalidState);
            }
            let reference = page.reference();
            let key = (reference.archive_id(), reference.page_ordinal());
            if !state.pages.contains_key(&key) {
                let archive_pages = state
                    .pages
                    .range((reference.archive_id(), 0)..=(reference.archive_id(), u32::MAX));
                let mut count = 0usize;
                let mut terminal = [0; 32];
                for (_, entry) in archive_pages {
                    if entry.2 == PageCreateDisposition::OutcomeUnknown {
                        return Err(LifecycleError::InvalidState);
                    }
                    count += 1;
                    terminal = entry.1.page_hash();
                }
                if usize::try_from(reference.page_ordinal()).ok() != Some(count)
                    || reference.previous_hash() != terminal
                {
                    return Err(LifecycleError::ChainMismatch);
                }
            }
            let entry = state.pages.entry(key).or_insert((
                deletion_fence,
                page.clone(),
                PageCreateDisposition::OutcomeUnknown,
            ));
            if entry.0 != deletion_fence || entry.1 != *page {
                return Err(LifecycleError::DuplicateConflict);
            }
            Ok(DurablePageCreateAdmission {
                deletion_fence,
                reference,
                disposition: entry.2,
            })
        }

        async fn recover_page_create_plan(
            &self,
            archive_id: ArchiveId,
            deletion_fence: ObjectId,
        ) -> Result<RecoveredPageCreatePlan, LifecycleError> {
            let state = self.state.lock().unwrap();
            let mut created = Vec::new();
            let mut outcome_unknown = None;
            for ((_archive, _ordinal), entry) in
                state.pages.range((archive_id, 0)..=(archive_id, u32::MAX))
            {
                if entry.0 != deletion_fence {
                    return Err(LifecycleError::InvalidState);
                }
                match entry.2 {
                    PageCreateDisposition::Created => created.push(entry.1.reference()),
                    PageCreateDisposition::OutcomeUnknown => {
                        if outcome_unknown.replace(entry.1.clone()).is_some() {
                            return Err(LifecycleError::Corrupt);
                        }
                    }
                }
            }
            RecoveredPageCreatePlan::for_test(archive_id, created, outcome_unknown)
        }

        async fn reconcile_page_created(
            &self,
            admission: DurablePageCreateAdmission,
            durable: &DurableInventoryPage,
        ) -> Result<(), LifecycleError> {
            let mut state = self.state.lock().unwrap();
            let entry = state
                .pages
                .get_mut(&(
                    admission.reference.archive_id(),
                    admission.reference.page_ordinal(),
                ))
                .ok_or(LifecycleError::InvalidState)?;
            if admission.disposition != PageCreateDisposition::OutcomeUnknown
                || entry.0 != admission.deletion_fence
                || entry.1.reference() != admission.reference
                || durable.page().reference() != admission.reference
            {
                return Err(LifecycleError::ChainMismatch);
            }
            entry.2 = PageCreateDisposition::Created;
            Ok(())
        }

        async fn authorize_page_cleanup(
            &self,
            completion: DurablePhysicalCompletion,
            references: &[InventoryPageReference],
        ) -> Result<FrozenPageCreateSet, LifecycleError> {
            let mut state = self.state.lock().unwrap();
            if state.pages.len() != references.len()
                || references.iter().any(|reference| {
                    state
                        .pages
                        .get(&(reference.archive_id(), reference.page_ordinal()))
                        .is_none_or(|entry| {
                            entry.0 != completion.physical_receipt().seal().deletion_fence()
                                || entry.1.reference() != *reference
                                || entry.2 != PageCreateDisposition::Created
                        })
                })
            {
                return Err(LifecycleError::InvalidState);
            }
            state.frozen = true;
            Ok(FrozenPageCreateSet {
                archive_id: completion.physical_receipt().seal().archive_id(),
                deletion_fence: completion.physical_receipt().seal().deletion_fence(),
                inventory_commitment: completion.physical_receipt().seal().inventory_commitment(),
                page_count: completion.physical_receipt().seal().page_count(),
                terminal_page_hash: completion.physical_receipt().seal().terminal_page_hash(),
            })
        }
    }

    fn archive(value: u8) -> ArchiveId {
        ArchiveId::from_bytes([value; 16])
    }

    fn fence(value: u8) -> ObjectId {
        ObjectId::from_bytes([value; 16])
    }

    fn page(
        archive_id: ArchiveId,
        page_ordinal: u32,
        previous_hash: [u8; 32],
        seed: u8,
    ) -> InventoryPage {
        let context = ObjectContext::new(
            archive_id,
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: u64::from(page_ordinal) + u64::from(seed),
            },
            ObjectId::from_bytes([seed; 16]),
            None,
        )
        .unwrap();
        let artifact = PlannedArtifact::new(
            archive_id,
            BootstrapAttemptId::from_bytes([seed.wrapping_add(1); 16]).unwrap(),
            page_ordinal,
            context.object_key(),
            ObjectRole::RootV3,
            [seed.wrapping_add(2); 32],
            100,
            ArtifactCreateState::Created,
        )
        .unwrap();
        InventoryPage::build(
            archive_id,
            page_ordinal,
            previous_hash,
            vec![artifact.inventory_object().unwrap()],
        )
        .unwrap()
    }

    fn store(transport: Arc<FakeTransport>) -> EncryptedLifecyclePageStore {
        store_with_admissions(transport, Arc::new(FakeAdmissionLedger::default()))
    }

    fn store_with_admissions(
        transport: Arc<FakeTransport>,
        admissions: Arc<FakeAdmissionLedger>,
    ) -> EncryptedLifecyclePageStore {
        EncryptedLifecyclePageStore::new(
            LifecyclePageControlKey::for_test([0x5a; 32]),
            transport,
            admissions,
        )
    }

    fn completion(pages: &[InventoryPage], deletion_fence: ObjectId) -> DurablePhysicalCompletion {
        let durable = pages
            .iter()
            .cloned()
            .map(|page| {
                let encoded = page.encoded().to_vec();
                DurableInventoryPage::from_exact_readback(page, &encoded).unwrap()
            })
            .collect::<Vec<_>>();
        let seal =
            DeletionInventorySeal::for_test(pages[0].archive_id(), deletion_fence, 7, &durable)
                .unwrap();
        let physical = PhysicalDeletionReceipt::for_test(seal, [0x99; 32]).unwrap();
        DurablePhysicalCompletion::for_test(physical, 8).unwrap()
    }

    #[tokio::test]
    async fn create_is_exact_named_encrypted_and_read_back_before_receipt() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let archive_id = archive(1);
        let deletion_fence = fence(2);
        let page = page(archive_id, 0, [0; 32], 10);

        let durable = store
            .create_exact_page(deletion_fence, &page)
            .await
            .unwrap();
        assert_eq!(durable.page(), &page);
        assert_eq!(transport.counts(), (1, 1, 0, 0));
        let (name, ciphertext) = transport.only_object();
        assert!(name.starts_with("control/archive-v3/lifecycle-pages/"));
        assert!(name.ends_with(".enc"));
        assert!(!name.contains("user"));
        assert_ne!(ciphertext, page.encoded());
        assert_eq!(&ciphertext[..4], PAGE_OBJECT_MAGIC);
        assert_eq!(
            transport.max_read(),
            Some(page_object_len(page.reference()).unwrap())
        );
    }

    #[tokio::test]
    async fn retry_after_restart_reuses_exact_name_bytes_and_authenticates_plaintext() {
        let transport = Arc::new(FakeTransport::default());
        let first_store = store(transport.clone());
        let page = page(archive(1), 0, [0; 32], 11);
        let deletion_fence = fence(2);
        transport.set_create_action(CreateAction::OutcomeUnknownAfterStore);
        transport.set_read_override(Err(LifecyclePageTransportError::Unavailable));
        assert_eq!(
            first_store.create_exact_page(deletion_fence, &page).await,
            Err(LifecycleError::Unavailable)
        );
        let first = transport.only_object();

        drop(first_store);
        let restarted = store(transport.clone());
        restarted
            .create_exact_page(deletion_fence, &page)
            .await
            .unwrap();
        let second = transport.only_object();
        assert_eq!(first, second);
        let attempted = transport.create_payloads();
        assert_eq!(attempted.len(), 2);
        assert_eq!(attempted[0], attempted[1]);
        assert_eq!(transport.counts(), (2, 2, 0, 0));
    }

    #[tokio::test]
    async fn lost_success_and_unavailable_after_commit_reconcile_only_by_exact_read() {
        for action in [
            CreateAction::OutcomeUnknownAfterStore,
            CreateAction::UnavailableAfterStore,
        ] {
            let transport = Arc::new(FakeTransport::default());
            transport.set_create_action(action);
            let store = store(transport.clone());
            let page = page(archive(1), 0, [0; 32], 12);
            assert_eq!(
                store
                    .create_exact_page(fence(2), &page)
                    .await
                    .unwrap()
                    .page(),
                &page
            );
            assert_eq!(transport.counts(), (1, 1, 0, 0));
        }
    }

    #[tokio::test]
    async fn no_receipt_when_create_or_ambiguous_response_has_no_exact_object() {
        for action in [
            CreateAction::CreatedWithoutStore,
            CreateAction::OutcomeUnknownWithoutStore,
        ] {
            let transport = Arc::new(FakeTransport::default());
            transport.set_create_action(action);
            let store = store(transport.clone());
            let page = page(archive(1), 0, [0; 32], 13);
            assert_eq!(
                store.create_exact_page(fence(2), &page).await,
                Err(LifecycleError::Unavailable)
            );
            assert_eq!(transport.counts(), (1, 1, 0, 0));
        }
    }

    #[tokio::test]
    async fn pre_submit_protocol_and_size_failures_do_not_read_or_mint() {
        for (action, expected) in [
            (CreateAction::Protocol, LifecycleError::Corrupt),
            (CreateAction::TooLarge, LifecycleError::Limit),
        ] {
            let transport = Arc::new(FakeTransport::default());
            transport.set_create_action(action);
            let store = store(transport.clone());
            let page = page(archive(1), 0, [0; 32], 14);
            assert_eq!(
                store.create_exact_page(fence(2), &page).await,
                Err(expected)
            );
            assert_eq!(transport.counts(), (1, 0, 0, 0));
        }
    }

    #[tokio::test]
    async fn exact_read_rejects_magic_version_nonce_tag_truncation_and_oversize() {
        let cases = ["magic", "version", "nonce", "tag", "truncated", "oversize"];
        for case in cases {
            let transport = Arc::new(FakeTransport::default());
            let store = store(transport.clone());
            let page = page(archive(1), 0, [0; 32], 15);
            let deletion_fence = fence(2);
            store
                .create_exact_page(deletion_fence, &page)
                .await
                .unwrap();
            let (name, mut bytes) = transport.only_object();
            match case {
                "magic" => bytes[0] ^= 1,
                "version" => bytes[5] ^= 1,
                "nonce" => bytes[PAGE_OBJECT_MAGIC.len() + 2] ^= 1,
                "tag" => *bytes.last_mut().unwrap() ^= 1,
                "truncated" => {
                    bytes.pop();
                }
                "oversize" => bytes.push(0),
                _ => unreachable!(),
            }
            transport.replace_object(name, bytes);
            assert!(store
                .read_exact_page(deletion_fence, page.reference())
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn legacy_generic_bound_blob_shape_is_never_accepted() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let page = page(archive(1), 0, [0; 32], 16);
        let exact_len = page_object_len(page.reference()).unwrap();
        let mut legacy = vec![0; exact_len];
        legacy[..11].copy_from_slice(b"KIOKU-BLOB\x02");
        transport.set_read_override(Ok(Some(legacy)));
        assert_eq!(
            store.read_exact_page(fence(2), page.reference()).await,
            Err(LifecycleError::Corrupt)
        );
    }

    #[tokio::test]
    async fn ciphertext_relocation_across_fence_archive_or_reference_fails_aead() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let original = page(archive(1), 0, [0; 32], 17);
        let original_fence = fence(2);
        store
            .create_exact_page(original_fence, &original)
            .await
            .unwrap();
        let (source_name, _) = transport.only_object();

        let other_fence = fence(3);
        let moved_name = LifecyclePageObjectName::derive(other_fence, original.reference())
            .unwrap()
            .0;
        transport.copy_object_to(&source_name, moved_name);
        assert_eq!(
            store
                .read_exact_page(other_fence, original.reference())
                .await,
            Err(LifecycleError::Corrupt)
        );

        let cross_archive = InventoryPageReference::for_test(
            archive(4),
            original.page_ordinal(),
            original.page_id(),
            original.previous_hash(),
            original.page_hash(),
            original.encoded().len() as u32,
        )
        .unwrap();
        let moved_name = LifecyclePageObjectName::derive(original_fence, cross_archive)
            .unwrap()
            .0;
        transport.copy_object_to(&source_name, moved_name);
        assert_eq!(
            store.read_exact_page(original_fence, cross_archive).await,
            Err(LifecycleError::Corrupt)
        );

        let moved_reference = InventoryPageReference::for_test(
            original.archive_id(),
            1,
            original.page_id(),
            [0x44; 32],
            original.page_hash(),
            original.encoded().len() as u32,
        )
        .unwrap();
        let moved_name = LifecyclePageObjectName::derive(original_fence, moved_reference)
            .unwrap()
            .0;
        transport.copy_object_to(&source_name, moved_name);
        assert_eq!(
            store.read_exact_page(original_fence, moved_reference).await,
            Err(LifecycleError::Corrupt)
        );
    }

    #[tokio::test]
    async fn wrong_control_key_cannot_authenticate_existing_page() {
        let transport = Arc::new(FakeTransport::default());
        let first = store(transport.clone());
        let page = page(archive(1), 0, [0; 32], 18);
        first.create_exact_page(fence(2), &page).await.unwrap();
        let wrong = EncryptedLifecyclePageStore::new(
            LifecyclePageControlKey::for_test([0x6b; 32]),
            transport,
            Arc::new(FakeAdmissionLedger::default()),
        );
        assert_eq!(
            wrong.read_exact_page(fence(2), page.reference()).await,
            Err(LifecycleError::Corrupt)
        );
    }

    #[tokio::test]
    async fn oversized_transport_response_fails_even_if_transport_breaks_its_bound() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let page = page(archive(1), 0, [0; 32], 19);
        transport.set_read_override(Ok(Some(vec![0; MAX_PAGE_OBJECT_BYTES + 1])));
        assert_eq!(
            store.read_exact_page(fence(2), page.reference()).await,
            Err(LifecycleError::Limit)
        );
    }

    #[tokio::test]
    async fn cancellation_after_commit_leaves_retryable_exact_object_not_a_receipt() {
        let transport = Arc::new(FakeTransport::default());
        transport.set_create_action(CreateAction::BlockAfterStore);
        let admissions = Arc::new(FakeAdmissionLedger::default());
        let store = Arc::new(store_with_admissions(
            transport.clone(),
            Arc::clone(&admissions),
        ));
        let page = page(archive(1), 0, [0; 32], 20);
        let deletion_fence = fence(2);
        let task = {
            let store = Arc::clone(&store);
            let page = page.clone();
            tokio::spawn(async move { store.create_exact_page(deletion_fence, &page).await })
        };
        transport.wait_until_committed().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(transport.counts(), (1, 0, 0, 0));

        let restarted = store_with_admissions(transport.clone(), admissions);
        let durable = restarted
            .resume_outcome_unknown_page(page.archive_id(), deletion_fence)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(durable.page(), &page);
        assert_eq!(transport.object_count(), 1);
    }

    #[tokio::test]
    async fn cleanup_validates_complete_chain_before_first_destructive_io() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let first = page(archive(1), 0, [0; 32], 21);
        let second = page(archive(1), 1, first.page_hash(), 22);
        let completion = completion(&[first.clone(), second.clone()], fence(2));

        assert_eq!(
            store
                .erase_exact_pages_after_physical_completion(
                    &completion,
                    &[second.reference(), first.reference()],
                )
                .await,
            Err(LifecycleError::ChainMismatch)
        );
        assert_eq!(transport.counts(), (0, 0, 0, 0));
    }

    #[tokio::test]
    async fn maximum_page_ordinal_is_accepted_and_cap_rejects_before_admission_or_io() {
        let transport = Arc::new(FakeTransport::default());
        let admissions = Arc::new(FakeAdmissionLedger::default());
        let store = store_with_admissions(transport.clone(), Arc::clone(&admissions));
        let max = u32::try_from(MAX_LIFECYCLE_PAGES - 1).unwrap();
        let accepted = page(archive(1), max, [0x44; 32], 30);
        assert!(LifecyclePageObjectName::derive(fence(2), accepted.reference()).is_ok());
        assert!(store.encrypt_page(fence(2), &accepted).is_ok());
        assert_eq!(transport.counts().0, 0);
        let admitted_before = admissions.state.lock().unwrap().pages.len();

        let rejected = InventoryPageReference::for_test(
            accepted.archive_id(),
            u32::try_from(MAX_LIFECYCLE_PAGES).unwrap(),
            accepted.page_id(),
            accepted.previous_hash(),
            accepted.page_hash(),
            accepted.encoded().len() as u32,
        );
        assert!(rejected.is_err());
        assert_eq!(
            admissions.state.lock().unwrap().pages.len(),
            admitted_before
        );
        assert_eq!(transport.counts().0, 0);
    }

    #[tokio::test]
    async fn stalled_admitted_create_blocks_cleanup_before_any_delete() {
        let transport = Arc::new(FakeTransport::default());
        transport.set_create_action(CreateAction::BlockAfterStore);
        let admissions = Arc::new(FakeAdmissionLedger::default());
        let store = Arc::new(store_with_admissions(
            transport.clone(),
            Arc::clone(&admissions),
        ));
        let page = page(archive(1), 0, [0; 32], 22);
        let deletion_fence = fence(2);
        let task = {
            let store = Arc::clone(&store);
            let page = page.clone();
            tokio::spawn(async move { store.create_exact_page(deletion_fence, &page).await })
        };
        transport.wait_until_committed().await;

        assert_eq!(
            store
                .erase_exact_pages_after_physical_completion(
                    &completion(std::slice::from_ref(&page), deletion_fence),
                    &[page.reference()],
                )
                .await,
            Err(LifecycleError::InvalidState)
        );
        assert_eq!(transport.counts().2, 0);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn provider_create_drain_is_required_after_control_freeze_before_delete() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let page = page(archive(1), 0, [0; 32], 29);
        let deletion_fence = fence(2);
        store
            .create_exact_page(deletion_fence, &page)
            .await
            .unwrap();
        transport.state.lock().unwrap().create_drain = Some(Ok(false));
        assert_eq!(
            store
                .erase_exact_pages_after_physical_completion(
                    &completion(std::slice::from_ref(&page), deletion_fence),
                    &[page.reference()],
                )
                .await,
            Err(LifecycleError::InvalidState)
        );
        assert_eq!(transport.counts().2, 0);
    }

    #[tokio::test]
    async fn cleanup_deletes_every_generation_and_requires_soft_delete_absence() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let first = page(archive(1), 0, [0; 32], 23);
        let second = page(archive(1), 1, first.page_hash(), 24);
        let deletion_fence = fence(2);
        for page in [&first, &second] {
            store.create_exact_page(deletion_fence, page).await.unwrap();
        }
        let names = {
            let state = transport.state.lock().unwrap();
            state.objects.keys().cloned().collect::<Vec<_>>()
        };
        for name in &names {
            transport.add_generation(name);
            transport.mark_soft_deleted(name);
        }
        let completion = completion(&[first.clone(), second.clone()], deletion_fence);
        let receipt = store
            .erase_exact_pages_after_physical_completion(
                &completion,
                &[first.reference(), second.reference()],
            )
            .await
            .unwrap();
        assert!(receipt.matches(completion));
        assert_eq!(transport.object_count(), 0);
        assert_eq!(transport.counts(), (2, 2, 2, 2));
    }

    #[tokio::test]
    async fn soft_deleted_residue_blocks_cleanup_receipt() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let page = page(archive(1), 0, [0; 32], 25);
        let deletion_fence = fence(2);
        store
            .create_exact_page(deletion_fence, &page)
            .await
            .unwrap();
        transport.set_delete_action(DeleteAction::LeaveSoftDeleted);
        assert_eq!(
            store
                .erase_exact_pages_after_physical_completion(
                    &completion(std::slice::from_ref(&page), deletion_fence),
                    &[page.reference()],
                )
                .await,
            Err(LifecycleError::InvalidState)
        );
    }

    #[tokio::test]
    async fn ambiguous_delete_is_accepted_only_after_exact_absence() {
        let transport = Arc::new(FakeTransport::default());
        let store = store(transport.clone());
        let page = page(archive(1), 0, [0; 32], 26);
        let deletion_fence = fence(2);
        store
            .create_exact_page(deletion_fence, &page)
            .await
            .unwrap();
        transport.set_delete_action(DeleteAction::OutcomeUnknownAfterDelete);
        let completion = completion(std::slice::from_ref(&page), deletion_fence);
        assert!(store
            .erase_exact_pages_after_physical_completion(&completion, &[page.reference()],)
            .await
            .unwrap()
            .matches(completion));
        assert_eq!(transport.counts(), (1, 1, 1, 1));
    }

    #[tokio::test]
    async fn restart_after_partial_cleanup_reuses_exact_names_and_completion() {
        let transport = Arc::new(FakeTransport::default());
        let admissions = Arc::new(FakeAdmissionLedger::default());
        let first_store = store_with_admissions(transport.clone(), Arc::clone(&admissions));
        let first = page(archive(1), 0, [0; 32], 27);
        let second = page(archive(1), 1, first.page_hash(), 28);
        let deletion_fence = fence(2);
        for page in [&first, &second] {
            first_store
                .create_exact_page(deletion_fence, page)
                .await
                .unwrap();
        }
        let completion = completion(&[first.clone(), second.clone()], deletion_fence);
        transport.set_fail_delete_call(2);
        assert_eq!(
            first_store
                .erase_exact_pages_after_physical_completion(
                    &completion,
                    &[first.reference(), second.reference()],
                )
                .await,
            Err(LifecycleError::InvalidState)
        );
        assert_eq!(transport.object_count(), 1);

        let restarted = store_with_admissions(transport.clone(), admissions);
        let receipt = restarted
            .erase_exact_pages_after_physical_completion(
                &completion,
                &[first.reference(), second.reference()],
            )
            .await
            .unwrap();
        assert!(receipt.matches(completion));
        assert_eq!(transport.object_count(), 0);
        assert_eq!(transport.counts().2, 4);
    }

    #[test]
    fn debug_output_and_source_surface_do_not_reveal_keys_or_add_runtime_wiring() {
        assert_eq!(
            format!("{:?}", LifecyclePageControlKey::for_test([0x5a; 32])),
            "LifecyclePageControlKey(<opaque>)"
        );
        let source = include_str!("archive_v3_lifecycle_page_store.rs");
        assert!(!source.contains(concat!(
            "pub(crate) struct AuthenticatedPageReadback(",
            "pub"
        )));
        assert!(!source.contains(concat!(
            "pub(crate) struct AuthenticatedPageAbsence(",
            "pub"
        )));
        assert!(!source.contains(concat!("impl Clone for EncryptedLifecycle", "PageStore")));
        assert!(!source.contains(concat!(
            "derive(Clone)\npub(crate) struct EncryptedLifecycle",
            "PageStore"
        )));
        for forbidden in [
            concat!("list", "_after("),
            concat!("Gcs", "Client"),
            concat!("Kms", "Client"),
            concat!("Control", "Store::"),
            concat!("crate::store::", "Store"),
            concat!("std::", "env"),
            concat!("dot", "env"),
            concat!("archive_v3_shadow", "_runtime"),
            concat!("FullReachability", "Seal"),
            concat!("Pre", "Witness"),
        ] {
            assert!(
                !source.contains(forbidden),
                "inactive page store unexpectedly contains {forbidden}"
            );
        }
        let runtime = include_str!("main.rs");
        assert!(!runtime.contains("EncryptedLifecyclePageStore::new"));
        assert!(!runtime.contains("LifecyclePageControlKey::from_loaded_control_generation"));
        for forbidden in [
            ".freeze_archive_inventory_snapshot(",
            ".load_archive_inventory_snapshot(",
            ".recover_lifecycle_page_create_plan(",
            ".resume_outcome_unknown_page(",
            ".admit_lifecycle_page_create(",
            ".reconcile_lifecycle_page_created(",
            ".authorize_lifecycle_page_cleanup(",
        ] {
            assert!(!runtime.contains(forbidden));
        }
    }

    #[test]
    fn production_receipt_and_control_key_factories_require_private_producer_tokens() {
        let lifecycle = include_str!("archive_v3_lifecycle.rs");
        let source = include_str!("archive_v3_lifecycle_page_store.rs");
        let control = include_str!("cp/control_store.rs");
        assert!(lifecycle.contains(
            "_producer: &crate::archive_v3_lifecycle_page_store::AuthenticatedPageReadback"
        ));
        assert!(lifecycle.contains(
            "_producer: &crate::archive_v3_lifecycle_page_store::AuthenticatedPageAbsence"
        ));
        assert!(source.contains("_producer: &LifecyclePersistenceContext"));
        assert!(source.contains("pub(crate) struct RecoveredPageCreatePlan"));
        assert!(source.contains("fn validated() -> Self"));
        assert!(!source.contains(concat!("pub(crate) fn validated()", " -> Self")));
        assert!(control.contains("pub(crate) struct LifecyclePersistenceContext(())"));
        assert!(!control.contains(concat!("pub(crate) fn validated()", " -> Self")));
        assert!(control.contains("impl LifecyclePageAdmissionLedger for ControlStore"));
        assert!(
            control.contains("CREATE TABLE IF NOT EXISTS archive_lifecycle_inventory_snapshots")
        );
        assert!(control.contains("inventory_snapshot_frozen != 0"));
        assert!(control.contains("load_archive_inventory_snapshot_conn"));
        assert!(control.contains("archive_lifecycle_one_unresolved_page_create"));
        assert!(control.contains("unresolved_encoded_page = NULL"));
        assert!(control.contains("state != 'created'"));
        assert!(!control.contains("if page_create_count != 0"));
    }
}
