#![allow(
    dead_code,
    reason = "inactive ADR-0022 legacy converter primitive is compiled and tested before provider or authority wiring"
)]

//! Inactive, migration-only streaming reader for historical AES-256-GCM blobs.
//!
//! It accepts only `nonce[12] || ciphertext || tag[16]`, authenticates all
//! ciphertext before opening a temporary sink, then re-reads the same pinned
//! generation to decrypt in bounded chunks. Its private pull marks every byte
//! provisional and attacker-controlled until one-shot completion; a future
//! child composition may place those bytes only in encrypted, non-observable,
//! non-authoritative staging. This is deliberately not wired into Store, GCS,
//! routes, flags, or any production authority.

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher},
    Aes256,
};
use async_trait::async_trait;
use ctr::Ctr32BE;
use ghash::{universal_hash::UniversalHash, GHash};
use sha2::{Digest, Sha256};
use std::{fmt, num::NonZeroU64};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::Dek,
    error::{EnclaveError, Result},
};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ENVELOPE_OVERHEAD: u64 = (NONCE_LEN + TAG_LEN) as u64;
const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_IDENTITY_BYTES: usize = 256;
const SOURCE_IDENTITY_COMMITMENT_DOMAIN: &[u8] =
    b"KIOKU-LEGACY-GCM-SOURCE-IDENTITY-COMMITMENT-v1\0";
const SOURCE_BINDING_DOMAIN: &[u8] = b"KIOKU-LEGACY-GCM-SOURCE-BINDING-v1\0";
// SP 800-38D §5.2.1.1: 2^39 - 256 bits, or (2^32 - 2) AES blocks.
const MAX_CIPHERTEXT_BYTES: u64 = ((u32::MAX as u64) - 1) * 16;
const MAX_AAD_BYTES: u64 = 1 << 36;
const MAX_LOGICAL_DATABASE_BYTES: u64 = crate::archive_v3::MAX_DATABASE_BYTES;
const V2_MAGIC: &[u8] = b"KIOKU-BLOB\x02";

// This child is the only inactive consumer allowed to turn provisional legacy
// plaintext into dense archive extents. It deliberately has neither a
// completion path nor a root-candidate path.
mod extent_candidate;

mod sealed {
    pub trait RangeReader {}
    pub trait Sink {}
}

/// Canonical nonzero decimal GCS object generation. Construction from a
/// provider response belongs in this sealed module (or a child module), after
/// validating its `x-goog-generation` / `Content-Range` fields; provider text
/// is never retained or surfaced by this type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyGeneration(NonZeroU64);

impl LegacyGeneration {
    pub(crate) fn new(value: u64) -> Result<Self> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| crypto_error("legacy generation must be nonzero"))
    }
}

/// A narrow, canonical opaque identity for the object selected by a future
/// adapter.  It is an adapter-defined stable byte string (for example an
/// already canonical provider object identity), never a path, URL, or display
/// name.  The adapter supplies it once to authentication and it is retained
/// only as a hash binding thereafter.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacySourceIdentity(Zeroizing<Vec<u8>>);

impl LegacySourceIdentity {
    pub(crate) fn new(canonical: &[u8]) -> Result<Self> {
        if canonical.is_empty() || canonical.len() > MAX_SOURCE_IDENTITY_BYTES {
            return Err(crypto_error(
                "legacy source identity must be nonempty and bounded",
            ));
        }
        Ok(Self(Zeroizing::new(canonical.to_vec())))
    }

    fn compatibility_wrapper() -> Self {
        // This preserves the historic wrapper signature only. New adapters
        // must use `authenticate_legacy_source` with their canonical identity.
        Self(Zeroizing::new(
            b"legacy-gcm-staging-compatibility-v1".to_vec(),
        ))
    }

    fn commitment(&self) -> LegacySourceIdentityCommitment {
        let mut digest = Sha256::new();
        digest.update(SOURCE_IDENTITY_COMMITMENT_DOMAIN);
        digest.update((self.0.len() as u64).to_be_bytes());
        digest.update(&*self.0);
        LegacySourceIdentityCommitment(digest.finalize().into())
    }
}

impl fmt::Debug for LegacySourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacySourceIdentity(<redacted>)")
    }
}

/// Fixed-size, non-loggable binding for the authenticated source selection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacySourceBinding([u8; 32]);

impl fmt::Debug for LegacySourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacySourceBinding(<redacted>)")
    }
}

impl LegacySourceBinding {
    fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }
}

/// Fixed-size commitment to one canonical source identity. The raw identity
/// is needed only while selecting metadata; all pinned state carries this
/// commitment instead.
#[derive(Clone, Copy, PartialEq, Eq)]
struct LegacySourceIdentityCommitment([u8; 32]);

impl LegacySourceIdentityCommitment {
    fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }
}

impl fmt::Debug for LegacySourceIdentityCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacySourceIdentityCommitment(<redacted>)")
    }
}

impl fmt::Debug for LegacyGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacyGeneration(<redacted>)")
    }
}

/// Exact immutable source metadata. A production adapter must acquire this
/// from object metadata and make every read fail if the generation differs.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PinnedLegacyObject {
    generation: LegacyGeneration,
    byte_len: u64,
    identity: LegacySourceIdentityCommitment,
}

impl fmt::Debug for PinnedLegacyObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedLegacyObject(<redacted>)")
    }
}

impl PinnedLegacyObject {
    fn new(identity: &LegacySourceIdentity, generation: LegacyGeneration, byte_len: u64) -> Self {
        Self {
            generation,
            byte_len,
            identity: identity.commitment(),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        let identity_matches = self.identity.matches(&other.identity);
        identity_matches && self.generation == other.generation && self.byte_len == other.byte_len
    }
}

/// A range response receipt checked before this module consumes bytes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacyRangeReceipt {
    object: PinnedLegacyObject,
    offset: u64,
    byte_len: u64,
}

impl fmt::Debug for LegacyRangeReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacyRangeReceipt(<redacted>)")
    }
}

impl LegacyRangeReceipt {
    fn new(object: PinnedLegacyObject, offset: u64, byte_len: u64) -> Self {
        Self {
            object,
            offset,
            byte_len,
        }
    }
}

/// Sealed generation-pinned range source. The production adapter must live in
/// this module or a child module. It must issue a single exact-generation GCS
/// range GET, require HTTP 206 plus a parsed `Content-Range` whose start,
/// inclusive end, total, and observed generation match this receipt, and fill
/// `destination` completely or error; it must not retry another generation.
/// The in-memory contract detects inconsistent receipts but cannot make a
/// malicious concrete adapter report provider metadata honestly; the future
/// sealed child adapter therefore remains a dedicated review boundary.
#[async_trait]
pub(crate) trait PinnedLegacyRangeReader: sealed::RangeReader + Send {
    /// Return the adapter's independently selected sealed object. The caller's
    /// requested identity is deliberately not provided here, so the adapter
    /// cannot satisfy pinning by merely echoing that request.
    async fn pin_legacy_object(&mut self) -> Result<PinnedLegacyObject>;
    async fn read_pinned_exact(
        &mut self,
        object: &PinnedLegacyObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<LegacyRangeReceipt>;
}

/// Explicit historic AAD profiles. No arbitrary AAD, fallback, or probe exists.
pub(crate) enum LegacyGcmAad<'a> {
    Empty(LegacyEmptyAad),
    MediaUserId(&'a [u8]),
}

/// Empty AAD was used by the historic SQLite, control, and ACME envelopes.
pub(crate) enum LegacyEmptyAad {
    Sqlite,
    Control,
    Acme,
}

impl LegacyGcmAad<'_> {
    fn discriminator(&self) -> u8 {
        match self {
            Self::Empty(LegacyEmptyAad::Sqlite) => 1,
            Self::Empty(LegacyEmptyAad::Control) => 2,
            Self::Empty(LegacyEmptyAad::Acme) => 3,
            Self::MediaUserId(_) => 4,
        }
    }

    fn bytes(&self) -> Result<&[u8]> {
        match self {
            Self::Empty(
                LegacyEmptyAad::Sqlite | LegacyEmptyAad::Control | LegacyEmptyAad::Acme,
            ) => Ok(&[]),
            Self::MediaUserId([]) => {
                Err(crypto_error("historic media user-id AAD must be nonempty"))
            }
            Self::MediaUserId(user_id) => {
                let user_id = std::str::from_utf8(user_id)
                    .map_err(|_| crypto_error("historic media user-id AAD is not UTF-8"))?;
                crate::store::validate_user_id(user_id)
                    .map_err(|_| crypto_error("invalid historic media user-id AAD"))?;
                Ok(user_id.as_bytes())
            }
        }
    }
}

/// An all-or-nothing temporary plaintext sink. `write` may touch a tmpfs
/// staging area, but only `commit` can make output observable. The caller
/// receives synchronous `abort` on every error or cancellation after `begin`.
/// `begin` is synchronous by design, so a staging object is either returned
/// under the RAII guard or has never existed when cancellation occurs.
/// `commit` must itself be atomic: cancellation while it is awaited leaves the
/// staging object abortable or already atomically committed, never half-visible.
/// A future child composition must encrypt provisional bytes in staging and
/// keep that staging non-observable and non-authoritative until completion and
/// atomic commit. Rust traits cannot prove that a concrete adapter honors
/// those provider-side properties, so such an adapter still requires review.
#[async_trait]
pub(crate) trait PlaintextStagingSink: sealed::Sink + Send {
    type Staging: Send;
    fn begin(&mut self, plaintext_len: u64) -> Result<Self::Staging>;
    async fn write(&mut self, staging: &mut Self::Staging, plaintext: &[u8]) -> Result<()>;
    async fn commit(&mut self, staging: &mut Self::Staging) -> Result<()>;
    fn abort(&mut self, staging: &mut Self::Staging);
}

/// Ensures a started plaintext staging area is aborted when an async migration
/// future is cancelled at a reader, sink-write, or commit await point.
struct StagingGuard<'a, S: PlaintextStagingSink> {
    sink: &'a mut S,
    staging: S::Staging,
    committed: bool,
}

impl<'a, S: PlaintextStagingSink> StagingGuard<'a, S> {
    fn new(sink: &'a mut S, staging: S::Staging) -> Self {
        Self {
            sink,
            staging,
            committed: false,
        }
    }

    fn parts_mut(&mut self) -> (&mut S, &mut S::Staging) {
        (self.sink, &mut self.staging)
    }

    async fn commit(&mut self) -> Result<()> {
        self.sink.commit(&mut self.staging).await?;
        self.committed = true;
        Ok(())
    }
}

impl<S: PlaintextStagingSink> Drop for StagingGuard<'_, S> {
    fn drop(&mut self) {
        if !self.committed {
            self.sink.abort(&mut self.staging);
        }
    }
}

/// This result grants no publication or write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyGcmRead {
    pub(crate) plaintext_len: u64,
}

/// Completion is minted only by a successful exact end-of-stream verification.
/// It is deliberately linear: callers cannot clone or copy it.
#[derive(Debug, PartialEq, Eq)]
struct LegacyGcmCompletion {
    plaintext_len: u64,
    binding: LegacySourceBinding,
}

impl LegacyGcmCompletion {
    /// Consume the one-shot completion and require its exact pre-staging
    /// binding before any later root candidate or authority-bearing record may
    /// be persisted.
    fn verify_binding(self, expected: LegacySourceBinding) -> Result<LegacySourceBinding> {
        if !self.binding.matches(&expected) {
            return Err(crypto_error(
                "legacy completion binding does not match the pre-staging source",
            ));
        }
        Ok(self.binding)
    }
}

/// A sealed, sequential source produced only after the first full GCM pass.
/// It has neither seek nor replay operations. Dropping it is deliberately not
/// completion and exposes no success signal. Its private pull yields
/// provisional attacker-controlled plaintext, not authenticated output: only
/// this module and reviewed child composition modules may consume those bytes,
/// and only into encrypted, non-observable, non-authoritative staging.
struct AuthenticatedLegacySource<'a, R: PinnedLegacyRangeReader> {
    reader: &'a mut R,
    object: PinnedLegacyObject,
    binding: LegacySourceBinding,
    ciphertext_len: u64,
    nonce: [u8; NONCE_LEN],
    tag: [u8; TAG_LEN],
    first_digest: [u8; 32],
    aad: Zeroizing<Vec<u8>>,
    ctr: Option<Ctr32BE<Aes256>>,
    authenticator: Option<GcmAuthenticator>,
    digest: Sha256,
    offset: u64,
    state: LegacySourceState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacySourceState {
    Unstarted,
    Reading,
    Finished,
    Failed,
}

/// A private marker for bytes decrypted during pass two. `len == 0` means the
/// ciphertext body is exhausted, but the bytes already emitted remain
/// provisional until `finish` returns its one-shot completion.
struct ProvisionalPlaintextChunk {
    len: usize,
}

impl ProvisionalPlaintextChunk {
    fn len(&self) -> usize {
        self.len
    }
}

/// Makes cancellation of a source operation terminal and scrubs retained
/// cipher/authentication state. Successful operations explicitly disarm it.
struct LegacySourceOperationGuard<'operation, 'reader, R: PinnedLegacyRangeReader> {
    source: &'operation mut AuthenticatedLegacySource<'reader, R>,
    completed: bool,
}

impl<'operation, 'reader, R: PinnedLegacyRangeReader>
    LegacySourceOperationGuard<'operation, 'reader, R>
{
    fn new(source: &'operation mut AuthenticatedLegacySource<'reader, R>) -> Self {
        Self {
            source,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl<R: PinnedLegacyRangeReader> Drop for LegacySourceOperationGuard<'_, '_, R> {
    fn drop(&mut self) {
        if !self.completed {
            self.source.state = LegacySourceState::Failed;
            self.source.scrub();
        }
    }
}

impl<R: PinnedLegacyRangeReader> fmt::Debug for AuthenticatedLegacySource<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedLegacySource(<redacted>)")
    }
}

impl<R: PinnedLegacyRangeReader> Drop for AuthenticatedLegacySource<'_, R> {
    fn drop(&mut self) {
        self.scrub();
    }
}

impl<'a, R: PinnedLegacyRangeReader> AuthenticatedLegacySource<'a, R> {
    fn scrub(&mut self) {
        self.nonce.zeroize();
        self.tag.zeroize();
        self.first_digest.zeroize();
        self.aad.zeroize();
        // `ctr` and `GcmAuthenticator::ghash` are built with their `zeroize`
        // features. Taking them here makes the terminal cleanup explicit even
        // when the source is cancelled at an async boundary.
        drop(self.ctr.take());
        drop(self.authenticator.take());
    }
    fn binding(&self) -> LegacySourceBinding {
        self.binding
    }

    fn plaintext_len(&self) -> u64 {
        self.ciphertext_len
    }

    async fn start(&mut self) -> Result<()> {
        if self.state != LegacySourceState::Unstarted {
            return Ok(());
        }
        let mut nonce: [u8; NONCE_LEN] = Default::default();
        if let Err(error) = read_exact(self.reader, &self.object, 0, &mut nonce).await {
            nonce.zeroize();
            return self.fail_with(error);
        }
        if nonce.ct_eq(&self.nonce).unwrap_u8() != 1 || nonce.starts_with(V2_MAGIC) {
            nonce.zeroize();
            return self.fail("legacy nonce changed between passes");
        }
        nonce.zeroize();
        self.state = LegacySourceState::Reading;
        Ok(())
    }

    /// Decrypt exactly the next bounded sequential chunk. The returned marker
    /// certifies only how many bytes were initialized; `destination[..len]`
    /// remains provisional attacker-controlled plaintext until `finish`.
    /// A future child composition may write it only to encrypted,
    /// non-observable, non-authoritative staging and must zeroize its buffer.
    async fn read_provisional(
        &mut self,
        destination: &mut [u8],
    ) -> Result<ProvisionalPlaintextChunk> {
        if destination.is_empty() || destination.len() > MAX_CHUNK_BYTES {
            return Err(crypto_error(
                "legacy plaintext destination must be nonempty and bounded",
            ));
        }
        // The sealed owner clears stale provisional plaintext up front. The
        // exact-range guard separately clears any partial ciphertext written
        // if the reader future is cancelled before CTR decryption.
        destination.zeroize();
        if self.state == LegacySourceState::Finished || self.state == LegacySourceState::Failed {
            return Err(crypto_error("legacy authenticated source is terminal"));
        }
        let mut operation = LegacySourceOperationGuard::new(self);
        let result = operation.source.read_provisional_inner(destination).await;
        if result.is_ok() {
            operation.complete();
        }
        result
    }

    async fn read_provisional_inner(
        &mut self,
        destination: &mut [u8],
    ) -> Result<ProvisionalPlaintextChunk> {
        self.start().await?;
        let end = match (NONCE_LEN as u64).checked_add(self.ciphertext_len) {
            Some(end) => end,
            None => return self.fail("legacy ciphertext range overflow"),
        };
        if self.offset == end {
            return Ok(ProvisionalPlaintextChunk { len: 0 });
        }
        let bytes = match usize::try_from((end - self.offset).min(destination.len() as u64)) {
            Ok(bytes) => bytes,
            Err(_) => return self.fail("legacy ciphertext chunk length overflow"),
        };
        let chunk = &mut destination[..bytes];
        if let Err(error) = read_exact(self.reader, &self.object, self.offset, chunk).await {
            chunk.zeroize();
            return self.fail_with(error);
        }
        self.authenticator
            .as_mut()
            .expect("authenticated source has GHASH state")
            .absorb_ciphertext(chunk);
        self.digest.update(&*chunk);
        if self
            .ctr
            .as_mut()
            .expect("authenticated source has CTR state")
            .try_apply_keystream(chunk)
            .is_err()
        {
            chunk.zeroize();
            return self.fail("legacy GCM counter exhausted during decrypt");
        }
        self.offset = match self.offset.checked_add(bytes as u64) {
            Some(offset) => offset,
            None => {
                chunk.zeroize();
                return self.fail("legacy ciphertext offset overflow");
            }
        };
        Ok(ProvisionalPlaintextChunk { len: bytes })
    }

    /// Verify the second-pass tag, digest, exact EOF, and return the only
    /// completion token. It can succeed exactly once.
    async fn finish(&mut self) -> Result<LegacyGcmCompletion> {
        if self.state == LegacySourceState::Finished || self.state == LegacySourceState::Failed {
            return Err(crypto_error("legacy authenticated source is terminal"));
        }
        let mut operation = LegacySourceOperationGuard::new(self);
        let result = operation.source.finish_inner().await;
        if result.is_ok() {
            operation.complete();
        }
        result
    }

    async fn finish_inner(&mut self) -> Result<LegacyGcmCompletion> {
        self.start().await?;
        let end = match (NONCE_LEN as u64).checked_add(self.ciphertext_len) {
            Some(end) => end,
            None => return self.fail("legacy ciphertext range overflow"),
        };
        if self.offset != end {
            return self.fail("legacy authenticated source has unread plaintext");
        }
        let tag_offset = end;
        let mut second_tag = [0u8; TAG_LEN];
        if let Err(error) = read_exact(self.reader, &self.object, tag_offset, &mut second_tag).await
        {
            second_tag.zeroize();
            return self.fail_with(error);
        }
        let tag_same = second_tag.ct_eq(&self.tag).unwrap_u8() == 1;
        let mut calculated = match self
            .authenticator
            .take()
            .expect("authenticated source has GHASH state")
            .finish(self.ciphertext_len)
        {
            Ok(tag) => tag,
            Err(error) => {
                second_tag.zeroize();
                return self.fail_with(error);
            }
        };
        let tag_valid = calculated.ct_eq(&second_tag).unwrap_u8() == 1;
        calculated.zeroize();
        second_tag.zeroize();
        let mut digest: [u8; 32] = std::mem::take(&mut self.digest).finalize().into();
        let digest_same = digest.ct_eq(&self.first_digest).unwrap_u8() == 1;
        digest.zeroize();
        if !tag_same || !tag_valid || !digest_same {
            return self.fail("legacy envelope changed or failed authentication in second pass");
        }
        self.state = LegacySourceState::Finished;
        self.scrub();
        Ok(LegacyGcmCompletion {
            plaintext_len: self.ciphertext_len,
            binding: self.binding,
        })
    }

    fn fail<T>(&mut self, message: &'static str) -> Result<T> {
        self.fail_with(crypto_error(message))
    }

    fn fail_with<T>(&mut self, error: EnclaveError) -> Result<T> {
        self.state = LegacySourceState::Failed;
        self.scrub();
        Err(error)
    }
}

/// Authenticate an exact historic envelope and return its sealed second-pass
/// source. The binding is domain-separated SHA-256 over the caller-supplied
/// canonical opaque identity's fixed commitment, pinned generation/lengths,
/// AAD profile class, and first-pass ciphertext digest; raw identity and raw
/// DEK are not retained.
async fn authenticate_legacy_source<'a, R>(
    reader: &'a mut R,
    dek: &Dek,
    aad_profile: LegacyGcmAad<'_>,
    source_identity: &LegacySourceIdentity,
) -> Result<AuthenticatedLegacySource<'a, R>>
where
    R: PinnedLegacyRangeReader,
{
    let requested_identity = source_identity.commitment();
    let object = reader.pin_legacy_object().await?;
    if !object.identity.matches(&requested_identity) {
        return Err(crypto_error(
            "pinned legacy source identity does not match the requested source",
        ));
    }
    let ciphertext_len = validate_envelope_len(object.byte_len)?;
    let aad = aad_profile.bytes()?;
    validate_aad_len(aad)?;
    let profile = aad_profile.discriminator();
    let mut nonce: [u8; NONCE_LEN] = Default::default();
    if let Err(error) = read_exact(reader, &object, 0, &mut nonce).await {
        nonce.zeroize();
        return Err(error);
    }
    if nonce.starts_with(V2_MAGIC) {
        nonce.zeroize();
        return Err(crypto_error("v2 envelope is not a historic legacy blob"));
    }
    let tag_offset = (NONCE_LEN as u64)
        .checked_add(ciphertext_len)
        .ok_or_else(|| crypto_error("legacy ciphertext offset overflow"))?;
    let mut tag = [0u8; TAG_LEN];
    if let Err(error) = read_exact(reader, &object, tag_offset, &mut tag).await {
        nonce.zeroize();
        tag.zeroize();
        return Err(error);
    }
    let key = Zeroizing::new(dek.0);
    let mut first_digest =
        match authenticate_pass(reader, &object, &key, &nonce, aad, ciphertext_len, &tag).await {
            Ok(digest) => digest,
            Err(error) => {
                nonce.zeroize();
                tag.zeroize();
                return Err(error);
            }
        };
    let mut ctr_iv = match gcm_counter_start(&nonce) {
        Ok(counter) => counter,
        Err(error) => {
            nonce.zeroize();
            tag.zeroize();
            first_digest.zeroize();
            return Err(error);
        }
    };
    let ctr = Ctr32BE::<Aes256>::new(
        GenericArray::from_slice(&*key),
        GenericArray::from_slice(&ctr_iv),
    );
    let authenticator = match GcmAuthenticator::new(&key, &nonce, aad) {
        Ok(authenticator) => authenticator,
        Err(error) => {
            nonce.zeroize();
            tag.zeroize();
            first_digest.zeroize();
            return Err(error);
        }
    };
    drop(key);
    ctr_iv.zeroize();
    let binding = source_binding(
        object.identity,
        object.generation,
        object.byte_len,
        ciphertext_len,
        profile,
        &first_digest,
    );
    Ok(AuthenticatedLegacySource {
        reader,
        object,
        binding,
        ciphertext_len,
        nonce,
        tag,
        first_digest,
        aad: Zeroizing::new(aad.to_vec()),
        ctr: Some(ctr),
        authenticator: Some(authenticator),
        digest: Sha256::new(),
        offset: NONCE_LEN as u64,
        state: LegacySourceState::Unstarted,
    })
}

/// Compatibility wrapper retaining the existing all-or-nothing staging and
/// cancellation/abort guard while consuming the authenticated source.
pub(crate) async fn authenticate_then_stage_decrypt<R, S>(
    reader: &mut R,
    sink: &mut S,
    dek: &Dek,
    aad_profile: LegacyGcmAad<'_>,
) -> Result<LegacyGcmRead>
where
    R: PinnedLegacyRangeReader,
    S: PlaintextStagingSink,
{
    let source_identity = LegacySourceIdentity::compatibility_wrapper();
    let mut source = authenticate_legacy_source(reader, dek, aad_profile, &source_identity).await?;
    let expected_binding = source.binding();
    let staging = match sink.begin(source.plaintext_len()) {
        Ok(staging) => staging,
        Err(error) => {
            return Err(error);
        }
    };
    let mut staging = StagingGuard::new(sink, staging);
    let mut buffer = Zeroizing::new(vec![0u8; MAX_CHUNK_BYTES]);
    loop {
        let provisional = source.read_provisional(&mut buffer).await?;
        let count = provisional.len();
        if count == 0 {
            break;
        }
        let (sink, temporary_output) = staging.parts_mut();
        sink.write(temporary_output, &buffer[..count]).await?;
        buffer[..count].zeroize();
    }
    buffer.zeroize();
    match source.finish().await {
        Ok(completion) => {
            let plaintext_len = completion.plaintext_len;
            completion.verify_binding(expected_binding)?;
            match staging.commit().await {
                Ok(()) => Ok(LegacyGcmRead { plaintext_len }),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn crypto_error(message: &'static str) -> EnclaveError {
    EnclaveError::Crypto(format!("legacy GCM migration: {message}"))
}

fn source_binding(
    identity: LegacySourceIdentityCommitment,
    generation: LegacyGeneration,
    encrypted_len: u64,
    plaintext_len: u64,
    aad_profile: u8,
    first_digest: &[u8; 32],
) -> LegacySourceBinding {
    let mut digest = Sha256::new();
    digest.update(SOURCE_BINDING_DOMAIN);
    digest.update(identity.0);
    digest.update(generation.0.get().to_be_bytes());
    digest.update(encrypted_len.to_be_bytes());
    digest.update(plaintext_len.to_be_bytes());
    digest.update([aad_profile]);
    digest.update(first_digest);
    LegacySourceBinding(digest.finalize().into())
}

fn validate_envelope_len(total_len: u64) -> Result<u64> {
    if total_len < ENVELOPE_OVERHEAD {
        return Err(crypto_error(
            "legacy envelope is shorter than nonce and tag",
        ));
    }
    let ciphertext_len = total_len - ENVELOPE_OVERHEAD;
    if ciphertext_len > MAX_CIPHERTEXT_BYTES {
        return Err(crypto_error("legacy ciphertext exceeds GCM counter bound"));
    }
    if ciphertext_len > MAX_LOGICAL_DATABASE_BYTES {
        return Err(crypto_error(
            "legacy ciphertext exceeds archive database cap",
        ));
    }
    Ok(ciphertext_len)
}

fn validate_aad_len(aad: &[u8]) -> Result<()> {
    if (aad.len() as u64) > MAX_AAD_BYTES {
        return Err(crypto_error("legacy AAD exceeds GCM bit-length bound"));
    }
    Ok(())
}

/// Zeroizes a range destination unless the exact receipt is validated. This
/// guard remains live across the reader await, so cancellation cannot leave a
/// caller-owned buffer containing a partial ciphertext response.
struct ExactRangeBuffer<'a> {
    destination: &'a mut [u8],
    validated: bool,
}

impl<'a> ExactRangeBuffer<'a> {
    fn new(destination: &'a mut [u8]) -> Self {
        Self {
            destination,
            validated: false,
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.destination
    }

    fn validate(&mut self) {
        self.validated = true;
    }
}

impl Drop for ExactRangeBuffer<'_> {
    fn drop(&mut self) {
        if !self.validated {
            self.destination.zeroize();
        }
    }
}

async fn read_exact<R: PinnedLegacyRangeReader>(
    reader: &mut R,
    object: &PinnedLegacyObject,
    offset: u64,
    destination: &mut [u8],
) -> Result<()> {
    let requested_len = u64::try_from(destination.len())
        .map_err(|_| crypto_error("legacy range length does not fit u64"))?;
    let end = offset
        .checked_add(requested_len)
        .ok_or_else(|| crypto_error("legacy range offset overflow"))?;
    if end > object.byte_len {
        return Err(crypto_error("legacy range exceeds pinned object length"));
    }
    let mut buffer = ExactRangeBuffer::new(destination);
    let receipt = match reader
        .read_pinned_exact(object, offset, buffer.bytes_mut())
        .await
    {
        Ok(receipt) => receipt,
        Err(error) => return Err(error),
    };
    if !receipt.object.matches(object)
        || receipt.offset != offset
        || receipt.byte_len != requested_len
    {
        return Err(crypto_error(
            "legacy range did not match pinned source, generation, and extent",
        ));
    }
    buffer.validate();
    Ok(())
}

async fn authenticate_pass<R: PinnedLegacyRangeReader>(
    reader: &mut R,
    object: &PinnedLegacyObject,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext_len: u64,
    expected_tag: &[u8; TAG_LEN],
) -> Result<[u8; 32]> {
    let mut authenticator = GcmAuthenticator::new(key, nonce, aad)?;
    let mut digest = Sha256::new();
    let mut offset = NONCE_LEN as u64;
    let end = offset
        .checked_add(ciphertext_len)
        .ok_or_else(|| crypto_error("legacy ciphertext range overflow"))?;
    let mut buffer = Zeroizing::new(vec![0u8; MAX_CHUNK_BYTES]);
    while offset < end {
        let bytes = usize::try_from((end - offset).min(MAX_CHUNK_BYTES as u64))
            .map_err(|_| crypto_error("legacy ciphertext chunk length overflow"))?;
        let chunk = &mut buffer[..bytes];
        if let Err(error) = read_exact(reader, object, offset, chunk).await {
            buffer.zeroize();
            return Err(error);
        }
        authenticator.absorb_ciphertext(chunk);
        digest.update(&*chunk);
        chunk.zeroize();
        offset = offset
            .checked_add(bytes as u64)
            .ok_or_else(|| crypto_error("legacy ciphertext offset overflow"))?;
    }
    buffer.zeroize();
    let mut calculated_tag = authenticator.finish(ciphertext_len)?;
    let valid = calculated_tag.ct_eq(expected_tag).unwrap_u8() == 1;
    calculated_tag.zeroize();
    if !valid {
        return Err(crypto_error("legacy envelope authentication failed"));
    }
    Ok(digest.finalize().into())
}

/// Exact `inc32(J0)` used for the first GCM CTR block. The length bound above
/// prevents a data stream from wrapping this 32-bit counter.
fn gcm_counter_start(nonce: &[u8; NONCE_LEN]) -> Result<[u8; 16]> {
    let mut counter = [0u8; 16];
    counter[..NONCE_LEN].copy_from_slice(nonce);
    counter[15] = 1;
    let mut low = [0u8; 4];
    low.copy_from_slice(&counter[12..]);
    let incremented = u32::from_be_bytes(low)
        .checked_add(1)
        .ok_or_else(|| crypto_error("legacy GCM counter overflow"))?;
    counter[12..].copy_from_slice(&incremented.to_be_bytes());
    low.zeroize();
    Ok(counter)
}

struct GcmAuthenticator {
    ghash: GHash,
    tag_mask: [u8; TAG_LEN],
    tail: [u8; 16],
    tail_len: usize,
    aad_len: u64,
}

impl GcmAuthenticator {
    fn new(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8]) -> Result<Self> {
        validate_aad_len(aad)?;
        let aes = Aes256::new(GenericArray::from_slice(key));
        let mut hash_key = GenericArray::default();
        aes.encrypt_block(&mut hash_key);
        let mut ghash = GHash::new(&hash_key);
        hash_key.zeroize();
        let mut j0 = [0u8; 16];
        j0[..NONCE_LEN].copy_from_slice(nonce);
        j0[15] = 1;
        let mut tag_mask = GenericArray::clone_from_slice(&j0);
        aes.encrypt_block(&mut tag_mask);
        // `aes` is built with its zeroize feature: its expanded-key state is
        // zeroized on drop. The raw key, hash key, nonce, and masks are all
        // explicitly scrubbed below where their APIs permit it.
        drop(aes);
        j0.zeroize();
        // Ciphertext gets exactly one final padding block, not one per chunk.
        ghash.update_padded(aad);
        Ok(Self {
            ghash,
            tag_mask: tag_mask.into(),
            tail: [0u8; 16],
            tail_len: 0,
            aad_len: aad.len() as u64,
        })
    }

    fn absorb_ciphertext(&mut self, mut ciphertext: &[u8]) {
        if self.tail_len != 0 {
            let take = (16 - self.tail_len).min(ciphertext.len());
            self.tail[self.tail_len..self.tail_len + take].copy_from_slice(&ciphertext[..take]);
            self.tail_len += take;
            ciphertext = &ciphertext[take..];
            if self.tail_len == 16 {
                let block = self.tail;
                self.update_block(&block);
                self.tail.zeroize();
                self.tail_len = 0;
            }
        }
        while ciphertext.len() >= 16 {
            let (block, rest) = ciphertext.split_at(16);
            self.update_block(block);
            ciphertext = rest;
        }
        if !ciphertext.is_empty() {
            self.tail[..ciphertext.len()].copy_from_slice(ciphertext);
            self.tail_len = ciphertext.len();
        }
    }

    fn update_block(&mut self, bytes: &[u8]) {
        debug_assert_eq!(bytes.len(), 16);
        self.ghash.update(&[GenericArray::clone_from_slice(bytes)]);
    }

    fn finish(mut self, ciphertext_len: u64) -> Result<[u8; TAG_LEN]> {
        if ciphertext_len > MAX_CIPHERTEXT_BYTES {
            return Err(crypto_error("legacy ciphertext exceeds GCM counter bound"));
        }
        if self.tail_len != 0 {
            let mut tail = self.tail;
            self.update_block(&tail);
            tail.zeroize();
        }
        self.tail.zeroize();
        self.tail_len = 0;
        let aad_bits = self
            .aad_len
            .checked_mul(8)
            .ok_or_else(|| crypto_error("legacy AAD bit length overflow"))?;
        let ciphertext_bits = ciphertext_len
            .checked_mul(8)
            .ok_or_else(|| crypto_error("legacy ciphertext bit length overflow"))?;
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&aad_bits.to_be_bytes());
        lengths[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
        self.update_block(&lengths);
        lengths.zeroize();
        // GHash does not expose a consuming zeroizing finalizer. Keep the
        // instance owned by `self` (so Drop still scrubs our public buffers)
        // and finalize an exact clone.
        let mut tag: [u8; TAG_LEN] = self.ghash.clone().finalize().into();
        for (byte, mask) in tag.iter_mut().zip(self.tag_mask.iter()) {
            *byte ^= *mask;
        }
        self.tag_mask.zeroize();
        Ok(tag)
    }
}

impl Drop for GcmAuthenticator {
    fn drop(&mut self) {
        self.tag_mask.zeroize();
        self.tail.zeroize();
        self.tail_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    use super::*;

    struct FakeReader {
        bytes: Vec<u8>,
        generation: LegacyGeneration,
        fragment_plan: VecDeque<usize>,
        receipt_fault: Option<ReceiptFault>,
        receipt_fault_after_call: Option<usize>,
        second_pass_mutation: Option<(usize, u8)>,
        pending_after_call: Option<usize>,
        pending_partial_bytes: usize,
        selected_identity: LegacySourceIdentity,
        calls: usize,
    }
    impl Default for FakeReader {
        fn default() -> Self {
            Self {
                bytes: Vec::new(),
                generation: LegacyGeneration::new(1).expect("nonzero test generation"),
                fragment_plan: VecDeque::new(),
                receipt_fault: None,
                receipt_fault_after_call: None,
                second_pass_mutation: None,
                pending_after_call: None,
                pending_partial_bytes: 0,
                selected_identity: LegacySourceIdentity::compatibility_wrapper(),
                calls: 0,
            }
        }
    }
    #[derive(Clone, Copy)]
    enum ReceiptFault {
        Generation,
        Offset,
        Length,
        Total,
        Identity,
    }
    impl FakeReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                generation: LegacyGeneration::new(123).unwrap(),
                ..Self::default()
            }
        }

        fn selected(bytes: Vec<u8>, identity: &LegacySourceIdentity) -> Self {
            Self {
                selected_identity: identity.clone(),
                ..Self::new(bytes)
            }
        }
    }
    impl sealed::RangeReader for FakeReader {}
    #[async_trait::async_trait]
    impl PinnedLegacyRangeReader for FakeReader {
        async fn pin_legacy_object(&mut self) -> Result<PinnedLegacyObject> {
            Ok(PinnedLegacyObject::new(
                &self.selected_identity,
                self.generation,
                self.bytes.len() as u64,
            ))
        }
        async fn read_pinned_exact(
            &mut self,
            object: &PinnedLegacyObject,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<LegacyRangeReceipt> {
            self.calls += 1;
            let start = usize::try_from(offset).map_err(|_| crypto_error("test offset"))?;
            let end = start
                .checked_add(destination.len())
                .ok_or_else(|| crypto_error("test range overflow"))?;
            if end > self.bytes.len() {
                return Err(crypto_error("test source range unavailable"));
            }
            if self
                .pending_after_call
                .is_some_and(|after| self.calls > after)
            {
                let partial = self.pending_partial_bytes.min(destination.len());
                destination[..partial].copy_from_slice(&self.bytes[start..start + partial]);
                std::future::pending::<()>().await;
                unreachable!("pending reader resumed")
            }
            let mut written = 0;
            while written < destination.len() {
                let take = self
                    .fragment_plan
                    .pop_front()
                    .unwrap_or(destination.len())
                    .max(1)
                    .min(destination.len() - written);
                destination[written..written + take]
                    .copy_from_slice(&self.bytes[start + written..start + written + take]);
                written += take;
            }
            if self.calls >= 4 {
                if let Some((index, xor)) = self.second_pass_mutation {
                    if index >= start && index < end {
                        destination[index - start] ^= xor;
                    }
                }
            }
            let mut receipt =
                LegacyRangeReceipt::new(object.clone(), offset, destination.len() as u64);
            let inject_fault = self
                .receipt_fault_after_call
                .map_or(true, |after| self.calls > after);
            match self.receipt_fault.filter(|_| inject_fault) {
                Some(ReceiptFault::Generation) => {
                    receipt.object.generation = LegacyGeneration::new(999).unwrap()
                }
                Some(ReceiptFault::Offset) => receipt.offset = offset.saturating_add(1),
                Some(ReceiptFault::Length) => receipt.byte_len = receipt.byte_len.saturating_sub(1),
                Some(ReceiptFault::Total) => {
                    receipt.object.byte_len = receipt.object.byte_len.saturating_add(1)
                }
                Some(ReceiptFault::Identity) => {
                    receipt.object.identity = LegacySourceIdentity::new(b"other-receipt-source")
                        .unwrap()
                        .commitment()
                }
                None => {}
            }
            Ok(receipt)
        }
    }
    #[derive(Default)]
    struct FakeSink {
        committed: Vec<u8>,
        writes: usize,
        commits: usize,
        aborts: usize,
        begins: usize,
        fail_begin: bool,
        pending_write: bool,
        pending_commit: bool,
    }
    #[derive(Default)]
    struct FakeStaging(Vec<u8>);
    impl sealed::Sink for FakeSink {}
    #[async_trait::async_trait]
    impl PlaintextStagingSink for FakeSink {
        type Staging = FakeStaging;
        fn begin(&mut self, _: u64) -> Result<Self::Staging> {
            self.begins += 1;
            if self.fail_begin {
                return Err(crypto_error("test sink begin failure"));
            }
            Ok(FakeStaging::default())
        }
        async fn write(&mut self, staging: &mut Self::Staging, plaintext: &[u8]) -> Result<()> {
            self.writes += 1;
            staging.0.extend_from_slice(plaintext);
            if self.pending_write {
                std::future::pending::<()>().await;
                unreachable!("pending sink write resumed")
            }
            Ok(())
        }
        async fn commit(&mut self, staging: &mut Self::Staging) -> Result<()> {
            if self.pending_commit {
                std::future::pending::<()>().await;
                unreachable!("pending sink commit resumed")
            }
            self.commits += 1;
            self.committed = std::mem::take(&mut staging.0);
            Ok(())
        }
        fn abort(&mut self, staging: &mut Self::Staging) {
            self.aborts += 1;
            staging.0.zeroize();
            staging.0.clear();
        }
    }
    fn dek() -> Dek {
        Dek([0; 32])
    }
    fn fixture_nonce(byte: u8) -> [u8; NONCE_LEN] {
        std::array::from_fn(|_| byte)
    }
    fn source_identity() -> LegacySourceIdentity {
        LegacySourceIdentity::new(b"test-canonical-source").unwrap()
    }
    fn envelope(plaintext: &[u8], aad: &[u8], nonce: [u8; NONCE_LEN]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&dek().0).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&encrypted);
        out
    }
    async fn run(
        bytes: Vec<u8>,
        aad: LegacyGcmAad<'_>,
    ) -> (Result<LegacyGcmRead>, FakeReader, FakeSink) {
        let mut reader = FakeReader::new(bytes);
        let mut sink = FakeSink::default();
        let result = authenticate_then_stage_decrypt(&mut reader, &mut sink, &dek(), aad).await;
        (result, reader, sink)
    }
    #[tokio::test]
    async fn nist_aes256_gcm_empty_plaintext_kat() {
        let blob = envelope(&[], &[], fixture_nonce(0));
        assert_eq!(
            &blob[NONCE_LEN..],
            &hex_bytes("530f8afbc74536b9a963b4f1c4cb738b")
        );
        let (result, _, sink) = run(blob, LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite)).await;
        assert_eq!(result.unwrap().plaintext_len, 0);
        assert!(sink.committed.is_empty());
        assert_eq!(sink.commits, 1);
    }
    #[tokio::test]
    async fn differential_boundaries_and_historic_aad_profiles() {
        for media in [false, true] {
            for len in [0usize, 1, 15, 16, 17, 31, 32, 33, MAX_CHUNK_BYTES + 3] {
                let plaintext: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(17)).collect();
                let aad: &[u8] = if media { b"actual-media-user-id" } else { b"" };
                let blob = envelope(&plaintext, aad, fixture_nonce(7));
                let profile = if media {
                    LegacyGcmAad::MediaUserId(aad)
                } else {
                    LegacyGcmAad::Empty(LegacyEmptyAad::Control)
                };
                let (result, _, sink) = run(blob, profile).await;
                assert_eq!(result.unwrap().plaintext_len, len as u64);
                assert_eq!(sink.committed, plaintext, "len={len}");
            }
        }
    }
    #[tokio::test]
    async fn nonce_ciphertext_tag_and_aad_tamper_never_write_plaintext() {
        let original = envelope(b"authenticated plaintext", &[], fixture_nonce(1));
        for index in [NONCE_LEN - 1, NONCE_LEN, original.len() - 1] {
            let mut blob = original.clone();
            blob[index] ^= 0x80;
            let (result, _, sink) = run(blob, LegacyGcmAad::Empty(LegacyEmptyAad::Acme)).await;
            assert!(result.is_err());
            assert_eq!(sink.writes, 0);
            assert_eq!(sink.commits, 0);
            assert!(sink.committed.is_empty());
        }
        let (result, _, sink) = run(original, LegacyGcmAad::MediaUserId(b"wrong-media-user")).await;
        assert!(result.is_err());
        assert_eq!(sink.writes, 0);
        assert_eq!(sink.commits, 0);
    }

    #[tokio::test]
    async fn rejects_an_empty_media_identity_instead_of_treating_it_as_empty_aad() {
        let blob = envelope(b"media", b"", fixture_nonce(9));
        let (result, _, sink) = run(blob, LegacyGcmAad::MediaUserId(b"")).await;
        assert!(result.is_err());
        assert_eq!(sink.writes, 0);
        assert_eq!(sink.commits, 0);
    }
    #[tokio::test]
    async fn rejects_invalid_media_user_id_instead_of_widening_historic_aad() {
        let blob = envelope(b"media", b"bad/user", fixture_nonce(9));
        let (result, _, sink) = run(blob, LegacyGcmAad::MediaUserId(b"bad/user")).await;
        assert!(result.is_err());
        assert_eq!(sink.writes, 0);
        assert_eq!(sink.commits, 0);
    }
    #[tokio::test]
    async fn sink_begin_failure_exposes_no_plaintext_or_commit() {
        let blob = envelope(b"authenticated", &[], fixture_nonce(8));
        let mut reader = FakeReader::new(blob);
        let mut sink = FakeSink {
            fail_begin: true,
            ..FakeSink::default()
        };
        assert!(authenticate_then_stage_decrypt(
            &mut reader,
            &mut sink,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite)
        )
        .await
        .is_err());
        assert_eq!(sink.writes, 0);
        assert_eq!(sink.commits, 0);
        assert_eq!(sink.aborts, 0);
        assert!(sink.committed.is_empty());
    }
    #[tokio::test]
    async fn wrong_independently_selected_object_fails_before_ranges_or_staging() {
        let blob = envelope(b"identity-bound pin", &[], fixture_nonce(15));
        let mut reader = FakeReader::new(blob);
        reader.selected_identity =
            LegacySourceIdentity::new(b"buggy-adapter-selected-another-source").unwrap();
        let mut sink = FakeSink::default();
        assert!(authenticate_then_stage_decrypt(
            &mut reader,
            &mut sink,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
        )
        .await
        .is_err());
        assert_eq!(reader.calls, 0);
        assert_eq!(sink.begins, 0);
        assert_eq!(sink.writes, 0);
        assert_eq!(sink.commits, 0);
        assert_eq!(sink.aborts, 0);
    }
    #[tokio::test]
    async fn rejects_truncation_and_v2_marker_without_output() {
        for blob in [vec![], vec![0; NONCE_LEN + TAG_LEN - 1], V2_MAGIC.to_vec()] {
            let (result, _, sink) = run(blob, LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite)).await;
            assert!(result.is_err());
            assert_eq!(sink.writes, 0);
            assert_eq!(sink.commits, 0);
        }
        let mut marker = V2_MAGIC.to_vec();
        marker.extend_from_slice(&[0; NONCE_LEN - V2_MAGIC.len() + TAG_LEN]);
        let (result, _, sink) = run(marker, LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite)).await;
        assert!(result.is_err());
        assert_eq!(sink.writes, 0);
    }
    #[tokio::test]
    async fn generation_and_range_receipt_faults_are_rejected_before_sink() {
        let blob = envelope(b"range check", &[], fixture_nonce(2));
        for fault in [
            ReceiptFault::Generation,
            ReceiptFault::Offset,
            ReceiptFault::Length,
            ReceiptFault::Total,
            ReceiptFault::Identity,
        ] {
            let mut reader = FakeReader::new(blob.clone());
            reader.receipt_fault = Some(fault);
            let mut sink = FakeSink::default();
            assert!(authenticate_then_stage_decrypt(
                &mut reader,
                &mut sink,
                &dek(),
                LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite)
            )
            .await
            .is_err());
            assert_eq!(sink.writes, 0);
            assert_eq!(sink.commits, 0);
        }
    }
    #[tokio::test]
    async fn arbitrary_source_fragmentation_preserves_single_ciphertext_padding() {
        let plaintext = vec![0x5a; MAX_CHUNK_BYTES + 37];
        let blob = envelope(&plaintext, b"media-user", fixture_nonce(3));
        let mut reader = FakeReader::new(blob);
        reader.fragment_plan = VecDeque::from(vec![1, 7, 16, 3, 29, 2, 127]);
        let mut sink = FakeSink::default();
        authenticate_then_stage_decrypt(
            &mut reader,
            &mut sink,
            &dek(),
            LegacyGcmAad::MediaUserId(b"media-user"),
        )
        .await
        .unwrap();
        assert_eq!(sink.committed, plaintext);
    }
    #[tokio::test]
    async fn second_pass_mutation_aborts_temporary_output_without_commit() {
        let plaintext = vec![0x41; 64];
        let blob = envelope(&plaintext, &[], fixture_nonce(4));
        let mut reader = FakeReader::new(blob);
        reader.second_pass_mutation = Some((NONCE_LEN + 7, 0x40));
        let mut sink = FakeSink::default();
        assert!(authenticate_then_stage_decrypt(
            &mut reader,
            &mut sink,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite)
        )
        .await
        .is_err());
        assert!(sink.writes > 0);
        assert_eq!(sink.commits, 0);
        assert_eq!(sink.aborts, 1);
        assert!(sink.committed.is_empty());
    }
    #[tokio::test]
    async fn second_pass_generation_receipt_fault_aborts_without_commit() {
        let blob = envelope(b"second-pass generation", &[], fixture_nonce(5));
        let mut reader = FakeReader::new(blob);
        reader.receipt_fault = Some(ReceiptFault::Generation);
        // Calls 1-3 are pass one (nonce, tag, ciphertext); call 4 is pass-two nonce.
        reader.receipt_fault_after_call = Some(3);
        let mut sink = FakeSink::default();
        assert!(authenticate_then_stage_decrypt(
            &mut reader,
            &mut sink,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite)
        )
        .await
        .is_err());
        assert_eq!(sink.commits, 0);
        assert_eq!(sink.aborts, 1);
        assert!(sink.committed.is_empty());
    }
    #[tokio::test]
    async fn second_pass_content_range_total_fault_aborts_without_commit() {
        let blob = envelope(b"second-pass total", &[], fixture_nonce(5));
        let mut reader = FakeReader::new(blob);
        reader.receipt_fault = Some(ReceiptFault::Total);
        reader.receipt_fault_after_call = Some(3);
        let mut sink = FakeSink::default();
        assert!(authenticate_then_stage_decrypt(
            &mut reader,
            &mut sink,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite)
        )
        .await
        .is_err());
        assert_eq!(sink.commits, 0);
        assert_eq!(sink.aborts, 1);
        assert!(sink.committed.is_empty());
    }
    #[tokio::test]
    async fn cancellation_while_second_pass_reader_waits_aborts_staging() {
        let blob = envelope(b"cancel reader", &[], fixture_nonce(6));
        let mut reader = FakeReader::new(blob);
        // Pass one uses nonce, tag, ciphertext. Pass-two nonce blocks forever.
        reader.pending_after_call = Some(3);
        let mut sink = FakeSink::default();
        let key = dek();
        {
            let future = authenticate_then_stage_decrypt(
                &mut reader,
                &mut sink,
                &key,
                LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            );
            tokio::pin!(future);
            tokio::select! {
                _ = &mut future => panic!("reader cancellation fixture unexpectedly completed"),
                _ = tokio::task::yield_now() => {}
            }
        }
        assert_eq!(sink.writes, 0);
        assert_eq!(sink.commits, 0);
        assert_eq!(sink.aborts, 1);
        assert!(sink.committed.is_empty());
    }
    #[tokio::test]
    async fn cancellation_while_sink_write_waits_aborts_staging() {
        let blob = envelope(b"cancel sink write", &[], fixture_nonce(7));
        let mut reader = FakeReader::new(blob);
        let mut sink = FakeSink {
            pending_write: true,
            ..FakeSink::default()
        };
        let key = dek();
        {
            let future = authenticate_then_stage_decrypt(
                &mut reader,
                &mut sink,
                &key,
                LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            );
            tokio::pin!(future);
            tokio::select! {
                _ = &mut future => panic!("sink cancellation fixture unexpectedly completed"),
                _ = tokio::task::yield_now() => {}
            }
        }
        assert_eq!(sink.writes, 1);
        assert_eq!(sink.commits, 0);
        assert_eq!(sink.aborts, 1);
        assert!(sink.committed.is_empty());
    }
    #[tokio::test]
    async fn cancellation_while_atomic_commit_waits_aborts_staging_without_visibility() {
        let blob = envelope(b"cancel commit", &[], fixture_nonce(10));
        let mut reader = FakeReader::new(blob);
        let mut sink = FakeSink {
            pending_commit: true,
            ..FakeSink::default()
        };
        let key = dek();
        {
            let future = authenticate_then_stage_decrypt(
                &mut reader,
                &mut sink,
                &key,
                LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            );
            tokio::pin!(future);
            tokio::select! {
                _ = &mut future => panic!("commit cancellation fixture unexpectedly completed"),
                _ = tokio::task::yield_now() => {}
            }
        }
        assert_eq!(sink.commits, 0, "fixture cancels before atomic visibility");
        assert_eq!(sink.aborts, 1);
        assert!(sink.committed.is_empty());
    }
    #[tokio::test]
    async fn authenticated_source_is_bounded_sequential_and_finishes_once() {
        let plaintext = b"source chunks are sequential".to_vec();
        let blob = envelope(&plaintext, &[], fixture_nonce(11));
        let identity = source_identity();
        let mut reader = FakeReader::selected(blob, &identity);
        let mut source = authenticate_legacy_source(
            &mut reader,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &identity,
        )
        .await
        .unwrap();
        let pre_staging_binding = source.binding();
        let mut output = Vec::new();
        let mut buffer = [0u8; 7];
        loop {
            let count = source.read_provisional(&mut buffer).await.unwrap().len();
            if count == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..count]);
            buffer[..count].zeroize();
        }
        assert_eq!(output, plaintext);
        let completion = source.finish().await.unwrap();
        assert_eq!(completion.plaintext_len, output.len() as u64);
        assert_eq!(
            completion.verify_binding(pre_staging_binding).unwrap(),
            pre_staging_binding
        );
        assert!(source.finish().await.is_err());
        assert!(source.read_provisional(&mut buffer).await.is_err());
    }
    #[tokio::test]
    async fn completion_binding_substitution_is_rejected() {
        let plaintext = b"completion is bound to the exact first pass";
        let blob = envelope(plaintext, &[], fixture_nonce(18));
        let identity = source_identity();
        let mut reader = FakeReader::selected(blob, &identity);
        let mut source = authenticate_legacy_source(
            &mut reader,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &identity,
        )
        .await
        .unwrap();
        let mut buffer = [0u8; 64];
        assert_eq!(
            source.read_provisional(&mut buffer).await.unwrap().len(),
            plaintext.len()
        );
        buffer.zeroize();
        assert_eq!(source.read_provisional(&mut buffer).await.unwrap().len(), 0);
        let mut substituted_binding = source.binding();
        substituted_binding.0[0] ^= 1;
        let completion = source.finish().await.unwrap();
        assert!(completion.verify_binding(substituted_binding).is_err());
        buffer.zeroize();
    }
    #[tokio::test]
    async fn source_binding_is_identity_and_profile_specific_and_redacted() {
        let blob = envelope(b"binding", &[], fixture_nonce(12));
        let first = LegacySourceIdentity::new(b"canonical-source-a").unwrap();
        let second = LegacySourceIdentity::new(b"canonical-source-b").unwrap();
        let mut reader_a = FakeReader::selected(blob.clone(), &first);
        let source_a = authenticate_legacy_source(
            &mut reader_a,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &first,
        )
        .await
        .unwrap();
        let binding_a = source_a.binding();
        drop(source_a);
        let mut reader_b = FakeReader::selected(blob.clone(), &second);
        let source_b = authenticate_legacy_source(
            &mut reader_b,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &second,
        )
        .await
        .unwrap();
        assert_ne!(binding_a, source_b.binding());
        drop(source_b);
        let mut reader_profile = FakeReader::selected(blob.clone(), &first);
        let source_profile = authenticate_legacy_source(
            &mut reader_profile,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Control),
            &first,
        )
        .await
        .unwrap();
        assert_ne!(binding_a, source_profile.binding());
        drop(source_profile);
        let mut reader_generation = FakeReader::selected(blob.clone(), &first);
        reader_generation.generation = LegacyGeneration::new(124).unwrap();
        let source_generation = authenticate_legacy_source(
            &mut reader_generation,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &first,
        )
        .await
        .unwrap();
        assert_ne!(binding_a, source_generation.binding());
        drop(source_generation);
        let mut reader_digest =
            FakeReader::selected(envelope(b"changed", &[], fixture_nonce(12)), &first);
        let source_digest = authenticate_legacy_source(
            &mut reader_digest,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &first,
        )
        .await
        .unwrap();
        assert_ne!(binding_a, source_digest.binding());
        assert!(!format!("{first:?}").contains("canonical-source-a"));
        assert!(!format!("{:?}", source_digest.binding()).contains("binding"));
        assert!(LegacySourceIdentity::new(b"").is_err());
        assert!(LegacySourceIdentity::new(&vec![1; MAX_SOURCE_IDENTITY_BYTES + 1]).is_err());
    }
    #[tokio::test]
    async fn early_finish_is_terminal_and_cannot_be_retried_or_replayed() {
        let blob = envelope(
            b"finish must consume every plaintext byte",
            &[],
            fixture_nonce(13),
        );
        let identity = source_identity();
        let mut reader = FakeReader::selected(blob, &identity);
        let mut source = authenticate_legacy_source(
            &mut reader,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &identity,
        )
        .await
        .unwrap();
        let mut chunk = [0u8; 4];
        assert!(source.finish().await.is_err());
        assert!(source.finish().await.is_err());
        assert!(source.read_provisional(&mut chunk).await.is_err());
        chunk.zeroize();
    }
    #[tokio::test]
    async fn source_owns_aad_state_after_first_pass() {
        let mut aad = b"mutable-media-user".to_vec();
        let plaintext = b"owned AAD protects the second pass".to_vec();
        let blob = envelope(&plaintext, &aad, fixture_nonce(16));
        let identity = source_identity();
        let mut reader = FakeReader::selected(blob, &identity);
        let mut source = authenticate_legacy_source(
            &mut reader,
            &dek(),
            LegacyGcmAad::MediaUserId(&aad),
            &identity,
        )
        .await
        .unwrap();
        aad.zeroize();
        aad.fill(b'x');

        let mut output = Vec::new();
        let mut chunk = [0u8; 9];
        loop {
            let provisional = source.read_provisional(&mut chunk).await.unwrap();
            if provisional.len() == 0 {
                break;
            }
            output.extend_from_slice(&chunk[..provisional.len()]);
            chunk.zeroize();
        }
        assert_eq!(output, plaintext);
        assert_eq!(
            source.finish().await.unwrap().plaintext_len,
            output.len() as u64
        );
        chunk.zeroize();
    }
    #[tokio::test]
    async fn cancelled_private_pull_zeroizes_partial_ciphertext_and_is_terminal() {
        let blob = envelope(
            b"partial ciphertext must not survive",
            &[],
            fixture_nonce(17),
        );
        let identity = source_identity();
        let mut reader = FakeReader::selected(blob, &identity);
        // Calls 1-3 are first pass; call 4 revalidates the nonce. Call 5
        // copies a partial ciphertext response and then remains pending.
        reader.pending_after_call = Some(4);
        reader.pending_partial_bytes = 5;
        let mut source = authenticate_legacy_source(
            &mut reader,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &identity,
        )
        .await
        .unwrap();
        let mut chunk = [0xa5; 64];
        {
            let future = source.read_provisional(&mut chunk);
            tokio::pin!(future);
            tokio::select! {
                _ = &mut future => panic!("partial ciphertext fixture unexpectedly completed"),
                _ = tokio::task::yield_now() => {}
            }
        }
        assert!(chunk.iter().all(|byte| *byte == 0));
        assert!(source.read_provisional(&mut chunk).await.is_err());
        assert!(source.finish().await.is_err());
        chunk.zeroize();
    }
    #[tokio::test]
    async fn second_pass_nonce_tag_and_receipt_faults_leave_source_terminal() {
        let blob = envelope(b"source second pass integrity", &[], fixture_nonce(14));
        for mutation in [0, NONCE_LEN + 3, blob.len() - TAG_LEN] {
            let identity = source_identity();
            let mut reader = FakeReader::selected(blob.clone(), &identity);
            reader.second_pass_mutation = Some((mutation, 0x80));
            let mut source = authenticate_legacy_source(
                &mut reader,
                &dek(),
                LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
                &identity,
            )
            .await
            .unwrap();
            let mut chunk = [0u8; 64];
            if mutation == 0 {
                assert!(source.read_provisional(&mut chunk).await.is_err());
            } else {
                assert!(source.read_provisional(&mut chunk).await.unwrap().len() > 0);
                chunk.zeroize();
                assert_eq!(source.read_provisional(&mut chunk).await.unwrap().len(), 0);
                assert!(source.finish().await.is_err());
            }
            assert!(source.finish().await.is_err());
            assert!(source.read_provisional(&mut chunk).await.is_err());
            chunk.zeroize();
        }

        let identity = source_identity();
        let mut reader = FakeReader::selected(blob.clone(), &identity);
        reader.receipt_fault = Some(ReceiptFault::Total);
        reader.receipt_fault_after_call = Some(3);
        let mut source = authenticate_legacy_source(
            &mut reader,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &identity,
        )
        .await
        .unwrap();
        let mut chunk = [0u8; 64];
        assert!(source.read_provisional(&mut chunk).await.is_err());
        assert!(source.read_provisional(&mut chunk).await.is_err());
        assert!(source.finish().await.is_err());
        chunk.zeroize();

        let identity = source_identity();
        let mut reader = FakeReader::selected(blob, &identity);
        // First pass uses three reads; second-pass nonce and ciphertext use
        // calls four and five, so only the exact tag/EOF receipt is malformed.
        reader.receipt_fault = Some(ReceiptFault::Total);
        reader.receipt_fault_after_call = Some(5);
        let mut source = authenticate_legacy_source(
            &mut reader,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            &identity,
        )
        .await
        .unwrap();
        let mut chunk = [0u8; 64];
        assert!(source.read_provisional(&mut chunk).await.unwrap().len() > 0);
        chunk.zeroize();
        assert_eq!(source.read_provisional(&mut chunk).await.unwrap().len(), 0);
        assert!(source.finish().await.is_err());
        assert!(source.read_provisional(&mut chunk).await.is_err());
        chunk.zeroize();
    }
    #[tokio::test]
    async fn early_source_drop_never_mints_completion() {
        let blob = envelope(b"drop before completion", &[], fixture_nonce(13));
        let identity = source_identity();
        let mut reader = FakeReader::selected(blob, &identity);
        {
            let mut source = authenticate_legacy_source(
                &mut reader,
                &dek(),
                LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
                &identity,
            )
            .await
            .unwrap();
            let mut buffer = [0u8; 4];
            assert!(source.read_provisional(&mut buffer).await.unwrap().len() > 0);
        }
        // Source drop has no completion value and no plaintext staging authority.
        assert!(reader.calls > 0);
    }
    #[test]
    fn provisional_pull_and_completion_are_not_crate_visible() {
        let source = include_str!("legacy_gcm.rs");
        for (kind, name) in [
            ("struct", "AuthenticatedLegacySource"),
            ("struct", "LegacyGcmCompletion"),
        ] {
            let forbidden = ["pub(crate) ", kind, " ", name].concat();
            assert!(!source.contains(&forbidden), "{name} became crate-visible");
        }
        for name in ["authenticate_legacy_source", "read_provisional"] {
            let definition = source
                .lines()
                .find(|line| line.contains(&format!("fn {name}")))
                .expect("sealed function definition exists");
            assert!(
                !definition.contains("pub(crate)"),
                "{name} became callable from sibling runtime modules"
            );
        }
        let parameterless_pin = [
            "async fn pin_",
            "legacy_object(&mut self) -> Result<PinnedLegacyObject>;",
        ]
        .concat();
        assert!(
            source.contains(&parameterless_pin),
            "pinning must independently select an object without receiving the requested identity"
        );
        let completion = source
            .find("struct LegacyGcmCompletion")
            .expect("completion type exists");
        let derive = source[..completion]
            .rsplit_once("#[derive(")
            .expect("completion derives are explicit")
            .1;
        assert!(!derive.contains("Clone"));
        assert!(!derive.contains("Copy"));
    }
    #[test]
    fn gcm_counter_starts_at_inc32_j0_and_enforces_bound() {
        let nonce = fixture_nonce(0xa5);
        let counter = gcm_counter_start(&nonce).unwrap();
        assert_eq!(&counter[..NONCE_LEN], &nonce);
        assert_eq!(&counter[12..], &2u32.to_be_bytes());
        assert_eq!(MAX_CIPHERTEXT_BYTES, (1u64 << 36) - 32);
        assert_eq!(MAX_LOGICAL_DATABASE_BYTES, 32 * 1024 * 1024 * 1024);
        assert!(validate_envelope_len(ENVELOPE_OVERHEAD + MAX_LOGICAL_DATABASE_BYTES).is_ok());
        assert!(validate_envelope_len(ENVELOPE_OVERHEAD + MAX_LOGICAL_DATABASE_BYTES + 1).is_err());
    }
    #[test]
    fn rejects_zero_generation_and_redacts_source_debug() {
        assert!(LegacyGeneration::new(0).is_err());
        let identity = source_identity();
        let object = PinnedLegacyObject::new(&identity, LegacyGeneration::new(123).unwrap(), 28);
        let receipt = LegacyRangeReceipt::new(object.clone(), 0, 12);
        let object_debug = format!("{object:?}");
        let receipt_debug = format!("{receipt:?}");
        assert!(!object_debug.contains("123"));
        assert!(!receipt_debug.contains("123"));
        assert!(!object_debug.contains("28"));
        assert!(!receipt_debug.contains("28"));
    }
    fn hex_bytes(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
