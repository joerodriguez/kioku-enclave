#![allow(
    dead_code,
    reason = "inactive ADR-0022 legacy converter primitive is compiled and tested before provider or authority wiring"
)]

//! Inactive, migration-only streaming reader for historical AES-256-GCM blobs.
//!
//! It accepts only `nonce[12] || ciphertext || tag[16]`, authenticates all
//! ciphertext before opening a temporary sink, then re-reads the same pinned
//! generation to decrypt in bounded chunks.  This is deliberately not wired
//! into Store, GCS, routes, flags, or any production authority.

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
// SP 800-38D §5.2.1.1: 2^39 - 256 bits, or (2^32 - 2) AES blocks.
const MAX_CIPHERTEXT_BYTES: u64 = ((u32::MAX as u64) - 1) * 16;
const MAX_AAD_BYTES: u64 = 1 << 36;
const MAX_LOGICAL_DATABASE_BYTES: u64 = crate::archive_v3::MAX_DATABASE_BYTES;
const V2_MAGIC: &[u8] = b"KIOKU-BLOB\x02";

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
}

impl fmt::Debug for PinnedLegacyObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedLegacyObject(<redacted>)")
    }
}

impl PinnedLegacyObject {
    pub(crate) fn new(generation: LegacyGeneration, byte_len: u64) -> Self {
        Self {
            generation,
            byte_len,
        }
    }
}

/// A range response receipt checked before this module consumes bytes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacyRangeReceipt {
    generation: LegacyGeneration,
    offset: u64,
    byte_len: u64,
    total_len: u64,
}

impl fmt::Debug for LegacyRangeReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacyRangeReceipt(<redacted>)")
    }
}

impl LegacyRangeReceipt {
    pub(crate) fn new(
        generation: LegacyGeneration,
        offset: u64,
        byte_len: u64,
        total_len: u64,
    ) -> Self {
        Self {
            generation,
            offset,
            byte_len,
            total_len,
        }
    }
}

/// Sealed generation-pinned range source. The production adapter must live in
/// this module or a child module. It must issue a single exact-generation GCS
/// range GET, require HTTP 206 plus a parsed `Content-Range` whose start,
/// inclusive end, total, and observed generation match this receipt, and fill
/// `destination` completely or error; it must not retry another generation.
#[async_trait]
pub(crate) trait PinnedLegacyRangeReader: sealed::RangeReader + Send {
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

/// Two-pass authenticate, then stage-decrypt an exact historic envelope.
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
    let object = reader.pin_legacy_object().await?;
    let ciphertext_len = validate_envelope_len(object.byte_len)?;
    let aad = aad_profile.bytes()?;
    validate_aad_len(aad)?;

    let mut nonce: [u8; NONCE_LEN] = Default::default();
    read_exact(reader, &object, 0, &mut nonce).await?;
    if nonce.starts_with(V2_MAGIC) {
        nonce.zeroize();
        return Err(crypto_error("v2 envelope is not a historic legacy blob"));
    }
    let tag_offset = (NONCE_LEN as u64)
        .checked_add(ciphertext_len)
        .ok_or_else(|| crypto_error("legacy ciphertext offset overflow"))?;
    let mut first_tag = [0u8; TAG_LEN];
    read_exact(reader, &object, tag_offset, &mut first_tag).await?;

    let key = Zeroizing::new(dek.0);
    let first_digest = authenticate_pass(
        reader,
        &object,
        &key,
        &nonce,
        aad,
        ciphertext_len,
        &first_tag,
    )
    .await;
    drop(key);
    let mut first_digest = match first_digest {
        Ok(digest) => digest,
        Err(error) => {
            nonce.zeroize();
            first_tag.zeroize();
            return Err(error);
        }
    };

    // No plaintext, even in a temporary sink, is written before authentication.
    let staging = match sink.begin(ciphertext_len) {
        Ok(staging) => staging,
        Err(error) => {
            first_digest.zeroize();
            nonce.zeroize();
            first_tag.zeroize();
            return Err(error);
        }
    };
    let mut staging = StagingGuard::new(sink, staging);
    let second = {
        let (sink, temporary_output) = staging.parts_mut();
        decrypt_second_pass(
            reader,
            &object,
            sink,
            temporary_output,
            dek,
            aad,
            ciphertext_len,
            &nonce,
            &first_tag,
            &first_digest,
        )
        .await
    };
    first_digest.zeroize();
    nonce.zeroize();
    first_tag.zeroize();

    match second {
        Ok(()) => match staging.commit().await {
            Ok(()) => Ok(LegacyGcmRead {
                plaintext_len: ciphertext_len,
            }),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

fn crypto_error(message: &'static str) -> EnclaveError {
    EnclaveError::Crypto(format!("legacy GCM migration: {message}"))
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
    let receipt = match reader.read_pinned_exact(object, offset, destination).await {
        Ok(receipt) => receipt,
        Err(error) => {
            destination.zeroize();
            return Err(error);
        }
    };
    if receipt.generation != object.generation
        || receipt.offset != offset
        || receipt.byte_len != requested_len
        || receipt.total_len != object.byte_len
    {
        destination.zeroize();
        return Err(crypto_error(
            "legacy range did not match pinned generation and extent",
        ));
    }
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

#[allow(clippy::too_many_arguments)]
async fn decrypt_second_pass<R, S>(
    reader: &mut R,
    object: &PinnedLegacyObject,
    sink: &mut S,
    staging: &mut S::Staging,
    dek: &Dek,
    aad: &[u8],
    ciphertext_len: u64,
    first_nonce: &[u8; NONCE_LEN],
    first_tag: &[u8; TAG_LEN],
    first_digest: &[u8; 32],
) -> Result<()>
where
    R: PinnedLegacyRangeReader,
    S: PlaintextStagingSink,
{
    let mut nonce: [u8; NONCE_LEN] = Default::default();
    read_exact(reader, object, 0, &mut nonce).await?;
    if nonce.ct_eq(first_nonce).unwrap_u8() != 1 || nonce.starts_with(V2_MAGIC) {
        nonce.zeroize();
        return Err(crypto_error("legacy nonce changed between passes"));
    }
    let key = Zeroizing::new(dek.0);
    let mut authenticator = GcmAuthenticator::new(&key, &nonce, aad)?;
    let mut ctr_iv = gcm_counter_start(&nonce)?;
    let mut ctr = Ctr32BE::<Aes256>::new(
        GenericArray::from_slice(&*key),
        GenericArray::from_slice(&ctr_iv),
    );
    drop(key);
    ctr_iv.zeroize();
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
            nonce.zeroize();
            return Err(error);
        }
        authenticator.absorb_ciphertext(chunk);
        digest.update(&*chunk);
        if ctr.try_apply_keystream(chunk).is_err() {
            chunk.zeroize();
            buffer.zeroize();
            nonce.zeroize();
            return Err(crypto_error("legacy GCM counter exhausted during decrypt"));
        }
        if let Err(error) = sink.write(staging, chunk).await {
            chunk.zeroize();
            buffer.zeroize();
            nonce.zeroize();
            return Err(error);
        }
        chunk.zeroize();
        offset = offset
            .checked_add(bytes as u64)
            .ok_or_else(|| crypto_error("legacy ciphertext offset overflow"))?;
    }
    buffer.zeroize();
    nonce.zeroize();

    let tag_offset = (NONCE_LEN as u64)
        .checked_add(ciphertext_len)
        .ok_or_else(|| crypto_error("legacy ciphertext offset overflow"))?;
    let mut second_tag = [0u8; TAG_LEN];
    read_exact(reader, object, tag_offset, &mut second_tag).await?;
    let tag_same = second_tag.ct_eq(first_tag).unwrap_u8() == 1;
    let mut calculated_tag = authenticator.finish(ciphertext_len)?;
    let tag_valid = calculated_tag.ct_eq(&second_tag).unwrap_u8() == 1;
    calculated_tag.zeroize();
    second_tag.zeroize();
    if !tag_same || !tag_valid {
        return Err(crypto_error(
            "legacy envelope changed or failed authentication in second pass",
        ));
    }
    let mut second_digest: [u8; 32] = digest.finalize().into();
    let same_digest = second_digest.ct_eq(first_digest).unwrap_u8() == 1;
    second_digest.zeroize();
    if !same_digest {
        return Err(crypto_error("legacy ciphertext changed between passes"));
    }
    Ok(())
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
    }
    impl FakeReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                generation: LegacyGeneration::new(123).unwrap(),
                ..Self::default()
            }
        }
    }
    impl sealed::RangeReader for FakeReader {}
    #[async_trait::async_trait]
    impl PinnedLegacyRangeReader for FakeReader {
        async fn pin_legacy_object(&mut self) -> Result<PinnedLegacyObject> {
            Ok(PinnedLegacyObject::new(
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
            if self
                .pending_after_call
                .is_some_and(|after| self.calls > after)
            {
                std::future::pending::<()>().await;
                unreachable!("pending reader resumed")
            }
            let start = usize::try_from(offset).map_err(|_| crypto_error("test offset"))?;
            let end = start
                .checked_add(destination.len())
                .ok_or_else(|| crypto_error("test range overflow"))?;
            if end > self.bytes.len() {
                return Err(crypto_error("test source range unavailable"));
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
            let mut receipt = LegacyRangeReceipt::new(
                object.generation,
                offset,
                destination.len() as u64,
                object.byte_len,
            );
            let inject_fault = self
                .receipt_fault_after_call
                .map_or(true, |after| self.calls > after);
            match self.receipt_fault.filter(|_| inject_fault) {
                Some(ReceiptFault::Generation) => {
                    receipt.generation = LegacyGeneration::new(999).unwrap()
                }
                Some(ReceiptFault::Offset) => receipt.offset = offset.saturating_add(1),
                Some(ReceiptFault::Length) => receipt.byte_len = receipt.byte_len.saturating_sub(1),
                Some(ReceiptFault::Total) => {
                    receipt.total_len = receipt.total_len.saturating_add(1)
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
        let object = PinnedLegacyObject::new(LegacyGeneration::new(123).unwrap(), 28);
        let receipt = LegacyRangeReceipt::new(LegacyGeneration::new(123).unwrap(), 0, 12, 28);
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
