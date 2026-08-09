#![allow(
    dead_code,
    reason = "this deliberately private, inactive module is compiled and unit-tested before ADR-0022 shadow-gate wiring"
)]

//! Inactive, format-versioned building blocks for ADR-0022 archive persistence.
//!
//! This module deliberately has **no production authority**.  It is not wired
//! to `Store`, SQLite, a VFS, GCS, the witness, routing, or account deletion.
//! Until the ADR-0022 shadow gates pass, the legacy encrypted database remains
//! the sole authoritative persistence path.  These primitives exist to make
//! the future format's cryptographic and bounded-decoding contract testable in
//! isolation.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    sync::Mutex,
};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Archive-v3 format version.  Decoders reject every other version.
pub const ARCHIVE_FORMAT_VERSION: u8 = 3;
const AAD_DOMAIN: &[u8] = b"kioku:archive:v3:aad\0";
const HKDF_SALT: &[u8] = b"kioku:archive:v3:hkdf-sha256\0";
const ENVELOPE_MAGIC: &[u8; 8] = b"KARCv3\0\0";
const NODE_MAGIC: &[u8; 8] = b"KARNv3\0\0";
const ROOT_MAGIC: &[u8; 8] = b"KARRv3\0\0";
const KEY_REGISTRY_MAGIC: &[u8; 16] = b"KIOKU-KEYREG-v3\0";
const KEY_REGISTRY_DOMAIN: &[u8] = b"kioku:archive:v3:kms-wrap\0";
const GCM_TAG_BYTES: usize = 16;
const FIXED_GCM_NONCE: [u8; 12] = [0; 12];

/// The format's fixed maximum encrypted payload, excluding envelope framing.
pub const MAX_CIPHERTEXT_BYTES: usize = 1_048_576 + GCM_TAG_BYTES;
/// Node decoding is deliberately bounded independently of archive size.
pub const MAX_NODE_BYTES: usize = 64 * 1024;
/// Root descriptor decoding has a separately named bound, so it can never grow
/// with database size even if node limits evolve later.
pub const MAX_ROOT_BYTES: usize = 64 * 1024;
/// The sparse radix tree fanout is an on-wire compatibility property.
pub const MAX_NODE_FANOUT: usize = 256;
/// Maximum page size for backend inventory.  Deletion/GC must persist cursors.
pub const MAX_ENUMERATION_PAGE: usize = 1_000;
/// The initial format supports only the ADR's fixed SQLite page size.
pub const SQLITE_PAGE_SIZE: u32 = 4096;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArchiveV3Error {
    #[error("archive-v3 input is malformed: {0}")]
    Malformed(&'static str),
    #[error("archive-v3 input exceeds a fixed format limit: {0}")]
    TooLarge(&'static str),
    #[error("archive-v3 object context has an invalid role/location pairing")]
    InvalidContext,
    #[error("archive-v3 object context was already sealed")]
    DuplicateSeal,
    #[error("archive-v3 authentication failed")]
    Authentication,
    #[error("immutable object already exists with different ciphertext")]
    Conflict,
}

pub type Result<T> = std::result::Result<T, ArchiveV3Error>;

/// Opaque 128-bit archive identity; it is never derived from an account ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArchiveId([u8; 16]);

/// Opaque 128-bit database identity.  Epochs do not reuse an existing value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DatabaseEpoch([u8; 16]);

/// Opaque 128-bit key-registry epoch identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyEpoch([u8; 16]);

/// Unique 128-bit immutable object version identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId([u8; 16]);

macro_rules! opaque_id {
    ($name:ident) => {
        impl $name {
            pub fn random() -> Self {
                let mut value = [0u8; 16];
                OsRng.fill_bytes(&mut value);
                Self(value)
            }

            pub const fn from_bytes(value: [u8; 16]) -> Self {
                Self(value)
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }
    };
}

opaque_id!(ArchiveId);
opaque_id!(DatabaseEpoch);
opaque_id!(KeyEpoch);
opaque_id!(ObjectId);

/// Internal canonical-path encoding.  Opaque IDs intentionally implement no
/// `Display`; regular formatting and logs therefore cannot reveal them.
fn canonical_id_component(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Versioned immutable archive object roles.  These tags are part of the AAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ObjectRole {
    // Tag 1 is reserved for a future bounded/streaming checkpoint-manifest
    // format.  This foundation does not pretend a multi-GiB checkpoint fits
    // inside one `MAX_CIPHERTEXT_BYTES` envelope.
    WalSegmentV3 = 2,
    ExtentV3 = 3,
    MerkleNodeV3 = 4,
    RootV3 = 5,
    KeyRegistryV3 = 6,
    StagingV3 = 7,
}

/// Key-registry namespaces are disjoint because archive and media DEKs may
/// never be derived from or substituted for one another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum KeyKind {
    Archive = 1,
    Media = 2,
}

impl KeyKind {
    const fn path_component(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Media => "media",
        }
    }
}

/// Exact logical location, independent of a storage-provider object name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LogicalLocation {
    Wal {
        root_seq: u64,
        wal_generation: u64,
        segment_index: u32,
    },
    Extent {
        extent_no: u64,
        byte_len: u32,
    },
    MerkleNode {
        level: u8,
        range_start: u64,
        range_end: u64,
    },
    Root {
        root_seq: u64,
    },
    KeyRegistry {
        key_kind: KeyKind,
    },
    Staging {
        operation_id: ObjectId,
    },
}

impl LogicalLocation {
    fn valid_for(&self, role: ObjectRole) -> bool {
        match (role, self) {
            (ObjectRole::WalSegmentV3, Self::Wal { .. })
            | (ObjectRole::RootV3, Self::Root { .. })
            | (ObjectRole::KeyRegistryV3, Self::KeyRegistry { .. })
            | (ObjectRole::StagingV3, Self::Staging { .. }) => true,
            (ObjectRole::ExtentV3, Self::Extent { byte_len, .. }) => {
                (1..=1_048_576).contains(byte_len) && byte_len.is_multiple_of(SQLITE_PAGE_SIZE)
            }
            (
                ObjectRole::MerkleNodeV3,
                Self::MerkleNode {
                    range_start,
                    range_end,
                    ..
                },
            ) => range_end > range_start,
            _ => false,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Wal {
                root_seq,
                wal_generation,
                segment_index,
            } => {
                out.push(2);
                push_u64(out, *root_seq);
                push_u64(out, *wal_generation);
                push_u32(out, *segment_index);
            }
            Self::Extent {
                extent_no,
                byte_len,
            } => {
                out.push(3);
                push_u64(out, *extent_no);
                push_u32(out, *byte_len);
            }
            Self::MerkleNode {
                level,
                range_start,
                range_end,
            } => {
                out.push(4);
                out.push(*level);
                push_u64(out, *range_start);
                push_u64(out, *range_end);
            }
            Self::Root { root_seq } => {
                out.push(5);
                push_u64(out, *root_seq);
            }
            Self::KeyRegistry { key_kind } => {
                out.push(6);
                out.push(*key_kind as u8);
            }
            Self::Staging { operation_id } => {
                out.push(7);
                out.extend_from_slice(operation_id.as_bytes());
            }
        }
    }
}

/// A prior immutable object bound into a successor's AAD where applicable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ParentReference {
    pub object_id: ObjectId,
    pub envelope_hash: [u8; 32],
}

/// Canonical AEAD/KDF context.  Its byte representation is fixed and
/// length-free because every field is fixed-width or an explicitly tagged enum.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObjectContext {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
    role: ObjectRole,
    location: LogicalLocation,
    object_id: ObjectId,
    parent: Option<ParentReference>,
}

impl ObjectContext {
    pub fn new(
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        role: ObjectRole,
        location: LogicalLocation,
        object_id: ObjectId,
        parent: Option<ParentReference>,
    ) -> Result<Self> {
        if !location.valid_for(role) {
            return Err(ArchiveV3Error::InvalidContext);
        }
        Ok(Self {
            archive_id,
            database_epoch,
            key_epoch,
            role,
            location,
            object_id,
            parent,
        })
    }

    pub const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }
    pub const fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }
    pub const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }
    pub const fn role(&self) -> ObjectRole {
        self.role
    }
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }
    pub fn location(&self) -> &LogicalLocation {
        &self.location
    }
    pub fn parent(&self) -> Option<&ParentReference> {
        self.parent.as_ref()
    }

    /// Canonical, unambiguous bytes used both as HKDF info and AEAD AAD.
    pub fn canonical_aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(AAD_DOMAIN);
        out.push(ARCHIVE_FORMAT_VERSION);
        out.extend_from_slice(self.archive_id.as_bytes());
        out.extend_from_slice(self.database_epoch.as_bytes());
        out.extend_from_slice(self.key_epoch.as_bytes());
        out.push(self.role as u8);
        self.location.encode_into(&mut out);
        out.extend_from_slice(self.object_id.as_bytes());
        match &self.parent {
            Some(parent) => {
                out.push(1);
                out.extend_from_slice(parent.object_id.as_bytes());
                out.extend_from_slice(&parent.envelope_hash);
            }
            None => out.push(0),
        }
        out
    }

    /// Canonical provider-neutral namespace from ADR-0022.  No user identity
    /// or caller-controlled value can appear in this object key.
    pub fn object_key(&self) -> ObjectKey {
        let archive = canonical_id_component(self.archive_id.as_bytes());
        let database_epoch = canonical_id_component(self.database_epoch.as_bytes());
        let key_epoch = canonical_id_component(self.key_epoch.as_bytes());
        let object = canonical_id_component(self.object_id.as_bytes());
        let name = match &self.location {
            LogicalLocation::Wal { root_seq, .. } => {
                format!("archive/v3/{archive}/wal/{database_epoch}/{root_seq}-{object}.walx")
            }
            LogicalLocation::Extent { extent_no, .. } => {
                format!("archive/v3/{archive}/extents/{database_epoch}/{extent_no}/{object}.extx")
            }
            LogicalLocation::MerkleNode { level, .. } => {
                format!("archive/v3/{archive}/nodes/{database_epoch}/{level}/{object}.nodex")
            }
            LogicalLocation::Root { root_seq } => {
                // Multiple immutable candidates for the same next sequence are
                // expected after crashes/CAS races. Only the exact ID/hash in
                // the independent witness is authoritative; recovery never
                // chooses a candidate by listing this prefix.
                format!(
                    "archive/v3/{archive}/root-candidates/{database_epoch}/{root_seq}-{object}.rootx"
                )
            }
            LogicalLocation::KeyRegistry { key_kind } => format!(
                "archive/v3/{archive}/keys/{}/{key_epoch}/{object}.keyx",
                key_kind.path_component()
            ),
            LogicalLocation::Staging { operation_id } => {
                let operation = canonical_id_component(operation_id.as_bytes());
                format!("archive/v3/{archive}/staging/{operation}/{object}")
            }
        };
        ObjectKey {
            canonical: name,
            object_id: self.object_id,
        }
    }
}

/// Opaque, canonical backend identity.  Only archive-v3 contexts construct it.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectKey {
    canonical: String,
    object_id: ObjectId,
}

impl fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObjectKey(<opaque>)")
    }
}

impl ObjectKey {
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }
}

/// Exact, archive-scoped enumeration selector.  This prevents a backend from
/// accepting arbitrary or cross-archive string prefixes.
#[derive(Clone, PartialEq, Eq)]
pub struct ArchivePrefix(String);

impl ArchivePrefix {
    pub fn for_archive(archive_id: ArchiveId) -> Self {
        Self(format!(
            "archive/v3/{}/",
            canonical_id_component(archive_id.as_bytes())
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArchivePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchivePrefix(<opaque>)")
    }
}

/// Canonical KMS-wrap context for one immutable registry entry.  It is
/// intentionally independent of `ObjectContext`: registry bytes cannot be
/// encrypted by the DEK they contain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyRegistryContext {
    archive_id: ArchiveId,
    key_kind: KeyKind,
    key_epoch: KeyEpoch,
}

impl KeyRegistryContext {
    pub const fn new(archive_id: ArchiveId, key_kind: KeyKind, key_epoch: KeyEpoch) -> Self {
        Self {
            archive_id,
            key_kind,
            key_epoch,
        }
    }

    pub fn object_key(&self, object_id: ObjectId) -> ObjectKey {
        let archive = canonical_id_component(self.archive_id.as_bytes());
        let key_epoch = canonical_id_component(self.key_epoch.as_bytes());
        let object = canonical_id_component(object_id.as_bytes());
        ObjectKey {
            canonical: format!(
                "archive/v3/{archive}/keys/{}/{key_epoch}/{object}.keyx",
                self.key_kind.path_component()
            ),
            object_id,
        }
    }
}

impl fmt::Debug for KeyRegistryContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRegistryContext")
            .field("archive_id", &"<opaque>")
            .field("key_kind", &self.key_kind)
            .field("key_epoch", &"<opaque>")
            .finish()
    }
}

/// Distinct media DEK type.  It cannot be passed to `ArchiveCipher`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MediaDek([u8; 32]);

impl MediaDek {
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Canonical versioned plaintext passed to Cloud KMS by future wiring.  This
/// type only frames/verifies bytes; it performs no KMS operation.
pub struct KeyRegistryPlaintext;

impl KeyRegistryPlaintext {
    pub fn encode_archive(
        context: &KeyRegistryContext,
        dek: &ArchiveDek,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if context.key_kind != KeyKind::Archive {
            return Err(ArchiveV3Error::InvalidContext);
        }
        Ok(Self::encode(context, &dek.0))
    }

    pub fn encode_media(
        context: &KeyRegistryContext,
        dek: &MediaDek,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if context.key_kind != KeyKind::Media {
            return Err(ArchiveV3Error::InvalidContext);
        }
        Ok(Self::encode(context, &dek.0))
    }

    fn encode(context: &KeyRegistryContext, dek: &[u8; 32]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            KEY_REGISTRY_MAGIC.len() + 1 + 2 + KEY_REGISTRY_DOMAIN.len() + 16 + 1 + 16 + 32,
        ));
        out.extend_from_slice(KEY_REGISTRY_MAGIC);
        out.push(ARCHIVE_FORMAT_VERSION);
        push_u16(&mut out, KEY_REGISTRY_DOMAIN.len() as u16);
        out.extend_from_slice(KEY_REGISTRY_DOMAIN);
        out.extend_from_slice(context.archive_id.as_bytes());
        out.push(context.key_kind as u8);
        out.extend_from_slice(context.key_epoch.as_bytes());
        out.extend_from_slice(dek);
        out
    }

    /// Decode KMS-unwrapped plaintext and verify every expected context field
    /// before returning a type that can expose the DEK.
    pub fn decode_verified(
        input: Zeroizing<Vec<u8>>,
        expected: &KeyRegistryContext,
    ) -> Result<VerifiedRegistryDek> {
        let input = input.as_slice();
        let minimum = KEY_REGISTRY_MAGIC.len() + 1 + 2 + 16 + 1 + 16 + 32;
        if input.len() < minimum {
            return Err(ArchiveV3Error::Malformed("key registry truncated"));
        }
        if &input[..KEY_REGISTRY_MAGIC.len()] != KEY_REGISTRY_MAGIC {
            return Err(ArchiveV3Error::Malformed("key registry magic"));
        }
        let mut offset = KEY_REGISTRY_MAGIC.len();
        if take(input, &mut offset, 1)?[0] != ARCHIVE_FORMAT_VERSION {
            return Err(ArchiveV3Error::Malformed("key registry version"));
        }
        let domain_len = read_u16(take(input, &mut offset, 2)?)? as usize;
        if domain_len != KEY_REGISTRY_DOMAIN.len()
            || take(input, &mut offset, domain_len)? != KEY_REGISTRY_DOMAIN
        {
            return Err(ArchiveV3Error::Malformed("key registry domain"));
        }
        let archive_id = ArchiveId::from_bytes(take_array(take(input, &mut offset, 16)?)?);
        let key_kind = match take(input, &mut offset, 1)?[0] {
            1 => KeyKind::Archive,
            2 => KeyKind::Media,
            _ => return Err(ArchiveV3Error::Malformed("key registry kind")),
        };
        let key_epoch = KeyEpoch::from_bytes(take_array(take(input, &mut offset, 16)?)?);
        let dek = take_array(take(input, &mut offset, 32)?)?;
        if offset != input.len() {
            return Err(ArchiveV3Error::Malformed("key registry trailing bytes"));
        }
        if archive_id != expected.archive_id
            || key_kind != expected.key_kind
            || key_epoch != expected.key_epoch
        {
            return Err(ArchiveV3Error::InvalidContext);
        }
        Ok(VerifiedRegistryDek { key_kind, dek })
    }
}

/// KMS-unwrapped DEK whose registry context has already been verified.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedRegistryDek {
    #[zeroize(skip)]
    key_kind: KeyKind,
    dek: [u8; 32],
}

impl VerifiedRegistryDek {
    pub fn into_archive_dek(self) -> Result<ArchiveDek> {
        if self.key_kind != KeyKind::Archive {
            return Err(ArchiveV3Error::InvalidContext);
        }
        let mut verified = self;
        Ok(ArchiveDek::from_bytes(std::mem::take(&mut verified.dek)))
    }

    pub fn into_media_dek(self) -> Result<MediaDek> {
        if self.key_kind != KeyKind::Media {
            return Err(ArchiveV3Error::InvalidContext);
        }
        let mut verified = self;
        Ok(MediaDek::from_bytes(std::mem::take(&mut verified.dek)))
    }
}

/// Versioned ciphertext envelope.  The fixed AES-GCM nonce is safe only
/// because a fresh per-object HKDF key is derived from a unique object context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphertextEnvelope {
    ciphertext: Vec<u8>,
}

impl CiphertextEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + self.ciphertext.len());
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.push(ARCHIVE_FORMAT_VERSION);
        push_u32(&mut out, self.ciphertext.len() as u32);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 13 {
            return Err(ArchiveV3Error::Malformed("envelope truncated"));
        }
        if &input[..8] != ENVELOPE_MAGIC {
            return Err(ArchiveV3Error::Malformed("envelope magic"));
        }
        if input[8] != ARCHIVE_FORMAT_VERSION {
            return Err(ArchiveV3Error::Malformed("envelope version"));
        }
        let length = read_u32(&input[9..13])? as usize;
        if length > MAX_CIPHERTEXT_BYTES {
            return Err(ArchiveV3Error::TooLarge("ciphertext"));
        }
        if length < GCM_TAG_BYTES {
            return Err(ArchiveV3Error::Malformed("ciphertext tag"));
        }
        if input.len() != 13 + length {
            return Err(ArchiveV3Error::Malformed("envelope length"));
        }
        Ok(Self {
            ciphertext: input[13..].to_vec(),
        })
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// A root archive DEK used only in enclave memory.  It is never embedded in an
/// archive-v3 object; the key registry owns KMS-wrapped copies by epoch.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ArchiveDek([u8; 32]);

impl ArchiveDek {
    pub fn generate() -> Self {
        let mut value = [0u8; 32];
        OsRng.fill_bytes(&mut value);
        Self(value)
    }

    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Seals every context at most once per process instance.  This catches local
/// accidental fixed-nonce reuse; cross-process ID collisions are rejected by
/// the immutable backend's different-ciphertext conflict.
pub struct ArchiveCipher {
    dek: ArchiveDek,
    sealed_contexts: Mutex<HashSet<[u8; 32]>>,
}

impl ArchiveCipher {
    pub fn new(dek: ArchiveDek) -> Self {
        Self {
            dek,
            sealed_contexts: Mutex::new(HashSet::new()),
        }
    }

    pub fn seal(&self, context: &ObjectContext, plaintext: &[u8]) -> Result<CiphertextEnvelope> {
        if context.role() == ObjectRole::KeyRegistryV3 {
            return Err(ArchiveV3Error::InvalidContext);
        }
        if matches!(
            context.location(),
            LogicalLocation::Extent { byte_len, .. }
                if plaintext.len() != *byte_len as usize
        ) {
            return Err(ArchiveV3Error::InvalidContext);
        }
        if plaintext.len() > MAX_CIPHERTEXT_BYTES - GCM_TAG_BYTES {
            return Err(ArchiveV3Error::TooLarge("plaintext"));
        }
        let aad = context.canonical_aad();
        let context_hash: [u8; 32] = Sha256::digest(&aad).into();
        let mut used = self
            .sealed_contexts
            .lock()
            .expect("archive cipher mutex poisoned");
        if !used.insert(context_hash) {
            return Err(ArchiveV3Error::DuplicateSeal);
        }
        drop(used);

        let key = derive_object_key(&self.dek, &aad)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key[..]).map_err(|_| ArchiveV3Error::Authentication)?;
        let ciphertext = cipher
            .encrypt(
                (&FIXED_GCM_NONCE).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ArchiveV3Error::Authentication)?;
        Ok(CiphertextEnvelope { ciphertext })
    }

    pub fn open(&self, context: &ObjectContext, envelope: &CiphertextEnvelope) -> Result<Vec<u8>> {
        if context.role() == ObjectRole::KeyRegistryV3 {
            return Err(ArchiveV3Error::InvalidContext);
        }
        if envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(ArchiveV3Error::TooLarge("ciphertext"));
        }
        let aad = context.canonical_aad();
        let key = derive_object_key(&self.dek, &aad)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key[..]).map_err(|_| ArchiveV3Error::Authentication)?;
        cipher
            .decrypt(
                (&FIXED_GCM_NONCE).into(),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ArchiveV3Error::Authentication)
    }
}

fn derive_object_key(dek: &ArchiveDek, aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), &dek.0);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(aad, &mut output[..])
        .map_err(|_| ArchiveV3Error::Malformed("HKDF output"))?;
    Ok(output)
}

/// Immutable reference used by Merkle nodes and roots.  The hash covers the
/// full versioned ciphertext envelope, never plaintext alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImmutableReference {
    pub object_id: ObjectId,
    pub envelope_hash: [u8; 32],
}

/// Actual leaf entry mapping one logical extent number to its immutable
/// ciphertext envelope, logical length, and monotonic extent revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtentReference {
    pub extent_no: u64,
    pub logical_byte_len: u32,
    pub revision: u64,
    pub reference: ImmutableReference,
}

impl ExtentReference {
    pub fn validate(&self) -> Result<()> {
        if self.logical_byte_len == 0
            || self.logical_byte_len > 1_048_576
            || !self.logical_byte_len.is_multiple_of(SQLITE_PAGE_SIZE)
            || self.revision == 0
        {
            return Err(ArchiveV3Error::Malformed("extent reference"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleChild {
    pub range_start: u64,
    pub range_end: u64,
    pub reference: ImmutableReference,
}

/// Node payload is explicitly tagged on wire.  Level zero contains extents;
/// every positive level contains child-node references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleEntries {
    Leaf(Vec<ExtentReference>),
    Internal(Vec<MerkleChild>),
}

/// Fixed-fanout sparse Merkle radix node.  Gaps are permitted; overlap and
/// out-of-parent ranges are not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleNode {
    pub level: u8,
    pub range_start: u64,
    pub range_end: u64,
    pub entries: MerkleEntries,
}

impl MerkleNode {
    pub fn validate(&self) -> Result<()> {
        if self.range_end <= self.range_start {
            return Err(ArchiveV3Error::Malformed("node range"));
        }
        match &self.entries {
            MerkleEntries::Leaf(extents) => {
                if self.level != 0 {
                    return Err(ArchiveV3Error::Malformed("leaf node level"));
                }
                if extents.is_empty() {
                    return Err(ArchiveV3Error::Malformed("empty leaf node"));
                }
                if extents.len() > MAX_NODE_FANOUT {
                    return Err(ArchiveV3Error::TooLarge("node fanout"));
                }
                let mut previous_extent = None;
                for extent in extents {
                    extent.validate()?;
                    if extent.extent_no < self.range_start
                        || extent.extent_no >= self.range_end
                        || previous_extent.is_some_and(|previous| extent.extent_no <= previous)
                    {
                        return Err(ArchiveV3Error::Malformed("leaf extent range"));
                    }
                    previous_extent = Some(extent.extent_no);
                }
            }
            MerkleEntries::Internal(children) => {
                if self.level == 0 {
                    return Err(ArchiveV3Error::Malformed("internal node level"));
                }
                if children.is_empty() {
                    return Err(ArchiveV3Error::Malformed("empty internal node"));
                }
                if children.len() > MAX_NODE_FANOUT {
                    return Err(ArchiveV3Error::TooLarge("node fanout"));
                }
                let mut previous_end = self.range_start;
                for child in children {
                    if child.range_end <= child.range_start
                        || child.range_start < self.range_start
                        || child.range_end > self.range_end
                        || child.range_start < previous_end
                    {
                        return Err(ArchiveV3Error::Malformed("node child range"));
                    }
                    previous_end = child.range_end;
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let (kind, count, entry_bytes) = match &self.entries {
            MerkleEntries::Leaf(extents) => (1u8, extents.len(), 68usize),
            MerkleEntries::Internal(children) => (2u8, children.len(), 64usize),
        };
        let length = 29usize
            .checked_add(
                count
                    .checked_mul(entry_bytes)
                    .ok_or(ArchiveV3Error::TooLarge("node"))?,
            )
            .ok_or(ArchiveV3Error::TooLarge("node"))?;
        if length > MAX_NODE_BYTES {
            return Err(ArchiveV3Error::TooLarge("node"));
        }
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(NODE_MAGIC);
        out.push(ARCHIVE_FORMAT_VERSION);
        out.push(kind);
        out.push(self.level);
        push_u16(&mut out, count as u16);
        push_u64(&mut out, self.range_start);
        push_u64(&mut out, self.range_end);
        match &self.entries {
            MerkleEntries::Leaf(extents) => {
                for extent in extents {
                    push_u64(&mut out, extent.extent_no);
                    push_u32(&mut out, extent.logical_byte_len);
                    push_u64(&mut out, extent.revision);
                    out.extend_from_slice(extent.reference.object_id.as_bytes());
                    out.extend_from_slice(&extent.reference.envelope_hash);
                }
            }
            MerkleEntries::Internal(children) => {
                for child in children {
                    push_u64(&mut out, child.range_start);
                    push_u64(&mut out, child.range_end);
                    out.extend_from_slice(child.reference.object_id.as_bytes());
                    out.extend_from_slice(&child.reference.envelope_hash);
                }
            }
        }
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_NODE_BYTES {
            return Err(ArchiveV3Error::TooLarge("node"));
        }
        if input.len() < 29 || &input[..8] != NODE_MAGIC || input[8] != ARCHIVE_FORMAT_VERSION {
            return Err(ArchiveV3Error::Malformed("node header"));
        }
        let kind = input[9];
        let level = input[10];
        let count = read_u16(&input[11..13])? as usize;
        if count > MAX_NODE_FANOUT {
            return Err(ArchiveV3Error::TooLarge("node fanout"));
        }
        let entry_bytes = match kind {
            1 => 68,
            2 => 64,
            _ => return Err(ArchiveV3Error::Malformed("node kind")),
        };
        let expected = 29usize
            .checked_add(
                count
                    .checked_mul(entry_bytes)
                    .ok_or(ArchiveV3Error::TooLarge("node"))?,
            )
            .ok_or(ArchiveV3Error::TooLarge("node"))?;
        if input.len() != expected {
            return Err(ArchiveV3Error::Malformed("node length"));
        }
        let range_start = read_u64(&input[13..21])?;
        let range_end = read_u64(&input[21..29])?;
        let mut offset = 29;
        let entries = if kind == 1 {
            let mut extents = Vec::with_capacity(count);
            for _ in 0..count {
                let extent_no = take_u64(input, &mut offset)?;
                let logical_byte_len = take_u32(input, &mut offset)?;
                let revision = take_u64(input, &mut offset)?;
                let object_id = object_id_from_slice(take(input, &mut offset, 16)?)?;
                let mut envelope_hash = [0u8; 32];
                envelope_hash.copy_from_slice(take(input, &mut offset, 32)?);
                extents.push(ExtentReference {
                    extent_no,
                    logical_byte_len,
                    revision,
                    reference: ImmutableReference {
                        object_id,
                        envelope_hash,
                    },
                });
            }
            MerkleEntries::Leaf(extents)
        } else {
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                let child_start = take_u64(input, &mut offset)?;
                let child_end = take_u64(input, &mut offset)?;
                let object_id = object_id_from_slice(take(input, &mut offset, 16)?)?;
                let mut envelope_hash = [0u8; 32];
                envelope_hash.copy_from_slice(take(input, &mut offset, 32)?);
                children.push(MerkleChild {
                    range_start: child_start,
                    range_end: child_end,
                    reference: ImmutableReference {
                        object_id,
                        envelope_hash,
                    },
                });
            }
            MerkleEntries::Internal(children)
        };
        let node = Self {
            level,
            range_start,
            range_end,
            entries,
        };
        node.validate()?;
        Ok(node)
    }
}

/// Bounded encrypted root descriptor plaintext.  Root authority and witness
/// CAS are intentionally outside this foundation module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveRoot {
    pub root_seq: u64,
    pub parent: Option<ParentReference>,
    pub database_epoch: DatabaseEpoch,
    pub key_epoch: KeyEpoch,
    pub owner_fencing_epoch: u64,
    pub sqlite_page_size: u32,
    pub logical_file_length: u64,
    pub user_schema_version: u32,
    pub storage_format_version: u8,
    /// Reference to a future bounded/streaming checkpoint-manifest object.
    /// This foundation intentionally cannot create a monolithic checkpoint.
    pub checkpoint_root: Option<ImmutableReference>,
    pub extent_tree_root: Option<ImmutableReference>,
    pub wal_chain_root: Option<ImmutableReference>,
}

impl ArchiveRoot {
    pub fn validate(&self) -> Result<()> {
        if self.sqlite_page_size != SQLITE_PAGE_SIZE {
            return Err(ArchiveV3Error::Malformed("SQLite page size"));
        }
        if !self
            .logical_file_length
            .is_multiple_of(u64::from(self.sqlite_page_size))
        {
            return Err(ArchiveV3Error::Malformed("logical file length"));
        }
        if self.storage_format_version != ARCHIVE_FORMAT_VERSION {
            return Err(ArchiveV3Error::Malformed("root format version"));
        }
        if self.root_seq == 0 && self.parent.is_some() {
            return Err(ArchiveV3Error::Malformed("genesis parent"));
        }
        if self.root_seq > 0 && self.parent.is_none() {
            return Err(ArchiveV3Error::Malformed("root parent"));
        }
        if self.wal_chain_root.is_some() && self.checkpoint_root.is_none() {
            return Err(ArchiveV3Error::Malformed("WAL root without checkpoint"));
        }
        if self.logical_file_length > 0
            && self.checkpoint_root.is_none()
            && self.extent_tree_root.is_none()
        {
            return Err(ArchiveV3Error::Malformed("root has no database base"));
        }
        Ok(())
    }

    /// Check the root plaintext against the context that authenticated it.
    /// This catches a malformed producer before a root can be published.
    pub fn validate_for_context(&self, context: &ObjectContext) -> Result<()> {
        self.validate()?;
        if context.role() != ObjectRole::RootV3
            || context.database_epoch() != self.database_epoch
            || context.key_epoch() != self.key_epoch
            || context.parent() != self.parent.as_ref()
            || !matches!(context.location(), LogicalLocation::Root { root_seq } if *root_seq == self.root_seq)
        {
            return Err(ArchiveV3Error::InvalidContext);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(ROOT_MAGIC);
        out.push(ARCHIVE_FORMAT_VERSION);
        push_u64(&mut out, self.root_seq);
        out.extend_from_slice(self.database_epoch.as_bytes());
        out.extend_from_slice(self.key_epoch.as_bytes());
        push_u64(&mut out, self.owner_fencing_epoch);
        push_u32(&mut out, self.sqlite_page_size);
        push_u64(&mut out, self.logical_file_length);
        push_u32(&mut out, self.user_schema_version);
        out.push(self.storage_format_version);
        encode_optional_parent(&mut out, &self.parent);
        encode_optional_reference(&mut out, &self.checkpoint_root);
        encode_optional_reference(&mut out, &self.extent_tree_root);
        encode_optional_reference(&mut out, &self.wal_chain_root);
        if out.len() > MAX_ROOT_BYTES {
            return Err(ArchiveV3Error::TooLarge("root"));
        }
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_ROOT_BYTES {
            return Err(ArchiveV3Error::TooLarge("root"));
        }
        if input.len() < 78 || &input[..8] != ROOT_MAGIC || input[8] != ARCHIVE_FORMAT_VERSION {
            return Err(ArchiveV3Error::Malformed("root header"));
        }
        let mut offset = 9;
        let root_seq = take_u64(input, &mut offset)?;
        let database_epoch = object_id_from_slice(take(input, &mut offset, 16)?)?;
        let key_epoch = object_id_from_slice(take(input, &mut offset, 16)?)?;
        let owner_fencing_epoch = take_u64(input, &mut offset)?;
        let sqlite_page_size = take_u32(input, &mut offset)?;
        let logical_file_length = take_u64(input, &mut offset)?;
        let user_schema_version = take_u32(input, &mut offset)?;
        let storage_format_version = *take(input, &mut offset, 1)?
            .first()
            .ok_or(ArchiveV3Error::Malformed("root format"))?;
        let parent = decode_optional_parent(input, &mut offset)?;
        let checkpoint_root = decode_optional_reference(input, &mut offset)?;
        let extent_tree_root = decode_optional_reference(input, &mut offset)?;
        let wal_chain_root = decode_optional_reference(input, &mut offset)?;
        if offset != input.len() {
            return Err(ArchiveV3Error::Malformed("root trailing bytes"));
        }
        let root = Self {
            root_seq,
            parent,
            database_epoch: DatabaseEpoch::from_bytes(*database_epoch.as_bytes()),
            key_epoch: KeyEpoch::from_bytes(*key_epoch.as_bytes()),
            owner_fencing_epoch,
            sqlite_page_size,
            logical_file_length,
            user_schema_version,
            storage_format_version,
            checkpoint_root,
            extent_tree_root,
            wal_chain_root,
        };
        root.validate()?;
        Ok(root)
    }
}

/// Outcome from a linearizable immutable create-if-absent call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateIfAbsent {
    Created,
    AlreadyPresentIdentical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnumerationLimit(usize);

impl EnumerationLimit {
    pub fn new(value: usize) -> Result<Self> {
        if value == 0 || value > MAX_ENUMERATION_PAGE {
            return Err(ArchiveV3Error::TooLarge("enumeration page"));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> usize {
        self.0
    }
}

/// Stable provider-neutral continuation point bound to one exact prefix.
#[derive(Clone, PartialEq, Eq)]
pub struct EnumerationCursor {
    prefix: ArchivePrefix,
    after: ObjectKey,
}

impl fmt::Debug for EnumerationCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnumerationCursor(<opaque>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumerationPage {
    pub objects: Vec<ObjectKey>,
    pub next_cursor: Option<EnumerationCursor>,
}

/// Immutable backend contract.  Production GCS/Bigtable implementations must
/// retain these exact semantics, including stable complete prefix enumeration.
pub trait ImmutableObjectBackend: Send + Sync {
    fn create_if_absent(&self, key: ObjectKey, value: CiphertextEnvelope)
        -> Result<CreateIfAbsent>;
    fn get(&self, key: &ObjectKey) -> Result<Option<CiphertextEnvelope>>;
    fn enumerate(
        &self,
        prefix: &ArchivePrefix,
        cursor: Option<&EnumerationCursor>,
        limit: EnumerationLimit,
    ) -> Result<EnumerationPage>;
    fn delete_exact(&self, key: &ObjectKey) -> Result<bool>;
}

/// Test-only-in-spirit backend implementation with the production contract's
/// retry/conflict and exact-delete semantics.  It is not a deployment backend.
#[derive(Default)]
pub struct InMemoryImmutableBackend {
    objects: Mutex<BTreeMap<ObjectKey, CiphertextEnvelope>>,
    object_ids: Mutex<BTreeMap<ObjectId, ObjectKey>>,
}

impl InMemoryImmutableBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ImmutableObjectBackend for InMemoryImmutableBackend {
    fn create_if_absent(
        &self,
        key: ObjectKey,
        value: CiphertextEnvelope,
    ) -> Result<CreateIfAbsent> {
        let mut objects = self.objects.lock().expect("backend mutex poisoned");
        match objects.get(&key) {
            Some(existing) if existing == &value => Ok(CreateIfAbsent::AlreadyPresentIdentical),
            Some(_) => Err(ArchiveV3Error::Conflict),
            None => {
                let mut object_ids = self.object_ids.lock().expect("backend mutex poisoned");
                if object_ids.contains_key(&key.object_id()) {
                    return Err(ArchiveV3Error::Conflict);
                }
                object_ids.insert(key.object_id(), key.clone());
                objects.insert(key, value);
                Ok(CreateIfAbsent::Created)
            }
        }
    }

    fn get(&self, key: &ObjectKey) -> Result<Option<CiphertextEnvelope>> {
        Ok(self
            .objects
            .lock()
            .expect("backend mutex poisoned")
            .get(key)
            .cloned())
    }

    fn enumerate(
        &self,
        prefix: &ArchivePrefix,
        cursor: Option<&EnumerationCursor>,
        limit: EnumerationLimit,
    ) -> Result<EnumerationPage> {
        if cursor.is_some_and(|cursor| cursor.prefix != *prefix) {
            return Err(ArchiveV3Error::InvalidContext);
        }
        let after = cursor.map(|cursor| &cursor.after);
        let mut objects: Vec<_> = self
            .objects
            .lock()
            .expect("backend mutex poisoned")
            .keys()
            .filter(|key| key.as_str().starts_with(prefix.as_str()))
            .filter(|key| after.is_none_or(|after| *key > after))
            .take(limit.get() + 1)
            .cloned()
            .collect();
        let next_cursor = if objects.len() > limit.get() {
            objects.truncate(limit.get());
            Some(EnumerationCursor {
                prefix: prefix.clone(),
                after: objects.last().expect("non-zero enumeration limit").clone(),
            })
        } else {
            None
        };
        Ok(EnumerationPage {
            objects,
            next_cursor,
        })
    }

    fn delete_exact(&self, key: &ObjectKey) -> Result<bool> {
        let mut objects = self.objects.lock().expect("backend mutex poisoned");
        let removed = objects.remove(key).is_some();
        // Intentionally retain the issued object ID after deletion: object IDs
        // are never reusable, so a later create cannot reintroduce a
        // fixed-nonce/subkey pair even after a delete retry.
        Ok(removed)
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn read_u16(input: &[u8]) -> Result<u16> {
    Ok(u16::from_be_bytes(take_array(input)?))
}
fn read_u32(input: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(take_array(input)?))
}
fn read_u64(input: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(take_array(input)?))
}
fn take_array<const N: usize>(input: &[u8]) -> Result<[u8; N]> {
    input
        .try_into()
        .map_err(|_| ArchiveV3Error::Malformed("integer"))
}
fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or(ArchiveV3Error::Malformed("overflow"))?;
    let slice = input
        .get(*offset..end)
        .ok_or(ArchiveV3Error::Malformed("truncated"))?;
    *offset = end;
    Ok(slice)
}
fn take_u32(input: &[u8], offset: &mut usize) -> Result<u32> {
    read_u32(take(input, offset, 4)?)
}
fn take_u64(input: &[u8], offset: &mut usize) -> Result<u64> {
    read_u64(take(input, offset, 8)?)
}
fn object_id_from_slice(input: &[u8]) -> Result<ObjectId> {
    Ok(ObjectId::from_bytes(take_array(input)?))
}

fn encode_optional_parent(out: &mut Vec<u8>, value: &Option<ParentReference>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(value.object_id.as_bytes());
            out.extend_from_slice(&value.envelope_hash);
        }
        None => out.push(0),
    }
}
fn encode_optional_reference(out: &mut Vec<u8>, value: &Option<ImmutableReference>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(value.object_id.as_bytes());
            out.extend_from_slice(&value.envelope_hash);
        }
        None => out.push(0),
    }
}
fn decode_optional_parent(input: &[u8], offset: &mut usize) -> Result<Option<ParentReference>> {
    match *take(input, offset, 1)?
        .first()
        .ok_or(ArchiveV3Error::Malformed("parent"))?
    {
        0 => Ok(None),
        1 => {
            let object_id = object_id_from_slice(take(input, offset, 16)?)?;
            let mut envelope_hash = [0u8; 32];
            envelope_hash.copy_from_slice(take(input, offset, 32)?);
            Ok(Some(ParentReference {
                object_id,
                envelope_hash,
            }))
        }
        _ => Err(ArchiveV3Error::Malformed("parent flag")),
    }
}
fn decode_optional_reference(
    input: &[u8],
    offset: &mut usize,
) -> Result<Option<ImmutableReference>> {
    match *take(input, offset, 1)?
        .first()
        .ok_or(ArchiveV3Error::Malformed("reference"))?
    {
        0 => Ok(None),
        1 => {
            let object_id = object_id_from_slice(take(input, offset, 16)?)?;
            let mut envelope_hash = [0u8; 32];
            envelope_hash.copy_from_slice(take(input, offset, 32)?);
            Ok(Some(ImmutableReference {
                object_id,
                envelope_hash,
            }))
        }
        _ => Err(ArchiveV3Error::Malformed("reference flag")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (ArchiveId, DatabaseEpoch, KeyEpoch) {
        (
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
        )
    }
    fn context(role: ObjectRole, location: LogicalLocation, object: u8) -> ObjectContext {
        let (archive, database, key) = ids();
        ObjectContext::new(
            archive,
            database,
            key,
            role,
            location,
            ObjectId::from_bytes([object; 16]),
            None,
        )
        .unwrap()
    }
    fn extent_context(object: u8) -> ObjectContext {
        context(
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 9,
                byte_len: 4096,
            },
            object,
        )
    }
    fn cipher() -> ArchiveCipher {
        ArchiveCipher::new(ArchiveDek::from_bytes([9; 32]))
    }

    fn extent_payload(byte: u8) -> Vec<u8> {
        vec![byte; SQLITE_PAGE_SIZE as usize]
    }

    fn extent_context_for(archive_byte: u8, extent_no: u64, object: u8) -> ObjectContext {
        let (_, database, key) = ids();
        ObjectContext::new(
            ArchiveId::from_bytes([archive_byte; 16]),
            database,
            key,
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no,
                byte_len: SQLITE_PAGE_SIZE,
            },
            ObjectId::from_bytes([object; 16]),
            None,
        )
        .unwrap()
    }

    #[test]
    fn envelope_round_trip_and_object_key_follow_the_canonical_namespace() {
        let context = extent_context(4);
        let cipher = cipher();
        let plaintext = extent_payload(42);
        let envelope = cipher.seal(&context, &plaintext).unwrap();
        let wire = envelope.encode();
        let decoded = CiphertextEnvelope::decode(&wire).unwrap();
        assert_eq!(cipher.open(&context, &decoded).unwrap(), plaintext);
        assert_eq!(context.object_key().as_str(), "archive/v3/01010101010101010101010101010101/extents/02020202020202020202020202020202/9/04040404040404040404040404040404.extx");
    }

    #[test]
    fn ciphertext_and_context_tampering_fail_closed() {
        let context = extent_context(4);
        let cipher = cipher();
        let mut wire = cipher.seal(&context, &extent_payload(42)).unwrap().encode();
        *wire.last_mut().unwrap() ^= 1;
        let tampered = CiphertextEnvelope::decode(&wire).unwrap();
        assert_eq!(
            cipher.open(&context, &tampered),
            Err(ArchiveV3Error::Authentication)
        );
        assert_eq!(
            CiphertextEnvelope::decode(&wire[..12]),
            Err(ArchiveV3Error::Malformed("envelope truncated"))
        );
    }

    #[test]
    fn substitutions_across_every_bound_context_component_fail() {
        let source = extent_context(4);
        let cipher = cipher();
        let envelope = cipher.seal(&source, &extent_payload(42)).unwrap();
        let (archive, database, key) = ids();
        let variants = [
            ObjectContext::new(
                ArchiveId::from_bytes([7; 16]),
                database,
                key,
                ObjectRole::ExtentV3,
                LogicalLocation::Extent {
                    extent_no: 9,
                    byte_len: 4096,
                },
                ObjectId::from_bytes([4; 16]),
                None,
            )
            .unwrap(),
            ObjectContext::new(
                archive,
                DatabaseEpoch::from_bytes([7; 16]),
                key,
                ObjectRole::ExtentV3,
                LogicalLocation::Extent {
                    extent_no: 9,
                    byte_len: 4096,
                },
                ObjectId::from_bytes([4; 16]),
                None,
            )
            .unwrap(),
            ObjectContext::new(
                archive,
                database,
                KeyEpoch::from_bytes([7; 16]),
                ObjectRole::ExtentV3,
                LogicalLocation::Extent {
                    extent_no: 9,
                    byte_len: 4096,
                },
                ObjectId::from_bytes([4; 16]),
                None,
            )
            .unwrap(),
            ObjectContext::new(
                archive,
                database,
                key,
                ObjectRole::WalSegmentV3,
                LogicalLocation::Wal {
                    root_seq: 9,
                    wal_generation: 1,
                    segment_index: 0,
                },
                ObjectId::from_bytes([4; 16]),
                None,
            )
            .unwrap(),
            ObjectContext::new(
                archive,
                database,
                key,
                ObjectRole::ExtentV3,
                LogicalLocation::Extent {
                    extent_no: 10,
                    byte_len: 4096,
                },
                ObjectId::from_bytes([4; 16]),
                None,
            )
            .unwrap(),
            ObjectContext::new(
                archive,
                database,
                key,
                ObjectRole::ExtentV3,
                LogicalLocation::Extent {
                    extent_no: 9,
                    byte_len: 4096,
                },
                ObjectId::from_bytes([5; 16]),
                None,
            )
            .unwrap(),
            ObjectContext::new(
                archive,
                database,
                key,
                ObjectRole::ExtentV3,
                LogicalLocation::Extent {
                    extent_no: 9,
                    byte_len: 4096,
                },
                ObjectId::from_bytes([4; 16]),
                Some(ParentReference {
                    object_id: ObjectId::from_bytes([8; 16]),
                    envelope_hash: [8; 32],
                }),
            )
            .unwrap(),
        ];
        for replacement in variants {
            assert_eq!(
                cipher.open(&replacement, &envelope),
                Err(ArchiveV3Error::Authentication)
            );
        }
    }

    #[test]
    fn object_context_cannot_be_sealed_twice_with_a_fixed_nonce() {
        let context = extent_context(4);
        let archive_cipher = cipher();
        archive_cipher.seal(&context, &extent_payload(1)).unwrap();
        assert_eq!(
            archive_cipher.seal(&context, &extent_payload(2)),
            Err(ArchiveV3Error::DuplicateSeal)
        );
        assert_eq!(
            cipher().seal(&extent_context(5), b"too short"),
            Err(ArchiveV3Error::InvalidContext)
        );
    }

    #[test]
    fn key_registry_is_kms_framed_context_verified_and_never_archive_encrypted() {
        let (archive, database, key_epoch) = ids();
        let registry = KeyRegistryContext::new(archive, KeyKind::Archive, key_epoch);
        let encoded =
            KeyRegistryPlaintext::encode_archive(&registry, &ArchiveDek::from_bytes([9; 32]))
                .unwrap();
        let verified = KeyRegistryPlaintext::decode_verified(encoded, &registry).unwrap();
        assert_eq!(verified.into_archive_dek().unwrap().0, [9; 32]);
        assert_eq!(
            registry
                .object_key(ObjectId::from_bytes([4; 16]))
                .as_str(),
            "archive/v3/01010101010101010101010101010101/keys/archive/03030303030303030303030303030303/04040404040404040404040404040404.keyx"
        );

        for wrong in [
            KeyRegistryContext::new(ArchiveId::from_bytes([8; 16]), KeyKind::Archive, key_epoch),
            KeyRegistryContext::new(archive, KeyKind::Media, key_epoch),
            KeyRegistryContext::new(archive, KeyKind::Archive, KeyEpoch::from_bytes([8; 16])),
        ] {
            assert!(matches!(
                KeyRegistryPlaintext::decode_verified(
                    KeyRegistryPlaintext::encode_archive(
                        &registry,
                        &ArchiveDek::from_bytes([9; 32])
                    )
                    .unwrap(),
                    &wrong
                ),
                Err(ArchiveV3Error::InvalidContext)
            ));
        }

        let archive_object_context = ObjectContext::new(
            archive,
            database,
            key_epoch,
            ObjectRole::KeyRegistryV3,
            LogicalLocation::KeyRegistry {
                key_kind: KeyKind::Archive,
            },
            ObjectId::from_bytes([4; 16]),
            None,
        )
        .unwrap();
        let encoded =
            KeyRegistryPlaintext::encode_archive(&registry, &ArchiveDek::from_bytes([9; 32]))
                .unwrap();
        assert_eq!(
            cipher().seal(&archive_object_context, &encoded),
            Err(ArchiveV3Error::InvalidContext)
        );
        assert_eq!(
            cipher().open(
                &archive_object_context,
                &CiphertextEnvelope {
                    ciphertext: vec![0; GCM_TAG_BYTES],
                }
            ),
            Err(ArchiveV3Error::InvalidContext)
        );
        let mut malformed_domain = encoded;
        malformed_domain[KEY_REGISTRY_MAGIC.len() + 3] ^= 1;
        assert!(matches!(
            KeyRegistryPlaintext::decode_verified(malformed_domain, &registry),
            Err(ArchiveV3Error::Malformed("key registry domain"))
        ));
    }

    #[test]
    fn nodes_and_roots_reject_malformed_oversized_and_inconsistent_shapes() {
        let leaf = MerkleNode {
            level: 0,
            range_start: 0,
            range_end: 8,
            entries: MerkleEntries::Leaf(vec![ExtentReference {
                extent_no: 3,
                logical_byte_len: SQLITE_PAGE_SIZE,
                revision: 7,
                reference: ImmutableReference {
                    object_id: ObjectId::from_bytes([4; 16]),
                    envelope_hash: [5; 32],
                },
            }]),
        };
        assert_eq!(MerkleNode::decode(&leaf.encode().unwrap()).unwrap(), leaf);
        let mut wrong_wire_level = leaf.encode().unwrap();
        wrong_wire_level[10] = 1;
        assert_eq!(
            MerkleNode::decode(&wrong_wire_level),
            Err(ArchiveV3Error::Malformed("leaf node level"))
        );

        let internal = MerkleNode {
            level: 1,
            range_start: 0,
            range_end: 8,
            entries: MerkleEntries::Internal(vec![MerkleChild {
                range_start: 0,
                range_end: 4,
                reference: ImmutableReference {
                    object_id: ObjectId::from_bytes([4; 16]),
                    envelope_hash: [5; 32],
                },
            }]),
        };
        assert_eq!(
            MerkleNode::decode(&internal.encode().unwrap()).unwrap(),
            internal
        );

        let overlap = MerkleNode {
            level: 1,
            range_start: 0,
            range_end: 8,
            entries: MerkleEntries::Internal(vec![
                MerkleChild {
                    range_start: 0,
                    range_end: 5,
                    reference: ImmutableReference {
                        object_id: ObjectId::from_bytes([1; 16]),
                        envelope_hash: [1; 32],
                    },
                },
                MerkleChild {
                    range_start: 4,
                    range_end: 8,
                    reference: ImmutableReference {
                        object_id: ObjectId::from_bytes([2; 16]),
                        envelope_hash: [2; 32],
                    },
                },
            ]),
        };
        assert_eq!(
            overlap.encode(),
            Err(ArchiveV3Error::Malformed("node child range"))
        );
        assert_eq!(
            MerkleNode::decode(&vec![0; MAX_NODE_BYTES + 1]),
            Err(ArchiveV3Error::TooLarge("node"))
        );
        assert_eq!(
            ExtentReference {
                extent_no: 0,
                logical_byte_len: 0,
                revision: 1,
                reference: ImmutableReference {
                    object_id: ObjectId::from_bytes([3; 16]),
                    envelope_hash: [3; 32],
                },
            }
            .validate(),
            Err(ArchiveV3Error::Malformed("extent reference"))
        );
        let wrong_level = MerkleNode {
            level: 1,
            range_start: 0,
            range_end: 1,
            entries: MerkleEntries::Leaf(vec![ExtentReference {
                extent_no: 0,
                logical_byte_len: SQLITE_PAGE_SIZE,
                revision: 1,
                reference: ImmutableReference {
                    object_id: ObjectId::from_bytes([1; 16]),
                    envelope_hash: [1; 32],
                },
            }]),
        };
        assert_eq!(
            wrong_level.encode(),
            Err(ArchiveV3Error::Malformed("leaf node level"))
        );
        let root = ArchiveRoot {
            root_seq: 1,
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes([1; 16]),
                envelope_hash: [2; 32],
            }),
            database_epoch: DatabaseEpoch::from_bytes([2; 16]),
            key_epoch: KeyEpoch::from_bytes([3; 16]),
            owner_fencing_epoch: 9,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: 8192,
            user_schema_version: 4,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([6; 16]),
                envelope_hash: [6; 32],
            }),
            extent_tree_root: None,
            wal_chain_root: None,
        };
        assert_eq!(ArchiveRoot::decode(&root.encode().unwrap()).unwrap(), root);
        let matching_context = ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            root.database_epoch,
            root.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: root.root_seq,
            },
            ObjectId::from_bytes([9; 16]),
            root.parent.clone(),
        )
        .unwrap();
        assert_eq!(root.validate_for_context(&matching_context), Ok(()));
        let substituted_parent_context = ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            root.database_epoch,
            root.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: root.root_seq,
            },
            ObjectId::from_bytes([9; 16]),
            Some(ParentReference {
                object_id: ObjectId::from_bytes([8; 16]),
                envelope_hash: [8; 32],
            }),
        )
        .unwrap();
        assert_eq!(
            root.validate_for_context(&substituted_parent_context),
            Err(ArchiveV3Error::InvalidContext)
        );
        let bad_root = ArchiveRoot {
            sqlite_page_size: 1024,
            ..root.clone()
        };
        assert_eq!(
            bad_root.encode(),
            Err(ArchiveV3Error::Malformed("SQLite page size"))
        );
        assert_eq!(
            ArchiveRoot::decode(&vec![0; MAX_ROOT_BYTES + 1]),
            Err(ArchiveV3Error::TooLarge("root"))
        );
        let wal_without_checkpoint = ArchiveRoot {
            checkpoint_root: None,
            wal_chain_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([7; 16]),
                envelope_hash: [7; 32],
            }),
            ..root
        };
        assert_eq!(
            wal_without_checkpoint.encode(),
            Err(ArchiveV3Error::Malformed("WAL root without checkpoint"))
        );
    }

    #[test]
    fn backend_is_linearizable_for_retries_prefix_isolated_and_delete_idempotent() {
        let backend = InMemoryImmutableBackend::new();
        let first = extent_context(4);
        let (archive, database, key) = ids();
        let second = ObjectContext::new(
            ArchiveId::from_bytes([6; 16]),
            database,
            key,
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 9,
                byte_len: 4096,
            },
            ObjectId::from_bytes([4; 16]),
            None,
        )
        .unwrap();
        let c = cipher();
        let first_value = c.seal(&first, &extent_payload(1)).unwrap();
        let second_value = c.seal(&second, &extent_payload(2)).unwrap();
        let first_key = first.object_key();
        assert_eq!(
            backend
                .create_if_absent(first_key.clone(), first_value.clone())
                .unwrap(),
            CreateIfAbsent::Created
        );
        assert_eq!(
            backend
                .create_if_absent(first_key.clone(), first_value)
                .unwrap(),
            CreateIfAbsent::AlreadyPresentIdentical
        );
        assert_eq!(
            backend.create_if_absent(first_key.clone(), second_value.clone()),
            Err(ArchiveV3Error::Conflict)
        );
        assert_eq!(
            backend.create_if_absent(second.object_key(), second_value.clone()),
            Err(ArchiveV3Error::Conflict),
            "a duplicate object ID must conflict even at a different canonical path"
        );
        let unique_second = ObjectContext::new(
            ArchiveId::from_bytes([6; 16]),
            database,
            key,
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: 9,
                byte_len: 4096,
            },
            ObjectId::from_bytes([7; 16]),
            None,
        )
        .unwrap();
        let unique_second_value = c.seal(&unique_second, &extent_payload(3)).unwrap();
        backend
            .create_if_absent(unique_second.object_key(), unique_second_value)
            .unwrap();

        let same_archive_second = extent_context_for(1, 9, 5);
        let same_archive_third = extent_context_for(1, 9, 6);
        backend
            .create_if_absent(
                same_archive_second.object_key(),
                c.seal(&same_archive_second, &extent_payload(4)).unwrap(),
            )
            .unwrap();
        backend
            .create_if_absent(
                same_archive_third.object_key(),
                c.seal(&same_archive_third, &extent_payload(5)).unwrap(),
            )
            .unwrap();

        let prefix = ArchivePrefix::for_archive(archive);
        let first_page = backend
            .enumerate(&prefix, None, EnumerationLimit::new(2).unwrap())
            .unwrap();
        assert_eq!(first_page.objects.len(), 2);
        let cursor = first_page.next_cursor.clone().unwrap();
        let repeated = backend
            .enumerate(
                &prefix,
                first_page.next_cursor.as_ref(),
                EnumerationLimit::new(2).unwrap(),
            )
            .unwrap();
        let second_page = backend
            .enumerate(&prefix, Some(&cursor), EnumerationLimit::new(2).unwrap())
            .unwrap();
        assert_eq!(second_page, repeated, "cursor pages must be stable");
        assert_eq!(second_page.objects.len(), 1);
        assert!(second_page.next_cursor.is_none());
        let mut enumerated = first_page.objects;
        enumerated.extend(second_page.objects);
        assert_eq!(enumerated.len(), 3);
        assert!(enumerated.contains(&first_key));

        let other_prefix = ArchivePrefix::for_archive(ArchiveId::from_bytes([6; 16]));
        assert_eq!(
            backend.enumerate(
                &other_prefix,
                Some(&cursor),
                EnumerationLimit::new(1).unwrap()
            ),
            Err(ArchiveV3Error::InvalidContext),
            "a cursor is bound to its exact archive prefix"
        );
        let isolated = backend
            .enumerate(
                &other_prefix,
                None,
                EnumerationLimit::new(MAX_ENUMERATION_PAGE).unwrap(),
            )
            .unwrap();
        assert_eq!(isolated.objects.len(), 1);
        assert_eq!(
            EnumerationLimit::new(MAX_ENUMERATION_PAGE + 1),
            Err(ArchiveV3Error::TooLarge("enumeration page"))
        );
        assert!(backend.delete_exact(&first_key).unwrap());
        assert!(!backend.delete_exact(&first_key).unwrap());
        assert_eq!(backend.get(&first_key).unwrap(), None);
    }

    #[test]
    fn opaque_id_debug_output_does_not_reveal_path_components() {
        let context = extent_context(4);
        assert_eq!(format!("{:?}", context.archive_id()), "ArchiveId(<opaque>)");
        assert_eq!(format!("{:?}", context.object_id()), "ObjectId(<opaque>)");
        assert_eq!(format!("{:?}", context.object_key()), "ObjectKey(<opaque>)");
    }
}
