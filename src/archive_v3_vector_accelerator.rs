#![allow(
    dead_code,
    reason = "inactive ADR-0022 vector accelerator is compiled and tested before runtime activation"
)]

//! Inactive ADR-0022 encrypted Approximate Nearest Neighbor (ANN) vector
//! accelerator.
//!
//! Per-user encrypted vector sidecar over authenticated immutable encrypted
//! extent objects. The honest contract:
//!
//! - **Fail-closed.** Authentication/AEAD failures, malformed or disconnected
//!   snapshot payloads, certification-floor violations, and internal graph
//!   integrity errors always surface as errors and never silently degrade to
//!   a table scan. The only sanctioned fallback to the exact path is a
//!   genuinely absent snapshot (no descriptor, or the backend holds no object
//!   at the descriptor's key); [`VectorSearchOutcome`] reports which path ran
//!   so callers and telemetry can observe the degradation.
//! - **Bounded size, not multi-gigabyte.** A snapshot holds at most
//!   [`MAX_ANN_NODES`] (32,768) vectors because the snapshot object context
//!   puns `ObjectRole::MerkleNodeV3` with a `LogicalLocation::MerkleNode`
//!   whose `range_end` is capped at
//!   `crate::archive_v3::MAX_DATABASE_EXTENT_SLOTS` (32,768). Larger
//!   descriptors would construct but could never load, so the cap is enforced
//!   at descriptor construction and at load. **Pre-activation blocker:** a
//!   dedicated `ObjectRole`/`LogicalLocation` variant must replace the punned
//!   Merkle role before any production activation; until then this module
//!   stays inactive and the cap stands.
//! - **Flat-graph beam search, not HNSW.** The index is a single flat
//!   neighbor list per node searched with bounded greedy beam search from the
//!   entry node (node index 0). Shared validation — run by both in-memory
//!   construction and storage load — proves every node reachable from the
//!   entry, and traversal is bounded by [`MAX_BEAM_SEARCH_VISITED`] plus a
//!   standard best-first termination criterion.
//! - **Certified recall, not asserted recall.** Snapshot builders measure
//!   recall@20 against exhaustive exact scoring ([`measure_recall_at_20`])
//!   and seal the result, in basis points, into both the descriptor and the
//!   AEAD-protected snapshot payload (which must match bit-for-bit at load).
//!   Construction and load reject certifications below
//!   [`MIN_VECTOR_RECALL_AT_20_BP`].
//! - **Snapshot as hint; live table authoritative.** Queries merge snapshot
//!   candidates with the bounded exact SQLite delta above the indexed
//!   watermark, then re-validate every snapshot-sourced hit against the live
//!   `embeddings` table: deleted rows are dropped and updated rows are
//!   re-scored with the live embedding.
//! - **Bounded exact scans.** The exact path keeps at most `limit` matches in
//!   a min-heap and visits at most [`MAX_EXACT_SCAN_ROWS`] rows before
//!   failing closed; the delta scan is bounded by
//!   [`MAX_UNINDEXED_DELTA_VECTORS`]; caller limits are clamped to
//!   [`MAX_QUERY_LIMIT`].
//! - Strict parsing (bounds before allocation, exact trailing-bytes check),
//!   hash-then-AEAD provenance order, finiteness rejection, and `total_cmp`
//!   orderings are load-bearing and preserved. Errors are content-free (no
//!   row ids, lengths, or SQLite detail in `Display`), and decoded embedding
//!   plaintext is zeroized.

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    fmt,
};

use rusqlite::{Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::archive_v3::{ArchiveId, DatabaseEpoch, ImmutableObjectBackend, ImmutableReference};
use crate::archive_v3_extent::ExtentCipher;

/// Minimum acceptable recall@20 for vector accelerator promotion, as a
/// fraction. Documentation form of [`MIN_VECTOR_RECALL_AT_20_BP`], which is
/// the enforced representation.
pub const MIN_VECTOR_RECALL_AT_20: f64 = 0.97;
/// [`MIN_VECTOR_RECALL_AT_20`] in basis points. Descriptors carry the
/// certified value in this form and construction/load enforce the floor.
pub const MIN_VECTOR_RECALL_AT_20_BP: u16 = 9_700;
/// Basis-point scale (100.00%): the maximum representable certification.
pub const RECALL_BASIS_POINTS_SCALE: u16 = 10_000;
/// The K used by build-time recall certification (the "20" in recall@20).
pub const RECALL_CERTIFICATION_K: usize = 20;
/// Maximum number of unindexed delta vectors allowed before requiring
/// background indexing. The delta scan fails closed past this bound.
pub const MAX_UNINDEXED_DELTA_VECTORS: usize = 100_000;
/// Maximum number of visited candidates during bounded greedy beam search
/// over the flat neighbor graph. This is the hard traversal bound.
pub const MAX_BEAM_SEARCH_VISITED: usize = 1_024;
/// Maximum number of vector nodes allowed in a single snapshot.
///
/// Bounded by the punned `LogicalLocation::MerkleNode` encoding used for the
/// snapshot object context: its `range_end` must not exceed
/// `crate::archive_v3::MAX_DATABASE_EXTENT_SLOTS` (32,768), so any larger
/// descriptor would construct but never load, and a zero-length range can
/// never load at all. A dedicated `ObjectRole`/`LogicalLocation` variant is a
/// documented follow-up required before any production activation (see the
/// module docs).
pub const MAX_ANN_NODES: usize = 32_768;
/// Maximum neighbors per node in the ANN graph.
pub const MAX_ANN_NEIGHBORS: usize = 64;
/// Hard row cap for the exact fallback scan: one full snapshot plus one full
/// unindexed delta. Visiting more rows fails closed instead of silently
/// degrading into an unbounded scan.
pub const MAX_EXACT_SCAN_ROWS: usize = MAX_ANN_NODES + MAX_UNINDEXED_DELTA_VECTORS;
/// Upper bound accepted for caller-provided `limit`/`k` values at every
/// public entry point.
pub const MAX_QUERY_LIMIT: usize = 512;

// The punned MerkleNode location encoding is the binding constraint on
// MAX_ANN_NODES; keep the relationship checked at compile time.
const _: () = assert!((MAX_ANN_NODES as u64) <= crate::archive_v3::MAX_DATABASE_EXTENT_SLOTS);
const _: () = assert!(MIN_VECTOR_RECALL_AT_20_BP <= RECALL_BASIS_POINTS_SCALE);

/// Content-free vector accelerator errors.
///
/// No variant carries row ids, lengths, blob contents, or SQLite error text.
/// The only payloads are `&'static str` reasons (compile-time literals) and
/// the already-content-free [`crate::archive_v3::ArchiveV3Error`].
#[derive(Debug, thiserror::Error)]
pub enum VectorError {
    #[error("vector dimension mismatch")]
    DimensionMismatch,
    #[error("non-finite float component in vector")]
    NonFiniteVectorComponent,
    #[error("unindexed delta vectors exceeded the fixed capacity limit")]
    DeltaOverflow,
    #[error("malformed embedding blob")]
    MalformedEmbeddingBlob,
    #[error("vector id out of valid range")]
    InvalidVectorId,
    #[error("ANN snapshot authentication failed")]
    AuthenticationFailed,
    #[error("ANN snapshot object absent from backend")]
    SnapshotAbsent,
    #[error("malformed ANN snapshot extent payload: {0}")]
    MalformedSnapshotExtent(&'static str),
    #[error("ANN snapshot graph is not fully reachable from its entry node")]
    SnapshotGraphDisconnected,
    #[error("ANN snapshot recall certification below the promotion floor")]
    CertificationBelowFloor,
    #[error("exact scan row limit exceeded")]
    ExactScanRowLimitExceeded,
    #[error("query limit outside the accepted range")]
    InvalidQueryLimit,
    #[error("recall measurement requires non-empty nodes, queries, and ground truth")]
    RecallSampleInvalid,
    #[error("SQLite query failed")]
    Sqlite,
    #[error("backend error: {0}")]
    Backend(#[from] crate::archive_v3::ArchiveV3Error),
}

impl From<rusqlite::Error> for VectorError {
    /// Deliberately discards the underlying rusqlite error: it can embed SQL
    /// text and user-derived values, and this module's errors are content-free.
    fn from(_: rusqlite::Error) -> Self {
        Self::Sqlite
    }
}

/// One vector search match candidate with cosine similarity score.
#[derive(Clone, Debug, PartialEq)]
pub struct VectorMatch {
    pub vector_id: u64,
    pub score: f32,
}

impl Eq for VectorMatch {}

impl Ord for VectorMatch {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.total_cmp(&other.score)
    }
}

impl PartialOrd for VectorMatch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Min-heap candidate wrapper for bounded top-K collection.
#[derive(Clone, Debug, PartialEq)]
struct MinHeapMatch(VectorMatch);

impl Eq for MinHeapMatch {}

impl Ord for MinHeapMatch {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order for min-heap behavior
        other.0.score.total_cmp(&self.0.score)
    }
}

impl PartialOrd for MinHeapMatch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Offer one candidate to a bounded min-heap keeping the `cap` best-scoring
/// matches seen so far. `cap` is validated by callers to be at least 1.
fn offer_bounded(top: &mut BinaryHeap<MinHeapMatch>, candidate: VectorMatch, cap: usize) {
    if top.len() < cap {
        top.push(MinHeapMatch(candidate));
    } else if let Some(worst) = top.peek() {
        if candidate.score > worst.0.score {
            top.pop();
            top.push(MinHeapMatch(candidate));
        }
    }
}

/// Drain a bounded min-heap into a descending-by-score match list.
fn into_sorted_matches(top: BinaryHeap<MinHeapMatch>) -> Vec<VectorMatch> {
    let mut results: Vec<VectorMatch> = top.into_iter().map(|m| m.0).collect();
    results.sort_by(|a, b| b.score.total_cmp(&a.score));
    results
}

/// Compute true cosine similarity (dot product divided by L2 norms) with
/// finite number validation.
///
/// Zero-length inputs and length mismatches are errors, never a silent `0.0`
/// score. A genuinely zero-norm vector still scores `0.0`: it carries no
/// direction, which is a data property rather than a caller contract
/// violation.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> Result<f32, VectorError> {
    if a.is_empty() || a.len() != b.len() {
        return Err(VectorError::DimensionMismatch);
    }
    let mut dot = 0.0f32;
    let mut norm_a_sq = 0.0f32;
    let mut norm_b_sq = 0.0f32;

    for (&x, &y) in a.iter().zip(b.iter()) {
        if !x.is_finite() || !y.is_finite() {
            return Err(VectorError::NonFiniteVectorComponent);
        }
        dot += x * y;
        norm_a_sq += x * x;
        norm_b_sq += y * y;
    }

    if !dot.is_finite() || !norm_a_sq.is_finite() || !norm_b_sq.is_finite() {
        return Err(VectorError::NonFiniteVectorComponent);
    }

    if norm_a_sq <= 0.0f32 || norm_b_sq <= 0.0f32 {
        return Ok(0.0f32);
    }

    let norm_prod = (norm_a_sq * norm_b_sq).sqrt();
    if norm_prod <= 0.0f32 || !norm_prod.is_finite() {
        return Ok(0.0f32);
    }

    let cos = dot / norm_prod;
    Ok(cos.clamp(-1.0f32, 1.0f32))
}

/// Reject caller limits outside `1..=`[`MAX_QUERY_LIMIT`] before any
/// allocation is sized by them.
fn validate_limit(limit: usize) -> Result<(), VectorError> {
    if limit == 0 || limit > MAX_QUERY_LIMIT {
        return Err(VectorError::InvalidQueryLimit);
    }
    Ok(())
}

/// Validate a caller query vector against the expected dimensionality and
/// reject non-finite components.
fn validate_query(query: &[f32], expected_dimensions: usize) -> Result<(), VectorError> {
    if query.is_empty() || query.len() != expected_dimensions {
        return Err(VectorError::DimensionMismatch);
    }
    for &value in query {
        if !value.is_finite() {
            return Err(VectorError::NonFiniteVectorComponent);
        }
    }
    Ok(())
}

/// Query validation when no snapshot descriptor exists to define the expected
/// dimensionality: the query must still be non-empty and finite.
fn validate_unindexed_query(query: &[f32]) -> Result<(), VectorError> {
    if query.is_empty() {
        return Err(VectorError::DimensionMismatch);
    }
    for &value in query {
        if !value.is_finite() {
            return Err(VectorError::NonFiniteVectorComponent);
        }
    }
    Ok(())
}

/// Decode a little-endian f32 embedding blob into a zeroized-on-drop buffer,
/// rejecting length mismatches and non-finite components.
fn decode_le_embedding(
    blob: &[u8],
    expected_dimensions: usize,
) -> Result<Zeroizing<Vec<f32>>, VectorError> {
    if blob.len() != expected_dimensions * 4 {
        return Err(VectorError::MalformedEmbeddingBlob);
    }
    let mut embedding = Zeroizing::new(Vec::with_capacity(expected_dimensions));
    for chunk in blob.chunks_exact(4) {
        let value = f32::from_le_bytes(chunk.try_into().unwrap());
        if !value.is_finite() {
            return Err(VectorError::NonFiniteVectorComponent);
        }
        embedding.push(value);
    }
    Ok(embedding)
}

/// Single vector node in the authenticated extent index.
///
/// The embedding is user content: it lives in a [`Zeroizing`] buffer wiped on
/// drop, and `Debug` is deliberately opaque.
#[derive(Clone)]
pub struct VectorNode {
    id: u64,
    embedding: Zeroizing<Vec<f32>>,
    neighbors: Vec<u64>,
}

impl VectorNode {
    pub(crate) fn new(
        id: u64,
        embedding: Vec<f32>,
        neighbors: Vec<u64>,
    ) -> Result<Self, VectorError> {
        if id > (i64::MAX as u64) {
            return Err(VectorError::InvalidVectorId);
        }
        if embedding.is_empty() {
            return Err(VectorError::DimensionMismatch);
        }
        for &value in &embedding {
            if !value.is_finite() {
                return Err(VectorError::NonFiniteVectorComponent);
            }
        }
        if neighbors.len() > MAX_ANN_NEIGHBORS {
            return Err(VectorError::MalformedSnapshotExtent(
                "neighbor count exceeds cap",
            ));
        }
        Ok(Self {
            id,
            embedding: Zeroizing::new(embedding),
            neighbors,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn embedding(&self) -> &[f32] {
        self.embedding.as_slice()
    }
    pub fn neighbors(&self) -> &[u64] {
        &self.neighbors
    }
}

impl fmt::Debug for VectorNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VectorNode(<opaque>)")
    }
}

/// Verified ANN snapshot facts authenticated in an ArchiveRoot.
///
/// `certified_recall_at_20_bp` is the build-time measured recall@20 in basis
/// points (`0..=`[`RECALL_BASIS_POINTS_SCALE`]). The same value is sealed
/// inside the AEAD-protected snapshot payload and must match bit-for-bit at
/// load. The promotion floor ([`MIN_VECTOR_RECALL_AT_20_BP`]) is enforced
/// when an accelerator is constructed or loaded — not here — so a low
/// measurement stays representable, and rejectable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnSnapshotDescriptor {
    ann_tree_root: ImmutableReference,
    highest_indexed_vector_id: u64,
    total_indexed_vectors: u64,
    embedding_dimensions: u32,
    certified_recall_at_20_bp: u16,
}

impl AnnSnapshotDescriptor {
    pub(crate) fn new(
        ann_tree_root: ImmutableReference,
        highest_indexed_vector_id: u64,
        total_indexed_vectors: u64,
        embedding_dimensions: u32,
        certified_recall_at_20_bp: u16,
    ) -> Result<Self, VectorError> {
        if highest_indexed_vector_id > (i64::MAX as u64) {
            return Err(VectorError::InvalidVectorId);
        }
        // Empty snapshots are never built (absence is handled by the
        // observable no-snapshot fallback), and the punned MerkleNode
        // location cannot encode a zero-length range anyway.
        if total_indexed_vectors == 0 {
            return Err(VectorError::MalformedSnapshotExtent(
                "empty snapshot descriptor",
            ));
        }
        if total_indexed_vectors > (MAX_ANN_NODES as u64) {
            return Err(VectorError::MalformedSnapshotExtent(
                "total indexed vectors exceeds max nodes cap",
            ));
        }
        if embedding_dimensions == 0 {
            return Err(VectorError::MalformedSnapshotExtent(
                "zero embedding dimensions",
            ));
        }
        if certified_recall_at_20_bp > RECALL_BASIS_POINTS_SCALE {
            return Err(VectorError::MalformedSnapshotExtent(
                "recall certification exceeds basis-point scale",
            ));
        }
        Ok(Self {
            ann_tree_root,
            highest_indexed_vector_id,
            total_indexed_vectors,
            embedding_dimensions,
            certified_recall_at_20_bp,
        })
    }

    pub fn ann_tree_root(&self) -> &ImmutableReference {
        &self.ann_tree_root
    }
    pub fn highest_indexed_vector_id(&self) -> u64 {
        self.highest_indexed_vector_id
    }
    pub fn total_indexed_vectors(&self) -> u64 {
        self.total_indexed_vectors
    }
    pub fn embedding_dimensions(&self) -> u32 {
        self.embedding_dimensions
    }
    pub fn certified_recall_at_20_bp(&self) -> u16 {
        self.certified_recall_at_20_bp
    }
}

/// Which execution path produced a [`VectorSearchOutcome`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchPath {
    /// The authenticated ANN snapshot was searched and merged with the exact
    /// SQLite delta, then re-validated against the live table.
    AnnWithDelta,
    /// No snapshot exists yet (descriptor absent, or the backend genuinely
    /// holds no object at the descriptor's key); the bounded exact scan ran.
    /// This is observable degradation, never a masked failure.
    ExactFallbackNoSnapshot,
}

/// Result of the fail-closed vector search entry point: the matches plus the
/// path that produced them, so degradation is observable to callers and
/// telemetry.
#[derive(Clone, Debug, PartialEq)]
pub struct VectorSearchOutcome {
    matches: Vec<VectorMatch>,
    path: SearchPath,
}

impl VectorSearchOutcome {
    pub fn matches(&self) -> &[VectorMatch] {
        &self.matches
    }
    pub fn path(&self) -> SearchPath {
        self.path
    }
    pub fn into_matches(self) -> Vec<VectorMatch> {
        self.matches
    }
}

/// In-memory vector accelerator merger searching ANN snapshot + unindexed
/// SQLite delta, with live-table re-validation of snapshot hits.
pub struct VectorSearchAccelerator {
    archive_id: ArchiveId,
    descriptor: AnnSnapshotDescriptor,
    snapshot_nodes: Vec<VectorNode>,
    node_index_by_id: HashMap<u64, usize>,
}

impl std::fmt::Debug for VectorSearchAccelerator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VectorSearchAccelerator(<opaque>)")
    }
}

impl VectorSearchAccelerator {
    /// Construct an accelerator from already-decoded nodes, running the same
    /// shared snapshot validation as [`Self::load_from_storage`].
    pub(crate) fn new(
        archive_id: ArchiveId,
        descriptor: AnnSnapshotDescriptor,
        snapshot_nodes: Vec<VectorNode>,
    ) -> Result<Self, VectorError> {
        let node_index_by_id = Self::validate_snapshot(&descriptor, &snapshot_nodes)?;
        Ok(Self {
            archive_id,
            descriptor,
            snapshot_nodes,
            node_index_by_id,
        })
    }

    pub fn descriptor(&self) -> &AnnSnapshotDescriptor {
        &self.descriptor
    }

    /// Shared invariant validation for BOTH in-memory construction and
    /// storage loads: certification floor, node-count caps and descriptor
    /// consistency, watermark containment, duplicate ids, per-node dimension
    /// and finiteness checks, neighbor caps and resolution, and full entry
    /// reachability. Returns the id -> index map on success.
    fn validate_snapshot(
        descriptor: &AnnSnapshotDescriptor,
        nodes: &[VectorNode],
    ) -> Result<HashMap<u64, usize>, VectorError> {
        if descriptor.certified_recall_at_20_bp < MIN_VECTOR_RECALL_AT_20_BP {
            return Err(VectorError::CertificationBelowFloor);
        }
        if nodes.is_empty() {
            return Err(VectorError::MalformedSnapshotExtent("empty snapshot graph"));
        }
        if nodes.len() > MAX_ANN_NODES {
            return Err(VectorError::MalformedSnapshotExtent(
                "node count exceeds cap",
            ));
        }
        if (nodes.len() as u64) != descriptor.total_indexed_vectors {
            return Err(VectorError::MalformedSnapshotExtent(
                "node count mismatch with descriptor",
            ));
        }

        let expected_dimensions = descriptor.embedding_dimensions as usize;
        let mut node_index_by_id = HashMap::with_capacity(nodes.len());
        for (idx, node) in nodes.iter().enumerate() {
            if node.id > (i64::MAX as u64) || node.id > descriptor.highest_indexed_vector_id {
                return Err(VectorError::InvalidVectorId);
            }
            if node.embedding().len() != expected_dimensions {
                return Err(VectorError::DimensionMismatch);
            }
            for &value in node.embedding() {
                if !value.is_finite() {
                    return Err(VectorError::NonFiniteVectorComponent);
                }
            }
            if node.neighbors.len() > MAX_ANN_NEIGHBORS {
                return Err(VectorError::MalformedSnapshotExtent(
                    "neighbor count exceeds cap",
                ));
            }
            if node_index_by_id.insert(node.id, idx).is_some() {
                return Err(VectorError::MalformedSnapshotExtent(
                    "duplicate node ID in graph",
                ));
            }
        }

        for node in nodes {
            for &neighbor_id in node.neighbors() {
                if !node_index_by_id.contains_key(&neighbor_id) {
                    return Err(VectorError::MalformedSnapshotExtent(
                        "dangling neighbor reference",
                    ));
                }
            }
        }

        // Entry reachability: BFS from node index 0 in O(V + E), with V and E
        // already bounded by the node and neighbor caps. A node the entry
        // cannot reach would be silently unsearchable, so reject the graph.
        let mut reached = vec![false; nodes.len()];
        let mut queue = VecDeque::with_capacity(nodes.len());
        reached[0] = true;
        let mut reached_count = 1usize;
        queue.push_back(0usize);
        while let Some(idx) = queue.pop_front() {
            for &neighbor_id in nodes[idx].neighbors() {
                let Some(&neighbor_idx) = node_index_by_id.get(&neighbor_id) else {
                    return Err(VectorError::InvalidVectorId);
                };
                if !reached[neighbor_idx] {
                    reached[neighbor_idx] = true;
                    reached_count += 1;
                    queue.push_back(neighbor_idx);
                }
            }
        }
        if reached_count != nodes.len() {
            return Err(VectorError::SnapshotGraphDisconnected);
        }

        Ok(node_index_by_id)
    }

    /// Load and authenticate encrypted ANN vector nodes from backend extent
    /// storage, then run the shared snapshot validation.
    ///
    /// Fail-closed contract: every authentication, decoding, topology, or
    /// certification failure surfaces as an error — callers must never react
    /// by degrading to a scan. The single non-error absence signal is
    /// [`VectorError::SnapshotAbsent`], returned only when the backend
    /// genuinely holds no object at the descriptor's key.
    pub async fn load_from_storage<C: ExtentCipher>(
        backend: &dyn ImmutableObjectBackend,
        cipher: &C,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        descriptor: AnnSnapshotDescriptor,
    ) -> Result<Self, VectorError> {
        let context = crate::archive_v3::ObjectContext::new(
            archive_id,
            database_epoch,
            cipher.key_epoch(),
            crate::archive_v3::ObjectRole::MerkleNodeV3,
            crate::archive_v3::LogicalLocation::MerkleNode {
                level: 0,
                range_start: 0,
                range_end: descriptor.total_indexed_vectors,
            },
            descriptor.ann_tree_root.object_id,
            None,
        )?;

        let envelope = backend
            .get(&context.object_key())
            .await?
            .ok_or(VectorError::SnapshotAbsent)?;

        // Provenance order is deliberate: bind the envelope hash to the
        // authenticated descriptor BEFORE any AEAD work happens.
        if envelope.hash() != descriptor.ann_tree_root.envelope_hash {
            return Err(VectorError::AuthenticationFailed);
        }

        let plaintext = Zeroizing::new(
            cipher
                .open(&context, &envelope)
                .map_err(|_| VectorError::AuthenticationFailed)?,
        );

        let mut offset = 0;
        if plaintext.len() < 10 {
            return Err(VectorError::MalformedSnapshotExtent("too short for header"));
        }

        let node_count = u32::from_be_bytes(plaintext[0..4].try_into().unwrap()) as usize;
        let dimensions = u32::from_be_bytes(plaintext[4..8].try_into().unwrap()) as usize;
        let certified_recall_at_20_bp = u16::from_be_bytes(plaintext[8..10].try_into().unwrap());
        offset += 10;

        if dimensions != descriptor.embedding_dimensions as usize {
            return Err(VectorError::DimensionMismatch);
        }

        if node_count > MAX_ANN_NODES || (node_count as u64) != descriptor.total_indexed_vectors {
            return Err(VectorError::MalformedSnapshotExtent(
                "node count mismatch or exceeds cap",
            ));
        }

        // The certification is sealed inside the AEAD payload and must match
        // the descriptor bit-for-bit; the floor itself is enforced by the
        // shared validation below.
        if certified_recall_at_20_bp != descriptor.certified_recall_at_20_bp {
            return Err(VectorError::MalformedSnapshotExtent(
                "certification mismatch with descriptor",
            ));
        }

        let mut nodes = Vec::with_capacity(node_count);
        let mut seen_ids = HashSet::with_capacity(node_count);

        for _ in 0..node_count {
            if offset + 12 > plaintext.len() {
                return Err(VectorError::MalformedSnapshotExtent(
                    "truncated node header",
                ));
            }
            let id = u64::from_be_bytes(plaintext[offset..offset + 8].try_into().unwrap());
            let neighbor_count =
                u32::from_be_bytes(plaintext[offset + 8..offset + 12].try_into().unwrap()) as usize;
            offset += 12;

            if id > (i64::MAX as u64) || id > descriptor.highest_indexed_vector_id {
                return Err(VectorError::InvalidVectorId);
            }
            if !seen_ids.insert(id) {
                return Err(VectorError::MalformedSnapshotExtent("duplicate node ID"));
            }
            if neighbor_count > MAX_ANN_NEIGHBORS {
                return Err(VectorError::MalformedSnapshotExtent(
                    "neighbor count exceeds cap",
                ));
            }

            let vec_bytes = dimensions * 4;
            if offset + vec_bytes > plaintext.len() {
                return Err(VectorError::MalformedSnapshotExtent("truncated embedding"));
            }

            let mut embedding = Zeroizing::new(Vec::with_capacity(dimensions));
            for chunk in plaintext[offset..offset + vec_bytes].chunks_exact(4) {
                let val = f32::from_be_bytes(chunk.try_into().unwrap());
                if !val.is_finite() {
                    return Err(VectorError::NonFiniteVectorComponent);
                }
                embedding.push(val);
            }
            offset += vec_bytes;

            let neighbors_bytes = neighbor_count * 8;
            if offset + neighbors_bytes > plaintext.len() {
                return Err(VectorError::MalformedSnapshotExtent("truncated neighbors"));
            }

            let mut neighbors = Vec::with_capacity(neighbor_count);
            for chunk in plaintext[offset..offset + neighbors_bytes].chunks_exact(8) {
                let n_id = u64::from_be_bytes(chunk.try_into().unwrap());
                neighbors.push(n_id);
            }
            offset += neighbors_bytes;

            nodes.push(VectorNode {
                id,
                embedding,
                neighbors,
            });
        }

        // Exact payload length check (no trailing unparsed garbage bytes)
        if offset != plaintext.len() {
            return Err(VectorError::MalformedSnapshotExtent(
                "trailing garbage bytes in extent payload",
            ));
        }

        // Shared validation covers neighbor resolution, connectivity, per-node
        // dimensions, finiteness, and the certification floor.
        Self::new(archive_id, descriptor, nodes)
    }

    /// Bounded greedy beam search over the flat neighbor graph (not HNSW; see
    /// the module docs). `k` must lie in `1..=`[`MAX_QUERY_LIMIT`].
    pub fn search_snapshot(
        &self,
        query: &[f32],
        k: usize,
    ) -> Result<Vec<VectorMatch>, VectorError> {
        validate_limit(k)?;
        validate_query(query, self.descriptor.embedding_dimensions as usize)?;
        beam_search_graph(&self.snapshot_nodes, &self.node_index_by_id, query, k)
    }

    /// Query the unindexed delta vectors from SQLite (`id` strictly above the
    /// snapshot watermark) and compute exact scores from the live rows.
    ///
    /// Fails closed if the delta exceeds [`MAX_UNINDEXED_DELTA_VECTORS`] or
    /// any row is malformed or non-finite. Decoded row plaintext is zeroized.
    pub fn search_sqlite_delta(
        &self,
        conn: &Connection,
        query: &[f32],
    ) -> Result<Vec<VectorMatch>, VectorError> {
        let expected_dimensions = self.descriptor.embedding_dimensions as usize;
        validate_query(query, expected_dimensions)?;

        let watermark = self.descriptor.highest_indexed_vector_id;
        if watermark > (i64::MAX as u64) {
            return Err(VectorError::InvalidVectorId);
        }

        let mut stmt = conn.prepare(
            "SELECT id, embedding FROM embeddings WHERE id > ? ORDER BY id ASC LIMIT ?;",
        )?;

        let mut matches = Vec::new();
        let rows = stmt.query_map(
            rusqlite::params![watermark as i64, (MAX_UNINDEXED_DELTA_VECTORS + 1) as i64],
            |row| {
                let id: i64 = row.get(0)?;
                let blob: Vec<u8> = row.get(1)?;
                Ok((id, Zeroizing::new(blob)))
            },
        )?;

        let mut count = 0usize;
        for item in rows {
            count += 1;
            if count > MAX_UNINDEXED_DELTA_VECTORS {
                return Err(VectorError::DeltaOverflow);
            }

            let (id_i64, blob) = item?;
            if id_i64 < 0 {
                return Err(VectorError::InvalidVectorId);
            }
            let embedding = decode_le_embedding(blob.as_slice(), expected_dimensions)?;
            let score = cosine_similarity(query, embedding.as_slice())?;
            matches.push(VectorMatch {
                vector_id: id_i64 as u64,
                score,
            });
        }

        Ok(matches)
    }

    /// Memory-bounded, row-capped exact scan: keeps at most `limit` matches
    /// in a min-heap and fails closed past [`MAX_EXACT_SCAN_ROWS`] rows.
    pub fn exact_sqlite_scan(
        &self,
        conn: &Connection,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorMatch>, VectorError> {
        validate_limit(limit)?;
        validate_query(query, self.descriptor.embedding_dimensions as usize)?;
        exact_scan_rows(conn, query, limit)
    }

    /// Combined search: bounded beam search over the authenticated snapshot
    /// graph merged with the exact SQLite delta, then re-validated against
    /// the live table.
    ///
    /// Fail-closed: every snapshot, delta, or integrity error propagates —
    /// there is no fallback here (see [`search_vectors_fail_closed`] for the
    /// only sanctioned absence fallback).
    ///
    /// The snapshot is an index hint only; the live `embeddings` table is
    /// authoritative for both membership and content. Snapshot-sourced hits
    /// are re-checked row by row (bounded by `limit`): deleted rows are
    /// dropped and updated rows are re-scored with the live embedding, so the
    /// result may hold fewer than `limit` matches when hints are stale.
    pub fn search_ann_with_delta(
        &self,
        conn: &Connection,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorMatch>, VectorError> {
        validate_limit(limit)?;
        validate_query(query, self.descriptor.embedding_dimensions as usize)?;

        let ann_matches =
            beam_search_graph(&self.snapshot_nodes, &self.node_index_by_id, query, limit)?;
        let delta_matches = self.search_sqlite_delta(conn, query)?;
        let merged = merge_results(ann_matches, delta_matches, limit);
        self.revalidate_snapshot_hits(conn, query, merged)
    }

    /// Live-table re-validation of snapshot-sourced candidates (ids at or
    /// below the watermark): membership and content are decided by SQLite,
    /// never by the snapshot. Bounded by the merged candidate count, which is
    /// itself bounded by the validated `limit`.
    fn revalidate_snapshot_hits(
        &self,
        conn: &Connection,
        query: &[f32],
        merged: Vec<VectorMatch>,
    ) -> Result<Vec<VectorMatch>, VectorError> {
        let watermark = self.descriptor.highest_indexed_vector_id;
        let expected_dimensions = self.descriptor.embedding_dimensions as usize;
        let mut stmt = conn.prepare("SELECT embedding FROM embeddings WHERE id = ?;")?;

        let mut live = Vec::with_capacity(merged.len());
        for candidate in merged {
            if candidate.vector_id > watermark {
                // Delta-sourced: scored from the live table in this query.
                live.push(candidate);
                continue;
            }
            let row: Option<Vec<u8>> = stmt
                .query_row(rusqlite::params![candidate.vector_id as i64], |row| {
                    row.get(0)
                })
                .optional()?;
            let Some(blob) = row else {
                // Deleted since the snapshot was built: never resurface it.
                continue;
            };
            let blob = Zeroizing::new(blob);
            let embedding = decode_le_embedding(blob.as_slice(), expected_dimensions)?;
            // The live value wins: recompute the score even when unchanged.
            let score = cosine_similarity(query, embedding.as_slice())?;
            live.push(VectorMatch {
                vector_id: candidate.vector_id,
                score,
            });
        }

        live.sort_by(|a, b| b.score.total_cmp(&a.score));
        Ok(live)
    }

    /// Recall@K of approximate results against exact ground truth.
    ///
    /// The denominator is `min(k, deduplicated ground-truth ids)`: duplicate
    /// ids never inflate recall, and a ground-truth set smaller than `k` is
    /// scored against its own size instead of being padded. An empty ground
    /// truth is a measurement error, never a vacuously perfect score.
    pub fn calculate_recall(
        approximate: &[VectorMatch],
        ground_truth: &[VectorMatch],
        k: usize,
    ) -> Result<f64, VectorError> {
        validate_limit(k)?;
        if ground_truth.is_empty() {
            return Err(VectorError::RecallSampleInvalid);
        }

        let mut top_truth = HashSet::new();
        for truth in ground_truth {
            top_truth.insert(truth.vector_id);
            if top_truth.len() == k {
                break;
            }
        }
        let mut top_approx = HashSet::new();
        for approx in approximate {
            top_approx.insert(approx.vector_id);
            if top_approx.len() == k {
                break;
            }
        }

        let hits = top_approx.intersection(&top_truth).count();
        Ok((hits as f64) / (top_truth.len() as f64))
    }
}

/// Bounded greedy beam search over the flat neighbor graph.
///
/// This is NOT HNSW: every node carries a single flat neighbor list and there
/// is no layered entry hierarchy. The entry point is node index 0, which the
/// shared snapshot validation proves can reach every node, making the choice
/// arbitrary but safe. Termination is the standard best-first criterion: once
/// `top_k` holds `k` results and the best remaining candidate scores strictly
/// below the current k-th best, no expansion is attempted (a candidate tied
/// with the k-th best is still expanded so score plateaus do not strand
/// hill-climbing). [`MAX_BEAM_SEARCH_VISITED`] remains the hard bound.
///
/// Unresolvable node or neighbor ids are internal integrity errors and fail
/// closed; they never silently skip work or trigger a fallback.
fn beam_search_graph(
    nodes: &[VectorNode],
    node_index_by_id: &HashMap<u64, usize>,
    query: &[f32],
    k: usize,
) -> Result<Vec<VectorMatch>, VectorError> {
    let Some(entry) = nodes.first() else {
        return Err(VectorError::MalformedSnapshotExtent("empty snapshot graph"));
    };

    let mut visited = HashSet::with_capacity(MAX_BEAM_SEARCH_VISITED);
    let mut candidates: BinaryHeap<VectorMatch> = BinaryHeap::new();
    let mut top_k: BinaryHeap<MinHeapMatch> = BinaryHeap::with_capacity(k);

    let entry_score = cosine_similarity(query, entry.embedding())?;
    visited.insert(entry.id);
    candidates.push(VectorMatch {
        vector_id: entry.id,
        score: entry_score,
    });
    top_k.push(MinHeapMatch(VectorMatch {
        vector_id: entry.id,
        score: entry_score,
    }));

    while let Some(current) = candidates.pop() {
        if visited.len() >= MAX_BEAM_SEARCH_VISITED {
            break;
        }
        if top_k.len() >= k {
            if let Some(worst) = top_k.peek() {
                if current.score < worst.0.score {
                    break;
                }
            }
        }

        let node_idx = *node_index_by_id
            .get(&current.vector_id)
            .ok_or(VectorError::InvalidVectorId)?;
        let node = &nodes[node_idx];
        for &neighbor_id in node.neighbors() {
            if visited.insert(neighbor_id) {
                let neighbor_idx = *node_index_by_id
                    .get(&neighbor_id)
                    .ok_or(VectorError::InvalidVectorId)?;
                let neighbor = &nodes[neighbor_idx];
                let score = cosine_similarity(query, neighbor.embedding())?;
                let candidate = VectorMatch {
                    vector_id: neighbor_id,
                    score,
                };
                candidates.push(candidate.clone());
                offer_bounded(&mut top_k, candidate, k);
            }
        }
    }

    Ok(into_sorted_matches(top_k))
}

/// Merge ANN-snapshot and delta candidates with set-based deduplication;
/// delta candidates win because they were scored from live rows. Ids are
/// disjoint by construction (delta ids lie strictly above the watermark,
/// snapshot ids at or below it), so the deduplication is defensive only.
fn merge_results(
    ann_candidates: Vec<VectorMatch>,
    delta_candidates: Vec<VectorMatch>,
    limit: usize,
) -> Vec<VectorMatch> {
    let mut seen_ids = HashSet::new();
    let mut combined = Vec::with_capacity(ann_candidates.len() + delta_candidates.len());

    // Delta candidates take precedence (newest/updated state)
    for cand in delta_candidates {
        if seen_ids.insert(cand.vector_id) {
            combined.push(cand);
        }
    }

    // Fill with snapshot candidates if not seen in delta
    for cand in ann_candidates {
        if seen_ids.insert(cand.vector_id) {
            combined.push(cand);
        }
    }

    // Sort descending by similarity score
    combined.sort_by(|a, b| b.score.total_cmp(&a.score));
    combined.truncate(limit);
    combined
}

/// Memory-bounded, row-capped exact scan over the live embeddings table.
///
/// Keeps at most `limit` candidates in a min-heap; visiting more than
/// [`MAX_EXACT_SCAN_ROWS`] rows fails closed with
/// [`VectorError::ExactScanRowLimitExceeded`] instead of silently running an
/// unbounded scan. Callers validate `query` and `limit` first. Decoded row
/// plaintext is zeroized.
fn exact_scan_rows(
    conn: &Connection,
    query: &[f32],
    limit: usize,
) -> Result<Vec<VectorMatch>, VectorError> {
    let expected_dimensions = query.len();
    let mut stmt = conn.prepare("SELECT id, embedding FROM embeddings ORDER BY id ASC LIMIT ?;")?;
    let mut top: BinaryHeap<MinHeapMatch> = BinaryHeap::with_capacity(limit);

    let rows = stmt.query_map(rusqlite::params![(MAX_EXACT_SCAN_ROWS + 1) as i64], |row| {
        let id: i64 = row.get(0)?;
        let blob: Vec<u8> = row.get(1)?;
        Ok((id, Zeroizing::new(blob)))
    })?;

    let mut row_count = 0usize;
    for item in rows {
        row_count += 1;
        if row_count > MAX_EXACT_SCAN_ROWS {
            return Err(VectorError::ExactScanRowLimitExceeded);
        }

        let (id_i64, blob) = item?;
        if id_i64 < 0 {
            return Err(VectorError::InvalidVectorId);
        }
        let embedding = decode_le_embedding(blob.as_slice(), expected_dimensions)?;
        let score = cosine_similarity(query, embedding.as_slice())?;
        offer_bounded(
            &mut top,
            VectorMatch {
                vector_id: id_i64 as u64,
                score,
            },
            limit,
        );
    }

    Ok(into_sorted_matches(top))
}

/// Build-time recall certification: measure recall@20 of the bounded beam
/// search against exhaustive exact scoring over `nodes`.
///
/// For every sample query the exact top-20 (full scan over all nodes) is
/// compared with the beam-search top-20; per-query recall uses the
/// `min(k, deduplicated ground truth)` denominator of
/// [`VectorSearchAccelerator::calculate_recall`]. The average across queries
/// is returned in basis points, rounded DOWN so a certification never
/// overstates measured recall.
///
/// Deliberately performs no connectivity or certification-floor checks: a
/// broken graph must remain measurable so it certifies low and is then
/// rejected at descriptor validation or load time.
pub(crate) fn measure_recall_at_20(
    nodes: &[VectorNode],
    sample_queries: &[Vec<f32>],
) -> Result<u16, VectorError> {
    if nodes.is_empty() || sample_queries.is_empty() {
        return Err(VectorError::RecallSampleInvalid);
    }
    if nodes.len() > MAX_ANN_NODES {
        return Err(VectorError::MalformedSnapshotExtent(
            "node count exceeds cap",
        ));
    }
    let dimensions = nodes[0].embedding().len();
    if dimensions == 0 {
        return Err(VectorError::DimensionMismatch);
    }

    let mut node_index_by_id = HashMap::with_capacity(nodes.len());
    for (idx, node) in nodes.iter().enumerate() {
        if node.embedding().len() != dimensions {
            return Err(VectorError::DimensionMismatch);
        }
        if node_index_by_id.insert(node.id, idx).is_some() {
            return Err(VectorError::MalformedSnapshotExtent(
                "duplicate node ID in graph",
            ));
        }
    }

    let mut recall_sum = 0.0f64;
    for query in sample_queries {
        validate_query(query, dimensions)?;

        let mut exact_top: BinaryHeap<MinHeapMatch> =
            BinaryHeap::with_capacity(RECALL_CERTIFICATION_K);
        for node in nodes {
            let score = cosine_similarity(query, node.embedding())?;
            offer_bounded(
                &mut exact_top,
                VectorMatch {
                    vector_id: node.id,
                    score,
                },
                RECALL_CERTIFICATION_K,
            );
        }
        let ground_truth = into_sorted_matches(exact_top);
        let approximate =
            beam_search_graph(nodes, &node_index_by_id, query, RECALL_CERTIFICATION_K)?;
        recall_sum += VectorSearchAccelerator::calculate_recall(
            &approximate,
            &ground_truth,
            RECALL_CERTIFICATION_K,
        )?;
    }

    let average = recall_sum / (sample_queries.len() as f64);
    let basis_points = (average * f64::from(RECALL_BASIS_POINTS_SCALE)).floor();
    Ok(basis_points.clamp(0.0, f64::from(RECALL_BASIS_POINTS_SCALE)) as u16)
}

/// Fail-closed vector search entry point (replaces the removed fail-open
/// `search_vectors_with_resilient_fallback`).
///
/// Contract:
/// - AEAD/authentication failures, malformed or disconnected snapshot
///   payloads, certification-floor violations, and internal graph integrity
///   errors are tamper signals: the error is returned and no scan ever runs
///   in their place.
/// - The only "no accelerator yet" cases are `descriptor == None` and a
///   backend object that is genuinely absent (`get` returned `None`). Those
///   run the memory-bounded, row-capped exact scan, and the outcome's
///   [`SearchPath::ExactFallbackNoSnapshot`] makes the degraded path
///   observable to callers and telemetry.
#[allow(clippy::too_many_arguments)]
pub async fn search_vectors_fail_closed<C: ExtentCipher>(
    conn: &Connection,
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    descriptor: Option<AnnSnapshotDescriptor>,
    query: &[f32],
    limit: usize,
) -> Result<VectorSearchOutcome, VectorError> {
    validate_limit(limit)?;

    let Some(descriptor) = descriptor else {
        // No snapshot has ever been published; the live table defines both
        // membership and dimensionality.
        validate_unindexed_query(query)?;
        let matches = exact_scan_rows(conn, query, limit)?;
        return Ok(VectorSearchOutcome {
            matches,
            path: SearchPath::ExactFallbackNoSnapshot,
        });
    };

    validate_query(query, descriptor.embedding_dimensions as usize)?;

    match VectorSearchAccelerator::load_from_storage(
        backend,
        cipher,
        archive_id,
        database_epoch,
        descriptor,
    )
    .await
    {
        Ok(accelerator) => {
            let matches = accelerator.search_ann_with_delta(conn, query, limit)?;
            Ok(VectorSearchOutcome {
                matches,
                path: SearchPath::AnnWithDelta,
            })
        }
        Err(VectorError::SnapshotAbsent) => {
            // The descriptor exists but no object was ever published at its
            // key: the one sanctioned degradation, observable in the path.
            let matches = exact_scan_rows(conn, query, limit)?;
            Ok(VectorSearchOutcome {
                matches,
                path: SearchPath::ExactFallbackNoSnapshot,
            })
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{
        ArchiveCipher, ArchiveDek, CiphertextEnvelope, InMemoryImmutableBackend, KeyEpoch,
        LogicalLocation, ObjectContext, ObjectId, ObjectRole,
    };

    struct TestCipher {
        archive: ArchiveId,
        epoch: KeyEpoch,
        cipher: ArchiveCipher,
    }

    impl TestCipher {
        fn new(archive: ArchiveId) -> Self {
            Self {
                archive,
                epoch: KeyEpoch::random(),
                cipher: ArchiveCipher::new(ArchiveDek::generate()),
            }
        }
    }

    impl ExtentCipher for TestCipher {
        fn archive_id(&self) -> ArchiveId {
            self.archive
        }
        fn key_epoch(&self) -> KeyEpoch {
            self.epoch
        }
        fn seal(
            &self,
            context: &ObjectContext,
            plaintext: &[u8],
        ) -> crate::archive_v3::Result<CiphertextEnvelope> {
            self.cipher.seal(context, plaintext)
        }
        fn open(
            &self,
            context: &ObjectContext,
            envelope: &CiphertextEnvelope,
        ) -> crate::archive_v3::Result<Vec<u8>> {
            self.cipher.open(context, envelope)
        }
    }

    fn unit(angle_degrees: f32) -> Vec<f32> {
        let radians = angle_degrees.to_radians();
        vec![radians.cos(), radians.sin()]
    }

    fn le_blob(embedding: &[f32]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(embedding.len() * 4);
        for value in embedding {
            blob.extend_from_slice(&value.to_le_bytes());
        }
        blob
    }

    fn embeddings_table() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE embeddings (id INTEGER PRIMARY KEY, embedding BLOB NOT NULL);",
            [],
        )
        .unwrap();
        conn
    }

    fn plain_descriptor(
        watermark: u64,
        total: u64,
        dimensions: u32,
        certified_bp: u16,
    ) -> AnnSnapshotDescriptor {
        AnnSnapshotDescriptor::new(
            ImmutableReference {
                object_id: ObjectId::random(),
                envelope_hash: [0x55; 32],
            },
            watermark,
            total,
            dimensions,
            certified_bp,
        )
        .unwrap()
    }

    fn single_node_accelerator(watermark: u64) -> VectorSearchAccelerator {
        let nodes = vec![VectorNode::new(0, unit(0.0), Vec::new()).unwrap()];
        VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(watermark, 1, 2, RECALL_BASIS_POINTS_SCALE),
            nodes,
        )
        .unwrap()
    }

    fn ring_nodes() -> Vec<VectorNode> {
        vec![
            VectorNode::new(1, unit(0.0), vec![2, 4]).unwrap(),
            VectorNode::new(2, unit(30.0), vec![1, 3]).unwrap(),
            VectorNode::new(3, unit(60.0), vec![2, 4]).unwrap(),
            VectorNode::new(4, unit(90.0), vec![3, 1]).unwrap(),
        ]
    }

    fn island_nodes() -> Vec<VectorNode> {
        vec![
            VectorNode::new(1, unit(0.0), vec![2]).unwrap(),
            VectorNode::new(2, unit(30.0), vec![1]).unwrap(),
            VectorNode::new(3, unit(60.0), vec![4]).unwrap(),
            VectorNode::new(4, unit(90.0), vec![3]).unwrap(),
        ]
    }

    fn encode_snapshot_payload(
        nodes: &[VectorNode],
        dimensions: u32,
        certified_bp: u16,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(nodes.len() as u32).to_be_bytes());
        out.extend_from_slice(&dimensions.to_be_bytes());
        out.extend_from_slice(&certified_bp.to_be_bytes());
        for node in nodes {
            out.extend_from_slice(&node.id().to_be_bytes());
            out.extend_from_slice(&(node.neighbors().len() as u32).to_be_bytes());
            for &value in node.embedding() {
                out.extend_from_slice(&value.to_be_bytes());
            }
            for &neighbor in node.neighbors() {
                out.extend_from_slice(&neighbor.to_be_bytes());
            }
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    async fn seal_snapshot_with(
        backend: &InMemoryImmutableBackend,
        cipher: &TestCipher,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        nodes: &[VectorNode],
        watermark: u64,
        dimensions: u32,
        payload_certified_bp: u16,
        descriptor_certified_bp: u16,
        trailing: &[u8],
    ) -> AnnSnapshotDescriptor {
        let object_id = ObjectId::random();
        let context = ObjectContext::new(
            archive_id,
            database_epoch,
            cipher.key_epoch(),
            ObjectRole::MerkleNodeV3,
            LogicalLocation::MerkleNode {
                level: 0,
                range_start: 0,
                range_end: nodes.len() as u64,
            },
            object_id,
            None,
        )
        .unwrap();
        let mut payload = encode_snapshot_payload(nodes, dimensions, payload_certified_bp);
        payload.extend_from_slice(trailing);
        let envelope = cipher.seal(&context, &payload).unwrap();
        let envelope_hash = envelope.hash();
        backend
            .create_if_absent(context.object_key(), envelope)
            .await
            .unwrap();
        AnnSnapshotDescriptor::new(
            ImmutableReference {
                object_id,
                envelope_hash,
            },
            watermark,
            nodes.len() as u64,
            dimensions,
            descriptor_certified_bp,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn seal_snapshot(
        backend: &InMemoryImmutableBackend,
        cipher: &TestCipher,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        nodes: &[VectorNode],
        watermark: u64,
        dimensions: u32,
        certified_bp: u16,
    ) -> AnnSnapshotDescriptor {
        seal_snapshot_with(
            backend,
            cipher,
            archive_id,
            database_epoch,
            nodes,
            watermark,
            dimensions,
            certified_bp,
            certified_bp,
            &[],
        )
        .await
    }

    #[test]
    fn beam_search_hill_climbs_and_terminates_with_exact_top_k() {
        // Chain 10 - 20 - 30 - 40 with similarity to the query improving
        // toward node 40, plus a low-similarity spur 10 - 50 - 60 whose head
        // scores strictly below any top-k entry.
        let nodes = vec![
            VectorNode::new(10, unit(90.0), vec![20, 50]).unwrap(),
            VectorNode::new(20, unit(60.0), vec![10, 30]).unwrap(),
            VectorNode::new(30, unit(30.0), vec![20, 40]).unwrap(),
            VectorNode::new(40, unit(0.0), vec![30]).unwrap(),
            VectorNode::new(50, unit(180.0), vec![10, 60]).unwrap(),
            VectorNode::new(60, unit(5.0), vec![50]).unwrap(),
        ];
        let accelerator = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(1_000, 6, 2, RECALL_BASIS_POINTS_SCALE),
            nodes,
        )
        .unwrap();
        let query = unit(0.0);

        // k = 1 hill-climbs through the improving chain to the true best node
        // (candidates tied with the current best are still expanded).
        let top_1 = accelerator.search_snapshot(&query, 1).unwrap();
        assert_eq!(top_1.len(), 1);
        assert_eq!(top_1[0].vector_id, 40);

        // k = 2: the -1.0-similarity spur head is strictly below the k-th
        // best, so traversal terminates without exploring behind it, yet the
        // returned top-k for the explored region is exact.
        let top_2 = accelerator.search_snapshot(&query, 2).unwrap();
        let ids: Vec<u64> = top_2.iter().map(|m| m.vector_id).collect();
        assert_eq!(ids, vec![40, 30]);
    }

    #[test]
    fn shared_validation_rejects_disconnected_and_previously_skipped_invariants() {
        // Two islands; the entry node (index 0) cannot reach ids 3 and 4.
        let err = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(100, 4, 2, RECALL_BASIS_POINTS_SCALE),
            island_nodes(),
        )
        .unwrap_err();
        assert!(matches!(err, VectorError::SnapshotGraphDisconnected));

        // Duplicate node ids.
        let dup = vec![
            VectorNode::new(1, unit(0.0), Vec::new()).unwrap(),
            VectorNode::new(1, unit(10.0), Vec::new()).unwrap(),
        ];
        let err = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(100, 2, 2, RECALL_BASIS_POINTS_SCALE),
            dup,
        )
        .unwrap_err();
        assert!(matches!(err, VectorError::MalformedSnapshotExtent(_)));

        // Node id above the descriptor watermark.
        let above = vec![VectorNode::new(101, unit(0.0), Vec::new()).unwrap()];
        let err = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(100, 1, 2, RECALL_BASIS_POINTS_SCALE),
            above,
        )
        .unwrap_err();
        assert!(matches!(err, VectorError::InvalidVectorId));

        // Per-node dimension mismatch against the descriptor.
        let wrong_dim = vec![VectorNode::new(1, unit(0.0), Vec::new()).unwrap()];
        let err = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(100, 1, 3, RECALL_BASIS_POINTS_SCALE),
            wrong_dim,
        )
        .unwrap_err();
        assert!(matches!(err, VectorError::DimensionMismatch));

        // Node count must match the descriptor exactly.
        let short = vec![VectorNode::new(1, unit(0.0), Vec::new()).unwrap()];
        let err = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(100, 3, 2, RECALL_BASIS_POINTS_SCALE),
            short,
        )
        .unwrap_err();
        assert!(matches!(err, VectorError::MalformedSnapshotExtent(_)));

        // Dangling neighbor reference.
        let dangling = vec![VectorNode::new(1, unit(0.0), vec![9]).unwrap()];
        let err = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(100, 1, 2, RECALL_BASIS_POINTS_SCALE),
            dangling,
        )
        .unwrap_err();
        assert!(matches!(err, VectorError::MalformedSnapshotExtent(_)));

        // Certification below the floor is rejected at construction.
        let low = vec![VectorNode::new(1, unit(0.0), Vec::new()).unwrap()];
        let err = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(100, 1, 2, MIN_VECTOR_RECALL_AT_20_BP - 1),
            low,
        )
        .unwrap_err();
        assert!(matches!(err, VectorError::CertificationBelowFloor));

        // Neighbor list overflow is rejected at node construction.
        let too_many: Vec<u64> = (0..=(MAX_ANN_NEIGHBORS as u64)).collect();
        let err = VectorNode::new(1, unit(0.0), too_many).unwrap_err();
        assert!(matches!(err, VectorError::MalformedSnapshotExtent(_)));
    }

    #[test]
    fn descriptor_enforces_structural_and_certification_caps() {
        let root = || ImmutableReference {
            object_id: ObjectId::random(),
            envelope_hash: [0x11; 32],
        };

        // Empty snapshots are unrepresentable: the punned location cannot
        // encode a zero-length range, so 0 could never load.
        assert!(matches!(
            AnnSnapshotDescriptor::new(root(), 100, 0, 4, RECALL_BASIS_POINTS_SCALE),
            Err(VectorError::MalformedSnapshotExtent(_))
        ));
        // The cap itself is representable...
        assert!(AnnSnapshotDescriptor::new(
            root(),
            100,
            MAX_ANN_NODES as u64,
            4,
            RECALL_BASIS_POINTS_SCALE
        )
        .is_ok());
        // ...and one past it is not (under the old 250k cap, 32,769..=250,000
        // constructed but could never load).
        assert!(matches!(
            AnnSnapshotDescriptor::new(
                root(),
                100,
                (MAX_ANN_NODES as u64) + 1,
                4,
                RECALL_BASIS_POINTS_SCALE
            ),
            Err(VectorError::MalformedSnapshotExtent(_))
        ));
        assert!(matches!(
            AnnSnapshotDescriptor::new(root(), 100, 1, 0, RECALL_BASIS_POINTS_SCALE),
            Err(VectorError::MalformedSnapshotExtent(_))
        ));
        assert!(matches!(
            AnnSnapshotDescriptor::new(root(), 100, 1, 4, RECALL_BASIS_POINTS_SCALE + 1),
            Err(VectorError::MalformedSnapshotExtent(_))
        ));
        assert!(matches!(
            AnnSnapshotDescriptor::new(root(), (i64::MAX as u64) + 1, 1, 4, 10_000),
            Err(VectorError::InvalidVectorId)
        ));
        // Low certifications stay constructible so load can reject them.
        assert!(AnnSnapshotDescriptor::new(root(), 100, 1, 4, 0).is_ok());
    }

    #[test]
    fn recall_measurement_certifies_connected_graph_and_flags_broken_graph() {
        // Fully connected 8-node graph: beam search reaches every node, so
        // measured recall@20 is exact.
        let mut nodes = Vec::new();
        for i in 0..8u64 {
            let neighbors: Vec<u64> = (0..8).filter(|&j| j != i).collect();
            nodes.push(VectorNode::new(i, unit((i as f32) * 40.0), neighbors).unwrap());
        }
        let queries: Vec<Vec<f32>> = (0..4).map(|i| unit((i as f32) * 33.0 + 5.0)).collect();

        let certified = measure_recall_at_20(&nodes, &queries).unwrap();
        assert_eq!(certified, RECALL_BASIS_POINTS_SCALE);
        assert!(certified >= MIN_VECTOR_RECALL_AT_20_BP);
        let descriptor = plain_descriptor(100, 8, 2, certified);
        assert!(
            VectorSearchAccelerator::new(ArchiveId::random(), descriptor, nodes.clone()).is_ok()
        );

        // Break the graph: strip every neighbor list. Beam search then only
        // reaches the entry node and the measurement must come out low.
        let broken: Vec<VectorNode> = nodes
            .iter()
            .map(|n| VectorNode::new(n.id(), n.embedding().to_vec(), Vec::new()).unwrap())
            .collect();
        let low = measure_recall_at_20(&broken, &queries).unwrap();
        assert!(low < MIN_VECTOR_RECALL_AT_20_BP);

        // Degenerate inputs are measurement errors, not scores.
        assert!(matches!(
            measure_recall_at_20(&[], &queries),
            Err(VectorError::RecallSampleInvalid)
        ));
        assert!(matches!(
            measure_recall_at_20(&broken, &[]),
            Err(VectorError::RecallSampleInvalid)
        ));
    }

    #[test]
    fn calculate_recall_rejects_empty_truth_and_uses_min_denominator() {
        let m = |id: u64| VectorMatch {
            vector_id: id,
            score: 0.5,
        };

        assert!(matches!(
            VectorSearchAccelerator::calculate_recall(&[m(1)], &[], 5),
            Err(VectorError::RecallSampleInvalid)
        ));
        assert!(matches!(
            VectorSearchAccelerator::calculate_recall(&[m(1)], &[m(1)], 0),
            Err(VectorError::InvalidQueryLimit)
        ));

        // Denominator is min(k, deduplicated truth): 3 unique truth ids with
        // k = 5, two of them recovered -> 2/3, never 2/5 or a vacuous 1.0.
        let approximate = [m(1), m(2), m(9)];
        let ground_truth = [m(1), m(1), m(2), m(3)];
        let recall =
            VectorSearchAccelerator::calculate_recall(&approximate, &ground_truth, 5).unwrap();
        assert!((recall - 2.0 / 3.0).abs() < 1e-9);

        // k caps both sides consistently.
        let recall =
            VectorSearchAccelerator::calculate_recall(&approximate, &ground_truth, 1).unwrap();
        assert!((recall - 1.0).abs() < 1e-9);
    }

    #[test]
    fn snapshot_hints_defer_to_live_table_membership_and_content() {
        let conn = embeddings_table();
        // Live truth: id 10 was UPDATED since indexing (now 80 degrees), id
        // 20 was DELETED, id 30 is unchanged, id 150 is post-watermark delta.
        conn.execute(
            "INSERT INTO embeddings (id, embedding) VALUES (10, ?);",
            [&le_blob(&unit(80.0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO embeddings (id, embedding) VALUES (30, ?);",
            [&le_blob(&unit(20.0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO embeddings (id, embedding) VALUES (150, ?);",
            [&le_blob(&unit(0.0))],
        )
        .unwrap();

        let nodes = vec![
            // Stale snapshot claim: a perfect match for the query.
            VectorNode::new(10, unit(0.0), vec![20]).unwrap(),
            VectorNode::new(20, unit(10.0), vec![10, 30]).unwrap(),
            VectorNode::new(30, unit(20.0), vec![20]).unwrap(),
        ];
        let accelerator = VectorSearchAccelerator::new(
            ArchiveId::random(),
            plain_descriptor(100, 3, 2, RECALL_BASIS_POINTS_SCALE),
            nodes,
        )
        .unwrap();

        let query = unit(0.0);
        let matches = accelerator
            .search_ann_with_delta(&conn, &query, 10)
            .unwrap();
        let ids: Vec<u64> = matches.iter().map(|m| m.vector_id).collect();

        // Deleted id 20 does not resurface; the updated id 10 is re-scored
        // with its live embedding and drops behind id 30 accordingly.
        assert_eq!(ids, vec![150, 30, 10]);
        let restored = matches.iter().find(|m| m.vector_id == 10).unwrap();
        let live_score = cosine_similarity(&query, &unit(80.0)).unwrap();
        assert!((restored.score - live_score).abs() < 1e-6);
    }

    #[test]
    fn exact_scan_is_row_capped_and_limits_are_validated() {
        let accelerator = single_node_accelerator(0);
        let conn = embeddings_table();
        let query = unit(0.0);

        // Limits are clamped at every public entry before any allocation.
        assert!(matches!(
            accelerator.exact_sqlite_scan(&conn, &query, 0),
            Err(VectorError::InvalidQueryLimit)
        ));
        assert!(matches!(
            accelerator.exact_sqlite_scan(&conn, &query, MAX_QUERY_LIMIT + 1),
            Err(VectorError::InvalidQueryLimit)
        ));
        assert!(matches!(
            accelerator.search_snapshot(&query, 0),
            Err(VectorError::InvalidQueryLimit)
        ));
        assert!(matches!(
            accelerator.search_ann_with_delta(&conn, &query, MAX_QUERY_LIMIT + 1),
            Err(VectorError::InvalidQueryLimit)
        ));

        // Exactly MAX_EXACT_SCAN_ROWS rows is scannable; one more fails
        // closed instead of silently degrading.
        let blob = le_blob(&unit(0.0));
        conn.execute(
            &format!(
                "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt \
                 WHERE x < {MAX_EXACT_SCAN_ROWS}) \
                 INSERT INTO embeddings (id, embedding) SELECT x, ?1 FROM cnt;"
            ),
            [&blob],
        )
        .unwrap();
        assert_eq!(
            accelerator
                .exact_sqlite_scan(&conn, &query, 3)
                .unwrap()
                .len(),
            3
        );

        conn.execute(
            "INSERT INTO embeddings (id, embedding) VALUES (?1, ?2);",
            rusqlite::params![(MAX_EXACT_SCAN_ROWS + 1) as i64, &blob],
        )
        .unwrap();
        assert!(matches!(
            accelerator.exact_sqlite_scan(&conn, &query, 3),
            Err(VectorError::ExactScanRowLimitExceeded)
        ));

        // The delta cap also fails closed (watermark 0 makes every row delta).
        assert!(matches!(
            accelerator.search_sqlite_delta(&conn, &query),
            Err(VectorError::DeltaOverflow)
        ));
    }

    #[test]
    fn errors_are_content_free_and_debug_is_opaque() {
        // A rusqlite failure (missing table) collapses to the unit Sqlite
        // variant with no SQL or schema detail in its display.
        let bare = Connection::open_in_memory().unwrap();
        let accelerator = single_node_accelerator(0);
        let err = accelerator
            .exact_sqlite_scan(&bare, &unit(0.0), 5)
            .unwrap_err();
        assert!(matches!(err, VectorError::Sqlite));
        let display = err.to_string();
        assert!(!display.contains("embeddings"));
        assert!(!display.contains("table"));

        assert_eq!(
            VectorError::DimensionMismatch.to_string(),
            "vector dimension mismatch"
        );
        assert_eq!(
            VectorError::InvalidVectorId.to_string(),
            "vector id out of valid range"
        );
        assert_eq!(
            VectorError::MalformedEmbeddingBlob.to_string(),
            "malformed embedding blob"
        );
        assert_eq!(
            VectorError::DeltaOverflow.to_string(),
            "unindexed delta vectors exceeded the fixed capacity limit"
        );

        // VectorNode Debug never renders embedding contents.
        let node = VectorNode::new(7, unit(0.0), Vec::new()).unwrap();
        assert_eq!(format!("{node:?}"), "VectorNode(<opaque>)");
    }

    #[test]
    fn cosine_similarity_and_query_validation_fail_closed() {
        assert!(matches!(
            cosine_similarity(&[1.0, 0.0], &[1.0]),
            Err(VectorError::DimensionMismatch)
        ));
        assert!(matches!(
            cosine_similarity(&[], &[]),
            Err(VectorError::DimensionMismatch)
        ));
        assert!(matches!(
            cosine_similarity(&[1.0, f32::NAN], &[1.0, 0.0]),
            Err(VectorError::NonFiniteVectorComponent)
        ));
        let cos = cosine_similarity(&[3.0, 4.0], &[6.0, 8.0]).unwrap();
        assert!((cos - 1.0).abs() < 1e-5);

        let accelerator = single_node_accelerator(0);
        let conn = embeddings_table();
        assert!(matches!(
            accelerator.search_snapshot(&[1.0, 0.0, 0.0], 5),
            Err(VectorError::DimensionMismatch)
        ));
        assert!(matches!(
            accelerator.search_snapshot(&[1.0, f32::NAN], 5),
            Err(VectorError::NonFiniteVectorComponent)
        ));
        assert!(matches!(
            accelerator.search_sqlite_delta(&conn, &[1.0]),
            Err(VectorError::DimensionMismatch)
        ));
        assert!(matches!(
            accelerator.search_ann_with_delta(&conn, &[1.0], 5),
            Err(VectorError::DimensionMismatch)
        ));
    }

    #[tokio::test]
    async fn load_from_storage_roundtrips_certified_snapshot() {
        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let backend = InMemoryImmutableBackend::new();
        let cipher = TestCipher::new(archive_id);

        let nodes = ring_nodes();
        let queries: Vec<Vec<f32>> = vec![unit(10.0), unit(50.0), unit(80.0)];
        let certified = measure_recall_at_20(&nodes, &queries).unwrap();
        assert!(certified >= MIN_VECTOR_RECALL_AT_20_BP);

        let descriptor = seal_snapshot(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            &nodes,
            100,
            2,
            certified,
        )
        .await;

        let accelerator = VectorSearchAccelerator::load_from_storage(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            descriptor,
        )
        .await
        .unwrap();
        assert_eq!(
            accelerator.descriptor().certified_recall_at_20_bp(),
            certified
        );

        let matches = accelerator.search_snapshot(&unit(0.0), 2).unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].vector_id, 1);
        assert_eq!(matches[1].vector_id, 2);
    }

    #[tokio::test]
    async fn load_from_storage_rejects_low_or_mismatched_certification_and_garbage() {
        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let backend = InMemoryImmutableBackend::new();
        let cipher = TestCipher::new(archive_id);
        let nodes = ring_nodes();

        // A connected graph whose descriptor honestly carries a
        // measured-too-low certification is rejected at load.
        let low = seal_snapshot(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            &nodes,
            100,
            2,
            MIN_VECTOR_RECALL_AT_20_BP - 1,
        )
        .await;
        let err = VectorSearchAccelerator::load_from_storage(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            low,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VectorError::CertificationBelowFloor));

        // Payload and descriptor certifications must match bit-for-bit.
        let mismatched = seal_snapshot_with(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            &nodes,
            100,
            2,
            RECALL_BASIS_POINTS_SCALE,
            9_800,
            &[],
        )
        .await;
        let err = VectorSearchAccelerator::load_from_storage(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            mismatched,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VectorError::MalformedSnapshotExtent(_)));

        // Strict trailing-bytes check stays load-bearing.
        let trailing = seal_snapshot_with(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            &nodes,
            100,
            2,
            RECALL_BASIS_POINTS_SCALE,
            RECALL_BASIS_POINTS_SCALE,
            &[0u8],
        )
        .await;
        let err = VectorSearchAccelerator::load_from_storage(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            trailing,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VectorError::MalformedSnapshotExtent(_)));
    }

    #[tokio::test]
    async fn load_rejects_disconnected_graph_claiming_perfect_recall() {
        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let backend = InMemoryImmutableBackend::new();
        let cipher = TestCipher::new(archive_id);

        // The certification claim is perfect, but the connectivity check
        // still rejects the graph.
        let descriptor = seal_snapshot(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            &island_nodes(),
            100,
            2,
            RECALL_BASIS_POINTS_SCALE,
        )
        .await;
        let err = VectorSearchAccelerator::load_from_storage(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            descriptor,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VectorError::SnapshotGraphDisconnected));
    }

    #[tokio::test]
    async fn search_vectors_fail_closed_reports_path_and_rejects_tamper() {
        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let backend = InMemoryImmutableBackend::new();
        let cipher = TestCipher::new(archive_id);

        let conn = embeddings_table();
        conn.execute(
            "INSERT INTO embeddings (id, embedding) VALUES (5, ?);",
            [&le_blob(&unit(20.0))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO embeddings (id, embedding) VALUES (150, ?);",
            [&le_blob(&unit(0.0))],
        )
        .unwrap();
        let query = unit(0.0);

        // (1) No descriptor: the exact path runs and says so.
        let outcome = search_vectors_fail_closed(
            &conn,
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            None,
            &query,
            10,
        )
        .await
        .unwrap();
        assert_eq!(outcome.path(), SearchPath::ExactFallbackNoSnapshot);
        assert_eq!(outcome.matches().len(), 2);
        assert_eq!(outcome.matches()[0].vector_id, 150);

        // (2) Descriptor present but the object was never published:
        // genuinely absent, so the observable exact fallback runs.
        let absent = plain_descriptor(100, 1, 2, RECALL_BASIS_POINTS_SCALE);
        let outcome = search_vectors_fail_closed(
            &conn,
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            Some(absent),
            &query,
            10,
        )
        .await
        .unwrap();
        assert_eq!(outcome.path(), SearchPath::ExactFallbackNoSnapshot);

        // Publish a real snapshot: ids 5 and 6, watermark 100.
        let nodes = vec![
            VectorNode::new(5, unit(20.0), vec![6]).unwrap(),
            VectorNode::new(6, unit(45.0), vec![5]).unwrap(),
        ];
        let descriptor = seal_snapshot(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            &nodes,
            100,
            2,
            RECALL_BASIS_POINTS_SCALE,
        )
        .await;

        // (3) Corrupted descriptor hash: a hard authentication error, never a
        // silent exact scan.
        let tampered = AnnSnapshotDescriptor::new(
            ImmutableReference {
                object_id: descriptor.ann_tree_root().object_id,
                envelope_hash: [0xAA; 32],
            },
            100,
            2,
            2,
            RECALL_BASIS_POINTS_SCALE,
        )
        .unwrap();
        let err = search_vectors_fail_closed(
            &conn,
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            Some(tampered),
            &query,
            10,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VectorError::AuthenticationFailed));

        // (4) Healthy snapshot: ANN + delta path. The snapshot hit id 6 is
        // gone from the live table and is dropped; id 5 survives; delta id
        // 150 is scored from the live row.
        let outcome = search_vectors_fail_closed(
            &conn,
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            Some(descriptor),
            &query,
            10,
        )
        .await
        .unwrap();
        assert_eq!(outcome.path(), SearchPath::AnnWithDelta);
        let ids: Vec<u64> = outcome.matches().iter().map(|m| m.vector_id).collect();
        assert_eq!(ids, vec![150, 5]);
    }
}
