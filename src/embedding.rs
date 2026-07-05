//! In-enclave text embedding — the query half of hybrid search.
//!
//! # Why the model runs inside the enclave
//!
//! Document embeddings are computed on the Mac and arrive via sync
//! (`embedding_b64` on utterances/screenshots). Query embeddings cannot: MCP
//! queries from Claude/ChatGPT reach the enclave as raw text with no Mac in
//! the loop. Embedding the query **inside** the attested TEE is the only
//! option that keeps query text within the privacy boundary — calling an
//! external embedding API would create a second plaintext egress (the Vertex
//! summarizer asterisk, doubled). Decision approved 2026-07-05.
//!
//! # Model contract — MUST match the Mac client byte-for-byte
//!
//! Both sides pin `paraphrase-multilingual-MiniLM-L12-v2` (384-dim, cosine,
//! mean pooling, L2-normalized). Cross-lingual by training (EN query → FR
//! utterance is the acceptance test). [`MODEL_ID`] names the embedding space;
//! the Mac sends it per sync batch and ingest drops vectors whose model id
//! does not match — mixing embedding spaces silently ruins KNN ranking, which
//! is worse than degrading to FTS.
//!
//! # Long-text handling (screenshots / OCR)
//!
//! OCR text is capped at [`MAX_EMBED_CHARS`] (product decision: cover the
//! ≤10k-char case; pathological text walls are out of scope), split into
//! ~[`CHUNK_CHARS`]-char whitespace-aligned chunks, each chunk embedded
//! (tokenizer truncates at [`MAX_TOKENS`]), and the chunk vectors averaged
//! then re-normalized. Queries are short and take the same path (one chunk).
//!
//! # Failure posture
//!
//! The engine is optional everywhere: if `EMBED_MODEL_DIR` is unset or the
//! model fails to load, the enclave logs and serves FTS-only — search quality
//! degrades, availability does not. Embed errors at query time likewise fall
//! back to FTS (`query_embedding: None`).

use std::path::Path;
use std::sync::Arc;

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config};
use tokenizers::Tokenizer;
use tracing::{info, warn};

use crate::error::{EnclaveError, Result};

/// Identifies the embedding space. Bump the `/N` suffix on ANY change to the
/// model weights, tokenizer, pooling, or normalization — vectors from
/// different spaces must never share a vec0 table.
pub const MODEL_ID: &str = "paraphrase-multilingual-MiniLM-L12-v2/1";

/// Embedding dimensionality (must match the vec0 schema `float[384]`).
pub const DIM: usize = 384;

/// Hard cap on input text; beyond this we embed a prefix. Product decision:
/// screens with ≤10k chars of OCR are the target; giant text walls degrade
/// gracefully to prefix + FTS coverage.
pub const MAX_EMBED_CHARS: usize = 10_000;

/// Chunk size in characters (whitespace-aligned). ~1000 chars ≈ 250–350
/// XLM-R sentencepiece tokens, inside the 256-token truncation window.
const CHUNK_CHARS: usize = 1_000;

/// Tokenizer truncation per chunk. The model supports 512 positions;
/// sentence-transformers ships this model with 128 — we use 256 as a
/// recall/latency compromise for OCR chunks.
const MAX_TOKENS: usize = 256;

/// A loaded encoder. Construction is expensive (~470 MB of f32 weights
/// mmap-loaded); embed calls are cheap (~10–50 ms CPU). Share via `Arc`.
pub struct EmbeddingEngine {
    tokenizer: Tokenizer,
    model: BertModel,
    device: Device,
}

impl EmbeddingEngine {
    /// Load model files (`config.json`, `tokenizer.json`, `model.safetensors`)
    /// from `dir`.
    pub fn load(dir: &Path) -> Result<Self> {
        let cfg_path = dir.join("config.json");
        let tok_path = dir.join("tokenizer.json");
        let weights_path = dir.join("model.safetensors");
        for p in [&cfg_path, &tok_path, &weights_path] {
            if !p.exists() {
                return Err(EnclaveError::Embedding(format!(
                    "model file missing: {}",
                    p.display()
                )));
            }
        }

        let config: Config = serde_json::from_str(&std::fs::read_to_string(&cfg_path)?)?;
        let mut tokenizer = Tokenizer::from_file(&tok_path)
            .map_err(|e| EnclaveError::Embedding(format!("tokenizer load: {e}")))?;
        tokenizer
            .with_truncation(Some(tokenizers::TruncationParams {
                max_length: MAX_TOKENS,
                ..Default::default()
            }))
            .map_err(|e| EnclaveError::Embedding(format!("tokenizer truncation: {e}")))?;

        let device = Device::Cpu;
        // SAFETY: mmap of a read-only weights file we just stat'd; candle's
        // documented loading path for safetensors.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DType::F32, &device)
                .map_err(|e| EnclaveError::Embedding(format!("weights load: {e}")))?
        };
        let model = BertModel::load(vb, &config)
            .map_err(|e| EnclaveError::Embedding(format!("model build: {e}")))?;

        info!(model = MODEL_ID, "embedding engine loaded");
        Ok(Self {
            tokenizer,
            model,
            device,
        })
    }

    /// Load from the `EMBED_MODEL_DIR` env var. Returns `None` (with a log
    /// line) when the var is unset or the load fails — callers treat a missing
    /// engine as "FTS-only mode", never as a fatal error.
    pub fn from_env() -> Option<Arc<Self>> {
        let dir = match std::env::var("EMBED_MODEL_DIR") {
            Ok(d) if !d.is_empty() => d,
            _ => {
                info!("EMBED_MODEL_DIR unset — hybrid search disabled (FTS-only)");
                return None;
            }
        };
        match Self::load(Path::new(&dir)) {
            Ok(engine) => Some(Arc::new(engine)),
            Err(e) => {
                warn!("embedding engine failed to load ({e}) — FTS-only mode");
                None
            }
        }
    }

    /// Embed arbitrary text into a unit-length 384-dim vector.
    ///
    /// Long text is chunked (see module docs); the result is the re-normalized
    /// mean of chunk embeddings. Empty/whitespace input is an error (callers
    /// should skip embedding rather than store a garbage vector).
    pub fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let text = text.trim();
        if text.is_empty() {
            return Err(EnclaveError::Embedding("empty text".into()));
        }
        let capped = cap_chars(text, MAX_EMBED_CHARS);

        let mut acc = vec![0f32; DIM];
        let mut n_chunks = 0usize;
        for chunk in chunk_text(capped, CHUNK_CHARS) {
            let v = self.embed_chunk(chunk)?;
            for (a, x) in acc.iter_mut().zip(v.iter()) {
                *a += x;
            }
            n_chunks += 1;
        }
        if n_chunks == 0 {
            return Err(EnclaveError::Embedding("no chunks".into()));
        }
        for a in acc.iter_mut() {
            *a /= n_chunks as f32;
        }
        l2_normalize(&mut acc);
        Ok(acc)
    }

    /// Embed one tokenizer-truncated chunk: encode → BERT forward →
    /// attention-mask mean pooling → L2 normalize.
    fn embed_chunk(&self, chunk: &str) -> Result<Vec<f32>> {
        let enc = self
            .tokenizer
            .encode(chunk, true)
            .map_err(|e| EnclaveError::Embedding(format!("tokenize: {e}")))?;
        let ids: Vec<u32> = enc.get_ids().to_vec();
        if ids.is_empty() {
            return Err(EnclaveError::Embedding("tokenizer produced no ids".into()));
        }
        let n = ids.len();

        let e = |e: candle_core::Error| EnclaveError::Embedding(format!("inference: {e}"));
        let input_ids = Tensor::new(ids.as_slice(), &self.device)
            .map_err(e)?
            .unsqueeze(0)
            .map_err(e)?;
        let token_type_ids = input_ids.zeros_like().map_err(e)?;
        // Single unpadded sequence → mask of ones; mean pooling over dim 1 is
        // then a plain mean.
        let hidden = self
            .model
            .forward(&input_ids, &token_type_ids, None)
            .map_err(e)?; // (1, n, 384)
        let pooled = (hidden.sum(1).map_err(e)? / (n as f64)).map_err(e)?; // (1, 384)
        let mut v: Vec<f32> = pooled.squeeze(0).map_err(e)?.to_vec1().map_err(e)?;
        l2_normalize(&mut v);
        Ok(v)
    }
}

/// Truncate to at most `max` chars on a char boundary.
fn cap_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}

/// Split into ~`chunk_chars`-char pieces, cutting at the last whitespace
/// inside each window when possible (never mid-char, never mid-word unless a
/// single word exceeds the window).
fn chunk_text(s: &str, chunk_chars: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let mut cut_byte = rest.len();
        let mut last_ws: Option<usize> = None;
        for (char_count, (bi, ch)) in rest.char_indices().enumerate() {
            if char_count == chunk_chars {
                cut_byte = bi;
                break;
            }
            if ch.is_whitespace() {
                last_ws = Some(bi);
            }
        }
        if cut_byte == rest.len() {
            out.push(rest);
            break;
        }
        // Prefer the last whitespace boundary; fall back to a hard cut.
        let cut = match last_ws {
            Some(ws) if ws > 0 => ws,
            _ => cut_byte,
        };
        let (head, tail) = rest.split_at(cut);
        if !head.trim().is_empty() {
            out.push(head);
        }
        rest = tail.trim_start();
    }
    out.retain(|c| !c.trim().is_empty());
    out
}

fn l2_normalize(v: &mut [f32]) {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure-logic tests (no model needed) ─────────────────────────────────

    #[test]
    fn cap_chars_respects_char_boundaries() {
        let s = "héllo wörld";
        assert_eq!(cap_chars(s, 5), "héllo");
        assert_eq!(cap_chars(s, 100), s);
    }

    #[test]
    fn chunk_text_splits_on_whitespace() {
        let words = vec!["word"; 100].join(" "); // 499 chars
        let chunks = chunk_text(&words, 100);
        assert!(chunks.len() >= 4, "expected several chunks");
        for c in &chunks {
            assert!(c.chars().count() <= 100);
            assert!(!c.trim().is_empty());
        }
        // No content lost (modulo the whitespace we split on).
        let rejoined: String = chunks.join(" ");
        assert_eq!(
            rejoined.split_whitespace().count(),
            words.split_whitespace().count()
        );
    }

    #[test]
    fn chunk_text_handles_unbroken_run() {
        let s = "x".repeat(2500);
        let chunks = chunk_text(&s, 1000);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 1000);
    }

    #[test]
    fn l2_normalize_unit_length() {
        let mut v = vec![3.0f32, 4.0];
        l2_normalize(&mut v);
        let norm = (v[0] * v[0] + v[1] * v[1]).sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
    }

    // ── Model-backed tests (skip when the model isn't downloaded) ──────────

    fn test_engine() -> Option<EmbeddingEngine> {
        let dir = std::env::var("EMBED_MODEL_DIR").unwrap_or_else(|_| {
            format!(
                "{}/Library/Application Support/Kioku/models/embedding/paraphrase-multilingual-MiniLM-L12-v2",
                std::env::var("HOME").unwrap_or_default()
            )
        });
        let path = std::path::PathBuf::from(&dir);
        if !path.join("model.safetensors").exists() {
            eprintln!("SKIP: embedding model not present at {dir}");
            return None;
        }
        Some(EmbeddingEngine::load(&path).expect("engine load"))
    }

    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b).map(|(x, y)| x * y).sum()
    }

    #[test]
    fn embed_returns_unit_384() {
        let Some(eng) = test_engine() else { return };
        let v = eng.embed("hello world").expect("embed");
        assert_eq!(v.len(), DIM);
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-4,
            "expected unit vector, norm={norm}"
        );
    }

    #[test]
    fn embed_is_cross_lingual() {
        let Some(eng) = test_engine() else { return };
        // EN query vs FR sentence about the same topic must be much closer
        // than an unrelated FR sentence — the core acceptance property.
        let q = eng.embed("What did I eat for breakfast?").unwrap();
        let fr_food = eng
            .embed("Je vais manger un croissant pour le petit déjeuner.")
            .unwrap();
        let fr_other = eng
            .embed("Le réacteur nucléaire produit de l'électricité.")
            .unwrap();
        let sim_food = cosine(&q, &fr_food);
        let sim_other = cosine(&q, &fr_other);
        assert!(
            sim_food > sim_other + 0.15,
            "cross-lingual recall failed: food={sim_food:.3} other={sim_other:.3}"
        );
    }

    #[test]
    fn embed_long_ocr_text_chunks() {
        let Some(eng) = test_engine() else { return };
        // Simulate a text-heavy screenshot: ~8k chars, mostly filler, with the
        // salient content buried past the first chunk.
        let filler = "menu file edit view window help ".repeat(150); // ~4.8k chars
        let ocr = format!("{filler} Fida joined the Zoom meeting about French grammar {filler}");
        let v = eng.embed(&ocr).expect("chunked embed");
        assert_eq!(v.len(), DIM);
        let q = eng.embed("who was in the meeting with me?").unwrap();
        let baseline = eng.embed(&filler).unwrap();
        assert!(
            cosine(&q, &v) > cosine(&q, &baseline),
            "salient mid-text content should move the embedding toward the query"
        );
    }

    #[test]
    fn embed_empty_is_error() {
        let Some(eng) = test_engine() else { return };
        assert!(eng.embed("   ").is_err());
    }
}
