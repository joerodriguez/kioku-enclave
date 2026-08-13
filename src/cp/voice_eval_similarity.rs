//! Content-free ADR-0016 voice-similarity measurement.
//!
//! The private corpus operator needs an objective way to choose the hardest
//! different-speaker pair and to inspect within-speaker stability without
//! publishing licensed audio, voice embeddings, names, or transcripts. This
//! module verifies an opaque, hash-bound private specification and the pinned
//! production WeSpeaker model, runs the same production preprocessing and
//! inference path, and emits only integer pairwise cosine measurements plus
//! source/model bindings.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

use super::media::AudioTurn;
use super::voice_memory::{self, VoiceEngine};
use super::voice_quality::{self, SampleDecision};

const MAX_SPEC_RECORDINGS: usize = 512;
const MAX_SPEC_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_MEDIA_BYTES: u64 = 64 * 1_024 * 1_024;
const MAX_MODEL_BYTES: u64 = 128 * 1_024 * 1_024;
const MIN_RECORDING_MS: u64 = 3_000;
const MAX_RECORDING_MS: u64 = 30_000;
const MAX_TOTAL_RECORDING_MS: u64 = 2 * 60 * 60 * 1_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimilaritySpec {
    schema_version: u32,
    corpus_id: String,
    derivation_receipt_sha256: String,
    recordings: Vec<SimilarityRecording>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SimilarityRecording {
    id: String,
    speaker_id: String,
    media_file: String,
    media_sha256: String,
    duration_ms: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairMeasurement {
    left_recording_id: String,
    right_recording_id: String,
    same_speaker: bool,
    cosine_millionths: i32,
}

#[derive(Debug, Serialize)]
struct SimilaritySummary {
    recording_count: usize,
    speaker_count: usize,
    same_speaker_pair_count: usize,
    different_speaker_pair_count: usize,
    hardest_genuine: PairMeasurement,
    hardest_impostor: PairMeasurement,
}

#[derive(Debug, Serialize)]
struct SimilarityReport {
    schema_version: u32,
    corpus_id: String,
    specification_sha256: String,
    derivation_receipt_sha256: String,
    embedding_space: &'static str,
    model_sha256: &'static str,
    recordings: Vec<SimilarityRecording>,
    pairs: Vec<PairMeasurement>,
    summary: SimilaritySummary,
}

fn invalid(message: impl Into<String>) -> EnclaveError {
    EnclaveError::InvalidRequest(message.into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hashed_id(value: &str, prefix: &str) -> bool {
    let Some(digest) = value.strip_prefix(prefix) else {
        return false;
    };
    (16..=64).contains(&digest.len())
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_spec(raw: &str) -> Result<SimilaritySpec> {
    if raw.is_empty() || raw.len() > MAX_SPEC_BYTES {
        return Err(invalid(
            "voice-similarity specification exceeds its byte bound",
        ));
    }
    let spec: SimilaritySpec = serde_json::from_str(raw)?;
    if spec.schema_version != 1
        || !valid_hashed_id(&spec.corpus_id, "corpus-")
        || !valid_sha256(&spec.derivation_receipt_sha256)
        || spec.recordings.len() < 4
        || spec.recordings.len() > MAX_SPEC_RECORDINGS
    {
        return Err(invalid(
            "invalid voice-similarity specification identity or bounds",
        ));
    }
    let mut recording_ids = HashSet::new();
    let mut media_files = HashSet::new();
    let mut media_hashes = HashSet::new();
    let mut speakers = HashMap::<&str, usize>::new();
    let mut total_duration_ms = 0_u64;
    for recording in &spec.recordings {
        let expected_file = format!("{}.wav", recording.id);
        if !valid_hashed_id(&recording.id, "recording-")
            || !valid_hashed_id(&recording.speaker_id, "speaker-")
            || recording.media_file != expected_file
            || !valid_sha256(&recording.media_sha256)
            || !(MIN_RECORDING_MS..=MAX_RECORDING_MS).contains(&recording.duration_ms)
            || !recording_ids.insert(recording.id.as_str())
            || !media_files.insert(recording.media_file.as_str())
            || !media_hashes.insert(recording.media_sha256.as_str())
        {
            return Err(invalid(
                "voice-similarity recordings must be unique, opaque, hash-bound canonical WAVs",
            ));
        }
        total_duration_ms = total_duration_ms
            .checked_add(recording.duration_ms)
            .filter(|total| *total <= MAX_TOTAL_RECORDING_MS)
            .ok_or_else(|| invalid("voice-similarity recording duration exceeds its bound"))?;
        *speakers.entry(recording.speaker_id.as_str()).or_default() += 1;
    }
    if speakers.len() < 2 || speakers.values().any(|count| *count < 2) {
        return Err(invalid(
            "voice-similarity measurement requires at least two recordings for each of at least two speakers",
        ));
    }
    Ok(spec)
}

fn canonical_private_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid("voice-similarity media directory must be absolute"));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| invalid(format!("cannot resolve voice-similarity media: {error}")))?;
    if !canonical.is_dir() {
        return Err(invalid("voice-similarity media path must be a directory"));
    }
    let repository = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).map_err(|error| {
        invalid(format!(
            "cannot resolve voice-similarity source checkout: {error}"
        ))
    })?;
    if canonical.starts_with(repository) {
        return Err(invalid(
            "voice-similarity media must remain outside the public repository",
        ));
    }
    Ok(canonical)
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("cannot inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(invalid(format!(
            "{label} must be a bounded nonempty regular file, not a symlink"
        )));
    }
    let mut file =
        File::open(path).map_err(|error| invalid(format!("cannot open {label}: {error}")))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| invalid(format!("cannot read {label}: {error}")))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(invalid(format!("{label} changed while it was read")));
    }
    Ok(bytes)
}

fn hash_bounded_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<String> {
    let bytes = read_bounded_regular_file(path, max_bytes, label)?;
    Ok(sha256_hex(&bytes))
}

fn score_millionths(left: &[f32], right: &[f32]) -> i32 {
    (voice_quality::cosine(left, right).clamp(-1.0, 1.0) * 1_000_000.0).round() as i32
}

fn score_from_vectors(raw: &str, vectors: &BTreeMap<String, Vec<f32>>) -> Result<String> {
    let mut spec = parse_spec(raw)?;
    spec.recordings
        .sort_by(|left, right| left.id.cmp(&right.id));
    if vectors.len() != spec.recordings.len() {
        return Err(invalid(
            "voice-similarity vectors do not match the reviewed recordings",
        ));
    }
    for recording in &spec.recordings {
        let vector = vectors
            .get(&recording.id)
            .ok_or_else(|| invalid("voice-similarity vector is missing"))?;
        let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
        if vector.len() != 256
            || vector.iter().any(|value| !value.is_finite())
            || !(0.999..=1.001).contains(&norm)
        {
            return Err(invalid(
                "voice-similarity vectors must be normalized production embeddings",
            ));
        }
    }
    if vectors
        .keys()
        .any(|id| !spec.recordings.iter().any(|recording| &recording.id == id))
    {
        return Err(invalid(
            "voice-similarity vectors include an unknown recording",
        ));
    }
    let mut pairs = Vec::new();
    for left_index in 0..spec.recordings.len() {
        for right_index in left_index + 1..spec.recordings.len() {
            let left = &spec.recordings[left_index];
            let right = &spec.recordings[right_index];
            pairs.push(PairMeasurement {
                left_recording_id: left.id.clone(),
                right_recording_id: right.id.clone(),
                same_speaker: left.speaker_id == right.speaker_id,
                cosine_millionths: score_millionths(&vectors[&left.id], &vectors[&right.id]),
            });
        }
    }
    let hardest_genuine = pairs
        .iter()
        .filter(|pair| pair.same_speaker)
        .min_by_key(|pair| pair.cosine_millionths)
        .cloned()
        .ok_or_else(|| invalid("voice-similarity report has no genuine pair"))?;
    let hardest_impostor = pairs
        .iter()
        .filter(|pair| !pair.same_speaker)
        .max_by_key(|pair| pair.cosine_millionths)
        .cloned()
        .ok_or_else(|| invalid("voice-similarity report has no impostor pair"))?;
    let same_speaker_pair_count = pairs.iter().filter(|pair| pair.same_speaker).count();
    let different_speaker_pair_count = pairs.len() - same_speaker_pair_count;
    let speaker_count = spec
        .recordings
        .iter()
        .map(|recording| recording.speaker_id.as_str())
        .collect::<HashSet<_>>()
        .len();
    let report = SimilarityReport {
        schema_version: 1,
        corpus_id: spec.corpus_id,
        specification_sha256: sha256_hex(raw.as_bytes()),
        derivation_receipt_sha256: spec.derivation_receipt_sha256,
        embedding_space: voice_memory::EMBEDDING_SPACE,
        model_sha256: voice_memory::MODEL_SHA256,
        recordings: spec.recordings,
        pairs,
        summary: SimilaritySummary {
            recording_count: vectors.len(),
            speaker_count,
            same_speaker_pair_count,
            different_speaker_pair_count,
            hardest_genuine,
            hardest_impostor,
        },
    };
    let mut output = serde_json::to_string_pretty(&report)?;
    output.push('\n');
    Ok(output)
}

pub fn measure_similarity(
    spec_raw: &str,
    media_directory: &Path,
    model_path: &Path,
) -> Result<String> {
    let spec = parse_spec(spec_raw)?;
    let media_directory = canonical_private_directory(media_directory)?;
    if hash_bounded_regular_file(model_path, MAX_MODEL_BYTES, "voice model")?
        != voice_memory::MODEL_SHA256
    {
        return Err(invalid(
            "voice model SHA-256 does not match the pinned production model",
        ));
    }
    let engine = VoiceEngine::load(model_path)?;
    let mut vectors = BTreeMap::new();
    for recording in &spec.recordings {
        let media_path = media_directory.join(&recording.media_file);
        let media = read_bounded_regular_file(&media_path, MAX_MEDIA_BYTES, "voice media")?;
        if sha256_hex(&media) != recording.media_sha256 {
            return Err(invalid(
                "voice media SHA-256 does not match the private specification",
            ));
        }
        let samples = voice_memory::decode_mono_16khz(&media, "audio/wav")?;
        let expected_samples = usize::try_from(recording.duration_ms)
            .ok()
            .and_then(|duration| duration.checked_mul(16))
            .ok_or_else(|| invalid("voice recording duration exceeds its bound"))?;
        if samples.len() != expected_samples
            || voice_quality::diagnose(&samples, false, &[]).decision != SampleDecision::Enroll
        {
            return Err(invalid(
                "voice-similarity media must exactly match its duration and pass enrollment quality",
            ));
        }
        let turn = AudioTurn {
            turn_id: recording.id.clone(),
            start_ms: 0,
            end_ms: recording.duration_ms as i64,
            speaker_local_id: recording.speaker_id.clone(),
            text: String::new(),
            language: None,
            speaker_name: None,
            speaker_name_confidence: None,
            speaker_name_evidence: None,
            person_facts: Vec::new(),
            overlap: false,
            quality_flags: Vec::new(),
        };
        let mut embedded = engine.embed_turns(&media, "audio/wav", &[turn])?;
        let vector = embedded
            .pop()
            .and_then(|turn| turn.embedding)
            .ok_or_else(|| invalid("voice model did not produce an enrollment embedding"))?;
        vectors.insert(recording.id.clone(), vector);
    }
    score_from_vectors(spec_raw, &vectors)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{json, Value};

    use super::*;

    fn hash(value: &str) -> String {
        sha256_hex(value.as_bytes())
    }

    fn recording(index: usize, speaker: usize) -> Value {
        let id = format!("recording-{index:016x}");
        json!({
            "id": id,
            "speaker_id": format!("speaker-{speaker:016x}"),
            "media_file": format!("recording-{index:016x}.wav"),
            "media_sha256": hash(&format!("media-{index}")),
            "duration_ms": 4000
        })
    }

    fn spec() -> Value {
        json!({
            "schema_version": 1,
            "corpus_id": "corpus-0000000000000001",
            "derivation_receipt_sha256": hash("receipt"),
            "recordings": [
                recording(1, 1),
                recording(2, 1),
                recording(3, 2),
                recording(4, 2)
            ]
        })
    }

    fn vector(first: f32, second: f32) -> Vec<f32> {
        let mut vector = vec![0.0; 256];
        vector[0] = first;
        vector[1] = second;
        voice_quality::normalize(&mut vector).unwrap();
        vector
    }

    fn vectors() -> BTreeMap<String, Vec<f32>> {
        BTreeMap::from([
            ("recording-0000000000000001".into(), vector(1.0, 0.0)),
            ("recording-0000000000000002".into(), vector(0.99, 0.1)),
            ("recording-0000000000000003".into(), vector(0.8, 0.6)),
            ("recording-0000000000000004".into(), vector(0.75, 0.66)),
        ])
    }

    fn assert_no_prohibited_key(value: &Value) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    assert!(!matches!(
                        key.as_str(),
                        "embedding" | "embeddings" | "name" | "transcript" | "email" | "url"
                    ));
                    assert_no_prohibited_key(value);
                }
            }
            Value::Array(values) => values.iter().for_each(assert_no_prohibited_key),
            _ => {}
        }
    }

    #[test]
    fn emits_only_opaque_pairwise_similarity() {
        let raw = serde_json::to_string(&spec()).unwrap();
        let result = score_from_vectors(&raw, &vectors()).unwrap();
        let report: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(report["pairs"].as_array().unwrap().len(), 6);
        assert_eq!(report["summary"]["same_speaker_pair_count"], 2);
        assert_eq!(report["summary"]["different_speaker_pair_count"], 4);
        assert_eq!(report["summary"]["hardest_impostor"]["same_speaker"], false);
        assert_eq!(report["model_sha256"], voice_memory::MODEL_SHA256);
        assert_no_prohibited_key(&report);
    }

    #[test]
    fn scoring_is_input_order_independent_and_raw_spec_bound() {
        let original = serde_json::to_string(&spec()).unwrap();
        let mut reordered = spec();
        reordered["recordings"].as_array_mut().unwrap().reverse();
        let reordered = serde_json::to_string(&reordered).unwrap();
        let original_report: Value =
            serde_json::from_str(&score_from_vectors(&original, &vectors()).unwrap()).unwrap();
        let reordered_report: Value =
            serde_json::from_str(&score_from_vectors(&reordered, &vectors()).unwrap()).unwrap();
        assert_eq!(original_report["pairs"], reordered_report["pairs"]);
        assert_ne!(
            original_report["specification_sha256"],
            reordered_report["specification_sha256"]
        );
    }

    #[test]
    fn rejects_unknown_or_content_bearing_fields() {
        for (field, value) in [
            ("name", json!("A Person")),
            ("transcript", json!("private words")),
            ("embedding", json!([0.1, 0.2])),
        ] {
            let mut invalid = spec();
            invalid["recordings"][0][field] = value;
            let raw = serde_json::to_string(&invalid).unwrap();
            assert!(score_from_vectors(&raw, &vectors()).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_media_or_underrepresented_speakers() {
        let mut duplicate = spec();
        duplicate["recordings"][1]["media_sha256"] =
            duplicate["recordings"][0]["media_sha256"].clone();
        assert!(parse_spec(&serde_json::to_string(&duplicate).unwrap()).is_err());

        let mut singleton = spec();
        singleton["recordings"][3]["speaker_id"] = json!("speaker-0000000000000003");
        assert!(parse_spec(&serde_json::to_string(&singleton).unwrap()).is_err());
    }

    #[test]
    fn rejects_traversal_and_malformed_hashes() {
        let mut traversal = spec();
        traversal["recordings"][0]["media_file"] = json!("../private.wav");
        assert!(parse_spec(&serde_json::to_string(&traversal).unwrap()).is_err());

        let mut malformed = spec();
        malformed["recordings"][0]["media_sha256"] = json!("ABC");
        assert!(parse_spec(&serde_json::to_string(&malformed).unwrap()).is_err());
    }

    #[test]
    fn rejects_an_unpinned_model_before_loading_it() {
        let media = tempfile::tempdir().unwrap();
        let model_directory = tempfile::tempdir().unwrap();
        let model = model_directory.path().join("model.onnx");
        fs::write(&model, b"not-the-reviewed-model").unwrap();
        let raw = serde_json::to_string(&spec()).unwrap();
        let error = measure_similarity(&raw, media.path(), &model)
            .unwrap_err()
            .to_string();
        assert!(error.contains("pinned production model"));
    }

    #[test]
    fn refuses_media_inside_the_public_checkout() {
        let error = canonical_private_directory(Path::new(env!("CARGO_MANIFEST_DIR")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside the public repository"));
    }

    #[test]
    fn checked_in_similarity_schema_is_strict_and_matches_runtime_bounds() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../eval/voice/similarity-spec-schema-v1.json"
        ))
        .unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["recordings"]["minItems"], 4);
        assert_eq!(schema["properties"]["recordings"]["maxItems"], 512);
        assert_eq!(
            schema["properties"]["recordings"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["recordings"]["items"]["properties"]["duration_ms"]["minimum"],
            MIN_RECORDING_MS
        );
        assert_eq!(
            schema["properties"]["recordings"]["items"]["properties"]["duration_ms"]["maximum"],
            MAX_RECORDING_MS
        );
        assert!(include_str!("../../Dockerfile").contains(voice_memory::MODEL_SHA256));
    }

    #[test]
    fn rejects_an_oversized_spec_before_json_parsing() {
        let oversized = " ".repeat(MAX_SPEC_BYTES + 1);
        let error = parse_spec(&oversized).unwrap_err().to_string();
        assert!(error.contains("byte bound"));
    }
}
