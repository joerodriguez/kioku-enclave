//! Deterministic, offline ADR-0016 real-corpus derivation.
//!
//! The release evaluator needs exact, reviewable media slices without checking
//! licensed audio, labels, transcripts, names, or biometric material into Git.
//! This module consumes a strict private recipe and the independently
//! hash-bound artifacts from the public source manifest. It extracts exact
//! `.tar.gz` or ZIP members in memory, accepts only canonical mono 16 kHz PCM16 WAV,
//! performs fixed-point trim/concatenate/mix operations, and writes canonical
//! WAV plus opaque timing labels and a hash receipt outside the checkout.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

use super::voice_eval::{EvaluationArtifact, EvaluationManifest, EvaluationSource};

const SAMPLE_RATE: usize = 16_000;
const SAMPLES_PER_MS: usize = SAMPLE_RATE / 1_000;
const MAX_INPUTS: usize = 512;
const MAX_RECORDINGS: usize = 512;
const MAX_TRACKS_PER_RECORDING: usize = 512;
const MAX_REFERENCE_TURNS: usize = 10_000;
const MAX_RECORDING_MS: u64 = 30 * 60 * 1_000;
const MAX_ARTIFACT_BYTES: u64 = 2 * 1_024 * 1_024 * 1_024;
const MAX_MEMBER_BYTES: usize = 256 * 1_024 * 1_024;
const MAX_ZIP_ENTRIES: usize = 250_000;
const MAX_TOTAL_INPUT_SAMPLES: usize = SAMPLE_RATE * 4 * 60 * 60;
const MAX_TOTAL_OUTPUT_SAMPLES: usize = SAMPLE_RATE * 2 * 60 * 60;
const MAX_TOTAL_REFERENCE_TURNS: usize = 100_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivationRecipe {
    schema_version: u32,
    corpus_id: String,
    source_manifest_sha256: String,
    derivation_id: String,
    inputs: Vec<RecipeInput>,
    recordings: Vec<RecipeRecording>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ArchiveFormat {
    Plain,
    TarGzip,
    Zip,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeInput {
    id: String,
    source_id: String,
    artifact_id: String,
    archive_format: ArchiveFormat,
    member_path: Option<String>,
    member_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeRecording {
    id: String,
    source_id: String,
    media_artifact_id: String,
    labels_artifact_id: String,
    selected_item_id: String,
    slice: String,
    duration_ms: u64,
    tracks: Vec<RecipeTrack>,
    reference_turns: Vec<ReferenceTurn>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeTrack {
    input_id: String,
    source_start_ms: u64,
    source_end_ms: u64,
    output_start_ms: u64,
    gain_milli: u32,
}

#[derive(Debug, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReferenceTurn {
    start_ms: u64,
    end_ms: u64,
    speaker_id: String,
}

#[derive(Debug)]
struct LoadedInput {
    source_id: String,
    artifact_id: String,
    samples: Vec<i16>,
}

#[derive(Debug, Serialize)]
struct LabelsFile<'a> {
    schema_version: u32,
    corpus_id: &'a str,
    recording_id: &'a str,
    source_id: &'a str,
    selected_item_id: &'a str,
    slice: &'a str,
    duration_ms: u64,
    augmentation_artifacts: &'a [AugmentationArtifactBinding],
    reference_turns: &'a [ReferenceTurn],
}

#[derive(Debug, Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct AugmentationArtifactBinding {
    source_id: String,
    artifact_id: String,
    sha256: String,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DerivationReceipt {
    schema_version: u32,
    corpus_id: String,
    derivation_id: String,
    source_manifest_sha256: String,
    recipe_sha256: String,
    outputs: Vec<DerivedOutput>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DerivedOutput {
    id: String,
    source_id: String,
    media_artifact_id: String,
    labels_artifact_id: String,
    selected_item_id: String,
    slice: String,
    duration_ms: u64,
    augmentation_artifacts: Vec<AugmentationArtifactBinding>,
    media_file: String,
    media_sha256: String,
    labels_file: String,
    labels_sha256: String,
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

fn valid_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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

fn canonical_private_directory(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid(format!(
            "voice evaluation {label} directory must be absolute"
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        invalid(format!(
            "cannot resolve voice evaluation {label} directory: {error}"
        ))
    })?;
    if !canonical.is_dir() {
        return Err(invalid(format!(
            "voice evaluation {label} path is not a directory"
        )));
    }
    let repository = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).map_err(|error| {
        invalid(format!(
            "cannot resolve voice evaluation source checkout: {error}"
        ))
    })?;
    if canonical.starts_with(repository) {
        return Err(invalid(format!(
            "voice evaluation {label} directory must be outside the public repository"
        )));
    }
    Ok(canonical)
}

fn hash_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("cannot inspect source artifact: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
        return Err(invalid(
            "source artifact must be a bounded regular file, not a symlink",
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| invalid(format!("cannot open source artifact: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| invalid(format!("cannot read source artifact: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_member_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 1_024
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid(
            "archive member path must be a bounded, relative, traversal-free path",
        ));
    }
    Ok(())
}

fn read_bounded(reader: &mut impl Read, limit: usize, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(format!("cannot read {label}: {error}")))?;
    if bytes.len() > limit {
        return Err(invalid(format!("{label} exceeds the bounded size limit")));
    }
    Ok(bytes)
}

fn read_exact_tar_gzip_member(artifact_path: &Path, member_path: &str) -> Result<Vec<u8>> {
    validate_member_path(member_path)?;
    let file = File::open(artifact_path)
        .map_err(|error| invalid(format!("cannot open source bundle: {error}")))?;
    let decoder = GzDecoder::new(BufReader::new(file));
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| invalid(format!("cannot read source tar bundle: {error}")))?;
    let mut selected = None;
    for entry in entries {
        let mut entry =
            entry.map_err(|error| invalid(format!("cannot read source tar entry: {error}")))?;
        let path = entry
            .path()
            .map_err(|error| invalid(format!("invalid source tar entry path: {error}")))?;
        let Some(path) = path.to_str() else {
            continue;
        };
        if path != member_path {
            continue;
        }
        if selected.is_some() || !entry.header().entry_type().is_file() {
            return Err(invalid(
                "selected source tar member must be one unique regular file",
            ));
        }
        selected = Some(read_bounded(
            &mut entry,
            MAX_MEMBER_BYTES,
            "source tar member",
        )?);
    }
    selected.ok_or_else(|| invalid("selected source tar member was not found"))
}

fn read_exact_zip_member(artifact_path: &Path, member_path: &str) -> Result<Vec<u8>> {
    validate_member_path(member_path)?;
    let file = File::open(artifact_path)
        .map_err(|error| invalid(format!("cannot open source ZIP bundle: {error}")))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| invalid(format!("cannot read source ZIP bundle: {error}")))?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(invalid("source ZIP bundle contains too many entries"));
    }
    let mut selected = None;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| invalid(format!("cannot read source ZIP entry: {error}")))?;
        if entry.name() != member_path {
            continue;
        }
        if selected.is_some() || !entry.is_file() {
            return Err(invalid(
                "selected source ZIP member must be one unique regular file",
            ));
        }
        if entry.size() > MAX_MEMBER_BYTES as u64 {
            return Err(invalid("source ZIP member exceeds the bounded size limit"));
        }
        selected = Some(read_bounded(
            &mut entry,
            MAX_MEMBER_BYTES,
            "source ZIP member",
        )?);
    }
    selected.ok_or_else(|| invalid("selected source ZIP member was not found"))
}

fn artifact_for<'a>(
    source: &'a EvaluationSource,
    artifact_id: &str,
) -> Result<&'a EvaluationArtifact> {
    source
        .artifacts
        .iter()
        .find(|artifact| artifact.id == artifact_id)
        .ok_or_else(|| invalid("derivation recipe references an unknown source artifact"))
}

fn artifact_path(artifact_directory: &Path, source_id: &str, artifact_id: &str) -> PathBuf {
    artifact_directory.join(format!("{source_id}.{artifact_id}.asset"))
}

fn verify_artifact_file(
    artifact_directory: &Path,
    source_id: &str,
    artifact: &EvaluationArtifact,
) -> Result<PathBuf> {
    let path = artifact_path(artifact_directory, source_id, &artifact.id);
    if hash_file(&path)? != artifact.sha256 {
        return Err(invalid(
            "source artifact SHA-256 does not match the reviewed manifest",
        ));
    }
    Ok(path)
}

fn load_input(
    input: &RecipeInput,
    sources: &HashMap<&str, &EvaluationSource>,
    artifact_directory: &Path,
) -> Result<LoadedInput> {
    if !valid_opaque_id(&input.id)
        || !valid_opaque_id(&input.source_id)
        || !valid_opaque_id(&input.artifact_id)
    {
        return Err(invalid("derivation input has an invalid opaque identifier"));
    }
    let source = sources
        .get(input.source_id.as_str())
        .ok_or_else(|| invalid("derivation input references an unknown source"))?;
    let artifact = artifact_for(source, &input.artifact_id)?;
    if !matches!(artifact.kind.as_str(), "media" | "bundle" | "augmentation") {
        return Err(invalid(
            "derivation audio input must bind a media, bundle, or augmentation artifact",
        ));
    }
    let artifact_path = verify_artifact_file(artifact_directory, &input.source_id, artifact)?;
    let media = match input.archive_format {
        ArchiveFormat::Plain => {
            if input.member_path.is_some() || input.member_sha256.is_some() {
                return Err(invalid(
                    "plain derivation input must not declare an archive member",
                ));
            }
            let mut file = File::open(&artifact_path)
                .map_err(|error| invalid(format!("cannot open source media: {error}")))?;
            read_bounded(&mut file, MAX_MEMBER_BYTES, "source media")?
        }
        ArchiveFormat::TarGzip => {
            let member_path = input.member_path.as_deref().ok_or_else(|| {
                invalid("tar_gzip derivation input requires an exact member path")
            })?;
            let expected_sha256 = input
                .member_sha256
                .as_deref()
                .filter(|hash| valid_sha256(hash))
                .ok_or_else(|| {
                    invalid("tar_gzip derivation input requires a lowercase member SHA-256")
                })?;
            let bytes = read_exact_tar_gzip_member(&artifact_path, member_path)?;
            if sha256_hex(&bytes) != expected_sha256 {
                return Err(invalid(
                    "source archive member SHA-256 does not match the private recipe",
                ));
            }
            bytes
        }
        ArchiveFormat::Zip => {
            let member_path = input
                .member_path
                .as_deref()
                .ok_or_else(|| invalid("ZIP derivation input requires an exact member path"))?;
            let expected_sha256 = input
                .member_sha256
                .as_deref()
                .filter(|hash| valid_sha256(hash))
                .ok_or_else(|| {
                    invalid("ZIP derivation input requires a lowercase member SHA-256")
                })?;
            let bytes = read_exact_zip_member(&artifact_path, member_path)?;
            if sha256_hex(&bytes) != expected_sha256 {
                return Err(invalid(
                    "source ZIP member SHA-256 does not match the private recipe",
                ));
            }
            bytes
        }
    };
    Ok(LoadedInput {
        source_id: input.source_id.clone(),
        artifact_id: input.artifact_id.clone(),
        samples: decode_canonical_pcm16_wav(&media)?,
    })
}

fn little_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| invalid("truncated PCM WAV field"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn little_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("truncated PCM WAV field"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn decode_canonical_pcm16_wav(bytes: &[u8]) -> Result<Vec<i16>> {
    if bytes.len() < 44
        || bytes.get(0..4) != Some(b"RIFF")
        || bytes.get(8..12) != Some(b"WAVE")
        || little_u32(bytes, 4)? as usize + 8 != bytes.len()
    {
        return Err(invalid(
            "derivation input must be a complete RIFF/WAVE file",
        ));
    }
    let mut offset = 12_usize;
    let mut format_seen = false;
    let mut pcm = None;
    while offset < bytes.len() {
        let id = bytes
            .get(offset..offset + 4)
            .ok_or_else(|| invalid("truncated PCM WAV chunk"))?;
        let size = little_u32(bytes, offset + 4)? as usize;
        let start = offset
            .checked_add(8)
            .ok_or_else(|| invalid("invalid PCM WAV chunk"))?;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid("PCM WAV chunk exceeds the file"))?;
        if id == b"fmt " {
            if format_seen
                || size < 16
                || little_u16(bytes, start)? != 1
                || little_u16(bytes, start + 2)? != 1
                || little_u32(bytes, start + 4)? != SAMPLE_RATE as u32
                || little_u32(bytes, start + 8)? != (SAMPLE_RATE * 2) as u32
                || little_u16(bytes, start + 12)? != 2
                || little_u16(bytes, start + 14)? != 16
            {
                return Err(invalid(
                    "derivation input must be mono 16 kHz little-endian PCM16",
                ));
            }
            format_seen = true;
        } else if id == b"data" {
            if pcm.is_some() || size == 0 || !size.is_multiple_of(2) {
                return Err(invalid("PCM WAV must contain one nonempty data chunk"));
            }
            pcm = Some(&bytes[start..end]);
        }
        offset = end
            .checked_add(size % 2)
            .filter(|offset| *offset <= bytes.len())
            .ok_or_else(|| invalid("invalid PCM WAV chunk padding"))?;
    }
    if !format_seen || offset != bytes.len() {
        return Err(invalid("PCM WAV is missing its canonical format chunk"));
    }
    let pcm = pcm.ok_or_else(|| invalid("PCM WAV is missing its data chunk"))?;
    let samples = pcm
        .chunks_exact(2)
        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    if samples.len() > MAX_TOTAL_INPUT_SAMPLES {
        return Err(invalid("one derivation input exceeds the audio bound"));
    }
    Ok(samples)
}

fn encode_canonical_pcm16_wav(samples: &[i16]) -> Result<Vec<u8>> {
    let data_len = samples
        .len()
        .checked_mul(2)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| invalid("derived PCM WAV exceeds the format bound"))?;
    let mut bytes = Vec::with_capacity(data_len as usize + 44);
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&(data_len + 36).to_le_bytes());
    bytes.extend_from_slice(b"WAVEfmt ");
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&(SAMPLE_RATE as u32).to_le_bytes());
    bytes.extend_from_slice(&((SAMPLE_RATE * 2) as u32).to_le_bytes());
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&data_len.to_le_bytes());
    for sample in samples {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    Ok(bytes)
}

fn milliseconds_to_samples(milliseconds: u64) -> Result<usize> {
    usize::try_from(milliseconds)
        .ok()
        .and_then(|value| value.checked_mul(SAMPLES_PER_MS))
        .ok_or_else(|| invalid("audio time exceeds the derivation bound"))
}

fn sorted_reference_turns(recording: &RecipeRecording) -> Result<Vec<ReferenceTurn>> {
    if recording.reference_turns.is_empty() || recording.reference_turns.len() > MAX_REFERENCE_TURNS
    {
        return Err(invalid(
            "derived recording must contain bounded reference speaker turns",
        ));
    }
    let mut unique = HashSet::new();
    for turn in &recording.reference_turns {
        if !valid_hashed_id(&turn.speaker_id, "speaker-")
            || turn.start_ms >= turn.end_ms
            || turn.end_ms > recording.duration_ms
            || !unique.insert((turn.start_ms, turn.end_ms, turn.speaker_id.as_str()))
        {
            return Err(invalid(
                "derived reference turns must have unique bounded opaque timing",
            ));
        }
    }
    let mut turns = recording.reference_turns.clone();
    turns.sort_by(|left, right| {
        (left.start_ms, left.end_ms, left.speaker_id.as_str()).cmp(&(
            right.start_ms,
            right.end_ms,
            right.speaker_id.as_str(),
        ))
    });
    Ok(turns)
}

fn render_recording(
    recipe: &DerivationRecipe,
    recording: &RecipeRecording,
    sources: &HashMap<&str, &EvaluationSource>,
    inputs: &HashMap<&str, LoadedInput>,
    referenced_inputs: &mut HashSet<String>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<AugmentationArtifactBinding>)> {
    if !valid_hashed_id(&recording.id, "recording-")
        || !valid_opaque_id(&recording.source_id)
        || !valid_opaque_id(&recording.media_artifact_id)
        || !valid_opaque_id(&recording.labels_artifact_id)
        || !valid_opaque_id(&recording.selected_item_id)
        || !valid_opaque_id(&recording.slice)
        || recording.duration_ms == 0
        || recording.duration_ms > MAX_RECORDING_MS
        || recording.tracks.is_empty()
        || recording.tracks.len() > MAX_TRACKS_PER_RECORDING
    {
        return Err(invalid("derived recording has an invalid bounded shape"));
    }
    let source = sources
        .get(recording.source_id.as_str())
        .ok_or_else(|| invalid("derived recording references an unknown source"))?;
    let media_artifact = artifact_for(source, &recording.media_artifact_id)?;
    let labels_artifact = artifact_for(source, &recording.labels_artifact_id)?;
    if !matches!(media_artifact.kind.as_str(), "media" | "bundle")
        || !matches!(labels_artifact.kind.as_str(), "labels" | "bundle")
        || !source
            .selected_item_ids
            .contains(&recording.selected_item_id)
        || !source.slices.contains(&recording.slice)
    {
        return Err(invalid(
            "derived recording does not match its manifest artifacts, selection, and slice",
        ));
    }
    let duration_samples = milliseconds_to_samples(recording.duration_ms)?;
    let mut mixed = vec![0_i64; duration_samples];
    let mut augmentation_artifacts = BTreeSet::new();
    for track in &recording.tracks {
        let input = inputs
            .get(track.input_id.as_str())
            .ok_or_else(|| invalid("derived track references an unknown input"))?;
        let input_source = sources
            .get(input.source_id.as_str())
            .ok_or_else(|| invalid("derived track references an unknown input source"))?;
        let input_artifact = artifact_for(input_source, &input.artifact_id)?;
        let is_primary_media = input.source_id == recording.source_id
            && input.artifact_id == recording.media_artifact_id;
        let is_augmentation =
            input_artifact.kind == "augmentation" && input_source.slices.contains(&recording.slice);
        if (!is_primary_media && !is_augmentation)
            || track.source_start_ms >= track.source_end_ms
            || track.gain_milli == 0
            || track.gain_milli > 4_000
        {
            return Err(invalid(
                "derived track has an invalid source, artifact, range, or gain",
            ));
        }
        if is_augmentation {
            augmentation_artifacts.insert(AugmentationArtifactBinding {
                source_id: input.source_id.clone(),
                artifact_id: input.artifact_id.clone(),
                sha256: input_artifact.sha256.clone(),
            });
        }
        let source_start = milliseconds_to_samples(track.source_start_ms)?;
        let source_end = milliseconds_to_samples(track.source_end_ms)?;
        let output_start = milliseconds_to_samples(track.output_start_ms)?;
        let sample_count = source_end
            .checked_sub(source_start)
            .filter(|count| *count > 0)
            .ok_or_else(|| invalid("derived track has an empty source range"))?;
        let output_end = output_start
            .checked_add(sample_count)
            .filter(|end| *end <= duration_samples)
            .ok_or_else(|| invalid("derived track exceeds recording duration"))?;
        if source_end > input.samples.len() {
            return Err(invalid("derived track exceeds its source media"));
        }
        for (target, sample) in mixed[output_start..output_end]
            .iter_mut()
            .zip(&input.samples[source_start..source_end])
        {
            *target += i64::from(*sample) * i64::from(track.gain_milli) / 1_000;
        }
        referenced_inputs.insert(track.input_id.clone());
    }
    let pcm = mixed
        .into_iter()
        .map(|sample| sample.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16)
        .collect::<Vec<_>>();
    let media = encode_canonical_pcm16_wav(&pcm)?;
    let reference_turns = sorted_reference_turns(recording)?;
    let augmentation_artifacts = augmentation_artifacts.into_iter().collect::<Vec<_>>();
    let labels = LabelsFile {
        schema_version: 1,
        corpus_id: &recipe.corpus_id,
        recording_id: &recording.id,
        source_id: &recording.source_id,
        selected_item_id: &recording.selected_item_id,
        slice: &recording.slice,
        duration_ms: recording.duration_ms,
        augmentation_artifacts: &augmentation_artifacts,
        reference_turns: &reference_turns,
    };
    let mut labels = serde_json::to_vec_pretty(&labels)?;
    labels.push(b'\n');
    Ok((media, labels, augmentation_artifacts))
}

fn write_exact_file(directory: &Path, file_name: &str, bytes: &[u8]) -> Result<()> {
    let destination = directory.join(file_name);
    if destination.exists() {
        let metadata = fs::symlink_metadata(&destination)
            .map_err(|error| invalid(format!("cannot inspect derived output: {error}")))?;
        if !metadata.file_type().is_file() {
            return Err(invalid("derived output path is not a regular file"));
        }
        let existing = fs::read(&destination)
            .map_err(|error| invalid(format!("cannot read derived output: {error}")))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(invalid(
            "derived output already exists with different bytes; refusing to replace it",
        ));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .map_err(|error| invalid(format!("cannot create derived output: {error}")))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| invalid(format!("cannot write derived output: {error}")))?;
    match temporary.persist_noclobber(&destination) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(&destination).map_err(|read_error| {
                invalid(format!("cannot read derived output: {read_error}"))
            })?;
            if existing == bytes {
                Ok(())
            } else {
                Err(invalid(
                    "derived output appeared concurrently with different bytes",
                ))
            }
        }
        Err(error) => Err(invalid(format!(
            "cannot persist derived output: {}",
            error.error
        ))),
    }
}

pub fn derive_assets(
    manifest_raw: &str,
    recipe_raw: &str,
    artifact_directory: &Path,
    output_directory: &Path,
) -> Result<String> {
    let manifest_sha256 = super::voice_eval::validate_manifest_json(manifest_raw)?;
    let manifest: EvaluationManifest = serde_json::from_str(manifest_raw)?;
    let recipe: DerivationRecipe = serde_json::from_str(recipe_raw)?;
    if recipe.schema_version != 1
        || recipe.corpus_id != manifest.corpus_id
        || recipe.source_manifest_sha256 != manifest_sha256
        || !valid_hashed_id(&recipe.derivation_id, "derivation-")
        || recipe.inputs.is_empty()
        || recipe.inputs.len() > MAX_INPUTS
        || recipe.recordings.is_empty()
        || recipe.recordings.len() > MAX_RECORDINGS
    {
        return Err(invalid(
            "invalid voice evaluation derivation recipe identity or bounds",
        ));
    }
    let artifact_directory = canonical_private_directory(artifact_directory, "artifact")?;
    let output_directory = canonical_private_directory(output_directory, "output")?;
    if artifact_directory == output_directory {
        return Err(invalid(
            "voice evaluation artifact and output directories must be distinct",
        ));
    }
    let sources = manifest
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<HashMap<_, _>>();
    let mut input_ids = HashSet::new();
    let mut total_input_samples = 0_usize;
    let mut inputs = HashMap::new();
    for input in &recipe.inputs {
        if !input_ids.insert(input.id.as_str()) {
            return Err(invalid("derivation input IDs must be unique"));
        }
        let loaded = load_input(input, &sources, &artifact_directory)?;
        total_input_samples = total_input_samples
            .checked_add(loaded.samples.len())
            .filter(|total| *total <= MAX_TOTAL_INPUT_SAMPLES)
            .ok_or_else(|| invalid("derivation inputs exceed the total audio bound"))?;
        inputs.insert(input.id.as_str(), loaded);
    }
    let mut recording_ids = HashSet::new();
    let mut referenced_inputs = HashSet::new();
    let mut pending_files = Vec::new();
    let mut outputs = Vec::new();
    let mut total_output_samples = 0_usize;
    let mut total_reference_turns = 0_usize;
    for recording in &recipe.recordings {
        if !recording_ids.insert(recording.id.as_str()) {
            return Err(invalid("derived recording IDs must be unique"));
        }
        total_output_samples = total_output_samples
            .checked_add(milliseconds_to_samples(recording.duration_ms)?)
            .filter(|total| *total <= MAX_TOTAL_OUTPUT_SAMPLES)
            .ok_or_else(|| invalid("derived recordings exceed the total audio bound"))?;
        total_reference_turns = total_reference_turns
            .checked_add(recording.reference_turns.len())
            .filter(|total| *total <= MAX_TOTAL_REFERENCE_TURNS)
            .ok_or_else(|| invalid("derived recordings exceed the total label bound"))?;
        let source = sources
            .get(recording.source_id.as_str())
            .ok_or_else(|| invalid("derived recording references an unknown source"))?;
        verify_artifact_file(
            &artifact_directory,
            &recording.source_id,
            artifact_for(source, &recording.media_artifact_id)?,
        )?;
        verify_artifact_file(
            &artifact_directory,
            &recording.source_id,
            artifact_for(source, &recording.labels_artifact_id)?,
        )?;
        let (media, labels, augmentation_artifacts) = render_recording(
            &recipe,
            recording,
            &sources,
            &inputs,
            &mut referenced_inputs,
        )?;
        let media_file = format!("{}.wav", recording.id);
        let labels_file = format!("{}.labels.json", recording.id);
        outputs.push(DerivedOutput {
            id: recording.id.clone(),
            source_id: recording.source_id.clone(),
            media_artifact_id: recording.media_artifact_id.clone(),
            labels_artifact_id: recording.labels_artifact_id.clone(),
            selected_item_id: recording.selected_item_id.clone(),
            slice: recording.slice.clone(),
            duration_ms: recording.duration_ms,
            augmentation_artifacts,
            media_file: media_file.clone(),
            media_sha256: sha256_hex(&media),
            labels_file: labels_file.clone(),
            labels_sha256: sha256_hex(&labels),
        });
        pending_files.push((media_file, media));
        pending_files.push((labels_file, labels));
    }
    if referenced_inputs.len() != inputs.len() {
        return Err(invalid(
            "every private derivation input must be referenced by a recording",
        ));
    }
    let receipt = DerivationReceipt {
        schema_version: 1,
        corpus_id: recipe.corpus_id,
        derivation_id: recipe.derivation_id,
        source_manifest_sha256: manifest_sha256,
        recipe_sha256: sha256_hex(recipe_raw.as_bytes()),
        outputs,
    };
    let mut receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
    receipt_bytes.push(b'\n');
    for (file_name, bytes) in pending_files {
        write_exact_file(&output_directory, &file_name, &bytes)?;
    }
    write_exact_file(&output_directory, "derivation-receipt.json", &receipt_bytes)?;
    String::from_utf8(receipt_bytes).map_err(|_| invalid("derivation receipt was not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;

    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn wav(samples: &[i16]) -> Vec<u8> {
        let data_len = u32::try_from(samples.len() * 2).unwrap();
        let mut bytes = Vec::with_capacity(samples.len() * 2 + 44);
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(data_len + 36).to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&16_000_u32.to_le_bytes());
        bytes.extend_from_slice(&32_000_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&16_u16.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&data_len.to_le_bytes());
        for sample in samples {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        bytes
    }

    fn manifest(media_sha256: &str, labels_sha256: &str, media_kind: &str) -> String {
        let all_slices = [
            "clean_remote_call",
            "three_plus_speakers",
            "overlap",
            "introduction",
            "repeated_meeting",
            "same_display_name",
            "similar_voices",
            "system_audio",
            "room_audio",
            "mac_microphone",
            "iphone_microphone",
            "bluetooth",
            "compression",
            "noise",
            "music",
            "echo",
            "french",
            "english",
            "mixed_language",
            "active_speaker_ui",
            "roster_only",
            "conflicting_evidence",
        ];
        json!({
            "schema_version": 2,
            "corpus_id": "corpus-0000000000000001",
            "sources": [{
                "id": "source-0",
                "license_id": "CC-BY-4.0",
                "license_url": "https://example.test/license",
                "artifacts": [
                    {"id":"media-0","kind":media_kind,"url":"https://example.test/media.wav","sha256":media_sha256},
                    {"id":"labels-0","kind":"labels","url":"https://example.test/labels.zip","sha256":labels_sha256}
                ],
                "selected_item_ids": ["item-0"],
                "slices": all_slices,
                "derivation_command": "kioku-enclave --derive-voice-eval-assets"
            }],
            "owner_fixtures": [{
                "id": "owner-0",
                "media_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "labels_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "authorization_record_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "physical_capture": true,
                "capture_origin": "licensed_playback",
                "derived_from_source_ids": ["source-0"],
                "capture_routes": ["mac_system_audio","mac_microphone","iphone_microphone","bluetooth","screen_capture"],
                "slices": ["system_audio","mac_microphone","iphone_microphone","bluetooth","active_speaker_ui","same_display_name"]
            }]
        })
        .to_string()
    }

    fn recipe(
        manifest: &str,
        archive_format: &str,
        member_path: Option<&str>,
        member_sha256: Option<String>,
    ) -> serde_json::Value {
        json!({
            "schema_version": 1,
            "corpus_id": "corpus-0000000000000001",
            "source_manifest_sha256": hash(manifest.as_bytes()),
            "derivation_id": "derivation-0000000000000001",
            "inputs": [{
                "id": "input-0",
                "source_id": "source-0",
                "artifact_id": "media-0",
                "archive_format": archive_format,
                "member_path": member_path,
                "member_sha256": member_sha256
            }],
            "recordings": [{
                "id": "recording-0000000000000001",
                "source_id": "source-0",
                "media_artifact_id": "media-0",
                "labels_artifact_id": "labels-0",
                "selected_item_id": "item-0",
                "slice": "clean_remote_call",
                "duration_ms": 1000,
                "tracks": [{
                    "input_id": "input-0",
                    "source_start_ms": 250,
                    "source_end_ms": 1250,
                    "output_start_ms": 0,
                    "gain_milli": 1000
                }],
                "reference_turns": [{
                    "start_ms": 0,
                    "end_ms": 1000,
                    "speaker_id": "speaker-0000000000000001"
                }]
            }]
        })
    }

    fn tar_gzip(member_path: &str, member: &[u8]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(member.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, member_path, member)
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap()
    }

    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (member_path, member) in entries {
            archive.start_file(member_path, options).unwrap();
            archive.write_all(member).unwrap();
        }
        archive.finish().unwrap().into_inner()
    }

    #[test]
    fn derives_a_hash_bound_plain_wav_and_opaque_labels() {
        let artifacts = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let source = wav(&vec![1_000; 32_000]);
        let source_labels = b"reviewed-label-artifact";
        fs::write(artifacts.path().join("source-0.media-0.asset"), &source).unwrap();
        fs::write(
            artifacts.path().join("source-0.labels-0.asset"),
            source_labels,
        )
        .unwrap();
        let manifest = manifest(&hash(&source), &hash(source_labels), "media");
        let recipe = recipe(&manifest, "plain", None, None).to_string();

        let receipt = derive_assets(&manifest, &recipe, artifacts.path(), output.path()).unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["outputs"][0]["duration_ms"], 1000);
        assert!(output
            .path()
            .join("recording-0000000000000001.wav")
            .is_file());
        assert!(output
            .path()
            .join("recording-0000000000000001.labels.json")
            .is_file());
        assert!(output.path().join("derivation-receipt.json").is_file());
    }

    #[test]
    fn cross_source_augmentation_retains_independent_license_lineage() {
        let artifacts = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let speech = wav(&vec![1_000; 32_000]);
        let noise = wav(&vec![250; 16_000]);
        let labels = b"reviewed-label-artifact";
        fs::write(artifacts.path().join("source-0.media-0.asset"), &speech).unwrap();
        fs::write(artifacts.path().join("source-0.labels-0.asset"), labels).unwrap();
        fs::write(
            artifacts.path().join("source-1.augmentation-0.asset"),
            &noise,
        )
        .unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_str(&manifest(&hash(&speech), &hash(labels), "media")).unwrap();
        manifest["sources"].as_array_mut().unwrap().push(json!({
            "id":"source-1",
            "license_id":"Apache-2.0",
            "license_url":"https://example.test/source-1-license",
            "artifacts":[{
                "id":"augmentation-0",
                "kind":"augmentation",
                "url":"https://example.test/noise.wav",
                "sha256":hash(&noise)
            }],
            "selected_item_ids":["noise-0"],
            "slices":["noise"],
            "derivation_command":"kioku-enclave --derive-voice-eval-assets"
        }));
        let manifest = manifest.to_string();

        let mut recipe = recipe(&manifest, "plain", None, None);
        recipe["inputs"].as_array_mut().unwrap().push(json!({
            "id":"input-augmentation",
            "source_id":"source-1",
            "artifact_id":"augmentation-0",
            "archive_format":"plain",
            "member_path":null,
            "member_sha256":null
        }));
        recipe["recordings"][0]["slice"] = json!("noise");
        recipe["recordings"][0]["tracks"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "input_id":"input-augmentation",
                "source_start_ms":0,
                "source_end_ms":1000,
                "output_start_ms":0,
                "gain_milli":500
            }));

        let receipt = derive_assets(
            &manifest,
            &recipe.to_string(),
            artifacts.path(),
            output.path(),
        )
        .unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(
            receipt["outputs"][0]["augmentation_artifacts"],
            json!([{
                "source_id":"source-1",
                "artifact_id":"augmentation-0",
                "sha256":hash(&noise)
            }])
        );
        let labels: serde_json::Value = serde_json::from_slice(
            &fs::read(output.path().join("recording-0000000000000001.labels.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            labels["augmentation_artifacts"],
            receipt["outputs"][0]["augmentation_artifacts"]
        );

        let mut invalid_manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        invalid_manifest["sources"][1]["artifacts"][0]["kind"] = json!("media");
        let invalid_manifest = invalid_manifest.to_string();
        recipe["source_manifest_sha256"] = json!(hash(invalid_manifest.as_bytes()));
        let invalid_output = tempfile::tempdir().unwrap();
        assert!(derive_assets(
            &invalid_manifest,
            &recipe.to_string(),
            artifacts.path(),
            invalid_output.path(),
        )
        .is_err());

        let mut invalid_manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        invalid_manifest["sources"][1]["slices"] = json!(["music"]);
        let invalid_manifest = invalid_manifest.to_string();
        recipe["source_manifest_sha256"] = json!(hash(invalid_manifest.as_bytes()));
        let invalid_output = tempfile::tempdir().unwrap();
        assert!(derive_assets(
            &invalid_manifest,
            &recipe.to_string(),
            artifacts.path(),
            invalid_output.path(),
        )
        .is_err());
    }

    #[test]
    fn extracts_exact_tar_member_and_uses_fixed_point_overlap_mix() {
        let artifacts = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let mut samples = vec![1_000; 16_000];
        samples.extend(vec![2_000; 16_000]);
        let member = wav(&samples);
        let member_path = "corpus/audio/item.wav";
        let bundle = tar_gzip(member_path, &member);
        let labels = b"reviewed-label-artifact";
        fs::write(artifacts.path().join("source-0.media-0.asset"), &bundle).unwrap();
        fs::write(artifacts.path().join("source-0.labels-0.asset"), labels).unwrap();
        let manifest = manifest(&hash(&bundle), &hash(labels), "bundle");
        let mut recipe = recipe(
            &manifest,
            "tar_gzip",
            Some(member_path),
            Some(hash(&member)),
        );
        recipe["recordings"][0]["tracks"] = json!([
            {
                "input_id":"input-0",
                "source_start_ms":0,
                "source_end_ms":1000,
                "output_start_ms":0,
                "gain_milli":1000
            },
            {
                "input_id":"input-0",
                "source_start_ms":1000,
                "source_end_ms":2000,
                "output_start_ms":0,
                "gain_milli":500
            }
        ]);
        recipe["recordings"][0]["reference_turns"] = json!([
            {"start_ms":500,"end_ms":1000,"speaker_id":"speaker-2222222222222222"},
            {"start_ms":0,"end_ms":700,"speaker_id":"speaker-1111111111111111"}
        ]);
        let recipe = recipe.to_string();

        let first = derive_assets(&manifest, &recipe, artifacts.path(), output.path()).unwrap();
        let second = derive_assets(&manifest, &recipe, artifacts.path(), output.path()).unwrap();
        assert_eq!(first, second);
        let derived = fs::read(output.path().join("recording-0000000000000001.wav")).unwrap();
        assert!(decode_canonical_pcm16_wav(&derived)
            .unwrap()
            .into_iter()
            .all(|sample| sample == 2_000));
        let labels: serde_json::Value = serde_json::from_slice(
            &fs::read(output.path().join("recording-0000000000000001.labels.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(labels["reference_turns"][0]["start_ms"], 0);

        fs::write(
            output.path().join("recording-0000000000000001.wav"),
            b"different",
        )
        .unwrap();
        assert!(derive_assets(&manifest, &recipe, artifacts.path(), output.path()).is_err());
    }

    #[test]
    fn extracts_one_exact_hash_bound_deflated_zip_member() {
        let artifacts = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let member = wav(&vec![1_000; 32_000]);
        let member_path = "RIRS_NOISES/pointsource_noises/noise.wav";
        let bundle = zip(&[(member_path, &member)]);
        let labels = b"reviewed-label-artifact";
        fs::write(artifacts.path().join("source-0.media-0.asset"), &bundle).unwrap();
        fs::write(artifacts.path().join("source-0.labels-0.asset"), labels).unwrap();
        let manifest_raw = manifest(&hash(&bundle), &hash(labels), "bundle");
        let recipe_value = recipe(&manifest_raw, "zip", Some(member_path), Some(hash(&member)));

        let receipt = derive_assets(
            &manifest_raw,
            &recipe_value.to_string(),
            artifacts.path(),
            output.path(),
        )
        .unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["outputs"][0]["duration_ms"], 1000);

        let mut wrong_hash = recipe_value.clone();
        wrong_hash["inputs"][0]["member_sha256"] = json!("f".repeat(64));
        let rejected = tempfile::tempdir().unwrap();
        assert!(derive_assets(
            &manifest_raw,
            &wrong_hash.to_string(),
            artifacts.path(),
            rejected.path(),
        )
        .is_err());

        let mut traversal = recipe_value.clone();
        traversal["inputs"][0]["member_path"] = json!("../noise.wav");
        let rejected = tempfile::tempdir().unwrap();
        assert!(derive_assets(
            &manifest_raw,
            &traversal.to_string(),
            artifacts.path(),
            rejected.path(),
        )
        .is_err());

        let mut missing = recipe_value;
        missing["inputs"][0]["member_path"] = json!("RIRS_NOISES/missing.wav");
        let rejected = tempfile::tempdir().unwrap();
        assert!(derive_assets(
            &manifest_raw,
            &missing.to_string(),
            artifacts.path(),
            rejected.path(),
        )
        .is_err());
    }

    #[test]
    fn rejects_unverified_labels_and_archive_traversal() {
        let artifacts = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let member = wav(&vec![1_000; 32_000]);
        let bundle = tar_gzip("audio/item.wav", &member);
        fs::write(artifacts.path().join("source-0.media-0.asset"), &bundle).unwrap();
        let manifest = manifest(
            &hash(&bundle),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bundle",
        );
        let traversal_recipe = recipe(
            &manifest,
            "tar_gzip",
            Some("../audio/item.wav"),
            Some(hash(&member)),
        )
        .to_string();
        let error = derive_assets(
            &manifest,
            &traversal_recipe,
            artifacts.path(),
            output.path(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("traversal-free") || error.contains("inspect source artifact"));

        fs::write(
            artifacts.path().join("source-0.labels-0.asset"),
            b"wrong-labels",
        )
        .unwrap();
        let valid_recipe = recipe(
            &manifest,
            "tar_gzip",
            Some("audio/item.wav"),
            Some(hash(&member)),
        )
        .to_string();
        let error = derive_assets(&manifest, &valid_recipe, artifacts.path(), output.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("SHA-256"));
    }

    #[test]
    fn rejects_unknown_recipe_fields_noncanonical_wav_and_repo_output() {
        let artifacts = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let mut source = wav(&vec![1_000; 32_000]);
        source[22..24].copy_from_slice(&2_u16.to_le_bytes());
        let labels = b"reviewed-label-artifact";
        fs::write(artifacts.path().join("source-0.media-0.asset"), &source).unwrap();
        fs::write(artifacts.path().join("source-0.labels-0.asset"), labels).unwrap();
        let manifest = manifest(&hash(&source), &hash(labels), "media");
        let mut unknown = recipe(&manifest, "plain", None, None);
        unknown["content"] = json!("forbidden transcript");
        assert!(derive_assets(
            &manifest,
            &unknown.to_string(),
            artifacts.path(),
            output.path()
        )
        .is_err());

        let recipe = recipe(&manifest, "plain", None, None).to_string();
        assert!(derive_assets(&manifest, &recipe, artifacts.path(), output.path()).is_err());
        assert!(derive_assets(
            &manifest,
            &recipe,
            artifacts.path(),
            Path::new(env!("CARGO_MANIFEST_DIR"))
        )
        .is_err());
    }
}
