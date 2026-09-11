//! Persistent server-side speaker memory.
//!
//! Audio decoding, Kaldi-compatible filterbanks, and WeSpeaker inference are
//! implemented in Rust. Voice embeddings never return to a client and are
//! persisted through PostgreSQL repository settlements. Gemini supplies turn
//! boundaries; this module independently fingerprints each sufficiently long
//! turn without owning structured persistence.

use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;

use kaldi_native_fbank::{
    fbank::{FbankComputer, FbankOptions},
    online::{FeatureComputer, OnlineFeature},
};
use sha2::{Digest, Sha256};
use symphonia::core::audio::SampleBuffer;
use symphonia::core::codecs::DecoderOptions;
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;
use tract_onnx::prelude::*;

use crate::error::{EnclaveError, Result};

use super::media::AudioTurn;
use super::voice_quality::{self, SampleDecision};

pub const EMBEDDING_SPACE: &str = "wespeaker-resnet34-lm-v1";
pub const MODEL_SHA256: &str = "e9848563da86f263117134dfd7ad63c92355b37de492b55e325400c9d9c39012";
pub(crate) const TARGET_SAMPLE_RATE: u32 = 16_000;
pub(crate) const MAX_TURN_SAMPLES: usize = TARGET_SAMPLE_RATE as usize * 30;
pub(crate) const MATCH_THRESHOLD: f32 = 0.60;
pub(crate) const NEW_PROFILE_THRESHOLD: f32 = 0.45;
pub(crate) const MIN_DECISION_MARGIN: f32 = 0.08;
const MAX_MODEL_BYTES: u64 = 128 * 1024 * 1024;

pub struct VoiceEngine {
    model: Arc<TypedRunnableModel>,
}

pub struct EmbeddedTurn {
    pub embedding: Option<Vec<f32>>,
}

impl VoiceEngine {
    /// Model selection is immutable for this process. Cohort and pause remain
    /// PostgreSQL operator state; an unavailable model never affects readiness.
    pub fn from_env() -> Option<Arc<Self>> {
        let path = std::env::var_os("VOICE_MODEL_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(
                    std::env::var_os("EMBED_MODEL_DIR").unwrap_or_else(|| "/models".into()),
                )
                .join("voice/wespeaker_en_voxceleb_resnet34_LM.onnx")
            });
        match Self::load(&path) {
            Ok(engine) => Some(Arc::new(engine)),
            Err(_) => {
                tracing::warn!(target: "kioku::voice", metric_schema = "voice_identity_v1",
                    outcome = "model_unavailable", "voice worker is unavailable");
                None
            }
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_MODEL_BYTES {
            return Err(EnclaveError::Config(
                "voice model exceeds size bound".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_MODEL_BYTES + 1).read_to_end(&mut bytes)?;
        verify_model_bytes(&bytes)?;
        // Parse the bytes whose digest was checked, avoiding a path reopen race.
        let model = tract_onnx::onnx()
            .model_for_read(&mut Cursor::new(bytes))
            .and_then(|model| model.into_optimized())
            .and_then(|model| model.into_runnable())
            .map_err(|error| EnclaveError::Embedding(format!("load voice model: {error}")))?;
        Ok(Self { model })
    }

    pub fn embed_turns(
        &self,
        media: &[u8],
        mime_type: &str,
        turns: &[AudioTurn],
    ) -> Result<Vec<EmbeddedTurn>> {
        let samples = decode_mono_16khz(media, mime_type)?;
        let mut output = Vec::new();
        for turn in turns {
            let start = ((turn.start_ms.max(0) as u64 * TARGET_SAMPLE_RATE as u64) / 1000) as usize;
            let end = ((turn.end_ms.max(0) as u64 * TARGET_SAMPLE_RATE as u64) / 1000) as usize;
            let end = end
                .min(samples.len())
                .min(start.saturating_add(MAX_TURN_SAMPLES));
            let chunk = samples.get(start..end).unwrap_or(&[]);
            let diagnostics = voice_quality::diagnose(chunk, turn.overlap, &turn.quality_flags);
            let embedding = if diagnostics.decision == SampleDecision::NoEmbedding {
                None
            } else {
                Some(self.embed_samples(chunk)?)
            };
            output.push(EmbeddedTurn { embedding });
        }
        Ok(output)
    }

    pub fn embed_samples(&self, samples: &[f32]) -> Result<Vec<f32>> {
        let mut options = FbankOptions::default();
        options.frame_opts.samp_freq = TARGET_SAMPLE_RATE as f32;
        options.frame_opts.dither = 0.0;
        options.frame_opts.snip_edges = true;
        options.mel_opts.num_bins = 80;
        options.use_energy = false;
        let computer = FbankComputer::new(options)
            .map_err(|error| EnclaveError::Embedding(format!("voice fbank: {error}")))?;
        let mut online = OnlineFeature::new(FeatureComputer::Fbank(computer));
        online.accept_waveform(TARGET_SAMPLE_RATE as f32, samples);
        online.input_finished();
        if online.features.len() < 50 {
            return Err(EnclaveError::Embedding(
                "voice turn has too few feature frames".into(),
            ));
        }
        let frame_count = online.features.len();
        let mut means = [0.0f32; 80];
        for frame in &online.features {
            for (index, value) in frame.iter().enumerate() {
                means[index] += *value;
            }
        }
        for mean in &mut means {
            *mean /= frame_count as f32;
        }
        let mut flattened = Vec::with_capacity(frame_count * 80);
        for frame in &online.features {
            for (index, value) in frame.iter().enumerate() {
                flattened.push(*value - means[index]);
            }
        }
        let input = tract_ndarray::Array3::from_shape_vec((1, frame_count, 80), flattened)
            .map_err(|error| EnclaveError::Embedding(format!("voice tensor: {error}")))?
            .into_tensor();
        let outputs = self
            .model
            .run(tvec!(input.into_tvalue()))
            .map_err(|error| EnclaveError::Embedding(format!("voice inference: {error}")))?;
        let view = outputs[0]
            .to_plain_array_view::<f32>()
            .map_err(|error| EnclaveError::Embedding(format!("voice output: {error}")))?;
        let mut embedding: Vec<f32> = view.iter().copied().collect();
        if embedding.len() != 256 {
            return Err(EnclaveError::Embedding(
                "voice embedding dimension mismatch".into(),
            ));
        }
        voice_quality::normalize(&mut embedding)?;
        Ok(embedding)
    }
}

fn verify_model_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_MODEL_BYTES
        || format!("{:x}", Sha256::digest(bytes)) != MODEL_SHA256
    {
        return Err(EnclaveError::Config(
            "voice model commitment mismatch".into(),
        ));
    }
    Ok(())
}

pub(crate) fn decode_mono_16khz(media: &[u8], mime_type: &str) -> Result<Vec<f32>> {
    let source = Box::new(Cursor::new(media.to_vec()));
    let stream = MediaSourceStream::new(source, Default::default());
    let mut hint = Hint::new();
    match mime_type {
        "audio/m4a" | "audio/mp4" => {
            hint.with_extension("m4a");
        }
        "audio/wav" | "audio/x-wav" => {
            hint.with_extension("wav");
        }
        _ => {
            return Err(EnclaveError::InvalidRequest(
                "voice decoder does not support this media type".into(),
            ))
        }
    }
    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            stream,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|error| EnclaveError::Embedding(format!("probe audio: {error}")))?;
    let mut format = probed.format;
    let track = format
        .default_track()
        .ok_or_else(|| EnclaveError::Embedding("audio has no default track".into()))?;
    let track_id = track.id;
    let source_rate = track
        .codec_params
        .sample_rate
        .ok_or_else(|| EnclaveError::Embedding("audio sample rate is missing".into()))?;
    if source_rate == 0 {
        return Err(EnclaveError::Embedding(
            "audio sample rate is invalid".into(),
        ));
    }
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|error| EnclaveError::Embedding(format!("create audio decoder: {error}")))?;
    let mut mono = Vec::new();
    loop {
        let packet = match format.next_packet() {
            Ok(packet) => packet,
            Err(SymphoniaError::IoError(error))
                if error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                break
            }
            Err(error) => {
                return Err(EnclaveError::Embedding(format!(
                    "read audio packet: {error}"
                )))
            }
        };
        if packet.track_id() != track_id {
            continue;
        }
        let decoded = match decoder.decode(&packet) {
            Ok(decoded) => decoded,
            Err(SymphoniaError::DecodeError(_)) => continue,
            Err(error) => return Err(EnclaveError::Embedding(format!("decode audio: {error}"))),
        };
        let spec = *decoded.spec();
        let channels = spec.channels.count();
        let mut buffer = SampleBuffer::<f32>::new(decoded.capacity() as u64, spec);
        buffer.copy_interleaved_ref(decoded);
        for frame in buffer.samples().chunks_exact(channels) {
            mono.push(frame.iter().copied().sum::<f32>() / channels as f32);
        }
    }
    if mono.is_empty() {
        return Err(EnclaveError::Embedding("decoded audio is empty".into()));
    }
    Ok(resample_linear(&mono, source_rate, TARGET_SAMPLE_RATE))
}

/// Encode normalized mono samples as a canonical 16 kHz PCM WAV for a bounded
/// multi-event Gemini audio window. This is deterministic and Python-free.
pub(crate) fn encode_mono_16khz_wav(samples: &[f32]) -> Result<Vec<u8>> {
    let data_len = samples
        .len()
        .checked_mul(2)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window is too large".into()))?;
    let riff_len = data_len
        .checked_add(36)
        .ok_or_else(|| EnclaveError::InvalidRequest("audio window is too large".into()))?;
    let mut output = Vec::with_capacity(data_len as usize + 44);
    output.extend_from_slice(b"RIFF");
    output.extend_from_slice(&riff_len.to_le_bytes());
    output.extend_from_slice(b"WAVEfmt ");
    output.extend_from_slice(&16_u32.to_le_bytes());
    output.extend_from_slice(&1_u16.to_le_bytes());
    output.extend_from_slice(&1_u16.to_le_bytes());
    output.extend_from_slice(&TARGET_SAMPLE_RATE.to_le_bytes());
    output.extend_from_slice(&(TARGET_SAMPLE_RATE * 2).to_le_bytes());
    output.extend_from_slice(&2_u16.to_le_bytes());
    output.extend_from_slice(&16_u16.to_le_bytes());
    output.extend_from_slice(b"data");
    output.extend_from_slice(&data_len.to_le_bytes());
    for sample in samples {
        let pcm = (sample.clamp(-1.0, 1.0) * i16::MAX as f32).round() as i16;
        output.extend_from_slice(&pcm.to_le_bytes());
    }
    Ok(output)
}

fn resample_linear(samples: &[f32], source_rate: u32, target_rate: u32) -> Vec<f32> {
    if source_rate == target_rate {
        return samples.to_vec();
    }
    let output_len = (samples.len() as u64 * target_rate as u64 / source_rate as u64) as usize;
    let ratio = source_rate as f64 / target_rate as f64;
    (0..output_len)
        .map(|index| {
            let position = index as f64 * ratio;
            let left = position.floor() as usize;
            let right = (left + 1).min(samples.len() - 1);
            let fraction = (position - left as f64) as f32;
            samples[left] * (1.0 - fraction) + samples[right] * fraction
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_model_rejects_unpinned_bytes_before_parsing() {
        assert!(
            verify_model_bytes(b"untrusted model").is_err(),
            "voice model must reject bytes outside the pinned commitment"
        );
    }

    #[test]
    fn voice_model_real_inference_is_normalized_when_configured() {
        let Some(path) = std::env::var_os("VOICE_MODEL_PATH") else {
            return;
        };
        let engine = VoiceEngine::load(Path::new(&path)).expect("pinned voice model loads");
        let samples = (0..TARGET_SAMPLE_RATE as usize * 3)
            .map(|i| {
                (i as f32 * 440.0 * std::f32::consts::TAU / TARGET_SAMPLE_RATE as f32).sin() * 0.2
            })
            .collect::<Vec<_>>();
        let vector = engine
            .embed_samples(&samples)
            .expect("real voice inference succeeds");
        assert_eq!(vector.len(), 256, "real voice embedding has 256 dimensions");
        let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 0.0001,
            "real voice embedding has unit norm"
        );
    }

    #[test]
    fn linear_resampling_preserves_endpoints_and_expected_length() {
        let input = [0.0, 0.5, 1.0, 0.5];
        let output = resample_linear(&input, 8_000, 16_000);
        assert_eq!(output.len(), 8);
        assert_eq!(output[0], 0.0);
        assert!((output[6] - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn canonical_wav_round_trips_through_the_rust_decoder() {
        let samples = vec![0.25; TARGET_SAMPLE_RATE as usize];
        let wav = encode_mono_16khz_wav(&samples).unwrap();
        let decoded = decode_mono_16khz(&wav, "audio/wav").unwrap();
        assert_eq!(decoded.len(), samples.len());
        assert!((decoded[0] - 0.25).abs() < 0.001);
    }
}
