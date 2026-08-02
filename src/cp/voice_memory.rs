//! Persistent server-side speaker memory.
//!
//! Audio decoding, Kaldi-compatible filterbanks, and WeSpeaker inference are
//! implemented in Rust. Voice embeddings never return to a client and are
//! stored only in the user's enclave-encrypted SQLite database. Gemini supplies
//! turn boundaries; this module independently fingerprints each sufficiently
//! long turn and matches it against prior profiles in the same capture domain.

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use kaldi_native_fbank::{
    fbank::{FbankComputer, FbankOptions},
    online::{FeatureComputer, OnlineFeature},
};
use rusqlite::{params, Connection};
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

pub const EMBEDDING_SPACE: &str = "wespeaker-resnet34-lm-v1";
const DEFAULT_MODEL_PATH: &str = "/models/voice/wespeaker_en_voxceleb_resnet34_LM.onnx";
pub(crate) const TARGET_SAMPLE_RATE: u32 = 16_000;
const MIN_TURN_SAMPLES: usize = TARGET_SAMPLE_RATE as usize;
const MAX_TURN_SAMPLES: usize = TARGET_SAMPLE_RATE as usize * 30;
const MATCH_THRESHOLD: f32 = 0.60;
const NEW_PROFILE_THRESHOLD: f32 = 0.45;
const MIN_DECISION_MARGIN: f32 = 0.08;

pub struct VoiceEngine {
    model: Arc<TypedRunnableModel>,
}

impl VoiceEngine {
    pub fn from_env() -> Option<Arc<Self>> {
        let path = std::env::var("VOICE_MODEL_PATH").unwrap_or_else(|_| DEFAULT_MODEL_PATH.into());
        match Self::load(Path::new(&path)) {
            Ok(engine) => Some(Arc::new(engine)),
            Err(error) => {
                tracing::warn!(error = %error, "voice embedding model unavailable");
                None
            }
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.is_file() {
            return Err(EnclaveError::Config(format!(
                "voice model not found at {}",
                path.display()
            )));
        }
        let model = tract_onnx::onnx()
            .model_for_path(path)
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
    ) -> Result<Vec<(String, Vec<f32>, f64)>> {
        let samples = decode_mono_16khz(media, mime_type)?;
        let mut output = Vec::new();
        for turn in turns {
            let start = ((turn.start_ms.max(0) as u64 * TARGET_SAMPLE_RATE as u64) / 1000) as usize;
            let end = ((turn.end_ms.max(0) as u64 * TARGET_SAMPLE_RATE as u64) / 1000) as usize;
            let end = end
                .min(samples.len())
                .min(start.saturating_add(MAX_TURN_SAMPLES));
            if end.saturating_sub(start) < MIN_TURN_SAMPLES {
                continue;
            }
            let chunk = &samples[start..end];
            let energy =
                chunk.iter().map(|value| value.abs() as f64).sum::<f64>() / chunk.len() as f64;
            if energy < 0.0005 {
                continue;
            }
            output.push((turn.turn_id.clone(), self.embed_samples(chunk)?, energy));
        }
        Ok(output)
    }

    fn embed_samples(&self, samples: &[f32]) -> Result<Vec<f32>> {
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
        for frame in online.features {
            flattened.extend(
                frame
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| value - means[index]),
            );
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
        normalize(&mut embedding)?;
        Ok(embedding)
    }
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

fn normalize(vector: &mut [f32]) -> Result<()> {
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if !norm.is_finite() || norm <= f32::EPSILON {
        return Err(EnclaveError::Embedding(
            "voice embedding has invalid norm".into(),
        ));
    }
    for value in vector {
        *value /= norm;
    }
    Ok(())
}

fn embedding_blob(vector: &[f32]) -> Vec<u8> {
    vector
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn embedding_from_blob(blob: &[u8]) -> Result<Vec<f32>> {
    if blob.is_empty() || !blob.len().is_multiple_of(4) {
        return Err(EnclaveError::Db(rusqlite::Error::InvalidQuery));
    }
    Ok(blob
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return -1.0;
    }
    a.iter().zip(b).map(|(left, right)| left * right).sum()
}

pub fn match_and_store(
    conn: &Connection,
    speaker_observation_id: i64,
    embedding: &[f32],
    channel_domain: &str,
    named_person_id: Option<i64>,
    quality_score: f64,
) -> Result<String> {
    if embedding.len() != 256 || !embedding.iter().all(|value| value.is_finite()) {
        return Err(EnclaveError::InvalidRequest(
            "voice embedding is invalid".into(),
        ));
    }
    let mut profiles = Vec::new();
    let mut statement = conn.prepare(
        "SELECT id,label,person_id,centroid,sample_count FROM voice_profiles \
         WHERE embedding_space=?1 AND channel_domain=?2 AND status<>'quarantined'",
    )?;
    for row in statement.query_map(params![EMBEDDING_SPACE, channel_domain], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })? {
        let (id, label, person_id, blob, sample_count) = row?;
        profiles.push((
            id,
            label,
            person_id,
            embedding_from_blob(&blob)?,
            sample_count,
        ));
    }
    profiles.sort_by(|left, right| {
        cosine(embedding, &right.3)
            .partial_cmp(&cosine(embedding, &left.3))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let best = profiles
        .first()
        .map(|profile| (profile, cosine(embedding, &profile.3)));
    let second = profiles
        .get(1)
        .map(|profile| cosine(embedding, &profile.3))
        .unwrap_or(-1.0);
    let clear_match = best.as_ref().is_some_and(|(_, score)| {
        let identity_compatible = named_person_id.is_none_or(|named| {
            best.as_ref()
                .and_then(|(profile, _)| profile.2)
                .is_none_or(|existing| existing == named)
        });
        identity_compatible && *score >= MATCH_THRESHOLD && *score - second >= MIN_DECISION_MARGIN
    });

    let (profile_id, similarity, margin, accepted) = if clear_match {
        let (profile, score) = best.unwrap();
        let old_weight = profile.4.max(1) as f32;
        let mut centroid: Vec<f32> = profile
            .3
            .iter()
            .zip(embedding)
            .map(|(old, new)| (old * old_weight + new) / (old_weight + 1.0))
            .collect();
        normalize(&mut centroid)?;
        conn.execute(
            "UPDATE voice_profiles SET centroid=?1,sample_count=sample_count+1, \
             person_id=COALESCE(person_id,?2),status=CASE WHEN sample_count+1>=5 THEN 'stable' ELSE status END, \
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?3",
            params![embedding_blob(&centroid), named_person_id, profile.0],
        )?;
        (Some(profile.0), Some(score), Some(score - second), true)
    } else if named_person_id.is_some()
        || best
            .as_ref()
            .is_none_or(|(_, score)| *score < NEW_PROFILE_THRESHOLD)
    {
        let temporary_label = format!("pending-{speaker_observation_id}");
        conn.execute(
            "INSERT INTO voice_profiles \
             (person_id,label,embedding_space,channel_domain,centroid,sample_count,status) \
             VALUES (?1,?2,?3,?4,?5,1,'tentative')",
            params![
                named_person_id,
                temporary_label,
                EMBEDDING_SPACE,
                channel_domain,
                embedding_blob(embedding)
            ],
        )?;
        let id = conn.last_insert_rowid();
        conn.execute(
            "UPDATE voice_profiles SET label=?1 WHERE id=?2",
            params![format!("Voice {id}"), id],
        )?;
        (Some(id), None, None, true)
    } else {
        (
            None,
            best.map(|(_, score)| score),
            best.map(|(_, score)| score - second),
            false,
        )
    };
    conn.execute(
        "INSERT INTO voice_samples \
         (speaker_observation_id,voice_profile_id,embedding_space,channel_domain,embedding, \
          quality_score,similarity,decision_margin,accepted) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            speaker_observation_id,
            profile_id,
            EMBEDDING_SPACE,
            channel_domain,
            embedding_blob(embedding),
            quality_score,
            similarity,
            margin,
            accepted as i64
        ],
    )?;
    let Some(profile_id) = profile_id else {
        return Ok("Unknown speaker".into());
    };
    Ok(conn.query_row(
        "SELECT COALESCE(p.display_name,v.label) FROM voice_profiles v \
         LEFT JOIN people p ON p.id=v.person_id WHERE v.id=?1",
        [profile_id],
        |row| row.get(0),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::media::init_schema;

    fn unit(index: usize) -> Vec<f32> {
        let mut vector = vec![0.0; 256];
        vector[index] = 1.0;
        vector
    }

    fn voice_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO capture_sessions(id,device_id,install_id,started_at,last_event_at,schema_version) \
             VALUES ('s','d','i','2026-01-01T00:00:00Z','2026-01-01T00:00:01Z',2)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO capture_streams(id,capture_session_id,device_id,stream_kind) VALUES ('st','s','d','mic')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO capture_events(event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence, \
             source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes,clock_uncertainty_ms, \
             asset_id,manifest_digest) VALUES ('e','d','i','s','st','mic',0,'2026-01-01T00:00:00Z','1', \
             '2026-01-01T00:00:00Z','2026-01-01T00:00:01Z','UTC',0,1,'a', \
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
            [],
        ).unwrap();
        for turn in ["t1", "t2", "t3"] {
            conn.execute(
                "INSERT INTO speaker_observations(event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text) \
                 VALUES ('e',?1,'speaker-1','2026-01-01T00:00:00Z','2026-01-01T00:00:01Z','x')",
                [turn],
            ).unwrap();
        }
        conn
    }

    #[test]
    fn matching_creates_then_reuses_a_profile_but_quarantines_ambiguous_samples() {
        let conn = voice_db();
        let first = match_and_store(&conn, 1, &unit(0), "mic", None, 0.9).unwrap();
        assert_eq!(first, "Voice 1");
        let second = match_and_store(&conn, 2, &unit(0), "mic", None, 0.9).unwrap();
        assert_eq!(second, "Voice 1");

        conn.execute(
            "INSERT INTO voice_profiles(label,embedding_space,channel_domain,centroid,sample_count,status) \
             VALUES ('Voice 2',?1,'mic',?2,1,'tentative')",
            params![EMBEDDING_SPACE, embedding_blob(&unit(1))],
        ).unwrap();
        let mut ambiguous = vec![0.0; 256];
        ambiguous[0] = 0.72;
        ambiguous[1] = 0.69;
        normalize(&mut ambiguous).unwrap();
        assert_eq!(
            match_and_store(&conn, 3, &ambiguous, "mic", None, 0.8).unwrap(),
            "Unknown speaker"
        );
        let accepted: i64 = conn
            .query_row(
                "SELECT accepted FROM voice_samples WHERE speaker_observation_id=3",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(accepted, 0);
    }

    #[test]
    fn linear_resampling_preserves_endpoints_and_expected_length() {
        let input = vec![0.0, 1.0, 0.0, -1.0];
        let output = resample_linear(&input, 4, 8);
        assert_eq!(output.len(), 8);
        assert_eq!(output[0], 0.0);
        assert!((output[2] - 1.0).abs() < 0.001);
    }

    #[test]
    fn assembled_audio_wav_round_trips_through_the_rust_decoder() {
        let samples = (0..TARGET_SAMPLE_RATE)
            .map(|index| ((index as f32 / 40.0).sin()) * 0.25)
            .collect::<Vec<_>>();
        let wav = encode_mono_16khz_wav(&samples).unwrap();
        let decoded = decode_mono_16khz(&wav, "audio/wav").unwrap();
        assert_eq!(decoded.len(), samples.len());
        assert!((decoded[1_000] - samples[1_000]).abs() < 0.001);
    }
}
