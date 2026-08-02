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
use super::voice_quality::{self, SampleDecision, VoiceDiagnostics};

pub const EMBEDDING_SPACE: &str = "wespeaker-resnet34-lm-v1";
const DEFAULT_MODEL_PATH: &str = "/models/voice/wespeaker_en_voxceleb_resnet34_LM.onnx";
pub(crate) const TARGET_SAMPLE_RATE: u32 = 16_000;
const MAX_TURN_SAMPLES: usize = TARGET_SAMPLE_RATE as usize * 30;
const MATCH_THRESHOLD: f32 = 0.60;
const NEW_PROFILE_THRESHOLD: f32 = 0.45;
const MIN_DECISION_MARGIN: f32 = 0.08;

pub struct VoiceEngine {
    model: Arc<TypedRunnableModel>,
}

pub struct EmbeddedTurn {
    pub turn_id: String,
    pub embedding: Option<Vec<f32>>,
    pub diagnostics: VoiceDiagnostics,
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
    ) -> Result<Vec<EmbeddedTurn>> {
        let samples = decode_mono_16khz(media, mime_type)?;
        let mut output = Vec::new();
        for turn in turns {
            let start = ((turn.start_ms.max(0) as u64 * TARGET_SAMPLE_RATE as u64) / 1000) as usize;
            let end = ((turn.end_ms.max(0) as u64 * TARGET_SAMPLE_RATE as u64) / 1000) as usize;
            let end = end
                .min(samples.len())
                .min(start.saturating_add(MAX_TURN_SAMPLES));
            let chunk = &samples[start..end];
            let diagnostics = voice_quality::diagnose(chunk, turn.overlap, &turn.quality_flags);
            let embedding = if diagnostics.decision == SampleDecision::NoEmbedding {
                None
            } else {
                Some(self.embed_samples(chunk)?)
            };
            output.push(EmbeddedTurn {
                turn_id: turn.turn_id.clone(),
                embedding,
                diagnostics,
            });
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
        voice_quality::normalize(&mut embedding)?;
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

/// Resolve only a calibrated, unambiguous existing biometric binding. Names
/// are intentionally absent from this lookup and cannot merge identities.
pub fn match_existing_person(
    conn: &Connection,
    embedding: &[f32],
    channel_domain: &str,
) -> Result<Option<i64>> {
    super::voice_lineage::backfill_profile_lineage(conn)?;
    let mut statement = conn.prepare(
        "SELECT person_id,centroid FROM voice_profiles WHERE person_id IS NOT NULL \
         AND embedding_space=?1 AND channel_domain=?2 AND scorer_version=?3 \
         AND status<>'quarantined' \
         AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
             WHERE r.profile_id=voice_profiles.id AND r.active=1 \
               AND r.status IN ('quarantined','superseded','split'))",
    )?;
    let mut scores = statement
        .query_map(
            params![
                EMBEDDING_SPACE,
                channel_domain,
                voice_quality::SCORER_VERSION
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?
        .map(|row| {
            let (person_id, blob) = row?;
            Ok((
                person_id,
                voice_quality::cosine(embedding, &embedding_from_blob(&blob)?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    scores.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let Some((person_id, best)) = scores.first().copied() else {
        return Ok(None);
    };
    let second = scores.get(1).map(|candidate| candidate.1).unwrap_or(-1.0);
    Ok((best >= MATCH_THRESHOLD && best - second >= MIN_DECISION_MARGIN).then_some(person_id))
}

pub fn match_and_store_candidate(
    conn: &Connection,
    speaker_observation_id: i64,
    candidate: &EmbeddedTurn,
    channel_domain: &str,
    named_person_id: Option<i64>,
) -> Result<Option<String>> {
    super::voice_lineage::backfill_profile_lineage(conn)?;
    let diagnostics_json = serde_json::to_string(&candidate.diagnostics)?;
    conn.execute(
        "UPDATE speaker_observations SET voice_eligibility=?1,voice_diagnostics_json=?2 \
         WHERE id=?3",
        params![
            candidate.diagnostics.decision.as_str(),
            diagnostics_json,
            speaker_observation_id
        ],
    )?;
    let Some(embedding) = candidate.embedding.as_deref() else {
        return Ok(None);
    };
    if embedding.len() != 256 || !embedding.iter().all(|value| value.is_finite()) {
        return Err(EnclaveError::InvalidRequest(
            "voice embedding is invalid".into(),
        ));
    }
    let mut profiles = Vec::new();
    let mut statement = conn.prepare(
        "SELECT id,label,person_id,centroid,sample_count FROM voice_profiles \
         WHERE embedding_space=?1 AND channel_domain=?2 AND scorer_version=?3 \
         AND status<>'quarantined' \
         AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
             WHERE r.profile_id=voice_profiles.id AND r.active=1 \
               AND r.status IN ('quarantined','superseded','split'))",
    )?;
    for row in statement.query_map(
        params![
            EMBEDDING_SPACE,
            channel_domain,
            voice_quality::SCORER_VERSION
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )? {
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
        voice_quality::cosine(embedding, &right.3)
            .partial_cmp(&voice_quality::cosine(embedding, &left.3))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let best = profiles
        .first()
        .map(|profile| (profile, voice_quality::cosine(embedding, &profile.3)));
    let second = profiles
        .get(1)
        .map(|profile| voice_quality::cosine(embedding, &profile.3))
        .unwrap_or(-1.0);
    let clear_match = best.as_ref().is_some_and(|(_, score)| {
        let identity_compatible = named_person_id.is_none_or(|named| {
            best.as_ref()
                .and_then(|(profile, _)| profile.2)
                .is_none_or(|existing| existing == named)
        });
        identity_compatible && *score >= MATCH_THRESHOLD && *score - second >= MIN_DECISION_MARGIN
    });

    let may_enroll = candidate.diagnostics.decision == SampleDecision::Enroll;
    let may_match = matches!(
        candidate.diagnostics.decision,
        SampleDecision::Enroll | SampleDecision::MatchOnly
    );
    let mut representative_update = None;
    let mut outlier = false;
    let (profile_id, similarity, margin, accepted, new_profile) = if clear_match && may_match {
        let (profile, score) = best.expect("clear match has best profile");
        if may_enroll {
            let mut statement = conn.prepare(
                "SELECT s.id,s.embedding FROM voice_samples s \
                 JOIN voice_sample_profile_assignments a ON a.sample_id=s.id \
                 WHERE a.profile_id=?1 AND a.active=1 \
                 AND s.accepted=1 AND s.eligibility='enroll' AND s.outlier=0 AND s.scorer_version=?2 \
                 ORDER BY s.id DESC LIMIT 100",
            )?;
            let rows = statement
                .query_map(params![profile.0, voice_quality::SCORER_VERSION], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut sample_ids = Vec::with_capacity(rows.len() + 1);
            let mut samples = Vec::with_capacity(rows.len() + 1);
            for (id, blob) in rows.into_iter().rev() {
                sample_ids.push(Some(id));
                samples.push(embedding_from_blob(&blob)?);
            }
            outlier = voice_quality::is_profile_outlier(&samples, embedding)?;
            if !outlier {
                sample_ids.push(None);
                samples.push(embedding.to_vec());
                let representative = voice_quality::robust_representative(&samples)?;
                debug_assert!(!representative
                    .excluded_indices
                    .contains(&(samples.len() - 1)));
                representative_update = Some((profile.0, representative, sample_ids));
            }
        }
        (
            Some(profile.0),
            Some(score),
            Some(score - second),
            !outlier,
            false,
        )
    } else if may_enroll
        && (named_person_id.is_some()
            || best
                .as_ref()
                .is_none_or(|(_, score)| *score < NEW_PROFILE_THRESHOLD))
    {
        let temporary_label = format!("pending-{speaker_observation_id}");
        conn.execute(
            "INSERT INTO voice_profiles \
             (person_id,label,embedding_space,channel_domain,centroid,sample_count,scorer_version,\
              representative_kind,status) \
             VALUES (?1,?2,?3,?4,?5,1,?6,'medoid_trimmed_centroid','tentative')",
            params![
                named_person_id,
                temporary_label,
                EMBEDDING_SPACE,
                channel_domain,
                embedding_blob(embedding),
                voice_quality::SCORER_VERSION,
            ],
        )?;
        let id = conn.last_insert_rowid();
        conn.execute(
            "UPDATE voice_profiles SET label=?1 WHERE id=?2",
            params![format!("Voice {id}"), id],
        )?;
        (Some(id), None, None, true, true)
    } else {
        (
            None,
            best.map(|(_, score)| score),
            best.map(|(_, score)| score - second),
            false,
            false,
        )
    };
    let embedding_norm = embedding
        .iter()
        .map(|value| value * value)
        .sum::<f32>()
        .sqrt();
    conn.execute(
        "INSERT INTO voice_samples \
         (speaker_observation_id,voice_profile_id,embedding_space,channel_domain,embedding, \
          quality_score,diagnostics_json,quality_version,scorer_version,eligibility,duration_ms,\
          speech_ratio,snr_proxy_db,clipping_ratio,silence_ratio,embedding_norm,outlier,\
          similarity,decision_margin,accepted) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        params![
            speaker_observation_id,
            profile_id,
            EMBEDDING_SPACE,
            channel_domain,
            embedding_blob(embedding),
            candidate.diagnostics.speech_ratio * (1.0 - candidate.diagnostics.clipping_ratio),
            diagnostics_json,
            candidate.diagnostics.quality_version,
            voice_quality::SCORER_VERSION,
            candidate.diagnostics.decision.as_str(),
            candidate.diagnostics.duration_ms,
            candidate.diagnostics.speech_ratio,
            candidate.diagnostics.snr_proxy_db,
            candidate.diagnostics.clipping_ratio,
            candidate.diagnostics.silence_ratio,
            embedding_norm,
            outlier as i64,
            similarity,
            margin,
            accepted as i64
        ],
    )?;
    let sample_id = conn.last_insert_rowid();
    if new_profile {
        conn.execute(
            "UPDATE voice_profiles SET medoid_sample_id=?1 WHERE id=?2",
            params![sample_id, profile_id],
        )?;
    }
    if let Some(profile_id) = profile_id {
        super::voice_lineage::record_sample_assignment(conn, profile_id, sample_id)?;
    }
    if let Some((profile_id, representative, sample_ids)) = representative_update {
        let medoid_sample_id = sample_ids[representative.medoid_index].unwrap_or(sample_id);
        let accepted_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM voice_samples s \
             JOIN voice_sample_profile_assignments a ON a.sample_id=s.id \
             WHERE a.profile_id=?1 AND a.active=1 AND s.accepted=1 \
             AND s.eligibility='enroll' AND s.outlier=0 AND s.scorer_version=?2",
            params![profile_id, voice_quality::SCORER_VERSION],
            |row| row.get(0),
        )?;
        conn.execute(
            "UPDATE voice_profiles SET centroid=?1,sample_count=?2,person_id=COALESCE(person_id,?3),\
             scorer_version=?4,representative_kind='medoid_trimmed_centroid',medoid_sample_id=?5,\
             status=CASE WHEN ?2>=3 THEN 'stable' ELSE status END,\
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?6",
            params![
                embedding_blob(&representative.centroid),
                accepted_count,
                named_person_id,
                voice_quality::SCORER_VERSION,
                medoid_sample_id,
                profile_id
            ],
        )?;
        super::voice_lineage::refresh_profile_revision(
            conn,
            profile_id,
            "representative_recomputed",
        )?;
    } else if let Some(profile_id) = profile_id {
        super::voice_lineage::refresh_profile_revision(conn, profile_id, "sample_assigned")?;
    }
    let Some(profile_id) = profile_id else {
        return Ok(None);
    };
    if !accepted {
        return Ok(None);
    }
    Ok(Some(conn.query_row(
        "SELECT COALESCE(p.display_name,v.label) FROM voice_profiles v \
         LEFT JOIN people p ON p.id=v.person_id WHERE v.id=?1",
        [profile_id],
        |row| row.get(0),
    )?))
}

/// Recompute robust representatives from already-encrypted raw embeddings.
/// This is bounded, idempotent, and makes no Gemini call.
pub fn reconcile_profiles(conn: &Connection, limit: usize) -> Result<usize> {
    if limit == 0 {
        return Ok(0);
    }
    super::voice_lineage::backfill_profile_lineage(conn)?;
    let mut statement = conn.prepare(
        "SELECT id FROM voice_profiles WHERE status<>'quarantined' AND \
         (scorer_version<>?1 OR representative_kind<>'medoid_trimmed_centroid') \
         AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
             WHERE r.profile_id=voice_profiles.id AND r.active=1 \
               AND r.status IN ('quarantined','superseded','split')) \
         ORDER BY id LIMIT ?2",
    )?;
    let profile_ids = statement
        .query_map(
            params![voice_quality::SCORER_VERSION, limit.min(100) as i64],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut updated = 0;
    for profile_id in profile_ids {
        let mut samples_statement = conn.prepare(
            "SELECT s.id,s.embedding FROM voice_samples s \
             JOIN voice_sample_profile_assignments a ON a.sample_id=s.id \
             WHERE a.profile_id=?1 AND a.active=1 \
             AND s.accepted=1 AND s.eligibility='enroll' AND s.outlier=0 \
             ORDER BY s.id DESC LIMIT 100",
        )?;
        let rows = samples_statement
            .query_map([profile_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if rows.is_empty() {
            continue;
        }
        let mut sample_ids = Vec::with_capacity(rows.len());
        let mut samples = Vec::with_capacity(rows.len());
        for (id, blob) in rows.into_iter().rev() {
            sample_ids.push(id);
            samples.push(embedding_from_blob(&blob)?);
        }
        let representative = voice_quality::robust_representative(&samples)?;
        let medoid_sample_id = sample_ids[representative.medoid_index];
        conn.execute(
            "UPDATE voice_profiles SET centroid=?1,sample_count=?2,scorer_version=?3,\
             representative_kind='medoid_trimmed_centroid',medoid_sample_id=?4,\
             status=CASE WHEN ?2>=3 THEN 'stable' ELSE status END,\
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?5",
            params![
                embedding_blob(&representative.centroid),
                samples.len() as i64 - representative.excluded_indices.len() as i64,
                voice_quality::SCORER_VERSION,
                medoid_sample_id,
                profile_id
            ],
        )?;
        super::voice_lineage::refresh_profile_revision(conn, profile_id, "bounded_reconciliation")?;
        updated += 1;
    }
    Ok(updated)
}

#[cfg(test)]
pub fn match_and_store(
    conn: &Connection,
    speaker_observation_id: i64,
    embedding: &[f32],
    channel_domain: &str,
    named_person_id: Option<i64>,
    _quality_score: f64,
) -> Result<String> {
    let candidate = EmbeddedTurn {
        turn_id: format!("test-{speaker_observation_id}"),
        embedding: Some(embedding.to_vec()),
        diagnostics: voice_quality::diagnose(
            &vec![0.2; voice_quality::SAMPLE_RATE as usize * 4],
            false,
            &[],
        ),
    };
    Ok(match_and_store_candidate(
        conn,
        speaker_observation_id,
        &candidate,
        channel_domain,
        named_person_id,
    )?
    .unwrap_or_else(|| "Unknown speaker".into()))
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
        for turn in ["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"] {
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
        voice_quality::normalize(&mut ambiguous).unwrap();
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

    fn candidate(turn_id: &str, embedding: Vec<f32>, seconds: usize) -> EmbeddedTurn {
        EmbeddedTurn {
            turn_id: turn_id.into(),
            embedding: Some(embedding),
            diagnostics: voice_quality::diagnose(
                &vec![0.2; voice_quality::SAMPLE_RATE as usize * seconds],
                false,
                &[],
            ),
        }
    }

    #[test]
    fn match_only_samples_link_but_never_change_the_robust_representative() {
        let conn = voice_db();
        let enrolled = candidate("t1", unit(0), 4);
        assert_eq!(
            match_and_store_candidate(&conn, 1, &enrolled, "mac-mic", None).unwrap(),
            Some("Voice 1".into())
        );
        let before: (Vec<u8>, i64) = conn
            .query_row(
                "SELECT centroid,sample_count FROM voice_profiles WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let match_only = candidate("t2", unit(0), 2);
        assert_eq!(
            match_and_store_candidate(&conn, 2, &match_only, "mac-mic", None).unwrap(),
            Some("Voice 1".into())
        );
        let after: (Vec<u8>, i64) = conn
            .query_row(
                "SELECT centroid,sample_count FROM voice_profiles WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(before, after);
        let eligibility: String = conn
            .query_row(
                "SELECT eligibility FROM voice_samples WHERE speaker_observation_id=2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(eligibility, "match_only");
    }

    #[test]
    fn bounded_reconciliation_replaces_legacy_running_mean_without_gemini() {
        let conn = voice_db();
        for observation_id in 1..=3 {
            match_and_store(&conn, observation_id, &unit(0), "legacy-domain", None, 0.9).unwrap();
        }
        conn.execute(
            "UPDATE voice_profiles SET scorer_version=1,representative_kind='running_mean'",
            [],
        )
        .unwrap();
        assert_eq!(reconcile_profiles(&conn, 1).unwrap(), 1);
        let state: (i64, String, i64, Option<i64>) = conn
            .query_row(
                "SELECT scorer_version,representative_kind,sample_count,medoid_sample_id \
                 FROM voice_profiles",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(state.0, voice_quality::SCORER_VERSION);
        assert_eq!(state.1, "medoid_trimmed_centroid");
        assert_eq!(state.2, 3);
        assert!(state.3.is_some());
        assert_eq!(reconcile_profiles(&conn, 1).unwrap(), 0);
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
