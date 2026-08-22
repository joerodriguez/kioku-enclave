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

use super::isotime;
use super::media::AudioTurn;
use super::voice_quality::{self, SampleDecision, VoiceDiagnostics};

pub const EMBEDDING_SPACE: &str = "wespeaker-resnet34-lm-v1";
pub const MODEL_SHA256: &str = "e9848563da86f263117134dfd7ad63c92355b37de492b55e325400c9d9c39012";
const DEFAULT_MODEL_PATH: &str = "/models/voice/wespeaker_en_voxceleb_resnet34_LM.onnx";
pub(crate) const TARGET_SAMPLE_RATE: u32 = 16_000;
const MAX_TURN_SAMPLES: usize = TARGET_SAMPLE_RATE as usize * 30;
pub(crate) const MATCH_THRESHOLD: f32 = 0.60;
pub(crate) const NEW_PROFILE_THRESHOLD: f32 = 0.45;
pub(crate) const MIN_DECISION_MARGIN: f32 = 0.08;

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
/// Matches an embedding against existing known persons within the same domain.
/// Checks within-domain representatives with calibrated decision margin.
pub fn match_existing_person(
    conn: &Connection,
    embedding: &[f32],
    channel_domain: &str,
) -> Result<Option<i64>> {
    super::voice_lineage::backfill_profile_lineage(conn)?;

    // 1. Check within-domain representatives using active accepted bindings
    let mut stmt = conn.prepare(
        "SELECT b.person_id, COALESCE(r.centroid, v.centroid) AS centroid \
         FROM voice_profiles v \
         JOIN profile_identity_bindings b \
           ON b.voice_profile_id = v.id AND b.active = 1 AND b.state = 'accepted' \
         LEFT JOIN voice_profile_representatives r \
           ON r.profile_id = v.id AND r.channel_domain = ?2 AND r.scorer_version = ?3 \
         WHERE v.embedding_space = ?1 \
           AND (v.channel_domain = ?2 OR r.centroid IS NOT NULL) \
           AND v.status <> 'quarantined' \
           AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions rev \
               WHERE rev.profile_id = v.id AND rev.active = 1 \
                 AND rev.status IN ('quarantined', 'superseded', 'split'))",
    )?;

    let scores = stmt
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

    // Group candidate scores per person taking MAX(score)
    let mut person_best: std::collections::HashMap<i64, f32> = std::collections::HashMap::new();
    for (person_id, score) in scores {
        let entry = person_best.entry(person_id).or_insert(score);
        if score > *entry {
            *entry = score;
        }
    }

    let mut person_scores: Vec<(i64, f32)> = person_best.into_iter().collect();
    person_scores.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if let Some((person_id, best)) = person_scores.first().copied() {
        let second = person_scores
            .get(1)
            .map(|candidate| candidate.1)
            .unwrap_or(-1.0);
        if best >= MATCH_THRESHOLD && best - second >= MIN_DECISION_MARGIN {
            return Ok(Some(person_id));
        }
    }

    Ok(None)
}

pub fn match_and_store_candidate(
    conn: &Connection,
    speaker_observation_id: i64,
    candidate: &EmbeddedTurn,
    channel_domain: &str,
    named_person_id: Option<i64>,
    embedding_job_id: Option<i64>,
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
          similarity,decision_margin,accepted,embedding_job_id) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
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
            accepted as i64,
            embedding_job_id
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
        sync_recompute_profile_representatives(conn, profile_id)?;
    } else if let Some(profile_id) = profile_id {
        super::voice_lineage::refresh_profile_revision(conn, profile_id, "sample_assigned")?;
        sync_recompute_profile_representatives(conn, profile_id)?;
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
        sync_recompute_profile_representatives(conn, profile_id)?;
        updated += 1;
    }
    Ok(updated)
}

/// Synchronously recomputes voice profile domain representatives, centroid, medoid,
/// and stability status following sample deletion.
pub fn sync_recompute_profile_representatives(conn: &Connection, profile_id: i64) -> Result<()> {
    super::voice_lineage::backfill_profile_lineage(conn)?;
    let mutation_stamp: String =
        conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
            row.get(0)
        })?;
    sync_recompute_profile_representatives_at(conn, profile_id, &mutation_stamp)
}

pub(crate) fn sync_recompute_profile_representatives_at(
    conn: &Connection,
    profile_id: i64,
    mutation_stamp: &str,
) -> Result<()> {
    if mutation_stamp.is_empty()
        || mutation_stamp.len() > 64
        || isotime::parse_epoch_millis(mutation_stamp)
            .is_none_or(|millis| isotime::format_epoch_millis(millis) != mutation_stamp)
    {
        return Err(EnclaveError::InvalidRequest(
            "voice purge mutation stamp is invalid".into(),
        ));
    }
    // 1. Find all distinct channel domains for this profile
    let domains: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT channel_domain FROM voice_profile_representatives WHERE profile_id = ?1 \
             UNION \
             SELECT DISTINCT s.channel_domain FROM voice_samples s \
             JOIN voice_sample_profile_assignments a ON a.sample_id = s.id \
             WHERE a.profile_id = ?1 AND a.active = 1 ORDER BY channel_domain",
        )?;
        let rows = stmt
            .query_map([profile_id], |r| r.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        rows
    };

    for domain in domains {
        let mut stmt = conn.prepare(
            "SELECT s.id, s.embedding FROM voice_samples s \
             JOIN voice_sample_profile_assignments a ON a.sample_id = s.id \
             WHERE a.profile_id = ?1 AND a.active = 1 AND s.channel_domain = ?2 \
               AND s.accepted = 1 AND s.eligibility = 'enroll' AND s.outlier = 0 \
             ORDER BY s.id ASC",
        )?;
        let rows = stmt
            .query_map(params![profile_id, domain], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if rows.is_empty() {
            conn.execute(
                "DELETE FROM voice_profile_representatives WHERE profile_id = ?1 AND channel_domain = ?2",
                params![profile_id, domain],
            )?;
        } else {
            let mut sample_ids = Vec::with_capacity(rows.len());
            let mut samples = Vec::with_capacity(rows.len());
            for (id, blob) in rows {
                sample_ids.push(id);
                samples.push(embedding_from_blob(&blob)?);
            }
            let rep = voice_quality::robust_representative(&samples)?;
            let medoid_id = sample_ids[rep.medoid_index];
            let effective_count = (samples.len() - rep.excluded_indices.len()) as i64;
            conn.execute(
                "INSERT INTO voice_profile_representatives \
                 (profile_id, channel_domain, centroid, sample_count, medoid_sample_id, scorer_version, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) \
                 ON CONFLICT(profile_id, channel_domain) DO UPDATE SET \
                     centroid = excluded.centroid, \
                     sample_count = excluded.sample_count, \
                     medoid_sample_id = excluded.medoid_sample_id, \
                     scorer_version = excluded.scorer_version, \
                     updated_at = excluded.updated_at",
                params![
                    profile_id,
                    domain,
                    embedding_blob(&rep.centroid),
                    effective_count,
                    medoid_id,
                    voice_quality::SCORER_VERSION,
                    mutation_stamp,
                ],
            )?;
        }
    }

    // 2. Recompute overall profile centroid across all active accepted samples
    let mut all_stmt = conn.prepare(
        "SELECT s.id, s.embedding FROM voice_samples s \
         JOIN voice_sample_profile_assignments a ON a.sample_id = s.id \
         WHERE a.profile_id = ?1 AND a.active = 1 \
           AND s.accepted = 1 AND s.eligibility = 'enroll' AND s.outlier = 0 \
         ORDER BY s.id ASC",
    )?;
    let all_rows = all_stmt
        .query_map([profile_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if all_rows.is_empty() {
        conn.execute(
            "UPDATE voice_profiles \
             SET status = 'quarantined', sample_count = 0, medoid_sample_id = NULL, person_id = NULL, \
                 updated_at = ?2 \
             WHERE id = ?1",
            params![profile_id, mutation_stamp],
        )?;
        conn.execute(
            "UPDATE profile_identity_bindings SET active = 0, updated_at = ?2 \
             WHERE voice_profile_id = ?1",
            params![profile_id, mutation_stamp],
        )?;
    } else {
        let mut sample_ids = Vec::with_capacity(all_rows.len());
        let mut samples = Vec::with_capacity(all_rows.len());
        for (id, blob) in all_rows {
            sample_ids.push(id);
            samples.push(embedding_from_blob(&blob)?);
        }
        let rep = voice_quality::robust_representative(&samples)?;
        let medoid_id = sample_ids[rep.medoid_index];
        let effective_count = (samples.len() - rep.excluded_indices.len()) as i64;
        conn.execute(
            "UPDATE voice_profiles \
             SET centroid = ?1, sample_count = ?2, medoid_sample_id = ?3, \
                 scorer_version = ?4, representative_kind = 'medoid_trimmed_centroid', \
                 status = CASE WHEN ?2 >= 3 THEN 'stable' ELSE 'tentative' END, \
                 updated_at = ?6 \
             WHERE id = ?5",
            params![
                embedding_blob(&rep.centroid),
                effective_count,
                medoid_id,
                voice_quality::SCORER_VERSION,
                profile_id,
                mutation_stamp,
            ],
        )?;
    }

    super::voice_lineage::refresh_profile_revision_at(
        conn,
        profile_id,
        "synchronous_purge_recompute",
        mutation_stamp,
    )?;
    Ok(())
}

/// Represents a row in the `voice_embedding_jobs` table.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub struct EmbeddingJobRecord {
    pub id: i64,
    pub speaker_observation_id: i64,
    pub embedding_space: String,
    pub processor_version: i64,
    pub quality_version: i64,
    pub scorer_version: i64,
    pub state: String,
    pub lease_owner: Option<String>,
    pub lease_token: Option<String>,
    pub lease_until: Option<String>,
    pub attempt_count: i64,
    pub next_attempt_at: Option<String>,
    pub error_code: Option<String>,
}

/// Enqueues a speaker observation into the voice embedding jobs table.
pub fn enqueue_embedding_job(conn: &Connection, speaker_observation_id: i64) -> Result<i64> {
    let mut stmt = conn.prepare(
        "INSERT INTO voice_embedding_jobs (
            speaker_observation_id, embedding_space, processor_version, quality_version, scorer_version, state, attempt_count, next_attempt_at
         ) VALUES (?1, ?2, 1, 1, ?3, 'pending', 0, NULL)
         ON CONFLICT(speaker_observation_id, embedding_space, processor_version, quality_version, scorer_version) DO UPDATE SET
            state = CASE WHEN state IN ('failed', 'retry_wait') THEN 'pending' ELSE state END,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         RETURNING id",
    )?;
    let id: i64 = stmt.query_row(
        params![
            speaker_observation_id,
            EMBEDDING_SPACE,
            voice_quality::SCORER_VERSION
        ],
        |r| r.get(0),
    )?;
    Ok(id)
}

/// Leases up to `limit` pending or expired voice embedding jobs.
pub fn lease_embedding_jobs(
    conn: &Connection,
    lease_owner: &str,
    lease_token: &str,
    now: &str,
    lease_duration_seconds: i64,
    limit: usize,
) -> Result<Vec<EmbeddingJobRecord>> {
    let lease_until = isotime::add_seconds(now, lease_duration_seconds as f64);
    let mut select_stmt = conn.prepare(
        "SELECT id, speaker_observation_id, embedding_space, processor_version, quality_version, scorer_version, \
                state, lease_owner, lease_token, lease_until, attempt_count, next_attempt_at, error_code \
         FROM voice_embedding_jobs \
         WHERE (state IN ('pending', 'retry_wait') AND (next_attempt_at IS NULL OR next_attempt_at <= ?1)) \
            OR (state = 'processing' AND lease_until < ?1) \
         ORDER BY id ASC \
         LIMIT ?2",
    )?;

    let candidates = select_stmt
        .query_map(params![now, limit as i64], |r| {
            Ok(EmbeddingJobRecord {
                id: r.get(0)?,
                speaker_observation_id: r.get(1)?,
                embedding_space: r.get(2)?,
                processor_version: r.get(3)?,
                quality_version: r.get(4)?,
                scorer_version: r.get(5)?,
                state: r.get(6)?,
                lease_owner: r.get(7)?,
                lease_token: r.get(8)?,
                lease_until: r.get(9)?,
                attempt_count: r.get(10)?,
                next_attempt_at: r.get(11)?,
                error_code: r.get(12)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut leased = Vec::new();
    let mut update_stmt = conn.prepare(
        "UPDATE voice_embedding_jobs \
         SET state = 'processing', lease_owner = ?1, lease_token = ?2, lease_until = ?3, \
             attempt_count = attempt_count + 1, updated_at = ?4 \
         WHERE id = ?5 AND ( \
             (state IN ('pending', 'retry_wait') AND (next_attempt_at IS NULL OR next_attempt_at <= ?4)) \
             OR (state = 'processing' AND lease_until < ?4) \
         )",
    )?;

    for mut job in candidates {
        let changed =
            update_stmt.execute(params![lease_owner, lease_token, lease_until, now, job.id])?;
        if changed > 0 {
            job.state = "processing".to_string();
            job.lease_owner = Some(lease_owner.to_string());
            job.lease_token = Some(lease_token.to_string());
            job.lease_until = Some(lease_until.clone());
            job.attempt_count += 1;
            leased.push(job);
        }
    }

    Ok(leased)
}

/// Marks a voice embedding job as completed (ready) or failed/retry_wait.
///
/// A successful completion may carry an annotation `error_code` (for example a
/// quality-policy abstention) meaning "settled: no sample can ever be produced";
/// that is a terminal non-degrading state, distinct from `failed`.
pub fn complete_embedding_job(
    conn: &Connection,
    job_id: i64,
    lease_token: &str,
    success: bool,
    error_code: Option<&str>,
    retry_at: Option<&str>,
) -> Result<()> {
    if success {
        conn.execute(
            "UPDATE voice_embedding_jobs \
             SET state = 'ready', lease_owner = NULL, lease_token = NULL, lease_until = NULL, \
                 error_code = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
             WHERE id = ?2 AND lease_token = ?3",
            params![error_code, job_id, lease_token],
        )?;
    } else {
        conn.execute(
            "UPDATE voice_embedding_jobs \
             SET state = CASE WHEN attempt_count >= 3 THEN 'failed' ELSE 'retry_wait' END, \
                 next_attempt_at = CASE WHEN attempt_count >= 3 THEN NULL ELSE COALESCE(?1, strftime('%Y-%m-%dT%H:%M:%fZ','now', '+60 seconds')) END, \
                 lease_owner = NULL, lease_token = NULL, lease_until = NULL, \
                 error_code = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
             WHERE id = ?3 AND lease_token = ?4",
            params![retry_at, error_code, job_id, lease_token],
        )?;
    }
    Ok(())
}

/// Slices one decoded 16-kHz mono source event by the recorded within-event
/// millisecond offsets. Clamped to the decoded length; an inverted or fully
/// out-of-range interval yields an empty slice rather than panicking.
pub fn slice_observation_source(decoded: &[f32], start_ms: i64, end_ms: i64) -> &[f32] {
    let s_ms = start_ms.max(0) as u64;
    let e_ms = end_ms.max(0) as u64;
    let sample_start = ((s_ms * TARGET_SAMPLE_RATE as u64) / 1000) as usize;
    let sample_end = (((e_ms * TARGET_SAMPLE_RATE as u64) / 1000) as usize).min(decoded.len());
    if sample_end > sample_start {
        &decoded[sample_start..sample_end]
    } else {
        &[]
    }
}

/// Terminally fails a voice embedding job regardless of remaining attempts.
///
/// Used when the failure is provably unrecoverable: the retained raw media was
/// pruned or expired, or the media deterministically fails to decode. Terminal
/// failure makes member episodes derive `degraded`.
pub fn fail_embedding_job_terminal(
    conn: &Connection,
    job_id: i64,
    lease_token: &str,
    error_code: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE voice_embedding_jobs \
         SET state = 'failed', next_attempt_at = NULL, \
             lease_owner = NULL, lease_token = NULL, lease_until = NULL, \
             error_code = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id = ?2 AND lease_token = ?3",
        params![error_code, job_id, lease_token],
    )?;
    Ok(())
}

/// Extends the lease timeout for an in-progress embedding job.
pub fn renew_embedding_job_lease(
    conn: &Connection,
    job_id: i64,
    lease_token: &str,
    extension_seconds: i64,
) -> Result<bool> {
    let count = conn.execute(
        "UPDATE voice_embedding_jobs \
         SET lease_until = strftime('%Y-%m-%dT%H:%M:%fZ','now', '+' || ?1 || ' seconds'), \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id = ?2 AND lease_token = ?3 AND state = 'processing'",
        params![extension_seconds, job_id, lease_token],
    )?;
    Ok(count > 0)
}

/// Recalculates and persists speaker_processing_status for all episodes where the
/// derived status from member voice embedding jobs differs from the stored value.
pub fn recalculate_all_episode_speaker_processing_status(conn: &Connection) -> Result<usize> {
    let count = conn.execute(
        "UPDATE episodes SET speaker_processing_status = CASE \
             WHEN EXISTS ( \
                 SELECT 1 FROM episode_members m \
                 JOIN utterances u ON u.id = m.record_id AND m.record_type = 'utterance' \
                 JOIN voice_embedding_jobs j ON j.speaker_observation_id = u.speaker_observation_id \
                 WHERE m.episode_id = episodes.id AND j.state IN ('pending', 'processing', 'retry_wait') \
             ) THEN 'pending' \
             WHEN EXISTS ( \
                 SELECT 1 FROM episode_members m \
                 JOIN utterances u ON u.id = m.record_id AND m.record_type = 'utterance' \
                 JOIN voice_embedding_jobs j ON j.speaker_observation_id = u.speaker_observation_id \
                 WHERE m.episode_id = episodes.id AND j.state = 'failed' \
             ) THEN 'degraded' \
             ELSE 'ready' \
         END, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE speaker_processing_status != CASE \
             WHEN EXISTS ( \
                 SELECT 1 FROM episode_members m \
                 JOIN utterances u ON u.id = m.record_id AND m.record_type = 'utterance' \
                 JOIN voice_embedding_jobs j ON j.speaker_observation_id = u.speaker_observation_id \
                 WHERE m.episode_id = episodes.id AND j.state IN ('pending', 'processing', 'retry_wait') \
             ) THEN 'pending' \
             WHEN EXISTS ( \
                 SELECT 1 FROM episode_members m \
                 JOIN utterances u ON u.id = m.record_id AND m.record_type = 'utterance' \
                 JOIN voice_embedding_jobs j ON j.speaker_observation_id = u.speaker_observation_id \
                 WHERE m.episode_id = episodes.id AND j.state = 'failed' \
             ) THEN 'degraded' \
             ELSE 'ready' \
         END",
        [],
    )?;
    Ok(count)
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
        None,
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
            match_and_store_candidate(&conn, 1, &enrolled, "mac-mic", None, None).unwrap(),
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
            match_and_store_candidate(&conn, 2, &match_only, "mac-mic", None, None).unwrap(),
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

    #[test]
    fn embedding_job_lifecycle_supports_leasing_retry_and_completion() {
        let conn = Connection::open_in_memory().unwrap();
        super::super::media::init_schema(&conn).unwrap();

        // Seed observation
        conn.execute(
            "INSERT INTO capture_sessions (id, device_id, install_id, started_at, last_event_at, schema_version) \
             VALUES ('s1', 'd1', 'i1', '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 2)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO capture_streams (id, capture_session_id, device_id, stream_kind) \
             VALUES ('st1', 's1', 'd1', 'mic')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO capture_events (event_id, device_id, install_id, capture_session_id, stream_id, stream_kind, sequence, source_wall_at, source_monotonic_ns, started_at, ended_at, timezone_id, utc_offset_minutes, clock_uncertainty_ms, asset_id, manifest_digest) \
             VALUES ('ev1', 'd1', 'i1', 's1', 'st1', 'mic', 0, '2026-07-31T18:00:00.000Z', '0', '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 'UTC', 0, 0, 'a1', 'd1')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO speaker_observations (id, event_id, turn_id, speaker_local_id, started_at, ended_at, transcript_text) \
             VALUES (101, 'ev1', 't1', 'spk1', '2026-07-31T18:00:00.000Z', '2026-07-31T18:00:05.000Z', 'Hello world')",
            [],
        ).unwrap();

        // 1. Enqueue job
        let job_id = enqueue_embedding_job(&conn, 101).unwrap();
        assert!(job_id > 0);

        // 2. Lease job
        let leased = lease_embedding_jobs(
            &conn,
            "worker-1",
            "token-abc",
            "2026-07-31T18:01:00.000Z",
            300,
            10,
        )
        .unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].id, job_id);
        assert_eq!(leased[0].state, "processing");
        assert_eq!(leased[0].attempt_count, 1);

        // Cannot be leased by another worker while unexpired
        let leased_again = lease_embedding_jobs(
            &conn,
            "worker-2",
            "token-def",
            "2026-07-31T18:02:00.000Z",
            300,
            10,
        )
        .unwrap();
        assert_eq!(leased_again.len(), 0);

        // 3. Renew lease
        let renewed = renew_embedding_job_lease(&conn, job_id, "token-abc", 600).unwrap();
        assert!(renewed);

        // 4. Complete job on failure (retry_wait)
        complete_embedding_job(
            &conn,
            job_id,
            "token-abc",
            false,
            Some("ERR_WESPEAKER_FAIL"),
            Some("2026-07-31T18:02:00.000Z"),
        )
        .unwrap();

        let state_after_fail: (String, Option<String>) = conn
            .query_row(
                "SELECT state, error_code FROM voice_embedding_jobs WHERE id = ?1",
                [job_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state_after_fail.0, "retry_wait");
        assert_eq!(state_after_fail.1.as_deref(), Some("ERR_WESPEAKER_FAIL"));

        // 5. Re-lease and complete successfully
        let leased_retry = lease_embedding_jobs(
            &conn,
            "worker-1",
            "token-xyz",
            "2026-07-31T18:05:00.000Z",
            300,
            10,
        )
        .unwrap();
        assert_eq!(leased_retry.len(), 1);
        assert_eq!(leased_retry[0].attempt_count, 2);

        complete_embedding_job(&conn, job_id, "token-xyz", true, None, None).unwrap();

        let state_ready: String = conn
            .query_row(
                "SELECT state FROM voice_embedding_jobs WHERE id = ?1",
                [job_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state_ready, "ready");
    }

    #[test]
    fn episode_speaker_processing_status_dynamically_tracks_jobs() {
        let conn = voice_db();
        // Insert episode, utterance member, and voice embedding job
        conn.execute(
            "INSERT INTO episodes (id, started_at, ended_at, type, title, summary, participants, languages, action_items, minute_summaries, substance, speaker_processing_status) \
             VALUES (400, '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 'conversation', 'Test', 'Summary', '[]', '[]', '[]', '[]', 'normal', 'ready')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO audio_segments (id, started_at, ended_at, duration_seconds, source_type) VALUES (1, '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 300.0, 'mic')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO speaker_observations (id, event_id, turn_id, speaker_local_id, started_at, ended_at, transcript_text) VALUES (10, 'e', 'turn-1', 'speaker-1', '2026-07-31T18:00:00.000Z', '2026-07-31T18:01:00.000Z', 'x')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label, source_key, speaker_observation_id) \
             VALUES (20, 1, 0.0, 5.0, 'Hello world', 'Unknown', 'cloud-v2:event-1:turn-1', 10)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (400, 'utterance', 20)",
            [],
        ).unwrap();
        let job_id = enqueue_embedding_job(&conn, 10).unwrap();

        // Recalculate status - should be 'pending' because job is pending
        recalculate_all_episode_speaker_processing_status(&conn).unwrap();
        let status: String = conn
            .query_row(
                "SELECT speaker_processing_status FROM episodes WHERE id = 400",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "pending");

        // Fail job permanently - should become 'degraded'
        conn.execute(
            "UPDATE voice_embedding_jobs SET state = 'failed' WHERE id = ?1",
            [job_id],
        )
        .unwrap();
        recalculate_all_episode_speaker_processing_status(&conn).unwrap();
        let status_failed: String = conn
            .query_row(
                "SELECT speaker_processing_status FROM episodes WHERE id = 400",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status_failed, "degraded");

        // Mark job ready - should become 'ready'
        conn.execute(
            "UPDATE voice_embedding_jobs SET state = 'ready' WHERE id = ?1",
            [job_id],
        )
        .unwrap();
        recalculate_all_episode_speaker_processing_status(&conn).unwrap();
        let status_ready: String = conn
            .query_row(
                "SELECT speaker_processing_status FROM episodes WHERE id = 400",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status_ready, "ready");
    }

    #[test]
    fn slice_observation_source_uses_exact_offsets_without_duplication() {
        // 3 seconds of decoded audio at 16 kHz where sample i == i as f32.
        let decoded: Vec<f32> = (0..48_000).map(|i| i as f32).collect();

        // Exact interior span: 500 ms .. 1250 ms -> samples 8000 .. 20000.
        let s = slice_observation_source(&decoded, 500, 1250);
        assert_eq!(s.len(), 12_000);
        assert_eq!(s[0], 8_000.0);
        assert_eq!(s[s.len() - 1], 19_999.0);

        // Two adjacent source events reconstruct contiguously with no overlap:
        // [0,1000) + [1000,2000) must cover exactly [0,2000) once.
        let a = slice_observation_source(&decoded, 0, 1000);
        let b = slice_observation_source(&decoded, 1000, 2000);
        assert_eq!(a.len() + b.len(), 32_000);
        assert_eq!(a[a.len() - 1], 15_999.0);
        assert_eq!(b[0], 16_000.0);

        // End clamped to the decoded length; inverted/out-of-range are empty.
        assert_eq!(
            slice_observation_source(&decoded, 2500, 10_000).len(),
            8_000
        );
        assert!(slice_observation_source(&decoded, 2000, 1000).is_empty());
        assert!(slice_observation_source(&decoded, 5000, 6000).is_empty());
        assert!(slice_observation_source(&decoded, -100, 0).is_empty());
    }

    fn seeded_job(conn: &Connection) -> i64 {
        conn.execute(
            "INSERT INTO capture_sessions (id, device_id, install_id, started_at, last_event_at, schema_version) \
             VALUES ('s1', 'd1', 'i1', '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 2)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO capture_streams (id, capture_session_id, device_id, stream_kind) \
             VALUES ('st1', 's1', 'd1', 'mic')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO capture_events (event_id, device_id, install_id, capture_session_id, stream_id, stream_kind, sequence, source_wall_at, source_monotonic_ns, started_at, ended_at, timezone_id, utc_offset_minutes, clock_uncertainty_ms, asset_id, manifest_digest) \
             VALUES ('ev1', 'd1', 'i1', 's1', 'st1', 'mic', 0, '2026-07-31T18:00:00.000Z', '0', '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 'UTC', 0, 0, 'a1', 'd1')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO speaker_observations (id, event_id, turn_id, speaker_local_id, started_at, ended_at, transcript_text) \
             VALUES (101, 'ev1', 't1', 'spk1', '2026-07-31T18:00:00.000Z', '2026-07-31T18:00:05.000Z', 'Hello world')",
            [],
        ).unwrap();
        enqueue_embedding_job(conn, 101).unwrap()
    }

    #[test]
    fn pruned_media_terminal_failure_derives_degraded_even_for_later_episode() {
        let conn = Connection::open_in_memory().unwrap();
        super::super::media::init_schema(&conn).unwrap();
        let job_id = seeded_job(&conn);

        let leased = lease_embedding_jobs(
            &conn,
            "worker-1",
            "token-prune",
            "2026-07-31T18:01:00.000Z",
            300,
            10,
        )
        .unwrap();
        assert_eq!(leased.len(), 1);

        // Pruned/expired media is terminal on the FIRST attempt, not after
        // exhausting retries.
        fail_embedding_job_terminal(&conn, job_id, "token-prune", "ERR_MEDIA_PRUNED").unwrap();
        let (state, code): (String, Option<String>) = conn
            .query_row(
                "SELECT state, error_code FROM voice_embedding_jobs WHERE id = ?1",
                [job_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "failed");
        assert_eq!(code.as_deref(), Some("ERR_MEDIA_PRUNED"));

        // The episode is created AFTER the terminal failure (segmentation runs
        // later than media processing) and must still derive `degraded`.
        conn.execute(
            "INSERT INTO episodes (id, started_at, ended_at, type, title, summary, participants) \
             VALUES (500, '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 'conversation', 'T', 'S', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audio_segments (id, started_at, ended_at, duration_seconds, source_type) VALUES (1, '2026-07-31T18:00:00.000Z', '2026-07-31T18:05:00.000Z', 300.0, 'mic')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label, source_key, speaker_observation_id) \
             VALUES (20, 1, 0.0, 5.0, 'Hello world', 'Unidentified voice', 'cloud-v2:ev1:t1', 101)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (500, 'utterance', 20)",
            [],
        )
        .unwrap();
        recalculate_all_episode_speaker_processing_status(&conn).unwrap();
        let status: String = conn
            .query_row(
                "SELECT speaker_processing_status FROM episodes WHERE id = 500",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "degraded");
    }

    #[test]
    fn quality_rejection_settles_ready_with_annotation_not_degraded() {
        let conn = Connection::open_in_memory().unwrap();
        super::super::media::init_schema(&conn).unwrap();
        let job_id = seeded_job(&conn);

        let leased = lease_embedding_jobs(
            &conn,
            "worker-1",
            "token-q",
            "2026-07-31T18:01:00.000Z",
            300,
            10,
        )
        .unwrap();
        assert_eq!(leased.len(), 1);
        complete_embedding_job(
            &conn,
            job_id,
            "token-q",
            true,
            Some("QUALITY_REJECTED"),
            None,
        )
        .unwrap();

        let (state, code): (String, Option<String>) = conn
            .query_row(
                "SELECT state, error_code FROM voice_embedding_jobs WHERE id = ?1",
                [job_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "ready");
        assert_eq!(code.as_deref(), Some("QUALITY_REJECTED"));
    }

    #[test]
    fn duplicate_samples_for_one_embedding_job_are_rejected() {
        let conn = Connection::open_in_memory().unwrap();
        super::super::media::init_schema(&conn).unwrap();
        let job_id = seeded_job(&conn);

        let insert = |conn: &Connection| {
            conn.execute(
                "INSERT INTO voice_samples \
                 (speaker_observation_id, embedding_space, channel_domain, embedding, quality_score, embedding_job_id) \
                 VALUES (101, 'space', 'mic', X'00000000', 1.0, ?1)",
                [job_id],
            )
        };
        insert(&conn).unwrap();
        // A crashed-lease replay attempting a second sample for the same job
        // violates the unique embedding-job index.
        let dup = insert(&conn);
        assert!(
            dup.is_err(),
            "duplicate sample for one embedding job must be rejected"
        );
    }

    #[test]
    fn reenqueueing_failed_job_resets_it_to_pending() {
        let conn = Connection::open_in_memory().unwrap();
        super::super::media::init_schema(&conn).unwrap();
        let job_id = seeded_job(&conn);
        let leased = lease_embedding_jobs(
            &conn,
            "worker-1",
            "token-r",
            "2026-07-31T18:01:00.000Z",
            300,
            10,
        )
        .unwrap();
        assert_eq!(leased.len(), 1);
        fail_embedding_job_terminal(&conn, job_id, "token-r", "ERR_MEDIA_PRUNED").unwrap();

        let requeued = enqueue_embedding_job(&conn, 101).unwrap();
        assert_eq!(requeued, job_id);
        let state: String = conn
            .query_row(
                "SELECT state FROM voice_embedding_jobs WHERE id = ?1",
                [job_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "pending");
    }
}
