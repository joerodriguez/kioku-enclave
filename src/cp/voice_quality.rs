//! Versioned voice-sample eligibility and robust profile representatives.

use serde::{Deserialize, Serialize};

use crate::error::{EnclaveError, Result};

pub const QUALITY_VERSION: i64 = 1;
pub const SCORER_VERSION: i64 = 2;
pub const SAMPLE_RATE: u32 = 16_000;
const MIN_EMBEDDING_MS: i64 = 1_000;
const MIN_ENROLLMENT_MS: i64 = 3_000;
const MIN_SPEECH_RATIO: f64 = 0.50;
const MAX_CLIPPING_RATIO: f64 = 0.01;
const OUTLIER_SIMILARITY: f32 = 0.50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleDecision {
    NoEmbedding,
    MatchOnly,
    Enroll,
    Quarantine,
}

impl SampleDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoEmbedding => "no_embedding",
            Self::MatchOnly => "match_only",
            Self::Enroll => "enroll",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceDiagnostics {
    pub quality_version: i64,
    pub duration_ms: i64,
    pub speech_ratio: f64,
    pub mean_abs_energy: f64,
    pub snr_proxy_db: f64,
    pub clipping_ratio: f64,
    pub silence_ratio: f64,
    pub overlap: bool,
    pub boundary_padding_ms: i64,
    pub model_quality_flags: Vec<String>,
    pub decision: SampleDecision,
}

pub fn diagnose(samples: &[f32], overlap: bool, quality_flags: &[String]) -> VoiceDiagnostics {
    let duration_ms = (samples.len() as u64 * 1_000 / u64::from(SAMPLE_RATE)) as i64;
    let mean_abs_energy = if samples.is_empty() {
        0.0
    } else {
        samples
            .iter()
            .map(|sample| sample.abs() as f64)
            .sum::<f64>()
            / samples.len() as f64
    };
    let clipping_ratio = if samples.is_empty() {
        0.0
    } else {
        samples.iter().filter(|sample| sample.abs() >= 0.98).count() as f64 / samples.len() as f64
    };
    let frame_samples = (SAMPLE_RATE / 50) as usize;
    let frames = samples
        .chunks(frame_samples)
        .filter(|frame| !frame.is_empty());
    let (speech_frames, frame_count) = frames.fold((0_usize, 0_usize), |(speech, count), frame| {
        let rms = (frame
            .iter()
            .map(|sample| f64::from(*sample) * f64::from(*sample))
            .sum::<f64>()
            / frame.len() as f64)
            .sqrt();
        (speech + usize::from(rms >= 0.01), count + 1)
    });
    let speech_ratio = if frame_count == 0 {
        0.0
    } else {
        speech_frames as f64 / frame_count as f64
    };
    let silence_ratio = 1.0 - speech_ratio;
    // A deliberately conservative, versioned proxy. Calibration may replace
    // this with a VAD-derived active/noise RMS ratio without changing history.
    let snr_proxy_db = if mean_abs_energy >= 0.01 && speech_ratio >= MIN_SPEECH_RATIO {
        20.0 + 10.0 * (speech_ratio - MIN_SPEECH_RATIO)
    } else {
        0.0
    };
    let model_rejects = quality_flags.iter().any(|flag| {
        matches!(
            flag.to_ascii_lowercase().as_str(),
            "music"
                | "music_dominant"
                | "echo"
                | "echo_dominant"
                | "clipping"
                | "severe_clipping"
                | "low_speech_purity"
                | "invalid_boundary"
        )
    });
    let quality_passes = !overlap
        && !model_rejects
        && mean_abs_energy >= 0.005
        && speech_ratio >= MIN_SPEECH_RATIO
        && clipping_ratio <= MAX_CLIPPING_RATIO;
    let decision = if duration_ms < MIN_EMBEDDING_MS {
        SampleDecision::NoEmbedding
    } else if !quality_passes {
        SampleDecision::Quarantine
    } else if duration_ms < MIN_ENROLLMENT_MS {
        SampleDecision::MatchOnly
    } else {
        SampleDecision::Enroll
    };
    VoiceDiagnostics {
        quality_version: QUALITY_VERSION,
        duration_ms,
        speech_ratio,
        mean_abs_energy,
        snr_proxy_db,
        clipping_ratio,
        silence_ratio,
        overlap,
        boundary_padding_ms: 0,
        model_quality_flags: quality_flags.to_vec(),
        decision,
    }
}

pub fn normalize(vector: &mut [f32]) -> Result<()> {
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

pub fn cosine(left: &[f32], right: &[f32]) -> f32 {
    if left.len() != right.len() || left.is_empty() {
        return -1.0;
    }
    left.iter().zip(right).map(|(a, b)| a * b).sum()
}

#[derive(Debug, Clone)]
pub struct RobustRepresentative {
    pub centroid: Vec<f32>,
    pub medoid_index: usize,
    pub excluded_indices: Vec<usize>,
}

pub fn robust_representative(samples: &[Vec<f32>]) -> Result<RobustRepresentative> {
    let dimension = samples
        .first()
        .map(Vec::len)
        .filter(|dimension| *dimension > 0)
        .ok_or_else(|| EnclaveError::InvalidRequest("voice profile has no samples".into()))?;
    if samples
        .iter()
        .any(|sample| sample.len() != dimension || sample.iter().any(|value| !value.is_finite()))
    {
        return Err(EnclaveError::InvalidRequest(
            "voice profile samples are incompatible".into(),
        ));
    }
    let medoid_index = (0..samples.len())
        .max_by(|left, right| {
            let score = |index: usize| {
                samples
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .map(|(_, sample)| cosine(&samples[index], sample))
                    .sum::<f32>()
            };
            score(*left)
                .partial_cmp(&score(*right))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.cmp(left))
        })
        .expect("nonempty samples");
    let excluded_indices = samples
        .iter()
        .enumerate()
        .filter_map(|(index, sample)| {
            (cosine(&samples[medoid_index], sample) < OUTLIER_SIMILARITY).then_some(index)
        })
        .collect::<Vec<_>>();
    let mut centroid = vec![0_f32; dimension];
    let mut accepted = 0_f32;
    for (index, sample) in samples.iter().enumerate() {
        if excluded_indices.contains(&index) {
            continue;
        }
        for (target, value) in centroid.iter_mut().zip(sample) {
            *target += *value;
        }
        accepted += 1.0;
    }
    if accepted == 0.0 {
        return Err(EnclaveError::InvalidRequest(
            "voice profile has no coherent samples".into(),
        ));
    }
    for value in &mut centroid {
        *value /= accepted;
    }
    normalize(&mut centroid)?;
    Ok(RobustRepresentative {
        centroid,
        medoid_index,
        excluded_indices,
    })
}

pub fn is_profile_outlier(accepted: &[Vec<f32>], candidate: &[f32]) -> Result<bool> {
    if accepted.is_empty() {
        return Ok(false);
    }
    let representative = robust_representative(accepted)?;
    Ok(cosine(&representative.centroid, candidate) < OUTLIER_SIMILARITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_samples(seconds: usize) -> Vec<f32> {
        (0..seconds * SAMPLE_RATE as usize)
            .map(|index| ((index as f32 / 17.0).sin()) * 0.2)
            .collect()
    }

    fn unit(index: usize) -> Vec<f32> {
        let mut vector = vec![0.0; 256];
        vector[index] = 1.0;
        vector
    }

    #[test]
    fn duration_and_quality_policy_separates_matching_from_enrollment() {
        assert_eq!(
            diagnose(&clean_samples(0), false, &[]).decision,
            SampleDecision::NoEmbedding
        );
        assert_eq!(
            diagnose(&clean_samples(2), false, &[]).decision,
            SampleDecision::MatchOnly
        );
        assert_eq!(
            diagnose(&clean_samples(3), false, &[]).decision,
            SampleDecision::Enroll
        );
        assert_eq!(
            diagnose(&clean_samples(4), true, &[]).decision,
            SampleDecision::Quarantine
        );
        assert_eq!(
            diagnose(&clean_samples(4), false, &["music".into()]).decision,
            SampleDecision::Quarantine
        );
    }

    #[test]
    fn silence_and_clipping_cannot_enroll_even_when_long() {
        assert_eq!(
            diagnose(&vec![0.0; SAMPLE_RATE as usize * 5], false, &[]).decision,
            SampleDecision::Quarantine
        );
        assert_eq!(
            diagnose(&vec![1.0; SAMPLE_RATE as usize * 5], false, &[]).decision,
            SampleDecision::Quarantine
        );
    }

    #[test]
    fn robust_representative_rejects_a_distant_outlier() {
        let mut near_a = unit(0);
        near_a[1] = 0.05;
        normalize(&mut near_a).unwrap();
        let mut near_b = unit(0);
        near_b[2] = 0.06;
        normalize(&mut near_b).unwrap();
        let outlier = unit(9);
        let representative = robust_representative(&[unit(0), near_a, near_b, outlier]).unwrap();
        assert_eq!(representative.medoid_index, 0);
        assert!(representative.excluded_indices.contains(&3));
        assert!(cosine(&representative.centroid, &unit(0)) > 0.99);
    }

    #[test]
    fn outlier_gate_abstains_before_a_stable_profile_can_be_poisoned() {
        let accepted = vec![unit(0), unit(0), unit(0)];
        assert!(!is_profile_outlier(&accepted, &unit(0)).unwrap());
        assert!(is_profile_outlier(&accepted, &unit(8)).unwrap());
    }
}
