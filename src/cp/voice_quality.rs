//! Versioned voice-sample eligibility and robust profile representatives.

use serde::{Deserialize, Serialize};

use crate::error::{EnclaveError, Result};

pub const QUALITY_VERSION: i64 = 1;
pub const SCORER_VERSION: i64 = 2;
pub const SAMPLE_RATE: u32 = 16_000;
/// The speech-frame detector inside quality policy 1. Version 1 counted a 20 ms
/// frame as speech only above an absolute -40 dBFS RMS, which a phone on a table
/// in a quiet room never reaches, so whole recordings were quarantined as
/// "silence". Version 2 is relative to the chunk's own level with an absolute
/// floor and a dynamic-range guard against steady noise. Eligibility
/// thresholds, the embedding space, and every stored sample are unchanged: the
/// detector only decides which chunks are admitted, and the per-utterance mean
/// normalization in front of the model makes the embedding gain-invariant.
pub const DETECTOR_VERSION: i64 = 2;
const MIN_EMBEDDING_MS: i64 = 1_000;
const MIN_ENROLLMENT_MS: i64 = 3_000;
const MIN_SPEECH_RATIO: f64 = 0.50;
const MAX_CLIPPING_RATIO: f64 = 0.01;
/// Detector 1's absolute speech-frame RMS; detector 2 never asks for more.
const FRAME_SPEECH_RMS: f64 = 0.01;
/// Detector 2 never counts a frame quieter than this (-50 dBFS) as speech.
const FRAME_SPEECH_RMS_FLOOR: f64 = 0.003;
/// Detector 2 counts a frame within about 16 dB of the chunk's loud frames.
const RELATIVE_SPEECH_FRACTION: f64 = 0.15;
/// A chunk whose loud and quiet frames differ by less than 6 dB is steady
/// noise or a tone, never conversational speech; it keeps detector 1's rule.
const STEADY_SIGNAL_RANGE: f64 = 2.0;
/// Detector 1 refused chunks quieter than -46 dBFS mean absolute level.
/// Detector 2 accepts a level consistent with its frame floor.
const MIN_MEAN_ABS_ENERGY: f64 = 0.002;
const FRAME_SAMPLES: usize = (SAMPLE_RATE / 50) as usize;
pub(crate) const OUTLIER_SIMILARITY: f32 = 0.50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleDecision {
    NoEmbedding,
    MatchOnly,
    Enroll,
    Quarantine,
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
    /// Which speech-frame detector produced `speech_ratio`.
    #[serde(default = "legacy_detector_version")]
    pub detector_version: i64,
    /// The frame RMS this chunk had to reach to count as speech.
    #[serde(default)]
    pub speech_threshold: f64,
    /// Where the embedded chunk starts inside its source turn, and how long the
    /// whole turn was; the caller fills these in after span selection.
    #[serde(default)]
    pub span_offset_ms: i64,
    #[serde(default)]
    pub turn_duration_ms: i64,
}

fn legacy_detector_version() -> i64 {
    1
}

fn frame_rms(samples: &[f32]) -> Vec<f64> {
    samples
        .chunks(FRAME_SAMPLES)
        .filter(|frame| !frame.is_empty())
        .map(|frame| {
            (frame
                .iter()
                .map(|sample| f64::from(*sample) * f64::from(*sample))
                .sum::<f64>()
                / frame.len() as f64)
                .sqrt()
        })
        .collect()
}

fn percentile(sorted: &[f64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

/// Detector 2: a frame is speech when it reaches a fraction of the chunk's loud
/// frames, never below the absolute floor and never above detector 1's absolute
/// rule, unless the chunk has no dynamic range, which keeps the absolute rule.
pub(crate) fn speech_threshold(frame_rms: &[f64]) -> f64 {
    let mut sorted = frame_rms.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let loud = percentile(&sorted, 0.95);
    let quiet = percentile(&sorted, 0.20);
    if loud <= 0.0 || loud < quiet * STEADY_SIGNAL_RANGE {
        return FRAME_SPEECH_RMS;
    }
    (loud * RELATIVE_SPEECH_FRACTION).clamp(FRAME_SPEECH_RMS_FLOOR, FRAME_SPEECH_RMS)
}

/// The window of at most `max_samples` inside a turn holding the most speech
/// frames under the turn-wide detector; ties keep the earliest window, so a
/// turn no longer than the bound is returned whole from offset zero. Gemini
/// often emits one turn per paragraph; embedding only its first thirty seconds
/// quarantined turns that opened with a pause or a quiet aside.
pub(crate) fn best_span(samples: &[f32], max_samples: usize) -> (usize, usize) {
    if samples.len() <= max_samples || max_samples < FRAME_SAMPLES {
        return (0, samples.len().min(max_samples));
    }
    let rms = frame_rms(samples);
    let threshold = speech_threshold(&rms);
    let speech = rms
        .iter()
        .map(|value| u32::from(*value >= threshold))
        .collect::<Vec<_>>();
    let window = max_samples / FRAME_SAMPLES;
    let mut best_start = 0_usize;
    let mut best_count = speech.iter().take(window).sum::<u32>();
    let mut count = best_count;
    for end in window..speech.len() {
        count = count + speech[end] - speech[end - window];
        if count > best_count {
            best_count = count;
            best_start = end + 1 - window;
        }
    }
    let offset = (best_start * FRAME_SAMPLES).min(samples.len() - max_samples);
    (offset, max_samples)
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
    let rms = frame_rms(samples);
    let threshold = speech_threshold(&rms);
    let frame_count = rms.len();
    let speech_frames = rms.iter().filter(|value| **value >= threshold).count();
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
        && mean_abs_energy >= MIN_MEAN_ABS_ENERGY
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
        detector_version: DETECTOR_VERSION,
        speech_threshold: threshold,
        span_offset_ms: 0,
        turn_duration_ms: duration_ms,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_samples(seconds: usize) -> Vec<f32> {
        (0..seconds * SAMPLE_RATE as usize)
            .map(|index| ((index as f32 / 17.0).sin()) * 0.2)
            .collect()
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

    /// Speech-like modulation: bursts of a tone separated by pauses, so frame
    /// levels span more than 6 dB like real conversation.
    fn quiet_conversation(seconds: usize, peak: f32) -> Vec<f32> {
        (0..seconds * SAMPLE_RATE as usize)
            .map(|index| {
                let burst = (index / (SAMPLE_RATE as usize / 4)) % 3 != 2;
                if burst {
                    ((index as f32 / 17.0).sin()) * peak
                } else {
                    ((index as f32 / 23.0).sin()) * peak * 0.02
                }
            })
            .collect()
    }

    #[test]
    fn a_quiet_room_recording_with_pauses_enrolls_and_steady_noise_does_not() {
        let quiet = quiet_conversation(6, 0.012);
        let diagnostics = diagnose(&quiet, false, &[]);
        assert_eq!(
            diagnostics.decision,
            SampleDecision::Enroll,
            "speech at -38 dBFS peaks with natural pauses is enrollment quality"
        );
        assert!(diagnostics.speech_threshold < FRAME_SPEECH_RMS);
        assert_eq!(diagnostics.detector_version, DETECTOR_VERSION);
        let loud = diagnose(&clean_samples(6), false, &[]);
        assert!(
            (loud.speech_threshold - FRAME_SPEECH_RMS).abs() < f64::EPSILON,
            "a close-mic chunk keeps detector 1's absolute rule"
        );
        let steady = (0..6 * SAMPLE_RATE as usize)
            .map(|index| ((index as f32 / 3.0).sin()) * 0.008)
            .collect::<Vec<_>>();
        assert_eq!(
            diagnose(&steady, false, &[]).decision,
            SampleDecision::Quarantine,
            "a steady -42 dBFS signal has no dynamic range and is not speech"
        );
        let whisper = quiet_conversation(6, 0.002);
        assert_eq!(
            diagnose(&whisper, false, &[]).decision,
            SampleDecision::Quarantine,
            "below the absolute floor nothing counts as speech"
        );
    }

    #[test]
    fn best_span_prefers_the_speech_dense_window_and_keeps_short_turns_whole() {
        let bound = SAMPLE_RATE as usize * 30;
        let short = clean_samples(10);
        assert_eq!(best_span(&short, bound), (0, short.len()));
        // Sixty seconds: a pause-filled opening, then dense speech.
        let mut turn = quiet_conversation(20, 0.002);
        turn.extend(vec![0.0_f32; SAMPLE_RATE as usize * 10]);
        turn.extend(clean_samples(30));
        let (offset, len) = best_span(&turn, bound);
        assert_eq!(len, bound);
        assert_eq!(
            offset,
            SAMPLE_RATE as usize * 30,
            "the embedded window is the dense half, not the first thirty seconds"
        );
        assert_eq!(
            diagnose(&turn[offset..offset + len], false, &[]).decision,
            SampleDecision::Enroll
        );
        assert_eq!(
            diagnose(&turn[..bound], false, &[]).decision,
            SampleDecision::Quarantine,
            "the first thirty seconds alone would still have been quarantined"
        );
        let uniform = clean_samples(60);
        assert_eq!(
            best_span(&uniform, bound).0,
            0,
            "ties keep the earliest window for determinism"
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
}
