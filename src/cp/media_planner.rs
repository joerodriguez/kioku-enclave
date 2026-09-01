//! Deterministic planning for bounded Gemini media work.

/// Audio and screen inference have independent queues and reservations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkClass {
    Audio,
    Screen,
}

pub const MAX_AUDIO_WINDOW_MS: i64 = 5 * 60 * 1_000;
pub const MAX_AUDIO_GAP_MS: i64 = 1_000;
pub const MAX_AUDIO_BYTES: i64 = 20 * 1024 * 1024;
pub const MAX_SCREEN_SPAN_MS: i64 = 90 * 1_000;
pub const MAX_SCREEN_FRAMES: usize = 12;
pub const MAX_SCREEN_BYTES: i64 = 16 * 1024 * 1024;
pub const MAX_SCREEN_PIXELS: i64 = 24_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningEvent {
    pub job_id: i64,
    pub event_id: String,
    pub class: WorkClass,
    pub capture_session_id: String,
    pub stream_id: String,
    pub sequence: i64,
    pub started_ms: i64,
    pub ended_ms: i64,
    pub byte_length: i64,
    pub pixel_count: i64,
    /// Versioned acoustic route/domain facts. A change closes an audio window.
    pub route_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkPlan {
    pub class: WorkClass,
    pub member_job_ids: Vec<i64>,
    /// The candidate this plan was anchored on — the minimum of
    /// `(started_ms, sequence, job_id)` — reported even when it was REJECTED
    /// and `member_job_ids` came back empty.
    ///
    /// An empty plan over a non-empty candidate list means the head could not
    /// enter a window of its own: an audio event longer than
    /// `MAX_AUDIO_WINDOW_MS` (ingest admits up to eight hours) or a frame over
    /// `MAX_SCREEN_BYTES`/`MAX_SCREEN_PIXELS`. That is a DETERMINISTIC refusal
    /// — the same head is re-selected by every sweep — so the claim boundary
    /// has to be able to name it. Deriving it a second time from the sort key
    /// would be a drift hazard; it is reported from the same `first` the fold
    /// already uses.
    pub head_job_id: i64,
    pub started_ms: i64,
    pub ended_ms: i64,
    pub total_bytes: i64,
    pub total_pixels: i64,
}

/// Plan the oldest eligible work unit. Callers pass only durable canonical jobs;
/// metadata-only references have no job and therefore cannot reserve or call a
/// model.
pub fn plan_first(candidates: &[PlanningEvent]) -> WorkPlan {
    let mut ordered = candidates.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|event| (event.started_ms, event.sequence, event.job_id));
    let first = ordered.first().expect("planner requires candidates");
    let mut members = Vec::new();
    let mut ended_ms = first.ended_ms;
    let mut total_bytes = 0_i64;
    let mut total_pixels = 0_i64;
    for candidate in &ordered {
        if candidate.class != first.class
            || candidate.capture_session_id != first.capture_session_id
            || candidate.stream_id != first.stream_id
        {
            // The repository orders all pending jobs in the class globally.
            // Mic and system-audio events therefore interleave even though a
            // provider work unit may contain only one stream. Preserve the
            // globally oldest head, but look past unrelated streams/sessions
            // so they cannot fragment that head stream into one-event calls.
            continue;
        }
        let accepted = match first.class {
            WorkClass::Audio => {
                candidate.route_key == first.route_key
                    && candidate.started_ms.saturating_sub(ended_ms) <= MAX_AUDIO_GAP_MS
                    && candidate.ended_ms.saturating_sub(first.started_ms) <= MAX_AUDIO_WINDOW_MS
                    && total_bytes.saturating_add(candidate.byte_length) <= MAX_AUDIO_BYTES
            }
            WorkClass::Screen => {
                members.len() < MAX_SCREEN_FRAMES
                    && candidate.started_ms.saturating_sub(first.started_ms) <= MAX_SCREEN_SPAN_MS
                    && total_bytes.saturating_add(candidate.byte_length) <= MAX_SCREEN_BYTES
                    && total_pixels.saturating_add(candidate.pixel_count) <= MAX_SCREEN_PIXELS
            }
        };
        if !accepted {
            break;
        }
        members.push(candidate.job_id);
        ended_ms = ended_ms.max(candidate.ended_ms);
        total_bytes = total_bytes.saturating_add(candidate.byte_length);
        total_pixels = total_pixels.saturating_add(candidate.pixel_count);
    }
    WorkPlan {
        class: first.class,
        member_job_ids: members,
        head_job_id: first.job_id,
        started_ms: first.started_ms,
        ended_ms,
        total_bytes,
        total_pixels,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInterval {
    pub event_id: String,
    pub start_ms: i64,
    pub end_ms: i64,
}

impl SourceInterval {
    pub fn new(event_id: &str, start_ms: i64, end_ms: i64) -> Self {
        Self {
            event_id: event_id.into(),
            start_ms,
            end_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedInterval {
    pub event_id: String,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub event_start_ms: i64,
    pub event_end_ms: i64,
}

impl ProjectedInterval {
    pub fn new(
        event_id: &str,
        window_start_ms: i64,
        window_end_ms: i64,
        event_start_ms: i64,
        event_end_ms: i64,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            window_start_ms,
            window_end_ms,
            event_start_ms,
            event_end_ms,
        }
    }
}

/// Split a model turn at immutable source-event boundaries. Inputs and outputs
/// use offsets from the start of the assembled audio window.
pub fn project_interval(
    sources: &[SourceInterval],
    turn_start_ms: i64,
    turn_end_ms: i64,
) -> Vec<ProjectedInterval> {
    sources
        .iter()
        .filter_map(|source| {
            let start = turn_start_ms.max(source.start_ms);
            let end = turn_end_ms.min(source.end_ms);
            (end > start).then(|| {
                ProjectedInterval::new(
                    &source.event_id,
                    start,
                    end,
                    start - source.start_ms,
                    end - source.start_ms,
                )
            })
        })
        .collect()
}

/// Protected audio always receives the first available worker slot.
pub fn schedule_classes(audio_pending: bool, screen_pending: bool, slots: usize) -> Vec<WorkClass> {
    let mut schedule = Vec::with_capacity(slots.min(2));
    if audio_pending && schedule.len() < slots {
        schedule.push(WorkClass::Audio);
    }
    if screen_pending && schedule.len() < slots {
        schedule.push(WorkClass::Screen);
    }
    schedule
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeHourFixture {
    pub capture_attempts: i64,
    pub reference_events: i64,
    pub screen_model_calls: i64,
    pub audio_model_calls: i64,
    pub reference_model_calls: i64,
    pub reserved_audio_tokens: i64,
    pub reserved_screen_tokens: i64,
}

/// Cost-regression fixture for three hours of capture. `canonical_every_ms`
/// represents a static screen refreshed conservatively at that interval.
#[cfg(test)]
pub fn simulate_three_hours(
    screen_cadence_ms: i64,
    canonical_every_ms: i64,
    audio_event_ms: i64,
) -> ThreeHourFixture {
    const DURATION_MS: i64 = 3 * 60 * 60 * 1_000;
    let ceil_div = |left: i64, right: i64| (left + right - 1) / right;
    let capture_attempts = DURATION_MS / screen_cadence_ms;
    let canonical_frames = ceil_div(DURATION_MS, canonical_every_ms);
    let reference_events = capture_attempts - canonical_frames;
    // Frames this far apart cannot share a 90-second storyboard. For shorter
    // intervals, both time and the 12-frame cap constrain each request.
    let frames_per_storyboard = if canonical_every_ms > MAX_SCREEN_SPAN_MS {
        1
    } else {
        (MAX_SCREEN_FRAMES as i64).min(MAX_SCREEN_SPAN_MS / canonical_every_ms + 1)
    };
    let screen_model_calls = ceil_div(canonical_frames, frames_per_storyboard);
    let audio_events = ceil_div(DURATION_MS, audio_event_ms);
    let audio_events_per_window = (MAX_AUDIO_WINDOW_MS / audio_event_ms).max(1);
    let audio_model_calls = ceil_div(audio_events, audio_events_per_window);
    ThreeHourFixture {
        capture_attempts,
        reference_events,
        screen_model_calls,
        audio_model_calls,
        reference_model_calls: 0,
        reserved_audio_tokens: audio_model_calls * 4_096,
        reserved_screen_tokens: screen_model_calls * 1_024,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};

    fn event(
        id: i64,
        class: WorkClass,
        stream: &str,
        sequence: i64,
        started_ms: i64,
        ended_ms: i64,
    ) -> PlanningEvent {
        PlanningEvent {
            job_id: id,
            event_id: format!("event-{id}"),
            class,
            capture_session_id: "session-1".into(),
            stream_id: stream.into(),
            sequence,
            started_ms,
            ended_ms,
            byte_length: 100_000,
            pixel_count: 2_000_000,
            route_key: "default".into(),
        }
    }

    #[test]
    fn audio_windows_close_on_gap_route_stream_and_five_minute_bounds() {
        let mut candidates = vec![
            event(1, WorkClass::Audio, "a", 0, 0, 60_000),
            event(2, WorkClass::Audio, "a", 1, 60_250, 120_000),
            event(3, WorkClass::Audio, "a", 2, 120_000, 180_000),
            event(4, WorkClass::Audio, "a", 3, 180_000, 240_000),
            event(5, WorkClass::Audio, "a", 4, 240_000, 300_000),
            event(6, WorkClass::Audio, "a", 5, 300_000, 360_000),
        ];
        candidates[2].route_key = "bluetooth".into();
        assert_eq!(plan_first(&candidates).member_job_ids, vec![1, 2]);

        candidates[2].route_key = "default".into();
        candidates[1].started_ms = 65_000;
        assert_eq!(plan_first(&candidates).member_job_ids, vec![1]);

        candidates[1].started_ms = 60_000;
        assert_eq!(plan_first(&candidates).member_job_ids, vec![1, 2, 3, 4, 5]);

        let mut interleaved = candidates.clone();
        interleaved.insert(1, event(7, WorkClass::Audio, "other", 0, 30_000, 90_000));
        assert_eq!(plan_first(&interleaved).member_job_ids, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn storyboards_are_chronological_and_hard_bounded() {
        let mut candidates = (0..20)
            .map(|index| {
                event(
                    index + 1,
                    WorkClass::Screen,
                    "screen",
                    index,
                    index * 7_000,
                    index * 7_000 + 1,
                )
            })
            .collect::<Vec<_>>();
        candidates.reverse();
        let plan = plan_first(&candidates);
        assert_eq!(plan.class, WorkClass::Screen);
        assert_eq!(plan.member_job_ids.len(), 12);
        assert_eq!(plan.started_ms, 0);
        assert_eq!(plan.ended_ms, 77_001);
        assert!(plan.total_bytes <= MAX_SCREEN_BYTES);
        assert!(plan.total_pixels <= MAX_SCREEN_PIXELS);
    }

    /// A head candidate that cannot enter a window of its OWN yields an empty
    /// plan, and the head is still named.
    ///
    /// This is not hypothetical. `CaptureEventManifest::validate` admits an
    /// audio event up to eight hours long and `validate_media` bounds only its
    /// bytes, so a single event longer than `MAX_AUDIO_WINDOW_MS` is ingested,
    /// is `pending` forever, and is re-selected as the head by every sweep.
    /// Without `head_job_id` the claim boundary sees only "no members" and
    /// cannot tell that apart from "nothing claimable", which is the
    /// difference between a quarantine and a permanent silent wedge.
    #[test]
    fn an_unwindowable_head_yields_an_empty_plan_that_still_names_it() {
        let long_audio = vec![event(
            7,
            WorkClass::Audio,
            "a",
            0,
            0,
            MAX_AUDIO_WINDOW_MS + 1_000,
        )];
        let plan = plan_first(&long_audio);
        assert!(plan.member_job_ids.is_empty());
        assert_eq!(plan.head_job_id, 7);

        let huge_frame = vec![PlanningEvent {
            byte_length: MAX_SCREEN_BYTES + 1,
            ..event(9, WorkClass::Screen, "s", 0, 0, 1)
        }];
        let plan = plan_first(&huge_frame);
        assert!(plan.member_job_ids.is_empty());
        assert_eq!(plan.head_job_id, 9);

        // The head is the sort-key minimum, not the first element given.
        let ordered = plan_first(&[
            event(3, WorkClass::Screen, "s", 2, 20_000, 20_001),
            event(1, WorkClass::Screen, "s", 0, 0, 1),
        ]);
        assert_eq!(ordered.head_job_id, 1);
        assert_eq!(ordered.member_job_ids, vec![1, 3]);
    }

    #[test]
    fn output_projection_preserves_exact_source_intervals() {
        let sources = vec![
            SourceInterval::new("a", 0, 60_000),
            SourceInterval::new("b", 60_000, 120_000),
        ];
        assert_eq!(
            project_interval(&sources, 59_500, 60_500),
            vec![
                ProjectedInterval::new("a", 59_500, 60_000, 59_500, 60_000),
                ProjectedInterval::new("b", 60_000, 60_500, 0, 500),
            ]
        );
    }

    #[test]
    fn scheduler_always_gives_pending_audio_the_first_slot() {
        assert_eq!(
            schedule_classes(true, true, 2),
            vec![WorkClass::Audio, WorkClass::Screen]
        );
        assert_eq!(schedule_classes(true, true, 1), vec![WorkClass::Audio]);
        assert_eq!(schedule_classes(false, true, 2), vec![WorkClass::Screen]);
    }

    #[test]
    fn three_hour_reference_fixture_has_bounded_calls_and_never_starves_audio() {
        let fixture = simulate_three_hours(2_000, 600_000, 60_000);
        assert_eq!(fixture.capture_attempts, 5_400);
        assert_eq!(fixture.reference_events, 5_382);
        assert_eq!(fixture.screen_model_calls, 18);
        assert_eq!(fixture.audio_model_calls, 36);
        assert_eq!(fixture.reference_model_calls, 0);
        assert!(fixture.reserved_audio_tokens <= 262_144);
        assert!(fixture.reserved_screen_tokens <= 131_072);
    }

    fn dual_track_three_hour_events(event_ms: i64) -> Vec<PlanningEvent> {
        const DURATION_MS: i64 = 3 * 60 * 60 * 1_000;
        assert!((1..=75_000).contains(&event_ms));
        let mut events = Vec::new();
        let mut job_id = 1_i64;
        for stream in ["mic", "system_audio"] {
            let mut started_ms = 0_i64;
            let mut sequence = 0_i64;
            while started_ms < DURATION_MS {
                let ended_ms = (started_ms + event_ms).min(DURATION_MS);
                events.push(PlanningEvent {
                    job_id,
                    event_id: format!("{stream}-{sequence}"),
                    class: WorkClass::Audio,
                    capture_session_id: "default-mac-three-hour-session".into(),
                    stream_id: stream.into(),
                    sequence,
                    started_ms,
                    ended_ms,
                    // Shipping AAC is 64 kbit/s. This exact byte estimate is
                    // deliberately conservative enough to exercise the real
                    // 20 MiB planner bound without becoming the active limit.
                    byte_length: (ended_ms - started_ms) * 8,
                    pixel_count: 0,
                    route_key: match stream {
                        "mic" => "mic:aac:default-route",
                        "system_audio" => "system_audio:aac:system-output",
                        _ => unreachable!(),
                    }
                    .into(),
                });
                job_id += 1;
                sequence += 1;
                started_ms = ended_ms;
            }
        }
        // Deliberately reverse the input: `plan_first` must impose the same
        // global order the PostgreSQL claim supplies.
        events.reverse();
        events
    }

    fn plan_all_audio_windows(mut pending: Vec<PlanningEvent>) -> BTreeMap<String, i64> {
        let mut calls_by_stream = BTreeMap::new();
        while !pending.is_empty() {
            let plan = plan_first(&pending);
            assert!(!plan.member_job_ids.is_empty());
            let members = plan.member_job_ids.iter().copied().collect::<HashSet<_>>();
            let member_streams = pending
                .iter()
                .filter(|event| members.contains(&event.job_id))
                .map(|event| event.stream_id.as_str())
                .collect::<HashSet<_>>();
            assert_eq!(member_streams.len(), 1, "a work unit crossed audio streams");
            let stream = (*member_streams.iter().next().unwrap()).to_string();
            *calls_by_stream.entry(stream).or_insert(0) += 1;
            pending.retain(|event| !members.contains(&event.job_id));
        }
        calls_by_stream
    }

    #[test]
    fn default_mac_dual_track_three_hour_fixture_coalesces_interleaved_streams() {
        let minute_segments = plan_all_audio_windows(dual_track_three_hour_events(60_000));
        assert_eq!(minute_segments.get("mic"), Some(&36));
        assert_eq!(minute_segments.get("system_audio"), Some(&36));
        assert_eq!(minute_segments.values().sum::<i64>(), 72);

        // The shipping soft cap is 40 seconds. Seven adjacent segments fit a
        // five-minute window, so 270 segments become 39 calls per track.
        let shipping_soft_cap = plan_all_audio_windows(dual_track_three_hour_events(40_000));
        assert_eq!(shipping_soft_cap.get("mic"), Some(&39));
        assert_eq!(shipping_soft_cap.get("system_audio"), Some(&39));
        assert_eq!(shipping_soft_cap.values().sum::<i64>(), 78);

        // For arbitrary adjacent shipping segments no longer than 75 seconds,
        // every non-tail five-minute window covers more than 225 seconds: the
        // next rejected segment is at most 75 seconds. Thus each track needs at
        // most ceil(3h / 225s) = 48 calls, or 96 calls for both default tracks.
        let per_track_conservative_bound = (3 * 60 * 60 * 1_000 + (MAX_AUDIO_WINDOW_MS - 75_000)
            - 1)
            / (MAX_AUDIO_WINDOW_MS - 75_000);
        assert_eq!(per_track_conservative_bound, 48);
        assert!(shipping_soft_cap.values().sum::<i64>() <= 2 * per_track_conservative_bound);
    }
}
