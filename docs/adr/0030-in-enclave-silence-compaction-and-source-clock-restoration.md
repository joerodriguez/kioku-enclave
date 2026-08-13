# ADR-0030: In-enclave silence compaction and source-clock restoration

- Status: Proposed; activation requires measured cost and quality gates
- Date: 2026-08-13
- Owners: Kioku audio and enclave platform
- Scope: Inbound audio work units, enclave speech detection, Vertex audio inference,
  timestamp reconstruction, voice embeddings, source provenance, and cost attribution

## Context

Kioku currently sends the complete duration of each assembled audio work unit to Gemini,
including quiet spans that contain no speech. An inbound upload may be short, while the
enclave may combine adjacent uploads from the same stream into a longer work unit. The
current planner keeps a unit within one capture session, `stream_id`, and format-derived
acoustic domain (`stream_kind`, MIME type, codec, sample rate, and channel count), allows
at most a one-second source-event gap, and caps the result at five minutes and 20 MiB.
That key is not a physical route epoch. See
[`media_planner.rs`](../../src/cp/media_planner.rs).

[`media_worker.rs`](../../src/cp/media_worker.rs) then:

1. decrypts and hash-verifies every member inside the enclave;
2. decodes each member to canonical mono 16 kHz samples;
3. creates a full original-time window, representing source gaps as zero-valued samples
   and averaging overlapping members of the same stream;
4. reserves the maximum audio output allowance;
5. sends the complete WAV to Gemini with `audioTimestamp=true`;
6. validates returned turn offsets against the full window duration;
7. extracts voice embeddings from that WAV at the returned offsets; and
8. persists those offsets directly as original-window time and projects them to the
   immutable source events.

The existing detector in [`voice_quality.rs`](../../src/cp/voice_quality.rs) evaluates
turn audio only after Gemini has returned. It protects voice-profile quality, but it
cannot avoid a paid request or reduce its audio input.

The current provider path already preserves much of the evidence needed to measure the
economic result. [`vertex.rs`](../../src/cp/vertex.rs) parses `usageMetadata`, including
AUDIO modality input tokens, output and thought tokens, cache details, returned model,
and traffic type. It separately measures elapsed time across the request, response parse,
and durable usage-ledger update. [`model_usage.rs`](../../src/cp/model_usage.rs) records
the privacy-preserving invocation ledger required by ADR-0019, and the media worker also
stores a subset of actual usage in the encrypted work-unit record.

Removing quiet audio is not merely a smaller-file optimization. Gemini audio billing is
token-based, and Google's published approximation implies duration-scaled audio tokens
independent of encoded byte size. It does not guarantee that silence and speech tokenize
identically, especially with timestamp mode, so Kioku must verify silence-versus-speech
and full-versus-compact behavior from actual usage metadata. A shorter PCM or AAC file
with the same duration should not be assumed cheaper. Conversely, removing duration
changes the clock visible to Gemini. A turn reported at compact time `00:20` may have
occurred minutes later in the source. Multiple removed gaps make a single accumulated
offset insufficient.

This decision must also preserve Kioku's trust boundary. Apple clients remain capture,
timestamp, encode, and upload clients. The primary detector, compactor, and timestamp
restorer run inside the attested enclave. No client becomes the authoritative speech
filter, no plaintext intermediate is persisted outside the existing encrypted per-user
store, and no new inference service receives audio.

## Decision

Kioku will add a versioned **speech-time compaction stage** inside the enclave. It will
operate on each fully assembled audio work unit, from a short single-event unit through
the five-minute maximum, immediately before the existing Vertex reservation and request.

The stage has three outcomes:

1. **Identity:** use the original assembled WAV for the attempt. This applies when
   speech-free intervals are too short, estimated savings are immaterial, detection is
   uncertain, or compaction cannot be proven safe.
2. **Compact:** concatenate conservative, source-derived retained spans into one shorter
   WAV, make at most one Gemini request per processing attempt, and restore every returned
   turn to the original sample clock before durable transcript persistence.
3. **No speech:** when the complete unit is confidently speech-free, make no output-token
   reservation, create no Vertex invocation intent, make no Gemini call, and complete the
   unit with no utterances.

The target is speech-free duration, not merely low amplitude. Quiet, whispered, distant,
clipped, accented, or overlapped speech must be retained. Music with vocals, laughter,
high-energy non-speech, and ambiguous frames are retained in the initial policy. This is
intentionally biased toward recall quality rather than maximum removal.

### Placement in the source-aware pipeline

Compaction is per source stream and never mixes microphone and system audio. The complete
ordering is:

```text
encrypted source members
        |
decrypt, authenticate, decode, and assemble on original 16 kHz clock
        |
source-aware conditioning / AEC when a valid far-end reference exists
        |
conservative speech detection and retained-span construction
        |
persist and validate compaction plan
        |
   +----+--------------------+
   |                         |
no speech                identity or compact WAV
   |                         |
no Vertex call           one source-labeled Gemini call per attempt
                             |
                  compact-clock validation and embeddings
                             |
                  original-clock reconstruction
                             |
             source-fragment projection and persistence
```

The current planner produces one-stream work units. This ADR does not authorize waveform
mixing or change source identity. When the companion Kioku ADR-0023 source-aware AEC
decision is implemented, AEC must consume the original aligned system reference and
microphone capture before either track is compacted. Compaction must never destroy the
far-end timing reference. Conditioning may preserve sample indexes exactly or perform
the bounded adaptive resampling allowed by ADR-0023. In either case it supplies a
versioned, reversible conditioned-clock-to-original-clock transform. Timestamp
restoration composes that transform with this ADR's compact-to-conditioned-clock map;
algorithmic delay may never be discarded or hidden. With no valid reference, such as iOS
microphone-only capture or an absent system track, the pipeline bypasses AEC and applies
only the conservative speech-time decision. Headphone and external-device routes also
bypass it unless route testing proves a useful, correctly aligned reference. This is a
future composition constraint: current work units remain single-stream and have no
cross-stream AEC coordinator.

WebRTC Audio Processing Module is the baseline enclave AEC candidate for that companion
pipeline, not a quality conclusion. It must be benchmarked on Kioku's route, echo,
double-talk, missing-reference, and clock-drift corpus before selection or activation.
Apple voice processing may be evaluated as route-tested client defense in depth, but it
cannot replace the enclave guarantee or the original system-audio reference.

Compaction is not an echo-removal mechanism. During a laptop-speaker remote call, an
unconditioned microphone echo may still look like speech and must be retained until the
source-aware AEC stage can distinguish it safely. Double-talk is always retained.

### Detector and edit policy

The implementation will use an image-baked, hash-pinned, versioned detector. WebRTC VAD
is the lightweight baseline to benchmark against a suitable model-based detector; this
ADR does not assert unmeasured recall or permanently select thresholds.

Evaluation starts with the following candidate policy, whose values remain disabled
until calibrated on Kioku's corpus:

- classify 10–20 ms frames;
- retain every speech or uncertain frame;
- expand activity by approximately 300 ms of pre-roll and 500 ms of post-roll/hangover;
- merge nearby retained islands;
- remove only the remaining center of a confidently speech-free run of roughly one
  second or longer; and
- use the identity outcome unless proposed removal exceeds both an absolute and a
  proportional benefit floor, initially evaluated near two seconds and ten percent.

The policy retains real source samples on both sides of every edit. Version 1 will not
insert synthetic tones, synthetic silence, crossfades, or time-stretched samples because
they have no source provenance and can create acoustic artifacts. Nearby islands are
merged rather than joined aggressively. A very short retained result is expanded with
neighboring original samples to meet a measured provider-safe minimum; it is never padded
with invented content.

An all-silence decision is separate from creating a zero-length asset. It requires a
higher, corpus-validated confidence gate than partial compaction. Any credible activity
produces identity or compact audio instead.

## Timestamp and synchronization contract

### Canonical clock

The compactor operates on a canonical **processing clock**. Before source-aware AEC
exists, that clock and sample array are exactly the original assembled work-unit clock:

```text
x[0 .. N) at R = 16,000 samples/second
```

After conditioning that resamples, `x` is instead the canonical conditioned array and the
plan also carries a versioned, monotonic, invertible conditioned-time-to-original-time
index transform `T`. This is a timestamp transform, not a claim that resampling preserves
or reconstructs PCM values. All edit decisions and mappings use integer sample indexes
and half-open intervals.
Wall-clock strings and floating-point seconds are presentation and persistence formats,
not mapping arithmetic. Without conditioning, this ADR preserves the current assembled
source clock exactly. It does not claim to repair capture-clock drift or inaccurate client
timestamps.
Because current provider and persistence contracts use integer milliseconds, every
retained-span endpoint and compact prefix is a multiple of 16 samples. The complete
compact sample count is therefore exactly representable in milliseconds at 16 kHz.

Let the padded and merged processing-clock spans retained for Gemini be:

```text
K_i = [a_i, b_i), where 0 <= a_i < b_i <= N
```

Their compact prefixes are:

```text
p_0 = 0
p_i = sum for j < i of (b_j - a_j)
```

The compact WAV is the ordered concatenation of `x[a_i .. b_i)`. Each durable compaction
map row is:

```text
compact  [p_i, p_i + (b_i - a_i))
processing [a_i, b_i)
```

The paired compact/processing spans always have equal lengths. No resampling or time
stretch occurs inside a compaction-map span. `T` is the identity when the processing and
original clocks are identical.

### Restoring Gemini intervals

Gemini returns a turn `[start_ms, end_ms)` in compact time. The enclave converts its start
to samples with floor rounding and its end with ceil rounding. It intersects that compact
interval with every map span. For an intersection `[l, r)` in span `i`, the corresponding
processing-clock fragment is:

```text
[a_i + (l - p_i), a_i + (r - p_i))
```

The enclave maps each resulting fragment through `T` to obtain an ordered list of one or
more original-clock fragments. This composed compact-to-processing-to-original mapping,
not “add the amount removed so far” to the whole transcript, is the restoration contract.
Processing-clock endpoints are exact on the required 16-sample grid. After applying `T`,
original-clock start and end are converted to milliseconds with floor and ceil rounding,
respectively. Clamping hides an invalid provider result and is not allowed.

A boundary exactly at a seam belongs to the following span for a start and the preceding
span for an end. Empty intersections are discarded.

### Map invariants

Before any paid egress, the enclave validates that:

- processing spans are sorted, nonempty, nonoverlapping, and within `[0, N)`;
- compact spans are sorted, nonempty, and contiguous from zero through the exact compact
  sample count;
- every processing endpoint and compact prefix is aligned to the
  16-sample/millisecond grid;
- every paired compact/processing span has the same sample length;
- retained sample **indexes** form an exact compact/processing bijection in both
  directions;
- `T` is versioned, strictly monotonic, invertible over the complete processing window,
  and maps its boundaries within the authoritative original work-unit window;
- the decoded compact PCM sample count equals the map coverage and the mono PCM16 WAV
  data chunk is exactly twice that sample count; and
- identity is exactly one compaction span `[0, N) <-> [0, N)`; it does not discard a
  nonidentity conditioned/original transform.

`no_speech` is the sole exception: it has an empty retained-span map, compact sample count
zero, and no compact WAV. Its higher-confidence detector evidence and input binding still
must validate before completion.

The plan is keyed by `(work_unit_id, processor_version, compaction_version)` with strict
mismatch rejection, or by a new versioned work-unit digest carrying equivalent fields.
Its input binding includes ordered member hashes, authoritative source layout
(timestamps/offsets), route facts, original and processing PCM hashes/sample counts, the
conditioned/original transform, detector artifact hash, and configuration hash. The
current `media-work-v1` identity does not contain all
of those facts and is insufficient by itself. The plan is durably flushed to the
encrypted per-user store before reservation or Vertex egress so a retry cannot silently
choose a different edit.

The detailed plan must not live only in `media_work_units.usage_json`, because lease,
reservation, returned-usage, and retry updates overwrite that value. Implementation will
add a durable plan record and ordered span records plus an append-only encrypted attempt
table, or an equivalently normalized structure. Before egress, each attempt row is
inserted and durably flushed with its work unit, plan hash, arm, attempt number, fresh
reservation, opaque ADR-0019 invocation ID, and a pending outcome that can transition to
the terminal provider result. That binding stays inside the encrypted user store and is
never added to the content-free external billing payload.

### Turn, voice, and source projection

Gemini output is first parsed and validated against the **compact** duration. Voice
embedding and turn diagnostics then use the compact WAV with compact-clock offsets, as
required by [`voice_memory.rs`](../../src/cp/voice_memory.rs). Only afterward does the
enclave create an original-clock copy of each turn for persistence. Remapping before
embedding would slice the wrong audio.

A turn whose compact interval intersects more than one retained span is seam-crossing.
Version 1 does not enroll a voice profile from such a turn. Match-only use is allowed only
after every contributing fragment independently passes the voice-quality gate and yields
one consistent existing-profile decision; otherwise the worker retains diagnostics but
no biometric embedding. This prevents an edit seam or an incorrectly merged cross-speaker
turn from contaminating durable voice memory. Corpus evaluation may relax this rule only
through a new calibrated voice-quality version.

Existing transcript tables have one scalar start and end for a logical turn. If Gemini
returns one turn crossing several retained spans, the logical turn uses the bounding
original start of its first fragment and end of its last fragment. The enclave does not
split or duplicate the text because Gemini has not supplied a word-to-fragment allocation.
The bounding interval may therefore include a removed quiet gap.

Exact provenance remains discontiguous. The implementation will project every restored
fragment independently through the existing original `SourceInterval`s and preserve all
intersections in `speaker_observation_sources`. It must not call the current scalar
`project_interval` on only the bounding interval, because that would falsely claim the
deleted middle as transcript evidence. The earliest covering source member remains the
deterministic anchor. Existing `audio_segments`, utterance offsets, feed timestamps, and
episode timestamps remain on the full original wall-clock timeline.

Every temporal screen/person/identity join also uses restored fragments rather than the
scalar bounding interval. In particular, a screen-active name visible only during a
removed gap must never corroborate an audio identity. Until a join is fragment-aware, it
abstains from screen-derived identity for a multi-fragment turn.

## Persistence and processing outcomes

An encrypted per-user compaction plan records at least:

- work-unit ID and input binding;
- original, processing, and compact sample counts and rates plus the versioned
  processing-to-original time-index transform;
- `identity`, `compact`, or `no_speech` outcome;
- detector, compactor, configuration, and processor versions;
- ordered retained-span mapping and a map hash;
- validation and fallback reason classes; and
- created/attempt timestamps needed for deterministic retry.

Exact retained spans exist only as long as needed for deterministic processing, bounded
retry, audit, and raw-media/source lifecycle. After terminal success and the applicable
raw-media retention horizon, they are pruned while retaining the plan hash, versions,
aggregate duration/cost fields, restored transcript fragments, and terminal attempt
outcomes. Terminal failures retain spans only for the same bounded diagnostic/retention
horizon. Account/source deletion removes them immediately under the existing lifecycle.

For `no_speech`, a dedicated no-inference completion transaction marks the work unit,
member jobs, and media objects succeeded/ready; leaves model, prompt, and provider-schema
fields null (or uses an explicit local-processor field separate from them); creates an
`audio_segments` carrier covering the complete original interval with zero speech and an
internal `no_speech` transcription outcome; and creates no utterances, speaker
observations, output reservation, or ADR-0019 Vertex intent. It must not reuse the current
success helper if that helper writes Gemini metadata. Raw encrypted media follows the
same retention, export, and deletion contract as any other capture. Queue, session, and
finalization consumers treat `no_speech` as a terminal success, not pending work or a
failed transcript.

For `identity` and `compact`, the worker makes at most one provider call per processing
attempt. Existing bounded retries may make another request with a fresh reservation and
ADR-0019 invocation intent, but every retry uses the identical persisted plan. The worker
never makes paired compact-plus-full requests or switches to full audio merely because a
compact attempt may already have consumed paid inference.

## Failure and fallback behavior

Failure policy favors transcript integrity while preventing hidden duplicate spend:

| Condition | Behavior |
|---|---|
| Media authentication, hash, decode, or assembly failure | Fail closed under the existing media policy; send no bytes. |
| Detector unavailable, uncertainty overflow, or invalid proposed map before egress | Persist an identity fallback and use the original assembled WAV for the attempt. |
| Compaction-plan persistence or encrypted-store flush failure | Send nothing; retry only after durable state is available. |
| Output reservation or Vertex-intent persistence failure | Send nothing under existing fail-closed controls. |
| Received non-2xx provider response | Record ADR-0019 `not_billed`; a bounded retry uses the exact plan and a fresh reservation/intent. |
| Timeout, lost response, or malformed HTTP 200 | Record ADR-0019 `ambiguous`; a bounded retry may be billable but uses the exact plan and a fresh reservation/intent. |
| Returned offsets invalid in compact time | Reject the result under the existing schema/timestamp policy; do not persist partial transcript; the ordinary bounded invalid-output retry policy may apply. |
| Post-response map or restoration invariant failure | Treat as a terminal `compaction_mapping_error`, persist no transcript, and make no automated provider retry. |
| Feature rollback | New, not-yet-egressed work uses identity; an already-attempted work unit keeps its bound plan. |

Forward source gaps greater than one second and changes to the current format-derived
acoustic-domain key close work units today. A physical route change with unchanged format
can still span one. Route epoch metadata, backward timestamp jumps, excessive overlaps,
and other source-clock discontinuities require the explicit companion capture/planner
contract, potentially using `source_monotonic_ns`; current planning does not prove they
close a unit. Compaction stays in identity mode when a route epoch or clock continuity is
unknown or invalid. Once route epochs exist, a compaction map never spans them.
Decoder/source-duration disagreement beyond a documented container tolerance is a
media-integrity failure; the compactor must not hide it by stretching or truncating time.

## Security and privacy boundaries

- Detection, canonical PCM, compact PCM, and timestamp restoration execute only in the
  attested process memory or SEV-protected tmpfs.
- Only the selected original-derived audio is sent through the already disclosed Vertex
  inference boundary. Compact audio is not added to persistent object storage.
- The edit map reveals when a user or participant was likely speaking. It is private user
  metadata, stored only in the per-user encrypted database and covered by export,
  source/work-unit deletion, account deletion, and archive migration. It does not extend
  the raw-media retention period.
- No map span, transcript, exact event timestamp, event ID, speech probability, or media
  sample is written to process logs or content-free billing systems.
- Fleet observability receives only bounded aggregate counters and fixed buckets that
  cannot reconstruct an individual's activity timeline.
- Detector code and model artifacts are open-source-compatible, license-reviewed,
  hash-pinned in the image, represented in the SBOM, and covered by the repository's
  build-provenance, attestation, and documented reproducibility-gap evidence. The
  detector makes no network request.
- Client-side VAD hints may be evaluated under a separate capture contract, but they
  cannot authorize omission or inference skipping under this ADR. The enclave remains
  authoritative and clients continue uploading bounded source evidence under the
  cloud-only contract.

## Cost assessment

### What can save money

The current Gemini 3.5 Flash pricing page charges Standard regional input at $1.65 per
million tokens and global input at $1.50 per million tokens as of this ADR's date. Google's
general audio guidance describes approximately 32 tokens per second of audio. Google does
not publish a Kioku-specific guarantee for Gemini 3.5 Flash with `audioTimestamp=true`, so
these figures are planning estimates, not acceptance evidence.

For the current regional Standard rate-card assumption, the estimated gross **uncached**
audio-input saving is:

```text
removed_seconds * 32 tokens/second * $1.65 / 1,000,000
= removed_seconds * $0.0000528
```

Illustrative input-only savings at 50% removed duration are:

| Original audio | Removed audio | Estimated gross saving |
|---:|---:|---:|
| 10 seconds | 5 seconds | $0.000264 |
| 5 minutes | 2.5 minutes | $0.00792 |
| 1 recording hour | 30 minutes | $0.09504 |
| 1,000 recording hours | 500 hours | $95.04 |

One completely removed audio hour is approximately $0.19008 of uncached audio input at
that assumption. Gemini 3.5 Flash non-global cached input is priced at $0.165 per million
tokens on the same rate card. Unique, one-shot audio should not be assumed cacheable, but
implicit caching also must not be assumed absent; returned cached modality counts decide.
An all-silence skip also avoids the repeated text prompt and any output the model would
otherwise generate. A speech-containing compact request should produce roughly the same
transcript, so the business case must not assume output-token savings.

### Net-savings contract

For one observed invocation `e`, the rate-card calculation is:

```text
provider_price(e) =
    sum by input modality m of
      (input_m - cached_input_m) * input_rate_m
      + cached_input_m * cached_input_rate_m
  + (output_tokens + thought_tokens) * output_rate

net saving =
    provider_price(control) - provider_price(treatment)
  - incremental enclave CPU and capacity cost
  - incremental retry cost
```

For a skipped no-speech treatment, provider price is zero; its avoided provider price is
an estimate from the predeclared shadow or randomized control, because the skipped side
has no provider usage metadata.

If output behavior is unchanged, audio input dominates. At the 32-token estimate, an
incremental enclave cost of $0.0001 requires about 1.9 removed seconds to break even;
$0.001 requires about 18.9 seconds. Marginal CPU may be near zero on an underutilized VM,
but it becomes real when the detector forces additional instances or reduces throughput.

Byte reduction, output-token reservation, and estimated duration alone are not evidence
of savings. Activation uses returned modality and cache tokens, returned model, configured
invocation location, ADR-0019-normalized traffic class, and the effective-dated owner
economics rate card. Missing usage is unknown, never zero. Under fixed Provisioned
Throughput, token reduction may free capacity without lowering the current invoice; the
current on-demand assumption must therefore be confirmed by the priced ADR-0019 event.

The conclusion is **conditionally yes**: shorter duration should lower direct on-demand
audio input cost, but the amount is modest at low volume and quality damage would cost
more than the saved tokens. Production activation requires measured positive net savings
and non-inferior transcript quality. A per-work-unit Count Tokens request is not added to
the production path; post-generation usage metadata is billing authority.

## Observability

The encrypted plan plus append-only attempt history retains exact evaluation fields per
attempt:

- original, compact, retained, and removed samples/duration;
- retained-span count and removal ratio;
- outcome, compactor/detector/config versions, and fallback reason;
- map validation result;
- actual audio, text, image, output, thought, total-cache, cached-audio, cached-text,
  cached-image, and total tokens;
- returned model, invocation location, traffic class, and immutable rate-selection
  dimensions or the corresponding encrypted priced result;
- detector CPU time, wall latency, and peak memory; and
- retry count and provider-result validity.

Content-free fleet metrics use fixed buckets for removal ratio, original-duration class,
span count, latency, CPU, outcome, and failure reason, plus totals for avoided calls.
Minimum cohort-size and suppression rules apply before emitting rare source/outcome
slices. Actual billed-token and cost totals remain authoritative in ADR-0019; compaction
telemetry supplies only cohort denominators and bounded operational aggregates. It must
not expose exact per-user activity patterns or join to capture, episode, or account
identity.

Dashboards compare:

- actual audio tokens per original minute and, only when compact duration is nonzero, per
  compact minute;
- direct cost per original recording hour;
- all-silence calls avoided and control-based estimated avoided tokens/cost;
- locally measured Vertex request-and-metering elapsed time and invalid-output/retry
  rate;
- detector capacity cost; and
- quality-gate results by approved non-identifying capture slice.

## Rollout and migration

1. **Offline benchmark:** evaluate full and compact paths on a consented, labeled corpus
   using the exact production request shape, model, location, and
   `audioTimestamp=true`. Include equal-duration silence-versus-speech and
   original-versus-compacted fixtures and compare actual response usage metadata. This is
   the only broad paired-inference phase.
2. **Shadow map:** produce, validate, and persist plans while sending identity audio. This
   measures detector behavior and capacity without changing transcripts and establishes
   the declared cost baseline for later no-speech skips.
3. **No-speech gate:** enable only high-confidence complete-unit skips. Audit that no
   reservation, intent, or provider request occurs.
4. **Sticky compact canary:** assign each eligible work unit deterministically to control
   or treatment and make only its assigned variant on every attempt. Compare cohorts
   using actual usage metadata and quality review; do not pay for compact and full
   variants as a pair in production. Before starting, predeclare sample size/power,
   minimum cohort suppression, stratification by source kind, original duration, and
   proposed removal ratio, and require the lower confidence bound on net savings to
   exceed zero.
5. **Source-sliced expansion:** ramp independently for iOS microphone, Mac microphone,
   and system audio only after each slice passes.
6. **General availability:** retain an image-baked identity mode and periodic cost and
   quality revalidation after detector, provider model, prompt, codec, or pricing changes.
   Activating that mode requires the normal newly attested image/release; it is not an
   unaudited runtime toggle.

Implementation introduces a new processor version consistently at ingest and worker
selection; it removes the current separate ingest hardcode. Never-attempted old-version
jobs are transactionally migrated once to the new version and versioned work/plan key.
Jobs with a persisted, metered, or ambiguous provider attempt remain on their original
processor and exact plan under a dual-reader/drain path until terminal. The release gate
proves neither version is stranded by the worker's exact-version lease filter. Previously
succeeded work is not reprocessed. Rollback affects new work and same-plan bounded retry;
it never replans an attempted unit or creates a compact/full pair.

## Testing and quality gates

### Deterministic tests

- Property-test map ordering, bounds, equal-length spans, exact retained-sample-index
  round-trips, identity maps, seam endpoints, and multi-seam intervals, plus composition
  with the versioned conditioned-clock-to-original-clock transform when AEC resamples.
- Verify the 16-sample grid and exact millisecond/sample conversion.
- Project restored fragments through source-event seams, gaps, and overlaps without
  claiming removed audio as evidence.
- Verify compact turns address compact WAV samples during voice embedding, while durable
  turns and feed timestamps use the original clock.
- Assert a seam-crossing turn cannot enroll a voice profile and cannot match unless every
  restored fragment independently passes quality and agrees on one existing profile.
- Assert a screen label visible only in a removed gap cannot corroborate a multi-fragment
  audio turn.
- Assert no-speech creates no reservation, ADR-0019 intent, HTTP request, utterance, or
  speaker observation, and leaves provider model/prompt fields null.
- Assert partial compaction produces one shorter WAV and one provider request per attempt.
- Assert detector/map preflight failure produces one identity variant per attempt, never
  a compact/full pair.
- Assert ambiguous retries reuse the exact plan, reserve again, and retain every attempt's
  usage/outcome.
- Assert post-response restoration failure is terminal, persists no transcript, and
  triggers no automated paid fallback.
- Reject work-ID/processor/plan collisions and prove never-attempted migration plus
  attempted-version drain cannot strand jobs.
- Exercise maximum five-minute windows under bounded CPU, memory, and latency.

### Corpus and product-quality matrix

Evaluation covers:

- 10-second through five-minute windows and very sparse speech;
- iOS and Mac, AAC and WAV, microphone and system sources;
- speech at the first/last frame and on both sides of source-event and edit seams;
- whispering, soft/far-field speech, clipping, accents, languages, and code-switching;
- laptop speakers, headphones, built-in/external microphones, Bluetooth, and route
  changes;
- in-person speech, remote calls, missing references, echo, double-talk, and overlap;
- steady/impulsive noise, fans, keyboard sounds, music with and without vocals, laughter,
  and long true silence; and
- one Gemini turn that crosses one or more removed gaps.

The release report compares full-audio control with treatment for word/character error,
speaker count and continuity, diarization/overlap error, named entities, action items and
person facts, silence hallucinations, seam hallucinations, timestamp error, voice-profile
acceptance/match behavior, and final memory quality. Thresholds are pre-registered from
the current full-audio baseline; this ADR does not label unmeasured values as acceptable.

Activation requires all of the following:

- no statistically meaningful recall regression on speech-bearing windows or critical
  names/facts;
- no material speaker-splitting or seam-hallucination regression;
- deterministic mapping and provenance tests at 100%;
- missed-speech rate among `no_speech` decisions below the pre-registered safety bound;
- coherent actual-usage coverage sufficient for a cost conclusion;
- positive net savings after measured enclave capacity and retry cost; and
- successful security, SBOM, export, deletion, build-provenance, and documented
  reproducibility-gap review.

## Consequences

### Positive

- Long quiet intervals are expected to consume fewer paid audio input tokens and reduce
  Vertex-path latency/capacity; activation verifies both.
- Completely speech-free units avoid paid inference and output reservation entirely.
- User-visible and evidentiary timestamps remain on the original timeline.
- The compact asset exposes less speech-free ambient audio to the inference provider.
- The mechanism remains source-aware and composes with future enclave AEC.

### Negative and limitations

- Speech detection, edit-plan persistence, fragment projection, and rollout logic add
  enclave complexity and capacity cost.
- Removing pauses can change punctuation, turn boundaries, speaker continuity, and
  diarization even when every spoken sample is retained.
- High-energy or ambiguous non-speech remains in version 1, limiting maximum savings.
- A logical turn spanning a removed gap has a bounding scalar interval containing that
  gap; exact discontiguous provenance is available separately, but current transcript
  rows cannot attach individual words to fragments.
- The conservative seam-crossing voice rule suppresses some otherwise usable enrollment
  samples until fragment-level quality is calibrated.
- A conservative fail-open posture leaves some recoverable cost on the table.
- Provider tokenization, pricing, and model behavior can change, so savings are not a
  permanent constant.

## Alternatives rejected

- **Amplitude/RMS-only trimming:** clips quiet and far-field speech and confuses steady
  background noise with useful content.
- **Client-authoritative VAD:** produces platform-dependent evidence loss outside the
  enclave guarantee. A client hint may optimize bandwidth later but cannot authorize
  deletion or inference skipping.
- **One Gemini request per speech island:** repeats fixed prompt/output overhead, resets
  local speaker continuity, increases retries, and can cost more than it saves.
- **Ask Gemini to ignore silence:** the audio still enters the context and consumes input
  tokens.
- **Send the edit list to Gemini and ask for original timestamps:** adds private activity
  metadata to the prompt and replaces deterministic local arithmetic with model behavior.
- **Playback-speed or time-stretch compression:** damages speech, diarization, and voice
  embeddings and makes timestamp mapping non-affine.
- **Lossy re-encoding or smaller WAVs:** reduces bytes, not decoded audio duration, and
  therefore is not a reliable token-cost control.
- **Post-transcription silence removal:** may clean the UI but cannot save the already
  consumed Vertex input.
- **Hard-concatenate activity with no real padding:** can join phonemes or speakers across
  a seam and increase hallucinations.
- **Only skip all-silence units forever:** it is the safest first rollout stage but leaves
  long internal quiet intervals billable.
- **Always send full audio:** preserves the simplest clock and maximum acoustic context,
  but continues paying for duration with no speech and provides no no-speech fast path.

## Follow-up work

1. Build the consented silence/quiet-speech evaluation corpus and pre-register quality
   thresholds.
2. Benchmark WebRTC VAD and a model-based detector, then pin the selected artifact and
   policy in the image and SBOM.
3. Implement a sample-domain compaction plan, encrypted schema, exact fragment projector,
   no-speech completion path, and processor-version migration behind identity mode.
4. Add the append-only encrypted plan-attempt binding and compaction/CPU/cache-modality
   fields while preserving ADR-0019's content-free external contract.
5. Add sticky single-variant control/treatment evaluation and owner cost reporting based
   on fully priced ADR-0019 evidence.
6. Compose the stage after source-aware AEC and residual echo suppression without
   compacting its far-end reference.
7. Evaluate word-level timestamps or a first-class multi-interval utterance model if the
   bounding-interval limitation harms evidence presentation.
8. Revalidate or disable compaction whenever the Gemini model, audio timestamp mode,
   detector, prompt, codec normalization, or provider rate changes.
9. Update `src/cp/map.md`, `SECURITY.md`, export schemas/API documentation, and active
   processing contracts when implementation changes those responsibilities.

## References

- [ADR-0019: Privacy-preserving Vertex cost attribution](0019-privacy-preserving-vertex-cost-attribution.md)
- [Google Cloud Gemini pricing](https://cloud.google.com/gemini-enterprise-agent-platform/generative-ai/pricing)
- [Google generative-AI glossary: audio token estimate](https://docs.cloud.google.com/docs/generative-ai/glossary#tokens)
- [Gemini 3.5 Flash model documentation](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/3-5-flash)
- [Vertex audio understanding and timestamp mode](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/capabilities/audio-understanding)
- [Vertex Count Tokens documentation](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/capabilities/get-token-count)
- [Vertex GenerateContent usage metadata](https://docs.cloud.google.com/gemini-enterprise-agent-platform/reference/rest/v1/GenerateContentResponse#UsageMetadata)
- [Vertex implicit and explicit context caching](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/context-cache/context-cache-overview)
