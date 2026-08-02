# Voice and identity evaluation

This directory is the public ADR-0016 scoring and release contract.
`voice_eval.rs` reads strict aggregate JSON, computes every release metric,
and refuses to mark a corpus release-ready without complete real-audio
coverage. Synthetic cases pin arithmetic, same-name collision handling,
abstention, and fact/export/delete coverage, but never contribute to release
metrics once real cases exist and can never substantiate a quality claim.

A real-corpus run emits one content-free case per scored source interval. It
must cover clean two-person calls, 3+ speakers, overlap, introductions,
repeated meetings, same-name people, similar voices, system and room audio,
Mac/iPhone/Bluetooth domains, compression, noise, music, echo, French,
English, mixed language, active-speaker evidence, roster-only names, and
conflicting evidence. Restricted media stays outside the repository. Its
acquisition manifest must record the authoritative source, license, immutable
archive SHA-256, selected speaker/clip IDs, and derivation command. Generated
case JSON contains opaque labels and aggregate timing/count decisions only. It
must not contain names, transcript text, URLs, image text, embeddings, raw
scores, media paths, or source-system identifiers.

The release report must pass all ADR gates. A model, scorer, quality threshold,
codec/domain mapping, or fixture change requires a new corpus/report ID and a
checked-in regression report; a synthetic-only report always has
`release_gates_pass: false`. Real quality metrics are calculated only from
`corpus_kind: "real_audio"` cases, so synthetic cases cannot pad precision or
recall.

Each aggregate case records:

- an opaque unique case ID, slice, expected/predicted opaque person IDs, and
  accepted-name/cross-meeting/after-three-samples decisions;
- reference speech and diarization-error milliseconds;
- accepted fact and provenance counts; and
- total, exported, and deleted counts for the ADR-0016 records created by the
  test. The last three counts come from an export assertion followed by an
  account-delete/storage assertion, not from a model response.

The corpus root includes `diarization_error_baselines` for `noise`,
`room_audio`, and `overlap`. The scorer reports weighted diarization error for
every slice and fails closed if a required baseline is absent/invalid or the
current slice exceeds it. Empty metric denominators, unknown corpus kinds,
duplicate case IDs, missing slices, stale reports, partial fact provenance,
and partial export/deletion also fail closed.

Run the checked-in contract fixture with:

```sh
cargo run --locked -- --score-voice-eval eval/voice/synthetic-contract-v1.json
```

## Release artifacts and commands

The two canonical, reviewed release inputs are intentionally not fabricated by
the repository:

- `eval/voice/release-cases-v1.json` — content-free aggregates produced from
  the licensed real corpus and owner-controlled export/delete assertions;
- `eval/voice/release-report-v1.json` — the deterministic scorer output for
  those exact cases.

After a real run, generate and validate the report with:

```sh
cargo run --locked -- \
  --score-voice-eval eval/voice/release-cases-v1.json \
  > eval/voice/release-report-v1.json

cargo run --locked -- \
  --check-voice-eval \
  eval/voice/release-cases-v1.json \
  eval/voice/release-report-v1.json
```

The check semantically recomputes the report and returns nonzero if it is stale
or any gate fails. `scripts/release.sh` runs it before creating a signed tag,
and tag CI runs it again before building or publishing a release. Until both
files exist and pass, the missing release is deliberate: an ordinary `main`
image may be built for evaluation, but it cannot become a release artifact.

A release corpus must contain `real_audio` cases for every scorer slice:
`clean_remote_call`, `three_plus_speakers`, `overlap`, `introduction`,
`repeated_meeting`, `same_display_name`, `similar_voices`, `system_audio`,
`room_audio`, `mac_microphone`, `iphone_microphone`, `bluetooth`, `compression`,
`noise`, `music`, `echo`, `french`, `english`, `mixed_language`,
`active_speaker_ui`, `roster_only`, and `conflicting_evidence`. The report lists
any missing slices and cannot pass while that list is nonempty.
