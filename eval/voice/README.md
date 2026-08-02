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
case JSON contains hash-shaped opaque case/person/collision labels and aggregate
timing/count decisions only. It
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

The strict source manifest has a corpus ID, one or more licensed public
sources, and one or more owner-controlled fixtures. A public source records an
opaque ID, HTTPS archive and license URLs, SPDX-style license ID, exact archive
SHA-256, opaque selected-item IDs, covered slices, and the bounded derivation
command. An owner fixture records only opaque IDs and SHA-256 bindings for its
media, ground-truth labels, and separately retained recording-authorization
record. The authorization document and all media/labels remain outside Git.
The manifest must cover every required slice, and owner fixtures specifically
must cover Mac system audio, Mac microphone, iPhone microphone, Bluetooth,
active-speaker UI, and same-display-name separation.

The aggregate cases include the exact raw-byte SHA-256 of the checked-in
manifest, and the report repeats that binding. Changing a source selection,
license, fixture, hash, or derivation command therefore makes the release
bundle stale until the real run and report are regenerated.

Suitable authoritative inputs include the
[AMI Meeting Corpus](https://groups.inf.ed.ac.uk/ami/corpus/) for licensed
multi-speaker, overlap, headset, and room-array recordings; the
[Mozilla Common Voice datasets](https://commonvoice.mozilla.org/en/datasets)
for CC0 English/French speakers; [MUSAN](https://www.openslr.org/17/) for
CC BY 4.0 noise/music augmentation; and the
[OpenSLR room impulse/noise set](https://www.openslr.org/28/) for Apache-2.0
room/echo transformations. These are source candidates, not pre-approved
substitutes for review: the final manifest must use direct immutable archive
URLs, exact hashes, license URLs, selected IDs, and deterministic derivation.
Derived mixtures retain every applicable source attribution and must never be
used to satisfy the owner-device/UI fixture requirement.

Run the checked-in contract fixture with:

```sh
cargo run --locked -- --score-voice-eval eval/voice/synthetic-contract-v1.json
```

## Release artifacts and commands

The three canonical, reviewed release inputs are intentionally not fabricated by
the repository:

- `eval/voice/release-manifest-v1.json` — licensed-source hashes/selections and
  opaque owner-fixture media/label/authorization bindings;
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
  eval/voice/release-manifest-v1.json \
  eval/voice/release-cases-v1.json \
  eval/voice/release-report-v1.json
```

Validate the completed manifest and fetch its exact licensed archives into an
explicit location outside the source checkout with:

```sh
cargo run --locked -- \
  --validate-voice-eval-manifest eval/voice/release-manifest-v1.json

./scripts/fetch_voice_eval_assets.sh \
  eval/voice/release-manifest-v1.json \
  /absolute/private/path/kioku-voice-eval-assets
```

Copy the validator's raw-byte SHA-256 into the aggregate cases as
`source_manifest_sha256` before scoring. Any later manifest edit deliberately
invalidates that binding.

The fetcher refuses an in-repository destination, uses HTTPS only, never
replaces an existing mismatched archive, and verifies SHA-256 before making a
download visible at its final path.

The check validates and hash-binds the manifest, semantically recomputes the
report, and returns nonzero if the bundle is stale or any gate fails.
`scripts/release.sh` runs it before creating a signed tag,
and tag CI runs it again before building or publishing a release. Until all
three files exist and pass, the missing release is deliberate: an ordinary `main`
image may be built for evaluation, but it cannot become a release artifact.

A release corpus must contain `real_audio` cases for every scorer slice:
`clean_remote_call`, `three_plus_speakers`, `overlap`, `introduction`,
`repeated_meeting`, `same_display_name`, `similar_voices`, `system_audio`,
`room_audio`, `mac_microphone`, `iphone_microphone`, `bluetooth`, `compression`,
`noise`, `music`, `echo`, `french`, `english`, `mixed_language`,
`active_speaker_ui`, `roster_only`, and `conflicting_evidence`. The report lists
any missing slices and cannot pass while that list is nonempty.
