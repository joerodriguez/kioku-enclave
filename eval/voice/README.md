# Voice and identity evaluation

This directory is the public ADR-0016 evidence, scoring, and release contract.
`voice_eval_evidence.rs` turns a strict private run export into content-free
schema-v3 release cases, while `voice_eval.rs` independently recomputes every
metric and refuses incomplete or modified evidence. Synthetic schema-v1 cases
pin arithmetic, same-name collision handling, abstention, and
fact/export/delete coverage, but can never substantiate a quality claim. A
hand-authored schema-v1 `real_audio` aggregate can no longer pass release gates.

A real-corpus run emits one content-free case per scored source interval. It
must cover clean two-person calls, 3+ speakers, overlap, introductions,
repeated meetings, same-name people, similar voices, system and room audio,
Mac/iPhone/Bluetooth domains, compression, noise, music, echo, French,
English, mixed language, active-speaker evidence, roster-only names, and
conflicting evidence. Restricted media stays outside the repository. Its
acquisition manifest must record each authoritative source and license, every
immutable artifact SHA-256, selected speaker/clip IDs, and derivation command. Generated
case JSON contains hash-shaped opaque case/person/collision/record labels,
source hashes, and timestamp intervals. It must not contain names, transcript
text, URLs, image text, embeddings, raw scores, media paths, or source-system
identifiers. Unknown fields are rejected, so prohibited content cannot be
smuggled alongside otherwise valid evidence.

The release report must pass all ADR gates. A model, scorer, quality threshold,
codec/domain mapping, or fixture change requires a new corpus/report ID and a
checked-in regression report; a synthetic-only report always has
`release_gates_pass: false`. Real quality metrics are calculated only from
`corpus_kind: "real_audio"` cases, so synthetic cases cannot pad precision or
recall.

The report emits `identity_metrics_by_slice` for every evaluated slice. Each
entry exposes the case, prediction, and abstention counts; accepted-name correct
and wrong counts; cross-meeting correct counts; after-three-sample recognized
counts; and the corresponding rates. Zero denominators remain visible as zero
counts and zero rates instead of disappearing. Global gates are computed from
the same shared counter implementation, not by averaging slice percentages.
This makes a model or threshold comparison reviewable for every device,
language, noise, overlap, and adversarial slice without publishing raw voice
scores or private content.

The private run input conforms to `run-evidence-schema-v3.json`. It binds the
evaluated enclave image digest, source commit, Vertex model, exact voice-model
hash, embedding/scorer/quality versions, exact match/new-profile/margin/outlier
thresholds, account-export artifact hash, and post-delete storage-scan hash. It records opaque reference and predicted
speaker intervals plus raw identity/fact/record decisions. The reducer derives,
rather than trusts, every metric-bearing case field.

Each schema-v3 case records:

- opaque unique case, recording, meeting, expected-person, predicted-person,
  collision, fact, evidence, source-record, and created-record IDs;
- the actual binding lifecycle state and prior high-quality sample count, from
  which accepted-name, cross-meeting, and after-three-sample decisions derive;
- accepted fact rows and their evidence/source-record bindings; and
- exact created, exported, and deleted record-ID sets. Export/delete IDs must
  be subsets of the created set and record IDs must be globally unique.

Each recording contains opaque reference and predicted speaker intervals plus
exactly one identity-decision row for every predicted speaker. The scorer
computes overlap-aware diarization error and a deterministic optimal one-to-one
mapping between the two opaque speaker namespaces. Each reference speaker has
exactly one identity case; that case names the reference speaker, and its
predicted person/binding state must equal the decision attached to the mapped
prediction. An unmatched reference must abstain. Reference speech, misses,
false alarms, confusion, overlapping speaker-time, and the speaker-to-identity
join are therefore not independent operator-supplied claims. Same-display-name
evidence must use distinct recordings/reference speakers for at least two
distinct expected people.

The record totals include profile proposals, append-only profile revisions,
active/superseded sample assignments, and proposal source/result membership.
Source profiles and prior assignments count toward export/delete coverage even
after a merge, split, or reversal.

The corpus root includes `diarization_error_baselines` for `noise`,
`room_audio`, and `overlap`. The scorer reports weighted diarization error for
every slice and fails closed if a required baseline is absent/invalid or the
current slice exceeds it. Empty metric denominators, unknown corpus kinds,
duplicate case IDs, missing slices, stale reports, partial fact provenance,
and partial export/deletion also fail closed.

The strict schema-v2 source manifest has a corpus ID, one or more licensed
public sources, and one or more owner-controlled fixtures. A public source
records an opaque ID, HTTPS license URL, SPDX-style license ID, and one or more
independently hash-bound artifacts. Artifact roles distinguish media, labels,
combined bundles, and augmentation inputs, so a meeting WAV cannot silently be
paired with unrelated annotations. The source also binds opaque selected-item
IDs, covered slices, and the bounded deterministic derivation command.

An owner fixture records opaque IDs and SHA-256 bindings for its media,
ground-truth labels, and separately retained recording-authorization record. It
must assert physical capture, its owner-speech/licensed-playback/mixed origin,
any licensed sources replayed into the device, and exact Mac system/Mac mic/
iPhone mic/Bluetooth/screen-capture routes. Route claims are checked against the
device/UI slices. The authorization document and all media/labels remain outside
Git. The manifest must cover every required slice, and owner fixtures
specifically must cover Mac system audio, Mac microphone, iPhone microphone,
Bluetooth, active-speaker UI, and same-display-name separation.

The case builder computes the exact raw-byte SHA-256 of both the checked-in
manifest and private run evidence. The cases and report repeat those bindings.
Changing a source selection, license, fixture, hash, derivation command, run
record, or pipeline identity therefore makes the release bundle stale until
the real run and report are regenerated.

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

- `eval/voice/release-manifest.json` — schema-v2 licensed-artifact hashes,
  selections, physical routes, playback lineage, and owner authorizations;
- `eval/voice/release-cases.json` — schema-v3 content-free evidence and
  derived cases produced from the licensed real corpus and owner-controlled
  export/delete assertions;
- `eval/voice/release-report.json` — the deterministic scorer output for
  those exact cases.

After a real run, generate the canonical cases from the reviewed manifest and
the private run export, then generate and validate the report:

```sh
cargo run --locked -- \
  --build-voice-eval-cases \
  eval/voice/release-manifest.json \
  /absolute/private/path/kioku-voice-run-evidence-v3.json \
  > eval/voice/release-cases.json

cargo run --locked -- \
  --score-voice-eval eval/voice/release-cases.json \
  > eval/voice/release-report.json

cargo run --locked -- \
  --check-voice-eval \
  eval/voice/release-manifest.json \
  eval/voice/release-cases.json \
  eval/voice/release-report.json
```

Validate the completed manifest and fetch its exact licensed artifacts into an
explicit location outside the source checkout with:

```sh
cargo run --locked -- \
  --validate-voice-eval-manifest eval/voice/release-manifest.json

./scripts/fetch_voice_eval_assets.sh \
  eval/voice/release-manifest.json \
  /absolute/private/path/kioku-voice-eval-assets
```

The case builder inserts the manifest and private run raw-byte SHA-256 bindings
automatically. They are not operator-entered fields. Any later input edit
deliberately invalidates the generated bundle.

The fetcher refuses an in-repository destination, uses HTTPS only, downloads
every separately identified artifact, never replaces an existing mismatched
file, and verifies SHA-256 before making a download visible at its final path.
The explicit private output directory must already exist.

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
