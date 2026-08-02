# Voice and identity evaluation

This directory is the public ADR-0016 scoring contract. `voice_eval.rs` reads
the strict JSON case shape, computes every release metric, and refuses to mark
a corpus release-ready unless at least one case is labeled `real_audio`.
Synthetic cases pin arithmetic, same-name collision handling, abstention, and
fact provenance but cannot substantiate product-quality claims.

A real-corpus run emits one content-free case per scored source interval. It
must cover clean two-person calls, 3+ speakers, overlap, introductions,
repeated meetings, same-name people, similar voices, system and room audio,
Mac/iPhone/Bluetooth domains, compression, noise, music, echo, French,
English, mixed language, active-speaker evidence, roster-only names, and
conflicting evidence. Restricted media stays outside the repository. Its
acquisition manifest must record the authoritative source, license, immutable
archive SHA-256, selected speaker/clip IDs, and derivation command. Generated
case JSON contains opaque labels and aggregate timing/count decisions only.

The release report must pass all ADR gates. A model, scorer, quality threshold,
codec/domain mapping, or fixture change requires a new corpus/report ID and a
checked-in regression report; a synthetic-only report always has
`release_gates_pass: false`.

Run the checked-in contract fixture with:

```sh
cargo run --locked -- --score-voice-eval eval/voice/synthetic-contract-v1.json
```

A release corpus must contain `real_audio` cases for every scorer slice:
`clean_remote_call`, `three_plus_speakers`, `overlap`, `introduction`,
`repeated_meeting`, `same_display_name`, `similar_voices`, `system_audio`,
`room_audio`, `mac_microphone`, `iphone_microphone`, `bluetooth`, `compression`,
`noise`, `music`, `echo`, `french`, `english`, `mixed_language`,
`active_speaker_ui`, `roster_only`, and `conflicting_evidence`. The report lists
any missing slices and cannot pass while that list is nonempty.
