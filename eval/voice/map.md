# map.md — eval/voice/

| File | Role |
|---|---|
| `README.md` | Aggregate case contract, denominator-visible per-slice identity/abstention metrics, required real-corpus coverage, multi-artifact licensing/hash rules, physical-route lineage, slice baselines, canonical release artifacts, and fail-closed release policy |
| `synthetic-contract-v1.json` | Redistributable content-free cases that pin scorer arithmetic and prove synthetic evidence can never pass release gates |
| `source-manifest-schema-v2.json` | Public source contract for separately hash-bound media/label/bundle/augmentation artifacts plus authorized physical owner captures, playback lineage, and exact device/UI routes |
| `derivation-recipe-schema-v1.json` | Strict private offline recipe contract for exact source members, fixed-point trims/mixes, opaque reference timing, and content-free hash receipts; recipes and outputs stay outside Git |
| `run-evidence-schema-v3.json` | Strict private run-input contract for pipeline/version identity, exact primary and independently licensed augmentation source-artifact bindings, opaque diarization intervals, exact predicted-speaker identity rows, reference-speaker cases, fact provenance, and exact create/export/delete record sets |

Run `kioku-enclave --build-voice-eval-cases <manifest.json>
<private-run-evidence.json>` to derive the schema-v3 content-free cases, then
`kioku-enclave --score-voice-eval <cases.json>` to emit an aggregate report,
then `kioku-enclave --check-voice-eval <manifest.json> <cases.json>
<report.json>` to require a hash-bound, exactly matching passing bundle.
Real audio stays in its licensed source location or an access-controlled evaluator;
committed reports contain only opaque case labels and aggregate measurements.
`scripts/fetch_voice_eval_assets.sh` validates the final manifest and downloads
each exact hash-pinned licensed artifact into an explicit directory outside Git.
`kioku-enclave --derive-voice-eval-assets` verifies those artifacts again,
permits only explicitly typed cross-source augmentations with slice-compatible
independent license lineage, and materializes deterministic canonical
WAV/opaque-label pairs plus a receipt in a separate private output directory.
