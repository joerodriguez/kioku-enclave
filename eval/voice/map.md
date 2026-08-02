# map.md — eval/voice/

| File | Role |
|---|---|
| `README.md` | Aggregate case contract, denominator-visible per-slice identity/abstention metrics, required real-corpus coverage, licensing/hash rules, slice baselines, canonical release artifacts, and fail-closed release policy |
| `synthetic-contract-v1.json` | Redistributable content-free cases that pin scorer arithmetic and prove synthetic evidence can never pass release gates |
| `run-evidence-schema-v2.json` | Strict private run-input contract for pipeline/version identity, hash-bound source recordings and labels, opaque diarization intervals, exact predicted-speaker identity rows, reference-speaker cases, fact provenance, and exact create/export/delete record sets |

Run `kioku-enclave --build-voice-eval-cases <manifest.json>
<private-run-evidence.json>` to derive the schema-v2 content-free cases, then
`kioku-enclave --score-voice-eval <cases.json>` to emit an aggregate report,
then `kioku-enclave --check-voice-eval <manifest.json> <cases.json>
<report.json>` to require a hash-bound, exactly matching passing bundle.
Real audio stays in its licensed source location or an access-controlled evaluator;
committed reports contain only opaque case labels and aggregate measurements.
`scripts/fetch_voice_eval_assets.sh` validates the final manifest and downloads
each exact hash-pinned licensed archive into an explicit directory outside Git.
