# map.md — eval/voice/

| File | Role |
|---|---|
| `README.md` | Aggregate case contract, required real-corpus coverage, licensing/hash rules, slice baselines, canonical release artifacts, and fail-closed release policy |
| `synthetic-contract-v1.json` | Redistributable content-free cases that pin scorer arithmetic and prove synthetic evidence can never pass release gates |

Run `kioku-enclave --score-voice-eval <cases.json>` to emit an aggregate report,
then `kioku-enclave --check-voice-eval <manifest.json> <cases.json>
<report.json>` to require a hash-bound, exactly matching passing bundle.
Real audio stays in its licensed source location or an access-controlled evaluator;
committed reports contain only opaque case labels and aggregate measurements.
`scripts/fetch_voice_eval_assets.sh` validates the final manifest and downloads
each exact hash-pinned licensed archive into an explicit directory outside Git.
