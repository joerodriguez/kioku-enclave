# map.md — eval/voice/

| File | Role |
|---|---|
| `README.md` | Required real-corpus coverage, licensing/hash rules, and release-report policy |
| `synthetic-contract-v1.json` | Redistributable content-free cases that pin scorer arithmetic and prove synthetic evidence can never pass release gates |

Run `kioku-enclave --score-voice-eval <cases.json>` to emit the aggregate report.
Real audio stays in its licensed source location or an access-controlled evaluator;
committed reports contain only opaque case labels and aggregate measurements.
