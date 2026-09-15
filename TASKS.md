# Voice thresholds for the classroom test (2026-09-15)

- [x] Creation threshold 0.45 → 0.35 and runner-up margin 0.08 → 0.10; match stays 0.60 per
      ADR-0006's real-capture calibration; two-mode quarantine keeps its own 0.45 separation
      constant instead of following the creation threshold.
- [ ] Revisit all four values only with labeled data: a bounded owner review of matched turns
      after the first classroom recording (wrong-person and same-name-merge counts must be zero),
      then the licensed-corpus calibration (`voice_eval_similarity.rs`). The run-evidence schema
      pins the new values; `MODE_SEPARATION_THRESHOLD` and `DETECTOR_VERSION` are not yet pinned.

# Voice fragment absorption (2026-09-15)

- [x] Absorb settled tentative fragments into the durably stable voice every clean sample
      matches (owner path first, runner-up margin, fragments as tolerant runner-ups, named
      fragments only into the same person), reconsidered and reversed under their own rule.
- [ ] Reversal depth: `reverse` requires the result's exact applied revision and membership,
      so after a second absorption (or merge) into the same result only the newest proposal
      is reversible and an earlier absorbed fragment cannot be unwound. Make reversal tolerant
      of revisions and assignments introduced by later reversed proposals on the same result.

# Voice sample yield (2026-09-15)

- [x] Embed a long turn's gate-admitted, speech-densest thirty seconds instead of its first
      thirty; judge frame levels relative to the chunk with a -50 dBFS floor and a 12 dB
      dynamic-range guard (detector 2 inside quality policy 1).
- [ ] Add `detector_version` and the span policy to the voice evaluation run-evidence pins
      (`voice_eval_evidence.rs`, `eval/voice/run-evidence-schema-v3.json`) before any
      real-corpus evidence is produced; today the evidence cannot distinguish detector 1 /
      first-thirty-seconds from detector 2 / best-span at the same `quality_version`.
- [ ] Decide whether samples quarantined under detector 1 are re-diagnosed (a bounded
      providerless maintenance pass over `accepted=false` samples with retained media) or
      left as history; today only new turns benefit.

# ADR-0048 one identity source (2026-09-13)

- [x] Implement immutable per-field maps, current label projection, transaction-coalesced
      semantic revisions and successful identity-refresh throttling in direct v34.
- [x] Freeze a provider-wide namespace for forward context and organizer requests;
      preserve original durable requests, staged maps and retained finalized text maps.
- [x] Integrate list/detail, search, capture status, person memories, playback and outbound
      freeze; fence delayed embeddings against the exact current resolved input.
- [x] Pass the complete real PostgreSQL/model gate on the final reviewed source:
      614 passed, zero failures, one existing manual probe ignored; formatting and
      strict all-target Clippy passed (1608.29 seconds). Earlier failed attempts and
      corrected fixtures/lints retain separate evidence; the final full rerun passed.
- [x] Independently review implementation and source-specific semantic reversals:
      39 compiling proof runs cover 38 distinct reversal models with exact restoration.
- Backend source is delivered through this reviewed PR; web/iPhone/operator source
  delivery and both merged refs are tracked in the monorepo Phase 5 progress record.
- [ ] Complete Phase 6 real owner-archive and ADR-0016 acceptance with content-free evidence.
      Synthetic verification does not establish owner accuracy or production behavior.

# ADR-0048 name evidence fusion (2026-09-12)

- [x] Implement typed grounded name evidence, exact screen joins, independent vocative
      votes and corroboration, deterministic versioned bindings and name-only conflicts.
- [x] Remove account-wide name reuse; preserve opaque people across acoustic domains,
      temporary introduction retirement and reciprocal same-name collision holds.
- [x] Persist actual scored fact candidates with current-authority public reads,
      bounded enrichment and explicit temporal role/organization replacement history.
- [x] Add the direct v33 companion to startup/readiness, export, erasure and the existing CLI.
- [x] Verify synthetic contracts, compiling production reversals and independent reviews.
- [x] Pass the exhaustive PostgreSQL/model gate on final reviewed source: 589 passed,
      zero failures, one existing manual probe ignored; formatting and strict all-target
      Clippy passed. The first attempt passed tests but failed two mechanical lints;
      both were independently reviewed and the complete corrected-source rerun passed.
- [x] Merge backend #520 (`ebef7b350235`) and operator #533 (`4f11ed760e6f`).
- [ ] Complete Phase 5 graph-driven briefs and Phase 6 real owner acceptance.

# ADR-0048 automatic profile reconciliation (2026-09-12)

- [x] Implement v32 proposal/member/slot provenance, reciprocal complete-population
      merging, exact reversal, mixed-mode quarantine and current-policy adoption.
- [x] Pass real PostgreSQL apply/reversal, stale/deletion/identity refusal,
      source/letter preservation, tenant/export/erasure and fourteen semantic
      production-reversal groups (nineteen focused runs, twenty-two named assertions).
- [x] Resolve six independent review findings, including complete competitors and
      sample bounds independent of scheduling/adoption.
- [x] Pass the exhaustive PostgreSQL/model/Clippy gate on the final reviewed source:
      560 passed, zero failures, one pre-existing manual probe ignored; formatting
      and strict all-target Clippy pass. Exact restored source hashes are recorded.
- [x] Merge reviewed backend #519 (`20d9776f`) and operator #532 (`cfa8d893`).
- [ ] Complete Phase 4 name fusion, Phase 5 identity-driven briefs and Phase 6 real
      owner acceptance. No release or production result is claimed here.

# ADR-0048 cross-memory matching and recurring People (2026-09-12)

- [x] Match against compatible stable account-wide voices after session continuity, with three clean observations for stability and bounded provider-free stored-sample reconsideration.
- [x] Erase expired/withdrawn non-owner support independently of Pause and recompute before projecting labels.
- [x] Promote stable voices at three current memories or twenty minutes of union speech; preserve opaque IDs and Speaker letters, current context, and complete withdrawal despite candidate overflow.
- [x] Add separately paged identified/recurring People routes with coherent read snapshots and owner/private-status exclusion.
- [x] Resolve independent foundation and People review findings; ten recurrence/label production reversals reach named semantic assertions and exact restored tests pass, alongside earlier scope and maintenance proofs.
- [x] Pass full PostgreSQL/model verification:545passed, one existing manual probe ignored; formatting and strict all-target Clippy pass. Independent final composed review has no unresolved finding.
- [x] Merge the matching/People source in #518 (`8780f100`); downstream client #528 is merged at `d13959ef` (web287, iPhone226).
- [x] Implement and verify Phase3 automatic proposals, exact append-only reversal,
      bimodal quarantine and current-policy adoption of stored assigned profiles;
      reviewed delivery is recorded in the section above.
- [ ] Finish Phase4 name fusion, Phase5 identity-driven summaries and Phase6 real owner acceptance. Synthetic verification does not establish production acceptance.

# Content-specific brief sections (2026-09-11)

- [x] Add bounded LLM-authored, evidence-backed sections; retain truthful semantic compatibility projections and legacy in-flight output handling.
- [x] Persist sections atomically and return/search/export them; preserve consented email/webhook parity.
- [x] Implement separately receipted v29 migration and mandatory serving verification without rewriting base/activation contracts.
- [x] Pass the full local gate: 454 Rust tests passed, one preexisting intentional ignore, PostgreSQL 17 contracts, formatting and all-target Clippy; independent review findings resolved.
- [ ] Separately authorize and perform v29 installation, drained homogeneous finalizer cutover, and coordinated backend/web/iPhone release.

# Memory playback and speaker projection repair

- [x] Bound public playback revisions to JavaScript's exact integer range so an unchanged
      browser manifest can authorize its segment instead of entering a permanent `409` loop.
- [x] Project episode-member and summary-evidence utterances at their stored turn time rather
      than repeating the enclosing audio segment's start time.
- [x] Preserve a sole local-transmit speaker as owner source and render owner-source attribution
      as **Me** without creating a duplicate self-named attendee.
- [x] Add focused revision, owner-source, and PostgreSQL query-shape regressions.
- [x] Pass the complete local gate against disposable PostgreSQL 17: 279 runnable Rust tests,
      one intentional ignore, the real PostgreSQL contract, formatting, check, and Clippy.
- [ ] Land and deploy the compatible enclave/web changes, then use a separately reviewed,
      versioned episode repair for any already persisted false person binding; replay must not
      mutate successful media work in place.

# PostgreSQL-only structured-state cleanup (ADR-0042)

Production has no users or legacy user data to migrate. This cleanup removes the retired
SQLite/GCS authority rather than preserving it as a swappable backend. It must not add backfill,
dual-write, shadow-read, import, or reverse-rollback machinery.

## Runtime and persistence

- [x] Make PostgreSQL the unconditional serving authority across startup, routes, workers,
  exports, episode/account deletion, restart recovery, search, and readiness.
- [x] Delete the SQLite ControlStore/Store implementation, SQLite search/FTS/vector adapters,
  backend selection/fallback branches, archive-v3/WAL/checkpoint/witness runtime, and legacy-only
  tests after PostgreSQL parity is proved.
- [x] Preserve domain repository ports and useful in-memory fakes; do not couple HTTP handlers or
  provider adapters directly to `sqlx`.
- [x] Keep GCS exclusively for live application-encrypted media and recording bytes, including
  exact-generation access, conditional writes, object-bound authenticated context, and complete
  deletion inventory. Do not delete live media buckets or PostgreSQL state.
- [x] Confirm the final serving source has no reachable SQLite authority/fallback, no obsolete
  archive/WAL/witness runtime, and no unjustified `rusqlite` or SQLite extension dependency.

## Configuration, tooling, and infrastructure

- [x] Remove obsolete checked-in archive/witness/genesis configuration, capacity fixtures,
  release-tag sequencing, SQLite image workaround, and legacy-only tooling tests.
- [x] Make `agent-verify.sh full` require an explicit real PostgreSQL URL, export the fail-closed
  contract signal, and refuse to silently assume Docker availability.
- [x] Keep the signed local release path, immutable source/tag/image binding, SBOM, vulnerability
  scan, Ed25519 evidence, canonical release metadata, and incompatible scale-to-zero lane.
- [x] Remove the dead image/runtime PostgreSQL schema-mode key; serving verifies schema
  unconditionally, while release evidence records that fixed source invariant directly.
- [x] Reduce production configuration to PostgreSQL, shared TLS, KMS, live media/recordings,
  authentication, billing, inference, and outbound-provider inputs.
- [x] In the deployment repository, remove retired authority selectors and unreachable infrastructure
  wiring while preserving Cloud SQL, live media/recordings, KMS admission, shared TLS, the regional
  fleet, health checks, and provider identities. Apply the source-only state transition and finish
  it with an independently reviewed refreshed no-change plan.
- [ ] After a homogeneous v0.9.10 rollout is proved, retire the five exact predecessor legacy-IAM
  edges and the separately inventoried protected provider objects through reviewed, staged plans;
  never combine that retirement with the serving rollout.

## Required verification before merge

- [x] Run focused Rust repository/worker/API tests continuously while source slices settle.
- [x] Run every checked-in Python and shell tooling contract.
- [x] Run `./scripts/agent-verify.sh full` against disposable PostgreSQL 17 and prove the harness
  cannot skip contracts when `KIOKU_REQUIRE_POSTGRES_CONTRACT=1`.
- [x] Prove real PostgreSQL tenant isolation, schema readiness, full-text/vector/time-zone queries,
  concurrent claims, expired-lease takeover, stale settlement refusal, provider ambiguity/no
  resend, restart enumeration, export, episode deletion, account deletion, and no resurrection.
- [x] Run clean formatting, locked tests, all-target Clippy, production-feature builds, RustSec,
  SBOM generation, and vulnerability scanning; record the exact commands and results in the PR.
- [x] Rebase onto current `origin/main`, obtain review, and rebase-merge. Do not push directly to
  `main`.

## Release and rollout, if the runtime digest changes

- [ ] Publish from a signed standard `vMAJOR.MINOR.PATCH` tag with schema-13 metadata and exact
  source/image/config/SBOM/scan/evidence bindings.
- [ ] Follow ADR-0041's staged zero-unavailable regional rollout: predecessor/candidate KMS
  admission, canary, PostgreSQL schema and shared-TLS readiness, authenticated API and content-free
  provider-effect probes, member-by-member replacement, predecessor retirement, and final
  no-change Terraform plan.
- [ ] Record the exact source commit, signed tag, image digest, KMS condition, PostgreSQL authority
  and schema, fleet member zones/digests, readiness/liveness, no-op/effect-safety receipts, and
  final infrastructure plan.

# Existing product gates preserved by the cleanup

## ADR-0029 ready-notification delivery

- [x] Persist per-installation APNs registrations with account-switch and credential-generation
  fencing; commit first-finalization deliveries atomically and never replay regeneration.
- [x] Use privacy-safe per-device handoff handles, owner-only resolution, bounded expiry/pacing,
  provider ambiguity as terminal no-resend, and content-free telemetry.
- [x] Use durable PostgreSQL claim/lease/settlement transitions so horizontal workers cannot send
  the same provider effect twice; deletion and credential rotation conflict with an in-flight
  destination before disclosure.
- [x] Keep APNs non-blocking to memory finalization while production startup and release fail closed
  on an incomplete provider configuration.

## ADR-0030 silence compaction

- [ ] Keep speech-time compaction disabled until its versioned real-corpus recall, timestamp
  restoration, provider-token, latency, and net-cost gates pass. The structured-state cleanup does
  not activate or weaken those gates.

## ADR-0036 durable recording audio

- [ ] Keep external durable-recording/playback activation blocked until export includes all media
  bytes and account/episode deletion inventories every exact live and noncurrent recording
  generation. The cleanup preserves the live recordings bucket and its KMS/media boundary.

## Organizer provider request frozen per attempt

- [x] Reproduce on real PostgreSQL that an accepted speaker name between two tries of one
  durable reconciliation attempt re-renders a different model input under the unchanged
  attempt identity, which the usage ledger refuses (`reconciliation_provider_request_contract`).
- [x] Freeze the exact rendered input and its speaker namespace on the first try
  (`reconciliation_provider_requests`, v36 companion) and replay it on every later try of
  the attempt, as capture formation replays its persisted page request; a ledger refusal of
  a reused attempt identity now settles from the stored outcome (not-billed advances,
  anything else is the conservative keep) instead of retrying the same identity forever.
- [ ] Release: install v36 after v35 (`reconciliation-provider-request-v36-install`); no
  producer contract re-pin.

## ADR-0049 memory language follows the reader

- [x] Accept an optional BCP-47 `locale_id` on the capture manifest, persist it through the
  receipted v35 `memory-language-v35-install` companion, and resolve the authoring language from
  the newest stamped recording (English when none) without persisting anything derived.
- [x] Append the output-language rule to the summarizer and finalizer prompts; carry it in the
  reconciler's committed producer contract with the tag as `memory_language` input so a language
  change re-fingerprints the source instead of altering an admitted provider attempt.
- [ ] Release: install v35 after v34, re-pin `MEMORY_RECONCILIATION_PRODUCER_CONTRACT_SHA256`
  (`sha256:65909856…`), and serve this revision before any companion stamps the field.
- [ ] Acceptance with the real model: a French recording on an English device authors an English
  title, bullets, gists, and brief with a quoted instruction, an amount, and a URL preserved and
  the transcript byte-identical.
