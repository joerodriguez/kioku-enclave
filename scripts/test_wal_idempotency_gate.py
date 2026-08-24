#!/usr/bin/env python3
"""Structural fail-closed inventory for the ADR-0022 WAL gate."""

from __future__ import annotations

import hashlib
import re
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLASSIFICATIONS = frozenset({"A", "B", "C"})
# Re-pinned after reviewing upstream 7db0162/901f3f0 (owner bodies moved, no
# semantics change) and 29be594's three additions: media_worker
# resurrect_user_failed_jobs (with_user + save_user, B) and summarizer
# span_holds_recoverable_media (read-only, A).
# Slice F-c: the only call-site delta is with_user_if_changed's owner body,
# whose refusal now reads the per-user resolver; its call expression and C
# classification are unchanged.
# Plan-family slice 1 (F1): the DEK bootstrap's with_user READ became the
# routed read (new A site in read_media_dek_wrapped) and the selected branch
# gained the submit (new B site under the same owner); the legacy with_user
# WRITE remains. 168 -> 169, diffed against pristine main, zero
# reclassifications.
# Plan-family slice 2 (F6): reserve_media_output gained its routed
# predecessor read and the sealed-plan submit, both under the existing B
# owner. 169 -> 171, diffed against pristine main, zero reclassifications
# and no removals -- the legacy write branch is intact.
# Plan-family slice 3 (F2): begin_invocation_settled adds its routed
# sequence-probe read and the sealed-plan submit (both B, new owner).
# 171 -> 173 under the bracket-aware scanner fix, which is
# inventory-neutral on the pre-slice tree (verified: 171 both ways).
# Plan-family slice 4 (F3/F4/F5): the Vertex drain's settled halves add
# eight routed sites under six new B owners (pending_events_settled,
# delivery read/settle, coverage read/settle, pending_coverage_settled).
# 173 -> 181, diffed against pristine main, zero reclassifications and no
# removals -- every legacy branch is intact.
# Plan-family slice 5 (F9): embed_episodes' read routes and the settled
# branch gains the submit; the legacy write branch remains. 181 -> 182,
# diffed against pristine main, zero reclassifications.
# Plan-family slice 6 (F10): the finalization lifecycle's routed
# predecessor read and sealed submit under two new B owners. 182 -> 184,
# diffed against pristine main, zero reclassifications; all three legacy
# branches intact.
# Plan-family slice 7 (F11-F15): the delivery ladders' settled halves --
# email settlement + bulk cancellation, push settlement (one choke point
# covering all four arms), webhook settlement, and the subscription cascade.
# 184 -> 194 (ten routed sites under five new B owners plus the two
# existing route owners), diffed against pristine main, zero
# reclassifications; every legacy branch intact.
# Plan-family slice 10e (screen storyboard): the screen arm's settled halves
# add four routed sites under two new B owners
# (settle_screen_storyboard_attempt: commitments read + attempt submit;
# settle_screen_storyboard_result: terminal-attempt/predecessor/id-base read
# + bound-result submit); rebased over the 10d finalization wiring, so the
# combined pin covers both.
# Slice 10g (selected-screenshot pre-provider chain): the upload route gains
# its WAL branch owner wal_selected_screenshot_image_upload with exactly six
# routed sites (preflight read + attempt submit, candidate-factory read +
# submit, send-start read + submit), all B under the new owner. The legacy
# rest_screenshot_image_upload owner only re-hashes for the added routing
# branch; every legacy call expression, ordinal, and classification is
# byte-identical (diffed against pristine origin/main after 10e/10f:
# 219 -> 225, zero reclassifications, zero removals).
# Plan-family slice 11 (audio-window transcripts): the audio arm's settled
# halves add five routed sites under two new B owners --
# settle_audio_window_attempt (the merged commitments+candidate-vocabulary
# read, then the attempt submit) and settle_audio_window_transcript (the
# immediately-pre-submit terminal-attempt/predecessor/sequence-pin read, the
# bound-transcript submit, and the single Conflict resubmission of the
# identical prepared object). 227 -> 232, dumped and diffed against a
# pristine origin/main (a475422) tree with the gate's own helpers: exactly
# five additions, zero removals, zero reclassifications, and zero moved
# call-expression hashes anywhere. The ONE other row delta is
# process_work_unit#0's OWNER-BODY hash, which moves because the audio WAL
# branch was added inside it; its three legacy call expressions
# (with_user#0, with_user#1, save_user#0) are byte-identical, so the legacy
# audio tail -- candidate_name_vocabulary via with_user, persist via
# with_user, save_user -- is intact for unselected users.
# Plan-family slice 10i (the media claim boundary): the media worker's claim
# and failure tails route. Six additions under two new B owners
# (claim_media_work_unit: the ONE pre-claim routed read that also carries the
# T24 audio gate, plus the claim submit; settle_media_work_failure: the
# predecessor read plus the settle submit), the read-only class scan's routed
# arm inside process_user (A, matching its legacy with_user#0 override), and
# settle_audio_window_transcript's pre-submit transcript-target occupancy
# probe (B, existing owner). 232 -> 238, dumped and diffed against a pristine
# origin/main (5fa1c0b) tree with the gate's own store_call_sites /
# classify_store_call / inventory_row / digest helpers: exactly six additions,
# ZERO removals, ZERO reclassifications, and ZERO moved call-expression
# hashes anywhere.
#
# R7 (the positional-key trap) was checked explicitly and did NOT fire. Every
# routed branch is an `if is_wal_authoritative { ... } else { <legacy call> }`,
# so all five process_user#0::with_user ordinals and all three save_user
# ordinals keep their original positions AND their byte-identical call
# expressions -- verified mechanically, key by key, against the pristine dump.
# The two out-of-scope voice calls (#3 reconcile_profiles, #4
# process_lineage_actions) therefore keep their own classifications. The only
# other row deltas are two OWNER-BODY hashes: process_user#0 (the three
# routing branches were added inside it) and settle_audio_window_transcript#0
# (the pre-check).
# Group D (archive-v3 deletion driver): exactly ONE addition --
# Store::freeze_wal_authoritative_media_keys' routed read, which freezes a
# WAL-authoritative account's exact media inventory before its binding is
# tombstoned. It is a Store-internal delegating wrapper, so it classifies "C"
# with with_user_read/with_user_if_changed. Rebased onto origin/main b096af0,
# which carries slice 10i's 238: 238 -> 239, dumped and diffed against a
# pristine origin/main (b096af0) tree with this module's own
# helpers: zero removals, zero reclassifications. The other row deltas are all
# OWNER-BODY hashes in model_usage.rs from the one-parameter Vertex cutoff
# (pending_events / pending_events_settled gained `stale_cutoff_millis`;
# settle_for_account_deletion gained the wal-lane branch; drain_outbox passes
# the 180s constant explicitly) -- every one of those call EXPRESSIONS is
# byte-identical. The single exception is
# settle_for_account_deletion#0::with_user#0, whose expression moved because
# the legacy sweep is now indented inside `if !wal_lane`; the sweep itself is
# unchanged and still runs for every unselected account.
# D1 (retired /v1 data plane): exactly TWELVE removals and zero additions.
# Deleting the handlers behind the `any(legacy_data_plane_retired)` 410 routes
# removed every Store call they owned: ingest_batch's with_user+save_user (the
# whole of src/ingest.rs is gone), handle_search#0::with_user, handle_context /
# handle_range / handle_stats' with_user, handle_episodes_upsert's
# with_user+save_user, handle_episodes_delete_range's with_user+save_user, and
# handle_episodes_list / handle_episodes_members' with_user. 239 -> 227, dumped
# and diffed against a pristine origin/main (4461f21) tree with this module's
# own helpers -- which reproduce the previous 239/6599ee98 pin exactly. Zero
# additions, zero reclassifications, and zero OWNER-BODY hash movement on any
# surviving row: the retained library functions (search_all/search_episodes,
# fetch_context, upsert_episodes/write_episode_embedding/purge_episode) take a
# `&Connection` and own no Store call sites of their own.
# Capture INGEST routed; its D4 gate and the four reads gated on it LIFTED.
# 229 -> 232.
#
# BASELINE: a pristine `git archive origin/main | tar -x` tree at commit
# 9d78c46 ("Route the summarizer window's evidence reads (unblocks the merged
# upsert plan) (#330)"), extracted OUTSIDE any shared working directory. Main
# moved twice while this branch was in progress (be3b0cb -> 8a6f948 -> 9d78c46)
# and each move re-pinned this same constant, so the delta below was re-derived
# from scratch after the final rebase -- 8a6f948's 229/1a4dec33 is NOT the
# baseline here even though this branch was first derived against it. The
# pristine tree was dumped with THAT tree's own store_call_sites() /
# classify_store_call() / inventory_row() / digest() helpers and reproduced
# 9d78c46's own 229/8eb21ded pin byte-for-byte, so the delta below is against a
# verified baseline. The store-surface (15/a2904b58) and policy-site
# (42/7b4d1591) digests are byte-identical to that pristine dump afterwards.
#
# As #330 records: a digest conflict on this constant is never resolvable by
# picking a side. The merged tree is a third state and has to be re-derived.
#
# DELTA, exactly:
#   * ONE one-for-one rename, `stream_ack#0::with_user#0` ->
#     `stream_ack#0::wal_authoritative_read#0`, keeping classification A. Its
#     D4 gate lifted with ingest (every canonical stream it could name is
#     written by `upload_capture_event`), and lifting a gate above an
#     UNROUTED legacy read would have handed a selected user a `with_user`
#     refusal, so the read had to route in the same change.
#   * THREE additions under `upload_capture_event#0`, all classified A by the
#     explicit overrides below: `wal_authoritative_read#0` (the routed
#     preflight -- the canonical arm's whole residual, because the sealed plan
#     treats an already-present event as a hard precondition failure while the
#     route answers 200) and `wal_authoritative_submit#0`/`#1`, one per media
#     disposition. Both submits are required: a mac_screen stream interleaves
#     canonical screenshots and reference pointers by sequence and
#     `advance_contiguous_ack` walks only while the next sequence exists, so a
#     half-migrated ingest stalls the stream at its first refused event.
#   * TWO changed rows with a moved CALL-EXPRESSION hash and no
#     reclassification: `upload_capture_event#0::with_user#0` and `#1`. Both
#     moved by INDENTATION ONLY -- they are now inside the `else` arm of the
#     routing branch. Verified line by line against the pristine dump: the two
#     expressions are identical after stripping leading whitespace, so the
#     legacy preflight and the legacy write+save pair are byte-intact.
#   * NINE rows changed in their OWNER-BODY hash only (TEN after the
#     REVIEW FIX addendum below), with byte-identical
#     call-EXPRESSION hashes and unchanged classifications:
#     `upload_capture_event#0`'s two save_user rows (the duplicate-branch save
#     is now skipped on the WAL branch, which has no in-memory half-state to
#     flush, but the call expression itself is one line and unchanged);
#     `upload_screen_reference_batch#0`'s four rows (the plan's rebase-refusal
#     sink is taken before `prepare` consumes it, and the submit's failure arm
#     now prefers the recorded reason); and `capture_status#0`,
#     `capture_session_status#0` and `list_capture_sessions#0`, whose D4 gates
#     were deleted above already-routed reads.
#
# Zero removals other than the one rename, zero reclassifications, and the
# relative order of every surviving key is unchanged.
#
# REVIEW FIX (adversarial review of #331, three confirmed defects). The COUNT
# is unchanged at 232 -- no Store call site was added, removed, renamed or
# reclassified -- but the digest moves, because three of the fixes edit owner
# bodies that already carry rows:
#
#   * the ingest plan families now take a plan-carried ENCLAVE commit stamp
#     instead of binding the seven live-clock column DEFAULTs to the DEVICE's
#     `manifest.source_wall_at`, so `upload_capture_event#0` and
#     `upload_screen_reference_batch#0` each gained an `enclave_commit_stamp()`
#     argument inside their WAL branch;
#   * the four gate-lifted reads (`stream_ack#0`, `capture_status#0`,
#     `capture_session_status#0`, `list_capture_sessions#0`) now hand their
#     `Err` arm to `cp::routed_read_unavailable` (503) instead of to
#     `EnclaveError::into_response` (500 for `EnclaveError::Store`);
#     `stream_ack#0` additionally keeps `Err(NotFound)` at 404, which is the
#     absence its lifted gate made truthful;
#   * `list_people#0`'s retained-gate comment was corrected to name the real
#     blocker. The owner body hash is taken over RAW source, so a comment-only
#     edit moves it; nothing executable in that owner changed.
#
# That makes it TEN owner-body-only rows rather than nine (the nine above plus
# `list_people#0::wal_authoritative_read#0`). Re-dumped and re-diffed against a
# freshly extracted pristine `git archive origin/main | tar -x` tree at 9d78c46
# -- extracted outside every shared and scratch directory -- with THAT tree's
# own store_call_sites() / classify_store_call() / inventory_row() / digest()
# helpers, which reproduced 9d78c46's own 229/8eb21ded pin byte-for-byte before
# anything was written. The branch script's scanner is byte-identical to that
# tree's (AST-diffed: only the three CALL_OVERRIDES additions above and these
# pin constants differ), so the two dumps are directly comparable. The delta
# against pristine is unchanged in shape: four additions, one removal (the
# `stream_ack#0::with_user#0` rename), zero reclassifications, the same two
# indentation-only call-expression moves re-verified line by line, and the
# relative order of every surviving key still unchanged. The store-surface
# (15/a2904b58) and policy-site (42/7b4d1591) digests did not move.
#
# ---- ADR-0022 Part B REBASED ON TOP of the ingest delta above (2026-08-21) ----
# Both branches independently moved 229 -> 232 by adding DIFFERENT call sites,
# so the merged tree is a THIRD state and NEITHER predecessor digest is correct
# here: ingest's 232/3f71214e and this branch's 232/ec8373dd are both wrong on
# the merged tree. Re-derived rather than resolved by picking a side.
#
# MERGED BASELINE: a pristine `git archive origin/main | tar -x` tree at
# 0d51bc8 ("Route capture-event ingest ... (#331)"), extracted under ~/.cache
# outside every worktree, and dumped with THAT tree's own store_call_sites() /
# classify_store_call() / inventory_row() / digest() helpers. It reproduced all
# FOUR of 0d51bc8's own declared pins byte-for-byte first -- store 232/3f71214e,
# surface 15/a2904b58, spawn 26/1741534d, policy 42/7b4d1591 -- so the delta
# below is against a verified baseline, not an assumed one.
#
# MERGED DELTA, exactly: 232 -> 235. THREE additions, all the advance_one_epoch
# sites enumerated below. ZERO removals, ZERO reclassifications, ZERO moved
# call-EXPRESSION hashes and ZERO moved owner-body hashes in this inventory --
# diffed key by key against the pristine dump. Ingest's own rows are already in
# the baseline and are untouched by this branch.
#
# The other three inventories on the merged tree: store-surface 15 with ONE
# owner-body move (async_main, from destructuring RelaunchCounts) -> 6f80aa29;
# worker-spawn 26 with the SAME single async_main owner-body move -> c821c699,
# which is NOT this branch's pre-rebase 34a018b2, because that value was derived
# against 85b83e0 before ingest landed and ingest had itself moved a spawn owner
# body; policy 42 completely unmoved at 7b4d1591.
#
# ADR-0022 Part B (the owner-side schema-ladder driver): exactly THREE
# additions and nothing else. 229 -> 232.
#
# BASELINE: a pristine `git archive origin/main | tar -x` tree at commit
# 9d78c46 ("Route the summarizer window's evidence reads (unblocks the merged
# upsert plan) (#330)"), dumped with THIS module's own store_call_sites() /
# classify_store_call() / inventory_row() / digest() helpers before anything
# was written. That pristine dump reproduced 9d78c46's own 229/8eb21ded pin
# byte-for-byte, so the delta below is against a verified baseline.
#
# DELTA, exactly:
#   * THREE additions, all under the ONE new B owner
#     `src/cp/schema_epoch/wal/advance.rs::advance_one_epoch#0`:
#     `wal_authoritative_read#0` (the single marker read -- `read_archive_epoch`
#     and nothing else; a second read would open a window in which the epoch
#     the plan is built for is not the epoch it is submitted against),
#     `wal_authoritative_submit#0` (the sealed step), and
#     `wal_authoritative_submit#1` (the ONE Conflict resubmission of the
#     identical prepared object). Three sites for two logical operations is the
#     same shape slice 11's settle_audio_window_transcript already carries.
#   * ZERO removals, ZERO reclassifications, ZERO moved call-EXPRESSION hashes,
#     and ZERO moved OWNER-BODY hashes anywhere -- diffed key by key against
#     the pristine dump. The relative order of every surviving key is
#     identical.
#
# Note what did NOT move and why: `archive_v3_serving_relaunch.rs::relaunch_one`
# gained the `advance_to_target_epoch` call, but neither that function nor
# `install_wal_serving_authority` is a tracked Store target, so relaunch_one
# owns no row here and its body hash is invisible to this inventory.
# Claim-lane wedge hardening adds one B-classified sealed quarantine submit:
# 235 -> 236. The final third-state derivation against the merged gate-lift
# baseline is recorded immediately above the digest below.
EXPECTED_STORE_CALL_COUNT = 258
# Slice J-c domain 1 (media capture-session-finish): the scanner now also
# inventories the routed wal_authoritative_read/submit surfaces; the delta is
# exactly finish_capture_session's three routed sites (probe read, settled
# submit, status read) inheriting the owner's pre-reviewed classification,
# plus that owner's body hash across its unchanged legacy branch.
# Slice J-c2 (media screen-reference batch): upload_screen_reference_batch
# gains its routed preflight-read and settle-submit sites; its legacy
# write+save pair stays inside the unselected branch (owner hash and the
# indentation-shifted with_user expression move; save_user expression
# unchanged).
# ADR-0022 D4 (the unmigrated-domain gate): 22 owners gained a one-line gate
# above their existing legacy access, so their OWNER-BODY hashes move. Dumped
# and diffed against a pristine origin/main (948e557) tree with this module's
# own helpers: the count holds at 227, every key and its ordinal is in the same
# order, every classification is unchanged, and every per-call-site expression
# hash is byte-identical. Zero Store calls were added, removed, reordered, or
# reclassified -- the gate returns BEFORE the call it guards.
# Billing margin read routed: one ADDED row,
# src/cp/billing.rs::current_account_drivers#0::wal_authoritative_read#0,
# classified A (read-only). Dumped and diffed against a pristine
# origin/main (9696081) tree using this module's own helpers; the
# pristine dump reproduced the prior 227/0cf0c7f5 pin exactly before
# anything was written. Zero removals, zero reclassifications, every
# surviving expression hash byte-identical.
#
# Note the count ROSE without a matching removal: the replaced call was
# `Store::read_user`, which this scanner does not track (it is a thin
# wrapper over with_user_read). Legacy reads reached through read_user
# are therefore invisible here — worth a sweep of Store's public
# surface for with_user delegation.
# Capture/session/people reads routed, D4 gates RETAINED. The count HOLDS
# at 228.
#
# BASELINE: a pristine `git worktree add --detach` checkout of origin/main
# at commit ea2bf62 ("fix(billing): route the margin-dashboard read instead
# of swallowing its refusal (#327)"), dumped with THIS module's own
# store_call_sites()/classify_store_call()/digest() helpers before anything
# was written. That pristine dump reproduced ea2bf62's own 228/bb8acbdf pin
# byte-for-byte, so the diff below is against a verified baseline.
#
# DELTA, 12 changed rows out of 228, count unchanged:
#   * SEVEN one-for-one key swaps, `with_user#0` -> `wal_authoritative_read#0`,
#     in capture_status, capture_session_status, list_capture_sessions,
#     list_people, person_profile, person_evidence and person_statements.
#     Every one keeps classification A. The routed call is retained on
#     purpose: it is strictly better than the bare `with_user` it replaced
#     (the legacy fallthrough is `with_user_read`, so an unselected user's
#     read now runs under SQLite's query_only guard), and it makes lifting
#     each gate a one-line deletion later.
#   * FIVE owner-body hash moves with byte-identical call-EXPRESSION hashes:
#     upload_capture_event's four rows and stream_ack's one. Both owners keep
#     their D4 gates; only the prose above those gates was rewritten, and
#     this scanner blanks comments in place, so a comment whose LENGTH
#     changes moves the owner-body hash without touching any call site.
#
# Zero reclassifications, zero call-expression hash moves on any surviving
# key, and the surviving-key order is identical.
#
# The digest does NOT return to ea2bf62's bb8acbdf even though all seven D4
# gates are back: the gates live above the call sites, and the call sites
# themselves stay routed. The count returning to the pre-PR 228 and the
# seven rows keeping classification A is the shape to expect here.
# Read lane routed, D4 gates RETAINED (the six MCP tools, /api/search,
# /api/episodes and /api/episodes/{id}, /api/episodes/{id}/members,
# /api/browser-snapshots/{k}, /api/feed, /api/screenshot-images/plan,
# /api/screenshot-images/{id}/content, /api/sync/status, /api/export).
# 228 -> 229.
#
# BASELINE: a pristine `git archive origin/main | tar -x` tree at commit
# be3b0cb ("Route the capture, session and people reads; scope the ingest
# write (media.rs) (#328)"). NOT ea2bf62, that commit's parent -- and the
# distinction is easy to miss here, because ea2bf62 carries the SAME count of
# 228 with a DIFFERENT digest (bb8acbdf); #328 held the count and moved the
# digest to b68a7595. Diffing against the parent would reproduce the right
# number and the wrong rows. The pristine tree was dumped with THIS module's
# own store_call_sites()/classify_store_call()/inventory_row()/digest()
# helpers before anything was written, and reproduced be3b0cb's own
# 228/b68a7595 pin byte-for-byte, so the delta below is against a verified
# baseline. The store-surface (15/ec7ce1bc) and policy-site (42/a6ddddfe)
# digests are byte-identical to that pristine dump afterwards.
#
# DELTA, exactly:
#   * THIRTEEN one-for-one call renames, `with_user#N` ->
#     `wal_authoritative_read#N`, under the SAME owner at the SAME ordinal,
#     keeping the SAME A classification: tool_search_screenshots,
#     query_episodes_value, tool_get_capture_status, dispatch_tool #0/#1/#2,
#     rest_episode_members, rest_browser_snapshot, rest_feed,
#     rest_screenshot_upload_plan, rest_screenshot_image_content #0/#1, and
#     sync_status. Each is a routed read that falls through to the ordinary
#     guarded legacy read for an unselected user, so no lane was added.
#   * ONE rename that also renames its OWNER, A -> A:
#     tool_search_transcripts#0::with_user#0 ->
#     query_transcripts_value#0::wal_authoritative_read#0. The function was
#     given a `Result` return so /api/search could stop answering a failed
#     read with HTTP 200, and renamed with it because the `tool_` prefix was
#     wrong -- MCP's own search_transcripts is served by
#     mcp_query::search_safe_transcripts, and this function's only caller was
#     the REST route.
#   * ONE net addition, src/cp/sync.rs::dump_user_export#0::
#     wal_authoritative_read#0, classified A (read-only export). The count
#     rises WITHOUT a matching removal because the call it replaced was
#     `Store::read_user`, which this scanner does not track. Do not read the
#     imbalance as a new lane: /api/export had exactly one legacy read before
#     and has exactly one routed read now, behind a RETAINED sync.export
#     gate. `read_user` has no production caller left after this change.
#   * SEVEN rows changed in their OWNER-BODY hash ONLY, with byte-identical
#     call-EXPRESSION hashes and unchanged classifications:
#     rest_episode_delete#0 (with_user#0, with_user#1, save_user#0, all C)
#     gained the comment recording why it is deliberately NOT migrated, and
#     rest_episode_finalize#0 (wal_authoritative_read#0,
#     wal_authoritative_submit#0, with_user#0, save_user#0, all A) had its
#     failure arm folded into cp::routed_read_unavailable. body_hash is taken
#     over raw source, so both prose and a replaced failure arm move it.
#
# Zero reclassifications, zero call-EXPRESSION hash moves on any surviving
# key, and the relative order of every surviving key is unchanged -- verified
# key by key against the pristine dump.
#
# As in #328, the digest does not return to any earlier value even though
# every D4 gate is retained: the gates sit ABOVE the call sites and the call
# sites themselves stay routed.
# Summarizer window + settled gate routed: count HOLDS at 229 with zero
# additions and zero removals. Ten rows changed: four key swaps
# (span_holds_recoverable_media, fetch_range, fetch_open_episodes,
# session_tail_is_settled -- with_user#0 -> wal_authoritative_read#0, all
# A->A), plus three summarize_user_window#0 and three
# wal_authoritative_upsert#0 rows whose owner bodies moved. Zero
# reclassifications. Re-derived against pristine origin/main (8a6f948,
# the read-lane merge) with this module's own helpers after rebasing;
# the pristine dump reproduced 229/1a4dec33 exactly first.
# NOTE this baseline is 8a6f948, NOT be3b0cb: main moved three times
# while this branch was in review, and each move re-pinned this same
# constant. A digest conflict here is never resolvable by picking a
# side -- the merged tree is a third state.
#
# Seven answerable D4 gates LIFTED (mcp.tools, query.search, query.episodes,
# query.episode_members, query.feed, sync.status, sync.export): count HOLDS at
# 235, with zero additions, zero removals, zero reorders, zero renames and zero
# reclassifications. Every call-EXPRESSION hash is byte-identical to the
# pristine dump; the delta is THREE owner-BODY hashes only --
# rest_episode_members#0, rest_feed#0 and sync_status#0, each of which had its
# `wal_domain_refusal` gate deleted and a comment added inside the same
# function body that owns its wal_authoritative_read#0 call. body_hash is taken
# over raw source, so a deleted gate and replacement prose both move it.
#
# The five other route functions, representing four lifted domains, move NO
# row, and that is the expected shape rather than a missed scan: rest_search,
# rest_episodes, rest_episode, export and mcp_endpoint own no tracked Store call
# at all -- their reads live one frame down in query_transcripts_value,
# query_episodes_value and dump_user_export, whose bodies this change does not
# touch.
#
# This is the inverse of #328's note and worth stating so the two are not read
# as contradicting: there, the digest moved while every gate was RETAINED,
# because the call sites moved under the gates. Here the digest moves while the
# gates are DELETED, because the gates sat inside three owner bodies. Neither
# direction is inferable from the digest; both have to be read row by row.
#
# Re-derived against pristine origin/main (2a5bca5, schema-epoch ladder Part B)
# with this module's own store_call_sites()/classify_store_call()/
# inventory_row()/digest() helpers, in a `git archive | tar -x` tree extracted
# outside every worktree; that pristine dump reproduced 2a5bca5's own
# 235/7ce82572 pin byte-for-byte BEFORE this value was written.
# NOTE this baseline is 2a5bca5, NOT 8a6f948: #332 merged while this branch was
# being written, and the FIRST derivation here was done against the stale
# 0d51bc8 base and produced 232 rows against a 235-row pin -- three
# src/cp/schema_epoch/*.rs files that only exist on the merged tree. The
# mismatch is what surfaced the moved base. Rebase first, derive second.
#
# Final post-review derivation against pristine origin/main (c834012, the T24
# claim refresh plus test-only Store liveness fix) used this module's own
# helpers after the final rebase. The pristine dump reproduced c834012's own
# 235/7ce82572 pin byte-for-byte first. The merged dump again held at 235 rows
# with no additions, removals, renames, reclassifications or call-expression
# moves; only the same three owner-body hashes moved, and the merged digest
# remained 24fcfb44. This appends the final third-state provenance rather than
# replacing the earlier derivations that explain how the pin arrived here.
#
# Claim-lane wedge hardening, rebased onto the merged gate-lift tip 12c9077:
# 235 -> 236. A pristine `git archive HEAD` tree was extracted under
# `/private/tmp` outside every worktree and its own gate passed all 14 tests,
# reproducing 12c9077's declared 235/24fcfb44 pin before this value was
# derived. The branch inventory was then diffed key by key with each tree's
# own scanner/classifier:
#   * ONE addition, `quarantine_unplannable_jobs#0::
#     wal_authoritative_submit#0`, classified B. It is the sealed mutation that
#     advances the named refused jobs onto their bounded retry/terminal ladder.
#   * ZERO removals and ZERO reclassifications.
#   * ELEVEN surviving rows move only in OWNER-BODY hash, with byte-identical
#     call-expression hashes: the two `claim_media_work_unit` routed rows (the
#     deterministic-refusal response now invokes quarantine) and all nine
#     `process_user` rows (the loop continues after a refusal instead of
#     returning and starving the next class).
#   * ZERO other moved rows; surviving-key order is unchanged.
#
# Post-independent-review repair was derived again from a fresh pristine
# `git archive HEAD` of the same 12c9077 base. Its own 14-test gate again
# reproduced 235/24fcfb44 exactly before comparison. The stable branch remains
# the same structural delta: one B quarantine submit, zero removals, zero
# reclassifications, zero call-expression moves, and the same eleven
# owner-body-only moves (two claim-owner rows plus nine process-user rows).
# The owner hashes change because claim now uses explicit durable
# member/duplicate/unit refusal classes, prioritizes global clock inversion,
# and carries exact immutable work-unit topology; those repairs add no Store
# surface. The key-by-key merged digest is therefore the third-state value
# below, not the pre-review a6fd6940 value above.
#
# Final attempt-cap/INTEGER-safety repair was re-derived once more against the
# same untouched 12c9077 archive. Its 14-test gate still reproduced
# 235/24fcfb44 exactly. The branch remains 236 rows: the same one B quarantine
# submit, zero removals and zero reclassifications. The surviving owner-body
# inventory also remains exactly eleven rows (two claim-owner rows and all
# nine process-user rows). Ten keep byte-identical call expressions; only
# `claim_media_work_unit#0::wal_authoritative_read#0` moves both hashes because
# the scan now receives the carried total-attempt cap. No owner moved and no
# Store surface changed beyond that explicitly accounted expression update.
#
# The post-full Clippy structural repair was then derived against that same
# untouched archive after its 14-test gate again reproduced 235/24fcfb44.
# Boxing the large attributable-refusal enum member changes source only inside
# the claim and quarantine owner bodies: relative to the reviewed 44c0feb1
# branch pin, exactly the two claim rows and the one added quarantine row move
# owner-body hash, while every call-expression hash, structural key and class
# remains byte-identical. The construction-context refactor lives outside a
# tracked Store owner. The resulting inventory is still 236 rows with the same
# one B addition, zero removals and zero reclassifications.
# Push-outbox activation was re-derived against a fresh pristine `git archive
# HEAD` at exact 1a55872782951024f9970c3b1690ce38fd522c5b. The untouched
# archive's own 14-test gate first reproduced its declared
# 236/3fbe72eafbf2236494f9b960d40366c8431f5fee9b7c331ed679eea47c90b89b
# pin byte-for-byte. Each tree was then dumped with its own scanner and
# classifier and compared key by key. The branch is 240 rows:
#   * TEN additions: two A routed reads in the live owner (open claim and
#     content-free depth), three B sites each for exact claim submit and exact
#     settlement submit (WAL submit plus retained legacy with_user/save), and
#     the A routed replacements in Store's scan and handoff resolver.
#   * SIX removals: the two B sites under the superseded update_delivery owner,
#     the two B legacy sites in the removed Store updater, and the two A legacy
#     with_user calls replaced by the Store routed scan/resolver reads.
#   * ZERO reclassifications and ZERO surviving call-expression moves. Eight
#     surviving finalizer rows move in owner-body hash only because selected
#     finalization now snapshots generation-bound APNs destinations; every
#     one of their call expressions is byte-identical. Surviving-key order is
#     unchanged. The scanner now also structurally inspects both active push
#     child modules, including their sealed registrations, bounded ledgers,
#     preconditions, and absence of Store/provider/runtime escape surfaces.
#
# The post-review A--I repair was derived again from a newly extracted archive
# of the same exact 1a55872782951024f9970c3b1690ce38fd522c5b base. Its own
# 14-test gate again reproduced
# 236/3fbe72eafbf2236494f9b960d40366c8431f5fee9b7c331ed679eea47c90b89b
# before comparison. The final branch is 242 rows: the same ten additions and
# six removals above, plus exactly TWO A reads --
# `load_send_claim_recovery#0::wal_authoritative_read#0` for typed cross-store
# outcome adoption and
# `validate_archive_send_authority#0::wal_authoritative_read#0` for the
# immediately-pre-provider exact claim/row/lease check. Key-by-key comparison
# proves zero reclassifications, zero surviving call-expression moves, and
# unchanged surviving-key order. The only surviving owner-body moves versus
# pristine remain the eight pre-existing `finalize_user_episodes_scoped` rows;
# their call expressions are byte-identical. This final pin therefore comes
# from the merged third state, not from incrementally editing the earlier
# 240-row digest.
#
# The final receipt/cancellation and singleton-topology review repair was
# re-derived once more from a fresh archive of that exact 1a55872 base. The
# pristine 14-test gate reproduced 236/3fbe72ea before comparison. Exact
# Control receipt replay, claimless live-claim refusal, and release topology
# verification add no Store escape; key-by-key comparison therefore reproduces
# the same 242/15a16011 third state, the same 12 additions/six removals, zero
# reclassifications, zero surviving expression moves, unchanged surviving-key
# order, and only the same eight finalizer owner-body moves. No pin value moves.
# The final topology follow-up replaces the release-local semantic regex with a
# pinned deployment HEAD plus exact Terraform root-source inventory/digest and
# adds no Rust or Store surface. The branch gate below therefore remains the
# already re-derived 242/15a16011 third state; no pin or owner inventory moves.
# The reviewed deployment companion then moved the source HEAD pin to exact
# 50dd58069e5fe7643640076ecdfe84f38acde704 without changing the Terraform
# digest, and added only release-script seal handoff/path checks. Rust and the
# Store inventory remain byte-for-byte unchanged, so the pin still does not move.
# Deployment correction da23a487c5c4060fc579c2b0863747c1b55eff6f adds
# replacement-ref refusal and replacement-disabled Git reads to both sides of
# the release seal. The enclave change remains script/docs-only, so this Store
# pin and owner inventory again remain unchanged.
# Genesis deployment policy 3fe93cd7753c8ac75ea0e339cb131b0a381ddadc
# adds only exact release admission and a frozen archive-authority helper; its
# Terraform root digest is unchanged and no Rust or Store surface moves.
# Email-outbox activation was re-derived against a fresh `git archive HEAD` at
# exact 252fb0f26d26c6f666117f075548bea1184a6ddd. The untouched archive ran its
# own 14-test gate first and reproduced 242/15a16011 byte-for-byte. Each tree
# was then dumped with its own scanner/classifier and compared key by key. The
# active branch is 243 rows:
#   * NINE additions: routed finalized-brief and due-row reads; five A owner
#     reads for open claim, frozen request, typed recovery, pre-send authority,
#     and content-free depth; and two B submits for claim and exact settlement.
#   * EIGHT removals: the two replaced legacy reads; four read/submit sites from
#     the superseded general/bulk selected settlement owners; and the legacy
#     retry-time updater's with_user/save pair, now folded atomically into the
#     existing legacy state update.
#   * ZERO reclassifications. Three surviving call expressions move for exact,
#     reviewed reasons: billing's routed query counts the real `accepted`
#     state; finalizer's legacy closure includes email in its returned delivery
#     count; and the legacy updater assigns retry time atomically with state.
#     Exactly fifteen surviving rows move owner-body hashes: billing's one
#     routed read, the finalizer's ten read/write rows, and the legacy
#     enqueue/update Store pairs (four rows, with update overlapping the
#     expression set above); no other surviving expression moves. This is the
#     merged third state, not an incremental edit of the push pin.
# Final warning-free boxing of the strict finalized-episode result changes only
# the body hash of its already-accounted added routed read; count, keys,
# classes, the three surviving expression moves, and every delta above remain
# identical. The final re-derived digest is therefore:
# Webhook-outbox activation was then derived against a fresh `git archive HEAD`
# at exact 2da2ad78d865f23cb9f62016d29387f4360fa301. The untouched archive ran its
# own 14-test gate and reproduced 243/d7d93932 byte-for-byte before comparison.
# Each tree was dumped with its own scanner/classifier and compared key by key.
# The active branch is 248 rows:
#   * THIRTEEN additions: the selected due-row scan; open claim, frozen request,
#     typed recovery, pre-send authority, and content-free depth reads; exact
#     claim and settlement submits; and the selected-read plus retained legacy
#     write/save sites in the new resumable subscription-cancellation owner.
#     The renamed legacy state owner contributes its retained write/save pair.
#   * EIGHT removals: four sites from the superseded general webhook settlement
#     owner and four from the old query-owned 256-row cascade.
#   * ZERO reclassifications. The sole surviving call-expression move is
#     `next_delivery#0::with_user#0`, whose legacy due-row query now carries the
#     same per-subscription predecessor-order predicate as the selected scan.
#     That same row is the sole surviving owner-body move. Every other surviving
#     expression/body hash and the surviving-key order are unchanged.
# The scanner now reads both active webhook child modules and pins their sealed
# registrations, bounded ledgers, preconditions, and absence of Store,
# Control, provider, or runtime escape.
#
# The fail-closed review repair was then derived against a fresh `git archive
# HEAD` at exact 01239d9c2e63f815963cc86c780299592a827961. That untouched
# archive ran its own 14-test gate and reproduced 248/471870c7 byte-for-byte.
# The repaired tree is 250 rows: exactly one A status read and one B exact-purge
# submit are added, with zero removals or reclassifications and unchanged
# surviving-key order. Two reviewed surviving call expressions move: the
# selected scan now names malformed far-future retry heads, and the deletion
# scan now returns exact active-or-terminal purge evidence. Exactly four
# surviving owner bodies move: those two reads plus the legacy write/save rows
# owned by the dual-path deletion function. No other surviving expression or
# owner-body hash moves. The re-derived third state is therefore:
#
# The final deletion-linearization repair keeps the same 250 keys, classes,
# order, and call expressions. Holding the per-user lifecycle guard from the
# webhook Control snapshot through the final archive commit changes only the
# owner-body hash of the eight surviving Store sites inside
# `finalize_user_episodes_scoped`; the status-503, identifier-free logging, and
# real-ledger adversarial tests add no Store surface. The final third state is:
# Screenshot-content integrity/lift was derived against pristine exact
# 2cf4a11dfd17ba57ad0f66bf44aa07934741a0e2. Its own 14-test gate first
# reproduced 250/2f26f4d1 exactly. The branch is 251 rows: exactly one added A
# routed read revalidates the authoritative screenshot tuple after an exact
# current-generation NotFound, so a retention race can distinguish truthful
# absence from storage unavailability. There are zero removals and zero
# reclassifications. The two surviving screenshot-content read expressions
# move because the lookup now carries the authenticated user for owner-derived
# object-key validation and the inserted revalidation shifts the later DEK
# read's ordinal. The seven surviving upload_capture_event rows move owner-body
# only with strict single-response lost-PUT recovery, and the two surviving
# screenshot-content rows move owner-body with exact generation/key/DEK/AAD/
# length/hash enforcement. No other row or surviving-key order changes.
# Screenshot-upload retirement was then derived against a fresh pristine
# archive of exact ef3bb3545a5cde545c4978552a85bf3bea948026. Its own gate
# reproduced 251/21f575c4 before comparison. The retired Genesis path removes
# the selected upload owner's four reads and four submits. The plan's one
# routed read is replaced one-for-one by the guarded legacy `with_user` read.
# There are zero reclassifications and zero surviving expression moves. The
# seven surviving legacy upload rows move owner-body only because the 410
# selection check now precedes multipart/KMS/lease/provider work; every legacy
# call expression remains byte-identical. Capturing Query/Multipart extractor
# rejections in the handler then moves only those same eight owner bodies so
# the selected 410 wins before framework-level validation; keys, classes,
# expressions, and surviving-key order remain unchanged.
# Browser-v2 evidence compatibility was derived against a fresh pristine
# `git archive` of exact 21e5db90113674ba8e43826fe8ef8f57a72f0caf. That
# untouched tree's own gate first reproduced 243/c205ca43 byte-for-byte. The
# branch remains exactly 243 rows with no additions, removals,
# reclassifications, or key-order movement. The sole moved row is
# `rest_browser_snapshot#0::wal_authoritative_read#0`: both its owner-body and
# call-expression hashes change because the routed read now invokes the strict
# browser-v2/legacy loader instead of querying the orphaned legacy state table.
# No other owner or expression moves. The independently derived third state is:
# Episode deletion/browser GC was derived against a fresh pristine `git
# archive` of exact 595958566c1d46c657e0aa515fe9100e4fc100d8. That
# untouched tree's own 14-test gate reproduced 243/a3098fd0 before any branch
# pin was written. The branch is 250/d1c7cbb5: exactly seven additions. Six
# are C sites under `rest_selected_episode_delete` (two exact state/work reads
# plus preparation, selector expansion/finish, provider-result, and completion
# submits); the seventh is the A read that inventories pending work for the
# bounded summarizer resume owner. There are zero removals, reclassifications, or
# surviving call-expression moves. Exactly four surviving rows move owner-body
# only: the legacy delete owner's two reads and save now sit below the selected
# branch, while the browser read loses its D4 gate. Their call expressions are
# byte-identical and the relative order of every surviving key is unchanged.
#
# The final capacity/authentication/sharing/fairness repair was re-derived from
# the same fresh pristine archive after its own 14-test gate again reproduced
# 243/a3098fd0. The branch is now 251 rows. Relative to pristine it has eight
# additions: the six C route sites above, one A durable rotated-batch read, and
# one C exact cursor-advance submit. There are still zero removals or
# reclassifications. Exactly four surviving rows move owner-body only (the
# legacy delete read/read/save trio and browser read), with byte-identical call
# expressions. The new dedicated episode-delete worker adds no Store factory or
# policy escape. This is the final key-by-key third state:
# Selected voice embedding was derived against a fresh pristine `git archive`
# of exact 0f9b536f5ef8355e947fe5571892f2622d46f59b. Its own 14-test
# gate first reproduced 251/798cdef5 byte-for-byte. The final branch has 256
# rows: exactly two B reads and three B submits under the new
# `process_selected_voice_embedding_jobs` owner. The first read/submit pair is
# the bounded provider-free historical v1 observation/job repair; the second
# read and final two submits are due evidence, exact claim, and exact result.
# There are zero removals, reclassifications, or surviving call-expression
# moves. Exactly seven surviving legacy `process_user_voice_embedding_jobs`
# rows move owner-body only because the selected branch now returns before
# that unchanged compatibility lane; their call expressions are byte-identical
# and surviving-key order is unchanged. The v2 transcript plan's fixed-id job
# inserts and the clock/source/topology repairs live wholly inside sealed
# children and add no further Store surface. The scanner reads both children
# directly and pins their registration, bounds, preconditions, and absence of
# Store/provider/runtime escape. This is the independently derived third state:
#
# Selected voice/profile completion was derived against a fresh pristine
# `git archive` of exact 41abc0f7ab6a65ad3b5ded68fa014d5025e29d93. Its own
# 14-test gate first reproduced 256/31eb36c9 byte-for-byte. The branch has 258
# rows: exactly one B read and one B submit under the new provider-free
# `process_user_voice_profiles` owner. There are zero removals,
# reclassifications, or surviving call-expression moves, and surviving-key
# order is unchanged. Exactly 17 surviving rows move owner-body only: nine
# compatibility calls under `process_user`, four transcript settlement calls,
# and the four lifted people reads. All operation internals remain inside the
# sealed child modules inventoried below.
# The final Clippy-only boxing of `VoiceProfileScan::Work` changes the body hash
# of the new voice-profile owner, so its B read and B submit are two additional
# owner-body-only moves. Their keys, classifications, and call-expression
# hashes are byte-identical; the count and surviving-key order remain fixed.
EXPECTED_STORE_CALL_SHA256 = "f2f02b476c8748846def0ca2901a8474be81ffde40ad244802a031beb171c2a1"
EXPECTED_STORE_SURFACE_COUNT = 15
# Slice F-c: the internal constructor's Store literal additionally initializes
# the always-empty per-user WAL-authority selection map; no construction
# surface was added or removed.
# Slice J-a: async_main's owner body gained the pre-admission WAL-authority
# selection installation; both constructor call expressions are unchanged.
# Slice J-b3: the internal constructor's Store literal additionally
# initializes the always-empty serving-authority registry.
# Slice J-b3b: async_main's owner body gained the pre-admission serving
# relaunch call and the concrete-KMS split; constructor expressions
# unchanged.
# SEL slice 1b: async_main's owner body again -- the relaunch now returns
# (relaunched, unavailable) and the unavailable count is logged. Both
# Store-construction call-site hashes and all 16 keys are byte-identical;
# only the enclosing function body moved.
# Phase-2 deletion PR 1: the solo-canary argv branch built its OWN Store, so
# removing it drops one construction site (16 -> 15). The surviving site is
# the serving construction -- its call-site hash is byte-identical to the
# second site before this change. async_main's owner body moves with it.
# Genesis spine G9: async_main's owner body gained the pre-admission genesis
# sign-in gate validation. Diffed against a pristine origin/main checkout of
# this inventory: the sole delta is that owner-body hash. The count holds at
# 15, both Store-construction call-site hashes are byte-identical, and the key
# set is unchanged.
# Group D (archive-v3 deletion driver): the internal constructor's Store
# literal additionally initializes the always-empty archive-v3 deletion-lane
# slot. Diffed against pristine origin/main (5fa1c0b) with this module's own
# helpers: the count holds at 15, the key set is unchanged, no construction
# surface was added or removed, and the sole delta is that literal (and its
# enclosing factory definition) moving.
# Group C (in-process WAL serving relaunch): the internal constructor's Store
# literal additionally initializes the always-empty relaunch-driver slot, and
# async_main's owner body gained the driver installation. Diffed against a
# pristine origin/main (4461f21) dump produced by this module's own helpers:
# the count holds at 15, the key set is byte-identical, no construction
# surface was added or removed, and the only deltas are that literal, its
# enclosing factory definition, and async_main's owner body.
# ADR-0022 Part B (schema-ladder driver, review fix [5]): the startup relaunch
# now returns a `RelaunchCounts` struct instead of `(relaunched, unavailable)`,
# because a user whose epoch advance failed IS being served -- the authority is
# installed before the advance runs and there is no removal API -- so counting
# them `unavailable` inverted the health signal. async_main destructures the
# new counts and reports the added `behind_target` / `unservable_epoch`
# subsets. Count HOLDS at 15 with zero additions, zero removals, zero
# reclassifications, and ZERO Store-construction call-EXPRESSION hash moves;
# the key set is byte-identical. The sole delta is async_main's owner body
# (05f35ac2 -> d3d8b028).
# Diffed with this module's own store_surface_sites()/inventory_row()/digest()
# helpers against TWO pristine `git archive | tar -x` trees extracted outside
# any shared directory: origin/main (85b83e0) and this branch's base (9d78c46).
# Both reproduced their own 15/a2904b58 pin byte-for-byte before anything was
# written, and their inventories are byte-identical to each other -- #333's
# main.rs edit is a module-level const array outside async_main's span, so the
# merged tree is not a third state here.
# Episode deletion's dedicated startup worker moves only async_main's owner
# body. All 15 construction keys and every construction expression remain
# byte-identical to pristine 5959585; no factory or policy surface was added.
# Archive-v3 deletion runtime wiring was re-derived against a fresh untouched
# `git archive` of exact 2ebb08c11e0dd8a2fa62800cb392c911081725e1.
# That tree's own 14-test gate reproduced its declared
# 15/d0b746ab3dd0482f2966d2ba2d1f5ab752ce234c658a38c2c2af15b191aecf88
# store-surface pin before comparison. The branch remains exactly 15 rows:
# zero additions, removals, reclassifications, key-order moves, or call-
# expression hash moves. The sole delta is async_main's owner-body hash,
# because startup now derives Control-bound deletion roots and installs the
# exact lane before loading WAL selections or launching reconcilers. The
# independently derived third-state digest is recorded below.
# ADR-0022 zero-archive cutover: startup now chooses the dedicated destructive
# cutover owner when the reviewed signup budget is exactly zero. A fresh,
# untouched `git archive` of exact 6dbd2fc47a04af9afd801c212ca4cde042cf138b
# ran its own 14-test gate and reproduced the prior 15/b50d6196... pin before
# comparison. The count, keys, classifications, order, and all call-expression
# hashes are unchanged; only async_main's enclosing owner-body hash moves.
# ADR-0022 production cutover liveness repair: the exact zero-budget image now
# suppresses legacy checkpoint reconciliation and the content-producing worker
# schedulers so they cannot retain or recreate archive write admission ahead of
# the sole destructive owner. A fresh `git archive` of exact
# deaacbb957ef491f82dcd2e9a9867e775ac689e6 ran its own 14-test gate first and
# reproduced 15/ba584b1b6fc4446ad244c67ee84ed2901ca69c45542453d9e736634cd90de4d8.
# The branch remains 15 rows with the identical key set, classification, order,
# and call-expression hashes. The only third-state delta is async_main's
# enclosing owner-body hash; no Store constructor or policy surface moved.
EXPECTED_STORE_SURFACE_SHA256 = "fcc890be7f410b5cd943979e6636abc0a02c55ee69a63f857874c6a6cd879746"
EXPECTED_STORE_SURFACE_KEYS = frozenset(
    {
        "src/main.rs::async_main#0::Store::new_with_media_and_legacy#0",
        "src/store.rs::new#2::Self::new_internal#0",
        "src/store.rs::new#2::factory_definition::new#0",
        "src/store.rs::new_internal#0::Self::new_internal_with_max_open#0",
        "src/store.rs::new_internal#0::factory_definition::new_internal#0",
        "src/store.rs::new_internal_with_max_open#0::Self::new_internal_with_max_open_and_shadow_capture#0",
        "src/store.rs::new_internal_with_max_open#0::factory_definition::new_internal_with_max_open#0",
        "src/store.rs::new_internal_with_max_open_and_shadow_capture#0::Self::new_internal_with_max_open_shadow_capture_and_policy#0",
        "src/store.rs::new_internal_with_max_open_and_shadow_capture#0::factory_definition::new_internal_with_max_open_and_shadow_capture#0",
        "src/store.rs::new_internal_with_max_open_shadow_capture_and_policy#0::Store_literal#0",
        "src/store.rs::new_internal_with_max_open_shadow_capture_and_policy#0::factory_definition::new_internal_with_max_open_shadow_capture_and_policy#0",
        "src/store.rs::new_with_media#0::Self::new_internal#0",
        "src/store.rs::new_with_media#0::factory_definition::new_with_media#0",
        "src/store.rs::new_with_media_and_legacy#0::Self::new_internal#0",
        "src/store.rs::new_with_media_and_legacy#0::factory_definition::new_with_media_and_legacy#0",
    }
)
# Deliberate ADR-0022 slice F-c re-pin: policy consultation is now the single
# private per-user resolver `persistence_policy_for` (whole-Store test seam OR
# the user's durable-terminal-backed WAL-authority selection; poisoned lock
# fails closed to WAL-logical). Every consult site keeps its exact refusal
# comparison but reads the resolver instead of the field; only the resolver
# and the construction chain touch `persistence_policy` directly.
EXPECTED_POLICY_SITE_COUNT = 42
# Slice J-b3: owner-body hashes moved for the constructor (serving-authority
# registry init), with_user (selected-user legacy-load refusal), and
# save_user (selected-user provider-silent no-op); every policy expression
# and count is unchanged.
#
# SEL slice 1a (+2): `StorePersistencePolicy::WalOwnerAuthoritative` — the
# non-mutating owner open. `from_authenticated_staging` moved off
# `LegacySnapshot` (-1/+1) and `open_db` gained the branch (+1) plus one more
# read of `persistence_policy` (+1). No pre-existing site changed its target,
# and `EXPECTED_WAL_LOGICAL_ONLY_KEYS` is byte-identical.
#
# ADR-0022 sealed re-baseline: `open_db`'s owner body hash moved
# (951834cd… -> 66727dfc…) because its `WalOwnerAuthoritative` branch gained
# the epoch-marker latch — `read_archive_epoch` + `validate_servable_epoch`,
# refusing via `wal_owner_open_error()`. That branch previously performed no
# schema comparison at all, so an archive built by a pre-re-baseline binary
# was served rather than refused. **Six rows changed — every
# `src/store.rs::open_db#0::*` row — and each changed ONLY in its owner-body
# field:** the count stays 42, the key set is byte-identical, no call site was
# added, removed or reclassified, and every policy expression hash is
# unchanged. (An earlier revision of this comment said "exactly one row";
# that was wrong, and these comments are the whole audit trail a reviewer
# has for a pinned security value.)
#
# Group D (archive-v3 deletion driver), rebased onto the sealed re-baseline:
# the count holds at 42 with zero additions, removals, or reclassifications.
# Both moved rows are the two persistence_policy sites inside the internal
# constructor, whose owner body gained the deletion-lane slot; their
# expressions are byte-identical. The six `open_db#0` rows keep the
# re-baseline's owner-body hashes.
#
# Group C (in-process WAL serving relaunch), rebased onto Group D: the count
# holds at 42 with zero additions, removals, or reclassifications. Both moved
# rows are again the two persistence_policy sites inside the internal
# constructor, whose owner body gained the relaunch-driver slot; their
# expressions are byte-identical, and every `open_db#0` row is unchanged.
EXPECTED_POLICY_SITE_SHA256 = "7b4d15912ada202d44b85fe68ec2862d245632e983874b58b6d049370ce6319d"
EXPECTED_WAL_LOGICAL_ONLY_KEYS = frozenset(
    {
        "src/store.rs::<module>#0::WalLogicalOnly#0",
        "src/store.rs::evict_candidate#0::WalLogicalOnly#0",
        "src/store.rs::flush_handle#0::WalLogicalOnly#0",
        "src/store.rs::flush_handle_with_admission#0::WalLogicalOnly#0",
        "src/store.rs::load_user#0::WalLogicalOnly#0",
        "src/store.rs::load_user#0::WalLogicalOnly#1",
        "src/store.rs::open_db#0::WalLogicalOnly#0",
        "src/store.rs::persistence_policy_for#0::WalLogicalOnly#0",
        "src/store.rs::persistence_policy_for#0::WalLogicalOnly#1",
        "src/store.rs::persistence_policy_for#0::WalLogicalOnly#2",
        "src/store.rs::persistence_policy_for#0::WalLogicalOnly#3",
        "src/store.rs::save_user#0::WalLogicalOnly#0",
        "src/store.rs::with_user#0::WalLogicalOnly#0",
        "src/store.rs::with_user#0::WalLogicalOnly#1",
        "src/store.rs::with_user_if_changed#0::WalLogicalOnly#0",
        "src/store.rs::with_user_mut#0::WalLogicalOnly#0",
    }
)
# The non-mutating owner open runs NO DDL, so it can only ever be pointed at a
# database whose schema is already established and pinned. Reaching it from any
# other site -- a legacy load, a routed read, a test helper promoted to
# production -- would silently skip `SCHEMA_SQL`, and with it the sole
# production `PRAGMA foreign_keys = ON` for a user database, leaving every
# `ON DELETE CASCADE` inert with no fingerprint or descriptor check to notice.
# Enumerated rather than counted so a new site has to be named here in review.
EXPECTED_WAL_OWNER_AUTHORITATIVE_KEYS = frozenset(
    {
        "src/store.rs::from_authenticated_staging#0::StorePersistencePolicy::WalOwnerAuthoritative#0",
        "src/store.rs::open_db#0::StorePersistencePolicy::WalOwnerAuthoritative#0",
    }
)
# Deliberate ADR-0022 Phase-2 re-pin (upstream: run_phase2's owned spawn) plus
# this change's media_worker sweep-closure delta (resurrection step).
# Phase-2 deletion: the eight advisory-family spawns went with the family
# (abort x2, abort_reconcile, controller canary, telemetry, the advisory
# importer's owned run, and the store's compare/retire pair). All 25
# surviving spawns are byte-identical to main -- diffed, not assumed.
# Genesis spine G9 adds exactly one spawn: the detached genesis convergence
# pass in src/archive_v3_genesis_trigger.rs. It is deliberately a worker and
# not an awaited call — sign-in must never block on, or fail because of,
# genesis — and it classifies "C" with the rest of the archive-v3 family.
EXPECTED_WORKER_SPAWN_COUNT = 29
# Slice J-a: the sole delta is async_main's owner-body hash (pre-admission
# selection installation); the spawn count and every spawn expression are
# unchanged.
# Slice J-b1: the actor and spawn_failed loop closures gained the Read arm
# (reads serialize behind the full settle ladder); spawn count stays 33 and
# no new spawn site exists.
# Slice J-b3b: async_main's owner-body hash only; spawn count stays 33 and
# every spawn expression is unchanged.
# Re-pinned after upstream #273/#274 (daily signup budget + content-free
# signup events) changed upsert_user's owner body without co-updating this
# gate — the gate fails on a clean origin/main checkout. Reviewed against the
# dumped inventory: the sole delta is that owner-body hash; the spawn count
# stays 33 and every spawn expression is unchanged.
# Audit fix: the actor loop's Read arm now authenticates a fresh head before
# serving, so the owner-actor spawn closure's hash moves. Spawn count stays 33
# and no new spawn site exists.
# SEL slice 1b: async_main's owner body moved (the relaunch's unavailable
# count). No spawn was added, removed, or reclassified; the count holds at 33
# and every spawn's own call-site hash is byte-identical.
# Phase-2 deletion PR 1: async_main owner body only; the spawn count holds
# at 33 and every spawn call-site hash is byte-identical.
# Slice 10g: rest_screenshot_image_upload's owner body moved (the WAL routing
# branch above its legacy GCS-put spawn). The spawn count holds at 25 and
# every spawn's own call-site hash is byte-identical (diffed against
# pristine origin/main: zero additions, zero removals).
# Genesis spine G9: two deltas, both reviewed against a pristine origin/main
# dump of this inventory. (1) One added spawn — the detached genesis
# convergence pass, 25 -> 26. (2) async_main's owner-body hash moved with the
# genesis gate validation; its own spawn call-site hash is byte-identical.
# Nothing was removed and no surviving spawn expression changed.
# Group C (in-process WAL serving relaunch): five deltas, all reviewed against
# a pristine origin/main (4461f21) dump produced by this module's own helpers.
# The count holds at 26 with zero additions and zero removals, and the key set
# is byte-identical. (1) `WalStoreLane::spawn` and (2) `spawn_with_builder`:
# the lane-thread closures now hold a residency guard that retires the thread
# from the authority's liveness census strictly after its store owner has been
# dropped. (3) `spawn_lane_with_fence` and (4) `spawn_failed`: the actor
# futures now hold a drop guard that raises the termination flag on completion
# and on unwind. (5) async_main's owner-body hash moved with the relaunch
# driver installation; its own spawn call-site hash is byte-identical.
# D4 (unmigrated-domain gate): one delta, re-derived against a pristine
# origin/main (948e557) dump -- NOT 16a7f41, which is that commit's parent
# and predates Group C's four spawn-expression changes above. Against the
# real baseline the count holds at 26, the key set is byte-identical, and
# the sole delta is `upload_capture_event`'s owner body, whose gate sits
# above the route's detached media-put spawn; every spawn call-site
# expression hash is unchanged.
# Capture reads routed, D4 gates RETAINED: count HOLDS at 26 with zero
# additions, zero removals, zero reclassifications and zero spawn
# call-EXPRESSION hash moves. The sole delta is `upload_capture_event`'s
# owner body, whose RETAINED D4 gate sits above the route's detached
# media-put spawn and whose rationale prose was rewritten in place. Same
# pristine origin/main (ea2bf62) worktree and the same
# worker_spawn_sites()/classify_worker_spawn()/digest() helpers as the
# store-call pin above; that pristine dump reproduced ea2bf62's own
# 26/5fb928cb pin byte-for-byte before anything was written.
# Read lane routed, D4 gates RETAINED: count HOLDS at 26 with zero
# additions, zero removals, zero reclassifications and zero spawn
# call-EXPRESSION hash moves. The sole delta is rest_episode_finalize#0's
# owner body (class B, unchanged), whose routed-read failure arm was folded
# into cp::routed_read_unavailable above the route's detached spawn; the
# spawn expression itself is byte-identical. Same pristine origin/main
# (be3b0cb) tree and the same worker_spawn_sites()/classify_worker_spawn()/
# digest() helpers as the store-call pin above; that pristine dump
# reproduced be3b0cb's own 26/fe52045d pin byte-for-byte before anything was
# written.
# Capture ingest routed: the sole delta is
# `upload_capture_event#0::tokio::spawn#0`'s OWNER-BODY hash. That spawn is the
# GCS media PUT, which keeps the provider write alive if the HTTP future is
# cancelled; it was not touched. Dumped and diffed against a pristine
# origin/main (9d78c46) tree with that tree's own helpers, which reproduced its
# own 26/e6dac368 pin exactly: the count holds at 26, the key set is
# byte-identical, no spawn was added, removed, reordered or reclassified, and
# every other spawn's own call-site hash is byte-identical.
# REVIEW FIX (adversarial review of #331): that same spawn's OWNER-BODY hash
# moves again, for the same reason and no other -- `upload_capture_event#0`
# gained the `enclave_commit_stamp()` argument on both of its plan
# constructions. The GCS media PUT itself is still untouched: its own
# call-site hash is byte-identical to the pristine dump, the count holds at 26,
# the key set is unchanged, and no spawn was added, removed, reordered or
# reclassified. Re-derived against the same freshly extracted pristine 9d78c46
# tree with that tree's own helpers, which reproduced its own 26/e6dac368 pin
# exactly first.
#
# ---- Part B rebased on top of the ingest delta above ----
# Both branches moved this pin for DIFFERENT reasons, so the merged tree is a
# third state and neither predecessor digest is correct. Re-derived below.
#
# ADR-0022 Part B (schema-ladder driver, review fix [5]): count HOLDS at 26
# with zero additions, zero removals, zero reclassifications and zero spawn
# call-EXPRESSION hash moves. The sole delta is async_main's owner body
# (05f35ac2 -> d3d8b028), the SAME owner-body move the store-surface pin above
# records and for the same reason: the startup relaunch now returns
# `RelaunchCounts` and async_main reports its `behind_target` /
# `unservable_epoch` subsets. No spawn was added, removed or moved. Same two
# pristine `git archive | tar -x` trees (origin/main 85b83e0 and this branch's
# base 9d78c46, both extracted outside any shared directory) and the same
# worker_spawn_sites()/classify_worker_spawn()/digest() helpers as the pins
# above; both reproduced their own 26/e6dac368 pin byte-for-byte, and their
# inventories are byte-identical to each other, before anything was written.
# Screenshot-content integrity keeps the same 26 spawn keys, classes, order,
# and byte-identical call expressions. Only upload_capture_event's owner-body
# hash moves around the existing cancellation-owned GCS PUT because its
# ambiguous result now exact-reads the current provider once, authenticates it
# with the installed DEK/strict v2 context, and returns that same generation.
# Pristine 2cf4a11 reproduced 26/c821c699 before derivation.
# Screenshot-upload retirement keeps the same 26 spawn keys, classes, order,
# and byte-identical expressions. Only the legacy upload owner's existing
# cancellation child moves in owner-body hash around the early 410 check and
# captured multipart rejection; the spawn expression itself is unchanged.
# Selected episode deletion adds exactly one B worker spawn: the dedicated
# immediate/30-second fair resume owner. The 26 pristine keys and expressions
# survive unchanged; async_main's owner body moves with the startup call. A
# fresh pristine 5959585 archive reproduced 26/5b946c3c before this 27-row
# branch inventory was derived key by key.
# Selected voice/profile completion adds no worker. The existing media sweep
# spawn alone changes owner and call-expression hashes because its swept future
# now includes the provider-free profile pass. A pristine 41abc0f archive
# reproduced the prior 27/a98e2c12 pin; count, classification, and key order
# are unchanged in this independently derived branch state.
# Archive-v3 deletion runtime wiring was re-derived against the same untouched
# 2ebb08c archive used for the Store-surface pin above. Its own gate first
# reproduced 27/fb45f5aafe15fb834a483cafb26845c699725764015b9dad1ecb6728dd12ae6a.
# The branch has exactly one added C spawn:
# `archive_v3_gcs_http.rs::create_if_absent#0::tokio::spawn#0`. It owns one
# lifecycle-page create until the provider response so caller cancellation
# cannot make the frozen-create drain lie. No surviving key, class, call
# expression, or relative order moves. The only surviving owner-body move is
# async_main's existing spawn, caused by the startup deletion-lane install.
# ADR-0022 zero-archive cutover adds exactly one C worker spawn:
# `sync::spawn_adr0022_zero_archive_cutover`. It is the reviewed destructive
# zero-budget owner and remains separate from the ordinary reconciler. The
# same pristine 6dbd2fc archive cited by the Store-surface pin reproduced its
# own 28/9f4435ee... inventory and 14/14 gate first. No key is removed or
# reclassified, every surviving spawn expression is byte-identical, and only
# async_main's enclosing owner body moves around the zero-budget branch.
# The production cutover liveness repair above moves that same async_main owner
# body again: zero mode now starts only billing detach plus the destructive
# owner, while ordinary mode retains all established schedulers. Against the
# same fresh deaacbb archive recorded by the Store-surface pin, count stays 29
# with zero additions, removals, reclassifications, order moves, or spawn-call
# expression moves. All 28 other owner-body hashes are byte-identical.
EXPECTED_WORKER_SPAWN_SHA256 = "f66254fc4eec2453129198c53787ee9084029799c0d90a5805debe5fe4901fa0"
RAW_STRING_START = re.compile(r"(?:br|r)(#{0,255})\"")


@dataclass(frozen=True)
class Span:
    start: int
    end: int


@dataclass(frozen=True)
class Owner:
    path: str
    name: str
    ordinal: int
    span: Span
    body_hash: str

    @property
    def key(self) -> str:
        return f"{self.path}::{self.name}#{self.ordinal}"


@dataclass(frozen=True)
class CallSite:
    owner: Owner
    target: str
    ordinal: int
    expression_hash: str

    @property
    def key(self) -> str:
        return f"{self.owner.key}::{self.target}#{self.ordinal}"

    def inventory_row(self, classification: str) -> str:
        return "|".join(
            (
                self.key,
                classification,
                self.owner.body_hash,
                self.expression_hash,
            )
        )


def _blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] != "\n":
            chars[index] = " "


def sanitize_rust(source: str) -> str:
    """Blank comments and literals while preserving byte offsets/newlines."""
    chars = list(source)
    index = 0
    block_depth = 0
    while index < len(source):
        if block_depth:
            if source.startswith("/*", index):
                block_depth += 1
                _blank(chars, index, index + 2)
                index += 2
            elif source.startswith("*/", index):
                block_depth -= 1
                _blank(chars, index, index + 2)
                index += 2
            else:
                _blank(chars, index, index + 1)
                index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end == -1 else end
            _blank(chars, index, end)
            index = end
            continue
        if source.startswith("/*", index):
            block_depth = 1
            _blank(chars, index, index + 2)
            index += 2
            continue

        raw = RAW_STRING_START.match(source, index)
        if raw:
            terminator = '"' + raw.group(1)
            content_start = raw.end()
            end = source.find(terminator, content_start)
            end = len(source) if end == -1 else end + len(terminator)
            _blank(chars, index, end)
            index = end
            continue

        quote_index = index + 1 if source.startswith('b"', index) else index
        if quote_index < len(source) and source[quote_index] == '"':
            cursor = quote_index + 1
            escaped = False
            while cursor < len(source):
                char = source[cursor]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    cursor += 1
                    break
                cursor += 1
            _blank(chars, index, cursor)
            index = cursor
            continue

        # Blank real character/byte-character literals, but retain Rust
        # lifetimes such as `'a` and `'_` so a lifetime cannot swallow a later
        # function body.
        char_index = index + 1 if source.startswith("b'", index) else index
        if char_index < len(source) and source[char_index] == "'":
            cursor = char_index + 1
            if cursor < len(source) and source[cursor] == "\\":
                cursor += 2
            else:
                cursor += 1
            if cursor < len(source) and source[cursor] == "'":
                cursor += 1
                _blank(chars, index, cursor)
                index = cursor
                continue
        index += 1
    if block_depth:
        raise AssertionError("unterminated Rust block comment")
    return "".join(chars)


def match_delimiter(code: str, opening: int, left: str, right: str) -> int:
    if opening >= len(code) or code[opening] != left:
        raise AssertionError(f"expected {left!r} at {opening}")
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == left:
            depth += 1
        elif code[index] == right:
            depth -= 1
            if depth == 0:
                return index + 1
    raise AssertionError(f"unclosed {left!r} at {opening}")


def cfg_test_spans(code: str) -> list[Span]:
    """Spans of complete `#[cfg(test)]` items in sanitized source.

    The scan after the attribute list tracks `()`/`[]` nesting so a `;` inside
    the item's signature (e.g. `fn mint(x: [u8; 32]) -> Self {`) cannot end the
    span early and leak the item's body into the production view. A `;` or a
    brace-matched `{ ... }` body at depth zero ends the item. Two containment
    rules keep an attribute that decorates a non-item from swallowing adjacent
    production code: an attribute on a struct-literal field, field declaration,
    or parameter (`name: value`) ends at its depth-zero comma, and a closing
    delimiter of the construct enclosing the attribute ends the span there.
    """
    spans: list[Span] = []
    cfg = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    field_like = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*:(?!:)")
    for match in cfg.finditer(code):
        cursor = match.end()
        while True:
            cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
            if code.startswith("#[", cursor):
                cursor = match_delimiter(code, cursor + 1, "[", "]")
                continue
            break
        non_item = bool(field_like.match(code, cursor))
        depth = 0
        end = None
        for index in range(cursor, len(code)):
            char = code[index]
            if char in "([":
                depth += 1
            elif char in ")]":
                if depth == 0:
                    end = index
                    break
                depth -= 1
            elif char == "}" and depth == 0:
                end = index
                break
            elif char == "," and depth == 0 and non_item:
                end = index + 1
                break
            elif char == ";" and depth == 0:
                end = index + 1
                break
            elif char == "{" and depth == 0:
                end = match_delimiter(code, index, "{", "}")
                break
        if end is None:
            raise AssertionError("cfg(test) attribute has no item")
        spans.append(Span(match.start(), end))
    return spans


def without_cfg_test_items(source: str) -> str:
    """Blank complete cfg(test) items while retaining production source text."""
    code = sanitize_rust(source)
    chars = list(source)
    for span in cfg_test_spans(code):
        _blank(chars, span.start, span.end)
    return "".join(chars)


def _excluded(offset: int, exclusions: list[Span]) -> bool:
    return any(span.start <= offset < span.end for span in exclusions)


def function_spans(path: str, source: str, code: str, exclusions: list[Span]) -> list[Owner]:
    candidates: list[tuple[str, Span]] = []
    for match in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", code):
        if _excluded(match.start(), exclusions):
            continue
        brace = code.find("{", match.end())
        # A declaration-only fn (trait signature) ends in `;` before any `{`
        # -- but only a semicolon at bracket depth 0 counts. `[u8; 32]` in a
        # parameter or return type contains one that does not end anything,
        # and treating it as a terminator silently drops the fn from the
        # owner list, orphaning every store call inside it.
        semicolon = -1
        depth = 0
        scan_end = brace if brace != -1 else len(code)
        for index in range(match.end(), scan_end):
            char = code[index]
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
            elif char == ";" and depth <= 0:
                semicolon = index
                break
        if brace == -1 or semicolon != -1:
            continue
        line_start = code.rfind("\n", 0, match.start()) + 1
        prefix = code[line_start : match.start()]
        last_delimiter = max(prefix.rfind(";"), prefix.rfind("{"), prefix.rfind("}"))
        declaration_start = line_start + last_delimiter + 1
        candidates.append(
            (
                match.group(1),
                Span(declaration_start, match_delimiter(code, brace, "{", "}")),
            )
        )
    ordinals: dict[str, int] = {}
    owners: list[Owner] = []
    for name, span in sorted(candidates, key=lambda item: item[1].start):
        ordinal = ordinals.get(name, 0)
        ordinals[name] = ordinal + 1
        owners.append(
            Owner(
                path,
                name,
                ordinal,
                span,
                hashlib.sha256(source[span.start : span.end].encode()).hexdigest(),
            )
        )
    return owners


def owner_at(owners: list[Owner], offset: int) -> Owner:
    containing = [
        owner for owner in owners if owner.span.start <= offset < owner.span.end
    ]
    if not containing:
        raise AssertionError(f"call at offset {offset} has no enclosing function")
    return min(containing, key=lambda owner: owner.span.end - owner.span.start)


def owner_or_module(path: str, owners: list[Owner], offset: int) -> Owner:
    containing = [
        owner for owner in owners if owner.span.start <= offset < owner.span.end
    ]
    if containing:
        return min(containing, key=lambda owner: owner.span.end - owner.span.start)
    module_identity = hashlib.sha256(f"{path}::<module>".encode()).hexdigest()
    return Owner(path, "<module>", 0, Span(offset, offset + 1), module_identity)


def call_sites_for_source(
    path: str, source: str, target_pattern: re.Pattern[str]
) -> list[CallSite]:
    code = sanitize_rust(source)
    exclusions = cfg_test_spans(code)
    owners = function_spans(path, source, code, exclusions)
    provisional: list[tuple[Owner, str, int, int]] = []
    for match in target_pattern.finditer(code):
        if _excluded(match.start(), exclusions):
            continue
        owner = owner_at(owners, match.start())
        opening = code.find("(", match.start(), match.end() + 1)
        if opening == -1:
            raise AssertionError(f"call {match.group('target')} has no opening delimiter")
        close = match_delimiter(code, opening, "(", ")")
        provisional.append((owner, match.group("target"), match.start(), close))
    ordinals: dict[tuple[str, str], int] = {}
    sites: list[CallSite] = []
    for owner, target, start, end in sorted(provisional, key=lambda item: item[2]):
        key = (owner.key, target)
        ordinal = ordinals.get(key, 0)
        ordinals[key] = ordinal + 1
        sites.append(
            CallSite(
                owner,
                target,
                ordinal,
                hashlib.sha256(source[start:end].encode()).hexdigest(),
            )
        )
    return sites


STORE_CALL = re.compile(
    r"(?:\.\s*|\bSelf\s*::\s*|"
    r"\b(?:crate\s*::\s*store\s*::\s*)?Store\s*::\s*|"
    r"<\s*(?:crate\s*::\s*store\s*::\s*)?Store\s*>\s*::\s*)"
    r"(?P<target>with_user_mut|with_user_if_changed|with_user|save_user"
    r"|wal_authoritative_read|wal_authoritative_submit)\s*\("
)
WORKER_SPAWN = re.compile(
    r"(?P<target>tokio::spawn)\s*\(|\.\s*(?P<method>spawn)\s*\(\s*async\b|"
    r"\.\s*(?P<thread>spawn)\s*\(\s*move\s*\|\||\.\s*(?P<local>spawn_local)\s*\("
)


def rust_sources() -> list[tuple[str, str]]:
    return [
        (str(path.relative_to(ROOT)), path.read_text(encoding="utf-8"))
        for path in sorted((ROOT / "src").rglob("*.rs"))
    ]


def store_call_sites() -> list[CallSite]:
    return [
        site
        for path, source in rust_sources()
        for site in call_sites_for_source(path, source, STORE_CALL)
    ]


def worker_spawn_sites() -> list[CallSite]:
    normalized = re.compile(
        r"(?P<target>tokio::spawn)\s*\(|\.\s*(?P<target_method>spawn)\s*\(\s*async\b|"
        r"\.\s*(?P<target_thread>spawn)\s*\(\s*move\s*\|\||"
        r"\.\s*(?P<target_local>spawn_local)\s*\("
    )
    sites: list[CallSite] = []
    for path, source in rust_sources():
        code = sanitize_rust(source)
        exclusions = cfg_test_spans(code)
        owners = function_spans(path, source, code, exclusions)
        provisional: list[tuple[Owner, str, int, int]] = []
        for match in normalized.finditer(code):
            if _excluded(match.start(), exclusions):
                continue
            target = next(value for value in match.groups() if value is not None)
            owner = owner_at(owners, match.start())
            opening = code.find("(", match.start(), match.end() + 1)
            close = match_delimiter(code, opening, "(", ")")
            provisional.append((owner, target, match.start(), close))
        ordinals: dict[tuple[str, str], int] = {}
        for owner, target, start, end in provisional:
            key = (owner.key, target)
            ordinal = ordinals.get(key, 0)
            ordinals[key] = ordinal + 1
            sites.append(
                CallSite(
                    owner,
                    target,
                    ordinal,
                    hashlib.sha256(source[start:end].encode()).hexdigest(),
                )
            )
    return sites


def impl_store_spans(code: str, exclusions: list[Span]) -> list[Span]:
    spans = []
    for match in re.finditer(r"\bimpl\s+Store\s*\{", code):
        if _excluded(match.start(), exclusions):
            continue
        opening = code.find("{", match.start(), match.end())
        spans.append(Span(match.start(), match_delimiter(code, opening, "{", "}")))
    return spans


def _relabel(sites: list[CallSite], prefix: str) -> list[CallSite]:
    return [
        CallSite(site.owner, f"{prefix}{site.target}", site.ordinal, site.expression_hash)
        for site in sites
    ]


def token_sites_for_source(
    path: str, source: str, pattern: re.Pattern[str], target_prefix: str = ""
) -> list[CallSite]:
    code = sanitize_rust(source)
    exclusions = cfg_test_spans(code)
    owners = function_spans(path, source, code, exclusions)
    provisional: list[tuple[Owner, str, int, int]] = []
    for match in pattern.finditer(code):
        if _excluded(match.start(), exclusions):
            continue
        target = match.groupdict().get("target") or match.group(0).strip()
        provisional.append(
            (
                owner_or_module(path, owners, match.start()),
                f"{target_prefix}{target}",
                match.start(),
                match.end(),
            )
        )
    ordinals: dict[tuple[str, str], int] = {}
    sites = []
    for owner, target, start, end in provisional:
        key = (owner.key, target)
        ordinal = ordinals.get(key, 0)
        ordinals[key] = ordinal + 1
        sites.append(
            CallSite(
                owner,
                target,
                ordinal,
                hashlib.sha256(source[start:end].encode()).hexdigest(),
            )
        )
    return sites


def store_surface_sites_from_sources(sources: list[tuple[str, str]]) -> list[CallSite]:
    store_path = "src/store.rs"
    store_source = next(source for path, source in sources if path == store_path)
    store_code = sanitize_rust(store_source)
    exclusions = cfg_test_spans(store_code)
    owners = function_spans(store_path, store_source, store_code, exclusions)
    impls = impl_store_spans(store_code, exclusions)

    factory_owners = []
    for owner in owners:
        if not any(span.start <= owner.span.start < span.end for span in impls):
            continue
        opening = store_code.find("{", owner.span.start, owner.span.end)
        header = store_code[owner.span.start:opening]
        if re.search(r"->[\s\S]*\b(?:Self|Store)\b", header):
            factory_owners.append(owner)
    factory_names = sorted({owner.name for owner in factory_owners})
    if not factory_names:
        raise AssertionError("Store has no structurally visible factory")
    names = "|".join(re.escape(name) for name in factory_names)

    store_call = re.compile(
        rf"\b(?:crate\s*::\s*store\s*::\s*)?Store\s*::\s*(?P<target>{names})\s*\("
    )
    sites = [
        site
        for path, source in sources
        for site in _relabel(call_sites_for_source(path, source, store_call), "Store::")
    ]
    self_call = re.compile(rf"\bSelf\s*::\s*(?P<target>{names})\s*\(")
    sites.extend(
        site
        for site in _relabel(
            call_sites_for_source(store_path, store_source, self_call), "Self::"
        )
        if any(span.start <= site.owner.span.start < span.end for span in impls)
    )
    sites.extend(
        CallSite(owner, f"factory_definition::{owner.name}", 0, owner.body_hash)
        for owner in factory_owners
    )

    for path, source in sources:
        code = sanitize_rust(source)
        source_exclusions = cfg_test_spans(code)
        source_owners = function_spans(path, source, code, source_exclusions)
        ordinals: dict[str, int] = {}
        for match in re.finditer(r"\bStore\s*\{", code):
            if _excluded(match.start(), source_exclusions):
                continue
            prefix = code[max(0, match.start() - 24) : match.start()]
            if re.search(r"\b(?:struct|impl)\s*$", prefix):
                continue
            opening = code.find("{", match.start(), match.end())
            end = match_delimiter(code, opening, "{", "}")
            owner = owner_or_module(path, source_owners, match.start())
            ordinal = ordinals.get(owner.key, 0)
            ordinals[owner.key] = ordinal + 1
            sites.append(
                CallSite(
                    owner,
                    "Store_literal",
                    ordinal,
                    hashlib.sha256(source[match.start() : end].encode()).hexdigest(),
                )
            )
    return sorted(sites, key=lambda site: site.key)


def store_surface_sites() -> list[CallSite]:
    return store_surface_sites_from_sources(rust_sources())


def policy_sites_from_sources(sources: list[tuple[str, str]]) -> list[CallSite]:
    sites = []
    patterns = (
        (re.compile(r"\b(?P<target>WalLogicalOnly)\b"), ""),
        (re.compile(r"\b(?P<target>persistence_policy)\b"), ""),
        (
            re.compile(
                r"\bStorePersistencePolicy::(?P<target>[A-Za-z_][A-Za-z0-9_]*)"
            ),
            "StorePersistencePolicy::",
        ),
    )
    for path, source in sources:
        for pattern, prefix in patterns:
            sites.extend(token_sites_for_source(path, source, pattern, prefix))
    return sorted(sites, key=lambda site: site.key)


def policy_sites() -> list[CallSite]:
    return policy_sites_from_sources(rust_sources())


# Owner defaults are used only after the exact call key has been pinned by the
# inventory digest below. Mixed owners use explicit call-site overrides.
A_OWNERS = frozenset(
    {
        # Routed margin-dashboard read (billing): page/media/email counters
        # only, no mutation. Added when the last ungated legacy read outside
        # the D4 sweep was routed; its `Option` return had been swallowing the
        # refusal into a driver-less dashboard row.
        "src/cp/billing.rs::current_account_drivers#0",
        "src/cp/delivery.rs::load_finalized_episode#0",
        "src/cp/email_worker.rs::load_open_email_claim#0",
        "src/cp/email_worker.rs::load_frozen_email_request#0",
        "src/cp/email_worker.rs::load_email_claim_recovery#0",
        "src/cp/email_worker.rs::validate_archive_email_send_authority#0",
        "src/cp/email_worker.rs::emit_email_depth#0",
        "src/cp/finalizer.rs::finalize_user_episodes_scoped#0",
        "src/cp/media.rs::read_media_dek_wrapped#0",
        "src/cp/media.rs::stream_ack#0",
        "src/cp/media.rs::capture_status#0",
        "src/cp/media.rs::capture_session_status#0",
        "src/cp/media.rs::list_capture_sessions#0",
        "src/cp/media.rs::finish_capture_session#0",
        "src/cp/media.rs::upload_screen_reference_batch#0",
        "src/cp/media.rs::list_people#0",
        "src/cp/media.rs::person_profile#0",
        "src/cp/media.rs::person_evidence#0",
        "src/cp/media.rs::person_statements#0",
        "src/cp/media_worker.rs::candidate_name_vocabulary#0",
        "src/cp/summarizer.rs::span_holds_recoverable_media#0",
        "src/cp/media_worker.rs::persist_actual_media_usage#0",
        "src/cp/media_worker.rs::prune_user_media_store#0",
        "src/cp/model_usage.rs::record_response#0",
        "src/cp/model_usage.rs::record_ambiguous#0",
        "src/cp/model_usage.rs::record_not_billed#0",
        "src/cp/model_usage.rs::complete_delivery#0",
        "src/cp/model_usage.rs::complete_coverage#0",
        "src/cp/model_usage.rs::persist_coverage_snapshot#0",
        "src/cp/model_usage.rs::invalidate_stale_coverage#0",
        "src/cp/query.rs::query_transcripts_value#0",
        "src/cp/query.rs::tool_search_screenshots#0",
        "src/cp/query.rs::query_episodes_value#0",
        "src/cp/query.rs::tool_get_capture_status#0",
        "src/cp/query.rs::dispatch_tool#0",
        "src/cp/query.rs::rest_episode_members#0",
        "src/cp/query.rs::rest_browser_snapshot#0",
        "src/cp/query.rs::rest_episode_finalize#0",
        "src/cp/query.rs::rest_feed#0",
        "src/cp/query.rs::resume_user_episode_deletions#0",
        "src/cp/query.rs::rest_screenshot_upload_plan#0",
        "src/cp/query.rs::rest_screenshot_image_content#0",
        "src/cp/reviewer.rs::ensure_demo_archive#0",
        "src/cp/push.rs::load_open_send_claim#0",
        "src/cp/push.rs::load_send_claim_recovery#0",
        "src/cp/push.rs::validate_archive_send_authority#0",
        "src/cp/push.rs::emit_push_depth#0",
        "src/cp/summarizer.rs::run_substance_backfill#0",
        "src/cp/summarizer.rs::run_visual_evidence_backfill#0",
        "src/cp/summarizer.rs::fetch_range#0",
        "src/cp/summarizer.rs::fetch_open_episodes#0",
        "src/cp/summarizer.rs::session_tail_is_settled#0",
        "src/cp/sync.rs::dump_user_export#0",
        "src/cp/sync.rs::sync_status#0",
        "src/cp/webhook_worker.rs::next_delivery#0",
        "src/cp/webhook_worker.rs::next_selected_delivery#0",
        "src/cp/webhook_worker.rs::load_open_webhook_claim#0",
        "src/cp/webhook_worker.rs::load_frozen_webhook_request#0",
        "src/cp/webhook_worker.rs::load_webhook_claim_recovery#0",
        "src/cp/webhook_worker.rs::validate_archive_webhook_send_authority#0",
        "src/cp/webhook_worker.rs::emit_webhook_depth#0",
        "src/cp/webhook_worker.rs::webhook_delivery_status#0",
        "src/store.rs::enqueue_email_delivery#0",
        "src/store.rs::next_email_delivery#0",
        "src/store.rs::next_push_delivery#0",
        "src/store.rs::resolve_push_handoff#0",
    }
)
B_OWNERS = frozenset(
    {
        "src/cp/finalizer.rs::set_finalization_status#0",
        "src/cp/finalizer.rs::read_finalization_predecessor#0",
        "src/cp/email_worker.rs::submit_email_claim#0",
        "src/cp/email_worker.rs::settle_exact_email#0",
        "src/cp/email_worker.rs::settle_email_delivery#0",
        "src/cp/email_worker.rs::cancel_user_email_deliveries#0",
        "src/cp/push.rs::submit_send_claim#0",
        "src/cp/push.rs::settle_delivery_at#0",
        "src/cp/finalizer.rs::settle_lifecycle#0",
        "src/cp/finalizer.rs::finalize_commit_settled#0",
        "src/cp/finalizer.rs::record_finalization_failure#0",
        "src/cp/finalizer.rs::defer_finalization_for_budget#0",
        "src/cp/media.rs::load_or_create_media_dek#0",
        "src/cp/media_worker.rs::claim_media_work_unit#0",
        "src/cp/media_worker.rs::quarantine_unplannable_jobs#0",
        "src/cp/media_worker.rs::process_user_voice_embedding_jobs#0",
        "src/cp/media_worker.rs::process_selected_voice_embedding_jobs#0",
        "src/cp/media_worker.rs::process_user_voice_profiles#0",
        "src/cp/media_worker.rs::reserve_media_output#0",
        "src/cp/media_worker.rs::settle_media_work_failure#0",
        "src/cp/media_worker.rs::resurrect_user_failed_jobs#0",
        "src/cp/media_worker.rs::settle_audio_window_attempt#0",
        "src/cp/media_worker.rs::settle_audio_window_transcript#0",
        "src/cp/media_worker.rs::settle_screen_storyboard_attempt#0",
        "src/cp/media_worker.rs::settle_screen_storyboard_result#0",
        # ADR-0022 Part B: the owner-side schema-ladder driver. Reads the
        # archive's own epoch marker, then submits ONE sealed step. It is the
        # only writer of `schema_epoch` after birth, so it classifies with the
        # other settle owners rather than as a read.
        "src/cp/schema_epoch/wal/advance.rs::advance_one_epoch#0",
        "src/cp/model_usage.rs::begin_invocation#0",
        "src/cp/model_usage.rs::settle_response_required#0",
        "src/cp/model_usage.rs::begin_invocation_settled#0",
        "src/cp/model_usage.rs::pending_events_settled#0",
        "src/cp/model_usage.rs::read_delivery_predecessors#0",
        "src/cp/model_usage.rs::settle_delivery#0",
        "src/cp/model_usage.rs::read_coverage_predecessor#0",
        "src/cp/model_usage.rs::settle_coverage#0",
        "src/cp/model_usage.rs::pending_coverage_settled#0",
        "src/cp/model_usage.rs::pending_events#0",
        "src/cp/model_usage.rs::pending_coverage#0",
        "src/cp/model_usage.rs::drain_coverage#0",
        "src/cp/model_usage.rs::note_delivery_failure#0",
        "src/cp/model_usage.rs::drain_outbox#0",
        "src/cp/query.rs::rest_delete_webhook#0",
        "src/cp/summarizer.rs::summarize_user_window#0",
        "src/cp/summarizer.rs::wal_authoritative_upsert#0",
        "src/cp/summarizer.rs::embed_episodes#0",
        "src/cp/webhook_worker.rs::set_delivery_state#0",
        "src/cp/webhook_worker.rs::set_legacy_delivery_state#0",
        "src/cp/webhook_worker.rs::cancel_subscription_deliveries#0",
        "src/cp/webhook_worker.rs::submit_webhook_claim#0",
        "src/cp/webhook_worker.rs::settle_exact_webhook#0",
        "src/cp/webhook_worker.rs::purge_exact_webhook#0",
        "src/store.rs::update_email_delivery_state#0",
        "src/store.rs::set_email_delivery_next_attempt#0",
        "src/store.rs::cancel_pending_email_deliveries#0",
    }
)
C_OWNERS = frozenset(
    {
        "src/cp/model_usage.rs::settle_for_account_deletion#0",
        "src/cp/query.rs::rest_episode_delete#0",
        "src/cp/query.rs::rest_selected_episode_delete#0",
        "src/store.rs::with_user_read#0",
        "src/store.rs::with_user_if_changed#0",
        "src/store.rs::freeze_wal_authoritative_media_keys#0",
    }
)

CALL_OVERRIDES = {
    # The durable scheduler inventory is read-only A, while the same owner's
    # cursor advance is a sealed episode-delete C mutation.
    "src/cp/query.rs::resume_user_episode_deletions#0::wal_authoritative_submit#0": "C",
    # The selected cancellation scan is read-only; the same owner retains the
    # legacy mutation/save pair for unselected archives.
    "src/cp/webhook_worker.rs::cancel_subscription_deliveries#0::wal_authoritative_read#0": "A",
    # Speaker-slot reconciliation allocates random participant keys and
    # rewrites labels from live attribution state before the evidence reads
    # (the legacy evidence arm); the second with_user is the legacy commit.
    "src/cp/finalizer.rs::finalize_user_episodes_scoped#0::with_user#0": "B",
    "src/cp/finalizer.rs::finalize_user_episodes_scoped#0::with_user#1": "B",
    # Stable capture record, but the complete owner has the B dependency below.
    # The routed sites join them at the same classification: the preflight is
    # read-only, and both settle-submits commit the same stable capture record
    # their legacy counterparts do -- one per media disposition, because this
    # one route serves both and a half-migrated ingest stalls an interleaved
    # mac_screen stream at its first refused event.
    "src/cp/media.rs::upload_capture_event#0::wal_authoritative_read#0": "A",
    "src/cp/media.rs::upload_capture_event#0::wal_authoritative_submit#0": "A",
    "src/cp/media.rs::upload_capture_event#0::wal_authoritative_submit#1": "A",
    "src/cp/media.rs::upload_capture_event#0::with_user#0": "A",
    "src/cp/media.rs::upload_capture_event#0::with_user#1": "A",
    "src/cp/media.rs::upload_capture_event#0::save_user#0": "A",
    "src/cp/media.rs::upload_capture_event#0::save_user#1": "A",
    # Deterministic work result is A; reservation/model attempts remain B.
    "src/cp/media_worker.rs::process_work_unit#0::with_user#0": "A",
    "src/cp/media_worker.rs::process_work_unit#0::with_user#1": "A",
    "src/cp/media_worker.rs::process_work_unit#0::save_user#0": "A",
    # Scan is read-only A; every lease/retry/reconciliation mutation is B.
    # Slice 10i: the scan's routed arm is the same read-only class scan as
    # with_user#0 below, at the same eligibility horizon the claim carries.
    # The claim and failure mutations live in their own B owners, so no
    # with_user/save_user ordinal below moved.
    "src/cp/media_worker.rs::process_user#0::wal_authoritative_read#0": "A",
    "src/cp/media_worker.rs::process_user#0::with_user#0": "A",
    "src/cp/media_worker.rs::process_user#0::with_user#1": "B",
    "src/cp/media_worker.rs::process_user#0::with_user#2": "B",
    "src/cp/media_worker.rs::process_user#0::with_user#3": "B",
    "src/cp/media_worker.rs::process_user#0::with_user#4": "B",
    "src/cp/media_worker.rs::process_user#0::save_user#0": "B",
    "src/cp/media_worker.rs::process_user#0::save_user#1": "B",
    "src/cp/media_worker.rs::process_user#0::save_user#2": "B",
    # Settled quality diagnostics are a deterministic record of immutable
    # audio, keyed by observation id; lease/plan/completion/match stay B.
    "src/cp/media_worker.rs::process_user_voice_embedding_jobs#0::with_user#4": "A",
    # Screenshot preflight/DEK lookup, B first-writer candidate, A record/rollback.
    "src/cp/query.rs::rest_screenshot_image_upload#0::with_user#0": "A",
    "src/cp/query.rs::rest_screenshot_image_upload#0::with_user#1": "A",
    "src/cp/query.rs::rest_screenshot_image_upload#0::with_user#2": "B",
    "src/cp/query.rs::rest_screenshot_image_upload#0::with_user#3": "A",
    "src/cp/query.rs::rest_screenshot_image_upload#0::with_user#4": "A",
    "src/cp/query.rs::rest_screenshot_image_upload#0::save_user#0": "A",
    "src/cp/query.rs::rest_screenshot_image_upload#0::save_user#1": "A",
}

DEPENDENCY_CLASS = {
    "src/cp/media.rs::upload_capture_event#0": "B",
    "src/cp/media_worker.rs::process_work_unit#0": "B",
    "src/cp/query.rs::rest_screenshot_image_upload#0": "B",
    "src/cp/finalizer.rs::finalize_user_episodes_scoped#0": "B",
}


def classify_store_call(site: CallSite) -> str:
    if site.key in CALL_OVERRIDES:
        return CALL_OVERRIDES[site.key]
    memberships = [
        category
        for category, owners in (("A", A_OWNERS), ("B", B_OWNERS), ("C", C_OWNERS))
        if site.owner.key in owners
    ]
    if len(memberships) != 1:
        raise AssertionError(f"unclassified or multiply classified Store call: {site.key}")
    return memberships[0]


def digest(rows: list[str]) -> str:
    return hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest()


def assert_inventory(
    sites: list[CallSite],
    classify,
    expected_count: int,
    expected_sha256: str,
) -> None:
    keys = [site.key for site in sites]
    if len(keys) != len(set(keys)):
        raise AssertionError("duplicate structural call-site key")
    rows = []
    for site in sites:
        classification = classify(site)
        if classification not in CLASSIFICATIONS:
            raise AssertionError(f"invalid classification for {site.key}: {classification}")
        rows.append(site.inventory_row(classification))
    if len(rows) != expected_count or digest(rows) != expected_sha256:
        raise AssertionError(
            "structural inventory changed:\n" + "\n".join(rows)
        )


class WalIdempotencyGateTest(unittest.TestCase):
    def test_structural_scanner_handles_cfg_literals_comments_and_nested_owners(self) -> None:
        source = r'''
#[cfg(test)]
mod tests { const X: &str = r#"{ .with_user("#; fn hidden() { x.with_user(1); } }
impl X {
    #[cfg(test)] fn hidden_method(&self) { self.with_user(1); }
    fn array_param(&self, value: &[u8; 32]) {
        let _ = value;
        self.with_user(4);
    }
    fn live(&self) {
        // }.with_user(
        /* outer { /* nested .with_user( */ } */
        let _ = "}.with_user(\\\"";
        let _ = r###"}.with_user("###;
        let _ = br##"}.with_user("##;
        let _ = '}';
        let _ = b'{';
        fn inner() { x.with_user(1); }
        self.with_user(2);
    }
}
'''
        sites = call_sites_for_source("fixture.rs", source, STORE_CALL)
        self.assertEqual(
            [site.key for site in sites],
            [
                "fixture.rs::array_param#0::with_user#0",
                "fixture.rs::inner#0::with_user#0",
                "fixture.rs::live#0::with_user#0",
            ],
        )
        with self.assertRaises(AssertionError):
            call_sites_for_source("bad.rs", "fn closed() {} x.with_user(1);", STORE_CALL)

    def test_cfg_test_span_is_not_truncated_by_bracket_nested_semicolon(self) -> None:
        source = (
            "impl T {\n"
            "    #[cfg(test)]\n"
            "    pub(crate) const fn mint(x: [u8; 32]) -> Self {\n"
            "        Self { field: x }\n"
            "    }\n"
            "}\n"
            "fn keep() {}\n"
        )
        stripped = without_cfg_test_items(source)
        self.assertNotIn(
            "Self { field", stripped, "signature [u8; 32] must not truncate the span"
        )
        self.assertIn("fn keep", stripped)
        hidden = (
            "impl T {\n"
            "    #[cfg(test)]\n"
            "    fn hidden(x: [u8; 32]) -> Self { self.with_user(1); }\n"
            "    fn live(&self) { self.with_user(2); }\n"
            "}\n"
        )
        sites = call_sites_for_source("fixture.rs", hidden, STORE_CALL)
        self.assertEqual(
            [site.key for site in sites], ["fixture.rs::live#0::with_user#0"]
        )

    def test_cfg_test_field_and_parameter_attributes_strip_only_the_field(self) -> None:
        literal = (
            "fn build() -> Result<Self> {\n"
            "    Ok(Self {\n"
            "        copy: value,\n"
            "        #[cfg(test)]\n"
            "        cleanup_sender: None,\n"
            "    })\n"
            "}\n"
            "fn production(&self) { self.with_user(1); }\n"
        )
        stripped = without_cfg_test_items(literal)
        self.assertNotIn("cleanup_sender", stripped)
        self.assertIn("copy: value", stripped)
        self.assertIn("fn production", stripped)
        sites = call_sites_for_source("fixture.rs", literal, STORE_CALL)
        self.assertEqual(
            [site.key for site in sites], ["fixture.rs::production#0::with_user#0"]
        )
        parameter = (
            "fn spawn_task(\n"
            "    connection: Arc<Mutex<Connection>>,\n"
            "    #[cfg(test)] gate: Option<Arc<TestBlockingGate>>,\n"
            ") -> JoinHandle<Result<()>> {\n"
            "    inner.with_user(3);\n"
            "}\n"
        )
        stripped = without_cfg_test_items(parameter)
        self.assertNotIn("TestBlockingGate", stripped)
        self.assertIn("inner.with_user", stripped)
        sites = call_sites_for_source("fixture.rs", parameter, STORE_CALL)
        self.assertEqual(
            [site.key for site in sites], ["fixture.rs::spawn_task#0::with_user#0"]
        )

    def test_new_call_body_or_classification_change_fails_inventory(self) -> None:
        first = call_sites_for_source("x.rs", "fn f(){ x.with_user(|| 1); }", STORE_CALL)
        changed = call_sites_for_source("x.rs", "fn f(){ x.with_user(|| 2); }", STORE_CALL)
        self.assertNotEqual(
            first[0].inventory_row("A"), changed[0].inventory_row("A")
        )
        with self.assertRaises(AssertionError):
            assert_inventory(first, lambda _: "B", 1, digest([first[0].inventory_row("A")]))
        added = call_sites_for_source(
            "x.rs", "fn f(){ x.with_user(|| 1); x.save_user(1); }", STORE_CALL
        )
        with self.assertRaises(AssertionError):
            assert_inventory(
                added, lambda _: "A", 1, digest([first[0].inventory_row("A")])
            )

    def test_every_store_call_is_structurally_pinned_and_exactly_classified(self) -> None:
        assert_inventory(
            store_call_sites(),
            classify_store_call,
            EXPECTED_STORE_CALL_COUNT,
            EXPECTED_STORE_CALL_SHA256,
        )
        self.assertEqual(set(DEPENDENCY_CLASS.values()), {"B"})
        self.assertTrue(set(DEPENDENCY_CLASS).issubset({site.owner.key for site in store_call_sites()}))

    def test_chosen_archive_key_constructor_stays_test_only(self) -> None:
        """`ArchiveDek::from_bytes` is the only chosen-key path; keep it test-only.

        Genesis mints a first archive key with `ArchiveDek::generate`, which is
        production-visible and draws from the system CSPRNG, so a caller cannot
        influence the key material. That argument holds only while the
        attacker-selected-bytes constructor remains unavailable outside tests --
        promoting it would silently turn key injection from a reviewed code
        change into an ordinary call.
        """
        source = (ROOT / "src/archive_v3.rs").read_text(encoding="utf-8")

        def dek_impl(text: str) -> str:
            # Several types in this file expose from_bytes([u8; 32]); scope the
            # assertion to ArchiveDek's own impl block.
            start = text.index("impl ArchiveDek {")
            return text[start : text.index("\n}", start)]

        self.assertIn("pub(crate) fn generate() -> Self", dek_impl(source))
        # Match the signature, not the bare name: the generate() doc comment
        # legitimately mentions from_bytes when explaining why it stays test-only.
        self.assertIn("fn from_bytes", dek_impl(source))
        self.assertNotIn("fn from_bytes", dek_impl(without_cfg_test_items(source)))

    def test_plan_family_subtypes_are_declared_and_pairwise_distinct(self) -> None:
        """Every plan family's operation-id subtype must be unique.

        Several families legitimately share one WalOperationKind ordinal
        (adding an ordinal is a reviewed, signed act), and the ids are derived
        from durable natural keys with no global operation index to catch a
        clash. Two families sharing an ordinal and a key would silently
        collide on one ledger row, so the subtype is the only thing keeping
        them apart -- and a duplicated constant would be invisible in review.
        """
        declarations: dict[str, list[str]] = {}
        for path, source in rust_sources():
            if "/wal" not in path:
                continue
            production = without_cfg_test_items(source)
            for match in re.finditer(
                r'const\s+SUBTYPE\s*:\s*&\[u8\]\s*=\s*b"([^"]*)"', production
            ):
                declarations.setdefault(match.group(1), []).append(path)
        self.assertTrue(declarations, "no plan-family subtype declarations found")
        for value, paths in sorted(declarations.items()):
            self.assertNotEqual(value, "", f"empty subtype in {paths}")
            self.assertEqual(
                len(paths),
                1,
                f"subtype {value!r} is declared in more than one family: {paths}",
            )

    def test_store_construction_policy_and_worker_surfaces_are_pinned(self) -> None:
        exact_store_surface = store_surface_sites()
        assert_inventory(
            exact_store_surface,
            lambda _: "C",
            EXPECTED_STORE_SURFACE_COUNT,
            EXPECTED_STORE_SURFACE_SHA256,
        )
        self.assertEqual(
            {site.key for site in exact_store_surface}, EXPECTED_STORE_SURFACE_KEYS
        )
        exact_policy_sites = policy_sites()
        assert_inventory(
            exact_policy_sites,
            lambda _: "C",
            EXPECTED_POLICY_SITE_COUNT,
            EXPECTED_POLICY_SITE_SHA256,
        )
        self.assertEqual(
            {
                site.key
                for site in exact_policy_sites
                if site.target == "WalLogicalOnly"
            },
            EXPECTED_WAL_LOGICAL_ONLY_KEYS,
        )
        self.assertEqual(
            {
                site.key
                for site in exact_policy_sites
                if site.target == "StorePersistencePolicy::WalOwnerAuthoritative"
            },
            EXPECTED_WAL_OWNER_AUTHORITATIVE_KEYS,
        )
        assert_inventory(
            worker_spawn_sites(),
            classify_worker_spawn,
            EXPECTED_WORKER_SPAWN_COUNT,
            EXPECTED_WORKER_SPAWN_SHA256,
        )

    def test_from_wal_conditional_main_and_qualified_mutation_bypasses_are_detected(self) -> None:
        synthetic = [
            (
                "src/store.rs",
                """
                enum StorePersistencePolicy { LegacySnapshot, WalLogicalOnly }
                struct Store { persistence_policy: StorePersistencePolicy }
                impl Store {
                    pub fn new() -> Self {
                        Store { persistence_policy: StorePersistencePolicy::LegacySnapshot }
                    }
                    pub fn from_wal(enabled: bool) -> Self {
                        Store { persistence_policy: if enabled {
                            StorePersistencePolicy::WalLogicalOnly
                        } else { StorePersistencePolicy::LegacySnapshot } }
                    }
                }
                """,
            ),
            (
                "src/main.rs",
                """fn main() {
                    let policy = if flag() {
                        StorePersistencePolicy::WalLogicalOnly
                    } else { StorePersistencePolicy::LegacySnapshot };
                    let _ = Store::from_wal(policy);
                }""",
            ),
        ]
        surfaces = store_surface_sites_from_sources(synthetic)
        surface_targets = {site.target for site in surfaces}
        self.assertIn("factory_definition::from_wal", surface_targets)
        self.assertIn("Store::from_wal", surface_targets)
        self.assertIn("Store_literal", surface_targets)
        exact_policy_sites = policy_sites_from_sources(synthetic)
        self.assertTrue(
            any(
                site.target == "WalLogicalOnly"
                and site.owner.key == "src/store.rs::from_wal#0"
                for site in exact_policy_sites
            )
        )
        self.assertTrue(
            any(
                site.target == "WalLogicalOnly"
                and site.owner.key == "src/main.rs::main#0"
                for site in exact_policy_sites
            )
        )
        with self.assertRaises(AssertionError):
            assert_inventory(
                surfaces,
                lambda _: "C",
                EXPECTED_STORE_SURFACE_COUNT,
                EXPECTED_STORE_SURFACE_SHA256,
            )
        private_factory = [
            (path, source.replace("pub fn from_wal", "fn from_wal"))
            for path, source in synthetic
        ]
        self.assertNotEqual(
            [site.inventory_row("C") for site in surfaces],
            [
                site.inventory_row("C")
                for site in store_surface_sites_from_sources(private_factory)
            ],
            "making a Store factory public must change the pinned owner hash",
        )

        qualified = call_sites_for_source(
            "qualified.rs",
            """impl Store {
                fn bypass(&self) {
                    Self::with_user(self, "u", |_| Ok(()));
                    Store::with_user(self, "u", |_| Ok(()));
                    crate::store::Store::save_user(self, "u");
                    <Store>::with_user_mut(self, "u", |_| Ok(()));
                    <crate::store::Store>::with_user_if_changed(
                        self, "u", |_| Ok(((), true))
                    );
                }
            }""",
            STORE_CALL,
        )
        self.assertEqual(
            [site.target for site in qualified],
            [
                "with_user",
                "with_user",
                "save_user",
                "with_user_mut",
                "with_user_if_changed",
            ],
        )
        with self.assertRaises(AssertionError):
            assert_inventory(
                qualified,
                lambda _: "C",
                EXPECTED_STORE_CALL_COUNT,
                EXPECTED_STORE_CALL_SHA256,
            )

    def test_store_policy_is_private_test_only_and_gates_every_escape(self) -> None:
        store = (ROOT / "src/store.rs").read_text(encoding="utf-8")
        main = (ROOT / "src/main.rs").read_text(encoding="utf-8")
        self.assertIn("enum StorePersistencePolicy", store)
        self.assertIn("StorePersistencePolicy::LegacySnapshot", store)
        self.assertIn("new_wal_logical_only_for_test", store)
        self.assertNotIn("WalLogicalOnly", main)
        self.assertNotIn("new_wal_logical_only_for_test", main)
        for needle in (
            'pragma_update(None, "query_only", true)',
            "validate_checkpointed_sqlite_file(path)",
            "ensure_no_sqlite_sidecars(path)",
            'uri.push_str("?mode=ro&immutable=1")',
            "return Err(wal_logical_only_error())",
        ):
            self.assertIn(needle, store)

    def test_new_gate_has_no_activation_or_universal_receipt_table(self) -> None:
        gate = (ROOT / "src/archive_v3_wal_idempotency.rs").read_text(encoding="utf-8")
        self.assertIn("trait WalLogicalDomainPlan: sealed::DomainPlan", gate)
        self.assertIn("trait WalLogicalDomainLedger", gate)
        self.assertIn("struct PreparedLogicalMutation", gate)
        for forbidden in (
            "archive_v3_wal_logical_operations",
            "crate::store::Store",
            "std::env::",
            "tokio::spawn",
            "GcsClient",
            "Witness::advance",
            "pub struct PreparedLogicalMutation",
        ):
            self.assertNotIn(forbidden, gate)

    def test_production_a_domains_are_closed_and_unwired(self) -> None:
        gate = (ROOT / "src/archive_v3_wal_idempotency.rs").read_text(encoding="utf-8")
        media = (ROOT / "src/cp/media.rs").read_text(encoding="utf-8")
        domain = (ROOT / "src/cp/media/wal.rs").read_text(encoding="utf-8")
        capture_event_domain = (
            ROOT / "src/cp/media/wal/capture_event.rs"
        ).read_text(encoding="utf-8")
        reference_event_domain = (
            ROOT / "src/cp/media/wal/reference_event.rs"
        ).read_text(encoding="utf-8")
        media_dek_domain = (
            ROOT / "src/cp/media/wal/media_dek.rs"
        ).read_text(encoding="utf-8")
        media_dek_production = without_cfg_test_items(media_dek_domain)
        model_usage = (ROOT / "src/cp/model_usage.rs").read_text(encoding="utf-8")
        vertex_domain = (ROOT / "src/cp/model_usage/wal.rs").read_text(
            encoding="utf-8"
        )
        query = (ROOT / "src/cp/query.rs").read_text(encoding="utf-8")
        query_production = without_cfg_test_items(query)
        selected_domain = (ROOT / "src/cp/query/wal.rs").read_text(
            encoding="utf-8"
        )
        selected_production = without_cfg_test_items(selected_domain)
        selected_attempt_domain = (
            ROOT / "src/cp/query/wal/selected_screenshot_attempt.rs"
        ).read_text(encoding="utf-8")
        selected_attempt_production = without_cfg_test_items(
            selected_attempt_domain
        )
        selected_upload_domain = (
            ROOT / "src/cp/query/wal/selected_screenshot_upload.rs"
        ).read_text(encoding="utf-8")
        selected_upload_production = without_cfg_test_items(selected_upload_domain)
        selected_send_domain = (
            ROOT / "src/cp/query/wal/selected_screenshot_send.rs"
        ).read_text(encoding="utf-8")
        selected_send_production = without_cfg_test_items(selected_send_domain)
        selected_provider_domain = (
            ROOT / "src/cp/query/wal/selected_screenshot_provider.rs"
        ).read_text(encoding="utf-8")
        selected_provider_production = without_cfg_test_items(
            selected_provider_domain
        )
        selected_termination_domain = (
            ROOT / "src/cp/query/wal/selected_screenshot_termination.rs"
        ).read_text(encoding="utf-8")
        selected_termination_production = without_cfg_test_items(
            selected_termination_domain
        )
        finalization_queue_domain = (
            ROOT / "src/cp/query/wal/finalization_queue.rs"
        ).read_text(encoding="utf-8")
        episode_delete_domain = (
            ROOT / "src/cp/query/wal/episode_delete.rs"
        ).read_text(encoding="utf-8")
        episode_delete_production = without_cfg_test_items(episode_delete_domain)
        finalizer = (ROOT / "src/cp/finalizer.rs").read_text(encoding="utf-8")
        finalization_commit_domain = (
            ROOT / "src/cp/finalizer/wal.rs"
        ).read_text(encoding="utf-8")
        media_worker = (ROOT / "src/cp/media_worker.rs").read_text(
            encoding="utf-8"
        )
        retention_domain = (ROOT / "src/cp/media_worker/wal.rs").read_text(
            encoding="utf-8"
        )
        attempt_domain = (
            ROOT / "src/cp/media_worker/wal/attempt.rs"
        ).read_text(encoding="utf-8")
        attempt_production = without_cfg_test_items(attempt_domain)
        result_domain = (ROOT / "src/cp/media_worker/wal/result.rs").read_text(
            encoding="utf-8"
        )
        result_production = without_cfg_test_items(result_domain)
        audio_attempt_domain = (
            ROOT / "src/cp/media_worker/wal/audio_attempt.rs"
        ).read_text(encoding="utf-8")
        audio_result_domain = (
            ROOT / "src/cp/media_worker/wal/audio_result.rs"
        ).read_text(encoding="utf-8")
        audio_result_production = without_cfg_test_items(audio_result_domain)
        voice_embedding_domain = (
            ROOT / "src/cp/media_worker/wal/voice_embedding.rs"
        ).read_text(encoding="utf-8")
        voice_embedding_production = without_cfg_test_items(voice_embedding_domain)
        voice_profile_domain = (
            ROOT / "src/cp/media_worker/wal/voice_profile.rs"
        ).read_text(encoding="utf-8")
        voice_profile_production = without_cfg_test_items(voice_profile_domain)
        email_worker = (ROOT / "src/cp/email_worker.rs").read_text(
            encoding="utf-8"
        )
        email_domain = (ROOT / "src/cp/email_worker/wal.rs").read_text(
            encoding="utf-8"
        )
        email_claim_domain = (
            ROOT / "src/cp/email_worker/wal/claim.rs"
        ).read_text(encoding="utf-8")
        email_claim_production = without_cfg_test_items(email_claim_domain)
        email_exact_domain = (
            ROOT / "src/cp/email_worker/wal/exact.rs"
        ).read_text(encoding="utf-8")
        email_exact_production = without_cfg_test_items(email_exact_domain)
        push = (ROOT / "src/cp/push.rs").read_text(encoding="utf-8")
        push_domain = (ROOT / "src/cp/push/wal.rs").read_text(encoding="utf-8")
        push_claim_domain = (ROOT / "src/cp/push/wal/claim.rs").read_text(
            encoding="utf-8"
        )
        push_claim_production = without_cfg_test_items(push_claim_domain)
        push_settlement_domain = (
            ROOT / "src/cp/push/wal/settlement.rs"
        ).read_text(encoding="utf-8")
        push_settlement_production = without_cfg_test_items(
            push_settlement_domain
        )
        webhook_worker = (ROOT / "src/cp/webhook_worker.rs").read_text(
            encoding="utf-8"
        )
        webhook_domain = (ROOT / "src/cp/webhook_worker/wal.rs").read_text(
            encoding="utf-8"
        )
        webhook_claim_domain = (
            ROOT / "src/cp/webhook_worker/wal/claim.rs"
        ).read_text(encoding="utf-8")
        webhook_claim_production = without_cfg_test_items(webhook_claim_domain)
        webhook_exact_domain = (
            ROOT / "src/cp/webhook_worker/wal/exact.rs"
        ).read_text(encoding="utf-8")
        webhook_exact_production = without_cfg_test_items(webhook_exact_domain)
        reviewer = (ROOT / "src/cp/reviewer.rs").read_text(encoding="utf-8")
        reviewer_domain = (ROOT / "src/cp/reviewer/wal.rs").read_text(
            encoding="utf-8"
        )
        summarizer = (ROOT / "src/cp/summarizer.rs").read_text(encoding="utf-8")
        substance_domain = (ROOT / "src/cp/summarizer/wal.rs").read_text(
            encoding="utf-8"
        )
        visual_domain = (
            ROOT / "src/cp/summarizer/wal/visual_evidence.rs"
        ).read_text(encoding="utf-8")
        main = (ROOT / "src/main.rs").read_text(encoding="utf-8")
        self.assertIn("pub(crate) mod wal;", media)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media::wal::CaptureSessionFinishPlan",
            gate,
        )
        self.assertIn("struct CaptureSessionFinishPlan", domain)
        self.assertIn("struct CaptureSessionFinishLedger", domain)
        self.assertIn("archive_v3_wal_capture_session_finish_operations", domain)
        self.assertIn("MAX_CAPTURE_SESSION_FINISH_ROWS", domain)
        self.assertIn("DomainLedgerBounds::new", domain)
        self.assertIn("WalIdempotencyError::Precondition", domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media::wal::CanonicalCaptureEventPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media::wal::CanonicalCaptureEventLedger",
            gate,
        )
        self.assertIn("struct CanonicalCaptureEventPlan", capture_event_domain)
        self.assertIn("struct CanonicalCaptureEventLedger", capture_event_domain)
        self.assertIn(
            "archive_v3_wal_canonical_capture_event_operations",
            capture_event_domain,
        )
        self.assertIn("canonical-capture-event-v1", capture_event_domain)
        self.assertIn("MAX_ROWS: u32 = 1_048_576", capture_event_domain)
        self.assertIn("DomainLedgerBounds::new", capture_event_domain)
        self.assertIn("WalIdempotencyError::Precondition", capture_event_domain)
        # Capture ingest MIGRATED. The former assertNotIn pinned the
        # deliberate pre-wiring state; this pins the wired one just as
        # exactly, the same way MediaDekInstallPlan's did in slice 1 (F1).
        # Canonical construction remains at exactly ONE shared site; the
        # `is_wal_authoritative` branch invokes that helper after routed
        # preflight, and the selected E2E fixture reuses it instead of minting
        # a second test-only constructor. Reference construction remains
        # directly in the route.
        self.assertEqual(media.count("CanonicalCaptureEventPlan::new("), 1)
        # The single-event reference family: the OTHER media disposition the
        # one ingest route serves. Both arms had to migrate together -- a
        # mac_screen stream interleaves canonical screenshots and reference
        # pointers by sequence and `advance_contiguous_ack` walks only while
        # the next sequence exists, so migrating one arm alone stalls the
        # stream permanently at the first refused event of the other.
        self.assertIn("mod reference_event;", domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media::wal::MediaReferenceEventPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media::wal::MediaReferenceEventLedger",
            gate,
        )
        self.assertIn("struct MediaReferenceEventPlan", reference_event_domain)
        self.assertIn("struct MediaReferenceEventLedger", reference_event_domain)
        self.assertIn(
            "archive_v3_wal_media_reference_event_operations",
            reference_event_domain,
        )
        # Its OWN operation-source subtype, distinct from the batch's
        # `reference-batch-v1` and the canonical family's
        # `canonical-capture-event-v1`. A bespoke plan reusing the batch id
        # derivation while committing its own Output would share one
        # `archive_v3_wal_publications` slot and one attempt ladder with a
        # fingerprint it could never match;
        # test_plan_family_subtypes_are_declared_and_pairwise_distinct is what
        # keeps the subtype unique in review.
        self.assertIn(
            "adr-0022-single-reference-capture-event-v1", reference_event_domain
        )
        self.assertIn("MAX_ROWS: u32 = 1_048_576", reference_event_domain)
        self.assertIn("DomainLedgerBounds::new", reference_event_domain)
        self.assertIn("WalIdempotencyError::Precondition", reference_event_domain)
        self.assertEqual(media.count("MediaReferenceEventPlan::new("), 1)
        self.assertIn("mod media_dek;", domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media::wal::MediaDekInstallPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media::wal::MediaDekInstallLedger",
            gate,
        )
        self.assertIn("struct MediaDekInstallPlan", media_dek_domain)
        self.assertIn("struct MediaDekInstallLedger", media_dek_domain)
        self.assertIn(
            "archive_v3_wal_media_dek_install_operations", media_dek_domain
        )
        self.assertIn("media-dek-install-v1", media_dek_domain)
        self.assertIn("MAX_ROWS: u32 = 1", media_dek_domain)
        self.assertIn("DomainLedgerBounds::new", media_dek_domain)
        self.assertIn("HmacSha256::new_from_slice", media_dek_domain)
        self.assertIn("wrapped_dek_commitment", media_dek_domain)
        self.assertIn("validate_installed_value", media_dek_domain)
        # Plan-family slice 1 (F1) WIRED the sealed install plan: the DEK
        # bootstrap constructs it at exactly one site, above the converge
        # path (R5). The former assertNotIn pinned the deliberate pre-wiring
        # state; this pins the wired one just as exactly.
        self.assertEqual(media.count("MediaDekInstallPlan::new("), 1)
        self.assertNotIn("cp::media::wal::", main)
        self.assertIn("pub(crate) mod wal;", model_usage)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::model_usage::wal::VertexUsageOutcomePlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::model_usage::wal::VertexUsageOutcomeLedger",
            gate,
        )
        self.assertIn("struct VertexUsageOutcomePlan", vertex_domain)
        self.assertIn("struct VertexUsageOutcomeLedger", vertex_domain)
        self.assertIn("archive_v3_wal_vertex_usage_operations", vertex_domain)
        self.assertIn("MAX_VERTEX_USAGE_ROWS", vertex_domain)
        self.assertIn("DomainLedgerBounds::new", vertex_domain)
        self.assertIn("WalIdempotencyError::Precondition", vertex_domain)
        self.assertNotIn("cp::model_usage::wal::", main)
        self.assertIn("pub(crate) mod wal;", query)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotLedger",
            gate,
        )
        self.assertIn("struct SelectedScreenshotPlan", selected_domain)
        self.assertIn("struct SelectedScreenshotLedger", selected_domain)
        self.assertIn("archive_v3_wal_selected_screenshot_operations", selected_domain)
        self.assertIn("DomainLedgerBounds::new", selected_domain)
        self.assertIn("WalIdempotencyError::Precondition", selected_domain)
        self.assertIn("selected-screenshot-result-bound-v2", selected_domain)
        self.assertIn("mod episode_delete;", selected_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::EpisodeDeletePreparePlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::EpisodeDeletePrepareLedger",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::EpisodeDeletePlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::EpisodeDeleteLedger",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::EpisodeDeleteCleanupPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::EpisodeDeleteCleanupLedger",
            gate,
        )
        self.assertIn("struct EpisodeDeletePreparePlan", episode_delete_domain)
        self.assertIn("struct EpisodeDeletePrepareLedger", episode_delete_domain)
        self.assertIn("struct EpisodeDeletePlan", episode_delete_domain)
        self.assertIn("struct EpisodeDeleteLedger", episode_delete_domain)
        self.assertIn(
            "archive_v3_wal_episode_delete_operations", episode_delete_domain
        )
        self.assertIn(
            "adr-0022-exact-episode-delete-prepare-v1", episode_delete_domain
        )
        self.assertIn(
            "adr-0022-exact-episode-delete-complete-v1", episode_delete_domain
        )
        self.assertIn("MAX_MEMBERS_PER_CLASS", episode_delete_domain)
        self.assertIn("MAX_SOURCE_ROWS", episode_delete_domain)
        self.assertIn("MAX_SOURCES_PER_EPISODE", episode_delete_domain)
        self.assertIn("DomainLedgerBounds::new", episode_delete_domain)
        self.assertIn("WalIdempotencyError::Precondition", episode_delete_domain)
        self.assertIn("purge_episode_transaction_at", episode_delete_domain)
        self.assertIn("predecessor_commitment", episode_delete_domain)
        self.assertIn("AND NOT EXISTS (", episode_delete_domain)
        self.assertEqual(query_production.count("EpisodeDeletePreparePlan::new("), 1)
        self.assertEqual(query_production.count("EpisodeDeletePlan::new("), 0)
        self.assertEqual(episode_delete_production.count("EpisodeDeletePlan::new("), 1)
        delete_owner = query_production[
            query_production.index("async fn rest_selected_episode_delete(") :
        ]
        prepare_index = delete_owner.index("EpisodeDeletePreparePlan::new(")
        work_index = delete_owner.index("wal::load_episode_delete_work(")
        provider_index = delete_owner.index(".delete_retained_media(")
        settle_index = delete_owner.index("EpisodeDeleteCleanupPlan::new(")
        self.assertLess(prepare_index, work_index)
        self.assertLess(work_index, provider_index)
        self.assertLess(provider_index, settle_index)
        lifecycle_index = delete_owner.index("s.store.lock_user_lifecycle(user_id).await")
        self.assertLess(lifecycle_index, prepare_index)
        self.assertIn(
            "selected-screenshot-provider-accepted-result-v3", selected_production
        )
        self.assertIn(
            "SelectedScreenshotRequestContract::ProviderAcceptedV3",
            selected_production,
        )
        self.assertIn("attempt_binding_commitment", selected_production)
        self.assertRegex(
            selected_production,
            r"(?m)^fn prepare_selected_screenshot_provider_accepted_result\(",
        )
        self.assertRegex(
            selected_production,
            r"(?m)^fn load_selected_screenshot_provider_accepted_result\(",
        )
        self.assertIn("authenticate_accepted_facts", selected_production)
        self.assertIn("authenticate_provider_execution_claim", selected_production)
        self.assertIn("request_version INTEGER NOT NULL", selected_production)
        self.assertIn("provider_generation BLOB", selected_production)
        self.assertIn("length(provider_generation)=8", selected_production)
        self.assertIn("readback_commitment BLOB", selected_production)
        self.assertIn("attempt_operation_id BLOB", selected_production)
        self.assertIn("LEDGER_SCHEMA_REVISION: i64 = 2", selected_production)
        self.assertIn("fn new_unbound_v1", selected_domain)
        self.assertNotIn("fn new_unbound_v1", selected_production)
        self.assertNotIn("\n    UnboundV1,\n", selected_production)
        self.assertNotIn("\n    BoundV2 {\n", selected_production)
        self.assertNotIn("pub(super) fn new(\n", selected_production)
        self.assertIn(
            "authenticate_selected_screenshot_attempt_binding",
            selected_attempt_domain,
        )
        self.assertIn(
            "selected_screenshot_attempt::authenticate_selected_screenshot_attempt_binding",
            selected_production,
        )
        self.assertIn("mod selected_screenshot_attempt;", selected_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotAttemptPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotAttemptLedger",
            gate,
        )
        self.assertIn("struct SelectedScreenshotAttemptPlan", selected_attempt_domain)
        self.assertIn("struct SelectedScreenshotAttemptLedger", selected_attempt_domain)
        self.assertIn(
            "archive_v3_wal_selected_screenshot_attempt_operations",
            selected_attempt_domain,
        )
        self.assertIn(
            "authenticate_selected_screenshot_upload_predecessor",
            selected_attempt_domain,
        )
        self.assertIn("source_key TEXT NOT NULL UNIQUE", selected_attempt_domain)
        self.assertIn(
            "screenshot_id INTEGER NOT NULL CHECK(screenshot_id>0)",
            selected_attempt_domain,
        )
        self.assertIn("MAX_EPISODE_IMAGES", selected_attempt_domain)
        self.assertIn("MAX_EPISODE_IMAGE_BYTES", selected_attempt_domain)
        self.assertIn("AND NOT EXISTS (", selected_attempt_domain)
        self.assertIn(
            "selected-screenshot-upload-attempt-v1", selected_attempt_domain
        )
        self.assertIn("MAX_ROWS: u32 = 1_048_576", selected_attempt_domain)
        self.assertIn("DomainLedgerBounds::new", selected_attempt_domain)
        self.assertIn(
            "WalIdempotencyError::Precondition", selected_attempt_domain
        )
        # Genesis retirement: the selected plan/multipart surfaces are stable
        # 410 tombstones before archive or provider work. The reviewed family
        # stays compiled and sealed, but has no production route owner.
        self.assertEqual(query.count("SelectedScreenshotAttemptPlan::new("), 0)
        self.assertNotIn(
            "authenticate_selected_screenshot_upload_predecessor(", query
        )
        self.assertIn("fn selected_screenshot_upload_retired()", query)
        self.assertIn('"screenshot_upload_retired"', query)
        self.assertIn("mod selected_screenshot_upload;", selected_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotUploadCandidatePlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotUploadCandidateLedger",
            gate,
        )
        self.assertIn("struct SelectedScreenshotUploadCandidatePlan", selected_upload_domain)
        self.assertIn("struct SelectedScreenshotUploadCandidateLedger", selected_upload_domain)
        self.assertIn(
            "archive_v3_wal_selected_screenshot_upload_candidates",
            selected_upload_domain,
        )
        self.assertIn(
            "selected-screenshot-upload-candidate-v1", selected_upload_domain
        )
        self.assertIn("CANDIDATE_BINDING_DOMAIN", selected_upload_domain)
        self.assertIn("HmacSha256::new_from_slice", selected_upload_domain)
        self.assertIn("decrypt_bound_blob", selected_upload_production)
        self.assertIn(
            "authenticate_unconsumed_selected_screenshot_attempt",
            selected_upload_domain,
        )
        self.assertIn(
            "authenticate_media_dek_install_receipt", selected_upload_domain
        )
        self.assertIn("MAX_RETAINED_CIPHERTEXT_BYTES", selected_upload_domain)
        self.assertIn("ciphertext BLOB NOT NULL", selected_upload_domain)
        self.assertIn(
            "load_authenticated_selected_screenshot_upload_candidate",
            selected_upload_domain,
        )
        self.assertIn(
            "pub(super) struct AuthenticatedSelectedScreenshotUploadCandidate",
            selected_upload_production,
        )
        self.assertIn(
            "pub(super) fn load_authenticated_selected_screenshot_upload_candidate",
            selected_upload_production,
        )
        self.assertIn("pub(super) fn ciphertext", selected_upload_production)
        self.assertNotIn(
            "pub(in crate::cp::query) struct AuthenticatedSelectedScreenshotUploadCandidate",
            selected_upload_production,
        )
        self.assertIn("SELECT length(ciphertext),length(result_bytes)", selected_upload_domain)
        # The ciphertext family stays private and inactive after retirement.
        self.assertEqual(
            query.count("prepare_selected_screenshot_upload_candidate("), 0
        )
        self.assertIn(
            "fn prepare_selected_screenshot_upload_candidate(",
            selected_production,
        )
        self.assertIn(
            "fn load_authenticated_media_dek_install_receipt(",
            selected_production,
        )
        self.assertNotIn("SelectedScreenshotUploadCandidatePlan::", query)
        self.assertNotIn(
            "load_authenticated_selected_screenshot_upload_candidate(", query
        )
        self.assertIn("mod selected_screenshot_send;", selected_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotSendStartedPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotSendStartedLedger",
            gate,
        )
        self.assertIn("struct SelectedScreenshotSendStartedPlan", selected_send_domain)
        self.assertIn("struct SelectedScreenshotSendStartedLedger", selected_send_domain)
        self.assertIn(
            "archive_v3_wal_selected_screenshot_send_started",
            selected_send_domain,
        )
        self.assertIn("selected-screenshot-send-started-v1", selected_send_domain)
        self.assertIn("SEND_REQUEST_ID_DOMAIN", selected_send_domain)
        self.assertIn("SEND_BINDING_DOMAIN", selected_send_domain)
        self.assertIn(
            "authenticate_selected_screenshot_upload_candidate",
            selected_send_domain,
        )
        self.assertIn(
            "load_authenticated_selected_screenshot_send_started",
            selected_send_domain,
        )
        self.assertIn(
            "prepare_selected_screenshot_send_started", selected_send_domain
        )
        self.assertIn(
            "pub(super) struct AuthenticatedSelectedScreenshotSendStarted",
            selected_send_production,
        )
        self.assertIn(
            "pub(super) fn load_authenticated_selected_screenshot_send_started(",
            selected_send_production,
        )
        self.assertIn(
            "fn prepare_selected_screenshot_send_started(",
            selected_production,
        )
        self.assertIn("MAX_ROWS: u32 = 1_048_576", selected_send_domain)
        self.assertIn("DomainLedgerBounds::new", selected_send_domain)
        # The send-start family likewise has no production route caller.
        self.assertEqual(
            query.count("prepare_selected_screenshot_send_started("), 0
        )
        self.assertNotIn("SelectedScreenshotSendStartedPlan::", query)
        self.assertNotIn(
            "load_authenticated_selected_screenshot_send_started(", query
        )
        self.assertNotIn(
            "fn load_authenticated_selected_screenshot_send_started(",
            selected_production,
        )
        self.assertIn("mod selected_screenshot_provider;", selected_domain)
        self.assertIn(
            "trait SelectedScreenshotExactCreateProvider",
            selected_provider_domain,
        )
        self.assertIn(
            "enum SelectedScreenshotProviderCreateResult",
            selected_provider_domain,
        )
        self.assertIn(
            "enum SelectedScreenshotProviderOutcome", selected_provider_domain
        )
        self.assertIn(
            "struct SelectedScreenshotProviderAccepted", selected_provider_domain
        )
        self.assertIn(
            "struct SelectedScreenshotProviderRejectedNoObject",
            selected_provider_domain,
        )
        self.assertIn(
            "prepare_selected_screenshot_provider_request",
            selected_provider_domain,
        )
        self.assertIn(
            "execute_selected_screenshot_provider_request",
            selected_provider_domain,
        )
        self.assertIn("create_if_absent(", selected_provider_domain)
        self.assertIn("get_exact(", selected_provider_domain)
        self.assertIn("max_ciphertext_bytes", selected_provider_domain)
        self.assertIn("ACCEPTED_BINDING_DOMAIN", selected_provider_domain)
        self.assertIn("REJECTED_BINDING_DOMAIN", selected_provider_domain)
        self.assertIn("EXECUTION_CLAIM_DOMAIN", selected_provider_domain)
        self.assertIn(
            "archive_v3_wal_selected_screenshot_provider_executions",
            selected_provider_domain,
        )
        self.assertIn("TransactionBehavior::Immediate", selected_provider_domain)
        self.assertIn("claim_provider_execution", selected_provider_domain)
        self.assertIn(
            "authenticate_provider_execution_claim", selected_provider_domain
        )
        self.assertIn("pub(super) fn into_parts", selected_provider_domain)
        self.assertIn("authenticate_accepted_facts", selected_provider_production)
        self.assertIn("MAX_EXECUTION_CLAIMS", selected_provider_domain)
        self.assertIn(
            "load_authenticated_selected_screenshot_send_started",
            selected_provider_domain,
        )
        # The provider link, provider-accepted A settlement, and C termination
        # remain deliberately unwired; the route now stops even earlier at
        # its explicit retirement response.
        self.assertNotIn(
            "impl SelectedScreenshotExactCreateProvider for",
            selected_provider_production,
        )
        self.assertNotIn(
            "prepare_selected_screenshot_provider_request(", query
        )
        self.assertNotIn(
            "prepare_selected_screenshot_provider_accepted_result(", query
        )
        self.assertNotIn(
            "load_selected_screenshot_provider_accepted_result(", query
        )
        self.assertIn("mod selected_screenshot_termination;", selected_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::SelectedScreenshotTerminationPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::SelectedScreenshotTerminationLedger",
            gate,
        )
        self.assertIn(
            "struct SelectedScreenshotTerminationPlan", selected_termination_domain
        )
        self.assertIn(
            "struct SelectedScreenshotTerminationLedger", selected_termination_domain
        )
        self.assertIn(
            "archive_v3_wal_selected_screenshot_terminations",
            selected_termination_domain,
        )
        self.assertIn(
            "selected-screenshot-upload-termination-v1",
            selected_termination_domain,
        )
        self.assertIn(
            "SelectedScreenshotProviderRejectedNoObject",
            selected_termination_domain,
        )
        self.assertIn(
            "authenticate_selected_screenshot_attempt_for_terminal",
            selected_termination_domain,
        )
        self.assertIn(
            "authenticate_selected_screenshot_send_provider_facts",
            selected_termination_domain,
        )
        self.assertIn(
            "authenticate_rejected_no_object_facts",
            selected_termination_domain,
        )
        self.assertIn(
            "authenticate_provider_execution_claim",
            selected_termination_domain,
        )
        self.assertIn(
            "load_selected_screenshot_termination_plan",
            selected_termination_domain,
        )
        self.assertIn(
            "authenticated_episode_release_totals",
            selected_termination_domain,
        )
        self.assertIn(
            "selected_screenshot_termination::ensure_attempt_not_terminated",
            selected_production,
        )
        self.assertIn(
            "selected_screenshot_termination::authenticated_episode_release_totals",
            selected_attempt_production,
        )
        self.assertNotIn("SelectedScreenshotTerminationPlan::", query)
        self.assertNotIn("prepare_selected_screenshot_termination(", query)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::query::wal::FinalizationQueuePlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::query::wal::FinalizationQueueLedger",
            gate,
        )
        self.assertIn("struct FinalizationQueuePlan", finalization_queue_domain)
        self.assertIn("struct FinalizationQueueLedger", finalization_queue_domain)
        self.assertIn(
            "archive_v3_wal_finalization_queue_operations",
            finalization_queue_domain,
        )
        self.assertIn("DomainLedgerBounds::new", finalization_queue_domain)
        self.assertIn("WalIdempotencyError::Precondition", finalization_queue_domain)
        # ADR-0022 slice 10: the queue transition is WIRED - the route
        # constructs the sealed plan and keeps the legacy UPDATE branch.
        self.assertIn("FinalizationQueuePlan::new(", query)
        self.assertIn("FinalizationQueuePredecessor::new(", query)
        self.assertIn("finalization-queue-request-v1", query)
        self.assertIn("finalization_status = 'queued'", query)
        self.assertNotIn("cp::query::wal::", main)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::finalizer::FinalizationCommitPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::finalizer::FinalizationCommitLedger",
            gate,
        )
        self.assertIn("struct FinalizationCommitPlan", finalization_commit_domain)
        self.assertIn("struct FinalizationCommitLedger", finalization_commit_domain)
        self.assertIn(
            "archive_v3_wal_finalization_commit_operations",
            finalization_commit_domain,
        )
        self.assertIn("DomainLedgerBounds::new", finalization_commit_domain)
        self.assertIn("WalIdempotencyError::Precondition", finalization_commit_domain)
        # ADR-0022 slice 10: the finalization commit is WIRED - the owner
        # settles the sealed plan (finalize_commit_settled) and keeps the
        # legacy optimistic transaction for unselected users.
        self.assertIn("FinalizationCommitPlan::new(", finalizer)
        self.assertIn("observed_commit_predecessor", finalizer)
        self.assertIn("read_finalization_evidence(conn, ep_id, true)", finalizer)
        self.assertNotIn("cp::finalizer::wal::", main)
        self.assertIn("pub(crate) mod wal;", media_worker)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media_worker::wal::ScreenStoryboardResultPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media_worker::wal::ScreenStoryboardResultLedger",
            gate,
        )
        self.assertIn("pub(super) mod result;", retention_domain)
        self.assertIn("pub(super) mod attempt;", retention_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media_worker::wal::ScreenStoryboardAttemptPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media_worker::wal::ScreenStoryboardAttemptLedger",
            gate,
        )
        self.assertIn("struct ScreenStoryboardAttemptPlan", attempt_domain)
        self.assertIn("struct ScreenStoryboardAttemptLedger", attempt_domain)
        self.assertIn(
            "archive_v3_wal_screen_vertex_attempt_operations", attempt_domain
        )
        self.assertIn("predecessor_commitment BLOB NOT NULL", attempt_domain)
        self.assertIn("current_screen_work_attempt_commitments", attempt_domain)
        self.assertIn(
            "authenticate_screen_storyboard_attempt_binding", attempt_domain
        )
        self.assertIn("MIN_PROVIDER_ATTEMPT_WINDOW_MILLIS", result_domain)
        self.assertIn("screen-storyboard-vertex-attempt-v1", attempt_domain)
        self.assertIn("MAX_ROWS: u32 = 1_048_576", attempt_domain)
        self.assertIn("DomainLedgerBounds::new", attempt_domain)
        self.assertIn("WalIdempotencyError::Precondition", attempt_domain)
        # ADR-0022 slice 10e: the attempt boundary is WIRED - the screen arm
        # settles the sealed plan after the settled reservation and BEFORE
        # the Vertex storyboard egress, anchored on the routed commitments
        # read; the receipt's derived event id pins the invocation identity
        # the media egress carries instead of a second freshly minted intent.
        self.assertIn("ScreenStoryboardAttemptPlan::new(", media_worker)
        self.assertIn("settle_screen_storyboard_attempt", media_worker)
        self.assertIn(
            "current_screen_work_attempt_commitments", media_worker
        )
        self.assertIn("struct ScreenStoryboardResultPlan", result_domain)
        self.assertIn("struct ScreenStoryboardResultLedger", result_domain)
        self.assertIn(
            "archive_v3_wal_screen_storyboard_result_operations", result_domain
        )
        self.assertIn("screen-storyboard-no-people-v1", result_domain)
        self.assertIn(
            "screen-storyboard-no-people-v2-bound-attempt", result_domain
        )
        self.assertIn(
            "ScreenStoryboardResultRequestContract::BoundV2", result_domain
        )
        self.assertIn("authenticate_attempt_binding", result_domain)
        self.assertIn(
            "#[cfg(test)]\n    #[allow(clippy::too_many_arguments)]\n    fn new_unbound_v1",
            result_domain,
        )
        self.assertIn("MAX_ROWS: u32 = 1_048_576", result_domain)
        self.assertIn("DomainLedgerBounds::new", result_domain)
        self.assertIn("WalIdempotencyError::Precondition", result_domain)
        # ADR-0022 slice 10e: the bound result is WIRED - it consumes the
        # attempt receipt's binding commitment against the routed terminal
        # Vertex attempt and exact work predecessor, replacing the legacy
        # storyboard persistence for WAL users; the legacy with_user branch
        # keeps its exact write for unselected users.
        self.assertIn("ScreenStoryboardResultPlan::new(", media_worker)
        self.assertIn("settle_screen_storyboard_result", media_worker)
        self.assertIn(
            "current_screen_vertex_attempt_commitment", media_worker
        )
        self.assertIn(
            "persist_storyboard_results(conn, &work.id, &work.jobs, results)",
            media_worker,
        )
        # ADR-0022 slice 11: the audio-window transcript family is WIRED --
        # a kind-7 attempt boundary and a kind-6 bound transcript, mirroring
        # the sealed screen chain, with the audio-specific facts the design
        # requires: the member bound is the lease LIMIT (128, never the
        # screen family's 12-frame cap) and the six AUTOINCREMENT ids come
        # from fingerprinted sqlite_sequence pins, never MAX(id)+1.
        self.assertIn("pub(super) mod audio_attempt;", retention_domain)
        self.assertIn("pub(super) mod audio_result;", retention_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media_worker::wal::AudioWindowAttemptPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media_worker::wal::AudioWindowAttemptLedger",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media_worker::wal::AudioWindowTranscriptPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media_worker::wal::AudioWindowTranscriptLedger",
            gate,
        )
        self.assertIn("struct AudioWindowAttemptPlan", audio_attempt_domain)
        self.assertIn("struct AudioWindowAttemptLedger", audio_attempt_domain)
        self.assertIn(
            "archive_v3_wal_audio_vertex_attempt_operations", audio_attempt_domain
        )
        self.assertIn("audio-window-vertex-attempt-v1", audio_attempt_domain)
        self.assertIn(
            "current_audio_work_attempt_commitments", audio_attempt_domain
        )
        self.assertIn(
            "authenticate_audio_window_attempt_binding", audio_attempt_domain
        )
        self.assertIn("MAX_ROWS: u32 = 1_048_576", audio_attempt_domain)
        self.assertIn("DomainLedgerBounds::new", audio_attempt_domain)
        self.assertIn("WalIdempotencyError::Precondition", audio_attempt_domain)
        self.assertIn("struct AudioWindowTranscriptPlan", audio_result_domain)
        self.assertIn("struct AudioWindowTranscriptLedger", audio_result_domain)
        self.assertIn(
            "archive_v3_wal_audio_transcript_result_operations", audio_result_domain
        )
        self.assertIn(
            "audio-window-transcript-v3-literal-identity-evidence",
            audio_result_domain,
        )
        # The member bound is the audio lease LIMIT. MAX_SCREEN_FRAMES (12)
        # is not an audio cap; pinning 128 keeps a future edit from importing
        # the screen number and terminal-failing every wider window.
        self.assertIn("const MAX_AUDIO_MEMBERS: usize = 128;", audio_result_domain)
        self.assertIn("MIN_PROVIDER_ATTEMPT_WINDOW_MILLIS", audio_result_domain)
        self.assertIn("MAX_ROWS: u32 = 1_048_576", audio_result_domain)
        self.assertIn("DomainLedgerBounds::new", audio_result_domain)
        self.assertIn("WalIdempotencyError::Precondition", audio_result_domain)
        self.assertIn("read_audio_sequence_pins", audio_result_domain)
        # The selected transcript settlement is the only sanctioned F8
        # coupling: one fixed-id pending embedding job per observation in the
        # same transaction. Literal high-confidence self-identification may
        # create only an unbound proposed identity-evidence row; profile,
        # sample and person mutation plus MAX(id) allocation remain absent.
        audio_result_code = sanitize_rust(audio_result_production)
        for forbidden in (
            "voice_samples",
            "voice_profiles",
            "enqueue_embedding_job",
            "person_name_claims",
            "resolve_speaker_attribution",
            "MAX(id)",
        ):
            self.assertNotIn(forbidden, audio_result_code)
        self.assertIn("voice_embedding_jobs: i64", audio_result_code)
        self.assertIn("identity_evidence: i64", audio_result_code)
        self.assertIn(
            "INSERT INTO voice_embedding_jobs", audio_result_production
        )
        self.assertIn("'pending'", audio_result_production)
        self.assertIn("INSERT INTO identity_evidence", audio_result_production)
        self.assertIn("'proposed'", audio_result_production)
        self.assertIn(
            "value.text.contains(identity.literal_evidence.as_str())",
            audio_result_production,
        )
        self.assertNotIn("enqueue_embedding_job", audio_result_code)
        # The audio arm is wired end to end and the legacy tail survives for
        # unselected users.
        self.assertIn("AudioWindowAttemptPlan::new(", media_worker)
        self.assertIn("settle_audio_window_attempt", media_worker)
        self.assertIn("AudioWindowTranscriptPlan::new(", media_worker)
        self.assertIn("settle_audio_window_transcript", media_worker)
        self.assertIn("current_audio_vertex_attempt_commitment", media_worker)
        self.assertIn("read_audio_sequence_pins", media_worker)
        self.assertIn("persist_audio_window_result(", media_worker)
        # ADR-0022 selected voice-embedding boundary: the archive claim is
        # durable before GCS/KMS/model work and the carried current-generation
        # topology is reauthenticated by the result plan before an explicit-id
        # pending sample or a bounded terminal/retry disposition is written.
        self.assertIn("pub(super) mod voice_embedding;", retention_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media_worker::wal::VoiceEmbeddingPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media_worker::wal::VoiceEmbeddingLedger",
            gate,
        )
        self.assertIn("struct VoiceEmbeddingPlan", voice_embedding_domain)
        self.assertIn("struct VoiceEmbeddingLedger", voice_embedding_domain)
        self.assertIn(
            "archive_v3_wal_voice_embedding_operations", voice_embedding_domain
        )
        self.assertIn("adr-0022-voice-embedding-claim-v1", voice_embedding_domain)
        self.assertIn("adr-0022-voice-embedding-result-v1", voice_embedding_domain)
        self.assertIn(
            "adr-0022-voice-embedding-job-backfill-v1", voice_embedding_domain
        )
        self.assertIn("const MAX_SOURCES: usize = 128;", voice_embedding_domain)
        self.assertIn("const MAX_ATTEMPTS: i64 = 3;", voice_embedding_domain)
        self.assertIn("MAX_ROWS: u32 = 1_048_576", voice_embedding_domain)
        self.assertIn("DomainLedgerBounds::new", voice_embedding_domain)
        self.assertIn("WalIdempotencyError::Precondition", voice_embedding_domain)
        self.assertIn("VoiceEmbeddingPlan::claim(", media_worker)
        self.assertIn("VoiceEmbeddingPlan::settle(", media_worker)
        self.assertIn("VoiceEmbeddingPlan::backfill_job(", media_worker)
        self.assertIn("observe_next_job_backfill", media_worker)
        self.assertIn("get_current_media_generation", media_worker)
        self.assertIn("decrypt_bound_blob_v2", media_worker)
        self.assertIn("decode_mono_16khz_prefix", media_worker)
        self.assertIn("MAX_TURN_SAMPLES", media_worker)
        self.assertIn("VoiceClaimDisposition::ClockDeferred", media_worker)
        self.assertIn("raw_source_count", voice_embedding_domain)
        self.assertIn("self.existing_samples.len() > 1", voice_embedding_domain)
        # ADR-0022 selected voice-profile boundary: this provider-free child
        # owns deterministic historical backfill, bounded sample assignment,
        # representative repair/quarantine, imported-action refusal, episode
        # speaker-status settlement, and provider-free literal identity
        # binding. It commits every decision row and allocator pin but has no
        # provider authority.
        self.assertIn("pub(super) mod voice_profile;", retention_domain)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media_worker::wal::VoiceProfilePlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media_worker::wal::VoiceProfileLedger",
            gate,
        )
        self.assertIn("struct VoiceProfilePlan", voice_profile_domain)
        self.assertIn("struct VoiceProfileLedger", voice_profile_domain)
        self.assertIn(
            "archive_v3_wal_voice_profile_operations", voice_profile_domain
        )
        self.assertIn("adr-0022-voice-profile-backfill-v1", voice_profile_domain)
        self.assertIn(
            "adr-0022-voice-assignment-backfill-v1", voice_profile_domain
        )
        self.assertIn(
            "adr-0022-voice-sample-assignment-v1", voice_profile_domain
        )
        self.assertIn(
            "adr-0022-voice-profile-reconcile-v1", voice_profile_domain
        )
        self.assertIn(
            "adr-0022-voice-lineage-action-refusal-v1", voice_profile_domain
        )
        self.assertIn("adr-0022-voice-episode-status-v1", voice_profile_domain)
        self.assertIn("adr-0022-person-self-identification-v1", voice_profile_domain)
        self.assertIn("const MAX_PROFILES: usize = 32;", voice_profile_domain)
        self.assertIn(
            "const MAX_PROFILE_SAMPLES: usize = 100;", voice_profile_domain
        )
        self.assertIn("MAX_ROWS: u32 = 1_048_576", voice_profile_domain)
        self.assertIn("DomainLedgerBounds::new", voice_profile_domain)
        self.assertIn("WalIdempotencyError::Precondition", voice_profile_domain)
        self.assertIn("process_user_voice_profiles", media_worker)
        self.assertIn("wal::voice_profile::observe_next", media_worker)
        self.assertIn("wal::VoiceProfilePlan::new", media_worker)
        for required in (
            "INSERT INTO people",
            "INSERT INTO person_name_claims",
            "INSERT INTO person_facts",
            "UPDATE identity_evidence",
            "profile_identity_bindings",
            "transcript_text.contains(envelope.literal_evidence.as_str())",
            "active,operation_id,conflicts_with_id",
            "assert_person_identity_poststate",
        ):
            self.assertIn(required, voice_profile_production)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::media_worker::wal::RetentionSettlementPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::media_worker::wal::RetentionSettlementLedger",
            gate,
        )
        self.assertIn("struct RetentionSettlementPlan", retention_domain)
        self.assertIn("struct RetentionSettlementLedger", retention_domain)
        self.assertIn("archive_v3_wal_retention_operations", retention_domain)
        self.assertIn("DomainLedgerBounds::new", retention_domain)
        self.assertIn("WalIdempotencyError::Precondition", retention_domain)
        # ADR-0022 slice 10: the retention receipt is WIRED - the prune
        # sweep settles the sealed plan after the provider delete and
        # keeps the legacy branch.
        self.assertIn("RetentionSettlementPlan::new(", media_worker)
        self.assertIn("delete_retained_media", media_worker)
        self.assertNotIn("cp::media_worker::wal::", main)
        self.assertIn("pub(crate) mod wal;", email_worker)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::email_worker::wal::EmailSendClaimPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::email_worker::wal::EmailSendClaimLedger",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::email_worker::wal::ExactEmailDeliverySettlementPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::email_worker::wal::ExactEmailDeliverySettlementLedger",
            gate,
        )
        self.assertIn("mod claim;", email_domain)
        self.assertIn("mod exact;", email_domain)
        self.assertNotIn("mod cancellation;", email_domain)
        self.assertNotIn("mod settlement;", email_domain)
        self.assertIn("struct EmailSendClaimPlan", email_claim_domain)
        self.assertIn("struct EmailSendClaimLedger", email_claim_domain)
        self.assertIn("archive_v3_wal_email_claim_operations", email_claim_domain)
        self.assertIn("archive_v3_wal_email_send_claims", email_claim_domain)
        self.assertIn("archive_v3_wal_email_frozen_requests", email_claim_domain)
        self.assertIn("MAX_DEFERRED_CLAIMS_PER_ATTEMPT", email_claim_domain)
        self.assertIn("MAX_FROZEN_REQUESTS: u32 = 65_536", email_claim_domain)
        self.assertIn(
            "MAX_FROZEN_REQUEST_BYTES: u64 = 1024 * 1024 * 1024",
            email_claim_domain,
        )
        self.assertIn(
            "archive_v3_wal_email_frozen_request_delete_accounting",
            email_claim_domain,
        )
        claim_table_ddl = email_claim_domain.split(
            "CREATE TABLE archive_v3_wal_email_send_claims", 1
        )[1].split(") STRICT;", 1)[0]
        self.assertIn("request_commitment BLOB NOT NULL", claim_table_ddl)
        self.assertNotIn("request_text_body TEXT", claim_table_ddl)
        self.assertNotIn("request_html_body TEXT", claim_table_ddl)
        self.assertIn("load_frozen_request", email_claim_domain)
        self.assertIn("DomainLedgerBounds::new", email_claim_domain)
        self.assertIn("WalIdempotencyError::Precondition", email_claim_domain)
        self.assertIn("struct ExactEmailDeliverySettlementPlan", email_exact_domain)
        self.assertIn("struct ExactEmailDeliverySettlementLedger", email_exact_domain)
        self.assertIn(
            "archive_v3_wal_email_exact_settlement_operations",
            email_exact_domain,
        )
        self.assertIn("DomainLedgerBounds::new", email_exact_domain)
        self.assertIn("WalIdempotencyError::Precondition", email_exact_domain)
        for forbidden in (
            "crate::store::Store",
            "ControlStore",
            "reqwest",
            "SystemTime",
            "tokio::spawn",
            ".send(",
        ):
            self.assertNotIn(forbidden, email_claim_production)
            self.assertNotIn(forbidden, email_exact_production)
        self.assertIn("EmailSendClaimPlan::new(", email_worker)
        self.assertIn("ExactEmailDeliverySettlementPlan::new(", email_worker)
        self.assertIn("begin_email_send_fence(", email_worker)
        self.assertIn("transport.send(request).await", email_worker)
        self.assertNotIn("EmailAcceptedPlan::", email_worker)
        self.assertNotIn("cp::email_worker::wal::", main)
        self.assertIn("pub(crate) mod wal;", push)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::push::wal::PushAcceptedPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::push::wal::PushAcceptedLedger",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::push::wal::PushSendClaimPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::push::wal::PushSendClaimLedger",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::push::wal::PushDeliverySettlementPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::push::wal::PushDeliverySettlementLedger",
            gate,
        )
        self.assertIn("struct PushAcceptedPlan", push_domain)
        self.assertIn("struct PushAcceptedLedger", push_domain)
        self.assertIn("archive_v3_wal_push_accepted_operations", push_domain)
        self.assertIn("DomainLedgerBounds::new", push_domain)
        self.assertIn("WalIdempotencyError::Precondition", push_domain)
        self.assertIn("struct PushSendClaimPlan", push_claim_domain)
        self.assertIn("struct PushSendClaimLedger", push_claim_domain)
        self.assertIn("archive_v3_wal_push_claim_operations", push_claim_domain)
        self.assertIn("archive_v3_wal_push_send_claims", push_claim_domain)
        self.assertIn("DomainLedgerBounds::new", push_claim_domain)
        self.assertIn("WalIdempotencyError::Precondition", push_claim_domain)
        self.assertIn("struct PushDeliverySettlementPlan", push_settlement_domain)
        self.assertIn("struct PushDeliverySettlementLedger", push_settlement_domain)
        self.assertIn(
            "archive_v3_wal_push_settlement_operations", push_settlement_domain
        )
        self.assertIn("DomainLedgerBounds::new", push_settlement_domain)
        self.assertIn("WalIdempotencyError::Precondition", push_settlement_domain)
        self.assertIn("PushSendClaimPlan::new(", push)
        self.assertIn("PushDeliverySettlementPlan::new(", push)
        self.assertIn("begin_push_send_fence(", push)
        self.assertIn(".send(PushRequest {", push)
        self.assertNotIn("PushAcceptedPlan::", push)
        self.assertNotIn("cp::push::wal::", main)
        self.assertIn("pub(crate) mod wal;", webhook_worker)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::webhook_worker::wal::WebhookSendClaimPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::webhook_worker::wal::WebhookSendClaimLedger",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::webhook_worker::wal::ExactWebhookDeliverySettlementPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::webhook_worker::wal::ExactWebhookDeliverySettlementLedger",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::webhook_worker::wal::ExactWebhookDeliveryPurgePlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::webhook_worker::wal::ExactWebhookDeliveryPurgeLedger",
            gate,
        )
        self.assertIn("mod claim;", webhook_domain)
        self.assertIn("mod exact;", webhook_domain)
        self.assertNotIn("mod cascade;", webhook_domain)
        self.assertNotIn("mod settlement;", webhook_domain)
        self.assertIn("struct WebhookSendClaimPlan", webhook_claim_domain)
        self.assertIn("struct WebhookSendClaimLedger", webhook_claim_domain)
        self.assertIn(
            "archive_v3_wal_webhook_claim_operations", webhook_claim_domain
        )
        self.assertIn("archive_v3_wal_webhook_send_claims", webhook_claim_domain)
        self.assertIn("archive_v3_wal_webhook_frozen_requests", webhook_claim_domain)
        self.assertIn("MAX_DEFERRED_CLAIMS_PER_ATTEMPT", webhook_claim_domain)
        self.assertIn("DomainLedgerBounds::new", webhook_claim_domain)
        self.assertIn("WalIdempotencyError::Precondition", webhook_claim_domain)
        self.assertIn(
            "struct ExactWebhookDeliverySettlementPlan", webhook_exact_domain
        )
        self.assertIn(
            "struct ExactWebhookDeliverySettlementLedger", webhook_exact_domain
        )
        self.assertIn("struct ExactWebhookDeliveryPurgePlan", webhook_exact_domain)
        self.assertIn("struct ExactWebhookDeliveryPurgeLedger", webhook_exact_domain)
        self.assertIn(
            "archive_v3_wal_webhook_exact_settlement_operations",
            webhook_exact_domain,
        )
        self.assertIn("DomainLedgerBounds::new", webhook_exact_domain)
        self.assertIn("WalIdempotencyError::Precondition", webhook_exact_domain)
        self.assertIn("WebhookSendClaimPlan::new(", webhook_worker)
        self.assertIn("ExactWebhookDeliverySettlementPlan::new(", webhook_worker)
        self.assertIn("ExactWebhookDeliveryPurgePlan::new(", webhook_worker)
        self.assertIn("begin_webhook_send_fence(", webhook_worker)
        self.assertIn("transport.send(request).await", webhook_worker)
        self.assertIn(".no_proxy()", webhook_worker)
        self.assertNotIn("WebhookSentPlan::", webhook_worker)
        self.assertNotIn("cp::webhook_worker::wal::", main)
        self.assertIn("pub(crate) mod wal;", reviewer)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::reviewer::wal::ReviewerFixturePlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::reviewer::wal::ReviewerFixtureLedger",
            gate,
        )
        self.assertIn("struct ReviewerFixturePlan", reviewer_domain)
        self.assertIn("struct ReviewerFixtureLedger", reviewer_domain)
        self.assertIn("archive_v3_wal_reviewer_fixture_operations", reviewer_domain)
        self.assertIn("DomainLedgerBounds::new", reviewer_domain)
        self.assertIn("WalIdempotencyError::Precondition", reviewer_domain)
        # ADR-0022 slice 10: the reviewer fixture is WIRED - the owner
        # settles the sealed plan for WAL users and keeps the legacy seed.
        self.assertIn("ReviewerFixturePlan::new(", reviewer)
        self.assertIn("is_wal_authoritative", reviewer)
        self.assertNotIn("cp::reviewer::wal::", main)
        self.assertIn("pub(crate) mod wal;", summarizer)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::summarizer::wal::SubstanceBackfillBatchPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::summarizer::wal::SubstanceBackfillBatchLedger",
            gate,
        )
        self.assertIn("struct SubstanceBackfillBatchPlan", substance_domain)
        self.assertIn("struct SubstanceBackfillBatchLedger", substance_domain)
        self.assertIn(
            "archive_v3_wal_substance_backfill_operations", substance_domain
        )
        self.assertIn("DomainLedgerBounds::new", substance_domain)
        self.assertIn("WalIdempotencyError::Precondition", substance_domain)
        self.assertNotIn("SubstanceBackfillBatchPlan::", summarizer)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::summarizer::wal::VisualEvidenceBackfillBatchPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::summarizer::wal::VisualEvidenceBackfillBatchLedger",
            gate,
        )
        self.assertIn("struct VisualEvidenceBackfillBatchPlan", visual_domain)
        self.assertIn("struct VisualEvidenceBackfillBatchLedger", visual_domain)
        self.assertIn(
            "archive_v3_wal_visual_evidence_backfill_operations", visual_domain
        )
        self.assertIn("DomainLedgerBounds::new", visual_domain)
        self.assertIn("WalIdempotencyError::Precondition", visual_domain)
        self.assertNotIn("VisualEvidenceBackfillBatchPlan::", summarizer)
        self.assertNotIn("cp::summarizer::wal::", main)
        for forbidden in (
            "crate::store::Store",
            "Store::new",
            "tokio::spawn",
            "std::env::",
            "GcsClient",
            "FirestoreWitness",
            "list_objects",
            "delete_exact",
        ):
            self.assertNotIn(forbidden, domain)
            self.assertNotIn(forbidden, capture_event_domain)
            self.assertNotIn(forbidden, media_dek_production)
            self.assertNotIn(forbidden, vertex_domain)
            self.assertNotIn(forbidden, selected_domain)
            self.assertNotIn(forbidden, selected_attempt_domain)
            self.assertNotIn(forbidden, selected_upload_production)
            self.assertNotIn(forbidden, selected_send_production)
            self.assertNotIn(forbidden, selected_provider_production)
            self.assertNotIn(forbidden, selected_termination_production)
            self.assertNotIn(forbidden, finalization_queue_domain)
            self.assertNotIn(forbidden, episode_delete_production)
            self.assertNotIn(forbidden, finalization_commit_domain)
            self.assertNotIn(forbidden, attempt_domain)
            self.assertNotIn(forbidden, result_domain)
            self.assertNotIn(forbidden, retention_domain)
            self.assertNotIn(forbidden, voice_embedding_production)
            self.assertNotIn(forbidden, voice_profile_production)
            self.assertNotIn(forbidden, email_domain)
            self.assertNotIn(forbidden, push_domain)
            self.assertNotIn(forbidden, push_claim_production)
            self.assertNotIn(forbidden, push_settlement_production)
            self.assertNotIn(forbidden, webhook_domain)
            self.assertNotIn(forbidden, webhook_claim_production)
            self.assertNotIn(forbidden, webhook_exact_production)
            self.assertNotIn(forbidden, reviewer_domain)
            self.assertNotIn(forbidden, substance_domain)
            self.assertNotIn(forbidden, visual_domain)
        for forbidden in (
            "begin_invocation(",
            "random_token_hex",
            "with_user(",
            "save_user(",
        ):
            self.assertNotIn(forbidden, vertex_domain)
        for forbidden in (
            "generate_and_wrap_dek",
            "load_or_create_media_dek",
            "encrypt_bound_blob",
            "put_user_media",
            "get_media",
            "delete_object",
            "list_objects",
            "reserve_recording_delivery",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, capture_event_domain)
        for forbidden in (
            "KmsClient",
            "generate_and_wrap_dek",
            "load_dek(",
            "encrypt_bound_blob",
            "put_user_media",
            "get_media(",
            "delete_media(",
            "list_objects",
            "thread_rng",
            "SystemTime",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, media_dek_production)
        for forbidden in (
            "generate_and_wrap_dek",
            "encrypt_bound_blob",
            "put_user_media",
            "random_token_hex",
            "thread_rng",
            "with_user(",
            "save_user(",
            "tokio::spawn",
        ):
            self.assertNotIn(forbidden, selected_domain)
        for forbidden in (
            "generate_and_wrap_dek",
            "load_dek(",
            "install_media_dek_candidate(",
            "encrypt_bound_blob",
            "put_user_media",
            "get_media(",
            "delete_media(",
            "random_token_hex",
            "thread_rng",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
            "record_screenshot_image_in_transaction(",
        ):
            self.assertNotIn(forbidden, selected_attempt_production)
        for forbidden in (
            "KmsClient",
            "generate_and_wrap_dek",
            "load_dek(",
            "encrypt_bound_blob",
            "put_user_media",
            "get_media(",
            "delete_media(",
            "list_objects",
            "random_token_hex",
            "thread_rng",
            "SystemTime",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
            "record_screenshot_image_in_transaction(",
        ):
            self.assertNotIn(forbidden, selected_upload_production)
        for forbidden in (
            "KmsClient",
            "generate_and_wrap_dek",
            "load_dek(",
            "encrypt_bound_blob",
            "create_if_absent(",
            "put_user_media",
            "get_media(",
            "delete_media(",
            "list_objects",
            "GcsClient",
            "ExactImmutableObjectBackend",
            "random_token_hex",
            "thread_rng",
            "SystemTime",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
            "record_screenshot_image_in_transaction(",
            "DefinitivelyRejected",
            "OutcomeUnknown",
        ):
            self.assertNotIn(forbidden, selected_send_production)
        for forbidden in (
            "crate::store::Store",
            "GcsClient",
            "ExactImmutableObjectBackend",
            "put_user_media",
            "get_media(",
            "delete_media(",
            "delete_object",
            "list_objects",
            "list_object_versions",
            "KmsClient",
            "generate_and_wrap_dek",
            "load_dek(",
            "random_token_hex",
            "thread_rng",
            "SystemTime",
            "std::time::",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "reqwest::",
            "record_screenshot_image_in_transaction(",
        ):
            self.assertNotIn(forbidden, selected_provider_production)
        for forbidden in (
            "crate::store::Store",
            "GcsClient",
            "ExactImmutableObjectBackend",
            "create_if_absent(",
            "get_exact(",
            "prepare_selected_screenshot_provider_request(",
            "execute_selected_screenshot_provider_request(",
            "put_user_media",
            "get_media(",
            "delete_media(",
            "delete_object",
            "list_objects",
            "list_object_versions",
            "KmsClient",
            "generate_and_wrap_dek",
            "load_dek(",
            "encrypt_bound_blob",
            "decrypt_bound_blob",
            "random_token_hex",
            "thread_rng",
            "SystemTime",
            "std::time::",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "reqwest::",
            "record_screenshot_image_in_transaction(",
        ):
            self.assertNotIn(forbidden, selected_termination_production)
        for forbidden in (
            "strftime(",
            "SystemTime",
            "random_token_hex",
            "new_uuid(",
            "finalize_user_episode(",
            "reserve_finalizer_output(",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, finalization_queue_domain)
        for forbidden in (
            "strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            "GcsClient",
            "ExactImmutableObjectBackend",
            "put_user_media",
            "get_media(",
            "delete_media(",
            "delete_object",
            "list_objects",
            "KmsClient",
            "random_token_hex",
            "thread_rng",
            "SystemTime",
            "std::time::",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, episode_delete_production)
        for forbidden in (
            "strftime(",
            "SystemTime",
            "random_token_hex",
            "new_uuid(",
            "generate_custom(",
            "begin_invocation(",
            "list_webhook_subscriptions(",
            "get_email_preference(",
            "list_push_installations(",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, finalization_commit_domain)
        for forbidden in (
            "SystemTime",
            "random_token_hex",
            "thread_rng",
            "begin_invocation(",
            "generate_custom(",
            "get_media(",
            "decrypt_bound_blob",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, attempt_production)
        for forbidden in (
            "delete_retained_media(",
            "delete_object",
            "list_objects",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
        ):
            self.assertNotIn(forbidden, retention_domain)
        for forbidden in (
            "strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            "GcsClient",
            "ExactImmutableObjectBackend",
            "get_current_media_generation(",
            "load_dek(",
            "decrypt_bound_blob_v2(",
            "VoiceEngine",
            "embed_samples(",
            "random_token_hex",
            "thread_rng",
            "SystemTime",
            "std::time::",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "reqwest::",
            "INSERT INTO voice_profiles",
            "INSERT INTO people",
            "INSERT INTO person_facts",
        ):
            self.assertNotIn(forbidden, voice_embedding_production)
        for forbidden in (
            "GcsClient",
            "ExactImmutableObjectBackend",
            "get_current_media_generation(",
            "load_dek(",
            "decrypt_bound_blob_v2(",
            "VoiceEngine",
            "embed_samples(",
            "random_token_hex",
            "thread_rng",
            "SystemTime",
            "std::time::",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, voice_profile_production)
        for forbidden in (
            "strftime(",
            "SystemTime",
            "random_token_hex",
            "new_uuid(",
            "begin_invocation(",
            "generate_custom(",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
            "INSERT INTO utterances",
            "INSERT INTO identity_evidence",
            "INSERT INTO person_name_claims",
            "INSERT INTO people",
            "INSERT INTO voice_",
            "UPDATE identity_evidence",
            "UPDATE person_name_claims",
            "UPDATE people",
            "UPDATE voice_",
        ):
            self.assertNotIn(forbidden, result_production)
        for forbidden in (
            "transport.send(",
            "update_email_delivery_state(",
            "set_email_delivery_next_attempt(",
            "next_email_delivery(",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
        ):
            self.assertNotIn(forbidden, email_domain)
        for forbidden in (
            "transport.send(",
            "update_push_delivery_state(",
            "next_push_delivery(",
            "disable_push_installation_generation(",
            "upsert_push_installation(",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
        ):
            self.assertNotIn(forbidden, push_domain)
            self.assertNotIn(forbidden, push_claim_production)
            self.assertNotIn(forbidden, push_settlement_production)
        for forbidden in (
            "send_signed(",
            "set_legacy_delivery_state(",
            "next_delivery(",
            "get_webhook_subscription(",
            "disable_webhook_subscription(",
            "with_user(",
            "save_user(",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, webhook_domain)
            self.assertNotIn(forbidden, webhook_claim_production)
            self.assertNotIn(forbidden, webhook_exact_production)
        for forbidden in (
            "ensure_demo_archive(",
            "with_user(",
            "save_user(",
            "generate_custom(",
            "random_token_hex",
            "tokio::spawn",
            "std::time::",
        ):
            self.assertNotIn(forbidden, reviewer_domain)
        for forbidden in (
            "reserve_vertex_output(",
            "generate_custom(",
            "with_user(",
            "save_user(",
            "random_token_hex",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
        ):
            self.assertNotIn(forbidden, substance_domain)
        for forbidden in (
            "reserve_vertex_output(",
            "generate_custom(",
            "with_user(",
            "save_user(",
            "random_token_hex",
            "tokio::spawn",
            "std::time::",
            "reqwest::",
            "get_user_media(",
            "decrypt_bound_blob(",
            "jpeg_decoder",
            "image::",
        ):
            self.assertNotIn(forbidden, visual_domain)

    def test_wal_owner_and_private_publisher_are_unwired(self) -> None:
        owner = (ROOT / "src/archive_v3_wal_owner.rs").read_text(encoding="utf-8")
        launcher = (ROOT / "src/archive_v3_wal_owner/launcher.rs").read_text(
            encoding="utf-8"
        )
        publisher = (ROOT / "src/archive_v3_wal_owner/publisher.rs").read_text(
            encoding="utf-8"
        )
        maintenance = (ROOT / "src/archive_v3_maintenance_import.rs").read_text(
            encoding="utf-8"
        )
        idempotency = (ROOT / "src/archive_v3_wal_idempotency.rs").read_text(
            encoding="utf-8"
        )
        main = (ROOT / "src/main.rs").read_text(encoding="utf-8")
        self.assertIn("mod archive_v3_wal_owner;", main)
        self.assertNotIn("archive_v3_wal_owner::", main)
        # Deliberate ADR-0022 serving-activation pin (slice J-a): serving
        # startup must install every durable-terminal WAL-authority
        # persistence selection BEFORE the listener binds, and the scan/install
        # pair appears exactly once (the pre-serving canary argv path returns
        # earlier and never installs selections).
        self.assertEqual(
            main.count("load_wal_authoritative_persistence_selections()"), 1
        )
        self.assertEqual(main.count(".install_wal_authority_persistence("), 1)
        install_at = main.index(".install_wal_authority_persistence(")
        first_bind_at = main.index("tokio::net::TcpListener::bind")
        self.assertLess(
            install_at,
            first_bind_at,
            "WAL-authority selections must install before any listener binds",
        )
        self.assertIn("mod launcher;", owner)
        self.assertIn("struct SingleArchiveWalOwner", owner)
        self.assertNotIn("pub(crate) struct SingleArchiveWalOwner", owner)
        self.assertNotIn("pub struct SingleArchiveWalOwner", owner)
        launcher_production = without_cfg_test_items(launcher)
        self.assertIn(
            "pub(super) struct SingleArchiveWalLauncherOwner", launcher_production
        )
        self.assertNotIn(
            "pub(crate) struct SingleArchiveWalLauncherOwner", launcher_production
        )
        self.assertNotIn("pub struct SingleArchiveWalLauncherOwner", launcher_production)
        self.assertIn(
            "SingleArchiveWalPublisher::start(handoff)", launcher_production
        )
        self.assertIn(
            "pub(super) async fn submit<P: WalLogicalDomainPlan>",
            launcher_production,
        )
        self.assertNotIn("WalOwnerHandle<", owner)
        self.assertIn("Box<dyn ErasedPreparedLogicalMutation>", owner)
        self.assertIn(
            "pub(crate) trait ErasedPreparedLogicalMutation:", idempotency
        )
        self.assertIn(
            "ErasedPreparedLogicalMutation for PreparedLogicalMutation<P>",
            idempotency,
        )
        self.assertEqual(
            idempotency.count("impl<P: WalLogicalDomainPlan> ErasedPreparedLogicalMutation"),
            1,
        )
        self.assertIn("pub(super) struct SingleArchiveWalPublisher", publisher)
        self.assertNotIn("pub(crate) struct SingleArchiveWalPublisher", publisher)
        self.assertNotIn("pub struct SingleArchiveWalPublisher", publisher)
        self.assertIn("impl WalPublicationAuthority for SingleArchiveWalPublisher", publisher)
        self.assertIn("CompletedMaintenanceWalHandoff", publisher)
        self.assertNotIn("operation_id: _", publisher)
        self.assertNotIn("source: _", publisher)
        self.assertIn("MaintenanceImportPersistence::load_exact", publisher)
        # G8: the retained parity evidence is inert after construction and
        # became Option — None only for the genesis-ledger lane, whose
        # archive has no maintenance history to certify. The launch guard
        # keeps the two lane authorities mutually exclusive.
        self.assertIn(
            "_maintenance_parity: Option<CompletedMaintenanceParityEvidence>", publisher
        )
        self.assertIn(
            "genesis_reservation.is_some() == parity.is_some()", publisher
        )
        self.assertIn("struct CompletedMaintenanceParityEvidence", maintenance)
        self.assertIn("reauthenticate_for_wal_owner", maintenance)
        for forbidden in (
            "GcsClient",
            "FirestoreWitness::",
            "Store::new",
            "list_objects",
            "delete_exact",
            "std::env::",
        ):
            self.assertNotIn(forbidden, owner)
            self.assertNotIn(forbidden, launcher_production)
            self.assertNotIn(forbidden, publisher)

    def test_advisory_owner_family_stays_deleted(self) -> None:
        """The Phase-1/Phase-2 advisory-owner family is DELETED, not dormant.

        Its compile-pinned full_reviewed_mutation_set_commitment was signed
        into the Phase-2 admission, so while any of it existed, adding a
        WalOperationKind ordinal forced an offline re-signing ceremony. The
        genesis-first replan removed the family; this pin keeps it removed.
        A revival must arrive as a reviewed design, not as a stray import.
        """
        self.assertFalse(
            (ROOT / "src/archive_v3_advisory_owner.rs").exists(),
            "the advisory-owner module must stay deleted",
        )
        self.assertFalse(
            (ROOT / "src/archive_v3_advisory_owner").exists(),
            "the advisory-owner directory must stay deleted",
        )
        for path, source in rust_sources():
            # The `::` suffix targets Rust module references. The bare name
            # still appears legitimately in retained control-store DDL
            # (`archive_v3_advisory_owners`, kept until the atomic schema PR)
            # and in the release-absence probe that reads it.
            self.assertNotIn(
                "archive_v3_advisory_owner::",
                source,
                f"{path} references the deleted advisory-owner family",
            )
            self.assertNotIn(
                "full_reviewed_mutation_set_commitment",
                source,
                f"{path} references the deleted Phase-2 commitment",
            )

def classify_worker_spawn(site: CallSite) -> str:
    # Exact sites remain pinned by the digest. This classification answers
    # whether a future WAL-only runtime could allow the spawned owner today.
    if site.owner.path.startswith("src/archive_v3_"):
        return "C"
    if site.owner.path in {"src/acme.rs", "src/cp/billing.rs", "src/cp/control_store.rs"}:
        return "C"
    if site.owner.path in {"src/cp/sync.rs", "src/store.rs"}:
        return "C"
    if site.owner.path in {
        "src/cp/media.rs",
        "src/cp/media_worker.rs",
        "src/cp/model_usage.rs",
        "src/cp/query.rs",
        "src/cp/summarizer.rs",
    }:
        return "B"
    if site.owner.path == "src/main.rs":
        return "C"
    raise AssertionError(f"unclassified worker spawn: {site.key}")


if __name__ == "__main__":
    unittest.main()
