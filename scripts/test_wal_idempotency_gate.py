#!/usr/bin/env python3
"""Structural fail-closed inventory for the inactive ADR-0022 WAL gate."""

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
EXPECTED_STORE_CALL_COUNT = 238
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
EXPECTED_STORE_CALL_SHA256 = "67960a4f5d14570629e4cced19c75f84ae910465064e7875d14e0cac66e82eb0"
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
EXPECTED_STORE_SURFACE_SHA256 = "9642f7988e47bc8c306be3a8ff2f8ccffcc6d1239ca977422857f3dff10a5b56"
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
# was served rather than refused. **Exactly one row changed and it changed
# only in the owner-body field:** the count stays 42, no call site was added,
# removed or reclassified, and every policy expression hash is byte-identical.
EXPECTED_POLICY_SITE_SHA256 = "11194ee709351375f51bc224823f0dbb1130e4c8380290c0c3d43e8dfcb29bf8"
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
EXPECTED_WORKER_SPAWN_COUNT = 26
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
EXPECTED_WORKER_SPAWN_SHA256 = "b313c238eba864456a9347c8beedbc0ac1409f6c5e53f9c6b5a0705ff461212e"
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
        "src/cp/delivery.rs::load_finalized_episode#0",
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
        "src/cp/query.rs::tool_search_transcripts#0",
        "src/cp/query.rs::tool_search_screenshots#0",
        "src/cp/query.rs::query_episodes_value#0",
        "src/cp/query.rs::tool_get_capture_status#0",
        "src/cp/query.rs::dispatch_tool#0",
        "src/cp/query.rs::rest_episode_members#0",
        "src/cp/query.rs::rest_browser_snapshot#0",
        "src/cp/query.rs::rest_episode_finalize#0",
        "src/cp/query.rs::rest_feed#0",
        "src/cp/query.rs::rest_screenshot_upload_plan#0",
        "src/cp/query.rs::rest_screenshot_image_content#0",
        "src/cp/reviewer.rs::ensure_demo_archive#0",
        "src/cp/summarizer.rs::run_substance_backfill#0",
        "src/cp/summarizer.rs::run_visual_evidence_backfill#0",
        "src/cp/summarizer.rs::fetch_range#0",
        "src/cp/summarizer.rs::fetch_open_episodes#0",
        "src/cp/summarizer.rs::session_tail_is_settled#0",
        "src/cp/sync.rs::sync_status#0",
        "src/cp/webhook_worker.rs::next_delivery#0",
        "src/episodes.rs::handle_episodes_list#0",
        "src/episodes.rs::handle_episodes_members#0",
        "src/search.rs::handle_search#0",
        "src/store.rs::enqueue_email_delivery#0",
        "src/store.rs::next_email_delivery#0",
        "src/store.rs::next_push_delivery#0",
        "src/store.rs::resolve_push_handoff#0",
        "src/timeline.rs::handle_context#0",
        "src/timeline.rs::handle_range#0",
        "src/timeline.rs::handle_stats#0",
    }
)
B_OWNERS = frozenset(
    {
        "src/cp/finalizer.rs::set_finalization_status#0",
        "src/cp/finalizer.rs::read_finalization_predecessor#0",
        "src/cp/email_worker.rs::settle_email_delivery#0",
        "src/cp/email_worker.rs::cancel_user_email_deliveries_settled#0",
        "src/cp/push.rs::update_delivery#0",
        "src/cp/finalizer.rs::settle_lifecycle#0",
        "src/cp/finalizer.rs::finalize_commit_settled#0",
        "src/cp/finalizer.rs::record_finalization_failure#0",
        "src/cp/finalizer.rs::defer_finalization_for_budget#0",
        "src/cp/media.rs::load_or_create_media_dek#0",
        "src/cp/media_worker.rs::claim_media_work_unit#0",
        "src/cp/media_worker.rs::process_user_voice_embedding_jobs#0",
        "src/cp/media_worker.rs::reserve_media_output#0",
        "src/cp/media_worker.rs::settle_media_work_failure#0",
        "src/cp/media_worker.rs::resurrect_user_failed_jobs#0",
        "src/cp/media_worker.rs::settle_audio_window_attempt#0",
        "src/cp/media_worker.rs::settle_audio_window_transcript#0",
        "src/cp/media_worker.rs::settle_screen_storyboard_attempt#0",
        "src/cp/media_worker.rs::settle_screen_storyboard_result#0",
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
        "src/cp/query.rs::wal_selected_screenshot_image_upload#0",
        "src/cp/summarizer.rs::summarize_user_window#0",
        "src/cp/summarizer.rs::wal_authoritative_upsert#0",
        "src/cp/summarizer.rs::embed_episodes#0",
        "src/cp/webhook_worker.rs::set_delivery_state#0",
        "src/store.rs::update_email_delivery_state#0",
        "src/store.rs::set_email_delivery_next_attempt#0",
        "src/store.rs::cancel_pending_email_deliveries#0",
        "src/store.rs::update_push_delivery_state#0",
    }
)
C_OWNERS = frozenset(
    {
        "src/cp/model_usage.rs::settle_for_account_deletion#0",
        "src/cp/query.rs::rest_episode_delete#0",
        "src/episodes.rs::handle_episodes_upsert#0",
        "src/episodes.rs::handle_episodes_delete_range#0",
        "src/ingest.rs::ingest_batch#0",
        "src/store.rs::with_user_read#0",
        "src/store.rs::with_user_if_changed#0",
    }
)

CALL_OVERRIDES = {
    # Speaker-slot reconciliation allocates random participant keys and
    # rewrites labels from live attribution state before the evidence reads
    # (the legacy evidence arm); the second with_user is the legacy commit.
    "src/cp/finalizer.rs::finalize_user_episodes_scoped#0::with_user#0": "B",
    "src/cp/finalizer.rs::finalize_user_episodes_scoped#0::with_user#1": "B",
    # Stable capture record, but the complete owner has the B dependency below.
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
        media_dek_domain = (
            ROOT / "src/cp/media/wal/media_dek.rs"
        ).read_text(encoding="utf-8")
        media_dek_production = without_cfg_test_items(media_dek_domain)
        model_usage = (ROOT / "src/cp/model_usage.rs").read_text(encoding="utf-8")
        vertex_domain = (ROOT / "src/cp/model_usage/wal.rs").read_text(
            encoding="utf-8"
        )
        query = (ROOT / "src/cp/query.rs").read_text(encoding="utf-8")
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
        email_worker = (ROOT / "src/cp/email_worker.rs").read_text(
            encoding="utf-8"
        )
        email_domain = (ROOT / "src/cp/email_worker/wal.rs").read_text(
            encoding="utf-8"
        )
        push = (ROOT / "src/cp/push.rs").read_text(encoding="utf-8")
        push_domain = (ROOT / "src/cp/push/wal.rs").read_text(encoding="utf-8")
        webhook_worker = (ROOT / "src/cp/webhook_worker.rs").read_text(
            encoding="utf-8"
        )
        webhook_domain = (ROOT / "src/cp/webhook_worker/wal.rs").read_text(
            encoding="utf-8"
        )
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
        self.assertNotIn("CanonicalCaptureEventPlan::", media)
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
        # ADR-0022 slice 10g: the pre-provider attempt is WIRED - the route
        # derives the predecessor through the routed read and constructs the
        # sealed attempt plan exactly once, durable BEFORE any encryption;
        # the legacy branch stays byte-identical.
        self.assertEqual(query.count("SelectedScreenshotAttemptPlan::new("), 1)
        self.assertIn(
            "authenticate_selected_screenshot_upload_predecessor(", query
        )
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
        # ADR-0022 slice 10g: the ciphertext candidate is WIRED through the
        # WAL-owned factory only - the route calls the factory exactly once
        # and never names the plan type or the ciphertext-bearing loader, so
        # pre-marker ciphertext stays confined to the WAL family.
        self.assertEqual(
            query.count("prepare_selected_screenshot_upload_candidate("), 1
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
        # ADR-0022 slice 10g: the send-start marker is WIRED through the
        # WAL-owned factory only - two sites: the resume probe (a settled
        # candidate must resume WITHOUT re-encrypting) and the fresh-chain
        # marker step. The route still cannot name the plan type or the
        # ciphertext-bearing marker loader, which stays WAL-private for the
        # provider child.
        self.assertEqual(
            query.count("prepare_selected_screenshot_send_started("), 2
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
        # ADR-0022 slice 10g stops fail-closed after the durable send-start
        # marker: the provider execution claim mutates inside its own
        # immediate transaction and has no routed admission lane for a
        # selected user (the submit lane accepts only sealed logical plans;
        # the serving read lane is query-only), so the provider link, the
        # provider-accepted A settlement, and the C termination remain
        # deliberately unwired and these dormancy pins stay in force.
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
        # screen family's 12-frame cap) and the four AUTOINCREMENT ids come
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
            "audio-window-transcript-v1-bound-attempt", audio_result_domain
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
        # The sealed identity/voice exclusion is structural, not a comment:
        # the production half of the transcript domain must contain no voice
        # or identity table, no embedding-job enqueue, and no MAX(id)
        # allocation. Scanned with comments and string literals blanked so a
        # doc-comment mention cannot satisfy or trip the pin. Any change here
        # re-opens F8's sealed recalculate-exclusion review.
        audio_result_code = sanitize_rust(audio_result_production)
        for forbidden in (
            "voice_embedding_jobs",
            "voice_samples",
            "voice_profiles",
            "enqueue_embedding_job",
            "identity_evidence",
            "person_name_claims",
            "resolve_speaker_attribution",
            "MAX(id)",
        ):
            self.assertNotIn(forbidden, audio_result_code)
        # The audio arm is wired end to end and the legacy tail survives for
        # unselected users.
        self.assertIn("AudioWindowAttemptPlan::new(", media_worker)
        self.assertIn("settle_audio_window_attempt", media_worker)
        self.assertIn("AudioWindowTranscriptPlan::new(", media_worker)
        self.assertIn("settle_audio_window_transcript", media_worker)
        self.assertIn("current_audio_vertex_attempt_commitment", media_worker)
        self.assertIn("read_audio_sequence_pins", media_worker)
        self.assertIn("persist_audio_window_result(", media_worker)
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
            "impl sealed::DomainPlan for crate::cp::email_worker::wal::EmailAcceptedPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::email_worker::wal::EmailAcceptedLedger",
            gate,
        )
        self.assertIn("struct EmailAcceptedPlan", email_domain)
        self.assertIn("struct EmailAcceptedLedger", email_domain)
        self.assertIn("archive_v3_wal_email_accepted_operations", email_domain)
        self.assertIn("DomainLedgerBounds::new", email_domain)
        self.assertIn("WalIdempotencyError::Precondition", email_domain)
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
        self.assertIn("struct PushAcceptedPlan", push_domain)
        self.assertIn("struct PushAcceptedLedger", push_domain)
        self.assertIn("archive_v3_wal_push_accepted_operations", push_domain)
        self.assertIn("DomainLedgerBounds::new", push_domain)
        self.assertIn("WalIdempotencyError::Precondition", push_domain)
        self.assertNotIn("PushAcceptedPlan::", push)
        self.assertNotIn("cp::push::wal::", main)
        self.assertIn("pub(crate) mod wal;", webhook_worker)
        self.assertIn(
            "impl sealed::DomainPlan for crate::cp::webhook_worker::wal::WebhookSentPlan",
            gate,
        )
        self.assertIn(
            "impl sealed::DomainLedger for crate::cp::webhook_worker::wal::WebhookSentLedger",
            gate,
        )
        self.assertIn("struct WebhookSentPlan", webhook_domain)
        self.assertIn("struct WebhookSentLedger", webhook_domain)
        self.assertIn("archive_v3_wal_webhook_sent_operations", webhook_domain)
        self.assertIn("DomainLedgerBounds::new", webhook_domain)
        self.assertIn("WalIdempotencyError::Precondition", webhook_domain)
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
            self.assertNotIn(forbidden, finalization_commit_domain)
            self.assertNotIn(forbidden, attempt_domain)
            self.assertNotIn(forbidden, result_domain)
            self.assertNotIn(forbidden, retention_domain)
            self.assertNotIn(forbidden, email_domain)
            self.assertNotIn(forbidden, push_domain)
            self.assertNotIn(forbidden, webhook_domain)
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
        for forbidden in (
            "send_signed(",
            "set_delivery_state(",
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
