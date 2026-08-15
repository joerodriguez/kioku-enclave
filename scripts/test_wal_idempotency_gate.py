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
EXPECTED_STORE_CALL_COUNT = 151
EXPECTED_STORE_CALL_SHA256 = "b558be76d3a94f57c0f96ba2658570c94d84f939283447100be370d433ac0d82"
EXPECTED_STORE_SURFACE_COUNT = 15
EXPECTED_STORE_SURFACE_SHA256 = "3abb7ccb5ae7ef2470b99a0de068af22ad64134d741c9bf2f0ebfdf6e431c54c"
EXPECTED_STORE_SURFACE_KEYS = frozenset(
    {
        "src/main.rs::main#0::Store::new_with_media_and_legacy#0",
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
EXPECTED_POLICY_SITE_COUNT = 41
EXPECTED_POLICY_SITE_SHA256 = "3f01dfb0975431289a72111b4e23a77f527b1c7105d60f134de4742cf89f9e60"
EXPECTED_WAL_LOGICAL_ONLY_KEYS = frozenset(
    {
        "src/store.rs::<module>#0::WalLogicalOnly#0",
        "src/store.rs::evict_candidate#0::WalLogicalOnly#0",
        "src/store.rs::flush_handle#0::WalLogicalOnly#0",
        "src/store.rs::flush_handle_with_admission#0::WalLogicalOnly#0",
        "src/store.rs::load_user#0::WalLogicalOnly#0",
        "src/store.rs::load_user#0::WalLogicalOnly#1",
        "src/store.rs::open_db#0::WalLogicalOnly#0",
        "src/store.rs::save_user#0::WalLogicalOnly#0",
        "src/store.rs::with_user#0::WalLogicalOnly#0",
        "src/store.rs::with_user#0::WalLogicalOnly#1",
        "src/store.rs::with_user_if_changed#0::WalLogicalOnly#0",
        "src/store.rs::with_user_mut#0::WalLogicalOnly#0",
    }
)
EXPECTED_WORKER_SPAWN_COUNT = 24
EXPECTED_WORKER_SPAWN_SHA256 = "9cc0d93f6da8418dc1db2ccf30245a8b938b44fd4525139d3a3fb5bd3f6f5506"
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
    spans: list[Span] = []
    cfg = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    for match in cfg.finditer(code):
        cursor = match.end()
        while True:
            cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
            if code.startswith("#[", cursor):
                cursor = match_delimiter(code, cursor + 1, "[", "]")
                continue
            break
        brace = code.find("{", cursor)
        semicolon = code.find(";", cursor)
        if semicolon != -1 and (brace == -1 or semicolon < brace):
            spans.append(Span(match.start(), semicolon + 1))
        elif brace != -1:
            spans.append(Span(match.start(), match_delimiter(code, brace, "{", "}")))
        else:
            raise AssertionError("cfg(test) attribute has no item")
    return spans


def _excluded(offset: int, exclusions: list[Span]) -> bool:
    return any(span.start <= offset < span.end for span in exclusions)


def function_spans(path: str, source: str, code: str, exclusions: list[Span]) -> list[Owner]:
    candidates: list[tuple[str, Span]] = []
    for match in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", code):
        if _excluded(match.start(), exclusions):
            continue
        brace = code.find("{", match.end())
        semicolon = code.find(";", match.end())
        if brace == -1 or (semicolon != -1 and semicolon < brace):
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
    r"(?P<target>with_user_mut|with_user_if_changed|with_user|save_user)\s*\("
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
        "src/cp/media.rs::stream_ack#0",
        "src/cp/media.rs::capture_status#0",
        "src/cp/media.rs::capture_session_status#0",
        "src/cp/media.rs::finish_capture_session#0",
        "src/cp/media.rs::upload_screen_reference_batch#0",
        "src/cp/media.rs::list_people#0",
        "src/cp/media.rs::person_profile#0",
        "src/cp/media.rs::person_evidence#0",
        "src/cp/media.rs::person_statements#0",
        "src/cp/media_worker.rs::candidate_name_vocabulary#0",
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
        "src/cp/finalizer.rs::record_finalization_failure#0",
        "src/cp/finalizer.rs::defer_finalization_for_budget#0",
        "src/cp/media.rs::load_or_create_media_dek#0",
        "src/cp/media_worker.rs::reserve_media_output#0",
        "src/cp/model_usage.rs::begin_invocation#0",
        "src/cp/model_usage.rs::pending_events#0",
        "src/cp/model_usage.rs::pending_coverage#0",
        "src/cp/model_usage.rs::drain_coverage#0",
        "src/cp/model_usage.rs::note_delivery_failure#0",
        "src/cp/model_usage.rs::drain_outbox#0",
        "src/cp/query.rs::rest_delete_webhook#0",
        "src/cp/summarizer.rs::summarize_user#0",
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
    "src/cp/media_worker.rs::process_user#0::with_user#0": "A",
    "src/cp/media_worker.rs::process_user#0::with_user#1": "B",
    "src/cp/media_worker.rs::process_user#0::with_user#2": "B",
    "src/cp/media_worker.rs::process_user#0::with_user#3": "B",
    "src/cp/media_worker.rs::process_user#0::with_user#4": "B",
    "src/cp/media_worker.rs::process_user#0::save_user#0": "B",
    "src/cp/media_worker.rs::process_user#0::save_user#1": "B",
    "src/cp/media_worker.rs::process_user#0::save_user#2": "B",
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
                "fixture.rs::inner#0::with_user#0",
                "fixture.rs::live#0::with_user#0",
            ],
        )
        with self.assertRaises(AssertionError):
            call_sites_for_source("bad.rs", "fn closed() {} x.with_user(1);", STORE_CALL)

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
        model_usage = (ROOT / "src/cp/model_usage.rs").read_text(encoding="utf-8")
        vertex_domain = (ROOT / "src/cp/model_usage/wal.rs").read_text(
            encoding="utf-8"
        )
        query = (ROOT / "src/cp/query.rs").read_text(encoding="utf-8")
        selected_domain = (ROOT / "src/cp/query/wal.rs").read_text(
            encoding="utf-8"
        )
        media_worker = (ROOT / "src/cp/media_worker.rs").read_text(
            encoding="utf-8"
        )
        retention_domain = (ROOT / "src/cp/media_worker/wal.rs").read_text(
            encoding="utf-8"
        )
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
        self.assertNotIn("cp::query::wal::", main)
        self.assertIn("pub(crate) mod wal;", media_worker)
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
        self.assertNotIn("RetentionSettlementPlan::", media_worker)
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
            self.assertNotIn(forbidden, vertex_domain)
            self.assertNotIn(forbidden, selected_domain)
            self.assertNotIn(forbidden, retention_domain)
            self.assertNotIn(forbidden, email_domain)
            self.assertNotIn(forbidden, push_domain)
            self.assertNotIn(forbidden, webhook_domain)
        for forbidden in (
            "begin_invocation(",
            "random_token_hex",
            "with_user(",
            "save_user(",
        ):
            self.assertNotIn(forbidden, vertex_domain)
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

    def test_wal_owner_and_private_publisher_are_unwired(self) -> None:
        owner = (ROOT / "src/archive_v3_wal_owner.rs").read_text(encoding="utf-8")
        publisher = (ROOT / "src/archive_v3_wal_owner/publisher.rs").read_text(
            encoding="utf-8"
        )
        main = (ROOT / "src/main.rs").read_text(encoding="utf-8")
        self.assertIn("mod archive_v3_wal_owner;", main)
        self.assertNotIn("archive_v3_wal_owner::", main)
        self.assertIn("struct SingleArchiveWalOwner", owner)
        self.assertNotIn("pub(crate) struct SingleArchiveWalOwner", owner)
        self.assertNotIn("pub struct SingleArchiveWalOwner", owner)
        self.assertIn("pub(super) struct SingleArchiveWalPublisher", publisher)
        self.assertNotIn("pub(crate) struct SingleArchiveWalPublisher", publisher)
        self.assertNotIn("pub struct SingleArchiveWalPublisher", publisher)
        self.assertIn("impl WalPublicationAuthority for SingleArchiveWalPublisher", publisher)
        self.assertIn("CompletedMaintenanceWalHandoff", publisher)
        for forbidden in (
            "GcsClient",
            "FirestoreWitness::",
            "Store::new",
            "list_objects",
            "delete_exact",
            "std::env::",
        ):
            self.assertNotIn(forbidden, owner)
            self.assertNotIn(forbidden, publisher)


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
