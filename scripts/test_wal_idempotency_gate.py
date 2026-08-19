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
EXPECTED_STORE_CALL_COUNT = 160
EXPECTED_STORE_CALL_SHA256 = "6910a19a12368a794d1e639d937fa03a7149d2bbd1fc92d2895f072ef0ae09a7"
EXPECTED_STORE_SURFACE_COUNT = 15
EXPECTED_STORE_SURFACE_SHA256 = "549c5d4e4bc03ced1604b868ef0ed9bb37a126eab20d7ef1816ce5ff33944f9b"
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
EXPECTED_POLICY_SITE_COUNT = 41
EXPECTED_POLICY_SITE_SHA256 = "8188d67b5cf5eeecf02cf9ac2a2991a12718edb3120179a4efd32f0713c01125"
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
EXPECTED_WORKER_SPAWN_COUNT = 32
EXPECTED_WORKER_SPAWN_SHA256 = "409eac6c165038d0cb39f1cb221be8254ca8fa24def14b8dfec9a166bec75182"
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
        "src/cp/media.rs::list_capture_sessions#0",
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
        "src/cp/finalizer.rs::record_finalization_failure#0",
        "src/cp/finalizer.rs::defer_finalization_for_budget#0",
        "src/cp/media.rs::load_or_create_media_dek#0",
        "src/cp/media_worker.rs::process_user_voice_embedding_jobs#0",
        "src/cp/media_worker.rs::reserve_media_output#0",
        "src/cp/model_usage.rs::begin_invocation#0",
        "src/cp/model_usage.rs::pending_events#0",
        "src/cp/model_usage.rs::pending_coverage#0",
        "src/cp/model_usage.rs::drain_coverage#0",
        "src/cp/model_usage.rs::note_delivery_failure#0",
        "src/cp/model_usage.rs::drain_outbox#0",
        "src/cp/query.rs::rest_delete_webhook#0",
        "src/cp/summarizer.rs::summarize_user_window#0",
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
    # rewrites labels from live attribution state before the evidence reads.
    "src/cp/finalizer.rs::finalize_user_episodes_scoped#0::with_user#3": "B",
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
        self.assertNotIn("MediaDekInstallPlan::", media)
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
        self.assertNotIn("SelectedScreenshotAttemptPlan::", query)
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
        self.assertNotIn("SelectedScreenshotSendStartedPlan::", query)
        self.assertNotIn(
            "load_authenticated_selected_screenshot_send_started(", query
        )
        self.assertNotIn(
            "fn load_authenticated_selected_screenshot_send_started(",
            selected_production,
        )
        self.assertNotIn("prepare_selected_screenshot_send_started(", query)
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
        self.assertNotIn("FinalizationQueuePlan::", query)
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
        self.assertNotIn("FinalizationCommitPlan::", finalizer)
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
        self.assertNotIn("ScreenStoryboardAttemptPlan::", media_worker)
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
        self.assertNotIn("ScreenStoryboardResultPlan::", media_worker)
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
        self.assertNotIn("ReviewerFixturePlan::", reviewer)
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
        self.assertIn("_maintenance_parity: CompletedMaintenanceParityEvidence", publisher)
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

    def test_phase1_advisory_owner_is_shadow_only_private_and_unwired(self) -> None:
        advisory = (ROOT / "src/archive_v3_advisory_owner.rs").read_text(
            encoding="utf-8"
        )
        advisory_production = without_cfg_test_items(advisory)
        main = (ROOT / "src/main.rs").read_text(encoding="utf-8")
        store = (ROOT / "src/store.rs").read_text(encoding="utf-8")
        store_production = without_cfg_test_items(store)
        query = (ROOT / "src/cp/query.rs").read_text(encoding="utf-8")
        runtime = (ROOT / "src/archive_v3_shadow_runtime.rs").read_text(
            encoding="utf-8"
        )
        runtime_production = without_cfg_test_items(runtime)
        shadow_wal = (ROOT / "src/archive_v3_shadow_wal.rs").read_text(
            encoding="utf-8"
        )
        shadow_wal_production = without_cfg_test_items(shadow_wal)
        shadow_checkpoint = (
            ROOT / "src/archive_v3_shadow_checkpoint.rs"
        ).read_text(encoding="utf-8")
        shadow_checkpoint_production = without_cfg_test_items(shadow_checkpoint)
        maintenance = (ROOT / "src/archive_v3_maintenance_import.rs").read_text(
            encoding="utf-8"
        )
        maintenance_production = without_cfg_test_items(maintenance)
        witness = (ROOT / "src/archive_v3_witness.rs").read_text(encoding="utf-8")
        control = (ROOT / "src/cp/control_store.rs").read_text(encoding="utf-8")
        control_production = without_cfg_test_items(control)
        canary = (
            ROOT / "src/archive_v3_advisory_owner/canary.rs"
        ).read_text(encoding="utf-8")
        canary_production = without_cfg_test_items(canary)
        canary_trust = (
            ROOT / "src/archive_v3_advisory_owner/canary_trust.rs"
        ).read_text(encoding="utf-8")
        canary_trust_production = without_cfg_test_items(canary_trust)
        sqlite_vfs = (ROOT / "src/archive_v3_sqlite_vfs.rs").read_text(
            encoding="utf-8"
        )
        sqlite_vfs_production = without_cfg_test_items(sqlite_vfs)
        comparison = (
            ROOT / "src/archive_v3_advisory_owner/comparison.rs"
        ).read_text(encoding="utf-8")
        comparison_production = without_cfg_test_items(comparison)
        abort = (
            ROOT / "src/archive_v3_advisory_owner/abort.rs"
        ).read_text(encoding="utf-8")
        abort_production = without_cfg_test_items(abort)
        abort_reconcile = (
            ROOT / "src/archive_v3_advisory_owner/abort_reconcile.rs"
        ).read_text(encoding="utf-8")
        abort_reconcile_production = without_cfg_test_items(abort_reconcile)

        self.assertIn("mod archive_v3_advisory_owner;", main)
        self.assertNotIn("archive_v3_advisory_owner::", main)
        self.assertIn("mod comparison;", advisory_production)
        self.assertIn("mod abort;", advisory_production)
        self.assertIn("mod abort_reconcile;", advisory_production)
        self.assertIn("mod canary;", advisory_production)
        self.assertIn("mod canary_trust;", advisory_production)
        self.assertNotIn("pub mod canary", advisory_production)
        self.assertNotIn("pub mod canary_trust", advisory_production)
        self.assertNotIn("pub mod comparison", advisory_production)
        self.assertNotIn("pub mod abort", advisory_production)
        self.assertNotIn("pub mod abort_reconcile", advisory_production)
        self.assertIn("struct SingleArchiveAdvisoryOwner", advisory_production)
        self.assertNotIn(
            "pub(crate) struct SingleArchiveAdvisoryOwner", advisory_production
        )
        self.assertIn(
            "async fn start(\n        handoff: CompletedAdvisoryShadowHandoff,\n        canary: AdvisoryCanaryScope,",
            advisory_production,
        )
        self.assertIn("pub(crate) struct AdvisoryCanaryScope", canary_production)
        for forbidden in ("derive(Clone", "derive(Copy", "Serialize", "Deserialize"):
            self.assertNotIn(forbidden, canary_production)
        self.assertIn(
            "_token: crate::cp::control_store::AdvisoryOwnerPersistenceContext",
            canary_production,
        )
        self.assertIn(
            "pub(crate) struct VerifiedAdvisoryCanaryAuthorization",
            canary_trust_production,
        )
        for forbidden in ("derive(Clone", "derive(Copy", "Serialize", "Deserialize"):
            self.assertNotIn(forbidden, canary_trust_production)
        for required in (
            'b"kioku/archive-v3/advisory-canary/operator-statement/v1\\0"',
            'b"kioku/archive-v3/advisory-canary/operator-statement-commitment/v1\\0"',
            'b"kioku/archive-v3/advisory-canary/image-attestation/v1\\0"',
            'b"kioku/archive-v3/advisory-canary/runtime-admission/v1\\0"',
            'b"kioku/archive-v3/advisory-canary/runtime-admission-commitment/v1\\0"',
            'b"kioku/archive-v3/advisory-canary/authoritative-mutation-set/empty/v1\\0"',
            'b"kioku/archive-v3/advisory-canary/authorization-evidence/v1\\0"',
            "const OPERATOR_STATEMENT_BYTES: usize = 242;",
            "const IMAGE_ATTESTATION_BYTES: usize = 82;",
            "const RUNTIME_ADMISSION_BYTES: usize = 298;",
            "const PINNED_OPERATOR_PUBLIC_KEY: [u8; 32] = [0; 32];",
            "const PINNED_IMAGE_ATTESTATION_PUBLIC_KEY: [u8; 32] = [0; 32];",
            "const PINNED_RUNTIME_ADMISSION_PUBLIC_KEY: [u8; 32] = [0; 32];",
            "operator == image_attestation",
            "operator == runtime_admission",
            "image_attestation == runtime_admission",
            "u16::from_be_bytes([bytes[291], bytes[292]]) != 0",
            "u32::from_be_bytes([bytes[294], bytes[295], bytes[296], bytes[297]]) != 0",
            "hasher.update(0_u16.to_be_bytes())",
            "UnparsedPublicKey::new(&ED25519, public_key)",
            "verify_pinned_advisory_canary_authorization",
            "authenticate_image_attestation",
            "authenticate_runtime_admission",
            "authenticate_for_control",
            "authorization_evidence_commitment",
            "hasher.update(scope_id)",
        ):
            self.assertIn(required, canary_trust_production)
        self.assertIn(
            "verify_pinned_advisory_canary_authorization, VerifiedAdvisoryCanaryAuthorization",
            advisory_production,
        )
        self.assertEqual(
            canary_trust_production.count(
                "-> Result<VerifiedAdvisoryCanaryAuthorization>"
            ),
            2,
        )
        self.assertIn("fn validated(", canary_trust_production)
        self.assertIn("runtime_admission: [u8; 32]", canary_trust_production)
        self.assertNotIn("pub(crate) fn validated(", canary_trust_production)
        self.assertIn(
            "fn verify_advisory_canary_authorization_with_roots(",
            canary_trust_production,
        )
        self.assertNotIn(
            "pub(crate) fn verify_advisory_canary_authorization_with_roots(",
            canary_trust_production,
        )
        for forbidden in (
            "Ed25519KeyPair",
            "private_key",
            "PRIVATE KEY",
            "std::env::",
            "std::time::SystemTime",
            "from_env",
            "fetch_attestation",
            "AttestationCredentials",
            "KIOKU_BUILD_PROFILE",
            "ArchiveV3ShadowRuntimeDeployment",
            "reqwest",
            "crate::store",
            "Gcs",
            "create_if_absent",
            ".put_object(",
            ".enumerate(",
            "delete_exact",
            "delete_object",
            "acknowledge_result",
        ):
            self.assertNotIn(forbidden, canary_trust_production)
        self.assertNotIn("verify_pinned_advisory_canary_authorization", main)
        self.assertNotIn("verify_pinned_advisory_canary_authorization", query)
        self.assertIn(
            "#[cfg(test)]\nfn authorize_advisory_canary_for_test_conn(", control
        )
        self.assertIn(
            "#[cfg(test)]\n    pub(crate) async fn authorize_advisory_canary_for_test(",
            control,
        )
        self.assertNotIn("authorize_advisory_canary_for_test", advisory_production)
        self.assertNotIn("authorize_advisory_canary_for_test", main)
        self.assertNotIn("authorize_advisory_canary_for_test", query)
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS archive_v3_advisory_canary_scopes",
            control_production,
        )
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS archive_v3_advisory_activation_preconditions",
            control_production,
        )
        issuer_begin = control_production.index("fn authorize_advisory_canary_conn(")
        issuer_end = control_production.index(
            "    Ok((capability, true))\n}", issuer_begin
        ) + len("    Ok((capability, true))\n}")
        issuer_control = control_production[issuer_begin:issuer_end]
        for required in (
            "advisory_canary_terminal_facts_conn",
            "authenticate_for_control",
            "load_advisory_canary_capability_conn",
            "load_advisory_canary_scope_conn",
            "INSERT INTO archive_v3_advisory_canary_scopes",
            "INSERT INTO archive_v3_advisory_activation_preconditions",
            "load_advisory_activation_preconditions_conn",
            "advisory canary authorization readback changed",
            "tx.commit()?",
        ):
            self.assertIn(required, issuer_control)
        self.assertLess(
            issuer_control.index("authenticate_for_control"),
            issuer_control.index("INSERT INTO archive_v3_advisory_canary_scopes"),
        )
        self.assertLess(
            issuer_control.index("INSERT INTO archive_v3_advisory_canary_scopes"),
            issuer_control.index(
                "INSERT INTO archive_v3_advisory_activation_preconditions"
            ),
        )
        self.assertNotIn("OsRng", issuer_control)
        self.assertIn(
            "pub(crate) async fn authorize_verified_advisory_canary(",
            control_production,
        )
        self.assertNotIn("authorize_verified_advisory_canary", main)
        self.assertNotIn("authorize_verified_advisory_canary", query)
        self.assertIn("fn reserve_advisory_owner_with_canary_conn(", control_production)
        self.assertNotIn("fn reserve_advisory_owner_conn(", control_production)
        self.assertIn(
            "async fn reserve_advisory_owner_with_canary(", advisory_production
        )
        start_begin = advisory_production.index("async fn start(")
        start_end = advisory_production.index("async fn maintain_lease", start_begin)
        start_owner = advisory_production[start_begin:start_end]
        self.assertEqual(start_owner.count("reserve_advisory_owner_with_canary("), 1)
        reauthenticate = start_owner.index("reauthenticate_for_advisory_owner")
        reserve = start_owner.index("reserve_advisory_owner_with_canary(")
        runtime_conversion = start_owner.index("let runtime = runtime")
        send_started = start_owner.index("mark_advisory_owner_send_started")
        self.assertLess(reauthenticate, reserve)
        self.assertLess(reserve, runtime_conversion)
        self.assertLess(runtime_conversion, send_started)
        reserve_begin = control_production.index(
            "fn reserve_advisory_owner_with_canary_conn("
        )
        reserve_end = control_production.index(
            "fn mark_advisory_owner_send_started_conn", reserve_begin
        )
        reserve_control = control_production[reserve_begin:reserve_end]
        for required in (
            "load_advisory_canary_scope_conn",
            "load_advisory_activation_preconditions_conn",
            "state='consumed'",
            "consumed_owner_id=?1",
            "authorization_commitment=?14",
            "commitment=?15",
            "revision=1",
            "INSERT INTO archive_v3_advisory_owners",
            "load_advisory_owner_reservation_conn",
            "advisory canary consumption readback changed",
            "tx.commit()?",
        ):
            self.assertIn(required, reserve_control)
        self.assertLess(
            reserve_control.index("UPDATE archive_v3_advisory_canary_scopes"),
            reserve_control.index(
                "UPDATE archive_v3_advisory_activation_preconditions"
            ),
        )
        self.assertLess(
            reserve_control.index(
                "UPDATE archive_v3_advisory_activation_preconditions"
            ),
            reserve_control.index("INSERT INTO archive_v3_advisory_owners"),
        )
        mark_begin = control_production.index("fn mark_advisory_owner_send_started_conn(")
        mark_end = control_production.index("fn bind_advisory_owner_conn(", mark_begin)
        mark_control = control_production[mark_begin:mark_end]
        self.assertIn("load_advisory_activation_preconditions_conn", mark_control)
        self.assertIn("preconditions.consumed", mark_control)
        self.assertLess(
            mark_control.index("load_advisory_activation_preconditions_conn"),
            mark_control.index("stage == AdvisoryOwnerStage::SendStarted"),
        )
        for forbidden in (
            "std::env::",
            "Store::new",
            "create_if_absent",
            ".put_object(",
            ".enumerate(",
            "delete_exact",
            "delete_object",
            "acknowledge_result",
        ):
            self.assertNotIn(forbidden, canary_production)
            self.assertNotIn(forbidden, reserve_control)
        self.assertNotIn("start_advisory_owner_for_test", advisory_production)
        self.assertIn("AdvisoryOwnerRuntimeContext(())", advisory_production)
        self.assertIn("MigrationState::ShadowWal", advisory_production)
        self.assertNotIn("MigrationState::WalAuthoritative", advisory_production)
        self.assertIn("exact_advisory_owner_acquire_from", advisory_production)
        self.assertIn("exact_advisory_owner_heartbeat_from", advisory_production)
        self.assertIn("exact_advisory_owner_reacquire_from", advisory_production)
        self.assertIn("async fn maintain_lease(&mut self)", advisory_production)
        self.assertIn("may_heartbeat: bool", advisory_production)
        self.assertIn("reacquire_advisory_owner_lease_unresolved", advisory_production)
        self.assertIn("persist_advisory_owner_successor", advisory_production)
        self.assertIn("into_advisory_owner", runtime)
        self.assertIn("maintain_advisory_owner_lease_unresolved", runtime)
        self.assertIn("is_exact_unleased_advisory_terminal", witness)
        self.assertIn("maintain_exact_advisory_owner_lease", witness)
        self.assertNotIn("archive_v3_advisory_owner::", query)
        self.assertIn(
            "pub(crate) struct StoreShadowCaptureSelection", store_production
        )
        self.assertIn(
            "shadow_capture: StdRwLock<Option<StoreShadowCaptureSelection>>",
            store_production,
        )
        self.assertIn("fn capture_for_user(&self, user_id: &str)", store_production)
        self.assertIn("selection.capture_for_user(user_id)", store_production)
        self.assertNotIn("StoreShadowCaptureSelection::for_test", store_production)
        self.assertIn(
            "fn shared_for_advisory_owner() -> Result<Arc<Self>>",
            store_production,
        )
        self.assertNotIn(
            "pub(crate) fn shared_for_advisory_owner", store_production
        )
        self.assertNotIn("StoreShadowCaptureSelection", main)
        self.assertEqual(
            advisory_production.count("crate::store::StoreAdvisoryCaptureTarget"), 1
        )
        self.assertIn(
            "_capture_target: crate::store::StoreAdvisoryCaptureTarget",
            advisory_production,
        )
        self.assertIn("into_advisory_capture_target", maintenance)
        self.assertIn("struct StoreAdvisoryCaptureTarget", store_production)
        self.assertEqual(store_production.count("impl StoreAdvisoryCaptureTarget"), 1)
        self.assertNotIn("exact_identity_for_test", store_production)
        self.assertIn("struct AdvisoryRelease", advisory_production)
        self.assertIn("AdvisoryReleaseStage::Prepared", advisory_production)
        self.assertIn("AdvisoryReleaseStage::DeleteStarted", advisory_production)
        self.assertIn("AdvisoryReleaseStage::Released", advisory_production)
        self.assertIn(
            "_token: crate::store::StoreMaintenanceContext",
            advisory_production,
        )
        self.assertIn("CREATE TABLE IF NOT EXISTS archive_v3_advisory_releases", control)
        self.assertIn(
            "advisory release permanently fenced lease advancement", control
        )
        self.assertIn(
            "async fn release_legacy_fence(self)", advisory_production
        )
        self.assertNotIn(
            "pub(crate) async fn release_legacy_fence", advisory_production
        )
        self.assertIn(
            "struct ReleasedSingleArchiveAdvisoryOwner", advisory_production
        )
        self.assertIn(
            "struct LocallyResumedSingleArchiveAdvisoryOwner", advisory_production
        )
        self.assertIn(
            ".acquire_advisory_release_lifecycle()", advisory_production
        )
        self.assertIn(
            "_release_lifecycle_guard: crate::store::StoreAdvisoryReleaseLifecycle",
            advisory_production,
        )
        self.assertIn(".observe_advisory_fence(&release)", advisory_production)
        self.assertIn(
            ".reconcile_advisory_fence_absence(&release)", advisory_production
        )
        release_start = advisory_production.index("async fn release_legacy_fence(self)")
        release_end = advisory_production.index(
            "fn map_advisory_store_error", release_start
        )
        release_method = advisory_production[release_start:release_end]
        self.assertIn("read_advisory_owner_current_exact", release_method)
        self.assertIn("current != *self._bound.observed()", release_method)
        self.assertIn(
            "async fn resume_local_admission(self)", advisory_production
        )
        self.assertNotIn(
            "pub(crate) async fn resume_local_admission", advisory_production
        )
        local_start = advisory_production.index(
            "async fn resume_local_admission(self)"
        )
        local_end = advisory_production.index(
            "fn map_advisory_store_error", local_start
        )
        local_owner = advisory_production[local_start:local_end]
        reauth_start = advisory_production.index(
            "async fn reauthenticate_boundary(&self)"
        )
        reauth_owner = advisory_production[reauth_start:local_start]
        self.assertIn("read_advisory_owner_current_exact", reauth_owner)
        self.assertIn("current != *self._owner._bound.observed()", reauth_owner)
        self.assertIn("load_advisory_release", reauth_owner)
        self.assertIn("retained != self._release", reauth_owner)
        self.assertIn("self.reauthenticate_boundary().await?", local_owner)
        self.assertIn("load_advisory_abort", local_owner)
        self.assertIn(".resume_advisory_local_admission", local_owner)
        self.assertLess(
            local_owner.index("load_advisory_abort"),
            local_owner.index(".resume_advisory_local_admission"),
        )
        self.assertIn("async fn begin_capture_drain(", advisory_production)
        self.assertNotIn(
            "pub(crate) async fn begin_capture_drain", advisory_production
        )
        self.assertEqual(
            advisory_production.count(".begin_advisory_capture_drain()"), 1
        )
        executor_start = store_production.index("impl StoreAdvisoryCaptureTarget")
        executor_end = store_production.index(
            "impl Drop for PinnedLegacySnapshot", executor_start
        )
        executor = store_production[executor_start:executor_end]
        resume_start = executor.index(
            "pub(crate) async fn resume_advisory_local_admission"
        )
        self.assertEqual(
            store_production.count("impl StoreAdvisoryResumedTarget"), 1
        )
        drain_start = executor.index(
            "pub(crate) async fn begin_advisory_capture_drain"
        )
        retirement_start = executor.index(
            "pub(crate) async fn retire_advisory_capture"
        )
        provider_executor = executor[
            executor.index("fn exact_marker_name_and_stage"):resume_start
        ]
        local_executor = executor[resume_start:drain_start]
        drain_executor = executor[drain_start:retirement_start]
        retirement_executor = executor[retirement_start:]
        self.assertIn("AdvisoryFenceObservation::from_store", executor)
        self.assertIn("AdvisoryFenceAbsence::from_store", executor)
        self.assertEqual(provider_executor.count(".delete_object_generation("), 1)
        self.assertEqual(provider_executor.count(".get_object(&marker_name)"), 3)
        self.assertIn("AdvisoryReleaseStoreStage::Prepared", executor)
        self.assertIn("AdvisoryReleaseStoreStage::DeleteStarted", executor)
        self.assertIn("identity_rebind_fence_object_name", executor)
        self.assertIn("fn acquire_advisory_release_lifecycle", executor)
        self.assertIn("AdvisoryReleaseStoreStage::Released", local_executor)
        self.assertIn("let mut registry = self._store.registry.lock().await", local_executor)
        self.assertIn("let mut barrier = self", local_executor)
        self.assertIn("registry_blocked != content_blocked", local_executor)
        self.assertIn("registry.open_users.contains_key", local_executor)
        self.assertIn(".active_writes", local_executor)
        self.assertIn(
            "StoreShadowCapture::shared_for_advisory_owner()", local_executor
        )
        self.assertIn(".shadow_capture", local_executor)
        self.assertIn(".write()", local_executor)
        self.assertIn("Arc::ptr_eq", local_executor)
        self.assertLess(
            local_executor.index(".shadow_capture"),
            local_executor.index("blocked_users.remove"),
        )
        self.assertEqual(local_executor.count("blocked_users.remove"), 2)
        self.assertIn("StoreAdvisoryResumedTarget", local_executor)
        for forbidden in (
            ".get_object(",
            ".delete_object",
            ".put_object(",
            "list_",
            ".with_user(",
            "CaptureRegistration",
            "CaptureRegistry",
            "open_db(",
            ".register(",
            "begin_drain",
            "acknowledge_result",
            "tokio::spawn",
            "std::env::",
        ):
            self.assertNotIn(forbidden, local_executor)
        self.assertIn("struct StoreAdvisoryCapturedDrain", store_production)
        self.assertIn("_snapshot: Connection", store_production)
        self.assertIn("_drain: OwnedAdvisoryCapturedDrain", store_production)
        self.assertEqual(store_production.count("impl StoreAdvisoryCapturedDrain"), 1)
        comparison_impl_start = store_production.index(
            "impl StoreAdvisoryCapturedDrain"
        )
        comparison_impl_open = store_production.index("{", comparison_impl_start)
        comparison_impl_end = match_delimiter(
            store_production, comparison_impl_open, "{", "}"
        )
        store_comparison = store_production[
            comparison_impl_start:comparison_impl_end
        ]
        self.assertEqual(store_comparison.count("pub(crate) async fn"), 1)
        self.assertIn("compare_recovered_advisory", store_comparison)
        self.assertIn("replay_advisory_captured_prefix", store_comparison)
        self.assertIn("compare_advisory_staged_snapshot", store_comparison)
        self.assertIn("restore_after_comparison", store_comparison)
        self.assertIn("StoreAdvisoryComparisonEvidence::from_restored", store_comparison)
        self.assertIn("tokio::spawn(async move", store_comparison)
        self.assertIn("tokio::task::spawn_blocking", store_comparison)
        for forbidden in (
            ".with_user(",
            ".save_user(",
            ".get_object(",
            ".put_object(",
            "list_",
            "delete_",
            ".settle(",
            "acknowledge_result",
            "std::env::",
        ):
            self.assertNotIn(forbidden, store_comparison)
        self.assertNotRegex(
            store_production,
            r"impl[^{}]{0,160}\bfor\s+StoreAdvisoryCapturedDrain\b",
        )
        self.assertIn("OpenStatus::Open", drain_executor)
        self.assertIn("handle.user_id != self._user_id", drain_executor)
        self.assertIn("registration.belongs_to(&self._capture.registry)", drain_executor)
        self.assertIn("registration.completed_len() == 0", drain_executor)
        self.assertIn("OpenFlags::SQLITE_OPEN_READ_ONLY", drain_executor)
        self.assertIn("OpenFlags::SQLITE_OPEN_NO_MUTEX", drain_executor)
        self.assertIn("&handle.temp_path", drain_executor)
        self.assertIn("PRAGMA query_only=ON", drain_executor)
        self.assertIn("PRAGMA trusted_schema=OFF", drain_executor)
        self.assertIn("BEGIN DEFERRED", drain_executor)
        self.assertIn("SELECT count(*) FROM sqlite_schema", drain_executor)
        self.assertLess(
            drain_executor.index("SELECT count(*) FROM sqlite_schema"),
            drain_executor.index(".begin_drain(session, attempt)"),
        )
        self.assertIn("ShadowSessionId::for_operation", drain_executor)
        self.assertIn("ShadowAttemptId::random()", drain_executor)
        self.assertIn(".begin_drain(session, attempt)", drain_executor)
        self.assertIn("lease.take_for_advisory()", drain_executor)
        for forbidden in (
            ".get_object(",
            ".delete_object",
            ".put_object(",
            "list_",
            ".with_user(",
            "open_db(",
            ".register(",
            ".commit()",
            ".settle(",
            "CapturedWalCommit",
            "acknowledge_result",
            "tokio::spawn",
            "std::env::",
        ):
            self.assertNotIn(forbidden, drain_executor)
        self.assertIn("StoreAdvisoryRetirementContext(())", retirement_executor)
        self.assertEqual(
            store_production.count("struct StoreAdvisoryRetirementContext"), 1
        )
        self.assertEqual(
            store_production.count("struct StoreAdvisoryCaptureRetired"), 1
        )
        self.assertNotRegex(
            store_production,
            r"impl[^{}]{0,160}\bfor\s+StoreAdvisoryCaptureRetired\b",
        )
        self.assertIn("authenticate_store_target", retirement_executor)
        self.assertIn("tokio::spawn(async move", retirement_executor)
        self.assertLess(
            retirement_executor.index("authenticate_store_target"),
            retirement_executor.index("retire_advisory_capture_owned("),
        )
        self.assertEqual(
            retirement_executor.count("async fn retire_advisory_capture_owned("), 1
        )
        self.assertLess(
            retirement_executor.index("retire_advisory_capture_owned("),
            retirement_executor.index("tokio::spawn(async move"),
        )
        self.assertEqual(
            retirement_executor.count("async fn retire_advisory_capture_state("), 1
        )
        self.assertIn("open.status == OpenStatus::Open", retirement_executor)
        self.assertIn("let registry = store.registry.lock().await", retirement_executor)
        self.assertIn("drop(registry);\n            return Ok(())", retirement_executor)
        self.assertLess(
            retirement_executor.index("let registry = store.registry.lock().await"),
            retirement_executor.index("let mut selection = store.shadow_capture.write()"),
        )
        self.assertIn("actor.state.lock().await", retirement_executor)
        self.assertIn("_shadow_capture_registration.take()", retirement_executor)
        self.assertIn("retained.belongs_to(&capture.registry)", retirement_executor)
        self.assertIn("Arc::ptr_eq(&retained.capture, &capture)", retirement_executor)
        self.assertIn("*selection = None", retirement_executor)
        self.assertIn("StoreAdvisoryCaptureRetired {", retirement_executor)
        self.assertIn("retire_advisory_capture_for_abort", retirement_executor)
        self.assertIn("advisory abort target changed", retirement_executor)
        live_take = retirement_executor.index("_shadow_capture_registration.take()")
        self.assertLess(
            live_take,
            retirement_executor.index("*selection = None", live_take),
        )
        for forbidden in (
            ".get_object(",
            ".delete_object",
            ".put_object(",
            "list_",
            ".with_user(",
            "open_db(",
            ".register(",
            ".commit()",
            ".settle(",
            "CapturedWalCommit",
            "acknowledge_result",
            "std::env::",
        ):
            self.assertNotIn(forbidden, retirement_executor)
        self.assertIn("struct OwnedAdvisoryCapturedDrain", sqlite_vfs_production)
        self.assertNotIn("pub struct OwnedAdvisoryCapturedDrain", sqlite_vfs_production)
        self.assertEqual(
            sqlite_vfs_production.count("impl OwnedAdvisoryCapturedDrain"), 1
        )
        owned_comparison_start = sqlite_vfs_production.index(
            "impl OwnedAdvisoryCapturedDrain"
        )
        owned_comparison_open = sqlite_vfs_production.index(
            "{", owned_comparison_start
        )
        owned_comparison_end = match_delimiter(
            sqlite_vfs_production, owned_comparison_open, "{", "}"
        )
        owned_comparison = sqlite_vfs_production[
            owned_comparison_start:owned_comparison_end
        ]
        self.assertEqual(owned_comparison.count("pub(crate) fn"), 2)
        self.assertIn("captured_prefix_for_comparison", owned_comparison)
        self.assertIn("restore_after_comparison", owned_comparison)
        self.assertIn("restore_completed_prefix(commits)", owned_comparison)
        self.assertIn("AdvisoryComparisonRestored", owned_comparison)
        for forbidden in (
            "pub fn",
            "settle",
            "release_completed_reservation",
            "provider",
            "list_",
            "delete_",
        ):
            self.assertNotIn(forbidden, owned_comparison)
        self.assertEqual(
            len(
                re.findall(
                    r"impl[^{}]{0,160}\bfor\s+OwnedAdvisoryCapturedDrain\b",
                    sqlite_vfs_production,
                )
            ),
            2,
        )
        self.assertEqual(
            sqlite_vfs_production.count(
                ".drain_completed_prefix_with_reservation("
            ),
            2,
        )
        owned_start = sqlite_vfs_production.index(
            "impl Drop for OwnedAdvisoryCapturedDrain"
        )
        owned_end = sqlite_vfs_production.index(
            "impl std::fmt::Debug for OwnedAdvisoryCapturedDrain", owned_start
        )
        owned_drain = sqlite_vfs_production[owned_start:owned_end]
        self.assertIn("restore_completed_prefix(commits)", owned_drain)

        runtime_recovery_start = runtime_production.index(
            "pub(crate) async fn recover_advisory_comparison_staging"
        )
        runtime_recovery_end = runtime_production.index(
            "impl fmt::Debug for AdvisoryOwnerRuntimeOwner", runtime_recovery_start
        )
        runtime_recovery = runtime_production[
            runtime_recovery_start:runtime_recovery_end
        ]
        for required in (
            "MigrationState::ShadowWal",
            "DeletionState::Active",
            "KeyRegistryContext::with_rotation_generation",
            "resolve_archive_cipher",
            "RecoveryRoot::from_exact_active_record",
            "recover_owned_maintenance_staging",
        ):
            self.assertIn(required, runtime_recovery)
        for forbidden in (
            "create_if_absent",
            "list_objects",
            "ImmutableObjectBackend::enumerate",
            "EnumerationPage",
            "EnumerationCursor",
            "delete_exact",
            "delete_object",
            ".put_object(",
        ):
            self.assertNotIn(forbidden, runtime_recovery)
        self.assertNotIn(".enumerate(", runtime_recovery)

        replay_start = shadow_wal_production.index(
            "pub(crate) async fn replay_advisory_captured_prefix"
        )
        replay_end = shadow_wal_production.index(
            "fn validate_advisory_captured_prefix", replay_start
        )
        replay = shadow_wal_production[replay_start:replay_end]
        for required in (
            "validate_advisory_captured_prefix(commits)?",
            "CompositeWalRecoverySink::new",
            "validate_segments(validation_sequence)",
            "sink.begin_generation",
            "sink.write_wal_frames",
            "sink.finish_generation",
            "refresh_after_advisory_replay",
        ):
            self.assertIn(required, replay)
        continuity_start = replay_end
        continuity_end = shadow_wal_production.index(
            "pub(crate) fn compare_advisory_staged_snapshot", continuity_start
        )
        continuity = shadow_wal_production[continuity_start:continuity_end]
        for required in (
            "first.wal_generation() != 1",
            "first.first_frame_no() != 1",
            "checked_add(u64::from(previous.frame_count()))",
            "commit.replay_header() == previous.replay_header()",
            "commit.replay_checksum_before() == captured_terminal_checksum(previous)?",
            "checked_add(1)",
        ):
            self.assertIn(required, continuity)
        comparison_start = continuity_end
        backup_start = shadow_wal_production.index(
            "fn backup_advisory_snapshot", comparison_start
        )
        staged_comparison = shadow_wal_production[comparison_start:backup_start]
        for required in (
            "PrivateStagedSqliteCopy::from_owned_maintenance_recovery(&primary)",
            "PrivateStagedSqliteCopy::from_owned_maintenance_recovery(&recovered.owned)",
            "ShadowParityVerifier::compare_staged_copies",
            "ShadowParityResult::Match",
            "ShadowParityResult::Mismatch",
            "ADVISORY_CAPTURE_PARITY_DOMAIN",
        ):
            self.assertIn(required, staged_comparison)
        backup_end = shadow_wal_production.index(
            "pub(crate) async fn recover_owned_maintenance_staging", backup_start
        )
        backup = shadow_wal_production[backup_start:backup_end]
        for required in (
            "fresh_recovery_path()?",
            "CompositeRecoveryCleanup::new",
            ".create_new(true)",
            ".mode(0o600)",
            '.backup("main", &path, None)',
            "OwnedPrivateStagedSqliteCopy::from_recovery_proof",
            "cleanup.disarm()",
        ):
            self.assertIn(required, backup)
        recovery_end = shadow_wal_production.index(
            "pub(crate) async fn recover_owned_wal_owner_staging", backup_end
        )
        maintenance_recovery = shadow_wal_production[backup_end:recovery_end]
        self.assertIn("OwnedExactBackend::Legacy(backend)", maintenance_recovery)
        private_recovery_start = shadow_wal_production.index(
            "async fn recover_owned_private_staging_inner"
        )
        private_recovery_end = shadow_wal_production.index(
            "fn observe_recovery", private_recovery_start
        )
        private_recovery = shadow_wal_production[
            private_recovery_start:private_recovery_end
        ]
        for required in (
            "recover_checkpoint_from_recovery_root",
            "recover_maintenance_zero_wal",
            "recover_witness_nominated_wal",
            "ensure_sqlite_sidecars_absent",
            "OwnedPrivateStagedSqliteCopy::from_recovery_proof",
        ):
            self.assertIn(required, private_recovery)
        for guarded in (replay, continuity, staged_comparison, backup, private_recovery):
            for forbidden in (
                "create_if_absent",
                "list_objects",
                "ImmutableObjectBackend::enumerate",
                "EnumerationPage",
                "EnumerationCursor",
                "delete_exact",
                "delete_object",
                ".put_object(",
            ):
                self.assertNotIn(forbidden, guarded)
            non_iteration_calls = guarded.replace(".iter().enumerate(", "").replace(
                ".into_iter().enumerate(", ""
            )
            self.assertNotIn(".enumerate(", non_iteration_calls)
        wal_recovery_start = shadow_wal_production.index(
            "pub(crate) async fn recover_witness_nominated_wal"
        )
        wal_recovery_end = shadow_wal_production.index(
            "#[cfg(test)]", wal_recovery_start
        ) if "#[cfg(test)]" in shadow_wal_production[wal_recovery_start:] else len(shadow_wal_production)
        wal_recovery = shadow_wal_production[wal_recovery_start:wal_recovery_end]
        for required in (
            "recover_witness_nominated_wal_inner",
            "recover_maintenance_zero_wal",
            "recover_exact_root_wal_mode",
            "load_exact_wal_segment",
            "load_exact_wal_commit_descriptor",
            "load_commit_segments",
            "load_root",
            ".get(&context.object_key())",
        ):
            self.assertIn(required, wal_recovery)
        checkpoint_recovery_start = shadow_checkpoint_production.index(
            "pub async fn recover_checkpoint_from_recovery_root"
        )
        checkpoint_recovery_end = shadow_checkpoint_production.index(
            "pub struct TmpfsCheckpointSink", checkpoint_recovery_start
        )
        checkpoint_recovery = shadow_checkpoint_production[
            checkpoint_recovery_start:checkpoint_recovery_end
        ]
        for required in (
            "recover_checkpoint_from_recovery_root_inner",
            "load_witness_root",
            "load_manifest",
            "load_exact_envelope",
            ".get(&context.object_key())",
        ):
            self.assertIn(required, checkpoint_recovery)
        for guarded in (wal_recovery, checkpoint_recovery):
            for forbidden in (
                "create_if_absent",
                "list_objects",
                "ImmutableObjectBackend::enumerate",
                "EnumerationPage",
                "EnumerationCursor",
                "delete_exact",
                "delete_object",
                ".put_object(",
            ):
                self.assertNotIn(forbidden, guarded)
            non_iteration_calls = guarded.replace(".iter().enumerate(", "").replace(
                ".into_iter().enumerate(", ""
            )
            self.assertNotIn(".enumerate(", non_iteration_calls)
        self.assertIn("async fn compare_captured_prefix(", advisory_production)
        self.assertNotIn(
            "pub(crate) async fn compare_captured_prefix", advisory_production
        )
        self.assertIn("async fn settle_comparison(self)", advisory_production)
        self.assertNotIn(
            "pub(crate) async fn settle_comparison", advisory_production
        )
        settlement_start = advisory_production.index(
            "async fn settle_comparison(self)"
        )
        settlement_end = advisory_production.index(
            "async fn abort_resumed(", settlement_start
        )
        settlement_owner = advisory_production[settlement_start:settlement_end]
        for required in (
            "reauthenticate_boundary(&self).await?",
            "load_advisory_comparison",
            "settle_advisory_comparison",
            "retire_advisory_capture(&settlement)",
            "SettledSingleArchiveAdvisoryOwner",
        ):
            self.assertIn(required, settlement_owner)
        self.assertEqual(
            settlement_owner.count("reauthenticate_boundary(&self).await?"), 3
        )
        first_auth = settlement_owner.index("reauthenticate_boundary(&self).await?")
        load = settlement_owner.index("load_advisory_comparison")
        settle = settlement_owner.index("settle_advisory_comparison")
        second_auth = settlement_owner.index(
            "reauthenticate_boundary(&self).await?", first_auth + 1
        )
        retirement = settlement_owner.index("retire_advisory_capture(&settlement)")
        third_auth = settlement_owner.index(
            "reauthenticate_boundary(&self).await?", second_auth + 1
        )
        self.assertLess(first_auth, load)
        self.assertLess(load, settle)
        self.assertLess(settle, second_auth)
        self.assertLess(second_auth, retirement)
        self.assertLess(retirement, third_auth)
        for forbidden in (
            "acknowledge_result",
            "create_if_absent",
            ".put_object(",
            "list_objects",
            ".enumerate(",
            "delete_exact",
            "delete_object",
            "Store::new",
            ".with_user(",
            "tokio::spawn",
            "std::env::",
        ):
            self.assertNotIn(forbidden, settlement_owner)
        abort_owner_start = advisory_production.index("async fn abort_resumed(")
        abort_owned_start = advisory_production.index(
            "async fn abort_resumed_owned(", abort_owner_start
        )
        abort_owner_end = advisory_production.index(
            "fn map_advisory_store_error", abort_owned_start
        )
        abort_wrapper = advisory_production[abort_owner_start:abort_owned_start]
        abort_owner = advisory_production[abort_owned_start:abort_owner_end]
        self.assertIn("tokio::spawn(async move", abort_wrapper)
        self.assertIn("self.abort_resumed_owned(reason).await", abort_wrapper)
        self.assertEqual(abort_wrapper.count("tokio::spawn(async move"), 1)
        for required in (
            "reauthenticate_boundary(&self).await?",
            "load_advisory_abort",
            "prepare_advisory_abort",
            "retire_advisory_capture_for_abort(&prepared)",
            "finalize_advisory_abort",
            "AbortedSingleArchiveAdvisoryOwner",
            "Err(AdvisoryOwnerError::Publication)",
            "Err(AdvisoryOwnerError::Persistence)",
        ):
            self.assertIn(required, abort_owner)
        self.assertEqual(
            abort_owner.count(
                "tokio::time::sleep(std::time::Duration::from_millis(100)).await"
            ),
            2,
        )
        self.assertEqual(abort_owner.count("reauthenticate_boundary(&self).await?"), 2)
        abort_first_auth = abort_owner.index("reauthenticate_boundary(&self).await?")
        abort_load = abort_owner.index("load_advisory_abort")
        abort_prepare = abort_owner.index("prepare_advisory_abort")
        abort_retire = abort_owner.index("retire_advisory_capture_for_abort(&prepared)")
        abort_finalize = abort_owner.index("finalize_advisory_abort")
        abort_last_auth = abort_owner.index(
            "reauthenticate_boundary(&self).await?", abort_first_auth + 1
        )
        self.assertLess(abort_first_auth, abort_load)
        self.assertLess(abort_load, abort_prepare)
        self.assertLess(abort_prepare, abort_retire)
        self.assertLess(abort_retire, abort_finalize)
        self.assertLess(abort_finalize, abort_last_auth)
        for forbidden in (
            "acknowledge_result",
            "create_if_absent",
            ".put_object(",
            "list_objects",
            ".enumerate(",
            "delete_exact",
            "delete_object",
            "Store::new",
            ".with_user(",
            "std::env::",
        ):
            self.assertNotIn(forbidden, abort_owner)

        released_abort_start = advisory_production.index(
            "async fn abort_before_local_resume("
        ) if "async fn abort_before_local_resume(" in advisory_production else advisory_production.index(
            "pub(super) async fn abort_before_local_resume("
        )
        released_abort_end = advisory_production.index(
            "impl LocallyResumedSingleArchiveAdvisoryOwner", released_abort_start
        )
        released_abort_owner = advisory_production[
            released_abort_start:released_abort_end
        ]
        for required in (
            "tokio::spawn(async move",
            "self.reauthenticate_boundary().await?",
            "preflight_released_advisory_abort(&release, lifecycle)",
            "prepare_released_advisory_abort(",
            "restore_released_advisory_local_admission_without_capture",
            "finalize_released_advisory_abort(",
            "AdvisoryAbortLocus::ReleasedBeforeResume",
            "AdvisoryAbortReason::StopRequested",
            "Err(AdvisoryOwnerError::Persistence)",
        ):
            self.assertIn(required, released_abort_owner)
        released_preflight = released_abort_owner.index(
            "preflight_released_advisory_abort"
        )
        released_prepare = released_abort_owner.index(
            "prepare_released_advisory_abort"
        )
        released_restore = released_abort_owner.index(
            "restore_released_advisory_local_admission_without_capture"
        )
        released_finalize = released_abort_owner.index(
            "finalize_released_advisory_abort"
        )
        self.assertLess(released_preflight, released_prepare)
        self.assertLess(released_prepare, released_restore)
        self.assertLess(released_restore, released_finalize)
        self.assertEqual(
            released_abort_owner.count("Err(AdvisoryOwnerError::Persistence)"),
            2,
        )
        prepare_retry = released_abort_owner.rfind(
            "let prepared = loop", 0, released_restore
        )
        prepare_persistence = released_abort_owner.index(
            "Err(AdvisoryOwnerError::Persistence)", released_prepare
        )
        self.assertLess(prepare_retry, released_prepare)
        self.assertLess(released_prepare, prepare_persistence)
        self.assertLess(prepare_persistence, released_restore)
        finalize_retry = released_abort_owner.rfind(
            "let terminal = loop", released_restore, released_finalize
        )
        finalize_persistence = released_abort_owner.index(
            "Err(AdvisoryOwnerError::Persistence)", released_finalize
        )
        self.assertLess(finalize_retry, released_finalize)
        self.assertLess(released_finalize, finalize_persistence)
        for forbidden in (
            "acknowledge_result",
            "create_if_absent",
            ".put_object(",
            "list_objects",
            ".enumerate(",
            "delete_exact",
            "delete_object",
            "Store::new",
            ".with_user(",
            "std::env::",
        ):
            self.assertNotIn(forbidden, released_abort_owner)

        released_preflight_start = store_production.index(
            "pub(crate) async fn preflight_released_advisory_abort"
        )
        released_restore_start = store_production.index(
            "pub(crate) async fn restore_released_advisory_local_admission_without_capture",
            released_preflight_start,
        )
        released_store_end = store_production.index(
            "fn exact_marker_name_and_stage", released_restore_start
        )
        released_preflight_store = store_production[
            released_preflight_start:released_restore_start
        ]
        released_restore_store = store_production[
            released_restore_start:released_store_end
        ]
        for required in (
            "!registry_blocked",
            "!content_blocked",
            "registry.open_users.contains_key",
            "active_writes",
            "selection.is_some()",
            "StoreReleasedAbortAdmission",
            "_lifecycle_guard: lifecycle_guard",
        ):
            self.assertIn(required, released_preflight_store)
        for required in (
            "AdvisoryAbortLocus::ReleasedBeforeResume",
            "registry_blocked != content_blocked",
            "registry.blocked_users.remove",
            "barrier.blocked_users.remove",
            "content_write_barrier.changed.notify_waiters",
            "registry_changed.notify_waiters",
            "StoreReleasedAbortRestored",
            "_lifecycle_guard: lifecycle_guard",
        ):
            self.assertIn(required, released_restore_store)
        for forbidden in (
            "StoreShadowCapture::",
            "*selection =",
            ".register(",
            "open_db(",
            ".with_user(",
            "create_if_absent",
            ".put_object(",
            ".enumerate(",
            "delete_object",
            "acknowledge_result",
        ):
            self.assertNotIn(forbidden, released_preflight_store + released_restore_store)
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS archive_v3_advisory_comparisons",
            control,
        )
        self.assertIn("fn load_advisory_comparison_conn", control)
        self.assertIn("fn settle_advisory_comparison_conn", control)
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS archive_v3_advisory_aborts", control
        )
        self.assertIn(
            "locus TEXT NOT NULL DEFAULT 'resumed_capture'", control
        )
        self.assertIn("fn migrate_advisory_abort_locus", control_production)
        self.assertNotIn("archive_v3_advisory_release_aborts", control)
        self.assertIn("fn load_advisory_abort_conn", control)
        self.assertIn("fn prepare_advisory_abort_conn", control)
        self.assertIn("fn finalize_advisory_abort_conn", control)
        abort_load_start = control_production.index(
            "fn load_optional_advisory_abort_conn"
        )
        abort_load_end = control_production.index(
            "fn prepare_advisory_abort_conn", abort_load_start
        )
        abort_load = control_production[abort_load_start:abort_load_end]
        self.assertIn("archive_v3_advisory_comparisons", abort_load)
        self.assertIn("load_advisory_comparison_conn(conn, archive_id)", abort_load)
        self.assertIn(
            "advisory comparison conflicts with retained abort", abort_load
        )
        abort_exists = abort_load.index("archive_v3_advisory_aborts")
        abort_none = abort_load.index("return Ok(None)")
        comparison_exists = abort_load.index("archive_v3_advisory_comparisons")
        self.assertLess(abort_exists, abort_none)
        self.assertLess(abort_none, comparison_exists)
        self.assertIn(
            "advisory abort permanently fenced comparison settlement", control
        )
        self.assertIn("advisory comparison permanently fenced abort", control)
        self.assertIn("load_optional_advisory_release_conn(&tx, owner)", control)
        self.assertIn("load_advisory_comparison_conn(&tx", control)
        self.assertIn("async fn compare_captured_prefix(", comparison_production)
        self.assertNotIn("pub fn", comparison_production)
        self.assertIn(
            "pub(crate) struct AdvisoryComparisonEvidence", comparison_production
        )
        self.assertIn(
            "pub(crate) struct AdvisoryComparisonSettlement", comparison_production
        )
        self.assertIn(
            "ADVISORY_COMPARISON_SETTLEMENT_DOMAIN", comparison_production
        )
        self.assertIn("fn from_evidence_for_control", comparison_production)
        self.assertIn("fn from_control", comparison_production)
        self.assertIn("fn control_view", comparison_production)
        self.assertIn("fn authenticate_store_target", comparison_production)
        self.assertIn("StoreAdvisoryRetirementContext", comparison_production)
        self.assertNotIn("pub(crate) fn new", comparison_production)
        self.assertNotIn("pub(crate) fn commitment", comparison_production)
        self.assertIn("reauthenticate_boundary(owner).await?", comparison_production)
        self.assertEqual(
            comparison_production.count("reauthenticate_boundary(owner).await?"),
            2,
        )
        self.assertIn("recover_advisory_comparison_staging", comparison_production)
        self.assertIn("compare_recovered_advisory", comparison_production)
        self.assertIn("AdvisoryComparisonEvidence", comparison_production)
        for forbidden in (
            "create_if_absent",
            ".put_object(",
            "list_objects",
            "delete_exact",
            "delete_object",
            "Store::new",
            ".with_user(",
            "acknowledge_result",
            "tokio::spawn",
            "std::env::",
        ):
            self.assertNotIn(forbidden, comparison_production)
        for required in (
            'b"kioku/archive-v3/advisory-resumed-abort/v1\\0"',
            'b"kioku/archive-v3/advisory-released-before-resume-abort/v1\\0"',
            "pub(crate) enum AdvisoryAbortLocus",
            "pub(crate) enum AdvisoryAbortReason",
            "pub(crate) enum AdvisoryAbortStage",
            "pub(crate) struct AdvisoryAbortTerminal",
            "fn prepared_for_control",
            "fn prepared_released_for_control",
            "fn aborted_for_control",
            "fn aborted_released_for_control",
            "fn from_control",
            "fn authenticate_store_target",
        ):
            self.assertIn(required, abort_production)
        for forbidden in (
            "Serialize",
            "Deserialize",
            "create_if_absent",
            ".put_object(",
            "list_objects",
            ".enumerate(",
            "delete_exact",
            "delete_object",
            "Store::new",
            ".with_user(",
            "acknowledge_result",
            "tokio::spawn",
            "std::env::",
        ):
            self.assertNotIn(forbidden, abort_production)
        self.assertIn(
            "#[derive(PartialEq, Eq)]\npub(crate) struct AdvisoryAbortTerminal",
            abort_production,
        )
        released_proof_start = store_production.index(
            "/// Read-only admission for stopping one exact released advisory owner"
        )
        released_proof_end = store_production.index(
            "impl StoreAdvisoryCaptureRetired", released_proof_start
        )
        released_proofs = store_production[released_proof_start:released_proof_end]
        for required in (
            "pub(crate) struct StoreReleasedAbortAdmission",
            "pub(crate) struct StoreReleasedAbortRestored",
            "_lifecycle_guard: OwnedMutexGuard<()>",
        ):
            self.assertIn(required, released_proofs)
        for forbidden in ("derive(Clone", "derive(Copy", "Serialize", "Deserialize"):
            self.assertNotIn(forbidden, released_proofs)
        self.assertIn(
            'b"kioku/archive-v3/advisory-released-abort-admission/v1\\0"',
            store_production,
        )
        self.assertIn(
            'b"kioku/archive-v3/advisory-abort-local-absence/v1\\0"',
            store_production,
        )

        released_prepare_start = control_production.index(
            "fn prepare_released_advisory_abort_conn"
        )
        released_finalize_start = control_production.index(
            "fn finalize_released_advisory_abort_conn", released_prepare_start
        )
        released_finalize_end = control_production.index(
            "fn finalize_advisory_abort_recovery_conn", released_prepare_start
        )
        released_prepare_control = control_production[
            released_prepare_start:released_finalize_start
        ]
        released_control = control_production[
            released_prepare_start:released_finalize_end
        ]
        for required in (
            "prepared_released_for_control",
            "load_advisory_abort_recovery_conn(&tx",
            "aborted_released_for_control",
            "locus=?10",
            "prepared_view.locus.as_db()",
            "released advisory abort final readback changed",
        ):
            self.assertIn(required, released_control)
        self.assertGreaterEqual(
            released_prepare_control.count("load_advisory_abort_recovery_conn(&tx"),
            2,
        )
        self.assertGreaterEqual(
            released_prepare_control.count("AdvisoryAbortRecoveryState::Prepared"),
            2,
        )
        retained_recovery = released_prepare_control.index(
            "released advisory abort retained recovery changed"
        )
        retained_exact = released_prepare_control.index(
            "retained.terminal_for_control(token) != &expected"
        )
        retained_commit = released_prepare_control.index("tx.commit()?", retained_exact)
        self.assertLess(retained_recovery, retained_exact)
        self.assertLess(retained_exact, retained_commit)
        for required in (
            "pub(crate) struct PreparedAdvisoryAbortRecovery",
            "pub(crate) enum AdvisoryAbortRecoveryState",
            "fn aborted_from_recovery_for_control",
            'b"kioku/archive-v3/advisory-abort-absent-user/v1\\0"',
            'b"kioku/archive-v3/advisory-abort-local-absence/v1\\0"',
        ):
            self.assertIn(required, abort_production + store_production)
        prepared_recovery_start = abort_production.index(
            "/// Opaque restart capability reconstructed only by encrypted Control"
        )
        prepared_recovery_end = abort_production.index(
            "pub(crate) enum AdvisoryAbortRecoveryState", prepared_recovery_start
        )
        prepared_recovery_definition = abort_production[
            prepared_recovery_start:prepared_recovery_end
        ]
        for forbidden in ("derive(Clone", "derive(Copy", "Serialize", "Deserialize"):
            self.assertNotIn(forbidden, prepared_recovery_definition)
        for required in (
            "load_advisory_abort_recovery",
            "prove_prepared_advisory_abort_local_absence(&recovery)",
            "finalize_advisory_abort_recovery",
            "tokio::spawn(async move",
            "Err(AdvisoryOwnerError::Persistence)",
            "Err(AdvisoryOwnerError::Publication)",
        ):
            self.assertIn(required, abort_reconcile_production)
        recovery_load = abort_reconcile_production.index(
            "load_advisory_abort_recovery"
        )
        recovery_absence = abort_reconcile_production.index(
            "prove_prepared_advisory_abort_local_absence(&recovery)"
        )
        recovery_finalize = abort_reconcile_production.index(
            "finalize_advisory_abort_recovery"
        )
        self.assertLess(recovery_load, recovery_absence)
        self.assertLess(recovery_absence, recovery_finalize)
        for forbidden in (
            "Store::new",
            ".with_user(",
            "open_db(",
            "create_if_absent",
            ".put_object(",
            "list_objects",
            ".enumerate(",
            "delete_exact",
            "delete_object",
            "acknowledge_result",
            "std::env::",
        ):
            self.assertNotIn(forbidden, abort_reconcile_production)

        absence_start = store_production.index(
            "pub(crate) async fn prove_prepared_advisory_abort_local_absence"
        )
        absence_end = store_production.index(
            "async fn retire_advisory_capture_owned", absence_start
        )
        absence_worker = store_production[absence_start:absence_end]
        for required in (
            "lock_user_lifecycle(&user_id).await?",
            "let registry = self.registry.lock().await",
            "content_write_barrier",
            "blocked_users.contains(&user_id)",
            "active_writes.get(&user_id)",
            "selection.is_some()",
            "open.status == OpenStatus::Open",
            "handle._shadow_capture_registration.is_some()",
            "StorePreparedAdvisoryAbortAbsent",
            "_lifecycle_guard: lifecycle_guard",
        ):
            self.assertIn(required, absence_worker)
        absence_proof_start = store_production.index(
            "/// Opaque proof that the controller-owned Store has no process-local capture"
        )
        absence_proof_end = store_production.index(
            "impl StoreAdvisoryCaptureRetired", absence_proof_start
        )
        absence_proof_definition = store_production[
            absence_proof_start:absence_proof_end
        ]
        self.assertIn(
            "pub(crate) struct StorePreparedAdvisoryAbortAbsent",
            absence_proof_definition,
        )
        self.assertIn(
            "_lifecycle_guard: OwnedMutexGuard<()>", absence_proof_definition
        )
        for forbidden in ("derive(Clone", "derive(Copy", "Serialize", "Deserialize"):
            self.assertNotIn(forbidden, absence_proof_definition)
        self.assertLess(
            absence_worker.index("lock_user_lifecycle(&user_id).await?"),
            absence_worker.index("let registry = self.registry.lock().await"),
        )
        for forbidden in (
            "Store::new",
            ".with_user(",
            "open_db(",
            "*selection =",
            ".take()",
            "blocked_users.remove",
            "notify_waiters",
            ".register(",
            "create_if_absent",
            ".put_object(",
            ".enumerate(",
            "delete_object",
            "acknowledge_result",
        ):
            self.assertNotIn(forbidden, absence_worker)

        recovery_control_start = control_production.index(
            "fn load_advisory_abort_recovery_conn"
        )
        recovery_control_end = control_production.index(
            "fn prepare_advisory_abort_conn", recovery_control_start
        )
        recovery_control = control_production[
            recovery_control_start:recovery_control_end
        ]
        for required in (
            "load_advisory_abort_conn(conn, archive_id)",
            "load_advisory_comparison_conn(conn, archive_id)",
            "load_retained_advisory_owner_conn(conn, operation_id)",
            "load_advisory_canary_capability_conn(conn, operation_id)",
            "load_advisory_canary_scope_conn(conn, &canary, expected)",
            "load_advisory_activation_preconditions_conn(",
            "AdvisoryOwnerReservation::new_for_control(",
            "scope.consumed != Some((owner_id, initial_commitment))",
            "preconditions.consumed != Some((owner_id, initial_commitment))",
            "archive_v3_maintenance_imports",
            "JOIN archive_bindings",
            "i.stage='parity_verified'",
            "b.state='active_legacy'",
            "PreparedAdvisoryAbortRecovery::from_control",
        ):
            self.assertIn(required, recovery_control)
        recovery_finalize_start = control_production.index(
            "fn finalize_advisory_abort_recovery_conn"
        )
        recovery_finalize_end = control_production.index(
            "fn map_wal_persistence_error", recovery_finalize_start
        )
        recovery_finalize_control = control_production[
            recovery_finalize_start:recovery_finalize_end
        ]
        for required in (
            "load_advisory_abort_recovery_conn(&tx",
            "stage='prepared'",
            "retirement_commitment IS NULL",
            "locus=?10 AND reason=?11",
            "commitment=?12 AND revision=1",
            "AdvisoryAbortRecoveryState::Aborted(loaded)",
            "tx.commit()?",
        ):
            self.assertIn(required, recovery_finalize_control)
        self.assertGreaterEqual(
            recovery_finalize_control.count("load_advisory_abort_recovery_conn(&tx"),
            2,
        )
        for active_parent in (main, query, store_production, maintenance_production):
            self.assertNotIn("settle_comparison(", active_parent)
            self.assertNotIn("settle_advisory_comparison(", active_parent)
            self.assertNotIn("reconcile_prepared_abort(", active_parent)
        for active_parent in (main, query, maintenance_production):
            self.assertNotIn("abort_resumed(", active_parent)
            self.assertNotIn("prepare_advisory_abort(", active_parent)
        self.assertEqual(
            advisory_production.count(".retire_advisory_capture(&settlement)"),
            1,
        )
        for active_parent in (main, query, maintenance_production):
            self.assertNotIn("retire_advisory_capture(", active_parent)
        self.assertEqual(
            maintenance_production.count(
                ".ensure_advisory_release_absent(operation_id)"
            ),
            2,
        )
        self.assertIn(
            "advisory release permanently fenced maintenance re-entry", control
        )
        run_start = maintenance_production.index("async fn run_owned(")
        run_end = maintenance_production.index(
            "fn from_terminal(", run_start
        )
        run_owned = maintenance_production[run_start:run_end]
        admission = run_owned.index(".acquire_archive_maintenance_admission(")
        final_release_check = run_owned.index(
            ".ensure_advisory_release_absent(operation_id)", admission
        )
        close_admission = run_owned.index("admission.begin().await", admission)
        self.assertLess(admission, final_release_check)
        self.assertLess(final_release_check, close_admission)
        for forbidden in (
            "list_",
            ".delete_object(",
            ".put_object(",
            ".with_user(",
            "blocked_users.remove",
            "content_write_barrier.changed.notify",
            "release_open_registration",
            "CaptureRegistration",
            "CaptureRegistry",
            "StoreShadowCapture",
            "tokio::spawn",
            "std::env::",
            "acknowledge_result",
        ):
            self.assertNotIn(forbidden, provider_executor)
        advisory_without_owned_abort_spawn = advisory_production.replace(
            "tokio::spawn(async move { self.abort_resumed_owned(reason).await })", ""
        ).replace(
            "tokio::spawn(async move { self.abort_before_local_resume_owned(reason).await })",
            "",
        )
        for forbidden in (
            "StoreShadowCapture",
            ".with_user(",
            ".with_user_mut(",
            ".save_user(",
            "CaptureRegistration",
            "CaptureRegistry",
            "create_if_absent(",
            "list_objects",
            "delete_exact",
            "delete_object(",
            "delete_object_generation(",
            "identity_write_fence_authority(",
            "tokio::spawn",
            "std::env::",
            "acknowledge_result(",
            "advance_root",
            "RootAdvance",
        ):
            self.assertNotIn(forbidden, advisory_without_owned_abort_spawn)

        controller_src = (
            ROOT / "src/archive_v3_advisory_owner/controller.rs"
        ).read_text(encoding="utf-8")
        controller_production = without_cfg_test_items(controller_src)
        window_src = (
            ROOT / "src/archive_v3_advisory_owner/window.rs"
        ).read_text(encoding="utf-8")
        window_production = without_cfg_test_items(window_src)
        telemetry_src = (
            ROOT / "src/archive_v3_advisory_owner/telemetry.rs"
        ).read_text(encoding="utf-8")
        telemetry_production = without_cfg_test_items(telemetry_src)
        maintenance_src = (
            ROOT / "src/archive_v3_maintenance_import.rs"
        ).read_text(encoding="utf-8")
        maintenance_production = without_cfg_test_items(maintenance_src)
        store_src = (
            ROOT / "src/store.rs"
        ).read_text(encoding="utf-8")
        store_production = without_cfg_test_items(store_src)
        control_store_src = (
            ROOT / "src/cp/control_store.rs"
        ).read_text(encoding="utf-8")
        control_store_production = without_cfg_test_items(control_store_src)

        # Controller encapsulation and ordering
        self.assertIn("struct SingleArchivePhase1AdvisoryController", controller_production)
        self.assertNotIn("pub(crate) struct SingleArchivePhase1AdvisoryController", controller_production)
        self.assertNotIn("pub struct SingleArchivePhase1AdvisoryController", controller_production)
        self.assertNotIn("SingleArchivePhase1AdvisoryController", main)
        self.assertNotIn("SingleArchivePhase1AdvisoryController", query)

        # P1: Preflight consuming token, bounded geometry observation without full-file read
        self.assertIn("observe_source_database_bytes", store_production)
        self.assertIn("PRAGMA page_count", store_production)
        self.assertIn("PRAGMA page_size", store_production)
        self.assertNotIn("tokio::fs::read", store_production.split("fn observe_source_database_bytes")[1].split("fn ")[0])

        preflight_idx = controller_production.index("importer.preflight().await")
        eval_policy_idx = controller_production.index("Phase1TmpfsPolicyV1::evaluate(database_bytes, vm_bytes)")
        advance_eligible_idx = controller_production.index("advance_advisory_controller_eligible")
        import_run_idx = controller_production.index("preflighted.run().await")
        self.assertLess(preflight_idx, eval_policy_idx)
        self.assertLess(eval_policy_idx, advance_eligible_idx)
        self.assertLess(advance_eligible_idx, import_run_idx)

        # P1: Exact fence authority required on pre-owner abort; no reason strings passed
        self.assertIn("&plan_fence_authority", controller_production)
        self.assertNotIn('abort_pre_owner(user_id, archive_id, operation_id, "window_lost")', controller_production)
        self.assertNotIn('abort_pre_owner(user_id, archive_id, operation_id, "auth_failed")', controller_production)
        self.assertNotIn('abort_pre_owner(user_id, archive_id, operation_id, "auth_mismatch")', controller_production)
        self.assertNotIn('abort_pre_owner(user_id, archive_id, operation_id, "missing_auth")', controller_production)
        self.assertNotIn('abort_pre_owner(user_id, archive_id, operation_id, "owner_start_failed")', controller_production)

        # P1: Restart reconciliation checks inner comparison / abort state
        self.assertIn("load_retained_advisory_comparison_exact", controller_production)
        self.assertIn("load_retained_advisory_abort_exact", controller_production)
        self.assertIn("record.user_id != user_id", controller_production)

        # P1: Strict loaders in control store CAS and replay branches
        self.assertIn("maintenance_import_record_conn", control_store_production)
        self.assertIn("authenticate_canary_scope_conn", control_store_production)
        self.assertIn("authenticate_advisory_owner_conn", control_store_production)
        self.assertIn("load_advisory_release_conn", control_store_production)
        self.assertIn("load_advisory_comparison_conn", control_store_production)

        # P1: Typed comparison settlement
        self.assertIn("enum AdvisorySettlementOutcome", ROOT.joinpath("src/archive_v3_advisory_owner.rs").read_text(encoding="utf-8"))
        self.assertIn("super::AdvisorySettlementOutcome::Settled(settlement)", controller_production)
        self.assertIn("super::AdvisorySettlementOutcome::Aborted(aborted)", controller_production)

        # P2: Unforgeable window proof
        self.assertIn("verify_revalidation_proof", controller_production)
        self.assertIn("struct VerifiedWindowRevalidation", window_production)
        self.assertNotIn("pub(crate) fn new(", window_production.split("struct VerifiedWindowRevalidation")[1].split("impl")[0] if "impl" in window_production.split("struct VerifiedWindowRevalidation")[1] else "")
        self.assertIn("struct HeldPhase1Window", window_production)
        for forbidden in ("derive(Clone", "derive(Copy", "Serialize", "Deserialize"):
            self.assertNotIn(forbidden, window_production)

        # P2: Policy commitment bound to DB_COPY_MULTIPLIER and VM_FRACTION_DENOMINATOR
        self.assertIn("DB_COPY_MULTIPLIER", controller_production)
        self.assertIn("VM_FRACTION_DENOMINATOR", controller_production)
        self.assertIn("compute_phase1_policy_commitment", control_store_production)
        self.assertIn("policy_commitment", control_store_production)

        # Telemetry panic isolation and bounding
        self.assertIn("catch_unwind", telemetry_production)
        self.assertIn("try_send", telemetry_production)
        self.assertIn("MAX_TELEMETRY_QUEUE_CAPACITY: usize = 256", telemetry_production)


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
