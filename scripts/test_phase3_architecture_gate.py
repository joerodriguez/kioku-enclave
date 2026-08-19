#!/usr/bin/env python3
"""ADR-0022 Phase 3 static architecture gate.

Token-level structural enforcement over comment/literal-blanked, cfg(test)-stripped
production source, using the shared self-tested Rust sanitizer from
``test_wal_idempotency_gate``. Two views of every file are used:

- ``prod_code``: production-only source with comments and string literals blanked, so
  a required or banned token can never be satisfied or hidden by a comment, string, or
  test module;
- ``prod_raw``: production-only source with literals intact, used only for SQL-shape
  assertions that must inspect string contents, always scoped to one brace-matched
  function or statement region first.

Enforced invariants:
1. Witness sealing: ``RootAdvance::new`` remains ``#[cfg(test)]`` and has no production
   caller anywhere in ``src/``; the extent VFS contains no witness symbols at all.
2. Commit-protocol authority: the witness stages are enterable only through the sealed
   ``WitnessSendAuthority``/``WitnessObservedEvidence`` tokens whose only constructors
   are ``#[cfg(test)]``; the stage enum is pinned exactly; the CAS UPDATE carries the
   full tuple predicate inside ``transition_attempt`` itself.
3. Shadow-only VFS: non-main file classes are refused; no parent-file I/O surface
   exists; no ``std::env`` reads; commits terminate at ``mark_shadow_settled``.
4. Backend authority: none of the Phase 3 files can call ``delete_exact`` or backend
   ``enumerate`` (Rust iterator ``.enumerate()`` is distinguished by its empty
   argument list).
5. Inactive wiring: every ``src/**/*.rs`` outside the Phase 3 files references no
   Phase 3 entry symbol in production code, and ``src/main.rs`` declares the modules
   without invoking them.
6. File-specific honesty checks for the WAL converter, vector accelerator, and shadow
   comparator (fail-closed posture, renamed non-cryptographic naming, fixed private
   staging, read-only enforcement).
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_wal_idempotency_gate import (  # noqa: E402
    match_delimiter,
    sanitize_rust,
    without_cfg_test_items,
)

PHASE3_FILES = [
    "src/archive_v3_extent.rs",
    "src/archive_v3_extent_commit.rs",
    "src/archive_v3_extent_vfs.rs",
    "src/archive_v3_extent_vfs/cache.rs",
    "src/archive_v3_extent_shadow.rs",
    "src/archive_v3_wal_to_extent.rs",
    "src/archive_v3_vector_accelerator.rs",
]

PHASE3_ENTRY_SYMBOLS = [
    "RegisteredExtentVfs",
    "ExtentCommitCoordinator",
    "SqliteExtentAttemptLedger",
    "ExtentAttemptLedger",
    "DurableExtentStaging",
    "ExtentShadowCoordinator",
    "VectorSearchAccelerator",
    "convert_wal_stream_to_extent_tree",
    "ChecksumValidatedWalIndex",
    "search_vectors_fail_closed",
]

ALLOWED_REFERENCING_FILES = set(PHASE3_FILES) | {
    "src/archive_v3_phase3_gates.rs",  # cfg(test)-gated gate suite
    "src/main.rs",  # module declarations only, asserted separately
}


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def prod_views(path: str) -> tuple[str, str]:
    """(prod_raw, prod_code) for one file."""
    raw = without_cfg_test_items(read(path))
    return raw, sanitize_rust(raw)


def fn_region(raw: str, code: str, fn_name: str) -> tuple[str, str]:
    """Brace-matched body region of the first `fn <name>` DEFINITION (trait
    declarations, whose signatures end in `;` before any `{`, are skipped)."""
    for match in re.finditer(rf"\bfn\s+{re.escape(fn_name)}\b", code):
        brace = code.find("{", match.end())
        semi = code.find(";", match.end())
        if brace == -1:
            continue
        if semi != -1 and semi < brace:
            continue  # bodyless trait declaration
        end = match_delimiter(code, brace, "{", "}")
        return raw[match.start() : end], code[match.start() : end]
    raise AssertionError(f"function definition {fn_name} not found in production code")


def banned_enumerate_calls(code: str) -> list[str]:
    """Every `.enumerate(` call whose argument list is non-empty (backend calls take
    arguments; the Rust iterator adaptor takes none)."""
    hits = []
    for match in re.finditer(r"\.enumerate\s*\(", code):
        after = code[match.end() :]
        stripped = after.lstrip()
        if not stripped.startswith(")"):
            hits.append(code[max(0, match.start() - 40) : match.end() + 20])
    return hits


class Phase3ArchitectureGateTest(unittest.TestCase):
    maxDiff = None

    # ---- 1. Witness sealing -------------------------------------------------

    def test_root_advance_new_is_test_only_and_uncalled_in_production(self):
        witness_raw = read("src/archive_v3_witness.rs")
        witness_code = sanitize_rust(witness_raw)
        # The raw constructor inside `impl RootAdvance` is cfg(test)-gated: the
        # attribute must immediately precede it.
        impl_match = re.search(r"impl\s+RootAdvance\s*\{", witness_code)
        self.assertIsNotNone(impl_match, "impl RootAdvance missing")
        impl_end = match_delimiter(witness_code, witness_code.find("{", impl_match.start()), "{", "}")
        impl_code = witness_code[impl_match.start() : impl_end]
        new_match = re.search(
            r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*pub\(crate\)\s+const\s+fn\s+new\s*\(",
            impl_code,
        )
        self.assertIsNotNone(
            new_match,
            "RootAdvance::new must be #[cfg(test)]; production advances go through "
            "authenticated constructors only",
        )
        # No production call site anywhere in src/.
        for path in sorted((ROOT / "src").rglob("*.rs")):
            rel = str(path.relative_to(ROOT))
            _, code = prod_views(rel)
            self.assertNotIn(
                "RootAdvance::new(",
                code,
                f"{rel}: production code must not construct RootAdvance directly",
            )

    def test_extent_vfs_contains_no_witness_surface(self):
        _, code = prod_views("src/archive_v3_extent_vfs.rs")
        for banned in [
            "RootAdvance",
            "RealWitnessPublisher",
            "ExtentWitnessPublisher",
            "compare_and_advance_root",
            "RootCommitment",
            "WitnessLease",
            "mark_witness_send_started",
            "mark_witness_advanced",
            "mark_published",
            "ShadowSessionBinding",
        ]:
            self.assertNotIn(banned, code, f"extent VFS must not reference {banned}")
        self.assertIn("mark_shadow_settled", code, "VFS commits terminate at ShadowSettled")

    # ---- 2. Commit protocol -------------------------------------------------

    def test_stage_enum_is_pinned_exactly(self):
        _, code = prod_views("src/archive_v3_extent_commit.rs")
        enum_match = re.search(r"pub\s+enum\s+ExtentCommitStage\s*\{", code)
        self.assertIsNotNone(enum_match)
        end = match_delimiter(code, code.find("{", enum_match.start()), "{", "}")
        body = code[enum_match.start() : end]
        expected = [
            ("Prepared", 1),
            ("ObjectsStaged", 2),
            ("CandidateReady", 3),
            ("WitnessSendStarted", 4),
            ("WitnessAdvanced", 5),
            ("Published", 6),
            ("ShadowSettled", 7),
            ("AbortedPreWitness", 8),
        ]
        for name, value in expected:
            self.assertIsNotNone(
                re.search(rf"\b{name}\s*=\s*{value}\s*,", body),
                f"stage {name} must be pinned to {value}",
            )
        found = re.findall(r"\b([A-Z][A-Za-z]*)\s*=\s*\d+\s*,", body)
        self.assertEqual(
            found,
            [name for name, _ in expected],
            "stage enum must contain exactly the eight pinned variants in order",
        )

    def test_witness_stage_tokens_have_no_production_constructor(self):
        raw, code = prod_views("src/archive_v3_extent_commit.rs")
        self.assertIn("pub struct WitnessSendAuthority", code)
        self.assertIn("pub struct WitnessObservedEvidence", code)
        # The only constructors are cfg(test) mints, which the production view blanks.
        self.assertNotIn("mint_for_test", code)
        for token in ["WitnessSendAuthority", "WitnessObservedEvidence"]:
            self.assertIsNone(
                re.search(rf"->\s*{token}\b", code),
                f"no production function may return {token}",
            )
            self.assertIsNone(
                re.search(rf"->\s*Result<\s*{token}\b", code),
                f"no production function may return Result<{token}>",
            )
        # No production Default impl or struct-literal construction may exist for the
        # sealed tokens; the only permitted occurrences of `Token {` are the struct
        # declaration and inherent/trait impl headers.
        for token in ["WitnessSendAuthority", "WitnessObservedEvidence"]:
            self.assertIsNone(
                re.search(rf"impl\s+Default\s+for\s+{token}\b", code),
                f"{token} must not be Default-constructible in production",
            )
            for match in re.finditer(rf"\b{token}\s*\{{", code):
                prefix = code[max(0, match.start() - 24) : match.start()]
                self.assertIsNotNone(
                    re.search(r"(struct|impl|for)\s+$", prefix),
                    f"production struct-literal construction of {token} is banned",
                )
        self.assertIsNone(
            re.search(r"Self\s*\{\s*_private", code),
            "production code must not literal-construct the sealed send authority",
        )
        self.assertIsNone(
            re.search(r"Self\s*\{\s*observed_commitment", code),
            "production code must not literal-construct sealed observed evidence",
        )
        # The coordinator entrypoints demand the sealed types by signature.
        self.assertIsNotNone(
            re.search(
                r"fn\s+mark_witness_send_started\s*\(\s*&mut\s+self\s*,\s*_authority\s*:\s*WitnessSendAuthority",
                code,
            ),
            "mark_witness_send_started must consume WitnessSendAuthority",
        )
        self.assertIsNotNone(
            re.search(
                r"fn\s+mark_witness_advanced\s*\(\s*&mut\s+self\s*,\s*evidence\s*:\s*WitnessObservedEvidence",
                code,
            ),
            "mark_witness_advanced must consume WitnessObservedEvidence",
        )

    def test_full_tuple_cas_lives_inside_transition_attempt(self):
        raw, code = prod_views("src/archive_v3_extent_commit.rs")
        fn_raw, fn_code = fn_region(raw, code, "transition_attempt")
        for clause in [
            "WHERE attempt_id = ?",
            "AND stage = ?",
            "AND monotonic_revision = ?",
            "AND row_commitment = ?",
        ]:
            self.assertIn(clause, fn_raw, f"CAS UPDATE must carry `{clause}`")
        self.assertIn("rows_affected != 1", fn_code)
        # Exact same-transaction readback: the reload and comparison occur before
        # commit within this function.
        self.assertIn("tx.commit()", fn_code)
        self.assertLess(
            fn_code.index("reloaded"),
            fn_code.rindex("tx.commit()"),
            "exact readback must precede commit",
        )

    def test_schema_ddl_shape(self):
        raw, code = prod_views("src/archive_v3_extent_commit.rs")
        fn_raw, _ = fn_region(raw, code, "new")
        for fragment in [
            "_kioku_extent_commit_attempts_v3",
            "CHECK(stage BETWEEN 1 AND 8)",
            "WHERE stage BETWEEN 1 AND 5",
            "stage = 7 AND monotonic_revision = 4",
            "stage = 8 AND monotonic_revision IN (2, 3)",
            "_kioku_extent_staged_objects_v1",
            "PRIMARY KEY (attempt_id, ordinal)",
        ]:
            self.assertIn(fragment, fn_raw, f"ledger DDL must contain `{fragment}`")
        self.assertNotIn("INSERT OR REPLACE", raw)
        self.assertNotIn("SystemTime", code)

    # ---- 3. Shadow-only VFS -------------------------------------------------

    def test_vfs_refuses_non_main_files_and_has_no_parent_file_io(self):
        raw, code = prod_views("src/archive_v3_extent_vfs.rs")
        open_raw, open_code = fn_region(raw, code, "extent_vfs_open")
        self.assertIn(
            "SQLITE_OPEN_MAIN_DB) == 0",
            open_code.replace("ffi::", ""),
            "xOpen must refuse every non-main file class",
        )
        self.assertIn("SQLITE_CANTOPEN", open_code)
        self.assertNotIn("SQLITE_OPEN_WAL", code, "no WAL open path may exist")
        self.assertNotIn("parent_file", code, "extent files never open a parent OS file")
        self.assertNotIn("std::env", code)
        self.assertNotIn("temp_dir", code)
        self.assertIn("main_db_handles", open_code, "single-main-handle enforcement")

    # ---- 4. Backend authority ----------------------------------------------

    def test_no_backend_delete_or_enumerate_in_phase3_files(self):
        for path in PHASE3_FILES:
            _, code = prod_views(path)
            self.assertNotIn("delete_exact", code, f"{path}: delete authority banned")
            hits = banned_enumerate_calls(code)
            self.assertEqual(
                hits, [], f"{path}: backend enumerate calls banned: {hits}"
            )

    # ---- 5. Inactive wiring -------------------------------------------------

    def test_phase3_symbols_unreferenced_outside_phase3_files(self):
        offenders: list[str] = []
        for path in sorted((ROOT / "src").rglob("*.rs")):
            rel = str(path.relative_to(ROOT)).replace("\\", "/")
            if rel in ALLOWED_REFERENCING_FILES:
                continue
            _, code = prod_views(rel)
            for symbol in PHASE3_ENTRY_SYMBOLS:
                if re.search(rf"\b{re.escape(symbol)}\b", code):
                    offenders.append(f"{rel}: {symbol}")
        self.assertEqual(
            offenders, [], f"Phase 3 entry symbols leaked into production wiring: {offenders}"
        )

    def test_main_rs_declares_modules_without_invoking_them(self):
        raw, code = prod_views("src/main.rs")
        for module in [
            "archive_v3_extent_vfs",
            "archive_v3_wal_to_extent",
            "archive_v3_extent_shadow",
            "archive_v3_extent_commit",
            "archive_v3_vector_accelerator",
        ]:
            self.assertIsNotNone(
                re.search(rf"\bmod\s+{module}\s*;", code),
                f"main.rs must declare mod {module};",
            )
            self.assertIsNone(
                re.search(rf"\b{module}\s*::", code),
                f"main.rs must not invoke {module}::",
            )
        gate_decl = re.search(
            r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+archive_v3_phase3_gates\s*;",
            sanitize_rust(read("src/main.rs")),
        )
        self.assertIsNotNone(gate_decl, "gate suite must stay cfg(test)-gated")

    # ---- 6. File-specific honesty checks ------------------------------------

    def test_wal_converter_shape(self):
        raw, code = prod_views("src/archive_v3_wal_to_extent.rs")
        self.assertNotIn("AuthenticatedWalIndex", code, "non-cryptographic naming enforced")
        self.assertIn("ChecksumValidatedWalIndex", code)
        self.assertNotIn("std::env", code, "no environment-controlled staging path")
        self.assertNotIn("temp_dir", code)
        self.assertIn('"/tmp"', raw, "staging is pinned to the fixed private tmpfs root")

    def test_vector_accelerator_shape(self):
        raw, code = prod_views("src/archive_v3_vector_accelerator.rs")
        self.assertIsNotNone(
            re.search(r"MAX_ANN_NODES\s*:\s*usize\s*=\s*32_768", code),
            "node cap must match the MerkleNode location encoding bound",
        )
        self.assertIn("certified_recall_at_20_bp", code, "recall certification is real")
        self.assertIn("search_vectors_fail_closed", code)
        self.assertNotIn(
            "if let Ok(accel)",
            code,
            "fail-open error discarding at the public entry is banned",
        )

    def test_shadow_comparator_shape(self):
        raw, code = prod_views("src/archive_v3_extent_shadow.rs")
        self.assertIn("readonly()", code, "statement-level read-only enforcement")
        self.assertIn("query_only", raw)
        self.assertIn("unchecked_transaction", code, "RAII transactions required")
        self.assertNotIn('"BEGIN', raw, "hand-rolled transaction strings banned")

    # ---- Negative controls ---------------------------------------------------

    def test_negative_control_string_literals_cannot_satisfy_token_checks(self):
        snippet = 'fn f() { let x = "RootAdvance::new( mark_witness_send_started"; }'
        self.assertNotIn("RootAdvance::new(", sanitize_rust(snippet))

    def test_negative_control_cfg_test_items_are_stripped(self):
        snippet = (
            "#[cfg(test)]\nmod anything_named { pub fn evil() { delete_exact(); } }\n"
            "fn keep() {}\n"
        )
        stripped = without_cfg_test_items(snippet)
        self.assertNotIn("delete_exact", stripped)
        self.assertIn("fn keep", stripped)

    def test_negative_control_token_literal_rule(self):
        snippet = "fn f() -> WitnessSendAuthority { WitnessSendAuthority { _private: () } }"
        code = sanitize_rust(snippet)
        hits = [
            m
            for m in re.finditer(r"\bWitnessSendAuthority\s*\{", code)
            if not re.search(r"(struct|impl|for)\s+$", code[max(0, m.start() - 24) : m.start()])
        ]
        self.assertGreaterEqual(len(hits), 1, "literal construction must be detectable")

    def test_negative_control_bracket_semicolon_span(self):
        snippet = (
            "impl T {\n    #[cfg(test)]\n    pub(crate) const fn mint(x: [u8; 32]) -> Self {\n"
            "        Self { field: x }\n    }\n}\nfn keep() {}\n"
        )
        stripped = without_cfg_test_items(snippet)
        self.assertNotIn("Self { field", stripped, "signature [u8; 32] must not truncate the span")
        self.assertIn("fn keep", stripped)

    def test_negative_control_enumerate_rule(self):
        self.assertEqual(banned_enumerate_calls("x.iter().enumerate()"), [])
        self.assertEqual(len(banned_enumerate_calls("backend.enumerate(&prefix, None, l)")), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
