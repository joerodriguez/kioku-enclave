#!/usr/bin/env python3
"""Freeze the epoch-0 product schema baseline and constrain the ladder.

Once an archive is WAL-authoritative its schema is pinned: the owner refuses a
database whose baseline DDL mutated anything, and parity compares the exact
plaintext hash. So after the ladder exists, a product schema change MUST be an
appended ladder step and MUST NOT be a baseline edit -- editing `SCHEMA_SQL` or
`run_migrations` would brick every migrated archive.

That rule is invisible in review, so it is enforced here.
"""

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "src/store.rs"
LADDER = ROOT / "src/schema_ladder.rs"
SEAL = ROOT / "scripts/schema_baseline_seal.json"
# `run_migrations` delegates part of the epoch-0 baseline to these two
# functions, which between them create 37 baseline tables. Hashing only
# store.rs left all of that DDL editable without tripping the freeze.
MEDIA = ROOT / "src/cp/media.rs"
PROJECTION = ROOT / "src/cp/mcp_projection.rs"
LADDER_DOMAIN = b"kioku.schema-ladder.v1"

# DDL a ladder step may never contain: each rewrites or removes existing
# sqlite_schema text, which breaks the identical-text property the ladder
# depends on. These need the separately reviewed rebuild path.
FORBIDDEN_STEP_SQL = (
    "drop table",
    "drop index",
    "drop column",
    "rename to",
    "rename column",
    "alter table" " " "drop",
)

# ── The seal ──────────────────────────────────────────────────────────────────
#
# The epoch-0 baseline may be re-pinned only while no archive exists. Once the
# seal is flipped the window is closed forever and the ladder is the only way
# product schema moves.
#
# Three literals live HERE, in the gate, rather than in the seal file, so that
# changing the seal file alone can never satisfy the gate. Together they close
# the three ways a re-pin could otherwise slip through:
#
#   * appending a history entry     -> SEALED_HISTORY_LEN stops matching
#   * rewriting the LAST history
#     entry in place (len unchanged) -> SEALED_HISTORY_HEAD stops matching
#   * unsealing, true -> false      -> SEALED_EXPECTED stops matching
#
# All three were reachable with the seal file plus the two Rust files and no
# gate edit at all, which made the seal a claim rather than a latch.
SEAL_DOMAIN = b"kioku.schema-baseline-seal.v1"

SEALED_HISTORY_LEN = 3

# Every history entry except the last, pinned verbatim. Append-only in the
# ordinary direction; the hash chain below covers the last entry too.
SEALED_HISTORY_PREFIX = (
    (
        "c9f277faac1419964b3f8f3c6a3c257808a43b7210490f28fdcb3e42a2b9c551",
        "2026-08-19",
        "genesis: the original ladder pin (#282/#286), store.rs only",
    ),
    (
        "bc90061eca42ecbab9afd93349afe1506c8cce638ecb81836ac1b4e8ba9c3f66",
        "2026-08-20",
        "#316: pin extended to the four DDL sources run_migrations executes",
    ),
)

# The hash chain over the WHOLE history, head included. This is what makes the
# history append-only in both directions: an entry rewritten in place changes
# the head, and the head is a literal in this file.
SEALED_HISTORY_HEAD = "5a1617bcfecfac7ef35791f73074e5252fac1a262cd75ce5b84b521776bc4fb1"

# The seal bit itself, pinned. Ships `False`: the machinery lands now, the flip
# is a separate cutover-time PR gated on the zero-archive proof.
SEALED_EXPECTED = False


def framed(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def schema_sql_body(source: str) -> str:
    """The exact SCHEMA_SQL raw-string body."""
    marker = 'const SCHEMA_SQL: &str = r#"'
    start = source.index(marker) + len(marker)
    end = source.index('"#;', start)
    return source[start:end]


def run_migrations_body(source: str) -> str:
    """The exact run_migrations function body, brace-balanced."""
    marker = "fn run_migrations(conn: &Connection) -> Result<()> {"
    start = source.index(marker) + len(marker)
    depth = 1
    index = start
    while depth:
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1
    return source[start : index - 1]


def function_body(source: str, marker: str) -> str:
    """The exact body of the function opened by `marker`, brace-balanced."""
    start = source.index(marker) + len(marker)
    depth = 1
    index = start
    while depth:
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1
    return source[start : index - 1]


def baseline_digest(source: str, media: str, projection: str) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(LADDER_DOMAIN)
    hasher.update(framed(schema_sql_body(source).encode()))
    hasher.update(framed(run_migrations_body(source).encode()))
    # `run_migrations` calls these; their DDL is as much the frozen baseline
    # as SCHEMA_SQL is, so the pin has to cover them or the freeze is a
    # statement about one file rather than about the baseline.
    hasher.update(
        framed(
            function_body(
                projection, "pub fn init_projection_schema(conn: &Connection) -> SqlResult<()> {"
            ).encode()
        )
    )
    hasher.update(
        framed(
            function_body(
                media, "pub fn init_schema(conn: &Connection) -> Result<()> {"
            ).encode()
        )
    )
    return hasher.digest()


def declared_baseline_digest(ladder: str) -> bytes:
    block = ladder[ladder.index("pub(crate) const BASELINE_DIGEST: [u8; 32] = [") :]
    block = block[: block.index("];")]
    values = [int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})", block)]
    return bytes(values)


def step_sql_literals(literal: str) -> list[str]:
    """Every `sql:` value in a ladder literal, plain AND raw strings.

    Raw strings were previously invisible to the scan, so a step written
    `sql: r#"DROP TABLE ..."#` -- the natural shape for the multi-line SQL a
    real step is most likely to use -- passed the additive-only rule
    vacuously.
    """
    found = re.findall(r'sql:\s*"((?:[^"\\]|\\.)*)"', literal)
    found += [body for _, body in re.findall(r'sql:\s*r(#*)"(.*?)"\1', literal, re.S)]
    return found


def history_chain(entries: list[dict]) -> list[str]:
    """The running hash chain over the seal history.

    `chain[i] = SHA256(DOMAIN || chain[i-1] || framed(digest,date,proof))`,
    with `chain[-1]` for i=0 being empty. Length-prefixing each field means a
    value cannot be shifted between fields without moving the chain.
    """
    chains = []
    previous = b""
    for entry in entries:
        hasher = hashlib.sha256()
        hasher.update(SEAL_DOMAIN)
        hasher.update(previous)
        for field in ("digest", "date", "proof"):
            hasher.update(framed(str(entry[field]).encode()))
        previous = hasher.digest()
        chains.append(previous.hex())
    return chains


def render_digest(digest: bytes) -> str:
    """`BASELINE_DIGEST`'s exact Rust literal, ready to paste."""
    rows = []
    for offset in range(0, 32, 16):
        chunk = digest[offset : offset + 16]
        rows.append("    " + " ".join(f"0x{byte:02x}," for byte in chunk))
    return "pub(crate) const BASELINE_DIGEST: [u8; 32] = [\n" + "\n".join(rows) + "\n];"


def print_digest() -> int:
    """Emit the computed baseline digest. NEVER transcribe one by hand.

    This path and `test_epoch_zero_baseline_is_frozen` call the same
    `baseline_digest`, so a typo cannot survive the round trip.
    """
    digest = baseline_digest(
        STORE.read_text(encoding="utf-8"),
        MEDIA.read_text(encoding="utf-8"),
        PROJECTION.read_text(encoding="utf-8"),
    )
    print(digest.hex())
    print(render_digest(digest))
    return 0


def print_seal_chain() -> int:
    """Emit the history chain for the seal file and `SEALED_HISTORY_HEAD`."""
    seal = json.loads(SEAL.read_text(encoding="utf-8"))
    for entry, chain in zip(seal["history"], history_chain(seal["history"])):
        print(f"{entry['digest'][:12]}…  chain={chain}")
    print(f"SEALED_HISTORY_HEAD = {history_chain(seal['history'])[-1]!r}")
    return 0


class SchemaLadderGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = STORE.read_text(encoding="utf-8")
        self.ladder = LADDER.read_text(encoding="utf-8")
        self.media = MEDIA.read_text(encoding="utf-8")
        self.projection = PROJECTION.read_text(encoding="utf-8")
        self.seal = json.loads(SEAL.read_text(encoding="utf-8"))

    def test_epoch_zero_baseline_is_frozen(self) -> None:
        """The recorded baseline digest must still describe the live baseline.

        A mismatch means someone edited SCHEMA_SQL or run_migrations after the
        ladder existed. That is the exact change that bricks every migrated
        archive, because the live database would then carry text a canonical
        rebuild never produces.
        """
        self.assertEqual(
            declared_baseline_digest(self.ladder).hex(),
            baseline_digest(self.store, self.media, self.projection).hex(),
            "epoch-0 baseline changed: express schema changes as an appended "
            "ladder step, never as a baseline edit",
        )

    def test_ladder_is_append_only_and_contiguous(self) -> None:
        epochs = [int(value) for value in re.findall(r"epoch:\s*(\d+)\s*,", self.ladder)]
        # Only the SCHEMA_LADDER literal region, not the test fixtures below it.
        literal = self.ladder[
            self.ladder.index("pub(crate) const SCHEMA_LADDER") : self.ladder.index(
                "pub(crate) const SCHEMA_EPOCH_HEAD"
            )
        ]
        declared = [int(value) for value in re.findall(r"epoch:\s*(\d+)\s*,", literal)]
        self.assertEqual(declared, list(range(1, len(declared) + 1)))
        ids = re.findall(r'id:\s*"([^"]+)"', literal)
        self.assertEqual(len(ids), len(set(ids)), "ladder step ids must be unique")
        self.assertEqual(len(declared), len(ids))
        del epochs

    def test_steps_are_additive_only(self) -> None:
        literal = self.ladder[
            self.ladder.index("pub(crate) const SCHEMA_LADDER") : self.ladder.index(
                "pub(crate) const SCHEMA_EPOCH_HEAD"
            )
        ]
        for sql in step_sql_literals(literal):
            lowered = sql.lower()
            for forbidden in FORBIDDEN_STEP_SQL:
                self.assertNotIn(
                    forbidden,
                    lowered,
                    f"ladder step performs a non-additive change: {forbidden}",
                )

    def test_baseline_digest_covers_the_delegated_schema_bodies(self) -> None:
        """`run_migrations` delegates baseline DDL; the pin must cover it.

        Hashing only store.rs left the 37 tables created by
        `cp::media::init_schema` and `cp::mcp_projection::init_projection_schema`
        editable without tripping the freeze. Perturbing either body must move
        the digest, or the freeze is a statement about one file rather than
        about the baseline.
        """
        real = baseline_digest(self.store, self.media, self.projection)
        self.assertNotEqual(
            real,
            baseline_digest(
                self.store,
                self.media.replace("CREATE TABLE", "CREATE  TABLE", 1),
                self.projection,
            ),
            "editing cp::media::init_schema must change the baseline digest",
        )
        self.assertNotEqual(
            real,
            baseline_digest(
                self.store,
                self.media,
                self.projection.replace("CREATE TABLE", "CREATE  TABLE", 1),
            ),
            "editing init_projection_schema must change the baseline digest",
        )

    def test_delegated_bodies_extract_cleanly(self) -> None:
        """Diagnose a mis-terminated body directly, not as a digest mismatch.

        `function_body` counts braces without skipping string literals, so an
        unbalanced brace inside SQL would make it stop early or run past the
        function. That still fails closed — the digest moves and the freeze
        trips — but it fails as an inscrutable mismatch. Assert the shape
        here so the real cause is named.
        """
        for label, source, marker in (
            (
                "cp::media::init_schema",
                self.media,
                "pub fn init_schema(conn: &Connection) -> Result<()> {",
            ),
            (
                "init_projection_schema",
                self.projection,
                "pub fn init_projection_schema(conn: &Connection) -> SqlResult<()> {",
            ),
        ):
            body = function_body(source, marker)
            self.assertEqual(
                body.count("{"),
                body.count("}"),
                f"{label}: extracted body is not brace-balanced, so the "
                f"baseline digest is hashing the wrong span",
            )
            self.assertTrue(
                body.rstrip().endswith("Ok(())"),
                f"{label}: extracted body does not end at the function's "
                f"return, so the baseline digest is hashing the wrong span",
            )

    def test_raw_string_steps_are_scanned_for_forbidden_sql(self) -> None:
        """A raw-string step must not bypass the additive-only rule."""
        plain = 'SchemaStep { epoch: 1, id: "a", sql: "ALTER TABLE t ADD COLUMN c TEXT" }'
        raw = 'SchemaStep { epoch: 2, id: "b", sql: r#"DROP TABLE t"# }'
        self.assertEqual(
            step_sql_literals(plain), ["ALTER TABLE t ADD COLUMN c TEXT"]
        )
        self.assertEqual(step_sql_literals(raw), ["DROP TABLE t"])
        self.assertTrue(
            any(
                forbidden in sql.lower()
                for sql in step_sql_literals(raw)
                for forbidden in FORBIDDEN_STEP_SQL
            ),
            "a raw-string step containing DROP TABLE must be caught",
        )

    def test_epoch_constants_are_ordered(self) -> None:
        def constant(name: str) -> int:
            match = re.search(rf"pub\(crate\) const {name}: u32 = (\d+);", self.ladder)
            assert match, f"missing {name}"
            return int(match.group(1))

        head = constant("SCHEMA_EPOCH_HEAD")
        target = constant("SCHEMA_EPOCH_TARGET")
        min_servable = constant("SCHEMA_EPOCH_MIN_SERVABLE")
        # Never drive an archive past what this binary can build, and never
        # refuse to serve an epoch it is willing to create.
        self.assertLessEqual(target, head)
        self.assertLessEqual(min_servable, target)

    # ── G-SEAL-1..5 and G4 ────────────────────────────────────────────────

    def test_seal_matches_the_live_baseline(self) -> None:
        """G-SEAL-1. The seal must describe the baseline that actually ships."""
        computed = baseline_digest(self.store, self.media, self.projection).hex()
        self.assertEqual(self.seal["digest"], computed)
        self.assertEqual(self.seal["digest"], declared_baseline_digest(self.ladder).hex())
        self.assertEqual(self.seal["history"][-1]["digest"], self.seal["digest"])

    def test_sealed_baseline_admits_no_further_repin(self) -> None:
        """G-SEAL-2. Unconditional: the history length is pinned in this file.

        This deliberately has NO `if seal["sealed"]` antecedent. Gating it on
        the seal bit made the rule vacuous for the entire window it was
        supposed to bound, and left "flip the bit later" as the only thing
        standing between a fourth re-pin and CI.
        """
        self.assertEqual(
            len(self.seal["history"]),
            SEALED_HISTORY_LEN,
            "a baseline re-pin must also move SEALED_HISTORY_LEN in this "
            "gate script, so the act cannot happen in the seal file alone",
        )

    def test_seal_is_latched_to_its_own_evidence(self) -> None:
        """G-SEAL-3. A seal may only be set once its proof records a take.

        The consequent this rule used to carry — `len(history) >= 2` — was
        provably DEAD, not merely vacuous: G-SEAL-2 already asserts
        `len == SEALED_HISTORY_LEN` (3) unconditionally and G-SEAL-4a forces
        the same, so it could never fail. Meanwhile the honesty property the
        rule is named for went unenforced: the chain binds the proof
        FILENAME, never the document, so `sealed: true` could be set with no
        `docs/` directory at all. That is a seal which asserts rather than
        latches — the exact defect this whole seal block exists to correct.

        Note what this does NOT do: it does not forbid `true` -> `false`.
        G-SEAL-5 is what forbids it, by pinning the bit itself.
        """
        if not self.seal["sealed"]:
            return
        proof = ROOT / self.seal["history"][-1]["proof"]
        self.assertTrue(
            proof.is_file(),
            f"sealed, but the proof it names does not exist: {proof}",
        )
        recorded = proof.read_text(encoding="utf-8")
        self.assertNotIn(
            "NO TAKE HAS BEEN RECORDED",
            recorded,
            f"sealed, but {proof} still declares the obligation undischarged",
        )
        self.assertNotIn(
            "*Not taken.*",
            recorded,
            f"sealed, but {proof} still has an untaken measurement",
        )

    def test_seal_history_is_append_only(self) -> None:
        """G-SEAL-4a. Every entry but the last is pinned verbatim here."""
        recorded = tuple(
            (entry["digest"], entry["date"], entry["proof"])
            for entry in self.seal["history"][:-1]
        )
        self.assertEqual(recorded, SEALED_HISTORY_PREFIX)

    def test_seal_history_chain_is_intact(self) -> None:
        """G-SEAL-4b. The chain covers the LAST entry, which the prefix cannot.

        Without this, a re-pin could rewrite `history[-1]` in place: the length
        never moves, the prefix never moves, and G-SEAL-1 is satisfied by
        construction because the rewritten entry is made to equal the new
        digest. That bypass needed three files and no gate edit — strictly
        cheaper than the intended path.
        """
        expected = history_chain(self.seal["history"])
        for entry, chain in zip(self.seal["history"], expected):
            self.assertEqual(
                entry["chain"], chain, f"history entry {entry['digest'][:12]} was rewritten"
            )
        self.assertEqual(
            expected[-1],
            SEALED_HISTORY_HEAD,
            "the seal history moved: a re-pin must update SEALED_HISTORY_HEAD "
            "in this gate script, which is what makes the diff unmissable",
        )

    def test_seal_bit_is_pinned(self) -> None:
        """G-SEAL-5. The seal bit is a literal here, so unsealing fails CI."""
        self.assertIs(self.seal["sealed"], SEALED_EXPECTED)

    def test_ladder_step_requires_a_sealed_baseline(self) -> None:
        """G4. No step may ship over a baseline that can still move.

        `chain_digest` anchors on `BASELINE_DIGEST`; a step shipped while the
        anchor is movable produces a chain that changes retroactively, so
        every archive that recorded the old chain is refused.
        """
        literal = self.ladder[
            self.ladder.index("pub(crate) const SCHEMA_LADDER") : self.ladder.index(
                "pub(crate) const SCHEMA_EPOCH_HEAD"
            )
        ]
        if re.search(r"epoch:\s*\d+\s*,", literal):
            self.assertTrue(
                self.seal["sealed"],
                "a ladder step shipped while the baseline is unsealed",
            )


if __name__ == "__main__":
    if "--print-digest" in sys.argv:
        raise SystemExit(print_digest())
    if "--print-seal-chain" in sys.argv:
        raise SystemExit(print_seal_chain())
    unittest.main(verbosity=2)
