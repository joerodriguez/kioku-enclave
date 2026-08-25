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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adr0022_fresh_release as fresh_release

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

# ── G5/G6: the shipped steps themselves ───────────────────────────────────────
#
# Everything above constrains the ladder's SHAPE -- contiguous epochs, unique
# ids, additive-only SQL -- and nothing constrained its CONTENT. Editing a
# shipped step's SQL passed all of it.
#
# That is not a cosmetic hole. A step's digest is chained into `chain_digest`,
# which every archive records in its `schema_epoch` marker and which
# `validate_servable_epoch` recomputes at owner open. Ship an edited step and
# two archives sit at nominal epoch 1 carrying different DDL and different
# chains, each permanently unopenable by the other's binary. Nothing at RUNTIME
# can catch it either: plan and running binary share one `&'static` ladder by
# construction, so the advance plan's own "is the step still what I recorded"
# precondition is an identity, and at `from_epoch = 0` the recorded chain is
# the bare baseline anchor and contains no step to disagree with.
#
# So the guard has to be here, and it has to be a pin: the digests are literals
# in THIS file, so editing a shipped step fails CI unless the gate is edited in
# the same diff, which is what makes the act unmissable in review.
#
# Recompute, never transcribe: `python3 scripts/test_schema_ladder_gate.py
# --print-ladder-pins`.

# Every shipped step, `(epoch, id, step_digest_hex)`, in declaration order.
# Empty because SCHEMA_LADDER is empty; G4 already refuses a step over an
# unsealed baseline. Appending a step means appending here too -- runbook
# step 3.
SEALED_STEP_DIGESTS: tuple[tuple[int, str, str], ...] = ()

# `chain_digest(SCHEMA_EPOCH_HEAD)` over the declared ladder, anchored on
# BASELINE_DIGEST.
#
# This is the exact value an archive records in its `schema_epoch` marker and
# that `validate_servable_epoch` recomputes at owner open, pinned end to end.
# What it adds over the per-step tuple above is the ANCHOR: the tuple says
# nothing about BASELINE_DIGEST, and the chain is built from it, so a baseline
# re-pin moves this even when no step moved. Not vacuous with an empty ladder
# either -- it is then exactly `SHA256(LADDER_DOMAIN || BASELINE_DIGEST)`.
SEALED_LADDER_CHAIN_HEAD = "44c94f297c002b76892e96f1449398610eaf981dc1f6c123cfa69630d8c72c98"

# One fixture triple digested by BOTH implementations of `step_digest`: this
# file's and `schema_ladder::step_digest`'s. The identical constant is asserted
# in `cp::schema_epoch::wal::advance`'s test module, so a drift in either
# language's framing, domain separation or integer width fails on one side.
# Keep the two in sync; that is the whole point of them.
CROSS_CHECKED_STEP = (
    1,
    "0001_capture_events_stream_sequence",
    "CREATE INDEX idx_capture_events_stream_sequence ON capture_events (stream_id, sequence);",
)
CROSS_CHECKED_STEP_DIGEST = (
    "00721b2e0796349ebb9200f0f2595b2537d9250212f0b0bf0dd77e5d21622887"
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


def schema_ladder_literal(ladder: str) -> str:
    """Only the SCHEMA_LADDER array, never the test fixtures below it."""
    return ladder[
        ladder.index("pub(crate) const SCHEMA_LADDER") : ladder.index(
            "pub(crate) const SCHEMA_EPOCH_HEAD"
        )
    ]


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


_SIMPLE_RUST_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "0": "\0",
    "\\": "\\",
    '"': '"',
    "'": "'",
}


def rust_string_literal_value(literal: str) -> str:
    """Decode one plain (non-raw) Rust string literal body to its real bytes.

    Digesting the SOURCE text instead of the value would be wrong the moment a
    step used `\\"` or a line continuation, and wrong silently -- the pin would
    still be stable, it would just be a pin on a different string than the one
    the compiler builds. So this decodes, and it raises on anything it does not
    understand rather than guessing: a step whose SQL this cannot read must
    fail the build, never be digested approximately.
    """
    out: list[str] = []
    index = 0
    while index < len(literal):
        char = literal[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(literal):
            raise ValueError("string literal ends in a backslash")
        escape = literal[index]
        if escape in _SIMPLE_RUST_ESCAPES:
            out.append(_SIMPLE_RUST_ESCAPES[escape])
            index += 1
        elif escape == "x":
            out.append(chr(int(literal[index + 1 : index + 3], 16)))
            index += 3
        elif escape == "u":
            close = literal.index("}", index)
            out.append(chr(int(literal[index + 2 : close].replace("_", ""), 16)))
            index = close + 1
        elif escape == "\n":
            # Rust's line continuation: the newline AND the following leading
            # whitespace vanish. This is the shape the ladder's own doc comment
            # recommends for multi-line SQL, so getting it wrong is not exotic.
            index += 1
            while index < len(literal) and literal[index] in " \t\r\n":
                index += 1
        else:
            raise ValueError(f"unsupported Rust string escape: \\{escape!r}")
    return "".join(out)


def ladder_steps(literal: str) -> list[tuple[int, str, str]]:
    """Every declared `SchemaStep` as `(epoch, id, sql)`, in source order.

    Fails closed: a struct missing any of the three fields, or carrying a
    literal shape this cannot decode, raises rather than being skipped.
    """
    steps: list[tuple[int, str, str]] = []
    # `SchemaStep\s*{`, not bare `SchemaStep`: the declaration's own type
    # annotation `&[SchemaStep]` is not a struct literal, and splitting on the
    # bare name made the empty ladder parse as one unreadable step.
    #
    # Each chunk runs from one struct's `{` to the next struct's name, NOT to
    # a closing brace -- a `}` can legally appear inside the SQL, and cutting
    # there would truncate the field it was hiding in. Requiring exactly one of
    # each field per chunk is what keeps the fields associated with their own
    # struct: a struct missing one would otherwise borrow the next struct's.
    for chunk in re.split(r"SchemaStep\s*\{", literal)[1:]:
        epochs = re.findall(r"epoch:\s*(\d+)\s*,", chunk)
        identifiers = re.findall(r'id:\s*"((?:[^"\\]|\\.)*)"', chunk)
        sql_values = step_sql_literals(chunk)
        if len(epochs) != 1 or len(identifiers) != 1 or len(sql_values) != 1:
            raise ValueError(f"ladder step is not parseable: {chunk[:160]!r}")
        # `step_sql_literals` returns raw-string bodies verbatim, which is
        # already the value; only a plain literal needs unescaping.
        raw = re.search(r'sql:\s*r(#*)"', chunk)
        sql = sql_values[0] if raw else rust_string_literal_value(sql_values[0])
        steps.append(
            (int(epochs[0]), rust_string_literal_value(identifiers[0]), sql)
        )
    return steps


def step_digest(epoch: int, identifier: str, sql: str) -> bytes:
    """`schema_ladder::step_digest`, byte for byte."""
    hasher = hashlib.sha256()
    hasher.update(LADDER_DOMAIN)
    hasher.update(epoch.to_bytes(4, "big"))
    hasher.update(framed(identifier.encode()))
    hasher.update(framed(sql.encode()))
    return hasher.digest()


def ladder_chain_head(steps: list[tuple[int, str, str]], baseline: bytes) -> bytes:
    """`LadderView::chain_digest(head)`, byte for byte."""
    hasher = hashlib.sha256()
    hasher.update(LADDER_DOMAIN)
    hasher.update(baseline)
    digest = hasher.digest()
    for step in steps:
        hasher = hashlib.sha256()
        hasher.update(digest)
        hasher.update(step_digest(*step))
        digest = hasher.digest()
    return digest


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


def print_ladder_pins() -> int:
    """Emit `SEALED_STEP_DIGESTS` and `SEALED_LADDER_CHAIN_HEAD` to paste.

    Uses the same `ladder_steps` / `step_digest` / `ladder_chain_head` the
    tests assert against, so a hand-transcription error cannot survive.
    """
    ladder = LADDER.read_text(encoding="utf-8")
    steps = ladder_steps(schema_ladder_literal(ladder))
    print("SEALED_STEP_DIGESTS: tuple[tuple[int, str, str], ...] = (")
    for epoch, identifier, sql in steps:
        print(f'    ({epoch}, "{identifier}", "{step_digest(epoch, identifier, sql).hex()}"),')
    print(")")
    head = ladder_chain_head(steps, declared_baseline_digest(ladder)).hex()
    print(f'SEALED_LADDER_CHAIN_HEAD = "{head}"')
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
        self.ladder_literal = schema_ladder_literal(self.ladder)

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
        literal = self.ladder_literal
        declared = [int(value) for value in re.findall(r"epoch:\s*(\d+)\s*,", literal)]
        self.assertEqual(declared, list(range(1, len(declared) + 1)))
        ids = re.findall(r'id:\s*"([^"]+)"', literal)
        self.assertEqual(len(ids), len(set(ids)), "ladder step ids must be unique")
        self.assertEqual(len(declared), len(ids))
        del epochs

    def test_steps_are_additive_only(self) -> None:
        literal = self.ladder_literal
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
        proof = ROOT / self.seal["history"][-1]["proof"]
        self.assertTrue(
            proof.is_file(),
            f"the baseline proof it names does not exist: {proof}",
        )
        if not self.seal["sealed"]:
            self.assertEqual(self.seal["evidence_sha256"], "0" * 64)
            recorded = proof.read_text(encoding="utf-8")
            self.assertNotIn(fresh_release.BASELINE_SEAL_EVIDENCE_BEGIN, recorded)
            self.assertNotIn(fresh_release.BASELINE_SEAL_EVIDENCE_END, recorded)
            return
        fresh_release.validate_baseline_seal_evidence(
            ROOT, expected_sha256=self.seal["evidence_sha256"]
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

    # ── G5/G6 ─────────────────────────────────────────────────────────────

    def test_every_shipped_step_digest_is_pinned(self) -> None:
        """G5. Editing, renumbering or re-identifying a shipped step fails CI.

        The pin is `(epoch, id, digest)` rather than the digest alone so the
        failure message names WHICH step moved, and so a step that swapped
        places with another is caught by position as well as by content.
        """
        steps = ladder_steps(self.ladder_literal)
        recorded = tuple(
            (epoch, identifier, step_digest(epoch, identifier, sql).hex())
            for epoch, identifier, sql in steps
        )
        self.assertEqual(
            recorded,
            SEALED_STEP_DIGESTS,
            "a shipped ladder step's epoch, id or SQL changed: a step's digest "
            "is chained into every archive's recorded schema_epoch marker, so "
            "editing one strands every archive that already took it. Append a "
            "NEW step instead; if this really is a new step, add its pin to "
            "SEALED_STEP_DIGESTS in this gate script",
        )

    def test_ladder_chain_head_is_pinned(self) -> None:
        """G6. The chain the archives record, pinned end to end.

        Catches what the per-step tuple alone cannot: a move of
        BASELINE_DIGEST, which the tuple does not mention and on which the
        chain is anchored.
        """
        steps = ladder_steps(self.ladder_literal)
        self.assertEqual(
            ladder_chain_head(steps, declared_baseline_digest(self.ladder)).hex(),
            SEALED_LADDER_CHAIN_HEAD,
            "the ladder chain moved: appending a step must also move "
            "SEALED_LADDER_CHAIN_HEAD in this gate script",
        )

    def test_step_digest_agrees_with_the_rust_implementation(self) -> None:
        """G5's cross-check. Two languages, one digest, one pinned value.

        This gate computes step digests independently of `schema_ladder.rs`, so
        the pin is only worth anything if the two agree. The same triple and
        the same expected hex are asserted in
        `cp::schema_epoch::wal::advance`'s tests against the real
        `schema_ladder::step_digest`; a drift in domain separation, integer
        width or length framing on either side fails on that side.
        """
        epoch, identifier, sql = CROSS_CHECKED_STEP
        self.assertEqual(
            step_digest(epoch, identifier, sql).hex(), CROSS_CHECKED_STEP_DIGEST
        )

    def test_step_sql_is_digested_by_value_and_never_by_source_text(self) -> None:
        """A literal's escapes must be decoded before it is digested.

        Digesting the source text would produce a pin that is stable and
        WRONG -- on a different string than the compiler builds -- for any step
        using `\\"`, `\\\\` or the line continuation the ladder's own docs
        recommend for multi-line SQL.
        """
        self.assertEqual(rust_string_literal_value(r"a\"b"), 'a"b')
        self.assertEqual(rust_string_literal_value(r"a\\b"), "a\\b")
        self.assertEqual(rust_string_literal_value(r"a\nb"), "a\nb")
        self.assertEqual(rust_string_literal_value("CREATE \\\n      INDEX"), "CREATE INDEX")
        # Fail closed on anything unrecognised rather than digesting a guess.
        with self.assertRaises(ValueError):
            rust_string_literal_value(r"a\qb")
        with self.assertRaises(ValueError):
            rust_string_literal_value("trailing\\")

    def test_ladder_steps_parse_both_literal_shapes_and_fail_closed(self) -> None:
        plain = (
            'SchemaStep { epoch: 1, id: "0001_x", class: StepClass::Index, '
            'sql: "CREATE INDEX a ON t (\\"c\\");" }'
        )
        self.assertEqual(
            ladder_steps(plain), [(1, "0001_x", 'CREATE INDEX a ON t ("c");')]
        )
        raw = (
            'SchemaStep { epoch: 2, id: "0002_y", class: StepClass::Table, '
            'sql: r#"CREATE TABLE y (a TEXT)"# }'
        )
        self.assertEqual(ladder_steps(raw), [(2, "0002_y", "CREATE TABLE y (a TEXT)")])
        # A struct the parser cannot read must stop the build, never be
        # silently skipped out of the pinned set.
        with self.assertRaises(ValueError):
            ladder_steps('SchemaStep { epoch: 3, class: StepClass::Index }')

    def test_ladder_step_requires_a_sealed_baseline(self) -> None:
        """G4. No step may ship over a baseline that can still move.

        `chain_digest` anchors on `BASELINE_DIGEST`; a step shipped while the
        anchor is movable produces a chain that changes retroactively, so
        every archive that recorded the old chain is refused.
        """
        literal = self.ladder_literal
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
    if "--print-ladder-pins" in sys.argv:
        raise SystemExit(print_ladder_pins())
    unittest.main(verbosity=2)
