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
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "src/store.rs"
LADDER = ROOT / "src/schema_ladder.rs"
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


class SchemaLadderGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = STORE.read_text(encoding="utf-8")
        self.ladder = LADDER.read_text(encoding="utf-8")
        self.media = MEDIA.read_text(encoding="utf-8")
        self.projection = PROJECTION.read_text(encoding="utf-8")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
