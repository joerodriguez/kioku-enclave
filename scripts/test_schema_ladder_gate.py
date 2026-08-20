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


def baseline_digest(source: str) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(LADDER_DOMAIN)
    hasher.update(framed(schema_sql_body(source).encode()))
    hasher.update(framed(run_migrations_body(source).encode()))
    return hasher.digest()


def declared_baseline_digest(ladder: str) -> bytes:
    block = ladder[ladder.index("pub(crate) const BASELINE_DIGEST: [u8; 32] = [") :]
    block = block[: block.index("];")]
    values = [int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})", block)]
    return bytes(values)


class SchemaLadderGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = STORE.read_text(encoding="utf-8")
        self.ladder = LADDER.read_text(encoding="utf-8")

    def test_epoch_zero_baseline_is_frozen(self) -> None:
        """The recorded baseline digest must still describe the live baseline.

        A mismatch means someone edited SCHEMA_SQL or run_migrations after the
        ladder existed. That is the exact change that bricks every migrated
        archive, because the live database would then carry text a canonical
        rebuild never produces.
        """
        self.assertEqual(
            declared_baseline_digest(self.ladder).hex(),
            baseline_digest(self.store).hex(),
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
        for sql in re.findall(r'sql:\s*"((?:[^"\\]|\\.)*)"', literal):
            lowered = sql.lower()
            for forbidden in FORBIDDEN_STEP_SQL:
                self.assertNotIn(
                    forbidden,
                    lowered,
                    f"ladder step performs a non-additive change: {forbidden}",
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
