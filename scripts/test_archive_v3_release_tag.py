#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import archive_v3_release_tag as release_tag  # noqa: E402


REMOTE = "\n".join(
    (
        "a" * 40 + "\trefs/tags/v0.8.35-archive-v3-wal.14",
        "b" * 40 + "\trefs/tags/v0.8.36-archive-v3-wal.17",
        "c" * 40 + "\trefs/tags/v0.8.36-archive-v3-wal.17^{}",
        "d" * 40 + "\trefs/tags/unrelated",
    )
) + "\n"


class ArchiveV3ReleaseTagTests(unittest.TestCase):
    def test_derives_the_next_global_wal_sequence_from_cargo_version(self) -> None:
        self.assertEqual(
            release_tag.next_tag("0.8.37", REMOTE),
            "v0.8.37-archive-v3-wal.18",
        )

    def test_candidate_must_match_cargo_and_the_next_sequence(self) -> None:
        expected = "v0.8.37-archive-v3-wal.18"
        self.assertEqual(
            release_tag.require_next_tag(expected, "0.8.37", REMOTE).name,
            expected,
        )
        for candidate in (
            "v0.8.36-archive-v3-wal.18",
            "v0.8.37-archive-v3-wal.17",
            "v0.8.37-archive-v3-wal.19",
            "v0.8.37-ARCHIVE-V3-WAL.18",
            "v00.8.37-archive-v3-wal.18",
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(release_tag.ReleaseTagError):
                    release_tag.require_next_tag(candidate, "0.8.37", REMOTE)

    def test_current_receipt_is_one_exact_source_bound_successor(self) -> None:
        receipt = release_tag.current_release_receipt("0.8.37", REMOTE)
        self.assertEqual(tuple(receipt), release_tag.RECEIPT_FIELDS)
        self.assertEqual(
            release_tag.validate_current_release_receipt(
                receipt, version="0.8.37"
            ).name,
            "v0.8.37-archive-v3-wal.18",
        )
        for field, value in (
            ("version", "0.8.38"),
            ("tag", "v0.8.37-archive-v3-wal.19"),
            ("predecessor_sequence", 16),
        ):
            changed = dict(receipt)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(
                release_tag.ReleaseTagError
            ):
                release_tag.validate_current_release_receipt(
                    changed, version="0.8.37"
                )

    def test_existing_highest_tag_is_allowed_only_for_publication_resume(self) -> None:
        with self.assertRaises(release_tag.ReleaseTagError):
            release_tag.require_next_tag(
                "v0.8.36-archive-v3-wal.17", "0.8.36", REMOTE
            )
        self.assertEqual(
            release_tag.require_next_tag(
                "v0.8.36-archive-v3-wal.17",
                "0.8.36",
                REMOTE,
                allow_existing=True,
            ).sequence,
            17,
        )

    def test_remote_inventory_is_bounded_and_structurally_strict(self) -> None:
        with self.assertRaises(release_tag.ReleaseTagError):
            release_tag.tags_from_remote_refs("not-a-tab-delimited-line\n")
        with self.assertRaises(release_tag.ReleaseTagError):
            release_tag.tags_from_remote_refs(
                "x\trefs/tags/v0.8.1-archive-v3-wal.1\n"
                + ("z" * release_tag.MAX_REMOTE_TAG_BYTES)
            )


if __name__ == "__main__":
    unittest.main()
