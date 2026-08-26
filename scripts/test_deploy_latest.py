#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_latest  # noqa: E402


class DeployLatestTests(unittest.TestCase):
    def test_pipeline_command_derives_source_ref_without_caller_tag(self) -> None:
        arguments = argparse.Namespace(
            stage="push",
            config=Path("/private/config.env"),
            output_dir=Path("/private/evidence"),
            apply=True,
            resume=True,
        )
        command = deploy_latest.pipeline_command(
            arguments, "v0.8.37-archive-v3-wal.18"
        )
        self.assertIn("--source-ref", command)
        self.assertEqual(
            command[command.index("--source-ref") + 1],
            "v0.8.37-archive-v3-wal.18",
        )
        self.assertIn("--apply", command)
        self.assertIn("--resume", command)

    def test_release_source_check_has_no_unsigned_or_lightweight_tag_path(self) -> None:
        source = (ROOT / "scripts/deploy_latest.py").read_text(encoding="utf-8")
        self.assertIn('"tag",\n                "-s",\n                tag', source)
        self.assertIn('f"refs/tags/{tag}^{{tag}}"', source)
        self.assertIn('f"refs/tags/{tag}^{{commit}}"', source)
        self.assertIn('"origin/main"', source)


if __name__ == "__main__":
    unittest.main()
