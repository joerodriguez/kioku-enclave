#!/usr/bin/env python3
"""Exact non-private audio contract for the ADR-0022 live launch witness."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest
import wave


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts" / "adr0022_launch_witness.json"
FIELDS = (
    "schema_version",
    "asset",
    "sha256",
    "byte_length",
    "mime_type",
    "codec",
    "sample_rate_hz",
    "channels",
    "sample_width_bytes",
    "frame_count",
    "expected_transcript",
    "transcript_normalization",
    "provenance",
)


class Adr0022LaunchWitnessTests(unittest.TestCase):
    def test_checked_in_audio_and_manifest_are_exact(self) -> None:
        raw_manifest = MANIFEST.read_bytes()
        self.assertLessEqual(len(raw_manifest), 4096)
        manifest = json.loads(raw_manifest)
        self.assertEqual(tuple(manifest), FIELDS)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["asset"], "adr0022_launch_witness.wav")
        self.assertEqual(manifest["mime_type"], "audio/wav")
        self.assertEqual(manifest["codec"], "pcm_s16le")
        self.assertEqual(
            manifest["expected_transcript"],
            "the blue lantern is ready for launch",
        )
        self.assertEqual(
            manifest["transcript_normalization"],
            "unicode-nfkc-lowercase-alphanumeric-space-collapse-v1",
        )
        self.assertIn("Non-private synthetic speech", manifest["provenance"])

        asset = MANIFEST.with_name(manifest["asset"])
        audio = asset.read_bytes()
        self.assertEqual(len(audio), manifest["byte_length"])
        self.assertEqual(hashlib.sha256(audio).hexdigest(), manifest["sha256"])
        self.assertEqual(audio[:4], b"RIFF")
        self.assertEqual(audio[8:12], b"WAVE")

        with wave.open(str(asset), "rb") as stream:
            self.assertEqual(stream.getcomptype(), "NONE")
            self.assertEqual(stream.getnchannels(), manifest["channels"])
            self.assertEqual(stream.getframerate(), manifest["sample_rate_hz"])
            self.assertEqual(stream.getsampwidth(), manifest["sample_width_bytes"])
            self.assertEqual(stream.getnframes(), manifest["frame_count"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
