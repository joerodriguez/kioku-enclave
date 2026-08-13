#!/usr/bin/env python3
"""Isolated contracts for deployed-image-to-local-config migration."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from test_select_build_configuration import environment as selected_environment  # noqa: E402


def load_module():
    specification = importlib.util.spec_from_file_location(
        "bootstrap_local_operator_config", SCRIPTS / "bootstrap_local_operator_config.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class BootstrapLocalOperatorConfigTests(unittest.TestCase):
    def image_environment(self, module) -> dict[str, str]:
        source = selected_environment()
        result = {"KIOKU_BUILD_PROFILE": "production"}
        for name in module.PROFILE_KEYS:
            image_name = module.IMAGE_ENVIRONMENT_NAMES.get(name, name)
            result[image_name] = source[f"PRODUCTION_{name}"]
        for group in module.OPTIONAL_PROFILE_GROUPS:
            for name in group:
                if f"PRODUCTION_{name}" in source:
                    result[name] = source[f"PRODUCTION_{name}"]
        return result

    def test_maps_and_writes_valid_private_production_config(self) -> None:
        module = load_module()
        image = (
            "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave@sha256:"
            + "a" * 64
        )
        _, coordinates = module.image_coordinates(image)
        values = module.operator_values(
            coordinates,
            self.image_environment(module),
            "local-builder@kioku-joerodriguez.iam.gserviceaccount.com",
        )
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve() / "private"
            parent.mkdir(mode=0o700)
            output = parent / "operator.env"
            module.write_private(output, values)
            content = output.read_text(encoding="utf-8")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertIn("PRODUCTION_ENCLAVE_KMS_PROJECT=", content)
            self.assertIn("PRODUCTION_ALLOWED_EMAILS=", content)
            self.assertIn("LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT=local-builder@", content)
            self.assertNotIn("\nKMS_PROJECT=", "\n" + content)
            with self.assertRaisesRegex(module.BootstrapError, "overwrite"):
                module.write_private(output, values)

    def test_requires_exact_digest_and_production_image(self) -> None:
        module = load_module()
        with self.assertRaisesRegex(module.BootstrapError, "sha256"):
            module.image_coordinates("us-central1-docker.pkg.dev/project/repo/image:latest")
        image_environment = self.image_environment(module)
        image_environment["KIOKU_BUILD_PROFILE"] = "evaluation"
        with self.assertRaisesRegex(module.BootstrapError, "production"):
            module.parse_deployed_entries(
                [f"{name}={value}" for name, value in image_environment.items()]
            )

    def test_output_must_be_outside_repository(self) -> None:
        module = load_module()
        with self.assertRaisesRegex(module.BootstrapError, "outside"):
            module.write_private(ROOT / "operator.env", {name: "x" for name in module.SHARED_KEYS})


if __name__ == "__main__":
    unittest.main()
