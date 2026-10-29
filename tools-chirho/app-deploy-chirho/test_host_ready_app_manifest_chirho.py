#!/usr/bin/env python3
# For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
"""Local synthetic staging tests. No Cargo, providers, old repositories, or credentials."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT_CHIRHO = Path(__file__).resolve().parents[2]
SPEC_CHIRHO = importlib.util.spec_from_file_location(
    "host_ready_manifest_chirho", Path(__file__).with_name("host_ready_app_manifest_chirho.py")
)
HELPER_CHIRHO = importlib.util.module_from_spec(SPEC_CHIRHO)
SPEC_CHIRHO.loader.exec_module(HELPER_CHIRHO)


class HostReadyManifestTestsChirho(unittest.TestCase):
    def setUp(self):
        self.scratch_parent_chirho = ROOT_CHIRHO / "target/source-tests-chirho"
        self.scratch_parent_chirho.mkdir(parents=True, exist_ok=True)
        self.scratch_chirho = tempfile.TemporaryDirectory(dir=self.scratch_parent_chirho)
        self.addCleanup(self.scratch_chirho.cleanup)
        self.root_chirho = Path(self.scratch_chirho.name)
        self.app_chirho = self.root_chirho / "app-chirho"
        self.stage_chirho = self.root_chirho / "stage-chirho"
        self.app_chirho.mkdir()

    def manifest_chirho(self, *, app_name_chirho="example-chirho", artifact_chirho=True):
        if artifact_chirho:
            (self.app_chirho / "guest-chirho.wasm").write_bytes(b"\x00asm-synthetic-fixture-chirho")
        (self.app_chirho / "style-chirho.css").write_text("body { color: black; }\n")
        value_chirho = {
            "app_chirho": app_name_chirho,
            "nodes_chirho": [{
                "id_chirho": "render-chirho",
                "source_chirho": {
                    "kind_chirho": "cargo-example-chirho",
                    "example_chirho": "guest-chirho",
                    "artifact_path_chirho": "guest-chirho.wasm",
                },
            }],
            "assets_chirho": [{
                "name_chirho": "style-chirho.css",
                "source_chirho": {"kind_chirho": "path-chirho", "path_chirho": "style-chirho.css"},
            }],
        }
        (self.app_chirho / HELPER_CHIRHO.EMITTED_MANIFEST_NAME_CHIRHO).write_text(json.dumps(value_chirho))

    def test_stages_existing_bytes_and_relative_hash_inventory_chirho(self):
        self.manifest_chirho()
        self.assertEqual(HELPER_CHIRHO.main_chirho(["helper-chirho", str(self.app_chirho), str(self.stage_chirho)]), 0)
        hosted_chirho = self.stage_chirho / ("example-chirho" + HELPER_CHIRHO.HOSTED_SUFFIX_CHIRHO)
        value_chirho = json.loads(hosted_chirho.read_text())
        self.assertEqual(value_chirho["nodes_chirho"][0]["source_chirho"], {"kind_chirho": "path-chirho", "path_chirho": "guest-chirho.wasm"})
        for line_chirho in (self.stage_chirho / HELPER_CHIRHO.SHA256_LIST_NAME_CHIRHO).read_text().splitlines():
            expected_chirho, relative_chirho = line_chirho.split("  ", 1)
            self.assertFalse(Path(relative_chirho).is_absolute())
            self.assertEqual(hashlib.sha256((self.stage_chirho / relative_chirho).read_bytes()).hexdigest(), expected_chirho)

    def test_missing_artifact_is_refused_without_build_chirho(self):
        self.manifest_chirho(artifact_chirho=False)
        with self.assertRaises(SystemExit) as error_chirho:
            HELPER_CHIRHO.main_chirho(["helper-chirho", str(self.app_chirho), str(self.stage_chirho)])
        self.assertEqual(error_chirho.exception.code, 2)
        self.assertFalse((self.app_chirho / "guest-chirho.wasm").exists())

    def test_output_paths_cannot_escape_staging_chirho(self):
        self.stage_chirho.mkdir()
        for relative_chirho in ["../escape-chirho", "/escape-chirho", "assets-chirho/../../escape-chirho", "..\\escape-chirho"]:
            with self.subTest(relative_chirho=relative_chirho), self.assertRaises(SystemExit):
                HELPER_CHIRHO.stage_file_chirho(Path(__file__), self.stage_chirho, relative_chirho)
        self.assertEqual(list(self.stage_chirho.iterdir()), [])

    def test_manifest_name_cannot_escape_staging_chirho(self):
        self.manifest_chirho(app_name_chirho="../escape-chirho")
        with self.assertRaises(SystemExit):
            HELPER_CHIRHO.main_chirho(["helper-chirho", str(self.app_chirho), str(self.stage_chirho)])
        self.assertFalse((self.root_chirho / ("escape-chirho" + HELPER_CHIRHO.HOSTED_SUFFIX_CHIRHO)).exists())

    def test_symlink_and_reused_stage_are_refused_chirho(self):
        self.stage_chirho.mkdir()
        (self.stage_chirho / "outside-chirho").symlink_to(self.app_chirho, target_is_directory=True)
        with self.assertRaises(SystemExit):
            HELPER_CHIRHO.stage_file_chirho(Path(__file__), self.stage_chirho, "outside-chirho/escape-chirho")
        self.manifest_chirho()
        with self.assertRaises(SystemExit):
            HELPER_CHIRHO.main_chirho(["helper-chirho", str(self.app_chirho), str(self.stage_chirho)])


if __name__ == "__main__":
    unittest.main()
