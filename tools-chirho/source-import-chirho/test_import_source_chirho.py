#!/usr/bin/env python3
# For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
"""Source-import safety tests using synthetic files under this repository's target."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT_CHIRHO = Path(__file__).resolve().parents[2]
SPEC_CHIRHO = importlib.util.spec_from_file_location(
    "source_import_chirho", Path(__file__).with_name("import_source_chirho.py")
)
IMPORT_CHIRHO = importlib.util.module_from_spec(SPEC_CHIRHO)
SPEC_CHIRHO.loader.exec_module(IMPORT_CHIRHO)


class SourceImportTestsChirho(unittest.TestCase):
    def setUp(self):
        parent_chirho = ROOT_CHIRHO / "target/source-tests-chirho"
        parent_chirho.mkdir(parents=True, exist_ok=True)
        self.scratch_chirho = tempfile.TemporaryDirectory(dir=parent_chirho)
        self.addCleanup(self.scratch_chirho.cleanup)
        self.root_chirho = Path(self.scratch_chirho.name)
        self.patch_chirho = patch.object(IMPORT_CHIRHO, "ROOT_CHIRHO", self.root_chirho)
        self.patch_chirho.start()
        self.addCleanup(self.patch_chirho.stop)

    def test_parent_owned_and_private_paths_are_not_imported_chirho(self):
        for relative_chirho in ["AGENTS.md", "README.md", ".gitignore", ".gitleaks.toml", ".env", ".env.local", "spec-chirho/private-chirho.json", "workspace-chirho/private-chirho.txt", "deploy-chirho/private-chirho.sh"]:
            with self.subTest(relative_chirho=relative_chirho):
                self.assertIsNone(IMPORT_CHIRHO.disposition_chirho(relative_chirho)[0])
        self.assertEqual(
            IMPORT_CHIRHO.disposition_chirho("crates/cairn-node-sdk-chirho/src/lib.rs")[0],
            "crates/cairn-node-sdk-chirho/src/lib.rs",
        )

    def test_import_cannot_overwrite_existing_files_chirho(self):
        path_chirho = self.root_chirho / "Cargo.toml"
        path_chirho.write_text("parent-owned-existing-content-chirho")
        with self.assertRaises(ValueError):
            IMPORT_CHIRHO.import_chirho(
                {"Cargo.toml": {"source_mode_chirho": "100644"}},
                {"Cargo.toml": b"replacement-chirho"},
                {"Cargo.toml": "Cargo.toml"},
            )
        self.assertEqual(path_chirho.read_text(), "parent-owned-existing-content-chirho")

    def test_escaping_symlink_is_refused_before_any_write_chirho(self):
        selected_chirho = {"Cargo.toml": "Cargo.toml", "source-chirho": "source-chirho"}
        with self.assertRaises(ValueError):
            IMPORT_CHIRHO.import_chirho(
                {"Cargo.toml": {"source_mode_chirho": "100644"}, "source-chirho": {"source_mode_chirho": "120000"}},
                {"Cargo.toml": b"content-chirho", "source-chirho": b"../outside-chirho"},
                selected_chirho,
            )
        self.assertEqual(list(self.root_chirho.iterdir()), [])

    def test_destination_traversal_and_parent_ownership_are_refused_chirho(self):
        for relative_chirho in ["../outside-chirho", "/outside-chirho", ".git/config", "spec-chirho/step-chirho.json", "AGENTS.md"]:
            with self.subTest(relative_chirho=relative_chirho), self.assertRaises(ValueError):
                IMPORT_CHIRHO.safe_destination_chirho(relative_chirho)

    def test_import_preserves_executable_mode_and_relative_symlink_chirho(self):
        IMPORT_CHIRHO.import_chirho(
            {"tool-chirho": {"source_mode_chirho": "100755"}, "alias-chirho": {"source_mode_chirho": "120000"}},
            {"tool-chirho": b"fixture-chirho", "alias-chirho": b"tool-chirho"},
            {"tool-chirho": "tool-chirho", "alias-chirho": "alias-chirho"},
        )
        self.assertEqual((self.root_chirho / "tool-chirho").stat().st_mode & 0o777, 0o755)
        self.assertTrue((self.root_chirho / "alias-chirho").is_symlink())
        self.assertEqual((self.root_chirho / "alias-chirho").read_bytes(), b"fixture-chirho")

    def test_missing_path_dependency_fails_instead_of_falling_back_chirho(self):
        (self.root_chirho / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["."]\n[dependencies]\nmissing-chirho = { path = "../old-private-chirho" }\n'
        )
        with self.assertRaisesRegex(ValueError, "missing path dependency"):
            IMPORT_CHIRHO.closure_chirho(["Cargo.toml"])


if __name__ == "__main__":
    unittest.main()
