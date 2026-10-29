# For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
import importlib.util
import unittest
from pathlib import Path

SCRIPT_CHIRHO = Path(__file__).resolve().parents[1] / "check_source_boundary_chirho.py"
SPEC_CHIRHO = importlib.util.spec_from_file_location("source_boundary_chirho", SCRIPT_CHIRHO)
assert SPEC_CHIRHO is not None and SPEC_CHIRHO.loader is not None
MODULE_CHIRHO = importlib.util.module_from_spec(SPEC_CHIRHO)
SPEC_CHIRHO.loader.exec_module(MODULE_CHIRHO)

class SourceBoundaryTestsChirho(unittest.TestCase):
    def test_operational_and_private_paths_refuse_chirho(self):
        for path_chirho in (
            ".env", "apps-chirho/demo/.env.production", "WORKSPACE-CHIRHO/raw.md",
            "deploy-chirho/live-host.md", "target/debug/binary",
            "data-chirho/private-secrets-chirho/credential", "signing-key-chirho.bin",
            "keys-chirho/customer.pem", "QUESTIONS-FOR-LJ-chirho.md",
            "prd_perffection_chirho.json", "review-evidence-chirho/probe.log",
        ):
            with self.subTest(path_chirho=path_chirho):
                self.assertTrue(MODULE_CHIRHO.refused_path_chirho(path_chirho))

    def test_source_examples_and_notices_are_not_substring_filtered_chirho(self):
        for path_chirho in (
            "src/attestation_stores_chirho/mod.rs", "src/tests_chirho.rs",
            ".env.example", "Cargo.lock", "LICENSE",
            "docs-chirho/release-gates-chirho.md", "assets_chirho/font-license.txt",
            "spec-chirho/progress-chirho.sqlite",
        ):
            with self.subTest(path_chirho=path_chirho):
                self.assertFalse(MODULE_CHIRHO.refused_path_chirho(path_chirho))

if __name__ == "__main__":
    unittest.main()
