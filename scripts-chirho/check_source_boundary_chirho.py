#!/usr/bin/env python3
# For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
"""Check tracked-path hygiene, not content secrecy or public-release approval."""
import json
import subprocess
from pathlib import Path, PurePosixPath

FORBIDDEN_COMPONENTS_CHIRHO = frozenset({
    ".git", "target", "workspace-chirho", "workspace_chirho",
    "private-secrets-chirho", "review-evidence-chirho",
})
FORBIDDEN_NAMES_CHIRHO = frozenset({
    "signing-key-chirho.bin", "pubkey-chirho.hex",
    "questions-for-lj-chirho.md", "prd_perffection_chirho.json",
    "prd_source_platform_chirho.json", "whitepaper-chirho.md",
    "state-and-path-chirho.md",
})

def refused_path_chirho(relative_chirho: str) -> bool:
    path_chirho = PurePosixPath(relative_chirho)
    parts_chirho = tuple(part_chirho.lower() for part_chirho in path_chirho.parts)
    name_chirho = path_chirho.name.lower()
    return (
        any(part_chirho in FORBIDDEN_COMPONENTS_CHIRHO for part_chirho in parts_chirho)
        or (bool(parts_chirho) and parts_chirho[0] == "deploy-chirho")
        or name_chirho in FORBIDDEN_NAMES_CHIRHO
        or (name_chirho.startswith(".env") and name_chirho != ".env.example")
        or name_chirho.endswith((".pem", ".key"))
    )

def main_chirho() -> int:
    root_chirho = Path(__file__).resolve().parent.parent
    process_chirho = subprocess.run(
        ["git", "-C", str(root_chirho), "ls-files", "-z"],
        check=True, stdout=subprocess.PIPE,
    )
    paths_chirho = [path_chirho for path_chirho in process_chirho.stdout.decode().split("\0") if path_chirho]
    refused_chirho = sorted(path_chirho for path_chirho in paths_chirho if refused_path_chirho(path_chirho))
    print(json.dumps({
        "tracked_paths_chirho": len(paths_chirho),
        "refused_paths_chirho": refused_chirho,
        "scope_chirho": "tracked-paths-only-not-content-or-release-clearance-chirho",
    }, sort_keys=True))
    return int(bool(refused_chirho))

if __name__ == "__main__":
    raise SystemExit(main_chirho())
