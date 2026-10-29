#!/usr/bin/env python3
# For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
"""Import or inventory the reviewed, committed Cairn source without copying history.

Only import-chirho writes runtime files. inventory-chirho records source and current
hashes after reviewed edits. verify-chirho checks those records without the old repo.
No command runs Cargo, contacts providers, reads .env, or changes Git state.
"""

import argparse
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import tarfile
import tomllib

BASE_COMMIT_CHIRHO = "74e0c48393d8ec105dc45b77954adae243a2d888"
ROOT_CHIRHO = Path(__file__).resolve().parents[2]
DOCS_CHIRHO = ROOT_CHIRHO / "docs-chirho/source-chirho"
PRIVATE_AUDIT_CHIRHO = ROOT_CHIRHO / "workspace-chirho/private-chirho/source-audit-chirho"
ROOT_FILES_CHIRHO = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rustfmt.toml"}
SOURCE_PREFIXES_CHIRHO = ("src/", "crates/", "tests/", "examples/", "examples-chirho/")
CLIENT_FILES_CHIRHO = {
    "client-chirho/host-chirho.js",
    "client-chirho/runtime-package-host-chirho.js",
    "client-chirho/transport-chirho.js",
    "client-chirho/htmx-lite-chirho.js",
    "client-chirho/htmx-lite-smoke-chirho.mjs",
    "client-chirho/demo-chirho.html",
}
RELOCATIONS_CHIRHO = {
    "deploy-chirho/beta-chirho/host_ready_app_manifest_chirho.py":
        "tools-chirho/app-deploy-chirho/host_ready_app_manifest_chirho.py",
    "deploy-chirho/beta-chirho/Caddyfile":
        "tools-chirho/app-deploy-chirho/journey-Caddyfile-chirho",
}
SCAN_BASE_CHIRHO = "crates/support-chirho/cairn-source-scan-chirho/src/"
PRIVATE_SCAN_TESTS_CHIRHO = {
    "cf6_cf7_transition_chirho/cf6_runbook_shell_guard_tests_chirho.rs",
    "cf6_cf7_transition_chirho/cf8_lineage_shared_journal_guard_tests_chirho.rs",
    "cf6_cf7_transition_chirho/finalization_prd_archive_guard_tests_chirho.rs",
    "cf6_cf7_transition_chirho/public_root_inventory_guard_tests_chirho.rs",
    "ha_gate1_flip_chirho/wave1_zero_gate_guard_tests_chirho.rs",
    "ha_gate1_soak_monitor_guard_tests_chirho.rs",
    "live_credential_fence_guard_tests_chirho.rs",
}
EXACT_EXCLUSIONS_CHIRHO = {
    SCAN_BASE_CHIRHO + "docs_guard_tests_chirho.rs": "private-doc-and-ops-guard-chirho",
    SCAN_BASE_CHIRHO + "growth_gate_chirho.rs": "private-deploy-timer-growth-census-chirho",
    "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/tests/cf7_foundation_config_chirho.rs":
        "private-host-packet-renderer-contract-chirho",
}
for relative_chirho in PRIVATE_SCAN_TESTS_CHIRHO:
    EXACT_EXCLUSIONS_CHIRHO[SCAN_BASE_CHIRHO + "source_scan_chirho/tests_chirho/" + relative_chirho] = (
        "private-doc-and-ops-guard-chirho"
    )
EXCLUDED_PREFIXES_CHIRHO = {
    SCAN_BASE_CHIRHO + "growth_gate_chirho/": "private-deploy-timer-growth-census-chirho",
    SCAN_BASE_CHIRHO + "source_scan_chirho/structure_report_chirho/":
        "old-workspace-advisory-structure-report-chirho",
    "spec-chirho/": "private-spec-prd-and-operational-evidence-chirho",
    "workspace-chirho/": "private-workspace-and-runtime-material-chirho",
    "deploy-chirho/": "private-host-deploy-and-operational-evidence-chirho",
    "fleet-tools-chirho/": "internal-agent-fleet-tooling-chirho",
    "docs-chirho/": "old-internal-design-strategy-and-fleet-docs-chirho",
    "client-reactive-chirho/": "optional-reactive-client-outside-runtime-closure-chirho",
}
PROTECTED_NAMES_CHIRHO = {"AGENTS.md", "CLAUDE.md", "README.md", ".gitignore", ".gitleaksignore", ".gitleaks.toml"}
SHARD_ROWS_CHIRHO = 500


def digest_chirho(blob_chirho: bytes) -> str:
    return hashlib.sha256(blob_chirho).hexdigest()


def git_chirho(repo_chirho: Path, *args_chirho: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo_chirho), *args_chirho])


def source_tree_chirho(repo_chirho: Path) -> dict:
    rows_chirho = git_chirho(repo_chirho, "ls-tree", "-r", "-z", "--full-tree", "--long", BASE_COMMIT_CHIRHO)
    tree_chirho = {}
    for row_chirho in rows_chirho.split(b"\0"):
        if not row_chirho:
            continue
        metadata_chirho, path_chirho = row_chirho.split(b"\t", 1)
        mode_chirho, kind_chirho, oid_chirho, size_chirho = metadata_chirho.decode().split()
        if kind_chirho != "blob":
            raise ValueError("unexpected non-blob source entry")
        tree_chirho[path_chirho.decode()] = {
            "source_mode_chirho": mode_chirho,
            "source_git_blob_chirho": oid_chirho,
            "source_bytes_chirho": int(size_chirho),
        }
    return tree_chirho


def disposition_chirho(path_chirho: str) -> tuple[str | None, str]:
    parts_chirho = PurePosixPath(path_chirho).parts
    if any(part_chirho in PROTECTED_NAMES_CHIRHO for part_chirho in parts_chirho):
        return None, "parent-owned-guide-or-private-ignore-chirho"
    if any(part_chirho == ".env" or part_chirho.startswith(".env.") for part_chirho in parts_chirho):
        return None, "credentials-configuration-chirho"
    if path_chirho in RELOCATIONS_CHIRHO:
        return RELOCATIONS_CHIRHO[path_chirho], "relocated-generic-offline-build-tool-chirho"
    if path_chirho in EXACT_EXCLUSIONS_CHIRHO:
        return None, EXACT_EXCLUSIONS_CHIRHO[path_chirho]
    for prefix_chirho, reason_chirho in EXCLUDED_PREFIXES_CHIRHO.items():
        if path_chirho.startswith(prefix_chirho):
            return None, reason_chirho
    if path_chirho in ROOT_FILES_CHIRHO or path_chirho in CLIENT_FILES_CHIRHO:
        return path_chirho, "build-contract-or-embedded-browser-asset-chirho"
    if path_chirho.startswith(SOURCE_PREFIXES_CHIRHO):
        if path_chirho.endswith(".md"):
            return None, "old-non-runtime-narrative-chirho"
        return path_chirho, "runtime-toolchain-test-or-authored-example-chirho"
    return None, "private-root-doc-config-strategy-or-editor-artifact-chirho"


def safe_destination_chirho(relative_chirho: str) -> Path:
    parts_chirho = PurePosixPath(relative_chirho).parts
    if not parts_chirho or PurePosixPath(relative_chirho).is_absolute() or ".." in parts_chirho:
        raise ValueError("invalid destination path")
    if parts_chirho[0] in {".git", "spec-chirho"} or any(part_chirho in PROTECTED_NAMES_CHIRHO for part_chirho in parts_chirho):
        raise ValueError("parent-owned destination")
    result_chirho = ROOT_CHIRHO / relative_chirho
    if not result_chirho.parent.resolve().is_relative_to(ROOT_CHIRHO):
        raise ValueError("destination parent escapes repository")
    return result_chirho


def source_blobs_chirho(repo_chirho: Path, paths_chirho: list[str]) -> dict:
    archive_bytes_chirho = git_chirho(repo_chirho, "archive", "--format=tar", BASE_COMMIT_CHIRHO, "--", *paths_chirho)
    blobs_chirho = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes_chirho)) as archive_chirho:
        for member_chirho in archive_chirho:
            if member_chirho.name not in paths_chirho:
                continue
            if member_chirho.issym():
                blobs_chirho[member_chirho.name] = member_chirho.linkname.encode()
            elif member_chirho.isfile():
                blobs_chirho[member_chirho.name] = archive_chirho.extractfile(member_chirho).read()
            else:
                raise ValueError("unsupported archive entry")
    if set(blobs_chirho) != set(paths_chirho):
        raise ValueError("git archive omitted selected source entries")
    return blobs_chirho


def path_dependencies_chirho(manifest_chirho: dict):
    for key_chirho, value_chirho in manifest_chirho.items():
        if not isinstance(value_chirho, dict):
            continue
        if key_chirho in {"dependencies", "dev-dependencies", "build-dependencies"}:
            for name_chirho, dependency_chirho in value_chirho.items():
                if isinstance(dependency_chirho, dict) and "path" in dependency_chirho:
                    yield name_chirho, dependency_chirho["path"]
        else:
            yield from path_dependencies_chirho(value_chirho)


def closure_chirho(paths_chirho: list[str]) -> dict:
    manifests_chirho = {}
    for relative_chirho in paths_chirho:
        if relative_chirho.endswith("Cargo.toml"):
            manifests_chirho[relative_chirho] = tomllib.loads(safe_destination_chirho(relative_chirho).read_text())
    dependencies_chirho = []
    for relative_chirho, manifest_chirho in manifests_chirho.items():
        for name_chirho, dependency_path_chirho in path_dependencies_chirho(manifest_chirho):
            resolved_chirho = posixpath.normpath(posixpath.join(posixpath.dirname(relative_chirho), dependency_path_chirho, "Cargo.toml"))
            if resolved_chirho not in manifests_chirho:
                raise ValueError(f"missing path dependency: {relative_chirho} -> {resolved_chirho}")
            dependencies_chirho.append({"from_chirho": relative_chirho, "dependency_chirho": name_chirho, "to_chirho": resolved_chirho})
    root_manifest_chirho = manifests_chirho["Cargo.toml"]
    for member_chirho in root_manifest_chirho["workspace"]["members"]:
        member_manifest_chirho = posixpath.normpath(posixpath.join(member_chirho, "Cargo.toml"))
        if member_manifest_chirho not in manifests_chirho:
            raise ValueError(f"missing workspace member: {member_chirho}")
    return {
        "manifest_count_chirho": len(manifests_chirho),
        "declared_workspace_member_count_chirho": len(root_manifest_chirho["workspace"]["members"]),
        "path_dependency_edges_chirho": len(dependencies_chirho),
        "all_path_dependencies_local_chirho": True,
        "lock_package_count_chirho": len(tomllib.loads((ROOT_CHIRHO / "Cargo.lock").read_text())["package"]),
        "dependencies_chirho": dependencies_chirho,
    }


def write_json_chirho(path_chirho: Path, value_chirho) -> None:
    path_chirho.parent.mkdir(parents=True, exist_ok=True)
    path_chirho.write_text(json.dumps(value_chirho, indent=2, sort_keys=True) + "\n")
    if path_chirho.is_relative_to(PRIVATE_AUDIT_CHIRHO):
        PRIVATE_AUDIT_CHIRHO.chmod(0o700)
        path_chirho.chmod(0o600)


def write_shards_chirho(kind_chirho: str, rows_chirho: list[dict], base_chirho: Path | None = None) -> list[str]:
    directory_chirho = (base_chirho or DOCS_CHIRHO / "manifests-chirho") / kind_chirho
    directory_chirho.mkdir(parents=True, exist_ok=True)
    private_chirho = directory_chirho.is_relative_to(PRIVATE_AUDIT_CHIRHO)
    if private_chirho:
        PRIVATE_AUDIT_CHIRHO.chmod(0o700)
        directory_chirho.chmod(0o700)
    names_chirho = []
    for start_chirho in range(0, len(rows_chirho), SHARD_ROWS_CHIRHO):
        shard_chirho = directory_chirho / f"{start_chirho:04d}-chirho.jsonl"
        shard_chirho.write_text("".join(json.dumps(row_chirho, sort_keys=True) + "\n" for row_chirho in rows_chirho[start_chirho:start_chirho + SHARD_ROWS_CHIRHO]))
        if private_chirho:
            shard_chirho.chmod(0o600)
        names_chirho.append(str(shard_chirho.relative_to(ROOT_CHIRHO)))
    for obsolete_chirho in directory_chirho.glob("*-chirho.jsonl"):
        if str(obsolete_chirho.relative_to(ROOT_CHIRHO)) not in names_chirho:
            obsolete_chirho.unlink()
    return names_chirho


def import_chirho(tree_chirho: dict, blobs_chirho: dict, selected_chirho: dict) -> None:
    # Check every overwrite and symlink before writing any imported bytes.
    for source_chirho, destination_chirho in selected_chirho.items():
        output_chirho = safe_destination_chirho(destination_chirho)
        if output_chirho.exists() or output_chirho.is_symlink():
            raise ValueError(f"refusing to overwrite an existing path: {destination_chirho}")
        if tree_chirho[source_chirho]["source_mode_chirho"] == "120000":
            target_chirho = blobs_chirho[source_chirho].decode()
            resolved_chirho = posixpath.normpath(posixpath.join(posixpath.dirname(destination_chirho), target_chirho))
            if target_chirho.startswith("/") or resolved_chirho.startswith("../"):
                raise ValueError("symlink escapes imported source")
    for source_chirho, destination_chirho in selected_chirho.items():
        if tree_chirho[source_chirho]["source_mode_chirho"] == "120000":
            continue
        output_chirho = safe_destination_chirho(destination_chirho)
        output_chirho.parent.mkdir(parents=True, exist_ok=True)
        output_chirho.write_bytes(blobs_chirho[source_chirho])
        output_chirho.chmod(int(tree_chirho[source_chirho]["source_mode_chirho"], 8) & 0o777)
    for source_chirho, destination_chirho in selected_chirho.items():
        if tree_chirho[source_chirho]["source_mode_chirho"] == "120000":
            output_chirho = safe_destination_chirho(destination_chirho)
            output_chirho.parent.mkdir(parents=True, exist_ok=True)
            output_chirho.symlink_to(blobs_chirho[source_chirho].decode())


def current_blob_chirho(path_chirho: Path) -> bytes:
    return os.readlink(path_chirho).encode() if path_chirho.is_symlink() else path_chirho.read_bytes()


def inventory_chirho(repo_chirho: Path, tree_chirho: dict, blobs_chirho: dict, selected_chirho: dict) -> dict:
    included_chirho = []
    excluded_chirho = []
    for source_chirho, record_chirho in sorted(tree_chirho.items()):
        destination_chirho, reason_chirho = disposition_chirho(source_chirho)
        row_chirho = {"source_path_chirho": source_chirho, "reason_chirho": reason_chirho, **record_chirho}
        if destination_chirho is None:
            excluded_chirho.append(row_chirho)
            continue
        path_chirho = safe_destination_chirho(destination_chirho)
        current_chirho = current_blob_chirho(path_chirho)
        row_chirho.update({
            "path_chirho": destination_chirho,
            "source_sha256_chirho": digest_chirho(blobs_chirho[source_chirho]),
            "sha256_chirho": digest_chirho(current_chirho),
            "bytes_chirho": len(current_chirho),
            "modified_chirho": current_chirho != blobs_chirho[source_chirho],
        })
        included_chirho.append(row_chirho)
    closure_report_chirho = closure_chirho(list(selected_chirho.values()))
    edges_chirho = closure_report_chirho.pop("dependencies_chirho")
    closure_report_chirho["dependency_shards_chirho"] = write_shards_chirho("dependencies-chirho", edges_chirho)
    write_json_chirho(DOCS_CHIRHO / "manifests-chirho/closure-chirho.json", closure_report_chirho)
    excluded_shards_chirho = write_shards_chirho("excluded-chirho", excluded_chirho, PRIVATE_AUDIT_CHIRHO)
    excluded_audit_sha256_chirho = digest_chirho("".join(json.dumps(row_chirho, sort_keys=True) + "\n" for row_chirho in excluded_chirho).encode())
    write_json_chirho(PRIVATE_AUDIT_CHIRHO / "excluded-inventory-chirho.json", {
        "base_commit_chirho": BASE_COMMIT_CHIRHO,
        "excluded_path_count_chirho": len(excluded_chirho),
        "excluded_shards_chirho": excluded_shards_chirho,
        "excluded_audit_sha256_chirho": excluded_audit_sha256_chirho,
        "scope_chirho": "private path-only audit; no excluded source content copied",
    })
    summary_chirho = {
        "schema_chirho": "committed-source-inventory-v1-chirho",
        "base_commit_chirho": BASE_COMMIT_CHIRHO,
        "base_tree_chirho": git_chirho(repo_chirho, "rev-parse", BASE_COMMIT_CHIRHO + "^{tree}").decode().strip(),
        "source_path_count_chirho": len(tree_chirho),
        "included_path_count_chirho": len(included_chirho),
        "excluded_path_count_chirho": len(excluded_chirho),
        "included_bytes_chirho": sum(row_chirho["bytes_chirho"] for row_chirho in included_chirho),
        "modified_paths_chirho": [row_chirho["path_chirho"] for row_chirho in included_chirho if row_chirho["modified_chirho"]],
        "included_shards_chirho": write_shards_chirho("included-chirho", included_chirho),
        "excluded_categories_chirho": dict(sorted(Counter(row_chirho["reason_chirho"] for row_chirho in excluded_chirho).items())),
        "excluded_audit_sha256_chirho": excluded_audit_sha256_chirho,
        "import_command_compiles_chirho": False,
        "runtime_parity_claimed_chirho": False,
    }
    write_json_chirho(DOCS_CHIRHO / "inventory-chirho.json", summary_chirho)
    return {key_chirho: value_chirho for key_chirho, value_chirho in summary_chirho.items() if not key_chirho.endswith("shards_chirho")}


def verify_chirho() -> dict:
    inventory_path_chirho = DOCS_CHIRHO / "inventory-chirho.json"
    summary_chirho = json.loads(inventory_path_chirho.read_text())
    if summary_chirho["base_commit_chirho"] != BASE_COMMIT_CHIRHO:
        raise ValueError("inventory source pin mismatch")
    paths_chirho = []
    for shard_chirho in summary_chirho["included_shards_chirho"]:
        for text_chirho in safe_destination_chirho(shard_chirho).read_text().splitlines():
            row_chirho = json.loads(text_chirho)
            relative_chirho = row_chirho["path_chirho"]
            expected_chirho, _reason_chirho = disposition_chirho(row_chirho["source_path_chirho"])
            if relative_chirho != expected_chirho or relative_chirho in paths_chirho:
                raise ValueError("inventory selection mismatch or duplicate")
            path_chirho = safe_destination_chirho(relative_chirho)
            blob_chirho = current_blob_chirho(path_chirho)
            if digest_chirho(blob_chirho) != row_chirho["sha256_chirho"] or len(blob_chirho) != row_chirho["bytes_chirho"]:
                raise ValueError(f"inventory hash mismatch: {relative_chirho}")
            if row_chirho["source_mode_chirho"] == "120000":
                if not path_chirho.is_symlink() or not path_chirho.resolve().is_relative_to(ROOT_CHIRHO) or not path_chirho.exists():
                    raise ValueError(f"broken or escaping source symlink: {relative_chirho}")
            elif path_chirho.is_symlink() or (path_chirho.stat().st_mode & 0o777) != (int(row_chirho["source_mode_chirho"], 8) & 0o777):
                raise ValueError(f"source type or mode mismatch: {relative_chirho}")
            paths_chirho.append(relative_chirho)
    if len(paths_chirho) != summary_chirho["included_path_count_chirho"]:
        raise ValueError("inventory count mismatch")
    closure_report_chirho = closure_chirho(paths_chirho)
    expected_closure_chirho = json.loads((DOCS_CHIRHO / "manifests-chirho/closure-chirho.json").read_text())
    expected_edges_chirho = []
    for shard_chirho in expected_closure_chirho.pop("dependency_shards_chirho"):
        expected_edges_chirho.extend(json.loads(line_chirho) for line_chirho in safe_destination_chirho(shard_chirho).read_text().splitlines())
    expected_closure_chirho["dependencies_chirho"] = expected_edges_chirho
    if closure_report_chirho != expected_closure_chirho:
        raise ValueError("path dependency closure changed")
    return {"schema_chirho": "committed-source-verify-v1-chirho", "verified_paths_chirho": len(paths_chirho), "path_dependencies_local_chirho": True}


def main_chirho() -> None:
    parser_chirho = argparse.ArgumentParser(description=__doc__)
    parser_chirho.add_argument("action_chirho", choices=["import-chirho", "inventory-chirho", "verify-chirho"])
    parser_chirho.add_argument("--source-repo-chirho", type=Path)
    args_chirho = parser_chirho.parse_args()
    if args_chirho.action_chirho == "verify-chirho":
        print(json.dumps(verify_chirho(), indent=2))
        return
    if args_chirho.source_repo_chirho is None:
        parser_chirho.error("--source-repo-chirho is required for import or inventory")
    repo_chirho = args_chirho.source_repo_chirho.resolve()
    if repo_chirho == ROOT_CHIRHO or ROOT_CHIRHO.is_relative_to(repo_chirho):
        parser_chirho.error("source and destination must be independent repositories")
    tree_chirho = source_tree_chirho(repo_chirho)
    selected_chirho = {path_chirho: disposition_chirho(path_chirho)[0] for path_chirho in tree_chirho if disposition_chirho(path_chirho)[0] is not None}
    blobs_chirho = source_blobs_chirho(repo_chirho, list(selected_chirho))
    if args_chirho.action_chirho == "import-chirho":
        import_chirho(tree_chirho, blobs_chirho, selected_chirho)
    print(json.dumps(inventory_chirho(repo_chirho, tree_chirho, blobs_chirho, selected_chirho), indent=2))


if __name__ == "__main__":
    main_chirho()
