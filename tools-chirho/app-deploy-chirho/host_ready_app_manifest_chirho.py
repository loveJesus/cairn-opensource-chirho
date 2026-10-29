#!/usr/bin/env python3
# For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
"""Turn a tree-build emitted app manifest into a HOST-READY manifest plus a staging directory.

A host has no Rust toolchain. `app-source-deploy` compiles every `cargo-example-chirho` node source
with cargo, so an emitted manifest cannot be deployed on the host as-is. This script rewrites each
cargo-example node into a `path-chirho` node pointing at the ALREADY-BUILT `.wasm` copied beside
the manifest, copies path-kind assets the same way, and writes a basename-only SHA-256 list so the
deploy step can verify the staged bytes before the host runs `app-source-deploy`.

It never runs cargo: a missing artifact is a refusal, not a build. The emitted manifest and the
guest wasm must be produced first (the app's own `cargo build --examples --target
wasm32-unknown-unknown` plus `tree-build-chirho emit`).

Usage:
  host_ready_app_manifest_chirho.py <app_dir> <stage_dir>
"""

import hashlib
import json
import pathlib
import shutil
import sys

EMITTED_MANIFEST_NAME_CHIRHO = ".emitted-manifest-chirho.json"
HOSTED_SUFFIX_CHIRHO = "-hosted-source-manifest-chirho.json"
SHA256_LIST_NAME_CHIRHO = "sha256-chirho.txt"


def sha256_file_chirho(path_chirho: pathlib.Path) -> str:
    digest_chirho = hashlib.sha256()
    with path_chirho.open("rb") as handle_chirho:
        for chunk_chirho in iter(lambda: handle_chirho.read(1 << 20), b""):
            digest_chirho.update(chunk_chirho)
    return digest_chirho.hexdigest()


def refuse_chirho(message_chirho: str) -> None:
    print(f"REFUSING: {message_chirho}", file=sys.stderr)
    sys.exit(2)


def stage_path_chirho(stage_dir_chirho: pathlib.Path, relative_name_chirho: str) -> pathlib.Path:
    relative_chirho = pathlib.PurePosixPath(relative_name_chirho)
    if (
        relative_chirho.is_absolute()
        or ".." in relative_chirho.parts
        or "\\" in relative_name_chirho
        or "\x00" in relative_name_chirho
        or not relative_chirho.parts
    ):
        refuse_chirho("staging name must be a nonempty relative path without traversal")
    destination_chirho = stage_dir_chirho / relative_name_chirho
    if not destination_chirho.resolve().is_relative_to(stage_dir_chirho.resolve()):
        refuse_chirho("staging destination escapes the selected directory")
    if destination_chirho.exists() or destination_chirho.is_symlink():
        refuse_chirho(f"staging collision, two sources want {relative_name_chirho}")
    return destination_chirho


def stage_file_chirho(
    source_chirho: pathlib.Path, stage_dir_chirho: pathlib.Path, relative_name_chirho: str
) -> pathlib.Path:
    if not source_chirho.is_file():
        refuse_chirho(f"artifact is not a regular file: {source_chirho}")
    destination_chirho = stage_path_chirho(stage_dir_chirho, relative_name_chirho)
    destination_chirho.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_chirho, destination_chirho)
    return destination_chirho


def main_chirho(argv_chirho: list[str]) -> int:
    if len(argv_chirho) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    app_dir_chirho = pathlib.Path(argv_chirho[1]).resolve()
    stage_dir_chirho = pathlib.Path(argv_chirho[2]).resolve()
    emitted_path_chirho = app_dir_chirho / EMITTED_MANIFEST_NAME_CHIRHO
    if not emitted_path_chirho.is_file():
        refuse_chirho(f"no emitted manifest at {emitted_path_chirho}; run tree-build emit first")
    if stage_dir_chirho.exists() and any(stage_dir_chirho.iterdir()):
        refuse_chirho(f"stage dir is not empty: {stage_dir_chirho}")
    stage_dir_chirho.mkdir(parents=True, exist_ok=True)

    manifest_chirho = json.loads(emitted_path_chirho.read_text())
    app_name_chirho = manifest_chirho["app_chirho"]
    staged_chirho: list[pathlib.Path] = []
    rewritten_nodes_chirho = 0

    for node_chirho in manifest_chirho.get("nodes_chirho", []):
        source_chirho = node_chirho["source_chirho"]
        kind_chirho = source_chirho["kind_chirho"]
        if kind_chirho == "cargo-example-chirho":
            manifest_rel_chirho = source_chirho.get("manifest_path_chirho") or "Cargo.toml"
            crate_dir_chirho = (app_dir_chirho / manifest_rel_chirho).resolve().parent
            artifact_chirho = (crate_dir_chirho / source_chirho["artifact_path_chirho"]).resolve()
            relative_name_chirho = f"{source_chirho['example_chirho']}.wasm"
            staged_chirho.append(stage_file_chirho(artifact_chirho, stage_dir_chirho, relative_name_chirho))
            node_chirho["source_chirho"] = {"kind_chirho": "path-chirho", "path_chirho": relative_name_chirho}
            rewritten_nodes_chirho += 1
        elif kind_chirho == "path-chirho":
            artifact_chirho = (app_dir_chirho / source_chirho["path_chirho"]).resolve()
            relative_name_chirho = f"nodes-chirho/{pathlib.Path(source_chirho['path_chirho']).name}"
            staged_chirho.append(stage_file_chirho(artifact_chirho, stage_dir_chirho, relative_name_chirho))
            node_chirho["source_chirho"] = {"kind_chirho": "path-chirho", "path_chirho": relative_name_chirho}
        # stored-node, builtin-node-template, and builtin-phi sources carry no local file.

    for asset_chirho in manifest_chirho.get("assets_chirho", []):
        source_chirho = asset_chirho["source_chirho"]
        if source_chirho.get("kind_chirho") != "path-chirho":
            continue
        artifact_chirho = (app_dir_chirho / source_chirho["path_chirho"]).resolve()
        relative_name_chirho = f"assets-chirho/{asset_chirho['name_chirho']}"
        staged_chirho.append(stage_file_chirho(artifact_chirho, stage_dir_chirho, relative_name_chirho))
        asset_chirho["source_chirho"] = {"kind_chirho": "path-chirho", "path_chirho": relative_name_chirho}

    hosted_path_chirho = stage_path_chirho(stage_dir_chirho, f"{app_name_chirho}{HOSTED_SUFFIX_CHIRHO}")
    hosted_path_chirho.write_text(json.dumps(manifest_chirho, indent=2, sort_keys=True) + "\n")

    rows_chirho = []
    for path_chirho in [hosted_path_chirho, *staged_chirho]:
        rows_chirho.append(f"{sha256_file_chirho(path_chirho)}  {path_chirho.relative_to(stage_dir_chirho)}")
    (stage_dir_chirho / SHA256_LIST_NAME_CHIRHO).write_text("\n".join(rows_chirho) + "\n")

    print(
        json.dumps(
            {
                "schema_chirho": "host-ready-app-manifest-report-v1-chirho",
                "app_chirho": app_name_chirho,
                "hosted_manifest_chirho": hosted_path_chirho.name,
                "rewritten_cargo_example_nodes_chirho": rewritten_nodes_chirho,
                "staged_file_count_chirho": len(staged_chirho),
                "sha256_list_chirho": SHA256_LIST_NAME_CHIRHO,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main_chirho(sys.argv))
