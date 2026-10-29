<!-- For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV) -->
# Local Quick-Start

Run from this repository's root. Rust 1.93.0 is pinned by `rust-toolchain.toml`. The lockfiles are retained; do not refresh them as part of setup. `--offline` requires the pinned dependencies already to be cached. A missing cached dependency is an explicit prerequisite failure, not permission to upgrade it.

## Pure WASM DAG

These commands build the real CLI/toolchain, then register and execute the shipped bytes-ABI WASM example twice. They use no public server, provider, credentials, product repository, or private source path. They are a runnable example, not a claim that this source preparation has already passed its frozen runtime gate.

```sh
export CARGO_TARGET_DIR="$PWD/target"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
unset CAIRN_BUILD_COMMIT_CHIRHO
cargo build --offline --locked -j2 -p cairn-cli-chirho -p cairn-tree-build-chirho --bins

CLI_CHIRHO="$PWD/target/debug/cairn-chirho"
ROOT_CHIRHO="$(mktemp -d "$PWD/target/quick-start-root-chirho.XXXXXX")"
NODE_CHIRHO="$("$CLI_CHIRHO" --root "$ROOT_CHIRHO" node-build examples-chirho/reverse-chirho.wat --name reverse_chirho --entry reverse_chirho)"
DAG_CHIRHO="$("$CLI_CHIRHO" --root "$ROOT_CHIRHO" dag-build --node "$NODE_CHIRHO")"
"$CLI_CHIRHO" --root "$ROOT_CHIRHO" dag-run "$DAG_CHIRHO" 'hello cairn'
"$CLI_CHIRHO" --root "$ROOT_CHIRHO" dag-run "$DAG_CHIRHO" 'hello cairn'
"$CLI_CHIRHO" --root "$ROOT_CHIRHO" run-cache-verify --json
"$CLI_CHIRHO" --version
```

The payload should be `nriac olleh`; the second run should report a cache hit. The runtime writes only the disposable selected root, including local signing material required by its provenance records. Do not use personal/customer input in this example or commit its generated root. Check `--version` against the actual reviewed clean-source commit before relying on a binary; the private base commit is provenance, not a replacement binary stamp.

## Authoring and Packaging

```sh
target/debug/tree-build-chirho check --json examples-chirho/tree-contact-chirho
target/debug/tree-build-chirho check --json examples-chirho/tree-template-landing-chirho
python3 -B tools-chirho/source-import-chirho/import_source_chirho.py verify-chirho
```

Tree-build also supplies `new`, `emit`, `source-dictionary`, `template-render`, `template-guest`, `style-compile`, and node-fixture testing. SDK guests live in `crates/cairn-node-sdk-chirho`; npm-free templating lives in `crates/authoring-chirho/cairn-node-templating-chirho`. Rust guest compilation needs the `wasm32-unknown-unknown` target; this pure-WAT example does not.

For an authored app with an emitted manifest and already-built guests, invoke the offline packaging helper with the app directory and a new empty staging directory:

```sh
python3 -B tools-chirho/app-deploy-chirho/host_ready_app_manifest_chirho.py "$APP_DIR_CHIRHO" "$STAGE_DIR_CHIRHO"
```

The helper copies existing guest/assets, rewrites sources to relative staged paths, and emits SHA-256 checksums. It does not compile or deploy. The separate `journey-Caddyfile-chirho` is a loopback-only product-test fixture for two pre-running local roots; it is not a host deployment configuration.
