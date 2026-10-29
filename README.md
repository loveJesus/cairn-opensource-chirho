<!-- For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV) -->
# Cairn

Cairn is a Rust-first, content-addressed dataflow runtime. Pure WebAssembly nodes run without ambient I/O. Platform-controlled effect modules mediate storage, queries and external operations. Immutable objects, signed provenance, reference history and explicit compensation connect execution to audit and recovery.

This source distribution includes the runtime, CLI, guest SDK, tree-build toolchain, npm-free templating, browser assets and synthetic regression fixtures. It does not contain the original private history, host runbooks, credentials, customer state, private strategy or patent documents. This is experimental software, not a claim that every integration or production safeguard is complete.

## Build And Run

Use the pinned Rust toolchain, rustfmt and clippy. Guest app builds also require `wasm32-unknown-unknown`. Preserve lockfiles. A fresh clone can fetch the locked dependencies; `--offline` requires an existing cache.

```sh
git clone --branch main_chirho https://github.com/loveJesus/cairn-opensource-chirho.git
cd cairn-opensource-chirho
unset CAIRN_BUILD_COMMIT_CHIRHO
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked -j2 -p cairn-cli-chirho -p cairn-tree-build-chirho --bins
target/debug/cairn-chirho --version
```

Follow `docs-chirho/source-chirho/quick-start-chirho.md` for a real pure-WASM DAG, repeat execution and cache verification. `tools-chirho/source-import-chirho/import_source_chirho.py verify-chirho` checks the included-source inventory without the private original repository. `docs-chirho/source-chirho/readiness-chirho.md` states the verification scope and limits.

Perffection is a separate application repository. Clone it beside this directory when building that product. Cairn has no dependency on a Perffection checkout.

## License

Runtime and tool code is AGPL-3.0-only, subject to actual third-party licenses. The guest SDK, node-templating library and pure guest examples retain MIT terms. A separate paid commercial license may be negotiated for project-owned rights. Read `LICENSE`, `LICENSE-MIT-CHIRHO.txt` and `docs-chirho/licensing-chirho.md`. Commercial AGPL use is permitted; the commercial alternative is not mandatory for every business.

No deployment, money movement, public signup, webhook, provider activation or real-user delivery is enabled merely by obtaining the source. Patent filing and publication decisions are not operational acceptance.
