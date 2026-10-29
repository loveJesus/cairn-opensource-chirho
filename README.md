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

## The Good News Of Jesus Christ

Jesus Christ is Lord. We share this work to honor Him and serve our neighbors. More important than any software we can offer is the good news of what He has done for us.

**God loves us.** He is our holy Creator, and He made us to know Him. "For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life." [John 3:16, KJV](https://www.biblegateway.com/passage/?search=John+3%3A16&version=KJV)

**We need forgiveness.** All of us have sinned and fallen short of God's glory. Sin brings death and separates us from God; good deeds, religious effort or useful work cannot erase our guilt. [Romans 3:23; 6:23](https://www.biblegateway.com/passage/?search=Romans+3%3A23%3B+6%3A23&version=KJV)

**Jesus Christ saves.** The eternal Son of God became man, lived without sin, and died on the cross for our sins. He was buried and rose bodily from the dead on the third day. Our hope rests in the living Savior, not in ourselves. [John 1:1, 14; 1 Corinthians 15:3-4](https://www.biblegateway.com/passage/?search=John+1%3A1%2C14%3B+1+Corinthians+15%3A3-4&version=KJV)

**Salvation is God's gift.** "For by grace are ye saved through faith; and that not of yourselves: it is the gift of God: Not of works, lest any man should boast." We do not earn salvation; we receive it through faith in Jesus Christ. [Ephesians 2:8-9, KJV](https://www.biblegateway.com/passage/?search=Ephesians+2%3A8-9&version=KJV)

**Turn to Him and believe.** Repent, turning to God from sin, and trust in Jesus Christ rather than your own goodness. Confess Him as Lord and believe that God raised Him from the dead. He promises that whoever calls on His name will be saved. [Acts 20:21; Romans 10:9-13](https://www.biblegateway.com/passage/?search=Acts+20%3A21%3B+Romans+10%3A9-13&version=KJV)

You can begin by reading the [Gospel of John](https://www.biblegateway.com/passage/?search=John+1&version=KJV). Bring your questions to God in prayer and seek a faithful, Bible-teaching church. You are welcome to use this software whether or not you share our faith; its license, not a religious profession, governs your rights to it.

## License

Runtime and tool code is AGPL-3.0-only, subject to actual third-party licenses. The guest SDK, node-templating library and pure guest examples retain MIT terms. A separate paid commercial license may be negotiated for project-owned rights. Read `LICENSE`, `LICENSE-MIT-CHIRHO.txt` and `docs-chirho/licensing-chirho.md`. Commercial AGPL use is permitted; the commercial alternative is not mandatory for every business.

No deployment, money movement, public signup, webhook, provider activation or real-user delivery is enabled merely by obtaining the source. Patent filing and publication decisions are not operational acceptance.
