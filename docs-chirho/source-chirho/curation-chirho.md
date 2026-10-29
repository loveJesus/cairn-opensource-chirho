<!-- For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV) -->
# Curation Decisions

## Retained Closure

The source cut preserves the root package, every declared workspace member and local path dependency, the standalone node-templating crate, nine standalone authored example manifests and their compatible lockfiles, Rust guest examples, WAT fixtures, and the browser assets embedded by the served runtime. The retained manifest graph has 130 manifests, 120 explicitly declared workspace members, 597 local dependency edges, and 552 packages in the root lockfile. These are source-analysis counts, not a parity claim.

Synthetic CAS/JSONL fixtures beneath crate test directories are retained because their source includes fixture generators and negative/tamper tests. They are not copied runtime or customer stores. DAG connection symlinks and executable file modes are preserved, not dereferenced into duplicate files.

The template landing example's checked-in emitted manifest is a required golden-test input. It contains relative source/build coordinates, not installed artifacts or private configuration. An initial exclusion caused the existing tree-build comparison test to fail; the fixture is restored byte-for-byte from the pinned source rather than removing the comparison.

Two generic product-test dependencies are relocated out of the excluded deployment tree:

| Clean Path | Adjustment |
| --- | --- |
| `tools-chirho/app-deploy-chirho/host_ready_app_manifest_chirho.py` | Offline staging helper retained; output paths now reject traversal, escape through symlinks, and collisions. |
| `tools-chirho/app-deploy-chirho/journey-Caddyfile-chirho` | Routing/privacy rules retained as a loopback-only fixture, with HTTP on port 9080, upstreams 8788/8789, no host addresses, no TLS activation, no host log path, and no private operational narrative. |

The staging helper never builds guests or deploys anything. It accepts a trusted local build manifest and existing build artifacts; it is not a public upload service. A refused/partial stage is not deployable and must be discarded or reviewed before reuse. Input artifact paths may intentionally name a workspace-level target directory.

## Exclusions

Excluded categories and counts are committed in `inventory-chirho.json`. Detailed original excluded paths stay only in the ignored private source-audit directory, bound by its aggregate digest. No old agent guides, private PRDs/specification tree, workspace files, host/deployment runbooks, operational evidence, credentials, runtime/customer data, strategy/whitepaper drafts, editor/fleet state, or inherited secret-ignore file is imported. The optional reactive-client experiment is outside the required runtime closure.

Historical workflow references and internal message identifiers in existing code comments are preserved as source provenance, not interpreted automatically as credentials or as shipped workflow documents. Content review and the parent's secret scanner remain separate gates.

## Source Adjustments

- The source walker remains a normal root dependency/re-export. Its production call sites outside its own crate are absent in the reviewed source; runtime regression tests use its JSONL discovery and source-boundary utilities. Its security guards and scanner tests are retained.
- The source-scan crate no longer mounts the private-document guard, the private-deploy-timer growth census, or the old advisory structure report. These were `cfg(test)` modules, not runtime enforcement.
- Seven source-scan test modules tied to excluded runbooks, host packet scripts, old PRD/tasklist archives, or deployment monitoring are omitted. Their mount points are removed. The remaining authority, privacy, ledger, replica, signer, source-walker, and bounded-runtime guards remain.
- The geo-node test-kind integration test that invokes the excluded private foundation-config shell renderer is omitted. Generic cluster/config parsing, authority separation, and host/runtime tests remain; no host packet is imported merely to satisfy this historical shell contract.
- Launch-readiness no longer embeds private hosted history or operator risk acceptance. Report schema v6 retains local contact evidence and the inherited contact-list refusal, supplies no inherited external evidence, and adds an explicit installation-evidence blocker. Local privacy/redaction smoke coverage is retained in a separate test file.
- Optional Git-mode SDK scaffolding now points at the clean source repository, not the original private repository. Default SDK path mode resolves within this source cut. A real reviewed clean commit must be supplied to Git mode; no historical pin is fabricated.

No DAG, auth, privacy, cache, ledger, storage, or provider behavior has been deleted to make a check green. The original root and standalone Cargo lockfiles are not upgraded. Added tests cover import overwrite/path/symlink safety and local artifact staging, not incidental UI text.

## Inherited Holds

The current contact example's submit path is available, but its legacy served contact-list read deliberately refuses with HTTP 400. The source retains that hold rather than reviving a retired read path. Source readiness must remain blocked on a reviewed replacement and installation-specific evidence.

Media integrations include deterministic stubs. Provider credentials, paid effects, public registration/webhooks, real-user delivery, live LLM calls, hosted topology/custody, and production money are not enabled or validated by this import. Product consumption requires an explicit clean-source dependency/pin migration in the app repository.

Some inherited proof scripts assume per-example Cargo target directories and invoke local builds/servers. They have not been executed in this worker's build-only iteration; the pure-WAT quick-start avoids that assumption. Ignored fixture-export tests intentionally rewrite their checked-in synthetic fixtures and must not be run as part of a blanket `--ignored` gate.

The imported structure also inherits a failing layout-policy gate: 13 Rust files have at least 1,500 lines and 31 source directories have at least 15 entries. The largest Rust file is 2,142 lines. These files remain intact; a follow-up structural split must preserve their behavior and tests. The generated lockfile is exempt. Exact included-source layout debt is recorded in `manifests-chirho/layout-holds-chirho.json`; clean compilation does not close it.
