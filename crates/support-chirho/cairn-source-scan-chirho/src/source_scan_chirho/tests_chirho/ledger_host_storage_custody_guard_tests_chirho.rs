// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Confines the writer-lock custody surface that a CRATE BOUNDARY forced into `pub`.
//!
//! Lane-D wave 1 extracted the ledger host's filesystem storage adapter into
//! `cairn-ledger-host-storage-chirho`. The move was byte-identical in behaviour — git recorded both
//! files as renames — but it could not be byte-identical in AUTHORITY, because **a crate boundary
//! cannot carry `pub(crate)`**. Items the host crate consumes had to become `pub`, and among them is
//! the entire writer-lock custody mechanism: the guard, its handle, the acquire, the custody check,
//! the storage accessor, and the lock provisioner.
//!
//! That mechanism is the money fence's custody path. A previous brick (BIND-1) spent itself
//! narrowing it — sole construction site, the guard carries its own storage, ten signatures taking
//! the guard alone. Without this file, the extraction would have quietly handed that surface to the
//! whole workspace, and **no test would have gone red**, because nothing pinned "this type is not
//! visible elsewhere". A widening that no test can see is exactly the change that wears an
//! identical-behaviour label.
//!
//! So the boundary that `pub(crate)` used to enforce by the compiler is enforced here by a guard
//! instead: the named custody items may be mentioned only by the crate that defines them and the
//! one crate that consumed them before the move. This is PRESERVATION, not improvement — it holds
//! the surface exactly as narrow as it was on 2026-08-08, no narrower and no wider.
//!
//! Confinement shape: it gets STRICTER as consumers disappear and never needs retiring. It pins the
//! SET of allowed crates, not a count, so a consumer that moves crate is a failure rather than a
//! silent pass.
//!
//! # MIGRATION PATH
//!
//! - A NEW crate legitimately needing custody access is a MONEY-AUTHORITY REVIEW, not a row edit.
//!   Add it here only with the reason it may hold a writer-lock guard.
//! - If the storage crate is ever folded back in, this guard becomes vacuous rather than wrong —
//!   delete it in the same brick that removes the boundary, and say so.
//! - If a needle stops appearing anywhere, do NOT retire it: the item may have been renamed, and a
//!   census that silently matches nothing is the failure this suite exists to prevent. The
//!   positive-control test below fails first in that case, by design.

use super::super::*;
use std::collections::BTreeSet;

/// The UNAMBIGUOUS custody needles: type names that exist nowhere else in the workspace.
///
/// The method names are deliberately NOT in this list. The first version of this guard used bare
/// `try_acquire_chirho` / `verify_custody_chirho` and reported four unrelated crates — the elector
/// handle, the durable descriptor root and others each own a method of the same name. **A bare
/// method name is not an identity**, which is the technique the sibling warrant-consumer guard
/// documents in its own header and which this file failed to apply on its first pass.
const CUSTODY_TYPE_NEEDLES_CHIRHO: &[&str] = &[
    "StableLedgerExclusiveLockGuardChirho",
    "StableLedgerExclusiveLockHandleChirho",
];

/// The custody METHODS. A file counts as touching them only when it ALSO names one of the types
/// above — that pairing is what distinguishes a real custody consumer from an unrelated user of a
/// similarly named method.
const CUSTODY_METHOD_NEEDLES_CHIRHO: &[&str] = &[
    "try_acquire_chirho",
    "verify_custody_chirho",
    "provision_exclusive_lock_handle_chirho",
    "open_existing_exclusive_lock_handle_chirho",
];

/// The only crates that may name a custody item: the definer, and the single consumer that held
/// this access before the extraction.
const ALLOWED_CRATE_PREFIXES_CHIRHO: &[&str] = &[
    "crates/ledger-chirho/host-chirho/cairn-ledger-host-storage-chirho/",
    "crates/ledger-chirho/cairn-ledger-host-chirho/",
];

/// Files exempt because they NAME these items in order to GUARD them. A guard is armour, not a
/// consumer: it holds no lock and calls no method, it asserts a property about the text.
///
/// Exempted by EXACT PATH rather than by crate, deliberately. Exempting all of
/// `cairn-source-scan-chirho` would let a future real consumer hide inside the guard suite — the
/// broad exemption that quietly disables the check is a failure this repo has already paid for.
const GUARD_FILE_EXEMPTIONS_CHIRHO: &[(&str, &str)] = &[
    (
        "crates/support-chirho/cairn-source-scan-chirho/src/source_scan_chirho/tests_chirho/ledger_host_storage_custody_guard_tests_chirho.rs",
        "this file: it names every needle in its own allowlist",
    ),
    (
        "crates/support-chirho/cairn-source-scan-chirho/src/source_scan_chirho/tests_chirho/ha2_writer_head_chirho/gd7_guard_storage_binding_guard_tests_chirho.rs",
        "the D1 storage-binding guard: pins that money-fence movers take the guard ALONE and reach \
         storage through it, so it must name the guard type and the custody check as literals",
    ),
];

fn workspace_rs_files_chirho() -> Vec<std::path::PathBuf> {
    let root_chirho = workspace_root_chirho();
    let mut files_chirho = Vec::new();
    collect_rs_files_chirho(&root_chirho.join("src"), &mut files_chirho);
    let mut crate_src_dirs_chirho = Vec::new();
    collect_workspace_crate_src_dirs_chirho(
        &root_chirho.join("crates"),
        &mut crate_src_dirs_chirho,
    );
    for dir_chirho in crate_src_dirs_chirho {
        collect_rs_files_chirho(&dir_chirho, &mut files_chirho);
    }
    files_chirho.sort();
    files_chirho.dedup();
    files_chirho
}

/// `(relative path, the needle it mentions)` for every workspace file naming a custody item.
fn custody_mentions_chirho() -> Vec<(String, &'static str)> {
    let root_chirho = workspace_root_chirho();
    let mut hits_chirho = Vec::new();
    for path_chirho in workspace_rs_files_chirho() {
        let relative_chirho = path_chirho
            .strip_prefix(&root_chirho)
            .unwrap_or(&path_chirho)
            .to_string_lossy()
            .replace('\\', "/");
        if GUARD_FILE_EXEMPTIONS_CHIRHO
            .iter()
            .any(|(path_chirho, _)| *path_chirho == relative_chirho)
        {
            continue;
        }
        let Ok(text_chirho) = std::fs::read_to_string(&path_chirho) else {
            continue;
        };
        let names_a_custody_type_chirho = CUSTODY_TYPE_NEEDLES_CHIRHO
            .iter()
            .any(|needle_chirho| text_chirho.contains(needle_chirho));
        for needle_chirho in CUSTODY_TYPE_NEEDLES_CHIRHO {
            if text_chirho.contains(needle_chirho) {
                hits_chirho.push((relative_chirho.clone(), *needle_chirho));
            }
        }
        // Methods only count ALONGSIDE a custody type — see the constant's header for why a bare
        // method name cannot identify a consumer.
        if names_a_custody_type_chirho {
            for needle_chirho in CUSTODY_METHOD_NEEDLES_CHIRHO {
                if text_chirho.contains(needle_chirho) {
                    hits_chirho.push((relative_chirho.clone(), *needle_chirho));
                }
            }
        }
    }
    hits_chirho
}

/// THE ARM. No crate outside the definer and its one pre-move consumer may name a custody item.
#[test]
fn storage_custody_exports_have_no_external_consumer_chirho() {
    let violations_chirho: BTreeSet<String> = custody_mentions_chirho()
        .into_iter()
        .filter(|(path_chirho, _)| {
            !ALLOWED_CRATE_PREFIXES_CHIRHO
                .iter()
                .any(|prefix_chirho| path_chirho.starts_with(prefix_chirho))
        })
        .map(|(path_chirho, needle_chirho)| format!("{path_chirho} names {needle_chirho}"))
        .collect();
    assert!(
        violations_chirho.is_empty(),
        "the writer-lock CUSTODY surface escaped its two allowed crates. A crate boundary cannot \
         carry pub(crate), so these items are `pub` by force rather than by intent, and this guard \
         is the boundary pub(crate) used to enforce. A new consumer here is a MONEY-AUTHORITY \
         review, not an allowlist edit:\n  {}",
        violations_chirho
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// POSITIVE CONTROL. A confinement guard whose needles match nothing passes forever while proving
/// nothing — the green-by-emptiness failure. This asserts the population is real: every needle is
/// found somewhere, and the definer crate is among the finders.
#[test]
fn every_custody_needle_is_actually_present_somewhere_chirho() {
    let mentions_chirho = custody_mentions_chirho();
    let found_chirho: BTreeSet<&str> = mentions_chirho
        .iter()
        .map(|(_, needle_chirho)| *needle_chirho)
        .collect();
    let missing_chirho: Vec<&str> = CUSTODY_TYPE_NEEDLES_CHIRHO
        .iter()
        .chain(CUSTODY_METHOD_NEEDLES_CHIRHO.iter())
        .filter(|needle_chirho| !found_chirho.contains(*needle_chirho))
        .copied()
        .collect();
    assert!(
        missing_chirho.is_empty(),
        "these custody needles match NOTHING in the workspace, so the arm above is vacuous for \
         them. Most likely they were renamed — retarget the needle rather than deleting it: {:?}",
        missing_chirho
    );
    assert!(
        mentions_chirho.iter().any(|(path_chirho, _)| path_chirho
            .starts_with("crates/ledger-chirho/host-chirho/cairn-ledger-host-storage-chirho/")),
        "the DEFINING crate names none of the custody items — the guard is pointed at the wrong \
         place, which would make its silence meaningless"
    );
}

/// THE FEATURE-EDGE ARM. `test-hooks-chirho` on every participating crate may be enabled ONLY from
/// a `[dev-dependencies]` section.
///
/// This is the boundary-crossing form of `cfg(test)`. Inside one crate, `cfg(test)` meant "visible
/// to tests, ABSENT FROM PRODUCTION" and the compiler enforced it. A crate boundary has no such
/// vocabulary, so the property is carried by a default-off feature that only a dev edge turns on —
/// resolver v2 then keeps it out of normal builds. **The PLACEMENT is the property**: the same
/// feature enabled from a `[dependencies]` section would ship test-only code into production builds
/// of the money-fence custody file, which is precisely what disposition A was rejected for.
///
/// Cargo will not forbid that edge, so this guard does. It scans every manifest, splits on section
/// headers, and fails if the feature is named under anything but `[dev-dependencies]`.
///
/// A `[features]` entry that chains a dependency's `test-hooks-chirho` is the same violation by
/// another route, so it is flagged too.
///
/// The census is crate-agnostic so a newly extracted test-support crate cannot silently fall outside
/// the guard. Each participating crate must have exactly one dev edge; zero is vacuous and multiple
/// edges mean a second consumer appeared and needs review. The covered feature set is explicitly
/// `{ "test-hooks-chirho" }`; `serve-runtime-test-hooks-chirho` is a separate runtime feature and
/// is intentionally outside this guard's family.
#[test]
fn storage_test_hooks_feature_is_enabled_only_from_dev_dependencies_chirho() {
    let root_chirho = workspace_root_chirho();
    let mut manifests_chirho = vec![root_chirho.join("Cargo.toml")];
    let mut crate_src_dirs_chirho = Vec::new();
    collect_workspace_crate_src_dirs_chirho(
        &root_chirho.join("crates"),
        &mut crate_src_dirs_chirho,
    );
    for src_chirho in crate_src_dirs_chirho {
        if let Some(crate_dir_chirho) = src_chirho.parent() {
            manifests_chirho.push(crate_dir_chirho.join("Cargo.toml"));
        }
    }
    manifests_chirho.sort();
    manifests_chirho.dedup();

    let mut violations_chirho: Vec<String> = Vec::new();
    let mut dev_edges_by_crate_chirho = std::collections::BTreeMap::<String, usize>::new();
    for manifest_chirho in manifests_chirho {
        let Ok(text_chirho) = std::fs::read_to_string(&manifest_chirho) else {
            continue;
        };
        let relative_chirho = manifest_chirho
            .strip_prefix(&root_chirho)
            .unwrap_or(&manifest_chirho)
            .to_string_lossy()
            .replace('\\', "/");
        let mut section_chirho = String::new();
        for line_chirho in text_chirho.lines() {
            let trimmed_chirho = line_chirho.trim();
            if trimmed_chirho.starts_with('[') && trimmed_chirho.ends_with(']') {
                section_chirho = trimmed_chirho.to_owned();
                continue;
            }
            // A `[features]` entry that turns ANOTHER crate's hooks on (`dep/test-hooks-chirho` or
            // `dep?/test-hooks-chirho`) enables them from a non-dev section. The quoted needle below
            // cannot see it, because the feature name follows a `/`, not a quote. This is how a
            // runtime feature once chained the view cache's hooks (CAIRN #25753).
            if section_chirho == "[features]" && trimmed_chirho.contains("/test-hooks-chirho\"") {
                violations_chirho.push(format!(
                    "{relative_chirho} chains a dependency's test-hooks-chirho from [features]: {trimmed_chirho}"
                ));
            }
            // A dependency edge that turns the feature on counts here; the crate's own
            // `[features]` declaration is the definition, not an enablement.
            if trimmed_chirho.contains("\"test-hooks-chirho\"")
                && trimmed_chirho.contains('=')
                && section_chirho != "[features]"
            {
                let crate_name_chirho = trimmed_chirho
                    .split_once('=')
                    .map(|(name_chirho, _)| name_chirho.trim().to_owned())
                    .unwrap_or_default();
                if crate_name_chirho.is_empty() {
                    continue;
                }
                if section_chirho.contains("dev-dependencies") {
                    *dev_edges_by_crate_chirho
                        .entry(crate_name_chirho)
                        .or_default() += 1;
                } else {
                    violations_chirho.push(format!(
                        "{relative_chirho} enables {crate_name_chirho} under {section_chirho}: {trimmed_chirho}"
                    ));
                }
            }
        }
    }
    assert!(
        violations_chirho.is_empty(),
        "test-hooks-chirho was enabled from a NON-dev section. That ships test-only code into \
         production builds of the writer-lock custody file — the disposition this brick explicitly \
         rejected. The placement IS the property:\n  {}",
        violations_chirho.join("\n  ")
    );
    assert!(
        !dev_edges_by_crate_chirho.is_empty(),
        "no test-hooks-chirho dependency edges were found; the census is vacuous"
    );
    let expected_crates_chirho: std::collections::BTreeSet<String> = [
        "cairn-app-control-chirho",
        // Reviewed 2026-10-01 (sign-in cost brick 2): its hook only raises the per-root view cap, so parallel root
        // tests do not evict each other's views; one root dev-dependency edge, no custody or authority surface.
        "cairn-auth-attempt-window-chirho",
        // Reviewed 2026-10-01 (bounded-growth census app A1): its hook is a thread-local reflog READ counter for
        // the serve-runtime growth arms. It counts and changes nothing; one serve-runtime dev-dependency edge, no
        // custody or authority surface.
        "cairn-core-chirho",
        "cairn-head-removal-chirho",
        "cairn-ledger-authority-chirho",
        "cairn-ledger-host-storage-chirho",
        "cairn-ledger-tenant-migration-durable-chirho",
        "cairn-store-redb-chirho",
        "cairn-usage-checkpoint-chirho",
        // Reviewed 2026-10-01 (checkpoint brick, the engine extraction): its hooks join and hold the background
        // jobs of the verified-prefix view engine extracted from the sign-in window. One dev-dependency edge, from
        // cairn-auth-attempt-window-chirho's own tests; no custody or authority surface.
        "cairn-verified-prefix-view-chirho",
        "cairn-verified-view-cache-chirho",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual_crates_chirho: std::collections::BTreeSet<String> =
        dev_edges_by_crate_chirho.keys().cloned().collect();
    assert_eq!(
        actual_crates_chirho, expected_crates_chirho,
        "test-hooks-chirho feature population changed; review the added or missing crate"
    );
    let malformed_edges_chirho: Vec<_> = dev_edges_by_crate_chirho
        .iter()
        .filter(|(_, count_chirho)| **count_chirho != 1)
        .collect();
    assert!(
        malformed_edges_chirho.is_empty(),
        "each test-hooks-chirho crate must have EXACTLY one dev-dependency edge; found: {:?}",
        malformed_edges_chirho
    );
}

/// FEATURE-DEFAULT CLOSURE ARM (disposition B, guard-completeness; authored by claude2_chirho while
/// gpt was unavailable — this file is claude2's to review, so review it as a fresh reviewer would).
///
/// The dev-edge arm above catches `[dependencies]`-style enablement of `test-hooks-chirho`. It
/// structurally CANNOT see the FEATURE-DECLARATION vector: a crate whose `default` feature — directly
/// or TRANSITIVELY — enables `test-hooks-chirho` ships the test-only custody surface in an ordinary
/// `cargo build`, with no dependency edge at all. Two shapes, one closure:
///   - self-default:  `default = ["test-hooks-chirho"]`
///   - transitive:    `default = ["foo-chirho"]`, `foo-chirho = ["test-hooks-chirho"]`
///
/// THE TRAP (why the resolver reads `[features]` by REACHABILITY, not presence): the legitimate
/// definition line `test-hooks-chirho = []` also lives in `[features]`, so a resolver keyed on
/// "the token appears in [features]" would fire on the off-by-default definition itself. The
/// discriminator is reachability FROM `default`. The fixture pins all three.
#[test]
fn storage_test_hooks_feature_is_not_default_enabled_chirho() {
    let root_chirho = workspace_root_chirho();
    let mut manifests_chirho = vec![root_chirho.join("Cargo.toml")];
    let mut crate_src_dirs_chirho = Vec::new();
    collect_workspace_crate_src_dirs_chirho(
        &root_chirho.join("crates"),
        &mut crate_src_dirs_chirho,
    );
    for src_chirho in crate_src_dirs_chirho {
        if let Some(crate_dir_chirho) = src_chirho.parent() {
            manifests_chirho.push(crate_dir_chirho.join("Cargo.toml"));
        }
    }
    manifests_chirho.sort();
    manifests_chirho.dedup();

    let mut violations_chirho: Vec<String> = Vec::new();
    for manifest_chirho in manifests_chirho {
        let Ok(text_chirho) = std::fs::read_to_string(&manifest_chirho) else {
            continue;
        };
        if let Some(path_chirho) = default_feature_closure_reaches_test_hooks_chirho(&text_chirho) {
            let relative_chirho = manifest_chirho
                .strip_prefix(&root_chirho)
                .unwrap_or(&manifest_chirho)
                .to_string_lossy()
                .replace('\\', "/");
            violations_chirho.push(format!("{relative_chirho}: {path_chirho}"));
        }
    }
    assert!(
        violations_chirho.is_empty(),
        "a crate's `default` feature closure reaches test-hooks-chirho, which ships the test-only \
         custody surface in an ordinary `cargo build` with no dev edge — the feature-declaration \
         counterpart to the dev-edge arm's [dependencies] vector:\n  {}",
        violations_chirho.join("\n  ")
    );
}

/// Resolve a manifest's `default` feature closure over its `[features]` graph and report the path if
/// it reaches `test-hooks-chirho`. Returns `None` when `default` does not (transitively) enable it —
/// so a crate that merely DEFINES `test-hooks-chirho = []` (off by default) does not fire. Pure over
/// the manifest text; unit-pinned by `default_feature_closure_detection_fixture_chirho`.
fn default_feature_closure_reaches_test_hooks_chirho(manifest_text_chirho: &str) -> Option<String> {
    let mut features_chirho: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut section_chirho = String::new();
    let mut pending_chirho = String::new();
    for line_chirho in manifest_text_chirho.lines() {
        // Strip a `#` comment BEFORE any parsing. Feature-array content carries no legitimate `#`, and
        // an un-stripped comment would be joined into the accumulated entry — a comment merely
        // MENTIONING the quoted token would be lifted out as a real feature, and a stray `]` or `"` in
        // a comment would perturb the bracket-balance / quote parity (the re-review's findings).
        let trimmed_chirho = line_chirho.split('#').next().unwrap_or("").trim();
        // A section header ends the [features] block. It never carries `=`, whereas a feature entry
        // always does — so requiring no `=` keeps a multi-line array's own `[` / `]` lines from being
        // mistaken for a header.
        if trimmed_chirho.starts_with('[')
            && trimmed_chirho.ends_with(']')
            && !trimmed_chirho.contains('=')
        {
            section_chirho = trimmed_chirho.to_owned();
            pending_chirho.clear();
            continue;
        }
        if section_chirho == "[features]" {
            if !pending_chirho.is_empty() {
                pending_chirho.push(' ');
            }
            pending_chirho.push_str(trimmed_chirho);
            // A feature entry is complete when its `[...]` array closes (or it is a bracket-free
            // scalar). MULTI-LINE arrays — the repo's convention for non-trivial entries, e.g. the
            // root manifest's own `default` closure — accumulate across physical lines until the
            // brackets balance; a line-by-line reader would parse them with an empty list and MISS a
            // default closure that reaches test-hooks-chirho through a multi-line hop.
            let open_chirho = pending_chirho.matches('[').count();
            let close_chirho = pending_chirho.matches(']').count();
            if pending_chirho.contains('=') && open_chirho == close_chirho {
                // Normalize single-quoted TOML literal arrays (`['x']`, honoured by cargo) to double
                // quotes so one extractor sees both quote styles.
                let entry_chirho = pending_chirho.replace('\'', "\"");
                let (name_chirho, rhs_chirho) = entry_chirho.split_once('=').unwrap();
                let name_chirho = name_chirho.trim().trim_matches('"').to_owned();
                if !name_chirho.is_empty() {
                    let enabled_chirho: Vec<String> = rhs_chirho
                        .split('"')
                        .enumerate()
                        .filter(|(index_chirho, _)| index_chirho % 2 == 1)
                        .map(|(_, value_chirho)| value_chirho.trim().to_owned())
                        .collect();
                    features_chirho.insert(name_chirho, enabled_chirho);
                }
                pending_chirho.clear();
            }
        }
    }
    let mut seen_chirho: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut queue_chirho: Vec<String> = vec!["default".to_owned()];
    while let Some(feature_chirho) = queue_chirho.pop() {
        if !seen_chirho.insert(feature_chirho.clone()) {
            continue;
        }
        if let Some(enabled_chirho) = features_chirho.get(&feature_chirho) {
            for target_chirho in enabled_chirho {
                // `dep/feat` (a dependency's feature) and `dep:opt` (an optional dependency) reference
                // OTHER crates, not this crate's local `test-hooks-chirho` feature — a distinct
                // cross-crate vector this arm does not target. Skip them rather than reduce: reducing
                // `dep:test-hooks-chirho` to a local name would FALSE-POSITIVE on a dependency that
                // merely shares the name.
                if target_chirho.contains('/') || target_chirho.contains(':') {
                    continue;
                }
                if target_chirho == "test-hooks-chirho" {
                    return Some(format!(
                        "default feature closure reaches test-hooks-chirho (via `{feature_chirho}`)"
                    ));
                }
                if !seen_chirho.contains(target_chirho) {
                    queue_chirho.push(target_chirho.clone());
                }
            }
        }
    }
    None
}

/// THE THREE-WAY POSITIVE CONTROL for the closure resolver (claude's trap, made executable): the bare
/// definition must stay SILENT while both enablement shapes fire. Without the bare-definition case the
/// resolver could "pass" by firing on everything in `[features]`, which is the vacuity this pins shut.
#[test]
fn default_feature_closure_detection_fixture_chirho() {
    // Bare definition, off by default -> MUST NOT fire.
    let bare_chirho = "[features]\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(bare_chirho).is_none(),
        "the bare `test-hooks-chirho = []` definition is off-by-default and must NOT fire"
    );
    // A default that enables only an unrelated feature -> MUST NOT fire.
    let unrelated_chirho =
        "[features]\ndefault = [\"other-chirho\"]\nother-chirho = []\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(unrelated_chirho).is_none(),
        "a default enabling only unrelated features must NOT fire"
    );
    // Self-default -> MUST fire.
    let self_default_chirho =
        "[features]\ndefault = [\"test-hooks-chirho\"]\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(self_default_chirho).is_some(),
        "`default = [\"test-hooks-chirho\"]` self-enables it in a normal build and MUST fire"
    );
    // Transitive -> MUST fire.
    let transitive_chirho = "[features]\ndefault = [\"foo-chirho\"]\nfoo-chirho = [\"test-hooks-chirho\"]\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(transitive_chirho).is_some(),
        "`default -> foo-chirho -> test-hooks-chirho` transitively enables it and MUST fire"
    );
    // MULTI-LINE array (the repo's convention for non-trivial [features]; the review-caught evasion)
    // -> MUST fire. The single-line form of this exact closure already fires, so array formatting
    // must not be an escape hatch.
    let multiline_chirho =
        "[features]\ndefault = [\"mid-chirho\"]\nmid-chirho = [\n    \"test-hooks-chirho\",\n]\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(multiline_chirho).is_some(),
        "a MULTI-LINE default closure reaching test-hooks-chirho MUST fire"
    );
    // SINGLE-QUOTE TOML literal array (cargo honours it) -> MUST fire.
    let single_quote_chirho =
        "[features]\ndefault = ['test-hooks-chirho']\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(single_quote_chirho).is_some(),
        "a single-quoted `default = ['test-hooks-chirho']` self-enables it and MUST fire"
    );
    // A default reaching a DEPENDENCY's feature (`dep/feat`) is a distinct cross-crate vector this
    // arm does not target -> MUST NOT fire, and must not false-positive on the shared name.
    let dep_feature_chirho =
        "[features]\ndefault = [\"some-dep-chirho/test-hooks-chirho\"]\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(dep_feature_chirho).is_none(),
        "`default = [\"dep/test-hooks-chirho\"]` targets a dependency's feature, not this crate's — \
         out of scope for this arm, must stay silent"
    );
    // A `#` comment MERELY MENTIONING the token inside a default-reachable array must NOT fire —
    // comments are stripped before parsing (the re-review's new false-positive, closed).
    let commented_mention_chirho = "[features]\ndefault = [\"proto-chirho\"]\nproto-chirho = [\n    \"dep:foo-chirho\",\n    # never add \"test-hooks-chirho\" to default\n]\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(commented_mention_chirho).is_none(),
        "a comment merely MENTIONING test-hooks-chirho inside a default-reachable array must NOT fire"
    );
    // A REAL token after a comment carrying a stray `]` must still FIRE — the comment must not
    // balance the array early (symmetric evasion, same root cause as the false positive above).
    let commented_stray_bracket_chirho = "[features]\ndefault = [\"mid-chirho\"]\nmid-chirho = [ # closes ]\n    \"test-hooks-chirho\",\n]\ntest-hooks-chirho = []\n";
    assert!(
        default_feature_closure_reaches_test_hooks_chirho(commented_stray_bracket_chirho).is_some(),
        "a real token after a comment containing a stray ] must still FIRE"
    );
}
