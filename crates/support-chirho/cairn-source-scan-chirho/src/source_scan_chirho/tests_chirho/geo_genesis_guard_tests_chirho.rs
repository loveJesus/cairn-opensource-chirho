// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The geo-genesis source-census guard (brick 8.2c): it pins the operator-only geo-genesis crate's
//! authority properties in production source — serve-runtime isolation (ruling 4), the load-bearing
//! never-generate enforcement (the 8.2b review's finding that compile-time gating does NOT hold under
//! Cargo workspace feature unification), one no-replace genesis-create door, and no caller-selected
//! money coordinates. Each check carries a positive control so a green result cannot be an empty scan.

use super::{
    production_text_chirho, workspace_production_rs_files_chirho, workspace_relative_chirho,
    workspace_root_chirho,
};
use std::collections::BTreeSet;

const GEO_GENESIS_CRATE_CHIRHO: &str = "crates/ledger-chirho/cairn-geo-genesis-chirho";
const SERVE_RUNTIME_CRATE_CHIRHO: &str = "crates/cairn-serve-runtime-chirho";
const LEDGER_REGENESIS_CRATE_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-regenesis-chirho";

/// The concatenated PRODUCTION source text of the geo-genesis crate: every top-level `src/*.rs` file
/// (the `tests_chirho/` subdirectory is all-test and is excluded by construction), each with its
/// `#[cfg(test)]` regions stripped. This is the exact surface the operator-only authority ships.
fn geo_genesis_production_source_chirho() -> String {
    let src_root_chirho = workspace_root_chirho()
        .join(GEO_GENESIS_CRATE_CHIRHO)
        .join("src");
    let mut entries_chirho = std::fs::read_dir(&src_root_chirho)
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    entries_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
    let mut source_chirho = String::new();
    for entry_chirho in entries_chirho {
        let path_chirho = entry_chirho.path();
        if path_chirho
            .extension()
            .and_then(|value_chirho| value_chirho.to_str())
            == Some("rs")
        {
            let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            source_chirho.push_str(&production_text_chirho(&text_chirho));
            source_chirho.push('\n');
        }
    }
    source_chirho
}

fn geo_genesis_manifest_chirho() -> String {
    std::fs::read_to_string(
        workspace_root_chirho()
            .join(GEO_GENESIS_CRATE_CHIRHO)
            .join("Cargo.toml"),
    )
    .unwrap()
}

/// The left-hand dependency names declared in a Cargo manifest's `*dependencies*` tables, with comment
/// text stripped first. This deliberately ignores the manifest's prose comments, so the intentional
/// mention of `rand_core` in the crate's header comment cannot be mistaken for a dependency edge.
pub(super) fn manifest_dependency_names_chirho(manifest_chirho: &str) -> Vec<String> {
    let mut names_chirho = Vec::new();
    let mut in_dependencies_chirho = false;
    for raw_line_chirho in manifest_chirho.lines() {
        let line_chirho = raw_line_chirho.split('#').next().unwrap_or("").trim();
        if line_chirho.starts_with('[') {
            in_dependencies_chirho = line_chirho.contains("dependencies");
            continue;
        }
        if !in_dependencies_chirho {
            continue;
        }
        if let Some((name_chirho, _rest_chirho)) = line_chirho.split_once('=') {
            let name_chirho = name_chirho.trim();
            if !name_chirho.is_empty() {
                names_chirho.push(name_chirho.to_owned());
            }
        }
    }
    names_chirho
}

// =============================================================================================
// (a) Serve isolation (ruling 4): no serve/runtime edge to or from the operator-only crate.
// =============================================================================================

#[test]
fn serve_runtime_has_no_edge_to_geo_genesis_and_geo_genesis_has_no_serve_edge_chirho() {
    let root_chirho = workspace_root_chirho();
    let serve_manifest_chirho = std::fs::read_to_string(
        root_chirho
            .join(SERVE_RUNTIME_CRATE_CHIRHO)
            .join("Cargo.toml"),
    )
    .unwrap();
    assert!(
        !serve_manifest_chirho.contains("cairn-geo-genesis-chirho"),
        "serve runtime must remain structurally unable to compile against geo-genesis authority"
    );

    // The one-root money crate must not depend back on the higher orchestration crate.
    let regenesis_manifest_chirho = std::fs::read_to_string(
        root_chirho
            .join(LEDGER_REGENESIS_CRATE_CHIRHO)
            .join("Cargo.toml"),
    )
    .unwrap();
    assert!(
        !regenesis_manifest_chirho.contains("cairn-geo-genesis-chirho"),
        "ledger regenesis must not gain a reverse dependency on geo-genesis"
    );

    let manifest_chirho = geo_genesis_manifest_chirho();
    let dependency_names_chirho = manifest_dependency_names_chirho(&manifest_chirho);
    // Positive control: the reviewed inward edges are present, so the parser is reading a real manifest.
    assert!(
        dependency_names_chirho
            .iter()
            .any(|name_chirho| name_chirho == "cairn-ledger-regenesis-chirho"),
        "geo-genesis must keep its reviewed inward edge on the one-root money crate"
    );
    assert!(
        dependency_names_chirho
            .iter()
            .any(|name_chirho| name_chirho == "cairn-durable-chirho"),
        "geo-genesis must keep its reviewed inward edge on the durable filesystem primitives"
    );
    for forbidden_chirho in ["cairn-serve-runtime-chirho", "axum", "hyper", "tower-http"] {
        assert!(
            !dependency_names_chirho
                .iter()
                .any(|name_chirho| name_chirho == forbidden_chirho),
            "geo-genesis gained a serve/runtime dependency edge: {forbidden_chirho}"
        );
    }

    // The production source imports no serve-runtime module.
    let source_chirho = geo_genesis_production_source_chirho();
    assert!(
        !source_chirho.contains("cairn_serve_runtime_chirho"),
        "geo-genesis production source gained a serve-runtime import"
    );
}

// =============================================================================================
// (b) Never-generate — the load-bearing enforcement (compile-time gating does NOT hold under
//     Cargo workspace feature unification, so this source-census is the real guarantee).
// =============================================================================================

#[test]
fn geo_genesis_source_never_generates_a_key_and_declares_no_rng_dependency_chirho() {
    let source_chirho = geo_genesis_production_source_chirho();

    // Positive controls: the crate really does use ed25519 signing keys via `from_bytes`, so the
    // absence of a generator below is a statement about real crypto code, not an empty scan.
    assert!(
        source_chirho.contains("SigningKey"),
        "geo-genesis production source must actually use ed25519 signing keys (positive control)"
    );
    assert!(
        source_chirho.contains("from_bytes"),
        "geo-genesis production source must load keys via from_bytes (positive control)"
    );

    for forbidden_chirho in [
        "::generate",
        "OsRng",
        "thread_rng",
        "from_entropy",
        "std::env::",
        "set_secret_chirho(",
    ] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "geo-genesis production source gained a key-generation or ambient-authority road: {forbidden_chirho}"
        );
    }

    // The RNG crates must not appear as dependency edges: ed25519-dalek's `rand_core` feature is
    // unified workspace-wide by sibling crates, so compile-time gating cannot forbid a generator —
    // only this source-census can, and it must also refuse a direct rand/rand_core edge.
    let dependency_names_chirho = manifest_dependency_names_chirho(&geo_genesis_manifest_chirho());
    for forbidden_chirho in ["rand", "rand_core", "rand-core"] {
        assert!(
            !dependency_names_chirho
                .iter()
                .any(|name_chirho| name_chirho == forbidden_chirho),
            "geo-genesis gained an RNG dependency edge that could enable key generation: {forbidden_chirho}"
        );
    }
}

// =============================================================================================
// (c) One genesis-create door: the marker is written through exactly one no-replace create call.
// =============================================================================================

#[test]
fn geo_genesis_has_one_no_replace_marker_create_call_site_chirho() {
    let source_chirho = geo_genesis_production_source_chirho();
    assert_eq!(
        source_chirho.matches("create_file_durable_chirho(").count(),
        1,
        "the geo-genesis guard must have exactly one no-replace genesis-create call site"
    );
    // The marker must never be written through a REPLACING durable write; the no-replace nonexistence
    // claim is what makes a second genesis impossible.
    assert!(
        !source_chirho.contains("write_file_durable_chirho("),
        "geo-genesis production source gained a replacing durable-write door for the marker"
    );
}

// =============================================================================================
// (d) No caller-selected money coordinates: the layer binds the ledger by digest only.
// =============================================================================================

#[test]
fn geo_genesis_source_has_no_caller_selected_money_coordinates_chirho() {
    let source_chirho = geo_genesis_production_source_chirho();
    // Positive control: the layer binds the ledger plan by its digest coordinate.
    assert!(
        source_chirho.contains("ledger_regenesis_plan_chirho"),
        "geo-genesis must bind the ledger plan by digest (positive control)"
    );
    for forbidden_chirho in [
        "amount_chirho",
        "journal_path_chirho",
        "storage_namespace_chirho",
        "mint_authority_chirho",
        "initial_mint_amount",
        "money_group_id_chirho",
    ] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "geo-genesis production source gained a caller-selected money coordinate: {forbidden_chirho}"
        );
    }
}

// =============================================================================================
// (e) Directory tripwire (never-generate completeness — the load-bearing check's own blind spot).
//     The never-generate census in (b) reads only TOP-LEVEL `src/*.rs`; a future NESTED production
//     module (`src/foo/bar.rs`) would silently escape it — a green-by-emptiness hole in the sole
//     never-generate enforcement. Rather than recurse, pin the crate's `src/` SHAPE: the only
//     subdirectory is the all-test `tests_chirho/`. The instant a nested production module directory
//     appears, this fails loud and names it, before the flat census can miss its contents. Reading
//     directory ENTRIES (never file text) means a legitimate test-only `std::env::` can never
//     false-trip it — the exact false-positive class the flat census would risk if made recursive.
// =============================================================================================

#[test]
fn geo_genesis_src_subdirectories_are_exactly_the_all_test_dir_chirho() {
    let src_root_chirho = workspace_root_chirho()
        .join(GEO_GENESIS_CRATE_CHIRHO)
        .join("src");
    let mut subdirectories_chirho: Vec<String> = std::fs::read_dir(&src_root_chirho)
        .unwrap()
        .map(|entry_chirho| entry_chirho.unwrap())
        .filter(|entry_chirho| entry_chirho.path().is_dir())
        .map(|entry_chirho| entry_chirho.file_name().to_string_lossy().into_owned())
        .collect();
    subdirectories_chirho.sort();
    // Exact set. A NEW subdirectory (a nested production module home) fails this the instant it
    // appears; a MISSING tests_chirho would fail it too — so the equality also proves the listing is
    // real, never an empty scan that could pass vacuously.
    assert_eq!(
        subdirectories_chirho,
        vec!["tests_chirho".to_owned()],
        "geo-genesis src/ subdirectories changed. The never-generate source-census \
         (geo_genesis_source_never_generates_a_key_and_declares_no_rng_dependency_chirho) scans only \
         top-level src/*.rs, so a nested production module here would silently escape that \
         load-bearing never-generate enforcement. Fold the module into a top-level src/*.rs file, or \
         extend the census to recurse BEFORE adding a src/ subdirectory."
    );
}

// =============================================================================================
// (f) D brick 1: the read-only operator is the one runner, and it names no mutating or key door.
// =============================================================================================

const GEO_GENESIS_OPERATOR_CRATE_CHIRHO: &str =
    "crates/ledger-chirho/host-chirho/cairn-geo-genesis-operator-chirho";

/// The verify and dry-run API, by call form. Outside the genesis crate, only the operator may call it.
const GEO_GENESIS_VERIFY_API_CALLS_CHIRHO: &[&str] = &[
    "verify_plan_chirho(",
    "verify_dry_run_packet_chirho(",
    "build_dry_run_packet_chirho(",
    "verify_custody_presence_chirho(",
    "cross_bind_member_configs_chirho(",
    "verify_acceptance_packet_chirho(",
];

/// The genesis crate's own doors a read-only runner must never name: plan authoring, intent
/// reservation, the reserve-then-run root action, and marker signing.
const GEO_GENESIS_MUTATING_DOORS_CHIRHO: &[&str] = &[
    "author_plan_chirho",
    "reserve_genesis_intent_chirho",
    "reserve_intent_then_run_root_chirho",
    "build_signed_intent_marker_chirho",
];

/// Key material and generation a read-only runner must never name.
const GEO_GENESIS_RUNNER_KEY_NEEDLES_CHIRHO: &[&str] = &["SigningKey", "::generate", "OsRng"];

/// The production text of one crate's whole `src/` tree, taken from the scanner's own production
/// inventory (recursive, with `#[cfg(test)]` module files resolved out), each file with its
/// `#[cfg(test)]` regions stripped. A nested module cannot escape it.
fn crate_production_source_chirho(crate_dir_chirho: &str) -> String {
    let src_prefix_chirho = format!("{crate_dir_chirho}/src/");
    let mut files_chirho: Vec<_> = workspace_production_rs_files_chirho()
        .into_iter()
        .filter(|path_chirho| {
            workspace_relative_chirho(path_chirho).starts_with(&src_prefix_chirho)
        })
        .collect();
    files_chirho.sort();
    let mut source_chirho = String::new();
    for path_chirho in files_chirho {
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_else(|error_chirho| {
            panic!("read {}: {error_chirho}", path_chirho.display())
        });
        source_chirho.push_str(&production_text_chirho(&text_chirho));
    }
    source_chirho
}

#[test]
fn the_geo_genesis_operator_is_the_one_production_runner_of_the_verify_api_chirho() {
    // Prefixes end in `/` so a sibling crate whose name merely starts the same way is not taken for
    // the genesis crate or the operator.
    let genesis_prefix_chirho = format!("{GEO_GENESIS_CRATE_CHIRHO}/");
    let operator_prefix_chirho = format!("{GEO_GENESIS_OPERATOR_CRATE_CHIRHO}/");
    let mut callers_chirho = BTreeSet::new();
    // The scanner's own production inventory: every crate's src, with cfg(test) modules resolved out.
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if relative_chirho.starts_with(&genesis_prefix_chirho) {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|error_chirho| panic!("read {relative_chirho}: {error_chirho}"));
        let source_chirho = production_text_chirho(&text_chirho);
        // A caller names the genesis crate AND uses one call form, so a same-named function in an
        // unrelated crate is not counted.
        if source_chirho.contains("cairn_geo_genesis_chirho")
            && GEO_GENESIS_VERIFY_API_CALLS_CHIRHO
                .iter()
                .any(|call_chirho| source_chirho.contains(call_chirho))
        {
            callers_chirho.insert(relative_chirho);
        }
    }
    assert!(
        callers_chirho
            .iter()
            .any(|file_chirho| file_chirho.starts_with(&operator_prefix_chirho)),
        "positive control: the read-only operator runs the verify API: {callers_chirho:?}"
    );
    assert!(
        callers_chirho
            .iter()
            .all(|file_chirho| file_chirho.starts_with(&operator_prefix_chirho)),
        "outside the genesis crate, only the read-only operator may run the verify API: \
         {callers_chirho:?}. A new runner (for example D brick 2's authoring crate) joins this \
         census by name, in review; it is never admitted by widening the prefix."
    );
}

/// Every non-comment line naming `crate_name_chirho` in any workspace manifest, as
/// (manifest, section). It is a walk rather than a `git grep` pathspec, because `'**/Cargo.toml'` does
/// not match the top-level manifest. A section header naming the crate counts too, so a table-form
/// edge (`[dependencies.<crate>]`, whose own lines never repeat the name) cannot hide.
fn manifest_references_chirho(crate_name_chirho: &str) -> BTreeSet<(String, String)> {
    fn walk_chirho(dir_chirho: &std::path::Path, out_chirho: &mut Vec<std::path::PathBuf>) {
        let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
            return;
        };
        for entry_chirho in entries_chirho.flatten() {
            let path_chirho = entry_chirho.path();
            let name_chirho = entry_chirho.file_name().to_string_lossy().to_string();
            if name_chirho.starts_with('.') || name_chirho == "target" {
                continue;
            }
            if path_chirho.is_dir() {
                walk_chirho(&path_chirho, out_chirho);
            } else if name_chirho == "Cargo.toml" {
                out_chirho.push(path_chirho);
            }
        }
    }

    let root_chirho = workspace_root_chirho();
    let mut manifests_chirho = vec![root_chirho.join("Cargo.toml")];
    walk_chirho(&root_chirho.join("crates"), &mut manifests_chirho);
    let mut references_chirho = BTreeSet::new();
    for manifest_chirho in manifests_chirho {
        let text_chirho =
            std::fs::read_to_string(&manifest_chirho).unwrap_or_else(|error_chirho| {
                panic!("read {}: {error_chirho}", manifest_chirho.display())
            });
        let relative_chirho = workspace_relative_chirho(&manifest_chirho);
        let mut section_chirho = String::from("<none>");
        for line_chirho in text_chirho.lines() {
            let trimmed_chirho = line_chirho.trim();
            if trimmed_chirho.starts_with('[') && trimmed_chirho.ends_with(']') {
                section_chirho = trimmed_chirho.to_owned();
            } else if trimmed_chirho.starts_with('#') {
                continue;
            }
            if trimmed_chirho.contains(crate_name_chirho) {
                references_chirho.insert((relative_chirho.clone(), section_chirho.clone()));
            }
        }
    }
    references_chirho
}

/// The edge-level form of the caller census above. A `pub use` re-export in one file and a call in
/// another would pass a per-file check, but every production caller needs a normal dependency edge.
/// The lawful references are an exact set, so a reference from a section this guard has not reviewed
/// fails and names itself: the crate's own `[package]`, the workspace members list, the operator's one
/// `[dependencies]` edge, and test-only `[dev-dependencies]` edges.
#[test]
fn only_the_geo_genesis_operator_has_a_normal_dependency_edge_on_the_genesis_crate_chirho() {
    let references_chirho = manifest_references_chirho("cairn-geo-genesis-chirho");
    let genesis_manifest_chirho = format!("{GEO_GENESIS_CRATE_CHIRHO}/Cargo.toml");
    let operator_manifest_chirho = format!("{GEO_GENESIS_OPERATOR_CRATE_CHIRHO}/Cargo.toml");
    let lawful_structure_chirho = [
        (genesis_manifest_chirho.as_str(), "[package]"),
        ("Cargo.toml", "[workspace]"),
        (operator_manifest_chirho.as_str(), "[dependencies]"),
    ];
    // Positive controls: each lawful reference is really found, so the census is reading real
    // manifests and the absences below are not green-by-emptiness.
    for (manifest_chirho, section_chirho) in lawful_structure_chirho {
        assert!(
            references_chirho.contains(&(manifest_chirho.to_owned(), section_chirho.to_owned())),
            "positive control: the census must find {manifest_chirho} {section_chirho}: \
             {references_chirho:?}"
        );
    }
    let unlawful_chirho: BTreeSet<&(String, String)> = references_chirho
        .iter()
        .filter(|(manifest_chirho, section_chirho)| {
            let lawful_chirho = lawful_structure_chirho.iter().any(|(m_chirho, s_chirho)| {
                manifest_chirho == m_chirho && section_chirho == s_chirho
            });
            !lawful_chirho && section_chirho != "[dev-dependencies]"
        })
        .collect();
    assert!(
        unlawful_chirho.is_empty(),
        "only the read-only operator may compile against the genesis crate in a normal build. \
         Unreviewed references: {unlawful_chirho:?}. A new production dependent (for example D brick \
         2's authoring crate) is added to the lawful set by name, in review."
    );
}

#[test]
fn the_geo_genesis_operator_names_no_mutating_or_key_door_chirho() {
    let operator_chirho = crate_production_source_chirho(GEO_GENESIS_OPERATOR_CRATE_CHIRHO);
    // Positive controls: the library's verify calls AND the binary's bounded read are both in the
    // scanned text, so neither `lib.rs` nor `main.rs` has dropped out of the census.
    assert!(
        operator_chirho.contains("verify_plan_chirho(")
            && operator_chirho.contains("verify_dry_run_packet_chirho("),
        "positive control: the operator's library really runs the verify API"
    );
    assert!(
        operator_chirho.contains("read_identity_stable_bounded_regular_file_chirho("),
        "positive control: the operator binary's source is in the scanned text"
    );
    let genesis_chirho = geo_genesis_production_source_chirho();
    for door_chirho in GEO_GENESIS_MUTATING_DOORS_CHIRHO {
        assert!(
            genesis_chirho.contains(door_chirho),
            "positive control: {door_chirho} is a real door in the genesis crate, so its absence below means something"
        );
        assert!(
            !operator_chirho.contains(door_chirho),
            "the read-only operator names a mutating genesis door: {door_chirho}. Authoring, \
             reservation and marker signing belong in their own crate (D brick 2), so the verify \
             binary stays unable to change a root."
        );
    }
    for needle_chirho in GEO_GENESIS_RUNNER_KEY_NEEDLES_CHIRHO {
        assert!(
            !operator_chirho.contains(needle_chirho),
            "the read-only operator names key material or a generator: {needle_chirho}"
        );
    }
    let operator_manifest_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join(GEO_GENESIS_OPERATOR_CRATE_CHIRHO)
            .join("Cargo.toml"),
    )
    .expect("the operator manifest");
    let dependency_names_chirho = manifest_dependency_names_chirho(&operator_manifest_chirho);
    for forbidden_chirho in ["rand", "rand_core", "rand-core", "ed25519-dalek"] {
        assert!(
            !dependency_names_chirho
                .iter()
                .any(|name_chirho| name_chirho == forbidden_chirho),
            "the read-only operator gained a key or RNG dependency edge: {forbidden_chirho}"
        );
    }
}
