// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Keeps `cairn-ledger-geo-node-testkind-chirho` a DEV-ONLY edge: no production crate may DEPEND on
//! the crate that carries the completing compensation provider.

use super::super::*;
use std::collections::BTreeSet;

const TESTKIND_CRATE_CHIRHO: &str = "cairn-ledger-geo-node-testkind-chirho";
const TESTKIND_OWN_MANIFEST_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/Cargo.toml";
const WORKSPACE_MANIFEST_CHIRHO: &str = "Cargo.toml";

/// Walk every `Cargo.toml` in the workspace, tracking the section each reference sits under.
///
/// Written as a walk rather than a `git grep` pathspec on purpose: a `'**/Cargo.toml'` pathspec does
/// NOT match the top-level `Cargo.toml`, and the workspace manifest is precisely where a members
/// entry lives — a census that silently skipped it would be green while blind. `cairn-ledger-geo-
/// node-chirho` is NOT a substring of `cairn-ledger-geo-node-testkind-chirho` and vice versa, so a
/// reference to the shipping crate never masquerades as one to the testkind crate.
fn testkind_reference_sections_chirho() -> BTreeSet<(String, String)> {
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
        let Ok(text_chirho) = std::fs::read_to_string(&manifest_chirho) else {
            continue;
        };
        let relative_chirho = workspace_relative_chirho(&manifest_chirho);
        let mut section_chirho = String::from("<none>");
        for line_chirho in text_chirho.lines() {
            let trimmed_chirho = line_chirho.trim();
            if trimmed_chirho.starts_with('[') && trimmed_chirho.ends_with(']') {
                section_chirho = trimmed_chirho.to_owned();
                continue;
            }
            if trimmed_chirho.starts_with('#') {
                continue;
            }
            if trimmed_chirho.contains(TESTKIND_CRATE_CHIRHO) {
                references_chirho.insert((relative_chirho.clone(), section_chirho.clone()));
            }
        }
    }
    references_chirho
}

/// THE CONFINEMENT CLAIM, executed rather than asserted in prose: the crate that carries the
/// completing compensation provider is never reachable from a production build.
///
/// The checkable form is the dependency EDGE: `[dev-dependencies]` is not compiled into a
/// dependent's normal build, the same shape the workspace already uses to confine the drill barrier
/// and `cairn-ledger-sim-chirho`. FAIL-CLOSED TOWARD COVERAGE: the assertion is the exact SET of
/// (manifest, section) pairs, so a reference from any section this guard has not reviewed fails and
/// names itself. Two reference kinds are lawful and both are structural, not dependency edges — the
/// crate's own `[package]`/`[[bin]]` and the workspace `[workspace]` members list. A `[dependencies]`
/// or `[build-dependencies]` entry anywhere — above all from `cairn-ledger-geo-node-chirho` — is the
/// defect this exists for.
///
/// CAUSAL-PROOF NOTE: that archetypal defect (a `[dependencies]` edge FROM the shipping
/// `cairn-ledger-geo-node-chirho` ONTO the testkind crate) cannot be exercised as a LIVE cargo
/// mutation, because the testkind crate already depends on that shipping crate (see its
/// `[dependencies]`), so the added edge closes a `geo-node -> testkind -> geo-node` cycle that cargo
/// rejects at resolution BEFORE this guard runs. The guard is therefore mutation-proven with a
/// NON-CYCLIC production edge instead — adding the testkind crate to `cairn-cli-chirho`'s
/// `[dependencies]` makes this census fail and name that manifest — which demonstrates the same
/// detection without a resolution cycle.
#[test]
fn testkind_geo_node_stays_a_dev_only_edge_chirho() {
    let references_chirho = testkind_reference_sections_chirho();

    // POSITIVE CONTROL FIRST: if the census finds nothing, every absence below is green-by-emptiness
    // — a renamed crate would silently satisfy an "is never a normal dependency" assertion.
    assert!(
        references_chirho
            .iter()
            .any(|(manifest_chirho, _section_chirho)| manifest_chirho
                == TESTKIND_OWN_MANIFEST_CHIRHO),
        "the testkind crate's own manifest must be found, or this census is measuring nothing"
    );
    assert!(
        references_chirho
            .iter()
            .any(|(manifest_chirho, _section_chirho)| manifest_chirho == WORKSPACE_MANIFEST_CHIRHO),
        "the workspace members entry must be found, or this census cannot see the root manifest"
    );

    let unlawful_chirho: BTreeSet<&(String, String)> = references_chirho
        .iter()
        .filter(|(manifest_chirho, section_chirho)| {
            // The crate's own manifest describes itself (`[package]`/`[[bin]]`); the workspace
            // manifest lists members. Neither is a dependency edge. Everything else must be a
            // dev-dependency.
            let structural_chirho = manifest_chirho == TESTKIND_OWN_MANIFEST_CHIRHO
                || (manifest_chirho == WORKSPACE_MANIFEST_CHIRHO
                    && section_chirho == "[workspace]");
            let dev_edge_chirho = section_chirho == "[dev-dependencies]";
            !structural_chirho && !dev_edge_chirho
        })
        .collect();

    assert!(
        unlawful_chirho.is_empty(),
        "the test-kind geo node must be reachable ONLY through [dev-dependencies]; a production edge \
         would link the completing compensation provider into a normal build. Unlawful references: \
         {unlawful_chirho:?}"
    );
}
