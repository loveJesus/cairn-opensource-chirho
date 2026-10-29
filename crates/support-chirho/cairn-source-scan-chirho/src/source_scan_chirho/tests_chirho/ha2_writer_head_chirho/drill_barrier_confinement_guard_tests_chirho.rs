// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Keeps the item-6 drill barrier a DEV-ONLY edge: nothing production may link a partition control.

use super::super::*;
use std::collections::BTreeSet;

const BARRIER_CRATE_CHIRHO: &str = "cairn-drill-barrier-chirho";
const BARRIER_OWN_MANIFEST_CHIRHO: &str =
    "crates/support-chirho/cairn-drill-barrier-chirho/Cargo.toml";
const WORKSPACE_MANIFEST_CHIRHO: &str = "Cargo.toml";

/// Walk every `Cargo.toml` in the workspace, tracking the section each line sits under.
///
/// Written as a walk rather than a `git grep` pathspec on purpose: a `'**/Cargo.toml'` pathspec does
/// NOT match the top-level `Cargo.toml`, and the workspace manifest is precisely where a members
/// entry lives — a census that silently skipped it would be green while blind.
fn barrier_reference_sections_chirho() -> BTreeSet<(String, String)> {
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
            if trimmed_chirho.contains(BARRIER_CRATE_CHIRHO) {
                references_chirho.insert((relative_chirho.clone(), section_chirho.clone()));
            }
        }
    }
    references_chirho
}

/// THE CONFINEMENT CLAIM THE CRATE HEADER MAKES, executed rather than asserted in prose.
///
/// A crate that can partition a cluster must never be reachable from a production build. The
/// checkable form of that is the dependency EDGE: `[dev-dependencies]` is not compiled into a
/// dependent's normal build, which is the same shape the workspace already uses to confine
/// `cairn-ledger-sim-chirho`'s fault injection.
///
/// FAIL-CLOSED TOWARD COVERAGE: the assertion is the exact SET of (manifest, section) pairs, so a
/// reference from any section this guard has not reviewed fails and names itself, rather than
/// passing because it did not match a pattern. Two entries are lawful and both are structural, not
/// dependency edges — the crate's own `[package]`/`[lib]` and the workspace `[workspace]` members
/// list. A `[dependencies]` or `[build-dependencies]` entry anywhere is the defect this exists for.
#[test]
fn drill_barrier_stays_a_dev_only_edge_chirho() {
    let references_chirho = barrier_reference_sections_chirho();

    // POSITIVE CONTROL FIRST: if the census finds nothing, every absence below is green-by-emptiness
    // — a renamed crate would silently satisfy an "is never a normal dependency" assertion.
    assert!(
        references_chirho.iter().any(
            |(manifest_chirho, _section_chirho)| manifest_chirho == BARRIER_OWN_MANIFEST_CHIRHO
        ),
        "the barrier crate's own manifest must be found, or this census is measuring nothing"
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
            // The crate's own manifest describes itself; the workspace manifest lists members.
            // Neither is a dependency edge. Everything else must be a dev-dependency.
            let structural_chirho = manifest_chirho == BARRIER_OWN_MANIFEST_CHIRHO
                || (manifest_chirho == WORKSPACE_MANIFEST_CHIRHO
                    && section_chirho == "[workspace]");
            let dev_edge_chirho = section_chirho == "[dev-dependencies]";
            !structural_chirho && !dev_edge_chirho
        })
        .collect();

    assert!(
        unlawful_chirho.is_empty(),
        "the drill barrier must be reachable ONLY through [dev-dependencies]; a production edge \
         would link a cluster-partition control into a normal build. Unlawful references: \
         {unlawful_chirho:?}"
    );
}

/// The barrier must stay dependency-free: every dependency widens what a drill control plane reaches.
///
/// This is the second half of the header's blessing argument. The verbs are fixed by review, but a
/// crate that grew a storage, signer, or elector dependency could gain reach without any new verb —
/// so the dependency list is pinned as a SET rather than described.
#[test]
fn drill_barrier_declares_no_dependencies_chirho() {
    let manifest_chirho = workspace_root_chirho().join(BARRIER_OWN_MANIFEST_CHIRHO);
    let text_chirho = std::fs::read_to_string(&manifest_chirho).expect("read the barrier manifest");
    let mut section_chirho = String::from("<none>");
    let mut declared_chirho: BTreeSet<String> = BTreeSet::new();
    for line_chirho in text_chirho.lines() {
        let trimmed_chirho = line_chirho.trim();
        if trimmed_chirho.starts_with('[') && trimmed_chirho.ends_with(']') {
            section_chirho = trimmed_chirho.to_owned();
            continue;
        }
        if trimmed_chirho.is_empty() || trimmed_chirho.starts_with('#') {
            continue;
        }
        if section_chirho == "[dependencies]"
            || section_chirho == "[build-dependencies]"
            || section_chirho == "[dev-dependencies]"
        {
            let name_chirho = trimmed_chirho
                .split_once('=')
                .map(|(name_chirho, _rest_chirho)| name_chirho.trim().to_owned())
                .unwrap_or_else(|| trimmed_chirho.to_owned());
            declared_chirho.insert(format!("{section_chirho} {name_chirho}"));
        }
    }
    assert!(
        declared_chirho.is_empty(),
        "the drill barrier must stay std-only; it cannot mint, append, sign, or move a ref because \
         it cannot NAME anything that does. Declared: {declared_chirho:?}"
    );
}
