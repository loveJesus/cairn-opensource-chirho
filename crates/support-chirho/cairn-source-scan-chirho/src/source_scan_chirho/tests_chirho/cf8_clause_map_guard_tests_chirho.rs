// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The CF8 clause map may not name things the tree does not have.
//!
//! `CLAUDE.md` tells every reader to consult an existing measurement BEFORE making a new one, and the
//! CF8 clause map in `cairn-placement-chirho` is the worked example of that advice. Advice to read a
//! map first is only safe if the map's claims are checkable — otherwise it is advice to inherit
//! unverified assertions.
//!
//! **It cost exactly that on 2026-08-01.** The map claimed clause 13's boundary was guarded by
//! `elected_fence_helper_has_one_definition_and_zero_production_references_chirho`. No such function
//! exists; the shipping guard asserts the OPPOSITE property — one reviewed production bridge, because
//! the clause requires the bridge to exist outside the elector crate. That name occurred in exactly
//! one file in the whole tree: the map's own claim about it. It was then relayed between seats as
//! fact, in good faith, in one hop. Nothing went red, because nothing was checking.
//!
//! # WHAT THIS GUARD CANNOT CATCH — read this before trusting a green run
//!
//! **It proves every named identifier RESOLVES. It does NOT prove any CLAIM about that identifier is
//! true.** The defect that prompted it was INVERTED SEMANTICS, and it was only mechanically visible
//! because the wrong name ALSO failed to exist. A future map row naming a REAL function with a WRONG
//! description passes this guard silently and stays just as misleading.
//!
//! Both are the map lying. Only one is checkable by machine. So a green run here means *the map does
//! not point at ghosts* — real, and considerably less than *the map is accurate*. Reading it as the
//! latter is the same over-reading this suite corrects elsewhere, and it would be a map about the map
//! carrying the original defect.
//!
//! Rows like "built" or "NEEDS A FLEET" name no identifier at all. Nothing here touches them.

use crate::source_scan_chirho::{workspace_all_rs_files_chirho, workspace_root_chirho};
use std::collections::BTreeSet;

/// The map under guard.
const CF8_CLAUSE_MAP_CHIRHO: &str = "crates/domain-chirho/cairn-placement-chirho/src/lib.rs";

/// Identifier-shaped tokens the map's `//!` header names.
///
/// Maximal runs of `[a-z0-9_-]` ending in `_chirho` or `-chirho`, which captures both our snake
/// identifiers and our kebab crate names. Backticks, `::`, and punctuation break a run, so
/// ``cairn-tenant-chirho::single_customer_app_chirho`` yields both halves separately.
fn named_identifiers_chirho(header_chirho: &str) -> BTreeSet<String> {
    let mut found_chirho = BTreeSet::new();
    let mut current_chirho = String::new();
    for char_chirho in header_chirho.chars().chain(std::iter::once(' ')) {
        if char_chirho.is_ascii_lowercase()
            || char_chirho.is_ascii_digit()
            || char_chirho == '_'
            || char_chirho == '-'
        {
            current_chirho.push(char_chirho);
            continue;
        }
        if current_chirho.ends_with("_chirho") || current_chirho.ends_with("-chirho") {
            found_chirho.insert(current_chirho.clone());
        }
        current_chirho.clear();
    }
    found_chirho
}

/// The map's own asserting lines, and everything else in that file, kept separate.
///
/// **Excluding the asserting LINES rather than the containing FILE is load-bearing.** The first
/// version of this audit excluded the whole file and reported `infrastructure_budget_chirho` missing
/// — while that module is `pub mod`-declared a few lines below the header, in the very file being
/// excluded. `lib.rs` is simultaneously the map AND the declaration site, so excluding the file
/// excludes the definition. That false positive was caught by recall, not by rigour; had the name
/// been unfamiliar it would have sent a seat hunting a symbol that exists.
fn split_map_chirho(source_chirho: &str) -> (String, String) {
    let mut header_chirho = String::new();
    let mut body_chirho = String::new();
    for line_chirho in source_chirho.lines() {
        if line_chirho.starts_with("//!") {
            header_chirho.push_str(line_chirho);
            header_chirho.push('\n');
        } else {
            body_chirho.push_str(line_chirho);
            body_chirho.push('\n');
        }
    }
    (header_chirho, body_chirho)
}

#[test]
fn the_cf8_clause_map_names_nothing_the_tree_does_not_have_chirho() {
    let map_path_chirho = workspace_root_chirho().join(CF8_CLAUSE_MAP_CHIRHO);
    let source_chirho = std::fs::read_to_string(&map_path_chirho)
        .unwrap_or_else(|e_chirho| panic!("read {}: {e_chirho}", map_path_chirho.display()));
    let (header_chirho, body_chirho) = split_map_chirho(&source_chirho);
    let names_chirho = named_identifiers_chirho(&header_chirho);

    // Non-vacuity: a header that stopped yielding names would make every check below pass over
    // nothing. This is the failure mode a resolution guard is least able to notice about itself.
    assert!(
        names_chirho.len() >= 5,
        "the CF8 clause map header yielded only {} identifiers — the map was gutted, or the token \
         scanner stopped matching. Either way this guard is measuring nothing",
        names_chirho.len()
    );

    // Resolution sources: a name may live in a PATH (a module file, a crate directory) and appear in
    // no file's contents at all, so paths are checked first and contents second.
    //
    // ALL `.rs` files, not just production ones — and this guard taught me the reason by failing.
    // The first version resolved against `workspace_production_rs_files_chirho`, the usual correct
    // choice in this suite, and it rejected the CORRECTED clause-13 name. That name is a GUARD
    // function, and guards live in `#[cfg(test)]` files. A map whose job includes saying "this clause
    // is guarded by X" must be able to name X, so a resolver scoped to production code structurally
    // cannot see the very things the map most needs to reference.
    // The production/test distinction governs what a guard ASSERTS ABOUT, not whether a name EXISTS.
    let all_rs_files_chirho = workspace_all_rs_files_chirho();
    let relative_paths_chirho: Vec<String> = all_rs_files_chirho
        .iter()
        .map(|path_chirho| path_chirho.to_string_lossy().into_owned())
        .collect();

    let mut unresolved_chirho = Vec::new();
    for name_chirho in &names_chirho {
        let in_a_path_chirho = relative_paths_chirho
            .iter()
            .any(|path_chirho| path_chirho.contains(name_chirho.as_str()));
        if in_a_path_chirho {
            continue;
        }
        // The map's own NON-header body counts: lib.rs declares the modules it documents.
        if body_chirho.contains(name_chirho.as_str()) {
            continue;
        }
        let in_other_source_chirho = all_rs_files_chirho.iter().any(|path_chirho| {
            if path_chirho
                .to_string_lossy()
                .contains(CF8_CLAUSE_MAP_CHIRHO)
            {
                return false;
            }
            std::fs::read_to_string(path_chirho)
                .map(|text_chirho| text_chirho.contains(name_chirho.as_str()))
                .unwrap_or(false)
        });
        if !in_other_source_chirho {
            unresolved_chirho.push(name_chirho.clone());
        }
    }

    assert!(
        unresolved_chirho.is_empty(),
        "the CF8 clause map names {unresolved_chirho:?}, which occur NOWHERE in the tree except the \
         map's own claim about them. A map that names something the tree does not have is stale or \
         inverted, and both are invisible to every other test we run — this exact shape was relayed \
         between seats as fact. Fix the MAP to match the code; do not add the name to the code to \
         make this green. And remember what this guard does NOT check: a row naming a REAL symbol \
         with a WRONG description passes here silently"
    );
}

#[test]
fn positive_control_the_resolver_can_distinguish_present_from_absent_chirho() {
    // A resolution guard that answers "resolves" for everything is decoration. Prove both verdicts
    // are reachable with a known-true and a known-false name, so an empty unresolved list above
    // means "all names resolve" and not "the resolver stopped discriminating".
    let all_rs_files_chirho = workspace_all_rs_files_chirho();
    let paths_chirho: Vec<String> = all_rs_files_chirho
        .iter()
        .map(|path_chirho| path_chirho.to_string_lossy().into_owned())
        .collect();

    assert!(
        paths_chirho
            .iter()
            .any(|path_chirho| path_chirho.contains("cairn-tenant-chirho")),
        "positive control failed: a crate that certainly exists did not resolve by path, so the \
         resolver is broken and the guard above proves nothing"
    );
    assert!(
        !paths_chirho
            .iter()
            .any(|path_chirho| path_chirho.contains("obviously_fake_symbol_chirho")),
        "negative control failed: a name that certainly does not exist resolved anyway"
    );
}

#[test]
fn the_token_scanner_reads_both_identifier_shapes_chirho() {
    // The scanner is the instrument the whole guard rests on; a scanner that silently stopped
    // matching would empty the name set and the length assert would be the only thing standing.
    let sample_chirho = "//! see `cairn-tenant-chirho::single_customer_app_chirho` and \
                         `topology_grant_chirho`, but not md2-sink-epoch-eq-granted";
    let found_chirho = named_identifiers_chirho(sample_chirho);
    assert!(
        found_chirho.contains("cairn-tenant-chirho"),
        "kebab crate name missed: {found_chirho:?}"
    );
    assert!(
        found_chirho.contains("single_customer_app_chirho"),
        "snake identifier after :: missed: {found_chirho:?}"
    );
    assert!(
        found_chirho.contains("topology_grant_chirho"),
        "backticked name missed: {found_chirho:?}"
    );
    assert!(
        !found_chirho.contains("md2-sink-epoch-eq-granted"),
        "a non-chirho token was captured: {found_chirho:?}"
    );
}
