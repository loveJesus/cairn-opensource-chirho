// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! CF8 clause 9's *"applied only through the … ports"* — DERIVED and enforced, not argued.
//!
//! The clause's first element is a NEGATIVE claim: no path mutates a registered node except through a
//! port carrying verified evidence. A negative claim is exactly the kind that reading cannot settle —
//! it is true when written and silent the day someone adds a sixth mutator.
//!
//! So the population is DERIVED rather than enumerated: every `pub fn` on the placement registry that
//! takes `&mut self`. Each must either accept a `Verified…Chirho` parameter, or appear in a small
//! reviewed allowlist with its reason recorded here. An enumerated list of "the mutators" would pass
//! forever while the real set grew underneath it.
//!
//! **Two failure modes this guard is written against, both hit while measuring this very population.**
//! First, slicing the file at the FIRST `#[cfg(test)]` cuts it at a mid-file test constructor and
//! silently measures a fraction — that produced a confident "one mutator" when there are five. So
//! `cfg(test)` is resolved per item, from the lines immediately above each signature. Second, a
//! derived population that comes back empty passes trivially, so the count is asserted.

use crate::source_scan_chirho::workspace_root_chirho;

const REGISTRY_PATH_CHIRHO: &str =
    "crates/domain-chirho/cairn-placement-chirho/src/placement_registry_chirho.rs";

/// Public mutators that do NOT take verified evidence, each with the reason it is allowed to.
///
/// Kept deliberately tiny. Adding to it is a decision about authority, not a formality.
///
/// It started with a THIRD entry for `set_measurement_for_test_chirho`, and the staleness arm below
/// rejected it on the guard's first run: that method is `pub(crate)`, so the derived population — which
/// is `pub fn` — never contained it, and the exemption was granting something nobody had asked for. An
/// unnecessary exemption is not harmless; it is a permanently open door nobody can see is unused.
const REVIEWED_NON_EVIDENCE_MUTATORS_CHIRHO: &[(&str, &str)] = &[
    (
        "upsert_node_chirho",
        "takes a RegisteredNodeChirho, whose only PRODUCTION constructor is \
         from_verified_capacity_chirho — verified evidence one hop removed, not an escape",
    ),
    (
        "record_placement_chirho",
        "records a placement, not node authority state: it moves no capacity, lifecycle or \
         measurement, and admission is decided before it is called",
    ),
];

/// Every `pub fn` taking `&mut self`, with its `cfg(test)` status resolved per item.
fn registry_mutators_chirho() -> Vec<(String, bool)> {
    let source_chirho = std::fs::read_to_string(workspace_root_chirho().join(REGISTRY_PATH_CHIRHO))
        .unwrap_or_else(|error_chirho| panic!("read {REGISTRY_PATH_CHIRHO}: {error_chirho}"));
    let lines_chirho = source_chirho.lines().collect::<Vec<_>>();
    let mut found_chirho = Vec::new();
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        let trimmed_chirho = line_chirho.trim_start();
        let Some(rest_chirho) = trimmed_chirho.strip_prefix("pub fn ") else {
            continue;
        };
        let Some(name_chirho) = rest_chirho.split(['(', '<']).next() else {
            continue;
        };
        // The signature may wrap, so gather until the parameter list closes.
        let mut signature_chirho = String::new();
        let mut depth_chirho = 0_i32;
        for later_chirho in lines_chirho.iter().skip(index_chirho) {
            signature_chirho.push_str(later_chirho);
            depth_chirho += later_chirho.matches('(').count() as i32;
            depth_chirho -= later_chirho.matches(')').count() as i32;
            if depth_chirho <= 0 && signature_chirho.contains('(') {
                break;
            }
        }
        if !signature_chirho.contains("&mut self") {
            continue;
        }
        // cfg(test) resolved PER ITEM: the first cfg(test) in this file is a mid-file constructor, so
        // slicing the file at it would measure a fraction and look plausible doing so.
        let is_test_chirho = lines_chirho[index_chirho.saturating_sub(4)..index_chirho]
            .iter()
            .any(|above_chirho| above_chirho.contains("#[cfg(test)]"));
        found_chirho.push((name_chirho.trim().to_string(), is_test_chirho));
    }
    found_chirho
}

#[test]
fn every_registry_mutator_takes_verified_evidence_or_is_reviewed_chirho() {
    let source_chirho = std::fs::read_to_string(workspace_root_chirho().join(REGISTRY_PATH_CHIRHO))
        .expect("read the registry");
    let mutators_chirho = registry_mutators_chirho();
    assert!(
        mutators_chirho.len() >= 4,
        "derived mutator population collapsed to {} — the parser drifted, and an empty or tiny \
         population would pass this guard trivially",
        mutators_chirho.len()
    );

    for (name_chirho, is_test_chirho) in &mutators_chirho {
        if *is_test_chirho {
            continue;
        }
        if REVIEWED_NON_EVIDENCE_MUTATORS_CHIRHO
            .iter()
            .any(|(reviewed_chirho, _reason_chirho)| reviewed_chirho == name_chirho)
        {
            continue;
        }
        // Does its signature name a Verified… type? Gather the whole signature again by name.
        let marker_chirho = format!("pub fn {name_chirho}");
        let start_chirho = source_chirho
            .find(&marker_chirho)
            .unwrap_or_else(|| panic!("signature for {name_chirho} vanished"));
        let window_chirho = &source_chirho[start_chirho..];
        let end_chirho = window_chirho.find(" {").unwrap_or(window_chirho.len());
        let signature_chirho = &window_chirho[..end_chirho];
        assert!(
            signature_chirho.contains("Verified"),
            "CF8 clause 9 requires a registered node to be mutated only through a port carrying \
             VERIFIED evidence. `{name_chirho}` takes none and is not in the reviewed allowlist. \
             Either give it verified evidence, or add it to \
             REVIEWED_NON_EVIDENCE_MUTATORS_CHIRHO with the reason it is safe — that is an authority \
             decision, not a formality."
        );
    }
}

#[test]
fn positive_control_the_mutator_parser_sees_a_known_mutator_chirho() {
    // Without this, a parser that found nothing would make the guard above pass while measuring an
    // empty world — the failure this repo calls green-by-emptiness, here at the guard's own input.
    let names_chirho = registry_mutators_chirho()
        .into_iter()
        .map(|(name_chirho, _test_chirho)| name_chirho)
        .collect::<Vec<_>>();
    for expected_chirho in [
        "advance_by_verified_transition_chirho",
        "advance_node_capacity_chirho",
        "upsert_node_chirho",
    ] {
        assert!(
            names_chirho
                .iter()
                .any(|name_chirho| name_chirho == expected_chirho),
            "the parser did not see `{expected_chirho}`; it found {names_chirho:?}"
        );
    }
}

#[test]
fn the_reviewed_allowlist_names_only_mutators_that_still_exist_chirho() {
    // An allowlist entry for a method that was deleted or renamed is a permanently-granted exemption
    // nobody can see is unused. Same shape as a stale census: true when written, silent afterwards.
    let names_chirho = registry_mutators_chirho()
        .into_iter()
        .map(|(name_chirho, _test_chirho)| name_chirho)
        .collect::<Vec<_>>();
    for (reviewed_chirho, _reason_chirho) in REVIEWED_NON_EVIDENCE_MUTATORS_CHIRHO {
        assert!(
            names_chirho.iter().any(|name_chirho| name_chirho == reviewed_chirho),
            "reviewed exemption `{reviewed_chirho}` names no current mutator — remove it rather than \
             leaving a granted exemption for something that no longer exists"
        );
    }
}
