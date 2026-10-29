// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! W3 brick-1 job J0a source guards: the frozen, authority-inert ledger schema-v2 landing.
//!
//! J0a defines the schema-v2 op binding but keeps ALL production money authority INACTIVE. This
//! guard pins one structural invariant load-bearingly: `ElectedTermV1Chirho` (the gated-A6
//! authority mode) has EXACTLY ONE production occurrence — its enum-variant definition — and ZERO
//! constructors anywhere, qualified OR unqualified. (The two-read-road inertness is proven
//! behaviorally by the root-crate ledger tests and the Gate-1 projection tests, not by a token
//! guard.)

use crate::source_scan_chirho::{
    production_text_chirho, workspace_production_rs_files_chirho, workspace_root_chirho,
};

const THIS_GUARD_RELATIVE_PATH_CHIRHO: &str = concat!(
    "crates/support-chirho/cairn-source-scan-chirho/src/source_scan_chirho/",
    "tests_chirho/ha_gate1_flip_chirho/w3_j0a_schema_guard_tests_chirho.rs"
);

/// The guard file itself names these identifiers in string literals; exclude it from the scan.
fn is_this_guard_file_chirho(path_chirho: &std::path::Path) -> bool {
    path_chirho == workspace_root_chirho().join(THIS_GUARD_RELATIVE_PATH_CHIRHO)
}

#[test]
fn guard_file_exclusion_is_exact_and_never_basename_wide_chirho() {
    let root_chirho = workspace_root_chirho();
    assert!(is_this_guard_file_chirho(
        &root_chirho.join(THIS_GUARD_RELATIVE_PATH_CHIRHO)
    ));
    assert!(!is_this_guard_file_chirho(
        &root_chirho.join("src/w3_j0a_schema_guard_tests_chirho.rs")
    ));
}

/// Count every `ElectedTermV1Chirho {` struct-literal in production (non-test) text — this matches
/// BOTH a qualified `Foo::ElectedTermV1Chirho { .. }` construction AND an unqualified (via `use`)
/// `ElectedTermV1Chirho { .. }` construction AND the enum-variant DEFINITION, so a `use`-imported
/// constructor cannot bypass it.
fn count_elected_term_literal_chirho(text_chirho: &str) -> usize {
    production_text_chirho(text_chirho)
        .matches("ElectedTermV1Chirho {")
        .count()
}

#[test]
fn elected_term_v1_has_exactly_one_definition_and_zero_constructors_chirho() {
    let mut definition_files_chirho = 0usize;
    for path_chirho in workspace_production_rs_files_chirho() {
        if is_this_guard_file_chirho(&path_chirho) {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_else(|error_chirho| {
            panic!(
                "production source {} must remain readable for the J0a authority guard: {error_chirho}",
                path_chirho.display()
            )
        });
        let occurrences_chirho = count_elected_term_literal_chirho(&text_chirho);
        if path_chirho.ends_with("op_binding_chirho.rs") {
            // The one allowed occurrence is the enum-variant DEFINITION. Any second occurrence in
            // this file would be a production constructor and must fail.
            assert_eq!(
                occurrences_chirho, 1,
                "op_binding_chirho.rs must contain ONLY the ElectedTermV1Chirho definition (no constructor)"
            );
            definition_files_chirho += 1;
        } else {
            assert_eq!(
                occurrences_chirho, 0,
                "ElectedTermV1Chirho must have zero constructors (qualified or unqualified) outside its definition; found one in {}",
                path_chirho.display()
            );
        }
    }
    assert_eq!(
        definition_files_chirho, 1,
        "the ElectedTermV1Chirho definition file must exist and be scanned"
    );
}

#[test]
fn the_zero_producer_guard_detects_an_unqualified_constructor_chirho() {
    // Meta-plant: a `use`-imported UNQUALIFIED constructor has no `::` prefix but still contains the
    // struct literal. The count-based guard catches it (a `::`-only needle would not).
    let planted_chirho =
        "use foo_chirho::MoneyWriterAuthorityContextChirho::ElectedTermV1Chirho;\n\
         let _ = ElectedTermV1Chirho { term_chirho: 1 };\n";
    assert_eq!(
        count_elected_term_literal_chirho(planted_chirho),
        1,
        "the guard must detect an unqualified ElectedTermV1Chirho constructor"
    );
    // A `#[cfg(test)]` construction is stripped and does not count (so split shape tests are exempt).
    let test_only_chirho =
        "#[cfg(test)]\nmod t { fn f() { let _ = ElectedTermV1Chirho { x: 1 }; } }\n";
    assert_eq!(count_elected_term_literal_chirho(test_only_chirho), 0);
}

#[test]
fn source_finality_issuer_socket_stays_absent_from_production_chirho() {
    const RETIRED_SOURCE_ISSUER_SYMBOLS_CHIRHO: &[&str] = &[
        "BurnDestinationBindingChirho",
        "IssuedFinalityProofChirho",
        "claim_for_issued_proof_chirho",
        "finality_issuer_chirho",
        "issue_finality_proof_chirho",
    ];
    let mut scanned_files_chirho = 0usize;
    for path_chirho in workspace_production_rs_files_chirho() {
        if is_this_guard_file_chirho(&path_chirho) {
            continue;
        }
        let source_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_else(|error_chirho| {
            panic!(
                "production source {} must remain readable for the source-finality absence guard: {error_chirho}",
                path_chirho.display()
            )
        });
        let production_chirho = production_text_chirho(&source_chirho);
        for symbol_chirho in RETIRED_SOURCE_ISSUER_SYMBOLS_CHIRHO {
            assert!(
                !production_chirho.contains(symbol_chirho),
                "retired source-finality issuer symbol {symbol_chirho} reappeared in production at {}",
                path_chirho.display()
            );
        }
        scanned_files_chirho += 1;
    }
    assert!(
        scanned_files_chirho > 100,
        "source-finality issuer absence must scan the production workspace, not an empty input"
    );
}
