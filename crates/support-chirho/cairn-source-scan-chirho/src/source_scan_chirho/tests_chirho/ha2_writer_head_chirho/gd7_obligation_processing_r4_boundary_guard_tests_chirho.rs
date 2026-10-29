// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Keeps R2/R3 independent from the R4 provider, journal, authority, and fence composition.

use super::super::*;

const GD7_OBLIGATION_PROCESSING_MODULE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/plan_chirho/obligation_processing_chirho/mod.rs";

const R4_FORBIDDEN_NEEDLES_CHIRHO: &[&str] = &[
    "append_effect_compensation_chirho(",
    "advance_accepted_winner_term_chirho(",
    "create_sink_term_fence_at_birth_chirho(",
    "execute_gd7_compensation_provider_chirho(",
    "derive_current_gd7_winner_compensation_authority_chirho(",
];

// The provider-adapter and winner-authority needles are live in the actor-owned typed seam. Their
// liveness is checked outside this guard so a renamed family cannot leave a green census.

#[test]
fn gd7_obligation_processing_has_no_r4_composition_symbols_chirho() {
    let module_path_chirho = workspace_root_chirho().join(GD7_OBLIGATION_PROCESSING_MODULE_CHIRHO);
    assert!(
        module_path_chirho.is_file(),
        "R2/R3 module moved or disappeared"
    );
    let raw_chirho = std::fs::read_to_string(&module_path_chirho).expect("read R2/R3 module");
    let source_chirho = production_text_chirho(&raw_chirho);
    for needle_chirho in R4_FORBIDDEN_NEEDLES_CHIRHO {
        assert!(
            !source_chirho.contains(needle_chirho),
            "R2/R3 contains forbidden R4 symbol {needle_chirho}; keep provider, journal, authority, and fence composition in R4"
        );
    }
}

#[test]
fn gd7_obligation_processing_guard_needles_are_live_outside_the_guard_chirho() {
    let guard_path_chirho = workspace_root_chirho().join(
        "crates/support-chirho/cairn-source-scan-chirho/src/source_scan_chirho/tests_chirho/ha2_writer_head_chirho/gd7_obligation_processing_r4_boundary_guard_tests_chirho.rs",
    );
    let production_paths_chirho = workspace_production_rs_files_chirho();
    for needle_chirho in R4_FORBIDDEN_NEEDLES_CHIRHO {
        let outside_guard_count_chirho = production_paths_chirho
            .iter()
            .filter(|path_chirho| *path_chirho != &guard_path_chirho)
            .map(|path_chirho| {
                let raw_chirho = std::fs::read_to_string(path_chirho)
                    .unwrap_or_else(|_| panic!("read {}", workspace_relative_chirho(path_chirho)));
                production_text_chirho(&raw_chirho)
                    .matches(needle_chirho)
                    .count()
            })
            .sum::<usize>();
        assert!(
            outside_guard_count_chirho > 0,
            "R4 guard needle {needle_chirho} resolved only inside the guard or nowhere; add a live symbol or remove it"
        );
    }
}

#[test]
fn gd7_obligation_processing_r4_guard_has_positive_module_control_chirho() {
    let module_path_chirho = workspace_root_chirho().join(GD7_OBLIGATION_PROCESSING_MODULE_CHIRHO);
    assert_eq!(
        workspace_production_rs_files_chirho()
            .into_iter()
            .filter(|path_chirho| path_chirho == &module_path_chirho)
            .count(),
        1,
        "R2/R3 module census must find exactly one production module"
    );
}
