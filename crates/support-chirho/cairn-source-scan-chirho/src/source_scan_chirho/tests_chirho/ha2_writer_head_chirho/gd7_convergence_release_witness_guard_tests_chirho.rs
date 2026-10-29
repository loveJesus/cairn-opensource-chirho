// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins the private, single-construction release witness for the GD7 convergence certificate.

use super::super::*;

const WITNESS_MODULE_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/plan_chirho/authority_chirho.rs";
const WITNESS_TYPE_NEEDLE_CHIRHO: &str = "struct VerifiedGd7ConvergenceReleaseWitnessChirho {";
const WITNESS_FIELD_NEEDLE_CHIRHO: &str = "certificate_digest_chirho: String";
const WITNESS_CONSTRUCTION_NEEDLE_CHIRHO: &str = "VerifiedGd7ConvergenceReleaseWitnessChirho {";

fn witness_source_chirho() -> String {
    let path_chirho = workspace_root_chirho().join(WITNESS_MODULE_PATH_CHIRHO);
    assert!(
        path_chirho.is_file(),
        "release witness module moved or disappeared"
    );
    let raw_chirho = std::fs::read_to_string(&path_chirho)
        .unwrap_or_else(|_| panic!("read {WITNESS_MODULE_PATH_CHIRHO}"));
    production_text_chirho(&raw_chirho).into_owned()
}

#[test]
fn gd7_release_witness_is_private_and_constructed_once_chirho() {
    let source_chirho = witness_source_chirho();
    assert_eq!(
        source_chirho.matches(WITNESS_TYPE_NEEDLE_CHIRHO).count(),
        1,
        "release witness type must resolve exactly once"
    );
    let declaration_offset_chirho = source_chirho
        .find(WITNESS_TYPE_NEEDLE_CHIRHO)
        .expect("release witness declaration exists");
    let body_start_chirho = declaration_offset_chirho + WITNESS_TYPE_NEEDLE_CHIRHO.len();
    let body_end_chirho = source_chirho[body_start_chirho..]
        .find('}')
        .map(|offset_chirho| body_start_chirho + offset_chirho)
        .expect("release witness body terminator exists");
    let body_chirho = &source_chirho[body_start_chirho..body_end_chirho];
    assert_eq!(body_chirho.matches(WITNESS_FIELD_NEEDLE_CHIRHO).count(), 1);
    assert!(
        body_chirho
            .lines()
            .filter(|line_chirho| line_chirho.contains(WITNESS_FIELD_NEEDLE_CHIRHO))
            .all(|line_chirho| field_line_is_private_chirho(
                line_chirho,
                WITNESS_FIELD_NEEDLE_CHIRHO
            )),
        "release witness field must remain private"
    );
    let construction_count_chirho = source_chirho
        .lines()
        .filter(|line_chirho| {
            line_chirho.contains(WITNESS_CONSTRUCTION_NEEDLE_CHIRHO)
                && !line_chirho.contains("struct ")
                && !line_chirho.contains("impl ")
                && !line_chirho.contains("->")
        })
        .count();
    assert_eq!(
        construction_count_chirho, 1,
        "release witness must have one construction site"
    );
}
