// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins the capability-tier witness that proves Pending/Bound ordering at resident birth.
//!
//! The witness is the ordering: it can be produced only after the sink cell write/recovery and is
//! consumed by the Bound identity path. A source guard is a backstop for the private-field and
//! single-construction contract; the type boundary remains the primary proof.

use super::super::*;

const WITNESS_MODULE_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_lifecycle_chirho.rs";
const WITNESS_TYPE_NEEDLE_CHIRHO: &str = "struct VerifiedResidentSinkTermCellAtBirthChirho {";
const WITNESS_FIELD_NEEDLES_CHIRHO: &[&str] =
    &["group_digest_chirho: String", "accepted_term_chirho: u64"];
const WITNESS_CONSTRUCTION_NEEDLE_CHIRHO: &str = "VerifiedResidentSinkTermCellAtBirthChirho {";

fn witness_source_chirho() -> String {
    let module_path_chirho = workspace_root_chirho().join(WITNESS_MODULE_PATH_CHIRHO);
    assert!(
        module_path_chirho.is_file(),
        "birth witness module moved or disappeared"
    );
    let raw_chirho = std::fs::read_to_string(&module_path_chirho)
        .unwrap_or_else(|_| panic!("read {WITNESS_MODULE_PATH_CHIRHO}"));
    production_text_chirho(&raw_chirho).into_owned()
}

fn witness_struct_body_chirho(source_chirho: &str) -> &str {
    let declaration_offset_chirho = source_chirho
        .find(WITNESS_TYPE_NEEDLE_CHIRHO)
        .expect("birth witness declaration needle");
    let body_start_chirho = declaration_offset_chirho + WITNESS_TYPE_NEEDLE_CHIRHO.len();
    let body_end_chirho = source_chirho[body_start_chirho..]
        .find('}')
        .map(|offset_chirho| body_start_chirho + offset_chirho)
        .expect("birth witness body terminator");
    &source_chirho[body_start_chirho..body_end_chirho]
}

#[test]
fn gd7_birth_witness_module_type_and_fields_are_live_once_chirho() {
    let production_paths_chirho = workspace_production_rs_files_chirho();
    let module_path_chirho = workspace_root_chirho().join(WITNESS_MODULE_PATH_CHIRHO);
    assert_eq!(
        production_paths_chirho
            .iter()
            .filter(|path_chirho| *path_chirho == &module_path_chirho)
            .count(),
        1,
        "birth witness module must resolve exactly once in production"
    );

    let source_chirho = witness_source_chirho();
    assert_eq!(
        source_chirho.matches(WITNESS_TYPE_NEEDLE_CHIRHO).count(),
        1,
        "birth witness type declaration must resolve exactly once"
    );
    let struct_body_chirho = witness_struct_body_chirho(&source_chirho);
    for field_needle_chirho in WITNESS_FIELD_NEEDLES_CHIRHO {
        assert_eq!(
            struct_body_chirho.matches(field_needle_chirho).count(),
            1,
            "birth witness field {field_needle_chirho} must resolve exactly once"
        );
        assert!(
            struct_body_chirho
                .lines()
                .filter(|line_chirho| line_chirho.contains(field_needle_chirho))
                .all(|line_chirho| {
                    field_line_is_private_chirho(line_chirho, field_needle_chirho)
                }),
            "birth witness field {field_needle_chirho} must remain private; widening visibility dissolves the capability tier"
        );
    }
}

#[test]
fn gd7_birth_witness_has_one_production_constructor_and_live_needles_chirho() {
    let source_chirho = witness_source_chirho();
    let construction_count_chirho = source_chirho
        .lines()
        .filter(|line_chirho| {
            line_chirho.contains(WITNESS_CONSTRUCTION_NEEDLE_CHIRHO)
                && !line_chirho.contains("struct ")
                && !line_chirho.contains("impl ")
        })
        .count();
    assert_eq!(
        construction_count_chirho, 1,
        "birth witness must have exactly one production construction site; a second constructor needs an authority review"
    );
    assert!(
        source_chirho.contains("VerifiedResidentSinkTermCellAtBirthChirho"),
        "birth witness needle must resolve in the production module"
    );
    for field_needle_chirho in WITNESS_FIELD_NEEDLES_CHIRHO {
        assert!(
            source_chirho.contains(field_needle_chirho),
            "birth witness field needle {field_needle_chirho} became unfindable"
        );
    }
}
