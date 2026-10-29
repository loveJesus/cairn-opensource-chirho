// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The verified sealed-plan obligation is evidence produced by the verifier, not a sibling-forgeable DTO.
//! This guard pins the in-crate boundary that an external compile-fail doctest cannot measure.

use super::super::*;

const TARGET_MODULE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/plan_chirho/obligation_mint_chirho/mod.rs";
const TYPE_DECLARATION_CHIRHO: &str = "pub(crate) struct VerifiedGd7SealedPlanObligationChirho";
const FIELD_NEEDLES_CHIRHO: [&str; 4] = [
    "plan_page_ref_chirho:",
    "plan_page_index_chirho:",
    "obligation_index_chirho:",
    "obligation_chirho:",
];

fn struct_body_chirho(source_chirho: &str) -> &str {
    let declaration_count_chirho = source_chirho.matches(TYPE_DECLARATION_CHIRHO).count();
    assert_eq!(
        declaration_count_chirho, 1,
        "expected exactly one verified sealed-plan obligation declaration; a moved or duplicated type makes this guard untrustworthy"
    );
    let declaration_start_chirho = source_chirho
        .find(TYPE_DECLARATION_CHIRHO)
        .expect("verified sealed-plan obligation declaration exists");
    let body_start_chirho = source_chirho[declaration_start_chirho..]
        .find('{')
        .map(|offset_chirho| declaration_start_chirho + offset_chirho + 1)
        .expect("verified sealed-plan obligation declaration has a body");
    let body_end_chirho = source_chirho[body_start_chirho..]
        .find("}\n\nimpl VerifiedGd7SealedPlanObligationChirho")
        .map(|offset_chirho| body_start_chirho + offset_chirho)
        .expect("verified sealed-plan obligation body has its expected impl boundary");
    &source_chirho[body_start_chirho..body_end_chirho]
}

#[test]
fn verified_sealed_plan_obligation_fields_are_sibling_private_chirho() {
    let mut module_count_chirho = 0usize;
    let mut private_field_bodies_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if relative_chirho != TARGET_MODULE_CHIRHO {
            continue;
        }
        module_count_chirho += 1;
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let production_source_chirho = production_text_chirho(&raw_chirho);
        let body_chirho = struct_body_chirho(&production_source_chirho);
        for field_needle_chirho in FIELD_NEEDLES_CHIRHO {
            assert_eq!(
                body_chirho.matches(field_needle_chirho).count(),
                1,
                "expected exactly one field {field_needle_chirho} in the verified obligation body"
            );
        }
        private_field_bodies_chirho.push(body_chirho.to_owned());
    }
    assert_eq!(
        module_count_chirho, 1,
        "expected exactly one obligation mint module; a moved or missing module is a failed measurement"
    );
    assert_eq!(private_field_bodies_chirho.len(), 1);
    for field_needle_chirho in FIELD_NEEDLES_CHIRHO {
        assert!(
            private_field_bodies_chirho[0]
                .lines()
                .filter(|line_chirho| line_chirho.contains(field_needle_chirho))
                .all(|line_chirho| {
                    field_line_is_private_chirho(line_chirho, field_needle_chirho)
                }),
            "verified sealed-plan obligation fields must remain private to obligation_mint_chirho so a sibling cannot manufacture verification"
        );
    }
}
