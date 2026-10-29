// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish but have everlasting life. - John 3:16 (KJV)

use super::super::*;

// FIVE ARMS RETIRED AT CF6 WAVE-1, and the reason is the file's own rule read forward.
//
// The comment below says a guard asserting a property of "billing" must read BOTH the writer and
// the retained evidence half, or the extraction silently narrows it. Wave-1 deleted the writer, so
// the five arms whose SUBJECT was writer behaviour -- recovery before append, reconciling authority
// before classifying the raw head, and the reviewed transition boundary -- have no subject left.
// They were removed rather than narrowed to the retained half: narrowing them would have kept five
// green tests whose names still promised a writer property nothing implements.
//
// CORRECTION 2026-07-26, same day, caught by the compiler rather than by review: this note first
// said "the arms below read the RETAINED half and are unaffected." THEY DO NOT. The two surviving
// arms read the successor crate's model and contract plus the projection crate; after the
// retirement NOTHING in this file read `legacy_billing_evidence_chirho.rs`, which is exactly the
// narrowing the rule three lines above warns about. The tell was two unused-constant warnings, on
// constants that pointed at LIVE files no arm here consumed any more.
//
// MEASURED BEFORE ACTING, because "this file stopped covering it" and "nothing covers it" are
// different claims: the retained half is still pinned by `positive_head_transition_guard_tests`
// (its `verified_head_transition_receipt_chirho` group), by the structure-report writer-head checks,
// and by 19 of its own characterization tests; the postings model is pinned by the r6e and
// wave1-zero-gate guards. So this was a FALSE SENTENCE, not a coverage hole, and the two dead
// constants are removed rather than propped up with an arm invented to justify them.
//
// Recover the deleted five from archive-chirho/26-07-26-cf6-wave1-money-spine-chirho if V2 billing
// wants them as a starting point.

const BILLING_MODEL_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-economic-chirho/src/billing_chirho.rs";
const BILLING_CONTRACT_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-economic-chirho/src/billing_contract_chirho.rs";
const TYPED_INGESTION_CHIRHO: &str = "crates/cairn-projection-chirho/src/typed_ingestion_chirho.rs";

fn production_file_chirho(path_chirho: &str) -> String {
    production_text_chirho(
        &std::fs::read_to_string(workspace_root_chirho().join(path_chirho)).unwrap(),
    )
    .into_owned()
}

fn between_markers_chirho<'a>(
    text_chirho: &'a str,
    start_chirho: &str,
    end_chirho: &str,
) -> &'a str {
    let start_chirho = text_chirho.find(start_chirho).unwrap();
    let end_chirho = text_chirho[start_chirho..]
        .find(end_chirho)
        .map(|offset_chirho| start_chirho + offset_chirho)
        .unwrap();
    &text_chirho[start_chirho..end_chirho]
}

#[test]
fn billing_v2_fields_are_additive_and_signed_chirho() {
    let model_chirho = production_file_chirho(BILLING_MODEL_CHIRHO);
    for required_chirho in [
        "BILLING_POLICY_RECORD_SCHEMA_CHIRHO: &str = \"billing-policy-record-v1-chirho\"",
        "BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO: &str = \"billing-policy-record-v2-chirho\"",
        "skip_serializing_if = \"String::is_empty\"",
        "pub transition_id_chirho: String",
        "skip_serializing_if = \"Option::is_none\"",
        "pub prepared_writer_fence_epoch_chirho: Option<u64>",
    ] {
        assert!(
            model_chirho.contains(required_chirho),
            "billing v2 contract lost {required_chirho}"
        );
    }
    let contract_chirho = production_file_chirho(BILLING_CONTRACT_CHIRHO);
    for required_chirho in [
        "transition_id_chirho: Option<&'a str>",
        "prepared_writer_fence_epoch_chirho: Option<u64>",
        "transition_id_chirho: nonempty_schema_chirho(&record_chirho.transition_id_chirho)",
        "prepared_writer_fence_epoch_chirho: record_chirho.prepared_writer_fence_epoch_chirho",
    ] {
        assert!(
            contract_chirho.contains(required_chirho),
            "billing signed message lost {required_chirho}"
        );
    }
}

#[test]
fn billing_projection_accepts_v2_without_widening_the_generic_parser_chirho() {
    let text_chirho = production_file_chirho(TYPED_INGESTION_CHIRHO);
    let billing_parser_chirho = between_markers_chirho(
        &text_chirho,
        "fn parse_billing_policy_record_chirho(",
        "fn parse_billing_usage_record_chirho(",
    );
    assert!(billing_parser_chirho.contains("BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO"));
    assert!(billing_parser_chirho.contains("canonical_line_chirho != line_chirho"));
    let generic_parser_chirho = between_markers_chirho(
        &text_chirho,
        "fn parse_typed_record_chirho<TChirho>(",
        "fn validate_schema_chirho(",
    );
    assert!(generic_parser_chirho.contains("validate_schema_chirho("));
    assert!(!generic_parser_chirho.contains("BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO"));
}
