// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;

const ONBOARDING_CHIRHO: &str = "src/edge_flows_chirho/onboarding_chirho.rs";
const ONBOARDING_MODEL_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/onboarding_chirho.rs";

fn production_onboarding_chirho() -> String {
    production_text_chirho(
        &std::fs::read_to_string(workspace_root_chirho().join(ONBOARDING_CHIRHO)).unwrap(),
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
fn onboarding_recovers_before_reading_previous_or_appending_chirho() {
    let text_chirho = production_onboarding_chirho();
    let set_chirho = between_markers_chirho(
        &text_chirho,
        "pub fn set_onboarding_guide_chirho(",
        "pub fn recover_onboarding_head_chirho(",
    );
    let recover_chirho = set_chirho
        .find("recover_onboarding_head_unlocked_chirho(")
        .unwrap();
    let previous_chirho = set_chirho.find("current_onboarding_hash_chirho(").unwrap();
    let append_chirho = set_chirho
        .find("append_onboarding_record_unlocked_chirho(")
        .unwrap();
    assert!(
        set_chirho.contains("with_head_transition_scope_chirho(")
            && recover_chirho < previous_chirho
            && previous_chirho < append_chirho,
        "onboarding must recover a verified pending transition before reading previous and appending the next signed row"
    );
}

#[test]
fn onboarding_recovery_verifies_before_lowering_prepared_rows_chirho() {
    let text_chirho = production_onboarding_chirho();
    let recovery_chirho = between_markers_chirho(
        &text_chirho,
        "fn recover_onboarding_head_unlocked_chirho(",
        "fn prepared_from_verified_onboarding_record_chirho(",
    );
    let verify_chirho = recovery_chirho
        .find("verified_onboarding_records_chirho(")
        .unwrap();
    let lower_chirho = recovery_chirho
        .find("prepared_from_verified_onboarding_record_chirho(")
        .unwrap();
    assert!(
        verify_chirho < lower_chirho,
        "verified onboarding records must be established before any row becomes Prepared"
    );
    assert!(
        !recovery_chirho.contains("load_onboarding_records_chirho("),
        "raw onboarding records must never mint Prepared transition authority"
    );
    let set_chirho = between_markers_chirho(
        &text_chirho,
        "pub fn set_onboarding_guide_chirho(",
        "pub fn recover_onboarding_head_chirho(",
    );
    assert!(
        set_chirho
            .find("verified_onboarding_records_chirho(")
            .unwrap()
            < set_chirho
                .find("prepared_from_verified_onboarding_record_chirho(")
                .unwrap(),
        "a newly appended onboarding row must pass the exact verified-vector boundary before binding"
    );
}

#[test]
fn onboarding_current_reads_require_verified_history_and_v2_receipt_chirho() {
    let text_chirho = production_onboarding_chirho();
    let selected_chirho = between_markers_chirho(
        &text_chirho,
        "fn selected_verified_onboarding_record_chirho(",
        "pub fn current_onboarding_hash_chirho(",
    );
    let verified_chirho = selected_chirho
        .find("verified_onboarding_records_chirho(")
        .unwrap();
    let raw_head_chirho = selected_chirho.find("onboarding_ref_head_chirho(").unwrap();
    let lower_chirho = selected_chirho
        .find("prepared_from_verified_onboarding_record_chirho(")
        .unwrap();
    let receipt_chirho = selected_chirho
        .find("verified_head_transition_receipt_chirho(")
        .unwrap();
    assert!(
        verified_chirho < raw_head_chirho
            && raw_head_chirho < lower_chirho
            && lower_chirho < receipt_chirho,
        "onboarding selected authority must verify signed history before reading the ref and must lower the exact selected v2 row before checking its Applied receipt"
    );
    let current_chirho = between_markers_chirho(
        &text_chirho,
        "pub fn current_onboarding_hash_chirho(",
        "pub fn current_onboarding_guide_chirho(",
    );
    assert!(
        current_chirho.contains("selected_verified_onboarding_record_chirho(")
            && !current_chirho.contains("onboarding_ref_head_chirho("),
        "public onboarding current reads must not consume the raw mutable ref directly"
    );
    // The whole-file raw-head occurrence count freeze (==3) was demoted to the advisory structure
    // report; the verify-before-read + no-raw-ref-consumption engine claims stay RED above.
}

#[test]
fn onboarding_v2_is_additive_and_legacy_rows_cannot_recover_chirho() {
    let text_chirho = production_onboarding_chirho();
    let model_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(ONBOARDING_MODEL_CHIRHO)).unwrap();
    for required_chirho in [
        "ONBOARDING_RECORD_SCHEMA_CHIRHO: &str = \"onboarding-record-v1-chirho\"",
        "ONBOARDING_RECORD_V2_SCHEMA_CHIRHO: &str = \"onboarding-record-v2-chirho\"",
        "skip_serializing_if = \"String::is_empty\"",
        "pub transition_id_chirho: String",
        "skip_serializing_if = \"Option::is_none\"",
        "pub prepared_writer_fence_epoch_chirho: Option<u64>",
    ] {
        assert!(
            model_chirho.contains(required_chirho),
            "onboarding v2 additive field or legacy contract missing: {required_chirho}"
        );
    }
    for required_chirho in [
        "record_chirho.schema_chirho == ONBOARDING_RECORD_V2_SCHEMA_CHIRHO",
        "only verified onboarding v2 rows can become prepared head transitions",
    ] {
        assert!(
            text_chirho.contains(required_chirho),
            "onboarding root transition adapter missing: {required_chirho}"
        );
    }
}

#[test]
fn onboarding_v2_signature_and_transition_binding_stay_load_bearing_chirho() {
    let text_chirho = production_onboarding_chirho();
    let model_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(ONBOARDING_MODEL_CHIRHO)).unwrap();
    let message_start_chirho = model_chirho
        .find("fn onboarding_record_message_chirho(")
        .unwrap();
    let message_chirho = &model_chirho[message_start_chirho..];
    for required_chirho in [
        "transition_id_chirho: Option<&'a str>",
        "prepared_writer_fence_epoch_chirho: Option<u64>",
        "transition_id_chirho: (!record_chirho.transition_id_chirho.is_empty())",
        "prepared_writer_fence_epoch_chirho: record_chirho",
    ] {
        assert!(
            message_chirho.contains(required_chirho),
            "onboarding v2 signed message must bind {required_chirho}"
        );
    }
    for required_chirho in [
        "derive_head_transition_id_chirho(",
        "bind_caller_verified_head_transition_chirho(",
        "serde_json::to_vec(record_chirho)?",
    ] {
        assert!(
            text_chirho.contains(required_chirho),
            "onboarding transition identity or canonical-line binding missing {required_chirho}"
        );
    }
}

#[test]
fn onboarding_model_contract_stays_pure_chirho() {
    let model_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(ONBOARDING_MODEL_CHIRHO)).unwrap();
    for (line_index_chirho, line_chirho) in model_chirho.lines().enumerate() {
        let line_chirho = line_chirho.trim();
        if line_chirho.is_empty() || line_chirho.starts_with("//") {
            continue;
        }
        for forbidden_chirho in [
            "std::fs",
            "std::path",
            "cairn_chirho::",
            "store_chirho::",
            "refs_chirho::",
            "seqlog_chirho::",
            "sign_message_chirho(",
            "verify_with_pubkey_chirho(",
            "cairn_writer_head_chirho",
            "HEAD_TRANSITION_ID_PREFIX_CHIRHO",
        ] {
            assert!(
                !line_chirho.contains(forbidden_chirho),
                "pure onboarding model owns forbidden I/O or trust token {forbidden_chirho} at {}:{}",
                ONBOARDING_MODEL_CHIRHO,
                line_index_chirho + 1
            );
        }
    }
}

#[test]
fn onboarding_cannot_bypass_the_reviewed_transition_boundary_chirho() {
    let text_chirho = production_onboarding_chirho();
    for forbidden_chirho in [
        "refs_chirho::commit_head_chirho(",
        "commit_head_with_transition_receipt_chirho(",
        "with_head_commit_chirho(",
        "refs_chirho::save_refs_chirho(",
        "refs_chirho::set_branch_chirho(",
        "refs_chirho::rollback_chirho(",
    ] {
        assert!(
            !text_chirho.contains(forbidden_chirho),
            "onboarding production path bypasses the reviewed positive-head protocol via {forbidden_chirho}"
        );
    }
    for required_chirho in [
        "pending_head_transition_index_unlocked_chirho(",
        "complete_head_transition_unlocked_chirho(",
    ] {
        assert!(
            text_chirho.contains(required_chirho),
            "onboarding production path must retain reviewed transition call {required_chirho}"
        );
    }
}
