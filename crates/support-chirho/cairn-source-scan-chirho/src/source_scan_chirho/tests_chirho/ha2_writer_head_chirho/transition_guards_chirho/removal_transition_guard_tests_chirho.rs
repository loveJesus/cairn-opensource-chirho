// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish but have everlasting life. - John 3:16 (KJV)

use super::super::*;
use std::collections::BTreeMap;

const HEAD_REMOVAL_CRATE_CHIRHO: &str = "crates/support-chirho/cairn-head-removal-chirho";
const REMOVAL_TRANSITION_CHIRHO: &str =
    "crates/support-chirho/cairn-head-removal-chirho/src/head_removal_transition_chirho.rs";
const APP_REMOVAL_ADOPTER_CHIRHO: &str =
    "crates/runtime-chirho/cairn-app-control-chirho/src/app_head_removal_chirho.rs";
const ROUTE_REMOVAL_ADOPTER_CHIRHO: &str =
    "crates/runtime-chirho/cairn-app-control-chirho/src/app_route_head_removal_chirho.rs";
const RESOURCE_POLICY_REMOVAL_ADOPTER_CHIRHO: &str =
    "src/app_metering_chirho/resource_chirho/policy_head_removal_chirho.rs";
const APP_DEPLOY_EVIDENCE_ADOPTER_CHIRHO: &str =
    "src/app_runtime_chirho/app_chirho/app_deploy_evidence_chirho.rs";
const APP_ROUTE_DEPLOY_EVIDENCE_ADOPTER_CHIRHO: &str =
    "crates/runtime-chirho/cairn-app-control-chirho/src/elected_app_route_deploy_chirho.rs";
const WRITER_HEAD_CRATE_CHIRHO: &str = "crates/support-chirho/cairn-writer-head-chirho";

fn removal_transition_forbidden_tokens_chirho(text_chirho: &str) -> Vec<&'static str> {
    let production_chirho = production_text_chirho(text_chirho);
    [
        "sign_message_chirho(",
        "load_or_create_signing_key_chirho(",
        "serde(untagged)",
        "refs_chirho::set_branch_chirho(",
        "refs_chirho::rollback_chirho(",
        "refs_chirho::save_refs_chirho(",
        "ledger_chirho::",
        "paid_chirho::",
        "provider_chirho::",
        "gate1_authority_chirho::",
        "axum::",
        "Sse",
        "WebSocket",
    ]
    .into_iter()
    .filter(|token_chirho| production_chirho.contains(token_chirho))
    .collect()
}

fn settled_and_fence_checks_precede_delete_chirho(text_chirho: &str) -> bool {
    let production_chirho = production_text_chirho(text_chirho);
    let Some(start_chirho) =
        production_chirho.find("pub fn complete_head_removal_unlocked_chirho(")
    else {
        return false;
    };
    let end_chirho = production_chirho[start_chirho..]
        .find("pub fn recover_head_removal_chirho(")
        .map(|offset_chirho| start_chirho + offset_chirho)
        .unwrap_or(production_chirho.len());
    let complete_chirho = &production_chirho[start_chirho..end_chirho];
    let Some(first_fence_chirho) = complete_chirho.find("verify_applier_fence_chirho(") else {
        return false;
    };
    let Some(settled_chirho) =
        complete_chirho.find("verified_applied_receipt_for_prepared_chirho(")
    else {
        return false;
    };
    let Some(delete_chirho) = complete_chirho.find("remove_branch_if_current_chirho(") else {
        return false;
    };
    let Some(receipt_chirho) = complete_chirho.find("append_applied_receipt_unlocked_chirho(")
    else {
        return false;
    };
    first_fence_chirho < settled_chirho
        && settled_chirho < delete_chirho
        && delete_chirho < receipt_chirho
        && complete_chirho
            .matches("verify_applier_fence_chirho(")
            .count()
            >= 3
}

#[test]
fn removal_transition_adopters_stay_in_the_reviewed_family_and_deploy_preflight_set_chirho() {
    for (marker_chirho, app_adopts_chirho, deploy_preflight_adopts_chirho) in [
        (
            "append_caller_verified_prepared_head_removal_unlocked_chirho(",
            true,
            false,
        ),
        (
            "bind_caller_verified_prepared_head_removal_chirho(",
            true,
            false,
        ),
        ("complete_head_removal_unlocked_chirho(", true, false),
        ("recover_head_removal_chirho(", false, false),
        (
            "verified_head_removal_applied_receipt_chirho(",
            false,
            false,
        ),
        ("pending_head_removal_index_unlocked_chirho(", true, false),
        (
            "root_signed_prepared_head_removal_records_chirho(",
            true,
            true,
        ),
    ] {
        let mut actual_chirho = BTreeMap::new();
        for (file_chirho, _line_chirho, _text_chirho) in
            production_source_lines_matching_chirho(marker_chirho)
        {
            *actual_chirho.entry(file_chirho).or_insert(0usize) += 1;
        }
        let mut expected_chirho = vec![REMOVAL_TRANSITION_CHIRHO.to_string()];
        if app_adopts_chirho {
            expected_chirho.insert(0, APP_REMOVAL_ADOPTER_CHIRHO.to_string());
            expected_chirho.insert(1, ROUTE_REMOVAL_ADOPTER_CHIRHO.to_string());
            expected_chirho.push(RESOURCE_POLICY_REMOVAL_ADOPTER_CHIRHO.to_string());
        }
        if deploy_preflight_adopts_chirho {
            expected_chirho.insert(2, APP_ROUTE_DEPLOY_EVIDENCE_ADOPTER_CHIRHO.to_string());
            expected_chirho.push(APP_DEPLOY_EVIDENCE_ADOPTER_CHIRHO.to_string());
        }
        assert_eq!(
            actual_chirho.keys().cloned().collect::<Vec<_>>(),
            expected_chirho
        );
    }
}

#[test]
fn resource_policy_removal_adopter_keeps_trust_boundaries_chirho() {
    let text_chirho = std::fs::read_to_string(
        workspace_root_chirho().join(RESOURCE_POLICY_REMOVAL_ADOPTER_CHIRHO),
    )
    .unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    for required_chirho in [
        "verify_writer_fence_for_root_chirho(",
        "verify_head_removal_records_chirho(",
        "latest_policy_event_chirho(",
        "resource_policy_unset_line_at_seq_chirho(",
        "RESOURCE_POLICY_UNSET_RECORDS_LOG_CHIRHO",
    ] {
        assert!(
            production_chirho.contains(required_chirho),
            "resource policy removal adopter must retain {required_chirho}"
        );
    }
    for forbidden_chirho in [
        "sign_message_chirho(",
        "load_or_create_signing_key_chirho(",
        "serde(untagged)",
        "refs_chirho::",
        "append_head_removal_record_unlocked_chirho(",
        "append_serialized_jsonl",
        "append_recovered_jsonl",
        "ledger_chirho::",
        "paid_chirho::",
        "provider_chirho::",
        "axum::",
        "Sse",
        "WebSocket",
    ] {
        assert!(
            !production_chirho.contains(forbidden_chirho),
            "resource policy removal adopter must not contain {forbidden_chirho}"
        );
    }
}

#[test]
fn removal_transition_dependency_is_strictly_downward_and_acyclic_chirho() {
    let removal_cargo_chirho = std::fs::read_to_string(
        workspace_root_chirho().join(format!("{HEAD_REMOVAL_CRATE_CHIRHO}/Cargo.toml")),
    )
    .unwrap();
    assert!(removal_cargo_chirho.contains("cairn-writer-head-chirho"));
    let writer_cargo_chirho = std::fs::read_to_string(
        workspace_root_chirho().join(format!("{WRITER_HEAD_CRATE_CHIRHO}/Cargo.toml")),
    )
    .unwrap();
    assert!(
        !writer_cargo_chirho.contains("cairn-head-removal-chirho"),
        "writer-head must never depend upward on head-removal"
    );
    for forbidden_chirho in [
        "cairn-chirho =",
        "cairn-cli-chirho",
        "cairn-serve-runtime-chirho",
        "axum",
        "reqwest",
        "stripe",
    ] {
        assert!(
            !removal_cargo_chirho.contains(forbidden_chirho),
            "removal transition foundation gained forbidden dependency {forbidden_chirho}"
        );
    }
}

#[test]
fn removal_transition_uses_schema_first_decode_existing_key_and_root_pin_chirho() {
    let text_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(REMOVAL_TRANSITION_CHIRHO)).unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    for required_chirho in [
        "HeadRemovalSchemaProbeChirho",
        "match probe_chirho.schema_chirho.as_str()",
        "HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO",
        "HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO",
        "HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO",
        "serde(deny_unknown_fields)",
        "existing_pubkey_hex_chirho(",
        "sign_message_with_existing_key_chirho(",
        "verify_with_pubkey_chirho(",
        "verify_writer_fence_for_root_chirho(",
        "recover_jsonl_len_unlocked_chirho(",
    ] {
        assert!(
            production_chirho.contains(required_chirho),
            "removal transition trust path must retain {required_chirho}"
        );
    }
    assert!(
        removal_transition_forbidden_tokens_chirho(&text_chirho).is_empty(),
        "removal transition foundation contains forbidden surfaces: {:?}",
        removal_transition_forbidden_tokens_chirho(&text_chirho)
    );
}

#[test]
fn removal_transition_settled_and_fence_checks_precede_delete_chirho() {
    let text_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(REMOVAL_TRANSITION_CHIRHO)).unwrap();
    assert!(
        settled_and_fence_checks_precede_delete_chirho(&text_chirho),
        "current fence and settled receipt must precede delete, then Applied must follow"
    );
}

#[test]
fn removal_transition_reuses_tracked_log_without_path_or_private_payload_chirho() {
    let text_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(REMOVAL_TRANSITION_CHIRHO)).unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    assert!(production_chirho.contains("head_removal_records_path_chirho("));
    assert!(
        !production_chirho.contains("root_chirho.join("),
        "removal foundation must reuse the inventoried head-removals log"
    );
    for forbidden_chirho in [
        "root_path_chirho",
        "canonical_root_chirho:",
        "private_value_chirho",
        "payload_chirho",
        "family_line_chirho:",
    ] {
        assert!(
            !production_chirho.contains(forbidden_chirho),
            "Prepared/Applied records must not persist path/private field {forbidden_chirho}"
        );
    }
    assert!(production_chirho.contains("validate_domain_log_basename_chirho("));
}

#[test]
fn removal_transition_guard_fixture_catches_create_capable_signer_and_early_delete_chirho() {
    let unsafe_chirho = r#"
        pub fn complete_head_removal_unlocked_chirho() {
            remove_branch_if_current_chirho();
            sign_message_chirho();
            verified_applied_receipt_for_prepared_chirho();
        }
    "#;
    assert_eq!(
        removal_transition_forbidden_tokens_chirho(unsafe_chirho),
        vec!["sign_message_chirho("]
    );
    assert!(
        !settled_and_fence_checks_precede_delete_chirho(unsafe_chirho),
        "guard fixture must catch delete before settled/fence checks"
    );
}
