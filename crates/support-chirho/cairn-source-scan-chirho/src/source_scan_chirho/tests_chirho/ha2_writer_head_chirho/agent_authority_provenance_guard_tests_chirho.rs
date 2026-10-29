// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;

const AGENT_AUTHORITY_CHIRHO: &str = "src/governance_flows_chirho/agent_authority_chirho/mod.rs";
const AGENT_AUTHORITY_POLICY_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-agent-authority-chirho/src/policy_chirho.rs";

fn production_file_chirho(relative_chirho: &str) -> String {
    production_text_chirho(
        &std::fs::read_to_string(workspace_root_chirho().join(relative_chirho)).unwrap(),
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
fn agent_authority_decisions_require_verified_selected_history_chirho() {
    let text_chirho = production_file_chirho(AGENT_AUTHORITY_CHIRHO);
    let configured_chirho = between_markers_chirho(
        &text_chirho,
        "pub fn check_configured_agent_action_authorized_chirho(",
        "pub fn check_agent_action_authorized_chirho(",
    );
    for required_chirho in [
        "verified_agent_authority_history_chirho(root_chirho)",
        "selected_verified_agent_authority_state_chirho(",
        ".states_by_agent_chirho",
        ".contains_key(agent_principal_chirho)",
        "current agent authority provenance is not verified",
    ] {
        assert!(
            configured_chirho.contains(required_chirho),
            "configured agent-authority decisions must retain verified-history requirement {required_chirho}"
        );
    }
    for forbidden_chirho in [
        "current_agent_authority_state_chirho(",
        "load_agent_authority_state_chirho(",
        "load_agent_authority_response_records_chirho(",
    ] {
        assert!(
            !configured_chirho.contains(forbidden_chirho),
            "configured agent-authority decisions must not trust raw loader {forbidden_chirho}"
        );
    }
}

#[test]
fn verified_agent_authority_history_preserves_every_trust_check_chirho() {
    let text_chirho = production_file_chirho(AGENT_AUTHORITY_CHIRHO);
    let history_chirho = between_markers_chirho(
        &text_chirho,
        "fn verified_agent_authority_history_chirho(",
        "pub fn verify_agent_authority_responses_chirho(",
    );
    for required_chirho in [
        "verify_agent_report_records_chirho(root_chirho)",
        "verify_with_pubkey_chirho(",
        "validate_response_record_matches_report_chirho(",
        "old state does not match replayed head",
        "old state is not prior verified same-agent history",
        "derive_state_from_record_chirho(",
        "hash_object_chirho(&stored_state_chirho)",
        "state does not replay from prior state",
    ] {
        assert!(
            history_chirho.contains(required_chirho),
            "verified agent-authority history lost trust check {required_chirho}"
        );
    }
    for forbidden_chirho in [
        "current_agent_authority_hash_chirho(",
        "current_agent_authority_state_chirho(",
        "load_refs_chirho(",
    ] {
        assert!(
            !history_chirho.contains(forbidden_chirho),
            "verified history construction must not let mutable refs shape signed history via {forbidden_chirho}"
        );
    }
}

#[test]
fn public_agent_authority_verifier_accepts_only_ref_selected_verified_history_chirho() {
    let text_chirho = production_file_chirho(AGENT_AUTHORITY_CHIRHO);
    let verifier_chirho = between_markers_chirho(
        &text_chirho,
        "pub fn verify_agent_authority_responses_chirho(",
        "pub fn agent_authority_ref_chirho(",
    );
    for required_chirho in [
        "verified_agent_authority_history_chirho(root_chirho)",
        "selected_verified_agent_authority_state_chirho(",
        "is not verified response history",
    ] {
        assert!(
            verifier_chirho.contains(required_chirho),
            "public agent-authority verification must retain rollback-aware history selection {required_chirho}"
        );
    }
    assert!(
        !verifier_chirho.contains("latest_by_agent_chirho"),
        "public verification must not reject deliberate rollback by requiring the latest appended v1 row"
    );
}

#[test]
fn agent_authority_v2_recovery_precedes_append_and_uses_reviewed_transition_sink_chirho() {
    let text_chirho = production_file_chirho(AGENT_AUTHORITY_CHIRHO);
    let apply_chirho = between_markers_chirho(
        &text_chirho,
        "pub fn apply_agent_authority_response_chirho(",
        "fn append_prepared_agent_authority_response_unlocked_chirho(",
    );
    let scope_chirho = apply_chirho
        .find("with_head_transition_scope_chirho(")
        .unwrap();
    let append_chirho = apply_chirho
        .find("append_prepared_agent_authority_response_unlocked_chirho(")
        .unwrap();
    let complete_chirho = apply_chirho
        .find("complete_head_transition_unlocked_chirho(")
        .unwrap();
    assert!(
        scope_chirho < append_chirho && append_chirho < complete_chirho,
        "agent-authority writes must prepare and verify the v2 row before the reviewed head sink completes it"
    );

    let prepare_chirho = between_markers_chirho(
        &text_chirho,
        "fn append_prepared_agent_authority_response_unlocked_chirho(",
        "pub fn recover_agent_authority_head_chirho(",
    );
    let recover_chirho = prepare_chirho
        .find("recover_agent_authority_head_unlocked_chirho(")
        .unwrap();
    let object_write_chirho = prepare_chirho
        .find("store_chirho::put_object_chirho(")
        .unwrap();
    let log_write_chirho = prepare_chirho
        .find("seqlog_chirho::append_recovered_jsonl_unlocked_chirho(")
        .unwrap();
    let bind_chirho = prepare_chirho
        .find("prepared_from_verified_agent_authority_record_chirho(")
        .unwrap();
    assert!(
        recover_chirho < object_write_chirho
            && object_write_chirho < log_write_chirho
            && log_write_chirho < bind_chirho,
        "agent-authority must recover its branch before a new state or v2 row and must bind only the reloaded verified row"
    );
    for forbidden_chirho in [
        "refs_chirho::commit_head_chirho(",
        "refs_chirho::set_branch_chirho(",
        "v2 branch-capable commit required",
    ] {
        assert!(
            !text_chirho.contains(forbidden_chirho),
            "agent-authority v2 adoption must remove legacy/direct head path {forbidden_chirho}"
        );
    }
}

#[test]
fn agent_authority_selected_v2_state_requires_verified_applied_receipt_chirho() {
    let text_chirho = production_file_chirho(AGENT_AUTHORITY_CHIRHO);
    let selected_chirho = between_markers_chirho(
        &text_chirho,
        "fn selected_verified_agent_authority_state_chirho(",
        "pub fn check_configured_agent_action_authorized_chirho(",
    );
    for required_chirho in [
        "record_index_by_agent_state_chirho",
        "prepared_from_verified_agent_authority_record_chirho(",
        "verified_head_transition_receipt_chirho(",
        "has no verified Applied receipt",
    ] {
        assert!(
            selected_chirho.contains(required_chirho),
            "selected v2 authority must retain Applied-receipt provenance check {required_chirho}"
        );
    }
    for forbidden_chirho in [
        "load_agent_authority_response_records_chirho(",
        "refs_chirho::load_reflog_chirho(",
    ] {
        assert!(
            !selected_chirho.contains(forbidden_chirho),
            "selected authority must not bypass verified history/receipt policy through {forbidden_chirho}"
        );
    }
}

#[test]
fn agent_authority_pending_recovery_is_scoped_per_agent_branch_chirho() {
    let text_chirho = production_file_chirho(AGENT_AUTHORITY_CHIRHO);
    let recovery_chirho = between_markers_chirho(
        &text_chirho,
        "fn recover_agent_authority_head_unlocked_chirho(",
        "fn prepared_from_verified_agent_authority_record_chirho(",
    );
    for required_chirho in [
        "record_chirho.agent_principal_chirho == agent_principal_chirho",
        "pending_head_transition_index_unlocked_chirho(",
        "complete_head_transition_unlocked_chirho(",
    ] {
        assert!(
            recovery_chirho.contains(required_chirho),
            "agent-authority pending recovery must remain branch-local via {required_chirho}"
        );
    }
}

#[test]
fn agent_authority_policy_extraction_stays_pure_chirho() {
    let policy_chirho = production_file_chirho(AGENT_AUTHORITY_POLICY_CHIRHO);
    for forbidden_chirho in [
        "std::fs",
        "std::path",
        "PathBuf",
        "root_chirho",
        "store_chirho::",
        "refs_chirho::",
        "seqlog_chirho::",
        "sign_message_chirho(",
        "verify_with_pubkey_chirho(",
        "append_",
        "commit_head_chirho(",
    ] {
        assert!(
            !policy_chirho.contains(forbidden_chirho),
            "pure agent-authority policy must not own I/O or trust-boundary token {forbidden_chirho}"
        );
    }
    for required_chirho in [
        "decide_agent_action_from_verified_state_chirho(",
        "validate_response_matches_report_chirho(",
        "validate_response_record_matches_report_chirho(",
        "agent_authority_transition_operation_bytes_chirho(",
        "agent_authority_record_message_chirho(",
    ] {
        assert!(
            policy_chirho.contains(required_chirho),
            "pure agent-authority policy extraction must retain {required_chirho}"
        );
    }
}

#[test]
fn agent_authority_transition_identity_binds_every_operation_field_chirho() {
    let policy_chirho = production_file_chirho(AGENT_AUTHORITY_POLICY_CHIRHO);
    let operation_chirho = between_markers_chirho(
        &policy_chirho,
        "pub fn agent_authority_transition_operation_bytes_chirho(",
        "pub fn agent_authority_record_message_chirho(",
    );
    for required_chirho in [
        "admin_principal_chirho",
        "agent_principal_chirho",
        "report_seq_chirho",
        "report_chirho",
        "change_kind_chirho",
        "rule_id_chirho",
        "scope_chirho",
        "budget_token_chirho",
        "parameter_changes_chirho",
        "reason_chirho",
    ] {
        assert!(
            operation_chirho.contains(required_chirho),
            "agent-authority transition operation identity must bind {required_chirho}"
        );
    }
    for forbidden_chirho in [
        "transition_id_chirho",
        "prepared_writer_fence_epoch_chirho",
        "sig_chirho",
    ] {
        assert!(
            !operation_chirho.contains(forbidden_chirho),
            "transition operation identity must stay non-circular and exclude {forbidden_chirho}"
        );
    }
}
