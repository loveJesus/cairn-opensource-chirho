// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::agent_report_chirho::{
    AgentReportCategoryChirho, AgentReportEvidenceKindChirho, AgentReportEvidenceRefChirho,
    AgentReportInputChirho, AgentReportPriorityChirho, AgentRequestedActionChirho,
    AgentRequestedActionKindChirho,
};
use crate::cas_chirho;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const AGENT_CHIRHO: &str = "agent/codex-chirho";
pub(super) const ADMIN_CHIRHO: &str = "owner/hallelujah-chirho";
pub(super) const RULE_CHIRHO: &str = "support-main-chirho";

pub(super) fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-agent-authority-test-{label_chirho}-{n_chirho}-{}",
        now_ms_chirho()
    ))
}

fn report_chirho(
    root_chirho: &Path,
    category_chirho: AgentReportCategoryChirho,
    kind_chirho: AgentRequestedActionKindChirho,
    target_chirho: &str,
) -> agent_report_chirho::AgentReportRecordChirho {
    report_for_agent_chirho(
        root_chirho,
        AGENT_CHIRHO,
        category_chirho,
        kind_chirho,
        target_chirho,
    )
}

pub(super) fn report_for_agent_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    category_chirho: AgentReportCategoryChirho,
    kind_chirho: AgentRequestedActionKindChirho,
    target_chirho: &str,
) -> agent_report_chirho::AgentReportRecordChirho {
    let evidence_chirho = cas_chirho::add_chirho(root_chirho, target_chirho.as_bytes()).unwrap();
    agent_report_chirho::grant_agent_report_budget_chirho(
        root_chirho,
        agent_report_chirho::AgentReportBudgetGrantInputChirho {
            agent_principal_chirho: agent_principal_chirho.to_string(),
            granted_by_chirho: ADMIN_CHIRHO.to_string(),
            amount_token_chirho: 16,
            reason_chirho: "Test authority report budget".to_string(),
        },
    )
    .unwrap();
    agent_report_chirho::emit_agent_report_chirho(
        root_chirho,
        AgentReportInputChirho {
            producer_principal_chirho: agent_principal_chirho.to_string(),
            category_chirho,
            priority_chirho: AgentReportPriorityChirho::HighChirho,
            happened_chirho: "Agent requested a bounded authority surface change".to_string(),
            affected_chirho: "Agent capability refs and future action checks".to_string(),
            why_matters_chirho: "The administrator response becomes enforceable runtime authority"
                .to_string(),
            evidence_refs_chirho: vec![AgentReportEvidenceRefChirho {
                kind_chirho: AgentReportEvidenceKindChirho::ObjectChirho,
                ref_chirho: evidence_chirho.0.clone(),
            }],
            related_run_ids_chirho: vec![evidence_chirho],
            related_effect_ids_chirho: vec!["effect-seq:32".to_string()],
            requested_action_chirho: Some(AgentRequestedActionChirho {
                kind_chirho,
                target_chirho: target_chirho.to_string(),
                reason_chirho: "Owner must decide this authority mutation".to_string(),
            }),
        },
    )
    .unwrap()
}

fn response_input_chirho(
    report_chirho: &agent_report_chirho::AgentReportRecordChirho,
    kind_chirho: AgentAuthorityChangeKindChirho,
    scope_chirho: Option<&str>,
    budget_token_chirho: Option<u64>,
    params_chirho: &[(&str, &str)],
) -> AgentAuthorityResponseInputChirho {
    response_input_for_agent_chirho(
        report_chirho,
        AGENT_CHIRHO,
        kind_chirho,
        scope_chirho,
        budget_token_chirho,
        params_chirho,
    )
}

pub(super) fn response_input_for_agent_chirho(
    report_chirho: &agent_report_chirho::AgentReportRecordChirho,
    agent_principal_chirho: &str,
    kind_chirho: AgentAuthorityChangeKindChirho,
    scope_chirho: Option<&str>,
    budget_token_chirho: Option<u64>,
    params_chirho: &[(&str, &str)],
) -> AgentAuthorityResponseInputChirho {
    AgentAuthorityResponseInputChirho {
        admin_principal_chirho: ADMIN_CHIRHO.to_string(),
        agent_principal_chirho: agent_principal_chirho.to_string(),
        report_seq_chirho: report_chirho.seq_chirho,
        report_chirho: report_chirho.report_chirho.clone(),
        change_kind_chirho: kind_chirho,
        rule_id_chirho: RULE_CHIRHO.to_string(),
        scope_chirho: scope_chirho.map(str::to_string),
        budget_token_chirho,
        parameter_changes_chirho: params_chirho
            .iter()
            .map(|(key_chirho, value_chirho)| (key_chirho.to_string(), value_chirho.to_string()))
            .collect(),
        reason_chirho: "Admin approved the requested authority change".to_string(),
    }
}

pub(super) fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, rows_chirho: &[T]) {
    let mut text_chirho = String::new();
    for row_chirho in rows_chirho {
        text_chirho.push_str(&serde_json::to_string(row_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

#[test]
fn unlogged_shape_valid_state_cannot_authorize_from_raw_ref_chirho() {
    let root_chirho = temp_root_chirho("unlogged-state");
    let forged_rule_chirho = AgentAuthorityRuleChirho {
        rule_id_chirho: RULE_CHIRHO.to_string(),
        scope_chirho: "support/*".to_string(),
        budget_token_chirho: Some(100),
        parameters_chirho: BTreeMap::new(),
        revoked_chirho: false,
        source_report_seq_chirho: 0,
        source_response_seq_chirho: 0,
        updated_at_ms_chirho: 1,
    };
    let forged_state_chirho = AgentAuthorityStateChirho {
        agent_principal_chirho: AGENT_CHIRHO.to_string(),
        rules_chirho: [(RULE_CHIRHO.to_string(), forged_rule_chirho)]
            .into_iter()
            .collect(),
        current_response_seq_chirho: Some(0),
        previous_state_chirho: None,
        updated_at_ms_chirho: 1,
    };
    validate_agent_authority_state_chirho(&forged_state_chirho).unwrap();
    let forged_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &forged_state_chirho).unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &agent_authority_ref_chirho(AGENT_CHIRHO).unwrap(),
        forged_hash_chirho,
    )
    .unwrap();

    assert!(
        !check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/forged",
            1,
        )
        .unwrap()
        .authorized_chirho,
        "a shape-valid state without verified signed response provenance must never authorize"
    );
    assert!(verify_agent_authority_responses_chirho(&root_chirho).is_err());

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn verified_state_for_one_agent_cannot_authorize_another_chirho() {
    const OTHER_AGENT_CHIRHO: &str = "agent/other-chirho";
    let root_chirho = temp_root_chirho("cross-agent-state");
    let grant_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    let grant_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &grant_report_chirho,
            AgentAuthorityChangeKindChirho::GrantChirho,
            Some("support/*"),
            Some(100),
            &[],
        ),
    )
    .unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &agent_authority_ref_chirho(OTHER_AGENT_CHIRHO).unwrap(),
        grant_chirho.new_state_chirho,
    )
    .unwrap();

    assert!(
        !check_agent_action_authorized_chirho(
            &root_chirho,
            OTHER_AGENT_CHIRHO,
            "support/issue/cross-agent",
            1,
        )
        .unwrap()
        .authorized_chirho
    );
    assert!(verify_agent_authority_responses_chirho(&root_chirho).is_err());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn rollback_selects_verified_authority_and_v2_branches_from_that_parent_chirho() {
    let root_chirho = temp_root_chirho("rollback-selection");
    let grant_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    let grant_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &grant_report_chirho,
            AgentAuthorityChangeKindChirho::GrantChirho,
            Some("support/*"),
            Some(100),
            &[],
        ),
    )
    .unwrap();
    let narrow_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::NarrowChirho,
        "support/issue/123/*",
    );
    apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &narrow_report_chirho,
            AgentAuthorityChangeKindChirho::NarrowChirho,
            Some("support/issue/123/*"),
            None,
            &[],
        ),
    )
    .unwrap();
    refs_chirho::rollback_chirho(
        &root_chirho,
        &agent_authority_ref_chirho(AGENT_CHIRHO).unwrap(),
        grant_chirho.new_state_chirho.clone(),
    )
    .unwrap();

    assert_eq!(
        verify_agent_authority_responses_chirho(&root_chirho).unwrap(),
        2
    );
    assert!(
        check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/outside-narrowed-branch",
            1,
        )
        .unwrap()
        .authorized_chirho
    );

    let change_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::BudgetChangeChirho,
        RULE_CHIRHO,
    );
    let branch_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &change_report_chirho,
            AgentAuthorityChangeKindChirho::BudgetChangeChirho,
            None,
            Some(50),
            &[],
        ),
    )
    .unwrap();
    assert_eq!(
        branch_chirho.old_state_chirho,
        Some(grant_chirho.new_state_chirho)
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(branch_chirho.new_state_chirho)
    );
    assert_eq!(
        load_agent_authority_response_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        3
    );
    assert!(
        check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/after-rollback",
            50,
        )
        .unwrap()
        .authorized_chirho
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn decisional_response_moves_ref_and_refuses_out_of_scope_chirho() {
    let root_chirho = temp_root_chirho("grant-narrow");
    let grant_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    let grant_record_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &grant_report_chirho,
            AgentAuthorityChangeKindChirho::GrantChirho,
            Some("support/*"),
            Some(100),
            &[("mode_chirho", "draft-chirho")],
        ),
    )
    .unwrap();
    assert_eq!(grant_record_chirho.old_state_chirho, None);

    assert!(
        check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/123/reply",
            7,
        )
        .unwrap()
        .authorized_chirho
    );
    assert!(
        !check_agent_action_authorized_chirho(&root_chirho, AGENT_CHIRHO, "billing/refund", 1,)
            .unwrap()
            .authorized_chirho
    );

    let narrow_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::NarrowChirho,
        "support/issue/123/*",
    );
    apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &narrow_report_chirho,
            AgentAuthorityChangeKindChirho::NarrowChirho,
            Some("support/issue/123/*"),
            None,
            &[],
        ),
    )
    .unwrap();

    assert!(
        check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/123/reply",
            7,
        )
        .unwrap()
        .authorized_chirho
    );
    assert!(
        !check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/999/reply",
            7,
        )
        .unwrap()
        .authorized_chirho
    );
    assert_eq!(
        verify_agent_authority_responses_chirho(&root_chirho).unwrap(),
        2
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn budget_parameter_and_revoke_changes_are_enforced_chirho() {
    let root_chirho = temp_root_chirho("budget-revoke");
    let grant_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &grant_report_chirho,
            AgentAuthorityChangeKindChirho::GrantChirho,
            Some("support/*"),
            Some(5),
            &[("mode_chirho", "draft-chirho")],
        ),
    )
    .unwrap();
    assert!(
        !check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/123/reply",
            6,
        )
        .unwrap()
        .authorized_chirho
    );

    let budget_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::BudgetChangeChirho,
        RULE_CHIRHO,
    );
    apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &budget_report_chirho,
            AgentAuthorityChangeKindChirho::BudgetChangeChirho,
            None,
            Some(9),
            &[],
        ),
    )
    .unwrap();
    assert!(
        check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/123/reply",
            6,
        )
        .unwrap()
        .authorized_chirho
    );

    let param_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::ParameterChangeChirho,
        RULE_CHIRHO,
    );
    apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &param_report_chirho,
            AgentAuthorityChangeKindChirho::ParameterChangeChirho,
            None,
            None,
            &[("mode_chirho", "live-chirho")],
        ),
    )
    .unwrap();
    let (_state_hash_chirho, state_chirho) =
        current_agent_authority_state_chirho(&root_chirho, AGENT_CHIRHO)
            .unwrap()
            .unwrap();
    assert_eq!(
        state_chirho.rules_chirho[RULE_CHIRHO].parameters_chirho["mode_chirho"],
        "live-chirho"
    );

    let revoke_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::RevokeChirho,
        RULE_CHIRHO,
    );
    apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &revoke_report_chirho,
            AgentAuthorityChangeKindChirho::RevokeChirho,
            None,
            None,
            &[],
        ),
    )
    .unwrap();
    assert!(
        !check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/123/reply",
            1,
        )
        .unwrap()
        .authorized_chirho
    );
    assert_eq!(
        verify_agent_authority_responses_chirho(&root_chirho).unwrap(),
        4
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn agent_authority_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
    let root_chirho = temp_root_chirho("schema");
    let grant_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    let record_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &grant_report_chirho,
            AgentAuthorityChangeKindChirho::GrantChirho,
            Some("support/*"),
            None,
            &[],
        ),
    )
    .unwrap();
    assert_eq!(
        record_chirho.schema_chirho,
        AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO
    );
    assert_eq!(
        verify_agent_authority_responses_chirho(&root_chirho).unwrap(),
        1
    );

    let mut records_chirho = load_agent_authority_response_records_chirho(&root_chirho).unwrap();
    records_chirho[0].schema_chirho = "agent-authority-response-record-v9-chirho".to_string();
    write_jsonl_chirho(
        &agent_authority_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let error_chirho = verify_agent_authority_responses_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported agent authority response record schema"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_agent_authority_records_without_schema_still_verify_chirho() {
    let root_chirho = temp_root_chirho("legacy-schema");
    let grant_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &grant_report_chirho,
            AgentAuthorityChangeKindChirho::GrantChirho,
            Some("support/*"),
            Some(100),
            &[],
        ),
    )
    .unwrap();
    let mut records_chirho = load_agent_authority_response_records_chirho(&root_chirho).unwrap();
    records_chirho[0].schema_chirho.clear();
    records_chirho[0].transition_id_chirho.clear();
    records_chirho[0].prepared_writer_fence_epoch_chirho = None;
    records_chirho[0].sig_chirho.clear();
    records_chirho[0].sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &agent_authority_record_message_chirho(&records_chirho[0]).unwrap(),
    )
    .unwrap();
    write_jsonl_chirho(
        &agent_authority_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let text_chirho =
        std::fs::read_to_string(agent_authority_records_path_chirho(&root_chirho)).unwrap();
    assert!(!text_chirho.contains("schema_chirho"));
    assert!(!text_chirho.contains("transition_id_chirho"));
    assert!(!text_chirho.contains("prepared_writer_fence_epoch_chirho"));
    assert_eq!(
        verify_agent_authority_responses_chirho(&root_chirho).unwrap(),
        1
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn informational_report_cannot_mutate_authority_chirho() {
    let root_chirho = temp_root_chirho("informational");
    let info_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::InformationalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    assert!(apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &info_report_chirho,
            AgentAuthorityChangeKindChirho::GrantChirho,
            Some("support/*"),
            None,
            &[],
        ),
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn tampered_authority_log_is_rejected_chirho() {
    let root_chirho = temp_root_chirho("tamper");
    let grant_report_chirho = report_chirho(
        &root_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    apply_agent_authority_response_chirho(
        &root_chirho,
        response_input_chirho(
            &grant_report_chirho,
            AgentAuthorityChangeKindChirho::GrantChirho,
            Some("support/*"),
            None,
            &[],
        ),
    )
    .unwrap();
    let path_chirho = agent_authority_records_path_chirho(&root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    std::fs::write(
        &path_chirho,
        text_chirho.replace("owner/hallelujah-chirho", "owner/forged-chirho"),
    )
    .unwrap();
    assert!(verify_agent_authority_responses_chirho(&root_chirho).is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}
