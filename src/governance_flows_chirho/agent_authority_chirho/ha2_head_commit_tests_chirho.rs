// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::tests_chirho::{
    report_for_agent_chirho, response_input_for_agent_chirho, temp_root_chirho, write_jsonl_chirho,
    ADMIN_CHIRHO, AGENT_CHIRHO, RULE_CHIRHO,
};
use super::*;
use crate::agent_report_chirho::{AgentReportCategoryChirho, AgentRequestedActionKindChirho};
use std::io::Write;

const OTHER_AGENT_CHIRHO: &str = "agent/other-chirho";

fn response_for_agent_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    kind_chirho: AgentAuthorityChangeKindChirho,
    requested_kind_chirho: AgentRequestedActionKindChirho,
    target_chirho: &str,
    scope_chirho: Option<&str>,
    budget_token_chirho: Option<u64>,
) -> AgentAuthorityResponseInputChirho {
    let report_chirho = report_for_agent_chirho(
        root_chirho,
        agent_principal_chirho,
        AgentReportCategoryChirho::DecisionalChirho,
        requested_kind_chirho,
        target_chirho,
    );
    response_input_for_agent_chirho(
        &report_chirho,
        agent_principal_chirho,
        kind_chirho,
        scope_chirho,
        budget_token_chirho,
        &[],
    )
}

fn grant_response_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    scope_chirho: &str,
    budget_token_chirho: u64,
) -> AgentAuthorityResponseInputChirho {
    response_for_agent_chirho(
        root_chirho,
        agent_principal_chirho,
        AgentAuthorityChangeKindChirho::GrantChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        scope_chirho,
        Some(scope_chirho),
        Some(budget_token_chirho),
    )
}

fn budget_response_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    budget_token_chirho: u64,
) -> AgentAuthorityResponseInputChirho {
    response_for_agent_chirho(
        root_chirho,
        agent_principal_chirho,
        AgentAuthorityChangeKindChirho::BudgetChangeChirho,
        AgentRequestedActionKindChirho::BudgetChangeChirho,
        RULE_CHIRHO,
        None,
        Some(budget_token_chirho),
    )
}

pub(super) fn append_pending_response_chirho(
    root_chirho: &Path,
    input_chirho: &AgentAuthorityResponseInputChirho,
) -> (
    AgentAuthorityResponseRecordChirho,
    PreparedHeadTransitionChirho,
    WriterFenceTokenChirho,
) {
    validate_response_input_chirho(input_chirho).unwrap();
    let mut output_chirho = None;
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        let (record_chirho, prepared_chirho) =
            append_prepared_agent_authority_response_unlocked_chirho(
                root_chirho,
                input_chirho,
                fence_chirho,
            )?;
        output_chirho = Some((record_chirho, prepared_chirho, fence_chirho.clone()));
        Ok(())
    })
    .unwrap();
    output_chirho.unwrap()
}

fn transition_receipts_chirho(root_chirho: &Path) -> Vec<refs_chirho::ReflogEntryChirho> {
    refs_chirho::reflog_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|entry_chirho| {
            entry_chirho.schema_chirho
                == head_transition_chirho::HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO
                && entry_chirho.family_log_chirho == AGENT_AUTHORITY_RESPONSE_RECORDS_LOG_CHIRHO
        })
        .collect()
}

fn resign_response_chirho(
    root_chirho: &Path,
    mut record_chirho: AgentAuthorityResponseRecordChirho,
) -> AgentAuthorityResponseRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &agent_authority_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

#[test]
fn v2_clean_apply_binds_transition_fields_and_receipt_chirho() {
    let root_chirho = temp_root_chirho("v2-clean");
    let record_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    )
    .unwrap();
    assert_eq!(
        record_chirho.schema_chirho,
        AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO
    );
    assert!(record_chirho
        .transition_id_chirho
        .starts_with(HEAD_TRANSITION_ID_PREFIX_CHIRHO));
    assert!(record_chirho.prepared_writer_fence_epoch_chirho.is_some());
    let history_chirho = verified_agent_authority_history_chirho(&root_chirho).unwrap();
    let prepared_chirho = prepared_from_verified_agent_authority_record_chirho(
        &root_chirho,
        &history_chirho.records_chirho[record_chirho.seq_chirho as usize],
    )
    .unwrap();
    assert!(
        head_transition_chirho::verified_head_transition_receipt_chirho(
            &root_chirho,
            &prepared_chirho,
        )
        .unwrap()
    );
    let receipts_chirho = transition_receipts_chirho(&root_chirho);
    assert_eq!(receipts_chirho.len(), 1);
    assert_eq!(
        receipts_chirho[0].prepared_writer_fence_epoch_chirho,
        record_chirho.prepared_writer_fence_epoch_chirho
    );
    assert_eq!(
        receipts_chirho[0].applied_writer_fence_epoch_chirho,
        record_chirho.prepared_writer_fence_epoch_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn selected_unreceipted_v2_state_denies_until_recovery_chirho() {
    let root_chirho = temp_root_chirho("unreceipted-deny");
    let (record_chirho, _prepared_chirho, _stale_fence_chirho) = append_pending_response_chirho(
        &root_chirho,
        &grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    );
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &agent_authority_ref_chirho(AGENT_CHIRHO).unwrap(),
        record_chirho.new_state_chirho.clone(),
    )
    .unwrap();

    assert!(
        !check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/unreceipted",
            1,
        )
        .unwrap()
        .authorized_chirho
    );
    assert!(verify_agent_authority_responses_chirho(&root_chirho).is_err());
    assert_eq!(
        recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::RepairedReflogChirho)
    );
    assert!(
        check_agent_action_authorized_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            "support/issue/receipted",
            1,
        )
        .unwrap()
        .authorized_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pending_v2_before_ref_recovers_with_later_epoch_chirho() {
    let root_chirho = temp_root_chirho("before-ref");
    let (record_chirho, _prepared_chirho, _stale_fence_chirho) = append_pending_response_chirho(
        &root_chirho,
        &grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    );
    assert_eq!(
        recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(record_chirho.new_state_chirho)
    );
    let receipts_chirho = transition_receipts_chirho(&root_chirho);
    assert_eq!(receipts_chirho.len(), 1);
    assert!(
        receipts_chirho[0]
            .applied_writer_fence_epoch_chirho
            .unwrap()
            > record_chirho.prepared_writer_fence_epoch_chirho.unwrap()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn torn_reflog_tail_recovers_one_valid_receipt_chirho() {
    let root_chirho = temp_root_chirho("torn-receipt");
    append_pending_response_chirho(
        &root_chirho,
        &grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    );
    let reflog_path_chirho = refs_chirho::reflog_path_chirho(&root_chirho);
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&reflog_path_chirho)
        .unwrap()
        .write_all(br#"{"schema_chirho":"head-transition-receipt-v1-chirho""#)
        .unwrap();
    assert_eq!(
        recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(transition_receipts_chirho(&root_chirho).len(), 1);
    assert_eq!(
        recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        None
    );
    assert_eq!(transition_receipts_chirho(&root_chirho).len(), 1);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn applied_receipt_prevents_rollback_resurrection_and_next_write_uses_rollback_head_chirho() {
    let root_chirho = temp_root_chirho("rollback-non-resurrection");
    let first_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    )
    .unwrap();
    let second_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        budget_response_chirho(&root_chirho, AGENT_CHIRHO, 80),
    )
    .unwrap();
    refs_chirho::rollback_chirho(
        &root_chirho,
        &agent_authority_ref_chirho(AGENT_CHIRHO).unwrap(),
        first_chirho.new_state_chirho.clone(),
    )
    .unwrap();
    let refs_before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();
    assert_eq!(
        recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        None
    );
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho
    );
    let history_chirho = verified_agent_authority_history_chirho(&root_chirho).unwrap();
    let settled_chirho = prepared_from_verified_agent_authority_record_chirho(
        &root_chirho,
        &history_chirho.records_chirho[second_chirho.seq_chirho as usize],
    )
    .unwrap();
    assert_eq!(
        writer_head_chirho::with_head_transition_scope_chirho(&root_chirho, |fence_chirho| {
            head_transition_chirho::complete_head_transition_unlocked_chirho(
                &root_chirho,
                &settled_chirho,
                fence_chirho,
            )
        },)
        .unwrap(),
        HeadTransitionRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho
    );
    let third_chirho = apply_agent_authority_response_chirho(
        &root_chirho,
        budget_response_chirho(&root_chirho, AGENT_CHIRHO, 60),
    )
    .unwrap();
    assert_eq!(
        third_chirho.old_state_chirho,
        Some(first_chirho.new_state_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn stale_preparer_cannot_complete_after_recovery_chirho() {
    let root_chirho = temp_root_chirho("zombie");
    let (_record_chirho, prepared_chirho, stale_fence_chirho) = append_pending_response_chirho(
        &root_chirho,
        &grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    );
    recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO).unwrap();
    let refs_before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();
    let reflog_before_chirho =
        std::fs::read(refs_chirho::reflog_path_chirho(&root_chirho)).unwrap();
    let error_chirho = seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            &root_chirho,
            &prepared_chirho,
            &stale_fence_chirho,
        )
    })
    .unwrap_err();
    assert!(format!("{error_chirho:#}").contains("StaleWriterFenceChirho"));
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho
    );
    assert_eq!(
        std::fs::read(refs_chirho::reflog_path_chirho(&root_chirho)).unwrap(),
        reflog_before_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn different_agent_pending_branches_recover_independently_chirho() {
    let root_chirho = temp_root_chirho("cross-branch");
    let (first_chirho, _first_prepared_chirho, _first_fence_chirho) =
        append_pending_response_chirho(
            &root_chirho,
            &grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
        );
    let (other_chirho, _other_prepared_chirho, _other_fence_chirho) =
        append_pending_response_chirho(
            &root_chirho,
            &grant_response_chirho(&root_chirho, OTHER_AGENT_CHIRHO, "support/*", 100),
        );
    assert_eq!(
        recover_agent_authority_head_chirho(&root_chirho, OTHER_AGENT_CHIRHO).unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, OTHER_AGENT_CHIRHO).unwrap(),
        Some(other_chirho.new_state_chirho)
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        None
    );
    assert_eq!(
        recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(first_chirho.new_state_chirho)
    );
    assert_eq!(transition_receipts_chirho(&root_chirho).len(), 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn same_agent_next_append_recovers_prior_prepared_parent_chirho() {
    let root_chirho = temp_root_chirho("recover-before-next");
    let (first_chirho, _prepared_chirho, _stale_fence_chirho) = append_pending_response_chirho(
        &root_chirho,
        &grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    );
    let second_input_chirho = budget_response_chirho(&root_chirho, AGENT_CHIRHO, 50);
    let (second_chirho, _second_prepared_chirho, _second_fence_chirho) =
        append_pending_response_chirho(&root_chirho, &second_input_chirho);
    assert_eq!(
        second_chirho.old_state_chirho,
        Some(first_chirho.new_state_chirho.clone())
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(first_chirho.new_state_chirho)
    );
    assert_eq!(transition_receipts_chirho(&root_chirho).len(), 1);
    assert_eq!(
        recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(transition_receipts_chirho(&root_chirho).len(), 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn v2_signature_binds_transition_id_and_prepared_epoch_chirho() {
    let root_chirho = temp_root_chirho("signed-v2");
    apply_agent_authority_response_chirho(
        &root_chirho,
        grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    )
    .unwrap();
    let original_chirho = load_agent_authority_response_records_chirho(&root_chirho).unwrap();
    let mut tampered_id_chirho = original_chirho.clone();
    tampered_id_chirho[0].transition_id_chirho =
        format!("{HEAD_TRANSITION_ID_PREFIX_CHIRHO}{}", "2".repeat(64));
    write_jsonl_chirho(
        &agent_authority_records_path_chirho(&root_chirho),
        &tampered_id_chirho,
    );
    assert!(verified_agent_authority_history_chirho(&root_chirho)
        .err()
        .unwrap()
        .to_string()
        .contains("signature invalid"));

    let mut tampered_epoch_chirho = original_chirho;
    tampered_epoch_chirho[0].prepared_writer_fence_epoch_chirho = Some(
        tampered_epoch_chirho[0]
            .prepared_writer_fence_epoch_chirho
            .unwrap()
            + 1,
    );
    write_jsonl_chirho(
        &agent_authority_records_path_chirho(&root_chirho),
        &tampered_epoch_chirho,
    );
    assert!(verified_agent_authority_history_chirho(&root_chirho)
        .err()
        .unwrap()
        .to_string()
        .contains("signature invalid"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn legacy_v1_message_bytes_stay_stable_and_never_prepare_chirho() {
    let record_chirho = AgentAuthorityResponseRecordChirho {
        schema_chirho: AGENT_AUTHORITY_RESPONSE_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 8,
        admin_principal_chirho: ADMIN_CHIRHO.to_string(),
        agent_principal_chirho: AGENT_CHIRHO.to_string(),
        report_seq_chirho: 7,
        report_chirho: HashChirho("b".repeat(64)),
        change_kind_chirho: AgentAuthorityChangeKindChirho::BudgetChangeChirho,
        rule_id_chirho: RULE_CHIRHO.to_string(),
        scope_chirho: None,
        budget_token_chirho: Some(55),
        parameter_changes_chirho: BTreeMap::new(),
        reason_chirho: "bounded legacy reason-chirho".to_string(),
        old_state_chirho: Some(HashChirho("a".repeat(64))),
        new_state_chirho: HashChirho("c".repeat(64)),
        at_ms_chirho: 999,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "legacy-signature-chirho".to_string(),
    };
    assert_eq!(
        String::from_utf8(agent_authority_record_message_chirho(&record_chirho).unwrap()).unwrap(),
        r#"{"schema_chirho":"agent-authority-response-record-v1-chirho","seq_chirho":8,"admin_principal_chirho":"owner/hallelujah-chirho","agent_principal_chirho":"agent/codex-chirho","report_seq_chirho":7,"report_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","change_kind_chirho":"BudgetChangeChirho","rule_id_chirho":"support-main-chirho","budget_token_chirho":55,"parameter_changes_chirho":{},"reason_chirho":"bounded legacy reason-chirho","old_state_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","new_state_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","at_ms_chirho":999,"sig_chirho":""}"#
    );
    let root_chirho = temp_root_chirho("legacy-never-prepare");
    assert!(
        prepared_from_verified_agent_authority_record_chirho(&root_chirho, &record_chirho)
            .err()
            .unwrap()
            .to_string()
            .contains("only verified agent authority v2")
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn resigned_transition_from_another_group_fails_before_ref_change_chirho() {
    let root_chirho = temp_root_chirho("wrong-group");
    append_pending_response_chirho(
        &root_chirho,
        &grant_response_chirho(&root_chirho, AGENT_CHIRHO, "support/*", 100),
    );
    let mut records_chirho = load_agent_authority_response_records_chirho(&root_chirho).unwrap();
    let wrong_fence_chirho = WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "wrong-group-chirho".to_string(),
        },
        epoch_chirho: records_chirho[0]
            .prepared_writer_fence_epoch_chirho
            .unwrap(),
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho =
        agent_authority_transition_operation_bytes_chirho(&records_chirho[0]).unwrap();
    let branch_chirho = agent_authority_ref_chirho(AGENT_CHIRHO).unwrap();
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: AGENT_AUTHORITY_RESPONSE_RECORDS_LOG_CHIRHO,
        family_seq_chirho: records_chirho[0].seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &records_chirho[0].old_state_chirho,
        next_chirho: &records_chirho[0].new_state_chirho,
        reason_chirho: AGENT_AUTHORITY_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &wrong_fence_chirho,
        at_ms_chirho: records_chirho[0].at_ms_chirho,
    };
    records_chirho[0].transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_chirho(&identity_chirho).unwrap();
    records_chirho[0] = resign_response_chirho(&root_chirho, records_chirho[0].clone());
    write_jsonl_chirho(
        &agent_authority_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    assert!(
        recover_agent_authority_head_chirho(&root_chirho, AGENT_CHIRHO)
            .unwrap_err()
            .to_string()
            .contains("transition id does not match")
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        None
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
