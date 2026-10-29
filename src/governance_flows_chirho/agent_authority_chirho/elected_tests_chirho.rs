// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::tests_chirho::{
    report_for_agent_chirho, response_input_for_agent_chirho, temp_root_chirho, AGENT_CHIRHO,
};
use super::*;
use crate::agent_report_chirho::{AgentReportCategoryChirho, AgentRequestedActionKindChirho};
use crate::elected_control_prepare_chirho::test_support_chirho::{
    rebind_root_chirho, rewrite_refs_chirho, snapshot_chirho, ControlAuthorityChirho,
};

fn fixture_chirho() -> (PathBuf, AgentAuthorityResponseInputChirho) {
    let root_chirho = temp_root_chirho("elected-control-chirho");
    let report_chirho = report_for_agent_chirho(
        &root_chirho,
        AGENT_CHIRHO,
        AgentReportCategoryChirho::DecisionalChirho,
        AgentRequestedActionKindChirho::GrantChirho,
        "support/*",
    );
    let input_chirho = response_input_for_agent_chirho(
        &report_chirho,
        AGENT_CHIRHO,
        AgentAuthorityChangeKindChirho::GrantChirho,
        Some("support/*"),
        Some(100),
        &[],
    );
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "test-fixture-chirho",
        report_chirho.report_chirho.clone(),
    )
    .unwrap();
    (root_chirho, input_chirho)
}

fn setup_chirho() -> (
    PathBuf,
    AgentAuthorityResponseInputChirho,
    ControlAuthorityChirho,
) {
    let (root_chirho, input_chirho) = fixture_chirho();
    let authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
    (root_chirho, input_chirho, authority_chirho)
}

#[test]
fn elected_control_agent_response_commits_verified_state_and_receipt_chirho() {
    let (root_chirho, input_chirho, authority_chirho) = setup_chirho();
    let record_chirho = apply_agent_authority_response_with_head_transition_authority_chirho(
        &root_chirho,
        input_chirho,
        &authority_chirho,
    )
    .unwrap();
    assert!(authority_chirho.called_chirho.get());
    let history_chirho = verified_agent_authority_history_chirho(&root_chirho).unwrap();
    assert_eq!(history_chirho.records_chirho.len(), 1);
    assert_eq!(history_chirho.records_chirho[0], record_chirho);
    let prepared_chirho =
        prepared_from_verified_agent_authority_record_chirho(&root_chirho, &record_chirho).unwrap();
    assert!(
        head_transition_chirho::verified_head_transition_receipt_chirho(
            &root_chirho,
            &prepared_chirho
        )
        .unwrap()
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(record_chirho.new_state_chirho)
    );
    assert!(
        recover_agent_authority_head_with_head_transition_authority_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            &authority_chirho
        )
        .unwrap()
        .is_none()
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_recovers_pending_record_once_chirho() {
    let (root_chirho, input_chirho) = fixture_chirho();
    let (record_chirho, prepared_chirho, _fence_chirho) =
        super::ha2_head_commit_tests_chirho::append_pending_response_chirho(
            &root_chirho,
            &input_chirho,
        );
    let mut authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
    authority_chirho.refuse_chirho = true;
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = recover_agent_authority_head_with_head_transition_authority_chirho(
        &root_chirho,
        AGENT_CHIRHO,
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(error_chirho.to_string(), "ElectedAuthorityDeposedChirho");
    assert!(snapshot_chirho(&root_chirho) == before_chirho);
    authority_chirho.refuse_chirho = false;
    assert_eq!(
        recover_agent_authority_head_with_head_transition_authority_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            &authority_chirho,
        )
        .unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho),
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(record_chirho.new_state_chirho.clone())
    );
    assert!(
        head_transition_chirho::verified_head_transition_receipt_chirho(
            &root_chirho,
            &prepared_chirho
        )
        .unwrap()
    );
    assert_eq!(
        verified_agent_authority_history_chirho(&root_chirho)
            .unwrap()
            .records_chirho,
        vec![record_chirho]
    );
    assert!(
        recover_agent_authority_head_with_head_transition_authority_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            &authority_chirho,
        )
        .unwrap()
        .is_none()
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_recovery_never_repairs_before_authority_chirho() {
    use std::io::Write;
    let (root_chirho, _input_chirho, mut authority_chirho) = setup_chirho();
    std::fs::OpenOptions::new()
        .append(true)
        .open(root_chirho.join("reflog-chirho.jsonl"))
        .unwrap()
        .write_all(b"{")
        .unwrap();
    authority_chirho.refuse_chirho = true;
    let before_chirho = snapshot_chirho(&root_chirho);
    assert!(
        recover_agent_authority_head_with_head_transition_authority_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            &authority_chirho,
        )
        .is_err()
    );
    assert!(
        snapshot_chirho(&root_chirho) == before_chirho,
        "PREPARE repaired a torn reflog before authority"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_recovery_repairs_torn_receipt_after_authority_chirho() {
    use std::io::Write;
    let (root_chirho, input_chirho) = fixture_chirho();
    let (record_chirho, prepared_chirho, _fence_chirho) =
        super::ha2_head_commit_tests_chirho::append_pending_response_chirho(
            &root_chirho,
            &input_chirho,
        );
    let mut authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
    std::fs::OpenOptions::new()
        .append(true)
        .open(root_chirho.join("reflog-chirho.jsonl"))
        .unwrap()
        .write_all(b"{")
        .unwrap();
    authority_chirho.refuse_chirho = true;
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = recover_agent_authority_head_with_head_transition_authority_chirho(
        &root_chirho,
        AGENT_CHIRHO,
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(error_chirho.to_string(), "ElectedAuthorityDeposedChirho");
    assert!(snapshot_chirho(&root_chirho) == before_chirho);
    authority_chirho.refuse_chirho = false;
    assert_eq!(
        recover_agent_authority_head_with_head_transition_authority_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            &authority_chirho,
        )
        .unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(record_chirho.new_state_chirho)
    );
    assert!(
        head_transition_chirho::verified_head_transition_receipt_chirho(
            &root_chirho,
            &prepared_chirho
        )
        .unwrap()
    );
    assert!(
        recover_agent_authority_head_with_head_transition_authority_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            &authority_chirho,
        )
        .unwrap()
        .is_none()
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_recovery_binds_root_even_without_pending_chirho() {
    for pending_chirho in [false, true] {
        let (root_chirho, input_chirho) = fixture_chirho();
        if pending_chirho {
            super::ha2_head_commit_tests_chirho::append_pending_response_chirho(
                &root_chirho,
                &input_chirho,
            );
        }
        let mut authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
        authority_chirho.before_chirho = Some(rebind_root_chirho);
        let before_chirho = snapshot_chirho(&root_chirho);
        let error_chirho = recover_agent_authority_head_with_head_transition_authority_chirho(
            &root_chirho,
            AGENT_CHIRHO,
            &authority_chirho,
        )
        .unwrap_err();
        assert!(
            error_chirho
                .to_string()
                .contains("HeadTransitionWrongRootChirho"),
            "{error_chirho:#}"
        );
        assert!(snapshot_chirho(&root_chirho.with_extension("held-chirho")) == before_chirho);
        assert_eq!(
            std::fs::read(root_chirho.join("reflog-chirho.jsonl")).unwrap(),
            std::fs::read(
                root_chirho
                    .with_extension("held-chirho")
                    .join("reflog-chirho.jsonl")
            )
            .unwrap(),
        );
        std::fs::remove_dir_all(root_chirho.with_extension("held-chirho")).unwrap();
        std::fs::remove_dir_all(root_chirho).unwrap();
    }
}

#[test]
fn elected_control_agent_deposed_authority_writes_nothing_chirho() {
    let (root_chirho, input_chirho, mut authority_chirho) = setup_chirho();
    authority_chirho.refuse_chirho = true;
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = apply_agent_authority_response_with_head_transition_authority_chirho(
        &root_chirho,
        input_chirho,
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(error_chirho.to_string(), "ElectedAuthorityDeposedChirho");
    assert!(
        snapshot_chirho(&root_chirho) == before_chirho,
        "refusal changed durable bytes"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_stale_inputs_refuse_before_object_or_record_chirho() {
    let (root_chirho, input_chirho, mut authority_chirho) = setup_chirho();
    authority_chirho.before_chirho = Some(rewrite_refs_chirho);
    let error_chirho = apply_agent_authority_response_with_head_transition_authority_chirho(
        &root_chirho,
        input_chirho,
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "ElectedControlPreparedStateChangedChirho"
    );
    assert!(verified_agent_authority_history_chirho(&root_chirho)
        .unwrap()
        .records_chirho
        .is_empty());
    assert!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO)
            .unwrap()
            .is_none()
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_wrong_report_never_calls_authority_chirho() {
    let (root_chirho, mut input_chirho, authority_chirho) = setup_chirho();
    input_chirho.report_chirho = HashChirho("f".repeat(64));
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = apply_agent_authority_response_with_head_transition_authority_chirho(
        &root_chirho,
        input_chirho,
        &authority_chirho,
    )
    .unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .starts_with("agent report seq 0 hash mismatch:"),
        "{error_chirho:#}"
    );
    assert!(!authority_chirho.called_chirho.get());
    assert!(
        snapshot_chirho(&root_chirho) == before_chirho,
        "report refusal changed durable bytes"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_legacy_door_still_refuses_elected_root_chirho() {
    let (root_chirho, input_chirho, _authority_chirho) = setup_chirho();
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho =
        apply_agent_authority_response_chirho(&root_chirho, input_chirho).unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "GeoWriterAuthorityAlreadyActiveChirho"
    );
    assert!(
        snapshot_chirho(&root_chirho) == before_chirho,
        "legacy door changed elected root"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_missing_signer_is_not_recreated_chirho() {
    let (root_chirho, input_chirho, authority_chirho) = setup_chirho();
    std::fs::remove_file(root_chirho.join("signing-key-chirho.bin")).unwrap();
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = apply_agent_authority_response_with_head_transition_authority_chirho(
        &root_chirho,
        input_chirho,
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "ElectedControlExistingSignerUnavailableChirho"
    );
    assert!(!authority_chirho.called_chirho.get());
    assert!(snapshot_chirho(&root_chirho) == before_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_root_rebinding_refuses_publication_chirho() {
    let (root_chirho, input_chirho, mut authority_chirho) = setup_chirho();
    authority_chirho.before_chirho = Some(rebind_root_chirho);
    let error_chirho = apply_agent_authority_response_with_head_transition_authority_chirho(
        &root_chirho,
        input_chirho,
        &authority_chirho,
    )
    .unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .contains("HeadTransitionWrongRootChirho"),
        "{error_chirho:#}"
    );
    assert!(!agent_authority_records_path_chirho(&root_chirho).exists());
    assert!(
        !agent_authority_records_path_chirho(&root_chirho.with_extension("held-chirho")).exists()
    );
    std::fs::remove_dir_all(root_chirho.with_extension("held-chirho")).unwrap();
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_agent_local_root_keeps_local_behavior_chirho() {
    let (root_chirho, input_chirho) = fixture_chirho();
    let authority_chirho = ControlAuthorityChirho::refusing_chirho(&root_chirho);
    let record_chirho = apply_agent_authority_response_with_head_transition_authority_chirho(
        &root_chirho,
        input_chirho,
        &authority_chirho,
    )
    .unwrap();
    assert!(!authority_chirho.called_chirho.get());
    assert_eq!(
        current_agent_authority_hash_chirho(&root_chirho, AGENT_CHIRHO).unwrap(),
        Some(record_chirho.new_state_chirho)
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}
