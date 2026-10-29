// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;

fn hash_chirho(byte_chirho: char) -> HashChirho {
    HashChirho(byte_chirho.to_string().repeat(64))
}

#[test]
fn input_and_record_derivation_remain_identical_chirho() {
    let input_chirho = AgentAuthorityResponseInputChirho {
        admin_principal_chirho: "owner/admin-chirho".to_string(),
        agent_principal_chirho: "agent/test-chirho".to_string(),
        report_seq_chirho: 4,
        report_chirho: hash_chirho('a'),
        change_kind_chirho: AgentAuthorityChangeKindChirho::GrantChirho,
        rule_id_chirho: "support-main-chirho".to_string(),
        scope_chirho: Some("support/*".to_string()),
        budget_token_chirho: Some(100),
        parameter_changes_chirho: [("mode-chirho".to_string(), "draft-chirho".to_string())]
            .into_iter()
            .collect(),
        reason_chirho: "Approve the bounded support surface".to_string(),
    };
    let record_chirho = AgentAuthorityResponseRecordChirho {
        schema_chirho: "agent-authority-response-record-v1-chirho".to_string(),
        seq_chirho: 2,
        admin_principal_chirho: input_chirho.admin_principal_chirho.clone(),
        agent_principal_chirho: input_chirho.agent_principal_chirho.clone(),
        report_seq_chirho: input_chirho.report_seq_chirho,
        report_chirho: input_chirho.report_chirho.clone(),
        change_kind_chirho: input_chirho.change_kind_chirho.clone(),
        rule_id_chirho: input_chirho.rule_id_chirho.clone(),
        scope_chirho: input_chirho.scope_chirho.clone(),
        budget_token_chirho: input_chirho.budget_token_chirho,
        parameter_changes_chirho: input_chirho.parameter_changes_chirho.clone(),
        reason_chirho: input_chirho.reason_chirho.clone(),
        old_state_chirho: None,
        new_state_chirho: hash_chirho('b'),
        at_ms_chirho: 7,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "fixture-signature-chirho".to_string(),
    };

    validate_response_input_chirho(&input_chirho).unwrap();
    validate_response_record_chirho(&record_chirho).unwrap();
    let from_input_chirho =
        derive_state_from_input_chirho(None, None, &input_chirho, 2, 7).unwrap();
    let from_record_chirho = derive_state_from_record_chirho(None, &record_chirho).unwrap();
    assert_eq!(from_input_chirho, from_record_chirho);
    validate_agent_authority_state_chirho(&from_input_chirho).unwrap();

    let original_operation_chirho =
        agent_authority_transition_operation_bytes_chirho(&record_chirho).unwrap();
    let mut changed_reason_chirho = record_chirho;
    changed_reason_chirho.reason_chirho = "A different bounded support reason".to_string();
    assert_ne!(
        agent_authority_transition_operation_bytes_chirho(&changed_reason_chirho).unwrap(),
        original_operation_chirho,
        "the transition operation identity must bind the admin-authored reason"
    );
}

#[test]
fn scope_matching_and_narrowing_policy_remain_bounded_chirho() {
    assert!(scope_matches_chirho("support/*", "support/issue/123"));
    assert!(scope_matches_chirho(
        "support/issue/123",
        "support/issue/123"
    ));
    assert!(!scope_matches_chirho(
        "support/issue/123",
        "support/issue/124"
    ));
    assert!(scope_is_narrower_chirho("support/*", "support/issue/123"));
    assert!(!scope_is_narrower_chirho("support/*", "support/*"));
}
