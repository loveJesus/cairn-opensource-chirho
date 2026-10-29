// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/elected-control-chirho/workflow-chirho.md.

use super::*;
use crate::elected_control_prepare_chirho::PreparedControlInputsChirho;
use cairn_writer_head_chirho::{
    head_transition_authority_chirho::{
        dispatch_head_transition_chirho, HeadTransitionAuthorityPortChirho,
        HeadTransitionCommitScopeChirho,
    },
    head_transition_chirho::PreparedFenceHeadTransitionIdentityInputChirho,
    writer_head_chirho::observe_prepared_fence_lower_bound_chirho,
};

const INPUTS_CHIRHO: &[&str] = &[
    AGENT_AUTHORITY_RESPONSE_RECORDS_LOG_CHIRHO,
    "agent-reports-chirho.jsonl",
    "refs-chirho.json",
    "reflog-chirho.jsonl",
    "identities-chirho.jsonl",
];

struct PreparedResponseChirho {
    state_chirho: AgentAuthorityStateChirho,
    record_chirho: AgentAuthorityResponseRecordChirho,
    head_chirho: PreparedHeadTransitionChirho,
    inputs_chirho: PreparedControlInputsChirho,
}

pub fn apply_agent_authority_response_with_head_transition_authority_chirho(
    root_chirho: &Path,
    input_chirho: AgentAuthorityResponseInputChirho,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<AgentAuthorityResponseRecordChirho> {
    validate_response_input_chirho(&input_chirho)?;
    dispatch_head_transition_chirho(
        root_chirho,
        Some(authority_chirho),
        |fence_chirho| {
            apply_agent_authority_response_unlocked_chirho(root_chirho, &input_chirho, fence_chirho)
        },
        || prepare_response_chirho(root_chirho, &input_chirho),
        |prepared_chirho, scope_chirho| {
            commit_response_chirho(root_chirho, prepared_chirho, scope_chirho)
        },
    )
}

fn prepare_response_chirho(
    root_chirho: &Path,
    input_chirho: &AgentAuthorityResponseInputChirho,
) -> Result<PreparedResponseChirho> {
    let inputs_chirho = PreparedControlInputsChirho::capture_chirho(root_chirho, INPUTS_CHIRHO)?;
    let history_chirho = verified_agent_authority_history_chirho(root_chirho)?;
    for record_chirho in history_chirho
        .records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.agent_principal_chirho == input_chirho.agent_principal_chirho
                && record_chirho.schema_chirho == AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO
        })
    {
        let head_chirho =
            prepared_from_verified_agent_authority_record_chirho(root_chirho, record_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &head_chirho,
        )? {
            bail!("AgentAuthorityHeadSettlementRequiredChirho");
        }
    }
    let report_chirho = load_response_report_chirho(root_chirho, input_chirho)?;
    validate_response_matches_report_chirho(input_chirho, &report_chirho)?;
    let selected_chirho = selected_verified_agent_authority_state_chirho(
        root_chirho,
        &input_chirho.agent_principal_chirho,
        &history_chirho,
    )?;
    let previous_chirho = selected_chirho
        .as_ref()
        .map(|(hash_chirho, _state_chirho)| hash_chirho.clone());
    let seq_chirho = u64::try_from(history_chirho.records_chirho.len())?;
    let at_ms_chirho = now_ms_chirho();
    let state_chirho = derive_state_from_input_chirho(
        selected_chirho
            .as_ref()
            .map(|(_hash_chirho, state_chirho)| state_chirho),
        previous_chirho.clone(),
        input_chirho,
        seq_chirho,
        at_ms_chirho,
    )?;
    validate_agent_authority_state_chirho(&state_chirho)?;
    let group_chirho = writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?;
    let fence_chirho = observe_prepared_fence_lower_bound_chirho(root_chirho, &group_chirho)?;
    let mut record_chirho = response_record_chirho(
        input_chirho,
        seq_chirho,
        at_ms_chirho,
        previous_chirho,
        store_chirho::hash_object_chirho(&state_chirho)?,
        fence_chirho.epoch_chirho(),
    );
    let operation_chirho = agent_authority_transition_operation_bytes_chirho(&record_chirho)?;
    let branch_chirho = agent_authority_ref_chirho(&input_chirho.agent_principal_chirho)?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: AGENT_AUTHORITY_RESPONSE_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.old_state_chirho,
        next_chirho: &record_chirho.new_state_chirho,
        reason_chirho: AGENT_AUTHORITY_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_chirho,
        prepared_fence_chirho: &fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    record_chirho.transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_from_prepared_fence_chirho(
            &identity_chirho,
        )?;
    record_chirho.sig_chirho = signer_chirho::sign_with_existing_key_possession_chirho(
        root_chirho,
        &agent_authority_record_message_chirho(&record_chirho)?,
    )?
    .into_signature_hex_chirho();
    let operation_chirho = agent_authority_transition_operation_bytes_chirho(&record_chirho)?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        operation_bytes_chirho: &operation_chirho,
        ..identity_chirho
    };
    let head_chirho =
        head_transition_chirho::bind_caller_verified_head_transition_from_prepared_fence_chirho(
            &identity_chirho,
            &record_chirho.transition_id_chirho,
            &serde_json::to_vec(&record_chirho)?,
        )?;
    inputs_chirho.validate_chirho(root_chirho)?;
    Ok(PreparedResponseChirho {
        state_chirho,
        record_chirho,
        head_chirho,
        inputs_chirho,
    })
}

fn commit_response_chirho(
    root_chirho: &Path,
    prepared_chirho: PreparedResponseChirho,
    scope_chirho: HeadTransitionCommitScopeChirho<'_>,
) -> Result<AgentAuthorityResponseRecordChirho> {
    scope_chirho.preflight_head_transition_chirho(root_chirho, &prepared_chirho.head_chirho)?;
    let _lifecycle_chirho = prepared_chirho
        .inputs_chirho
        .hold_for_commit_chirho(root_chirho)?;
    store_chirho::put_object_chirho(root_chirho, &prepared_chirho.state_chirho)?;
    seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
        &agent_authority_records_path_chirho(root_chirho),
        prepared_chirho.record_chirho.seq_chirho,
        &prepared_chirho.record_chirho,
    )?;
    scope_chirho.complete_head_transition_chirho(root_chirho, &prepared_chirho.head_chirho)?;
    Ok(prepared_chirho.record_chirho)
}

pub fn recover_agent_authority_head_with_head_transition_authority_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    validate_principal_chirho("agent principal", agent_principal_chirho)?;
    dispatch_head_transition_chirho(
        root_chirho,
        Some(authority_chirho),
        |fence_chirho| {
            recover_agent_authority_head_unlocked_chirho(
                root_chirho,
                agent_principal_chirho,
                fence_chirho,
            )
        },
        || {
            let inputs_chirho =
                PreparedControlInputsChirho::capture_chirho(root_chirho, INPUTS_CHIRHO)?;
            let history_chirho = verified_agent_authority_history_chirho(root_chirho)?;
            let transitions_chirho = history_chirho
                .records_chirho
                .iter()
                .filter(|record_chirho| {
                    record_chirho.agent_principal_chirho == agent_principal_chirho
                        && record_chirho.schema_chirho
                            == AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO
                })
                .map(|record_chirho| {
                    prepared_from_verified_agent_authority_record_chirho(root_chirho, record_chirho)
                })
                .collect::<Result<Vec<_>>>()?;
            let group_chirho = writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?;
            let fence_chirho =
                observe_prepared_fence_lower_bound_chirho(root_chirho, &group_chirho)?;
            inputs_chirho.validate_chirho(root_chirho)?;
            Ok((inputs_chirho, transitions_chirho, fence_chirho))
        },
        |(inputs_chirho, transitions_chirho, fence_chirho), scope_chirho| {
            scope_chirho.preflight_prepared_fence_chirho(root_chirho, &fence_chirho)?;
            let _lifecycle_chirho = inputs_chirho.hold_for_commit_chirho(root_chirho)?;
            let current_chirho =
                current_agent_authority_hash_chirho(root_chirho, agent_principal_chirho)?;
            let index_chirho =
                head_transition_chirho::pending_head_transition_index_unlocked_chirho(
                    root_chirho,
                    &current_chirho,
                    &transitions_chirho,
                )?;
            let pending_chirho = index_chirho
                .and_then(|index_chirho| transitions_chirho.into_iter().nth(index_chirho));
            pending_chirho
                .map(|pending_chirho| {
                    scope_chirho.complete_head_transition_chirho(root_chirho, &pending_chirho)
                })
                .transpose()
        },
    )
}
