// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Turns signed admin responses to decisional agent reports into current agent authority refs.

mod elected_chirho;
#[cfg(test)]
mod elected_tests_chirho;
pub use elected_chirho::{
    apply_agent_authority_response_with_head_transition_authority_chirho,
    recover_agent_authority_head_with_head_transition_authority_chirho,
};

pub use crate::agent_authority_model_chirho::policy_chirho::{
    agent_authority_change_kind_label_chirho, parse_agent_authority_change_kind_chirho,
    parse_agent_authority_param_chirho,
};
use crate::agent_authority_model_chirho::policy_chirho::{
    agent_authority_denial_chirho, agent_authority_record_message_chirho,
    agent_authority_transition_operation_bytes_chirho,
    decide_agent_action_from_verified_state_chirho, derive_state_from_input_chirho,
    derive_state_from_record_chirho, validate_agent_authority_state_chirho,
    validate_principal_chirho, validate_response_input_chirho,
    validate_response_matches_report_chirho, validate_response_record_chirho,
    validate_response_record_matches_report_chirho, validate_scope_chirho,
};
pub use crate::agent_authority_model_chirho::{
    AgentAuthorityChangeKindChirho, AgentAuthorityDecisionChirho,
    AgentAuthorityResponseInputChirho, AgentAuthorityResponseRecordChirho,
    AgentAuthorityRuleChirho, AgentAuthorityStateChirho,
    AGENT_AUTHORITY_RESPONSE_RECORD_SCHEMA_CHIRHO,
    AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO,
};
use crate::agent_report_chirho;
use crate::model_chirho::HashChirho;
use crate::{refs_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::{
    head_transition_chirho::{
        self as head_transition_chirho, HeadTransitionIdentityInputChirho,
        HeadTransitionRecoveryOutcomeChirho, PreparedHeadTransitionChirho,
        HEAD_TRANSITION_ID_PREFIX_CHIRHO,
    },
    writer_head_chirho::{self as writer_head_chirho, WriterFenceTokenChirho},
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const AGENT_AUTHORITY_RESPONSE_RECORDS_LOG_CHIRHO: &str = "agent-authority-responses-chirho.jsonl";
const AGENT_AUTHORITY_HEAD_REASON_CHIRHO: &str = "agent-authority-response";

struct VerifiedAgentAuthorityHistoryChirho {
    records_chirho: Vec<AgentAuthorityResponseRecordChirho>,
    states_by_agent_chirho: BTreeMap<String, BTreeMap<HashChirho, AgentAuthorityStateChirho>>,
    record_index_by_agent_state_chirho: BTreeMap<String, BTreeMap<HashChirho, usize>>,
}

pub fn apply_agent_authority_response_chirho(
    root_chirho: &Path,
    input_chirho: AgentAuthorityResponseInputChirho,
) -> Result<AgentAuthorityResponseRecordChirho> {
    validate_response_input_chirho(&input_chirho)?;
    // Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/
    // cairn-engine-definition-of-done-chirho.md
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        apply_agent_authority_response_unlocked_chirho(root_chirho, &input_chirho, fence_chirho)
    })
}

fn apply_agent_authority_response_unlocked_chirho(
    root_chirho: &Path,
    input_chirho: &AgentAuthorityResponseInputChirho,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<AgentAuthorityResponseRecordChirho> {
    let (record_chirho, prepared_chirho) =
        append_prepared_agent_authority_response_unlocked_chirho(
            root_chirho,
            input_chirho,
            fence_chirho,
        )?;
    head_transition_chirho::complete_head_transition_unlocked_chirho(
        root_chirho,
        &prepared_chirho,
        fence_chirho,
    )?;
    Ok(record_chirho)
}

fn append_prepared_agent_authority_response_unlocked_chirho(
    root_chirho: &Path,
    input_chirho: &AgentAuthorityResponseInputChirho,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<(
    AgentAuthorityResponseRecordChirho,
    PreparedHeadTransitionChirho,
)> {
    agent_report_chirho::verify_agent_report_records_chirho(root_chirho)?;
    recover_agent_authority_head_unlocked_chirho(
        root_chirho,
        &input_chirho.agent_principal_chirho,
        fence_chirho,
    )?;
    let report_chirho = load_response_report_chirho(root_chirho, input_chirho)?;
    validate_response_matches_report_chirho(input_chirho, &report_chirho)?;

    let verified_history_chirho = verified_agent_authority_history_chirho(root_chirho)?;
    let selected_chirho = selected_verified_agent_authority_state_chirho(
        root_chirho,
        &input_chirho.agent_principal_chirho,
        &verified_history_chirho,
    )?;
    let old_state_hash_chirho = selected_chirho
        .as_ref()
        .map(|(hash_chirho, _state_chirho)| hash_chirho.clone());
    let old_state_chirho = selected_chirho
        .as_ref()
        .map(|(_hash_chirho, state_chirho)| state_chirho);
    let path_chirho = agent_authority_records_path_chirho(root_chirho);
    let seq_chirho = u64::try_from(verified_history_chirho.records_chirho.len())
        .context("agent authority response count does not fit u64")?;
    let at_ms_chirho = now_ms_chirho();
    let new_state_chirho = derive_state_from_input_chirho(
        old_state_chirho,
        old_state_hash_chirho.clone(),
        input_chirho,
        seq_chirho,
        at_ms_chirho,
    )?;
    validate_agent_authority_state_chirho(&new_state_chirho)?;
    let new_state_hash_chirho = store_chirho::put_object_chirho(root_chirho, &new_state_chirho)?;
    let mut record_chirho = response_record_chirho(
        input_chirho,
        seq_chirho,
        at_ms_chirho,
        old_state_hash_chirho,
        new_state_hash_chirho,
        fence_chirho.epoch_chirho,
    );
    let operation_bytes_chirho = agent_authority_transition_operation_bytes_chirho(&record_chirho)?;
    let branch_chirho = agent_authority_ref_chirho(&record_chirho.agent_principal_chirho)?;
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: AGENT_AUTHORITY_RESPONSE_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.old_state_chirho,
        next_chirho: &record_chirho.new_state_chirho,
        reason_chirho: AGENT_AUTHORITY_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    record_chirho.transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_chirho(&identity_chirho)?;
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &agent_authority_record_message_chirho(&record_chirho)?,
    )?;
    seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
        &path_chirho,
        record_chirho.seq_chirho,
        &record_chirho,
    )?;
    let verified_records_chirho = verified_agent_authority_history_chirho(root_chirho)?;
    let verified_index_chirho = usize::try_from(record_chirho.seq_chirho)
        .context("new agent authority sequence does not fit usize")?;
    let verified_record_chirho = verified_records_chirho
        .records_chirho
        .get(verified_index_chirho)
        .filter(|verified_chirho| *verified_chirho == &record_chirho)
        .ok_or_else(|| {
            anyhow!("new agent authority response did not verify at its signed sequence")
        })?;
    let prepared_chirho =
        prepared_from_verified_agent_authority_record_chirho(root_chirho, verified_record_chirho)?;
    Ok((record_chirho, prepared_chirho))
}

fn response_record_chirho(
    input_chirho: &AgentAuthorityResponseInputChirho,
    seq_chirho: u64,
    at_ms_chirho: u64,
    old_state_chirho: Option<HashChirho>,
    new_state_chirho: HashChirho,
    epoch_chirho: u64,
) -> AgentAuthorityResponseRecordChirho {
    AgentAuthorityResponseRecordChirho {
        schema_chirho: AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
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
        old_state_chirho,
        new_state_chirho,
        at_ms_chirho,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: Some(epoch_chirho),
        sig_chirho: String::new(),
    }
}

/// Recover one fully verified v2 response transition for an agent branch, if one is pending.
pub fn recover_agent_authority_head_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    validate_principal_chirho("agent principal", agent_principal_chirho)?;
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        recover_agent_authority_head_unlocked_chirho(
            root_chirho,
            agent_principal_chirho,
            fence_chirho,
        )
    })
}

fn recover_agent_authority_head_unlocked_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    seqlog_chirho::recover_jsonl_len_unlocked_chirho(&agent_authority_records_path_chirho(
        root_chirho,
    ))?;
    let history_chirho = verified_agent_authority_history_chirho(root_chirho)?;
    let prepared_chirho = history_chirho
        .records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.agent_principal_chirho == agent_principal_chirho
                && record_chirho.schema_chirho == AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO
        })
        .map(|record_chirho| {
            prepared_from_verified_agent_authority_record_chirho(root_chirho, record_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    let current_head_chirho =
        current_agent_authority_hash_chirho(root_chirho, agent_principal_chirho)?;
    let Some(pending_index_chirho) =
        head_transition_chirho::pending_head_transition_index_unlocked_chirho(
            root_chirho,
            &current_head_chirho,
            &prepared_chirho,
        )?
    else {
        return Ok(None);
    };
    Ok(Some(
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            root_chirho,
            &prepared_chirho[pending_index_chirho],
            applier_fence_chirho,
        )?,
    ))
}

fn prepared_from_verified_agent_authority_record_chirho(
    root_chirho: &Path,
    record_chirho: &AgentAuthorityResponseRecordChirho,
) -> Result<PreparedHeadTransitionChirho> {
    if record_chirho.schema_chirho != AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO {
        bail!("only verified agent authority v2 rows can become prepared head transitions");
    }
    let prepared_epoch_chirho = record_chirho
        .prepared_writer_fence_epoch_chirho
        .ok_or_else(|| anyhow!("verified agent authority v2 row is missing its prepared epoch"))?;
    let prepared_fence_chirho = WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?,
        epoch_chirho: prepared_epoch_chirho,
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho = agent_authority_transition_operation_bytes_chirho(record_chirho)?;
    let branch_chirho = agent_authority_ref_chirho(&record_chirho.agent_principal_chirho)?;
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: AGENT_AUTHORITY_RESPONSE_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.old_state_chirho,
        next_chirho: &record_chirho.new_state_chirho,
        reason_chirho: AGENT_AUTHORITY_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    head_transition_chirho::bind_caller_verified_head_transition_chirho(
        &identity_chirho,
        &record_chirho.transition_id_chirho,
        &serde_json::to_vec(record_chirho)?,
    )
}

pub fn load_agent_authority_response_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AgentAuthorityResponseRecordChirho>> {
    let path_chirho = agent_authority_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(records_chirho)
}

pub fn load_agent_authority_state_chirho(
    root_chirho: &Path,
    state_chirho: &HashChirho,
) -> Result<AgentAuthorityStateChirho> {
    store_chirho::get_object_chirho(root_chirho, state_chirho)
}

/// Raw display loader. Permission decisions must use the verified-current history resolver.
pub fn current_agent_authority_state_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
) -> Result<Option<(HashChirho, AgentAuthorityStateChirho)>> {
    validate_principal_chirho("agent principal", agent_principal_chirho)?;
    let Some(hash_chirho) =
        current_agent_authority_hash_chirho(root_chirho, agent_principal_chirho)?
    else {
        return Ok(None);
    };
    let state_chirho = load_agent_authority_state_chirho(root_chirho, &hash_chirho)?;
    Ok(Some((hash_chirho, state_chirho)))
}

fn selected_verified_agent_authority_state_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    history_chirho: &VerifiedAgentAuthorityHistoryChirho,
) -> Result<Option<(HashChirho, AgentAuthorityStateChirho)>> {
    validate_principal_chirho("agent principal", agent_principal_chirho)?;
    let Some(hash_chirho) =
        current_agent_authority_hash_chirho(root_chirho, agent_principal_chirho)?
    else {
        return Ok(None);
    };
    let states_chirho = history_chirho
        .states_by_agent_chirho
        .get(agent_principal_chirho)
        .ok_or_else(|| {
            anyhow!("current agent authority ref is not backed by verified signed response history")
        })?;
    let state_chirho = states_chirho.get(&hash_chirho).cloned().ok_or_else(|| {
        anyhow!("current agent authority ref is not backed by verified signed response history")
    })?;
    let record_index_chirho = history_chirho
        .record_index_by_agent_state_chirho
        .get(agent_principal_chirho)
        .and_then(|indexes_chirho| indexes_chirho.get(&hash_chirho))
        .copied()
        .ok_or_else(|| anyhow!("current agent authority state has no verified response record"))?;
    let record_chirho = history_chirho
        .records_chirho
        .get(record_index_chirho)
        .ok_or_else(|| anyhow!("current agent authority response index is missing"))?;
    if record_chirho.schema_chirho == AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO {
        let prepared_chirho =
            prepared_from_verified_agent_authority_record_chirho(root_chirho, record_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("current agent authority v2 state has no verified Applied receipt");
        }
    }
    Ok(Some((hash_chirho, state_chirho)))
}

/// Returns `None` only when this agent has no verified authority history and no selected ref.
pub fn check_configured_agent_action_authorized_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    action_scope_chirho: &str,
    cost_token_chirho: u64,
) -> Result<Option<AgentAuthorityDecisionChirho>> {
    validate_principal_chirho("agent principal", agent_principal_chirho)?;
    validate_scope_chirho(action_scope_chirho)?;
    let history_chirho = match verified_agent_authority_history_chirho(root_chirho) {
        Ok(history_chirho) => history_chirho,
        Err(_error_chirho) => {
            return Ok(Some(agent_authority_denial_chirho(
                agent_principal_chirho,
                action_scope_chirho,
                "current agent authority provenance is not verified",
            )));
        }
    };
    let configured_chirho = history_chirho
        .states_by_agent_chirho
        .contains_key(agent_principal_chirho);
    let selected_chirho = match selected_verified_agent_authority_state_chirho(
        root_chirho,
        agent_principal_chirho,
        &history_chirho,
    ) {
        Ok(selected_chirho) => selected_chirho,
        Err(_error_chirho) => {
            return Ok(Some(agent_authority_denial_chirho(
                agent_principal_chirho,
                action_scope_chirho,
                "current agent authority provenance is not verified",
            )));
        }
    };
    let Some((_state_hash_chirho, state_chirho)) = selected_chirho else {
        return if configured_chirho {
            Ok(Some(agent_authority_denial_chirho(
                agent_principal_chirho,
                action_scope_chirho,
                "current agent authority provenance is not verified",
            )))
        } else {
            Ok(None)
        };
    };
    Ok(Some(decide_agent_action_from_verified_state_chirho(
        &state_chirho,
        agent_principal_chirho,
        action_scope_chirho,
        cost_token_chirho,
    )))
}

pub fn check_agent_action_authorized_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
    action_scope_chirho: &str,
    cost_token_chirho: u64,
) -> Result<AgentAuthorityDecisionChirho> {
    Ok(check_configured_agent_action_authorized_chirho(
        root_chirho,
        agent_principal_chirho,
        action_scope_chirho,
        cost_token_chirho,
    )?
    .unwrap_or_else(|| {
        agent_authority_denial_chirho(
            agent_principal_chirho,
            action_scope_chirho,
            "no current agent authority ref",
        )
    }))
}

fn verified_agent_authority_history_chirho(
    root_chirho: &Path,
) -> Result<VerifiedAgentAuthorityHistoryChirho> {
    agent_report_chirho::verify_agent_report_records_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let report_records_chirho = agent_report_chirho::load_agent_report_records_chirho(root_chirho)?;
    let records_chirho = load_agent_authority_response_records_chirho(root_chirho)?;
    let mut states_by_agent_chirho =
        BTreeMap::<String, BTreeMap<HashChirho, AgentAuthorityStateChirho>>::new();
    let mut record_index_by_agent_state_chirho =
        BTreeMap::<String, BTreeMap<HashChirho, usize>>::new();
    let mut latest_by_agent_chirho = BTreeMap::<String, HashChirho>::new();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "agent authority response seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        verify_agent_authority_record_schema_chirho(record_chirho)?;
        validate_response_record_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &agent_authority_record_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "agent authority response {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        let report_chirho =
            load_record_report_chirho(root_chirho, &report_records_chirho, record_chirho)?;
        validate_response_record_matches_report_chirho(record_chirho, &report_chirho)?;
        let expected_old_chirho = latest_by_agent_chirho
            .get(&record_chirho.agent_principal_chirho)
            .cloned();
        let is_v2_chirho =
            record_chirho.schema_chirho == AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO;
        let prior_states_chirho = states_by_agent_chirho
            .get(&record_chirho.agent_principal_chirho)
            .filter(|states_chirho| !states_chirho.is_empty());
        if !is_v2_chirho && record_chirho.old_state_chirho != expected_old_chirho {
            bail!(
                "agent authority v1 response {} old state does not match replayed head",
                record_chirho.seq_chirho
            );
        }
        if is_v2_chirho {
            match (&record_chirho.old_state_chirho, prior_states_chirho) {
                (None, None) => {}
                (Some(old_state_chirho), Some(states_chirho))
                    if states_chirho.contains_key(old_state_chirho) => {}
                (None, Some(_states_chirho)) => bail!(
                    "agent authority v2 response {} may use no parent only at genesis",
                    record_chirho.seq_chirho
                ),
                (Some(_old_state_chirho), _) => bail!(
                    "agent authority v2 response {} parent is not prior verified same-agent history",
                    record_chirho.seq_chirho
                ),
            }
        }
        let old_state_chirho = match &record_chirho.old_state_chirho {
            Some(hash_chirho) => Some(
                states_by_agent_chirho
                    .get(&record_chirho.agent_principal_chirho)
                    .and_then(|states_chirho| states_chirho.get(hash_chirho))
                    .cloned()
                    .ok_or_else(|| {
                        anyhow!(
                            "agent authority response {} old state is not prior verified same-agent history",
                            record_chirho.seq_chirho
                        )
                    })?,
            ),
            None => None,
        };
        let expected_state_chirho =
            derive_state_from_record_chirho(old_state_chirho.as_ref(), record_chirho)?;
        validate_agent_authority_state_chirho(&expected_state_chirho)?;
        let stored_state_chirho =
            load_agent_authority_state_chirho(root_chirho, &record_chirho.new_state_chirho)?;
        if store_chirho::hash_object_chirho(&stored_state_chirho)? != record_chirho.new_state_chirho
        {
            bail!(
                "agent authority response {} points at a non-canonical state hash",
                record_chirho.seq_chirho
            );
        }
        if stored_state_chirho != expected_state_chirho {
            bail!(
                "agent authority response {} state does not replay from prior state",
                record_chirho.seq_chirho
            );
        }
        let states_chirho = states_by_agent_chirho
            .entry(record_chirho.agent_principal_chirho.clone())
            .or_default();
        if states_chirho
            .insert(record_chirho.new_state_chirho.clone(), stored_state_chirho)
            .is_some()
        {
            bail!(
                "agent authority response {} duplicates a prior verified state hash",
                record_chirho.seq_chirho
            );
        }
        record_index_by_agent_state_chirho
            .entry(record_chirho.agent_principal_chirho.clone())
            .or_default()
            .insert(record_chirho.new_state_chirho.clone(), i_chirho);
        latest_by_agent_chirho.insert(
            record_chirho.agent_principal_chirho.clone(),
            record_chirho.new_state_chirho.clone(),
        );
    }

    Ok(VerifiedAgentAuthorityHistoryChirho {
        records_chirho,
        states_by_agent_chirho,
        record_index_by_agent_state_chirho,
    })
}

pub fn verify_agent_authority_responses_chirho(root_chirho: &Path) -> Result<usize> {
    let history_chirho = verified_agent_authority_history_chirho(root_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    for agent_chirho in history_chirho.states_by_agent_chirho.keys() {
        let branch_chirho = agent_authority_ref_chirho(agent_chirho)?;
        selected_verified_agent_authority_state_chirho(root_chirho, agent_chirho, &history_chirho)?
            .ok_or_else(|| anyhow!("agent authority ref {branch_chirho} is missing"))?;
    }
    for (branch_chirho, current_chirho) in &refs_chirho.branches_chirho {
        let Some(agent_chirho) = branch_chirho.strip_prefix("agent-authority/") else {
            continue;
        };
        validate_principal_chirho("agent principal", agent_chirho)?;
        let selected_chirho = selected_verified_agent_authority_state_chirho(
            root_chirho,
            agent_chirho,
            &history_chirho,
        )?;
        if selected_chirho
            .as_ref()
            .map(|(hash_chirho, _state_chirho)| hash_chirho)
            != Some(current_chirho)
        {
            bail!("agent authority ref {branch_chirho} is not verified response history");
        }
    }
    Ok(history_chirho.records_chirho.len())
}

pub fn agent_authority_ref_chirho(agent_principal_chirho: &str) -> Result<String> {
    validate_principal_chirho("agent principal", agent_principal_chirho)?;
    Ok(format!("agent-authority/{agent_principal_chirho}"))
}

fn verify_agent_authority_record_schema_chirho(
    record_chirho: &AgentAuthorityResponseRecordChirho,
) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != AGENT_AUTHORITY_RESPONSE_RECORD_SCHEMA_CHIRHO
        && record_chirho.schema_chirho != AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported agent authority response record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    if record_chirho.schema_chirho == AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO {
        if !record_chirho
            .transition_id_chirho
            .starts_with(HEAD_TRANSITION_ID_PREFIX_CHIRHO)
            || record_chirho.prepared_writer_fence_epoch_chirho.is_none()
            || record_chirho.prepared_writer_fence_epoch_chirho == Some(0)
        {
            bail!("agent authority v2 response has incomplete head transition evidence");
        }
    } else if !record_chirho.transition_id_chirho.is_empty()
        || record_chirho.prepared_writer_fence_epoch_chirho.is_some()
    {
        bail!("legacy agent authority response must not carry head transition evidence");
    }
    Ok(())
}

fn load_response_report_chirho(
    root_chirho: &Path,
    input_chirho: &AgentAuthorityResponseInputChirho,
) -> Result<agent_report_chirho::AgentReportChirho> {
    let records_chirho = agent_report_chirho::load_agent_report_records_chirho(root_chirho)?;
    let record_chirho = records_chirho
        .iter()
        .find(|record_chirho| record_chirho.seq_chirho == input_chirho.report_seq_chirho)
        .ok_or_else(|| {
            anyhow!(
                "agent report seq {} not found",
                input_chirho.report_seq_chirho
            )
        })?;
    if record_chirho.report_chirho != input_chirho.report_chirho {
        bail!(
            "agent report seq {} hash mismatch: record has {}, response named {}",
            input_chirho.report_seq_chirho,
            record_chirho.report_chirho.0,
            input_chirho.report_chirho.0
        );
    }
    agent_report_chirho::load_agent_report_chirho(root_chirho, &input_chirho.report_chirho)
}

fn load_record_report_chirho(
    root_chirho: &Path,
    report_records_chirho: &[agent_report_chirho::AgentReportRecordChirho],
    record_chirho: &AgentAuthorityResponseRecordChirho,
) -> Result<agent_report_chirho::AgentReportChirho> {
    let report_record_chirho = report_records_chirho
        .iter()
        .find(|report_record_chirho| {
            report_record_chirho.seq_chirho == record_chirho.report_seq_chirho
        })
        .ok_or_else(|| {
            anyhow!(
                "agent report seq {} not found",
                record_chirho.report_seq_chirho
            )
        })?;
    if report_record_chirho.report_chirho != record_chirho.report_chirho {
        bail!(
            "agent authority response {} report hash does not match source report record",
            record_chirho.seq_chirho
        );
    }
    agent_report_chirho::load_agent_report_chirho(root_chirho, &record_chirho.report_chirho)
}

fn current_agent_authority_hash_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
) -> Result<Option<HashChirho>> {
    let branch_chirho = agent_authority_ref_chirho(agent_principal_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    Ok(refs_chirho.branches_chirho.get(&branch_chirho).cloned())
}

fn agent_authority_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(AGENT_AUTHORITY_RESPONSE_RECORDS_LOG_CHIRHO)
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "ha2_head_commit_tests_chirho.rs"]
mod ha2_head_commit_tests_chirho;

#[cfg(test)]
mod tests_chirho;
