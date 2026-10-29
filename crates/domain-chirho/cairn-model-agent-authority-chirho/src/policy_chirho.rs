// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure agent-authority state derivation, validation, and scope policy.

use super::{
    AgentAuthorityChangeKindChirho, AgentAuthorityDecisionChirho,
    AgentAuthorityResponseInputChirho, AgentAuthorityResponseRecordChirho,
    AgentAuthorityRuleChirho, AgentAuthorityStateChirho,
};
use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_agent_report_chirho::{
    AgentReportCategoryChirho, AgentReportChirho, AgentRequestedActionKindChirho,
};
use serde::Serialize;
use std::collections::BTreeMap;

const AGENT_AUTHORITY_TRANSITION_OPERATION_SCHEMA_CHIRHO: &str =
    "agent-authority-transition-operation-v1-chirho";

pub fn agent_authority_change_kind_label_chirho(
    kind_chirho: &AgentAuthorityChangeKindChirho,
) -> &'static str {
    match kind_chirho {
        AgentAuthorityChangeKindChirho::GrantChirho => "grant-chirho",
        AgentAuthorityChangeKindChirho::NarrowChirho => "narrow-chirho",
        AgentAuthorityChangeKindChirho::RevokeChirho => "revoke-chirho",
        AgentAuthorityChangeKindChirho::BudgetChangeChirho => "budget-change-chirho",
        AgentAuthorityChangeKindChirho::ScopeChangeChirho => "scope-change-chirho",
        AgentAuthorityChangeKindChirho::ParameterChangeChirho => "parameter-change-chirho",
    }
}

pub fn derive_state_from_input_chirho(
    old_state_chirho: Option<&AgentAuthorityStateChirho>,
    old_state_hash_chirho: Option<HashChirho>,
    input_chirho: &AgentAuthorityResponseInputChirho,
    response_seq_chirho: u64,
    at_ms_chirho: u64,
) -> Result<AgentAuthorityStateChirho> {
    let mut state_chirho = old_state_chirho
        .cloned()
        .unwrap_or_else(|| AgentAuthorityStateChirho {
            agent_principal_chirho: input_chirho.agent_principal_chirho.clone(),
            rules_chirho: BTreeMap::new(),
            current_response_seq_chirho: None,
            previous_state_chirho: None,
            updated_at_ms_chirho: at_ms_chirho,
        });
    if state_chirho.agent_principal_chirho != input_chirho.agent_principal_chirho {
        bail!("cannot apply authority response to a different agent principal");
    }
    apply_transition_chirho(
        &mut state_chirho,
        &input_chirho.change_kind_chirho,
        &input_chirho.rule_id_chirho,
        input_chirho.scope_chirho.as_deref(),
        input_chirho.budget_token_chirho,
        &input_chirho.parameter_changes_chirho,
        input_chirho.report_seq_chirho,
        response_seq_chirho,
        at_ms_chirho,
    )?;
    state_chirho.previous_state_chirho = old_state_hash_chirho;
    state_chirho.current_response_seq_chirho = Some(response_seq_chirho);
    state_chirho.updated_at_ms_chirho = at_ms_chirho;
    Ok(state_chirho)
}

pub fn derive_state_from_record_chirho(
    old_state_chirho: Option<&AgentAuthorityStateChirho>,
    record_chirho: &AgentAuthorityResponseRecordChirho,
) -> Result<AgentAuthorityStateChirho> {
    let mut state_chirho = old_state_chirho
        .cloned()
        .unwrap_or_else(|| AgentAuthorityStateChirho {
            agent_principal_chirho: record_chirho.agent_principal_chirho.clone(),
            rules_chirho: BTreeMap::new(),
            current_response_seq_chirho: None,
            previous_state_chirho: None,
            updated_at_ms_chirho: record_chirho.at_ms_chirho,
        });
    if state_chirho.agent_principal_chirho != record_chirho.agent_principal_chirho {
        bail!("cannot replay authority response onto a different agent principal");
    }
    apply_transition_chirho(
        &mut state_chirho,
        &record_chirho.change_kind_chirho,
        &record_chirho.rule_id_chirho,
        record_chirho.scope_chirho.as_deref(),
        record_chirho.budget_token_chirho,
        &record_chirho.parameter_changes_chirho,
        record_chirho.report_seq_chirho,
        record_chirho.seq_chirho,
        record_chirho.at_ms_chirho,
    )?;
    state_chirho.previous_state_chirho = record_chirho.old_state_chirho.clone();
    state_chirho.current_response_seq_chirho = Some(record_chirho.seq_chirho);
    state_chirho.updated_at_ms_chirho = record_chirho.at_ms_chirho;
    Ok(state_chirho)
}

#[allow(clippy::too_many_arguments)]
fn apply_transition_chirho(
    state_chirho: &mut AgentAuthorityStateChirho,
    kind_chirho: &AgentAuthorityChangeKindChirho,
    rule_id_chirho: &str,
    scope_chirho: Option<&str>,
    budget_token_chirho: Option<u64>,
    parameter_changes_chirho: &BTreeMap<String, String>,
    report_seq_chirho: u64,
    response_seq_chirho: u64,
    at_ms_chirho: u64,
) -> Result<()> {
    match kind_chirho {
        AgentAuthorityChangeKindChirho::GrantChirho => {
            let scope_chirho = scope_chirho
                .ok_or_else(|| anyhow!("grant requires --scope"))?
                .to_string();
            let rule_chirho = AgentAuthorityRuleChirho {
                rule_id_chirho: rule_id_chirho.to_string(),
                scope_chirho,
                budget_token_chirho,
                parameters_chirho: parameter_changes_chirho.clone(),
                revoked_chirho: false,
                source_report_seq_chirho: report_seq_chirho,
                source_response_seq_chirho: response_seq_chirho,
                updated_at_ms_chirho: at_ms_chirho,
            };
            state_chirho
                .rules_chirho
                .insert(rule_id_chirho.to_string(), rule_chirho);
        }
        AgentAuthorityChangeKindChirho::NarrowChirho => {
            ensure_no_budget_or_params_chirho(
                kind_chirho,
                budget_token_chirho,
                parameter_changes_chirho,
            )?;
            let new_scope_chirho =
                scope_chirho.ok_or_else(|| anyhow!("narrow requires --scope"))?;
            let rule_chirho = active_rule_mut_chirho(state_chirho, rule_id_chirho)?;
            if !scope_is_narrower_chirho(&rule_chirho.scope_chirho, new_scope_chirho) {
                bail!(
                    "new scope {new_scope_chirho} is not narrower than current scope {}",
                    rule_chirho.scope_chirho
                );
            }
            rule_chirho.scope_chirho = new_scope_chirho.to_string();
            touch_rule_chirho(
                rule_chirho,
                report_seq_chirho,
                response_seq_chirho,
                at_ms_chirho,
            );
        }
        AgentAuthorityChangeKindChirho::RevokeChirho => {
            ensure_no_scope_budget_or_params_chirho(
                kind_chirho,
                scope_chirho,
                budget_token_chirho,
                parameter_changes_chirho,
            )?;
            let rule_chirho = state_chirho
                .rules_chirho
                .get_mut(rule_id_chirho)
                .ok_or_else(|| anyhow!("cannot revoke missing rule {rule_id_chirho}"))?;
            rule_chirho.revoked_chirho = true;
            touch_rule_chirho(
                rule_chirho,
                report_seq_chirho,
                response_seq_chirho,
                at_ms_chirho,
            );
        }
        AgentAuthorityChangeKindChirho::BudgetChangeChirho => {
            let budget_chirho = budget_token_chirho
                .ok_or_else(|| anyhow!("budget-change requires --budget-token"))?;
            ensure_no_scope_or_params_chirho(kind_chirho, scope_chirho, parameter_changes_chirho)?;
            let rule_chirho = active_rule_mut_chirho(state_chirho, rule_id_chirho)?;
            rule_chirho.budget_token_chirho = Some(budget_chirho);
            touch_rule_chirho(
                rule_chirho,
                report_seq_chirho,
                response_seq_chirho,
                at_ms_chirho,
            );
        }
        AgentAuthorityChangeKindChirho::ScopeChangeChirho => {
            ensure_no_budget_or_params_chirho(
                kind_chirho,
                budget_token_chirho,
                parameter_changes_chirho,
            )?;
            let new_scope_chirho =
                scope_chirho.ok_or_else(|| anyhow!("scope-change requires --scope"))?;
            let rule_chirho = active_rule_mut_chirho(state_chirho, rule_id_chirho)?;
            rule_chirho.scope_chirho = new_scope_chirho.to_string();
            touch_rule_chirho(
                rule_chirho,
                report_seq_chirho,
                response_seq_chirho,
                at_ms_chirho,
            );
        }
        AgentAuthorityChangeKindChirho::ParameterChangeChirho => {
            if parameter_changes_chirho.is_empty() {
                bail!("parameter-change requires at least one --param key=value");
            }
            if scope_chirho.is_some() || budget_token_chirho.is_some() {
                bail!("parameter-change cannot include scope or budget-token");
            }
            let rule_chirho = active_rule_mut_chirho(state_chirho, rule_id_chirho)?;
            for (key_chirho, value_chirho) in parameter_changes_chirho {
                rule_chirho
                    .parameters_chirho
                    .insert(key_chirho.clone(), value_chirho.clone());
            }
            touch_rule_chirho(
                rule_chirho,
                report_seq_chirho,
                response_seq_chirho,
                at_ms_chirho,
            );
        }
    }
    Ok(())
}

pub fn validate_response_input_chirho(
    input_chirho: &AgentAuthorityResponseInputChirho,
) -> Result<()> {
    validate_principal_chirho("admin principal", &input_chirho.admin_principal_chirho)?;
    validate_principal_chirho("agent principal", &input_chirho.agent_principal_chirho)?;
    validate_rule_id_chirho(&input_chirho.rule_id_chirho)?;
    validate_safe_text_chirho(
        "authority response reason",
        &input_chirho.reason_chirho,
        360,
    )?;
    if let Some(scope_chirho) = &input_chirho.scope_chirho {
        validate_scope_chirho(scope_chirho)?;
    }
    for (key_chirho, value_chirho) in &input_chirho.parameter_changes_chirho {
        validate_param_key_chirho(key_chirho)?;
        validate_safe_text_chirho("authority param value", value_chirho, 240)?;
    }
    Ok(())
}

pub fn validate_response_record_chirho(
    record_chirho: &AgentAuthorityResponseRecordChirho,
) -> Result<()> {
    validate_principal_chirho("admin principal", &record_chirho.admin_principal_chirho)?;
    validate_principal_chirho("agent principal", &record_chirho.agent_principal_chirho)?;
    validate_rule_id_chirho(&record_chirho.rule_id_chirho)?;
    validate_safe_text_chirho(
        "authority response reason",
        &record_chirho.reason_chirho,
        360,
    )?;
    if let Some(scope_chirho) = &record_chirho.scope_chirho {
        validate_scope_chirho(scope_chirho)?;
    }
    for (key_chirho, value_chirho) in &record_chirho.parameter_changes_chirho {
        validate_param_key_chirho(key_chirho)?;
        validate_safe_text_chirho("authority param value", value_chirho, 240)?;
    }
    Ok(())
}

pub fn validate_agent_authority_state_chirho(
    state_chirho: &AgentAuthorityStateChirho,
) -> Result<()> {
    validate_principal_chirho("agent principal", &state_chirho.agent_principal_chirho)?;
    for (key_chirho, rule_chirho) in &state_chirho.rules_chirho {
        if key_chirho != &rule_chirho.rule_id_chirho {
            bail!("authority rule map key does not match rule_id_chirho");
        }
        validate_rule_id_chirho(&rule_chirho.rule_id_chirho)?;
        validate_scope_chirho(&rule_chirho.scope_chirho)?;
        for (param_key_chirho, value_chirho) in &rule_chirho.parameters_chirho {
            validate_param_key_chirho(param_key_chirho)?;
            validate_safe_text_chirho("authority param value", value_chirho, 240)?;
        }
    }
    Ok(())
}

fn active_rule_mut_chirho<'a>(
    state_chirho: &'a mut AgentAuthorityStateChirho,
    rule_id_chirho: &str,
) -> Result<&'a mut AgentAuthorityRuleChirho> {
    let rule_chirho = state_chirho
        .rules_chirho
        .get_mut(rule_id_chirho)
        .ok_or_else(|| anyhow!("missing active authority rule {rule_id_chirho}"))?;
    if rule_chirho.revoked_chirho {
        bail!("authority rule {rule_id_chirho} has been revoked");
    }
    Ok(rule_chirho)
}

fn touch_rule_chirho(
    rule_chirho: &mut AgentAuthorityRuleChirho,
    report_seq_chirho: u64,
    response_seq_chirho: u64,
    at_ms_chirho: u64,
) {
    rule_chirho.source_report_seq_chirho = report_seq_chirho;
    rule_chirho.source_response_seq_chirho = response_seq_chirho;
    rule_chirho.updated_at_ms_chirho = at_ms_chirho;
}

pub fn scope_matches_chirho(rule_scope_chirho: &str, action_scope_chirho: &str) -> bool {
    if rule_scope_chirho == action_scope_chirho {
        return true;
    }
    if let Some(prefix_chirho) = rule_scope_chirho.strip_suffix('*') {
        return action_scope_chirho.starts_with(prefix_chirho);
    }
    false
}

fn scope_is_narrower_chirho(old_scope_chirho: &str, new_scope_chirho: &str) -> bool {
    if old_scope_chirho == new_scope_chirho {
        return false;
    }
    if let Some(prefix_chirho) = old_scope_chirho.strip_suffix('*') {
        return new_scope_chirho.starts_with(prefix_chirho)
            && new_scope_chirho.len() > prefix_chirho.len();
    }
    false
}

fn ensure_no_scope_budget_or_params_chirho(
    kind_chirho: &AgentAuthorityChangeKindChirho,
    scope_chirho: Option<&str>,
    budget_token_chirho: Option<u64>,
    parameter_changes_chirho: &BTreeMap<String, String>,
) -> Result<()> {
    if scope_chirho.is_some()
        || budget_token_chirho.is_some()
        || !parameter_changes_chirho.is_empty()
    {
        bail!(
            "{} cannot include scope, budget-token, or params",
            agent_authority_change_kind_label_chirho(kind_chirho)
        );
    }
    Ok(())
}

fn ensure_no_scope_or_params_chirho(
    kind_chirho: &AgentAuthorityChangeKindChirho,
    scope_chirho: Option<&str>,
    parameter_changes_chirho: &BTreeMap<String, String>,
) -> Result<()> {
    if scope_chirho.is_some() || !parameter_changes_chirho.is_empty() {
        bail!(
            "{} cannot include scope or params",
            agent_authority_change_kind_label_chirho(kind_chirho)
        );
    }
    Ok(())
}

fn ensure_no_budget_or_params_chirho(
    kind_chirho: &AgentAuthorityChangeKindChirho,
    budget_token_chirho: Option<u64>,
    parameter_changes_chirho: &BTreeMap<String, String>,
) -> Result<()> {
    if budget_token_chirho.is_some() || !parameter_changes_chirho.is_empty() {
        bail!(
            "{} cannot include budget-token or params",
            agent_authority_change_kind_label_chirho(kind_chirho)
        );
    }
    Ok(())
}

pub fn validate_principal_chirho(label_chirho: &str, principal_chirho: &str) -> Result<()> {
    validate_safe_text_chirho(label_chirho, principal_chirho, 160)?;
    if principal_chirho.chars().any(char::is_whitespace)
        || !principal_chirho.contains('/')
        || principal_chirho.starts_with('/')
        || principal_chirho.ends_with('/')
        || principal_chirho.contains("//")
        || principal_chirho.contains("..")
        || principal_chirho.contains('\\')
    {
        bail!("{label_chirho} must be a safe path-like principal such as agent/name-chirho");
    }
    Ok(())
}

pub fn validate_rule_id_chirho(rule_id_chirho: &str) -> Result<()> {
    validate_safe_text_chirho("authority rule id", rule_id_chirho, 120)?;
    if rule_id_chirho.contains('/') || rule_id_chirho.contains("..") {
        bail!("authority rule id must be a single safe segment");
    }
    Ok(())
}

pub fn validate_scope_chirho(scope_chirho: &str) -> Result<()> {
    validate_safe_text_chirho("authority scope", scope_chirho, 240)?;
    if scope_chirho.starts_with('/')
        || scope_chirho.ends_with('/')
        || scope_chirho.contains("//")
        || scope_chirho.contains("..")
        || scope_chirho.contains('\\')
    {
        bail!("authority scope must be a safe slash-delimited scope");
    }
    let wildcard_count_chirho = scope_chirho
        .chars()
        .filter(|char_chirho| *char_chirho == '*')
        .count();
    if wildcard_count_chirho > 1
        || (wildcard_count_chirho == 1 && (!scope_chirho.ends_with('*') || scope_chirho.len() == 1))
    {
        bail!("authority scope may use one trailing wildcard only");
    }
    if !scope_chirho.chars().all(|char_chirho| {
        char_chirho.is_ascii_alphanumeric()
            || matches!(char_chirho, '/' | '-' | '_' | '.' | ':' | '*')
    }) {
        bail!("authority scope contains unsupported characters");
    }
    Ok(())
}

pub fn validate_param_key_chirho(key_chirho: &str) -> Result<()> {
    validate_safe_text_chirho("authority param key", key_chirho, 80)?;
    if !key_chirho
        .chars()
        .all(|char_chirho| char_chirho.is_ascii_alphanumeric() || matches!(char_chirho, '-' | '_'))
    {
        bail!("authority param key contains unsupported characters");
    }
    Ok(())
}

pub fn validate_safe_text_chirho(
    label_chirho: &str,
    value_chirho: &str,
    max_chars_chirho: usize,
) -> Result<()> {
    let trimmed_chirho = value_chirho.trim();
    if trimmed_chirho.is_empty() {
        bail!("{label_chirho} must not be empty");
    }
    if trimmed_chirho != value_chirho {
        bail!("{label_chirho} must not have leading or trailing whitespace");
    }
    if value_chirho.chars().any(char::is_control) {
        bail!("{label_chirho} must not contain control characters");
    }
    if value_chirho.chars().count() > max_chars_chirho {
        bail!("{label_chirho} is too long");
    }
    Ok(())
}

pub fn agent_authority_denial_chirho(
    agent_principal_chirho: &str,
    action_scope_chirho: &str,
    reason_chirho: &str,
) -> AgentAuthorityDecisionChirho {
    AgentAuthorityDecisionChirho {
        authorized_chirho: false,
        agent_principal_chirho: agent_principal_chirho.to_string(),
        action_scope_chirho: action_scope_chirho.to_string(),
        matched_rule_chirho: None,
        remaining_budget_token_chirho: None,
        reason_chirho: reason_chirho.to_string(),
    }
}

pub fn decide_agent_action_from_verified_state_chirho(
    state_chirho: &AgentAuthorityStateChirho,
    agent_principal_chirho: &str,
    action_scope_chirho: &str,
    cost_token_chirho: u64,
) -> AgentAuthorityDecisionChirho {
    let mut budget_denial_chirho = None;
    for rule_chirho in state_chirho.rules_chirho.values() {
        if rule_chirho.revoked_chirho {
            continue;
        }
        if !scope_matches_chirho(&rule_chirho.scope_chirho, action_scope_chirho) {
            continue;
        }
        if let Some(limit_chirho) = rule_chirho.budget_token_chirho {
            if limit_chirho < cost_token_chirho {
                budget_denial_chirho = Some(AgentAuthorityDecisionChirho {
                    authorized_chirho: false,
                    agent_principal_chirho: agent_principal_chirho.to_string(),
                    action_scope_chirho: action_scope_chirho.to_string(),
                    matched_rule_chirho: Some(rule_chirho.rule_id_chirho.clone()),
                    remaining_budget_token_chirho: Some(limit_chirho),
                    reason_chirho: format!(
                        "matched rule {} has budget {limit_chirho} below requested cost {cost_token_chirho}",
                        rule_chirho.rule_id_chirho
                    ),
                });
                continue;
            }
        }
        return AgentAuthorityDecisionChirho {
            authorized_chirho: true,
            agent_principal_chirho: agent_principal_chirho.to_string(),
            action_scope_chirho: action_scope_chirho.to_string(),
            matched_rule_chirho: Some(rule_chirho.rule_id_chirho.clone()),
            remaining_budget_token_chirho: rule_chirho
                .budget_token_chirho
                .map(|limit_chirho| limit_chirho.saturating_sub(cost_token_chirho)),
            reason_chirho: "authorized by current agent authority ref".to_string(),
        };
    }
    if let Some(decision_chirho) = budget_denial_chirho {
        return decision_chirho;
    }
    AgentAuthorityDecisionChirho {
        authorized_chirho: false,
        agent_principal_chirho: agent_principal_chirho.to_string(),
        action_scope_chirho: action_scope_chirho.to_string(),
        matched_rule_chirho: None,
        remaining_budget_token_chirho: None,
        reason_chirho: "no active authority rule matches requested scope".to_string(),
    }
}

pub fn parse_agent_authority_change_kind_chirho(
    raw_chirho: &str,
) -> Result<AgentAuthorityChangeKindChirho> {
    match raw_chirho.trim() {
        "grant" | "grant-chirho" => Ok(AgentAuthorityChangeKindChirho::GrantChirho),
        "narrow" | "narrow-chirho" => Ok(AgentAuthorityChangeKindChirho::NarrowChirho),
        "revoke" | "revoke-chirho" => Ok(AgentAuthorityChangeKindChirho::RevokeChirho),
        "budget-change" | "budget-change-chirho" => {
            Ok(AgentAuthorityChangeKindChirho::BudgetChangeChirho)
        }
        "scope-change" | "scope-change-chirho" => {
            Ok(AgentAuthorityChangeKindChirho::ScopeChangeChirho)
        }
        "parameter-change" | "parameter-change-chirho" => {
            Ok(AgentAuthorityChangeKindChirho::ParameterChangeChirho)
        }
        other_chirho => bail!("unknown agent authority change kind '{other_chirho}'"),
    }
}

pub fn parse_agent_authority_param_chirho(raw_chirho: &str) -> Result<(String, String)> {
    let (key_chirho, value_chirho) = raw_chirho
        .split_once('=')
        .ok_or_else(|| anyhow!("authority param must be key=value"))?;
    let key_chirho = key_chirho.trim().to_string();
    let value_chirho = value_chirho.trim().to_string();
    validate_param_key_chirho(&key_chirho)?;
    validate_safe_text_chirho("authority param value", &value_chirho, 240)?;
    Ok((key_chirho, value_chirho))
}

pub fn validate_response_matches_report_chirho(
    input_chirho: &AgentAuthorityResponseInputChirho,
    report_chirho: &AgentReportChirho,
) -> Result<()> {
    if report_chirho.category_chirho != AgentReportCategoryChirho::DecisionalChirho {
        bail!("authority responses must reference decisional agent reports");
    }
    if report_chirho.producer_principal_chirho != input_chirho.agent_principal_chirho {
        bail!("authority response agent must match the report producer principal");
    }
    let requested_chirho = report_chirho
        .requested_action_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("decisional report must include a requested action"))?;
    if requested_chirho.kind_chirho != requested_kind_chirho(&input_chirho.change_kind_chirho) {
        bail!("authority response kind does not match the report requested action kind");
    }
    if !requested_target_matches_chirho(
        &requested_chirho.target_chirho,
        &input_chirho.rule_id_chirho,
        input_chirho.scope_chirho.as_deref(),
    ) {
        bail!("authority response target does not match the report requested action target");
    }
    Ok(())
}

pub fn validate_response_record_matches_report_chirho(
    record_chirho: &AgentAuthorityResponseRecordChirho,
    report_chirho: &AgentReportChirho,
) -> Result<()> {
    if report_chirho.category_chirho != AgentReportCategoryChirho::DecisionalChirho {
        bail!(
            "agent authority response {} references a non-decisional report",
            record_chirho.seq_chirho
        );
    }
    if report_chirho.producer_principal_chirho != record_chirho.agent_principal_chirho {
        bail!(
            "agent authority response {} agent does not match report producer",
            record_chirho.seq_chirho
        );
    }
    let requested_chirho = report_chirho
        .requested_action_chirho
        .as_ref()
        .ok_or_else(|| {
            anyhow!(
                "agent authority response {} references a report without requested action",
                record_chirho.seq_chirho
            )
        })?;
    if requested_chirho.kind_chirho != requested_kind_chirho(&record_chirho.change_kind_chirho) {
        bail!(
            "agent authority response {} kind does not match requested action",
            record_chirho.seq_chirho
        );
    }
    if !requested_target_matches_chirho(
        &requested_chirho.target_chirho,
        &record_chirho.rule_id_chirho,
        record_chirho.scope_chirho.as_deref(),
    ) {
        bail!(
            "agent authority response {} target does not match requested action",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

pub fn agent_authority_transition_operation_bytes_chirho(
    record_chirho: &AgentAuthorityResponseRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AgentAuthorityTransitionOperationChirho<'a> {
        schema_chirho: &'static str,
        admin_principal_chirho: &'a str,
        agent_principal_chirho: &'a str,
        report_seq_chirho: u64,
        report_chirho: &'a HashChirho,
        change_kind_chirho: &'a AgentAuthorityChangeKindChirho,
        rule_id_chirho: &'a str,
        scope_chirho: &'a Option<String>,
        budget_token_chirho: Option<u64>,
        parameter_changes_chirho: &'a BTreeMap<String, String>,
        reason_chirho: &'a str,
    }
    Ok(serde_json::to_vec(
        &AgentAuthorityTransitionOperationChirho {
            schema_chirho: AGENT_AUTHORITY_TRANSITION_OPERATION_SCHEMA_CHIRHO,
            admin_principal_chirho: &record_chirho.admin_principal_chirho,
            agent_principal_chirho: &record_chirho.agent_principal_chirho,
            report_seq_chirho: record_chirho.report_seq_chirho,
            report_chirho: &record_chirho.report_chirho,
            change_kind_chirho: &record_chirho.change_kind_chirho,
            rule_id_chirho: &record_chirho.rule_id_chirho,
            scope_chirho: &record_chirho.scope_chirho,
            budget_token_chirho: record_chirho.budget_token_chirho,
            parameter_changes_chirho: &record_chirho.parameter_changes_chirho,
            reason_chirho: &record_chirho.reason_chirho,
        },
    )?)
}

pub fn agent_authority_record_message_chirho(
    record_chirho: &AgentAuthorityResponseRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn requested_kind_chirho(
    kind_chirho: &AgentAuthorityChangeKindChirho,
) -> AgentRequestedActionKindChirho {
    match kind_chirho {
        AgentAuthorityChangeKindChirho::GrantChirho => AgentRequestedActionKindChirho::GrantChirho,
        AgentAuthorityChangeKindChirho::NarrowChirho => {
            AgentRequestedActionKindChirho::NarrowChirho
        }
        AgentAuthorityChangeKindChirho::RevokeChirho => {
            AgentRequestedActionKindChirho::RevokeChirho
        }
        AgentAuthorityChangeKindChirho::BudgetChangeChirho => {
            AgentRequestedActionKindChirho::BudgetChangeChirho
        }
        AgentAuthorityChangeKindChirho::ScopeChangeChirho => {
            AgentRequestedActionKindChirho::ScopeChangeChirho
        }
        AgentAuthorityChangeKindChirho::ParameterChangeChirho => {
            AgentRequestedActionKindChirho::ParameterChangeChirho
        }
    }
}

fn requested_target_matches_chirho(
    target_chirho: &str,
    rule_id_chirho: &str,
    scope_chirho: Option<&str>,
) -> bool {
    target_chirho == rule_id_chirho || scope_chirho == Some(target_chirho)
}

#[cfg(test)]
#[path = "policy_tests_chirho.rs"]
mod tests_chirho;
