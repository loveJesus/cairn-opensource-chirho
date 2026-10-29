// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure agent-authority model records and policy.
//!
//! This crate owns serializable agent-authority DTOs and deterministic policy over already-loaded
//! values. It does not read a cairn root, verify signatures, sign records, write logs, store
//! states, or move refs.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod policy_chirho;

pub const AGENT_AUTHORITY_RESPONSE_RECORD_SCHEMA_CHIRHO: &str =
    "agent-authority-response-record-v1-chirho";
pub const AGENT_AUTHORITY_RESPONSE_RECORD_V2_SCHEMA_CHIRHO: &str =
    "agent-authority-response-record-v2-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAuthorityChangeKindChirho {
    GrantChirho,
    NarrowChirho,
    RevokeChirho,
    BudgetChangeChirho,
    ScopeChangeChirho,
    ParameterChangeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorityRuleChirho {
    pub rule_id_chirho: String,
    pub scope_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_token_chirho: Option<u64>,
    #[serde(default)]
    pub parameters_chirho: BTreeMap<String, String>,
    pub revoked_chirho: bool,
    pub source_report_seq_chirho: u64,
    pub source_response_seq_chirho: u64,
    pub updated_at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorityStateChirho {
    pub agent_principal_chirho: String,
    pub rules_chirho: BTreeMap<String, AgentAuthorityRuleChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_response_seq_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state_chirho: Option<HashChirho>,
    pub updated_at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAuthorityResponseInputChirho {
    pub admin_principal_chirho: String,
    pub agent_principal_chirho: String,
    pub report_seq_chirho: u64,
    pub report_chirho: HashChirho,
    pub change_kind_chirho: AgentAuthorityChangeKindChirho,
    pub rule_id_chirho: String,
    pub scope_chirho: Option<String>,
    pub budget_token_chirho: Option<u64>,
    pub parameter_changes_chirho: BTreeMap<String, String>,
    pub reason_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorityResponseRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub admin_principal_chirho: String,
    pub agent_principal_chirho: String,
    pub report_seq_chirho: u64,
    pub report_chirho: HashChirho,
    pub change_kind_chirho: AgentAuthorityChangeKindChirho,
    pub rule_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_token_chirho: Option<u64>,
    #[serde(default)]
    pub parameter_changes_chirho: BTreeMap<String, String>,
    pub reason_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_state_chirho: Option<HashChirho>,
    pub new_state_chirho: HashChirho,
    pub at_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transition_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_writer_fence_epoch_chirho: Option<u64>,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorityDecisionChirho {
    pub authorized_chirho: bool,
    pub agent_principal_chirho: String,
    pub action_scope_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_budget_token_chirho: Option<u64>,
    pub reason_chirho: String,
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn hash_chirho(byte_chirho: char) -> HashChirho {
        HashChirho(byte_chirho.to_string().repeat(64))
    }

    #[test]
    fn agent_authority_enum_serialization_stays_stable_chirho() {
        assert_eq!(
            serde_json::to_string(&AgentAuthorityChangeKindChirho::GrantChirho).unwrap(),
            "\"GrantChirho\""
        );
        assert_eq!(
            serde_json::to_string(&AgentAuthorityChangeKindChirho::ParameterChangeChirho).unwrap(),
            "\"ParameterChangeChirho\""
        );
    }

    #[test]
    fn agent_authority_state_serialization_stays_stable_chirho() {
        let mut parameters_chirho = BTreeMap::new();
        parameters_chirho.insert("mode_chirho".to_string(), "reviewed_chirho".to_string());
        let mut rules_chirho = BTreeMap::new();
        rules_chirho.insert(
            "rule-one-chirho".to_string(),
            AgentAuthorityRuleChirho {
                rule_id_chirho: "rule-one-chirho".to_string(),
                scope_chirho: "crm/email/*".to_string(),
                budget_token_chirho: Some(55),
                parameters_chirho,
                revoked_chirho: false,
                source_report_seq_chirho: 3,
                source_response_seq_chirho: 4,
                updated_at_ms_chirho: 123,
            },
        );
        let state_chirho = AgentAuthorityStateChirho {
            agent_principal_chirho: "agent/helper-chirho".to_string(),
            rules_chirho,
            current_response_seq_chirho: Some(4),
            previous_state_chirho: Some(hash_chirho('a')),
            updated_at_ms_chirho: 123,
        };
        assert_eq!(
            serde_json::to_string(&state_chirho).unwrap(),
            r#"{"agent_principal_chirho":"agent/helper-chirho","rules_chirho":{"rule-one-chirho":{"rule_id_chirho":"rule-one-chirho","scope_chirho":"crm/email/*","budget_token_chirho":55,"parameters_chirho":{"mode_chirho":"reviewed_chirho"},"revoked_chirho":false,"source_report_seq_chirho":3,"source_response_seq_chirho":4,"updated_at_ms_chirho":123}},"current_response_seq_chirho":4,"previous_state_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","updated_at_ms_chirho":123}"#
        );
    }

    #[test]
    fn agent_authority_response_record_serialization_stays_stable_chirho() {
        let mut params_chirho = BTreeMap::new();
        params_chirho.insert("tone_chirho".to_string(), "calm_chirho".to_string());
        let record_chirho = AgentAuthorityResponseRecordChirho {
            schema_chirho: "agent-authority-response-record-v1-chirho".to_string(),
            seq_chirho: 8,
            admin_principal_chirho: "owner/admin-chirho".to_string(),
            agent_principal_chirho: "agent/helper-chirho".to_string(),
            report_seq_chirho: 7,
            report_chirho: hash_chirho('b'),
            change_kind_chirho: AgentAuthorityChangeKindChirho::ParameterChangeChirho,
            rule_id_chirho: "rule-one-chirho".to_string(),
            scope_chirho: None,
            budget_token_chirho: None,
            parameter_changes_chirho: params_chirho,
            reason_chirho: "tune behavior-chirho".to_string(),
            old_state_chirho: Some(hash_chirho('a')),
            new_state_chirho: hash_chirho('c'),
            at_ms_chirho: 999,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: "sig-hex-chirho".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&record_chirho).unwrap(),
            r#"{"schema_chirho":"agent-authority-response-record-v1-chirho","seq_chirho":8,"admin_principal_chirho":"owner/admin-chirho","agent_principal_chirho":"agent/helper-chirho","report_seq_chirho":7,"report_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","change_kind_chirho":"ParameterChangeChirho","rule_id_chirho":"rule-one-chirho","parameter_changes_chirho":{"tone_chirho":"calm_chirho"},"reason_chirho":"tune behavior-chirho","old_state_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","new_state_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","at_ms_chirho":999,"sig_chirho":"sig-hex-chirho"}"#
        );
    }

    #[test]
    fn agent_authority_decision_serialization_stays_stable_chirho() {
        let decision_chirho = AgentAuthorityDecisionChirho {
            authorized_chirho: true,
            agent_principal_chirho: "agent/helper-chirho".to_string(),
            action_scope_chirho: "crm/email/customer-chirho".to_string(),
            matched_rule_chirho: Some("rule-one-chirho".to_string()),
            remaining_budget_token_chirho: Some(50),
            reason_chirho: "authorized by current agent authority ref".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&decision_chirho).unwrap(),
            r#"{"authorized_chirho":true,"agent_principal_chirho":"agent/helper-chirho","action_scope_chirho":"crm/email/customer-chirho","matched_rule_chirho":"rule-one-chirho","remaining_budget_token_chirho":50,"reason_chirho":"authorized by current agent authority ref"}"#
        );
    }
}
