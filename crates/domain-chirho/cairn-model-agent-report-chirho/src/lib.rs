// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure agent-report model records.
//!
//! This crate owns serializable agent-report DTOs only. It does not read a cairn root, write
//! reports, sign records, charge budgets, or update support/customer surfaces.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentReportCategoryChirho {
    InformationalChirho,
    DecisionalChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AgentReportPriorityChirho {
    LowChirho,
    NormalChirho,
    HighChirho,
    CriticalChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AgentReportEvidenceKindChirho {
    ObjectChirho,
    LogChirho,
    RunChirho,
    EffectChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReportEvidenceRefChirho {
    pub kind_chirho: AgentReportEvidenceKindChirho,
    pub ref_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReportLedeChirho {
    pub happened_chirho: String,
    pub affected_chirho: String,
    pub why_matters_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRequestedActionKindChirho {
    GrantChirho,
    NarrowChirho,
    RevokeChirho,
    BudgetChangeChirho,
    ScopeChangeChirho,
    ParameterChangeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRequestedActionChirho {
    pub kind_chirho: AgentRequestedActionKindChirho,
    pub target_chirho: String,
    pub reason_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReportChirho {
    pub lede_chirho: AgentReportLedeChirho,
    pub category_chirho: AgentReportCategoryChirho,
    pub priority_chirho: AgentReportPriorityChirho,
    pub evidence_refs_chirho: Vec<AgentReportEvidenceRefChirho>,
    pub producer_principal_chirho: String,
    pub related_run_ids_chirho: Vec<HashChirho>,
    pub related_effect_ids_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_action_chirho: Option<AgentRequestedActionChirho>,
    pub created_at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReportRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub report_chirho: HashChirho,
    pub producer_principal_chirho: String,
    pub category_chirho: AgentReportCategoryChirho,
    pub priority_chirho: AgentReportPriorityChirho,
    pub evidence_count_chirho: usize,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn agent_report_enum_serialization_stays_stable_chirho() {
        assert_eq!(
            serde_json::to_string(&AgentReportCategoryChirho::DecisionalChirho).unwrap(),
            "\"DecisionalChirho\""
        );
        assert_eq!(
            serde_json::to_string(&AgentRequestedActionKindChirho::BudgetChangeChirho).unwrap(),
            "\"BudgetChangeChirho\""
        );
    }

    #[test]
    fn agent_report_serialization_stays_stable_chirho() {
        let report_chirho = AgentReportChirho {
            lede_chirho: AgentReportLedeChirho {
                happened_chirho: "built-chirho".to_string(),
                affected_chirho: "engine-chirho".to_string(),
                why_matters_chirho: "audit-chirho".to_string(),
            },
            category_chirho: AgentReportCategoryChirho::DecisionalChirho,
            priority_chirho: AgentReportPriorityChirho::HighChirho,
            evidence_refs_chirho: vec![AgentReportEvidenceRefChirho {
                kind_chirho: AgentReportEvidenceKindChirho::ObjectChirho,
                ref_chirho: "object-hash-chirho".to_string(),
            }],
            producer_principal_chirho: "owner/abc123-chirho".to_string(),
            related_run_ids_chirho: vec![HashChirho("run-hash-chirho".to_string())],
            related_effect_ids_chirho: vec!["effect-1-chirho".to_string()],
            requested_action_chirho: Some(AgentRequestedActionChirho {
                kind_chirho: AgentRequestedActionKindChirho::GrantChirho,
                target_chirho: "agent/one-chirho".to_string(),
                reason_chirho: "scope-chirho".to_string(),
            }),
            created_at_ms_chirho: 42,
        };
        assert_eq!(
            serde_json::to_string(&report_chirho).unwrap(),
            r#"{"lede_chirho":{"happened_chirho":"built-chirho","affected_chirho":"engine-chirho","why_matters_chirho":"audit-chirho"},"category_chirho":"DecisionalChirho","priority_chirho":"HighChirho","evidence_refs_chirho":[{"kind_chirho":"ObjectChirho","ref_chirho":"object-hash-chirho"}],"producer_principal_chirho":"owner/abc123-chirho","related_run_ids_chirho":["run-hash-chirho"],"related_effect_ids_chirho":["effect-1-chirho"],"requested_action_chirho":{"kind_chirho":"GrantChirho","target_chirho":"agent/one-chirho","reason_chirho":"scope-chirho"},"created_at_ms_chirho":42}"#
        );
    }

    #[test]
    fn agent_report_record_serialization_stays_stable_chirho() {
        let record_chirho = AgentReportRecordChirho {
            schema_chirho: "agent-report-record-v1-chirho".to_string(),
            seq_chirho: 9,
            report_chirho: HashChirho("report-hash-chirho".to_string()),
            producer_principal_chirho: "owner/abc123-chirho".to_string(),
            category_chirho: AgentReportCategoryChirho::InformationalChirho,
            priority_chirho: AgentReportPriorityChirho::NormalChirho,
            evidence_count_chirho: 2,
            at_ms_chirho: 77,
            sig_chirho: "sig-hex-chirho".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&record_chirho).unwrap(),
            r#"{"schema_chirho":"agent-report-record-v1-chirho","seq_chirho":9,"report_chirho":"report-hash-chirho","producer_principal_chirho":"owner/abc123-chirho","category_chirho":"InformationalChirho","priority_chirho":"NormalChirho","evidence_count_chirho":2,"at_ms_chirho":77,"sig_chirho":"sig-hex-chirho"}"#
        );
    }
}
