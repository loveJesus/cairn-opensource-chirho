// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure review model records for candidate app review.
//!
//! This crate owns serializable review DTOs only. It does not read a cairn root, sign review
//! records, verify source evidence, promote/reject apps, or inspect DAG capabilities.

use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

pub const REVIEW_RECORD_SCHEMA_CHIRHO: &str = "review-record-v1-chirho";
pub const REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO: &str = "review-policy-envelope-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewPaidEffectCostChirho {
    pub effect_chirho: String,
    pub count_chirho: u64,
    pub unit_cost_token_chirho: i64,
    pub total_cost_token_chirho: i64,
    pub source_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSurfaceDiffChirho {
    pub app_chirho: String,
    pub live_chirho: Option<HashChirho>,
    pub candidate_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_book_chirho: Option<HashChirho>,
    pub live_node_count_chirho: usize,
    pub candidate_node_count_chirho: usize,
    pub live_edge_count_chirho: usize,
    pub candidate_edge_count_chirho: usize,
    pub added_nodes_chirho: Vec<HashChirho>,
    pub removed_nodes_chirho: Vec<HashChirho>,
    pub added_capabilities_chirho: Vec<String>,
    pub removed_capabilities_chirho: Vec<String>,
    pub live_paid_effects_chirho: Vec<ReviewPaidEffectCostChirho>,
    pub candidate_paid_effects_chirho: Vec<ReviewPaidEffectCostChirho>,
    pub live_cost_token_chirho: i64,
    pub candidate_cost_token_chirho: i64,
    pub cost_delta_token_chirho: i64,
    pub warnings_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewDecisionChirho {
    PromoteChirho,
    RejectChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSourceManifestEvidenceChirho {
    pub effective_manifest_hash_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_manifest_hash_chirho: Option<HashChirho>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReviewSourceEvidenceChirho {
    pub source_review_report_chirho: Option<HashChirho>,
    pub source_manifest_chirho: Option<ReviewSourceManifestEvidenceChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho")]
pub enum ReviewPolicyEnvelopeScopeChirho {
    OwnerPrincipalChirho { owner_principal_chirho: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewPolicyEnvelopeRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub app_chirho: String,
    pub scope_chirho: ReviewPolicyEnvelopeScopeChirho,
    pub allowed_capability_labels_chirho: Vec<String>,
    pub max_candidate_cost_token_chirho: i64,
    pub allowed_contract_refs_chirho: Vec<String>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho")]
pub enum ReviewPolicyEnvelopeEvidenceChirho {
    BoundChirho {
        envelope_seq_chirho: u64,
        envelope_line_hash_chirho: HashChirho,
    },
    AbsentChirho {
        checked_envelope_count_chirho: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub live_before_chirho: Option<HashChirho>,
    pub candidate_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_review_report_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_manifest_chirho: Option<ReviewSourceManifestEvidenceChirho>,
    pub decision_chirho: ReviewDecisionChirho,
    pub accepted_capability_escalation_chirho: bool,
    pub accepted_cost_increase_chirho: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_policy_envelope_chirho: Option<ReviewPolicyEnvelopeEvidenceChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_record_seq_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_chirho: Option<String>,
    pub diff_chirho: ReviewSurfaceDiffChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn hash_chirho(hex_chirho: &str) -> HashChirho {
        HashChirho(hex_chirho.to_string())
    }

    fn diff_chirho() -> ReviewSurfaceDiffChirho {
        let candidate_chirho =
            hash_chirho("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        ReviewSurfaceDiffChirho {
            app_chirho: "reviewed-app-chirho".to_string(),
            live_chirho: None,
            candidate_chirho,
            price_book_chirho: None,
            live_node_count_chirho: 0,
            candidate_node_count_chirho: 1,
            live_edge_count_chirho: 0,
            candidate_edge_count_chirho: 0,
            added_nodes_chirho: Vec::new(),
            removed_nodes_chirho: Vec::new(),
            added_capabilities_chirho: Vec::new(),
            removed_capabilities_chirho: Vec::new(),
            live_paid_effects_chirho: Vec::new(),
            candidate_paid_effects_chirho: Vec::new(),
            live_cost_token_chirho: 0,
            candidate_cost_token_chirho: 0,
            cost_delta_token_chirho: 0,
            warnings_chirho: Vec::new(),
        }
    }

    #[test]
    fn review_decision_serialization_stays_stable_chirho() {
        assert_eq!(
            serde_json::to_value(ReviewDecisionChirho::PromoteChirho).unwrap(),
            serde_json::json!("PromoteChirho")
        );
        assert_eq!(
            serde_json::to_value(ReviewDecisionChirho::RejectChirho).unwrap(),
            serde_json::json!("RejectChirho")
        );
    }

    #[test]
    fn review_record_omits_legacy_empty_schema_and_optional_fields_chirho() {
        let candidate_chirho =
            hash_chirho("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let record_chirho = ReviewRecordChirho {
            seq_chirho: 0,
            schema_chirho: String::new(),
            app_chirho: "reviewed-app-chirho".to_string(),
            owner_principal_chirho: "owner/reviewer-chirho".to_string(),
            live_before_chirho: None,
            candidate_chirho,
            source_review_report_chirho: None,
            source_manifest_chirho: None,
            decision_chirho: ReviewDecisionChirho::RejectChirho,
            accepted_capability_escalation_chirho: false,
            accepted_cost_increase_chirho: false,
            review_policy_envelope_chirho: None,
            app_record_seq_chirho: None,
            reason_chirho: None,
            diff_chirho: diff_chirho(),
            at_ms_chirho: 1,
            sig_chirho: "sig-chirho".to_string(),
        };
        let value_chirho = serde_json::to_value(record_chirho).unwrap();
        assert!(value_chirho.get("schema_chirho").is_none());
        assert!(value_chirho.get("source_review_report_chirho").is_none());
        assert!(value_chirho.get("source_manifest_chirho").is_none());
        assert!(value_chirho.get("review_policy_envelope_chirho").is_none());
        assert!(value_chirho.get("app_record_seq_chirho").is_none());
        assert!(value_chirho.get("reason_chirho").is_none());
    }

    #[test]
    fn review_source_manifest_evidence_omits_missing_raw_hash_chirho() {
        let evidence_chirho = ReviewSourceManifestEvidenceChirho {
            effective_manifest_hash_chirho: hash_chirho(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
            raw_manifest_hash_chirho: None,
        };
        let value_chirho = serde_json::to_value(evidence_chirho).unwrap();
        assert!(value_chirho.get("raw_manifest_hash_chirho").is_none());
    }

    #[test]
    fn review_policy_envelope_record_serialization_stays_stable_chirho() {
        let record_chirho = ReviewPolicyEnvelopeRecordChirho {
            seq_chirho: 0,
            schema_chirho: REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO.to_string(),
            app_chirho: "reviewed-app-chirho".to_string(),
            scope_chirho: ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
                owner_principal_chirho: "owner/reviewer-chirho".to_string(),
            },
            allowed_capability_labels_chirho: vec!["write-store:orders-chirho".to_string()],
            max_candidate_cost_token_chirho: 5,
            allowed_contract_refs_chirho: vec![format!("blessed-contract:{}", "a".repeat(64))],
            at_ms_chirho: 7,
            sig_chirho: "sig-chirho".to_string(),
        };

        assert_eq!(
            serde_json::to_string(&record_chirho).unwrap(),
            format!(
                "{{\"seq_chirho\":0,\"schema_chirho\":\"review-policy-envelope-v1-chirho\",\"app_chirho\":\"reviewed-app-chirho\",\"scope_chirho\":{{\"kind_chirho\":\"OwnerPrincipalChirho\",\"owner_principal_chirho\":\"owner/reviewer-chirho\"}},\"allowed_capability_labels_chirho\":[\"write-store:orders-chirho\"],\"max_candidate_cost_token_chirho\":5,\"allowed_contract_refs_chirho\":[\"blessed-contract:{}\"],\"at_ms_chirho\":7,\"sig_chirho\":\"sig-chirho\"}}",
                "a".repeat(64)
            )
        );
    }
}
