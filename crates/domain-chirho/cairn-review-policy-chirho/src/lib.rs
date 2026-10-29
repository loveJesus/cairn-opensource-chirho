// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure app-review diff policy.
//!
//! This crate receives already-loaded and already-trusted review surfaces. It does not read a
//! cairn root, verify ownership, validate source evidence, sign records, or append review history.

use anyhow::{anyhow, Result};
use cairn_app_model_chirho::{
    AppSourceReviewReportChirho, APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO,
    APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO,
};
use cairn_capability_chirho::capability_plain_chirho;
use cairn_core_chirho::model_chirho::{CapabilityChirho, HashChirho};
use cairn_model_app_chirho as cairn_app_model_chirho;
pub use cairn_model_review_chirho::{
    ReviewPaidEffectCostChirho, ReviewPolicyEnvelopeRecordChirho, ReviewPolicyEnvelopeScopeChirho,
    ReviewSourceManifestEvidenceChirho, ReviewSurfaceDiffChirho,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReviewDagSurfaceChirho {
    pub node_count_chirho: usize,
    pub edge_count_chirho: usize,
    pub nodes_chirho: BTreeSet<HashChirho>,
    pub capabilities_chirho: BTreeMap<String, u64>,
    pub paid_effect_counts_chirho: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewResolvedPriceChirho {
    pub unit_cost_token_chirho: i64,
    pub source_chirho: String,
}

pub struct ReviewSurfaceDiffInputChirho<'a> {
    pub app_chirho: &'a str,
    pub live_chirho: Option<HashChirho>,
    pub candidate_chirho: HashChirho,
    pub price_book_chirho: Option<HashChirho>,
    pub live_summary_chirho: Option<&'a ReviewDagSurfaceChirho>,
    pub candidate_summary_chirho: &'a ReviewDagSurfaceChirho,
    pub live_prices_chirho: &'a BTreeMap<String, ReviewResolvedPriceChirho>,
    pub candidate_prices_chirho: &'a BTreeMap<String, ReviewResolvedPriceChirho>,
    pub warnings_chirho: Vec<String>,
}

pub struct ReviewLoadedSourceReportChirho<'a> {
    pub source_review_report_chirho: &'a HashChirho,
    pub canonical_hash_chirho: &'a HashChirho,
    pub report_chirho: &'a AppSourceReviewReportChirho,
}

pub struct ReviewSourceEvidenceBindingInputChirho<'a> {
    pub candidate_chirho: &'a HashChirho,
    pub diff_chirho: &'a ReviewSurfaceDiffChirho,
    pub source_review_report_chirho: Option<ReviewLoadedSourceReportChirho<'a>>,
    pub source_manifest_chirho: Option<&'a ReviewSourceManifestEvidenceChirho>,
}

pub struct ReviewPolicyEnvelopeCheckInputChirho<'a> {
    pub envelope_chirho: &'a ReviewPolicyEnvelopeRecordChirho,
    pub app_chirho: &'a str,
    pub owner_principal_chirho: &'a str,
    pub candidate_capability_labels_chirho: &'a BTreeSet<String>,
    pub candidate_cost_token_chirho: i64,
    pub candidate_contract_refs_chirho: &'a BTreeSet<String>,
}

pub fn review_surface_diff_chirho(
    input_chirho: ReviewSurfaceDiffInputChirho<'_>,
) -> Result<ReviewSurfaceDiffChirho> {
    let live_nodes_chirho = input_chirho
        .live_summary_chirho
        .map(|summary_chirho| summary_chirho.nodes_chirho.clone())
        .unwrap_or_default();
    let live_caps_chirho = input_chirho
        .live_summary_chirho
        .map(|summary_chirho| summary_chirho.capabilities_chirho.clone())
        .unwrap_or_default();
    let live_paid_chirho = input_chirho
        .live_summary_chirho
        .map(|summary_chirho| summary_chirho.paid_effect_counts_chirho.clone())
        .unwrap_or_default();

    let added_nodes_chirho = sorted_set_difference_chirho(
        &input_chirho.candidate_summary_chirho.nodes_chirho,
        &live_nodes_chirho,
    );
    let removed_nodes_chirho = sorted_set_difference_chirho(
        &live_nodes_chirho,
        &input_chirho.candidate_summary_chirho.nodes_chirho,
    );
    let added_capabilities_chirho = sorted_count_difference_chirho(
        &input_chirho.candidate_summary_chirho.capabilities_chirho,
        &live_caps_chirho,
    );
    let removed_capabilities_chirho = sorted_count_difference_chirho(
        &live_caps_chirho,
        &input_chirho.candidate_summary_chirho.capabilities_chirho,
    );
    let (live_paid_effects_chirho, live_cost_token_chirho) =
        paid_effect_costs_chirho(&live_paid_chirho, input_chirho.live_prices_chirho)?;
    let (candidate_paid_effects_chirho, candidate_cost_token_chirho) = paid_effect_costs_chirho(
        &input_chirho
            .candidate_summary_chirho
            .paid_effect_counts_chirho,
        input_chirho.candidate_prices_chirho,
    )?;

    Ok(ReviewSurfaceDiffChirho {
        app_chirho: input_chirho.app_chirho.to_string(),
        live_chirho: input_chirho.live_chirho,
        candidate_chirho: input_chirho.candidate_chirho,
        price_book_chirho: input_chirho.price_book_chirho,
        live_node_count_chirho: input_chirho
            .live_summary_chirho
            .map(|summary_chirho| summary_chirho.node_count_chirho)
            .unwrap_or(0),
        candidate_node_count_chirho: input_chirho.candidate_summary_chirho.node_count_chirho,
        live_edge_count_chirho: input_chirho
            .live_summary_chirho
            .map(|summary_chirho| summary_chirho.edge_count_chirho)
            .unwrap_or(0),
        candidate_edge_count_chirho: input_chirho.candidate_summary_chirho.edge_count_chirho,
        added_nodes_chirho,
        removed_nodes_chirho,
        added_capabilities_chirho,
        removed_capabilities_chirho,
        live_paid_effects_chirho,
        candidate_paid_effects_chirho,
        live_cost_token_chirho,
        candidate_cost_token_chirho,
        cost_delta_token_chirho: candidate_cost_token_chirho - live_cost_token_chirho,
        warnings_chirho: input_chirho.warnings_chirho,
    })
}

pub fn validate_review_policy_envelope_shape_chirho(
    envelope_chirho: &ReviewPolicyEnvelopeRecordChirho,
) -> Result<()> {
    if envelope_chirho.app_chirho.trim().is_empty()
        || envelope_chirho.app_chirho.contains('/')
        || envelope_chirho.app_chirho.chars().any(char::is_whitespace)
    {
        anyhow::bail!("review-policy envelope app_chirho is invalid");
    }
    match &envelope_chirho.scope_chirho {
        ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
            owner_principal_chirho,
        } => {
            if !owner_principal_chirho.starts_with("owner/")
                || owner_principal_chirho.chars().any(char::is_whitespace)
            {
                anyhow::bail!("review-policy envelope owner principal is invalid");
            }
        }
    }
    if envelope_chirho.max_candidate_cost_token_chirho < 0 {
        anyhow::bail!("review-policy envelope max candidate cost must not be negative");
    }
    let mut caps_chirho = BTreeSet::new();
    for cap_chirho in &envelope_chirho.allowed_capability_labels_chirho {
        if cap_chirho.trim().is_empty() {
            anyhow::bail!("review-policy envelope capability label must not be empty");
        }
        if !caps_chirho.insert(cap_chirho) {
            anyhow::bail!("review-policy envelope capability label duplicated: {cap_chirho}");
        }
    }
    let mut refs_chirho = BTreeSet::new();
    for contract_ref_chirho in &envelope_chirho.allowed_contract_refs_chirho {
        validate_review_policy_contract_ref_chirho(contract_ref_chirho)?;
        if !refs_chirho.insert(contract_ref_chirho) {
            anyhow::bail!("review-policy envelope contract ref duplicated: {contract_ref_chirho}");
        }
    }
    Ok(())
}

pub fn validate_review_policy_contract_ref_chirho(contract_ref_chirho: &str) -> Result<()> {
    let Some(hex_chirho) = contract_ref_chirho.strip_prefix("blessed-contract:") else {
        anyhow::bail!(
            "review-policy contract ref '{contract_ref_chirho}' must use blessed-contract:<64-hex>"
        );
    };
    if hex_chirho.len() != 64
        || !hex_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_hexdigit())
    {
        anyhow::bail!(
            "review-policy contract ref '{contract_ref_chirho}' must use blessed-contract:<64-hex>"
        );
    }
    Ok(())
}

pub fn enforce_review_policy_envelope_chirho(
    input_chirho: ReviewPolicyEnvelopeCheckInputChirho<'_>,
) -> Result<()> {
    validate_review_policy_envelope_shape_chirho(input_chirho.envelope_chirho)?;
    if input_chirho.envelope_chirho.app_chirho != input_chirho.app_chirho {
        anyhow::bail!(
            "review-policy envelope app bound '{}' does not match candidate app '{}'",
            input_chirho.envelope_chirho.app_chirho,
            input_chirho.app_chirho
        );
    }
    match &input_chirho.envelope_chirho.scope_chirho {
        ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
            owner_principal_chirho,
        } if owner_principal_chirho == input_chirho.owner_principal_chirho => {}
        ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
            owner_principal_chirho,
        } => anyhow::bail!(
            "review-policy envelope owner bound '{}' does not match candidate owner '{}'",
            owner_principal_chirho,
            input_chirho.owner_principal_chirho
        ),
    }

    let allowed_caps_chirho = input_chirho
        .envelope_chirho
        .allowed_capability_labels_chirho
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for capability_chirho in input_chirho.candidate_capability_labels_chirho {
        if !allowed_caps_chirho.contains(capability_chirho) {
            anyhow::bail!("review-policy envelope capability bound blocks {capability_chirho}");
        }
    }
    if input_chirho.candidate_cost_token_chirho
        > input_chirho.envelope_chirho.max_candidate_cost_token_chirho
    {
        anyhow::bail!(
            "review-policy envelope cost bound max={} candidate={}",
            input_chirho.envelope_chirho.max_candidate_cost_token_chirho,
            input_chirho.candidate_cost_token_chirho
        );
    }

    let allowed_refs_chirho = input_chirho
        .envelope_chirho
        .allowed_contract_refs_chirho
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !allowed_refs_chirho.is_empty() && input_chirho.candidate_contract_refs_chirho.is_empty() {
        anyhow::bail!(
            "review-policy envelope contract-ref bound requires source evidence contract refs"
        );
    }
    for contract_ref_chirho in input_chirho.candidate_contract_refs_chirho {
        if !allowed_refs_chirho.contains(contract_ref_chirho) {
            anyhow::bail!("review-policy envelope contract-ref bound blocks {contract_ref_chirho}");
        }
    }
    Ok(())
}

pub fn app_source_review_steward_body_chirho(
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<String> {
    let mut lines_chirho = vec![
        format!("app={}", report_chirho.candidate_chirho.app_chirho),
        "steward powers".to_string(),
    ];
    let cards_chirho = capability_plain_chirho::learner_catalog_cards_chirho();
    for contract_ref_chirho in &report_chirho.candidate_chirho.contract_refs_chirho {
        match cards_chirho
            .iter()
            .find(|card_chirho| &card_chirho.contract_ref_chirho == contract_ref_chirho)
        {
            Some(card_chirho) => {
                lines_chirho.push(format!("card={}", card_chirho.id_chirho));
                lines_chirho.push(format!("power={}", card_chirho.power_body_chirho));
            }
            None => lines_chirho.push(
                "card=(custom reviewed blessed contract; details available in the technical report)"
                    .to_string(),
            ),
        }
    }
    for cap_chirho in &report_chirho.review_chirho.added_capabilities_chirho {
        lines_chirho.push(format!("power={}", steward_power_body_chirho(cap_chirho)));
    }
    let body_chirho = lines_chirho.join("\n");
    ensure_steward_body_has_no_raw_tokens_chirho(&body_chirho)?;
    Ok(body_chirho)
}

fn steward_power_body_chirho(capability_label_chirho: &str) -> String {
    match capability_plain_chirho::describe_review_capability_label_with_dictionary_chirho(
        capability_label_chirho,
    ) {
        Some(line_chirho) => format!(
            "form={}\tcategory={}\tplain={}",
            line_chirho.form_id_chirho, line_chirho.category_chirho, line_chirho.plain_chirho
        ),
        None => {
            "form=(missing)\tcategory=(unknown)\tplain=(capability is not in the steward dictionary)"
                .to_string()
        }
    }
}

fn ensure_steward_body_has_no_raw_tokens_chirho(body_chirho: &str) -> Result<()> {
    for forbidden_chirho in [
        "WriteStoreChirho(",
        "ReadStoreChirho(",
        "QueryChirho(",
        "PaidEffectChirho(",
        "TemplateAppDeployChirho(",
        "NetChirho(",
        "InvokeChirho(",
        "blessed-contract:",
    ] {
        if body_chirho.contains(forbidden_chirho) {
            anyhow::bail!("steward view leaked raw token {forbidden_chirho}");
        }
    }
    if body_chirho
        .split(|c_chirho: char| !c_chirho.is_ascii_alphanumeric())
        .any(|part_chirho| {
            part_chirho.len() == 64
                && part_chirho
                    .chars()
                    .all(|c_chirho| c_chirho.is_ascii_hexdigit())
        })
    {
        anyhow::bail!("steward view leaked a bare 64-hex token");
    }
    Ok(())
}

pub fn canonical_app_source_review_report_chirho(
    report_chirho: &AppSourceReviewReportChirho,
) -> AppSourceReviewReportChirho {
    let mut canonical_chirho = report_chirho.clone();
    canonical_chirho.source_review_report_chirho = None;
    canonical_chirho
}

pub fn validate_app_source_review_report_schema_chirho(
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<()> {
    if !report_chirho.schema_chirho.is_empty()
        && report_chirho.schema_chirho != APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO
    {
        anyhow::bail!(
            "unsupported app source review report schema '{}'",
            report_chirho.schema_chirho
        );
    }
    if !report_chirho.candidate_chirho.schema_chirho.is_empty()
        && report_chirho.candidate_chirho.schema_chirho != APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO
    {
        anyhow::bail!(
            "unsupported app source candidate report schema '{}'",
            report_chirho.candidate_chirho.schema_chirho
        );
    }
    Ok(())
}

pub fn validate_review_source_evidence_binding_chirho(
    input_chirho: ReviewSourceEvidenceBindingInputChirho<'_>,
) -> Result<Option<ReviewSourceManifestEvidenceChirho>> {
    let Some(source_review_report_chirho) = input_chirho.source_review_report_chirho else {
        return Ok(None);
    };
    validate_app_source_review_report_schema_chirho(source_review_report_chirho.report_chirho)?;
    if source_review_report_chirho.canonical_hash_chirho
        != source_review_report_chirho.source_review_report_chirho
    {
        anyhow::bail!(
            "review source report hash mismatch: record points at {}, canonical hash is {}",
            source_review_report_chirho.source_review_report_chirho.0,
            source_review_report_chirho.canonical_hash_chirho.0
        );
    }
    if source_review_report_chirho
        .report_chirho
        .candidate_chirho
        .root_dag_chirho
        != *input_chirho.candidate_chirho
        || source_review_report_chirho
            .report_chirho
            .review_chirho
            .candidate_chirho
            != *input_chirho.candidate_chirho
    {
        anyhow::bail!("review source report candidate does not match signed review record");
    }
    if source_review_report_chirho.report_chirho.review_chirho != *input_chirho.diff_chirho {
        anyhow::bail!("review source report diff does not match signed review record");
    }
    let report_source_manifest_chirho = source_review_report_chirho
        .report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .as_ref()
        .map(
            |source_manifest_chirho| ReviewSourceManifestEvidenceChirho {
                effective_manifest_hash_chirho: source_manifest_chirho
                    .effective_manifest_hash_chirho
                    .clone(),
                raw_manifest_hash_chirho: source_manifest_chirho.raw_manifest_hash_chirho.clone(),
            },
        );
    if let (Some(report_source_manifest_chirho), Some(source_manifest_chirho)) = (
        &report_source_manifest_chirho,
        input_chirho.source_manifest_chirho,
    ) {
        if report_source_manifest_chirho != source_manifest_chirho {
            anyhow::bail!(
                "review source manifest evidence does not match bound source review report"
            );
        }
    }
    Ok(report_source_manifest_chirho)
}

fn paid_effect_costs_chirho(
    counts_chirho: &BTreeMap<String, u64>,
    prices_chirho: &BTreeMap<String, ReviewResolvedPriceChirho>,
) -> Result<(Vec<ReviewPaidEffectCostChirho>, i64)> {
    let mut out_chirho = Vec::new();
    let mut total_chirho = 0_i64;
    for (effect_chirho, count_chirho) in counts_chirho {
        let price_chirho = prices_chirho
            .get(effect_chirho)
            .ok_or_else(|| anyhow!("review price missing for paid effect '{effect_chirho}'"))?;
        let total_cost_token_chirho = price_chirho
            .unit_cost_token_chirho
            .checked_mul(*count_chirho as i64)
            .ok_or_else(|| anyhow!("review cost total overflow"))?;
        total_chirho = total_chirho
            .checked_add(total_cost_token_chirho)
            .ok_or_else(|| anyhow!("review cost total overflow"))?;
        out_chirho.push(ReviewPaidEffectCostChirho {
            effect_chirho: effect_chirho.clone(),
            count_chirho: *count_chirho,
            unit_cost_token_chirho: price_chirho.unit_cost_token_chirho,
            total_cost_token_chirho,
            source_chirho: price_chirho.source_chirho.clone(),
        });
    }
    Ok((out_chirho, total_chirho))
}

fn sorted_set_difference_chirho(
    left_chirho: &BTreeSet<HashChirho>,
    right_chirho: &BTreeSet<HashChirho>,
) -> Vec<HashChirho> {
    left_chirho.difference(right_chirho).cloned().collect()
}

fn sorted_count_difference_chirho(
    left_chirho: &BTreeMap<String, u64>,
    right_chirho: &BTreeMap<String, u64>,
) -> Vec<String> {
    let mut out_chirho = Vec::new();
    for (label_chirho, left_count_chirho) in left_chirho {
        let right_count_chirho = right_chirho.get(label_chirho).copied().unwrap_or(0);
        if *left_count_chirho <= right_count_chirho {
            continue;
        }
        for _ in 0..(*left_count_chirho - right_count_chirho) {
            out_chirho.push(label_chirho.clone());
        }
    }
    out_chirho
}

pub fn review_capability_label_chirho(capability_chirho: &CapabilityChirho) -> String {
    match capability_chirho {
        CapabilityChirho::ReadStoreChirho { prefix_chirho } => {
            format!("ReadStoreChirho(prefix={prefix_chirho})")
        }
        CapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            format!("WriteStoreChirho(prefix={prefix_chirho})")
        }
        CapabilityChirho::PaidEffectChirho {
            effect_chirho,
            caller_chirho,
        } => format!("PaidEffectChirho(effect={effect_chirho},caller={caller_chirho})"),
        CapabilityChirho::UserIdentityChirho {
            principal_chirho,
            client_id_chirho,
            token_hash_chirho,
        } => format!(
            "UserIdentityChirho(principal={principal_chirho},client={client_id_chirho},token={token_hash_chirho})"
        ),
        CapabilityChirho::AppContextChirho {
            app_chirho,
            owner_principal_chirho,
            price_book_chirho,
            billing_policy_chirho,
        } => format!(
            "AppContextChirho(app={app_chirho},owner={owner_principal_chirho},pricebook={},billing={})",
            price_book_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.as_str())
                .unwrap_or("none"),
            billing_policy_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.as_str())
                .unwrap_or("none")
        ),
        CapabilityChirho::SecretRefChirho { name_chirho } => {
            format!("SecretRefChirho(name={name_chirho})")
        }
        CapabilityChirho::RealtimeSessionChirho {
            app_chirho,
            caller_chirho,
        } => format!("RealtimeSessionChirho(app={app_chirho},caller={caller_chirho})"),
        CapabilityChirho::SupportIssueChirho {
            issue_chirho,
            actions_chirho,
        } => format!(
            "SupportIssueChirho(issue={issue_chirho},actions={})",
            actions_chirho.join(",")
        ),
        CapabilityChirho::CausalReversionChirho { branch_chirho } => {
            format!("CausalReversionChirho(branch={branch_chirho})")
        }
        CapabilityChirho::NetChirho { allowlist_chirho } => {
            format!("NetChirho(allowlist={})", allowlist_chirho.join(","))
        }
        CapabilityChirho::QueryChirho {
            prefix_chirho,
            caller_chirho,
            max_rows_chirho,
        } => format!(
            "QueryChirho(prefix={prefix_chirho},caller={caller_chirho},max_rows={max_rows_chirho})"
        ),
        CapabilityChirho::ClockChirho => "ClockChirho".to_string(),
        CapabilityChirho::RandomChirho => "RandomChirho".to_string(),
        CapabilityChirho::InvokeChirho { node_chirho } => {
            format!("InvokeChirho(node={})", node_chirho.0)
        }
        CapabilityChirho::TemplateAppDeployChirho { template_id_chirho } => {
            format!("TemplateAppDeployChirho(template={template_id_chirho})")
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_model_app_chirho::{AppSourceCandidateReportChirho, AppSourceManifestEvidenceChirho};
    use cairn_model_review_chirho::REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO;

    fn hash_chirho(label_chirho: &str) -> HashChirho {
        HashChirho(label_chirho.to_string())
    }

    fn envelope_chirho() -> ReviewPolicyEnvelopeRecordChirho {
        ReviewPolicyEnvelopeRecordChirho {
            seq_chirho: 0,
            schema_chirho: REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO.to_string(),
            app_chirho: "review-app-chirho".to_string(),
            scope_chirho: ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
                owner_principal_chirho: "owner/review-chirho".to_string(),
            },
            allowed_capability_labels_chirho: vec!["ClockChirho".to_string()],
            max_candidate_cost_token_chirho: 5,
            allowed_contract_refs_chirho: Vec::new(),
            at_ms_chirho: 7,
            sig_chirho: "sig-chirho".to_string(),
        }
    }

    fn hash64_chirho(label_chirho: &str) -> HashChirho {
        HashChirho(format!("{label_chirho:0<64}").chars().take(64).collect())
    }

    fn review_report_with_cap_and_ref_chirho(
        capability_label_chirho: &str,
        contract_ref_chirho: &str,
    ) -> AppSourceReviewReportChirho {
        AppSourceReviewReportChirho {
            schema_chirho: String::new(),
            source_review_report_chirho: None,
            candidate_chirho: AppSourceCandidateReportChirho {
                schema_chirho: String::new(),
                source_manifest_chirho: None,
                app_chirho: "learner-app-chirho".to_string(),
                owner_chirho: "owner/learner-chirho".to_string(),
                request_access_policy_chirho: None,
                nodes_chirho: Vec::new(),
                dags_chirho: Vec::new(),
                modules_chirho: Vec::new(),
                assets_chirho: Vec::new(),
                contract_refs_chirho: vec![contract_ref_chirho.to_string()],
                undo_plan_bindings_chirho: None,
                root_dag_chirho: hash64_chirho("candidate"),
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                routes_chirho: Vec::new(),
            },
            review_chirho: ReviewSurfaceDiffChirho {
                app_chirho: "learner-app-chirho".to_string(),
                live_chirho: None,
                candidate_chirho: hash64_chirho("candidate"),
                price_book_chirho: None,
                live_node_count_chirho: 0,
                candidate_node_count_chirho: 1,
                live_edge_count_chirho: 0,
                candidate_edge_count_chirho: 0,
                added_nodes_chirho: Vec::new(),
                removed_nodes_chirho: Vec::new(),
                added_capabilities_chirho: vec![capability_label_chirho.to_string()],
                removed_capabilities_chirho: Vec::new(),
                live_paid_effects_chirho: Vec::new(),
                candidate_paid_effects_chirho: Vec::new(),
                live_cost_token_chirho: 0,
                candidate_cost_token_chirho: 0,
                cost_delta_token_chirho: 0,
                warnings_chirho: Vec::new(),
            },
            non_authoritative_chirho: true,
        }
    }

    #[test]
    fn steward_view_hides_raw_capability_grammar_chirho() {
        let report_chirho = review_report_with_cap_and_ref_chirho(
            "WriteStoreChirho(prefix=public,x=victim)",
            "blessed-contract:614d12abeb18b308dd4ad0c9d4464d5d9112dc6efef2af2e3ee14e86d692b735",
        );
        let body_chirho = app_source_review_steward_body_chirho(&report_chirho).unwrap();
        assert!(!body_chirho.contains("WriteStoreChirho("));
        assert!(!body_chirho.contains("public,x=victim"));
        assert!(body_chirho.contains("capability is not in the steward dictionary"));
    }

    #[test]
    fn steward_view_hides_bare_contract_hashes_chirho() {
        let report_chirho = review_report_with_cap_and_ref_chirho(
            "WriteStoreChirho(prefix=classroom-submissions-chirho)",
            "blessed-contract:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let body_chirho = app_source_review_steward_body_chirho(&report_chirho).unwrap();
        assert!(!body_chirho
            .contains("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        assert!(!body_chirho.contains("blessed-contract:"));
        assert!(body_chirho.contains("custom reviewed blessed contract"));
    }

    #[test]
    fn review_diff_policy_is_sorted_and_sums_resolved_prices_chirho() {
        let live_a_chirho =
            hash_chirho("1111111111111111111111111111111111111111111111111111111111111111");
        let live_b_chirho =
            hash_chirho("2222222222222222222222222222222222222222222222222222222222222222");
        let candidate_c_chirho =
            hash_chirho("3333333333333333333333333333333333333333333333333333333333333333");
        let candidate_d_chirho =
            hash_chirho("4444444444444444444444444444444444444444444444444444444444444444");
        let live_summary_chirho = ReviewDagSurfaceChirho {
            node_count_chirho: 2,
            edge_count_chirho: 1,
            nodes_chirho: BTreeSet::from([live_a_chirho.clone(), live_b_chirho.clone()]),
            capabilities_chirho: BTreeMap::from([
                ("ClockChirho".to_string(), 1),
                (
                    "PaidEffectChirho(effect=email,caller=owner/a)".to_string(),
                    1,
                ),
            ]),
            paid_effect_counts_chirho: BTreeMap::from([("email".to_string(), 1)]),
        };
        let candidate_summary_chirho = ReviewDagSurfaceChirho {
            node_count_chirho: 3,
            edge_count_chirho: 2,
            nodes_chirho: BTreeSet::from([
                live_b_chirho,
                candidate_c_chirho.clone(),
                candidate_d_chirho.clone(),
            ]),
            capabilities_chirho: BTreeMap::from([
                ("ClockChirho".to_string(), 1),
                ("NetChirho(allowlist=https://api.example)".to_string(), 1),
                (
                    "PaidEffectChirho(effect=email,caller=owner/a)".to_string(),
                    2,
                ),
            ]),
            paid_effect_counts_chirho: BTreeMap::from([("email".to_string(), 2)]),
        };
        let live_prices_chirho = BTreeMap::from([(
            "email".to_string(),
            ReviewResolvedPriceChirho {
                unit_cost_token_chirho: 7,
                source_chirho: "pricebook:live".to_string(),
            },
        )]);
        let candidate_prices_chirho = BTreeMap::from([(
            "email".to_string(),
            ReviewResolvedPriceChirho {
                unit_cost_token_chirho: 11,
                source_chirho: "pricebook:candidate".to_string(),
            },
        )]);

        let diff_chirho = review_surface_diff_chirho(ReviewSurfaceDiffInputChirho {
            app_chirho: "mail-app-chirho",
            live_chirho: Some(hash_chirho(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
            candidate_chirho: hash_chirho(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            price_book_chirho: Some(hash_chirho(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )),
            live_summary_chirho: Some(&live_summary_chirho),
            candidate_summary_chirho: &candidate_summary_chirho,
            live_prices_chirho: &live_prices_chirho,
            candidate_prices_chirho: &candidate_prices_chirho,
            warnings_chirho: vec!["carry-root-warning-chirho".to_string()],
        })
        .unwrap();

        assert_eq!(
            diff_chirho.added_nodes_chirho,
            vec![candidate_c_chirho, candidate_d_chirho]
        );
        assert_eq!(diff_chirho.removed_nodes_chirho, vec![live_a_chirho]);
        assert_eq!(
            diff_chirho.added_capabilities_chirho,
            vec![
                "NetChirho(allowlist=https://api.example)".to_string(),
                "PaidEffectChirho(effect=email,caller=owner/a)".to_string()
            ]
        );
        assert!(diff_chirho.removed_capabilities_chirho.is_empty());
        assert_eq!(diff_chirho.live_cost_token_chirho, 7);
        assert_eq!(diff_chirho.candidate_cost_token_chirho, 22);
        assert_eq!(diff_chirho.cost_delta_token_chirho, 15);
        assert_eq!(
            diff_chirho.warnings_chirho,
            vec!["carry-root-warning-chirho".to_string()]
        );
        assert_eq!(
            diff_chirho.live_paid_effects_chirho[0].source_chirho,
            "pricebook:live"
        );
        assert_eq!(
            diff_chirho.candidate_paid_effects_chirho[0].source_chirho,
            "pricebook:candidate"
        );
    }

    #[test]
    fn review_capability_labels_are_stable_chirho() {
        assert_eq!(
            review_capability_label_chirho(&CapabilityChirho::QueryChirho {
                prefix_chirho: "contacts".to_string(),
                caller_chirho: "owner/demo".to_string(),
                max_rows_chirho: 10,
            }),
            "QueryChirho(prefix=contacts,caller=owner/demo,max_rows=10)"
        );
        assert_eq!(
            review_capability_label_chirho(&CapabilityChirho::TemplateAppDeployChirho {
                template_id_chirho: "starter-chirho".to_string(),
            }),
            "TemplateAppDeployChirho(template=starter-chirho)"
        );
    }

    #[test]
    fn review_policy_envelope_allows_declared_capability_and_cost_chirho() {
        enforce_review_policy_envelope_chirho(ReviewPolicyEnvelopeCheckInputChirho {
            envelope_chirho: &envelope_chirho(),
            app_chirho: "review-app-chirho",
            owner_principal_chirho: "owner/review-chirho",
            candidate_capability_labels_chirho: &BTreeSet::from(["ClockChirho".to_string()]),
            candidate_cost_token_chirho: 5,
            candidate_contract_refs_chirho: &BTreeSet::new(),
        })
        .unwrap();
    }

    #[test]
    fn review_policy_envelope_contract_refs_fail_closed_until_source_evidence_chirho() {
        let mut envelope_chirho = envelope_chirho();
        envelope_chirho.allowed_contract_refs_chirho =
            vec![format!("blessed-contract:{}", "a".repeat(64))];

        let error_chirho =
            enforce_review_policy_envelope_chirho(ReviewPolicyEnvelopeCheckInputChirho {
                envelope_chirho: &envelope_chirho,
                app_chirho: "review-app-chirho",
                owner_principal_chirho: "owner/review-chirho",
                candidate_capability_labels_chirho: &BTreeSet::from(["ClockChirho".to_string()]),
                candidate_cost_token_chirho: 5,
                candidate_contract_refs_chirho: &BTreeSet::new(),
            })
            .unwrap_err()
            .to_string();

        assert!(error_chirho.contains("contract-ref bound requires source evidence"));
    }

    #[test]
    fn review_policy_envelope_contract_refs_are_subset_checked_chirho() {
        let allowed_chirho = format!("blessed-contract:{}", "a".repeat(64));
        let unused_chirho = format!("blessed-contract:{}", "b".repeat(64));
        let outside_chirho = format!("blessed-contract:{}", "c".repeat(64));
        let mut envelope_chirho = envelope_chirho();
        envelope_chirho.allowed_contract_refs_chirho =
            vec![allowed_chirho.clone(), unused_chirho.clone()];
        let mut candidate_refs_chirho = BTreeSet::new();
        candidate_refs_chirho.insert(allowed_chirho.clone());

        enforce_review_policy_envelope_chirho(ReviewPolicyEnvelopeCheckInputChirho {
            envelope_chirho: &envelope_chirho,
            app_chirho: "review-app-chirho",
            owner_principal_chirho: "owner/review-chirho",
            candidate_capability_labels_chirho: &BTreeSet::new(),
            candidate_cost_token_chirho: 5,
            candidate_contract_refs_chirho: &candidate_refs_chirho,
        })
        .unwrap();

        candidate_refs_chirho.insert(outside_chirho.clone());
        let error_chirho =
            enforce_review_policy_envelope_chirho(ReviewPolicyEnvelopeCheckInputChirho {
                envelope_chirho: &envelope_chirho,
                app_chirho: "review-app-chirho",
                owner_principal_chirho: "owner/review-chirho",
                candidate_capability_labels_chirho: &BTreeSet::new(),
                candidate_cost_token_chirho: 5,
                candidate_contract_refs_chirho: &candidate_refs_chirho,
            })
            .unwrap_err()
            .to_string();

        assert!(error_chirho.contains(&outside_chirho));
    }

    #[test]
    fn source_review_report_canonicalization_clears_self_hash_chirho() {
        let report_chirho = AppSourceReviewReportChirho {
            schema_chirho: APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO.to_string(),
            source_review_report_chirho: Some(hash_chirho(
                "9999999999999999999999999999999999999999999999999999999999999999",
            )),
            candidate_chirho: AppSourceCandidateReportChirho {
                schema_chirho: APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO.to_string(),
                source_manifest_chirho: None,
                app_chirho: "review-app-chirho".to_string(),
                owner_chirho: "owner/review-chirho".to_string(),
                request_access_policy_chirho: None,
                nodes_chirho: Vec::new(),
                dags_chirho: Vec::new(),
                modules_chirho: Vec::new(),
                assets_chirho: Vec::new(),
                contract_refs_chirho: Vec::new(),
                undo_plan_bindings_chirho: None,
                root_dag_chirho: hash_chirho(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                routes_chirho: Vec::new(),
            },
            review_chirho: review_surface_diff_chirho(ReviewSurfaceDiffInputChirho {
                app_chirho: "review-app-chirho",
                live_chirho: None,
                candidate_chirho: hash_chirho(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                price_book_chirho: None,
                live_summary_chirho: None,
                candidate_summary_chirho: &ReviewDagSurfaceChirho::default(),
                live_prices_chirho: &BTreeMap::new(),
                candidate_prices_chirho: &BTreeMap::new(),
                warnings_chirho: Vec::new(),
            })
            .unwrap(),
            non_authoritative_chirho: true,
        };
        let canonical_chirho = canonical_app_source_review_report_chirho(&report_chirho);
        assert!(canonical_chirho.source_review_report_chirho.is_none());
        assert!(report_chirho.source_review_report_chirho.is_some());
    }

    #[test]
    fn source_review_evidence_binding_requires_candidate_and_diff_match_chirho() {
        let candidate_chirho =
            hash_chirho("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let other_candidate_chirho =
            hash_chirho("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let diff_chirho = review_surface_diff_chirho(ReviewSurfaceDiffInputChirho {
            app_chirho: "review-app-chirho",
            live_chirho: None,
            candidate_chirho: candidate_chirho.clone(),
            price_book_chirho: None,
            live_summary_chirho: None,
            candidate_summary_chirho: &ReviewDagSurfaceChirho::default(),
            live_prices_chirho: &BTreeMap::new(),
            candidate_prices_chirho: &BTreeMap::new(),
            warnings_chirho: Vec::new(),
        })
        .unwrap();
        let manifest_evidence_chirho = AppSourceManifestEvidenceChirho {
            effective_manifest_hash_chirho: hash_chirho(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
            raw_manifest_hash_chirho: Some(hash_chirho(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            )),
        };
        let report_chirho = AppSourceReviewReportChirho {
            schema_chirho: APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO.to_string(),
            source_review_report_chirho: None,
            candidate_chirho: AppSourceCandidateReportChirho {
                schema_chirho: APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO.to_string(),
                source_manifest_chirho: Some(manifest_evidence_chirho),
                app_chirho: "review-app-chirho".to_string(),
                owner_chirho: "owner/review-chirho".to_string(),
                request_access_policy_chirho: None,
                nodes_chirho: Vec::new(),
                dags_chirho: Vec::new(),
                modules_chirho: Vec::new(),
                assets_chirho: Vec::new(),
                contract_refs_chirho: Vec::new(),
                undo_plan_bindings_chirho: None,
                root_dag_chirho: candidate_chirho.clone(),
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                routes_chirho: Vec::new(),
            },
            review_chirho: diff_chirho.clone(),
            non_authoritative_chirho: true,
        };
        let source_report_hash_chirho =
            hash_chirho("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let matched_chirho = validate_review_source_evidence_binding_chirho(
            ReviewSourceEvidenceBindingInputChirho {
                candidate_chirho: &candidate_chirho,
                diff_chirho: &diff_chirho,
                source_review_report_chirho: Some(ReviewLoadedSourceReportChirho {
                    source_review_report_chirho: &source_report_hash_chirho,
                    canonical_hash_chirho: &source_report_hash_chirho,
                    report_chirho: &report_chirho,
                }),
                source_manifest_chirho: None,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            matched_chirho.effective_manifest_hash_chirho,
            hash_chirho("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        );

        let error_chirho = validate_review_source_evidence_binding_chirho(
            ReviewSourceEvidenceBindingInputChirho {
                candidate_chirho: &other_candidate_chirho,
                diff_chirho: &diff_chirho,
                source_review_report_chirho: Some(ReviewLoadedSourceReportChirho {
                    source_review_report_chirho: &source_report_hash_chirho,
                    canonical_hash_chirho: &source_report_hash_chirho,
                    report_chirho: &report_chirho,
                }),
                source_manifest_chirho: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("candidate does not match"));
    }
}
