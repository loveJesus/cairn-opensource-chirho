// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Is this plan permitted under the grant this principal actually holds? Answered from durable
//! evidence, and answered by REPORTING.
//!
//! This is the composition the three pieces below were each built for and none of them could do alone:
//!
//! ```text
//! grant_store        -> the CURRENT signed grant for a principal, replay-protected
//! plan_store         -> the plan a digest names, resolved and re-hashed
//! plan_refusals      -> whether that plan fits inside that grant
//! ```
//!
//! Order matters and is not interchangeable. The GRANT is loaded first, because a plan checked against
//! a grant nobody holds is a calculation about nothing; and the plan is RESOLVED before it is checked,
//! because clause 9's whole point is that a hash resolving to nothing is evidence of nothing. Either
//! failing is a refusal with its own identity rather than a permitted-looking empty answer.
//!
//! It applies nothing. There is no path here that provisions, drains, or moves a ref — asking whether
//! a change would be allowed costs no authority, which is what makes it safe to run against a live
//! root.

use super::grant_store_chirho::{
    load_current_verified_grant_chirho, TopologyGrantStoreRefusalChirho,
};
use super::plan_reference_chirho::{
    verify_topology_plan_reference_chirho, TopologyPlanReferenceRefusalChirho,
};
use super::plan_store_chirho::RootPlanResolverChirho;
use cairn_placement_chirho::topology_chirho::topology_grant_attestation_chirho::TopologyGrantAuthorityPortChirho;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::plan_refusals_chirho;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const TOPOLOGY_PLAN_AUTHORITY_REPORT_SCHEMA_V1_CHIRHO: &str =
    "topology-plan-authority-report-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanAuthorityRefusalChirho {
    /// No grant on record for this principal. Distinct from "the plan does not fit": nothing was
    /// checked, because there was no ceiling to check against.
    GrantChirho {
        refusal_chirho: TopologyGrantStoreRefusalChirho,
    },
    /// The plan digest did not resolve, or resolved to something else. Distinct from a plan that
    /// resolved fine and was over its bounds.
    PlanReferenceChirho {
        refusal_chirho: TopologyPlanReferenceRefusalChirho,
    },
    RenderChirho,
}

/// What the durable evidence says about one plan under one principal's grant.
///
/// Node ids, counts and bounds only — no key material, no paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyPlanAuthorityReportChirho {
    pub schema_chirho: String,
    pub principal_chirho: String,
    pub plan_digest_chirho: String,
    pub grant_id_chirho: String,
    pub grant_issued_seq_chirho: u64,
    pub max_nodes_chirho: u32,
    pub planned_nodes_chirho: u32,
    pub max_spend_rate_micros_per_hour_chirho: u64,
    pub planned_spend_rate_micros_per_hour_chirho: u64,
    /// Empty means the plan fits its grant. This is NOT an Option, unlike the placement probe next
    /// door, because here the check is unconditional — you cannot ask this question without asking it.
    pub refusals_chirho: Vec<String>,
    pub permitted_chirho: bool,
}

pub fn build_topology_plan_authority_report_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    plan_digest_chirho: &str,
    authority_chirho: &dyn TopologyGrantAuthorityPortChirho,
) -> Result<TopologyPlanAuthorityReportChirho, PlanAuthorityRefusalChirho> {
    let grant_chirho =
        load_current_verified_grant_chirho(root_chirho, principal_chirho, authority_chirho)
            .map_err(|refusal_chirho| PlanAuthorityRefusalChirho::GrantChirho { refusal_chirho })?;

    let reference_chirho = verify_topology_plan_reference_chirho(
        plan_digest_chirho,
        &RootPlanResolverChirho::new_chirho(root_chirho),
    )
    .map_err(|refusal_chirho| PlanAuthorityRefusalChirho::PlanReferenceChirho { refusal_chirho })?;

    let plan_chirho = reference_chirho.plan_chirho();
    let refusals_chirho = plan_refusals_chirho(plan_chirho, grant_chirho.grant_chirho())
        .into_iter()
        .map(|refusal_chirho| format!("{refusal_chirho:?}"))
        .collect::<Vec<_>>();

    Ok(TopologyPlanAuthorityReportChirho {
        schema_chirho: TOPOLOGY_PLAN_AUTHORITY_REPORT_SCHEMA_V1_CHIRHO.to_string(),
        principal_chirho: principal_chirho.to_string(),
        plan_digest_chirho: plan_digest_chirho.to_string(),
        grant_id_chirho: grant_chirho.grant_chirho().grant_id_chirho.clone(),
        grant_issued_seq_chirho: grant_chirho.issued_seq_chirho(),
        max_nodes_chirho: grant_chirho.grant_chirho().max_nodes_chirho,
        planned_nodes_chirho: plan_chirho.nodes_chirho.len().min(u32::MAX as usize) as u32,
        max_spend_rate_micros_per_hour_chirho: grant_chirho
            .grant_chirho()
            .max_spend_rate_micros_per_hour_chirho,
        planned_spend_rate_micros_per_hour_chirho: plan_chirho.spend_rate_micros_per_hour_chirho,
        permitted_chirho: refusals_chirho.is_empty(),
        refusals_chirho,
    })
}

pub fn render_topology_plan_authority_report_chirho(
    report_chirho: &TopologyPlanAuthorityReportChirho,
) -> Result<String, PlanAuthorityRefusalChirho> {
    serde_json::to_string(report_chirho)
        .map_err(|_error_chirho| PlanAuthorityRefusalChirho::RenderChirho)
}

#[cfg(test)]
#[path = "plan_authority_report_tests_chirho.rs"]
mod plan_authority_report_tests_chirho;
