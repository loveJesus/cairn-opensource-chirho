// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the plan-under-grant report.
//!
//! The pair worth naming is [`no_grant_refuses_differently_from_a_plan_that_does_not_fit_chirho`] and
//! [`an_unresolvable_plan_digest_refuses_differently_from_an_over_bound_plan_chirho`]. Both distinguish
//! NOTHING WAS CHECKED from CHECKED AND REFUSED. Collapsing them would let a missing grant or a
//! dangling plan digest read as a bounds decision, which is the shape of every conflation this repo
//! has paid for.

use super::*;
use crate::topology_chirho::grant_store_chirho::{
    append_verified_topology_grant_chirho, TopologyGrantStoreRefusalChirho,
};
use crate::topology_chirho::plan_store_chirho::store_topology_plan_chirho;
use cairn_placement_chirho::topology_chirho::topology_grant_attestation_chirho::*;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::{
    DesiredTopologyPlanChirho, NodeRoleChirho, PlannedNodeChirho, TopologyGrantChirho,
};

const AUTHORITY_KEY_CHIRHO: &str = "topology-authority-key-chirho";
const PRINCIPAL_CHIRHO: &str = "planner-principal-chirho";

struct AuthorityChirho;

impl TopologyGrantAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        AUTHORITY_KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

fn seed_grant_chirho(root_chirho: &Path, max_nodes_chirho: u32) {
    let intent_chirho = TopologyGrantIntentChirho {
        schema_chirho: TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        principal_chirho: PRINCIPAL_CHIRHO.to_string(),
        grant_chirho: TopologyGrantChirho {
            grant_id_chirho: "grant-a-chirho".to_string(),
            max_nodes_chirho,
            max_spend_rate_micros_per_hour_chirho: 1_000_000,
            allowed_providers_chirho: ["hetzner-chirho".to_string()].into_iter().collect(),
            minimum_control_nodes_chirho: 1,
            minimum_storage_nodes_chirho: 1,
        },
        issued_seq_chirho: 1,
    };
    let digest_chirho = topology_grant_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = TopologyGrantAttestationChirho {
        schema_chirho: TOPOLOGY_GRANT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TOPOLOGY_GRANT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: AUTHORITY_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_topology_grant_message_chirho(&record_chirho)
    );
    append_verified_topology_grant_chirho(root_chirho, &record_chirho, &AuthorityChirho)
        .expect("seed grant");
}

fn plan_chirho(node_count_chirho: usize) -> DesiredTopologyPlanChirho {
    let mut nodes_chirho = vec![
        PlannedNodeChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            role_chirho: NodeRoleChirho::ControlChirho,
        },
        PlannedNodeChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            role_chirho: NodeRoleChirho::StorageChirho,
        },
    ];
    while nodes_chirho.len() < node_count_chirho {
        nodes_chirho.push(PlannedNodeChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            role_chirho: NodeRoleChirho::WorkerChirho,
        });
    }
    DesiredTopologyPlanChirho {
        cited_grant_id_chirho: "grant-a-chirho".to_string(),
        nodes_chirho,
        spend_rate_micros_per_hour_chirho: 500_000,
        proposed_grant_chirho: None,
    }
}

#[test]
fn a_plan_inside_its_grant_reports_permitted_chirho() {
    // Positive control: every refusal arm below would pass against a report that refused everything.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, 10);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &plan_chirho(3)).expect("store plan");

    let report_chirho = build_topology_plan_authority_report_chirho(
        root_chirho,
        PRINCIPAL_CHIRHO,
        &digest_chirho,
        &AuthorityChirho,
    )
    .expect("a lawful plan under a real grant must report");
    assert!(report_chirho.permitted_chirho);
    assert!(report_chirho.refusals_chirho.is_empty());
    assert_eq!(report_chirho.planned_nodes_chirho, 3);
    assert_eq!(report_chirho.max_nodes_chirho, 10);
}

#[test]
fn an_over_bound_plan_reports_the_bound_it_broke_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, 3);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &plan_chirho(9)).expect("store plan");

    let report_chirho = build_topology_plan_authority_report_chirho(
        root_chirho,
        PRINCIPAL_CHIRHO,
        &digest_chirho,
        &AuthorityChirho,
    )
    .expect("an over-bound plan still REPORTS -- refusing to answer would hide the reason");
    assert!(!report_chirho.permitted_chirho);
    assert!(
        report_chirho
            .refusals_chirho
            .iter()
            .any(|refusal_chirho| refusal_chirho.contains("NodeCountOverBoundChirho")),
        "{:?}",
        report_chirho.refusals_chirho
    );
}

#[test]
fn no_grant_refuses_differently_from_a_plan_that_does_not_fit_chirho() {
    // NOTHING WAS CHECKED, versus checked and refused. A missing grant reported as a bounds decision
    // would be the most misleading answer available: it reads as "we looked, and no".
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &plan_chirho(3)).expect("store plan");

    let refusal_chirho = build_topology_plan_authority_report_chirho(
        root_chirho,
        PRINCIPAL_CHIRHO,
        &digest_chirho,
        &AuthorityChirho,
    )
    .expect_err("no grant must refuse");
    assert_eq!(
        refusal_chirho,
        PlanAuthorityRefusalChirho::GrantChirho {
            refusal_chirho: TopologyGrantStoreRefusalChirho::NoGrantForPrincipalChirho {
                principal_chirho: PRINCIPAL_CHIRHO.to_string(),
            },
        }
    );
}

#[test]
fn an_unresolvable_plan_digest_refuses_differently_from_an_over_bound_plan_chirho() {
    // The other half of the same distinction, and clause 9's point: a hash resolving to nothing is
    // evidence of nothing, so it must not come back as a bounds verdict.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, 10);
    let never_stored_chirho = "a".repeat(64);

    let refusal_chirho = build_topology_plan_authority_report_chirho(
        root_chirho,
        PRINCIPAL_CHIRHO,
        &never_stored_chirho,
        &AuthorityChirho,
    )
    .expect_err("an unresolvable digest must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlanAuthorityRefusalChirho::PlanReferenceChirho { .. }
        ),
        "{refusal_chirho:?}"
    );
}

#[test]
fn a_self_modifying_plan_is_refused_alone_chirho() {
    // The planner reports self-modification BY ITSELF: a plan trying to become its own authority
    // should not have its capacity numbers discussed as though the rest were a negotiation.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, 3);
    let mut plan_chirho = plan_chirho(9);
    plan_chirho.proposed_grant_chirho = Some(TopologyGrantChirho {
        grant_id_chirho: "grant-a-chirho".to_string(),
        max_nodes_chirho: 9_999,
        max_spend_rate_micros_per_hour_chirho: 9_999_999,
        allowed_providers_chirho: ["hetzner-chirho".to_string()].into_iter().collect(),
        minimum_control_nodes_chirho: 1,
        minimum_storage_nodes_chirho: 1,
    });
    let digest_chirho = store_topology_plan_chirho(root_chirho, &plan_chirho).expect("store plan");

    let report_chirho = build_topology_plan_authority_report_chirho(
        root_chirho,
        PRINCIPAL_CHIRHO,
        &digest_chirho,
        &AuthorityChirho,
    )
    .expect("report");
    assert!(!report_chirho.permitted_chirho);
    assert_eq!(
        report_chirho.refusals_chirho.len(),
        1,
        "{:?}",
        report_chirho.refusals_chirho
    );
    assert!(report_chirho.refusals_chirho[0].contains("SelfModificationChirho"));
}
