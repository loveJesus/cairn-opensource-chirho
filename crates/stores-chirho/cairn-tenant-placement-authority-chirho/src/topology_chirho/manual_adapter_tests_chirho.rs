// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the manual topology adapter.
//!
//! Two centrepieces. [`an_over_bound_plan_yields_no_actionable_steps_chirho`] pins that authority-first
//! PROPAGATES: the planner computes nothing for an unauthorised plan, and a ready-to-run step list is
//! more dangerous coming from here than from the planner because these steps look actionable. And
//! [`the_candidate_joins_before_the_incumbent_drains_chirho`] pins the ordering invariant at the
//! adapter's own output, since that is where an operator reads it.
//!
//! Helper names carry an `adapter_` prefix: a workspace census propagates names defined exactly once,
//! and a test helper colliding with a production entry point silently shrinks a security guard.

use super::*;
use crate::topology_chirho::grant_store_chirho::append_verified_topology_grant_chirho;
use crate::topology_chirho::plan_store_chirho::store_topology_plan_chirho;
use cairn_placement_chirho::budget_chirho::budget_funding_attestation_chirho::*;
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::*;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::NodeMeasurementAuthorityPortChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::*;
use cairn_placement_chirho::node_lifecycle_chirho::{
    LifecycleTransitionChirho, NodeLifecycleStateChirho,
};
use cairn_placement_chirho::topology_chirho::topology_grant_attestation_chirho::*;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::{
    DesiredTopologyPlanChirho, NodeRoleChirho, PlannedNodeChirho, TopologyGrantChirho,
};
use std::path::{Path, PathBuf};

const ADAPTER_KEY_CHIRHO: &str = "adapter-authority-key-chirho";
const ADAPTER_PRINCIPAL_CHIRHO: &str = "planner-principal-chirho";
const ADAPTER_NODE_CHIRHO: &str = "node-a-chirho";

struct AdapterWorldChirho {
    _temp_chirho: tempfile::TempDir,
    root_chirho: PathBuf,
    budget_authority_root_chirho: PathBuf,
}

impl AdapterWorldChirho {
    fn new_chirho() -> Self {
        let temp_chirho = tempfile::tempdir().expect("world");
        let root_chirho = temp_chirho.path().join("evidence-root-chirho");
        let budget_authority_root_chirho = temp_chirho.path().join("budget-authority-root-chirho");
        std::fs::create_dir_all(&root_chirho).expect("evidence root");
        std::fs::create_dir_all(&budget_authority_root_chirho).expect("authority root");
        cairn_signer_chirho::signer_chirho::pubkey_hex_chirho(&root_chirho).expect("root key");
        adapter_seed_funding_chirho(&root_chirho, &budget_authority_root_chirho);
        Self {
            _temp_chirho: temp_chirho,
            root_chirho,
            budget_authority_root_chirho,
        }
    }

    fn root_chirho(&self) -> &Path {
        &self.root_chirho
    }
}

struct AdapterAuthorityChirho;

macro_rules! adapter_verify_impl_chirho {
    ($trait_chirho:path, $method_chirho:ident) => {
        impl $trait_chirho for AdapterAuthorityChirho {
            fn $method_chirho(&self) -> String {
                ADAPTER_KEY_CHIRHO.to_string()
            }
            fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
                sig_chirho == format!("sig-over:{msg_chirho}")
            }
        }
    };
}
adapter_verify_impl_chirho!(TopologyGrantAuthorityPortChirho, authority_key_id_chirho);
adapter_verify_impl_chirho!(NodeRegistrationAuthorityPortChirho, authority_key_id_chirho);
adapter_verify_impl_chirho!(LifecycleAuthorityPortChirho, authority_key_id_chirho);
adapter_verify_impl_chirho!(NodeMeasurementAuthorityPortChirho, node_key_id_chirho);
adapter_verify_impl_chirho!(
    cairn_placement_chirho::budget_chirho::budget_event_attestation_chirho::BudgetAuthorityPortChirho,
    authority_key_id_chirho
);

impl NodeMeasurementAuthorityResolverChirho for AdapterAuthorityChirho {
    fn authority_for_node_chirho(
        &self,
        _node_id_chirho: &str,
    ) -> Option<&dyn NodeMeasurementAuthorityPortChirho> {
        Some(self)
    }
}

fn adapter_authorities_chirho() -> ManualAdapterAuthoritiesChirho<'static> {
    ManualAdapterAuthoritiesChirho {
        grant_chirho: &AdapterAuthorityChirho,
        capacity_chirho: &AdapterAuthorityChirho,
        lifecycle_chirho: &AdapterAuthorityChirho,
        measurement_chirho: &AdapterAuthorityChirho,
        budget_chirho: &AdapterAuthorityChirho,
    }
}

fn adapter_seed_grant_chirho(root_chirho: &Path, max_nodes_chirho: u32) {
    let intent_chirho = TopologyGrantIntentChirho {
        schema_chirho: TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        principal_chirho: ADAPTER_PRINCIPAL_CHIRHO.to_string(),
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
    let mut record_chirho = TopologyGrantAttestationChirho {
        schema_chirho: TOPOLOGY_GRANT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TOPOLOGY_GRANT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: topology_grant_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: ADAPTER_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_topology_grant_message_chirho(&record_chirho)
    );
    append_verified_topology_grant_chirho(root_chirho, &record_chirho, &AdapterAuthorityChirho)
        .expect("seed grant");
}

fn adapter_seed_node_chirho(root_chirho: &Path) {
    let intent_chirho = NodeCapacityIntentChirho {
        schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: ADAPTER_NODE_CHIRHO.to_string(),
        domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fsn1-chirho".to_string(),
        },
        allocatable_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 4_000,
            memory_bytes_chirho: 8 << 30,
            durable_bytes_chirho: 200 << 30,
        },
        registration_seq_chirho: 1,
    };
    let mut record_chirho = NodeCapacityAttestationChirho {
        schema_chirho: NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: node_capacity_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: ADAPTER_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_node_capacity_message_chirho(&record_chirho)
    );
    crate::attestation_stores_chirho::capacity_attestation_store_chirho::append_verified_capacity_attestation_chirho(
        root_chirho,
        &record_chirho,
        &AdapterAuthorityChirho,
    )
    .expect("seed node");

    for (from_chirho, transition_chirho, seq_chirho) in [
        (
            NodeLifecycleStateChirho::ProvisionedChirho,
            LifecycleTransitionChirho::InspectChirho,
            1,
        ),
        (
            NodeLifecycleStateChirho::InspectedChirho,
            LifecycleTransitionChirho::JoinChirho,
            2,
        ),
    ] {
        let intent_chirho = LifecycleTransitionIntentChirho {
            schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
            node_id_chirho: ADAPTER_NODE_CHIRHO.to_string(),
            from_state_chirho: from_chirho,
            transition_chirho,
            asserted_facts_chirho: AssertedLifecycleFactsChirho {
                holds_leadership_chirho: false,
                ownership_proven_chirho: true,
                resident_placements_chirho: 0,
            },
            transition_seq_chirho: seq_chirho,
        };
        let mut record_chirho = LifecycleTransitionAttestationChirho {
            schema_chirho: LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
            signature_domain_chirho: LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
            intent_digest_chirho: lifecycle_intent_digest_chirho(&intent_chirho).expect("digest"),
            intent_chirho,
            authority_key_id_chirho: ADAPTER_KEY_CHIRHO.to_string(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = format!(
            "sig-over:{}",
            unsigned_lifecycle_message_chirho(&record_chirho)
        );
        crate::attestation_stores_chirho::lifecycle_transition_store_chirho::append_verified_lifecycle_transition_chirho(
            root_chirho,
            &record_chirho,
            &AdapterAuthorityChirho,
        )
        .expect("seed transition");
    }
}

fn adapter_plan_chirho(node_count_chirho: usize) -> DesiredTopologyPlanChirho {
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

fn adapter_dominating_replacement_chirho(
) -> Vec<(String, AllocatableCapacityChirho, BTreeSet<String>)> {
    vec![(
        ADAPTER_NODE_CHIRHO.to_string(),
        AllocatableCapacityChirho {
            cpu_millicores_chirho: 8_000,
            memory_bytes_chirho: 16 << 30,
            durable_bytes_chirho: 400 << 30,
        },
        BTreeSet::new(),
    )]
}

const ADAPTER_BUDGET_CHIRHO: &str = "budget-a-chirho";
const ADAPTER_CEILING_CHIRHO: u64 = 100_000;

fn adapter_funding_record_chirho(root_chirho: &Path) -> BudgetFundingAttestationChirho {
    let scope_chirho =
        crate::attestation_stores_chirho::budget_event_store_chirho::budget_evidence_scope_chirho(
            root_chirho,
            ADAPTER_BUDGET_CHIRHO,
        )
        .expect("scope");
    let intent_chirho = BudgetFundingIntentChirho {
        schema_chirho: BUDGET_FUNDING_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        evidence_root_key_id_chirho: scope_chirho.evidence_root_key_id_chirho,
        tenant_id_chirho: scope_chirho.tenant_id_chirho,
        budget_id_chirho: scope_chirho.budget_id_chirho,
        prepaid_ceiling_micros_chirho: ADAPTER_CEILING_CHIRHO,
    };
    let mut record_chirho = BudgetFundingAttestationChirho {
        schema_chirho: BUDGET_FUNDING_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: BUDGET_FUNDING_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: budget_funding_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: ADAPTER_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_budget_funding_message_chirho(&record_chirho)
    );
    record_chirho
}

fn adapter_seed_funding_chirho(root_chirho: &Path, authority_root_chirho: &Path) {
    let record_chirho = adapter_funding_record_chirho(root_chirho);
    crate::attestation_stores_chirho::budget_event_store_chirho::publish_verified_budget_funding_chirho(
        root_chirho,
        authority_root_chirho,
        &record_chirho,
        &AdapterAuthorityChirho,
    )
    .expect("funding");
}

/// Seed a reservation so the budget has less than its full ceiling available.
fn adapter_hold_credits_chirho(
    root_chirho: &Path,
    authority_root_chirho: &Path,
    micros_chirho: u64,
) {
    use cairn_placement_chirho::budget_chirho::budget_event_attestation_chirho::*;
    let scope_chirho =
        crate::attestation_stores_chirho::budget_event_store_chirho::budget_evidence_scope_chirho(
            root_chirho,
            ADAPTER_BUDGET_CHIRHO,
        )
        .expect("scope");
    let funding_digest_chirho =
        budget_funding_record_digest_chirho(&adapter_funding_record_chirho(root_chirho))
            .expect("funding digest");
    let intent_chirho = BudgetEventIntentChirho {
        schema_chirho: BUDGET_EVENT_INTENT_SCHEMA_V2_CHIRHO.to_string(),
        evidence_root_key_id_chirho: scope_chirho.evidence_root_key_id_chirho,
        tenant_id_chirho: scope_chirho.tenant_id_chirho,
        budget_id_chirho: ADAPTER_BUDGET_CHIRHO.to_string(),
        funding_record_digest_chirho: funding_digest_chirho,
        reservation_id_chirho: "held-chirho".to_string(),
        kind_chirho: BudgetEventKindChirho::ReserveChirho {
            requested_micros_chirho: micros_chirho,
            deadline_millis_chirho: 1_000_000,
        },
        event_seq_chirho: 1,
    };
    let mut record_chirho = BudgetEventAttestationChirho {
        schema_chirho: BUDGET_EVENT_ATTESTATION_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: BUDGET_EVENT_ATTESTATION_DOMAIN_V2_CHIRHO.to_string(),
        intent_digest_chirho: budget_event_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: ADAPTER_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_budget_event_message_chirho(&record_chirho)
    );
    crate::attestation_stores_chirho::budget_event_store_chirho::append_verified_budget_event_chirho(
        root_chirho,
        authority_root_chirho,
        &record_chirho,
        &AdapterAuthorityChirho,
    )
    .expect("hold credits");
}

fn adapter_run_chirho(
    world_chirho: &AdapterWorldChirho,
    digest_chirho: &str,
) -> Result<ManualTopologyStepsChirho, ManualAdapterRefusalChirho> {
    adapter_run_priced_chirho(world_chirho, digest_chirho, 1_000)
}

fn adapter_run_priced_chirho(
    world_chirho: &AdapterWorldChirho,
    digest_chirho: &str,
    price_chirho: u64,
) -> Result<ManualTopologyStepsChirho, ManualAdapterRefusalChirho> {
    adapter_run_full_chirho(world_chirho, digest_chirho, price_chirho, &[])
}

fn adapter_run_full_chirho(
    world_chirho: &AdapterWorldChirho,
    digest_chirho: &str,
    price_chirho: u64,
    upgrades_chirho: &[(String, AllocatableCapacityChirho)],
) -> Result<ManualTopologyStepsChirho, ManualAdapterRefusalChirho> {
    let node_ids_chirho = vec![ADAPTER_NODE_CHIRHO.to_string()];
    let replacements_chirho = adapter_dominating_replacement_chirho();
    plan_manual_topology_steps_chirho(
        &ManualAdapterInputsChirho {
            root_chirho: world_chirho.root_chirho(),
            budget_authority_root_chirho: &world_chirho.budget_authority_root_chirho,
            principal_chirho: ADAPTER_PRINCIPAL_CHIRHO,
            plan_digest_chirho: digest_chirho,
            node_ids_chirho: &node_ids_chirho,
            replacements_chirho: &replacements_chirho,
            minimum_spread_chirho: MinimumSpreadChirho {
                distinct_providers_chirho: 1,
                distinct_regions_chirho: 1,
            },
            budget_id_chirho: ADAPTER_BUDGET_CHIRHO.to_string(),
            priced_maximum_micros_chirho: price_chirho,
            required_capacities_chirho: upgrades_chirho,
        },
        &adapter_authorities_chirho(),
    )
}

#[test]
fn a_lawful_change_emits_plan_bound_steps_chirho() {
    // Positive control, and the "plan hashes in evidence" property: every step names the plan it came
    // from, so an operator signs a transition bound to a resolved plan rather than to an intention.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");

    let steps_chirho = adapter_run_chirho(&world_chirho, &digest_chirho).expect("a lawful change");
    assert_eq!(steps_chirho.plan_digest_chirho, digest_chirho);
    assert_eq!(
        steps_chirho.steps_chirho.len(),
        5,
        "{:?}",
        steps_chirho.steps_chirho
    );
    assert!(
        steps_chirho
            .steps_chirho
            .iter()
            .all(|step_chirho| step_chirho.plan_digest_chirho == digest_chirho),
        "every step must carry the plan digest"
    );
}

#[test]
fn the_candidate_joins_before_the_incumbent_drains_chirho() {
    // The ordering invariant, pinned where an OPERATOR reads it. Everything after the join is safe to
    // lose the incumbent; a drain that came first would dip capacity.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");

    let steps_chirho = adapter_run_chirho(&world_chirho, &digest_chirho).expect("lawful");
    let position_chirho = |wanted_chirho: ReplacementStepChirho| {
        steps_chirho
            .steps_chirho
            .iter()
            .position(|step_chirho| {
                step_chirho.step_chirho == TopologyStepChirho::ReplacementChirho(wanted_chirho)
            })
            .expect("step present")
    };
    assert!(
        position_chirho(ReplacementStepChirho::JoinCandidateChirho)
            < position_chirho(ReplacementStepChirho::DrainIncumbentChirho),
        "join must precede drain: {:?}",
        steps_chirho.steps_chirho
    );
    assert!(
        position_chirho(ReplacementStepChirho::DrainIncumbentChirho)
            < position_chirho(ReplacementStepChirho::RetireIncumbentChirho),
        "and retire comes last"
    );
    // The order field must agree with list position, since a step can travel alone.
    for (index_chirho, step_chirho) in steps_chirho.steps_chirho.iter().enumerate() {
        assert_eq!(step_chirho.order_chirho, index_chirho as u32);
    }
}

#[test]
fn an_over_bound_plan_yields_no_actionable_steps_chirho() {
    // THE arm. Authority-first must PROPAGATE: a ready-to-run step list for an unauthorised plan is
    // more dangerous coming from the adapter than from the planner, because these steps look
    // actionable and an operator may simply execute them.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 2);
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(9)).expect("plan");

    let refusal_chirho = adapter_run_chirho(&world_chirho, &digest_chirho)
        .expect_err("an over-bound plan must refuse");
    match refusal_chirho {
        ManualAdapterRefusalChirho::PlannerChirho { refusals_chirho } => {
            assert!(
                !refusals_chirho.is_empty(),
                "the reasons must survive the refusal"
            );
        }
        other_chirho => panic!("expected a planner refusal, got {other_chirho:?}"),
    }
}

#[test]
fn a_missing_grant_refuses_before_anything_is_planned_chirho() {
    // Distinct identity: nothing was planned, as against planned and refused.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");
    assert!(matches!(
        adapter_run_chirho(&world_chirho, &digest_chirho).expect_err("no grant"),
        ManualAdapterRefusalChirho::GrantChirho { .. }
    ));
}

#[test]
fn a_dangling_plan_digest_refuses_as_a_reference_chirho() {
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    adapter_seed_node_chirho(root_chirho);
    assert!(matches!(
        adapter_run_chirho(&world_chirho, &"c".repeat(64)).expect_err("dangling digest"),
        ManualAdapterRefusalChirho::PlanReferenceChirho { .. }
    ));
}

#[test]
fn a_node_without_a_capacity_grant_refuses_as_a_registry_failure_chirho() {
    // The fleet must come off disk. A node the caller names but no grant introduces is a refusal, not
    // a quietly smaller registry that a change then gets planned against.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");
    assert!(matches!(
        adapter_run_chirho(&world_chirho, &digest_chirho).expect_err("no node grant"),
        ManualAdapterRefusalChirho::RegistryChirho { .. }
    ));
}

#[test]
fn an_affordable_change_reports_the_reservation_an_operator_must_authorize_chirho() {
    // The adapter does not RESERVE -- it cannot sign. It says what must be authorized, and says what
    // the budget currently has, so the operator is not asked to trust an unexplained yes.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");

    let steps_chirho =
        adapter_run_priced_chirho(&world_chirho, &digest_chirho, 40_000).expect("affordable");
    assert_eq!(steps_chirho.required_reservation_micros_chirho, 40_000);
    assert_eq!(
        steps_chirho.budget_available_micros_chirho,
        ADAPTER_CEILING_CHIRHO
    );
    assert_eq!(steps_chirho.steps_chirho.len(), 5);
}

#[test]
fn a_change_the_budget_cannot_afford_yields_no_provision_steps_chirho() {
    // CF8 clause 11's "reserves a priced maximum BEFORE simulated provision", enforced by ABSENCE: a
    // provision step for a change nobody can pay for is the ready-to-run artifact ordering exists to
    // prevent. Note the change is PERMITTED -- the grant allows it and the plan resolves -- so this
    // arm isolates affordability rather than passing on some other refusal.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");
    assert!(
        adapter_run_priced_chirho(&world_chirho, &digest_chirho, 40_000).is_ok(),
        "the same change IS permitted and affordable at this price -- so the refusal below is about \
         price alone"
    );

    adapter_hold_credits_chirho(
        root_chirho,
        &world_chirho.budget_authority_root_chirho,
        80_000,
    );
    match adapter_run_priced_chirho(&world_chirho, &digest_chirho, 40_000)
        .expect_err("unaffordable must refuse")
    {
        ManualAdapterRefusalChirho::UnaffordableChirho {
            priced_maximum_micros_chirho,
            available_micros_chirho,
        } => {
            assert_eq!(priced_maximum_micros_chirho, 40_000);
            assert_eq!(
                available_micros_chirho, 20_000,
                "the held reservation is not available"
            );
        }
        other_chirho => panic!("expected unaffordable, got {other_chirho:?}"),
    }
}

#[test]
fn a_node_below_what_the_plan_needs_gets_an_upgrade_step_not_a_replacement_chirho() {
    // CF8 clause 9 names replace and UPGRADE separately, and this is the difference at the adapter's
    // output: the node is not drained, not retired and not swapped -- it is re-granted in place, and
    // the step says so.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");

    let bigger_chirho = AllocatableCapacityChirho {
        cpu_millicores_chirho: 8_000,
        memory_bytes_chirho: 16 << 30,
        durable_bytes_chirho: 400 << 30,
    };
    let steps_chirho = adapter_run_full_chirho(
        &world_chirho,
        &digest_chirho,
        1_000,
        &[(ADAPTER_NODE_CHIRHO.to_string(), bigger_chirho)],
    )
    .expect("a lawful, affordable change with an upgrade");

    let upgrade_chirho = steps_chirho
        .steps_chirho
        .iter()
        .find(|step_chirho| {
            matches!(
                step_chirho.step_chirho,
                TopologyStepChirho::UpgradeCapacityChirho { .. }
            )
        })
        .expect("an upgrade step must be emitted");
    assert_eq!(upgrade_chirho.incumbent_node_id_chirho, ADAPTER_NODE_CHIRHO);
    assert_eq!(
        upgrade_chirho.plan_digest_chirho, digest_chirho,
        "and it is plan-bound like every other step"
    );
}

#[test]
fn a_node_already_at_what_the_plan_needs_gets_no_upgrade_step_chirho() {
    // An upgrade nobody needs is noise in a list an operator is meant to act on. Without this arm the
    // arm above would pass against an adapter that emitted an upgrade unconditionally.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");

    let same_chirho = AllocatableCapacityChirho {
        cpu_millicores_chirho: 4_000,
        memory_bytes_chirho: 8 << 30,
        durable_bytes_chirho: 200 << 30,
    };
    let steps_chirho = adapter_run_full_chirho(
        &world_chirho,
        &digest_chirho,
        1_000,
        &[(ADAPTER_NODE_CHIRHO.to_string(), same_chirho)],
    )
    .expect("lawful");
    assert!(
        !steps_chirho.steps_chirho.iter().any(|step_chirho| matches!(
            step_chirho.step_chirho,
            TopologyStepChirho::UpgradeCapacityChirho { .. }
        )),
        "a node already at its requirement needs no upgrade: {:?}",
        steps_chirho.steps_chirho
    );
}

#[test]
fn a_required_capacity_below_placed_demand_refuses_with_the_registrys_own_reason_chirho() {
    // The adapter does not re-implement the rule; it asks the registry, so the refusal that reaches an
    // operator is the same one the applying path would give.
    let world_chirho = AdapterWorldChirho::new_chirho();
    let root_chirho = world_chirho.root_chirho();
    adapter_seed_grant_chirho(root_chirho, 10);
    adapter_seed_node_chirho(root_chirho);
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &adapter_plan_chirho(3)).expect("plan");

    let unknown_chirho = AllocatableCapacityChirho {
        cpu_millicores_chirho: 1,
        memory_bytes_chirho: 1,
        durable_bytes_chirho: 1,
    };
    match adapter_run_full_chirho(
        &world_chirho,
        &digest_chirho,
        1_000,
        &[("node-never-registered-chirho".to_string(), unknown_chirho)],
    )
    .expect_err("an unknown node must refuse")
    {
        ManualAdapterRefusalChirho::UpgradeChirho {
            node_id_chirho,
            refusal_chirho,
        } => {
            assert_eq!(node_id_chirho, "node-never-registered-chirho");
            assert!(matches!(
                refusal_chirho,
                CapacityAdvanceRefusalChirho::UnknownNodeChirho { .. }
            ));
        }
        other_chirho => panic!("expected an upgrade refusal, got {other_chirho:?}"),
    }
}
