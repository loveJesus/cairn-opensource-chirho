// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::attestation_stores_chirho::capacity_attestation_store_chirho::append_verified_capacity_attestation_chirho;
use crate::attestation_stores_chirho::lifecycle_transition_store_chirho::append_verified_lifecycle_transition_chirho;
use crate::attestation_stores_chirho::placement_record_store_chirho::tests_chirho::successor_chirho;
use crate::attestation_stores_chirho::placement_record_store_chirho::{
    append_verified_placement_record_chirho, tenant_placement_population_digest_chirho,
};
use crate::attestation_stores_chirho::usage_measurement_store_chirho::append_verified_usage_measurement_chirho;
use crate::tests_chirho::{fixture_chirho, FixtureChirho};
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::*;
use cairn_placement_chirho::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::*;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::*;
use cairn_placement_chirho::node_lifecycle_chirho::{
    LifecycleTransitionChirho, NodeLifecycleStateChirho,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use std::path::{Path, PathBuf};

struct StagedAdmissionEvidenceChirho {
    _evidence_temp_chirho: tempfile::TempDir,
    _authority_temp_chirho: tempfile::TempDir,
    placement_fixture_chirho: FixtureChirho,
    config_chirho: TenantCapacityEvidenceConfigChirho,
    current_placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    target_node_id_chirho: String,
    demand_chirho: TenantCapacityDemandChirho,
    headroom_chirho: TenantCapacityDemandChirho,
    /// Exposed so an identity-drift arm can append a further NON-usage row. The snapshot digest
    /// covers the capacity, lifecycle, and usage logs; proving drift through the usage log alone
    /// would name the arm after its most salient input rather than its actual scope.
    lifecycle_root_chirho: PathBuf,
    /// A second assigned node, so a drift arm can move a log WITHOUT moving the target's own
    /// lifecycle field — leaving the snapshot digest as the only identity input that changed.
    non_target_node_id_chirho: String,
    authorities_chirho: ControlPlaneAuthoritiesChirho,
}

impl StagedAdmissionEvidenceChirho {
    fn adapter_chirho(&self) -> VerifiedTenantCapacityAdmissionChirho {
        VerifiedTenantCapacityAdmissionChirho::new_chirho(
            self.config_chirho.clone(),
            Arc::clone(&self.current_placement_chirho),
        )
        .unwrap()
    }
}

fn provision_key_chirho(root_chirho: &Path) -> String {
    sign_message_chirho(root_chirho, b"provision-capacity-admission-chirho").unwrap();
    pubkey_hex_chirho(root_chirho).unwrap()
}

fn capacity_record_chirho(
    node_id_chirho: &str,
    authority_key_chirho: &str,
    authority_root_chirho: &Path,
) -> NodeCapacityAttestationChirho {
    let intent_chirho = NodeCapacityIntentChirho {
        schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_id_chirho.to_string(),
        domain_chirho: FailureDomainChirho {
            provider_chirho: "capacity-provider-chirho".to_string(),
            region_chirho: "capacity-region-chirho".to_string(),
        },
        allocatable_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 4_000,
            memory_bytes_chirho: 8 * 1024 * 1024 * 1024,
            durable_bytes_chirho: 100 * 1024 * 1024 * 1024,
        },
        registration_seq_chirho: 1,
    };
    let intent_digest_chirho = node_capacity_intent_digest_chirho(&intent_chirho).unwrap();
    let mut record_chirho = NodeCapacityAttestationChirho {
        schema_chirho: NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        authority_key_id_chirho: authority_key_chirho.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        authority_root_chirho,
        unsigned_node_capacity_message_chirho(&record_chirho).as_bytes(),
    )
    .unwrap();
    record_chirho
}

fn lifecycle_record_chirho(
    node_id_chirho: &str,
    authority_key_chirho: &str,
    authority_root_chirho: &Path,
    from_state_chirho: NodeLifecycleStateChirho,
    transition_chirho: LifecycleTransitionChirho,
    transition_seq_chirho: u64,
) -> LifecycleTransitionAttestationChirho {
    let intent_chirho = LifecycleTransitionIntentChirho {
        schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_id_chirho.to_string(),
        from_state_chirho,
        transition_chirho,
        asserted_facts_chirho: AssertedLifecycleFactsChirho {
            holds_leadership_chirho: false,
            ownership_proven_chirho: true,
            resident_placements_chirho: 0,
        },
        transition_seq_chirho,
    };
    let intent_digest_chirho = lifecycle_intent_digest_chirho(&intent_chirho).unwrap();
    let mut record_chirho = LifecycleTransitionAttestationChirho {
        schema_chirho: LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        authority_key_id_chirho: authority_key_chirho.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        authority_root_chirho,
        unsigned_lifecycle_message_chirho(&record_chirho).as_bytes(),
    )
    .unwrap();
    record_chirho
}

fn usage_record_chirho(
    node_id_chirho: &str,
    node_root_chirho: &Path,
    observed_cpu_chirho: u64,
    sequence_chirho: u64,
) -> UsageMeasurementAttestationChirho {
    let intent_chirho = UsageMeasurementIntentChirho {
        schema_chirho: USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_id_chirho.to_string(),
        stamp_chirho: MeasurementStampChirho {
            hlc_millis_chirho: 10_000 + sequence_chirho,
            sequence_chirho,
        },
        observed_usage_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: observed_cpu_chirho,
            memory_bytes_chirho: 2 * 1024 * 1024 * 1024,
            durable_bytes_chirho: 20 * 1024 * 1024 * 1024,
        },
    };
    let intent_digest_chirho = usage_intent_digest_chirho(&intent_chirho).unwrap();
    let mut record_chirho = UsageMeasurementAttestationChirho {
        schema_chirho: USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        node_key_id_chirho: node_id_chirho.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        node_root_chirho,
        unsigned_usage_message_chirho(&record_chirho).as_bytes(),
    )
    .unwrap();
    record_chirho
}

fn stage_evidence_chirho(target_usage_cpu_chirho: u64) -> StagedAdmissionEvidenceChirho {
    stage_evidence_with_target_usage_row_chirho(target_usage_cpu_chirho, true)
}

/// Stage the same evidence, optionally OMITTING the target node's own usage row.
///
/// Omitting the row is not the same as deleting the log: the log stays present and valid, its
/// external snapshot still matches, and every other node reports normally. That distinction is the
/// whole point — it is the only way to reach the case where a node is in the population and has no
/// observed usage of its own.
fn stage_evidence_with_target_usage_row_chirho(
    target_usage_cpu_chirho: u64,
    include_target_usage_row_chirho: bool,
) -> StagedAdmissionEvidenceChirho {
    let evidence_temp_chirho = tempfile::tempdir().unwrap();
    let authority_temp_chirho = tempfile::tempdir().unwrap();
    let evidence_root_chirho = evidence_temp_chirho.path();
    let placement_fixture_chirho = fixture_chirho();
    let capacity_root_chirho = authority_temp_chirho.path().join("capacity-key-chirho");
    let lifecycle_root_chirho = authority_temp_chirho.path().join("lifecycle-key-chirho");
    let topology_root_chirho = authority_temp_chirho.path().join("topology-key-chirho");
    let budget_root_chirho = authority_temp_chirho.path().join("budget-key-chirho");
    let capacity_key_chirho = provision_key_chirho(&capacity_root_chirho);
    let lifecycle_key_chirho = provision_key_chirho(&lifecycle_root_chirho);
    let topology_key_chirho = provision_key_chirho(&topology_root_chirho);
    let budget_key_chirho = provision_key_chirho(&budget_root_chirho);
    let node_measurement_pubkeys_chirho = placement_fixture_chirho
        .record_chirho
        .intent_chirho
        .assigned_nodes_chirho
        .iter()
        .map(|node_chirho| {
            (
                node_chirho.node_id_chirho.clone(),
                node_chirho.node_id_chirho.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let authorities_chirho = resolve_control_plane_authorities_chirho(
        &capacity_key_chirho,
        &lifecycle_key_chirho,
        &topology_key_chirho,
        &budget_key_chirho,
        &node_measurement_pubkeys_chirho,
    )
    .unwrap();

    let current_placement_chirho = Arc::new(
        append_verified_placement_record_chirho(
            evidence_root_chirho,
            placement_fixture_chirho.record_chirho.clone(),
            &placement_fixture_chirho.placement_key_chirho,
            &placement_fixture_chirho.roster_key_chirho,
            &placement_fixture_chirho.plan_key_chirho,
        )
        .unwrap(),
    );
    let target_node_id_chirho = current_placement_chirho.assigned_nodes_chirho()[0]
        .node_id_chirho
        .clone();
    for (index_chirho, (node_chirho, node_root_chirho)) in current_placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .zip(&placement_fixture_chirho.serving_node_roots_chirho)
        .enumerate()
    {
        append_verified_capacity_attestation_chirho(
            evidence_root_chirho,
            &capacity_record_chirho(
                &node_chirho.node_id_chirho,
                &capacity_key_chirho,
                &capacity_root_chirho,
            ),
            authorities_chirho.capacity_registrar_chirho(),
        )
        .unwrap();
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
            append_verified_lifecycle_transition_chirho(
                evidence_root_chirho,
                &lifecycle_record_chirho(
                    &node_chirho.node_id_chirho,
                    &lifecycle_key_chirho,
                    &lifecycle_root_chirho,
                    from_chirho,
                    transition_chirho,
                    seq_chirho,
                ),
                authorities_chirho.lifecycle_chirho(),
            )
            .unwrap();
        }
        let observed_cpu_chirho = if index_chirho == 0 {
            target_usage_cpu_chirho
        } else {
            1_000
        };
        if index_chirho == 0 && !include_target_usage_row_chirho {
            continue;
        }
        append_verified_usage_measurement_chirho(
            evidence_root_chirho,
            &usage_record_chirho(
                &node_chirho.node_id_chirho,
                node_root_chirho,
                observed_cpu_chirho,
                1,
            ),
            authorities_chirho
                .node_measurement_chirho(&node_chirho.node_id_chirho)
                .unwrap(),
        )
        .unwrap();
    }
    let population_digest_chirho =
        tenant_placement_population_digest_chirho(&[current_placement_chirho
            .assignment_digest_chirho()
            .to_string()]);
    let snapshot_digest_chirho =
        capacity_load_snapshot_digest_chirho(evidence_root_chirho).unwrap();
    let config_chirho = TenantCapacityEvidenceConfigChirho {
        evidence_root_chirho: evidence_root_chirho.to_path_buf(),
        expected_placement_population_digest_chirho: population_digest_chirho,
        expected_capacity_load_snapshot_digest_chirho: snapshot_digest_chirho,
        placement_pubkey_hex_chirho: placement_fixture_chirho.placement_key_chirho.clone(),
        roster_operator_pubkey_hex_chirho: placement_fixture_chirho.roster_key_chirho.clone(),
        geo_plan_pubkey_hex_chirho: placement_fixture_chirho.plan_key_chirho.clone(),
        capacity_registrar_pubkey_hex_chirho: capacity_key_chirho,
        lifecycle_pubkey_hex_chirho: lifecycle_key_chirho,
        topology_grant_pubkey_hex_chirho: topology_key_chirho,
        budget_pubkey_hex_chirho: budget_key_chirho,
        node_measurement_pubkeys_chirho,
    };
    let non_target_node_id_chirho = current_placement_chirho.assigned_nodes_chirho()[1]
        .node_id_chirho
        .clone();
    StagedAdmissionEvidenceChirho {
        _evidence_temp_chirho: evidence_temp_chirho,
        _authority_temp_chirho: authority_temp_chirho,
        lifecycle_root_chirho: lifecycle_root_chirho.clone(),
        non_target_node_id_chirho,
        authorities_chirho: authorities_chirho.clone(),
        placement_fixture_chirho,
        config_chirho,
        current_placement_chirho: Arc::clone(&current_placement_chirho),
        target_node_id_chirho,
        demand_chirho: demand_from_allocatable_chirho(
            &current_placement_chirho.intent_chirho().demand_chirho,
        ),
        headroom_chirho: TenantCapacityDemandChirho {
            cpu_millicores_chirho: 500,
            memory_bytes_chirho: 512 * 1024 * 1024,
            durable_bytes_chirho: 5 * 1024 * 1024 * 1024,
        },
    }
}

#[test]
fn a_complete_fresh_snapshot_admits_an_existing_placement_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert!(verdict_chirho.refusals_chirho.is_empty());
    assert_eq!(verdict_chirho.considered_chirho, 5);
    assert_eq!(verdict_chirho.evidence_identity_chirho.len(), 64);
}

#[test]
fn observed_load_closes_headroom_without_double_counting_the_migrating_tenant_chirho() {
    let staged_chirho = stage_evidence_chirho(3_800);
    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec!["migration-target-headroom-insufficient-chirho"]
    );
    assert!(verdict_chirho.considered_chirho > 0);
}

#[test]
fn truncating_a_valid_usage_log_refuses_against_the_external_snapshot_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let usage_log_chirho = staged_chirho
        .config_chirho
        .evidence_root_chirho
        .join(NODE_USAGE_MEASUREMENT_LOG_CHIRHO);
    let usage_text_chirho = std::fs::read_to_string(&usage_log_chirho).unwrap();
    let retained_chirho = usage_text_chirho.lines().take(2).collect::<Vec<_>>();
    std::fs::write(
        &usage_log_chirho,
        format!("{}\n", retained_chirho.join("\n")),
    )
    .unwrap();
    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec!["capacity-evidence-snapshot-mismatch-chirho"]
    );
    assert_eq!(verdict_chirho.considered_chirho, 0);
}

#[test]
fn a_snapshot_that_contains_an_unverifiable_usage_row_refuses_strictly_chirho() {
    let mut staged_chirho = stage_evidence_chirho(3_000);
    let target_index_chirho = staged_chirho
        .current_placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .position(|node_chirho| node_chirho.node_id_chirho == staged_chirho.target_node_id_chirho)
        .unwrap();
    let mut forged_chirho = usage_record_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho
            .placement_fixture_chirho
            .serving_node_roots_chirho[target_index_chirho],
        100,
        2,
    );
    forged_chirho.sig_chirho = "forged-chirho".to_string();
    let mut line_chirho = serde_json::to_vec(&forged_chirho).unwrap();
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(
        &staged_chirho
            .config_chirho
            .evidence_root_chirho
            .join(NODE_USAGE_MEASUREMENT_LOG_CHIRHO),
        &line_chirho,
    )
    .unwrap();
    staged_chirho
        .config_chirho
        .expected_capacity_load_snapshot_digest_chirho =
        capacity_load_snapshot_digest_chirho(&staged_chirho.config_chirho.evidence_root_chirho)
            .unwrap();

    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec!["capacity-registry-refused-chirho"],
        "corruption must not be reported as absent evidence or substituted by the prior low row"
    );
}

#[test]
fn missing_usage_evidence_is_not_a_zero_load_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    std::fs::remove_file(
        staged_chirho
            .config_chirho
            .evidence_root_chirho
            .join(NODE_USAGE_MEASUREMENT_LOG_CHIRHO),
    )
    .unwrap();
    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec!["capacity-evidence-snapshot-unavailable-chirho"]
    );
    assert_eq!(verdict_chirho.considered_chirho, 0);
}

#[test]
fn an_authentic_replayed_usage_measurement_freezes_admission_chirho() {
    let mut staged_chirho = stage_evidence_chirho(3_000);
    let target_index_chirho = staged_chirho
        .current_placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .position(|node_chirho| node_chirho.node_id_chirho == staged_chirho.target_node_id_chirho)
        .unwrap();
    let replay_chirho = usage_record_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho
            .placement_fixture_chirho
            .serving_node_roots_chirho[target_index_chirho],
        100,
        1,
    );
    let authorities_chirho = resolve_control_plane_authorities_chirho(
        &staged_chirho
            .config_chirho
            .capacity_registrar_pubkey_hex_chirho,
        &staged_chirho.config_chirho.lifecycle_pubkey_hex_chirho,
        &staged_chirho.config_chirho.topology_grant_pubkey_hex_chirho,
        &staged_chirho.config_chirho.budget_pubkey_hex_chirho,
        &staged_chirho.config_chirho.node_measurement_pubkeys_chirho,
    )
    .unwrap();
    append_verified_usage_measurement_chirho(
        &staged_chirho.config_chirho.evidence_root_chirho,
        &replay_chirho,
        authorities_chirho
            .node_measurement_chirho(&staged_chirho.target_node_id_chirho)
            .unwrap(),
    )
    .unwrap();
    staged_chirho
        .config_chirho
        .expected_capacity_load_snapshot_digest_chirho =
        capacity_load_snapshot_digest_chirho(&staged_chirho.config_chirho.evidence_root_chirho)
            .unwrap();

    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec!["capacity-load-evidence-frozen-chirho"]
    );
    assert!(verdict_chirho.considered_chirho > 0);
}

#[test]
fn a_placement_node_missing_from_the_evidence_population_refuses_chirho() {
    let mut staged_chirho = stage_evidence_chirho(3_000);
    let omitted_node_chirho = staged_chirho
        .current_placement_chirho
        .assigned_nodes_chirho()[1]
        .node_id_chirho
        .clone();
    staged_chirho
        .config_chirho
        .node_measurement_pubkeys_chirho
        .remove(&omitted_node_chirho);
    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec!["placement-node-evidence-missing-chirho"]
    );
}

/// A node in the population with NO usage row of its own is refused by BOTH mechanisms.
///
/// This pins WHICH mechanisms hold the property, and executing it corrected what two seats concluded
/// by reading. The sibling arm `missing_usage_evidence_is_not_a_zero_load_chirho` deletes the entire
/// usage LOG and is refused far upstream as an unavailable snapshot — a missing FILE. This is the
/// missing ROW: log present, valid, snapshot matching, every other node reporting normally, and no
/// measurement for the target.
///
/// **Both defences fire, and that was not obvious from the source.** The posture clause refuses
/// `capacity-load-evidence-frozen-chirho`; independently, `effective_occupied_for_chirho` returns
/// `None` for a node with no observed usage and the occupancy arithmetic refuses every dimension
/// rather than treating the absence as zero load. Two readings of this file concluded the `Option`
/// was unreachable as a decision — it is not; it produces three of these four refusals.
///
/// **Why the redundancy matters rather than being waste.** Mutating `effective_occupied_for_chirho`
/// so absent usage becomes ZERO LOAD leaves both suites green, because the posture refusal survives
/// in the same `Vec` and the verdict is still "refused". The occupancy half is therefore load-bearing
/// in the refusal SET and not decisive in the VERDICT on this input — which is exactly why asserting
/// the whole vector, rather than "it refused", is what pins it.
#[test]
fn a_node_with_no_usage_row_of_its_own_is_frozen_by_its_own_evidence_chirho() {
    let staged_chirho = stage_evidence_with_target_usage_row_chirho(3_000, false);
    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec![
            "capacity-load-evidence-frozen-chirho",
            "migration-target-headroom-insufficient-chirho",
            "migration-target-headroom-insufficient-chirho",
            "migration-target-headroom-insufficient-chirho",
        ],
        "BOTH defences fire: the posture clause, and one occupancy refusal per dimension because \
         absent usage is not zero load"
    );
    assert!(
        !verdict_chirho
            .refusals_chirho
            .iter()
            .any(|refusal_chirho| refusal_chirho
                .contains("capacity-evidence-snapshot-unavailable")),
        "and this must be the missing-ROW case, not the missing-FILE case the sibling arm covers"
    );
    assert_eq!(
        verdict_chirho.considered_chirho, 4,
        "the four upstream-validated conditions are counted, while the missing observed-usage row \
         must keep the only independently varying fifth condition unearned"
    );
    assert!(
        !verdict_chirho.is_admitted_over_evidence_chirho(),
        "an unmeasured node is never admitted"
    );
}

// ---------------------------------------------------------------------------------------------
// REAL-EVIDENCE IDENTITY DRIFT
//
// The composition pins `evidence_identity_chirho` at begin and re-compares it at activation, so the
// whole gate rests on one property: that the identity actually MOVES when the evidence underneath it
// moves. The composition's own arms prove the COMPARISON with a test port. These arms prove the
// thing being compared is sensitive to real evidence, which a test port cannot show.
//
// SCOPE, measured rather than assumed: these arms live in this crate because
// `cairn-ledger-host-chirho` does not depend on `cairn-tenant-placement-authority-chirho`, and
// `admit_target_root_chirho` is `pub(crate)`. Only `cairn-ledger-geo-node-chirho` and
// `cairn-ledger-regenesis-chirho` can see both, so real evidence cannot be attached at the
// composition level. These prove drift at the port; the composition's arms prove the comparison.
// Neither alone covers the gate.
// ---------------------------------------------------------------------------------------------

fn verdict_for_chirho(
    staged_chirho: &StagedAdmissionEvidenceChirho,
    target_node_id_chirho: &str,
) -> TenantCapacityAdmissionVerdictChirho {
    staged_chirho.adapter_chirho().admit_target_chirho(
        target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    )
}

/// POSITIVE CONTROL. Every drift arm below asserts an identity CHANGED; all of them would pass
/// against an identity that is simply unstable — recomputed from a clock, a path, or an iteration
/// order. This is the arm that makes the others mean something.
#[test]
fn an_unchanged_root_yields_a_stable_admission_identity_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let first_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho);
    let second_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho);

    assert!(
        first_chirho.is_admitted_over_evidence_chirho(),
        "the control must ADMIT — an adapter that refuses every input would satisfy every drift \
         arm below without binding anything"
    );
    assert_eq!(first_chirho.considered_chirho, 5);
    assert_eq!(
        first_chirho.evidence_identity_chirho, second_chirho.evidence_identity_chirho,
        "identical bytes, identical arrangement, identical identity"
    );
    assert_eq!(first_chirho.evidence_identity_chirho.len(), 64);
}

/// A NON-usage log moves the identity.
///
/// The snapshot digest covers the capacity, lifecycle, AND usage logs. Drifting only the usage log
/// would name this arm after its most salient input rather than its actual scope, so this appends a
/// legal lifecycle transition — and appends it for a node that is NOT the migration target, so the
/// target's own `target_lifecycle_chirho` field does not move. The snapshot digest is then the only
/// identity input that changed, which is what makes the attribution exact.
#[test]
fn a_non_usage_log_append_moves_the_admission_identity_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let before_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho);
    assert!(before_chirho.is_admitted_over_evidence_chirho());

    append_verified_lifecycle_transition_chirho(
        &staged_chirho.config_chirho.evidence_root_chirho,
        &lifecycle_record_chirho(
            &staged_chirho.non_target_node_id_chirho,
            &staged_chirho.config_chirho.lifecycle_pubkey_hex_chirho,
            &staged_chirho.lifecycle_root_chirho,
            NodeLifecycleStateChirho::JoinedChirho,
            LifecycleTransitionChirho::DrainChirho,
            3,
        ),
        staged_chirho.authorities_chirho.lifecycle_chirho(),
    )
    .expect("draining an already-joined non-target node is a legal, authentic transition");

    let after_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho);
    assert_ne!(
        before_chirho.evidence_identity_chirho, after_chirho.evidence_identity_chirho,
        "authentic new evidence in a non-usage log must move the admission identity"
    );
    assert_eq!(
        after_chirho.evidence_identity_chirho,
        failure_identity_chirho(
            &staged_chirho.target_node_id_chirho,
            "capacity-evidence-snapshot-mismatch-chirho"
        ),
        "and it moves by REFUSING against the externally pinned snapshot — asserting the exact \
         refusal identity, not mere inequality, is what makes a mutation of the pin redden this arm"
    );
    assert!(!after_chirho.is_admitted_over_evidence_chirho());
}

/// A legitimate new placement REVISION moves the identity, through the other pinned coordinate.
///
/// Measured at this hash: `capacity_load_snapshot_digest_chirho` digests exactly the capacity,
/// lifecycle, and usage logs — NOT the placement log. So the two externally pinned coordinates are
/// genuinely independent, and this arm's refusal is attributable to the population alone.
///
/// The successor is fully valid and correctly chained — every readiness receipt re-signed against
/// the new intent digest. A corrupt append would refuse under the SAME collapsed label
/// (`PlacementPopulationChirho(_)` erases which inner refusal fired), so a tampered fixture here
/// would pass this assertion while measuring the adjacent question. Valid evidence that has
/// legitimately advanced is the case worth pinning: it still refuses, because the pin is external.
#[test]
fn a_legitimate_new_placement_revision_moves_the_admission_identity_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let before_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho);
    assert!(before_chirho.is_admitted_over_evidence_chirho());

    let successor_record_chirho = successor_chirho(
        &staged_chirho.placement_fixture_chirho,
        &staged_chirho.placement_fixture_chirho.record_chirho,
        1,
        Some(
            staged_chirho
                .current_placement_chirho
                .assignment_digest_chirho()
                .to_string(),
        ),
    );
    append_verified_placement_record_chirho(
        &staged_chirho.config_chirho.evidence_root_chirho,
        successor_record_chirho,
        &staged_chirho.placement_fixture_chirho.placement_key_chirho,
        &staged_chirho.placement_fixture_chirho.roster_key_chirho,
        &staged_chirho.placement_fixture_chirho.plan_key_chirho,
    )
    .expect("a correctly chained, fully re-signed revision 1 appends");

    let after_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho);
    assert_ne!(
        before_chirho.evidence_identity_chirho, after_chirho.evidence_identity_chirho,
        "a moved population must move the admission identity"
    );
    assert_eq!(
        after_chirho.evidence_identity_chirho,
        failure_identity_chirho(
            &staged_chirho.target_node_id_chirho,
            "placement-population-refused-chirho"
        )
    );
    assert_ne!(
        after_chirho.evidence_identity_chirho,
        failure_identity_chirho(
            &staged_chirho.target_node_id_chirho,
            "capacity-evidence-snapshot-mismatch-chirho"
        ),
        "the two pinned coordinates must not collapse into one identity — drifting the population \
         is a different fact from drifting the log snapshot, and an operator reading the refusal \
         has to be able to tell which evidence moved"
    );
}

/// The migration TARGET is bound into the identity.
///
/// The runtime derives the target node id from the target root's own keypair precisely so a caller
/// cannot substitute one beside the path. This is the complementary half: even holding the evidence
/// byte-identical, naming a different target yields a different identity, so a substituted target
/// cannot reuse a pinned one. Both nodes are legitimately assigned, so neither call is refused for
/// being off-placement — the identities differ on the target's own bound facts.
///
/// MEASURED LIMIT — this arm pins the PROPERTY, not one field. Blanking `target_node_id_chirho` in
/// the identity material leaves this arm GREEN (mutation run 2026-08-21, anchor 1/1, no compile
/// error). That is not a weakness in the arm and not a defect: the two nodes also differ in their
/// bound allocatable, lifecycle, measurement, observed usage, reserved and occupied facts, so the
/// identity is carried by several fields at once. Recorded because a reader who assumed this arm
/// pins the id alone would draw a stronger conclusion than the evidence supports.
#[test]
fn a_different_migration_target_yields_a_different_identity_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let target_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho);
    let other_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.non_target_node_id_chirho);

    assert_ne!(
        staged_chirho.target_node_id_chirho, staged_chirho.non_target_node_id_chirho,
        "fixture control: the two nodes must actually be distinct"
    );
    assert_ne!(
        target_chirho.evidence_identity_chirho, other_chirho.evidence_identity_chirho,
        "the same evidence admitting a different target is a different admission"
    );
    assert_ne!(
        other_chirho.evidence_identity_chirho,
        failure_identity_chirho(
            &staged_chirho.non_target_node_id_chirho,
            "migration-target-not-assigned-chirho"
        ),
        "and the difference must come from the bound target facts, not from the second node being \
         rejected as off-placement — otherwise this arm proves nothing about identity binding"
    );
}

/// A rotated AUTHORITY role is admitted and STILL changes the identity.
///
/// The identity binds twenty-two fields, of which seven are control-plane keys. Rotating the
/// topology-grant role to a fresh authority leaves four distinct authorities, so resolution
/// succeeds; leaves every evidence byte untouched, so both pinned digests still match; and admits,
/// so `refusals_chirho` and `considered_chirho` are identical to the control. The identity is the
/// only thing that can tell the two arrangements apart.
///
/// This is not hypothetical: measured at this hash, `topology_grant_chirho()` and `budget_chirho()`
/// have ZERO call sites crate-wide (control: `lifecycle_chirho()` resolves to fifteen across eight
/// files). Those two authorities are required-distinct and identity-bound but never read, so this
/// arm is the only thing standing between a mis-wired role and a silently accepted migration.
#[test]
fn a_rotated_authority_role_admits_and_still_changes_identity_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let control_chirho = verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho);
    assert!(control_chirho.is_admitted_over_evidence_chirho());

    // EXACTLY ONE identity field moves. An earlier version of this arm swapped topology-grant with
    // budget, which reads as the tidier hazard but changes TWO fields — and a mutation unbinding
    // topology-grant alone then SURVIVED, because budget still carried the difference. A swap cannot
    // attribute to a field. Rotating one role to a fresh distinct authority can.
    let replacement_temp_chirho = tempfile::tempdir().unwrap();
    let replacement_key_chirho = provision_key_chirho(
        &replacement_temp_chirho
            .path()
            .join("replacement-key-chirho"),
    );
    let mut swapped_config_chirho = staged_chirho.config_chirho.clone();
    swapped_config_chirho.topology_grant_pubkey_hex_chirho = replacement_key_chirho.clone();
    assert_ne!(
        replacement_key_chirho, staged_chirho.config_chirho.topology_grant_pubkey_hex_chirho,
        "fixture control: the replacement must actually change the arrangement"
    );
    assert_eq!(
        swapped_config_chirho.budget_pubkey_hex_chirho,
        staged_chirho.config_chirho.budget_pubkey_hex_chirho,
        "and every OTHER authority must be untouched, so a difference in identity can only be \
         attributed to the one rotated role"
    );

    let swapped_chirho = VerifiedTenantCapacityAdmissionChirho::new_chirho(
        swapped_config_chirho,
        Arc::clone(&staged_chirho.current_placement_chirho),
    )
    .expect("four distinct authorities in a different arrangement still resolve")
    .admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );

    assert!(
        swapped_chirho.is_admitted_over_evidence_chirho(),
        "the reshuffled arrangement must still ADMIT — an arm where the swap merely refuses would \
         prove nothing about identity, only that resolution rejected it"
    );
    assert_eq!(
        swapped_chirho.refusals_chirho, control_chirho.refusals_chirho,
        "identical verdict surface..."
    );
    assert_eq!(
        swapped_chirho.considered_chirho, control_chirho.considered_chirho,
        "...identical anti-vacuity count..."
    );
    assert_ne!(
        swapped_chirho.evidence_identity_chirho, control_chirho.evidence_identity_chirho,
        "...and the identity is the ONLY thing that distinguishes the two arrangements"
    );
}

// ---------------------------------------------------------------------------------------------
// CALLER-SUBSTITUTION AND STALENESS GUARDS
//
// `admit_target_chirho` takes the target id, the demand and the headroom FROM ITS CALLER. Three
// checks stop a caller naming coordinates the pinned placement does not support, and a fourth stops
// a pinned placement the evidence population has already moved past.
//
// Measured 2026-08-21 by mutating each refusal LABEL to a sentinel -- the labels are what
// `failure_identity_chirho` derives from, so a name census of the VARIANTS undercounts and reported
// several of these as covered when no arm asserted the identity. Six of the adapter's thirteen
// refusal identities had no arm at all. These close the three that are load-bearing and stageable.
// ---------------------------------------------------------------------------------------------

/// A target outside the pinned placement refuses BEFORE any evidence is read.
///
/// The runtime derives the node id from the target root's own keypair so a caller cannot substitute
/// one beside the path. This is the port-level backstop for the same hazard, and its ordering is the
/// point: the check sits above the registry load, so a caller cannot spend a target-controlled
/// evidence read to learn about a root it was never authorised to select.
#[test]
fn a_target_outside_the_pinned_placement_refuses_by_its_own_identity_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let foreign_target_chirho = "unassigned-node-chirho";
    assert!(
        staged_chirho
            .current_placement_chirho
            .assigned_node_chirho(foreign_target_chirho)
            .is_none(),
        "fixture control: the substituted target must genuinely not be assigned"
    );

    let verdict_chirho = verdict_for_chirho(&staged_chirho, foreign_target_chirho);
    assert_eq!(
        verdict_chirho.evidence_identity_chirho,
        failure_identity_chirho(foreign_target_chirho, "migration-target-not-assigned-chirho"),
        "an unassigned target must refuse by NOT-ASSIGNED -- not by target-evidence-missing, which \
         would mean the registry was loaded before the authority check"
    );
    assert!(!verdict_chirho.is_admitted_over_evidence_chirho());
    assert_eq!(verdict_chirho.considered_chirho, 0);
}

/// A demand that does not match the pinned placement's declared demand refuses.
///
/// The caller supplies the demand; the placement declares it. If admission trusted the caller's
/// number it would admit against a demand the placement never committed to, which is the whole
/// substitution the check exists to stop.
#[test]
fn a_demand_that_does_not_match_the_pinned_placement_refuses_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);
    let mut understated_chirho = staged_chirho.demand_chirho;
    understated_chirho.cpu_millicores_chirho -= 1;
    assert_ne!(
        understated_chirho.cpu_millicores_chirho, staged_chirho.demand_chirho.cpu_millicores_chirho,
        "fixture control: the substituted demand must actually differ"
    );

    let verdict_chirho = staged_chirho.adapter_chirho().admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &understated_chirho,
        &staged_chirho.headroom_chirho,
    );
    assert_eq!(
        verdict_chirho.evidence_identity_chirho,
        failure_identity_chirho(
            &staged_chirho.target_node_id_chirho,
            "current-tenant-demand-changed-chirho"
        ),
        "understating demand by ONE millicore must refuse -- a gate that only catches large \
         substitutions is not a gate"
    );
    assert!(!verdict_chirho.is_admitted_over_evidence_chirho());
}

/// A pinned placement the evidence population has already moved past refuses.
///
/// This is the staleness direction rather than the substitution direction: the adapter holds
/// revision 0 while the log's current head is revision 1, and the operator has re-pinned the
/// population digest to match the new head. Everything verifies; the two simply describe different
/// generations, and admitting against the older one would place work using a superseded assignment.
#[test]
fn a_pinned_placement_the_population_moved_past_refuses_chirho() {
    let staged_chirho = stage_evidence_chirho(3_000);

    // POSITIVE CONTROL: before the population moves, this exact adapter admits.
    assert!(
        verdict_for_chirho(&staged_chirho, &staged_chirho.target_node_id_chirho)
            .is_admitted_over_evidence_chirho(),
        "the control must admit, or the refusal below could come from anything"
    );

    let revision_zero_digest_chirho = staged_chirho
        .current_placement_chirho
        .assignment_digest_chirho()
        .to_string();
    let revision_one_chirho = crate::attestation_stores_chirho::placement_record_store_chirho::tests_chirho::successor_chirho(
        &staged_chirho.placement_fixture_chirho,
        &staged_chirho.placement_fixture_chirho.record_chirho,
        1,
        Some(revision_zero_digest_chirho.clone()),
    );
    let revision_one_verified_chirho = append_verified_placement_record_chirho(
        &staged_chirho.config_chirho.evidence_root_chirho,
        revision_one_chirho,
        &staged_chirho.placement_fixture_chirho.placement_key_chirho,
        &staged_chirho.placement_fixture_chirho.roster_key_chirho,
        &staged_chirho.placement_fixture_chirho.plan_key_chirho,
    )
    .expect("a correctly chained revision 1 appends");
    assert_ne!(
        revision_one_verified_chirho.assignment_digest_chirho(),
        revision_zero_digest_chirho,
        "fixture control: the population must actually have moved"
    );

    // The operator re-pins the population to the NEW head, but the adapter still holds revision 0.
    let mut repinned_chirho = staged_chirho.config_chirho.clone();
    repinned_chirho.expected_placement_population_digest_chirho =
        tenant_placement_population_digest_chirho(&[revision_one_verified_chirho
            .assignment_digest_chirho()
            .to_string()]);

    let verdict_chirho = VerifiedTenantCapacityAdmissionChirho::new_chirho(
        repinned_chirho,
        Arc::clone(&staged_chirho.current_placement_chirho),
    )
    .expect("the re-pinned config still resolves")
    .admit_target_chirho(
        &staged_chirho.target_node_id_chirho,
        &staged_chirho.demand_chirho,
        &staged_chirho.headroom_chirho,
    );

    assert_eq!(
        verdict_chirho.evidence_identity_chirho,
        failure_identity_chirho(
            &staged_chirho.target_node_id_chirho,
            "current-tenant-assignment-changed-chirho"
        ),
        "a stale pinned placement must refuse by ASSIGNMENT-CHANGED -- not by population mismatch, \
         which the operator's re-pin deliberately repaired so this arm cannot pass for that reason"
    );
    assert!(!verdict_chirho.is_admitted_over_evidence_chirho());
}
