// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for building a registry from durable evidence.
//!
//! The centrepiece is [`a_grant_alone_never_admits_placements_chirho`]: it asserts the practical
//! consequence rather than the field. `admits_new_placement_chirho` is what actually decides whether a
//! node can take work, so an arm that checked only the enum would still pass if the consequence were
//! wired the other way.

use super::*;
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::*;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::*;
use cairn_placement_chirho::node_lifecycle_chirho::{
    admits_new_placement_chirho, LifecycleTransitionChirho, NodeLifecycleStateChirho,
};

const KEY_CHIRHO: &str = "authority-key-1-chirho";

struct TestAuthorityChirho;

impl crate::placement_registry_load_chirho::NodeMeasurementAuthorityResolverChirho
    for TestAuthorityChirho
{
    fn authority_for_node_chirho(
        &self,
        _node_id_chirho: &str,
    ) -> Option<&dyn cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::NodeMeasurementAuthorityPortChirho>
    {
        Some(self)
    }
}

impl cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::NodeMeasurementAuthorityPortChirho
    for TestAuthorityChirho
{
    fn node_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

impl NodeRegistrationAuthorityPortChirho for TestAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

impl LifecycleAuthorityPortChirho for TestAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

fn grant_chirho(node_chirho: &str) -> NodeCapacityAttestationChirho {
    let intent_chirho = NodeCapacityIntentChirho {
        schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_chirho.to_string(),
        domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "eu-central-chirho".to_string(),
        },
        allocatable_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 4000,
            memory_bytes_chirho: 8 << 30,
            durable_bytes_chirho: 200 << 30,
        },
        registration_seq_chirho: 1,
    };
    let digest_chirho = node_capacity_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = NodeCapacityAttestationChirho {
        schema_chirho: NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_node_capacity_message_chirho(&record_chirho)
    );
    record_chirho
}

fn transition_chirho(
    node_chirho: &str,
    from_chirho: NodeLifecycleStateChirho,
    t_chirho: LifecycleTransitionChirho,
    seq_chirho: u64,
) -> LifecycleTransitionAttestationChirho {
    let intent_chirho = LifecycleTransitionIntentChirho {
        schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_chirho.to_string(),
        from_state_chirho: from_chirho,
        transition_chirho: t_chirho,
        asserted_facts_chirho: AssertedLifecycleFactsChirho {
            holds_leadership_chirho: false,
            ownership_proven_chirho: true,
            resident_placements_chirho: 0,
        },
        transition_seq_chirho: seq_chirho,
    };
    let digest_chirho = lifecycle_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = LifecycleTransitionAttestationChirho {
        schema_chirho: LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_lifecycle_message_chirho(&record_chirho)
    );
    record_chirho
}

fn seed_grant_chirho(root_chirho: &std::path::Path, node_chirho: &str) {
    crate::attestation_stores_chirho::capacity_attestation_store_chirho::append_verified_capacity_attestation_chirho(
        root_chirho,
        &grant_chirho(node_chirho),
        &TestAuthorityChirho,
    )
    .expect("seed grant");
}

#[test]
fn a_grant_alone_never_admits_placements_chirho() {
    // THE property, asserted at the CONSEQUENCE rather than the field. A node with a signed capacity
    // grant and no signed transitions must not be able to take work.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, "node-a-chirho");

    let registry_chirho = load_verified_placement_registry_chirho(
        root_chirho,
        &["node-a-chirho".to_string()],
        &TestAuthorityChirho,
        &TestAuthorityChirho,
        &TestAuthorityChirho,
    )
    .expect("a granted node must load");
    let node_chirho = registry_chirho
        .node_chirho("node-a-chirho")
        .expect("node present");
    assert_eq!(
        node_chirho.lifecycle_chirho(),
        NodeLifecycleStateChirho::ProvisionedChirho
    );
    assert!(
        !admits_new_placement_chirho(node_chirho.lifecycle_chirho()),
        "a capacity grant alone must never make a node able to take placements"
    );
    // The capacity itself did survive the trip, so this is not passing because the node is empty.
    assert_eq!(node_chirho.allocatable_chirho().cpu_millicores_chirho, 4000);
}

#[test]
fn signed_transitions_carry_a_node_to_joined_and_only_then_it_admits_placements_chirho() {
    // The positive half: refusing to invent Joined must not also make Joined unreachable.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, "node-a-chirho");
    for (from_chirho, t_chirho, seq_chirho) in [
        (
            NodeLifecycleStateChirho::ProvisionedChirho,
            LifecycleTransitionChirho::InspectChirho,
            1u64,
        ),
        (
            NodeLifecycleStateChirho::InspectedChirho,
            LifecycleTransitionChirho::JoinChirho,
            2u64,
        ),
    ] {
        crate::attestation_stores_chirho::lifecycle_transition_store_chirho::append_verified_lifecycle_transition_chirho(
            root_chirho,
            &transition_chirho("node-a-chirho", from_chirho, t_chirho, seq_chirho),
            &TestAuthorityChirho,
        )
        .expect("append transition");
    }

    let registry_chirho = load_verified_placement_registry_chirho(
        root_chirho,
        &["node-a-chirho".to_string()],
        &TestAuthorityChirho,
        &TestAuthorityChirho,
        &TestAuthorityChirho,
    )
    .expect("load");
    let node_chirho = registry_chirho
        .node_chirho("node-a-chirho")
        .expect("node present");
    assert_eq!(
        node_chirho.lifecycle_chirho(),
        NodeLifecycleStateChirho::JoinedChirho
    );
    assert!(admits_new_placement_chirho(node_chirho.lifecycle_chirho()));
}

#[test]
fn a_node_with_no_grant_refuses_by_name_rather_than_being_skipped_chirho() {
    // Silently omitting it would hand back a registry that LOOKS complete and is quietly smaller than
    // asked for, and a placement decision made against a short registry reads as fine.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, "node-a-chirho");
    let refusal_chirho = load_verified_placement_registry_chirho(
        root_chirho,
        &["node-a-chirho".to_string(), "node-b-chirho".to_string()],
        &TestAuthorityChirho,
        &TestAuthorityChirho,
        &TestAuthorityChirho,
    )
    .expect_err("an ungranted node must refuse");
    match refusal_chirho {
        RegistryLoadRefusalChirho::NoCapacityGrantChirho { node_id_chirho } => {
            assert_eq!(node_id_chirho, "node-b-chirho");
        }
        other_chirho => panic!("expected NoCapacityGrant naming the node, got {other_chirho:?}"),
    }
}

#[test]
fn one_nodes_transitions_do_not_advance_another_chirho() {
    // Two granted nodes, transitions for only one. The other must stay at the entry state -- the
    // registry is per-node evidence, not a shared timeline.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, "node-a-chirho");
    seed_grant_chirho(root_chirho, "node-b-chirho");
    crate::attestation_stores_chirho::lifecycle_transition_store_chirho::append_verified_lifecycle_transition_chirho(
        root_chirho,
        &transition_chirho(
            "node-a-chirho",
            NodeLifecycleStateChirho::ProvisionedChirho,
            LifecycleTransitionChirho::InspectChirho,
            1,
        ),
        &TestAuthorityChirho,
    )
    .expect("append");

    let registry_chirho = load_verified_placement_registry_chirho(
        root_chirho,
        &["node-a-chirho".to_string(), "node-b-chirho".to_string()],
        &TestAuthorityChirho,
        &TestAuthorityChirho,
        &TestAuthorityChirho,
    )
    .expect("load");
    assert_eq!(
        registry_chirho
            .node_chirho("node-a-chirho")
            .unwrap()
            .lifecycle_chirho(),
        NodeLifecycleStateChirho::InspectedChirho
    );
    assert_eq!(
        registry_chirho
            .node_chirho("node-b-chirho")
            .unwrap()
            .lifecycle_chirho(),
        NodeLifecycleStateChirho::ProvisionedChirho,
        "node-b has no transitions of its own and must not inherit node-a's"
    );
}

// ---- The usage log reaching the registry, off disk ----
//
// Until these, the durable usage store and the registry's measurement advance existed and had never
// met: the store proved the log and the registry proved the arithmetic, with nothing joining them.

use cairn_placement_chirho::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::{
    unsigned_usage_message_chirho, usage_intent_digest_chirho, UsageMeasurementAttestationChirho,
    UsageMeasurementIntentChirho, USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO,
    USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO, USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO,
};

/// A resolver that declares no key for any node.
struct NoMeasurementKeyChirho;

impl crate::placement_registry_load_chirho::NodeMeasurementAuthorityResolverChirho
    for NoMeasurementKeyChirho
{
    fn authority_for_node_chirho(
        &self,
        _node_id_chirho: &str,
    ) -> Option<&dyn cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::NodeMeasurementAuthorityPortChirho>
    {
        None
    }
}

fn seed_measurement_chirho(
    root_chirho: &std::path::Path,
    node_chirho: &str,
    hlc_millis_chirho: u64,
    sequence_chirho: u64,
) {
    let intent_chirho = UsageMeasurementIntentChirho {
        schema_chirho: USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_chirho.to_string(),
        stamp_chirho: MeasurementStampChirho {
            hlc_millis_chirho,
            sequence_chirho,
        },
        observed_usage_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 500,
            memory_bytes_chirho: 1 << 30,
            durable_bytes_chirho: 10 << 30,
        },
    };
    let digest_chirho = usage_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = UsageMeasurementAttestationChirho {
        schema_chirho: USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        node_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho =
        format!("sig-over:{}", unsigned_usage_message_chirho(&record_chirho));
    crate::attestation_stores_chirho::usage_measurement_store_chirho::append_verified_usage_measurement_chirho(
        root_chirho,
        &record_chirho,
        &TestAuthorityChirho,
    )
    .expect("seed measurement");
}

#[test]
fn a_node_whose_latest_logged_report_is_a_replay_loads_frozen_chirho() {
    // The whole chain off disk: node-signed report -> durable log -> loader -> registry -> admission.
    // Nothing in this arm sets a posture or a baseline by hand.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, "node-a-chirho");
    seed_measurement_chirho(root_chirho, "node-a-chirho", 1_000, 5);
    seed_measurement_chirho(root_chirho, "node-a-chirho", 2_000, 5); // a replay

    let registry_chirho = load_verified_placement_registry_chirho(
        root_chirho,
        &["node-a-chirho".to_string()],
        &TestAuthorityChirho,
        &TestAuthorityChirho,
        &TestAuthorityChirho,
    )
    .expect("the registry must still load — a replay freezes the node, it does not fail the load");

    let node_chirho = registry_chirho
        .node_chirho("node-a-chirho")
        .expect("node present");

    // ATTRIBUTION FIRST, and this assertion is why the arm means anything. A never-measured node is
    // ALSO frozen, so "frozen" alone passes with the loader's measurement wiring DELETED -- which is
    // exactly what a mutation showed before this line existed. The accepted baseline proves the log
    // was read and the FIRST report applied, so the freeze can only have come from the second.
    assert_eq!(
        node_chirho.last_measurement_chirho(),
        Some(MeasurementStampChirho {
            hlc_millis_chirho: 1_000,
            sequence_chirho: 5,
        }),
        "the loader must have applied the first report; without this, the freeze below is \
         indistinguishable from a node that was never measured at all"
    );
    assert!(
        !node_chirho
            .scaling_posture_chirho()
            .scale_out_allowed_chirho(),
        "a replayed latest report must freeze scale-out"
    );
    assert!(
        !node_chirho
            .scaling_posture_chirho()
            .scale_in_allowed_chirho(),
        "and scale-in too — acting on a replayed low-usage number would drain a busy node"
    );
}

#[test]
fn a_node_whose_logged_reports_are_fresh_loads_unfrozen_chirho() {
    // Positive control for the arm above: without it, a loader that froze everything would pass.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, "node-a-chirho");
    seed_measurement_chirho(root_chirho, "node-a-chirho", 1_000, 5);
    seed_measurement_chirho(root_chirho, "node-a-chirho", 2_000, 6);

    let registry_chirho = load_verified_placement_registry_chirho(
        root_chirho,
        &["node-a-chirho".to_string()],
        &TestAuthorityChirho,
        &TestAuthorityChirho,
        &TestAuthorityChirho,
    )
    .expect("loads");
    let node_chirho = registry_chirho
        .node_chirho("node-a-chirho")
        .expect("node present");
    assert!(node_chirho
        .scaling_posture_chirho()
        .scale_out_allowed_chirho());
    assert!(node_chirho
        .scaling_posture_chirho()
        .scale_in_allowed_chirho());
}

#[test]
fn a_node_with_no_declared_measurement_key_is_refused_not_skipped_chirho() {
    // A node whose measurements cannot be verified must not load looking exactly like a node whose
    // measurements were verified and found fine.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, "node-a-chirho");

    assert_eq!(
        load_verified_placement_registry_chirho(
            root_chirho,
            &["node-a-chirho".to_string()],
            &TestAuthorityChirho,
            &TestAuthorityChirho,
            &NoMeasurementKeyChirho,
        )
        .expect_err("a node with no measurement verifier must refuse"),
        RegistryLoadRefusalChirho::NoMeasurementKeyForNodeChirho {
            node_id_chirho: "node-a-chirho".to_string(),
        }
    );
}

/// The control-plane report renders as parseable JSON, and the render path had NO arm at all.
///
/// Measured 2026-08-21: `render_placement_control_plane_report_chirho` had zero test sites. It is the
/// last step of the `placement-control-verify` operator command, so everything the registry proves
/// reaches a human through this function.
///
/// **Its ERROR identity is deliberately not armed, and that is a statement rather than an omission.**
/// `PlacementControlPlaneReportChirho` is Strings, bools, enums, u64-bearing structs, `Vec` and
/// `Option<Vec<String>>` — no floats and no non-string map keys — so `serde_json::to_string` cannot
/// fail and `RenderChirho` is unreachable. Manufacturing a fixture to reach it would pin a shape
/// production cannot produce. The variant exists so the encode failure does not BORROW an identity
/// that asserts something false, which is a claim about naming, not about behaviour.
#[test]
fn a_control_plane_report_renders_as_parseable_json_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    seed_grant_chirho(root_chirho, "node-a-chirho");

    let registry_chirho = load_verified_placement_registry_chirho(
        root_chirho,
        &["node-a-chirho".to_string()],
        &TestAuthorityChirho,
        &TestAuthorityChirho,
        &TestAuthorityChirho,
    )
    .expect("a granted node must load");
    let report_chirho = build_placement_control_plane_report_chirho(
        &registry_chirho,
        &["node-a-chirho".to_string()],
        None,
    );

    let rendered_chirho =
        render_placement_control_plane_report_chirho(&report_chirho).expect("the report renders");
    let parsed_chirho: serde_json::Value =
        serde_json::from_str(&rendered_chirho).expect("and the render is parseable JSON");

    assert_eq!(
        parsed_chirho["schema_chirho"], PLACEMENT_CONTROL_PLANE_REPORT_SCHEMA_V1_CHIRHO,
        "the schema must survive the render, or a consumer cannot tell what it is reading"
    );
    assert_eq!(
        parsed_chirho["nodes_chirho"][0]["node_id_chirho"], "node-a-chirho",
        "and the node must actually be in it — a render of an EMPTY report would satisfy a check \
         that only asserted the render succeeded"
    );
    assert_eq!(
        parsed_chirho["nodes_chirho"][0]["probe_refusals_chirho"],
        serde_json::Value::Null,
        "NOT PROBED must render as null rather than as an empty list: collapsing those two would let \
         'nobody asked' read as 'it would be admitted'"
    );
}
