// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! The composition proof itself: provision -> inspect -> join -> drain -> retire, off disk.

use crate::attestation_stores_chirho::capacity_attestation_store_chirho::append_verified_capacity_attestation_chirho;
use crate::attestation_stores_chirho::lifecycle_transition_store_chirho::{
    append_verified_lifecycle_transition_chirho, current_lifecycle_state_chirho,
    LifecycleStoreRefusalChirho,
};
use crate::placement_registry_load_chirho::load_verified_placement_registry_chirho;
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::*;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::*;
use cairn_placement_chirho::node_lifecycle_chirho::{
    admits_new_placement_chirho, LifecycleTransitionChirho, NodeLifecycleStateChirho,
};
use std::path::Path;

const KEY_CHIRHO: &str = "authority-key-1-chirho";
const NODE_CHIRHO: &str = "node-a-chirho";

struct AuthorityChirho;

impl crate::placement_registry_load_chirho::NodeMeasurementAuthorityResolverChirho
    for AuthorityChirho
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
    for AuthorityChirho
{
    fn node_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

impl NodeRegistrationAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

impl LifecycleAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

fn provision_chirho(root_chirho: &Path) {
    let intent_chirho = NodeCapacityIntentChirho {
        schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: NODE_CHIRHO.to_string(),
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
    append_verified_capacity_attestation_chirho(root_chirho, &record_chirho, &AuthorityChirho)
        .expect("provision: the capacity grant must append");
}

fn step_chirho(
    root_chirho: &Path,
    from_chirho: NodeLifecycleStateChirho,
    t_chirho: LifecycleTransitionChirho,
    seq_chirho: u64,
    leadership_chirho: bool,
    ownership_chirho: bool,
    placements_chirho: u32,
) -> Result<NodeLifecycleStateChirho, LifecycleStoreRefusalChirho> {
    let intent_chirho = LifecycleTransitionIntentChirho {
        schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: NODE_CHIRHO.to_string(),
        from_state_chirho: from_chirho,
        transition_chirho: t_chirho,
        asserted_facts_chirho: AssertedLifecycleFactsChirho {
            holds_leadership_chirho: leadership_chirho,
            ownership_proven_chirho: ownership_chirho,
            resident_placements_chirho: placements_chirho,
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
    append_verified_lifecycle_transition_chirho(root_chirho, &record_chirho, &AuthorityChirho)
}

fn admits_chirho(root_chirho: &Path) -> bool {
    let registry_chirho = load_verified_placement_registry_chirho(
        root_chirho,
        &[NODE_CHIRHO.to_string()],
        &AuthorityChirho,
        &AuthorityChirho,
        &AuthorityChirho,
    )
    .expect("the registry must load from durable evidence");
    admits_new_placement_chirho(
        registry_chirho
            .node_chirho(NODE_CHIRHO)
            .expect("node present")
            .lifecycle_chirho(),
    )
}

#[test]
fn the_full_composition_runs_off_disk_and_each_named_property_holds_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();

    // PROVISION -- a grant alone, and the node cannot take work yet.
    provision_chirho(root_chirho);
    assert_eq!(
        current_lifecycle_state_chirho(root_chirho, NODE_CHIRHO, &AuthorityChirho).unwrap(),
        NodeLifecycleStateChirho::ProvisionedChirho
    );
    assert!(
        !admits_chirho(root_chirho),
        "provisioned must not admit placements"
    );

    // INSPECT -- still not admitting.
    assert_eq!(
        step_chirho(
            root_chirho,
            NodeLifecycleStateChirho::ProvisionedChirho,
            LifecycleTransitionChirho::InspectChirho,
            1,
            false,
            true,
            0
        )
        .unwrap(),
        NodeLifecycleStateChirho::InspectedChirho
    );
    assert!(
        !admits_chirho(root_chirho),
        "inspected must not admit placements"
    );

    // JOIN -- the only state that admits work.
    assert_eq!(
        step_chirho(
            root_chirho,
            NodeLifecycleStateChirho::InspectedChirho,
            LifecycleTransitionChirho::JoinChirho,
            2,
            false,
            true,
            0
        )
        .unwrap(),
        NodeLifecycleStateChirho::JoinedChirho
    );
    assert!(admits_chirho(root_chirho), "joined must admit placements");

    // DRAIN -- "no new placement during drain", asserted off disk rather than in memory.
    assert_eq!(
        step_chirho(
            root_chirho,
            NodeLifecycleStateChirho::JoinedChirho,
            LifecycleTransitionChirho::DrainChirho,
            3,
            false,
            true,
            0
        )
        .unwrap(),
        NodeLifecycleStateChirho::DrainingChirho
    );
    assert!(
        !admits_chirho(root_chirho),
        "NO NEW PLACEMENT DURING DRAIN -- the clause's property, read back through the registry"
    );

    // RETIRE is gated by three independently sufficient preconditions. Each is refused ALONE, so the
    // proof shows the gate rather than a happy path with a gate somewhere near it.
    for (label_chirho, leadership_chirho, ownership_chirho, placements_chirho) in [
        ("leadership not handed off", true, true, 0),
        ("ownership not proven", false, false, 0),
        ("placements still resident", false, true, 2),
    ] {
        let refusal_chirho = step_chirho(
            root_chirho,
            NodeLifecycleStateChirho::DrainingChirho,
            LifecycleTransitionChirho::RetireChirho,
            4,
            leadership_chirho,
            ownership_chirho,
            placements_chirho,
        )
        .expect_err(&format!("retire must refuse: {label_chirho}"));
        assert_eq!(
            refusal_chirho,
            LifecycleStoreRefusalChirho::NotVerifiedChirho,
            "an illegal retire is refused before it reaches the log: {label_chirho}"
        );
        assert_eq!(
            current_lifecycle_state_chirho(root_chirho, NODE_CHIRHO, &AuthorityChirho).unwrap(),
            NodeLifecycleStateChirho::DrainingChirho,
            "a refused retire must leave the node draining: {label_chirho}"
        );
    }

    // RETIRE succeeds only with all three clean -- LEADERSHIP HANDED OFF, OWNERSHIP PROVEN, NO
    // PLACEMENTS RESIDENT.
    assert_eq!(
        step_chirho(
            root_chirho,
            NodeLifecycleStateChirho::DrainingChirho,
            LifecycleTransitionChirho::RetireChirho,
            4,
            false,
            true,
            0
        )
        .unwrap(),
        NodeLifecycleStateChirho::RetiredChirho
    );
    assert!(
        !admits_chirho(root_chirho),
        "retired must not admit placements"
    );
    assert_eq!(
        current_lifecycle_state_chirho(root_chirho, NODE_CHIRHO, &AuthorityChirho).unwrap(),
        NodeLifecycleStateChirho::RetiredChirho,
        "the whole sequence is derivable from the log alone"
    );
}
