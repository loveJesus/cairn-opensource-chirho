// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The mirror's joined production view: verified tenant placement joined to one coherent live Raft
//! observation. Placement names exactly three serving voters plus one held observer; Raft must report
//! those exact roles and authenticated identities at one applied configuration. Leadership, term, and
//! configuration come only from Raft. Failure domains and the assignment digest come only from the
//! verified placement. No static "leader" role survives in the placement half.
//!
//! A routine learner addition creates a second learner and therefore refuses this join. Mirror-gated
//! tenant writes deliberately halt for that membership-transition window rather than accepting a
//! holder population not authorized by the signed placement.

use crate::digest_chirho::{
    update_digest_field_chirho, valid_lower_hex_chirho, DIGEST_HEX_BYTES_CHIRHO,
    NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use cairn_write_relay_chirho::RelayRosterChirho;
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftElectionObservationChirho;
use std::collections::{BTreeMap, BTreeSet};

const MIRROR_MEMBERSHIP_VIEW_DIGEST_DOMAIN_V2_CHIRHO: &[u8] =
    b"cairn-mirror-membership-view-v2-chirho";
const MIRROR_SERVING_HOLDER_COUNT_CHIRHO: usize = 3;
const MIRROR_TRANSPORT_MEMBER_COUNT_CHIRHO: usize = 4;
const MIRROR_DOMAIN_LABEL_MAX_BYTES_CHIRHO: usize = 64;

/// One coherent observation of the receiver's live election authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorElectionObservationChirho {
    pub leadership_chirho: LeadershipChirho,
    pub authenticated_members_chirho: Vec<(u64, NodeIdChirho)>,
    pub voter_raft_ids_chirho: Vec<u64>,
    pub learner_raft_ids_chirho: Vec<u64>,
    pub applied_conf_index_chirho: u64,
    pub leader_lease_remaining_millis_chirho: Option<u64>,
}

impl MirrorElectionObservationChirho {
    /// Attenuate the generic elector observation into the mirror's read-only input.
    pub fn from_raft_chirho(observation_chirho: &RaftElectionObservationChirho) -> Self {
        Self {
            leadership_chirho: observation_chirho.leadership_chirho().clone(),
            authenticated_members_chirho: observation_chirho
                .authenticated_members_chirho()
                .to_vec(),
            voter_raft_ids_chirho: observation_chirho.voter_raft_ids_chirho().to_vec(),
            learner_raft_ids_chirho: observation_chirho.learner_raft_ids_chirho().to_vec(),
            applied_conf_index_chirho: observation_chirho.applied_conf_index_chirho(),
            leader_lease_remaining_millis_chirho: observation_chirho
                .leader_lease_remaining_millis_chirho(),
        }
    }
}

/// Read-only election observation port. Production implements this over one exact running elector.
pub trait MirrorLeadershipViewChirho: Send + Sync {
    fn observe_election_chirho(
        &self,
    ) -> Result<MirrorElectionObservationChirho, MirrorContractErrorChirho>;
}

/// One placement-authorized serving holder. Leadership is intentionally absent; it is observed live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorHolderChirho {
    node_id_chirho: String,
    failure_domain_chirho: FailureDomainChirho,
}

impl MirrorHolderChirho {
    pub fn new_chirho(
        node_id_chirho: impl Into<String>,
        failure_domain_chirho: FailureDomainChirho,
    ) -> Result<Self, MirrorContractErrorChirho> {
        let holder_chirho = Self {
            node_id_chirho: node_id_chirho.into(),
            failure_domain_chirho,
        };
        if !valid_lower_hex_chirho(&holder_chirho.node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO) {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorOriginNodeInvalidChirho,
                "mirror holder node id must be canonical public-key hex",
            ));
        }
        if !valid_domain_label_chirho(&holder_chirho.failure_domain_chirho.provider_chirho)
            || !valid_domain_label_chirho(&holder_chirho.failure_domain_chirho.region_chirho)
        {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho,
                "mirror holder failure domain must contain bounded canonical labels",
            ));
        }
        Ok(holder_chirho)
    }

    pub fn node_id_chirho(&self) -> &str {
        &self.node_id_chirho
    }

    pub fn failure_domain_chirho(&self) -> &FailureDomainChirho {
        &self.failure_domain_chirho
    }
}

/// The exact placement/election view bound into each mirror frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorMembershipViewChirho {
    consistency_group_digest_chirho: String,
    assignment_digest_chirho: String,
    term_chirho: u64,
    applied_conf_index_chirho: u64,
    serving_holders_chirho: Vec<MirrorHolderChirho>,
    held_observer_chirho: MirrorHolderChirho,
}

impl MirrorMembershipViewChirho {
    fn from_join_chirho(
        placement_chirho: &VerifiedTenantPlacementChirho,
        observation_chirho: &MirrorElectionObservationChirho,
    ) -> Result<Self, MirrorContractErrorChirho> {
        if observation_chirho.leadership_chirho.term_chirho == 0 {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorTermInvalidChirho,
                "mirror joined view term must be nonzero",
            ));
        }
        let serving_holders_chirho = placement_chirho
            .assigned_nodes_chirho()
            .iter()
            .map(|binding_chirho| {
                MirrorHolderChirho::new_chirho(
                    binding_chirho.node_id_chirho.clone(),
                    binding_chirho.failure_domain_chirho.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        if serving_holders_chirho.len() != MIRROR_SERVING_HOLDER_COUNT_CHIRHO {
            return Err(MirrorContractErrorChirho::holder_set_unsatisfiable_chirho());
        }
        let held_binding_chirho = placement_chirho.held_observer_node_chirho();
        let held_observer_chirho = MirrorHolderChirho::new_chirho(
            held_binding_chirho.node_id_chirho.clone(),
            held_binding_chirho.failure_domain_chirho.clone(),
        )?;
        let consistency_group_digest_chirho = blake3::hash(
            placement_chirho
                .intent_chirho()
                .consistency_group_id_chirho
                .as_bytes(),
        )
        .to_hex()
        .to_string();
        let assignment_digest_chirho = placement_chirho.assignment_digest_chirho().to_string();
        if !valid_lower_hex_chirho(&consistency_group_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
            || !valid_lower_hex_chirho(&assignment_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
        {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho,
                "mirror placement group or assignment digest is not canonical hex",
            ));
        }
        Ok(Self {
            consistency_group_digest_chirho,
            assignment_digest_chirho,
            term_chirho: observation_chirho.leadership_chirho.term_chirho,
            applied_conf_index_chirho: observation_chirho.applied_conf_index_chirho,
            serving_holders_chirho,
            held_observer_chirho,
        })
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }

    pub fn term_chirho(&self) -> u64 {
        self.term_chirho
    }

    pub fn applied_conf_index_chirho(&self) -> u64 {
        self.applied_conf_index_chirho
    }

    pub fn holders_chirho(&self) -> &[MirrorHolderChirho] {
        &self.serving_holders_chirho
    }

    pub fn held_observer_chirho(&self) -> &MirrorHolderChirho {
        &self.held_observer_chirho
    }

    pub fn contains_chirho(&self, node_id_chirho: &str) -> bool {
        self.serving_holders_chirho
            .iter()
            .any(|holder_chirho| holder_chirho.node_id_chirho == node_id_chirho)
            || self.held_observer_chirho.node_id_chirho == node_id_chirho
    }

    pub fn is_serving_holder_chirho(&self, node_id_chirho: &str) -> bool {
        self.serving_holders_chirho
            .iter()
            .any(|holder_chirho| holder_chirho.node_id_chirho == node_id_chirho)
    }

    pub fn holder_chirho(&self, node_id_chirho: &str) -> Option<&MirrorHolderChirho> {
        self.serving_holders_chirho
            .iter()
            .find(|holder_chirho| holder_chirho.node_id_chirho == node_id_chirho)
    }

    /// Transport authentication includes all three voters and the held learner; holder selection does
    /// not. Authority verification separately requires sender and receiver to be serving holders.
    pub fn relay_roster_chirho(&self) -> Result<RelayRosterChirho, MirrorContractErrorChirho> {
        RelayRosterChirho::new_chirho(
            self.serving_holders_chirho
                .iter()
                .map(|holder_chirho| holder_chirho.node_id_chirho.clone())
                .chain(std::iter::once(
                    self.held_observer_chirho.node_id_chirho.clone(),
                )),
        )
        .map_err(|_| {
            MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho,
                "mirror membership view does not form a valid bounded transport roster",
            )
        })
    }

    pub fn view_digest_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(MIRROR_MEMBERSHIP_VIEW_DIGEST_DOMAIN_V2_CHIRHO);
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"group-digest-chirho",
            self.consistency_group_digest_chirho.as_bytes(),
        );
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"assignment-digest-chirho",
            self.assignment_digest_chirho.as_bytes(),
        );
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"term-chirho",
            &self.term_chirho.to_le_bytes(),
        );
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"applied-conf-index-chirho",
            &self.applied_conf_index_chirho.to_le_bytes(),
        );
        for holder_chirho in &self.serving_holders_chirho {
            update_holder_digest_chirho(&mut hasher_chirho, b"serving-holder", holder_chirho);
        }
        update_holder_digest_chirho(
            &mut hasher_chirho,
            b"held-observer",
            &self.held_observer_chirho,
        );
        hasher_chirho.finalize().to_hex().to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinedMirrorViewChirho {
    view_chirho: MirrorMembershipViewChirho,
    leadership_chirho: LeadershipChirho,
    leader_lease_remaining_millis_chirho: Option<u64>,
}

impl JoinedMirrorViewChirho {
    pub fn view_chirho(&self) -> &MirrorMembershipViewChirho {
        &self.view_chirho
    }

    pub fn leadership_chirho(&self) -> &LeadershipChirho {
        &self.leadership_chirho
    }

    pub fn term_chirho(&self) -> u64 {
        self.view_chirho.term_chirho
    }

    pub fn elected_leader_node_id_chirho(&self) -> Option<&str> {
        self.leadership_chirho
            .leader_id_chirho
            .as_ref()
            .map(|leader_chirho| leader_chirho.0.as_str())
    }

    pub fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.leader_lease_remaining_millis_chirho
    }

    /// Whether this node may SEND as this view's elected leader: the election names it the established leader, it
    /// holds a valid lease, and a remaining lease is present to carry in a frame. It is the one sender's predicate,
    /// shared by the ledger mirror's sender and erasure propagation's, so the two cannot drift (C5 B3-a3, item 14
    /// D3). A RECEIVER never consults its own leader bit (reviewer F1); it uses
    /// `verify_mirror_receiver_elected_leader_chirho`.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn local_sender_is_elected_leader_chirho(&self, local_node_id_chirho: &str) -> bool {
        self.leadership_chirho.is_leader_chirho
            && self.leadership_chirho.lease_valid_chirho
            && self.elected_leader_node_id_chirho() == Some(local_node_id_chirho)
            && self.leader_lease_remaining_millis_chirho.is_some()
    }
}

/// Join verified placement to one coherent live election observation.
pub fn join_mirror_view_chirho(
    placement_chirho: &VerifiedTenantPlacementChirho,
    election_view_chirho: &dyn MirrorLeadershipViewChirho,
) -> Result<JoinedMirrorViewChirho, MirrorContractErrorChirho> {
    let observation_chirho = election_view_chirho.observe_election_chirho()?;
    let auth_by_raft_chirho = exact_authenticated_map_chirho(&observation_chirho)?;
    let assigned_nodes_chirho = placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<BTreeSet<_>>();
    let held_observer_node_chirho = &placement_chirho.held_observer_node_chirho().node_id_chirho;
    let expected_transport_nodes_chirho = assigned_nodes_chirho
        .iter()
        .cloned()
        .chain(std::iter::once(held_observer_node_chirho.clone()))
        .collect::<BTreeSet<_>>();
    let authenticated_nodes_chirho = auth_by_raft_chirho
        .values()
        .map(|node_chirho| node_chirho.0.clone())
        .collect::<BTreeSet<_>>();
    if auth_by_raft_chirho.len() < MIRROR_TRANSPORT_MEMBER_COUNT_CHIRHO {
        return Err(MirrorContractErrorChirho::authenticated_member_population_incomplete_chirho());
    }
    if auth_by_raft_chirho.len() > MIRROR_TRANSPORT_MEMBER_COUNT_CHIRHO {
        return Err(MirrorContractErrorChirho::authenticated_member_population_excess_chirho());
    }
    if authenticated_nodes_chirho != expected_transport_nodes_chirho {
        return Err(MirrorContractErrorChirho::authenticated_member_binding_mismatch_chirho());
    }
    let voter_nodes_chirho = resolve_role_nodes_chirho(
        &observation_chirho.voter_raft_ids_chirho,
        &auth_by_raft_chirho,
    )?;
    let learner_nodes_chirho = resolve_role_nodes_chirho(
        &observation_chirho.learner_raft_ids_chirho,
        &auth_by_raft_chirho,
    )?;
    if voter_nodes_chirho != assigned_nodes_chirho {
        return Err(MirrorContractErrorChirho::placement_election_population_mismatch_chirho());
    }
    if learner_nodes_chirho.len() != 1 || !learner_nodes_chirho.contains(held_observer_node_chirho)
    {
        return Err(MirrorContractErrorChirho::election_topology_mismatch_chirho());
    }
    if observation_chirho
        .leadership_chirho
        .leader_id_chirho
        .as_ref()
        .is_some_and(|leader_chirho| !assigned_nodes_chirho.contains(&leader_chirho.0))
    {
        return Err(MirrorContractErrorChirho::elected_leader_unassigned_chirho());
    }
    let view_chirho =
        MirrorMembershipViewChirho::from_join_chirho(placement_chirho, &observation_chirho)?;
    Ok(JoinedMirrorViewChirho {
        view_chirho,
        leadership_chirho: observation_chirho.leadership_chirho,
        leader_lease_remaining_millis_chirho: observation_chirho
            .leader_lease_remaining_millis_chirho,
    })
}

fn exact_authenticated_map_chirho(
    observation_chirho: &MirrorElectionObservationChirho,
) -> Result<BTreeMap<u64, NodeIdChirho>, MirrorContractErrorChirho> {
    let mut by_raft_chirho = BTreeMap::new();
    let mut node_ids_chirho = BTreeSet::new();
    for (raft_id_chirho, node_id_chirho) in &observation_chirho.authenticated_members_chirho {
        if *raft_id_chirho == 0
            || !valid_lower_hex_chirho(&node_id_chirho.0, NODE_ID_HEX_BYTES_CHIRHO)
            || by_raft_chirho
                .insert(*raft_id_chirho, node_id_chirho.clone())
                .is_some()
            || !node_ids_chirho.insert(node_id_chirho.0.clone())
        {
            return Err(MirrorContractErrorChirho::authenticated_member_identity_refused_chirho());
        }
    }
    Ok(by_raft_chirho)
}

fn resolve_role_nodes_chirho(
    raft_ids_chirho: &[u64],
    auth_by_raft_chirho: &BTreeMap<u64, NodeIdChirho>,
) -> Result<BTreeSet<String>, MirrorContractErrorChirho> {
    let mut nodes_chirho = BTreeSet::new();
    for raft_id_chirho in raft_ids_chirho {
        let node_chirho = auth_by_raft_chirho
            .get(raft_id_chirho)
            .ok_or_else(MirrorContractErrorChirho::election_role_resolution_refused_chirho)?;
        if !nodes_chirho.insert(node_chirho.0.clone()) {
            return Err(MirrorContractErrorChirho::election_role_resolution_refused_chirho());
        }
    }
    Ok(nodes_chirho)
}

fn update_holder_digest_chirho(
    hasher_chirho: &mut blake3::Hasher,
    role_chirho: &[u8],
    holder_chirho: &MirrorHolderChirho,
) {
    update_digest_field_chirho(hasher_chirho, b"holder-role-chirho", role_chirho);
    update_digest_field_chirho(
        hasher_chirho,
        b"holder-node-id-chirho",
        holder_chirho.node_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        hasher_chirho,
        b"holder-provider-chirho",
        holder_chirho
            .failure_domain_chirho
            .provider_chirho
            .as_bytes(),
    );
    update_digest_field_chirho(
        hasher_chirho,
        b"holder-region-chirho",
        holder_chirho.failure_domain_chirho.region_chirho.as_bytes(),
    );
}

fn valid_domain_label_chirho(label_chirho: &str) -> bool {
    !label_chirho.is_empty()
        && label_chirho.len() <= MIRROR_DOMAIN_LABEL_MAX_BYTES_CHIRHO
        && !label_chirho.starts_with('-')
        && !label_chirho.ends_with('-')
        && label_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase() || byte_chirho.is_ascii_digit() || byte_chirho == b'-'
        })
}

#[cfg(test)]
pub(crate) struct TestPlacementChirho {
    pub(crate) verified_chirho: VerifiedTenantPlacementChirho,
    pub(crate) assigned_nodes_chirho: Vec<String>,
    pub(crate) held_observer_chirho: String,
}

#[cfg(test)]
pub(crate) fn test_verified_placement_chirho() -> TestPlacementChirho {
    use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
    use cairn_tenant_placement_authority_chirho::{
        tenant_placement_intent_digest_chirho,
        unsigned_tenant_placement_held_observer_readiness_message_chirho,
        unsigned_tenant_placement_readiness_message_chirho,
        unsigned_tenant_placement_record_message_chirho, verify_tenant_placement_record_chirho,
        TenantPlacementHeldObserverReadinessReceiptChirho, TenantPlacementIntentChirho,
        TenantPlacementNodeBindingChirho, TenantPlacementNodeReadinessReceiptChirho,
        TenantPlacementRecordChirho, TenantPlacementResidencyChirho,
        TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO,
        TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO,
        TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO, TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO,
        TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO,
        TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO, TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO,
        TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO, TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn hex_chirho(bytes_chirho: &[u8]) -> String {
        bytes_chirho
            .iter()
            .map(|byte_chirho| format!("{byte_chirho:02x}"))
            .collect()
    }
    fn node_id_chirho(key_chirho: &SigningKey) -> String {
        hex_chirho(key_chirho.verifying_key().as_bytes())
    }
    fn sign_chirho(key_chirho: &SigningKey, bytes_chirho: &[u8]) -> String {
        hex_chirho(&key_chirho.sign(bytes_chirho).to_bytes())
    }

    let placement_key_chirho = SigningKey::from_bytes(&[1; 32]);
    let roster_key_chirho = SigningKey::from_bytes(&[2; 32]);
    let plan_key_chirho = SigningKey::from_bytes(&[3; 32]);
    let mut node_keys_chirho = (10_u8..14)
        .map(|seed_chirho| SigningKey::from_bytes(&[seed_chirho; 32]))
        .collect::<Vec<_>>();
    node_keys_chirho.sort_by_key(node_id_chirho);
    let held_key_chirho = node_keys_chirho.pop().expect("held key");
    let domains_chirho = [
        FailureDomainChirho {
            provider_chirho: "provider-a-chirho".to_string(),
            region_chirho: "region-a-chirho".to_string(),
        },
        FailureDomainChirho {
            provider_chirho: "provider-b-chirho".to_string(),
            region_chirho: "region-b-chirho".to_string(),
        },
        FailureDomainChirho {
            provider_chirho: "provider-b-chirho".to_string(),
            region_chirho: "region-c-chirho".to_string(),
        },
    ];
    let assigned_nodes_chirho = node_keys_chirho
        .iter()
        .enumerate()
        .map(
            |(index_chirho, key_chirho)| TenantPlacementNodeBindingChirho {
                node_id_chirho: node_id_chirho(key_chirho),
                failure_domain_chirho: domains_chirho[index_chirho].clone(),
                expected_root_binding_chirho: format!(
                    "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
                    char::from(b'a' + u8::try_from(index_chirho).unwrap())
                        .to_string()
                        .repeat(64)
                ),
                expected_cluster_config_blake3_chirho: char::from(
                    b'd' + u8::try_from(index_chirho).unwrap(),
                )
                .to_string()
                .repeat(64),
            },
        )
        .collect::<Vec<_>>();
    let held_observer_node_chirho = TenantPlacementNodeBindingChirho {
        node_id_chirho: node_id_chirho(&held_key_chirho),
        failure_domain_chirho: FailureDomainChirho {
            provider_chirho: "provider-a-chirho".to_string(),
            region_chirho: "region-held-chirho".to_string(),
        },
        expected_root_binding_chirho: format!(
            "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
            "1".repeat(64)
        ),
        expected_cluster_config_blake3_chirho: "2".repeat(64),
    };
    let mut allowed_domains_chirho = domains_chirho.to_vec();
    allowed_domains_chirho.sort();
    let intent_chirho = TenantPlacementIntentChirho {
        schema_chirho: TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        digest_domain_chirho: TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO.to_string(),
        revision_chirho: 0,
        previous_assignment_digest_chirho: None,
        tenant_id_chirho: "mirror-fixture-chirho".to_string(),
        consistency_group_id_chirho: "tenant-chirho:mirror-fixture-chirho".to_string(),
        assigned_nodes_chirho: assigned_nodes_chirho.clone(),
        held_observer_node_chirho: held_observer_node_chirho.clone(),
        preferred_node_chirho: assigned_nodes_chirho[0].node_id_chirho.clone(),
        demand_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 1,
            memory_bytes_chirho: 1,
            durable_bytes_chirho: 1,
        },
        residency_chirho: TenantPlacementResidencyChirho {
            allowed_domains_chirho,
        },
        topology_plan_digest_chirho: "f".repeat(64),
    };
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(&intent_chirho).unwrap();
    let serving_readiness_receipts_chirho = node_keys_chirho
        .iter()
        .zip(&assigned_nodes_chirho)
        .map(|(key_chirho, binding_chirho)| {
            let mut receipt_chirho = TenantPlacementNodeReadinessReceiptChirho {
                schema_chirho: TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO.to_string(),
                signature_domain_chirho: TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO
                    .to_string(),
                intent_digest_chirho: intent_digest_chirho.clone(),
                node_id_chirho: binding_chirho.node_id_chirho.clone(),
                failure_domain_chirho: binding_chirho.failure_domain_chirho.clone(),
                root_binding_chirho: binding_chirho.expected_root_binding_chirho.clone(),
                cluster_config_blake3_chirho: binding_chirho
                    .expected_cluster_config_blake3_chirho
                    .clone(),
                activation_anchor_digest_chirho: None,
                prepared_at_ms_chirho: 1,
                signer_key_id_chirho: binding_chirho.node_id_chirho.clone(),
                sig_chirho: String::new(),
            };
            receipt_chirho.sig_chirho = sign_chirho(
                key_chirho,
                &unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho).unwrap(),
            );
            receipt_chirho
        })
        .collect::<Vec<_>>();
    let mut held_observer_readiness_receipt_chirho =
        TenantPlacementHeldObserverReadinessReceiptChirho {
            schema_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO.to_string(),
            signature_domain_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO
                .to_string(),
            intent_digest_chirho: intent_digest_chirho.clone(),
            node_id_chirho: held_observer_node_chirho.node_id_chirho.clone(),
            failure_domain_chirho: held_observer_node_chirho.failure_domain_chirho.clone(),
            root_binding_chirho: held_observer_node_chirho
                .expected_root_binding_chirho
                .clone(),
            cluster_config_blake3_chirho: held_observer_node_chirho
                .expected_cluster_config_blake3_chirho
                .clone(),
            prepared_at_ms_chirho: 1,
            signer_key_id_chirho: held_observer_node_chirho.node_id_chirho.clone(),
            sig_chirho: String::new(),
        };
    held_observer_readiness_receipt_chirho.sig_chirho = sign_chirho(
        &held_key_chirho,
        &unsigned_tenant_placement_held_observer_readiness_message_chirho(
            &held_observer_readiness_receipt_chirho,
        )
        .unwrap(),
    );
    let mut record_chirho = TenantPlacementRecordChirho {
        schema_chirho: TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        serving_readiness_receipts_chirho,
        held_observer_readiness_receipt_chirho,
        placement_key_id_chirho: node_id_chirho(&placement_key_chirho),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_chirho(
        &placement_key_chirho,
        &unsigned_tenant_placement_record_message_chirho(&record_chirho).unwrap(),
    );
    let verified_chirho = verify_tenant_placement_record_chirho(
        record_chirho,
        &node_id_chirho(&placement_key_chirho),
        &node_id_chirho(&roster_key_chirho),
        &node_id_chirho(&plan_key_chirho),
    )
    .unwrap();
    TestPlacementChirho {
        assigned_nodes_chirho: verified_chirho
            .assigned_nodes_chirho()
            .iter()
            .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
            .collect(),
        held_observer_chirho: verified_chirho
            .held_observer_node_chirho()
            .node_id_chirho
            .clone(),
        verified_chirho,
    }
}

#[cfg(test)]
pub(crate) struct FixtureElectionViewChirho {
    pub(crate) observation_chirho: MirrorElectionObservationChirho,
}

#[cfg(test)]
impl MirrorLeadershipViewChirho for FixtureElectionViewChirho {
    fn observe_election_chirho(
        &self,
    ) -> Result<MirrorElectionObservationChirho, MirrorContractErrorChirho> {
        Ok(self.observation_chirho.clone())
    }
}

#[cfg(test)]
pub(crate) fn test_observation_chirho(
    placement_chirho: &TestPlacementChirho,
    leader_chirho: Option<&str>,
    term_chirho: u64,
    applied_conf_index_chirho: u64,
) -> MirrorElectionObservationChirho {
    let mut authenticated_members_chirho = placement_chirho
        .assigned_nodes_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, node_chirho)| {
            (
                u64::try_from(index_chirho).unwrap() + 1,
                NodeIdChirho(node_chirho.clone()),
            )
        })
        .collect::<Vec<_>>();
    authenticated_members_chirho.push((
        4,
        NodeIdChirho(placement_chirho.held_observer_chirho.clone()),
    ));
    MirrorElectionObservationChirho {
        leadership_chirho: LeadershipChirho {
            is_leader_chirho: false,
            leader_id_chirho: leader_chirho
                .map(|node_chirho| NodeIdChirho(node_chirho.to_string())),
            term_chirho,
            lease_valid_chirho: true,
        },
        authenticated_members_chirho,
        voter_raft_ids_chirho: vec![1, 2, 3],
        learner_raft_ids_chirho: vec![4],
        applied_conf_index_chirho,
        leader_lease_remaining_millis_chirho: Some(10_000),
    }
}
