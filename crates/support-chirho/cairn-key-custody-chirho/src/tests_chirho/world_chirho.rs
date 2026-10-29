// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! One placement-authorized world for the tests: a leader, two peers and a held observer, a verified placement, and the real two-authority join, plus helpers that drive the whole custody and erasure flows.
//!
//! The placement is built and verified exactly as the mirror's own integration test builds it, so the
//! joined view these tests admit frames against is a production-shaped one, not a hand-made struct.

use crate::custody_chirho::binding_chirho::{subject_digest_hex_chirho, CustodyBindingChirho};
use crate::custody_chirho::frame_chirho::{
    authorize_custody_frame_chirho, decode_and_authenticate_custody_frame_chirho,
    OpenedCustodyKeyChirho, PreparedCustodyFrameChirho,
};
use crate::custody_chirho::receipt_chirho::{
    CustodyReceiptV1Chirho, PreparedCustodyReceiptChirho, VerifiedCustodyReceiptChirho,
};
use crate::custody_chirho::wrap_chirho::{seal_wrapped_key_chirho, ShredKeyRecordChirho};
use crate::custody_key_chirho::{
    NodeCustodySecretChirho, PreparedCustodyAnnouncementChirho, VerifiedCustodyAnnouncementChirho,
};
use crate::digest_chirho::hex_chirho;
use crate::erasure_chirho::frame_chirho::{
    authorize_erasure_frame_chirho, decode_and_authenticate_erasure_frame_chirho,
    AuthorizedErasureFrameChirho, ErasureFrameInputChirho, PreparedErasureFrameChirho,
};
use crate::erasure_chirho::receipt_chirho::{
    PreparedErasureReceiptChirho, VerifiedErasureReceiptChirho,
};
use crate::erasure_chirho::tombstone_chirho::HolderTombstonesChirho;
use crate::refusal_chirho::KeyCustodyErrorChirho;
use cairn_mirror_chirho::{
    join_mirror_view_chirho, JoinedMirrorViewChirho, MirrorContractErrorChirho,
    MirrorElectionObservationChirho, MirrorLeadershipViewChirho,
};
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_tenant_placement_authority_chirho::{
    tenant_placement_intent_digest_chirho,
    unsigned_tenant_placement_held_observer_readiness_message_chirho,
    unsigned_tenant_placement_readiness_message_chirho,
    unsigned_tenant_placement_record_message_chirho, verify_tenant_placement_record_chirho,
    TenantPlacementHeldObserverReadinessReceiptChirho, TenantPlacementIntentChirho,
    TenantPlacementNodeBindingChirho, TenantPlacementNodeReadinessReceiptChirho,
    TenantPlacementRecordChirho, TenantPlacementResidencyChirho, VerifiedTenantPlacementChirho,
    TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO, TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO, TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO, TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO,
};
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    FakeMonotonicClockChirho, DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;
use std::sync::Arc;

pub(crate) const TERM_CHIRHO: u64 = 5;
const CONF_INDEX_CHIRHO: u64 = 11;
pub(crate) const LEASE_MILLIS_CHIRHO: u64 = 10_000;
pub(crate) const SUBJECT_CHIRHO: &str = "app/contact-chirho/submission/one";
pub(crate) const OTHER_SUBJECT_CHIRHO: &str = "app/contact-chirho/submission/two";

pub(crate) struct NodeChirho {
    pub(crate) key_chirho: SigningKey,
    pub(crate) id_chirho: String,
}

pub(crate) fn node_chirho(seed_chirho: u8) -> NodeChirho {
    let key_chirho = SigningKey::from_bytes(&[seed_chirho; 32]);
    let id_chirho = hex_chirho(key_chirho.verifying_key().as_bytes());
    NodeChirho {
        key_chirho,
        id_chirho,
    }
}

impl NodeChirho {
    pub(crate) fn sign_chirho(&self, digest_chirho: &[u8; 32]) -> String {
        hex_chirho(&self.key_chirho.sign(digest_chirho).to_bytes())
    }

    pub(crate) fn custody_secret_chirho(&self) -> NodeCustodySecretChirho {
        NodeCustodySecretChirho::derive_from_node_signing_key_chirho(&self.key_chirho)
    }

    pub(crate) fn announcement_chirho(&self) -> VerifiedCustodyAnnouncementChirho {
        let prepared_chirho = PreparedCustodyAnnouncementChirho::new_chirho(
            &self.id_chirho,
            &self.custody_secret_chirho(),
        )
        .expect("announcement prepares");
        let signature_chirho = self.sign_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("announcement signs")
            .verify_chirho()
            .expect("announcement verifies")
    }
}

/// A 32-hex key id from a small number.
pub(crate) fn key_id_chirho(number_chirho: u8) -> String {
    format!("{number_chirho:032x}")
}

pub(crate) fn record_chirho(subject_chirho: &str, fill_chirho: u8) -> ShredKeyRecordChirho {
    ShredKeyRecordChirho::new_chirho(subject_chirho, format!("{fill_chirho:02x}").repeat(32))
        .expect("record in form")
}

struct FixtureElectionViewChirho {
    observation_chirho: MirrorElectionObservationChirho,
}

impl MirrorLeadershipViewChirho for FixtureElectionViewChirho {
    fn observe_election_chirho(
        &self,
    ) -> Result<MirrorElectionObservationChirho, MirrorContractErrorChirho> {
        Ok(self.observation_chirho.clone())
    }
}

pub(crate) struct WorldChirho {
    pub(crate) leader_chirho: NodeChirho,
    pub(crate) peer_one_chirho: NodeChirho,
    pub(crate) peer_two_chirho: NodeChirho,
    pub(crate) placement_chirho: VerifiedTenantPlacementChirho,
    pub(crate) joined_chirho: JoinedMirrorViewChirho,
    pub(crate) clock_chirho: Arc<FakeMonotonicClockChirho>,
}

pub(crate) fn world_chirho() -> WorldChirho {
    let leader_chirho = node_chirho(1);
    let peer_one_chirho = node_chirho(2);
    let peer_two_chirho = node_chirho(3);
    let held_observer_chirho = node_chirho(4);
    let placement_chirho = verified_placement_chirho(
        [&leader_chirho, &peer_one_chirho, &peer_two_chirho],
        &held_observer_chirho,
    );
    let joined_chirho = joined_view_chirho(
        &placement_chirho,
        Some(&leader_chirho.id_chirho),
        TERM_CHIRHO,
    );
    WorldChirho {
        leader_chirho,
        peer_one_chirho,
        peer_two_chirho,
        placement_chirho,
        joined_chirho,
        clock_chirho: FakeMonotonicClockChirho::new_chirho(),
    }
}

/// The real two-authority join over this placement, with the named leader at the given term.
pub(crate) fn joined_view_chirho(
    placement_chirho: &VerifiedTenantPlacementChirho,
    leader_chirho: Option<&str>,
    term_chirho: u64,
) -> JoinedMirrorViewChirho {
    let mut authenticated_members_chirho = placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .enumerate()
        .map(|(index_chirho, binding_chirho)| {
            (
                u64::try_from(index_chirho).unwrap() + 1,
                NodeIdChirho(binding_chirho.node_id_chirho.clone()),
            )
        })
        .collect::<Vec<_>>();
    authenticated_members_chirho.push((
        4,
        NodeIdChirho(
            placement_chirho
                .held_observer_node_chirho()
                .node_id_chirho
                .clone(),
        ),
    ));
    join_mirror_view_chirho(
        placement_chirho,
        &FixtureElectionViewChirho {
            observation_chirho: MirrorElectionObservationChirho {
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
                applied_conf_index_chirho: CONF_INDEX_CHIRHO,
                leader_lease_remaining_millis_chirho: Some(LEASE_MILLIS_CHIRHO),
            },
        },
    )
    .expect("the fixture placement and election join")
}

impl WorldChirho {
    pub(crate) fn group_chirho(&self) -> String {
        self.joined_chirho
            .view_chirho()
            .consistency_group_digest_chirho()
            .to_string()
    }

    pub(crate) fn view_digest_chirho(&self) -> String {
        self.joined_chirho.view_chirho().view_digest_chirho()
    }

    /// The binding the leader uses for one key sent to one holder under the current view.
    pub(crate) fn binding_chirho(
        &self,
        holder_chirho: &NodeChirho,
        key_id_chirho: &str,
        subject_chirho: &str,
        blob_seq_chirho: u64,
    ) -> CustodyBindingChirho {
        CustodyBindingChirho {
            consistency_group_digest_chirho: self.group_chirho(),
            membership_view_digest_chirho: self.view_digest_chirho(),
            elected_term_chirho: TERM_CHIRHO,
            origin_node_id_chirho: self.leader_chirho.id_chirho.clone(),
            holder_node_id_chirho: holder_chirho.id_chirho.clone(),
            key_id_chirho: key_id_chirho.to_string(),
            subject_digest_chirho: subject_digest_hex_chirho(subject_chirho),
            ciphertext_addr_chirho: format!("{:064x}", blob_seq_chirho + 7),
            blob_seq_chirho,
        }
    }

    /// A custody frame for `binding_chirho`, sealed to its holder and signed by `signer_chirho`.
    pub(crate) fn custody_wire_chirho(
        &self,
        binding_chirho: &CustodyBindingChirho,
        record_chirho: &ShredKeyRecordChirho,
        holder_chirho: &NodeChirho,
        lease_chirho: Option<u64>,
        signer_chirho: &NodeChirho,
    ) -> Vec<u8> {
        let wrapped_chirho = seal_wrapped_key_chirho(
            record_chirho,
            &holder_chirho.announcement_chirho(),
            binding_chirho,
        )
        .expect("seal");
        let prepared_chirho = PreparedCustodyFrameChirho::new_chirho(
            binding_chirho.clone(),
            lease_chirho,
            wrapped_chirho,
        )
        .expect("frame prepares");
        let signature_chirho = signer_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("frame signs")
            .to_wire_bytes_chirho()
            .expect("frame encodes")
    }

    /// The holder's whole receive path: decode and authenticate, authorize against ITS joined view and
    /// tombstones, then open with its own custody secret.
    pub(crate) fn receive_custody_chirho(
        &self,
        joined_chirho: &JoinedMirrorViewChirho,
        receiver_chirho: &NodeChirho,
        wire_chirho: &[u8],
        tombstones_chirho: &HolderTombstonesChirho,
    ) -> Result<OpenedCustodyKeyChirho, KeyCustodyErrorChirho> {
        let authenticated_chirho = decode_and_authenticate_custody_frame_chirho(wire_chirho)?;
        let authorized_chirho = authorize_custody_frame_chirho(
            authenticated_chirho,
            joined_chirho,
            &receiver_chirho.id_chirho,
            tombstones_chirho,
            &*self.clock_chirho,
            DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
        )?;
        authorized_chirho.open_chirho(&receiver_chirho.custody_secret_chirho())
    }

    /// Deliver one key to one holder and return the holder's signed, verified receipt.
    pub(crate) fn custody_receipt_chirho(
        &self,
        holder_chirho: &NodeChirho,
        key_id_chirho: &str,
        subject_chirho: &str,
        blob_seq_chirho: u64,
    ) -> VerifiedCustodyReceiptChirho {
        self.signed_custody_receipt_chirho(
            holder_chirho,
            key_id_chirho,
            subject_chirho,
            blob_seq_chirho,
            holder_chirho,
        )
        .verify_chirho()
        .expect("receipt verifies")
    }

    /// Deliver one key to one holder and return its receipt signed by `signer_chirho`, unverified.
    pub(crate) fn signed_custody_receipt_chirho(
        &self,
        holder_chirho: &NodeChirho,
        key_id_chirho: &str,
        subject_chirho: &str,
        blob_seq_chirho: u64,
        signer_chirho: &NodeChirho,
    ) -> CustodyReceiptV1Chirho {
        let binding_chirho = self.binding_chirho(
            holder_chirho,
            key_id_chirho,
            subject_chirho,
            blob_seq_chirho,
        );
        let wire_chirho = self.custody_wire_chirho(
            &binding_chirho,
            &record_chirho(subject_chirho, 0x5a),
            holder_chirho,
            Some(LEASE_MILLIS_CHIRHO),
            &self.leader_chirho,
        );
        let opened_chirho = self
            .receive_custody_chirho(
                &self.joined_chirho,
                holder_chirho,
                &wire_chirho,
                &HolderTombstonesChirho::new_chirho(),
            )
            .expect("custody received");
        let prepared_chirho =
            PreparedCustodyReceiptChirho::for_durably_stored_key_chirho(&opened_chirho);
        let signature_chirho = signer_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("receipt signs")
    }

    /// An erasure frame from `signer_chirho` to `holder_chirho`, on the wire.
    pub(crate) fn erasure_wire_chirho(
        &self,
        holder_chirho: &NodeChirho,
        subject_chirho: &str,
        erased_below_blob_seq_chirho: u64,
        key_ids_chirho: &[String],
        signer_chirho: &NodeChirho,
    ) -> Vec<u8> {
        let prepared_chirho = PreparedErasureFrameChirho::new_chirho(ErasureFrameInputChirho {
            consistency_group_digest_chirho: self.group_chirho(),
            membership_view_digest_chirho: self.view_digest_chirho(),
            elected_term_chirho: TERM_CHIRHO,
            origin_node_id_chirho: signer_chirho.id_chirho.clone(),
            holder_node_id_chirho: holder_chirho.id_chirho.clone(),
            leader_lease_remaining_millis_chirho: Some(LEASE_MILLIS_CHIRHO),
            subject_digest_chirho: subject_digest_hex_chirho(subject_chirho),
            erased_below_blob_seq_chirho,
            key_ids_chirho: key_ids_chirho.iter().cloned().collect(),
        })
        .expect("erasure frame prepares");
        let signature_chirho = signer_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("erasure frame signs")
            .to_wire_bytes_chirho()
            .expect("erasure frame encodes")
    }

    pub(crate) fn receive_erasure_chirho(
        &self,
        receiver_chirho: &NodeChirho,
        wire_chirho: &[u8],
    ) -> Result<AuthorizedErasureFrameChirho, KeyCustodyErrorChirho> {
        authorize_erasure_frame_chirho(
            decode_and_authenticate_erasure_frame_chirho(wire_chirho)?,
            &self.joined_chirho,
            &receiver_chirho.id_chirho,
            &*self.clock_chirho,
            DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
        )
    }

    /// A holder's full erasure answer: authorize the leader's frame, then sign the given accounting.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn erasure_receipt_chirho(
        &self,
        holder_chirho: &NodeChirho,
        subject_chirho: &str,
        erased_below_blob_seq_chirho: u64,
        listed_chirho: &[String],
        removed_chirho: &[String],
        absent_chirho: &[String],
        by_subject_chirho: &[String],
    ) -> VerifiedErasureReceiptChirho {
        let wire_chirho = self.erasure_wire_chirho(
            holder_chirho,
            subject_chirho,
            erased_below_blob_seq_chirho,
            listed_chirho,
            &self.leader_chirho,
        );
        let frame_chirho = self
            .receive_erasure_chirho(holder_chirho, &wire_chirho)
            .expect("erasure authorized");
        let set_chirho =
            |ids_chirho: &[String]| ids_chirho.iter().cloned().collect::<BTreeSet<_>>();
        let prepared_chirho = PreparedErasureReceiptChirho::after_durable_erasure_chirho(
            &frame_chirho,
            set_chirho(removed_chirho),
            set_chirho(absent_chirho),
            set_chirho(by_subject_chirho),
        )
        .expect("erasure receipt prepares");
        let signature_chirho = holder_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("erasure receipt signs")
            .verify_chirho()
            .expect("erasure receipt verifies")
    }
}

pub(crate) fn verified_placement_chirho(
    serving_nodes_chirho: [&NodeChirho; 3],
    held_observer_chirho: &NodeChirho,
) -> VerifiedTenantPlacementChirho {
    verified_placement_for_tenant_chirho(
        serving_nodes_chirho,
        held_observer_chirho,
        "custody-fixture-chirho",
    )
}

/// The same placement for a named tenant, so a test can build a view of ANOTHER consistency group.
pub(crate) fn verified_placement_for_tenant_chirho(
    serving_nodes_chirho: [&NodeChirho; 3],
    held_observer_chirho: &NodeChirho,
    tenant_chirho: &str,
) -> VerifiedTenantPlacementChirho {
    let placement_authority_chirho = node_chirho(5);
    let roster_authority_chirho = node_chirho(6);
    let plan_authority_chirho = node_chirho(7);
    let domains_chirho = [
        ("provider-a-chirho", "region-a-chirho"),
        ("provider-b-chirho", "region-b-chirho"),
        ("provider-b-chirho", "region-c-chirho"),
    ]
    .map(|(provider_chirho, region_chirho)| FailureDomainChirho {
        provider_chirho: provider_chirho.to_string(),
        region_chirho: region_chirho.to_string(),
    });
    let mut assigned_nodes_chirho = serving_nodes_chirho
        .iter()
        .zip(domains_chirho.iter())
        .enumerate()
        .map(
            |(index_chirho, (node_chirho, domain_chirho))| TenantPlacementNodeBindingChirho {
                node_id_chirho: node_chirho.id_chirho.clone(),
                failure_domain_chirho: domain_chirho.clone(),
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
    assigned_nodes_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.node_id_chirho.cmp(&right_chirho.node_id_chirho)
    });
    let held_observer_node_chirho = TenantPlacementNodeBindingChirho {
        node_id_chirho: held_observer_chirho.id_chirho.clone(),
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
        tenant_id_chirho: tenant_chirho.to_string(),
        consistency_group_id_chirho: format!("tenant-chirho:{tenant_chirho}"),
        preferred_node_chirho: serving_nodes_chirho[0].id_chirho.clone(),
        assigned_nodes_chirho,
        held_observer_node_chirho,
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
    let serving_readiness_receipts_chirho = intent_chirho
        .assigned_nodes_chirho
        .iter()
        .map(|binding_chirho| {
            let node_chirho = serving_nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.id_chirho == binding_chirho.node_id_chirho)
                .expect("assigned fixture node");
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
            receipt_chirho.sig_chirho = sign_message_hex_chirho(
                node_chirho,
                &unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho).unwrap(),
            );
            receipt_chirho
        })
        .collect::<Vec<_>>();
    let held_binding_chirho = &intent_chirho.held_observer_node_chirho;
    let mut held_observer_readiness_receipt_chirho =
        TenantPlacementHeldObserverReadinessReceiptChirho {
            schema_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO.to_string(),
            signature_domain_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO
                .to_string(),
            intent_digest_chirho: intent_digest_chirho.clone(),
            node_id_chirho: held_binding_chirho.node_id_chirho.clone(),
            failure_domain_chirho: held_binding_chirho.failure_domain_chirho.clone(),
            root_binding_chirho: held_binding_chirho.expected_root_binding_chirho.clone(),
            cluster_config_blake3_chirho: held_binding_chirho
                .expected_cluster_config_blake3_chirho
                .clone(),
            prepared_at_ms_chirho: 1,
            signer_key_id_chirho: held_binding_chirho.node_id_chirho.clone(),
            sig_chirho: String::new(),
        };
    held_observer_readiness_receipt_chirho.sig_chirho = sign_message_hex_chirho(
        held_observer_chirho,
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
        placement_key_id_chirho: placement_authority_chirho.id_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_hex_chirho(
        &placement_authority_chirho,
        &unsigned_tenant_placement_record_message_chirho(&record_chirho).unwrap(),
    );
    verify_tenant_placement_record_chirho(
        record_chirho,
        &placement_authority_chirho.id_chirho,
        &roster_authority_chirho.id_chirho,
        &plan_authority_chirho.id_chirho,
    )
    .expect("fixture placement verifies")
}

fn sign_message_hex_chirho(node_chirho: &NodeChirho, bytes_chirho: &[u8]) -> String {
    hex_chirho(&node_chirho.key_chirho.sign(bytes_chirho).to_bytes())
}
