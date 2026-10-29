// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fixture proof for the mirror-before-ACK skeleton: in-process and ephemeral-loopback holder doubles
//! over three region-labeled roots, driving the pre-registered arms A1-A9. The load-bearing arm is A8
//! (Arm C): the inverted-leadership predicate must let the real leader's prepare succeed AND refuse a
//! rostered non-leader, so a naive `leader == self` copy or a dropped sender-is-leader check reddens.
//!
//! Every view here is resolved through the REAL two-authority join `join_mirror_view_chirho` over a
//! fixture election-view double, so the arms exercise the production join rather than a hand-built
//! view — and the J-arms below drive the join's own refusals.

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_mirror_chirho::frame_chirho::PreparedFinalizeMirrorReceiptFrameChirho;
use cairn_mirror_chirho::{
    decode_and_verify_mirror_receipt_chirho, join_mirror_view_chirho,
    verify_mirror_prepare_authority_chirho, FinalizeMirrorReceiptFrameInputChirho,
    InlineSealedPayloadChirho, JoinedMirrorViewChirho, KeyCustodyConfirmationChirho,
    KeyCustodyStatusChirho, LogPrefixBindingChirho, MirrorClosureManifestChirho,
    MirrorClosureManifestInputChirho, MirrorContractErrorChirho, MirrorDurableCommitClassChirho,
    MirrorElectionObservationChirho, MirrorFamilyMemberChirho, MirrorHolderFailureChirho,
    MirrorHolderPortChirho, MirrorHolderSetChirho, MirrorLeadershipViewChirho,
    MirrorReceiptInputChirho, MirrorReceiptStageChirho, MirrorRefusalIdentityChirho,
    MirrorResidencyPolicyChirho, PrepareMirrorClosureFrameInputChirho,
    PrepareMirrorClosureFrameV1Chirho, PreparedMirrorReceiptChirho,
    PreparedPrepareMirrorClosureFrameChirho, PRIVATE_BLOB_ALG_CHIRHO,
};
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
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
use cairn_write_relay_chirho::CallerIdempotencyKeyChirho;
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use cairn_writer_elector_chirho::monotonic_clock_chirho::FakeMonotonicClockChirho;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const TRANSIT_BUDGET_MILLIS_CHIRHO: u64 = 250;
const LEADER_LEASE_MILLIS_CHIRHO: u64 = 10_000;
const TERM_CHIRHO: u64 = 5;
const CONF_INDEX_CHIRHO: u64 = 11;

// ---------------------------------------------------------------------------------------------------
// Keys, nodes, and the three region-labeled roots.
// ---------------------------------------------------------------------------------------------------

struct NodeChirho {
    signing_key_chirho: SigningKey,
    node_id_chirho: String,
}

fn new_node_chirho() -> NodeChirho {
    let signing_key_chirho = SigningKey::generate(&mut OsRng);
    let node_id_chirho = hex_chirho(signing_key_chirho.verifying_key().as_bytes());
    NodeChirho {
        signing_key_chirho,
        node_id_chirho,
    }
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn sign_hex_chirho(node_chirho: &NodeChirho, digest_chirho: &[u8; 32]) -> String {
    hex_chirho(
        &node_chirho
            .signing_key_chirho
            .sign(digest_chirho)
            .to_bytes(),
    )
}

/// The fixture half of the production seam: a `MirrorLeadershipViewChirho` returning ONE fixed
/// election observation. Production implements this port over the node's own elector; nothing in the
/// join or the authority check can tell the difference, which is the point of the port.
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

// The mirror RECEIVER is a follower storing on behalf of the leader: `is_leader=false` (it is not
// itself the leader), with the established leader named. `is_leader` is no longer read by the predicate
// (reviewer F1, 2026-08-09) — kept false so the fixture models a real follower's view rather than an
// impossible self-leading follower.
fn observation_chirho(
    placement_chirho: &VerifiedTenantPlacementChirho,
    leader_node_id_chirho: Option<&str>,
    term_chirho: u64,
    applied_conf_index_chirho: u64,
) -> MirrorElectionObservationChirho {
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
    MirrorElectionObservationChirho {
        leadership_chirho: LeadershipChirho {
            is_leader_chirho: false,
            leader_id_chirho: leader_node_id_chirho
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

fn sign_message_hex_chirho(node_chirho: &NodeChirho, bytes_chirho: &[u8]) -> String {
    hex_chirho(&node_chirho.signing_key_chirho.sign(bytes_chirho).to_bytes())
}

fn verified_placement_chirho(
    serving_nodes_chirho: [&NodeChirho; 3],
    held_observer_chirho: &NodeChirho,
) -> VerifiedTenantPlacementChirho {
    let placement_authority_chirho = new_node_chirho();
    let roster_authority_chirho = new_node_chirho();
    let plan_authority_chirho = new_node_chirho();
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
    let mut assigned_nodes_chirho = serving_nodes_chirho
        .iter()
        .zip(domains_chirho.iter())
        .enumerate()
        .map(
            |(index_chirho, (node_chirho, domain_chirho))| TenantPlacementNodeBindingChirho {
                node_id_chirho: node_chirho.node_id_chirho.clone(),
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
        node_id_chirho: held_observer_chirho.node_id_chirho.clone(),
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
        preferred_node_chirho: serving_nodes_chirho[0].node_id_chirho.clone(),
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
                .find(|node_chirho| node_chirho.node_id_chirho == binding_chirho.node_id_chirho)
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
        placement_key_id_chirho: placement_authority_chirho.node_id_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_hex_chirho(
        &placement_authority_chirho,
        &unsigned_tenant_placement_record_message_chirho(&record_chirho).unwrap(),
    );
    verify_tenant_placement_record_chirho(
        record_chirho,
        &placement_authority_chirho.node_id_chirho,
        &roster_authority_chirho.node_id_chirho,
        &plan_authority_chirho.node_id_chirho,
    )
    .expect("fixture placement verifies")
}

struct WorldChirho {
    leader_chirho: NodeChirho,
    peer_one_chirho: NodeChirho,
    peer_two_chirho: NodeChirho,
    held_observer_chirho: NodeChirho,
    group_digest_chirho: String,
    placement_chirho: VerifiedTenantPlacementChirho,
    joined_chirho: JoinedMirrorViewChirho,
}

/// The placement-authorized three-serving-voter world plus its separate held observer. The view is
/// resolved through the real placement/election join.
fn new_world_chirho() -> WorldChirho {
    let leader_chirho = new_node_chirho();
    let peer_one_chirho = new_node_chirho();
    let peer_two_chirho = new_node_chirho();
    let held_observer_chirho = new_node_chirho();
    let placement_chirho = verified_placement_chirho(
        [&leader_chirho, &peer_one_chirho, &peer_two_chirho],
        &held_observer_chirho,
    );
    let joined_chirho = join_mirror_view_chirho(
        &placement_chirho,
        &FixtureElectionViewChirho {
            observation_chirho: observation_chirho(
                &placement_chirho,
                Some(&leader_chirho.node_id_chirho),
                TERM_CHIRHO,
                CONF_INDEX_CHIRHO,
            ),
        },
    )
    .expect("the fixture placement and election join");
    let group_digest_chirho = joined_chirho
        .view_chirho()
        .consistency_group_digest_chirho()
        .to_string();

    WorldChirho {
        leader_chirho,
        peer_one_chirho,
        peer_two_chirho,
        held_observer_chirho,
        group_digest_chirho,
        placement_chirho,
        joined_chirho,
    }
}

// ---------------------------------------------------------------------------------------------------
// A sealed F12 manifest + its inline sealed payload.
// ---------------------------------------------------------------------------------------------------

struct SealedClosureChirho {
    manifest_chirho: MirrorClosureManifestChirho,
    payloads_chirho: Vec<InlineSealedPayloadChirho>,
}

fn new_sealed_closure_chirho(
    group_digest_chirho: &str,
    caller_key_digest_chirho: &str,
) -> SealedClosureChirho {
    // The "sealed ciphertext" is arbitrary opaque bytes; its address is its real blake3, so the
    // holder's verify-before-count is genuine.
    let ciphertext_bytes_chirho = b"sealed-ciphertext-opaque-bytes-chirho".to_vec();
    let ciphertext_addr_chirho =
        HashChirho(blake3::hash(&ciphertext_bytes_chirho).to_hex().to_string());
    let key_id_chirho = "ab".repeat(16); // 16 bytes => 32 hex, a short key id (NOT a 32-byte key)

    let member_chirho = MirrorFamilyMemberChirho::SealedPrivateBlobChirho {
        ciphertext_addr_chirho: ciphertext_addr_chirho.clone(),
        privacy_record_prefix_chirho: LogPrefixBindingChirho {
            family_name_chirho: "privacy-blobs-chirho".to_string(),
            record_count_chirho: 1,
            byte_length_chirho: ciphertext_bytes_chirho.len() as u64,
            verified_prefix_digest_chirho: "cd".repeat(32),
        },
        blob_ref_chirho: PrivateBlobRefChirho {
            ciphertext_chirho: ciphertext_addr_chirho.clone(),
            key_id_chirho: key_id_chirho.clone(),
            nonce_chirho: "ef".repeat(24),
            mac_chirho: "12".repeat(32),
            alg_chirho: PRIVATE_BLOB_ALG_CHIRHO.to_string(),
        },
        key_custody_confirmation_chirho: KeyCustodyConfirmationChirho {
            bound_key_id_chirho: key_id_chirho,
            required_custody_regions_chirho: vec![
                "region-a-chirho".to_string(),
                "region-b-chirho".to_string(),
            ],
            status_chirho: KeyCustodyStatusChirho::PlaceholderPendingCustodyChirho,
        },
    };
    let manifest_chirho =
        MirrorClosureManifestChirho::new_chirho(MirrorClosureManifestInputChirho {
            consistency_group_digest_chirho: group_digest_chirho.to_string(),
            caller_idempotency_key_digest_chirho: caller_key_digest_chirho.to_string(),
            members_chirho: vec![member_chirho],
        })
        .expect("well-formed sealed manifest");

    SealedClosureChirho {
        manifest_chirho,
        payloads_chirho: vec![InlineSealedPayloadChirho {
            ciphertext_addr_chirho,
            ciphertext_bytes_chirho,
        }],
    }
}

fn caller_key_chirho() -> CallerIdempotencyKeyChirho {
    CallerIdempotencyKeyChirho::new_chirho("caller-op-key-chirho").unwrap()
}

/// Build a PREPARE frame from `sender` to `target`, signed by `sender`, with a live leader lease.
fn signed_prepare_chirho(
    world_chirho: &WorldChirho,
    sender_chirho: &NodeChirho,
    target_node_id_chirho: &str,
    term_chirho: u64,
    lease_remaining_millis_chirho: Option<u64>,
) -> PrepareMirrorClosureFrameV1Chirho {
    let caller_key_chirho = caller_key_chirho();
    let sealed_chirho = new_sealed_closure_chirho(
        &world_chirho.group_digest_chirho,
        &caller_key_chirho.digest_hex_chirho(),
    );
    let prepared_chirho =
        PreparedPrepareMirrorClosureFrameChirho::new_chirho(PrepareMirrorClosureFrameInputChirho {
            origin_node_id_chirho: sender_chirho.node_id_chirho.clone(),
            target_node_id_chirho: target_node_id_chirho.to_string(),
            consistency_group_digest_chirho: world_chirho.group_digest_chirho.clone(),
            expected_term_chirho: term_chirho,
            membership_view_digest_chirho: world_chirho
                .joined_chirho
                .view_chirho()
                .view_digest_chirho(),
            leader_lease_remaining_millis_chirho: lease_remaining_millis_chirho,
            caller_idempotency_key_digest_chirho: caller_key_chirho.digest_hex_chirho(),
            manifest_chirho: sealed_chirho.manifest_chirho,
            inline_sealed_payloads_chirho: sealed_chirho.payloads_chirho,
        })
        .expect("well-formed prepare frame");
    let signature_chirho = sign_hex_chirho(sender_chirho, &prepared_chirho.signing_digest_chirho());
    prepared_chirho
        .into_signed_chirho(signature_chirho)
        .expect("signed prepare frame")
}

// ---------------------------------------------------------------------------------------------------
// The holder double: a real temp-dir root, real durable store + re-read verify-before-count.
// ---------------------------------------------------------------------------------------------------

struct HolderDoubleChirho {
    node_id_chirho: String,
    signing_key_chirho: SigningKey,
    /// The receiver's OWN two-authority joined view. One field, not a roster plus a leadership, so a
    /// holder double cannot model a pair the production join would never produce.
    joined_chirho: JoinedMirrorViewChirho,
    clock_chirho: Arc<FakeMonotonicClockChirho>,
    group_digest_chirho: String,
    root_chirho: PathBuf,
    corrupt_on_store_chirho: bool,
    durable_write_count_chirho: Arc<AtomicUsize>,
}

impl HolderDoubleChirho {
    fn new_chirho(
        node_chirho: &NodeChirho,
        world_chirho: &WorldChirho,
        corrupt_on_store_chirho: bool,
    ) -> Self {
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-mirror-double-{}-{}",
            &node_chirho.node_id_chirho[..12],
            std::process::id()
        ));
        std::fs::create_dir_all(root_chirho.join("blobs")).unwrap();
        std::fs::create_dir_all(root_chirho.join("prepared")).unwrap();
        Self {
            node_id_chirho: node_chirho.node_id_chirho.clone(),
            signing_key_chirho: node_chirho.signing_key_chirho.clone(),
            joined_chirho: world_chirho.joined_chirho.clone(),
            clock_chirho: FakeMonotonicClockChirho::new_chirho(),
            group_digest_chirho: world_chirho.group_digest_chirho.clone(),
            root_chirho,
            corrupt_on_store_chirho,
            durable_write_count_chirho: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn transit_budget_chirho(&self) -> NonZeroU64 {
        NonZeroU64::new(TRANSIT_BUDGET_MILLIS_CHIRHO).unwrap()
    }

    /// The full receiver-side prepare pipeline, from wire bytes (both doubles feed wire in).
    fn receiver_prepare_from_wire_chirho(
        &self,
        wire_chirho: &[u8],
    ) -> Result<Vec<u8>, MirrorHolderFailureChirho> {
        let roster_chirho = self.joined_chirho.view_chirho().relay_roster_chirho()?;
        let authenticated_chirho =
            cairn_mirror_chirho::decode_and_authenticate_mirror_prepare_chirho(
                wire_chirho,
                &roster_chirho,
            )?;
        let verified_chirho = authenticated_chirho.bind_destination_chirho(
            &self.group_digest_chirho,
            &self.node_id_chirho,
            &roster_chirho,
        )?;
        // THE money/authority seam: the inverted-leadership check, over the ONE joined view.
        let _authorized_chirho = verify_mirror_prepare_authority_chirho(
            &verified_chirho,
            &self.joined_chirho,
            &self.node_id_chirho,
            self.clock_chirho.as_ref(),
            self.transit_budget_chirho(),
        )?;
        // Verify-before-count: the inline sealed bytes must re-derive the manifest's addresses.
        let payloads_chirho = verified_chirho.verify_inline_payloads_against_manifest_chirho()?;

        let marker_chirho = self
            .root_chirho
            .join("prepared")
            .join(verified_chirho.prepare_frame_digest_chirho());
        let already_prepared_chirho = marker_chirho.exists();
        for payload_chirho in &payloads_chirho {
            self.durably_store_and_verify_chirho(
                payload_chirho.ciphertext_addr_chirho.0.as_str(),
                payload_chirho.ciphertext_bytes_chirho,
                already_prepared_chirho,
            )?;
        }
        if !already_prepared_chirho {
            std::fs::write(&marker_chirho, verified_chirho.mirror_closure_id_chirho()).unwrap();
        }

        let receipt_chirho = self.sign_receipt_chirho(
            verified_chirho.prepare_frame_digest_chirho(),
            verified_chirho.caller_idempotency_key_digest_chirho(),
            verified_chirho.mirror_closure_id_chirho(),
            MirrorReceiptStageChirho::PreparedChirho,
        )?;
        Ok(receipt_chirho.to_wire_bytes_chirho()?)
    }

    /// Store bytes durably (fsync), then RE-READ and verify the content address before counting the
    /// mirror. A storage fault (the corrupt flag) is caught here => `MirrorClosureUnverifiedChirho`.
    fn durably_store_and_verify_chirho(
        &self,
        addr_chirho: &str,
        bytes_chirho: &[u8],
        already_prepared_chirho: bool,
    ) -> Result<(), MirrorHolderFailureChirho> {
        let path_chirho = self.root_chirho.join("blobs").join(addr_chirho);
        if !already_prepared_chirho {
            let stored_bytes_chirho: Vec<u8> = if self.corrupt_on_store_chirho {
                b"a-storage-fault-corrupted-these-bytes".to_vec()
            } else {
                bytes_chirho.to_vec()
            };
            let mut file_chirho = std::fs::File::create(&path_chirho).unwrap();
            file_chirho.write_all(&stored_bytes_chirho).unwrap();
            file_chirho.sync_all().unwrap();
            self.durable_write_count_chirho
                .fetch_add(1, Ordering::SeqCst);
        }
        // Verify-before-count: re-read from disk and confirm the true content address.
        let read_back_chirho = std::fs::read(&path_chirho).unwrap();
        if blake3::hash(&read_back_chirho).to_hex().to_string() != addr_chirho {
            return Err(MirrorContractErrorChirho::closure_unverified_chirho().into());
        }
        Ok(())
    }

    fn sign_receipt_chirho(
        &self,
        prepare_frame_digest_chirho: &str,
        caller_key_digest_chirho: &str,
        mirror_closure_id_chirho: &str,
        stage_chirho: MirrorReceiptStageChirho,
    ) -> Result<cairn_mirror_chirho::MirrorReceiptChirho, MirrorHolderFailureChirho> {
        let prepared_chirho = PreparedMirrorReceiptChirho::new_chirho(MirrorReceiptInputChirho {
            prepare_frame_digest_chirho: prepare_frame_digest_chirho.to_string(),
            caller_idempotency_key_digest_chirho: caller_key_digest_chirho.to_string(),
            responder_node_id_chirho: self.node_id_chirho.clone(),
            consistency_group_digest_chirho: self.group_digest_chirho.clone(),
            mirror_closure_id_chirho: mirror_closure_id_chirho.to_string(),
            actual_term_chirho: self.joined_chirho.term_chirho(),
            stage_chirho,
            durable_commit_class_chirho:
                MirrorDurableCommitClassChirho::SealedBlobNativeDurablePlaceholderCustodyChirho,
        })?;
        let signature_chirho = hex_chirho(
            &self
                .signing_key_chirho
                .sign(&prepared_chirho.signing_digest_chirho())
                .to_bytes(),
        );
        Ok(prepared_chirho.into_signed_chirho(signature_chirho)?)
    }

    fn stored_blob_count_chirho(&self) -> usize {
        std::fs::read_dir(self.root_chirho.join("blobs"))
            .map(|entries_chirho| entries_chirho.count())
            .unwrap_or(0)
    }
}

impl Drop for HolderDoubleChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_chirho);
    }
}

impl MirrorHolderPortChirho for HolderDoubleChirho {
    fn prepare_durably_chirho(
        &self,
        frame_chirho: &PrepareMirrorClosureFrameV1Chirho,
    ) -> Result<cairn_mirror_chirho::MirrorReceiptChirho, MirrorHolderFailureChirho> {
        // Serialize to wire first, so the in-process double proves the wire round trip too.
        let wire_chirho = frame_chirho.to_wire_bytes_chirho()?;
        let receipt_wire_chirho = self.receiver_prepare_from_wire_chirho(&wire_chirho)?;
        decode_and_verify_mirror_receipt_chirho(
            &receipt_wire_chirho,
            frame_chirho.prepare_frame_digest_chirho(),
            &caller_key_chirho().digest_hex_chirho(),
            &self.group_digest_chirho,
            &self.node_id_chirho,
            frame_chirho.mirror_closure_id_chirho(),
        )
        .map(|verified_chirho| verified_chirho.into_receipt_chirho())
        .map_err(MirrorHolderFailureChirho::from)
    }

    fn finalize_chirho(
        &self,
        frame_chirho: &cairn_mirror_chirho::FinalizeMirrorReceiptFrameV1Chirho,
    ) -> Result<cairn_mirror_chirho::MirrorReceiptChirho, MirrorHolderFailureChirho> {
        let wire_chirho = frame_chirho.to_wire_bytes_chirho()?;
        let roster_chirho = self.joined_chirho.view_chirho().relay_roster_chirho()?;
        let verified_chirho = cairn_mirror_chirho::decode_and_verify_mirror_finalize_chirho(
            &wire_chirho,
            &self.group_digest_chirho,
            &self.node_id_chirho,
            &roster_chirho,
        )?;
        // The holder must already hold the prepared closure it is being asked to finalize.
        let marker_chirho = self
            .root_chirho
            .join("prepared")
            .join(verified_chirho.prepare_frame_digest_chirho());
        if !marker_chirho.exists() {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorClosureUnverifiedChirho,
                "finalize names a prepared closure this holder never stored",
            )
            .into());
        }
        self.sign_receipt_chirho(
            verified_chirho.prepare_frame_digest_chirho(),
            verified_chirho.caller_idempotency_key_digest_chirho(),
            verified_chirho.mirror_closure_id_chirho(),
            MirrorReceiptStageChirho::FinalizedChirho,
        )
    }
}

fn expect_contract_refusal_chirho(
    result_chirho: Result<cairn_mirror_chirho::MirrorReceiptChirho, MirrorHolderFailureChirho>,
    expected_chirho: MirrorRefusalIdentityChirho,
) {
    match result_chirho {
        Ok(_) => panic!("expected refusal {expected_chirho:?} but the mirror prepare SUCCEEDED"),
        Err(failure_chirho) => assert_eq!(
            failure_chirho.identity_chirho(),
            expected_chirho,
            "wrong refusal: got {:?}, expected {expected_chirho:?}",
            failure_chirho.identity_chirho()
        ),
    }
}

// ===================================================================================================
// ARMS
// ===================================================================================================

// A8 / Arm C — the load-bearing negative control (in two directions), placed first.

#[test]
fn arm_c_a8_legitimate_leader_prepare_succeeds_and_non_leader_refuses_chirho() {
    let world_chirho = new_world_chirho();
    let holder_chirho =
        HolderDoubleChirho::new_chirho(&world_chirho.peer_two_chirho, &world_chirho, false);

    // Direction A: the REAL leader's prepare SUCCEEDS. A `leader == self` copy would refuse this (the
    // receiver is a follower), so this assertion reddens if the inversion is un-inverted.
    let legit_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    let receipt_chirho = holder_chirho
        .prepare_durably_chirho(&legit_chirho)
        .expect("the real leader's mirror prepare must succeed");
    assert_eq!(
        receipt_chirho.stage_chirho(),
        MirrorReceiptStageChirho::PreparedChirho
    );
    assert_eq!(
        receipt_chirho.durable_commit_class_chirho(),
        MirrorDurableCommitClassChirho::SealedBlobNativeDurablePlaceholderCustodyChirho,
        "the receipt records a native durable point, never 'bytes accepted'"
    );

    // Direction B: a rostered NON-leader (the sibling peer) commanding a mirror write REFUSES.
    // Dropping the sender-is-leader check would let this succeed, so this assertion reddens then.
    let non_leader_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.peer_one_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    expect_contract_refusal_chirho(
        holder_chirho.prepare_durably_chirho(&non_leader_chirho),
        MirrorRefusalIdentityChirho::MirrorSenderNotLeaderChirho,
    );
}

// J1 (Arm C, the production JOIN) — a roster/leadership TERM disagreement is UNREPRESENTABLE.
//
// The 7.2a skeleton handed `view` and `leadership` to the authority check as independent arguments,
// and the fixture happened to keep them consistent (reviewer F3). There is now no way to express the
// inconsistency: the roster half has no term field at all, so whatever the single election
// observation reports is the term BOTH halves of the joined view carry. This arm proves that over a
// range of terms and shows the term reaching the wire through the frame the receiver accepts.

#[test]
fn arm_j1_a_joined_view_cannot_carry_two_different_terms_chirho() {
    let world_chirho = new_world_chirho();

    let mut digests_chirho = Vec::new();
    for term_chirho in [1_u64, TERM_CHIRHO, 900_719_925_474_099] {
        let joined_chirho = join_mirror_view_chirho(
            &world_chirho.placement_chirho,
            &FixtureElectionViewChirho {
                observation_chirho: observation_chirho(
                    &world_chirho.placement_chirho,
                    Some(&world_chirho.leader_chirho.node_id_chirho),
                    term_chirho,
                    CONF_INDEX_CHIRHO,
                ),
            },
        )
        .expect("a consistent placement and election join");
        assert_eq!(joined_chirho.term_chirho(), term_chirho);
        assert_eq!(
            joined_chirho.view_chirho().term_chirho(),
            joined_chirho.leadership_chirho().term_chirho,
            "the placement half and election half of a joined view always name the same term"
        );
        digests_chirho.push(joined_chirho.view_chirho().view_digest_chirho());
    }
    // The term reaches the wire: distinct terms over the SAME roster are distinct bound views, so a
    // frame bound at one term cannot be replayed at a receiver standing in another.
    digests_chirho.sort();
    digests_chirho.dedup();
    assert_eq!(digests_chirho.len(), 3);
}

// J2 (Arm C, the production JOIN) — the two authorities must name the same population, and a node
// rostered in one half while leading in the other refuses by its own name.

#[test]
fn arm_j2_two_authority_disagreements_refuse_by_distinct_names_chirho() {
    let world_chirho = new_world_chirho();
    let stranger_chirho = new_node_chirho();
    let join_chirho = |observation_chirho: MirrorElectionObservationChirho| {
        join_mirror_view_chirho(
            &world_chirho.placement_chirho,
            &FixtureElectionViewChirho { observation_chirho },
        )
    };

    // Positive control: without it, every arm below would "pass" for the wrong reason.
    join_chirho(observation_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    ))
    .expect("ordering does not change the exact population");

    // The voter population differs from signed placement.
    let mut missing_voter_chirho = observation_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    );
    missing_voter_chirho.voter_raft_ids_chirho.pop();
    let refusal_chirho =
        join_chirho(missing_voter_chirho).expect_err("a serving voter disagreement must refuse");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorPlacementElectionPopulationMismatchChirho
    );

    // An authenticated identity outside the placement/election role population also refuses.
    let mut extra_auth_chirho = observation_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    );
    extra_auth_chirho
        .authenticated_members_chirho
        .push((5, NodeIdChirho(stranger_chirho.node_id_chirho.clone())));
    let refusal_chirho =
        join_chirho(extra_auth_chirho).expect_err("an extra authenticated identity must refuse");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberPopulationExcessChirho
    );

    // A partially applied transport population is transiently incomplete, not an identity defect.
    let mut missing_auth_chirho = observation_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    );
    missing_auth_chirho.authenticated_members_chirho.pop();
    let refusal_chirho = join_chirho(missing_auth_chirho)
        .expect_err("an incomplete authenticated population must refuse");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberPopulationIncompleteChirho
    );

    // Duplicate identity mappings cannot manufacture two authenticated members.
    let mut duplicate_auth_chirho = observation_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    );
    duplicate_auth_chirho.authenticated_members_chirho[1].1 = duplicate_auth_chirho
        .authenticated_members_chirho[0]
        .1
        .clone();
    let refusal_chirho = join_chirho(duplicate_auth_chirho)
        .expect_err("a duplicate authenticated identity must refuse");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberIdentityRefusedChirho
    );

    // The cardinality can be right while the authenticated set is bound to the wrong node.
    let mut wrong_auth_binding_chirho = observation_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    );
    wrong_auth_binding_chirho.authenticated_members_chirho[3].1 =
        NodeIdChirho(stranger_chirho.node_id_chirho.clone());
    let refusal_chirho = join_chirho(wrong_auth_binding_chirho)
        .expect_err("an authenticated population bound to the wrong node must refuse");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorAuthenticatedMemberBindingMismatchChirho
    );

    // A role vector cannot name a raft member absent from the authenticated map.
    let mut unknown_role_chirho = observation_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    );
    unknown_role_chirho.voter_raft_ids_chirho[0] = 99;
    let refusal_chirho =
        join_chirho(unknown_role_chirho).expect_err("an unknown role member must refuse");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorElectionRoleResolutionRefusedChirho
    );

    // The populations agree, but the election names a leader placement never assigned.
    let unassigned_leader_chirho = join_chirho(observation_chirho(
        &world_chirho.placement_chirho,
        Some(&stranger_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    ))
    .expect_err("an elected leader outside placement must refuse");
    assert_eq!(
        unassigned_leader_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorElectedLeaderUnassignedChirho,
    );

    // Routine learner addition is fail-closed for mirrored writes until the final topology applies.
    let mut second_learner_chirho = observation_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.node_id_chirho),
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO + 1,
    );
    second_learner_chirho.learner_raft_ids_chirho.push(3);
    let topology_refusal_chirho =
        join_chirho(second_learner_chirho).expect_err("a second learner halts mirror-gated writes");
    assert_eq!(
        topology_refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorElectionTopologyMismatchChirho
    );

    // A vacant leadership joins and authorises nobody.
    let vacant_chirho = join_chirho(observation_chirho(
        &world_chirho.placement_chirho,
        None,
        TERM_CHIRHO,
        CONF_INDEX_CHIRHO,
    ))
    .expect("a vacant leadership is a well-formed joined view");
    assert_eq!(vacant_chirho.elected_leader_node_id_chirho(), None);
}

// J3 (Arm C, the production JOIN) — a receiver whose joined view says NOBODY leads refuses a prepare
// through the real serve path, and stores nothing.

#[test]
fn arm_j3_a_vacant_joined_view_authorises_no_prepare_chirho() {
    let world_chirho = new_world_chirho();
    // Re-join the same placement against an election that names no leader — the exact fixture the
    // production port would return between elections.
    let vacant_joined_chirho = join_mirror_view_chirho(
        &world_chirho.placement_chirho,
        &FixtureElectionViewChirho {
            observation_chirho: observation_chirho(
                &world_chirho.placement_chirho,
                None,
                TERM_CHIRHO,
                CONF_INDEX_CHIRHO,
            ),
        },
    )
    .expect("a vacant leadership joins");
    let mut holder_chirho =
        HolderDoubleChirho::new_chirho(&world_chirho.peer_two_chirho, &world_chirho, false);
    holder_chirho.joined_chirho = vacant_joined_chirho;

    let prepare_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    expect_contract_refusal_chirho(
        holder_chirho.prepare_durably_chirho(&prepare_chirho),
        MirrorRefusalIdentityChirho::MirrorSenderNotLeaderChirho,
    );
    assert_eq!(
        holder_chirho.stored_blob_count_chirho(),
        0,
        "a prepare refused at the authority seam stores nothing"
    );
}

// A1 — holder selection and residency both fail before any durable prepare.

#[test]
fn arm_a1_holder_set_unsatisfiable_refuses_with_zero_durable_state_chirho() {
    let world_chirho = new_world_chirho();
    let selection_chirho = MirrorHolderSetChirho::select_chirho(
        world_chirho.joined_chirho.view_chirho(),
        &world_chirho.held_observer_chirho.node_id_chirho,
        &MirrorResidencyPolicyChirho::AnyDomainChirho,
    );
    assert_eq!(
        selection_chirho
            .expect_err("a held observer cannot be selected as the serving leader")
            .identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorHolderSetUnsatisfiableChirho
    );

    // Placement cannot override a residency policy that forbids any selected holder domain.
    let spread_world_chirho = new_world_chirho();
    let residency_chirho =
        MirrorResidencyPolicyChirho::allowed_domains_chirho([spread_world_chirho
            .joined_chirho
            .view_chirho()
            .holders_chirho()[0]
            .failure_domain_chirho()
            .clone()]);
    assert_eq!(
        MirrorHolderSetChirho::select_chirho(
            spread_world_chirho.joined_chirho.view_chirho(),
            &spread_world_chirho.leader_chirho.node_id_chirho,
            &residency_chirho
        )
        .expect_err("a residency-forbidden placement holder must be vetoed")
        .identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorResidencyVetoChirho
    );
}

// A2 — a holder that stored bytes it cannot re-verify counts ABSENT (verify-before-count).

#[test]
fn arm_a2_stored_but_unverifiable_bytes_count_absent_chirho() {
    let world_chirho = new_world_chirho();
    let holder_chirho =
        HolderDoubleChirho::new_chirho(&world_chirho.peer_two_chirho, &world_chirho, true);
    let prepare_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    expect_contract_refusal_chirho(
        holder_chirho.prepare_durably_chirho(&prepare_chirho),
        MirrorRefusalIdentityChirho::MirrorClosureUnverifiedChirho,
    );
}

// A3 — a mirror-internal key present but the caller idempotency key absent => refuse.

#[test]
fn arm_a3_caller_key_absent_refuses_even_with_a_mirror_key_chirho() {
    let world_chirho = new_world_chirho();
    // An empty caller-key digest (no caller key) while the closure still has its mirror-internal key.
    let refusal_chirho =
        MirrorClosureManifestChirho::new_chirho(MirrorClosureManifestInputChirho {
            consistency_group_digest_chirho: world_chirho.group_digest_chirho.clone(),
            caller_idempotency_key_digest_chirho: String::new(),
            members_chirho: new_sealed_closure_chirho(
                &world_chirho.group_digest_chirho,
                &"9".repeat(64),
            )
            .manifest_chirho
            .members_chirho()
            .to_vec(),
        })
        .expect_err("a closure with no caller key must refuse");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorCallerKeyMissingChirho
    );
}

// A4 — a sealed-ref-only closure: 32 key bytes on the wire refuse, and the type cannot carry them.

#[test]
fn arm_a4_key_bytes_on_the_wire_refuse_chirho() {
    let world_chirho = new_world_chirho();
    let key_shaped_chirho = "cc".repeat(32); // 64 hex = 32 bytes = a full shred key
    let member_chirho = MirrorFamilyMemberChirho::SealedPrivateBlobChirho {
        ciphertext_addr_chirho: HashChirho("dd".repeat(32)),
        privacy_record_prefix_chirho: LogPrefixBindingChirho {
            family_name_chirho: "privacy-blobs-chirho".to_string(),
            record_count_chirho: 1,
            byte_length_chirho: 10,
            verified_prefix_digest_chirho: "ee".repeat(32),
        },
        blob_ref_chirho: PrivateBlobRefChirho {
            ciphertext_chirho: HashChirho("dd".repeat(32)),
            key_id_chirho: key_shaped_chirho.clone(),
            nonce_chirho: "ab".repeat(24),
            mac_chirho: "cd".repeat(32),
            alg_chirho: PRIVATE_BLOB_ALG_CHIRHO.to_string(),
        },
        key_custody_confirmation_chirho: KeyCustodyConfirmationChirho {
            bound_key_id_chirho: key_shaped_chirho,
            required_custody_regions_chirho: vec!["region-a-chirho".to_string()],
            status_chirho: KeyCustodyStatusChirho::PlaceholderPendingCustodyChirho,
        },
    };
    let refusal_chirho =
        MirrorClosureManifestChirho::new_chirho(MirrorClosureManifestInputChirho {
            consistency_group_digest_chirho: world_chirho.group_digest_chirho,
            caller_idempotency_key_digest_chirho: "9".repeat(64),
            members_chirho: vec![member_chirho],
        })
        .expect_err("key bytes on the wire must refuse");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorKeyBytesOnWireChirho
    );
}

// A5 — a stale bound term refuses (distinct from the non-leader refusal).

#[test]
fn arm_a5_stale_term_refuses_chirho() {
    let world_chirho = new_world_chirho();
    let holder_chirho =
        HolderDoubleChirho::new_chirho(&world_chirho.peer_two_chirho, &world_chirho, false);
    // A prepare bound to term 4 while the receiver's known current term is 5 (in the view/leadership).
    // The membership view digest is still term-5's, so we bind term 4 on the frame directly.
    let stale_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO - 1,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    expect_contract_refusal_chirho(
        holder_chirho.prepare_durably_chirho(&stale_chirho),
        MirrorRefusalIdentityChirho::MirrorTermInvalidChirho,
    );
}

// A6 — the receiver is not in the joined view => refuse.

#[test]
fn arm_a6_receiver_not_in_the_joined_view_refuses_chirho() {
    let world_chirho = new_world_chirho();
    // A stranger node acts as the holder but is NOT in the view; the frame targets the stranger.
    let stranger_chirho = new_node_chirho();
    let holder_chirho = HolderDoubleChirho::new_chirho(&stranger_chirho, &world_chirho, false);
    let prepare_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &stranger_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    expect_contract_refusal_chirho(
        holder_chirho.prepare_durably_chirho(&prepare_chirho),
        MirrorRefusalIdentityChirho::MirrorReceiverUnrosteredChirho,
    );
}

// A7 — an expired leader lease (remaining <= transit budget) refuses.

#[test]
fn arm_a7_expired_leader_lease_refuses_chirho() {
    let world_chirho = new_world_chirho();
    let holder_chirho =
        HolderDoubleChirho::new_chirho(&world_chirho.peer_two_chirho, &world_chirho, false);
    // Remaining below the transit budget is expired-by-construction at receipt.
    let expired_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(TRANSIT_BUDGET_MILLIS_CHIRHO - 1),
    );
    expect_contract_refusal_chirho(
        holder_chirho.prepare_durably_chirho(&expired_chirho),
        MirrorRefusalIdentityChirho::MirrorLeaseExpiredChirho,
    );

    // And an ABSENT lease (None) is expired, never "unknown, assume valid".
    let absent_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        None,
    );
    expect_contract_refusal_chirho(
        holder_chirho.prepare_durably_chirho(&absent_chirho),
        MirrorRefusalIdentityChirho::MirrorLeaseExpiredChirho,
    );
}

// A9 — an idempotent replay re-acks the same receipt with NO second durable closure written.

#[test]
fn arm_a9_idempotent_replay_writes_no_second_durable_closure_chirho() {
    let world_chirho = new_world_chirho();
    let holder_chirho =
        HolderDoubleChirho::new_chirho(&world_chirho.peer_two_chirho, &world_chirho, false);
    let prepare_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    let first_chirho = holder_chirho
        .prepare_durably_chirho(&prepare_chirho)
        .expect("first prepare");
    let writes_after_first_chirho = holder_chirho
        .durable_write_count_chirho
        .load(Ordering::SeqCst);
    let blobs_after_first_chirho = holder_chirho.stored_blob_count_chirho();

    let second_chirho = holder_chirho
        .prepare_durably_chirho(&prepare_chirho)
        .expect("idempotent replay");
    assert_eq!(
        holder_chirho
            .durable_write_count_chirho
            .load(Ordering::SeqCst),
        writes_after_first_chirho,
        "an idempotent replay must NOT write a second durable closure"
    );
    assert_eq!(
        holder_chirho.stored_blob_count_chirho(),
        blobs_after_first_chirho
    );
    assert_eq!(
        first_chirho.to_wire_bytes_chirho().unwrap(),
        second_chirho.to_wire_bytes_chirho().unwrap(),
        "the replay re-acks the byte-identical receipt"
    );
}

// A3-frame — sealed-ref-only on the wire: the PREPARE never carries the 32-byte key, only a short id.

#[test]
fn sealed_ref_only_no_key_bytes_cross_the_wire_chirho() {
    let world_chirho = new_world_chirho();
    let prepare_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    let wire_chirho = prepare_chirho.to_wire_bytes_chirho().unwrap();
    let wire_text_chirho = String::from_utf8_lossy(&wire_chirho);
    // The key id (32 hex) may appear; a 32-BYTE key never should. Assert the wire carries no 64-hex
    // key-material-length token in a key field by construction (the type has no such field).
    assert!(
        wire_text_chirho.contains("key_id_chirho"),
        "the sealed ref names a key id"
    );
    assert!(
        !wire_text_chirho.contains("key_hex_chirho") && !wire_text_chirho.contains("shred_key"),
        "no raw key material field is present on the wire"
    );
}

// Ephemeral-loopback double — the frames survive a real serialize/socket/deserialize round trip.

#[test]
fn ephemeral_loopback_prepare_round_trips_over_a_real_socket_chirho() {
    let world_chirho = new_world_chirho();
    let prepare_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    let prepare_frame_digest_chirho = prepare_chirho.prepare_frame_digest_chirho().to_string();
    let foreign_node_id_chirho = world_chirho.peer_two_chirho.node_id_chirho.clone();
    let group_digest_chirho = world_chirho.group_digest_chirho.clone();
    let closure_id_chirho = new_sealed_closure_chirho(
        &group_digest_chirho,
        &caller_key_chirho().digest_hex_chirho(),
    )
    .manifest_chirho
    .mirror_closure_id_chirho()
    .to_string();

    let listener_chirho = TcpListener::bind("127.0.0.1:0").expect("loopback bind stays private");
    let addr_chirho = listener_chirho.local_addr().unwrap();
    assert!(
        addr_chirho.ip().is_loopback(),
        "the push socket is loopback-only"
    );

    let server_world_chirho = new_world_shared_view_chirho(&world_chirho);
    let server_handle_chirho = std::thread::spawn(move || {
        let (mut stream_chirho, _peer_chirho) = listener_chirho.accept().unwrap();
        let mut wire_chirho = Vec::new();
        stream_chirho.read_to_end(&mut wire_chirho).unwrap();
        let holder_chirho = HolderDoubleChirho::new_chirho(
            &server_world_chirho.peer_two_chirho,
            &server_world_chirho,
            false,
        );
        let receipt_wire_chirho = holder_chirho
            .receiver_prepare_from_wire_chirho(&wire_chirho)
            .unwrap();
        stream_chirho.write_all(&receipt_wire_chirho).unwrap();
        stream_chirho.shutdown(std::net::Shutdown::Write).unwrap();
    });

    // The client sends the PREPARE wire and reads the signed receipt back.
    let mut client_chirho = TcpStream::connect(addr_chirho).unwrap();
    client_chirho
        .write_all(&prepare_chirho.to_wire_bytes_chirho().unwrap())
        .unwrap();
    client_chirho.shutdown(std::net::Shutdown::Write).unwrap();
    let mut receipt_wire_chirho = Vec::new();
    client_chirho.read_to_end(&mut receipt_wire_chirho).unwrap();
    server_handle_chirho.join().unwrap();

    let verified_chirho = decode_and_verify_mirror_receipt_chirho(
        &receipt_wire_chirho,
        &prepare_frame_digest_chirho,
        &caller_key_chirho().digest_hex_chirho(),
        &group_digest_chirho,
        &foreign_node_id_chirho,
        &closure_id_chirho,
    )
    .expect("the receipt survives the socket round trip and verifies");
    assert_eq!(
        verified_chirho.stage_chirho(),
        MirrorReceiptStageChirho::PreparedChirho
    );
}

// FINALIZE — after a prepare, a signed finalize returns a Finalized receipt.

#[test]
fn finalize_after_prepare_returns_a_finalized_receipt_chirho() {
    let world_chirho = new_world_chirho();
    let holder_chirho =
        HolderDoubleChirho::new_chirho(&world_chirho.peer_two_chirho, &world_chirho, false);
    let prepare_chirho = signed_prepare_chirho(
        &world_chirho,
        &world_chirho.leader_chirho,
        &world_chirho.peer_two_chirho.node_id_chirho,
        TERM_CHIRHO,
        Some(LEADER_LEASE_MILLIS_CHIRHO),
    );
    let prepare_receipt_chirho = holder_chirho
        .prepare_durably_chirho(&prepare_chirho)
        .expect("prepare");

    let caller_key_chirho = caller_key_chirho();
    let finalize_prepared_chirho = PreparedFinalizeMirrorReceiptFrameChirho::new_chirho(
        FinalizeMirrorReceiptFrameInputChirho {
            origin_node_id_chirho: world_chirho.leader_chirho.node_id_chirho.clone(),
            target_node_id_chirho: world_chirho.peer_two_chirho.node_id_chirho.clone(),
            consistency_group_digest_chirho: world_chirho.group_digest_chirho.clone(),
            expected_term_chirho: TERM_CHIRHO,
            membership_view_digest_chirho: world_chirho
                .joined_chirho
                .view_chirho()
                .view_digest_chirho(),
            leader_lease_remaining_millis_chirho: Some(LEADER_LEASE_MILLIS_CHIRHO),
            caller_idempotency_key_digest_chirho: caller_key_chirho.digest_hex_chirho(),
            mirror_closure_id_chirho: prepare_receipt_chirho
                .mirror_closure_id_chirho()
                .to_string(),
            prepare_frame_digest_chirho: prepare_receipt_chirho
                .prepare_frame_digest_chirho()
                .to_string(),
            local_commit_binding_chirho: "77".repeat(32),
        },
    )
    .expect("finalize frame");
    let finalize_sig_chirho = sign_hex_chirho(
        &world_chirho.leader_chirho,
        &finalize_prepared_chirho.signing_digest_chirho(),
    );
    let finalize_frame_chirho = finalize_prepared_chirho
        .into_signed_chirho(finalize_sig_chirho)
        .unwrap();

    let finalize_receipt_chirho = holder_chirho
        .finalize_chirho(&finalize_frame_chirho)
        .expect("finalize");
    assert_eq!(
        finalize_receipt_chirho.stage_chirho(),
        MirrorReceiptStageChirho::FinalizedChirho
    );
}

/// A second `WorldChirho` reusing the same node keys + view as `world_chirho`, so a server thread can
/// own its own value without borrowing across the thread boundary.
fn new_world_shared_view_chirho(world_chirho: &WorldChirho) -> WorldChirho {
    WorldChirho {
        leader_chirho: NodeChirho {
            signing_key_chirho: world_chirho.leader_chirho.signing_key_chirho.clone(),
            node_id_chirho: world_chirho.leader_chirho.node_id_chirho.clone(),
        },
        peer_one_chirho: NodeChirho {
            signing_key_chirho: world_chirho.peer_one_chirho.signing_key_chirho.clone(),
            node_id_chirho: world_chirho.peer_one_chirho.node_id_chirho.clone(),
        },
        peer_two_chirho: NodeChirho {
            signing_key_chirho: world_chirho.peer_two_chirho.signing_key_chirho.clone(),
            node_id_chirho: world_chirho.peer_two_chirho.node_id_chirho.clone(),
        },
        held_observer_chirho: NodeChirho {
            signing_key_chirho: world_chirho.held_observer_chirho.signing_key_chirho.clone(),
            node_id_chirho: world_chirho.held_observer_chirho.node_id_chirho.clone(),
        },
        group_digest_chirho: world_chirho.group_digest_chirho.clone(),
        placement_chirho: world_chirho.placement_chirho.clone(),
        joined_chirho: world_chirho.joined_chirho.clone(),
    }
}
