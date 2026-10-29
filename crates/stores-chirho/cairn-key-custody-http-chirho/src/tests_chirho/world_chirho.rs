// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A three-voter world for the holder: the holder signs from a real sign root, the leader and the others from plain keys, over a real verified placement and the mirror's real join.

use crate::holder_chirho::{KeyCustodyHolderChirho, KeyCustodyHolderConfigChirho};
use cairn_key_custody_chirho::{
    authorize_erasure_frame_chirho, decode_and_authenticate_erasure_frame_chirho,
    seal_wrapped_key_chirho, subject_digest_hex_chirho, CustodyBindingChirho, CustodyFrameV1Chirho,
    ErasureFrameInputChirho, ErasureFrameV1Chirho, PreparedCustodyFrameChirho,
    PreparedErasureFrameChirho, PreparedErasureReceiptChirho, ShredKeyRecordChirho,
    VerifiedErasureReceiptChirho,
};
use cairn_mirror_chirho::{
    join_mirror_view_chirho, JoinedMirrorViewChirho, MirrorContractErrorChirho,
    MirrorElectionObservationChirho, MirrorLeadershipViewChirho,
};
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_signer_chirho::signer_chirho::{
    existing_keypair_pubkey_hex_chirho, sign_message_chirho, sign_message_with_existing_key_chirho,
};
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
    FakeMonotonicClockChirho, MonotonicClockChirho, DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
};
use ed25519_dalek::{Signer, SigningKey};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub(crate) const FIRST_TERM_CHIRHO: u64 = 5;
const CONF_INDEX_CHIRHO: u64 = 11;
const LEASE_MILLIS_CHIRHO: u64 = 10_000;
pub(crate) const SUBJECT_CHIRHO: &str = "app/contact-chirho/submission/one";
pub(crate) const OTHER_SUBJECT_CHIRHO: &str = "app/contact-chirho/submission/two";

/// A node that signs: the holder from its sign root, every other node from a plain key.
pub(crate) enum NodeChirho {
    PlainChirho {
        key_chirho: SigningKey,
        id_chirho: String,
    },
    SignRootChirho {
        root_chirho: PathBuf,
        id_chirho: String,
    },
}

impl NodeChirho {
    pub(crate) fn plain_chirho(seed_chirho: u8) -> Self {
        let key_chirho = SigningKey::from_bytes(&[seed_chirho; 32]);
        let id_chirho = hex_chirho(key_chirho.verifying_key().as_bytes());
        Self::PlainChirho {
            key_chirho,
            id_chirho,
        }
    }

    pub(crate) fn id_chirho(&self) -> &str {
        match self {
            Self::PlainChirho { id_chirho, .. } | Self::SignRootChirho { id_chirho, .. } => {
                id_chirho
            }
        }
    }

    pub(crate) fn sign_hex_chirho(&self, message_chirho: &[u8]) -> String {
        match self {
            Self::PlainChirho { key_chirho, .. } => {
                hex_chirho(&key_chirho.sign(message_chirho).to_bytes())
            }
            Self::SignRootChirho { root_chirho, .. } => {
                sign_message_with_existing_key_chirho(root_chirho, message_chirho)
                    .expect("the holder's sign root signs")
            }
        }
    }
}

/// The holder's election view: the leader it sees and the term, changeable between admissions. A view may also
/// charge each read some time on a clock, so an arm can make reading authority itself take time.
pub(crate) struct ElectionViewChirho {
    observation_chirho: Mutex<MirrorElectionObservationChirho>,
    read_cost_chirho: Mutex<Option<(Arc<FakeMonotonicClockChirho>, u64)>>,
    read_times_chirho: Mutex<Vec<u64>>,
}

impl ElectionViewChirho {
    pub(crate) fn new_chirho(observation_chirho: MirrorElectionObservationChirho) -> Self {
        Self {
            observation_chirho: Mutex::new(observation_chirho),
            read_cost_chirho: Mutex::new(None),
            read_times_chirho: Mutex::new(Vec::new()),
        }
    }

    /// The election this view reports from now on.
    pub(crate) fn set_chirho(&self, observation_chirho: MirrorElectionObservationChirho) {
        *self.observation_chirho.lock().unwrap() = observation_chirho;
    }

    /// From now on every read of this view is logged at its start time on `clock_chirho`, then advances that clock by
    /// `millis_chirho` before it answers.
    pub(crate) fn charge_reads_chirho(
        &self,
        clock_chirho: Arc<FakeMonotonicClockChirho>,
        millis_chirho: u64,
    ) {
        *self.read_cost_chirho.lock().unwrap() = Some((clock_chirho, millis_chirho));
    }

    /// When each logged read began, in order.
    pub(crate) fn read_times_chirho(&self) -> Vec<u64> {
        self.read_times_chirho.lock().unwrap().clone()
    }
}

impl MirrorLeadershipViewChirho for ElectionViewChirho {
    fn observe_election_chirho(
        &self,
    ) -> Result<MirrorElectionObservationChirho, MirrorContractErrorChirho> {
        if let Some((clock_chirho, millis_chirho)) = &*self.read_cost_chirho.lock().unwrap() {
            self.read_times_chirho
                .lock()
                .unwrap()
                .push(clock_chirho.now_millis_chirho());
            clock_chirho.advance_millis_chirho(*millis_chirho);
        }
        Ok(self.observation_chirho.lock().unwrap().clone())
    }
}

pub(crate) struct WorldChirho {
    _dir_chirho: tempfile::TempDir,
    pub(crate) holder_dir_chirho: PathBuf,
    pub(crate) sign_root_chirho: PathBuf,
    pub(crate) holder_chirho: NodeChirho,
    pub(crate) leader_chirho: NodeChirho,
    pub(crate) peer_chirho: NodeChirho,
    placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    view_chirho: Arc<ElectionViewChirho>,
    clock_chirho: Arc<FakeMonotonicClockChirho>,
}

pub(crate) fn world_chirho() -> WorldChirho {
    let dir_chirho = tempfile::tempdir().expect("temp dir");
    let sign_root_chirho = dir_chirho.path().join("sign-root-chirho");
    sign_message_chirho(&sign_root_chirho, b"provision the holder's node key")
        .expect("the holder's node key is created");
    let holder_chirho = NodeChirho::SignRootChirho {
        id_chirho: existing_keypair_pubkey_hex_chirho(&sign_root_chirho).unwrap(),
        root_chirho: sign_root_chirho.clone(),
    };
    let leader_chirho = NodeChirho::plain_chirho(1);
    let peer_chirho = NodeChirho::plain_chirho(3);
    let held_observer_chirho = NodeChirho::plain_chirho(4);
    let placement_chirho = Arc::new(verified_placement_chirho(
        [&leader_chirho, &holder_chirho, &peer_chirho],
        &held_observer_chirho,
    ));
    let view_chirho = Arc::new(ElectionViewChirho::new_chirho(observation_chirho(
        &placement_chirho,
        leader_chirho.id_chirho(),
        FIRST_TERM_CHIRHO,
    )));
    WorldChirho {
        holder_dir_chirho: dir_chirho.path().join("key-custody-chirho"),
        _dir_chirho: dir_chirho,
        sign_root_chirho,
        holder_chirho,
        leader_chirho,
        peer_chirho,
        placement_chirho,
        view_chirho,
        clock_chirho: FakeMonotonicClockChirho::new_chirho(),
    }
}

impl WorldChirho {
    /// Open (or reopen, as after a restart) the holder over this world's directories.
    pub(crate) fn open_holder_chirho(&self) -> KeyCustodyHolderChirho {
        KeyCustodyHolderChirho::open_chirho(
            self.holder_config_chirho(self.holder_chirho.id_chirho()),
        )
        .expect("the holder opens")
    }

    /// The holder's configuration over this world, claiming to be `local_node_id_chirho`.
    pub(crate) fn holder_config_chirho(
        &self,
        local_node_id_chirho: &str,
    ) -> KeyCustodyHolderConfigChirho {
        let clock_chirho: Arc<dyn MonotonicClockChirho> = self.clock_chirho.clone();
        let view_chirho: Arc<dyn MirrorLeadershipViewChirho> = self.view_chirho.clone();
        KeyCustodyHolderConfigChirho {
            holder_dir_chirho: self.holder_dir_chirho.clone(),
            sign_root_chirho: self.sign_root_chirho.clone(),
            local_node_id_chirho: local_node_id_chirho.to_string(),
            placement_chirho: self.placement_chirho.clone(),
            election_view_chirho: view_chirho,
            clock_chirho,
            transit_budget_millis_chirho: DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
        }
    }

    /// The holder now sees the same leader at `term_chirho`.
    pub(crate) fn set_term_chirho(&self, term_chirho: u64) {
        *self.view_chirho.observation_chirho.lock().unwrap() = observation_chirho(
            &self.placement_chirho,
            self.leader_chirho.id_chirho(),
            term_chirho,
        );
    }

    pub(crate) fn joined_chirho(&self) -> JoinedMirrorViewChirho {
        join_mirror_view_chirho(&self.placement_chirho, self.view_chirho.as_ref())
            .expect("the world's view joins")
    }

    /// The binding the current leader uses for one key sent to the holder, under the current view.
    pub(crate) fn binding_chirho(
        &self,
        key_id_chirho: &str,
        subject_chirho: &str,
        blob_seq_chirho: u64,
        origin_chirho: &NodeChirho,
    ) -> CustodyBindingChirho {
        let joined_chirho = self.joined_chirho();
        CustodyBindingChirho {
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho()
                .to_string(),
            membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
            elected_term_chirho: joined_chirho.term_chirho(),
            origin_node_id_chirho: origin_chirho.id_chirho().to_string(),
            holder_node_id_chirho: self.holder_chirho.id_chirho().to_string(),
            key_id_chirho: key_id_chirho.to_string(),
            subject_digest_chirho: subject_digest_hex_chirho(subject_chirho),
            ciphertext_addr_chirho: format!("{:064x}", blob_seq_chirho + 7),
            blob_seq_chirho,
        }
    }

    /// A custody frame for one key, sealed to the holder's own announcement and signed by `origin`.
    pub(crate) fn custody_frame_chirho(
        &self,
        holder_chirho: &KeyCustodyHolderChirho,
        key_id_chirho: &str,
        subject_chirho: &str,
        blob_seq_chirho: u64,
        fill_chirho: u8,
        origin_chirho: &NodeChirho,
    ) -> CustodyFrameV1Chirho {
        let binding_chirho = self.binding_chirho(
            key_id_chirho,
            subject_chirho,
            blob_seq_chirho,
            origin_chirho,
        );
        let announcement_chirho = holder_chirho
            .announcement_chirho()
            .expect("the holder announces")
            .verify_chirho()
            .expect("the announcement verifies");
        let wrapped_chirho = seal_wrapped_key_chirho(
            &record_chirho(subject_chirho, fill_chirho),
            &announcement_chirho,
            &binding_chirho,
        )
        .expect("seal");
        let prepared_chirho = PreparedCustodyFrameChirho::new_chirho(
            binding_chirho,
            Some(LEASE_MILLIS_CHIRHO),
            wrapped_chirho,
        )
        .expect("frame prepares");
        let signature_chirho =
            origin_chirho.sign_hex_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("frame signs")
    }

    /// An erasure frame for the holder under the current view, signed by `origin`.
    pub(crate) fn erasure_frame_chirho(
        &self,
        subject_chirho: &str,
        erased_below_blob_seq_chirho: u64,
        key_ids_chirho: &[String],
        origin_chirho: &NodeChirho,
    ) -> ErasureFrameV1Chirho {
        self.erasure_frame_to_chirho(
            self.holder_chirho.id_chirho(),
            subject_chirho,
            erased_below_blob_seq_chirho,
            key_ids_chirho,
            origin_chirho,
        )
    }

    /// A target node's genuine erasure receipt for a frame from the current leader under the current view: the
    /// frame is authenticated and authorized for that node, and the receipt is signed with its own key.
    /// `removed` and `absent` split the listed ids.
    pub(crate) fn erasure_receipt_for_chirho(
        &self,
        target_chirho: &NodeChirho,
        subject_chirho: &str,
        erased_below_blob_seq_chirho: u64,
        removed_chirho: &[String],
        absent_chirho: &[String],
    ) -> VerifiedErasureReceiptChirho {
        let listed_chirho = removed_chirho
            .iter()
            .chain(absent_chirho)
            .cloned()
            .collect::<Vec<_>>();
        let frame_chirho = self.erasure_frame_to_chirho(
            target_chirho.id_chirho(),
            subject_chirho,
            erased_below_blob_seq_chirho,
            &listed_chirho,
            &self.leader_chirho,
        );
        let authorized_chirho = authorize_erasure_frame_chirho(
            decode_and_authenticate_erasure_frame_chirho(
                &frame_chirho.to_wire_bytes_chirho().expect("frame encodes"),
            )
            .expect("frame authenticates"),
            &self.joined_chirho(),
            target_chirho.id_chirho(),
            self.clock_chirho.as_ref(),
            DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
        )
        .expect("the current leader's frame is authorized for its target");
        let prepared_chirho = PreparedErasureReceiptChirho::after_durable_erasure_chirho(
            &authorized_chirho,
            removed_chirho.iter().cloned().collect(),
            absent_chirho.iter().cloned().collect(),
            std::collections::BTreeSet::new(),
        )
        .expect("receipt prepares");
        let signature_chirho =
            target_chirho.sign_hex_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("receipt signs")
            .verify_chirho()
            .expect("receipt verifies")
    }

    /// An erasure frame for `holder_node_id_chirho` under the current view, signed by `origin`.
    pub(crate) fn erasure_frame_to_chirho(
        &self,
        holder_node_id_chirho: &str,
        subject_chirho: &str,
        erased_below_blob_seq_chirho: u64,
        key_ids_chirho: &[String],
        origin_chirho: &NodeChirho,
    ) -> ErasureFrameV1Chirho {
        let joined_chirho = self.joined_chirho();
        let prepared_chirho = PreparedErasureFrameChirho::new_chirho(ErasureFrameInputChirho {
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho()
                .to_string(),
            membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
            elected_term_chirho: joined_chirho.term_chirho(),
            origin_node_id_chirho: origin_chirho.id_chirho().to_string(),
            holder_node_id_chirho: holder_node_id_chirho.to_string(),
            leader_lease_remaining_millis_chirho: Some(LEASE_MILLIS_CHIRHO),
            subject_digest_chirho: subject_digest_hex_chirho(subject_chirho),
            erased_below_blob_seq_chirho,
            key_ids_chirho: key_ids_chirho.iter().cloned().collect(),
        })
        .expect("erasure frame prepares");
        let signature_chirho =
            origin_chirho.sign_hex_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("erasure frame signs")
    }

    pub(crate) fn subject_dir_chirho(&self, subject_chirho: &str) -> PathBuf {
        let digest_chirho = subject_digest_hex_chirho(subject_chirho);
        self.holder_dir_chirho
            .join("keys-chirho")
            .join(&digest_chirho[..2])
            .join(digest_chirho)
    }

    pub(crate) fn key_path_chirho(&self, subject_chirho: &str, key_id_chirho: &str) -> PathBuf {
        self.subject_dir_chirho(subject_chirho)
            .join(format!("{key_id_chirho}.key.json"))
    }

    pub(crate) fn binding_path_chirho(&self, subject_chirho: &str, key_id_chirho: &str) -> PathBuf {
        self.subject_dir_chirho(subject_chirho)
            .join(format!("{key_id_chirho}.binding.json"))
    }
}

/// A 32-hex key id from a small number.
pub(crate) fn key_id_chirho(number_chirho: u8) -> String {
    format!("{number_chirho:032x}")
}

/// A synthetic test key for `subject`, every byte `fill`.
pub(crate) fn record_chirho(subject_chirho: &str, fill_chirho: u8) -> ShredKeyRecordChirho {
    ShredKeyRecordChirho::new_chirho(subject_chirho, format!("{fill_chirho:02x}").repeat(32))
        .expect("record in form")
}

pub(crate) fn mode_chirho(path_chirho: &Path) -> u32 {
    std::fs::metadata(path_chirho)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn observation_chirho(
    placement_chirho: &VerifiedTenantPlacementChirho,
    leader_chirho: &str,
    term_chirho: u64,
) -> MirrorElectionObservationChirho {
    observation_for_chirho(
        placement_chirho,
        leader_chirho,
        term_chirho,
        ObservedLeaseChirho {
            is_leader_chirho: false,
            lease_valid_chirho: true,
            remaining_millis_chirho: Some(LEASE_MILLIS_CHIRHO),
        },
    )
}

/// What one node observes of its own lease: whether it is the leader, whether its lease is valid, and how much of
/// it remains to carry on the wire.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ObservedLeaseChirho {
    pub(crate) is_leader_chirho: bool,
    pub(crate) lease_valid_chirho: bool,
    pub(crate) remaining_millis_chirho: Option<u64>,
}

/// One node's election observation over this placement: `leader_chirho` leads at `term_chirho`, and `lease_chirho`
/// is what this node sees of the lease.
pub(crate) fn observation_for_chirho(
    placement_chirho: &VerifiedTenantPlacementChirho,
    leader_chirho: &str,
    term_chirho: u64,
    lease_chirho: ObservedLeaseChirho,
) -> MirrorElectionObservationChirho {
    let mut members_chirho = placement_chirho
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
    members_chirho.push((
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
            is_leader_chirho: lease_chirho.is_leader_chirho,
            leader_id_chirho: Some(NodeIdChirho(leader_chirho.to_string())),
            term_chirho,
            lease_valid_chirho: lease_chirho.lease_valid_chirho,
        },
        authenticated_members_chirho: members_chirho,
        voter_raft_ids_chirho: vec![1, 2, 3],
        learner_raft_ids_chirho: vec![4],
        applied_conf_index_chirho: CONF_INDEX_CHIRHO,
        leader_lease_remaining_millis_chirho: lease_chirho.remaining_millis_chirho,
    }
}

pub(crate) fn verified_placement_chirho(
    serving_nodes_chirho: [&NodeChirho; 3],
    held_observer_chirho: &NodeChirho,
) -> VerifiedTenantPlacementChirho {
    let placement_authority_chirho = NodeChirho::plain_chirho(5);
    let roster_authority_chirho = NodeChirho::plain_chirho(6);
    let plan_authority_chirho = NodeChirho::plain_chirho(7);
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
                node_id_chirho: node_chirho.id_chirho().to_string(),
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
        node_id_chirho: held_observer_chirho.id_chirho().to_string(),
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
        tenant_id_chirho: "custody-holder-fixture-chirho".to_string(),
        consistency_group_id_chirho: "tenant-chirho:custody-holder-fixture-chirho".to_string(),
        preferred_node_chirho: serving_nodes_chirho[0].id_chirho().to_string(),
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
                .find(|node_chirho| node_chirho.id_chirho() == binding_chirho.node_id_chirho)
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
            receipt_chirho.sig_chirho = node_chirho.sign_hex_chirho(
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
    held_observer_readiness_receipt_chirho.sig_chirho = held_observer_chirho.sign_hex_chirho(
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
        placement_key_id_chirho: placement_authority_chirho.id_chirho().to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = placement_authority_chirho
        .sign_hex_chirho(&unsigned_tenant_placement_record_message_chirho(&record_chirho).unwrap());
    verify_tenant_placement_record_chirho(
        record_chirho,
        placement_authority_chirho.id_chirho(),
        roster_authority_chirho.id_chirho(),
        plan_authority_chirho.id_chirho(),
    )
    .expect("fixture placement verifies")
}

/// Serve `router_chirho` on a fresh loopback port, on its own runtime, and return the runtime and the origin.
pub(crate) fn serve_router_chirho(
    router_chirho: axum::Router,
) -> (tokio::runtime::Runtime, String) {
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let listener_chirho = runtime_chirho
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address_chirho = listener_chirho.local_addr().unwrap();
    runtime_chirho.spawn(async move {
        axum::serve(listener_chirho, router_chirho).await.unwrap();
    });
    (runtime_chirho, format!("http://{address_chirho}"))
}
