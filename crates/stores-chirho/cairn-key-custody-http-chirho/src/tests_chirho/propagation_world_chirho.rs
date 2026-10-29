// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The erasure-propagation test world: three placed nodes with real holders, the leader's store, a recording seam, and clocks an arm can move.

use super::world_chirho::{
    key_id_chirho, observation_for_chirho, serve_router_chirho, verified_placement_chirho,
    ElectionViewChirho, NodeChirho, ObservedLeaseChirho, FIRST_TERM_CHIRHO, SUBJECT_CHIRHO,
};
use crate::holder_chirho::{KeyCustodyHolderChirho, KeyCustodyHolderConfigChirho};
use crate::leader_chirho::propagate_chirho::{
    propagate_erasure_requirement_chirho, retry_erasure_propagation_chirho,
    ErasureDeliveryErrorChirho, ErasureHolderSeamChirho, ErasureHoldersChirho,
    ErasureLeaderAuthorityChirho, ErasurePropagationPacingChirho, ErasurePropagationPolicyChirho,
    ErasurePropagationReportChirho,
};
use crate::leader_chirho::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
use crate::leader_chirho::store_chirho::{
    EarlierErasureChirho, ErasureAttemptChirho, ErasureAttemptIdentityChirho,
    ErasurePropagationStoreChirho, RecordRequirementRequestChirho,
    ERASURE_PROPAGATION_STORE_DIR_CHIRHO,
};
use crate::server_chirho::key_custody_router_chirho;
use cairn_key_custody_chirho::{
    subject_digest_hex_chirho, ErasureFrameV1Chirho, ErasurePropagationContextChirho,
    ErasureStatusChirho, VerifiedErasureReceiptChirho,
};
use cairn_mirror_chirho::join_mirror_view_chirho;
use cairn_signer_chirho::signer_chirho::{existing_keypair_pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    FakeMonotonicClockChirho, MonotonicClockChirho, DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub(crate) const TENANT_CHIRHO: &str = "item6-drill-chirho";
pub(crate) const INSTANCE_CHIRHO: &str = "genesis-instance-one-chirho";
pub(crate) const BOUND_CHIRHO: u64 = 5;
pub(crate) const LEASE_MILLIS_CHIRHO: u64 = 10_000;

/// Three placed nodes, each with its own sign root and holder. The leader's holder is reached in process; the two
/// peers' are served over real HTTP. The leader's root also holds the propagation store.
pub(crate) struct PropagationWorldChirho {
    _dir_chirho: tempfile::TempDir,
    pub(crate) leader_chirho: NodeChirho,
    pub(crate) peer_a_chirho: NodeChirho,
    pub(crate) peer_b_chirho: NodeChirho,
    pub(crate) leader_root_chirho: PathBuf,
    pub(crate) placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    pub(crate) leader_view_chirho: Arc<ElectionViewChirho>,
    pub(crate) clock_chirho: Arc<FakeMonotonicClockChirho>,
    pub(crate) store_chirho: ErasurePropagationStoreChirho,
    pub(crate) leader_holder_chirho: KeyCustodyHolderChirho,
    pub(crate) peer_origins_chirho: BTreeMap<String, String>,
    _servers_chirho: Vec<tokio::runtime::Runtime>,
}

pub(crate) fn sign_root_node_chirho(root_chirho: &Path) -> NodeChirho {
    fs::create_dir(root_chirho).expect("node root");
    sign_message_chirho(root_chirho, b"provision this node's key").expect("node key");
    NodeChirho::SignRootChirho {
        id_chirho: existing_keypair_pubkey_hex_chirho(root_chirho).expect("node id"),
        root_chirho: root_chirho.to_path_buf(),
    }
}

pub(crate) fn lease_chirho(
    is_leader_chirho: bool,
    remaining_chirho: Option<u64>,
) -> ObservedLeaseChirho {
    ObservedLeaseChirho {
        is_leader_chirho,
        lease_valid_chirho: remaining_chirho.is_some(),
        remaining_millis_chirho: remaining_chirho,
    }
}

pub(crate) fn propagation_world_chirho() -> PropagationWorldChirho {
    let dir_chirho = tempfile::tempdir().expect("temp dir");
    let leader_root_chirho = dir_chirho.path().join("leader-root-chirho");
    let leader_chirho = sign_root_node_chirho(&leader_root_chirho);
    let peer_a_chirho = sign_root_node_chirho(&dir_chirho.path().join("peer-a-root-chirho"));
    let peer_b_chirho = sign_root_node_chirho(&dir_chirho.path().join("peer-b-root-chirho"));
    let placement_chirho = Arc::new(verified_placement_chirho(
        [&leader_chirho, &peer_a_chirho, &peer_b_chirho],
        &NodeChirho::plain_chirho(4),
    ));
    let leader_view_chirho = Arc::new(ElectionViewChirho::new_chirho(observation_for_chirho(
        &placement_chirho,
        leader_chirho.id_chirho(),
        FIRST_TERM_CHIRHO,
        lease_chirho(true, Some(LEASE_MILLIS_CHIRHO)),
    )));
    let follower_view_chirho = Arc::new(ElectionViewChirho::new_chirho(observation_for_chirho(
        &placement_chirho,
        leader_chirho.id_chirho(),
        FIRST_TERM_CHIRHO,
        lease_chirho(false, Some(LEASE_MILLIS_CHIRHO)),
    )));
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let holder_for_chirho = |node_chirho: &NodeChirho, view_chirho: &Arc<ElectionViewChirho>| {
        let NodeChirho::SignRootChirho { root_chirho, .. } = node_chirho else {
            unreachable!("every placed node here signs from its own root")
        };
        KeyCustodyHolderChirho::open_chirho(KeyCustodyHolderConfigChirho {
            holder_dir_chirho: root_chirho.join("key-custody-holder-chirho"),
            sign_root_chirho: root_chirho.clone(),
            local_node_id_chirho: node_chirho.id_chirho().to_string(),
            placement_chirho: placement_chirho.clone(),
            election_view_chirho: view_chirho.clone(),
            clock_chirho: clock_chirho.clone(),
            transit_budget_millis_chirho: DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
        })
        .expect("holder opens")
    };
    let leader_holder_chirho = holder_for_chirho(&leader_chirho, &leader_view_chirho);
    let mut servers_chirho = Vec::new();
    let mut peer_origins_chirho = BTreeMap::new();
    for peer_chirho in [&peer_a_chirho, &peer_b_chirho] {
        let holder_chirho = holder_for_chirho(peer_chirho, &follower_view_chirho);
        let (runtime_chirho, origin_chirho) =
            serve_router_chirho(key_custody_router_chirho(Arc::new(holder_chirho)));
        servers_chirho.push(runtime_chirho);
        peer_origins_chirho.insert(peer_chirho.id_chirho().to_string(), origin_chirho);
    }
    let group_chirho = join_mirror_view_chirho(&placement_chirho, leader_view_chirho.as_ref())
        .expect("the world's view joins")
        .view_chirho()
        .consistency_group_digest_chirho()
        .to_string();
    let store_chirho = ErasurePropagationStoreChirho::open_chirho(
        &leader_root_chirho,
        ErasurePropagationContextChirho::new_chirho(
            &group_chirho,
            TENANT_CHIRHO,
            INSTANCE_CHIRHO,
            leader_chirho.id_chirho(),
        )
        .expect("context in form"),
    )
    .expect("store opens");
    PropagationWorldChirho {
        _dir_chirho: dir_chirho,
        leader_chirho,
        peer_a_chirho,
        peer_b_chirho,
        leader_root_chirho,
        placement_chirho,
        leader_view_chirho,
        clock_chirho,
        store_chirho,
        leader_holder_chirho,
        peer_origins_chirho,
        _servers_chirho: servers_chirho,
    }
}

pub(crate) fn subject_chirho() -> String {
    subject_digest_hex_chirho(SUBJECT_CHIRHO)
}

impl PropagationWorldChirho {
    pub(crate) fn holder_ids_chirho(&self) -> BTreeSet<String> {
        [
            &self.leader_chirho,
            &self.peer_a_chirho,
            &self.peer_b_chirho,
        ]
        .iter()
        .map(|node_chirho| node_chirho.id_chirho().to_string())
        .collect()
    }

    /// Record the requirement at `seq` over keys 1 and 2 for all three holders, binding it when asked.
    pub(crate) fn record_chirho(
        &self,
        seq_chirho: u64,
        earlier_chirho: BTreeMap<u64, EarlierErasureChirho>,
        bind_chirho: bool,
    ) {
        self.store_chirho
            .record_requirement_chirho(&RecordRequirementRequestChirho {
                subject_digest_chirho: subject_chirho(),
                erasure_seq_chirho: seq_chirho,
                erased_below_blob_seq_chirho: BOUND_CHIRHO,
                key_ids_chirho: [key_id_chirho(1), key_id_chirho(2)].into(),
                holders_chirho: self.holder_ids_chirho(),
                earlier_chirho,
            })
            .expect("requirement records");
        if bind_chirho {
            self.store_chirho
                .record_binding_chirho(&subject_chirho(), seq_chirho, &"ab".repeat(32))
                .expect("requirement binds");
        }
    }

    /// The real seam: the leader's own holder in process, the peers whose origins are given over HTTP.
    pub(crate) fn seam_with_chirho(
        &self,
        peer_origins_chirho: BTreeMap<String, String>,
    ) -> ErasureHoldersChirho<'_> {
        ErasureHoldersChirho::new_chirho(
            self.leader_chirho.id_chirho(),
            Some(&self.leader_holder_chirho),
            peer_origins_chirho,
        )
    }

    pub(crate) fn seam_chirho(&self) -> ErasureHoldersChirho<'_> {
        self.seam_with_chirho(self.peer_origins_chirho.clone())
    }

    pub(crate) fn set_leader_view_chirho(
        &self,
        leader_chirho: &str,
        remaining_chirho: Option<u64>,
    ) {
        self.leader_view_chirho.set_chirho(observation_for_chirho(
            &self.placement_chirho,
            leader_chirho,
            FIRST_TERM_CHIRHO,
            lease_chirho(
                leader_chirho == self.leader_chirho.id_chirho(),
                remaining_chirho,
            ),
        ));
    }

    pub(crate) fn propagate_chirho(
        &self,
        seq_chirho: u64,
        seam_chirho: &dyn ErasureHolderSeamChirho,
        policy_chirho: ErasurePropagationPolicyChirho,
    ) -> Result<ErasurePropagationReportChirho, LeaderRefusalChirho> {
        self.propagate_with_clock_chirho(
            seq_chirho,
            seam_chirho,
            policy_chirho,
            self.clock_chirho.as_ref(),
        )
    }

    /// Propagate with `pacing_clock_chirho` as the engine's clock. Its pauses still advance the world's clock.
    pub(crate) fn propagate_with_clock_chirho(
        &self,
        seq_chirho: u64,
        seam_chirho: &dyn ErasureHolderSeamChirho,
        policy_chirho: ErasurePropagationPolicyChirho,
        pacing_clock_chirho: &dyn MonotonicClockChirho,
    ) -> Result<ErasurePropagationReportChirho, LeaderRefusalChirho> {
        let sleep_chirho = self.sleep_chirho();
        propagate_erasure_requirement_chirho(
            &self.store_chirho,
            &subject_chirho(),
            seq_chirho,
            &self.authority_chirho(),
            seam_chirho,
            &ErasurePropagationPacingChirho {
                policy_chirho,
                clock_chirho: pacing_clock_chirho,
                sleep_chirho: &sleep_chirho,
            },
        )
    }

    /// Retry by an attempt's identity alone, under the world's authority and clock.
    pub(crate) fn retry_chirho(
        &self,
        identity_chirho: &ErasureAttemptIdentityChirho,
        seam_chirho: &dyn ErasureHolderSeamChirho,
        policy_chirho: ErasurePropagationPolicyChirho,
    ) -> Result<ErasureAttemptChirho, LeaderRefusalChirho> {
        let sleep_chirho = self.sleep_chirho();
        retry_erasure_propagation_chirho(
            &self.store_chirho,
            identity_chirho,
            &self.authority_chirho(),
            seam_chirho,
            &ErasurePropagationPacingChirho {
                policy_chirho,
                clock_chirho: self.clock_chirho.as_ref(),
                sleep_chirho: &sleep_chirho,
            },
        )
    }

    fn authority_chirho(&self) -> ErasureLeaderAuthorityChirho<'_> {
        ErasureLeaderAuthorityChirho {
            placement_chirho: &self.placement_chirho,
            election_view_chirho: self.leader_view_chirho.as_ref(),
        }
    }

    /// A pause advances the world's clock instead of waiting.
    fn sleep_chirho(&self) -> impl Fn(Duration) {
        let clock_chirho = self.clock_chirho.clone();
        move |pause_chirho: Duration| {
            clock_chirho.advance_millis_chirho(pause_chirho.as_millis() as u64);
        }
    }

    /// The consistency group of the world's joined view, which is the store's.
    pub(crate) fn group_chirho(&self) -> String {
        join_mirror_view_chirho(&self.placement_chirho, self.leader_view_chirho.as_ref())
            .expect("the world's view joins")
            .view_chirho()
            .consistency_group_digest_chirho()
            .to_string()
    }

    pub(crate) fn receipts_dir_chirho(&self, seq_chirho: u64) -> PathBuf {
        let subject_chirho = subject_chirho();
        self.leader_root_chirho
            .join(ERASURE_PROPAGATION_STORE_DIR_CHIRHO)
            .join(&subject_chirho[..2])
            .join(&subject_chirho)
            .join(format!("{seq_chirho}.receipts"))
    }
}

/// One delivery the seam saw: the holder, the frame's digest and lease, and the timeout it was given.
#[derive(Clone, Debug)]
pub(crate) struct DeliveryChirho {
    pub(crate) holder_chirho: String,
    pub(crate) frame_digest_chirho: String,
    pub(crate) lease_chirho: Option<u64>,
    pub(crate) timeout_chirho: Duration,
    /// The world clock's reading as the delivery began, when the seam was given that clock.
    pub(crate) at_millis_chirho: Option<u64>,
}

/// Before the nth delivery to a holder: answer instead of delivering, or let it through.
pub(crate) type BeforeHookChirho<'hook_chirho> =
    Box<dyn Fn(usize, &str) -> Option<ErasureDeliveryErrorChirho> + 'hook_chirho>;

/// Wraps a seam: records every delivery, and lets an arm answer or act before and after each one.
pub(crate) struct RecordingSeamChirho<'inner_chirho> {
    pub(crate) inner_chirho: &'inner_chirho dyn ErasureHolderSeamChirho,
    pub(crate) deliveries_chirho: RefCell<Vec<DeliveryChirho>>,
    pub(crate) before_chirho: BeforeHookChirho<'inner_chirho>,
    pub(crate) after_chirho: Box<dyn Fn(usize) + 'inner_chirho>,
    pub(crate) stamp_clock_chirho: Option<Arc<FakeMonotonicClockChirho>>,
}

impl<'inner_chirho> RecordingSeamChirho<'inner_chirho> {
    pub(crate) fn passing_chirho(inner_chirho: &'inner_chirho dyn ErasureHolderSeamChirho) -> Self {
        Self {
            inner_chirho,
            deliveries_chirho: RefCell::new(Vec::new()),
            before_chirho: Box::new(|_, _| None),
            after_chirho: Box::new(|_| ()),
            stamp_clock_chirho: None,
        }
    }

    pub(crate) fn holders_chirho(&self) -> Vec<String> {
        self.deliveries_chirho
            .borrow()
            .iter()
            .map(|delivery_chirho| delivery_chirho.holder_chirho.clone())
            .collect()
    }
}

impl ErasureHolderSeamChirho for RecordingSeamChirho<'_> {
    fn deliver_erasure_chirho(
        &self,
        holder_chirho: &str,
        frame_chirho: &ErasureFrameV1Chirho,
        timeout_chirho: Duration,
    ) -> Result<VerifiedErasureReceiptChirho, ErasureDeliveryErrorChirho> {
        let index_chirho = self.deliveries_chirho.borrow().len();
        let wire_chirho: serde_json::Value = serde_json::to_value(frame_chirho).unwrap();
        self.deliveries_chirho.borrow_mut().push(DeliveryChirho {
            holder_chirho: holder_chirho.to_string(),
            frame_digest_chirho: frame_chirho.frame_digest_chirho().to_string(),
            lease_chirho: wire_chirho["leader_lease_remaining_millis_chirho"].as_u64(),
            timeout_chirho,
            at_millis_chirho: self
                .stamp_clock_chirho
                .as_ref()
                .map(|clock_chirho| clock_chirho.now_millis_chirho()),
        });
        if let Some(error_chirho) = (self.before_chirho)(index_chirho, holder_chirho) {
            return Err(error_chirho);
        }
        let answer_chirho =
            self.inner_chirho
                .deliver_erasure_chirho(holder_chirho, frame_chirho, timeout_chirho);
        (self.after_chirho)(index_chirho);
        answer_chirho
    }
}

pub(crate) fn pending_chirho(holders_chirho: &[&str]) -> ErasureStatusChirho {
    ErasureStatusChirho::ErasurePropagationPendingChirho {
        pending_holders_chirho: holders_chirho
            .iter()
            .map(|holder_chirho| holder_chirho.to_string())
            .collect(),
    }
}

pub(crate) fn leader_refusal_chirho<TChirho>(
    result_chirho: Result<TChirho, LeaderRefusalChirho>,
) -> LeaderRefusalIdentityChirho {
    match result_chirho {
        Ok(_) => panic!("expected a refusal"),
        Err(error_chirho) => error_chirho
            .leader_identity_chirho()
            .unwrap_or_else(|| panic!("expected a store refusal, got {error_chirho}")),
    }
}

/// An origin nothing listens on: a port bound and released.
pub(crate) fn dead_origin_chirho() -> String {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address_chirho = listener_chirho.local_addr().unwrap();
    drop(listener_chirho);
    format!("http://{address_chirho}")
}

/// A pacing clock that moves on its own: every reading first advances the world's clock by one tick, so any two
/// readings, such as the two around a frame's signing, are at least a tick apart.
#[derive(Debug)]
pub(crate) struct TickingClockChirho {
    pub(crate) inner_chirho: Arc<FakeMonotonicClockChirho>,
    pub(crate) tick_millis_chirho: u64,
}

impl MonotonicClockChirho for TickingClockChirho {
    fn now_millis_chirho(&self) -> u64 {
        self.inner_chirho
            .advance_millis_chirho(self.tick_millis_chirho);
        self.inner_chirho.now_millis_chirho()
    }
}
