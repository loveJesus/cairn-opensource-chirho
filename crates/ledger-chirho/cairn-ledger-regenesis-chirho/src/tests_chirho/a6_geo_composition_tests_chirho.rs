// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::{
    fixture_chirho, refresh_fixture_activation_authorization_chirho, request_chirho,
    temp_root_chirho, RegenesisFixtureChirho,
};
use crate::run_ledger_regenesis_chirho;
use cairn_config_chirho::config_chirho::{load_config_chirho, LedgerHostConfigChirho};
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitJournalPortChirho, EffectCommitJournalPortErrorChirho,
    EffectCommitJournalResidentRefusalIdentityChirho, EffectCommitJournalViewPortChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_geo_node_chirho::a6_authority_composition_chirho::A6GeoResidentAuthorityCompositionChirho;
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho, HostLedgerSignersChirho,
    ResidentEffectJournalHandleChirho,
};
use cairn_ledger_mirror_http_chirho::{
    compose_ledger_append_mirror_chirho, LedgerAppendMirrorCompositionChirho,
    LedgerMirrorJournalVerifierBindingChirho, LedgerMirrorPeerEndpointChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerRecordChirho};
use cairn_ledger_model_chirho::wire_chirho::stored_line_digest_chirho;
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_signer_chirho::signer_chirho::{
    existing_keypair_pubkey_hex_chirho, pubkey_hex_chirho, sign_message_with_existing_key_chirho,
};
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
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
use cairn_writer_elector_chirho::elector_port_chirho::{LeaseTierChirho, NodeIdChirho};
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::ShadowCanaryGenerationStoreChirho;
use cairn_writer_elector_http_chirho::cluster_node_chirho::{
    ClusterNodeChirho, ClusterNodeConfigChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, issue_elected_writer_fence_chirho,
    split_writer_epoch_chirho, writer_fence_path_chirho, ConsistencyGroupIdChirho,
};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;

const TEST_TICK_INTERVAL_CHIRHO: Duration = Duration::from_millis(250);
const RECOVERY_TENANT_ID_CHIRHO: &str = "item7-recovery-drill-chirho";
const MIRROR_ROOT_DIR_CHIRHO: &str = "ledger-mirror-f1-chirho";
const MIRROR_FOLLOWER_DIR_CHIRHO: &str = "follower-f1-chirho";
const MIRROR_HIGH_WATER_FILE_CHIRHO: &str = "high-water-chirho.json";

struct TenantRegenesisFixtureChirho {
    platform_root_chirho: PathBuf,
    fixture_chirho: RegenesisFixtureChirho,
}

impl TenantRegenesisFixtureChirho {
    fn new_chirho() -> Self {
        let mut fixture_chirho = fixture_chirho();
        let old_root_chirho = fixture_chirho.root_chirho.clone();
        let config_name_chirho = fixture_chirho
            .config_path_chirho
            .file_name()
            .expect("fixture config filename")
            .to_owned();
        let plan_name_chirho = fixture_chirho
            .plan_path_chirho
            .file_name()
            .expect("fixture plan filename")
            .to_owned();
        let authorization_name_chirho = fixture_chirho
            .activation_authorization_path_chirho
            .file_name()
            .expect("fixture authorization filename")
            .to_owned();
        let platform_root_chirho = temp_root_chirho();
        std::fs::create_dir(&platform_root_chirho).expect("create tenant fixture platform root");
        let tenant_root_chirho =
            prepare_tenant_root_chirho(&platform_root_chirho, RECOVERY_TENANT_ID_CHIRHO)
                .expect("prepare independently rooted tenant fixture");
        for entry_chirho in
            std::fs::read_dir(&old_root_chirho).expect("read portable regenesis fixture")
        {
            let entry_chirho = entry_chirho.expect("fixture entry");
            std::fs::rename(
                entry_chirho.path(),
                tenant_root_chirho.join(entry_chirho.file_name()),
            )
            .expect("move regenesis fixture below its tenant marker");
        }
        std::fs::remove_dir(&old_root_chirho).expect("remove empty portable fixture root");
        fixture_chirho.root_chirho = tenant_root_chirho;
        fixture_chirho.config_path_chirho = fixture_chirho.root_chirho.join(config_name_chirho);
        fixture_chirho.plan_path_chirho = fixture_chirho.root_chirho.join(plan_name_chirho);
        fixture_chirho.activation_authorization_path_chirho =
            fixture_chirho.root_chirho.join(authorization_name_chirho);
        refresh_fixture_activation_authorization_chirho(&mut fixture_chirho);
        Self {
            platform_root_chirho,
            fixture_chirho,
        }
    }

    fn node_id_chirho(&self) -> NodeIdChirho {
        NodeIdChirho(
            existing_keypair_pubkey_hex_chirho(&self.fixture_chirho.root_chirho)
                .expect("read tenant fixture node identity"),
        )
    }
}

impl Drop for TenantRegenesisFixtureChirho {
    fn drop(&mut self) {
        let _remove_result_chirho = std::fs::remove_dir_all(&self.platform_root_chirho);
    }
}

struct RunningRecoveryMirrorServerChirho {
    stop_chirho: Option<tokio::sync::oneshot::Sender<()>>,
    thread_chirho: Option<JoinHandle<()>>,
}

impl RunningRecoveryMirrorServerChirho {
    fn start_chirho(listener_chirho: TcpListener, router_chirho: axum::Router) -> Self {
        listener_chirho
            .set_nonblocking(true)
            .expect("set recovery mirror listener nonblocking");
        let (stop_sender_chirho, stop_receiver_chirho) = tokio::sync::oneshot::channel();
        let (ready_sender_chirho, ready_receiver_chirho) = mpsc::sync_channel(1);
        let thread_chirho = std::thread::spawn(move || {
            let runtime_chirho = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build recovery mirror runtime");
            runtime_chirho.block_on(async move {
                let listener_chirho = tokio::net::TcpListener::from_std(listener_chirho)
                    .expect("adopt recovery mirror listener");
                ready_sender_chirho
                    .send(())
                    .expect("signal recovery mirror ready");
                axum::serve(listener_chirho, router_chirho)
                    .with_graceful_shutdown(async move {
                        let _stop_result_chirho = stop_receiver_chirho.await;
                    })
                    .await
                    .expect("serve recovery mirror router");
            });
        });
        ready_receiver_chirho
            .recv()
            .expect("recovery mirror server ready");
        Self {
            stop_chirho: Some(stop_sender_chirho),
            thread_chirho: Some(thread_chirho),
        }
    }
}

impl Drop for RunningRecoveryMirrorServerChirho {
    fn drop(&mut self) {
        if let Some(stop_chirho) = self.stop_chirho.take() {
            let _send_result_chirho = stop_chirho.send(());
        }
        if let Some(thread_chirho) = self.thread_chirho.take() {
            let _join_result_chirho = thread_chirho.join();
        }
    }
}

struct RunningRecoveryElectionClockChirho {
    stop_chirho: Option<mpsc::Sender<()>>,
    thread_chirho: Option<JoinHandle<()>>,
}

impl RunningRecoveryElectionClockChirho {
    fn start_chirho(
        nodes_chirho: &[ClusterNodeChirho],
        leader_index_chirho: usize,
        absent_raft_ids_chirho: Vec<u64>,
    ) -> Self {
        let electors_chirho = nodes_chirho
            .iter()
            .map(|node_chirho| Arc::clone(node_chirho.elector_chirho()))
            .collect::<Vec<_>>();
        let (stop_sender_chirho, stop_receiver_chirho) = mpsc::channel();
        let thread_chirho = std::thread::spawn(move || loop {
            match stop_receiver_chirho.recv_timeout(Duration::from_millis(25)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let mut messages_chirho = electors_chirho[leader_index_chirho].tick_chirho();
            for _round_chirho in 0..1_000 {
                if messages_chirho.is_empty() {
                    break;
                }
                let mut next_chirho = Vec::new();
                for message_chirho in messages_chirho.drain(..) {
                    if absent_raft_ids_chirho.contains(&message_chirho.to) {
                        continue;
                    }
                    let target_chirho = electors_chirho
                        .iter()
                        .find(|elector_chirho| {
                            elector_chirho.local_raft_id_chirho() == message_chirho.to
                        })
                        .unwrap_or_else(|| {
                            panic!(
                                "recovery election clock has no route for raft id {}",
                                message_chirho.to
                            )
                        });
                    next_chirho.extend(
                        target_chirho
                            .step_chirho(message_chirho)
                            .expect("recovery election clock delivers heartbeat traffic"),
                    );
                }
                messages_chirho = next_chirho;
            }
            assert!(
                messages_chirho.is_empty(),
                "recovery election clock drains every heartbeat cascade"
            );
        });
        Self {
            stop_chirho: Some(stop_sender_chirho),
            thread_chirho: Some(thread_chirho),
        }
    }

    fn finish_chirho(mut self) {
        if let Some(stop_chirho) = self.stop_chirho.take() {
            stop_chirho
                .send(())
                .expect("stop the recovery election clock");
        }
        if let Some(thread_chirho) = self.thread_chirho.take() {
            thread_chirho
                .join()
                .expect("recovery election clock stayed healthy");
        }
    }
}

impl Drop for RunningRecoveryElectionClockChirho {
    fn drop(&mut self) {
        if let Some(stop_chirho) = self.stop_chirho.take() {
            let _send_result_chirho = stop_chirho.send(());
        }
        if let Some(thread_chirho) = self.thread_chirho.take() {
            let _join_result_chirho = thread_chirho.join();
        }
    }
}

struct ReopenedA6ClusterFleetChirho {
    nodes_chirho: Vec<ClusterNodeChirho>,
    local_node_chirho: NodeIdChirho,
}

fn cluster_config_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    local_raft_id_chirho: u64,
    voters_chirho: &[(u64, NodeIdChirho)],
    held_learner_chirho: &(u64, NodeIdChirho),
    sign_root_chirho: &Path,
) -> ClusterNodeConfigChirho {
    let peers_chirho = voters_chirho
        .iter()
        .chain(std::iter::once(held_learner_chirho))
        .filter(|(raft_id_chirho, _node_chirho)| *raft_id_chirho != local_raft_id_chirho)
        .map(|(raft_id_chirho, _node_chirho)| {
            (
                *raft_id_chirho,
                format!("http://127.0.0.1:{}", 39_000 + raft_id_chirho),
            )
        })
        .collect();
    ClusterNodeConfigChirho {
        group_chirho: group_chirho.clone(),
        local_raft_id_chirho,
        voters_chirho: voters_chirho.to_vec(),
        learners_chirho: vec![held_learner_chirho.clone()],
        peers_chirho,
        durable_dir_chirho: root_chirho
            .join(format!("a6-geo-cluster-node-{local_raft_id_chirho}-chirho")),
        sign_root_chirho: sign_root_chirho.to_path_buf(),
        tick_interval_chirho: TEST_TICK_INTERVAL_CHIRHO,
        membership_control_chirho: None,
    }
}

fn build_reopened_a6_cluster_fleet_chirho(
    fixture_chirho: &RegenesisFixtureChirho,
) -> ReopenedA6ClusterFleetChirho {
    let fleet_chirho = open_reopened_a6_cluster_nodes_chirho(fixture_chirho);
    drive_cluster_campaign_chirho(&fleet_chirho.nodes_chirho);
    drive_cluster_warm_ticks_chirho(&fleet_chirho.nodes_chirho, 12);
    let leadership_chirho = fleet_chirho.nodes_chirho[0]
        .elector_chirho()
        .current_leadership_chirho();
    assert!(leadership_chirho.is_leader_chirho);
    assert!(leadership_chirho.lease_valid_chirho);
    assert_eq!(
        leadership_chirho.leader_id_chirho.as_ref(),
        Some(&fleet_chirho.local_node_chirho)
    );
    fleet_chirho
}

/// Seed and reopen the real three-voter cluster for `fixture_chirho`, with nobody leading yet.
fn open_reopened_a6_cluster_nodes_chirho(
    fixture_chirho: &RegenesisFixtureChirho,
) -> ReopenedA6ClusterFleetChirho {
    let root_chirho = fixture_chirho.root_chirho.canonicalize().unwrap();
    let local_node_chirho = NodeIdChirho(existing_keypair_pubkey_hex_chirho(&root_chirho).unwrap());
    let second_sign_root_chirho = root_chirho.join("a6-voter-two-signing-chirho");
    let third_sign_root_chirho = root_chirho.join("a6-voter-three-signing-chirho");
    let held_sign_root_chirho = root_chirho.join("a6-held-learner-signing-chirho");
    let second_node_chirho = NodeIdChirho(pubkey_hex_chirho(&second_sign_root_chirho).unwrap());
    let third_node_chirho = NodeIdChirho(pubkey_hex_chirho(&third_sign_root_chirho).unwrap());
    let held_node_chirho = NodeIdChirho(pubkey_hex_chirho(&held_sign_root_chirho).unwrap());
    let voters_chirho = vec![
        (1, local_node_chirho.clone()),
        (2, second_node_chirho),
        (3, third_node_chirho),
    ];
    let held_learner_chirho = (4, held_node_chirho);
    let sign_roots_chirho = [
        root_chirho.clone(),
        second_sign_root_chirho,
        third_sign_root_chirho,
    ];
    let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();

    let seeded_nodes_chirho = (1..=3)
        .zip(sign_roots_chirho.iter())
        .map(|(raft_id_chirho, sign_root_chirho)| {
            ClusterNodeChirho::build_chirho(cluster_config_chirho(
                &root_chirho,
                &group_chirho,
                raft_id_chirho,
                &voters_chirho,
                &held_learner_chirho,
                sign_root_chirho,
            ))
            .expect("seed the durable production cluster member")
        })
        .collect::<Vec<_>>();
    drop(seeded_nodes_chirho);

    let nodes_chirho = (1..=3)
        .zip(sign_roots_chirho.iter())
        .map(|(raft_id_chirho, sign_root_chirho)| {
            ClusterNodeChirho::open_existing_chirho(cluster_config_chirho(
                &root_chirho,
                &group_chirho,
                raft_id_chirho,
                &voters_chirho,
                &held_learner_chirho,
                sign_root_chirho,
            ))
            .expect("reopen the exact durable production cluster member")
        })
        .collect::<Vec<_>>();
    ReopenedA6ClusterFleetChirho {
        nodes_chirho,
        local_node_chirho,
    }
}

fn drive_cluster_campaign_chirho(nodes_chirho: &[ClusterNodeChirho]) {
    let mut messages_chirho = nodes_chirho[0]
        .elector_chirho()
        .campaign_chirho()
        .expect("the first real cluster node starts a campaign");
    for _round_chirho in 0..1_000 {
        if messages_chirho.is_empty() {
            return;
        }
        let mut next_chirho = Vec::new();
        for message_chirho in messages_chirho.drain(..) {
            let Some(target_chirho) = nodes_chirho.iter().find(|node_chirho| {
                node_chirho.elector_chirho().local_raft_id_chirho() == message_chirho.to
            }) else {
                assert_eq!(
                    message_chirho.to, 4,
                    "only the deliberately offline held learner may lack a test driver"
                );
                continue;
            };
            next_chirho.extend(
                target_chirho
                    .elector_chirho()
                    .step_chirho(message_chirho)
                    .expect("the target persists and applies campaign traffic"),
            );
        }
        messages_chirho = next_chirho;
    }
    panic!("the real cluster campaign did not drain within the fixed bound");
}

fn drive_cluster_warm_ticks_chirho(nodes_chirho: &[ClusterNodeChirho], count_chirho: usize) {
    for _tick_chirho in 0..count_chirho {
        std::thread::sleep(TEST_TICK_INTERVAL_CHIRHO);
        let mut messages_chirho = nodes_chirho[0].elector_chirho().tick_chirho();
        for _round_chirho in 0..1_000 {
            if messages_chirho.is_empty() {
                break;
            }
            let mut next_chirho = Vec::new();
            for message_chirho in messages_chirho.drain(..) {
                let Some(target_chirho) = nodes_chirho.iter().find(|node_chirho| {
                    node_chirho.elector_chirho().local_raft_id_chirho() == message_chirho.to
                }) else {
                    assert_eq!(
                        message_chirho.to, 4,
                        "only the deliberately offline held learner may lack a test driver"
                    );
                    continue;
                };
                next_chirho.extend(
                    target_chirho
                        .elector_chirho()
                        .step_chirho(message_chirho)
                        .expect("the target persists and applies warmup traffic"),
                );
            }
            messages_chirho = next_chirho;
        }
        assert!(messages_chirho.is_empty());
    }
}

fn drive_recovery_transfer_without_old_leader_chirho(
    nodes_chirho: &[ClusterNodeChirho],
    leader_index_chirho: usize,
    target_raft_id_chirho: u64,
) {
    let mut messages_chirho = nodes_chirho[leader_index_chirho]
        .elector_chirho()
        .transfer_leadership_to_chirho(target_raft_id_chirho)
        .expect("the surviving leader starts preferred-owner transfer");
    for _round_chirho in 0..1_000 {
        if messages_chirho.is_empty() {
            return;
        }
        let mut next_chirho = Vec::new();
        for (target_id_chirho, message_bytes_chirho) in messages_chirho.drain(..) {
            if matches!(target_id_chirho, 1 | 4) {
                continue;
            }
            let target_chirho = nodes_chirho
                .iter()
                .find(|node_chirho| {
                    node_chirho.elector_chirho().local_raft_id_chirho() == target_id_chirho
                })
                .expect("every surviving transfer target is present");
            next_chirho.extend(
                target_chirho
                    .elector_chirho()
                    .step_encoded_chirho(&message_bytes_chirho)
                    .expect("surviving target accepts preferred-owner transfer traffic"),
            );
        }
        messages_chirho = next_chirho;
    }
    panic!("the recovery leadership transfer did not drain within the fixed bound");
}

/// Tick the cluster until one node's leadership lease is warm and live, or give up loudly.
///
/// A FIXED tick count cannot express "the lease is warm": it expresses "this much wall clock has
/// probably passed", which is true on an idle machine and false under a loaded one. Waiting on the
/// CONDITION removes that guess. Once it becomes true, one final successful heartbeat refreshes the
/// lease before the caller begins startup instead of handing it an arbitrarily old still-valid lease.
/// The bound keeps a genuine never-warms failure from hanging, and the panic says which node failed.
fn drive_cluster_ticks_until_lease_warm_chirho(
    nodes_chirho: &[ClusterNodeChirho],
    node_index_chirho: usize,
    max_ticks_chirho: usize,
) {
    for _tick_chirho in 0..max_ticks_chirho {
        let leadership_chirho = nodes_chirho[node_index_chirho]
            .elector_chirho()
            .current_leadership_chirho();
        if leadership_chirho.is_leader_chirho && leadership_chirho.lease_valid_chirho {
            drive_cluster_warm_ticks_chirho(nodes_chirho, 1);
            let refreshed_chirho = nodes_chirho[node_index_chirho]
                .elector_chirho()
                .current_leadership_chirho();
            if refreshed_chirho.is_leader_chirho && refreshed_chirho.lease_valid_chirho {
                return;
            }
        }
        drive_cluster_warm_ticks_chirho(nodes_chirho, 1);
    }
    let final_chirho = nodes_chirho[node_index_chirho]
        .elector_chirho()
        .current_leadership_chirho();
    panic!(
        "node {node_index_chirho} lease never became warm within {max_ticks_chirho} ticks: is_leader={} lease_valid={}",
        final_chirho.is_leader_chirho, final_chirho.lease_valid_chirho
    );
}

fn drive_recovery_heal_ticks_chirho(nodes_chirho: &[ClusterNodeChirho], count_chirho: usize) {
    for _tick_chirho in 0..count_chirho {
        std::thread::sleep(TEST_TICK_INTERVAL_CHIRHO);
        let mut messages_chirho = nodes_chirho[1].elector_chirho().tick_chirho();
        for _round_chirho in 0..1_000 {
            if messages_chirho.is_empty() {
                break;
            }
            let mut next_chirho = Vec::new();
            for message_chirho in messages_chirho.drain(..) {
                if message_chirho.to == 4 {
                    continue;
                }
                let target_chirho = nodes_chirho
                    .iter()
                    .find(|node_chirho| {
                        node_chirho.elector_chirho().local_raft_id_chirho() == message_chirho.to
                    })
                    .expect("every healed warmup target is present");
                next_chirho.extend(
                    target_chirho
                        .elector_chirho()
                        .step_chirho(message_chirho)
                        .expect("healed target accepts current-leader traffic"),
                );
            }
            messages_chirho = next_chirho;
        }
        assert!(messages_chirho.is_empty());
    }
}

struct RecoveryClusterFleetChirho {
    nodes_chirho: Vec<ClusterNodeChirho>,
    held_node_chirho: NodeIdChirho,
}

fn build_recovery_cluster_fleet_chirho(
    fixtures_chirho: &[TenantRegenesisFixtureChirho],
    held_sign_root_chirho: &Path,
) -> RecoveryClusterFleetChirho {
    assert_eq!(fixtures_chirho.len(), 3);
    let node_ids_chirho = fixtures_chirho
        .iter()
        .map(TenantRegenesisFixtureChirho::node_id_chirho)
        .collect::<Vec<_>>();
    assert!(node_ids_chirho
        .windows(2)
        .all(|pair_chirho| pair_chirho[0].0 < pair_chirho[1].0));
    let held_node_chirho = NodeIdChirho(
        pubkey_hex_chirho(held_sign_root_chirho).expect("provision held observer identity"),
    );
    let voters_chirho = node_ids_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, node_chirho)| {
            (
                u64::try_from(index_chirho).expect("raft index") + 1,
                node_chirho.clone(),
            )
        })
        .collect::<Vec<_>>();
    let held_learner_chirho = (4, held_node_chirho.clone());
    let group_chirho =
        consistency_group_for_root_chirho(&fixtures_chirho[0].fixture_chirho.root_chirho)
            .expect("derive tenant recovery group");
    for fixture_chirho in fixtures_chirho {
        assert_eq!(
            consistency_group_for_root_chirho(&fixture_chirho.fixture_chirho.root_chirho)
                .expect("derive peer tenant group"),
            group_chirho,
            "independent roots must converge on the tenant-scoped consistency group"
        );
    }
    let seeded_nodes_chirho = fixtures_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, fixture_chirho)| {
            let raft_id_chirho = u64::try_from(index_chirho).expect("raft index") + 1;
            ClusterNodeChirho::build_chirho(cluster_config_chirho(
                &fixture_chirho.fixture_chirho.root_chirho,
                &group_chirho,
                raft_id_chirho,
                &voters_chirho,
                &held_learner_chirho,
                &fixture_chirho.fixture_chirho.root_chirho,
            ))
            .expect("seed recovery drill cluster node")
        })
        .collect::<Vec<_>>();
    drop(seeded_nodes_chirho);
    let nodes_chirho = fixtures_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, fixture_chirho)| {
            let raft_id_chirho = u64::try_from(index_chirho).expect("raft index") + 1;
            ClusterNodeChirho::open_existing_chirho(cluster_config_chirho(
                &fixture_chirho.fixture_chirho.root_chirho,
                &group_chirho,
                raft_id_chirho,
                &voters_chirho,
                &held_learner_chirho,
                &fixture_chirho.fixture_chirho.root_chirho,
            ))
            .expect("reopen recovery drill cluster node")
        })
        .collect::<Vec<_>>();
    drive_cluster_campaign_chirho(&nodes_chirho);
    drive_cluster_warm_ticks_chirho(&nodes_chirho, 12);
    RecoveryClusterFleetChirho {
        nodes_chirho,
        held_node_chirho,
    }
}

fn sign_existing_node_message_chirho(root_chirho: &Path, bytes_chirho: &[u8]) -> String {
    sign_message_with_existing_key_chirho(root_chirho, bytes_chirho)
        .expect("sign placement fixture with an existing node identity")
}

fn recovery_placement_chirho(
    fixtures_chirho: &[TenantRegenesisFixtureChirho],
    held_sign_root_chirho: &Path,
) -> Arc<VerifiedTenantPlacementChirho> {
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
    let assigned_nodes_chirho = fixtures_chirho
        .iter()
        .zip(domains_chirho.iter())
        .enumerate()
        .map(
            |(index_chirho, (fixture_chirho, domain_chirho))| TenantPlacementNodeBindingChirho {
                node_id_chirho: fixture_chirho.node_id_chirho().0,
                failure_domain_chirho: domain_chirho.clone(),
                expected_root_binding_chirho: format!(
                    "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
                    char::from(b'a' + u8::try_from(index_chirho).expect("binding index"))
                        .to_string()
                        .repeat(64)
                ),
                expected_cluster_config_blake3_chirho: char::from(
                    b'd' + u8::try_from(index_chirho).expect("config index"),
                )
                .to_string()
                .repeat(64),
            },
        )
        .collect::<Vec<_>>();
    let held_node_id_chirho =
        existing_keypair_pubkey_hex_chirho(held_sign_root_chirho).expect("held observer identity");
    let held_binding_chirho = TenantPlacementNodeBindingChirho {
        node_id_chirho: held_node_id_chirho.clone(),
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
        tenant_id_chirho: RECOVERY_TENANT_ID_CHIRHO.to_string(),
        consistency_group_id_chirho: format!("tenant-chirho:{RECOVERY_TENANT_ID_CHIRHO}"),
        preferred_node_chirho: assigned_nodes_chirho[0].node_id_chirho.clone(),
        assigned_nodes_chirho,
        held_observer_node_chirho: held_binding_chirho,
        demand_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 1,
            memory_bytes_chirho: 1,
            durable_bytes_chirho: 1,
        },
        residency_chirho: TenantPlacementResidencyChirho {
            allowed_domains_chirho,
        },
        topology_plan_digest_chirho: "9".repeat(64),
    };
    let intent_digest_chirho =
        tenant_placement_intent_digest_chirho(&intent_chirho).expect("hash recovery placement");
    let serving_readiness_receipts_chirho = intent_chirho
        .assigned_nodes_chirho
        .iter()
        .zip(fixtures_chirho.iter())
        .map(|(binding_chirho, fixture_chirho)| {
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
            receipt_chirho.sig_chirho = sign_existing_node_message_chirho(
                &fixture_chirho.fixture_chirho.root_chirho,
                &unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho)
                    .expect("render serving readiness"),
            );
            receipt_chirho
        })
        .collect::<Vec<_>>();
    let held_binding_chirho = &intent_chirho.held_observer_node_chirho;
    let mut held_receipt_chirho = TenantPlacementHeldObserverReadinessReceiptChirho {
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
    held_receipt_chirho.sig_chirho = sign_existing_node_message_chirho(
        held_sign_root_chirho,
        &unsigned_tenant_placement_held_observer_readiness_message_chirho(&held_receipt_chirho)
            .expect("render held readiness"),
    );
    let authority_root_chirho = &fixtures_chirho[0].fixture_chirho.root_chirho;
    let placement_sign_root_chirho = authority_root_chirho.join("placement-authority-chirho");
    let roster_sign_root_chirho = authority_root_chirho.join("roster-authority-chirho");
    let plan_sign_root_chirho = authority_root_chirho.join("plan-authority-chirho");
    let placement_key_chirho =
        pubkey_hex_chirho(&placement_sign_root_chirho).expect("placement authority key");
    let roster_key_chirho =
        pubkey_hex_chirho(&roster_sign_root_chirho).expect("roster authority key");
    let plan_key_chirho = pubkey_hex_chirho(&plan_sign_root_chirho).expect("plan authority key");
    let mut record_chirho = TenantPlacementRecordChirho {
        schema_chirho: TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        serving_readiness_receipts_chirho,
        held_observer_readiness_receipt_chirho: held_receipt_chirho,
        placement_key_id_chirho: placement_key_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_existing_node_message_chirho(
        &placement_sign_root_chirho,
        &unsigned_tenant_placement_record_message_chirho(&record_chirho)
            .expect("render placement record"),
    );
    Arc::new(
        verify_tenant_placement_record_chirho(
            record_chirho,
            &placement_key_chirho,
            &roster_key_chirho,
            &plan_key_chirho,
        )
        .expect("verify recovery placement"),
    )
}

fn mirror_peer_endpoints_chirho(
    fixtures_chirho: &[TenantRegenesisFixtureChirho],
    held_node_chirho: &NodeIdChirho,
    serving_addresses_chirho: &[SocketAddr],
    held_address_chirho: SocketAddr,
) -> Vec<LedgerMirrorPeerEndpointChirho> {
    fixtures_chirho
        .iter()
        .zip(serving_addresses_chirho.iter())
        .map(|(fixture_chirho, socket_addr_chirho)| {
            LedgerMirrorPeerEndpointChirho::new_chirho(
                fixture_chirho.node_id_chirho().0,
                *socket_addr_chirho,
            )
            .expect("bind serving mirror endpoint")
        })
        .chain(std::iter::once(
            LedgerMirrorPeerEndpointChirho::new_chirho(
                held_node_chirho.0.clone(),
                held_address_chirho,
            )
            .expect("bind held mirror endpoint"),
        ))
        .collect()
}

fn compose_recovery_mirror_chirho(
    fixture_chirho: &TenantRegenesisFixtureChirho,
    node_chirho: &ClusterNodeChirho,
    placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    endpoints_chirho: &[LedgerMirrorPeerEndpointChirho],
) -> LedgerAppendMirrorCompositionChirho {
    let config_chirho = ledger_config_chirho(&fixture_chirho.fixture_chirho);
    let pins_chirho = config_chirho
        .held_verifier_pins_chirho
        .as_ref()
        .expect("recovery fixture carries journal verifier pins");
    let verifier_chirho = LedgerMirrorJournalVerifierBindingChirho::new_chirho(
        format!(
            "journal-chirho:{}",
            config_chirho.signer_secrets_chirho.journal_chirho
        ),
        pins_chirho.journal_verifying_key_hex_chirho.clone(),
    )
    .expect("bind recovery mirror journal verifier");
    compose_ledger_append_mirror_chirho(
        &fixture_chirho.fixture_chirho.root_chirho,
        &fixture_chirho.fixture_chirho.root_chirho,
        &fixture_chirho.node_id_chirho().0,
        placement_chirho,
        verifier_chirho,
        Arc::clone(node_chirho.elector_chirho()),
        endpoints_chirho.to_vec(),
    )
    .expect("compose production recovery mirror")
}

fn follower_high_water_chirho(root_chirho: &Path) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(
            root_chirho
                .join(MIRROR_ROOT_DIR_CHIRHO)
                .join(MIRROR_FOLLOWER_DIR_CHIRHO)
                .join(MIRROR_HIGH_WATER_FILE_CHIRHO),
        )
        .expect("read follower high-water"),
    )
    .expect("parse follower high-water")
}

fn record_coordinate_chirho(record_chirho: &LedgerRecordChirho) -> (u64, String) {
    let line_chirho = serde_json::to_string(record_chirho).expect("render journal record");
    (
        record_chirho.seq_chirho,
        stored_line_digest_chirho(&line_chirho).0,
    )
}

fn ledger_config_chirho(fixture_chirho: &RegenesisFixtureChirho) -> LedgerHostConfigChirho {
    load_config_chirho(&fixture_chirho.config_path_chirho)
        .unwrap()
        .ledger_host_chirho
        .expect("the regenesis fixture carries ledger-host config")
}

fn signed_hold_line_chirho(
    fixture_chirho: &RegenesisFixtureChirho,
    config_chirho: &LedgerHostConfigChirho,
    actor_chirho: &ResidentEffectJournalHandleChirho,
) -> String {
    signed_hold_line_with_request_ref_chirho(fixture_chirho, config_chirho, actor_chirho, 'e')
}

fn signed_hold_line_with_request_ref_chirho(
    fixture_chirho: &RegenesisFixtureChirho,
    config_chirho: &LedgerHostConfigChirho,
    actor_chirho: &ResidentEffectJournalHandleChirho,
    request_ref_fill_chirho: char,
) -> String {
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho).unwrap();
    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &fixture_chirho.root_chirho,
        &signer_refs_chirho,
    )
    .unwrap();
    let kind_id_chirho = AssetKindIdChirho(fixture_chirho.plan_chirho.kind_id_chirho.clone());
    let continuation_chirho = actor_chirho
        .current_continuation_chirho(&kind_id_chirho)
        .unwrap()
        .expect("the published kind has one verified continuation");
    let digest_chirho =
        |character_chirho: char| DigestChirho(character_chirho.to_string().repeat(64));
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: actor_chirho.effect_intent_cut_chirho().unwrap(),
            contract_set_digest_chirho: digest_chirho('a'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "capability_fingerprint_chirho": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }))
            .unwrap(),
            reversion_contract_digest_chirho: digest_chirho('d'),
            request_ref_chirho: digest_chirho(request_ref_fill_chirho),
            request_context_ref_chirho: digest_chirho('f'),
            evidence_refs_chirho: vec![digest_chirho('9')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: kind_id_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho(
                fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
                kind_id_chirho,
            ),
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signers_chirho.effect_intent_signer_chirho(),
    )
    .unwrap();
    canonical_effect_intent_line_chirho(&intent_chirho).unwrap()
}

fn persisted_writer_epoch_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Option<u64> {
    let fence_path_chirho = writer_fence_path_chirho(root_chirho, group_chirho).unwrap();
    if !fence_path_chirho.exists() {
        return None;
    }
    let value_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fence_path_chirho).unwrap()).unwrap();
    Some(
        value_chirho["epoch_chirho"]
            .as_u64()
            .expect("persisted writer fence carries its numeric composite epoch"),
    )
}

fn journal_path_chirho(root_chirho: &Path, config_chirho: &LedgerHostConfigChirho) -> PathBuf {
    root_chirho
        .join(&config_chirho.storage_namespace_chirho)
        .join(&config_chirho.journal_path_chirho)
}

fn last_journal_record_chirho(
    root_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
) -> LedgerRecordChirho {
    let journal_chirho = std::fs::read_to_string(journal_path_chirho(root_chirho, config_chirho))
        .expect("read the durable journal after the composed append");
    serde_json::from_str(
        journal_chirho
            .lines()
            .last()
            .expect("the activated journal is nonempty"),
    )
    .expect("the final journal line is a canonical ledger record")
}

fn open_unmirrored_shared_elector_test_fixture_chirho(
    composition_chirho: &A6GeoResidentAuthorityCompositionChirho,
    root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
) -> anyhow::Result<ResidentEffectJournalHandleChirho> {
    open_resident_effect_journal_handle_with_shared_elector_chirho(
        root_chirho,
        config_path_chirho,
        config_chirho,
        composition_chirho.elector_chirho(),
        None,
        None,
    )
}

#[test]
fn real_geo_composition_actor_dies_with_external_cluster_elector_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let config_chirho = ledger_config_chirho(&fixture_chirho);
    let fleet_chirho = build_reopened_a6_cluster_fleet_chirho(&fixture_chirho);
    let composition_chirho = A6GeoResidentAuthorityCompositionChirho::from_cluster_node_chirho(
        &fleet_chirho.nodes_chirho[0],
    )
    .expect("the real three-voter ClusterNode selects the A6 authority path");
    let actor_chirho = open_unmirrored_shared_elector_test_fixture_chirho(
        &composition_chirho,
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &config_chirho,
    )
    .expect("the test-only shared-elector fixture opens the resident actor");

    drop(composition_chirho);
    drop(fleet_chirho);
    assert!(
        actor_chirho.effect_intent_cut_chirho().is_err(),
        "the geo actor must not outlive or replace its transport-owned cluster elector"
    );
}

#[test]
fn real_geo_composition_persists_fence_before_rejected_journal_mutation_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let config_chirho = ledger_config_chirho(&fixture_chirho);
    let group_chirho = consistency_group_for_root_chirho(&fixture_chirho.root_chirho).unwrap();
    let before_epoch_chirho =
        persisted_writer_epoch_chirho(&fixture_chirho.root_chirho, &group_chirho).unwrap();
    let journal_path_chirho = journal_path_chirho(&fixture_chirho.root_chirho, &config_chirho);
    let journal_before_chirho = std::fs::read(&journal_path_chirho).unwrap();
    let fleet_chirho = build_reopened_a6_cluster_fleet_chirho(&fixture_chirho);
    let composition_chirho = A6GeoResidentAuthorityCompositionChirho::from_cluster_node_chirho(
        &fleet_chirho.nodes_chirho[0],
    )
    .expect("the real three-voter ClusterNode selects the A6 authority path");
    let leadership_chirho = composition_chirho
        .elector_chirho()
        .current_leadership_chirho();
    let mut actor_chirho = open_unmirrored_shared_elector_test_fixture_chirho(
        &composition_chirho,
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &config_chirho,
    )
    .expect("the test-only shared-elector fixture opens the resident actor");
    let intent_line_chirho =
        signed_hold_line_chirho(&fixture_chirho, &config_chirho, &actor_chirho);
    let mut tampered_intent_chirho: serde_json::Value =
        serde_json::from_str(&intent_line_chirho).unwrap();
    tampered_intent_chirho["request_ref_chirho"] = serde_json::json!("8".repeat(64));
    let tampered_line_chirho = serde_json::to_string(&tampered_intent_chirho).unwrap();

    let refusal_chirho = actor_chirho
        .append_hold_chirho(&tampered_line_chirho)
        .expect_err("a signature-invalid effect intent cannot enter the journal");
    // RETARGETED AGAIN 2026-08-17 for the same reason as the deposed-writer arm below, and likewise
    // strengthened with an identity assertion. The warrant-publication refusal that catches this
    // tampered line used to share the generic `RefusedChirho` with ~30 unrelated conditions; it now
    // reports the named residual group, which is what makes "none of the specific groups" readable.
    let EffectCommitJournalPortErrorChirho::ResidentRefusedChirho {
        identity_chirho,
        detail_chirho,
    } = refusal_chirho
    else {
        panic!("the invalid intent must return the resident refusal identity");
    };
    assert_eq!(
        identity_chirho,
        EffectCommitJournalResidentRefusalIdentityChirho::AuthorityCompositionOtherChirho
    );
    // RETARGETED, not weakened. This test's properties are the three below — the fence was
    // persisted, its geo term matches the leadership term, and the journal did not move. They are
    // unchanged. What moved is WHERE the tampered line is caught: the resident boundary now
    // publishes each effect warrant before its append, so a signature-invalid intent is refused as
    // an unverifiable WARRANT and never reaches the journal door. That refusal is strictly earlier
    // than the old one and still strictly later than the fence durability boundary at
    // `resident_authority_chirho.rs` (fence `atomic_write_chirho`, then publish, then append).
    //
    // If this now reads "resident journal mutation was refused" again, the warrant publisher stopped
    // running ahead of the append — retarget at the publisher, not at this string. If it reads
    // anything else, a THIRD refusal boundary appeared between the fence and the journal.
    assert_eq!(
        detail_chirho,
        "resident effect warrant was not published, so its append is refused: \
         effect intent warrant did not verify"
    );
    let persisted_epoch_chirho =
        persisted_writer_epoch_chirho(&fixture_chirho.root_chirho, &group_chirho).unwrap();
    assert!(persisted_epoch_chirho > before_epoch_chirho);
    assert_eq!(
        u64::from(split_writer_epoch_chirho(persisted_epoch_chirho).geo_term_chirho),
        leadership_chirho.term_chirho
    );
    assert_eq!(
        std::fs::read(journal_path_chirho).unwrap(),
        journal_before_chirho,
        "the rejected append cannot move the journal after the fence durability boundary"
    );
}

#[test]
fn real_geo_composition_persists_elected_composite_epoch_before_append_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let config_chirho = ledger_config_chirho(&fixture_chirho);
    let group_chirho = consistency_group_for_root_chirho(&fixture_chirho.root_chirho).unwrap();
    let before_epoch_chirho =
        persisted_writer_epoch_chirho(&fixture_chirho.root_chirho, &group_chirho).unwrap_or(0);
    let fleet_chirho = build_reopened_a6_cluster_fleet_chirho(&fixture_chirho);
    let composition_chirho = A6GeoResidentAuthorityCompositionChirho::from_cluster_node_chirho(
        &fleet_chirho.nodes_chirho[0],
    )
    .expect("the real three-voter ClusterNode selects the A6 authority path");
    assert!(Arc::ptr_eq(
        composition_chirho.elector_chirho(),
        fleet_chirho.nodes_chirho[0].elector_chirho()
    ));
    assert_eq!(
        composition_chirho.elector_chirho().lease_tier_chirho(),
        LeaseTierChirho::MonotonicDecayChirho
    );
    let leadership_chirho = composition_chirho
        .elector_chirho()
        .current_leadership_chirho();
    assert_eq!(
        leadership_chirho.leader_id_chirho.as_ref(),
        Some(&fleet_chirho.local_node_chirho)
    );

    let mut actor_chirho = open_unmirrored_shared_elector_test_fixture_chirho(
        &composition_chirho,
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &config_chirho,
    )
    .expect("the test-only shared-elector fixture opens the resident actor");
    let intent_line_chirho =
        signed_hold_line_chirho(&fixture_chirho, &config_chirho, &actor_chirho);
    let receipt_chirho = actor_chirho
        .append_hold_chirho(&intent_line_chirho)
        .expect("the elected A6 authority reaches the real final append");

    let persisted_epoch_chirho =
        persisted_writer_epoch_chirho(&fixture_chirho.root_chirho, &group_chirho)
            .expect("the selected elected writer fence is durable after the append");
    assert!(
        persisted_epoch_chirho > before_epoch_chirho,
        "the replacement elected fence must be durable before the append succeeds"
    );
    assert_eq!(
        u64::from(split_writer_epoch_chirho(persisted_epoch_chirho).geo_term_chirho),
        leadership_chirho.term_chirho
    );
    let final_record_chirho =
        last_journal_record_chirho(&fixture_chirho.root_chirho, &config_chirho);
    assert_eq!(final_record_chirho.seq_chirho, receipt_chirho.seq_chirho);
    assert_eq!(final_record_chirho.epoch_chirho, persisted_epoch_chirho);

    drop(composition_chirho);
    drop(fleet_chirho);
    assert!(
        actor_chirho.effect_intent_cut_chirho().is_err(),
        "the geo actor must not outlive or replace its transport-owned cluster elector"
    );
}

#[test]
fn real_geo_composition_refuses_a_deposed_term_without_mutation_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let config_chirho = ledger_config_chirho(&fixture_chirho);
    let group_chirho = consistency_group_for_root_chirho(&fixture_chirho.root_chirho).unwrap();
    let higher_fence_chirho =
        issue_elected_writer_fence_chirho(&fixture_chirho.root_chirho, &group_chirho, 2)
            .expect("persist the already-accepted higher geo term");
    assert_eq!(
        split_writer_epoch_chirho(higher_fence_chirho.epoch_chirho).geo_term_chirho,
        2
    );
    let fence_path_chirho =
        writer_fence_path_chirho(&fixture_chirho.root_chirho, &group_chirho).unwrap();
    let journal_path_chirho = journal_path_chirho(&fixture_chirho.root_chirho, &config_chirho);
    let fence_before_chirho = std::fs::read(&fence_path_chirho).unwrap();
    let journal_before_chirho = std::fs::read(&journal_path_chirho).unwrap();

    let fleet_chirho = build_reopened_a6_cluster_fleet_chirho(&fixture_chirho);
    let composition_chirho = A6GeoResidentAuthorityCompositionChirho::from_cluster_node_chirho(
        &fleet_chirho.nodes_chirho[0],
    )
    .expect("the real three-voter ClusterNode selects the A6 authority path");
    let leadership_chirho = composition_chirho
        .elector_chirho()
        .current_leadership_chirho();
    assert_eq!(leadership_chirho.term_chirho, 1);
    let mut actor_chirho = open_unmirrored_shared_elector_test_fixture_chirho(
        &composition_chirho,
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &config_chirho,
    )
    .expect("the test-only lower-term actor opens before the sink consults its persisted fence");
    let intent_line_chirho =
        signed_hold_line_chirho(&fixture_chirho, &config_chirho, &actor_chirho);

    let refusal_chirho = actor_chirho
        .append_hold_chirho(&intent_line_chirho)
        .expect_err("the persisted higher term must depose this composed writer");
    // RETARGETED 2026-08-17, not weakened, and STRENGTHENED by one assertion. The property is
    // unchanged: a deposed composed writer is refused, with that exact detail, before any journal
    // mutation. What moved is only how specific the port variant is -- `WriterFenceRefusedChirho`
    // used to fall into the generic `RefusedChirho` together with ~30 unrelated authority refusals,
    // and now reports the fence/continuity group so a Clause 14 loss drill can tell them apart.
    // The identity is asserted too, so this arm pins WHICH refusal rather than merely that one came.
    let EffectCommitJournalPortErrorChirho::ResidentRefusedChirho {
        identity_chirho,
        detail_chirho,
    } = refusal_chirho
    else {
        panic!("the deposed writer must return the resident fence refusal identity");
    };
    assert_eq!(
        identity_chirho,
        EffectCommitJournalResidentRefusalIdentityChirho::FenceOrContinuityChirho
    );
    assert_eq!(
        detail_chirho,
        "resident descriptor-owned writer fence was refused: DeposedWriterGeoTermChirho"
    );
    assert!(!detail_chirho.contains("StaleWriterFenceChirho"));
    assert!(!detail_chirho.contains("ForgedEpochChirho"));
    assert_eq!(
        std::fs::read(fence_path_chirho).unwrap(),
        fence_before_chirho
    );
    assert_eq!(
        std::fs::read(journal_path_chirho).unwrap(),
        journal_before_chirho
    );
}

#[path = "a6_geo_composition_tests_chirho/recovery_adoption_drill_chirho.rs"]
mod recovery_adoption_drill_chirho;

#[path = "a6_geo_composition_tests_chirho/recovery_warmup_chirho.rs"]
mod recovery_warmup_chirho;
use recovery_warmup_chirho::drive_recovery_until_adopter_warm_without_old_leader_chirho;
