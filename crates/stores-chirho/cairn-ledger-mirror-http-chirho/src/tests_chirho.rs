// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::client_chirho::{
    private_mesh_agent_chirho, HttpMirrorHolderChirho, LedgerMirrorDirectoryChirho,
    ProductionLedgerAppendMirrorInputChirho, ProductionLedgerAppendMirrorPortChirho,
    RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO,
};
use crate::family_chirho::{LedgerMirrorJournalVerifierBindingChirho, LedgerMirrorRecordChirho};
use crate::recovery_chirho::{
    LedgerMirrorRecoveryHeadRefusalChirho, LedgerMirrorRecoveryHeadRequestChirho,
    LedgerMirrorRecoveryHeadRequestInputChirho, ProductionLedgerMirrorRecoveryInputChirho,
    ProductionLedgerMirrorRecoveryPortChirho,
};
use crate::server_chirho::{
    finalize_result_for_test_chirho, ledger_mirror_router_chirho, LedgerMirrorServerStateChirho,
};
use crate::store_chirho::{
    LedgerMirrorFollowerStoreChirho, LedgerMirrorHighWaterChirho, LedgerMirrorHighWaterInputChirho,
    LedgerMirrorLeaderPendingChirho, LedgerMirrorLeaderStoreChirho,
    LedgerMirrorPrepareOutcomeChirho,
};
use anyhow::{anyhow, Result};
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::append_mirror_chirho::{
    LedgerAppendMirrorPortChirho, LedgerAppendMirrorTailChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerClockPortChirho, LedgerSignerPortChirho,
    LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorOrdinaryTermAcceptanceChallengeChirho,
    LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho,
    LedgerMirrorOrdinaryTermAcceptanceExpectationChirho,
    LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho,
    LedgerMirrorOrdinaryTermAcceptanceReceiptChirho,
    LedgerMirrorOrdinaryTermAcceptanceReceiptInputChirho, RawCanonicalGroupIdDigestChirho,
    VerifiedOrdinaryElectionSinkTermAcceptanceChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use cairn_mirror_chirho::{
    join_mirror_view_chirho, FinalizeMirrorReceiptFrameInputChirho, MirrorClosureManifestChirho,
    MirrorClosureManifestInputChirho, MirrorContractErrorChirho, MirrorElectionObservationChirho,
    MirrorHolderPortChirho, MirrorLeadershipViewChirho, MirrorReceiptStageChirho,
    MirrorResidencyPolicyChirho, PrepareMirrorClosureFrameInputChirho,
    PrepareMirrorClosureFrameV1Chirho, PreparedFinalizeMirrorReceiptFrameChirho,
    PreparedPrepareMirrorClosureFrameChirho,
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
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;

pub(crate) const GENESIS_DIGEST_CHIRHO: &str =
    "53c617517a916c8a36d4f8a898f83a4132a1f9a8367998a9149cafa492afffdf";
const TERM_CHIRHO: u64 = 7;
const CONF_INDEX_CHIRHO: u64 = 11;
pub(crate) const JOURNAL_KEY_ID_CHIRHO: &str = "journal-chirho:mirror-fixture-journal-chirho";
const GOLDEN_RECORD_LINE_CHIRHO: &str = r#"{"schema_chirho":"ledger-record-v1-chirho","format_version_chirho":1,"seq_chirho":1,"prev_chirho":"53c617517a916c8a36d4f8a898f83a4132a1f9a8367998a9149cafa492afffdf","epoch_chirho":1,"hlc_chirho":{"physical_ms_chirho":1000,"logical_chirho":0},"legs_chirho":[{"account_chirho":{"owner_chirho":"alice-chirho","kind_id_chirho":"money-chirho"},"kind_policy_ref_chirho":"policy-v1-digest-chirho","delta_chirho":"debit","amount_chirho":25,"post_chirho":{"credits_total_chirho":100,"debits_total_chirho":25,"held_chirho":0}},{"account_chirho":{"owner_chirho":"bob-chirho","kind_id_chirho":"money-chirho"},"kind_policy_ref_chirho":"policy-v1-digest-chirho","delta_chirho":"credit","amount_chirho":25,"post_chirho":{"credits_total_chirho":25,"debits_total_chirho":0,"held_chirho":0}}],"op_chirho":"transfer","idempotency_key_chirho":"idem-0001-chirho","attribution_chirho":{"causer":{"principal_chirho":"alice-chirho"}},"sig_chirho":"sig-r1-golden-chirho","key_id_chirho":"journal-key-1-chirho"}"#;

pub(crate) fn provision_node_chirho(root_chirho: &Path) -> String {
    cairn_signer_chirho::signer_chirho::sign_message_chirho(root_chirho, b"seed-node-chirho")
        .expect("provision node key");
    cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)
        .expect("read node id")
}

fn sign_existing_chirho(root_chirho: &Path, bytes_chirho: &[u8]) -> String {
    cairn_signer_chirho::signer_chirho::sign_message_with_existing_key_chirho(
        root_chirho,
        bytes_chirho,
    )
    .expect("sign fixture bytes")
}

pub(crate) struct TestNodeChirho {
    root_chirho: tempfile::TempDir,
    pub(crate) node_id_chirho: String,
}

impl TestNodeChirho {
    fn new_chirho() -> Self {
        let root_chirho = tempfile::tempdir().expect("node root");
        let node_id_chirho = provision_node_chirho(root_chirho.path());
        Self {
            root_chirho,
            node_id_chirho,
        }
    }

    pub(crate) fn root_chirho(&self) -> &Path {
        self.root_chirho.path()
    }
}

pub(crate) struct PlacementFixtureChirho {
    pub(crate) serving_nodes_chirho: Vec<TestNodeChirho>,
    pub(crate) placement_chirho: Arc<VerifiedTenantPlacementChirho>,
}

pub(crate) fn placement_fixture_chirho() -> PlacementFixtureChirho {
    placement_revision_fixture_chirho(0, None)
}

pub(crate) fn placement_successor_fixture_chirho(
    previous_assignment_digest_chirho: &str,
) -> PlacementFixtureChirho {
    placement_revision_fixture_chirho(1, Some(previous_assignment_digest_chirho.to_string()))
}

pub(crate) fn placement_revision_fixture_chirho(
    revision_chirho: u64,
    previous_assignment_digest_chirho: Option<String>,
) -> PlacementFixtureChirho {
    let mut serving_nodes_chirho = (0..3)
        .map(|_| TestNodeChirho::new_chirho())
        .collect::<Vec<_>>();
    serving_nodes_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.node_id_chirho.cmp(&right_chirho.node_id_chirho)
    });
    let held_observer_chirho = TestNodeChirho::new_chirho();
    let placement_authority_chirho = TestNodeChirho::new_chirho();
    let roster_authority_chirho = TestNodeChirho::new_chirho();
    let plan_authority_chirho = TestNodeChirho::new_chirho();
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
    let assigned_nodes_chirho = serving_nodes_chirho
        .iter()
        .zip(domains_chirho.iter())
        .enumerate()
        .map(
            |(index_chirho, (node_chirho, domain_chirho))| TenantPlacementNodeBindingChirho {
                node_id_chirho: node_chirho.node_id_chirho.clone(),
                failure_domain_chirho: domain_chirho.clone(),
                expected_root_binding_chirho: format!(
                    "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
                    char::from(b'a' + u8::try_from(index_chirho).expect("fixture index"))
                        .to_string()
                        .repeat(64)
                ),
                expected_cluster_config_blake3_chirho: char::from(
                    b'd' + u8::try_from(index_chirho).expect("fixture index"),
                )
                .to_string()
                .repeat(64),
            },
        )
        .collect::<Vec<_>>();
    let held_binding_chirho = TenantPlacementNodeBindingChirho {
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
        revision_chirho,
        previous_assignment_digest_chirho,
        tenant_id_chirho: "mirror-http-fixture-chirho".to_string(),
        consistency_group_id_chirho: "tenant-chirho:mirror-http-fixture-chirho".to_string(),
        assigned_nodes_chirho,
        held_observer_node_chirho: held_binding_chirho,
        preferred_node_chirho: serving_nodes_chirho[0].node_id_chirho.clone(),
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
    let intent_digest_chirho =
        tenant_placement_intent_digest_chirho(&intent_chirho).expect("hash placement intent");
    let serving_readiness_receipts_chirho = intent_chirho
        .assigned_nodes_chirho
        .iter()
        .map(|binding_chirho| {
            let node_chirho = serving_nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.node_id_chirho == binding_chirho.node_id_chirho)
                .expect("assigned serving node");
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
            receipt_chirho.sig_chirho = sign_existing_chirho(
                node_chirho.root_chirho(),
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
    held_receipt_chirho.sig_chirho = sign_existing_chirho(
        held_observer_chirho.root_chirho(),
        &unsigned_tenant_placement_held_observer_readiness_message_chirho(&held_receipt_chirho)
            .expect("render observer readiness"),
    );
    let mut record_chirho = TenantPlacementRecordChirho {
        schema_chirho: TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        serving_readiness_receipts_chirho,
        held_observer_readiness_receipt_chirho: held_receipt_chirho,
        placement_key_id_chirho: placement_authority_chirho.node_id_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_existing_chirho(
        placement_authority_chirho.root_chirho(),
        &unsigned_tenant_placement_record_message_chirho(&record_chirho)
            .expect("render placement record"),
    );
    let placement_chirho = verify_tenant_placement_record_chirho(
        record_chirho,
        &placement_authority_chirho.node_id_chirho,
        &roster_authority_chirho.node_id_chirho,
        &plan_authority_chirho.node_id_chirho,
    )
    .expect("verify placement fixture");
    PlacementFixtureChirho {
        serving_nodes_chirho,
        placement_chirho: Arc::new(placement_chirho),
    }
}

#[derive(Clone)]
pub(crate) struct FixedElectionViewChirho {
    pub(crate) observation_chirho: MirrorElectionObservationChirho,
}

impl MirrorLeadershipViewChirho for FixedElectionViewChirho {
    fn observe_election_chirho(
        &self,
    ) -> Result<MirrorElectionObservationChirho, MirrorContractErrorChirho> {
        Ok(self.observation_chirho.clone())
    }
}

struct SequencedElectionViewChirho {
    first_chirho: MirrorElectionObservationChirho,
    later_chirho: MirrorElectionObservationChirho,
    calls_chirho: AtomicUsize,
}

impl MirrorLeadershipViewChirho for SequencedElectionViewChirho {
    fn observe_election_chirho(
        &self,
    ) -> Result<MirrorElectionObservationChirho, MirrorContractErrorChirho> {
        if self.calls_chirho.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(self.first_chirho.clone())
        } else {
            Ok(self.later_chirho.clone())
        }
    }
}

pub(crate) fn election_observation_chirho(
    placement_chirho: &VerifiedTenantPlacementChirho,
    leader_node_id_chirho: &str,
    local_is_leader_chirho: bool,
) -> MirrorElectionObservationChirho {
    let mut authenticated_members_chirho = placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .enumerate()
        .map(|(index_chirho, node_chirho)| {
            (
                u64::try_from(index_chirho).expect("fixture raft index") + 1,
                NodeIdChirho(node_chirho.node_id_chirho.clone()),
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
            is_leader_chirho: local_is_leader_chirho,
            leader_id_chirho: Some(NodeIdChirho(leader_node_id_chirho.to_string())),
            term_chirho: TERM_CHIRHO,
            lease_valid_chirho: true,
        },
        authenticated_members_chirho,
        voter_raft_ids_chirho: vec![1, 2, 3],
        learner_raft_ids_chirho: vec![4],
        applied_conf_index_chirho: CONF_INDEX_CHIRHO,
        leader_lease_remaining_millis_chirho: Some(10_000),
    }
}

pub(crate) struct RunningMirrorServerChirho {
    pub(crate) endpoint_chirho: String,
    stop_chirho: Option<tokio::sync::oneshot::Sender<()>>,
    thread_chirho: Option<JoinHandle<()>>,
}

impl RunningMirrorServerChirho {
    pub(crate) fn start_chirho(router_chirho: axum::Router) -> Self {
        let listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind mirror test server");
        Self::start_with_listener_chirho(listener_chirho, router_chirho)
    }

    pub(crate) fn start_with_listener_chirho(
        listener_chirho: TcpListener,
        router_chirho: axum::Router,
    ) -> Self {
        let socket_addr_chirho = listener_chirho.local_addr().expect("mirror server address");
        listener_chirho
            .set_nonblocking(true)
            .expect("set mirror listener nonblocking");
        let (stop_sender_chirho, stop_receiver_chirho) = tokio::sync::oneshot::channel();
        let (ready_sender_chirho, ready_receiver_chirho) = mpsc::sync_channel(1);
        let thread_chirho = std::thread::spawn(move || {
            let runtime_chirho = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build mirror test runtime");
            runtime_chirho.block_on(async move {
                let listener_chirho = tokio::net::TcpListener::from_std(listener_chirho)
                    .expect("adopt mirror test listener");
                ready_sender_chirho.send(()).expect("signal mirror ready");
                axum::serve(listener_chirho, router_chirho)
                    .with_graceful_shutdown(async move {
                        let _result_chirho = stop_receiver_chirho.await;
                    })
                    .await
                    .expect("serve mirror test router");
            });
        });
        ready_receiver_chirho.recv().expect("mirror server ready");
        Self {
            endpoint_chirho: format!("http://{socket_addr_chirho}"),
            stop_chirho: Some(stop_sender_chirho),
            thread_chirho: Some(thread_chirho),
        }
    }
}

impl Drop for RunningMirrorServerChirho {
    fn drop(&mut self) {
        if let Some(stop_chirho) = self.stop_chirho.take() {
            let _send_result_chirho = stop_chirho.send(());
        }
        if let Some(thread_chirho) = self.thread_chirho.take() {
            let _join_result_chirho = thread_chirho.join();
        }
    }
}

pub(crate) fn journal_verifier_chirho(
    journal_root_chirho: &Path,
) -> Arc<LedgerMirrorJournalVerifierBindingChirho> {
    Arc::new(
        LedgerMirrorJournalVerifierBindingChirho::new_chirho(
            JOURNAL_KEY_ID_CHIRHO.to_string(),
            cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(
                journal_root_chirho,
            )
            .expect("read journal verifier key"),
        )
        .expect("construct journal verifier binding"),
    )
}

pub(crate) fn signed_record_chirho(
    sign_root_chirho: &Path,
    key_id_chirho: &str,
) -> LedgerMirrorRecordChirho {
    let parsed_chirho = parse_canonical_ledger_journal_line_chirho(GOLDEN_RECORD_LINE_CHIRHO)
        .expect("parse golden ledger record");
    let LedgerJournalLineChirho::RecordChirho(mut record_chirho) = parsed_chirho else {
        panic!("fixture is a record");
    };
    record_chirho.key_id_chirho = key_id_chirho.to_string();
    record_chirho.sig_chirho.clear();
    let signed_content_chirho =
        ledger_record_signed_content_line_chirho(&record_chirho).expect("render signed content");
    record_chirho.sig_chirho =
        cairn_signer_chirho::signer_chirho::sign_message_with_existing_key_chirho(
            sign_root_chirho,
            signed_content_chirho.as_bytes(),
        )
        .expect("sign ledger record");
    let line_chirho = canonical_ledger_record_line_chirho(&record_chirho)
        .expect("render canonical signed record");
    LedgerMirrorRecordChirho {
        cluster_id_chirho: "cluster-f1-chirho".to_string(),
        journal_genesis_digest_chirho: GENESIS_DIGEST_CHIRHO.to_string(),
        predecessor_seq_chirho: 0,
        predecessor_digest_chirho: GENESIS_DIGEST_CHIRHO.to_string(),
        record_seq_chirho: record_chirho.seq_chirho,
        record_digest_chirho: stored_line_digest_chirho(&line_chirho).0,
        record_epoch_chirho: record_chirho.epoch_chirho,
        record_hlc_physical_ms_chirho: record_chirho.hlc_chirho.physical_ms_chirho,
        record_hlc_logical_chirho: record_chirho.hlc_chirho.logical_chirho,
        canonical_record_line_chirho: line_chirho,
    }
}

pub(crate) struct RecoveryJournalFixtureChirho {
    pub(crate) journal_root_chirho: tempfile::TempDir,
    pub(crate) local_tail_chirho: LedgerAppendMirrorTailChirho,
    pub(crate) advanced_local_tail_chirho: LedgerAppendMirrorTailChirho,
    pub(crate) source_record_chirho: LedgerMirrorRecordChirho,
}

pub(crate) fn recovery_journal_fixture_chirho() -> RecoveryJournalFixtureChirho {
    let journal_root_chirho = tempfile::tempdir().expect("recovery journal signer root");
    let verifying_key_hex_chirho = provision_node_chirho(journal_root_chirho.path());
    let storage_chirho = TestLedgerStorageChirho::default();
    let signer_chirho = ExistingJournalSignerChirho {
        root_chirho: journal_root_chirho.path().to_path_buf(),
        verifying_key_hex_chirho,
    };
    let clock_chirho = FixedLedgerClockChirho;
    let membership_chirho = OpenTestMembershipChirho;
    let registry_chirho = TestMoneyRegistryChirho;
    let authority_chirho = TestMintAuthorityChirho;
    let ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let cluster_id_chirho = ClusterIdChirho("cluster-f1-recovery-selection-chirho".to_string());
    let local_path_chirho = StoragePathChirho::new_chirho("journals/recovery-local-chirho.jsonl");
    let local_journal_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        local_path_chirho,
        cluster_id_chirho.clone(),
        1,
    )
    .expect("create local recovery base journal");
    let local_tail_chirho = local_journal_chirho.verified_append_mirror_tail_chirho();

    let source_path_chirho = StoragePathChirho::new_chirho("journals/recovery-source-chirho.jsonl");
    let mut source_journal_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        source_path_chirho.clone(),
        cluster_id_chirho,
        1,
    )
    .expect("create matching recovery source journal");
    source_journal_chirho
        .append_chirho(AppendRequestChirho {
            op_chirho: LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho(TEST_MINT_EVIDENCE_CHIRHO.to_string()),
            },
            legs_chirho: vec![AppendLegRequestChirho {
                account_chirho: LogIdChirho::new_chirho("alice-chirho", TEST_MONEY_KIND_CHIRHO),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    TEST_MONEY_POLICY_CHIRHO.to_string(),
                )),
                delta_chirho: LegDeltaChirho::CreditChirho,
                amount_chirho: 7,
                counterpart_chirho: None,
            }],
            idempotency_key_chirho: "recovery-source-append-0001-chirho".to_string(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
        })
        .expect("append one verified recovery source record");
    let source_tail_chirho = source_journal_chirho.verified_append_mirror_tail_chirho();
    assert_eq!(
        source_tail_chirho.journal_genesis_digest_chirho(),
        local_tail_chirho.journal_genesis_digest_chirho()
    );
    let source_bytes_chirho = storage_chirho
        .read_all_chirho(&source_path_chirho)
        .expect("read source journal")
        .expect("source journal exists");
    let source_text_chirho =
        std::str::from_utf8(&source_bytes_chirho).expect("source journal UTF-8");
    let record_line_chirho = source_text_chirho
        .lines()
        .last()
        .expect("source journal has a record line");
    let LedgerJournalLineChirho::RecordChirho(record_chirho) =
        parse_canonical_ledger_journal_line_chirho(record_line_chirho)
            .expect("parse source record")
    else {
        panic!("last source line is a record");
    };
    let source_record_chirho = LedgerMirrorRecordChirho::from_verified_record_chirho(
        &source_tail_chirho.cluster_id_chirho().0,
        &source_tail_chirho.journal_genesis_digest_chirho().0,
        &record_chirho,
    )
    .expect("convert verified source record");
    source_journal_chirho
        .append_chirho(AppendRequestChirho {
            op_chirho: LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho(TEST_MINT_EVIDENCE_CHIRHO.to_string()),
            },
            legs_chirho: vec![AppendLegRequestChirho {
                account_chirho: LogIdChirho::new_chirho("alice-chirho", TEST_MONEY_KIND_CHIRHO),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    TEST_MONEY_POLICY_CHIRHO.to_string(),
                )),
                delta_chirho: LegDeltaChirho::CreditChirho,
                amount_chirho: 3,
                counterpart_chirho: None,
            }],
            idempotency_key_chirho: "recovery-local-advance-0002-chirho".to_string(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
        })
        .expect("append a second local record for behind-head selection tests");
    let advanced_local_tail_chirho = source_journal_chirho.verified_append_mirror_tail_chirho();

    RecoveryJournalFixtureChirho {
        journal_root_chirho,
        local_tail_chirho,
        advanced_local_tail_chirho,
        source_record_chirho,
    }
}

pub(crate) fn prepare_frame_chirho(
    leader_root_chirho: &Path,
    leader_node_id_chirho: &str,
    target_node_id_chirho: &str,
    term_chirho: u64,
    group_digest_chirho: &str,
    view_digest_chirho: &str,
    record_chirho: LedgerMirrorRecordChirho,
) -> PrepareMirrorClosureFrameV1Chirho {
    prepare_frame_with_lease_chirho(PrepareFrameFixtureInputChirho {
        leader_root_chirho,
        leader_node_id_chirho,
        target_node_id_chirho,
        term_chirho,
        group_digest_chirho,
        view_digest_chirho,
        record_chirho,
        leader_lease_remaining_millis_chirho: Some(10_000),
    })
}

struct PrepareFrameFixtureInputChirho<'fixture_chirho> {
    leader_root_chirho: &'fixture_chirho Path,
    leader_node_id_chirho: &'fixture_chirho str,
    target_node_id_chirho: &'fixture_chirho str,
    term_chirho: u64,
    group_digest_chirho: &'fixture_chirho str,
    view_digest_chirho: &'fixture_chirho str,
    record_chirho: LedgerMirrorRecordChirho,
    leader_lease_remaining_millis_chirho: Option<u64>,
}

fn prepare_frame_with_lease_chirho(
    input_chirho: PrepareFrameFixtureInputChirho<'_>,
) -> PrepareMirrorClosureFrameV1Chirho {
    let caller_digest_chirho = "2".repeat(64);
    let manifest_chirho =
        MirrorClosureManifestChirho::new_chirho(MirrorClosureManifestInputChirho {
            consistency_group_digest_chirho: input_chirho.group_digest_chirho.to_string(),
            caller_idempotency_key_digest_chirho: caller_digest_chirho.clone(),
            members_chirho: vec![input_chirho.record_chirho.into_member_chirho()],
        })
        .expect("build F1 manifest");
    let prepared_chirho =
        PreparedPrepareMirrorClosureFrameChirho::new_chirho(PrepareMirrorClosureFrameInputChirho {
            origin_node_id_chirho: input_chirho.leader_node_id_chirho.to_string(),
            target_node_id_chirho: input_chirho.target_node_id_chirho.to_string(),
            consistency_group_digest_chirho: input_chirho.group_digest_chirho.to_string(),
            expected_term_chirho: input_chirho.term_chirho,
            membership_view_digest_chirho: input_chirho.view_digest_chirho.to_string(),
            leader_lease_remaining_millis_chirho: input_chirho.leader_lease_remaining_millis_chirho,
            caller_idempotency_key_digest_chirho: caller_digest_chirho,
            manifest_chirho,
            inline_sealed_payloads_chirho: Vec::new(),
        })
        .expect("build generic mirror prepare");
    let signature_chirho =
        cairn_signer_chirho::signer_chirho::sign_message_with_existing_key_chirho(
            input_chirho.leader_root_chirho,
            &prepared_chirho.signing_digest_chirho(),
        )
        .expect("sign generic mirror prepare");
    prepared_chirho
        .into_signed_chirho(signature_chirho)
        .expect("attach prepare signature")
}

fn finalize_frame_chirho(
    leader_root_chirho: &Path,
    prepare_chirho: &PrepareMirrorClosureFrameV1Chirho,
    local_commit_binding_chirho: String,
) -> cairn_mirror_chirho::FinalizeMirrorReceiptFrameV1Chirho {
    let prepared_chirho = PreparedFinalizeMirrorReceiptFrameChirho::new_chirho(
        FinalizeMirrorReceiptFrameInputChirho {
            origin_node_id_chirho: prepare_chirho.origin_node_id_chirho().to_string(),
            target_node_id_chirho: prepare_chirho.target_node_id_chirho().to_string(),
            consistency_group_digest_chirho: prepare_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            expected_term_chirho: prepare_chirho.expected_term_chirho(),
            membership_view_digest_chirho: prepare_chirho
                .membership_view_digest_chirho()
                .to_string(),
            leader_lease_remaining_millis_chirho: prepare_chirho
                .leader_lease_remaining_millis_chirho(),
            caller_idempotency_key_digest_chirho: prepare_chirho
                .caller_idempotency_key_digest_chirho()
                .to_string(),
            mirror_closure_id_chirho: prepare_chirho.mirror_closure_id_chirho().to_string(),
            prepare_frame_digest_chirho: prepare_chirho.prepare_frame_digest_chirho().to_string(),
            local_commit_binding_chirho,
        },
    )
    .expect("build mirror finalize");
    let signature_chirho =
        sign_existing_chirho(leader_root_chirho, &prepared_chirho.signing_digest_chirho());
    prepared_chirho
        .into_signed_chirho(signature_chirho)
        .expect("attach finalize signature")
}

#[test]
fn mirror_paths_are_private_generic_mirror_commands_chirho() {
    assert!(LEDGER_MIRROR_PREPARE_PATH_CHIRHO.starts_with("/ledger-mirror-chirho/"));
    assert!(LEDGER_MIRROR_FINALIZE_PATH_CHIRHO.starts_with("/ledger-mirror-chirho/"));
    assert_ne!(
        LEDGER_MIRROR_PREPARE_PATH_CHIRHO,
        LEDGER_MIRROR_FINALIZE_PATH_CHIRHO
    );
}

#[test]
fn f1_record_verification_separates_journal_authority_from_node_control_chirho() {
    let journal_root_chirho = tempfile::tempdir().expect("journal signer root");
    let leader_root_chirho = tempfile::tempdir().expect("leader root");
    let leader_node_id_chirho = provision_node_chirho(leader_root_chirho.path());
    provision_node_chirho(journal_root_chirho.path());
    let verifier_chirho = journal_verifier_chirho(journal_root_chirho.path());
    let record_chirho = signed_record_chirho(journal_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);

    record_chirho
        .verify_with_journal_chirho(&verifier_chirho)
        .expect("journal-signed record verifies independently of node control");
    let node_labeled_record_chirho =
        signed_record_chirho(leader_root_chirho.path(), &leader_node_id_chirho);
    assert!(node_labeled_record_chirho
        .verify_with_journal_chirho(&verifier_chirho)
        .expect_err("a node-control key label cannot substitute for journal authority")
        .to_string()
        .contains("LedgerMirrorJournalSignerBindingRefusedChirho"));
    let relabeled_node_record_chirho =
        signed_record_chirho(leader_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);
    assert!(relabeled_node_record_chirho
        .verify_with_journal_chirho(&verifier_chirho)
        .expect_err("a node-control signature cannot hide behind the journal label")
        .to_string()
        .contains("LedgerMirrorRecordSignatureRefusedChirho"));
}

#[test]
fn current_leader_replaces_abandoned_slot_and_store_replay_binds_exact_high_water_chirho() {
    let root_chirho = tempfile::tempdir().expect("follower mirror root");
    let holder_root_chirho = tempfile::tempdir().expect("holder signer root");
    let prior_root_chirho = tempfile::tempdir().expect("prior leader root");
    let current_root_chirho = tempfile::tempdir().expect("current leader root");
    let journal_root_chirho = tempfile::tempdir().expect("journal signer root");
    let holder_chirho = provision_node_chirho(holder_root_chirho.path());
    let prior_chirho = provision_node_chirho(prior_root_chirho.path());
    let current_chirho = provision_node_chirho(current_root_chirho.path());
    provision_node_chirho(journal_root_chirho.path());
    let journal_verifier_chirho = journal_verifier_chirho(journal_root_chirho.path());
    let store_chirho = LedgerMirrorFollowerStoreChirho::open_chirho(
        root_chirho.path(),
        holder_chirho.clone(),
        journal_verifier_chirho,
    )
    .expect("open follower mirror store");
    let prior_record_chirho =
        signed_record_chirho(journal_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);
    let current_record_chirho = prior_record_chirho.clone();
    let prior_prepare_chirho = prepare_frame_chirho(
        prior_root_chirho.path(),
        &prior_chirho,
        &holder_chirho,
        7,
        &"1".repeat(64),
        &"3".repeat(64),
        prior_record_chirho.clone(),
    );
    let current_prepare_chirho = prepare_frame_chirho(
        current_root_chirho.path(),
        &current_chirho,
        &holder_chirho,
        8,
        &"1".repeat(64),
        &"3".repeat(64),
        current_record_chirho.clone(),
    );

    assert!(matches!(
        store_chirho
            .prepare_chirho(prior_prepare_chirho.clone(), prior_record_chirho.clone())
            .expect("prepare under prior elected leader"),
        LedgerMirrorPrepareOutcomeChirho::PreparedChirho
    ));
    assert!(matches!(
        store_chirho
            .prepare_chirho(
                current_prepare_chirho.clone(),
                current_record_chirho.clone()
            )
            .expect("current elected leader replaces abandoned prepared slot"),
        LedgerMirrorPrepareOutcomeChirho::PreparedChirho
    ));

    let high_water_chirho = LedgerMirrorHighWaterChirho::sign_chirho(
        LedgerMirrorHighWaterInputChirho {
            consistency_group_digest_chirho: current_prepare_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            origin_leader_node_id_chirho: current_chirho.clone(),
            holder_node_id_chirho: holder_chirho.clone(),
            assignment_digest_chirho: "2".repeat(64),
            assigned_node_ids_chirho: [
                current_chirho.clone(),
                holder_chirho.clone(),
                "9".repeat(64),
            ],
            membership_view_digest_chirho: current_prepare_chirho
                .membership_view_digest_chirho()
                .to_string(),
            historical_term_chirho: current_prepare_chirho.expected_term_chirho(),
            mirror_closure_id_chirho: current_prepare_chirho
                .mirror_closure_id_chirho()
                .to_string(),
            prepare_frame_digest_chirho: current_prepare_chirho
                .prepare_frame_digest_chirho()
                .to_string(),
            caller_idempotency_key_digest_chirho: current_prepare_chirho
                .caller_idempotency_key_digest_chirho()
                .to_string(),
            record_chirho: current_record_chirho.clone(),
        },
        holder_root_chirho.path(),
    )
    .expect("sign holder high water");
    assert!(store_chirho
        .finalize_chirho(
            prior_prepare_chirho.prepare_frame_digest_chirho(),
            &prior_record_chirho,
            &high_water_chirho,
        )
        .expect_err("the displaced leader cannot finalize the replacement slot")
        .to_string()
        .contains("LedgerMirrorFinalizePreparedBindingRefusedChirho"));
    let finalized_chirho = store_chirho
        .finalize_chirho(
            current_prepare_chirho.prepare_frame_digest_chirho(),
            &current_record_chirho,
            &high_water_chirho,
        )
        .expect("the current leader finalizes its replacement slot");
    assert_eq!(finalized_chirho.record_chirho().record_seq_chirho, 1);
    assert_eq!(
        store_chirho
            .load_high_water_chirho()
            .expect("read and reverify durable follower high water"),
        Some(finalized_chirho.clone())
    );
    assert_eq!(
        store_chirho
            .finalize_chirho(
                current_prepare_chirho.prepare_frame_digest_chirho(),
                &current_record_chirho,
                &high_water_chirho,
            )
            .expect("an exact store-level FINALIZE replay is idempotent"),
        finalized_chirho
    );
    let different_high_water_chirho = LedgerMirrorHighWaterChirho::sign_chirho(
        LedgerMirrorHighWaterInputChirho {
            consistency_group_digest_chirho: current_prepare_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            origin_leader_node_id_chirho: current_prepare_chirho
                .origin_node_id_chirho()
                .to_string(),
            holder_node_id_chirho: holder_chirho.clone(),
            assignment_digest_chirho: "2".repeat(64),
            assigned_node_ids_chirho: [current_chirho, holder_chirho, "9".repeat(64)],
            membership_view_digest_chirho: current_prepare_chirho
                .membership_view_digest_chirho()
                .to_string(),
            historical_term_chirho: current_prepare_chirho.expected_term_chirho(),
            mirror_closure_id_chirho: current_prepare_chirho
                .mirror_closure_id_chirho()
                .to_string(),
            prepare_frame_digest_chirho: "f".repeat(64),
            caller_idempotency_key_digest_chirho: current_prepare_chirho
                .caller_idempotency_key_digest_chirho()
                .to_string(),
            record_chirho: current_record_chirho.clone(),
        },
        holder_root_chirho.path(),
    )
    .expect("sign a same-record high-water with a different PREPARE identity");
    assert!(store_chirho
        .finalize_chirho(
            current_prepare_chirho.prepare_frame_digest_chirho(),
            &current_record_chirho,
            &different_high_water_chirho,
        )
        .expect_err("store replay must bind the exact signed high-water")
        .to_string()
        .contains("LedgerMirrorFinalizedStoreReplayBindingRefusedChirho"));
}

#[test]
fn migration_source_fence_probe_reads_real_leader_pending_store_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let journal_root_chirho = tempfile::tempdir().expect("journal signer root");
    provision_node_chirho(journal_root_chirho.path());
    let journal_verifier_chirho = journal_verifier_chirho(journal_root_chirho.path());
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let election_view_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &fixture_chirho.placement_chirho,
        election_view_chirho.as_ref(),
    )
    .expect("join current leader view");
    let view_digest_chirho = joined_chirho.view_chirho().view_digest_chirho();
    let residency_chirho = MirrorResidencyPolicyChirho::allowed_domains_chirho(
        fixture_chirho
            .placement_chirho
            .intent_chirho()
            .residency_chirho
            .allowed_domains_chirho
            .clone(),
    );
    let leader_store_root_chirho = tempfile::tempdir().expect("leader store root");
    let leader_store_chirho =
        LedgerMirrorLeaderStoreChirho::open_chirho(leader_store_root_chirho.path())
            .expect("open production leader store");
    let record_chirho = signed_record_chirho(journal_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);
    let pending_chirho = LedgerMirrorLeaderPendingChirho {
        prepare_frames_chirho: [
            prepare_frame_chirho(
                leader_chirho.root_chirho(),
                &leader_chirho.node_id_chirho,
                &fixture_chirho.serving_nodes_chirho[1].node_id_chirho,
                joined_chirho.term_chirho(),
                joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho(),
                &view_digest_chirho,
                record_chirho.clone(),
            ),
            prepare_frame_chirho(
                leader_chirho.root_chirho(),
                &leader_chirho.node_id_chirho,
                &fixture_chirho.serving_nodes_chirho[2].node_id_chirho,
                joined_chirho.term_chirho(),
                joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho(),
                &view_digest_chirho,
                record_chirho,
            ),
        ],
    };
    let production_mirror_chirho = ProductionLedgerAppendMirrorPortChirho::new_chirho(
        ProductionLedgerAppendMirrorInputChirho {
            local_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            sign_root_chirho: leader_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&fixture_chirho.placement_chirho),
            election_view_chirho,
            residency_chirho,
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::new()),
            leader_store_chirho,
            journal_verifier_chirho,
        },
    );
    production_mirror_chirho
        .require_no_unreconciled_pending_append_chirho()
        .expect("an empty production leader store is migration-drained");
    LedgerMirrorLeaderStoreChirho::open_chirho(leader_store_root_chirho.path())
        .expect("reopen production leader store")
        .write_pending_chirho(&pending_chirho)
        .expect("persist the real leader pending record");
    assert_eq!(
        production_mirror_chirho
            .require_no_unreconciled_pending_append_chirho()
            .expect_err("a real pending record must refuse the migration source fence")
            .detail_chirho(),
        "LedgerMirrorPendingSourceFenceRefusedChirho"
    );
}

#[test]
fn real_http_prepare_and_finalize_persist_a_verified_follower_high_water_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let journal_root_chirho = tempfile::tempdir().expect("journal signer root");
    provision_node_chirho(journal_root_chirho.path());
    let journal_verifier_chirho = journal_verifier_chirho(journal_root_chirho.path());
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let election_view_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                false,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &fixture_chirho.placement_chirho,
        election_view_chirho.as_ref(),
    )
    .expect("join follower mirror view");
    let follower_store_root_chirho = tempfile::tempdir().expect("follower store root");
    let follower_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            follower_store_root_chirho.path(),
            follower_chirho.node_id_chirho.clone(),
            Arc::clone(&journal_verifier_chirho),
        )
        .expect("open follower store"),
    );
    let residency_chirho = MirrorResidencyPolicyChirho::allowed_domains_chirho(
        fixture_chirho
            .placement_chirho
            .intent_chirho()
            .residency_chirho
            .allowed_domains_chirho
            .clone(),
    );
    let server_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        follower_chirho.node_id_chirho.clone(),
        follower_chirho.root_chirho().to_path_buf(),
        Arc::clone(&fixture_chirho.placement_chirho),
        election_view_chirho,
        residency_chirho,
        Arc::clone(&follower_store_chirho),
    )
    .expect("compose follower server state");
    let server_chirho =
        RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(server_state_chirho));
    let holder_chirho = HttpMirrorHolderChirho::new_chirho(
        follower_chirho.node_id_chirho.clone(),
        server_chirho.endpoint_chirho.clone(),
    );
    let record_chirho = signed_record_chirho(journal_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);
    let prepare_chirho = prepare_frame_chirho(
        leader_chirho.root_chirho(),
        &leader_chirho.node_id_chirho,
        &follower_chirho.node_id_chirho,
        TERM_CHIRHO,
        joined_chirho
            .view_chirho()
            .consistency_group_digest_chirho(),
        &joined_chirho.view_chirho().view_digest_chirho(),
        record_chirho.clone(),
    );

    let prepared_receipt_chirho = holder_chirho
        .prepare_durably_chirho(&prepare_chirho)
        .expect("real HTTP PREPARE returns a verified holder receipt");
    assert_eq!(
        prepared_receipt_chirho.stage_chirho(),
        MirrorReceiptStageChirho::PreparedChirho
    );
    assert!(follower_store_chirho
        .load_prepared_chirho()
        .expect("read durable prepared slot")
        .is_some());

    let finalize_chirho = finalize_frame_chirho(
        leader_chirho.root_chirho(),
        &prepare_chirho,
        record_chirho.record_digest_chirho.clone(),
    );
    let finalized_receipt_chirho = holder_chirho
        .finalize_chirho(&finalize_chirho)
        .expect("real HTTP FINALIZE returns a verified holder receipt");
    assert_eq!(
        finalized_receipt_chirho.stage_chirho(),
        MirrorReceiptStageChirho::FinalizedChirho
    );
    let high_water_chirho = follower_store_chirho
        .load_high_water_chirho()
        .expect("reverify follower high water")
        .expect("finalize writes follower high water");
    assert_eq!(
        high_water_chirho.record_chirho().record_digest_chirho,
        record_chirho.record_digest_chirho
    );
    assert!(follower_store_chirho
        .load_prepared_chirho()
        .expect("read cleared prepared slot")
        .is_none());

    holder_chirho
        .prepare_durably_chirho(&prepare_chirho)
        .expect("an exact PREPARE replay remains idempotent after finalization");
    holder_chirho
        .finalize_chirho(&finalize_chirho)
        .expect("an exact FINALIZE replay remains idempotent after finalization");

    let different_prepare_chirho =
        prepare_frame_with_lease_chirho(PrepareFrameFixtureInputChirho {
            leader_root_chirho: leader_chirho.root_chirho(),
            leader_node_id_chirho: &leader_chirho.node_id_chirho,
            target_node_id_chirho: &follower_chirho.node_id_chirho,
            term_chirho: TERM_CHIRHO,
            group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            view_digest_chirho: &joined_chirho.view_chirho().view_digest_chirho(),
            record_chirho: record_chirho.clone(),
            leader_lease_remaining_millis_chirho: Some(9_999),
        });
    assert_eq!(
        different_prepare_chirho.mirror_closure_id_chirho(),
        prepare_chirho.mirror_closure_id_chirho(),
        "the control changes only the PREPARE identity, not the mirrored closure"
    );
    assert_ne!(
        different_prepare_chirho.prepare_frame_digest_chirho(),
        prepare_chirho.prepare_frame_digest_chirho(),
        "the changed leader-lease duration must produce a distinct signed PREPARE identity"
    );
    let different_finalize_chirho = finalize_frame_chirho(
        leader_chirho.root_chirho(),
        &different_prepare_chirho,
        record_chirho.record_digest_chirho.clone(),
    );
    let different_finalize_result_chirho =
        holder_chirho.finalize_chirho(&different_finalize_chirho);
    let different_prepare_result_chirho =
        holder_chirho.prepare_durably_chirho(&different_prepare_chirho);
    assert_eq!(
        (
            different_finalize_result_chirho.is_err(),
            different_prepare_result_chirho.is_err(),
        ),
        (true, true),
        "a finalized holder must refuse both FINALIZE and PREPARE frames naming a different signed PREPARE identity"
    );
}

const TEST_MONEY_KIND_CHIRHO: &str = "money-chirho";
const TEST_MONEY_POLICY_CHIRHO: &str = "policy-money-v1-chirho";
const TEST_MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";

#[derive(Default)]
struct TestLedgerStorageChirho {
    objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl LedgerStoragePortChirho for TestLedgerStorageChirho {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<CreateDurableOutcomeChirho> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        match objects_chirho.entry(path_chirho.0.clone()) {
            std::collections::btree_map::Entry::Vacant(entry_chirho) => {
                entry_chirho.insert(bytes_chirho.to_vec());
                Ok(CreateDurableOutcomeChirho::CreatedChirho)
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Ok(CreateDurableOutcomeChirho::AlreadyExistsChirho)
            }
        }
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        self.objects_chirho
            .borrow_mut()
            .entry(path_chirho.0.clone())
            .or_default()
            .extend_from_slice(bytes_chirho);
        Ok(())
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<Vec<u8>>> {
        Ok(self.objects_chirho.borrow().get(&path_chirho.0).cloned())
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>> {
        Ok(self
            .objects_chirho
            .borrow()
            .get(&path_chirho.0)
            .map(|bytes_chirho| bytes_chirho.len() as u64))
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        let objects_chirho = self.objects_chirho.borrow();
        let bytes_chirho = objects_chirho
            .get(&path_chirho.0)
            .ok_or_else(|| anyhow!("missing test ledger object"))?;
        let end_chirho = offset_chirho
            .checked_add(len_chirho)
            .ok_or_else(|| anyhow!("test ledger range overflow"))?;
        if end_chirho > bytes_chirho.len() as u64 {
            return Err(anyhow!("test ledger range exceeds object"));
        }
        Ok(bytes_chirho[offset_chirho as usize..end_chirho as usize].to_vec())
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        self.objects_chirho
            .borrow_mut()
            .insert(path_chirho.0.clone(), bytes_chirho.to_vec());
        Ok(())
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        new_len_chirho: u64,
    ) -> Result<()> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .get_mut(&path_chirho.0)
            .ok_or_else(|| anyhow!("missing test ledger truncate object"))?;
        if new_len_chirho > bytes_chirho.len() as u64 {
            return Err(anyhow!("test ledger truncate can only shorten"));
        }
        bytes_chirho.truncate(new_len_chirho as usize);
        Ok(())
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> Result<()> {
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .remove(&from_chirho.0)
            .ok_or_else(|| anyhow!("missing test ledger rename source"))?;
        objects_chirho.insert(to_chirho.0.clone(), bytes_chirho);
        Ok(())
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()> {
        self.objects_chirho.borrow_mut().remove(&path_chirho.0);
        Ok(())
    }

    fn list_chirho(&self, prefix_chirho: &StoragePathChirho) -> Result<Vec<StoragePathChirho>> {
        Ok(self
            .objects_chirho
            .borrow()
            .keys()
            .filter(|key_chirho| key_chirho.starts_with(&prefix_chirho.0))
            .map(|key_chirho| StoragePathChirho(key_chirho.clone()))
            .collect())
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool> {
        Ok(self.objects_chirho.borrow().contains_key(&path_chirho.0))
    }
}

struct ExistingJournalSignerChirho {
    root_chirho: PathBuf,
    verifying_key_hex_chirho: String,
}

impl LedgerSignerPortChirho for ExistingJournalSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        cairn_signer_chirho::signer_chirho::sign_message_with_existing_key_chirho(
            &self.root_chirho,
            signed_content_line_chirho.as_bytes(),
        )
    }

    fn key_id_chirho(&self) -> String {
        JOURNAL_KEY_ID_CHIRHO.to_string()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho(
            &self.verifying_key_hex_chirho,
            signed_content_line_chirho.as_bytes(),
            sig_chirho,
        )
        .unwrap_or(false)
    }
}

struct FixedLedgerClockChirho;

impl LedgerClockPortChirho for FixedLedgerClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        1_000
    }
}

struct OpenTestMembershipChirho;

impl MembershipViewChirho for OpenTestMembershipChirho {
    fn status_chirho(
        &self,
        account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        if matches!(
            account_chirho.owner_chirho.as_str(),
            "issuer-chirho" | "alice-chirho"
        ) {
            MembershipStatusChirho::MemberChirho
        } else {
            MembershipStatusChirho::NonMemberChirho
        }
    }
}

struct TestMoneyRegistryChirho;

impl KindRegistryViewChirho for TestMoneyRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        if policy_ref_chirho.0 .0 != TEST_MONEY_POLICY_CHIRHO {
            return KindResolutionChirho::UnknownChirho;
        }
        KindResolutionChirho::CurrentChirho(KindPolicyViewChirho {
            kind_id_chirho: TEST_MONEY_KIND_CHIRHO.into(),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(1_000),
            },
            rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
            settlement_owner_chirho: None,
            idempotency_window_chirho: None,
        })
    }
}

struct TestMintAuthorityChirho;

impl AuthorityVerifierViewChirho for TestMintAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        if evidence_chirho.0 == TEST_MINT_EVIDENCE_CHIRHO
            && kind_id_chirho.0 == TEST_MONEY_KIND_CHIRHO
        {
            AuthorityVerdictChirho::VerifiedChirho
        } else {
            AuthorityVerdictChirho::UnverifiedChirho
        }
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

mod ordinary_term_acceptance_tests_chirho;
mod prepare_finalize_response_tests_chirho;
mod recovery_head_response_tests_chirho;
