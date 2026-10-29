// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Real held-sender transport arms for same-winner term rollover.

use super::*;
use crate::winner_view_transfer_chirho::test_stub_chirho::{
    Gd7WinnerViewTransferTestDispatchChirho, Gd7WinnerViewTransferTestEndpointChirho,
};
use crate::winner_view_transfer_chirho::Gd7WinnerViewTransferOperationChirho;
use cairn_config_chirho::config_chirho::{
    load_config_chirho, LedgerHostActivationPinConfigChirho, LedgerHostConfigChirho,
};
use cairn_kind_registry_chirho::chain_chirho::{KindProjectionChirho, VerifiedRegistryChirho};
use cairn_kind_registry_chirho::record_chirho::{KindPolicyBodyChirho, MintAuthorityRecordChirho};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, gd7_reconciliation_group_head_path_chirho,
    gd7_reconciliation_identity_digest_chirho, gd7_winner_handoff_attempt_digest_chirho,
    generate_gd7_winner_current_view_challenge_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho, ExistingNodeGd7SignerChirho,
    Gd7ForkCoordinateChirho, Gd7HeldViewTransferIdentityChirho, Gd7HeldViewTransferStoreChirho,
    Gd7JournalTailCoordinateChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationHeadChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    Gd7WinnerCurrentViewEvidenceChirho, Gd7WinnerCurrentViewInspectionChirho,
    Gd7WinnerHandoffAttemptIdentityChirho, Gd7WinnerHandoffPhaseChirho,
    Gd7WinnerViewBundleRootChirho, PinnedNodeGd7VerifierChirho,
    GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO, GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO,
    GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO,
    GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::{
    activate_reviewed_h3_chirho, canonical_resident_ledger_activation_statement_chirho,
    host_ledger_signer_refs_from_config_chirho, open_resident_gd7_held_coordinator_chirho,
    resident_ledger_activation_statement_chirho, ElectedClusterMembershipChirho,
    FsLedgerStorageChirho, HostLedgerSignersChirho, PinnedLedgerActivationVerifierChirho,
    PlatformPolicyMintAuthorityChirho, ResidentGd7HeldCoordinatorHandleChirho,
    ResidentGd7WinnerHandoffStatusChirho, ResidentLedgerActivationAuthorizationChirho,
    ResidentLedgerActivationInputChirho, ResidentLedgerActivationStatementInputChirho,
    ResidentLedgerClockChirho, ResidentLedgerLocalPortsChirho, ResidentLedgerMintIntentChirho,
    StaticClusterMembershipChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_read_model_chirho::account_net_projection_fold_ref_chirho;
use cairn_secret_chirho::secret_chirho::set_secret_chirho;
use cairn_signer_chirho::signer_chirho::{existing_keypair_pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::shadow_canary_chirho::{
    observe_shadow_canary_chirho, ShadowCanaryAppendCutChirho, ShadowCanaryEvidenceStoreChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho,
    consistency_group_for_root_chirho, split_writer_epoch_chirho, ConsistencyGroupIdChirho,
};
use ed25519_dalek::{Signer as DalekSignerChirho, SigningKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const JOURNAL_SECRET_CHIRHO: &str = "gd7-real-transport-journal-chirho";
const CONFIG_SECRET_CHIRHO: &str = "gd7-real-transport-config-chirho";
const FEEDER_SECRET_CHIRHO: &str = "gd7-real-transport-feeder-chirho";
const KIND_ROOT_SECRET_CHIRHO: &str = "gd7-real-transport-kind-root-chirho";
const EFFECT_INTENT_SECRET_CHIRHO: &str = "gd7-real-transport-effect-intent-chirho";
const EFFECT_TERMINAL_SECRET_CHIRHO: &str = "gd7-real-transport-effect-terminal-chirho";

struct TestRootChirho(PathBuf, PathBuf);

impl Drop for TestRootChirho {
    fn drop(&mut self) {
        let _remove_result_chirho = fs::remove_dir_all(&self.1);
    }
}

struct RealHandoffFixtureChirho {
    held_root_chirho: TestRootChirho,
    winner_root_chirho: TestRootChirho,
    group_chirho: ConsistencyGroupIdChirho,
    group_digest_chirho: String,
    winner_node_chirho: NodeIdChirho,
    held_node_chirho: NodeIdChirho,
    nodes_chirho: Vec<Arc<RaftWriterElectorChirho>>,
    historical_term_chirho: u64,
    current_term_chirho: u64,
    checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
    completed_view_chirho: ActiveGd7HeldViewTransferChirho,
    held_signer_chirho: ExistingNodeGd7SignerChirho,
    winner_verifier_chirho: PinnedNodeGd7VerifierChirho,
    coordinator_chirho: ResidentGd7HeldCoordinatorHandleChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RealHandoffTransportCaseChirho {
    returned_phase_chirho: Option<Gd7WinnerHandoffPhaseChirho>,
    roll_winner_term_chirho: bool,
}

#[test]
fn preparing_status_at_newer_term_sends_no_begin_handoff_chirho() {
    assert_handoff_transport_case_chirho(RealHandoffTransportCaseChirho {
        returned_phase_chirho: Some(Gd7WinnerHandoffPhaseChirho::PreparingChirho),
        roll_winner_term_chirho: true,
    });
}

#[test]
fn actor_state_changed_at_newer_term_sends_no_begin_handoff_chirho() {
    assert_handoff_transport_case_chirho(RealHandoffTransportCaseChirho {
        returned_phase_chirho: None,
        roll_winner_term_chirho: true,
    });
}

#[test]
fn accepted_status_at_newer_term_reuses_without_begin_handoff_chirho() {
    assert_handoff_transport_case_chirho(RealHandoffTransportCaseChirho {
        returned_phase_chirho: Some(Gd7WinnerHandoffPhaseChirho::AcceptedChirho),
        roll_winner_term_chirho: true,
    });
}

#[test]
fn historical_term_no_barrier_records_one_begin_handoff_chirho() {
    assert_handoff_transport_case_chirho(RealHandoffTransportCaseChirho {
        returned_phase_chirho: None,
        roll_winner_term_chirho: false,
    });
}

fn assert_handoff_transport_case_chirho(case_chirho: RealHandoffTransportCaseChirho) {
    let roll_winner_term_chirho = case_chirho.roll_winner_term_chirho;
    let expected_begin_count_chirho = usize::from(!roll_winner_term_chirho);
    let mut fixture_chirho = real_handoff_fixture_chirho(roll_winner_term_chirho);
    let baseline_chirho = fixture_chirho
        .coordinator_chirho
        .inspect_chirho()
        .expect("real held coordinator inspects the historical sealed coordinate");
    assert_eq!(
        baseline_chirho.winner_term_chirho,
        fixture_chirho.historical_term_chirho
    );
    assert_eq!(
        fixture_chirho.nodes_chirho[2]
            .current_leadership_chirho()
            .leader_id_chirho
            .as_ref(),
        Some(&fixture_chirho.winner_node_chirho),
        "the held observation sees A at the term selected for this transport case"
    );
    assert_eq!(
        fixture_chirho.nodes_chirho[2]
            .current_leadership_chirho()
            .term_chirho,
        fixture_chirho.current_term_chirho
    );
    if roll_winner_term_chirho {
        assert!(fixture_chirho.current_term_chirho > fixture_chirho.historical_term_chirho);
    } else {
        assert_eq!(
            fixture_chirho.current_term_chirho, fixture_chirho.historical_term_chirho,
            "the positive control stays at the historical term"
        );
    }

    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&fixture_chirho.held_root_chirho.0)
            .expect("reopen held evidence storage");
    let view_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.winner_verifier_chirho,
        fixture_chirho
            .completed_view_chirho
            .checkpoint_chirho
            .identity_chirho
            .clone(),
    )
    .expect("reopen exact complete held view");
    let attempt_identity_chirho = Gd7WinnerHandoffAttemptIdentityChirho {
        held_transfer_identity_chirho: fixture_chirho
            .completed_view_chirho
            .checkpoint_chirho
            .identity_chirho
            .clone(),
        held_transfer_checkpoint_ref_chirho: fixture_chirho
            .completed_view_chirho
            .checkpoint_ref_chirho
            .clone(),
        expected_bundle_root_object_digest_chirho: fixture_chirho
            .completed_view_chirho
            .checkpoint_chirho
            .inspection_chirho
            .as_ref()
            .expect("complete view carries its winner inspection")
            .bundle_root_object_digest_chirho
            .clone(),
        challenge_digest_chirho: parse_canonical_gd7_winner_current_view_challenge_chirho(
            fixture_chirho
                .completed_view_chirho
                .checkpoint_chirho
                .canonical_challenge_chirho
                .as_ref()
                .expect("complete view carries its canonical challenge")
                .as_bytes(),
        )
        .expect("parse the complete view challenge")
        .digest_chirho()
        .expect("digest the complete view challenge"),
    };
    let attempt_digest_chirho = gd7_winner_handoff_attempt_digest_chirho(&attempt_identity_chirho)
        .expect("digest the exact handoff attempt");
    let status_phase_chirho = case_chirho
        .returned_phase_chirho
        .unwrap_or(Gd7WinnerHandoffPhaseChirho::PreparingChirho);
    let configured_status_chirho = ResidentGd7WinnerHandoffStatusChirho {
        attempt_digest_chirho,
        checkpoint_ref_chirho: "d".repeat(64),
        attempt_identity_chirho: attempt_identity_chirho.clone(),
        phase_chirho: status_phase_chirho,
        inspection_chirho: fixture_chirho
            .completed_view_chirho
            .checkpoint_chirho
            .inspection_chirho
            .clone()
            .expect("complete view carries its winner inspection"),
        preparing_process_generation_chirho: 17,
        accepting_process_generation_chirho: matches!(
            status_phase_chirho,
            Gd7WinnerHandoffPhaseChirho::AcceptedChirho
        )
        .then_some(18),
    };
    let expected_retained_status_chirho = matches!(
        case_chirho.returned_phase_chirho,
        Some(Gd7WinnerHandoffPhaseChirho::AcceptedChirho)
    )
    .then(|| configured_status_chirho.clone());
    let dispatch_chirho = match case_chirho.returned_phase_chirho {
        Some(_) => Gd7WinnerViewTransferTestDispatchChirho::StatusChirho(Box::new(
            configured_status_chirho,
        )),
        None => Gd7WinnerViewTransferTestDispatchChirho::ActorStateChangedChirho,
    };
    let mut endpoint_chirho = Gd7WinnerViewTransferTestEndpointChirho::spawn_chirho(
        &fixture_chirho.winner_root_chirho.0,
        &fixture_chirho.group_chirho,
        fixture_chirho.winner_node_chirho.clone(),
        fixture_chirho.held_node_chirho.clone(),
        Arc::clone(&fixture_chirho.nodes_chirho[0]),
        dispatch_chirho,
    )
    .expect("open the signed actor-dispatch test endpoint");
    std::thread::sleep(Duration::from_millis(25));

    let group_head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(&fixture_chirho.group_digest_chirho)
            .expect("derive fixed reconciliation head path");
    let head_before_chirho = storage_chirho
        .read_all_chirho(&group_head_path_chirho)
        .expect("read fixed reconciliation head")
        .expect("fixed reconciliation head exists");
    let inventory_before_chirho = storage_chirho
        .list_chirho(&StoragePathChirho::new_chirho("gd7-reconciliation-chirho"))
        .expect("inventory reconciliation evidence before the request");
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build();
    let result_chirho = establish_accepted_handoff_chirho(
        &agent_chirho,
        endpoint_chirho.base_url_chirho(),
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.winner_node_chirho,
        view_store_chirho.identity_digest_chirho(),
        &baseline_chirho,
        fixture_chirho.nodes_chirho[2].as_ref(),
        &fixture_chirho.coordinator_chirho,
        &view_store_chirho,
        &fixture_chirho.completed_view_chirho,
        &fixture_chirho.checkpoint_chirho,
    );
    let observations_chirho = endpoint_chirho.observations_chirho();
    assert_eq!(
        observations_chirho
            .iter()
            .filter(|observation_chirho| matches!(
                observation_chirho.operation_chirho,
                Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho { .. }
            ))
            .count(),
        1,
        "one verified status request is the non-vacuity control"
    );
    assert_eq!(
        observations_chirho
            .iter()
            .filter(|observation_chirho| matches!(
                observation_chirho.operation_chirho,
                Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho { .. }
            ))
            .count(),
        expected_begin_count_chirho,
        "the same recorder distinguishes rollover refusal from historical-term Begin"
    );
    match (case_chirho.returned_phase_chirho, roll_winner_term_chirho) {
        (Some(Gd7WinnerHandoffPhaseChirho::PreparingChirho) | None, true) => {
            let refusal_chirho = result_chirho
                .expect_err("a newer term without an exact retained Accepted barrier must refuse");
            assert_eq!(
                refusal_chirho.downcast_ref::<Gd7HeldHandoffContinuationRefusalChirho>(),
                Some(
                    &Gd7HeldHandoffContinuationRefusalChirho::NewerWinnerTermWithoutRetainedBarrierChirho
                )
            );
            assert!(!refusal_chirho
                .to_string()
                .contains("historical winner changed"));
            assert!(!refusal_chirho.to_string().contains("regressed"));
        }
        (Some(Gd7WinnerHandoffPhaseChirho::AcceptedChirho), true) => {
            let retained_status_chirho = result_chirho
                .expect("an exact retained Accepted barrier remains reachable at the newer term");
            assert_eq!(
                Some(&retained_status_chirho),
                expected_retained_status_chirho.as_ref(),
                "the held sender returns the exact retained status rather than minting another"
            );
            assert_eq!(
                retained_status_chirho
                    .attempt_identity_chirho
                    .held_transfer_identity_chirho
                    .winner_term_chirho,
                fixture_chirho.historical_term_chirho,
                "retained acceptance keeps the immutable historical identity"
            );
        }
        (None, false) => {
            let refusal_chirho =
                result_chirho.expect_err("historical Begin reaches the configured actor refusal");
            assert!(
                refusal_chirho
                    .to_string()
                    .contains("ActorStateChangedChirho"),
                "the historical control reaches Begin and receives the configured actor refusal"
            );
            assert!(
                refusal_chirho
                    .downcast_ref::<Gd7HeldHandoffContinuationRefusalChirho>()
                    .is_none(),
                "the historical control must not masquerade as the newer-term refusal"
            );
            assert!(!refusal_chirho
                .to_string()
                .contains("historical winner changed"));
            assert!(!refusal_chirho.to_string().contains("regressed"));
        }
        _ => panic!("unsupported real handoff transport fixture case"),
    }
    assert!(observations_chirho.iter().all(|observation_chirho| {
        observation_chirho.expected_raft_term_chirho == fixture_chirho.current_term_chirho
            && observation_chirho.sender_node_chirho == fixture_chirho.held_node_chirho.0
    }));
    assert_eq!(
        attempt_identity_chirho
            .held_transfer_identity_chirho
            .winner_term_chirho,
        fixture_chirho.historical_term_chirho
    );
    assert_eq!(
        fixture_chirho.completed_view_chirho,
        view_store_chirho
            .load_active_chirho()
            .expect("reload complete held view")
            .expect("complete held view remains active")
    );
    assert_eq!(
        storage_chirho
            .read_all_chirho(&group_head_path_chirho)
            .expect("reread fixed reconciliation head")
            .expect("fixed reconciliation head remains present"),
        head_before_chirho
    );
    assert_eq!(
        storage_chirho
            .list_chirho(&StoragePathChirho::new_chirho("gd7-reconciliation-chirho"))
            .expect("inventory reconciliation evidence after the request"),
        inventory_before_chirho
    );

    endpoint_chirho
        .close_chirho()
        .expect("close signed test endpoint");
    fixture_chirho
        .coordinator_chirho
        .close_chirho()
        .expect("close real held coordinator");
}

fn real_handoff_fixture_chirho(roll_winner_term_chirho: bool) -> RealHandoffFixtureChirho {
    let held_root_chirho = test_tenant_root_chirho("held");
    let winner_root_chirho = test_tenant_root_chirho("winner");
    sign_message_chirho(&held_root_chirho.0, b"provision held node identity")
        .expect("provision held node identity");
    sign_message_chirho(&winner_root_chirho.0, b"provision winner node identity")
        .expect("provision winner node identity");
    let held_node_chirho = NodeIdChirho(
        existing_keypair_pubkey_hex_chirho(&held_root_chirho.0).expect("read held node identity"),
    );
    let winner_node_chirho = NodeIdChirho(
        existing_keypair_pubkey_hex_chirho(&winner_root_chirho.0)
            .expect("read winner node identity"),
    );
    let config_path_chirho = provision_held_config_chirho(&held_root_chirho.0);
    let config_chirho = load_config_chirho(&config_path_chirho)
        .expect("load held config")
        .ledger_host_chirho
        .expect("held config carries ledger host");
    let group_chirho = consistency_group_for_root_chirho(
        &held_root_chirho
            .0
            .canonicalize()
            .expect("canonicalize held root"),
    )
    .expect("derive held consistency group");
    let group_digest_chirho =
        consistency_group_digest_chirho(&group_chirho).expect("digest held consistency group");
    let losing_tail_chirho = activate_held_resident_chirho(
        &held_root_chirho.0,
        &config_chirho,
        &group_chirho,
        &held_node_chirho,
    );
    let losing_term_chirho =
        u64::from(split_writer_epoch_chirho(losing_tail_chirho.epoch_chirho).geo_term_chirho);

    let replacement_node_chirho = NodeIdChirho(hex_chirho(
        SigningKey::from_bytes(&[83; 32]).verifying_key().as_bytes(),
    ));
    let voters_chirho = vec![
        (1, winner_node_chirho.clone()),
        (2, replacement_node_chirho.clone()),
    ];
    let learners_chirho = vec![(3, held_node_chirho.clone())];
    let nodes_chirho = (1..=3)
        .map(|raft_id_chirho| {
            Arc::new(
                RaftWriterElectorChirho::new_cluster_node_with_learners_chirho(
                    group_chirho.clone(),
                    raft_id_chirho,
                    voters_chirho.clone(),
                    learners_chirho.clone(),
                )
                .expect("construct A/B/held election")
                .with_leadership_warmup_lease_chirho(),
            )
        })
        .collect::<Vec<_>>();
    drive_campaign_chirho(&nodes_chirho, 0);
    drive_ticks_chirho(&nodes_chirho, 0, 10);
    while nodes_chirho[2].current_leadership_chirho().term_chirho <= losing_term_chirho {
        drive_transfer_chirho(&nodes_chirho, 0, nodes_chirho[1].local_raft_id_chirho());
        drive_ticks_chirho(&nodes_chirho, 1, 10);
        drive_transfer_chirho(&nodes_chirho, 1, nodes_chirho[0].local_raft_id_chirho());
        drive_ticks_chirho(&nodes_chirho, 0, 10);
    }
    let historical_leadership_chirho = nodes_chirho[2].current_leadership_chirho();
    assert_eq!(
        historical_leadership_chirho.leader_id_chirho.as_ref(),
        Some(&winner_node_chirho)
    );
    let historical_term_chirho = historical_leadership_chirho.term_chirho;
    let identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        winner_node_chirho: winner_node_chirho.0.clone(),
        held_node_chirho: held_node_chirho.0.clone(),
        winner_term_chirho: historical_term_chirho,
        losing_term_chirho,
        winner_journal_genesis_digest_chirho: losing_tail_chirho.prev_chirho.0.clone(),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(historical_term_chirho, 1)
                .expect("compose winner tail epoch"),
            seq_chirho: losing_tail_chirho.seq_chirho + 1,
            record_digest_chirho: "b".repeat(64),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(losing_term_chirho, 0)
                .expect("compose genesis fork epoch"),
            seq_chirho: 0,
            record_digest_chirho: losing_tail_chirho.prev_chirho.0.clone(),
        },
        losing_journal_genesis_digest_chirho: losing_tail_chirho.prev_chirho.0.clone(),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: losing_tail_chirho.epoch_chirho,
            seq_chirho: losing_tail_chirho.seq_chirho,
            record_digest_chirho: digest_record_chirho(&losing_tail_chirho),
        },
    };
    let held_signer_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(&held_root_chirho.0, &held_node_chirho)
            .expect("open held control signer");
    let winner_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &winner_root_chirho.0,
        &winner_node_chirho,
    )
    .expect("open winner control signer");
    let (checkpoint_ref_chirho, checkpoint_chirho) = install_plan_sealed_chirho(
        &held_root_chirho.0,
        &group_digest_chirho,
        identity_chirho,
        &held_signer_chirho,
    );
    let completed_view_chirho = install_complete_view_chirho(CompleteViewFixtureInputChirho {
        root_chirho: &held_root_chirho.0,
        reconciliation_checkpoint_ref_chirho: &checkpoint_ref_chirho,
        reconciliation_checkpoint_chirho: &checkpoint_chirho,
        held_signer_chirho: &held_signer_chirho,
        winner_signer_chirho: &winner_signer_chirho,
        held_elector_chirho: &nodes_chirho[2],
        group_chirho: &group_chirho,
        winner_node_chirho: &winner_node_chirho,
        held_node_chirho: &held_node_chirho,
    });

    if roll_winner_term_chirho {
        drive_transfer_chirho(&nodes_chirho, 0, nodes_chirho[1].local_raft_id_chirho());
        assert_eq!(
            nodes_chirho[2]
                .current_leadership_chirho()
                .leader_id_chirho
                .as_ref(),
            Some(&replacement_node_chirho),
            "B genuinely leads between A's two terms"
        );
        drive_ticks_chirho(&nodes_chirho, 1, 10);
        drive_transfer_chirho(&nodes_chirho, 1, nodes_chirho[0].local_raft_id_chirho());
        drive_ticks_chirho(&nodes_chirho, 0, 10);
    }
    let current_leadership_chirho = nodes_chirho[2].current_leadership_chirho();
    assert_eq!(
        current_leadership_chirho.leader_id_chirho.as_ref(),
        Some(&winner_node_chirho)
    );
    if roll_winner_term_chirho {
        assert!(current_leadership_chirho.term_chirho > historical_term_chirho);
    } else {
        assert_eq!(
            current_leadership_chirho.term_chirho,
            historical_term_chirho
        );
    }
    assert!(
        nodes_chirho[0]
            .current_leadership_chirho()
            .lease_valid_chirho
    );
    let coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        &held_root_chirho.0,
        &config_path_chirho,
        &config_chirho,
        Arc::clone(&nodes_chirho[2]),
    )
    .expect("open real held coordinator after same-winner rollover");
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(winner_node_chirho.clone())
            .expect("pin winner control verifier");
    RealHandoffFixtureChirho {
        held_root_chirho,
        winner_root_chirho,
        group_chirho,
        group_digest_chirho,
        winner_node_chirho,
        held_node_chirho,
        nodes_chirho,
        historical_term_chirho,
        current_term_chirho: current_leadership_chirho.term_chirho,
        checkpoint_chirho,
        completed_view_chirho,
        held_signer_chirho,
        winner_verifier_chirho,
        coordinator_chirho,
    }
}

fn activate_held_resident_chirho(
    root_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    held_node_chirho: &NodeIdChirho,
) -> cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho {
    let canonical_root_chirho = root_chirho
        .canonicalize()
        .expect("canonicalize held activation root");
    let storage_root_chirho = canonical_root_chirho.join(&config_chirho.storage_namespace_chirho);
    fs::create_dir_all(&storage_root_chirho).expect("create held journal namespace");
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho)
        .expect("open held journal namespace");
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho)
            .expect("derive signer refs from held config");
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&canonical_root_chirho, &signer_refs_chirho)
            .expect("load held ledger signers");
    let account_chirho = AccountIdChirho {
        owner_chirho: "gd7-real-transport-owner-chirho".to_owned(),
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
    };
    let static_membership_chirho =
        StaticClusterMembershipChirho::new_chirho(0, [account_chirho.clone()])
            .expect("construct activation membership");
    let membership_chirho: ElectedClusterMembershipChirho =
        static_membership_chirho.elected_view_chirho();
    let policy_ref_chirho = AssetKindRefChirho(DigestChirho("11".repeat(32)));
    let registry_chirho = VerifiedRegistryChirho {
        records_chirho: Vec::new(),
        tail_digest_chirho: DigestChirho("44".repeat(32)),
        kinds_chirho: [(
            account_chirho.kind_id_chirho.clone(),
            KindProjectionChirho {
                current_policy_chirho: KindPolicyBodyChirho {
                    unit_chirho: "credit-chirho".to_owned(),
                    precision_chirho: 0,
                    mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
                        max_supply_chirho: Some(1_000),
                    },
                    rounding_chirho: RoundingChirho::ExactChirho,
                    shard_attachment_chirho: "credits-shard-chirho".to_owned(),
                    settlement_owner_chirho: None,
                    idempotency_window_chirho: None,
                },
                current_ref_chirho: policy_ref_chirho.clone(),
                superseded_refs_chirho: Default::default(),
            },
        )]
        .into_iter()
        .collect(),
    };
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
    let clock_chirho = ResidentLedgerClockChirho::reviewed_chirho(900);
    let ports_chirho = ResidentLedgerLocalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: signers_chirho.journal_signer_chirho(),
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let birth_elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        held_node_chirho.clone(),
        group_chirho.clone(),
    )
    .expect("construct reviewed activation elector")
    .with_leadership_warmup_lease_chirho();
    birth_elector_chirho
        .campaign_chirho()
        .expect("campaign reviewed activation elector");
    for _tick_chirho in 0..10 {
        let _outbound_chirho = birth_elector_chirho.tick_chirho();
    }
    let journal_path_chirho = StoragePathChirho::new_chirho(&config_chirho.journal_path_chirho);
    let cluster_id_chirho = ClusterIdChirho(config_chirho.cluster_id_chirho.clone());
    let activation_seed_chirho = [91; 32];
    let activation_key_chirho = SigningKey::from_bytes(&activation_seed_chirho);
    let activation_pin_chirho = LedgerHostActivationPinConfigChirho {
        principal_chirho: "gd7-real-transport-activation-chirho".to_owned(),
        verifying_key_hex_chirho: hex_chirho(activation_key_chirho.verifying_key().as_bytes()),
    };
    let verifier_chirho =
        PinnedLedgerActivationVerifierChirho::from_config_chirho(&activation_pin_chirho)
            .expect("pin activation verifier");
    let intent_chirho = ResidentLedgerMintIntentChirho {
        plan_digest_chirho: "ac".repeat(32),
        activation_principal_chirho: activation_pin_chirho.principal_chirho.clone(),
        initial_owner_chirho: account_chirho.owner_chirho,
        kind_id_chirho: account_chirho.kind_id_chirho,
        kind_policy_ref_chirho: policy_ref_chirho,
        amount_chirho: 25,
        idempotency_key_chirho: format!("regenesis-initial-mint-{}-chirho", &"ac".repeat(32)[..24]),
    };
    let statement_chirho =
        resident_ledger_activation_statement_chirho(ResidentLedgerActivationStatementInputChirho {
            root_chirho: &canonical_root_chirho,
            identity_storage_namespace_chirho: &storage_root_chirho,
            journal_path_chirho: &journal_path_chirho,
            cluster_id_chirho: &cluster_id_chirho,
            opening_epoch_chirho: 0,
            append_physical_ms_chirho: 1_000,
            elected_node_chirho: &held_node_chirho.0,
            consistency_group_chirho: group_chirho,
            intent_chirho: intent_chirho.clone(),
        })
        .expect("construct reviewed activation statement");
    let canonical_statement_chirho =
        canonical_resident_ledger_activation_statement_chirho(&statement_chirho)
            .expect("encode reviewed activation statement");
    let authorization_chirho = ResidentLedgerActivationAuthorizationChirho {
        principal_chirho: activation_pin_chirho.principal_chirho,
        statement_chirho,
        signature_hex_chirho: hex_chirho(
            &activation_key_chirho
                .sign(&canonical_statement_chirho)
                .to_bytes(),
        ),
    };
    let receipt_chirho = activate_reviewed_h3_chirho(ResidentLedgerActivationInputChirho {
        root_chirho: &canonical_root_chirho,
        identity_storage_namespace_chirho: &storage_root_chirho,
        ports_chirho,
        journal_path_chirho: journal_path_chirho.clone(),
        cluster_id_chirho,
        opening_epoch_chirho: 0,
        append_physical_ms_chirho: 1_000,
        local_authority_chirho: birth_elector_chirho.local_append_authority_handle_chirho(),
        verifier_chirho: &verifier_chirho,
        intent_chirho,
        authorization_chirho,
    })
    .expect("activate the held resident through the reviewed production path");
    let append_cut_chirho = ShadowCanaryAppendCutChirho {
        append_seq_chirho: receipt_chirho.append_seq_chirho,
        append_record_digest_chirho: receipt_chirho.append_record_digest_chirho.0.clone(),
        append_hlc_physical_ms_chirho: receipt_chirho.append_hlc_physical_ms_chirho,
        append_hlc_logical_chirho: receipt_chirho.append_hlc_logical_chirho,
        process_generation_chirho: receipt_chirho.process_generation_chirho,
        durable_term_chirho: receipt_chirho.durable_term_chirho,
        fence_epoch_chirho: receipt_chirho.fence_epoch_chirho,
        fence_group_digest_chirho: receipt_chirho.fence_group_digest_chirho,
    };
    let observation_chirho = observe_shadow_canary_chirho(
        &birth_elector_chirho,
        group_chirho,
        held_node_chirho,
        append_cut_chirho,
        1_100,
    );
    assert!(observation_chirho.cutover_would_permit_chirho);
    let canary_store_chirho = ShadowCanaryEvidenceStoreChirho::open_chirho(
        &root_chirho
            .join(&config_chirho.monitor_evidence_namespace_chirho)
            .join("writer-canary-chirho"),
        root_chirho,
        group_chirho.clone(),
        held_node_chirho.clone(),
    )
    .expect("open held shadow-canary store");
    canary_store_chirho
        .append_observation_chirho(observation_chirho)
        .expect("persist held shadow-canary evidence");
    let journal_text_chirho =
        fs::read_to_string(storage_root_chirho.join(journal_path_chirho.key_chirho()))
            .expect("read held journal");
    journal_text_chirho
        .lines()
        .filter_map(|line_chirho| {
            match parse_canonical_ledger_journal_line_chirho(line_chirho)
                .expect("parse canonical held journal line")
            {
                LedgerJournalLineChirho::GenesisChirho(_) => None,
                LedgerJournalLineChirho::RecordChirho(record_chirho) => Some(record_chirho),
            }
        })
        .next_back()
        .expect("reviewed activation wrote one record")
}

fn install_plan_sealed_chirho(
    root_chirho: &Path,
    group_digest_chirho: &str,
    identity_chirho: Gd7ReconciliationIdentityChirho,
    held_signer_chirho: &ExistingNodeGd7SignerChirho,
) -> (String, Gd7ReconciliationCheckpointChirho) {
    let plan_ref_chirho = "3".repeat(64);
    let mut checkpoint_chirho = Gd7ReconciliationCheckpointChirho {
        schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho,
        winner_fork_witness_object_digest_chirho: "4".repeat(64),
        state_chirho: Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
            transition_seq_chirho: 2,
            previous_checkpoint_ref_chirho: Some("1".repeat(64)),
            manifest_head_ref_chirho: Some("2".repeat(64)),
            manifest_page_count_chirho: 1,
            manifest_record_count_chirho: 1,
            plan_head_ref_chirho: Some(plan_ref_chirho.clone()),
            plan_page_count_chirho: 1,
            sealed_plan_ref_chirho: Some(plan_ref_chirho),
            effect_obligation_count_chirho: 0,
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: None,
        },
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    checkpoint_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(
            std::str::from_utf8(
                &serde_json::to_vec(&checkpoint_chirho).expect("encode unsigned checkpoint"),
            )
            .expect("checkpoint JSON is UTF-8"),
        )
        .expect("sign PlanSealed checkpoint");
    let checkpoint_bytes_chirho =
        serde_json::to_vec(&checkpoint_chirho).expect("encode checkpoint");
    let checkpoint_ref_chirho = blake3::hash(&checkpoint_bytes_chirho).to_hex().to_string();
    let identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&checkpoint_chirho.identity_chirho)
            .expect("digest reconciliation identity");
    let mut head_chirho = Gd7ReconciliationHeadChirho {
        schema_chirho: GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: group_digest_chirho.to_owned(),
        reconciliation_identity_digest_chirho: identity_digest_chirho,
        active_checkpoint_ref_chirho: checkpoint_ref_chirho.clone(),
        transition_seq_chirho: checkpoint_chirho.state_chirho.transition_seq_chirho,
        phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    head_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(
            std::str::from_utf8(&serde_json::to_vec(&head_chirho).expect("encode unsigned head"))
                .expect("head JSON is UTF-8"),
        )
        .expect("sign PlanSealed head");
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(root_chirho).expect("open authority storage");
    assert_eq!(
        storage_chirho
            .create_durable_chirho(
                &gd7_reconciliation_checkpoint_path_chirho(&checkpoint_ref_chirho)
                    .expect("derive checkpoint path"),
                &checkpoint_bytes_chirho,
            )
            .expect("persist checkpoint"),
        CreateDurableOutcomeChirho::CreatedChirho
    );
    assert_eq!(
        storage_chirho
            .create_durable_chirho(
                &gd7_reconciliation_group_head_path_chirho(group_digest_chirho)
                    .expect("derive group head path"),
                &serde_json::to_vec(&head_chirho).expect("encode signed head"),
            )
            .expect("persist group head"),
        CreateDurableOutcomeChirho::CreatedChirho
    );
    (checkpoint_ref_chirho, checkpoint_chirho)
}

struct CompleteViewFixtureInputChirho<'a> {
    root_chirho: &'a Path,
    reconciliation_checkpoint_ref_chirho: &'a str,
    reconciliation_checkpoint_chirho: &'a Gd7ReconciliationCheckpointChirho,
    held_signer_chirho: &'a ExistingNodeGd7SignerChirho,
    winner_signer_chirho: &'a ExistingNodeGd7SignerChirho,
    held_elector_chirho: &'a RaftWriterElectorChirho,
    group_chirho: &'a ConsistencyGroupIdChirho,
    winner_node_chirho: &'a NodeIdChirho,
    held_node_chirho: &'a NodeIdChirho,
}

fn install_complete_view_chirho(
    input_chirho: CompleteViewFixtureInputChirho<'_>,
) -> ActiveGd7HeldViewTransferChirho {
    let CompleteViewFixtureInputChirho {
        root_chirho,
        reconciliation_checkpoint_ref_chirho,
        reconciliation_checkpoint_chirho,
        held_signer_chirho,
        winner_signer_chirho,
        held_elector_chirho,
        group_chirho,
        winner_node_chirho,
        held_node_chirho,
    } = input_chirho;
    let identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: reconciliation_checkpoint_chirho
            .identity_chirho
            .consistency_group_digest_chirho
            .clone(),
        reconciliation_checkpoint_ref_chirho: reconciliation_checkpoint_ref_chirho.to_owned(),
        winner_node_chirho: reconciliation_checkpoint_chirho
            .identity_chirho
            .winner_node_chirho
            .clone(),
        held_node_chirho: reconciliation_checkpoint_chirho
            .identity_chirho
            .held_node_chirho
            .clone(),
        winner_term_chirho: reconciliation_checkpoint_chirho
            .identity_chirho
            .winner_term_chirho,
    };
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(root_chirho).expect("open held-view storage");
    let store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &storage_chirho,
        held_signer_chirho,
        winner_signer_chirho,
        identity_chirho.clone(),
    )
    .expect("open held-view store");
    let initial_chirho = store_chirho
        .ensure_initialized_chirho()
        .expect("initialize held-view transfer");
    let root_record_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: reconciliation_checkpoint_chirho
            .identity_chirho
            .winner_journal_genesis_digest_chirho
            .clone(),
        source_cut_chirho: reconciliation_checkpoint_chirho
            .identity_chirho
            .winner_journal_tail_chirho
            .clone(),
        lowest_page_ref_chirho: None,
        page_count_chirho: 0,
        row_count_chirho: 0,
    };
    let root_bytes_chirho = serde_json::to_vec(&root_record_chirho).expect("encode zero-page root");
    let root_digest_chirho = blake3::hash(&root_bytes_chirho).to_hex().to_string();
    let issued_challenge_chirho = generate_gd7_winner_current_view_challenge_chirho(
        held_elector_chirho,
        group_chirho,
        winner_node_chirho,
        held_node_chirho,
        store_chirho.identity_digest_chirho(),
    )
    .expect("mint held-view challenge from the historical elected-winner observation");
    let challenge_bytes_chirho = issued_challenge_chirho
        .canonical_bytes_chirho()
        .expect("encode held-view challenge");
    let challenge_chirho =
        parse_canonical_gd7_winner_current_view_challenge_chirho(&challenge_bytes_chirho)
            .expect("parse the production-minted held-view challenge");
    let challenged_chirho = store_chirho
        .commit_challenge_issued_chirho(
            &initial_chirho.checkpoint_ref_chirho,
            0,
            root_digest_chirho.clone(),
            0,
            0,
            &challenge_bytes_chirho,
        )
        .expect("commit exact held-view challenge");
    let mut evidence_chirho = Gd7WinnerCurrentViewEvidenceChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        challenge_digest_chirho: challenge_chirho.digest_chirho().expect("digest challenge"),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho,
        winner_node_chirho: identity_chirho.winner_node_chirho,
        raft_term_chirho: identity_chirho.winner_term_chirho,
        winner_process_generation_chirho: 19,
        winner_journal_genesis_digest_chirho: root_record_chirho
            .winner_journal_genesis_digest_chirho
            .clone(),
        latest_verified_journal_cut_chirho: root_record_chirho.source_cut_chirho.clone(),
        view_bundle_root_chirho: root_digest_chirho.clone(),
        key_id_chirho: winner_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    evidence_chirho.sig_chirho = winner_signer_chirho
        .sign_chirho(
            std::str::from_utf8(
                &serde_json::to_vec(&evidence_chirho).expect("encode unsigned evidence"),
            )
            .expect("winner evidence JSON is UTF-8"),
        )
        .expect("sign winner evidence");
    let evidence_bytes_chirho =
        serde_json::to_vec(&evidence_chirho).expect("encode winner evidence");
    let inspection_chirho = Gd7WinnerCurrentViewInspectionChirho {
        evidence_object_digest_chirho: blake3::hash(&evidence_bytes_chirho).to_hex().to_string(),
        evidence_chirho,
        bundle_root_object_digest_chirho: root_digest_chirho,
        bundle_root_chirho: root_record_chirho,
    };
    store_chirho
        .commit_sealed_chirho(
            &challenged_chirho.checkpoint_ref_chirho,
            inspection_chirho,
            None,
        )
        .expect("seal zero-page held view");
    store_chirho
        .load_active_chirho()
        .expect("reload complete held view")
        .expect("complete held view remains active")
}

fn provision_held_config_chirho(root_chirho: &Path) -> PathBuf {
    for (index_chirho, secret_name_chirho) in [
        JOURNAL_SECRET_CHIRHO,
        CONFIG_SECRET_CHIRHO,
        FEEDER_SECRET_CHIRHO,
        KIND_ROOT_SECRET_CHIRHO,
        EFFECT_INTENT_SECRET_CHIRHO,
        EFFECT_TERMINAL_SECRET_CHIRHO,
    ]
    .iter()
    .enumerate()
    {
        set_secret_chirho(
            root_chirho,
            secret_name_chirho,
            &[(index_chirho + 1) as u8; 32],
        )
        .expect("provision held signer secret");
    }
    let journal_key_chirho =
        hex_chirho(SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes());
    let issuer_key_chirho =
        hex_chirho(SigningKey::from_bytes(&[80; 32]).verifying_key().as_bytes());
    let activation_key_chirho =
        hex_chirho(SigningKey::from_bytes(&[91; 32]).verifying_key().as_bytes());
    let config_path_chirho = root_chirho.join("gd7-real-transport-config-chirho.toml");
    fs::write(
        &config_path_chirho,
        format!(
            r#"[ledger_host_chirho]
schema_chirho = "ledger-host-config-v3-chirho"
storage_namespace_chirho = "ledger-namespace-chirho"
monitor_evidence_namespace_chirho = "ops-chirho"
monitor_evidence_path_chirho = "monitor/cycles-chirho.jsonl"
money_group_id_chirho = "money-group-real-transport-chirho"
cluster_id_chirho = "cluster-real-transport-chirho"
journal_path_chirho = "journals/main-chirho.jsonl"
local_epoch_chirho = 1
members_chirho = [{{ owner_chirho = "gd7-real-transport-owner-chirho", kind_id_chirho = "credits-chirho" }}]
kind_registry_path_chirho = "registries/kinds-chirho.jsonl"
kind_registry_id_chirho = "kind-registry-real-transport-chirho"
projection_registry_path_chirho = "registries/projections-chirho.jsonl"
projection_registry_id_chirho = "projection-registry-real-transport-chirho"
source_registry_path_chirho = "registries/sources-chirho.jsonl"
source_registry_id_chirho = "source-registry-real-transport-chirho"
projection_routes_chirho = [{{ projection_name_chirho = "credits-balance-chirho", head_path_chirho = "published/credits-balance-head-chirho.json" }}]
monitor_cadence_ms_chirho = 5000

[ledger_host_chirho.kind_issuer_chirho]
principal_chirho = "gd7-real-transport-issuer-chirho"
verifying_key_hex_chirho = "{issuer_key_chirho}"

[ledger_host_chirho.activation_authority_chirho]
principal_chirho = "gd7-real-transport-activation-chirho"
verifying_key_hex_chirho = "{activation_key_chirho}"

[ledger_host_chirho.held_verifier_pins_chirho]
journal_verifying_key_hex_chirho = "{journal_key_chirho}"

[ledger_host_chirho.signer_secrets_chirho]
journal_chirho = "{JOURNAL_SECRET_CHIRHO}"
config_chirho = "{CONFIG_SECRET_CHIRHO}"
feeder_chirho = "{FEEDER_SECRET_CHIRHO}"
kind_root_chirho = "{KIND_ROOT_SECRET_CHIRHO}"
effect_intent_chirho = "{EFFECT_INTENT_SECRET_CHIRHO}"
effect_terminal_chirho = "{EFFECT_TERMINAL_SECRET_CHIRHO}"
"#,
        ),
    )
    .expect("write held ledger config");
    set_private_mode_chirho(&config_path_chirho);
    config_path_chirho
}

fn drive_campaign_chirho(nodes_chirho: &[Arc<RaftWriterElectorChirho>], campaigner_chirho: usize) {
    let bus_chirho = nodes_chirho[campaigner_chirho]
        .campaign_encoded_chirho()
        .expect("campaign starts");
    drive_encoded_message_bus_chirho(nodes_chirho, bus_chirho);
}

fn drive_ticks_chirho(
    nodes_chirho: &[Arc<RaftWriterElectorChirho>],
    ticking_node_chirho: usize,
    tick_count_chirho: usize,
) {
    for _tick_chirho in 0..tick_count_chirho {
        drive_encoded_message_bus_chirho(
            nodes_chirho,
            nodes_chirho[ticking_node_chirho]
                .tick_encoded_chirho()
                .expect("encode election tick messages"),
        );
    }
}

fn drive_encoded_message_bus_chirho(
    nodes_chirho: &[Arc<RaftWriterElectorChirho>],
    mut bus_chirho: Vec<(u64, Vec<u8>)>,
) {
    for _round_chirho in 0..1_000 {
        if bus_chirho.is_empty() {
            return;
        }
        let mut next_chirho = Vec::new();
        for (target_id_chirho, message_bytes_chirho) in bus_chirho.drain(..) {
            let target_chirho = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == target_id_chirho)
                .expect("every message target is in the fixed roster");
            next_chirho.extend(
                target_chirho
                    .step_encoded_chirho(&message_bytes_chirho)
                    .expect("step encoded message"),
            );
        }
        bus_chirho = next_chirho;
    }
    panic!("election message bus did not drain within its fixed bound");
}

fn drive_transfer_chirho(
    nodes_chirho: &[Arc<RaftWriterElectorChirho>],
    leader_chirho: usize,
    target_raft_id_chirho: u64,
) {
    let bus_chirho = nodes_chirho[leader_chirho]
        .transfer_leadership_to_chirho(target_raft_id_chirho)
        .expect("leader starts transfer");
    drive_encoded_message_bus_chirho(nodes_chirho, bus_chirho);
}

fn digest_record_chirho(
    record_chirho: &cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho,
) -> String {
    blake3::hash(
        cairn_ledger_model_chirho::wire_chirho::canonical_ledger_record_line_chirho(record_chirho)
            .expect("encode canonical record")
            .as_bytes(),
    )
    .to_hex()
    .to_string()
}

fn test_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nonce_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "gd7-real-handoff-{label_chirho}-{}-{nonce_chirho}-{counter_chirho}-chirho",
        std::process::id()
    ))
}

fn test_tenant_root_chirho(label_chirho: &str) -> TestRootChirho {
    let platform_root_chirho = test_root_chirho(label_chirho);
    fs::create_dir_all(&platform_root_chirho).expect("create fixture platform root");
    let tenant_root_chirho = prepare_tenant_root_chirho(
        &platform_root_chirho,
        &format!("gd7-real-{label_chirho}-tenant-chirho"),
    )
    .expect("prepare fixture tenant root");
    TestRootChirho(tenant_root_chirho, platform_root_chirho)
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        use std::fmt::Write;
        write!(&mut encoded_chirho, "{byte_chirho:02x}").expect("write hex byte");
    }
    encoded_chirho
}

#[cfg(unix)]
fn set_private_mode_chirho(path_chirho: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path_chirho, fs::Permissions::from_mode(0o600))
        .expect("set private config mode");
}

#[cfg(not(unix))]
fn set_private_mode_chirho(_path_chirho: &Path) {}
