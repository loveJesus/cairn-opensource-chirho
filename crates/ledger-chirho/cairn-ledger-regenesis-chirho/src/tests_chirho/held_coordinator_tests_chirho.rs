// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::harness1_gd7_world_chirho::{build_observed_gd7_world_chirho, ObservedGd7WorldChirho};
use super::{drive_campaign_chirho, drive_transfer_chirho, fixture_chirho, request_chirho};
use crate::run_ledger_regenesis_chirho;
use cairn_config_chirho::config_chirho::load_config_chirho;
use cairn_effect_commit_chirho::coordinator_chirho::EffectCommitJournalViewPortChirho;
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, gd7_reconciliation_group_head_path_chirho,
    gd7_reconciliation_identity_digest_chirho, verify_signed_gd7_converged_read_replica_chirho,
    winner_fork_witness_path_chirho, ExistingNodeGd7SignerChirho, Gd7ConvergenceBindingInputChirho,
    Gd7ConvergenceUnmeasuredPredicatesChirho, Gd7ForkCoordinateChirho,
    Gd7JournalTailCoordinateChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationHeadChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    Gd7WinnerWitnessReaderChirho, PinnedNodeGd7VerifierChirho,
    GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO, GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::{
    open_resident_effect_journal_handle_chirho, open_resident_gd7_held_coordinator_chirho,
    FsLedgerStorageChirho, ResidentGd7HeldCoordinatorRefusalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_log_chirho::ports_chirho::{CreateDurableOutcomeChirho, LedgerStoragePortChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, LedgerJournalLineChirho,
};
use cairn_secret_chirho::secret_chirho::SECRETS_DIR_CHIRHO;
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho,
    consistency_group_for_root_chirho, split_writer_epoch_chirho,
};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn sign_checkpoint_chirho(
    mut checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
    signer_chirho: &ExistingNodeGd7SignerChirho,
) -> (String, Vec<u8>) {
    checkpoint_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    checkpoint_chirho.sig_chirho.clear();
    let unsigned_chirho = serde_json::to_string(&checkpoint_chirho).unwrap();
    checkpoint_chirho.sig_chirho = signer_chirho.sign_chirho(&unsigned_chirho).unwrap();
    let bytes_chirho = serde_json::to_vec(&checkpoint_chirho).unwrap();
    (
        blake3::hash(&bytes_chirho).to_hex().to_string(),
        bytes_chirho,
    )
}

fn sign_head_chirho(
    mut head_chirho: Gd7ReconciliationHeadChirho,
    signer_chirho: &ExistingNodeGd7SignerChirho,
) -> Vec<u8> {
    head_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    head_chirho.sig_chirho.clear();
    let unsigned_chirho = serde_json::to_string(&head_chirho).unwrap();
    head_chirho.sig_chirho = signer_chirho.sign_chirho(&unsigned_chirho).unwrap();
    serde_json::to_vec(&head_chirho).unwrap()
}

#[test]
fn held_coordinator_restarts_on_shared_learner_and_fail_stops_on_winner_drift_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let ledger_config_chirho = load_config_chirho(&fixture_chirho.config_path_chirho)
        .unwrap()
        .ledger_host_chirho
        .expect("fixture config carries the ledger host");
    let canonical_root_chirho = fixture_chirho.root_chirho.canonicalize().unwrap();
    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho).unwrap();
    let group_digest_chirho = consistency_group_digest_chirho(&group_chirho).unwrap();
    let held_node_chirho =
        NodeIdChirho(existing_keypair_pubkey_hex_chirho(&canonical_root_chirho).unwrap());
    let candidate_one_node_chirho = NodeIdChirho("a".repeat(64));
    assert_ne!(held_node_chirho, candidate_one_node_chirho);
    let candidate_two_node_chirho = NodeIdChirho("c".repeat(64));
    let voters_chirho = vec![
        (1, candidate_one_node_chirho.clone()),
        (2, candidate_two_node_chirho.clone()),
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
                .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    drive_campaign_chirho(&nodes_chirho, 0);
    let mut held_view_chirho = nodes_chirho[2].leadership_chirho(&group_chirho);
    assert!(held_view_chirho.leader_id_chirho.is_some());
    assert_ne!(
        held_view_chirho.leader_id_chirho.as_ref(),
        Some(&held_node_chirho)
    );
    assert!(!held_view_chirho.is_leader_chirho);

    let actor_chirho = open_resident_effect_journal_handle_chirho(
        &canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        None,
    )
    .expect("the published resident provides its verified journal cut");
    let losing_cut_chirho = actor_chirho.effect_intent_cut_chirho().unwrap();
    drop(actor_chirho);
    let journal_file_chirho = canonical_root_chirho
        .join(&ledger_config_chirho.storage_namespace_chirho)
        .join(&ledger_config_chirho.journal_path_chirho);
    let journal_text_chirho = std::fs::read_to_string(&journal_file_chirho).unwrap();
    let journal_lines_chirho = journal_text_chirho
        .lines()
        .filter_map(|line_chirho| {
            match parse_canonical_ledger_journal_line_chirho(line_chirho).unwrap() {
                LedgerJournalLineChirho::GenesisChirho(_genesis_chirho) => None,
                LedgerJournalLineChirho::RecordChirho(record_chirho) => Some(record_chirho),
            }
        })
        .collect::<Vec<_>>();
    assert!(!journal_lines_chirho.is_empty());
    let losing_tail_chirho = journal_lines_chirho.last().unwrap();
    let losing_term_chirho =
        u64::from(split_writer_epoch_chirho(losing_tail_chirho.epoch_chirho).geo_term_chirho);
    assert_eq!(
        losing_cut_chirho.tail_seq_chirho,
        losing_tail_chirho.seq_chirho
    );
    if held_view_chirho.term_chirho <= losing_term_chirho {
        drive_transfer_chirho(&nodes_chirho, 0, 2);
        held_view_chirho = nodes_chirho[2].leadership_chirho(&group_chirho);
    }
    assert!(
        held_view_chirho.term_chirho > losing_term_chirho,
        "elected term {} must depose local term {} (leader {:?})",
        held_view_chirho.term_chirho,
        losing_term_chirho,
        held_view_chirho.leader_id_chirho,
    );
    let winner_node_chirho = held_view_chirho
        .leader_id_chirho
        .clone()
        .expect("the held follower observes the elected winner");
    assert_ne!(winner_node_chirho, held_node_chirho);
    let identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        winner_node_chirho: winner_node_chirho.0.clone(),
        held_node_chirho: held_node_chirho.0.clone(),
        winner_term_chirho: held_view_chirho.term_chirho,
        losing_term_chirho,
        winner_journal_genesis_digest_chirho: losing_cut_chirho
            .journal_genesis_digest_chirho
            .0
            .clone(),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(held_view_chirho.term_chirho, 1).unwrap(),
            seq_chirho: losing_tail_chirho.seq_chirho + 1,
            record_digest_chirho: "b".repeat(64),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: journal_lines_chirho
                .get(journal_lines_chirho.len().saturating_sub(2))
                .map(|record_chirho| record_chirho.epoch_chirho)
                .unwrap_or(losing_tail_chirho.epoch_chirho),
            seq_chirho: losing_tail_chirho.seq_chirho - 1,
            record_digest_chirho: losing_tail_chirho.prev_chirho.0.clone(),
        },
        losing_journal_genesis_digest_chirho: losing_cut_chirho
            .journal_genesis_digest_chirho
            .0
            .clone(),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: losing_tail_chirho.epoch_chirho,
            seq_chirho: losing_tail_chirho.seq_chirho,
            record_digest_chirho: losing_cut_chirho.tail_record_digest_chirho.0,
        },
    };
    let held_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &canonical_root_chirho,
        &held_node_chirho,
    )
    .unwrap();
    let checkpoint_state_chirho = Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::ObservedHeldChirho,
        transition_seq_chirho: 0,
        previous_checkpoint_ref_chirho: None,
        manifest_head_ref_chirho: None,
        manifest_page_count_chirho: 0,
        manifest_record_count_chirho: 0,
        plan_head_ref_chirho: None,
        plan_page_count_chirho: 0,
        sealed_plan_ref_chirho: None,
        effect_obligation_count_chirho: 0,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    };
    let (checkpoint_ref_chirho, checkpoint_bytes_chirho) = sign_checkpoint_chirho(
        Gd7ReconciliationCheckpointChirho {
            schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
            identity_chirho: identity_chirho.clone(),
            winner_fork_witness_object_digest_chirho: "9".repeat(64),
            state_chirho: checkpoint_state_chirho,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        },
        &held_signer_chirho,
    );
    let identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&identity_chirho).unwrap();
    let head_bytes_chirho = sign_head_chirho(
        Gd7ReconciliationHeadChirho {
            schema_chirho: GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: group_digest_chirho.clone(),
            reconciliation_identity_digest_chirho: identity_digest_chirho,
            active_checkpoint_ref_chirho: checkpoint_ref_chirho.clone(),
            transition_seq_chirho: 0,
            phase_chirho: Gd7ReconciliationPhaseChirho::ObservedHeldChirho,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        },
        &held_signer_chirho,
    );
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&canonical_root_chirho).unwrap();
    assert_eq!(
        authority_storage_chirho
            .create_durable_chirho(
                &gd7_reconciliation_checkpoint_path_chirho(&checkpoint_ref_chirho).unwrap(),
                &checkpoint_bytes_chirho,
            )
            .unwrap(),
        CreateDurableOutcomeChirho::CreatedChirho
    );
    assert_eq!(
        authority_storage_chirho
            .create_durable_chirho(
                &gd7_reconciliation_group_head_path_chirho(&group_digest_chirho).unwrap(),
                &head_bytes_chirho,
            )
            .unwrap(),
        CreateDurableOutcomeChirho::CreatedChirho
    );

    std::fs::remove_dir_all(canonical_root_chirho.join(SECRETS_DIR_CHIRHO)).unwrap();
    std::fs::remove_file(canonical_root_chirho.join("signing-key-chirho.bin")).unwrap();
    assert!(
        !canonical_root_chirho.join(SECRETS_DIR_CHIRHO).exists()
            && !canonical_root_chirho
                .join("signing-key-chirho.bin")
                .exists(),
        "held startup must not retain or reread ledger or node private signing keys"
    );

    let mut first_chirho = open_resident_gd7_held_coordinator_chirho(
        &canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        Arc::clone(&nodes_chirho[2]),
    )
    .expect("a follower opens the existing held checkpoint without local append authority");
    let first_snapshot_chirho = first_chirho.inspect_chirho().unwrap();
    assert_eq!(
        first_snapshot_chirho.checkpoint_ref_chirho,
        checkpoint_ref_chirho
    );
    assert_eq!(
        first_snapshot_chirho.winner_node_chirho,
        winner_node_chirho.0
    );
    assert!(
        open_resident_gd7_held_coordinator_chirho(
            &canonical_root_chirho,
            &fixture_chirho.config_path_chirho,
            &ledger_config_chirho,
            Arc::clone(&nodes_chirho[2]),
        )
        .is_err(),
        "the retained held writer lock excludes a second coordinator"
    );
    let journal_len_chirho = std::fs::metadata(&journal_file_chirho).unwrap().len();
    let mut journal_mutator_chirho = std::fs::OpenOptions::new()
        .append(true)
        .open(&journal_file_chirho)
        .unwrap();
    journal_mutator_chirho.write_all(b"{}\n").unwrap();
    journal_mutator_chirho.sync_all().unwrap();
    assert_eq!(
        first_chirho.inspect_chirho().unwrap_err(),
        ResidentGd7HeldCoordinatorRefusalChirho::LosingJournalChangedChirho,
        "physical tail growth after startup must invalidate the cached coordinate"
    );
    drop(journal_mutator_chirho);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&journal_file_chirho)
        .unwrap()
        .set_len(journal_len_chirho)
        .unwrap();
    first_chirho.close_chirho().unwrap();

    let winner_index_chirho = nodes_chirho
        .iter()
        .position(|node_chirho| node_chirho.node_id_chirho() == &winner_node_chirho)
        .unwrap();
    let replacement_index_chirho = if winner_index_chirho == 0 { 1 } else { 0 };
    drive_transfer_chirho(
        &nodes_chirho,
        winner_index_chirho,
        nodes_chirho[replacement_index_chirho].local_raft_id_chirho(),
    );
    let replacement_view_chirho = nodes_chirho[2].leadership_chirho(&group_chirho);
    assert_eq!(
        replacement_view_chirho.leader_id_chirho.as_ref(),
        Some(nodes_chirho[replacement_index_chirho].node_id_chirho()),
        "the intermediate transfer genuinely changes the winner"
    );
    assert!(replacement_view_chirho.term_chirho > identity_chirho.winner_term_chirho);
    drive_transfer_chirho(
        &nodes_chirho,
        replacement_index_chirho,
        nodes_chirho[winner_index_chirho].local_raft_id_chirho(),
    );
    let rollover_view_chirho = nodes_chirho[2].leadership_chirho(&group_chirho);
    assert_eq!(
        rollover_view_chirho.leader_id_chirho.as_ref(),
        Some(&winner_node_chirho),
        "the historical winner is genuinely re-elected"
    );
    assert!(
        rollover_view_chirho.term_chirho > replacement_view_chirho.term_chirho
            && rollover_view_chirho.term_chirho > identity_chirho.winner_term_chirho,
        "the same winner must return at a strictly newer term"
    );

    let group_head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(&group_digest_chirho).unwrap();
    let group_head_before_chirho = authority_storage_chirho
        .read_all_chirho(&group_head_path_chirho)
        .unwrap()
        .expect("the historical fixed group head exists");
    let reconciliation_inventory_before_chirho = authority_storage_chirho
        .list_chirho(&StoragePathChirho::new_chirho("gd7-reconciliation-chirho"))
        .unwrap();

    let mut reopened_chirho = open_resident_gd7_held_coordinator_chirho(
        &canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        Arc::clone(&nodes_chirho[2]),
    )
    .expect("same-winner rollover restart reaches the historical checkpoint read-only");
    assert_eq!(
        reopened_chirho
            .bootstrap_chirho()
            .unwrap()
            .winner_term_chirho,
        identity_chirho.winner_term_chirho,
        "bootstrap reports the immutable historical term, not the live transport term"
    );
    assert_eq!(
        reopened_chirho.inspect_chirho().unwrap(),
        first_snapshot_chirho,
        "read-only inspection remains bound to the exact historical checkpoint"
    );

    let monitor_stop_chirho = Arc::new(AtomicBool::new(false));
    let mut monitor_chirho = reopened_chirho
        .start_fail_stop_monitor_chirho(Arc::clone(&monitor_stop_chirho), Duration::from_millis(5))
        .expect("held learner starts a continuous fail-stop monitor");
    std::thread::sleep(Duration::from_millis(40));
    assert!(
        !monitor_stop_chirho.load(Ordering::Acquire),
        "same-winner newer-term read-only observations must not stop the held actor"
    );

    let mutation_refusal_chirho = reopened_chirho
        .advance_one_page_chirho(checkpoint_ref_chirho.clone())
        .unwrap_err();
    assert_eq!(
        mutation_refusal_chirho,
        ResidentGd7HeldCoordinatorRefusalChirho::NewerWinnerTermWithoutRetainedBarrierChirho
    );
    let mutation_message_chirho = mutation_refusal_chirho.to_string();
    assert!(
        !mutation_message_chirho.contains("regressed")
            && !mutation_message_chirho.contains("different elected winner")
            && !mutation_message_chirho.contains("no elected winner"),
        "newer-term mutation refusal stays distinct from its election neighbours"
    );
    assert_eq!(
        authority_storage_chirho
            .read_all_chirho(&group_head_path_chirho)
            .unwrap()
            .unwrap(),
        group_head_before_chirho,
        "the fixed group head stays byte-exact when the strict mutation gate refuses"
    );
    assert_eq!(
        authority_storage_chirho
            .list_chirho(&StoragePathChirho::new_chirho("gd7-reconciliation-chirho"))
            .unwrap(),
        reconciliation_inventory_before_chirho,
        "no reconciliation checkpoint or page is minted behind the refusal"
    );

    drive_transfer_chirho(
        &nodes_chirho,
        winner_index_chirho,
        nodes_chirho[replacement_index_chirho].local_raft_id_chirho(),
    );
    for _attempt_chirho in 0..200 {
        if monitor_stop_chirho.load(Ordering::Acquire) {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        monitor_stop_chirho.load(Ordering::Acquire),
        "winner drift must stop the held process within the fixed test bound"
    );
    let monitor_error_chirho = monitor_chirho.close_chirho().unwrap_err().to_string();
    assert!(monitor_error_chirho.contains("different elected winner"));
    assert!(
        !monitor_error_chirho.contains("regressed")
            && !monitor_error_chirho.contains("no elected winner")
            && !monitor_error_chirho.contains("lacks an actor-owned retained barrier")
    );
    assert_eq!(
        reopened_chirho.inspect_chirho().unwrap_err(),
        ResidentGd7HeldCoordinatorRefusalChirho::WinnerNodeChangedChirho
    );
    reopened_chirho.close_chirho().unwrap();

    assert!(
        !nodes_chirho[2]
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "the held learner remains structurally non-electable"
    );
}

#[test]
fn held_coordinator_v4_restarts_mid_progression_and_verifies_exact_sealed_plan_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    // BORROWED rather than moved apart. This suite now continues past its own PlanSealed into the
    // ladder's adoption rungs, and `adopt_sealed_world_chirho` takes the whole world by reference —
    // so the world has to survive the destructure instead of being consumed by it.
    let world_chirho =
        build_observed_gd7_world_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    let ObservedGd7WorldChirho {
        ledger_config_chirho,
        canonical_root_chirho,
        group_chirho,
        group_digest_chirho,
        held_node_chirho,
        winner_node_chirho,
        nodes_chirho,
        winner_term_chirho,
        losing_journal_genesis_digest_chirho,
        identity_chirho,
        observation_import_chirho,
        unchanged_journal_bytes_chirho,
        signers_chirho,
        ..
    } = &world_chirho;

    // A verifier root backed by the held node's OWN control private key would let the held node
    // authenticate its own winner evidence. That refusal is this suite's claim, not a property of
    // the world, so it stays here rather than travelling into the builder.
    let mut control_collision_config_chirho = ledger_config_chirho.clone();
    control_collision_config_chirho
        .held_verifier_pins_chirho
        .as_mut()
        .expect("v4 carries held verifier roots")
        .journal_verifying_key_hex_chirho = held_node_chirho.0.clone();
    control_collision_config_chirho
        .validate_chirho()
        .expect("config-only validation cannot know the selected root control key");
    let control_collision_chirho = open_resident_gd7_held_coordinator_chirho(
        canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &control_collision_config_chirho,
        Arc::clone(&nodes_chirho[2]),
    )
    .err()
    .expect("held runtime rejects a verifier root backed by its control private key");
    assert!(control_collision_chirho
        .to_string()
        .contains("distinct from every GD7 control key"));

    let mut coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        ledger_config_chirho,
        Arc::clone(&nodes_chirho[2]),
    )
    .expect("schema v4 admits a no-head bootstrap under the retained writer lock");
    let bootstrap_chirho = coordinator_chirho.bootstrap_chirho().unwrap();
    assert_eq!(
        bootstrap_chirho.consistency_group_digest_chirho,
        *group_digest_chirho
    );
    assert_eq!(bootstrap_chirho.held_node_chirho, held_node_chirho.0);
    assert_eq!(bootstrap_chirho.winner_node_chirho, winner_node_chirho.0);
    assert_eq!(bootstrap_chirho.winner_term_chirho, *winner_term_chirho);
    assert_eq!(
        bootstrap_chirho.losing_journal_genesis_digest_chirho,
        *losing_journal_genesis_digest_chirho
    );
    assert!(bootstrap_chirho.active_checkpoint_ref_chirho.is_none());
    assert_eq!(
        coordinator_chirho.inspect_chirho().unwrap_err(),
        ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho
    );
    coordinator_chirho.close_chirho().unwrap();

    let mut reopened_chirho = open_resident_gd7_held_coordinator_chirho(
        canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        ledger_config_chirho,
        Arc::clone(&nodes_chirho[2]),
    )
    .expect("no-head bootstrap is restart-stable before observation import");
    assert_eq!(
        reopened_chirho.bootstrap_chirho().unwrap(),
        bootstrap_chirho
    );
    let observed_chirho = reopened_chirho
        .install_authenticated_observation_chirho(observation_import_chirho.clone())
        .expect("the held coordinator authenticates and installs the exact winner observation");
    assert_eq!(
        observed_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::ObservedHeldChirho
    );
    let stale_checkpoint_ref_chirho = observed_chirho.checkpoint_ref_chirho.clone();
    let first_progress_chirho = reopened_chirho
        .advance_one_page_chirho(stale_checkpoint_ref_chirho.clone())
        .expect("one command advances at most one bounded manifest page");
    assert_ne!(
        first_progress_chirho.checkpoint_ref_chirho,
        stale_checkpoint_ref_chirho
    );
    assert_eq!(
        reopened_chirho
            .advance_one_page_chirho(stale_checkpoint_ref_chirho)
            .unwrap_err(),
        ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChangedIdentityChirho
    );
    reopened_chirho.close_chirho().unwrap();

    let mut progressing_chirho = open_resident_gd7_held_coordinator_chirho(
        canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        ledger_config_chirho,
        Arc::clone(&nodes_chirho[2]),
    )
    .expect("restart reloads the exact in-progress checkpoint");
    assert_eq!(
        progressing_chirho.inspect_chirho().unwrap(),
        first_progress_chirho
    );
    let mut current_chirho = first_progress_chirho;
    for _page_chirho in 0..16 {
        if current_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::PlanSealedChirho {
            break;
        }
        current_chirho = progressing_chirho
            .advance_one_page_chirho(current_chirho.checkpoint_ref_chirho.clone())
            .expect("each command advances exactly one bounded reconciliation page");
    }
    assert_eq!(
        current_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho
    );
    let sealed_chirho = progressing_chirho
        .verify_sealed_plan_chirho(current_chirho.checkpoint_ref_chirho.clone())
        .expect("the exact immutable plan chain re-verifies after sealing");
    assert_eq!(
        sealed_chirho.checkpoint_ref_chirho,
        current_chirho.checkpoint_ref_chirho
    );
    assert_eq!(sealed_chirho.winner_term_chirho, *winner_term_chirho);
    assert!(sealed_chirho.plan_page_count_chirho > 0);
    assert!(sealed_chirho.manifest_record_count_chirho > 0);
    assert_eq!(
        std::fs::read(
            canonical_root_chirho
                .join(&ledger_config_chirho.storage_namespace_chirho)
                .join(&ledger_config_chirho.journal_path_chirho)
        )
        .unwrap(),
        *unchanged_journal_bytes_chirho,
        "reconciliation evidence may progress without appending or adopting the losing journal"
    );
    assert!(
        !nodes_chirho[2]
            .leadership_chirho(group_chirho)
            .is_leader_chirho,
        "the held learner remains non-electable after PlanSealed"
    );
    progressing_chirho.close_chirho().unwrap();

    let provider_fixture_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let verified_losing_tail_chirho = provider_fixture_chirho
        .verified_losing_tail_chirho()
        .expect("the public losing-journal reader verifies the exact current tail");
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(canonical_root_chirho).unwrap();
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(NodeIdChirho(winner_node_chirho.0.clone()))
            .unwrap();
    let wrong_key_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(NodeIdChirho(held_node_chirho.0.clone())).unwrap();
    assert!(
        Gd7WinnerWitnessReaderChirho::new_chirho(
            &authority_storage_chirho,
            &wrong_key_verifier_chirho,
            signers_chirho.journal_signer_chirho(),
        )
        .load_authenticated_deposed_fork_observation_chirho(
            identity_chirho,
            &provider_fixture_chirho
                .verified_losing_tail_chirho()
                .unwrap(),
        )
        .is_err(),
        "a wrong control key must refuse the observation"
    );
    let witness_path_chirho = winner_fork_witness_path_chirho(
        &gd7_reconciliation_identity_digest_chirho(identity_chirho).unwrap(),
    )
    .unwrap();
    let witness_bytes_before_chirho = authority_storage_chirho
        .read_all_chirho(&witness_path_chirho)
        .unwrap()
        .expect("the imported witness object exists at its exact address");
    let mut tampered_witness_bytes_chirho = witness_bytes_before_chirho.clone();
    let tamper_index_chirho = tampered_witness_bytes_chirho
        .iter()
        .position(|byte_chirho| *byte_chirho != b' ')
        .expect("the signed witness has mutable test bytes");
    tampered_witness_bytes_chirho[tamper_index_chirho] ^= 1;
    assert_ne!(tampered_witness_bytes_chirho, witness_bytes_before_chirho);
    authority_storage_chirho
        .atomic_write_chirho(&witness_path_chirho, &tampered_witness_bytes_chirho)
        .unwrap();
    assert!(
        Gd7WinnerWitnessReaderChirho::new_chirho(
            &authority_storage_chirho,
            &winner_verifier_chirho,
            signers_chirho.journal_signer_chirho(),
        )
        .load_authenticated_deposed_fork_observation_chirho(
            identity_chirho,
            &verified_losing_tail_chirho,
        )
        .is_err(),
        "a tampered stored witness must refuse through the public loader"
    );
    authority_storage_chirho
        .atomic_write_chirho(&witness_path_chirho, &witness_bytes_before_chirho)
        .unwrap();
    assert_eq!(
        authority_storage_chirho
            .read_all_chirho(&witness_path_chirho)
            .unwrap()
            .unwrap(),
        witness_bytes_before_chirho,
        "the mutation arm restores the witness byte-for-byte"
    );
    let authenticated_observation_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &authority_storage_chirho,
        &winner_verifier_chirho,
        signers_chirho.journal_signer_chirho(),
    )
    .load_authenticated_deposed_fork_observation_chirho(
        identity_chirho,
        &verified_losing_tail_chirho,
    )
    .expect("the public observation loader re-verifies the installed signed witness objects");
    assert_eq!(
        authenticated_observation_chirho
            .identity_chirho()
            .winner_term_chirho,
        *winner_term_chirho
    );
    let absent_provider_actor_chirho = open_resident_effect_journal_handle_chirho(
        canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        ledger_config_chirho,
        None,
    )
    .expect("the production-shaped opener accepts an explicitly absent provider");
    let absent_provider_refusal_chirho = absent_provider_actor_chirho
        .converge_and_certify_gd7_chirho(
            &authenticated_observation_chirho,
            &current_chirho.checkpoint_ref_chirho,
            Gd7ConvergenceBindingInputChirho {
                adopted_checkpoint_ref_chirho: current_chirho.checkpoint_ref_chirho.clone(),
            },
            Gd7ConvergenceUnmeasuredPredicatesChirho {
                winner_view_matches_chirho: true,
            },
        )
        .expect_err("the absent production provider must refuse before convergence");
    assert!(format!("{absent_provider_refusal_chirho:?}")
        .contains("ConservationSnapshotUnavailableChirho"));
    drop(absent_provider_actor_chirho);
    let provider_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let actor_chirho = open_resident_effect_journal_handle_chirho(
        canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        ledger_config_chirho,
        Some(Arc::new(provider_chirho)),
    )
    .expect("the resident actor opens with the explicitly injected provider");
    let advance_refusal_chirho = actor_chirho
        .advance_gd7_sink_term_chirho(
            &authenticated_observation_chirho,
            &current_chirho.checkpoint_ref_chirho,
        )
        .expect_err("a sealed but not adopted checkpoint must refuse the lawful advance");
    assert!(
        format!("{advance_refusal_chirho:?}").contains("Adopted"),
        "the real mailbox must identify the missing adoption phase: {advance_refusal_chirho:?}"
    );

    // ---- THE OBLIGATION REACHES A LAWFUL TERMINAL OUTCOME, and only then does convergence hold ----
    //
    // WHAT THIS SUITE CLAIMS, stated because the addition could be misread as a scope change: its
    // subject is still the RESTART-RESILIENCE of the held coordinator's progression, proven above by
    // the bootstrap/reopen and in-progress/reopen probes on unchanged bytes. Convergence is the
    // terminal read that suite has always ended on; it could not hold while the sealed plan carried
    // an obligation with no terminal outcome, and it refused BY THAT REASON
    // (`UnconvergedObligationChirho`) rather than by anything about restarts.
    //
    // WHICH lawful terminal the obligation reaches is incidental to the restart claim, and DISPOSAL
    // is real production behaviour: B3B-INT-1's design counts a roster-verified operator disposition
    // as terminal, checked at read time. The COMPENSATED terminal — adopt -> advance -> release ->
    // fenced append -> complete, carrying a journal receipt — belongs to the capstone's own test and
    // must never be satisfied by this path.
    //
    // ORDER MATTERS AND IS NOT INCIDENTAL: the adoption happens HERE, after the advance-refusal arm
    // above, because that arm's whole premise is a checkpoint that is sealed and NOT adopted.
    // Adopting earlier would leave the arm green while measuring nothing.
    drop(actor_chirho);
    let adopted_chirho = super::harness1_success_ladder_tests_chirho::adopt_sealed_world_chirho(
        &world_chirho,
        &mut fixture_chirho,
        &sealed_chirho,
    );
    assert!(
        adopted_chirho.effect_obligation_count_chirho > 0,
        "the sealed plan carries NO effect obligation, so there is nothing to drive to a terminal \
         outcome and the convergence below would be green by EMPTINESS rather than by disposal"
    );
    let minted_chirho = {
        let mut minting_coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
            canonical_root_chirho,
            &fixture_chirho.config_path_chirho,
            &adopted_chirho.ledger_config_chirho,
            Arc::clone(&adopted_chirho.held_elector_chirho),
        )
        .expect("the held coordinator reopens on its own adopted world");
        let minted_chirho = minting_coordinator_chirho
            .mint_losing_effect_obligation_chirho(
                cairn_ledger_host_chirho::reconciliation_chirho::Gd7LosingEffectObligationSelectorChirho::new_chirho(
                    adopted_chirho.sealed_plan_ref_chirho.clone(),
                    0,
                )
                .expect("a lower-hex plan page ref and a zero index are a well-formed selector"),
            )
            .expect("the adopted held coordinator mints the exact selected obligation");
        minting_coordinator_chirho.close_chirho().unwrap();
        minted_chirho
    };
    // Read before the move: the receipt is affine and is consumed by the tail driver below.
    let expected_mint_identity_chirho = minted_chirho.mint_identity_digest_chirho().to_owned();
    let disposal_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(canonical_root_chirho)
            .expect("the held root's own storage opens");
    let roster_signer_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(canonical_root_chirho, held_node_chirho)
            .expect("the held root's own key custody opens");
    // THE OPERATOR IS THE WINNER ROOT'S PRINCIPAL. The held root cannot produce this signature.
    let operator_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &adopted_chirho.winner_source_root_chirho,
        winner_node_chirho,
    )
    .expect("the winner root's own key custody opens as the operator principal");
    let provider_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let actor_chirho = open_resident_effect_journal_handle_chirho(
        canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &adopted_chirho.ledger_config_chirho,
        Some(Arc::new(provider_chirho)),
    )
    .expect("the resident actor reopens with the explicitly injected provider");

    // THE NEGATIVE CONTROL, and it is the whole reason this suite's green can be trusted.
    //
    // Before the disposition, the SAME convergence call on the SAME world must refuse — and refuse
    // by naming THIS MINT IDENTITY. Without this arm, a later green would be equally consistent with
    // "the disposition converged the obligation" and with "the obligation stopped being enumerated",
    // and the second is green by POPULATION CHANGE: the classifier finding nothing to object to
    // rather than finding a satisfied terminal. Naming the digest is what distinguishes them.
    let unconverged_refusal_chirho = actor_chirho
        .converge_and_certify_gd7_chirho(
            &authenticated_observation_chirho,
            &adopted_chirho.adopted_checkpoint_ref_chirho,
            Gd7ConvergenceBindingInputChirho {
                adopted_checkpoint_ref_chirho: adopted_chirho.adopted_checkpoint_ref_chirho.clone(),
            },
            Gd7ConvergenceUnmeasuredPredicatesChirho {
                winner_view_matches_chirho: true,
            },
        )
        .expect_err("an undisposed obligation must block convergence");
    let unconverged_text_chirho = format!("{unconverged_refusal_chirho:?}");
    assert!(
        unconverged_text_chirho.contains("UnconvergedObligationChirho")
            && unconverged_text_chirho.contains(&expected_mint_identity_chirho),
        "convergence must refuse by naming THIS obligation. A refusal for any other reason means \
         the arm below would prove nothing about disposal: {unconverged_text_chirho}"
    );

    let disposed_chirho =
        super::harness1_obligation_tail_arms_chirho::drive_minted_obligation_to_disposal_chirho(
            &actor_chirho,
            &disposal_storage_chirho,
            minted_chirho,
            &adopted_chirho.group_digest_chirho,
            &roster_signer_chirho,
            &held_node_chirho.0,
            &operator_signer_chirho,
            &winner_node_chirho.0,
        );

    let certificate_chirho = actor_chirho
        .converge_and_certify_gd7_chirho(
            &authenticated_observation_chirho,
            &adopted_chirho.adopted_checkpoint_ref_chirho,
            Gd7ConvergenceBindingInputChirho {
                adopted_checkpoint_ref_chirho: adopted_chirho.adopted_checkpoint_ref_chirho.clone(),
            },
            Gd7ConvergenceUnmeasuredPredicatesChirho {
                winner_view_matches_chirho: true,
            },
        )
        .expect("the real mailbox converges the sealed fixture through the injected provider");
    let certificate_verifier_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(canonical_root_chirho, held_node_chirho)
            .expect("open the held control verifier used by the certificate loader");
    verify_signed_gd7_converged_read_replica_chirho(
        &certificate_chirho,
        &certificate_verifier_chirho,
    )
    .expect("the certificate must verify through the same signed loader used by D4");
    let non_converged_chirho = actor_chirho
        .converge_and_certify_gd7_chirho(
            &authenticated_observation_chirho,
            &adopted_chirho.adopted_checkpoint_ref_chirho,
            Gd7ConvergenceBindingInputChirho {
                adopted_checkpoint_ref_chirho: adopted_chirho.adopted_checkpoint_ref_chirho.clone(),
            },
            Gd7ConvergenceUnmeasuredPredicatesChirho {
                winner_view_matches_chirho: false,
            },
        )
        .expect_err("a non-converged world must refuse through the mailbox");
    assert!(format!("{non_converged_chirho:?}").contains("InvalidPageShapeChirho"));
    assert_eq!(
        certificate_chirho.schema_chirho(),
        "gd7-converged-read-replica-v2-chirho"
    );
    assert!(!certificate_chirho.certificate_sig_chirho().is_empty());
    // THE CAUSE, ASSERTED RATHER THAN INFERRED. `(completed, disposed)` — exactly zero completed and
    // exactly one disposed. The `1` is the classifier reporting that it SAW this suite's disposed
    // row, which is what makes the green above an effect of the disposition rather than of an empty
    // population. The `0` is the other half: disposal must never launder itself into the COMPLETED
    // bucket, because that bucket is the capstone's claim and a compensated obligation is a
    // materially different thing from an operator-retired one.
    assert_eq!(
        certificate_chirho.verified_v2_counts_chirho().unwrap(),
        (0, 1),
        "the certificate must count one DISPOSED obligation and zero COMPLETED ones"
    );
    assert_eq!(
        disposed_chirho.mint_identity_digest_chirho, expected_mint_identity_chirho,
        "the row that was disposed must be the one convergence named as unconverged"
    );
    drop(actor_chirho);
}

/// THE CONVERGER'S TWO-COORDINATE CONTRACT, armed where a caller can reach it.
///
/// The fix this pins: after adoption the plan proof is taken at S (the sealed cut the adoption
/// names) while the certificate's `adopted_checkpoint_ref` stays A (the active adopted cut). These
/// arms exist because S is now REACHED THROUGH A, and a pointer that is followed must be
/// authenticated at every step a forger could reach.
///
/// # WHAT IS UNBUILDABLE HERE, and why that is the fix rather than a gap
///
/// A FORGED CALLER-SUPPLIED S is unrepresentable, not merely refused. The caller passes only the
/// ACTIVE checkpoint ref and the binding's adopted ref; S is read from the adoption binding INSIDE
/// the authenticated active checkpoint. There is no caller-supplied S to validate and therefore
/// none to get wrong — the same shape the mint's selector has, and for the same reason.
///
/// # MIGRATION PATH
///
/// If the baseline convergence fails, the two-coordinate resolution regressed and the refusal names
/// which coordinate. If a TAMPER arm stops refusing, an authentication step on the A -> S path was
/// dropped and this file names which one.
#[test]
fn converger_authenticates_every_step_of_the_adopted_to_sealed_coordinate_path_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let world_chirho =
        build_observed_gd7_world_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    let mut coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        &world_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &world_chirho.ledger_config_chirho,
        Arc::clone(&world_chirho.nodes_chirho[2]),
    )
    .expect("the held coordinator opens on the observed world");
    let mut current_chirho = coordinator_chirho
        .install_authenticated_observation_chirho(world_chirho.observation_import_chirho.clone())
        .expect("the exact winner observation installs");
    for _page_chirho in 0..16 {
        if current_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::PlanSealedChirho {
            break;
        }
        current_chirho = coordinator_chirho
            .advance_one_page_chirho(current_chirho.checkpoint_ref_chirho.clone())
            .expect("each command advances exactly one bounded page");
    }
    let sealed_chirho = coordinator_chirho
        .verify_sealed_plan_chirho(current_chirho.checkpoint_ref_chirho.clone())
        .expect("the sealed plan chain re-verifies");
    let sealed_checkpoint_ref_chirho = sealed_chirho.checkpoint_ref_chirho.clone();
    coordinator_chirho.close_chirho().unwrap();

    let adopted_chirho = super::harness1_success_ladder_tests_chirho::adopt_sealed_world_chirho(
        &world_chirho,
        &mut fixture_chirho,
        &sealed_chirho,
    );
    // ARM (a), the premise every other arm below stands on: the two coordinates really are
    // DIFFERENT. On a world where S == A this whole contract would be vacuous and every tamper arm
    // would be planting against the same object twice.
    assert_ne!(
        adopted_chirho.adopted_checkpoint_ref_chirho, sealed_checkpoint_ref_chirho,
        "adoption must advance the active checkpoint, or S and A are the same cut and this suite \
         proves nothing about resolving one from the other"
    );

    let minted_chirho = {
        let mut minting_chirho = open_resident_gd7_held_coordinator_chirho(
            &world_chirho.canonical_root_chirho,
            &fixture_chirho.config_path_chirho,
            &adopted_chirho.ledger_config_chirho,
            Arc::clone(&adopted_chirho.held_elector_chirho),
        )
        .expect("the held coordinator reopens on the adopted world");
        let minted_chirho = minting_chirho
            .mint_losing_effect_obligation_chirho(
                cairn_ledger_host_chirho::reconciliation_chirho::Gd7LosingEffectObligationSelectorChirho::new_chirho(
                    adopted_chirho.sealed_plan_ref_chirho.clone(),
                    0,
                )
                .expect("a well-formed selector"),
            )
            .expect("the adopted held coordinator mints the selected obligation");
        minting_chirho.close_chirho().unwrap();
        minted_chirho
    };

    let provider_fixture_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let verified_losing_tail_chirho = provider_fixture_chirho
        .verified_losing_tail_chirho()
        .expect("the public losing-journal reader verifies the tail");
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&world_chirho.canonical_root_chirho).unwrap();
    let winner_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(NodeIdChirho(
        world_chirho.winner_node_chirho.0.clone(),
    ))
    .unwrap();
    let authenticated_observation_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &authority_storage_chirho,
        &winner_verifier_chirho,
        world_chirho.signers_chirho.journal_signer_chirho(),
    )
    .load_authenticated_deposed_fork_observation_chirho(
        &world_chirho.identity_chirho,
        &verified_losing_tail_chirho,
    )
    .expect("the public observation loader re-verifies the installed witness objects");

    let actor_chirho = open_resident_effect_journal_handle_chirho(
        &world_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &adopted_chirho.ledger_config_chirho,
        Some(Arc::new(
            super::harness1_conservation_provider_tests_chirho::
                RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho),
        )),
    )
    .expect("the resident actor opens with the injected conservation provider");
    let roster_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &world_chirho.canonical_root_chirho,
        &world_chirho.held_node_chirho,
    )
    .expect("the held root's own custody opens");
    let operator_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &adopted_chirho.winner_source_root_chirho,
        &world_chirho.winner_node_chirho,
    )
    .expect("the winner root's own custody opens as the operator");
    super::harness1_obligation_tail_arms_chirho::drive_minted_obligation_to_disposal_chirho(
        &actor_chirho,
        &authority_storage_chirho,
        minted_chirho,
        &adopted_chirho.group_digest_chirho,
        &roster_signer_chirho,
        &world_chirho.held_node_chirho.0,
        &operator_signer_chirho,
        &world_chirho.winner_node_chirho.0,
    );

    let converge_chirho =
        |actor_chirho: &cairn_ledger_host_chirho::ResidentEffectJournalHandleChirho,
         active_ref_chirho: &str| {
            actor_chirho.converge_and_certify_gd7_chirho(
                &authenticated_observation_chirho,
                active_ref_chirho,
                Gd7ConvergenceBindingInputChirho {
                    adopted_checkpoint_ref_chirho: adopted_chirho
                        .adopted_checkpoint_ref_chirho
                        .clone(),
                },
                Gd7ConvergenceUnmeasuredPredicatesChirho {
                    winner_view_matches_chirho: true,
                },
            )
        };

    // BASELINE, and it is the positive control for all three tamper arms below: without it a
    // refusal proves only that SOMETHING is wrong, never that the tamper caused it.
    assert_eq!(
        converge_chirho(&actor_chirho, &adopted_chirho.adopted_checkpoint_ref_chirho)
            .expect("the two-coordinate resolution certifies the disposed population")
            .verified_v2_counts_chirho()
            .unwrap(),
        (0, 1),
        "the baseline must certify exactly one DISPOSED and zero COMPLETED"
    );

    // ---- ARM (d): REF SUBSTITUTION. Naming S where the ACTIVE cut is required must refuse. ----
    // The staleness guard is what stops a caller pointing the converger at a superseded cut of its
    // own choosing, and admitting the adopted phase must not have loosened it.
    assert!(
        format!(
            "{:?}",
            converge_chirho(&actor_chirho, &sealed_checkpoint_ref_chirho)
                .expect_err("naming the superseded sealed cut as the active one must refuse")
        )
        .contains("StaleCheckpointChirho"),
        "substituting S for A must refuse BY STALENESS -- if this ever refuses for another reason \
         the caller can no longer tell 'you named an old cut' from 'the world is inconsistent'"
    );

    // ---- ARM (b): TAMPER S ITSELF. The cut reached THROUGH A must still authenticate. ----
    // S is now loaded by ref rather than read from the active head, so its own signature check is
    // the only thing standing between a forger and the population the certificate counts.
    let sealed_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&sealed_checkpoint_ref_chirho).unwrap();
    let sealed_bytes_before_chirho = authority_storage_chirho
        .read_all_chirho(&sealed_path_chirho)
        .unwrap()
        .expect("the sealed checkpoint exists at its exact address");
    let mut tampered_sealed_chirho = sealed_bytes_before_chirho.clone();
    let tamper_index_chirho = tampered_sealed_chirho
        .iter()
        .position(|byte_chirho| *byte_chirho != b' ')
        .expect("the signed checkpoint has mutable test bytes");
    tampered_sealed_chirho[tamper_index_chirho] ^= 1;
    assert_ne!(tampered_sealed_chirho, sealed_bytes_before_chirho);
    authority_storage_chirho
        .atomic_write_chirho(&sealed_path_chirho, &tampered_sealed_chirho)
        .unwrap();
    let tampered_refusal_chirho = format!(
        "{:?}",
        converge_chirho(&actor_chirho, &adopted_chirho.adopted_checkpoint_ref_chirho)
            .expect_err("a tampered sealed checkpoint must refuse")
    );
    assert!(
        !tampered_refusal_chirho.contains("UnconvergedObligation"),
        "a TAMPERED S must not be reported as an unconverged obligation -- that would tell an \
         operator to go dispose a row when the real fault is a forged plan cut: \
         {tampered_refusal_chirho}"
    );
    authority_storage_chirho
        .atomic_write_chirho(&sealed_path_chirho, &sealed_bytes_before_chirho)
        .unwrap();
    assert_eq!(
        authority_storage_chirho
            .read_all_chirho(&sealed_path_chirho)
            .unwrap()
            .unwrap(),
        sealed_bytes_before_chirho,
        "the tamper arm restores S byte-for-byte"
    );
    // POSITIVE CONTROL: without it, "the tamper refused" is equally consistent with "everything
    // refuses from here on", and the restore above would be unproven.
    assert!(
        converge_chirho(&actor_chirho, &adopted_chirho.adopted_checkpoint_ref_chirho).is_ok(),
        "convergence must certify again once S is restored"
    );

    // ---- ARM (c): BREAK THE A -> S RELATION WITH A GENUINELY VALID SIGNATURE. ----
    // THE SHARP ONE. Everything a signature check can see is correct: this checkpoint is signed by
    // the real held custody and the head naming it is signed too. Only the RELATION is wrong -- it
    // claims a predecessor that is not the sealed cut it was adopted from. If the refusal here were
    // a signature refusal, the arm would be green while the relation went unchecked.
    let active_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&adopted_chirho.adopted_checkpoint_ref_chirho)
            .unwrap();
    let head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(&adopted_chirho.group_digest_chirho).unwrap();
    let head_bytes_before_chirho = authority_storage_chirho
        .read_all_chirho(&head_path_chirho)
        .unwrap()
        .expect("the group head exists");
    let mut relocated_chirho: Gd7ReconciliationCheckpointChirho = serde_json::from_slice(
        &authority_storage_chirho
            .read_all_chirho(&active_path_chirho)
            .unwrap()
            .expect("the adopted checkpoint exists"),
    )
    .unwrap();
    relocated_chirho.state_chirho.previous_checkpoint_ref_chirho = Some("b".repeat(64));
    let (relocated_ref_chirho, relocated_bytes_chirho) =
        sign_checkpoint_chirho(relocated_chirho, &roster_signer_chirho);
    authority_storage_chirho
        .atomic_write_chirho(
            &gd7_reconciliation_checkpoint_path_chirho(&relocated_ref_chirho).unwrap(),
            &relocated_bytes_chirho,
        )
        .unwrap();
    let mut relocated_head_chirho: Gd7ReconciliationHeadChirho =
        serde_json::from_slice(&head_bytes_before_chirho).unwrap();
    relocated_head_chirho.active_checkpoint_ref_chirho = relocated_ref_chirho.clone();
    authority_storage_chirho
        .atomic_write_chirho(
            &head_path_chirho,
            &sign_head_chirho(relocated_head_chirho, &roster_signer_chirho),
        )
        .unwrap();
    let relation_refusal_chirho = format!(
        "{:?}",
        converge_chirho(&actor_chirho, &relocated_ref_chirho)
            .expect_err("an adopted cut whose predecessor is not the sealed cut must refuse")
    );
    // WHAT THIS ARM PINS, and what it HONESTLY DOES NOT.
    //
    // PINNED: a substituted adopted cut cannot certify. That is the security property, and it holds.
    //
    // NOT ISOLATED, recorded rather than dressed up: the refusal arrives as
    // `StoreChirho(MalformedCheckpointChirho)` from the store's OWN checkpoint validation, BEFORE
    // the `A.previous == S` relation check in the converger is reached. So this arm proves the
    // forged cut is refused; it does NOT prove the relation check is what refused it. The relation
    // check is therefore DEFENCE IN DEPTH that no arm here isolates -- a survivor, named at the
    // assertion instead of counted as a pass. Isolating it needs a forged checkpoint the store
    // accepts as well-formed, which this fixture could not produce.
    assert!(
        !relation_refusal_chirho.contains("UnconvergedObligation"),
        "a substituted adopted cut must never be reported as an unconverged obligation -- that \
         would send an operator to dispose a row when the real fault is a forged cut: \
         {relation_refusal_chirho}"
    );
    authority_storage_chirho
        .atomic_write_chirho(&head_path_chirho, &head_bytes_before_chirho)
        .unwrap();
    assert!(
        converge_chirho(&actor_chirho, &adopted_chirho.adopted_checkpoint_ref_chirho).is_ok(),
        "restoring the honest head must restore certification"
    );

    drop(actor_chirho);
}
