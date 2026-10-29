// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::tests_chirho::{
    commit_prefix_chirho, manifest_for_record_chirho, residency_chirho,
    RecoveryManifestBindingChirho, TestCanonicalHistorySourceChirho,
};
use super::{
    LedgerMirrorRecoveryHeadReceiptChirho, LedgerMirrorVerifiedPrefixPageChirho,
    ProductionLedgerMirrorRecoveryInputChirho, ProductionLedgerMirrorRecoveryPortChirho,
};
use crate::client_chirho::LedgerMirrorDirectoryChirho;
use crate::family_chirho::LedgerMirrorRecordChirho;
use crate::server_chirho::{ledger_mirror_router_chirho, LedgerMirrorServerStateChirho};
use crate::store_chirho::{
    LedgerMirrorBootstrapCommitPreparationChirho, LedgerMirrorBootstrapHeadChirho,
    LedgerMirrorFollowerStoreChirho, LedgerMirrorHighWaterChirho, LedgerMirrorHighWaterInputChirho,
    LedgerMirrorPrepareOutcomeChirho,
};
use crate::tests_chirho::{
    election_observation_chirho, journal_verifier_chirho, placement_revision_fixture_chirho,
    placement_successor_fixture_chirho, prepare_frame_chirho, recovery_journal_fixture_chirho,
    FixedElectionViewChirho, RunningMirrorServerChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::LedgerMirrorRecoveryPortChirho;
use cairn_mirror_chirho::{join_mirror_view_chirho, MirrorLeadershipViewChirho};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

const PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
const UNRELATED_ASSIGNMENT_DIGEST_CHIRHO: &str =
    "5555555555555555555555555555555555555555555555555555555555555555";
const R1_ASSIGNMENT_DIGEST_CHIRHO: &str =
    "7777777777777777777777777777777777777777777777777777777777777777";
const PREDECESSOR_VIEW_DIGEST_CHIRHO: &str =
    "6666666666666666666666666666666666666666666666666666666666666666";

struct LiveHeadBindingChirho<'binding_chirho> {
    leader_root_chirho: &'binding_chirho Path,
    leader_node_id_chirho: &'binding_chirho str,
    holder_root_chirho: &'binding_chirho Path,
    holder_node_id_chirho: &'binding_chirho str,
    assigned_node_ids_chirho: [String; 3],
    consistency_group_digest_chirho: &'binding_chirho str,
    assignment_digest_chirho: &'binding_chirho str,
    membership_view_digest_chirho: &'binding_chirho str,
    expected_term_chirho: u64,
}

fn commit_live_head_chirho(
    store_chirho: &LedgerMirrorFollowerStoreChirho,
    binding_chirho: LiveHeadBindingChirho<'_>,
    record_chirho: &LedgerMirrorRecordChirho,
) {
    let prepare_chirho = prepare_frame_chirho(
        binding_chirho.leader_root_chirho,
        binding_chirho.leader_node_id_chirho,
        binding_chirho.holder_node_id_chirho,
        binding_chirho.expected_term_chirho,
        binding_chirho.consistency_group_digest_chirho,
        binding_chirho.membership_view_digest_chirho,
        record_chirho.clone(),
    );
    assert!(matches!(
        store_chirho
            .prepare_chirho(prepare_chirho.clone(), record_chirho.clone())
            .expect("prepare predecessor live head"),
        LedgerMirrorPrepareOutcomeChirho::PreparedChirho
    ));
    let high_water_chirho = LedgerMirrorHighWaterChirho::sign_chirho(
        LedgerMirrorHighWaterInputChirho {
            consistency_group_digest_chirho: binding_chirho
                .consistency_group_digest_chirho
                .to_string(),
            origin_leader_node_id_chirho: binding_chirho.leader_node_id_chirho.to_string(),
            holder_node_id_chirho: binding_chirho.holder_node_id_chirho.to_string(),
            assignment_digest_chirho: binding_chirho.assignment_digest_chirho.to_string(),
            assigned_node_ids_chirho: binding_chirho.assigned_node_ids_chirho,
            membership_view_digest_chirho: binding_chirho.membership_view_digest_chirho.to_string(),
            historical_term_chirho: binding_chirho.expected_term_chirho,
            mirror_closure_id_chirho: prepare_chirho.mirror_closure_id_chirho().to_string(),
            prepare_frame_digest_chirho: prepare_chirho.prepare_frame_digest_chirho().to_string(),
            caller_idempotency_key_digest_chirho: prepare_chirho
                .caller_idempotency_key_digest_chirho()
                .to_string(),
            record_chirho: record_chirho.clone(),
        },
        binding_chirho.holder_root_chirho,
    )
    .expect("sign predecessor live high-water");
    store_chirho
        .finalize_chirho(
            prepare_chirho.prepare_frame_digest_chirho(),
            record_chirho,
            &high_water_chirho,
        )
        .expect("finalize predecessor live high-water");
}

#[test]
fn contiguous_successor_recovers_from_its_signed_predecessor_assignment_chirho() {
    let placement_fixture_chirho =
        placement_successor_fixture_chirho(PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO);
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let historical_leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let adopter_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let remote_holder_chirho = &placement_fixture_chirho.serving_nodes_chirho[2];
    assert_ne!(
        placement_fixture_chirho
            .placement_chirho
            .assignment_digest_chirho(),
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO
    );

    let local_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &adopter_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        local_election_chirho.as_ref(),
    )
    .expect("join successor placement and election");
    let assigned_node_ids_chirho: [String; 3] = placement_fixture_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("three assigned successor nodes");
    let local_store_root_chirho = tempfile::tempdir().expect("local successor holder store");
    let local_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            local_store_root_chirho.path(),
            adopter_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open local successor holder store"),
    );
    commit_live_head_chirho(
        &local_store_chirho,
        LiveHeadBindingChirho {
            leader_root_chirho: historical_leader_chirho.root_chirho(),
            leader_node_id_chirho: &historical_leader_chirho.node_id_chirho,
            holder_root_chirho: adopter_chirho.root_chirho(),
            holder_node_id_chirho: &adopter_chirho.node_id_chirho,
            assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO,
            membership_view_digest_chirho: PREDECESSOR_VIEW_DIGEST_CHIRHO,
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
    );

    let remote_store_root_chirho = tempfile::tempdir().expect("remote successor holder store");
    let remote_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            remote_store_root_chirho.path(),
            remote_holder_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open remote successor holder store"),
    );
    commit_live_head_chirho(
        &remote_store_chirho,
        LiveHeadBindingChirho {
            leader_root_chirho: historical_leader_chirho.root_chirho(),
            leader_node_id_chirho: &historical_leader_chirho.node_id_chirho,
            holder_root_chirho: remote_holder_chirho.root_chirho(),
            holder_node_id_chirho: &remote_holder_chirho.node_id_chirho,
            assigned_node_ids_chirho,
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO,
            membership_view_digest_chirho: PREDECESSOR_VIEW_DIGEST_CHIRHO,
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
    );
    let remote_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &adopter_chirho.node_id_chirho,
                false,
            ),
        });
    let remote_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        remote_holder_chirho.node_id_chirho.clone(),
        remote_holder_chirho.root_chirho().to_path_buf(),
        Arc::clone(&placement_fixture_chirho.placement_chirho),
        remote_election_chirho,
        residency_chirho(&placement_fixture_chirho.placement_chirho),
        remote_store_chirho,
    )
    .expect("compose remote successor holder");
    let remote_server_chirho =
        RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(remote_state_chirho));
    let recovery_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: adopter_chirho.node_id_chirho.clone(),
            sign_root_chirho: adopter_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&placement_fixture_chirho.placement_chirho),
            election_view_chirho: local_election_chirho,
            residency_chirho: residency_chirho(&placement_fixture_chirho.placement_chirho),
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
                remote_holder_chirho.node_id_chirho.clone(),
                remote_server_chirho.endpoint_chirho.clone(),
            )])),
            follower_store_chirho: Arc::clone(&local_store_chirho),
        },
    );

    let canonical_source_chirho = TestCanonicalHistorySourceChirho {
        anchor_mismatch_chirho: false,
    };
    let candidate_chirho = recovery_chirho
        .select_recovery_candidate_chirho(
            &journal_fixture_chirho.local_tail_chirho,
            &canonical_source_chirho,
        )
        .expect("the signed immediate predecessor remains recovery-authorized")
        .expect("the predecessor heads are ahead of the local journal");
    assert_eq!(
        candidate_chirho.assignment_digest_chirho(),
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO
    );
    recovery_chirho
        .revalidate_recovery_authority_chirho(&candidate_chirho)
        .expect("current successor authority revalidates its predecessor candidate");
    let record_bytes_chirho = recovery_chirho
        .read_recovery_record_chirho(
            &candidate_chirho,
            candidate_chirho.tail_seq_chirho(),
            candidate_chirho.tail_record_digest_chirho(),
        )
        .expect("candidate record reads retain the same predecessor assignment authority");
    let expected_bytes_chirho = journal_fixture_chirho
        .source_record_chirho
        .canonical_record_line_chirho
        .as_bytes()
        .to_vec();
    assert_eq!(record_bytes_chirho, expected_bytes_chirho);
    recovery_chirho
        .ensure_verified_prefix_bootstrapped_chirho(
            &journal_fixture_chirho.local_tail_chirho,
            &canonical_source_chirho,
        )
        .expect("current holders may prove the exact prefix through predecessor live heads");
    let selected_source_chirho = local_store_chirho
        .load_recovery_source_head_chirho()
        .expect("load post-bootstrap source head")
        .expect("post-bootstrap source head exists");
    let selected_receipt_chirho =
        LedgerMirrorRecoveryHeadReceiptChirho::sign_from_source_head_chirho(
            &selected_source_chirho,
            adopter_chirho.root_chirho(),
        )
        .expect("sign the source selected by current-holder verification");
    assert_eq!(
        selected_receipt_chirho.assignment_digest_chirho(),
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO,
        "equal-sequence live high-water remains the positive control for the fifth gate"
    );

    let r2_placement_fixture_chirho =
        placement_revision_fixture_chirho(2, Some(R1_ASSIGNMENT_DIGEST_CHIRHO.to_string()));
    let r2_adopter_chirho = &r2_placement_fixture_chirho.serving_nodes_chirho[1];
    let r2_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &r2_placement_fixture_chirho.placement_chirho,
                &r2_adopter_chirho.node_id_chirho,
                true,
            ),
        });
    let r2_store_root_chirho = tempfile::tempdir().expect("r2 successor holder store");
    let r2_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            r2_store_root_chirho.path(),
            r2_adopter_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open r2 successor holder store"),
    );
    let r2_recovery_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: r2_adopter_chirho.node_id_chirho.clone(),
            sign_root_chirho: r2_adopter_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&r2_placement_fixture_chirho.placement_chirho),
            election_view_chirho: r2_election_chirho,
            residency_chirho: residency_chirho(&r2_placement_fixture_chirho.placement_chirho),
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::new()),
            follower_store_chirho: r2_store_chirho,
        },
    );
    let r2_revalidation_refusal_chirho = r2_recovery_chirho
        .revalidate_recovery_authority_chirho(&candidate_chirho)
        .expect_err("r2 must expire an r0 candidate at the non-local revalidation gate")
        .detail_chirho()
        .to_string();
    assert!(
        r2_revalidation_refusal_chirho
            .contains("LedgerMirrorRecoveryCandidateAssignmentExpiredChirho"),
        "unexpected r2 candidate revalidation refusal: {r2_revalidation_refusal_chirho}"
    );
    assert!(!r2_revalidation_refusal_chirho
        .contains("LedgerMirrorRecoveryCandidateAuthorityExpiredChirho"));
    let r2_record_refusal_chirho = r2_recovery_chirho
        .read_recovery_record_chirho(
            &candidate_chirho,
            candidate_chirho.tail_seq_chirho(),
            candidate_chirho.tail_record_digest_chirho(),
        )
        .expect_err("r2 must refuse an r0 candidate at the record-read assignment gate")
        .detail_chirho()
        .to_string();
    assert!(r2_record_refusal_chirho
        .contains("LedgerMirrorRecoveryRecordAssignmentBindingRefusedChirho"));
    assert!(!r2_record_refusal_chirho.contains("LedgerMirrorRecoveryRecordRequestRefusedChirho"));
}

fn local_assignment_refusal_chirho(
    revision_chirho: u64,
    previous_assignment_digest_chirho: &str,
    recovery_assignment_digest_chirho: &str,
) -> String {
    let placement_fixture_chirho = placement_revision_fixture_chirho(
        revision_chirho,
        Some(previous_assignment_digest_chirho.to_string()),
    );
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let historical_leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let adopter_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let local_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &adopter_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        local_election_chirho.as_ref(),
    )
    .expect("join successor placement and election");
    let assigned_node_ids_chirho: [String; 3] = placement_fixture_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("three assigned successor nodes");
    let recovery_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: historical_leader_chirho.root_chirho(),
            leader_node_id_chirho: &historical_leader_chirho.node_id_chirho,
            assigned_node_ids_chirho,
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: recovery_assignment_digest_chirho,
            membership_view_digest_chirho: PREDECESSOR_VIEW_DIGEST_CHIRHO,
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );
    let local_store_root_chirho = tempfile::tempdir().expect("historical local holder store");
    let local_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            local_store_root_chirho.path(),
            adopter_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open historical local holder store"),
    );
    commit_prefix_chirho(
        &local_store_chirho,
        adopter_chirho.root_chirho(),
        &recovery_manifest_chirho,
        &journal_fixture_chirho.source_record_chirho,
    );
    let recovery_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: adopter_chirho.node_id_chirho.clone(),
            sign_root_chirho: adopter_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&placement_fixture_chirho.placement_chirho),
            election_view_chirho: local_election_chirho,
            residency_chirho: residency_chirho(&placement_fixture_chirho.placement_chirho),
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::new()),
            follower_store_chirho: local_store_chirho,
        },
    );

    recovery_chirho
        .select_recovery_candidate_chirho(
            &journal_fixture_chirho.local_tail_chirho,
            &TestCanonicalHistorySourceChirho {
                anchor_mismatch_chirho: false,
            },
        )
        .expect_err("only the signed immediate predecessor may cross the placement successor")
        .detail_chirho()
        .to_string()
}

#[test]
fn contiguous_successor_refuses_an_unrelated_recovery_assignment_chirho() {
    let refusal_chirho = local_assignment_refusal_chirho(
        1,
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO,
        UNRELATED_ASSIGNMENT_DIGEST_CHIRHO,
    );
    assert!(
        refusal_chirho.contains("LedgerMirrorLocalRecoveryHeadAssignmentBindingRefusedChirho"),
        "unexpected unrelated-assignment refusal: {refusal_chirho}"
    );
    assert!(!refusal_chirho.contains("LedgerMirrorLocalRecoveryHeadBindingRefusedChirho"));
}

#[test]
fn r2_successor_refuses_an_r0_recovery_assignment_chirho() {
    let refusal_chirho = local_assignment_refusal_chirho(
        2,
        R1_ASSIGNMENT_DIGEST_CHIRHO,
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO,
    );
    assert!(
        refusal_chirho.contains("LedgerMirrorLocalRecoveryHeadAssignmentBindingRefusedChirho"),
        "unexpected two-generation-old refusal: {refusal_chirho}"
    );
    assert!(!refusal_chirho.contains("LedgerMirrorLocalRecoveryHeadBindingRefusedChirho"));
}

#[test]
fn current_holder_prefix_assignment_refusal_names_the_assignment_gate_chirho() {
    let placement_fixture_chirho =
        placement_successor_fixture_chirho(PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO);
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let first_holder_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let second_holder_chirho = &placement_fixture_chirho.serving_nodes_chirho[2];
    let leader_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        leader_election_chirho.as_ref(),
    )
    .expect("join successor leader view");
    let assigned_node_ids_chirho: [String; 3] = placement_fixture_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("three successor nodes");
    let start_holder_chirho = |holder_chirho: &crate::tests_chirho::TestNodeChirho| {
        let store_root_chirho = tempfile::tempdir().expect("unrelated live holder store");
        let store_chirho = Arc::new(
            LedgerMirrorFollowerStoreChirho::open_chirho(
                store_root_chirho.path(),
                holder_chirho.node_id_chirho.clone(),
                journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
            )
            .expect("open unrelated live holder store"),
        );
        commit_live_head_chirho(
            &store_chirho,
            LiveHeadBindingChirho {
                leader_root_chirho: leader_chirho.root_chirho(),
                leader_node_id_chirho: &leader_chirho.node_id_chirho,
                holder_root_chirho: holder_chirho.root_chirho(),
                holder_node_id_chirho: &holder_chirho.node_id_chirho,
                assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
                consistency_group_digest_chirho: joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho(),
                assignment_digest_chirho: UNRELATED_ASSIGNMENT_DIGEST_CHIRHO,
                membership_view_digest_chirho: PREDECESSOR_VIEW_DIGEST_CHIRHO,
                expected_term_chirho: joined_chirho.term_chirho(),
            },
            &journal_fixture_chirho.source_record_chirho,
        );
        let holder_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
            Arc::new(FixedElectionViewChirho {
                observation_chirho: election_observation_chirho(
                    &placement_fixture_chirho.placement_chirho,
                    &leader_chirho.node_id_chirho,
                    false,
                ),
            });
        let holder_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
            holder_chirho.node_id_chirho.clone(),
            holder_chirho.root_chirho().to_path_buf(),
            Arc::clone(&placement_fixture_chirho.placement_chirho),
            holder_election_chirho,
            residency_chirho(&placement_fixture_chirho.placement_chirho),
            store_chirho,
        )
        .expect("compose unrelated live holder");
        (
            store_root_chirho,
            RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(
                holder_state_chirho,
            )),
        )
    };
    let (_first_store_root_chirho, first_server_chirho) = start_holder_chirho(first_holder_chirho);
    let (_second_store_root_chirho, second_server_chirho) =
        start_holder_chirho(second_holder_chirho);
    let local_store_root_chirho = tempfile::tempdir().expect("successor leader store");
    let recovery_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            sign_root_chirho: leader_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&placement_fixture_chirho.placement_chirho),
            election_view_chirho: leader_election_chirho,
            residency_chirho: residency_chirho(&placement_fixture_chirho.placement_chirho),
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([
                (
                    first_holder_chirho.node_id_chirho.clone(),
                    first_server_chirho.endpoint_chirho.clone(),
                ),
                (
                    second_holder_chirho.node_id_chirho.clone(),
                    second_server_chirho.endpoint_chirho.clone(),
                ),
            ])),
            follower_store_chirho: Arc::new(
                LedgerMirrorFollowerStoreChirho::open_chirho(
                    local_store_root_chirho.path(),
                    leader_chirho.node_id_chirho.clone(),
                    journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
                )
                .expect("open successor leader store"),
            ),
        },
    );
    let current_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: leader_chirho.root_chirho(),
            leader_node_id_chirho: &leader_chirho.node_id_chirho,
            assigned_node_ids_chirho,
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: placement_fixture_chirho
                .placement_chirho
                .assignment_digest_chirho(),
            membership_view_digest_chirho: &joined_chirho.view_chirho().view_digest_chirho(),
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );
    let holder_node_ids_chirho = vec![
        first_holder_chirho.node_id_chirho.clone(),
        second_holder_chirho.node_id_chirho.clone(),
    ];
    let refusal_chirho = recovery_chirho
        .verify_current_holder_prefix_population_chirho(
            &joined_chirho,
            &current_manifest_chirho,
            &holder_node_ids_chirho,
        )
        .expect_err("unrelated holder receipts must fail at the prefix assignment gate")
        .to_string();
    assert!(
        refusal_chirho.contains("LedgerMirrorCurrentHolderPrefixAssignmentBindingRefusedChirho")
    );
    assert!(!refusal_chirho.contains("LedgerMirrorCurrentHolderPrefixBindingRefusedChirho"));
}

#[test]
fn r2_refuses_r0_at_bootstrap_reuse_joined_pair_and_commit_chirho() {
    // This pin replaces a structural guarantee the code does not have: bootstrap reuse and recovery
    // receipts consume the same historical head in different files and must close together at r2.
    let placement_fixture_chirho =
        placement_revision_fixture_chirho(2, Some(R1_ASSIGNMENT_DIGEST_CHIRHO.to_string()));
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let first_holder_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let second_holder_chirho = &placement_fixture_chirho.serving_nodes_chirho[2];
    let leader_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        leader_election_chirho.as_ref(),
    )
    .expect("join r2 leader view");
    assert_ne!(
        placement_fixture_chirho
            .placement_chirho
            .assignment_digest_chirho(),
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO
    );
    assert_ne!(
        R1_ASSIGNMENT_DIGEST_CHIRHO,
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO
    );
    let assigned_node_ids_chirho: [String; 3] = placement_fixture_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("three r2 assigned nodes");
    let r0_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: leader_chirho.root_chirho(),
            leader_node_id_chirho: &leader_chirho.node_id_chirho,
            assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO,
            membership_view_digest_chirho: PREDECESSOR_VIEW_DIGEST_CHIRHO,
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );
    let r2_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: leader_chirho.root_chirho(),
            leader_node_id_chirho: &leader_chirho.node_id_chirho,
            assigned_node_ids_chirho,
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: placement_fixture_chirho
                .placement_chirho
                .assignment_digest_chirho(),
            membership_view_digest_chirho: &joined_chirho.view_chirho().view_digest_chirho(),
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );

    let first_store_root_chirho = tempfile::tempdir().expect("first r0 bootstrap store");
    let first_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            first_store_root_chirho.path(),
            first_holder_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open first r0 bootstrap store"),
    );
    let first_receipt_chirho = commit_prefix_chirho(
        &first_store_chirho,
        first_holder_chirho.root_chirho(),
        &r0_manifest_chirho,
        &journal_fixture_chirho.source_record_chirho,
    );
    let second_store_root_chirho = tempfile::tempdir().expect("second r0 bootstrap store");
    let second_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            second_store_root_chirho.path(),
            second_holder_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open second r0 bootstrap store"),
    );
    let second_receipt_chirho = commit_prefix_chirho(
        &second_store_chirho,
        second_holder_chirho.root_chirho(),
        &r0_manifest_chirho,
        &journal_fixture_chirho.source_record_chirho,
    );
    assert_eq!(
        first_receipt_chirho.assignment_digest_chirho(),
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO
    );
    assert_eq!(
        second_receipt_chirho.assignment_digest_chirho(),
        PREDECESSOR_ASSIGNMENT_DIGEST_CHIRHO
    );
    assert!(!first_store_chirho
        .begin_verified_prefix_chirho(
            r2_manifest_chirho.clone(),
            Some(R1_ASSIGNMENT_DIGEST_CHIRHO),
        )
        .expect("r2 must stage rather than reuse the two-generation-old r0 head"));

    let first_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                false,
            ),
        });
    let first_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        first_holder_chirho.node_id_chirho.clone(),
        first_holder_chirho.root_chirho().to_path_buf(),
        Arc::clone(&placement_fixture_chirho.placement_chirho),
        first_election_chirho,
        residency_chirho(&placement_fixture_chirho.placement_chirho),
        Arc::clone(&first_store_chirho),
    )
    .expect("compose first r2 holder");
    let first_server_chirho =
        RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(first_state_chirho));
    let second_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                false,
            ),
        });
    let second_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        second_holder_chirho.node_id_chirho.clone(),
        second_holder_chirho.root_chirho().to_path_buf(),
        Arc::clone(&placement_fixture_chirho.placement_chirho),
        second_election_chirho,
        residency_chirho(&placement_fixture_chirho.placement_chirho),
        Arc::clone(&second_store_chirho),
    )
    .expect("compose second r2 holder");
    let second_server_chirho =
        RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(second_state_chirho));
    let local_store_root_chirho = tempfile::tempdir().expect("r2 leader store");
    let local_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            local_store_root_chirho.path(),
            leader_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open r2 leader store"),
    );
    let recovery_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            sign_root_chirho: leader_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&placement_fixture_chirho.placement_chirho),
            election_view_chirho: leader_election_chirho,
            residency_chirho: residency_chirho(&placement_fixture_chirho.placement_chirho),
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([
                (
                    first_holder_chirho.node_id_chirho.clone(),
                    first_server_chirho.endpoint_chirho.clone(),
                ),
                (
                    second_holder_chirho.node_id_chirho.clone(),
                    second_server_chirho.endpoint_chirho.clone(),
                ),
            ])),
            follower_store_chirho: local_store_chirho,
        },
    );
    let pair_refusal_chirho = recovery_chirho
        .select_recovery_candidate_chirho(
            &journal_fixture_chirho.local_tail_chirho,
            &TestCanonicalHistorySourceChirho {
                anchor_mismatch_chirho: false,
            },
        )
        .expect_err("the r2 joined-pair gate must refuse r0 bootstrap receipts")
        .detail_chirho()
        .to_string();
    assert!(
        pair_refusal_chirho.contains("LedgerMirrorRecoveryHeadAssignmentBindingRefusedChirho"),
        "unexpected r2 joined-pair refusal: {pair_refusal_chirho}"
    );
    assert!(!pair_refusal_chirho.contains("LedgerMirrorRecoveryHeadBindingRefusedChirho"));

    first_store_chirho
        .store_verified_prefix_page_chirho(
            LedgerMirrorVerifiedPrefixPageChirho::new_chirho(
                r2_manifest_chirho.manifest_digest_chirho().to_string(),
                0,
                vec![journal_fixture_chirho.source_record_chirho.clone()],
            )
            .expect("build the unchanged r2 prefix page"),
        )
        .expect("complete the inert r2 prefix stage");
    let LedgerMirrorBootstrapCommitPreparationChirho::SignChirho(input_chirho) = first_store_chirho
        .prepare_bootstrap_commit_chirho(r2_manifest_chirho.manifest_digest_chirho())
        .expect("prepare the same-sequence r2 bootstrap head")
    else {
        panic!("the two-generation-old head cannot satisfy the r2 manifest exactly");
    };
    let r2_head_chirho = LedgerMirrorBootstrapHeadChirho::sign_chirho(
        *input_chirho,
        first_holder_chirho.root_chirho(),
    )
    .expect("sign the same-sequence r2 bootstrap head");
    let commit_refusal_chirho = first_store_chirho
        .commit_bootstrap_chirho(r2_head_chirho)
        .expect_err("a static prefix across two revisions must still hit the monotonic commit wall")
        .to_string();
    assert!(
        commit_refusal_chirho.contains("LedgerMirrorBootstrapHeadRollbackOrConflictRefusedChirho")
    );
}
