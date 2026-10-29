// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::resident_authority_tests_chirho::{
    resident_mint_request_chirho, with_bound_resident_fixture_chirho,
};
use crate::reconciliation_chirho::{
    ExistingNodeGd7SignerChirho, Gd7AdoptionCheckpointBindingChirho, Gd7ForkCoordinateChirho,
    Gd7JournalTailCoordinateChirho, Gd7ReconciliationCheckpointStateChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho, Gd7ReconciliationStoreChirho,
    GD7_ADOPTION_CHECKPOINT_BINDING_SCHEMA_V1_CHIRHO,
};
use crate::{
    FsLedgerStorageChirho, ResidentLedgerAppendPermitChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerAuthorityRefusalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, writer_fence_storage_key_chirho,
    ConsistencyGroupIdChirho,
};
use std::path::Path;

fn digest_chirho(nibble_chirho: char) -> String {
    std::iter::repeat_n(nibble_chirho, 64).collect()
}

fn reconciliation_identity_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    held_node_chirho: &NodeIdChirho,
) -> Gd7ReconciliationIdentityChirho {
    Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(group_chirho).unwrap(),
        winner_node_chirho: digest_chirho('a'),
        held_node_chirho: held_node_chirho.0.clone(),
        winner_term_chirho: 9,
        losing_term_chirho: 8,
        winner_journal_genesis_digest_chirho: digest_chirho('2'),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(9, 0).unwrap(),
            seq_chirho: 12,
            record_digest_chirho: digest_chirho('3'),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(8, 0).unwrap(),
            seq_chirho: 5,
            record_digest_chirho: digest_chirho('4'),
        },
        losing_journal_genesis_digest_chirho: digest_chirho('2'),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(8, 3).unwrap(),
            seq_chirho: 10,
            record_digest_chirho: digest_chirho('6'),
        },
    }
}

fn observed_state_chirho() -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
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
    }
}

fn manifesting_state_chirho(
    observed_checkpoint_ref_chirho: &str,
) -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::ManifestingChirho,
        transition_seq_chirho: 1,
        previous_checkpoint_ref_chirho: Some(observed_checkpoint_ref_chirho.to_owned()),
        manifest_head_ref_chirho: Some(digest_chirho('7')),
        manifest_page_count_chirho: 1,
        manifest_record_count_chirho: 3,
        plan_head_ref_chirho: None,
        plan_page_count_chirho: 0,
        sealed_plan_ref_chirho: None,
        effect_obligation_count_chirho: 0,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    }
}

fn sealed_state_chirho(
    manifest_checkpoint_ref_chirho: &str,
) -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
        transition_seq_chirho: 2,
        previous_checkpoint_ref_chirho: Some(manifest_checkpoint_ref_chirho.to_owned()),
        manifest_head_ref_chirho: Some(digest_chirho('7')),
        manifest_page_count_chirho: 1,
        manifest_record_count_chirho: 3,
        plan_head_ref_chirho: Some(digest_chirho('8')),
        plan_page_count_chirho: 1,
        sealed_plan_ref_chirho: Some(digest_chirho('8')),
        effect_obligation_count_chirho: 2,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    }
}

pub(super) fn adoption_binding_chirho(
    plan_checkpoint_ref_chirho: &str,
) -> Gd7AdoptionCheckpointBindingChirho {
    Gd7AdoptionCheckpointBindingChirho {
        schema_chirho: GD7_ADOPTION_CHECKPOINT_BINDING_SCHEMA_V1_CHIRHO.to_owned(),
        plan_checkpoint_ref_chirho: plan_checkpoint_ref_chirho.to_owned(),
        materialization_input_binding_digest_chirho: digest_chirho('1'),
        evidence_checkpoint_ref_chirho: digest_chirho('2'),
        evidence_manifest_ref_chirho: digest_chirho('3'),
        held_view_checkpoint_ref_chirho: digest_chirho('4'),
        held_view_bundle_root_ref_chirho: digest_chirho('5'),
        read_only_branch_checkpoint_ref_chirho: digest_chirho('6'),
        prefix_root_ref_chirho: digest_chirho('7'),
        winner_history_root_ref_chirho: digest_chirho('8'),
        fork_baseline_root_ref_chirho: digest_chirho('9'),
        winner_handoff_attempt_digest_chirho: digest_chirho('a'),
        projection_fold_ref_chirho: digest_chirho('b'),
        accepted_projection_digest_chirho: digest_chirho('c'),
        candidate_journal_digest_chirho: digest_chirho('d'),
        candidate_journal_byte_len_chirho: 41,
        candidate_record_count_chirho: 12,
        candidate_projection_digest_chirho: digest_chirho('e'),
        candidate_projection_byte_len_chirho: 29,
        candidate_projection_row_count_chirho: 1,
    }
}

fn install_valid_adopted_hold_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    held_node_chirho: &NodeIdChirho,
) {
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
    let signer_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, held_node_chirho).unwrap();
    let store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        reconciliation_identity_chirho(group_chirho, held_node_chirho),
    )
    .unwrap();
    let observed_chirho = store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let manifesting_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&observed_chirho.checkpoint_ref_chirho),
            manifesting_state_chirho(&observed_chirho.checkpoint_ref_chirho),
        )
        .unwrap();
    let sealed_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&manifesting_chirho.checkpoint_ref_chirho),
            sealed_state_chirho(&manifesting_chirho.checkpoint_ref_chirho),
        )
        .unwrap();
    store_chirho
        .commit_adopted_held_checkpoint_chirho(
            &sealed_chirho.checkpoint_ref_chirho,
            adoption_binding_chirho(&sealed_chirho.checkpoint_ref_chirho),
        )
        .unwrap();
    assert_eq!(
        store_chirho
            .load_active_chirho()
            .unwrap()
            .unwrap()
            .checkpoint_chirho
            .state_chirho
            .phase_chirho,
        Gd7ReconciliationPhaseChirho::AdoptedHeldChirho,
        "the sink arm uses a valid held-signed Adopted checkpoint rather than mere path presence"
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn adopted_held_checkpoint_keeps_the_final_sink_held_without_journal_or_fence_mutation_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-adopted-hold",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho =
                super::resident_authority_tests_chirho::warm_single_node_elector_chirho(
                    node_chirho,
                    group_chirho,
                );
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .unwrap();
            install_valid_adopted_hold_chirho(root_chirho, group_chirho, node_chirho);

            let authority_storage_chirho =
                FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
            let ledger_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(
                &root_chirho.join("ledger-namespace-chirho"),
            )
            .unwrap();
            let fence_path_chirho = StoragePathChirho::new_chirho(
                writer_fence_storage_key_chirho(group_chirho).unwrap(),
            );
            let fence_before_chirho = authority_storage_chirho
                .read_all_chirho(&fence_path_chirho)
                .unwrap();
            let journal_before_chirho = ledger_storage_chirho
                .read_all_chirho(journal_path_chirho)
                .unwrap();

            let refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    resident_mint_request_chirho(3, "resident-adopted-held-chirho"),
                )
                .unwrap_err();
            assert_eq!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldActiveChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("held by active GD7 reconciliation"));
            assert!(!rendered_chirho.contains("writer fence"));
            assert!(!rendered_chirho.contains("journal is ahead"));
            assert_eq!(
                authority_storage_chirho
                    .read_all_chirho(&fence_path_chirho)
                    .unwrap(),
                fence_before_chirho,
                "Adopted remains held before writer-fence mutation"
            );
            assert_eq!(
                ledger_storage_chirho
                    .read_all_chirho(journal_path_chirho)
                    .unwrap(),
                journal_before_chirho,
                "Adopted remains held before journal mutation"
            );
        },
    );
}
