// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::reconciliation_chirho::{
    Gd7ForkCoordinateChirho, Gd7JournalTailCoordinateChirho, Gd7ReconciliationIdentityChirho,
};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_model_chirho::record_chirho::{HlcChirho, LedgerGenesisRecordChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_genesis_line_chirho, stored_line_digest_chirho,
    LEDGER_FORMAT_VERSION_V1_CHIRHO, LEDGER_GENESIS_SCHEMA_V1_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};

fn transfer_identity_chirho(
    genesis_digest_chirho: &str,
    fork_seq_chirho: u64,
    fork_digest_chirho: String,
) -> Gd7HeldEvidenceTransferIdentityChirho {
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "gd7-read-only-branch-shape-chirho".to_owned(),
    };
    Gd7HeldEvidenceTransferIdentityChirho {
        reconciliation_identity_chirho: Gd7ReconciliationIdentityChirho {
            consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho)
                .expect("derive test group digest"),
            winner_node_chirho: "a".repeat(64),
            held_node_chirho: "b".repeat(64),
            winner_term_chirho: 7,
            losing_term_chirho: 6,
            winner_journal_genesis_digest_chirho: genesis_digest_chirho.to_owned(),
            winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
                epoch_chirho: compose_writer_epoch_chirho(7, 0).expect("winner epoch"),
                seq_chirho: 2,
                record_digest_chirho: "d".repeat(64),
            },
            fork_chirho: Gd7ForkCoordinateChirho {
                epoch_chirho: compose_writer_epoch_chirho(6, 0).expect("fork epoch"),
                seq_chirho: fork_seq_chirho,
                record_digest_chirho: fork_digest_chirho,
            },
            losing_journal_genesis_digest_chirho: genesis_digest_chirho.to_owned(),
            losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
                epoch_chirho: compose_writer_epoch_chirho(6, 0).expect("losing epoch"),
                seq_chirho: 2,
                record_digest_chirho: "e".repeat(64),
            },
        },
        reconciliation_checkpoint_ref_chirho: "f".repeat(64),
        held_view_transfer_checkpoint_ref_chirho: "1".repeat(64),
        winner_handoff_attempt_digest_chirho: "2".repeat(64),
    }
}

#[test]
fn empty_prefix_is_valid_only_for_the_exact_genesis_fork_chirho() {
    let genesis_chirho = LedgerGenesisRecordChirho {
        schema_chirho: LEDGER_GENESIS_SCHEMA_V1_CHIRHO.to_owned(),
        format_version_chirho: LEDGER_FORMAT_VERSION_V1_CHIRHO,
        cluster_id_chirho: ClusterIdChirho("gd7-empty-prefix-cluster-chirho".to_owned()),
        epoch_chirho: compose_writer_epoch_chirho(6, 0).expect("genesis epoch"),
        hlc_chirho: HlcChirho {
            physical_ms_chirho: 1,
            logical_chirho: 0,
        },
        sig_chirho: "signed-genesis-chirho".to_owned(),
        key_id_chirho: "b".repeat(64),
    };
    let genesis_line_chirho =
        canonical_ledger_genesis_line_chirho(&genesis_chirho).expect("canonical test genesis");
    let genesis_digest_chirho = stored_line_digest_chirho(&genesis_line_chirho).0;
    let valid_identity_chirho =
        transfer_identity_chirho(&genesis_digest_chirho, 0, genesis_digest_chirho.clone());
    let valid_root_chirho = Gd7ReadOnlyBranchPrefixRootChirho {
        schema_chirho: GD7_READ_ONLY_BRANCH_PREFIX_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        transfer_identity_digest_chirho: gd7_held_evidence_transfer_identity_digest_chirho(
            &valid_identity_chirho,
        )
        .expect("digest valid transfer identity"),
        transfer_identity_chirho: valid_identity_chirho,
        genesis_line_chirho,
        losing_tail_epoch_chirho: compose_writer_epoch_chirho(6, 0).expect("losing epoch"),
        losing_tail_seq_chirho: 2,
        losing_tail_record_digest_chirho: "e".repeat(64),
        oldest_page_ref_chirho: None,
        page_count_chirho: 0,
        record_count_chirho: 0,
        key_id_chirho: "b".repeat(64),
        sig_chirho: "signed-chirho".to_owned(),
    };
    validate_prefix_root_shape_chirho(&valid_root_chirho)
        .expect("exact genesis fork permits an empty prefix chain");

    let invalid_identity_chirho =
        transfer_identity_chirho(&genesis_digest_chirho, 1, "9".repeat(64));
    let invalid_root_chirho = Gd7ReadOnlyBranchPrefixRootChirho {
        transfer_identity_digest_chirho: gd7_held_evidence_transfer_identity_digest_chirho(
            &invalid_identity_chirho,
        )
        .expect("digest valid non-genesis transfer identity"),
        transfer_identity_chirho: invalid_identity_chirho,
        ..valid_root_chirho
    };
    assert_eq!(
        validate_prefix_root_shape_chirho(&invalid_root_chirho).unwrap_err(),
        Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixShapeChirho,
        "a non-genesis fork cannot hide behind a vacuously empty prefix"
    );
}
