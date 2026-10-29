// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::winner_handoff_tests_chirho::{
    durable_commit_chirho, handoff_fixture_for_cut_chirho,
    InstalledAtomicWriteSyncFaultStorageChirho, TestWinnerHandoffSignerChirho,
};
use super::*;
use crate::reconciliation_chirho::{
    Gd7ForkCoordinateChirho, Gd7LedgerRecordVerifierPortChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationPhaseChirho, GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO,
};
use crate::SystemLedgerClockChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::LosingSuffixReaderChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use ed25519_dalek::{Signature, Signer as Ed25519SignerChirho, SigningKey, Verifier};

struct WinnerHistoryMembershipChirho;

impl MembershipViewChirho for WinnerHistoryMembershipChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

struct WinnerHistoryKindRegistryChirho;

impl KindRegistryViewChirho for WinnerHistoryKindRegistryChirho {
    fn resolve_chirho(&self, _policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        KindResolutionChirho::CurrentChirho(KindPolicyViewChirho {
            kind_id_chirho: AssetKindIdChirho("gd7-winner-history-kind-chirho".to_owned()),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(10_000),
            },
            rounding_chirho: RoundingChirho::ExactChirho,
            settlement_owner_chirho: None,
            idempotency_window_chirho: None,
        })
    }
}

struct WinnerHistoryAuthorityChirho;

impl AuthorityVerifierViewChirho for WinnerHistoryAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::VerifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::VerifiedChirho
    }
}

struct TestJournalSignerChirho {
    key_id_chirho: String,
    signing_key_chirho: SigningKey,
}

impl TestJournalSignerChirho {
    fn new_chirho(key_id_chirho: &str, seed_chirho: [u8; 32]) -> Self {
        Self {
            key_id_chirho: key_id_chirho.to_owned(),
            signing_key_chirho: SigningKey::from_bytes(&seed_chirho),
        }
    }

    fn signature_chirho(&self, signed_content_line_chirho: &str) -> String {
        self.signing_key_chirho
            .sign(signed_content_line_chirho.as_bytes())
            .to_bytes()
            .iter()
            .map(|byte_chirho| format!("{byte_chirho:02x}"))
            .collect()
    }

    fn verify_signature_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        if sig_chirho.len() != 128 {
            return false;
        }
        let signature_bytes_chirho = (0..64)
            .map(|index_chirho| {
                u8::from_str_radix(&sig_chirho[index_chirho * 2..index_chirho * 2 + 2], 16)
            })
            .collect::<Result<Vec<_>, _>>();
        let Ok(signature_bytes_chirho) = signature_bytes_chirho else {
            return false;
        };
        let Ok(signature_bytes_chirho) = <[u8; 64]>::try_from(signature_bytes_chirho) else {
            return false;
        };
        self.signing_key_chirho
            .verifying_key()
            .verify(
                signed_content_line_chirho.as_bytes(),
                &Signature::from_bytes(&signature_bytes_chirho),
            )
            .is_ok()
    }
}

impl LedgerSignerPortChirho for TestJournalSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_signature_chirho(signed_content_line_chirho, sig_chirho)
    }
}

impl Gd7LedgerRecordVerifierPortChirho for TestJournalSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_signature_chirho(signed_content_line_chirho, sig_chirho)
    }
}

fn winner_history_append_chirho(index_chirho: usize) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho("5".repeat(64)),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: LogIdChirho::new_chirho(
                "gd7-winner-history-owner-chirho",
                "gd7-winner-history-kind-chirho",
            ),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("6".repeat(64))),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 1,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: format!("gd7-winner-history-{index_chirho:04}-chirho"),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

fn signed_plan_checkpoint_chirho(
    identity_chirho: Gd7ReconciliationIdentityChirho,
    held_signer_chirho: &TestWinnerHandoffSignerChirho,
) -> (String, Gd7ReconciliationCheckpointChirho) {
    let sealed_plan_ref_chirho = "7".repeat(64);
    let mut checkpoint_chirho = Gd7ReconciliationCheckpointChirho {
        schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho,
        winner_fork_witness_object_digest_chirho: "8".repeat(64),
        state_chirho: Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
            transition_seq_chirho: 2,
            previous_checkpoint_ref_chirho: Some("9".repeat(64)),
            manifest_head_ref_chirho: Some("a".repeat(64)),
            manifest_page_count_chirho: 1,
            manifest_record_count_chirho: 1,
            plan_head_ref_chirho: Some(sealed_plan_ref_chirho.clone()),
            plan_page_count_chirho: 1,
            sealed_plan_ref_chirho: Some(sealed_plan_ref_chirho),
            effect_obligation_count_chirho: 0,
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: None,
        },
        key_id_chirho:
            <TestWinnerHandoffSignerChirho as Gd7ReconciliationVerifierPortChirho>::key_id_chirho(
                held_signer_chirho,
            ),
        sig_chirho: String::new(),
    };
    let unsigned_chirho = serde_json::to_string(&checkpoint_chirho).unwrap();
    checkpoint_chirho.sig_chirho =
        Gd7ReconciliationSignerPortChirho::sign_chirho(held_signer_chirho, &unsigned_chirho)
            .unwrap();
    let bytes_chirho = serde_json::to_vec(&checkpoint_chirho).unwrap();
    (
        blake3::hash(&bytes_chirho).to_hex().to_string(),
        checkpoint_chirho,
    )
}

#[test]
fn accepted_handoff_stages_and_reverifies_two_real_winner_history_pages_chirho() {
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho(false);
    let winner_control_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("a".repeat(64));
    let journal_key_id_chirho = "journal-chirho:shared-winner-journal-secret-chirho";
    let winner_journal_signer_chirho =
        TestJournalSignerChirho::new_chirho(journal_key_id_chirho, [0x41; 32]);
    let foreign_journal_verifier_chirho =
        TestJournalSignerChirho::new_chirho(journal_key_id_chirho, [0x42; 32]);
    let held_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("b".repeat(64));
    let clock_chirho = SystemLedgerClockChirho;
    let membership_chirho = WinnerHistoryMembershipChirho;
    let kind_registry_chirho = WinnerHistoryKindRegistryChirho;
    let authority_chirho = WinnerHistoryAuthorityChirho;
    let journal_ports_chirho = || JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &winner_journal_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let mut winner_journal_chirho = LedgerJournalChirho::create_chirho(
        journal_ports_chirho(),
        StoragePathChirho::new_chirho("journals-chirho/gd7-winner-history-chirho.jsonl"),
        ClusterIdChirho("gd7-winner-history-cluster-chirho".to_owned()),
        compose_writer_epoch_chirho(6, 0).unwrap(),
    )
    .unwrap();
    let winner_genesis_chirho = winner_journal_chirho.genesis_digest_chirho().0.clone();
    let fork_receipt_chirho = winner_journal_chirho
        .append_chirho(winner_history_append_chirho(0))
        .unwrap();
    let fork_epoch_chirho = compose_writer_epoch_chirho(6, 0).unwrap();
    winner_journal_chirho
        .advance_epoch_chirho(compose_writer_epoch_chirho(7, 0).unwrap())
        .unwrap();
    for index_chirho in 1..=300 {
        winner_journal_chirho
            .append_chirho(winner_history_append_chirho(index_chirho))
            .unwrap();
    }
    let winner_tail_chirho = winner_journal_chirho.verified_losing_tail_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/tmp/gd7-winner-handoff-chirho".to_owned(),
    };
    let identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        winner_node_chirho: "a".repeat(64),
        held_node_chirho: "b".repeat(64),
        winner_term_chirho: 7,
        losing_term_chirho: 6,
        winner_journal_genesis_digest_chirho: winner_genesis_chirho.clone(),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: winner_tail_chirho.record_epoch_chirho(),
            seq_chirho: winner_tail_chirho.coordinate_chirho().seq_chirho(),
            record_digest_chirho: winner_tail_chirho
                .coordinate_chirho()
                .record_digest_chirho()
                .0
                .clone(),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: fork_epoch_chirho,
            seq_chirho: fork_receipt_chirho.seq_chirho,
            record_digest_chirho: fork_receipt_chirho.record_digest_chirho.0.clone(),
        },
        losing_journal_genesis_digest_chirho: winner_genesis_chirho.clone(),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: fork_epoch_chirho,
            seq_chirho: fork_receipt_chirho.seq_chirho + 1,
            record_digest_chirho: "c".repeat(64),
        },
    };
    let (plan_checkpoint_ref_chirho, plan_checkpoint_chirho) =
        signed_plan_checkpoint_chirho(identity_chirho.clone(), &held_signer_chirho);
    let (group_digest_chirho, handoff_identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_for_cut_chirho(
            plan_checkpoint_ref_chirho.clone(),
            winner_genesis_chirho,
            identity_chirho.winner_journal_tail_chirho.clone(),
        );
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &winner_control_signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                handoff_identity_chirho,
                &challenge_bytes_chirho,
                inspection_chirho,
                19,
            )
            .unwrap(),
    );
    durable_commit_chirho(
        store_chirho
            .commit_accepted_chirho(
                &preparing_chirho.attempt_digest_chirho,
                &preparing_chirho.checkpoint_ref_chirho,
                20,
            )
            .unwrap(),
    );

    let first_outcome_chirho = store_chirho
        .stage_next_accepted_winner_history_page_chirho(
            &plan_checkpoint_ref_chirho,
            &plan_checkpoint_chirho,
            &held_signer_chirho,
            &winner_journal_chirho,
            None,
        )
        .unwrap();
    let first_restart_chirho = match &first_outcome_chirho {
        Gd7WinnerHistoryStageOutcomeChirho::ContinueChirho { restart_chirho } => {
            restart_chirho.clone()
        }
        Gd7WinnerHistoryStageOutcomeChirho::CompleteChirho { .. } => {
            panic!("three hundred winner records must require a second bounded page")
        }
    };
    let replayed_first_chirho = store_chirho
        .stage_next_accepted_winner_history_page_chirho(
            &plan_checkpoint_ref_chirho,
            &plan_checkpoint_chirho,
            &held_signer_chirho,
            &winner_journal_chirho,
            None,
        )
        .unwrap();
    assert_eq!(
        replayed_first_chirho, first_outcome_chirho,
        "a lost response must recreate the exact immutable first page"
    );
    let complete_root_chirho = match store_chirho
        .stage_next_accepted_winner_history_page_chirho(
            &plan_checkpoint_ref_chirho,
            &plan_checkpoint_chirho,
            &held_signer_chirho,
            &winner_journal_chirho,
            Some(&first_restart_chirho),
        )
        .unwrap()
    {
        Gd7WinnerHistoryStageOutcomeChirho::CompleteChirho { root_chirho } => root_chirho,
        Gd7WinnerHistoryStageOutcomeChirho::ContinueChirho { .. } => {
            panic!("the second bounded page must reach the exact fork")
        }
    };
    assert_eq!(complete_root_chirho.root_chirho().page_count_chirho, 2);
    assert_eq!(complete_root_chirho.root_chirho().record_count_chirho, 300);
    let verified_chain_chirho = verify_complete_gd7_winner_history_chain_chirho(
        &storage_chirho,
        complete_root_chirho.object_digest_chirho(),
        &complete_root_chirho.root_chirho().identity_chirho,
        &winner_control_signer_chirho,
        &winner_journal_signer_chirho,
    )
    .unwrap();
    assert_eq!(
        verified_chain_chirho.root_chirho().object_digest_chirho(),
        complete_root_chirho.object_digest_chirho()
    );

    let oldest_page_path_chirho = gd7_winner_history_page_path_chirho(
        &complete_root_chirho.root_chirho().oldest_page_ref_chirho,
    )
    .unwrap();
    let foreign_root_refusal_chirho = verify_complete_gd7_winner_history_chain_chirho(
        &storage_chirho,
        complete_root_chirho.object_digest_chirho(),
        &complete_root_chirho.root_chirho().identity_chirho,
        &winner_control_signer_chirho,
        &foreign_journal_verifier_chirho,
    )
    .unwrap_err();
    assert_eq!(
        foreign_root_refusal_chirho,
        Gd7WinnerHistoryRefusalChirho::InvalidLedgerSignatureChirho,
        "InvalidLedgerSignatureChirho means the configured journal root rejected a same-label foreign key; WrongJournalLabelChirho would mean control and journal identity were conflated again"
    );
    let rendered_foreign_refusal_chirho = foreign_root_refusal_chirho.to_string();
    assert!(rendered_foreign_refusal_chirho.contains("ledger signature is invalid"));
    assert!(!rendered_foreign_refusal_chirho.contains("record label"));
    assert!(!rendered_foreign_refusal_chirho.contains("root signature"));

    storage_chirho
        .atomic_write_chirho(&oldest_page_path_chirho, b"{}")
        .unwrap();
    assert!(matches!(
        verify_complete_gd7_winner_history_chain_chirho(
            &storage_chirho,
            complete_root_chirho.object_digest_chirho(),
            &complete_root_chirho.root_chirho().identity_chirho,
            &winner_control_signer_chirho,
            &winner_journal_signer_chirho,
        ),
        Err(Gd7WinnerHistoryRefusalChirho::ObjectDigestMismatchChirho)
    ));
}

#[test]
fn accepted_handoff_stages_a_valid_page_under_a_distinct_journal_label_chirho() {
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho(false);
    let winner_control_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("a".repeat(64));
    let foreign_journal_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("c".repeat(64));
    let held_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("b".repeat(64));
    let clock_chirho = SystemLedgerClockChirho;
    let membership_chirho = WinnerHistoryMembershipChirho;
    let kind_registry_chirho = WinnerHistoryKindRegistryChirho;
    let authority_chirho = WinnerHistoryAuthorityChirho;
    let journal_ports_chirho = || JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &foreign_journal_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let mut winner_journal_chirho = LedgerJournalChirho::create_chirho(
        journal_ports_chirho(),
        StoragePathChirho::new_chirho("journals-chirho/gd7-foreign-winner-history-chirho.jsonl"),
        ClusterIdChirho("gd7-foreign-winner-history-cluster-chirho".to_owned()),
        compose_writer_epoch_chirho(6, 0).unwrap(),
    )
    .unwrap();
    let winner_genesis_chirho = winner_journal_chirho.genesis_digest_chirho().0.clone();
    let fork_receipt_chirho = winner_journal_chirho
        .append_chirho(winner_history_append_chirho(0))
        .unwrap();
    let fork_epoch_chirho = compose_writer_epoch_chirho(6, 0).unwrap();
    winner_journal_chirho
        .advance_epoch_chirho(compose_writer_epoch_chirho(7, 0).unwrap())
        .unwrap();
    winner_journal_chirho
        .append_chirho(winner_history_append_chirho(1))
        .unwrap();
    let winner_tail_chirho = winner_journal_chirho.verified_losing_tail_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/tmp/gd7-winner-handoff-chirho".to_owned(),
    };
    let identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        winner_node_chirho: "a".repeat(64),
        held_node_chirho: "b".repeat(64),
        winner_term_chirho: 7,
        losing_term_chirho: 6,
        winner_journal_genesis_digest_chirho: winner_genesis_chirho.clone(),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: winner_tail_chirho.record_epoch_chirho(),
            seq_chirho: winner_tail_chirho.coordinate_chirho().seq_chirho(),
            record_digest_chirho: winner_tail_chirho
                .coordinate_chirho()
                .record_digest_chirho()
                .0
                .clone(),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: fork_epoch_chirho,
            seq_chirho: fork_receipt_chirho.seq_chirho,
            record_digest_chirho: fork_receipt_chirho.record_digest_chirho.0.clone(),
        },
        losing_journal_genesis_digest_chirho: winner_genesis_chirho.clone(),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: fork_epoch_chirho,
            seq_chirho: fork_receipt_chirho.seq_chirho + 1,
            record_digest_chirho: "d".repeat(64),
        },
    };
    let (plan_checkpoint_ref_chirho, plan_checkpoint_chirho) =
        signed_plan_checkpoint_chirho(identity_chirho.clone(), &held_signer_chirho);
    let (group_digest_chirho, handoff_identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_for_cut_chirho(
            plan_checkpoint_ref_chirho.clone(),
            winner_genesis_chirho,
            identity_chirho.winner_journal_tail_chirho.clone(),
        );
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &winner_control_signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                handoff_identity_chirho,
                &challenge_bytes_chirho,
                inspection_chirho,
                19,
            )
            .unwrap(),
    );
    durable_commit_chirho(
        store_chirho
            .commit_accepted_chirho(
                &preparing_chirho.attempt_digest_chirho,
                &preparing_chirho.checkpoint_ref_chirho,
                20,
            )
            .unwrap(),
    );

    let outcome_chirho = store_chirho
        .stage_next_accepted_winner_history_page_chirho(
            &plan_checkpoint_ref_chirho,
            &plan_checkpoint_chirho,
            &held_signer_chirho,
            &winner_journal_chirho,
            None,
        )
        .expect(
            "a journal label distinct from the winner control id is valid when the injected journal root authenticates it",
        );
    let Gd7WinnerHistoryStageOutcomeChirho::CompleteChirho { root_chirho } = outcome_chirho else {
        panic!("one post-fork record must complete in one page")
    };
    verify_complete_gd7_winner_history_chain_chirho(
        &storage_chirho,
        root_chirho.object_digest_chirho(),
        &root_chirho.root_chirho().identity_chirho,
        &winner_control_signer_chirho,
        &foreign_journal_signer_chirho,
    )
    .expect("the distinct journal label remains valid during complete-chain verification");
}

#[test]
fn history_staging_refuses_preparing_and_cut_drift_by_identity_chirho() {
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho(false);
    let winner_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("a".repeat(64));
    let held_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("b".repeat(64));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/tmp/gd7-winner-handoff-chirho".to_owned(),
    };
    let identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        winner_node_chirho: "a".repeat(64),
        held_node_chirho: "b".repeat(64),
        winner_term_chirho: 7,
        losing_term_chirho: 6,
        winner_journal_genesis_digest_chirho: "1".repeat(64),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(7, 0).unwrap(),
            seq_chirho: 2,
            record_digest_chirho: "2".repeat(64),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(6, 0).unwrap(),
            seq_chirho: 1,
            record_digest_chirho: "3".repeat(64),
        },
        losing_journal_genesis_digest_chirho: "1".repeat(64),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(6, 0).unwrap(),
            seq_chirho: 2,
            record_digest_chirho: "4".repeat(64),
        },
    };
    let (plan_checkpoint_ref_chirho, plan_checkpoint_chirho) =
        signed_plan_checkpoint_chirho(identity_chirho.clone(), &held_signer_chirho);
    let (group_digest_chirho, handoff_identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_for_cut_chirho(
            plan_checkpoint_ref_chirho.clone(),
            identity_chirho.winner_journal_genesis_digest_chirho.clone(),
            identity_chirho.winner_journal_tail_chirho.clone(),
        );
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &winner_signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                handoff_identity_chirho,
                &challenge_bytes_chirho,
                inspection_chirho,
                19,
            )
            .unwrap(),
    );
    struct NeverReadWinnerHistoryChirho;
    impl LosingSuffixReaderChirho for NeverReadWinnerHistoryChirho {
        fn injected_journal_key_id_chirho(&self) -> String {
            panic!("a refused handoff must not inspect the winner journal label")
        }

        fn revalidate_current_losing_tail_chirho(
            &self,
        ) -> Result<
            cairn_ledger_log_chirho::losing_suffix_chirho::VerifiedLosingJournalTailChirho,
            cairn_ledger_log_chirho::losing_suffix_chirho::LosingSuffixReadErrorChirho,
        > {
            panic!("a refused handoff must not inspect winner history")
        }

        fn decode_verified_losing_suffix_cursor_chirho(
            &self,
            _bytes_chirho: &[u8],
        ) -> Result<
            cairn_ledger_log_chirho::losing_suffix_chirho::LosingSuffixCursorChirho,
            cairn_ledger_log_chirho::losing_suffix_chirho::LosingSuffixReadErrorChirho,
        > {
            panic!("a refused handoff must not decode winner-history cursors")
        }

        fn read_verified_losing_suffix_page_chirho(
            &self,
            _request_chirho: &cairn_ledger_log_chirho::losing_suffix_chirho::LosingSuffixPageRequestChirho,
        ) -> Result<
            cairn_ledger_log_chirho::losing_suffix_chirho::VerifiedLosingSuffixPageChirho,
            cairn_ledger_log_chirho::losing_suffix_chirho::LosingSuffixReadErrorChirho,
        > {
            panic!("a refused handoff must not read winner history")
        }
    }
    let never_read_chirho = NeverReadWinnerHistoryChirho;
    assert!(matches!(
        store_chirho.stage_next_accepted_winner_history_page_chirho(
            &plan_checkpoint_ref_chirho,
            &plan_checkpoint_chirho,
            &held_signer_chirho,
            &never_read_chirho,
            None,
        ),
        Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho)
    ));
    durable_commit_chirho(
        store_chirho
            .commit_accepted_chirho(
                &preparing_chirho.attempt_digest_chirho,
                &preparing_chirho.checkpoint_ref_chirho,
                20,
            )
            .unwrap(),
    );
    let mut wrong_cut_chirho = plan_checkpoint_chirho.clone();
    wrong_cut_chirho
        .identity_chirho
        .winner_journal_tail_chirho
        .record_digest_chirho = "d".repeat(64);
    assert!(matches!(
        store_chirho.stage_next_accepted_winner_history_page_chirho(
            &plan_checkpoint_ref_chirho,
            &wrong_cut_chirho,
            &held_signer_chirho,
            &never_read_chirho,
            None,
        ),
        Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidWinnerEvidenceChirho)
    ));
}
