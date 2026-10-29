// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::bundle_chirho::{
    parse_verified_inline_bundle_page_chirho, Gd7WinnerViewBundlePageChirho,
};
use super::*;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, AssetKindIdChirho};
use cairn_ledger_read_model_chirho::{
    account_net_projection_fold_ref_chirho, AccountNetProjectionRowChirho,
};
use cairn_ledger_sim_chirho::fault_chirho::FaultPlanChirho;
use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;
use cairn_writer_elector_chirho::elector_port_chirho::{
    LeadershipChirho, NodeIdChirho, WriterElectorChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::cell::RefCell;
use std::collections::VecDeque;

#[derive(Clone)]
struct AdoptionTestSignerChirho {
    key_id_chirho: String,
    key_byte_chirho: u8,
}

impl AdoptionTestSignerChirho {
    fn signature_chirho(&self, line_chirho: &str) -> String {
        blake3::keyed_hash(&[self.key_byte_chirho; 32], line_chirho.as_bytes())
            .to_hex()
            .to_string()
    }
}

impl Gd7ReconciliationVerifierPortChirho for AdoptionTestSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(canonical_unsigned_chirho) == sig_chirho
    }
}

impl Gd7ReconciliationSignerPortChirho for AdoptionTestSignerChirho {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> anyhow::Result<String> {
        Ok(self.signature_chirho(canonical_unsigned_chirho))
    }
}

struct AdoptionSequenceElectorChirho {
    node_id_chirho: NodeIdChirho,
    observations_chirho: RefCell<VecDeque<LeadershipChirho>>,
    fallback_chirho: LeadershipChirho,
}

impl AdoptionSequenceElectorChirho {
    fn stable_chirho(
        held_node_chirho: &NodeIdChirho,
        winner_node_chirho: &NodeIdChirho,
        term_chirho: u64,
    ) -> Self {
        let leadership_chirho = follower_leadership_chirho(winner_node_chirho, term_chirho);
        Self {
            node_id_chirho: held_node_chirho.clone(),
            observations_chirho: RefCell::new(VecDeque::new()),
            fallback_chirho: leadership_chirho,
        }
    }

    fn changing_chirho(
        held_node_chirho: &NodeIdChirho,
        winner_node_chirho: &NodeIdChirho,
        term_chirho: u64,
    ) -> Self {
        let stable_chirho = follower_leadership_chirho(winner_node_chirho, term_chirho);
        let changed_chirho = LeadershipChirho {
            leader_id_chirho: Some(NodeIdChirho("9".repeat(64))),
            term_chirho: term_chirho + 1,
            ..stable_chirho.clone()
        };
        Self {
            node_id_chirho: held_node_chirho.clone(),
            observations_chirho: RefCell::new([stable_chirho.clone(), changed_chirho].into()),
            fallback_chirho: stable_chirho,
        }
    }
}

impl WriterElectorChirho for AdoptionSequenceElectorChirho {
    fn leadership_chirho(&self, _group_chirho: &ConsistencyGroupIdChirho) -> LeadershipChirho {
        self.observations_chirho
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| self.fallback_chirho.clone())
    }

    fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }
}

struct CompleteTransferFixtureChirho {
    storage_chirho: SimStorageChirho,
    held_signer_chirho: AdoptionTestSignerChirho,
    winner_signer_chirho: AdoptionTestSignerChirho,
    identity_chirho: Gd7HeldViewTransferIdentityChirho,
    group_chirho: ConsistencyGroupIdChirho,
    active_chirho: ActiveGd7HeldViewTransferChirho,
    root_chirho: Gd7WinnerViewBundleRootChirho,
    root_ref_chirho: String,
    highest_page_ref_chirho: String,
}

#[derive(Clone, Copy)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
enum BundleShapeChirho {
    ExactChirho,
    CrossPageOverlapChirho,
    InteriorCumulativeLieChirho,
}

#[test]
fn complete_chain_then_fresh_winner_evidence_is_read_only_and_exact_chirho() {
    let fixture_chirho = complete_transfer_fixture_chirho();
    let before_chirho = fixture_chirho.storage_chirho.snapshot_chirho();
    let chain_chirho = verify_complete_gd7_held_winner_view_chain_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.winner_signer_chirho,
        fixture_chirho.identity_chirho.clone(),
        &fixture_chirho.active_chirho.checkpoint_ref_chirho,
    )
    .expect("reverify every held winner-view page");
    assert_eq!(chain_chirho.received_page_count_chirho(), 2);
    assert_eq!(chain_chirho.received_row_count_chirho(), 258);
    assert_eq!(
        chain_chirho.bundle_root_object_digest_chirho(),
        fixture_chirho.root_ref_chirho
    );

    let held_node_chirho = NodeIdChirho(fixture_chirho.identity_chirho.held_node_chirho.clone());
    let winner_node_chirho =
        NodeIdChirho(fixture_chirho.identity_chirho.winner_node_chirho.clone());
    let elector_chirho = AdoptionSequenceElectorChirho::stable_chirho(
        &held_node_chirho,
        &winner_node_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
    );
    let issued_challenge_chirho = generate_gd7_winner_current_view_challenge_chirho(
        &elector_chirho,
        &fixture_chirho.group_chirho,
        &winner_node_chirho,
        &held_node_chirho,
        chain_chirho.transfer_identity_digest_chirho(),
    )
    .expect("mint adoption-time challenge from the current real-election view");
    let transport_challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
        &issued_challenge_chirho
            .canonical_bytes_chirho()
            .expect("encode fresh adoption challenge"),
    )
    .expect("parse transport challenge");
    let fresh_inspection_chirho = signed_inspection_chirho(
        &fixture_chirho.winner_signer_chirho,
        &transport_challenge_chirho,
        &fixture_chirho.root_chirho,
        &fixture_chirho.root_ref_chirho,
        19,
    );
    let freshness_chirho = verify_fresh_gd7_held_winner_view_evidence_chirho(
        chain_chirho,
        &fixture_chirho.winner_signer_chirho,
        &elector_chirho,
        &fixture_chirho.group_chirho,
        &winner_node_chirho,
        issued_challenge_chirho,
        &fresh_inspection_chirho,
    )
    .expect("fresh point-in-time evidence matches the completely received chain");
    assert_eq!(
        freshness_chirho.transfer_checkpoint_ref_chirho(),
        fixture_chirho.active_chirho.checkpoint_ref_chirho
    );
    assert_eq!(freshness_chirho.winner_process_generation_chirho(), 19);
    assert_eq!(
        fixture_chirho.storage_chirho.snapshot_chirho(),
        before_chirho,
        "both complete-chain and fresh-evidence verification must remain read-only"
    );
}

#[test]
fn empty_complete_chain_verifies_without_page_reads_or_writes_chirho() {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let held_signer_chirho = AdoptionTestSignerChirho {
        key_id_chirho: "2".repeat(64),
        key_byte_chirho: 0x22,
    };
    let winner_signer_chirho = AdoptionTestSignerChirho {
        key_id_chirho: "1".repeat(64),
        key_byte_chirho: 0x11,
    };
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "gd7-empty-adoption-chain-test-chirho".to_owned(),
    };
    let identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        reconciliation_checkpoint_ref_chirho: "3".repeat(64),
        winner_node_chirho: winner_signer_chirho.key_id_chirho(),
        held_node_chirho: held_signer_chirho.key_id_chirho(),
        winner_term_chirho: 7,
    };
    let store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &winner_signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    let initial_chirho = store_chirho.ensure_initialized_chirho().unwrap();
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "6".repeat(64),
        source_cut_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(7, 1).unwrap(),
            seq_chirho: 11,
            record_digest_chirho: "5".repeat(64),
        },
        lowest_page_ref_chirho: None,
        page_count_chirho: 0,
        row_count_chirho: 0,
    };
    let root_ref_chirho = digest_bytes_chirho(&canonical_json_chirho(&root_chirho).unwrap());
    let challenge_chirho = test_challenge_chirho_for_identity_chirho(
        &identity_chirho,
        store_chirho.identity_digest_chirho(),
        "4",
    );
    let challenged_chirho = store_chirho
        .commit_challenge_issued_chirho(
            &initial_chirho.checkpoint_ref_chirho,
            0,
            root_ref_chirho.clone(),
            0,
            0,
            &challenge_chirho.canonical_bytes_chirho().unwrap(),
        )
        .unwrap();
    let inspection_chirho = signed_inspection_chirho(
        &winner_signer_chirho,
        &challenge_chirho,
        &root_chirho,
        &root_ref_chirho,
        17,
    );
    let complete_chirho = store_chirho
        .commit_sealed_chirho(
            &challenged_chirho.checkpoint_ref_chirho,
            inspection_chirho,
            None,
        )
        .unwrap();
    let before_chirho = storage_chirho.snapshot_chirho();
    let verified_chirho = verify_complete_gd7_held_winner_view_chain_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &winner_signer_chirho,
        identity_chirho,
        &complete_chirho.checkpoint_ref_chirho,
    )
    .expect("zero-page Complete transfer is an exact empty chain");
    assert_eq!(verified_chirho.received_page_count_chirho(), 0);
    assert_eq!(verified_chirho.received_row_count_chirho(), 0);
    assert_eq!(storage_chirho.snapshot_chirho(), before_chirho);
}

#[test]
fn missing_or_replaced_interior_page_refuses_without_advancing_transfer_head_chirho() {
    let fixture_chirho = complete_transfer_fixture_chirho();
    let original_head_chirho = fixture_chirho.active_chirho.clone();
    let highest_page_path_chirho =
        gd7_held_view_transfer_received_page_path_chirho(&fixture_chirho.highest_page_ref_chirho)
            .expect("derive received highest-page path");
    fixture_chirho
        .storage_chirho
        .atomic_write_chirho(&highest_page_path_chirho, b"{}")
        .expect("replace one received page for the tamper test");

    assert!(matches!(
        verify_complete_gd7_held_winner_view_chain_chirho(
            &fixture_chirho.storage_chirho,
            &fixture_chirho.held_signer_chirho,
            &fixture_chirho.winner_signer_chirho,
            fixture_chirho.identity_chirho.clone(),
            &fixture_chirho.active_chirho.checkpoint_ref_chirho,
        ),
        Err(
            Gd7HeldWinnerViewVerificationRefusalChirho::CurrentViewChirho(
                Gd7WinnerCurrentViewRefusalChirho::MalformedBundlePageChirho
            )
        )
    ));
    let store_chirho = transfer_store_chirho(&fixture_chirho);
    assert_eq!(
        store_chirho
            .load_active_chirho()
            .expect("reload transfer head after page refusal")
            .expect("transfer head remains present"),
        original_head_chirho,
        "page verification must not mutate the durable transfer head"
    );
}

#[test]
fn complete_transfer_rejects_cross_page_order_and_interior_cumulative_lie_chirho() {
    for shape_chirho in [
        BundleShapeChirho::CrossPageOverlapChirho,
        BundleShapeChirho::InteriorCumulativeLieChirho,
    ] {
        let fixture_chirho = complete_transfer_fixture_with_shape_chirho(shape_chirho);
        assert_eq!(
            verify_complete_gd7_held_winner_view_chain_chirho(
                &fixture_chirho.storage_chirho,
                &fixture_chirho.held_signer_chirho,
                &fixture_chirho.winner_signer_chirho,
                fixture_chirho.identity_chirho.clone(),
                &fixture_chirho.active_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
            Gd7HeldWinnerViewVerificationRefusalChirho::InvalidReceivedChainChirho,
            "individually valid pages cannot hide a cross-page semantic defect"
        );
    }
}

#[test]
fn changed_winner_root_or_election_refuses_point_in_time_freshness_evidence_chirho() {
    let fixture_chirho = complete_transfer_fixture_chirho();
    let chain_chirho = verified_chain_chirho(&fixture_chirho);
    let held_node_chirho = NodeIdChirho(fixture_chirho.identity_chirho.held_node_chirho.clone());
    let winner_node_chirho =
        NodeIdChirho(fixture_chirho.identity_chirho.winner_node_chirho.clone());
    let stable_elector_chirho = AdoptionSequenceElectorChirho::stable_chirho(
        &held_node_chirho,
        &winner_node_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
    );
    let issued_challenge_chirho = generate_gd7_winner_current_view_challenge_chirho(
        &stable_elector_chirho,
        &fixture_chirho.group_chirho,
        &winner_node_chirho,
        &held_node_chirho,
        chain_chirho.transfer_identity_digest_chirho(),
    )
    .unwrap();
    let transport_challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
        &issued_challenge_chirho.canonical_bytes_chirho().unwrap(),
    )
    .unwrap();
    let mut changed_root_chirho = fixture_chirho.root_chirho.clone();
    changed_root_chirho.source_cut_chirho.seq_chirho += 1;
    changed_root_chirho.source_cut_chirho.record_digest_chirho = "8".repeat(64);
    let changed_root_ref_chirho =
        digest_bytes_chirho(&canonical_json_chirho(&changed_root_chirho).unwrap());
    let changed_inspection_chirho = signed_inspection_chirho(
        &fixture_chirho.winner_signer_chirho,
        &transport_challenge_chirho,
        &changed_root_chirho,
        &changed_root_ref_chirho,
        21,
    );
    assert_eq!(
        verify_fresh_gd7_held_winner_view_evidence_chirho(
            chain_chirho,
            &fixture_chirho.winner_signer_chirho,
            &stable_elector_chirho,
            &fixture_chirho.group_chirho,
            &winner_node_chirho,
            issued_challenge_chirho,
            &changed_inspection_chirho,
        )
        .unwrap_err(),
        Gd7HeldWinnerViewVerificationRefusalChirho::WinnerViewChangedChirho
    );

    let chain_chirho = verified_chain_chirho(&fixture_chirho);
    let changing_elector_chirho = AdoptionSequenceElectorChirho::changing_chirho(
        &held_node_chirho,
        &winner_node_chirho,
        fixture_chirho.identity_chirho.winner_term_chirho,
    );
    let issued_challenge_chirho = IssuedGd7WinnerCurrentViewChallengeChirho {
        challenge_chirho: test_challenge_chirho(
            &fixture_chirho,
            chain_chirho.transfer_identity_digest_chirho(),
            "7",
        ),
    };
    let transport_challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
        &issued_challenge_chirho.canonical_bytes_chirho().unwrap(),
    )
    .unwrap();
    let inspection_chirho = signed_inspection_chirho(
        &fixture_chirho.winner_signer_chirho,
        &transport_challenge_chirho,
        &fixture_chirho.root_chirho,
        &fixture_chirho.root_ref_chirho,
        22,
    );
    assert_eq!(
        verify_fresh_gd7_held_winner_view_evidence_chirho(
            chain_chirho,
            &fixture_chirho.winner_signer_chirho,
            &changing_elector_chirho,
            &fixture_chirho.group_chirho,
            &winner_node_chirho,
            issued_challenge_chirho,
            &inspection_chirho,
        )
        .unwrap_err(),
        Gd7HeldWinnerViewVerificationRefusalChirho::WinnerViewChangedChirho
    );
}

fn complete_transfer_fixture_chirho() -> CompleteTransferFixtureChirho {
    complete_transfer_fixture_with_shape_chirho(BundleShapeChirho::ExactChirho)
}

fn complete_transfer_fixture_with_shape_chirho(
    shape_chirho: BundleShapeChirho,
) -> CompleteTransferFixtureChirho {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let held_signer_chirho = AdoptionTestSignerChirho {
        key_id_chirho: "2".repeat(64),
        key_byte_chirho: 0x22,
    };
    let winner_signer_chirho = AdoptionTestSignerChirho {
        key_id_chirho: "1".repeat(64),
        key_byte_chirho: 0x11,
    };
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "gd7-adoption-chain-test-chirho".to_owned(),
    };
    let identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        reconciliation_checkpoint_ref_chirho: "3".repeat(64),
        winner_node_chirho: winner_signer_chirho.key_id_chirho(),
        held_node_chirho: held_signer_chirho.key_id_chirho(),
        winner_term_chirho: 7,
    };
    let store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &winner_signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    let initial_chirho = store_chirho.ensure_initialized_chirho().unwrap();
    let (root_chirho, root_ref_chirho, page_bytes_chirho) =
        bundle_chirho(&identity_chirho, shape_chirho);
    let challenge_chirho = test_challenge_chirho_for_identity_chirho(
        &identity_chirho,
        store_chirho.identity_digest_chirho(),
        "4",
    );
    let challenge_bytes_chirho = challenge_chirho.canonical_bytes_chirho().unwrap();
    let challenged_chirho = store_chirho
        .commit_challenge_issued_chirho(
            &initial_chirho.checkpoint_ref_chirho,
            0,
            root_ref_chirho.clone(),
            root_chirho.page_count_chirho,
            root_chirho.row_count_chirho,
            &challenge_bytes_chirho,
        )
        .unwrap();
    let inspection_chirho = signed_inspection_chirho(
        &winner_signer_chirho,
        &challenge_chirho,
        &root_chirho,
        &root_ref_chirho,
        17,
    );
    let grants_chirho = page_bytes_chirho
        .iter()
        .map(|bytes_chirho| {
            let page_chirho = parse_verified_inline_bundle_page_chirho(bytes_chirho).unwrap();
            signed_grant_chirho(
                &winner_signer_chirho,
                &identity_chirho,
                &inspection_chirho,
                page_chirho.page_chirho.page_index_chirho,
                &page_chirho.object_digest_chirho,
            )
        })
        .collect::<Vec<_>>();
    let sealed_chirho = store_chirho
        .commit_sealed_chirho(
            &challenged_chirho.checkpoint_ref_chirho,
            inspection_chirho,
            grants_chirho.first().cloned(),
        )
        .unwrap();
    let mut prior_ref_chirho = sealed_chirho.checkpoint_ref_chirho;
    let mut complete_chirho = None;
    for (index_chirho, (grant_chirho, bytes_chirho)) in grants_chirho
        .iter()
        .cloned()
        .zip(page_bytes_chirho.iter())
        .enumerate()
    {
        let committed_chirho = store_chirho
            .commit_received_page_chirho(
                &prior_ref_chirho,
                grant_chirho,
                bytes_chirho,
                grants_chirho.get(index_chirho + 1).cloned(),
            )
            .unwrap();
        prior_ref_chirho = committed_chirho.checkpoint_ref_chirho.clone();
        complete_chirho = Some(committed_chirho);
    }
    let complete_chirho = complete_chirho.expect("nonempty test bundle reaches Complete");
    let highest_page_ref_chirho = grants_chirho
        .last()
        .expect("nonempty test bundle has a highest page")
        .page_object_digest_chirho
        .clone();
    CompleteTransferFixtureChirho {
        storage_chirho,
        held_signer_chirho,
        winner_signer_chirho,
        identity_chirho,
        group_chirho,
        active_chirho: ActiveGd7HeldViewTransferChirho {
            checkpoint_ref_chirho: complete_chirho.checkpoint_ref_chirho,
            checkpoint_chirho: complete_chirho.checkpoint_chirho,
        },
        root_chirho,
        root_ref_chirho,
        highest_page_ref_chirho,
    }
}

fn verified_chain_chirho(
    fixture_chirho: &CompleteTransferFixtureChirho,
) -> VerifiedGd7HeldWinnerViewChainChirho {
    verify_complete_gd7_held_winner_view_chain_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.winner_signer_chirho,
        fixture_chirho.identity_chirho.clone(),
        &fixture_chirho.active_chirho.checkpoint_ref_chirho,
    )
    .unwrap()
}

fn transfer_store_chirho(
    fixture_chirho: &CompleteTransferFixtureChirho,
) -> Gd7HeldViewTransferStoreChirho<'_> {
    Gd7HeldViewTransferStoreChirho::new_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.winner_signer_chirho,
        fixture_chirho.identity_chirho.clone(),
    )
    .unwrap()
}

fn bundle_chirho(
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    shape_chirho: BundleShapeChirho,
) -> (Gd7WinnerViewBundleRootChirho, String, Vec<Vec<u8>>) {
    let source_cut_chirho = Gd7JournalTailCoordinateChirho {
        epoch_chirho: compose_writer_epoch_chirho(identity_chirho.winner_term_chirho, 1).unwrap(),
        seq_chirho: 11,
        record_digest_chirho: "5".repeat(64),
    };
    if matches!(shape_chirho, BundleShapeChirho::InteriorCumulativeLieChirho) {
        return three_page_cumulative_lie_bundle_chirho(identity_chirho, source_cut_chirho);
    }
    let mut high_rows_chirho = (0_u64..256)
        .map(|index_chirho| AccountNetProjectionRowChirho {
            account_chirho: account_chirho(format!("m-account-{index_chirho:04}-chirho")),
            account_net_chirho: index_chirho + 1,
        })
        .collect::<Vec<_>>();
    let low_rows_chirho = vec![
        AccountNetProjectionRowChirho {
            account_chirho: account_chirho("a-account-0000-chirho"),
            account_net_chirho: 7,
        },
        AccountNetProjectionRowChirho {
            account_chirho: account_chirho("a-account-0001-chirho"),
            account_net_chirho: 8,
        },
    ];
    let high_cumulative_row_count_chirho = match shape_chirho {
        BundleShapeChirho::ExactChirho => 256,
        BundleShapeChirho::CrossPageOverlapChirho => {
            high_rows_chirho[0].account_chirho =
                low_rows_chirho.last().unwrap().account_chirho.clone();
            256
        }
        BundleShapeChirho::InteriorCumulativeLieChirho => unreachable!(
            "the three-page cumulative-lie fixture returns before two-page construction"
        ),
    };
    let high_page_chirho = Gd7WinnerViewBundlePageChirho {
        schema_chirho: "gd7-winner-view-bundle-page-v1-chirho".to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "6".repeat(64),
        source_cut_chirho: source_cut_chirho.clone(),
        page_index_chirho: 0,
        higher_page_ref_chirho: None,
        next_upper_exclusive_account_chirho: Some(high_rows_chirho[0].account_chirho.clone()),
        rows_chirho: high_rows_chirho,
        cumulative_page_count_chirho: 1,
        cumulative_row_count_chirho: high_cumulative_row_count_chirho,
    };
    let high_bytes_chirho = canonical_json_chirho(&high_page_chirho).unwrap();
    parse_verified_inline_bundle_page_chirho(&high_bytes_chirho).unwrap();
    let high_ref_chirho = digest_bytes_chirho(&high_bytes_chirho);
    let low_page_chirho = Gd7WinnerViewBundlePageChirho {
        schema_chirho: "gd7-winner-view-bundle-page-v1-chirho".to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "6".repeat(64),
        source_cut_chirho: source_cut_chirho.clone(),
        page_index_chirho: 1,
        higher_page_ref_chirho: Some(high_ref_chirho),
        rows_chirho: low_rows_chirho,
        next_upper_exclusive_account_chirho: None,
        cumulative_page_count_chirho: 2,
        cumulative_row_count_chirho: 258,
    };
    let low_bytes_chirho = canonical_json_chirho(&low_page_chirho).unwrap();
    parse_verified_inline_bundle_page_chirho(&low_bytes_chirho).unwrap();
    let low_ref_chirho = digest_bytes_chirho(&low_bytes_chirho);
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "6".repeat(64),
        source_cut_chirho,
        lowest_page_ref_chirho: Some(low_ref_chirho),
        page_count_chirho: 2,
        row_count_chirho: 258,
    };
    let root_ref_chirho = digest_bytes_chirho(&canonical_json_chirho(&root_chirho).unwrap());
    (
        root_chirho,
        root_ref_chirho,
        vec![low_bytes_chirho, high_bytes_chirho],
    )
}

fn three_page_cumulative_lie_bundle_chirho(
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    source_cut_chirho: Gd7JournalTailCoordinateChirho,
) -> (Gd7WinnerViewBundleRootChirho, String, Vec<Vec<u8>>) {
    let high_rows_chirho = (0_u64..256)
        .map(|index_chirho| AccountNetProjectionRowChirho {
            account_chirho: account_chirho(format!("z-account-{index_chirho:04}-chirho")),
            account_net_chirho: index_chirho + 1,
        })
        .collect::<Vec<_>>();
    let high_page_chirho = bundle_page_chirho(
        identity_chirho,
        &source_cut_chirho,
        0,
        None,
        Some(high_rows_chirho[0].account_chirho.clone()),
        high_rows_chirho,
        1,
        256,
    );
    let high_bytes_chirho = canonical_json_chirho(&high_page_chirho).unwrap();
    parse_verified_inline_bundle_page_chirho(&high_bytes_chirho).unwrap();
    let high_ref_chirho = digest_bytes_chirho(&high_bytes_chirho);

    let middle_rows_chirho = (0_u64..256)
        .map(|index_chirho| AccountNetProjectionRowChirho {
            account_chirho: account_chirho(format!("m-account-{index_chirho:04}-chirho")),
            account_net_chirho: index_chirho + 1,
        })
        .collect::<Vec<_>>();
    let middle_page_chirho = bundle_page_chirho(
        identity_chirho,
        &source_cut_chirho,
        1,
        Some(high_ref_chirho),
        Some(middle_rows_chirho[0].account_chirho.clone()),
        middle_rows_chirho,
        2,
        511,
    );
    let middle_bytes_chirho = canonical_json_chirho(&middle_page_chirho).unwrap();
    parse_verified_inline_bundle_page_chirho(&middle_bytes_chirho).unwrap();
    let middle_ref_chirho = digest_bytes_chirho(&middle_bytes_chirho);

    let low_page_chirho = bundle_page_chirho(
        identity_chirho,
        &source_cut_chirho,
        2,
        Some(middle_ref_chirho),
        None,
        vec![AccountNetProjectionRowChirho {
            account_chirho: account_chirho("a-account-0000-chirho"),
            account_net_chirho: 7,
        }],
        3,
        513,
    );
    let low_bytes_chirho = canonical_json_chirho(&low_page_chirho).unwrap();
    parse_verified_inline_bundle_page_chirho(&low_bytes_chirho).unwrap();
    let low_ref_chirho = digest_bytes_chirho(&low_bytes_chirho);
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "6".repeat(64),
        source_cut_chirho,
        lowest_page_ref_chirho: Some(low_ref_chirho),
        page_count_chirho: 3,
        row_count_chirho: 513,
    };
    let root_ref_chirho = digest_bytes_chirho(&canonical_json_chirho(&root_chirho).unwrap());
    (
        root_chirho,
        root_ref_chirho,
        vec![low_bytes_chirho, middle_bytes_chirho, high_bytes_chirho],
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test builder spells one complete bounded page shape"
)]
fn bundle_page_chirho(
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    source_cut_chirho: &Gd7JournalTailCoordinateChirho,
    page_index_chirho: u64,
    higher_page_ref_chirho: Option<String>,
    next_upper_exclusive_account_chirho: Option<AccountIdChirho>,
    rows_chirho: Vec<AccountNetProjectionRowChirho>,
    cumulative_page_count_chirho: u64,
    cumulative_row_count_chirho: u64,
) -> Gd7WinnerViewBundlePageChirho {
    Gd7WinnerViewBundlePageChirho {
        schema_chirho: "gd7-winner-view-bundle-page-v1-chirho".to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "6".repeat(64),
        source_cut_chirho: source_cut_chirho.clone(),
        page_index_chirho,
        higher_page_ref_chirho,
        next_upper_exclusive_account_chirho,
        rows_chirho,
        cumulative_page_count_chirho,
        cumulative_row_count_chirho,
    }
}

fn test_challenge_chirho(
    fixture_chirho: &CompleteTransferFixtureChirho,
    transfer_identity_digest_chirho: &str,
    nonce_chirho: &str,
) -> Gd7WinnerCurrentViewChallengeChirho {
    test_challenge_chirho_for_identity_chirho(
        &fixture_chirho.identity_chirho,
        transfer_identity_digest_chirho,
        nonce_chirho,
    )
}

fn test_challenge_chirho_for_identity_chirho(
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    transfer_identity_digest_chirho: &str,
    nonce_chirho: &str,
) -> Gd7WinnerCurrentViewChallengeChirho {
    Gd7WinnerCurrentViewChallengeChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO.to_owned(),
        nonce_chirho: nonce_chirho.repeat(64),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        expected_winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        held_node_chirho: identity_chirho.held_node_chirho.clone(),
        transfer_identity_digest_chirho: transfer_identity_digest_chirho.to_owned(),
        raft_term_chirho: identity_chirho.winner_term_chirho,
    }
}

fn signed_inspection_chirho(
    signer_chirho: &AdoptionTestSignerChirho,
    challenge_chirho: &Gd7WinnerCurrentViewChallengeChirho,
    root_chirho: &Gd7WinnerViewBundleRootChirho,
    root_ref_chirho: &str,
    process_generation_chirho: u64,
) -> Gd7WinnerCurrentViewInspectionChirho {
    let mut evidence_chirho = Gd7WinnerCurrentViewEvidenceChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        challenge_digest_chirho: challenge_chirho.digest_chirho().unwrap(),
        consistency_group_digest_chirho: challenge_chirho
            .consistency_group_digest_chirho()
            .to_owned(),
        winner_node_chirho: challenge_chirho.expected_winner_node_chirho().to_owned(),
        raft_term_chirho: challenge_chirho.raft_term_chirho(),
        winner_process_generation_chirho: process_generation_chirho,
        winner_journal_genesis_digest_chirho: root_chirho
            .winner_journal_genesis_digest_chirho
            .clone(),
        latest_verified_journal_cut_chirho: root_chirho.source_cut_chirho.clone(),
        view_bundle_root_chirho: root_ref_chirho.to_owned(),
        key_id_chirho: signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    let unsigned_chirho = canonical_json_chirho(&evidence_chirho).unwrap();
    evidence_chirho.sig_chirho = signer_chirho
        .sign_chirho(std::str::from_utf8(&unsigned_chirho).unwrap())
        .unwrap();
    let evidence_object_digest_chirho =
        digest_bytes_chirho(&canonical_json_chirho(&evidence_chirho).unwrap());
    Gd7WinnerCurrentViewInspectionChirho {
        evidence_object_digest_chirho,
        evidence_chirho,
        bundle_root_object_digest_chirho: root_ref_chirho.to_owned(),
        bundle_root_chirho: root_chirho.clone(),
    }
}

fn signed_grant_chirho(
    signer_chirho: &AdoptionTestSignerChirho,
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    inspection_chirho: &Gd7WinnerCurrentViewInspectionChirho,
    page_index_chirho: u64,
    page_ref_chirho: &str,
) -> Gd7WinnerViewPageGrantChirho {
    let mut grant_chirho = Gd7WinnerViewPageGrantChirho {
        schema_chirho: GD7_WINNER_VIEW_PAGE_GRANT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        held_node_chirho: identity_chirho.held_node_chirho.clone(),
        winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        raft_term_chirho: identity_chirho.winner_term_chirho,
        winner_process_generation_chirho: inspection_chirho
            .evidence_chirho
            .winner_process_generation_chirho,
        winner_evidence_object_digest_chirho: inspection_chirho
            .evidence_object_digest_chirho
            .clone(),
        bundle_root_object_digest_chirho: inspection_chirho
            .bundle_root_object_digest_chirho
            .clone(),
        source_cut_chirho: inspection_chirho
            .bundle_root_chirho
            .source_cut_chirho
            .clone(),
        page_index_chirho,
        page_object_digest_chirho: page_ref_chirho.to_owned(),
        key_id_chirho: signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    let unsigned_chirho = canonical_json_chirho(&grant_chirho).unwrap();
    grant_chirho.sig_chirho = signer_chirho
        .sign_chirho(std::str::from_utf8(&unsigned_chirho).unwrap())
        .unwrap();
    grant_chirho
}

fn follower_leadership_chirho(
    winner_node_chirho: &NodeIdChirho,
    term_chirho: u64,
) -> LeadershipChirho {
    LeadershipChirho {
        is_leader_chirho: false,
        leader_id_chirho: Some(winner_node_chirho.clone()),
        term_chirho,
        lease_valid_chirho: false,
    }
}

fn account_chirho(owner_chirho: impl Into<String>) -> AccountIdChirho {
    AccountIdChirho::new_chirho(
        owner_chirho,
        AssetKindIdChirho("test-credits-chirho".to_owned()),
    )
}
