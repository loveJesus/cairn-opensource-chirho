// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn production_journal_append_ack_requires_both_http_follower_high_waters_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let journal_root_chirho = tempfile::tempdir().expect("journal signer root");
    let journal_verifying_key_hex_chirho = provision_node_chirho(journal_root_chirho.path());
    assert!(!fixture_chirho
        .serving_nodes_chirho
        .iter()
        .any(|node_chirho| node_chirho.node_id_chirho == journal_verifying_key_hex_chirho));
    let journal_verifier_chirho = Arc::new(
        LedgerMirrorJournalVerifierBindingChirho::new_chirho(
            JOURNAL_KEY_ID_CHIRHO.to_string(),
            journal_verifying_key_hex_chirho.clone(),
        )
        .expect("bind distinct journal verifier"),
    );
    let residency_chirho = MirrorResidencyPolicyChirho::allowed_domains_chirho(
        fixture_chirho
            .placement_chirho
            .intent_chirho()
            .residency_chirho
            .allowed_domains_chirho
            .clone(),
    );
    let mut follower_root_custody_chirho = Vec::new();
    let mut follower_stores_chirho = Vec::new();
    let mut follower_servers_chirho = Vec::new();
    let mut endpoints_chirho = BTreeMap::new();
    for follower_chirho in &fixture_chirho.serving_nodes_chirho[1..] {
        let follower_root_chirho = tempfile::tempdir().expect("follower mirror root");
        let follower_store_chirho = Arc::new(
            LedgerMirrorFollowerStoreChirho::open_chirho(
                follower_root_chirho.path(),
                follower_chirho.node_id_chirho.clone(),
                Arc::clone(&journal_verifier_chirho),
            )
            .expect("open production-path follower store"),
        );
        let election_view_chirho: Arc<dyn MirrorLeadershipViewChirho> =
            Arc::new(FixedElectionViewChirho {
                observation_chirho: election_observation_chirho(
                    &fixture_chirho.placement_chirho,
                    &leader_chirho.node_id_chirho,
                    false,
                ),
            });
        let server_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
            follower_chirho.node_id_chirho.clone(),
            follower_chirho.root_chirho().to_path_buf(),
            Arc::clone(&fixture_chirho.placement_chirho),
            election_view_chirho,
            residency_chirho.clone(),
            Arc::clone(&follower_store_chirho),
        )
        .expect("compose production-path follower server");
        let server_chirho = RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(
            server_state_chirho,
        ));
        endpoints_chirho.insert(
            follower_chirho.node_id_chirho.clone(),
            server_chirho.endpoint_chirho.clone(),
        );
        follower_root_custody_chirho.push(follower_root_chirho);
        follower_stores_chirho.push(follower_store_chirho);
        follower_servers_chirho.push(server_chirho);
    }
    let mirror_directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(endpoints_chirho.clone());

    let leader_store_root_chirho = tempfile::tempdir().expect("leader mirror root");
    let leader_store_chirho =
        LedgerMirrorLeaderStoreChirho::open_chirho(leader_store_root_chirho.path())
            .expect("open production leader reconciliation store");
    let leader_election_view_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                true,
            ),
        });
    let production_mirror_chirho: Arc<dyn LedgerAppendMirrorPortChirho> =
        Arc::new(ProductionLedgerAppendMirrorPortChirho::new_chirho(
            ProductionLedgerAppendMirrorInputChirho {
                local_node_id_chirho: leader_chirho.node_id_chirho.clone(),
                sign_root_chirho: leader_chirho.root_chirho().to_path_buf(),
                placement_chirho: Arc::clone(&fixture_chirho.placement_chirho),
                election_view_chirho: Arc::clone(&leader_election_view_chirho),
                residency_chirho: residency_chirho.clone(),
                directory_chirho: mirror_directory_chirho.clone(),
                leader_store_chirho,
                journal_verifier_chirho: Arc::clone(&journal_verifier_chirho),
            },
        ));

    let storage_chirho = TestLedgerStorageChirho::default();
    let signer_chirho = ExistingJournalSignerChirho {
        root_chirho: journal_root_chirho.path().to_path_buf(),
        verifying_key_hex_chirho: journal_verifying_key_hex_chirho,
    };
    let clock_chirho = FixedLedgerClockChirho;
    let membership_chirho = OpenTestMembershipChirho;
    let registry_chirho = TestMoneyRegistryChirho;
    let authority_chirho = TestMintAuthorityChirho;
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        JournalPortsChirho {
            storage_chirho: &storage_chirho,
            signer_chirho: &signer_chirho,
            clock_chirho: &clock_chirho,
            membership_chirho: &membership_chirho,
            kind_registry_chirho: &registry_chirho,
            authority_chirho: &authority_chirho,
        },
        StoragePathChirho::new_chirho("journals/production-mirror-chirho.jsonl"),
        ClusterIdChirho("cluster-production-mirror-chirho".to_string()),
        1,
    )
    .expect("create signed journal")
    .with_append_mirror_chirho(production_mirror_chirho);
    let receipt_chirho = journal_chirho
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
            idempotency_key_chirho: "production-mirror-append-0001-chirho".to_string(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
        })
        .expect("the local ACK waits for both production HTTP followers");

    assert_eq!(receipt_chirho.seq_chirho, 1);
    assert_eq!(journal_chirho.tail_seq_chirho(), 1);
    assert_eq!(follower_servers_chirho.len(), 2);
    assert_eq!(follower_root_custody_chirho.len(), 2);
    for store_chirho in follower_stores_chirho {
        let high_water_chirho = store_chirho
            .load_high_water_chirho()
            .expect("reverify production-path follower high water")
            .expect("ACK requires each follower high water");
        assert_eq!(high_water_chirho.record_chirho().record_seq_chirho, 1);
        assert_eq!(
            high_water_chirho.record_chirho().record_digest_chirho,
            receipt_chirho.record_digest_chirho.0
        );
    }

    let local_source_root_chirho = tempfile::tempdir().expect("local recovery source root");
    let local_source_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            local_source_root_chirho.path(),
            leader_chirho.node_id_chirho.clone(),
            Arc::clone(&journal_verifier_chirho),
        )
        .expect("open leader-local recovery source store"),
    );
    let ordinary_source_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            sign_root_chirho: leader_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&fixture_chirho.placement_chirho),
            election_view_chirho: Arc::clone(&leader_election_view_chirho),
            residency_chirho: residency_chirho.clone(),
            directory_chirho: mirror_directory_chirho.clone(),
            follower_store_chirho: Arc::clone(&local_source_store_chirho),
        },
    );
    let local_tail_chirho = journal_chirho.verified_append_mirror_tail_chirho();
    let challenge_chirho =
        LedgerMirrorOrdinaryTermAcceptanceChallengeChirho::from_entropy_chirho([7_u8; 32]);
    let receipt_wires_chirho = ordinary_source_chirho
        .read_ordinary_term_acceptance_receipts_chirho(&challenge_chirho, &local_tail_chirho)
        .expect("both production HTTP holders re-attest the exact acknowledged tail");
    let raw_group_digest_chirho = RawCanonicalGroupIdDigestChirho::from_canonical_group_id_chirho(
        &fixture_chirho
            .placement_chirho
            .intent_chirho()
            .consistency_group_id_chirho,
    );
    let placement_binding_chirho =
        LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho::new_chirho(
            fixture_chirho
                .placement_chirho
                .assignment_digest_chirho()
                .to_owned(),
            fixture_chirho
                .placement_chirho
                .assigned_nodes_chirho()
                .iter()
                .map(|node_chirho| node_chirho.node_id_chirho.clone())
                .collect::<Vec<_>>()
                .try_into()
                .expect("production placement has exactly three assigned nodes"),
        )
        .expect("verified placement forms one local ordinary-term binding");
    let verified_chirho = VerifiedOrdinaryElectionSinkTermAcceptanceChirho::verify_chirho(
        &receipt_wires_chirho,
        LedgerMirrorOrdinaryTermAcceptanceExpectationChirho {
            challenge_chirho: &challenge_chirho,
            consistency_group_digest_chirho: &raw_group_digest_chirho,
            placement_binding_chirho: &placement_binding_chirho,
            local_leader_node_id_chirho: &leader_chirho.node_id_chirho,
            published_raft_term_chirho: TERM_CHIRHO,
            local_tail_chirho: &local_tail_chirho,
        },
    )
    .expect("the complete holder population mints one private ordinary-election proof");
    assert_eq!(verified_chirho.accepted_term_chirho(), TERM_CHIRHO);
    assert_eq!(verified_chirho.tail_seq_chirho(), receipt_chirho.seq_chirho);
    assert_eq!(
        verified_chirho.tail_record_digest_chirho(),
        receipt_chirho.record_digest_chirho.0
    );

    let duplicated_holder_receipt_wires_chirho = [
        receipt_wires_chirho[0].clone(),
        receipt_wires_chirho[0].clone(),
    ];
    let duplicated_holder_refusal_chirho =
        match VerifiedOrdinaryElectionSinkTermAcceptanceChirho::verify_chirho(
            &duplicated_holder_receipt_wires_chirho,
            LedgerMirrorOrdinaryTermAcceptanceExpectationChirho {
                challenge_chirho: &challenge_chirho,
                consistency_group_digest_chirho: &raw_group_digest_chirho,
                placement_binding_chirho: &placement_binding_chirho,
                local_leader_node_id_chirho: &leader_chirho.node_id_chirho,
                published_raft_term_chirho: TERM_CHIRHO,
                local_tail_chirho: &local_tail_chirho,
            },
        ) {
            Ok(_) => panic!("one holder cannot occupy both required receipt slots"),
            Err(error_chirho) => error_chirho,
        };
    assert_eq!(
        duplicated_holder_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptHolderPopulationRefusedChirho"
    );
    assert_ne!(
        duplicated_holder_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptExpectedPlacementBindingRefusedChirho"
    );
    assert_ne!(
        duplicated_holder_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptPairBindingMismatchRefusedChirho"
    );

    let wrong_placement_binding_chirho =
        LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho::new_chirho(
            "f".repeat(64),
            fixture_chirho
                .placement_chirho
                .assigned_nodes_chirho()
                .iter()
                .map(|node_chirho| node_chirho.node_id_chirho.clone())
                .collect::<Vec<_>>()
                .try_into()
                .expect("production placement has exactly three assigned nodes"),
        )
        .expect("the negative arm carries a well-shaped but wrong placement binding");
    let wrong_placement_refusal_chirho =
        match VerifiedOrdinaryElectionSinkTermAcceptanceChirho::verify_chirho(
            &receipt_wires_chirho,
            LedgerMirrorOrdinaryTermAcceptanceExpectationChirho {
                challenge_chirho: &challenge_chirho,
                consistency_group_digest_chirho: &raw_group_digest_chirho,
                placement_binding_chirho: &wrong_placement_binding_chirho,
                local_leader_node_id_chirho: &leader_chirho.node_id_chirho,
                published_raft_term_chirho: TERM_CHIRHO,
                local_tail_chirho: &local_tail_chirho,
            },
        ) {
            Ok(_) => panic!("two agreeing signatures cannot choose a different local assignment"),
            Err(error_chirho) => error_chirho,
        };
    assert_eq!(
        wrong_placement_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptExpectedPlacementBindingRefusedChirho"
    );
    assert_ne!(
        wrong_placement_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptHolderPopulationRefusedChirho"
    );

    let joined_for_mismatch_chirho = join_mirror_view_chirho(
        &fixture_chirho.placement_chirho,
        leader_election_view_chirho.as_ref(),
    )
    .expect("derive the exact current placement/election join for the signed mismatch arm");
    let assigned_node_ids_chirho = placement_binding_chirho.assigned_node_ids_chirho().clone();
    let sign_mismatched_receipt_chirho = |holder_index_chirho: usize| {
        LedgerMirrorOrdinaryTermAcceptanceReceiptChirho::sign_chirho(
            LedgerMirrorOrdinaryTermAcceptanceReceiptInputChirho {
                challenge_nonce_hex_chirho: challenge_chirho.as_str_chirho().to_owned(),
                current_consistency_group_digest_chirho: raw_group_digest_chirho
                    .as_str_chirho()
                    .to_owned(),
                current_assignment_digest_chirho: placement_binding_chirho
                    .assignment_digest_chirho()
                    .to_owned(),
                current_assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
                current_leader_node_id_chirho: leader_chirho.node_id_chirho.clone(),
                current_membership_view_digest_chirho: joined_for_mismatch_chirho
                    .view_chirho()
                    .view_digest_chirho(),
                current_term_chirho: TERM_CHIRHO,
                acknowledged_consistency_group_digest_chirho: raw_group_digest_chirho
                    .as_str_chirho()
                    .to_owned(),
                acknowledged_assignment_digest_chirho: placement_binding_chirho
                    .assignment_digest_chirho()
                    .to_owned(),
                acknowledged_assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
                acknowledged_leader_node_id_chirho: leader_chirho.node_id_chirho.clone(),
                acknowledged_membership_view_digest_chirho: joined_for_mismatch_chirho
                    .view_chirho()
                    .view_digest_chirho(),
                acknowledged_term_chirho: TERM_CHIRHO + 1,
                holder_node_id_chirho: fixture_chirho.serving_nodes_chirho[holder_index_chirho]
                    .node_id_chirho
                    .clone(),
                cluster_id_chirho: local_tail_chirho.cluster_id_chirho().0.clone(),
                journal_genesis_digest_chirho: local_tail_chirho
                    .journal_genesis_digest_chirho()
                    .0
                    .clone(),
                tail_seq_chirho: local_tail_chirho.tail_seq_chirho(),
                tail_record_digest_chirho: local_tail_chirho.tail_record_digest_chirho().0.clone(),
                tail_epoch_chirho: local_tail_chirho.tail_record_epoch_chirho(),
                tail_hlc_physical_ms_chirho: local_tail_chirho.tail_hlc_chirho().physical_ms_chirho,
                tail_hlc_logical_chirho: local_tail_chirho.tail_hlc_chirho().logical_chirho,
            },
            fixture_chirho.serving_nodes_chirho[holder_index_chirho].root_chirho(),
        )
        .expect("sign a valid current/acknowledged mismatch receipt")
        .to_wire_bytes_chirho()
        .expect("encode a valid current/acknowledged mismatch receipt")
    };
    let mismatched_receipt_wires_chirho = [
        sign_mismatched_receipt_chirho(1),
        sign_mismatched_receipt_chirho(2),
    ];
    let current_acknowledged_refusal_chirho =
        match VerifiedOrdinaryElectionSinkTermAcceptanceChirho::verify_chirho(
            &mismatched_receipt_wires_chirho,
            LedgerMirrorOrdinaryTermAcceptanceExpectationChirho {
                challenge_chirho: &challenge_chirho,
                consistency_group_digest_chirho: &raw_group_digest_chirho,
                placement_binding_chirho: &placement_binding_chirho,
                local_leader_node_id_chirho: &leader_chirho.node_id_chirho,
                published_raft_term_chirho: TERM_CHIRHO,
                local_tail_chirho: &local_tail_chirho,
            },
        ) {
            Ok(_) => panic!("current authority cannot relabel an ACK from a different term"),
            Err(error_chirho) => error_chirho,
        };
    assert_eq!(
        current_acknowledged_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptCurrentAcknowledgedAuthorityMismatchRefusedChirho"
    );
    assert_ne!(
        current_acknowledged_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptPairBindingMismatchRefusedChirho"
    );

    let replay_challenge_chirho =
        LedgerMirrorOrdinaryTermAcceptanceChallengeChirho::from_entropy_chirho([8_u8; 32]);
    let replay_refusal_chirho =
        match VerifiedOrdinaryElectionSinkTermAcceptanceChirho::verify_chirho(
            &receipt_wires_chirho,
            LedgerMirrorOrdinaryTermAcceptanceExpectationChirho {
                challenge_chirho: &replay_challenge_chirho,
                consistency_group_digest_chirho: &raw_group_digest_chirho,
                placement_binding_chirho: &placement_binding_chirho,
                local_leader_node_id_chirho: &leader_chirho.node_id_chirho,
                published_raft_term_chirho: TERM_CHIRHO,
                local_tail_chirho: &local_tail_chirho,
            },
        ) {
            Ok(_) => panic!("a prior pair cannot answer a fresh challenge"),
            Err(error_chirho) => error_chirho,
        };
    assert_eq!(
        replay_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptChallengeMismatchRefusedChirho"
    );
    let stale_term_refusal_chirho =
        match VerifiedOrdinaryElectionSinkTermAcceptanceChirho::verify_chirho(
            &receipt_wires_chirho,
            LedgerMirrorOrdinaryTermAcceptanceExpectationChirho {
                challenge_chirho: &challenge_chirho,
                consistency_group_digest_chirho: &raw_group_digest_chirho,
                placement_binding_chirho: &placement_binding_chirho,
                local_leader_node_id_chirho: &leader_chirho.node_id_chirho,
                published_raft_term_chirho: TERM_CHIRHO + 1,
                local_tail_chirho: &local_tail_chirho,
            },
        ) {
            Ok(_) => panic!("a signed prior-term pair cannot satisfy the held local generation"),
            Err(error_chirho) => error_chirho,
        };
    assert_eq!(
        stale_term_refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptExpectedAuthorityBindingRefusedChirho"
    );

    let first_local_observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        true,
    );
    let mut expired_local_observation_chirho = first_local_observation_chirho.clone();
    expired_local_observation_chirho
        .leadership_chirho
        .lease_valid_chirho = false;
    expired_local_observation_chirho.leader_lease_remaining_millis_chirho = None;
    let sequenced_election_view_chirho = Arc::new(SequencedElectionViewChirho {
        first_chirho: first_local_observation_chirho,
        later_chirho: expired_local_observation_chirho,
        calls_chirho: AtomicUsize::new(0),
    });
    let authority_loss_source_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            sign_root_chirho: leader_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&fixture_chirho.placement_chirho),
            election_view_chirho: sequenced_election_view_chirho.clone(),
            residency_chirho: residency_chirho.clone(),
            directory_chirho: mirror_directory_chirho.clone(),
            follower_store_chirho: Arc::clone(&local_source_store_chirho),
        },
    );
    let authority_loss_refusal_chirho = authority_loss_source_chirho
        .read_ordinary_term_acceptance_receipts_chirho(&challenge_chirho, &local_tail_chirho)
        .expect_err("a receipt pair cannot survive loss of the local leader lease after its read");
    assert_eq!(
        authority_loss_refusal_chirho.detail_chirho(),
        "LedgerMirrorLocalLeaderAuthorityRefusedChirho"
    );
    assert_ne!(
        authority_loss_refusal_chirho.detail_chirho(),
        "LedgerMirrorOrdinaryTermAuthorityChangedAfterReceiptReadChirho"
    );
    assert_eq!(
        sequenced_election_view_chirho
            .calls_chirho
            .load(Ordering::SeqCst),
        2,
        "the refusal must come from the post-receipt local authority observation"
    );

    endpoints_chirho.remove(&fixture_chirho.serving_nodes_chirho[2].node_id_chirho);
    let degraded_source_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            sign_root_chirho: leader_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&fixture_chirho.placement_chirho),
            election_view_chirho: leader_election_view_chirho,
            residency_chirho,
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(endpoints_chirho),
            follower_store_chirho: local_source_store_chirho,
        },
    );
    let degraded_refusal_chirho = degraded_source_chirho
        .read_ordinary_term_acceptance_receipts_chirho(&challenge_chirho, &local_tail_chirho)
        .expect_err("ordinary term acceptance never degrades to one holder");
    assert!(
        degraded_refusal_chirho
            .detail_chirho()
            .contains("LedgerMirrorPeerEndpointUnavailableChirho"),
        "unexpected single-holder refusal: {}",
        degraded_refusal_chirho.detail_chirho()
    );
}
