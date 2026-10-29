// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

fn independently_minted_same_seq_journal_chirho(
    initial_journal_chirho: &[u8],
    expected_seq_chirho: u64,
    forbidden_digest_chirho: &str,
) -> Vec<u8> {
    let divergent_fixture_chirho = TenantRegenesisFixtureChirho::new_chirho();
    run_ledger_regenesis_chirho(request_chirho(&divergent_fixture_chirho.fixture_chirho))
        .expect("publish the independent same-sequence branch fixture");
    let divergent_config_chirho = ledger_config_chirho(&divergent_fixture_chirho.fixture_chirho);
    assert_eq!(
        std::fs::read(journal_path_chirho(
            &divergent_fixture_chirho.fixture_chirho.root_chirho,
            &divergent_config_chirho,
        ))
        .expect("read the independent branch genesis"),
        initial_journal_chirho,
        "the equal-sequence branch must start from the same canonical genesis"
    );
    let divergent_fleet_chirho =
        build_reopened_a6_cluster_fleet_chirho(&divergent_fixture_chirho.fixture_chirho);
    let divergent_composition_chirho =
        A6GeoResidentAuthorityCompositionChirho::from_cluster_node_chirho(
            &divergent_fleet_chirho.nodes_chirho[0],
        )
        .expect("compose the independent same-sequence writer");
    let mut divergent_actor_chirho = open_unmirrored_shared_elector_test_fixture_chirho(
        &divergent_composition_chirho,
        &divergent_fixture_chirho.fixture_chirho.root_chirho,
        &divergent_fixture_chirho.fixture_chirho.config_path_chirho,
        &divergent_config_chirho,
    )
    .expect("open the independent same-sequence writer");
    let divergent_intent_chirho = signed_hold_line_with_request_ref_chirho(
        &divergent_fixture_chirho.fixture_chirho,
        &divergent_config_chirho,
        &divergent_actor_chirho,
        '8',
    );
    let divergent_receipt_chirho = divergent_actor_chirho
        .append_hold_chirho(&divergent_intent_chirho)
        .expect("commit the independently authorized same-sequence branch");
    let divergent_record_chirho = last_journal_record_chirho(
        &divergent_fixture_chirho.fixture_chirho.root_chirho,
        &divergent_config_chirho,
    );
    let divergent_coordinate_chirho = record_coordinate_chirho(&divergent_record_chirho);
    assert_eq!(divergent_receipt_chirho.seq_chirho, expected_seq_chirho);
    assert_eq!(divergent_coordinate_chirho.0, expected_seq_chirho);
    assert_ne!(
        divergent_coordinate_chirho.1, forbidden_digest_chirho,
        "the equal-sequence branch must carry a different record digest"
    );
    let divergent_journal_chirho = std::fs::read(journal_path_chirho(
        &divergent_fixture_chirho.fixture_chirho.root_chirho,
        &divergent_config_chirho,
    ))
    .expect("snapshot the independently authorized same-sequence branch");
    drop(divergent_actor_chirho);
    drop(divergent_composition_chirho);
    drop(divergent_fleet_chirho);
    divergent_journal_chirho
}

fn assert_recovery_refusal_identity_chirho(
    refusal_chirho: &anyhow::Error,
    expected_identity_chirho: &str,
    neighbouring_identities_chirho: &[&str],
) {
    let detail_chirho = refusal_chirho.to_string();
    let observed_identity_chirho = detail_chirho
        .strip_prefix("resident effect-journal actor refused startup: ")
        .unwrap_or(&detail_chirho);
    assert_eq!(
        observed_identity_chirho, expected_identity_chirho,
        "startup must preserve the exact recovery refusal identity"
    );
    for neighbouring_identity_chirho in neighbouring_identities_chirho {
        assert_ne!(
            observed_identity_chirho, *neighbouring_identity_chirho,
            "refusal {expected_identity_chirho} must not collapse to its neighbour"
        );
    }
}

#[test]
fn three_node_ack_adopts_without_the_old_leader_and_quarantines_its_suffix_chirho() {
    let mut fixtures_chirho = (0..3)
        .map(|_| TenantRegenesisFixtureChirho::new_chirho())
        .collect::<Vec<_>>();
    fixtures_chirho.sort_by_key(TenantRegenesisFixtureChirho::node_id_chirho);
    for fixture_chirho in &fixtures_chirho {
        run_ledger_regenesis_chirho(request_chirho(&fixture_chirho.fixture_chirho))
            .expect("publish one independently rooted tenant journal");
    }
    let configs_chirho = fixtures_chirho
        .iter()
        .map(|fixture_chirho| ledger_config_chirho(&fixture_chirho.fixture_chirho))
        .collect::<Vec<_>>();
    let initial_journal_chirho = std::fs::read(journal_path_chirho(
        &fixtures_chirho[0].fixture_chirho.root_chirho,
        &configs_chirho[0],
    ))
    .expect("read initial leader journal");
    for (fixture_chirho, config_chirho) in fixtures_chirho.iter().zip(configs_chirho.iter()) {
        assert_eq!(
            std::fs::read(journal_path_chirho(
                &fixture_chirho.fixture_chirho.root_chirho,
                config_chirho,
            ))
            .expect("read independently regenerated peer journal"),
            initial_journal_chirho,
            "all three independent tenant roots must start from the identical verified cut"
        );
    }

    let held_sign_root_chirho = fixtures_chirho[0]
        .platform_root_chirho
        .join("held-observer-signing-chirho");
    let fleet_chirho =
        build_recovery_cluster_fleet_chirho(&fixtures_chirho, &held_sign_root_chirho);
    let placement_chirho = recovery_placement_chirho(&fixtures_chirho, &held_sign_root_chirho);
    let mut serving_listeners_chirho = (0..3)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").expect("bind serving mirror listener")))
        .collect::<Vec<_>>();
    let serving_addresses_chirho = serving_listeners_chirho
        .iter()
        .map(|listener_chirho| {
            listener_chirho
                .as_ref()
                .expect("reserved mirror listener")
                .local_addr()
                .expect("serving mirror address")
        })
        .collect::<Vec<_>>();
    let held_listener_chirho =
        TcpListener::bind("127.0.0.1:0").expect("reserve held observer endpoint");
    let held_address_chirho = held_listener_chirho
        .local_addr()
        .expect("held observer address");
    drop(held_listener_chirho);
    let endpoints_chirho = mirror_peer_endpoints_chirho(
        &fixtures_chirho,
        &fleet_chirho.held_node_chirho,
        &serving_addresses_chirho,
        held_address_chirho,
    );
    let leader_composition_chirho = compose_recovery_mirror_chirho(
        &fixtures_chirho[0],
        &fleet_chirho.nodes_chirho[0],
        Arc::clone(&placement_chirho),
        &endpoints_chirho,
    );
    let adopter_composition_chirho = compose_recovery_mirror_chirho(
        &fixtures_chirho[1],
        &fleet_chirho.nodes_chirho[1],
        Arc::clone(&placement_chirho),
        &endpoints_chirho,
    );
    let third_composition_chirho = compose_recovery_mirror_chirho(
        &fixtures_chirho[2],
        &fleet_chirho.nodes_chirho[2],
        Arc::clone(&placement_chirho),
        &endpoints_chirho,
    );
    let LedgerAppendMirrorCompositionChirho {
        runtime_ports_chirho: leader_runtime_chirho,
        router_chirho: leader_router_chirho,
    } = leader_composition_chirho;
    let LedgerAppendMirrorCompositionChirho {
        runtime_ports_chirho: adopter_runtime_chirho,
        router_chirho: adopter_router_chirho,
    } = adopter_composition_chirho;
    let LedgerAppendMirrorCompositionChirho {
        runtime_ports_chirho: _third_runtime_chirho,
        router_chirho: third_router_chirho,
    } = third_composition_chirho;
    drop(
        serving_listeners_chirho[0]
            .take()
            .expect("release the absent old-leader endpoint"),
    );
    let _adopter_server_chirho = RunningRecoveryMirrorServerChirho::start_chirho(
        serving_listeners_chirho[1]
            .take()
            .expect("adopter listener"),
        adopter_router_chirho,
    );
    let _third_server_chirho = RunningRecoveryMirrorServerChirho::start_chirho(
        serving_listeners_chirho[2]
            .take()
            .expect("third-node listener"),
        third_router_chirho,
    );
    // Wait for the leader's lease to be WARM rather than for one tick's worth of wall clock: a fixed
    // count expresses "this much clock has probably passed", which is true idle and false loaded.
    // The fixture's 250 ms tick matches the deployed leader coordinate, so its election-derived
    // 2.5-second lease can cover the real actor startup and mirrored append under concurrent tests.
    drive_cluster_ticks_until_lease_warm_chirho(&fleet_chirho.nodes_chirho, 0, 40);
    let mut leader_actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &fixtures_chirho[0].fixture_chirho.root_chirho,
        &fixtures_chirho[0].fixture_chirho.config_path_chirho,
        &configs_chirho[0],
        fleet_chirho.nodes_chirho[0].elector_chirho(),
        Some(leader_runtime_chirho),
        None,
    )
    .expect("the original leader bootstraps A+B and opens");
    let acknowledged_intent_chirho = signed_hold_line_chirho(
        &fixtures_chirho[0].fixture_chirho,
        &configs_chirho[0],
        &leader_actor_chirho,
    );
    drive_cluster_warm_ticks_chirho(&fleet_chirho.nodes_chirho, 1);
    drop(
        fleet_chirho.nodes_chirho[0]
            .elector_chirho()
            .local_append_authority_handle_chirho()
            .try_acquire_chirho()
            .expect("the original write starts from one stable local append generation"),
    );
    let acknowledged_receipt_chirho = leader_actor_chirho
        .append_hold_chirho(&acknowledged_intent_chirho)
        .expect("the original leader ACKs only after A+B finalize");
    let acknowledged_record_chirho = last_journal_record_chirho(
        &fixtures_chirho[0].fixture_chirho.root_chirho,
        &configs_chirho[0],
    );
    let acknowledged_coordinate_chirho = record_coordinate_chirho(&acknowledged_record_chirho);
    assert_eq!(
        acknowledged_receipt_chirho.seq_chirho,
        acknowledged_coordinate_chirho.0
    );
    for holder_chirho in [&fixtures_chirho[1], &fixtures_chirho[2]] {
        let high_water_chirho =
            follower_high_water_chirho(&holder_chirho.fixture_chirho.root_chirho);
        assert_eq!(
            high_water_chirho["record_chirho"]["record_seq_chirho"].as_u64(),
            Some(acknowledged_coordinate_chirho.0)
        );
        assert_eq!(
            high_water_chirho["record_chirho"]["record_digest_chirho"].as_str(),
            Some(acknowledged_coordinate_chirho.1.as_str())
        );
    }
    drop(leader_actor_chirho);
    drive_cluster_warm_ticks_chirho(&fleet_chirho.nodes_chirho, 1);

    // This lower test seam constructs the production-reachable crash state: local commit completed,
    // but no follower FINALIZE was allowed to make the line acknowledged.
    let mut divergent_actor_chirho =
        open_resident_effect_journal_handle_with_shared_elector_chirho(
            &fixtures_chirho[0].fixture_chirho.root_chirho,
            &fixtures_chirho[0].fixture_chirho.config_path_chirho,
            &configs_chirho[0],
            fleet_chirho.nodes_chirho[0].elector_chirho(),
            None,
            None,
        )
        .expect("open the bounded unmirrored crash-state fixture");
    let divergent_intent_chirho = signed_hold_line_chirho(
        &fixtures_chirho[0].fixture_chirho,
        &configs_chirho[0],
        &divergent_actor_chirho,
    );
    let divergent_receipt_chirho = divergent_actor_chirho
        .append_hold_chirho(&divergent_intent_chirho)
        .expect("persist the committed-but-unacknowledged losing suffix");
    let divergent_record_chirho = last_journal_record_chirho(
        &fixtures_chirho[0].fixture_chirho.root_chirho,
        &configs_chirho[0],
    );
    let divergent_coordinate_chirho = record_coordinate_chirho(&divergent_record_chirho);
    assert_eq!(
        divergent_receipt_chirho.seq_chirho,
        divergent_coordinate_chirho.0
    );
    assert_eq!(
        divergent_coordinate_chirho.0,
        acknowledged_coordinate_chirho.0 + 1
    );
    let divergent_journal_bytes_chirho = std::fs::read(journal_path_chirho(
        &fixtures_chirho[0].fixture_chirho.root_chirho,
        &configs_chirho[0],
    ))
    .expect("snapshot the old leader's divergent canonical journal");
    drop(divergent_actor_chirho);

    let warmup_chirho =
        drive_recovery_until_adopter_warm_without_old_leader_chirho(&fleet_chirho.nodes_chirho);
    eprintln!(
        "RecoveryWarmupChirho:ticks_chirho={}:transfers_chirho={:?}",
        warmup_chirho.ticks_chirho, warmup_chirho.transfers_chirho
    );
    let adopter_leadership_chirho = fleet_chirho.nodes_chirho[1]
        .elector_chirho()
        .current_leadership_chirho();
    assert!(adopter_leadership_chirho.is_leader_chirho);
    assert!(adopter_leadership_chirho.lease_valid_chirho);
    assert_eq!(
        adopter_leadership_chirho.leader_id_chirho.as_ref(),
        Some(&fixtures_chirho[1].node_id_chirho())
    );
    let adopter_group_chirho =
        consistency_group_for_root_chirho(&fixtures_chirho[1].fixture_chirho.root_chirho)
            .expect("derive adopter group for the fence-only crash state");
    let adopter_fence_path_chirho = writer_fence_path_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &adopter_group_chirho,
    )
    .expect("derive adopter writer-fence path");
    let adopter_canary_root_chirho = fixtures_chirho[1]
        .fixture_chirho
        .root_chirho
        .join(&configs_chirho[1].monitor_evidence_namespace_chirho)
        .join("writer-canary-chirho");
    let canary_generation_head_path_chirho =
        adopter_canary_root_chirho.join("generation-head-chirho.json");
    let conflicting_generation_descriptor_path_chirho = adopter_canary_root_chirho
        .join("generations-chirho")
        .join("generation-00000000000000000001-chirho")
        .join("adoption-generation-chirho.json");
    std::fs::create_dir_all(
        conflicting_generation_descriptor_path_chirho
            .parent()
            .expect("W1 conflict descriptor has a parent"),
    )
    .expect("create the W1 immutable-generation conflict directory");
    std::fs::write(
        &conflicting_generation_descriptor_path_chirho,
        b"not-a-shadow-canary-generation-chirho",
    )
    .expect("plant the W1 post-fence canary-commit refusal");
    let adopter_clock_without_old_leader_chirho =
        RunningRecoveryElectionClockChirho::start_chirho(&fleet_chirho.nodes_chirho, 1, vec![1, 4]);
    let w1_refusal_chirho = match open_resident_effect_journal_handle_with_shared_elector_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &fixtures_chirho[1].fixture_chirho.config_path_chirho,
        &configs_chirho[1],
        fleet_chirho.nodes_chirho[1].elector_chirho(),
        Some(adopter_runtime_chirho.clone()),
        None,
    ) {
        Ok(_unexpected_actor_chirho) => {
            panic!("W1 must stop after the fence and before the adoption head")
        }
        Err(error_chirho) => error_chirho,
    };
    assert!(
        w1_refusal_chirho
            .to_string()
            .contains("decode immutable shadow canary generation"),
        "W1 must attribute to the post-fence canary commit, got {w1_refusal_chirho}"
    );
    assert!(
        !canary_generation_head_path_chirho.exists(),
        "W1 has a prospective current-term fence but no committed adoption selector"
    );
    assert_eq!(
        std::fs::read(journal_path_chirho(
            &fixtures_chirho[1].fixture_chirho.root_chirho,
            &configs_chirho[1],
        ))
        .expect("read W1 adopter canonical journal"),
        initial_journal_chirho,
        "the orphaned prospective fence must not install imported bytes"
    );
    let w1_fence_epoch_chirho = persisted_writer_epoch_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &adopter_group_chirho,
    )
    .expect("W1 leaves the production recovery fence durable");
    assert_eq!(
        u64::from(split_writer_epoch_chirho(w1_fence_epoch_chirho).geo_term_chirho),
        adopter_leadership_chirho.term_chirho,
        "W1 recovery fence must bind the adopter's current elected term"
    );
    let w1_fence_bytes_chirho =
        std::fs::read(&adopter_fence_path_chirho).expect("snapshot the W1 prospective fence");
    let w1_candidates_root_chirho = fixtures_chirho[1]
        .fixture_chirho
        .root_chirho
        .join(&configs_chirho[1].storage_namespace_chirho)
        .join("f1-recovery-adoption-chirho")
        .join("candidates-chirho");
    let w1_candidate_count_chirho = std::fs::read_dir(&w1_candidates_root_chirho)
        .expect("W1 leaves one inert candidate population")
        .filter_map(Result::ok)
        .filter(|entry_chirho| {
            entry_chirho
                .path()
                .join("candidate-journal-chirho.jsonl")
                .is_file()
        })
        .count();
    assert_eq!(
        w1_candidate_count_chirho, 1,
        "the post-fence/pre-head crash leaves exactly one inert candidate"
    );
    let w1_recovery_file_population_chirho = relative_file_population_chirho(
        w1_candidates_root_chirho
            .parent()
            .expect("W1 candidates root has a recovery root"),
    );
    let w1_candidate_paths_chirho = w1_recovery_file_population_chirho
        .iter()
        .filter(|path_chirho| path_chirho.ends_with("/candidate-journal-chirho.jsonl"))
        .collect::<Vec<_>>();
    let [w1_candidate_relative_path_chirho] = w1_candidate_paths_chirho.as_slice() else {
        panic!(
            "W1 must leave exactly one inert candidate file, got {w1_recovery_file_population_chirho:?}"
        );
    };
    let w1_candidate_binding_chirho = w1_candidate_relative_path_chirho
        .strip_prefix("candidates-chirho/")
        .and_then(|path_chirho| path_chirho.strip_suffix("/candidate-journal-chirho.jsonl"))
        .expect("W1 candidate path carries its binding digest");
    let w1_candidate_bytes_chirho = std::fs::read(
        w1_candidates_root_chirho
            .parent()
            .expect("W1 candidates root has a recovery root")
            .join(w1_candidate_relative_path_chirho),
    )
    .expect("read W1 inert candidate journal");
    let w1_candidate_text_chirho =
        std::str::from_utf8(&w1_candidate_bytes_chirho).expect("W1 candidate is canonical UTF-8");
    let mut expected_w1_recovery_files_chirho = vec![(*w1_candidate_relative_path_chirho).clone()];
    for record_line_chirho in w1_candidate_text_chirho.lines().skip(1) {
        let record_chirho: LedgerRecordChirho =
            serde_json::from_str(record_line_chirho).expect("decode W1 staged ledger record");
        expected_w1_recovery_files_chirho.push(format!(
            "staging-chirho/{w1_candidate_binding_chirho}/records-chirho/{:020}-{}.json",
            record_chirho.seq_chirho,
            stored_line_digest_chirho(record_line_chirho).0
        ));
    }
    expected_w1_recovery_files_chirho.sort();
    assert_eq!(
        w1_recovery_file_population_chirho, expected_w1_recovery_files_chirho,
        "W1 permits exactly the dense inert staging records plus one assembled candidate before the head"
    );
    std::fs::remove_file(&conflicting_generation_descriptor_path_chirho)
        .expect("remove the W1 canary-commit refusal before retry");

    let adopter_actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &fixtures_chirho[1].fixture_chirho.config_path_chirho,
        &configs_chirho[1],
        fleet_chirho.nodes_chirho[1].elector_chirho(),
        Some(adopter_runtime_chirho.clone()),
        None,
    )
    .expect("A adopts the A+B ACK while old leader L is unreachable");
    let adopted_cut_chirho = adopter_actor_chirho
        .effect_intent_cut_chirho()
        .expect("read the fully verified adopted resident cut");
    assert_eq!(
        adopted_cut_chirho.tail_seq_chirho,
        acknowledged_coordinate_chirho.0
    );
    assert_eq!(
        adopted_cut_chirho.tail_record_digest_chirho.0,
        acknowledged_coordinate_chirho.1
    );
    assert_eq!(
        adopter_actor_chirho
            .effective_ledger_config_chirho()
            .journal_path_chirho,
        configs_chirho[1].journal_path_chirho,
        "adoption must install verified bytes at the journal key already signed by the Bound identity"
    );
    assert_eq!(
        adopter_actor_chirho
            .active_hold_intent_refs_chirho()
            .expect("read active holds from adopted history")
            .len(),
        1,
        "the old leader's unacknowledged suffix must not enter adopted state"
    );
    let group_chirho =
        consistency_group_for_root_chirho(&fixtures_chirho[1].fixture_chirho.root_chirho)
            .expect("derive adopter tenant group");
    let canary_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &adopter_canary_root_chirho,
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        group_chirho,
        fixtures_chirho[1].node_id_chirho(),
    )
    .expect("open adopter canary generations");
    let current_generation_chirho = canary_store_chirho
        .verify_current_read_only_chirho()
        .expect("verify adopter generation selector");
    assert_eq!(current_generation_chirho.generation_chirho(), 1);
    let adoption_chirho = current_generation_chirho
        .adoption_chirho()
        .expect("generation one records its adoption provenance");
    let candidate_binding_digest_chirho = adoption_chirho
        .candidate_journal_binding_digest_chirho()
        .to_string();
    assert_eq!(
        adoption_chirho.historical_leader_node_id_chirho(),
        fixtures_chirho[0].node_id_chirho().0
    );
    assert_eq!(
        adoption_chirho
            .adopted_ledger_cut_chirho()
            .append_seq_chirho(),
        acknowledged_coordinate_chirho.0
    );
    assert_eq!(
        std::fs::read(journal_path_chirho(
            &fixtures_chirho[0].fixture_chirho.root_chirho,
            &configs_chirho[0],
        ))
        .expect("re-read old leader journal after adoption"),
        divergent_journal_bytes_chirho,
        "adoption must neither trust nor erase the old leader's unacknowledged suffix"
    );
    let adopted_journal_bytes_chirho = std::fs::read(journal_path_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &configs_chirho[1],
    ))
    .expect("snapshot the adopted canonical journal");
    let canary_head_after_adoption_chirho = std::fs::read(&canary_generation_head_path_chirho)
        .expect("snapshot the committed adoption selector");
    let fence_after_adoption_chirho =
        std::fs::read(&adopter_fence_path_chirho).expect("snapshot the adoption writer fence");
    assert_ne!(
        fence_after_adoption_chirho, w1_fence_bytes_chirho,
        "a restarted W1 retry must mint a fresh process-lifetime fence grant"
    );
    let fence_after_adoption_epoch_chirho = persisted_writer_epoch_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &adopter_group_chirho,
    )
    .expect("read the W1 retry fence epoch");
    assert!(
        fence_after_adoption_epoch_chirho > w1_fence_epoch_chirho,
        "W1 retry must advance rather than roll back the durable fence"
    );
    assert_eq!(
        split_writer_epoch_chirho(fence_after_adoption_epoch_chirho).geo_term_chirho,
        split_writer_epoch_chirho(w1_fence_epoch_chirho).geo_term_chirho,
        "W1 retry stays inside the unchanged elected Raft term"
    );
    let same_seq_divergent_journal_chirho = independently_minted_same_seq_journal_chirho(
        &initial_journal_chirho,
        acknowledged_coordinate_chirho.0,
        &acknowledged_coordinate_chirho.1,
    );
    drop(adopter_actor_chirho);
    adopter_clock_without_old_leader_chirho.finish_chirho();

    // W2: model a crash after the signed head commits but before the durable rename. The selected
    // candidate bytes remain inert while the old canonical bytes still match the head's prior cut.
    let adopter_storage_root_chirho = fixtures_chirho[1]
        .fixture_chirho
        .root_chirho
        .join(&configs_chirho[1].storage_namespace_chirho);
    let adopter_canonical_journal_path_chirho = journal_path_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &configs_chirho[1],
    );
    let inert_candidate_path_chirho = adopter_storage_root_chirho
        .join("f1-recovery-adoption-chirho")
        .join("candidates-chirho")
        .join(&candidate_binding_digest_chirho)
        .join("candidate-journal-chirho.jsonl");
    std::fs::create_dir_all(
        inert_candidate_path_chirho
            .parent()
            .expect("W2 candidate has a parent"),
    )
    .expect("recreate the W2 inert candidate directory");
    std::fs::rename(
        &adopter_canonical_journal_path_chirho,
        &inert_candidate_path_chirho,
    )
    .expect("move selected bytes back to their pre-activation inert location");
    let w2_clock_chirho =
        RunningRecoveryElectionClockChirho::start_chirho(&fleet_chirho.nodes_chirho, 1, vec![1, 4]);

    std::fs::write(
        &adopter_canonical_journal_path_chirho,
        &divergent_journal_bytes_chirho,
    )
    .expect("plant a newer canonical tail before W2 resume");
    let rollback_refusal_chirho =
        match open_resident_effect_journal_handle_with_shared_elector_chirho(
            &fixtures_chirho[1].fixture_chirho.root_chirho,
            &fixtures_chirho[1].fixture_chirho.config_path_chirho,
            &configs_chirho[1],
            fleet_chirho.nodes_chirho[1].elector_chirho(),
            Some(adopter_runtime_chirho.clone()),
            None,
        ) {
            Ok(_unexpected_actor_chirho) => {
                panic!("W2 must not install an older adopted cut over a newer canonical tail")
            }
            Err(refusal_chirho) => refusal_chirho,
        };
    assert_recovery_refusal_identity_chirho(
        &rollback_refusal_chirho,
        "ShadowCanaryCommittedAdoptionCanonicalTailRollbackRefusedChirho",
        &[
            "ShadowCanaryCommittedAdoptionCanonicalTailDivergenceRefusedChirho",
            "ShadowCanaryCommittedAdoptionCanonicalBaseRefusedChirho",
            "ShadowCanaryCommittedAdoptionCandidateBytesMissingChirho",
        ],
    );
    assert_eq!(
        std::fs::read(&adopter_canonical_journal_path_chirho)
            .expect("read the refused newer canonical tail"),
        divergent_journal_bytes_chirho
    );
    assert_eq!(
        std::fs::read(&inert_candidate_path_chirho)
            .expect("read the still-inert candidate after rollback refusal"),
        adopted_journal_bytes_chirho
    );

    std::fs::write(
        &adopter_canonical_journal_path_chirho,
        &same_seq_divergent_journal_chirho,
    )
    .expect("plant an equal-sequence divergent canonical tail before W2 resume");
    let divergence_refusal_chirho =
        match open_resident_effect_journal_handle_with_shared_elector_chirho(
            &fixtures_chirho[1].fixture_chirho.root_chirho,
            &fixtures_chirho[1].fixture_chirho.config_path_chirho,
            &configs_chirho[1],
            fleet_chirho.nodes_chirho[1].elector_chirho(),
            Some(adopter_runtime_chirho.clone()),
            None,
        ) {
            Ok(_unexpected_actor_chirho) => {
                panic!("W2 must not install an adopted cut over an equal-sequence divergent tail")
            }
            Err(refusal_chirho) => refusal_chirho,
        };
    assert_recovery_refusal_identity_chirho(
        &divergence_refusal_chirho,
        "ShadowCanaryCommittedAdoptionCanonicalTailDivergenceRefusedChirho",
        &[
            "ShadowCanaryCommittedAdoptionCanonicalTailRollbackRefusedChirho",
            "ShadowCanaryCommittedAdoptionCanonicalBaseRefusedChirho",
            "ShadowCanaryCommittedAdoptionCandidateBytesMissingChirho",
        ],
    );
    assert_eq!(
        std::fs::read(&adopter_canonical_journal_path_chirho)
            .expect("read the refused equal-sequence divergent canonical tail"),
        same_seq_divergent_journal_chirho
    );
    assert_eq!(
        std::fs::read(&inert_candidate_path_chirho)
            .expect("read the still-inert candidate after divergence refusal"),
        adopted_journal_bytes_chirho
    );
    assert_eq!(
        std::fs::read(&canary_generation_head_path_chirho)
            .expect("read the unchanged W2 adoption selector after tail refusals"),
        canary_head_after_adoption_chirho
    );
    assert_eq!(
        std::fs::read(&adopter_fence_path_chirho)
            .expect("read the unchanged W2 writer fence after tail refusals"),
        fence_after_adoption_chirho
    );

    std::fs::write(
        &adopter_canonical_journal_path_chirho,
        &initial_journal_chirho,
    )
    .expect("restore the W2 prior canonical journal fixture");
    let mut w2_resumed_actor_chirho =
        open_resident_effect_journal_handle_with_shared_elector_chirho(
            &fixtures_chirho[1].fixture_chirho.root_chirho,
            &fixtures_chirho[1].fixture_chirho.config_path_chirho,
            &configs_chirho[1],
            fleet_chirho.nodes_chirho[1].elector_chirho(),
            Some(adopter_runtime_chirho.clone()),
            None,
        )
        .expect("W2 resumes the committed head by installing the still-inert candidate bytes");
    assert_eq!(
        std::fs::read(&adopter_canonical_journal_path_chirho)
            .expect("read W2 resumed canonical journal"),
        adopted_journal_bytes_chirho
    );
    assert!(!inert_candidate_path_chirho.exists());
    assert_eq!(
        std::fs::read(&canary_generation_head_path_chirho).expect("read W2 adoption selector"),
        canary_head_after_adoption_chirho,
        "W2 resume must not mint a duplicate adoption head"
    );
    assert_eq!(
        std::fs::read(&adopter_fence_path_chirho).expect("read W2 writer fence"),
        fence_after_adoption_chirho,
        "W2 resume relies on the fence committed before the head and must not reissue it"
    );
    w2_clock_chirho.finish_chirho();
    drop(
        fleet_chirho.nodes_chirho[1]
            .elector_chirho()
            .local_append_authority_handle_chirho()
            .try_acquire_chirho()
            .expect("W2 negative write starts from one stable local append generation"),
    );
    let unavailable_holder_intent_chirho = signed_hold_line_chirho(
        &fixtures_chirho[1].fixture_chirho,
        w2_resumed_actor_chirho.effective_ledger_config_chirho(),
        &w2_resumed_actor_chirho,
    );
    let unavailable_holder_refusal_chirho = w2_resumed_actor_chirho
        .append_hold_chirho(&unavailable_holder_intent_chirho)
        .expect_err("W2 reads remain available but writes require every current mirror holder");
    // RETARGETED 2026-08-18. This arm used to read the identity out of the free-text detail. The
    // final-sink loss-witness work moved refusal identity into CLOSED-SET TYPES precisely because
    // drill reports and packets cannot carry unbounded fields, so asserting on prose was asserting
    // the old contract. The property is unchanged: a missing current mirror holder must refuse, and
    // the refusal must SAY it was mirror prepare rather than land in the generic residual.
    //
    // If this now reports `AuthorityCompositionOtherChirho`, the resident-path mapping regressed and
    // a missing holder has become unattributable on the exact path the loss drills reach.
    let EffectCommitJournalPortErrorChirho::ResidentRefusedChirho {
        identity_chirho,
        detail_chirho,
    } = unavailable_holder_refusal_chirho
    else {
        panic!(
            "missing current holder must refuse before local commit, got {unavailable_holder_refusal_chirho:?}"
        );
    };
    assert_eq!(
        identity_chirho,
        EffectCommitJournalResidentRefusalIdentityChirho::MirrorPrepareOrReconciliationChirho,
        "the unavailable-holder refusal must be typed as mirror prepare/reconciliation, got {identity_chirho:?} with detail {detail_chirho}"
    );
    assert_eq!(
        std::fs::read(&adopter_canonical_journal_path_chirho)
            .expect("read W2 canonical journal after refused append"),
        adopted_journal_bytes_chirho,
        "an unavailable mirror holder must refuse before local journal commit"
    );
    assert_eq!(
        std::fs::read(&canary_generation_head_path_chirho)
            .expect("read W2 canary head after refused append"),
        canary_head_after_adoption_chirho,
        "a PREPARE refusal must not advance the canary generation"
    );
    let fence_after_refused_write_chirho = std::fs::read(&adopter_fence_path_chirho)
        .expect("read the prospective fence left by the refused W2 append");
    assert_ne!(
        fence_after_refused_write_chirho, fence_after_adoption_chirho,
        "the refused append may leave only its prospective writer fence ahead of the journal"
    );
    drop(w2_resumed_actor_chirho);

    drive_recovery_heal_ticks_chirho(&fleet_chirho.nodes_chirho, 4);
    let returned_leadership_chirho = fleet_chirho.nodes_chirho[0]
        .elector_chirho()
        .current_leadership_chirho();
    assert!(!returned_leadership_chirho.is_leader_chirho);
    assert_eq!(
        returned_leadership_chirho.leader_id_chirho.as_ref(),
        Some(&fixtures_chirho[1].node_id_chirho())
    );
    let returned_listener_chirho = TcpListener::bind(serving_addresses_chirho[0])
        .expect("return the old leader only as an inert mirror endpoint");
    let _returned_server_chirho = RunningRecoveryMirrorServerChirho::start_chirho(
        returned_listener_chirho,
        leader_router_chirho,
    );
    let healed_adopter_clock_chirho =
        RunningRecoveryElectionClockChirho::start_chirho(&fleet_chirho.nodes_chirho, 1, vec![4]);
    let equal_local_source_head_chirho =
        follower_high_water_chirho(&fixtures_chirho[1].fixture_chirho.root_chirho);
    assert_eq!(
        equal_local_source_head_chirho["record_chirho"]["record_seq_chirho"].as_u64(),
        Some(adopted_cut_chirho.tail_seq_chirho),
        "W3 pins the equal-sequence boundary: an exact local holder head remains admissible"
    );
    assert_eq!(
        equal_local_source_head_chirho["record_chirho"]["record_digest_chirho"].as_str(),
        Some(adopted_cut_chirho.tail_record_digest_chirho.0.as_str()),
        "W3's equal local holder head must bind the exact canonical adopted cut"
    );

    let mut restarted_adopter_actor_chirho =
        open_resident_effect_journal_handle_with_shared_elector_chirho(
            &fixtures_chirho[1].fixture_chirho.root_chirho,
            &fixtures_chirho[1].fixture_chirho.config_path_chirho,
            &configs_chirho[1],
            fleet_chirho.nodes_chirho[1].elector_chirho(),
            Some(adopter_runtime_chirho.clone()),
            None,
        )
        .expect("A reconciles its verified prefix to the current L+B holder set");
    assert_eq!(
        std::fs::read(&canary_generation_head_path_chirho).expect("read W3 adoption selector"),
        canary_head_after_adoption_chirho,
        "W3 aligned restart must not mint a duplicate adoption head"
    );
    assert_eq!(
        std::fs::read(&adopter_fence_path_chirho).expect("read W3 writer fence"),
        fence_after_refused_write_chirho,
        "W3 aligned restart must not rewrite the latest already-durable prospective fence"
    );
    assert!(
        !inert_candidate_path_chirho.exists(),
        "W3 must not recreate a candidate after canonical bytes already match the signed head"
    );
    // The shared elector clock is a concurrent production transition: every tick intentionally
    // closes the nonblocking append gate while publishing its new observation. Recovery/bootstrap
    // above needs that clock to keep the lease fresh; this one append should measure mirror
    // continuity, not whether it wins a scheduler race against the next 25 ms tick.
    healed_adopter_clock_chirho.finish_chirho();
    let next_intent_chirho = signed_hold_line_chirho(
        &fixtures_chirho[1].fixture_chirho,
        restarted_adopter_actor_chirho.effective_ledger_config_chirho(),
        &restarted_adopter_actor_chirho,
    );
    let next_receipt_chirho = restarted_adopter_actor_chirho
        .append_hold_chirho(&next_intent_chirho)
        .expect("the next A-led write ACKs only after returned L and B finalize");
    let effective_adopter_config_chirho = restarted_adopter_actor_chirho
        .effective_ledger_config_chirho()
        .clone();
    let next_record_chirho = last_journal_record_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &effective_adopter_config_chirho,
    );
    let next_coordinate_chirho = record_coordinate_chirho(&next_record_chirho);
    assert_eq!(next_receipt_chirho.seq_chirho, next_coordinate_chirho.0);
    assert_eq!(
        next_coordinate_chirho.0,
        acknowledged_coordinate_chirho.0 + 1
    );
    assert_ne!(
        next_coordinate_chirho.1, divergent_coordinate_chirho.1,
        "the acknowledged A-led line must not inherit L's losing suffix at the same sequence"
    );
    for holder_chirho in [&fixtures_chirho[0], &fixtures_chirho[2]] {
        let high_water_chirho =
            follower_high_water_chirho(&holder_chirho.fixture_chirho.root_chirho);
        assert_eq!(
            high_water_chirho["origin_leader_node_id_chirho"].as_str(),
            Some(fixtures_chirho[1].node_id_chirho().0.as_str())
        );
        assert_eq!(
            high_water_chirho["record_chirho"]["record_seq_chirho"].as_u64(),
            Some(next_coordinate_chirho.0)
        );
        assert_eq!(
            high_water_chirho["record_chirho"]["record_digest_chirho"].as_str(),
            Some(next_coordinate_chirho.1.as_str())
        );
    }
    assert_eq!(
        std::fs::read(journal_path_chirho(
            &fixtures_chirho[0].fixture_chirho.root_chirho,
            &configs_chirho[0],
        ))
        .expect("re-read quarantined old-leader journal"),
        divergent_journal_bytes_chirho,
        "transport-only reconciliation must preserve the losing canonical suffix for GD7 audit"
    );
    let returned_mirror_record_chirho = fixtures_chirho[0]
        .fixture_chirho
        .root_chirho
        .join(MIRROR_ROOT_DIR_CHIRHO)
        .join(MIRROR_FOLLOWER_DIR_CHIRHO)
        .join("records-chirho")
        .join(format!(
            "{:020}-{}.jsonl",
            next_coordinate_chirho.0, next_coordinate_chirho.1
        ));
    assert!(
        returned_mirror_record_chirho.exists(),
        "the current A-led line lives only in L's inert follower namespace"
    );

    let post_adoption_journal_bytes_chirho = std::fs::read(&adopter_canonical_journal_path_chirho)
        .expect("snapshot the post-adoption canonical journal");
    let post_adoption_canary_head_chirho = std::fs::read(&canary_generation_head_path_chirho)
        .expect("snapshot the post-adoption canary selector");
    let post_adoption_fence_chirho =
        std::fs::read(&adopter_fence_path_chirho).expect("snapshot the post-adoption writer fence");
    let stale_local_source_head_chirho =
        follower_high_water_chirho(&fixtures_chirho[1].fixture_chirho.root_chirho);
    assert_eq!(
        stale_local_source_head_chirho["origin_leader_node_id_chirho"].as_str(),
        Some(fixtures_chirho[0].node_id_chirho().0.as_str()),
        "A still carries the original L-authored follower source head"
    );
    assert_eq!(
        stale_local_source_head_chirho["record_chirho"]["record_seq_chirho"].as_u64(),
        Some(adopted_cut_chirho.tail_seq_chirho),
        "the stale local source head is the adopted canonical anchor"
    );
    assert_eq!(
        stale_local_source_head_chirho["record_chirho"]["record_digest_chirho"].as_str(),
        Some(adopted_cut_chirho.tail_record_digest_chirho.0.as_str()),
        "the behind source head must agree with canonical history before selection excludes it"
    );
    assert!(
        next_coordinate_chirho.0 > adopted_cut_chirho.tail_seq_chirho,
        "the normal restart control requires the local source head to be strictly behind canonical"
    );
    drop(restarted_adopter_actor_chirho);
    std::fs::write(
        &adopter_canonical_journal_path_chirho,
        &adopted_journal_bytes_chirho,
    )
    .expect("restore the byte-exact adopted cut behind its post-adoption canary window");
    let planted_adopted_coordinate_chirho = record_coordinate_chirho(&last_journal_record_chirho(
        &fixtures_chirho[1].fixture_chirho.root_chirho,
        &configs_chirho[1],
    ));
    let advanced_generation_chirho = canary_store_chirho
        .verify_current_read_only_chirho()
        .expect("verify the post-adoption canary window");
    let advanced_adoption_chirho = advanced_generation_chirho
        .adoption_chirho()
        .expect("the advanced generation retains its adoption provenance");
    assert!(
        advanced_generation_chirho.window_chirho().is_some(),
        "the behind-window arm requires a post-adoption observation"
    );
    assert_eq!(
        planted_adopted_coordinate_chirho.0,
        advanced_adoption_chirho
            .adopted_ledger_cut_chirho()
            .append_seq_chirho(),
        "the planted canonical journal must have the adopted cut's exact sequence"
    );
    assert_eq!(
        planted_adopted_coordinate_chirho.1,
        advanced_adoption_chirho
            .adopted_ledger_cut_chirho()
            .append_record_digest_chirho(),
        "the planted canonical journal must have the adopted cut's exact digest"
    );
    assert!(
        advanced_generation_chirho
            .latest_ledger_cut_chirho()
            .append_seq_chirho()
            > planted_adopted_coordinate_chirho.0,
        "the current canary window must be ahead of the byte-exact adopted cut"
    );

    let post_adoption_window_clock_chirho =
        RunningRecoveryElectionClockChirho::start_chirho(&fleet_chirho.nodes_chirho, 1, vec![4]);
    let behind_window_refusal_chirho =
        match open_resident_effect_journal_handle_with_shared_elector_chirho(
            &fixtures_chirho[1].fixture_chirho.root_chirho,
            &fixtures_chirho[1].fixture_chirho.config_path_chirho,
            &configs_chirho[1],
            fleet_chirho.nodes_chirho[1].elector_chirho(),
            Some(adopter_runtime_chirho.clone()),
            None,
        ) {
            Ok(_unexpected_actor_chirho) => {
                panic!("an adopted-cut journal behind its canary window must not serve")
            }
            Err(refusal_chirho) => refusal_chirho,
        };
    assert_recovery_refusal_identity_chirho(
        &behind_window_refusal_chirho,
        "ShadowCanaryCommittedAdoptionCanonicalTailBehindCanaryWindowRefusedChirho",
        &[
            "ShadowCanaryCommittedAdoptionCanonicalTailDivergenceRefusedChirho",
            "ShadowCanaryCommittedAdoptionCanonicalTailRollbackRefusedChirho",
            "ShadowCanaryCommittedAdoptionCanonicalBaseRefusedChirho",
            "ShadowCanaryCommittedAdoptionCandidateBytesMissingChirho",
        ],
    );
    assert_eq!(
        std::fs::read(&adopter_canonical_journal_path_chirho)
            .expect("read the refused behind-window canonical journal"),
        adopted_journal_bytes_chirho
    );
    assert_eq!(
        std::fs::read(&canary_generation_head_path_chirho)
            .expect("read the unchanged post-adoption canary selector"),
        post_adoption_canary_head_chirho
    );
    assert_eq!(
        std::fs::read(&adopter_fence_path_chirho)
            .expect("read the unchanged post-adoption writer fence"),
        post_adoption_fence_chirho
    );
    assert!(!inert_candidate_path_chirho.exists());

    std::fs::write(
        &adopter_canonical_journal_path_chirho,
        &post_adoption_journal_bytes_chirho,
    )
    .expect("restore the canonical journal aligned with the post-adoption canary window");
    let post_adoption_reopened_actor_chirho =
        open_resident_effect_journal_handle_with_shared_elector_chirho(
            &fixtures_chirho[1].fixture_chirho.root_chirho,
            &fixtures_chirho[1].fixture_chirho.config_path_chirho,
            &configs_chirho[1],
            fleet_chirho.nodes_chirho[1].elector_chirho(),
            Some(adopter_runtime_chirho),
            None,
        )
        .expect("restoring the window-aligned canonical journal reopens without another adoption");
    drop(post_adoption_reopened_actor_chirho);
    post_adoption_window_clock_chirho.finish_chirho();
}

fn relative_file_population_chirho(root_chirho: &Path) -> Vec<String> {
    fn walk_chirho(root_chirho: &Path, current_chirho: &Path, files_chirho: &mut Vec<String>) {
        if !current_chirho.exists() {
            return;
        }
        for entry_chirho in std::fs::read_dir(current_chirho)
            .expect("read recovery-adoption durable-state directory")
        {
            let path_chirho = entry_chirho
                .expect("read recovery-adoption durable-state entry")
                .path();
            if path_chirho.is_dir() {
                walk_chirho(root_chirho, &path_chirho, files_chirho);
            } else {
                files_chirho.push(
                    path_chirho
                        .strip_prefix(root_chirho)
                        .expect("recovery-adoption file remains below its root")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }

    let mut files_chirho = Vec::new();
    walk_chirho(root_chirho, root_chirho, &mut files_chirho);
    files_chirho.sort();
    files_chirho
}
