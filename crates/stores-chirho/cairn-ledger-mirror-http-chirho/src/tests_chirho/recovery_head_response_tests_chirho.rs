// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

fn recovery_residency_chirho(
    fixture_chirho: &PlacementFixtureChirho,
) -> MirrorResidencyPolicyChirho {
    MirrorResidencyPolicyChirho::allowed_domains_chirho(
        fixture_chirho
            .placement_chirho
            .intent_chirho()
            .residency_chirho
            .allowed_domains_chirho
            .clone(),
    )
}

fn signed_recovery_request_chirho(
    fixture_chirho: &PlacementFixtureChirho,
    leader_chirho: &TestNodeChirho,
    follower_chirho: &TestNodeChirho,
    observation_chirho: &MirrorElectionObservationChirho,
) -> LedgerMirrorRecoveryHeadRequestChirho {
    let joined_chirho = join_mirror_view_chirho(
        &fixture_chirho.placement_chirho,
        &FixedElectionViewChirho {
            observation_chirho: observation_chirho.clone(),
        },
    )
    .expect("join the requester's baseline recovery view");
    LedgerMirrorRecoveryHeadRequestChirho::sign_chirho(
        LedgerMirrorRecoveryHeadRequestInputChirho {
            requester_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            target_node_id_chirho: follower_chirho.node_id_chirho.clone(),
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho()
                .to_string(),
            assignment_digest_chirho: fixture_chirho
                .placement_chirho
                .assignment_digest_chirho()
                .to_string(),
            expected_term_chirho: joined_chirho.term_chirho(),
            membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
        },
        leader_chirho.root_chirho(),
    )
    .expect("sign a recovery-head request")
}

fn start_recovery_server_chirho(
    fixture_chirho: &PlacementFixtureChirho,
    follower_chirho: &TestNodeChirho,
    observation_chirho: MirrorElectionObservationChirho,
) -> (tempfile::TempDir, RunningMirrorServerChirho) {
    let journal_root_chirho = tempfile::tempdir().expect("journal verifier root");
    provision_node_chirho(journal_root_chirho.path());
    let store_root_chirho = tempfile::tempdir().expect("recovery follower store root");
    let store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            store_root_chirho.path(),
            follower_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_root_chirho.path()),
        )
        .expect("open recovery follower store"),
    );
    let server_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        follower_chirho.node_id_chirho.clone(),
        follower_chirho.root_chirho().to_path_buf(),
        Arc::clone(&fixture_chirho.placement_chirho),
        Arc::new(FixedElectionViewChirho { observation_chirho }),
        recovery_residency_chirho(fixture_chirho),
        store_chirho,
    )
    .expect("compose recovery follower server");
    (
        store_root_chirho,
        RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(server_state_chirho)),
    )
}

fn read_recovery_refusal_chirho(
    follower_chirho: &TestNodeChirho,
    request_chirho: &LedgerMirrorRecoveryHeadRequestChirho,
    server_chirho: &RunningMirrorServerChirho,
) -> String {
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        server_chirho.endpoint_chirho.clone(),
    )]));
    directory_chirho
        .read_recovery_head_with_retry_wait_for_test_chirho(
            &follower_chirho.node_id_chirho,
            request_chirho,
            &private_mesh_agent_chirho(),
            || {},
        )
        .expect_err("the mutated holder view must refuse")
        .to_string()
}

fn vacant_loopback_address_chirho() -> std::net::SocketAddr {
    let listener_chirho = TcpListener::bind("127.0.0.1:0").expect("reserve vacant loopback port");
    let socket_addr_chirho = listener_chirho
        .local_addr()
        .expect("read vacant loopback address");
    drop(listener_chirho);
    socket_addr_chirho
}

fn signed_recovery_head_wire_chirho(
    fixture_chirho: &PlacementFixtureChirho,
    leader_chirho: &TestNodeChirho,
    follower_chirho: &TestNodeChirho,
) -> Vec<u8> {
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let joined_chirho = join_mirror_view_chirho(
        &fixture_chirho.placement_chirho,
        &FixedElectionViewChirho { observation_chirho },
    )
    .expect("join signed response recovery view");
    let record_chirho = signed_record_chirho(
        follower_chirho.root_chirho(),
        &follower_chirho.node_id_chirho,
    );
    let high_water_chirho = LedgerMirrorHighWaterChirho::sign_chirho(
        LedgerMirrorHighWaterInputChirho {
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho()
                .to_string(),
            origin_leader_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            holder_node_id_chirho: follower_chirho.node_id_chirho.clone(),
            assignment_digest_chirho: fixture_chirho
                .placement_chirho
                .assignment_digest_chirho()
                .to_string(),
            assigned_node_ids_chirho: std::array::from_fn(|index_chirho| {
                fixture_chirho.serving_nodes_chirho[index_chirho]
                    .node_id_chirho
                    .clone()
            }),
            membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
            historical_term_chirho: joined_chirho.term_chirho(),
            mirror_closure_id_chirho: "4".repeat(64),
            prepare_frame_digest_chirho: "5".repeat(64),
            caller_idempotency_key_digest_chirho: "6".repeat(64),
            record_chirho,
        },
        follower_chirho.root_chirho(),
    )
    .expect("sign recovery high water");
    LedgerMirrorRecoveryHeadReceiptChirho::sign_from_high_water_chirho(
        &high_water_chirho,
        follower_chirho.root_chirho(),
    )
    .expect("sign recovery head receipt")
    .to_wire_bytes_chirho()
    .expect("encode signed recovery head receipt")
}

fn start_term_gated_recovery_server_chirho(
    remote_term_chirho: Arc<AtomicU64>,
    response_wire_chirho: Arc<Vec<u8>>,
    request_bodies_chirho: Arc<Mutex<Vec<Vec<u8>>>>,
) -> RunningMirrorServerChirho {
    let router_chirho = axum::Router::new().route(
        LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO,
        axum::routing::post(move |body_chirho: axum::body::Bytes| {
            let remote_term_chirho = Arc::clone(&remote_term_chirho);
            let response_wire_chirho = Arc::clone(&response_wire_chirho);
            let request_bodies_chirho = Arc::clone(&request_bodies_chirho);
            async move {
                let body_chirho = body_chirho.to_vec();
                let request_chirho =
                    LedgerMirrorRecoveryHeadRequestChirho::decode_and_verify_chirho(&body_chirho)
                        .expect("verify the term-gated recovery request");
                request_bodies_chirho
                    .lock()
                    .expect("lock captured recovery requests")
                    .push(body_chirho);
                if request_chirho.expected_term_chirho()
                    != remote_term_chirho.load(Ordering::SeqCst)
                {
                    (
                        axum::http::StatusCode::CONFLICT,
                        LedgerMirrorRecoveryHeadRefusalChirho::TERM_MISMATCH_CHIRHO
                            .as_str_chirho()
                            .as_bytes()
                            .to_vec(),
                    )
                } else {
                    (
                        axum::http::StatusCode::OK,
                        response_wire_chirho.as_ref().clone(),
                    )
                }
            }
        }),
    );
    RunningMirrorServerChirho::start_chirho(router_chirho)
}

#[test]
fn signed_term_mismatch_retries_until_behind_holder_converges_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let expected_request_bytes_chirho = request_chirho
        .to_wire_bytes_chirho()
        .expect("encode the frozen recovery request");
    let expected_wire_chirho = Arc::new(signed_recovery_head_wire_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
    ));
    let remote_term_chirho = Arc::new(AtomicU64::new(
        request_chirho
            .expected_term_chirho()
            .checked_sub(1)
            .expect("fixture term permits a behind holder"),
    ));
    let request_bodies_chirho = Arc::new(Mutex::new(Vec::new()));
    let server_chirho = start_term_gated_recovery_server_chirho(
        Arc::clone(&remote_term_chirho),
        Arc::clone(&expected_wire_chirho),
        Arc::clone(&request_bodies_chirho),
    );
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        server_chirho.endpoint_chirho.clone(),
    )]));
    let mut retry_wait_count_chirho = 0;
    let received_wire_chirho = directory_chirho
        .read_recovery_head_with_retry_wait_for_test_chirho(
            &follower_chirho.node_id_chirho,
            &request_chirho,
            &private_mesh_agent_chirho(),
            || {
                retry_wait_count_chirho += 1;
                assert_eq!(retry_wait_count_chirho, 1, "only one convergence wait");
                remote_term_chirho.store(request_chirho.expected_term_chirho(), Ordering::SeqCst);
            },
        )
        .expect("a behind holder that reaches the frozen term must recover")
        .expect("the converged holder returns a signed recovery head");
    assert_eq!(received_wire_chirho, *expected_wire_chirho);
    assert_eq!(retry_wait_count_chirho, 1);
    let request_bodies_chirho = request_bodies_chirho
        .lock()
        .expect("lock captured recovery requests");
    assert_eq!(request_bodies_chirho.len(), 2);
    assert!(
        request_bodies_chirho
            .iter()
            .all(|body_chirho| body_chirho == &expected_request_bytes_chirho),
        "every status retry must carry the exact frozen signed request"
    );
}

#[test]
fn stable_behind_term_mismatch_exhausts_with_exact_identity_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let remote_term_chirho = Arc::new(AtomicU64::new(
        request_chirho
            .expected_term_chirho()
            .checked_sub(1)
            .expect("fixture term permits a behind holder"),
    ));
    let request_bodies_chirho = Arc::new(Mutex::new(Vec::new()));
    let server_chirho = start_term_gated_recovery_server_chirho(
        remote_term_chirho,
        Arc::new(signed_recovery_head_wire_chirho(
            &fixture_chirho,
            leader_chirho,
            follower_chirho,
        )),
        Arc::clone(&request_bodies_chirho),
    );
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        server_chirho.endpoint_chirho.clone(),
    )]));
    let mut retry_wait_count_chirho = 0;
    let refusal_chirho = directory_chirho
        .read_recovery_head_with_retry_wait_for_test_chirho(
            &follower_chirho.node_id_chirho,
            &request_chirho,
            &private_mesh_agent_chirho(),
            || retry_wait_count_chirho += 1,
        )
        .expect_err("a holder that stays behind must exhaust the bounded envelope")
        .to_string();
    assert_eq!(
        refusal_chirho,
        LedgerMirrorRecoveryHeadRefusalChirho::TERM_MISMATCH_CHIRHO.as_str_chirho()
    );
    assert_eq!(
        retry_wait_count_chirho,
        RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO - 1
    );
    assert_eq!(
        request_bodies_chirho
            .lock()
            .expect("lock captured recovery requests")
            .len(),
        RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO
    );
}

#[test]
fn higher_remote_term_never_satisfies_the_frozen_request_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let remote_term_chirho = Arc::new(AtomicU64::new(
        request_chirho
            .expected_term_chirho()
            .checked_add(1)
            .expect("fixture term permits a higher holder"),
    ));
    let request_bodies_chirho = Arc::new(Mutex::new(Vec::new()));
    let server_chirho = start_term_gated_recovery_server_chirho(
        remote_term_chirho,
        Arc::new(signed_recovery_head_wire_chirho(
            &fixture_chirho,
            leader_chirho,
            follower_chirho,
        )),
        Arc::clone(&request_bodies_chirho),
    );
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        server_chirho.endpoint_chirho.clone(),
    )]));
    let mut retry_wait_count_chirho = 0;
    let refusal_chirho = directory_chirho
        .read_recovery_head_with_retry_wait_for_test_chirho(
            &follower_chirho.node_id_chirho,
            &request_chirho,
            &private_mesh_agent_chirho(),
            || retry_wait_count_chirho += 1,
        )
        .expect_err("a holder with a higher term must never satisfy a frozen request")
        .to_string();
    assert_eq!(
        refusal_chirho,
        LedgerMirrorRecoveryHeadRefusalChirho::TERM_MISMATCH_CHIRHO.as_str_chirho()
    );
    assert_eq!(
        retry_wait_count_chirho,
        RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO - 1
    );
    assert_eq!(
        request_bodies_chirho
            .lock()
            .expect("lock captured recovery requests")
            .len(),
        RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO
    );
}

#[test]
fn connection_failed_recovery_head_retries_then_accepts_signed_response_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let expected_wire_chirho = Arc::new(signed_recovery_head_wire_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
    ));
    let request_count_chirho = Arc::new(AtomicUsize::new(0));
    let route_wire_chirho = Arc::clone(&expected_wire_chirho);
    let route_count_chirho = Arc::clone(&request_count_chirho);
    let router_chirho = axum::Router::new().route(
        LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO,
        axum::routing::post(move || {
            let wire_chirho = Arc::clone(&route_wire_chirho);
            let count_chirho = Arc::clone(&route_count_chirho);
            async move {
                count_chirho.fetch_add(1, Ordering::SeqCst);
                (axum::http::StatusCode::OK, wire_chirho.as_ref().clone())
            }
        }),
    );
    let socket_addr_chirho = vacant_loopback_address_chirho();
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        format!("http://{socket_addr_chirho}"),
    )]));
    let mut retry_wait_count_chirho = 0;
    let mut delayed_server_chirho = None;
    let received_wire_chirho = directory_chirho
        .read_recovery_head_with_retry_wait_for_test_chirho(
            &follower_chirho.node_id_chirho,
            &request_chirho,
            &private_mesh_agent_chirho(),
            || {
                retry_wait_count_chirho += 1;
                assert_eq!(retry_wait_count_chirho, 1, "only one retry is expected");
                let listener_chirho = TcpListener::bind(socket_addr_chirho)
                    .expect("bind delayed recovery server after connection refusal");
                delayed_server_chirho =
                    Some(RunningMirrorServerChirho::start_with_listener_chirho(
                        listener_chirho,
                        router_chirho.clone(),
                    ));
            },
        )
        .expect("a connection failure followed by a bound holder must recover")
        .expect("the delayed holder returns a signed recovery head");
    assert_eq!(received_wire_chirho, *expected_wire_chirho);
    LedgerMirrorRecoveryHeadReceiptChirho::decode_and_verify_chirho(
        &received_wire_chirho,
        &follower_chirho.node_id_chirho,
    )
    .expect("the delayed response must remain a valid signed recovery receipt");
    assert_eq!(retry_wait_count_chirho, 1);
    assert_eq!(request_count_chirho.load(Ordering::SeqCst), 1);
    assert!(delayed_server_chirho.is_some());
}

#[test]
fn connection_failed_recovery_head_exhaustion_keeps_transport_identity_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let socket_addr_chirho = vacant_loopback_address_chirho();
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        format!("http://{socket_addr_chirho}"),
    )]));
    let mut retry_wait_count_chirho = 0;
    let refusal_chirho = directory_chirho
        .read_recovery_head_with_retry_wait_for_test_chirho(
            &follower_chirho.node_id_chirho,
            &request_chirho,
            &private_mesh_agent_chirho(),
            || retry_wait_count_chirho += 1,
        )
        .expect_err("an endpoint that never binds must exhaust the retry envelope")
        .to_string();
    assert_eq!(
        refusal_chirho,
        "LedgerMirrorRecoveryHeadTransportRefusedChirho"
    );
    assert_eq!(
        retry_wait_count_chirho,
        RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO - 1
    );
}

#[test]
fn non_connection_transport_failure_is_terminal_without_retry_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let listener_chirho =
        TcpListener::bind("127.0.0.1:0").expect("bind accept-then-close recovery transport");
    let socket_addr_chirho = listener_chirho
        .local_addr()
        .expect("read accept-then-close address");
    let accept_count_chirho = Arc::new(AtomicUsize::new(0));
    let server_accept_count_chirho = Arc::clone(&accept_count_chirho);
    let server_thread_chirho = std::thread::spawn(move || {
        let (stream_chirho, _peer_chirho) = listener_chirho
            .accept()
            .expect("accept one recovery request before closing");
        server_accept_count_chirho.fetch_add(1, Ordering::SeqCst);
        stream_chirho
            .shutdown(std::net::Shutdown::Both)
            .expect("close accepted recovery transport");
    });
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        format!("http://{socket_addr_chirho}"),
    )]));
    let mut retry_wait_count_chirho = 0;
    let refusal_chirho = directory_chirho
        .read_recovery_head_with_retry_wait_for_test_chirho(
            &follower_chirho.node_id_chirho,
            &request_chirho,
            &private_mesh_agent_chirho(),
            || retry_wait_count_chirho += 1,
        )
        .expect_err("an accepted-then-closed transport must remain terminal")
        .to_string();
    server_thread_chirho
        .join()
        .expect("join accept-then-close recovery server");
    assert_eq!(
        refusal_chirho,
        "LedgerMirrorRecoveryHeadTransportRefusedChirho"
    );
    assert_eq!(retry_wait_count_chirho, 0);
    assert_eq!(accept_count_chirho.load(Ordering::SeqCst), 1);
}

#[test]
fn different_signed_recovery_head_refusal_is_not_retried_or_relabelled_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let request_count_chirho = Arc::new(AtomicUsize::new(0));
    let route_count_chirho = Arc::clone(&request_count_chirho);
    let router_chirho = axum::Router::new().route(
        LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO,
        axum::routing::post(move || {
            let count_chirho = Arc::clone(&route_count_chirho);
            async move {
                count_chirho.fetch_add(1, Ordering::SeqCst);
                (
                    axum::http::StatusCode::CONFLICT,
                    LedgerMirrorRecoveryHeadRefusalChirho::MEMBERSHIP_VIEW_MISMATCH_CHIRHO
                        .as_str_chirho(),
                )
            }
        }),
    );
    let server_chirho = RunningMirrorServerChirho::start_chirho(router_chirho);
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        server_chirho.endpoint_chirho.clone(),
    )]));
    let mut retry_wait_count_chirho = 0;
    let refusal_chirho = directory_chirho
        .read_recovery_head_with_retry_wait_for_test_chirho(
            &follower_chirho.node_id_chirho,
            &request_chirho,
            &private_mesh_agent_chirho(),
            || retry_wait_count_chirho += 1,
        )
        .expect_err("a different signed HTTP refusal must remain terminal")
        .to_string();
    assert_eq!(
        refusal_chirho,
        LedgerMirrorRecoveryHeadRefusalChirho::MEMBERSHIP_VIEW_MISMATCH_CHIRHO.as_str_chirho()
    );
    assert_eq!(request_count_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(retry_wait_count_chirho, 0);
}

#[test]
fn unavailable_is_the_only_exact_body_that_the_client_treats_as_no_head_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let request_count_chirho = Arc::new(AtomicUsize::new(0));
    let route_count_chirho = Arc::clone(&request_count_chirho);
    let router_chirho = axum::Router::new().route(
        LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO,
        axum::routing::post(move || {
            let count_chirho = Arc::clone(&route_count_chirho);
            async move {
                count_chirho.fetch_add(1, Ordering::SeqCst);
                (
                    axum::http::StatusCode::CONFLICT,
                    LedgerMirrorRecoveryHeadRefusalChirho::UNAVAILABLE_CHIRHO.as_str_chirho(),
                )
            }
        }),
    );
    let server_chirho = RunningMirrorServerChirho::start_chirho(router_chirho);
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        server_chirho.endpoint_chirho.clone(),
    )]));
    let mut retry_wait_count_chirho = 0;
    assert_eq!(
        directory_chirho
            .read_recovery_head_with_retry_wait_for_test_chirho(
                &follower_chirho.node_id_chirho,
                &request_chirho,
                &private_mesh_agent_chirho(),
                || retry_wait_count_chirho += 1,
            )
            .expect("an exact unavailable sentinel is a valid empty recovery source"),
        None
    );
    assert_eq!(request_count_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(retry_wait_count_chirho, 0);

    let unknown_router_chirho = axum::Router::new().route(
        LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO,
        axum::routing::post(|| async {
            (
                axum::http::StatusCode::CONFLICT,
                "LedgerMirrorRecoveryHeadUnavailableChirhoX",
            )
        }),
    );
    let unknown_server_chirho = RunningMirrorServerChirho::start_chirho(unknown_router_chirho);
    let unknown_directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        follower_chirho.node_id_chirho.clone(),
        unknown_server_chirho.endpoint_chirho.clone(),
    )]));
    let refusal_chirho = unknown_directory_chirho
        .read_recovery_head_chirho(
            &follower_chirho.node_id_chirho,
            &request_chirho,
            &private_mesh_agent_chirho(),
        )
        .expect_err("an unlisted extension of the sentinel must remain a refusal")
        .to_string();
    assert!(refusal_chirho.contains("LedgerMirrorRecoveryHeadResponseRefusedChirho"));
    assert!(!refusal_chirho.contains("LedgerMirrorRecoveryHeadUnavailableChirhoX"));
}

#[test]
fn joined_view_population_and_identity_failures_cross_http_as_distinct_labels_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let baseline_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &baseline_chirho,
    );

    let mut incomplete_chirho = baseline_chirho.clone();
    incomplete_chirho.authenticated_members_chirho.pop();
    let (_incomplete_root_chirho, incomplete_server_chirho) =
        start_recovery_server_chirho(&fixture_chirho, follower_chirho, incomplete_chirho);
    let incomplete_refusal_chirho =
        read_recovery_refusal_chirho(follower_chirho, &request_chirho, &incomplete_server_chirho);
    assert_eq!(
        incomplete_refusal_chirho,
        "LedgerMirrorRecoveryHeadAuthenticatedMemberPopulationIncompleteChirho"
    );

    let mut duplicate_chirho = baseline_chirho.clone();
    duplicate_chirho.authenticated_members_chirho[1].1 =
        duplicate_chirho.authenticated_members_chirho[0].1.clone();
    let (_duplicate_root_chirho, duplicate_server_chirho) =
        start_recovery_server_chirho(&fixture_chirho, follower_chirho, duplicate_chirho);
    let duplicate_refusal_chirho =
        read_recovery_refusal_chirho(follower_chirho, &request_chirho, &duplicate_server_chirho);
    assert_eq!(
        duplicate_refusal_chirho,
        "LedgerMirrorRecoveryHeadAuthenticatedMemberIdentityRefusedChirho"
    );
    assert_ne!(incomplete_refusal_chirho, duplicate_refusal_chirho);
}

#[test]
fn runtime_term_and_membership_view_drift_keep_distinct_http_identities_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let baseline_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &baseline_chirho,
    );

    let mut later_term_chirho = baseline_chirho.clone();
    later_term_chirho.leadership_chirho.term_chirho += 1;
    let (_term_root_chirho, term_server_chirho) =
        start_recovery_server_chirho(&fixture_chirho, follower_chirho, later_term_chirho);
    let term_refusal_chirho =
        read_recovery_refusal_chirho(follower_chirho, &request_chirho, &term_server_chirho);
    assert_eq!(
        term_refusal_chirho,
        "LedgerMirrorRecoveryHeadTermMismatchChirho"
    );

    let mut later_view_chirho = baseline_chirho;
    later_view_chirho.applied_conf_index_chirho += 1;
    let (_view_root_chirho, view_server_chirho) =
        start_recovery_server_chirho(&fixture_chirho, follower_chirho, later_view_chirho);
    let view_refusal_chirho =
        read_recovery_refusal_chirho(follower_chirho, &request_chirho, &view_server_chirho);
    assert_eq!(
        view_refusal_chirho,
        "LedgerMirrorRecoveryHeadMembershipViewMismatchChirho"
    );
    assert_ne!(term_refusal_chirho, view_refusal_chirho);
}

#[test]
fn holder_storage_detail_is_replaced_by_one_fixed_source_read_identity_chirho() {
    let fixture_chirho = placement_fixture_chirho();
    let leader_chirho = &fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &fixture_chirho.serving_nodes_chirho[1];
    let observation_chirho = election_observation_chirho(
        &fixture_chirho.placement_chirho,
        &leader_chirho.node_id_chirho,
        false,
    );
    let request_chirho = signed_recovery_request_chirho(
        &fixture_chirho,
        leader_chirho,
        follower_chirho,
        &observation_chirho,
    );
    let (store_root_chirho, server_chirho) =
        start_recovery_server_chirho(&fixture_chirho, follower_chirho, observation_chirho);
    let needle_chirho = "/private/recovery-head-storage-needle-chirho";
    std::fs::write(
        store_root_chirho
            .path()
            .join("follower-f1-chirho/high-water-chirho.json"),
        needle_chirho,
    )
    .expect("plant a malformed high-water carrying a private-path-shaped needle");

    let refusal_chirho =
        read_recovery_refusal_chirho(follower_chirho, &request_chirho, &server_chirho);
    assert_eq!(
        refusal_chirho,
        "LedgerMirrorRecoveryHeadSourceReadRefusedChirho"
    );
    assert!(!refusal_chirho.contains(needle_chirho));
}
