// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_ledger_host_chirho::reconciliation_chirho::{
    generate_gd7_winner_current_view_challenge_chirho, Gd7HeldViewTransferIdentityChirho,
    Gd7HeldViewTransferPhaseChirho, Gd7HeldViewTransferStoreChirho,
};
use cairn_ledger_host_chirho::FsLedgerStorageChirho;
use cairn_signer_chirho::signer_chirho::pubkey_hex_chirho;
use cairn_writer_elector_http_chirho::serve_router_blocking_with_shutdown_chirho;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn test_root_chirho(label_chirho: &str) -> PathBuf {
    let nonce_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "gd7-winner-view-transfer-{label_chirho}-{}-{nonce_chirho}-chirho",
        std::process::id()
    ))
}

#[test]
fn transfer_origin_requires_confidential_transport_outside_loopback_chirho() {
    validate_winner_view_transfer_base_url_chirho("http://127.0.0.1:8300")
        .expect("IPv4 loopback is permitted for local execution");
    validate_winner_view_transfer_base_url_chirho("http://[::1]:8300")
        .expect("IPv6 loopback is permitted for local execution");
    validate_winner_view_transfer_base_url_chirho("https://10.100.0.7:8300")
        .expect("encrypted cluster transport is permitted");
    assert!(
        validate_winner_view_transfer_base_url_chirho("http://10.100.0.7:8300")
            .unwrap_err()
            .to_string()
            .contains("requires HTTPS")
    );
    assert!(
        validate_winner_view_transfer_base_url_chirho("https://winner.example/path-chirho")
            .unwrap_err()
            .to_string()
            .contains("must be an origin")
    );
}

#[test]
fn actor_refusals_preserve_retry_and_stale_meaning_chirho() {
    assert_eq!(
        map_actor_refusal_code_chirho(ResidentGd7WinnerEvidenceRefusalChirho::MailboxFullChirho),
        Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho
    );
    assert_eq!(
        map_actor_refusal_code_chirho(
            ResidentGd7WinnerEvidenceRefusalChirho::ActorUnavailableChirho
        ),
        Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho
    );
    assert_eq!(
        map_actor_refusal_code_chirho(ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho(
            Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho(
                LocalAppendAuthorityRefusalChirho::GuardBusyChirho
            )
        )),
        Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho
    );
    assert_eq!(
        map_actor_refusal_code_chirho(ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho(
            Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho(
                LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho
            )
        )),
        Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho
    );
    assert_eq!(
        map_actor_refusal_code_chirho(ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho(
            Gd7WinnerCurrentViewRefusalChirho::StageIndexMismatchChirho
        )),
        Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
    );
    assert_eq!(
        map_actor_refusal_code_chirho(ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho(
            Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho
        )),
        Gd7WinnerViewTransferRefusalCodeChirho::ActorRefusedChirho
    );
    assert_eq!(
        map_adoption_evidence_refusal_code_chirho(
            ResidentGd7WinnerAdoptionEvidenceRefusalChirho::AcceptedBarrierMissingChirho
        ),
        Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho,
        "a missing accepted append barrier must surface as state drift, not a generic refusal"
    );
}

#[test]
fn adoption_evidence_operations_require_the_restored_transfer_binding_chirho() {
    let request_chirho =
        |transfer_identity_digest_chirho: String,
         operation_chirho: Gd7WinnerViewTransferOperationChirho| {
            Gd7WinnerViewTransferRequestChirho {
                schema_chirho: GD7_WINNER_VIEW_TRANSFER_REQUEST_SCHEMA_V1_CHIRHO.to_owned(),
                consistency_group_digest_chirho: "a".repeat(64),
                sender_node_chirho: "b".repeat(64),
                recipient_node_chirho: "c".repeat(64),
                transfer_identity_digest_chirho,
                expected_raft_term_chirho: 7,
                nonce_chirho: "d".repeat(64),
                operation_chirho,
                key_id_chirho: "b".repeat(64),
                sig_chirho: "test-signature-chirho".to_owned(),
            }
        };
    let active_transfer_chirho = "e".repeat(64);
    let exact_chirho = request_chirho(
        active_transfer_chirho.clone(),
        Gd7WinnerViewTransferOperationChirho::PrepareAdoptionEvidenceChirho,
    );
    verify_staging_operation_binding_chirho(&exact_chirho, Some(&active_transfer_chirho))
        .expect("the exact restored transfer may request accepted adoption evidence");

    let foreign_chirho = request_chirho(
        "f".repeat(64),
        Gd7WinnerViewTransferOperationChirho::PrepareAdoptionEvidenceChirho,
    );
    assert_eq!(
        verify_staging_operation_binding_chirho(&foreign_chirho, Some(&active_transfer_chirho)),
        Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho)
    );
    assert_eq!(
        verify_staging_operation_binding_chirho(&exact_chirho, None),
        Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho),
        "adoption evidence cannot establish a new session binding after restart"
    );
}

#[test]
fn restored_handoff_binding_refuses_stale_stage_zero_and_allows_new_term_management_chirho() {
    let group_digest_chirho =
        consistency_group_digest_chirho(&ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/tmp/gd7-restored-handoff-binding-chirho".to_owned(),
        })
        .expect("derive one canonical consistency-group digest");
    let winner_node_chirho = "b".repeat(64);
    let held_node_chirho = "c".repeat(64);
    let historical_term_chirho = 7_u64;
    let current_term_chirho = historical_term_chirho + 1;
    let held_identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        reconciliation_checkpoint_ref_chirho: "d".repeat(64),
        winner_node_chirho: winner_node_chirho.clone(),
        held_node_chirho: held_node_chirho.clone(),
        winner_term_chirho: historical_term_chirho,
    };
    let attempt_identity_chirho = Gd7WinnerHandoffAttemptIdentityChirho {
        held_transfer_identity_chirho: held_identity_chirho.clone(),
        held_transfer_checkpoint_ref_chirho: "e".repeat(64),
        expected_bundle_root_object_digest_chirho: "f".repeat(64),
        challenge_digest_chirho: "1".repeat(64),
    };
    let active_transfer_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&held_identity_chirho)
            .expect("encode the restored transfer identity"),
    );
    let attempt_digest_chirho = gd7_winner_handoff_attempt_digest_chirho(&attempt_identity_chirho)
        .expect("digest the restored handoff attempt");
    let request_chirho =
        |transfer_identity_digest_chirho: String,
         operation_chirho: Gd7WinnerViewTransferOperationChirho| {
            Gd7WinnerViewTransferRequestChirho {
                schema_chirho: GD7_WINNER_VIEW_TRANSFER_REQUEST_SCHEMA_V1_CHIRHO.to_owned(),
                consistency_group_digest_chirho: group_digest_chirho.clone(),
                sender_node_chirho: held_node_chirho.clone(),
                recipient_node_chirho: winner_node_chirho.clone(),
                transfer_identity_digest_chirho,
                expected_raft_term_chirho: current_term_chirho,
                nonce_chirho: "2".repeat(64),
                operation_chirho,
                key_id_chirho: held_node_chirho.clone(),
                sig_chirho: "test-signature-chirho".to_owned(),
            }
        };

    let stale_stage_zero_chirho = request_chirho(
        "3".repeat(64),
        Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
            expected_stage_index_chirho: 0,
        },
    );
    assert_eq!(
        verify_staging_operation_binding_chirho(
            &stale_stage_zero_chirho,
            Some(&active_transfer_digest_chirho),
        ),
        Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho),
        "a restored durable handoff binding must refuse a different Stage-0 identity"
    );
    let exact_stage_zero_chirho = request_chirho(
        active_transfer_digest_chirho.clone(),
        Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
            expected_stage_index_chirho: 0,
        },
    );
    verify_staging_operation_binding_chirho(
        &exact_stage_zero_chirho,
        Some(&active_transfer_digest_chirho),
    )
    .expect("the exact restored transfer identity remains bound");

    for operation_chirho in [
        Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho {
            attempt_digest_chirho: attempt_digest_chirho.clone(),
        },
        Gd7WinnerViewTransferOperationChirho::AbortHandoffChirho {
            attempt_digest_chirho: attempt_digest_chirho.clone(),
        },
    ] {
        let management_request_chirho =
            request_chirho(active_transfer_digest_chirho.clone(), operation_chirho);
        validate_operation_binding_chirho(
            &management_request_chirho.operation_chirho,
            &group_digest_chirho,
            &held_node_chirho,
            &winner_node_chirho,
            &active_transfer_digest_chirho,
            current_term_chirho,
        )
        .expect("new-term status management is a valid authenticated transport operation");
        verify_handoff_attempt_request_binding_chirho(
            &management_request_chirho,
            &attempt_identity_chirho,
        )
        .expect("status and abort remain bound after a newer-term restart");
    }
}

#[test]
fn authenticated_real_socket_returns_signed_bounded_actor_refusal_chirho() {
    let winner_root_chirho = test_root_chirho("winner");
    let held_root_chirho = test_root_chirho("held");
    let winner_node_chirho = NodeIdChirho(
        pubkey_hex_chirho(&winner_root_chirho).expect("create isolated winner signer"),
    );
    let held_node_chirho =
        NodeIdChirho(pubkey_hex_chirho(&held_root_chirho).expect("create isolated held signer"));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: winner_root_chirho
            .canonicalize()
            .expect("canonicalize winner root")
            .to_string_lossy()
            .into_owned(),
    };
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_cluster_node_with_learners_chirho(
            group_chirho.clone(),
            1,
            vec![(1, winner_node_chirho.clone())],
            vec![(2, held_node_chirho.clone())],
        )
        .expect("construct one-voter plus held-learner election")
        .with_message_authentication_chirho(winner_root_chirho.clone())
        .with_leadership_warmup_lease_chirho(),
    );
    elector_chirho
        .campaign_chirho()
        .expect("campaign one-voter winner");
    for _tick_chirho in 0..10 {
        let _messages_chirho = elector_chirho.tick_chirho();
    }
    let leadership_chirho = elector_chirho.current_leadership_chirho();
    assert!(leadership_chirho.is_leader_chirho);
    assert!(leadership_chirho.lease_valid_chirho);

    let service_chirho = Gd7WinnerViewTransferServiceChirho::open_chirho(
        &winner_root_chirho,
        &group_chirho,
        winner_node_chirho.clone(),
        held_node_chirho.clone(),
        Arc::clone(&elector_chirho),
    )
    .expect("open private transfer surface");
    let admissions_chirho = (0..MAX_GD7_WINNER_VIEW_TRANSFER_INFLIGHT_CHIRHO)
        .map(|_index_chirho| {
            service_chirho
                .try_admit_chirho()
                .expect("fixed transfer admission remains available")
        })
        .collect::<Vec<_>>();
    assert!(
        service_chirho.try_admit_chirho().is_none(),
        "the ninth request refuses before body extraction or blocking work"
    );
    drop(admissions_chirho);
    assert!(
        service_chirho.try_admit_chirho().is_some(),
        "dropping admitted work releases its fixed slot"
    );

    let later_term_frame_chirho = service_chirho
        .signed_response_chirho(
            &"a".repeat(64),
            leadership_chirho.term_chirho + 1,
            Gd7WinnerViewTransferResultChirho::RefusedChirho {
                code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho,
            },
            &[],
        )
        .expect("sign authenticated leadership drift");
    let (later_term_header_chirho, later_term_payload_chirho) =
        decode_frame_chirho(&later_term_frame_chirho).expect("decode leadership drift");
    verify_response_chirho(
        &later_term_header_chirho,
        later_term_payload_chirho,
        &consistency_group_digest_chirho(&group_chirho).expect("digest test group"),
        &"a".repeat(64),
        &winner_node_chirho,
        leadership_chirho.term_chirho,
        &PinnedNodeGd7VerifierChirho::new_chirho(winner_node_chirho.clone())
            .expect("pin winner for leadership-drift response"),
    )
    .expect("a signed later-term leadership refusal reaches typed stale handling");

    let listener_chirho =
        TcpListener::bind("127.0.0.1:0").expect("bind isolated transfer listener");
    let address_chirho = listener_chirho.local_addr().expect("read listener address");
    let admission_probe_service_chirho = service_chirho.clone();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let server_stop_chirho = Arc::clone(&stop_chirho);
    let server_thread_chirho = std::thread::spawn(move || {
        serve_router_blocking_with_shutdown_chirho(
            listener_chirho,
            service_chirho.router_chirho(),
            server_stop_chirho,
        )
    });
    std::thread::sleep(Duration::from_millis(50));

    let held_signer_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(&held_root_chirho, &held_node_chirho)
            .expect("open isolated held signer");
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(1))
        .build();
    let base_url_chirho = format!("http://{address_chirho}");
    let group_digest_chirho =
        consistency_group_digest_chirho(&group_chirho).expect("digest test group");
    let request_nonce_chirho = "e".repeat(64);
    let transfer_identity_digest_chirho = "f".repeat(64);
    let route_admissions_chirho = (0..MAX_GD7_WINNER_VIEW_TRANSFER_INFLIGHT_CHIRHO)
        .map(|_index_chirho| {
            admission_probe_service_chirho
                .try_admit_chirho()
                .expect("reserve every fixed route admission")
        })
        .collect::<Vec<_>>();
    let mut admission_probe_chirho =
        TcpStream::connect(address_chirho).expect("connect raw admission probe");
    admission_probe_chirho
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("bound raw admission response wait");
    write!(
        admission_probe_chirho,
        "POST {GD7_WINNER_VIEW_TRANSFER_PATH_CHIRHO} HTTP/1.1\r\n\
             Host: {address_chirho}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
        MAX_GD7_WINNER_VIEW_TRANSFER_REQUEST_BYTES_CHIRHO + 1
    )
    .expect("send headers without the declared body");
    admission_probe_chirho
        .flush()
        .expect("flush raw admission probe");
    let mut admission_response_chirho = [0_u8; 256];
    let admission_response_len_chirho = admission_probe_chirho
        .read(&mut admission_response_chirho)
        .expect("admission refusal arrives without reading the declared body");
    let admission_status_chirho =
        std::str::from_utf8(&admission_response_chirho[..admission_response_len_chirho])
            .expect("HTTP response status is UTF-8");
    assert!(
        admission_status_chirho.starts_with("HTTP/1.1 503"),
        "fixed admission must reject before body extraction, got {admission_status_chirho:?}"
    );
    drop(route_admissions_chirho);

    let restart_challenge_chirho = generate_gd7_winner_current_view_challenge_chirho(
        elector_chirho.as_ref(),
        &group_chirho,
        &winner_node_chirho,
        &held_node_chirho,
        &transfer_identity_digest_chirho,
    )
    .expect("mint exact held restart challenge")
    .canonical_bytes_chirho()
    .expect("encode exact held restart challenge");
    let restart_reply_chirho = call_winner_view_transfer_chirho(
        Gd7WinnerViewTransferCallContextChirho {
            agent_chirho: &agent_chirho,
            base_url_chirho: &base_url_chirho,
            consistency_group_digest_chirho: &group_digest_chirho,
            sender_signer_chirho: &held_signer_chirho,
            winner_node_chirho: &winner_node_chirho,
            transfer_identity_digest_chirho: &transfer_identity_digest_chirho,
            expected_raft_term_chirho: leadership_chirho.term_chirho,
            request_nonce_chirho: &"c".repeat(64),
        },
        Gd7WinnerViewTransferOperationChirho::SealCurrentViewChirho {
            canonical_challenge_chirho: std::str::from_utf8(&restart_challenge_chirho)
                .expect("restart challenge is UTF-8")
                .to_owned(),
        },
    )
    .expect("winner signs a stale refusal after losing its staging state");
    assert_eq!(
        restart_reply_chirho.result_chirho,
        Gd7WinnerViewTransferResultChirho::RefusedChirho {
            code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho
        }
    );
    let held_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&held_root_chirho)
        .expect("open held transfer evidence storage");
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(winner_node_chirho.clone())
            .expect("pin winner for held transfer evidence");
    let held_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &held_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        Gd7HeldViewTransferIdentityChirho {
            consistency_group_digest_chirho: group_digest_chirho.clone(),
            reconciliation_checkpoint_ref_chirho: "9".repeat(64),
            winner_node_chirho: winner_node_chirho.0.clone(),
            held_node_chirho: held_node_chirho.0.clone(),
            winner_term_chirho: leadership_chirho.term_chirho,
        },
    )
    .expect("open held transfer evidence store");
    let held_active_chirho = held_store_chirho
        .ensure_initialized_chirho()
        .expect("initialize held transfer evidence");
    crate::held_view_transfer_chirho::handle_winner_refusal_chirho(
        &held_store_chirho,
        &held_active_chirho,
        Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho,
    )
    .expect_err("winner restart state makes the held transfer durably stale");
    assert_eq!(
        held_store_chirho
            .load_active_chirho()
            .expect("reload stale held transfer")
            .expect("stale held transfer head remains present")
            .checkpoint_chirho
            .phase_chirho,
        Gd7HeldViewTransferPhaseChirho::StaleChirho
    );

    let reply_chirho = call_winner_view_transfer_chirho(
        Gd7WinnerViewTransferCallContextChirho {
            agent_chirho: &agent_chirho,
            base_url_chirho: &base_url_chirho,
            consistency_group_digest_chirho: &group_digest_chirho,
            sender_signer_chirho: &held_signer_chirho,
            winner_node_chirho: &winner_node_chirho,
            transfer_identity_digest_chirho: &transfer_identity_digest_chirho,
            expected_raft_term_chirho: leadership_chirho.term_chirho,
            request_nonce_chirho: &request_nonce_chirho,
        },
        Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
            expected_stage_index_chirho: 0,
        },
    )
    .expect("first Stage-0 request receives a signed unavailable response");
    assert_eq!(
        reply_chirho.result_chirho,
        Gd7WinnerViewTransferResultChirho::RefusedChirho {
            code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho
        },
        "absent actor handles must refuse without binding the first transfer identity"
    );
    assert!(reply_chirho.canonical_page_bytes_chirho.is_empty());

    let different_transfer_identity_chirho = "1".repeat(64);
    let different_reply_chirho = call_winner_view_transfer_chirho(
        Gd7WinnerViewTransferCallContextChirho {
            agent_chirho: &agent_chirho,
            base_url_chirho: &base_url_chirho,
            consistency_group_digest_chirho: &group_digest_chirho,
            sender_signer_chirho: &held_signer_chirho,
            winner_node_chirho: &winner_node_chirho,
            transfer_identity_digest_chirho: &different_transfer_identity_chirho,
            expected_raft_term_chirho: leadership_chirho.term_chirho,
            request_nonce_chirho: &request_nonce_chirho,
        },
        Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
            expected_stage_index_chirho: 0,
        },
    )
    .expect("different Stage-0 request receives a signed unavailable response");
    assert_eq!(
        different_reply_chirho.result_chirho,
        Gd7WinnerViewTransferResultChirho::RefusedChirho {
            code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho,
        },
        "the first unavailable Stage-0 request must not bind and reject a second identity"
    );

    let original_retry_reply_chirho = call_winner_view_transfer_chirho(
        Gd7WinnerViewTransferCallContextChirho {
            agent_chirho: &agent_chirho,
            base_url_chirho: &base_url_chirho,
            consistency_group_digest_chirho: &group_digest_chirho,
            sender_signer_chirho: &held_signer_chirho,
            winner_node_chirho: &winner_node_chirho,
            transfer_identity_digest_chirho: &transfer_identity_digest_chirho,
            expected_raft_term_chirho: leadership_chirho.term_chirho,
            request_nonce_chirho: &"2".repeat(64),
        },
        Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
            expected_stage_index_chirho: 0,
        },
    )
    .expect("original Stage-0 retry receives a signed unavailable response");
    assert_eq!(
        original_retry_reply_chirho.result_chirho,
        Gd7WinnerViewTransferResultChirho::RefusedChirho {
            code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho,
        },
        "the second unavailable Stage-0 request must not bind its different identity either"
    );

    stop_chirho.store(true, Ordering::Release);
    server_thread_chirho
        .join()
        .expect("transfer server thread does not panic")
        .expect("transfer server shuts down cleanly");
    std::fs::remove_dir_all(winner_root_chirho).expect("remove winner fixture");
    std::fs::remove_dir_all(held_root_chirho).expect("remove held fixture");
}
