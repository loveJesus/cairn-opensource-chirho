// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 full-stack: three nodes assembled exactly as a real deployment would run them — via
//! `ClusterNodeChirho`, each with a DURABLE crash-safe store, AUTHENTICATED messages (real per-node
//! keys), a fire-and-forget driver, and served endpoints on its own socket — elect one leader driven
//! only by their timers. This proves the composition capstone: the whole production stack, wired the way
//! the ≥3-domain fleet will be, elects over real sockets.

use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::cluster_node_chirho::{
    ClusterNodeChirho, ClusterNodeConfigChirho, LocalLeadershipTransferRequestOutcomeChirho,
};
use cairn_writer_elector_http_chirho::{discover_leader_chirho, LeaseTierChirho};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn temp_dir_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-clusternode-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    dir_chirho
}

/// Provision a signing root with a fresh node key and return `(sign_root, node_id=pubkey)`.
fn provision_node_chirho(tag_chirho: &str) -> (PathBuf, NodeIdChirho) {
    let root_chirho = temp_dir_chirho(tag_chirho);
    sign_message_chirho(&root_chirho, b"provision node key").unwrap();
    let pubkey_chirho = pubkey_hex_chirho(&root_chirho).unwrap();
    (root_chirho, NodeIdChirho(pubkey_chirho))
}

#[test]
fn three_durable_authenticated_nodes_elect_via_the_cluster_node_runner_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-clusternode-3node-chirho".to_string(),
    };
    let (root1_chirho, node1_chirho) = provision_node_chirho("n1");
    let (root2_chirho, node2_chirho) = provision_node_chirho("n2");
    let (root3_chirho, node3_chirho) = provision_node_chirho("n3");
    let sign_roots_chirho = [root1_chirho, root2_chirho, root3_chirho];
    let voters_chirho: Vec<(u64, NodeIdChirho)> =
        vec![(1, node1_chirho), (2, node2_chirho), (3, node3_chirho)];

    // Bind sockets first so peer URLs are known before any node is built.
    let listeners_chirho: Vec<std::net::TcpListener> = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let urls_chirho: Vec<String> = listeners_chirho
        .iter()
        .map(|listener_chirho| format!("http://{}", listener_chirho.local_addr().unwrap()))
        .collect();

    // Build each node exactly as a deployment would: durable store, its own key, peers = the other two.
    let nodes_chirho: Vec<ClusterNodeChirho> = (0..3usize)
        .map(|index_chirho| {
            let peers_chirho: Vec<(u64, String)> = (0..3usize)
                .filter(|peer_index_chirho| *peer_index_chirho != index_chirho)
                .map(|peer_index_chirho| {
                    (
                        (peer_index_chirho + 1) as u64,
                        urls_chirho[peer_index_chirho].clone(),
                    )
                })
                .collect();
            ClusterNodeChirho::build_chirho(ClusterNodeConfigChirho {
                group_chirho: group_chirho.clone(),
                local_raft_id_chirho: (index_chirho + 1) as u64,
                voters_chirho: voters_chirho.clone(),
                learners_chirho: Vec::new(),
                peers_chirho,
                durable_dir_chirho: temp_dir_chirho(&format!("durable-{index_chirho}")),
                sign_root_chirho: sign_roots_chirho[index_chirho].clone(),
                tick_interval_chirho: Duration::from_millis(50),
                membership_control_chirho: None,
            })
            .expect("build a cluster node")
        })
        .collect();

    // Read leadership through the same electors the nodes will tick.
    let electors_chirho: Vec<Arc<RaftWriterElectorChirho>> = nodes_chirho
        .iter()
        .map(|node_chirho| node_chirho.elector_chirho().clone())
        .collect();
    let transfer_ports_chirho = nodes_chirho
        .iter()
        .map(ClusterNodeChirho::local_leadership_transfer_port_chirho)
        .collect::<Vec<_>>();
    let empty_transfer_error_chirho = transfer_ports_chirho[0].request_chirho().expect_err(
        "a follower with no known leader must not report an empty transfer as delivered",
    );
    assert!(
        format!("{empty_transfer_error_chirho:?}")
            .contains("LocalLeadershipTransferBatchEmptyRefusedChirho"),
        "the target-free port must fail closed on the primitive's silent empty batch"
    );

    // Run each node (serve + tick) on its own thread.
    let stop_chirho = Arc::new(AtomicBool::new(false));
    for (node_chirho, listener_chirho) in nodes_chirho.into_iter().zip(listeners_chirho) {
        let stop_chirho = stop_chirho.clone();
        std::thread::spawn(move || {
            let _ = node_chirho.serve_blocking_chirho(listener_chirho, stop_chirho);
        });
    }

    // Poll (up to ~20s) for one leader that is stable across two consecutive observations.
    let mut stable_leader_chirho: Option<NodeIdChirho> = None;
    let mut previous_chirho: Option<NodeIdChirho> = None;
    for _poll_chirho in 0..200 {
        std::thread::sleep(Duration::from_millis(100));
        let leaders_chirho: Vec<NodeIdChirho> = electors_chirho
            .iter()
            .filter_map(|elector_chirho| {
                let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
                leadership_chirho
                    .is_leader_chirho
                    .then_some(leadership_chirho.leader_id_chirho)
                    .flatten()
            })
            .collect();
        match leaders_chirho.as_slice() {
            [only_chirho] if previous_chirho.as_ref() == Some(only_chirho) => {
                stable_leader_chirho = Some(only_chirho.clone());
                break;
            }
            [only_chirho] => previous_chirho = Some(only_chirho.clone()),
            _ => previous_chirho = None,
        }
    }

    let leader_chirho =
        stable_leader_chirho.expect("the durable, authenticated cluster elects one stable leader");
    for elector_chirho in &electors_chirho {
        assert_eq!(
            elector_chirho
                .leadership_chirho(&group_chirho)
                .leader_id_chirho
                .as_ref(),
            Some(&leader_chirho),
            "every node agrees on the leader elected by the full production stack"
        );
    }

    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(1))
        .build();
    let lease_wait_deadline_chirho = Instant::now() + Duration::from_secs(5);
    let leader_wire_chirho = loop {
        let responses_chirho = urls_chirho
            .iter()
            .filter_map(|url_chirho| discover_leader_chirho(&agent_chirho, url_chirho).ok())
            .collect::<Vec<_>>();
        for response_chirho in &responses_chirho {
            assert_eq!(
                response_chirho.lease_tier_chirho,
                LeaseTierChirho::MonotonicDecayChirho,
                "every deployable node must structurally advertise the tier-1 monotonic lease"
            );
        }
        if let Some(response_chirho) = responses_chirho.into_iter().find(|response_chirho| {
            response_chirho.is_local_leader_chirho
                && response_chirho.lease_remaining_millis_chirho.is_some()
        }) {
            break response_chirho;
        }
        assert!(
            Instant::now() < lease_wait_deadline_chirho,
            "the deployable leader-info handler must emit a real duration after warm-up"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(
        leader_wire_chirho.leader_node_id_chirho.as_deref(),
        Some(leader_chirho.0.as_str()),
        "the duration-bearing wire response must name the elected leader"
    );
    assert!(
        matches!(
            leader_wire_chirho.lease_remaining_millis_chirho,
            Some(1..=500)
        ),
        "the 50ms deployment tick must yield a bounded one-election-timeout duration"
    );

    let target_index_chirho = voters_chirho
        .iter()
        .position(|(_raft_id_chirho, node_chirho)| node_chirho != &leader_chirho)
        .expect("the three-voter fixture has a follower target");
    let target_node_chirho = voters_chirho[target_index_chirho].1.clone();
    let prior_term_chirho = electors_chirho[target_index_chirho]
        .current_leadership_chirho()
        .term_chirho;
    let transfer_outcome_chirho = transfer_ports_chirho[target_index_chirho]
        .request_chirho()
        .expect("the follower target forwards one authenticated transfer request");
    assert_eq!(
        transfer_outcome_chirho,
        LocalLeadershipTransferRequestOutcomeChirho::DispatchedChirho,
        "a follower request must report that its authenticated control batch was dispatched"
    );
    let transfer_deadline_chirho = Instant::now() + Duration::from_secs(10);
    let transferred_term_chirho = loop {
        let leadership_chirho = electors_chirho[target_index_chirho].current_leadership_chirho();
        let all_agree_chirho = electors_chirho.iter().all(|elector_chirho| {
            elector_chirho
                .current_leadership_chirho()
                .leader_id_chirho
                .as_ref()
                == Some(&target_node_chirho)
        });
        if leadership_chirho.is_leader_chirho
            && leadership_chirho.lease_valid_chirho
            && all_agree_chirho
        {
            break leadership_chirho.term_chirho;
        }
        assert!(
            Instant::now() < transfer_deadline_chirho,
            "the real three-voter driver must deliver the follower-forwarded transfer"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(
        transferred_term_chirho > prior_term_chirho,
        "accepted transfer must make the target leader at a strictly higher term"
    );
    let idempotent_outcome_chirho = transfer_ports_chirho[target_index_chirho]
        .request_chirho()
        .expect("a target-free local request is idempotent after local leadership is achieved");
    assert_eq!(
        idempotent_outcome_chirho,
        LocalLeadershipTransferRequestOutcomeChirho::AlreadyLocalLeaderChirho,
        "the idempotent race path must not be reported as a dispatched transfer"
    );

    stop_chirho.store(true, Ordering::Relaxed);
    for root_chirho in &sign_roots_chirho {
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

#[test]
fn deployed_cluster_node_requires_a_continuous_leadership_warmup_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-clusternode-warmup-chirho".to_string(),
    };
    let (root_chirho, node_id_chirho) = provision_node_chirho("warmup-n1");
    let node_chirho = ClusterNodeChirho::build_chirho(ClusterNodeConfigChirho {
        group_chirho: group_chirho.clone(),
        local_raft_id_chirho: 1,
        voters_chirho: vec![(1, node_id_chirho.clone())],
        learners_chirho: Vec::new(),
        peers_chirho: Vec::new(),
        durable_dir_chirho: temp_dir_chirho("warmup-durable"),
        sign_root_chirho: root_chirho.clone(),
        tick_interval_chirho: Duration::from_millis(50),
        membership_control_chirho: None,
    })
    .expect("build a cluster node");
    node_chirho
        .elector_chirho()
        .campaign_chirho()
        .expect("campaign the deployed elector");

    let fresh_chirho = node_chirho
        .elector_chirho()
        .leadership_chirho(&group_chirho);
    assert_eq!(
        fresh_chirho.leader_id_chirho.as_ref(),
        Some(&node_id_chirho)
    );
    assert!(fresh_chirho.is_leader_chirho);
    assert!(
        !fresh_chirho.lease_valid_chirho,
        "a freshly elected production-composed leader must not receive immediate write authority"
    );
    assert_eq!(
        node_chirho.elector_chirho().lease_tier_chirho(),
        LeaseTierChirho::MonotonicDecayChirho,
        "the deployable constructor must install tier 1 rather than the diagnostic-only tick tier"
    );
    assert_eq!(
        node_chirho
            .elector_chirho()
            .current_lease_remaining_millis_chirho(),
        None,
        "an unwarmed tier-1 leader must advertise no duration"
    );
    let warm_deadline_chirho = Instant::now() + Duration::from_secs(3);
    while !node_chirho
        .elector_chirho()
        .leadership_chirho(&group_chirho)
        .lease_valid_chirho
    {
        assert!(
            Instant::now() < warm_deadline_chirho,
            "the production-composed lease must warm while healthy ticks continue"
        );
        std::thread::sleep(Duration::from_millis(20));
        node_chirho.elector_chirho().tick_chirho();
    }
    assert!(
        node_chirho
            .elector_chirho()
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "one full real-time election timeout of continuous leadership completes production warm-up"
    );
    assert!(
        matches!(
            node_chirho
                .elector_chirho()
                .current_lease_remaining_millis_chirho(),
            Some(1..=500)
        ),
        "a warmed deployable leader must advertise only the remaining bounded duration"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn deployed_cluster_node_refuses_to_open_missing_durable_membership_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-clusternode-missing-state-chirho".to_string(),
    };
    let (root_chirho, node_id_chirho) = provision_node_chirho("missing-state-n1");
    let durable_dir_chirho = temp_dir_chirho("missing-state-durable");

    let result_chirho = ClusterNodeChirho::open_existing_chirho(ClusterNodeConfigChirho {
        group_chirho,
        local_raft_id_chirho: 1,
        voters_chirho: vec![(1, node_id_chirho)],
        learners_chirho: Vec::new(),
        peers_chirho: Vec::new(),
        durable_dir_chirho: durable_dir_chirho.clone(),
        sign_root_chirho: root_chirho.clone(),
        tick_interval_chirho: Duration::from_millis(50),
        membership_control_chirho: None,
    });

    assert!(
        result_chirho.is_err(),
        "authority-bearing cluster serving must refuse missing durable election state"
    );
    assert!(
        !durable_dir_chirho.exists(),
        "an existing-only open must not create or seed a replacement election generation"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn deployed_cluster_node_refuses_incomplete_peer_coverage_before_seeding_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-clusternode-incomplete-peers-chirho".to_string(),
    };
    let (root_chirho, node_id_chirho) = provision_node_chirho("incomplete-peers-n1");
    let durable_dir_chirho = temp_dir_chirho("incomplete-peers-durable");

    let result_chirho = ClusterNodeChirho::build_chirho(ClusterNodeConfigChirho {
        group_chirho,
        local_raft_id_chirho: 1,
        voters_chirho: vec![(1, node_id_chirho), (2, NodeIdChirho("2".repeat(64)))],
        learners_chirho: Vec::new(),
        peers_chirho: Vec::new(),
        durable_dir_chirho: durable_dir_chirho.clone(),
        sign_root_chirho: root_chirho.clone(),
        tick_interval_chirho: Duration::from_millis(50),
        membership_control_chirho: None,
    });

    assert!(
        result_chirho.is_err(),
        "a deployable node must not start with a silently unreachable roster member"
    );
    assert!(
        !durable_dir_chirho.exists(),
        "invalid transport coverage must refuse before durable membership is seeded"
    );

    let self_route_dir_chirho = temp_dir_chirho("self-route-durable");
    let self_route_result_chirho = ClusterNodeChirho::build_chirho(ClusterNodeConfigChirho {
        group_chirho: ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/var/lib/cairn-clusternode-self-route-chirho".to_string(),
        },
        local_raft_id_chirho: 1,
        voters_chirho: vec![(1, NodeIdChirho("1".repeat(64)))],
        learners_chirho: Vec::new(),
        peers_chirho: vec![(1, "http://127.0.0.1:9".to_string())],
        durable_dir_chirho: self_route_dir_chirho.clone(),
        sign_root_chirho: root_chirho.clone(),
        tick_interval_chirho: Duration::from_millis(50),
        membership_control_chirho: None,
    });
    assert!(
        self_route_result_chirho.is_err(),
        "a local self-route must not create a redundant worker or self-delivery path"
    );
    assert!(
        !self_route_dir_chirho.exists(),
        "a local self-route refuses before durable membership is seeded"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn deployed_cluster_node_reopens_an_exact_persisted_roster_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-clusternode-existing-state-chirho".to_string(),
    };
    let (root_chirho, node_id_chirho) = provision_node_chirho("existing-state-n1");
    let durable_dir_chirho = temp_dir_chirho("existing-state-durable");
    let build_config_chirho = || ClusterNodeConfigChirho {
        group_chirho: group_chirho.clone(),
        local_raft_id_chirho: 1,
        voters_chirho: vec![(1, node_id_chirho.clone())],
        learners_chirho: Vec::new(),
        peers_chirho: Vec::new(),
        durable_dir_chirho: durable_dir_chirho.clone(),
        sign_root_chirho: root_chirho.clone(),
        tick_interval_chirho: Duration::from_millis(50),
        membership_control_chirho: None,
    };

    let seeded_node_chirho =
        ClusterNodeChirho::build_chirho(build_config_chirho()).expect("seed durable membership");
    drop(seeded_node_chirho);

    let reopened_node_chirho = ClusterNodeChirho::open_existing_chirho(build_config_chirho())
        .expect("reopen the exact durable membership without reseeding it");
    assert!(
        !reopened_node_chirho
            .elector_chirho()
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "reopening exact membership must not grant write authority before election and warmup"
    );

    drop(reopened_node_chirho);
    let _ = std::fs::remove_dir_all(durable_dir_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn a_cluster_node_shuts_down_cleanly_when_stopped_chirho() {
    // Setting the stop flag makes serve_blocking gracefully shut down and RETURN, so the serve thread
    // exits — the node is cleanly restartable (the drain/roll step), not only killable.
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-clusternode-shutdown-chirho".to_string(),
    };
    let (root_chirho, node_id_chirho) = provision_node_chirho("shutdown-n1");
    let node_chirho = ClusterNodeChirho::build_chirho(ClusterNodeConfigChirho {
        group_chirho,
        local_raft_id_chirho: 1,
        voters_chirho: vec![(1, node_id_chirho)],
        learners_chirho: Vec::new(),
        peers_chirho: Vec::new(),
        durable_dir_chirho: temp_dir_chirho("shutdown-durable"),
        sign_root_chirho: root_chirho.clone(),
        tick_interval_chirho: Duration::from_millis(50),
        membership_control_chirho: None,
    })
    .expect("build a cluster node");

    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let serve_stop_chirho = stop_chirho.clone();
    let handle_chirho = std::thread::spawn(move || {
        node_chirho.serve_blocking_chirho(listener_chirho, serve_stop_chirho)
    });

    // Let it come up, then ask it to stop.
    std::thread::sleep(Duration::from_millis(300));
    stop_chirho.store(true, Ordering::Relaxed);

    // The serve thread must exit within a bounded time (a broken shutdown would hang, and this fails
    // rather than hanging the suite).
    let mut exited_chirho = false;
    for _wait_chirho in 0..50 {
        if handle_chirho.is_finished() {
            exited_chirho = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        exited_chirho,
        "the node's serve loop returns on stop (graceful shutdown), so the node is cleanly restartable"
    );
    let _ = handle_chirho.join();
    let _ = std::fs::remove_dir_all(&root_chirho);
}
