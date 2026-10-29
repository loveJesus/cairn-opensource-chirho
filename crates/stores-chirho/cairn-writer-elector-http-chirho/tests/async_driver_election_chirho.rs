// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 async driver end-to-end: a 3-node cluster elects one stable leader driven ONLY by each node's own
//! timer — no explicit campaign, no synchronous bus. Each node runs a `RaftDriverChirho` that ticks its
//! elector on a ~50ms timer and fire-and-forgets the resulting messages to its peers' fire endpoints;
//! each peer steps them and pumps its own replies onward. This is the production peer-to-peer path. The
//! test waits (generously) for a single leader that stays stable across consecutive observations, so it
//! asserts on the settled state rather than a timing coincidence.

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::driver_chirho::{RaftDriverChirho, RAFT_FIRE_PATH_CHIRHO};
use cairn_writer_elector_http_chirho::{
    raft_fire_router_chirho, serve_router_blocking_chirho,
    serve_router_blocking_with_shutdown_chirho, MAX_RAFT_MESSAGE_BYTES_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn driver_refuses_unbounded_or_ambiguous_worker_configuration_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-bounded-driver-config-chirho".to_string(),
    };
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(NodeIdChirho("1".repeat(64)), group_chirho)
            .expect("build the local elector"),
    );
    assert!(
        RaftDriverChirho::new_chirho(elector_chirho.clone(), Vec::new(), Duration::ZERO,).is_err(),
        "delivery workers require a finite nonzero request timeout"
    );
    assert!(
        RaftDriverChirho::new_chirho(elector_chirho.clone(), Vec::new(), Duration::from_secs(6),)
            .is_err(),
        "delivery workers refuse a request timeout outside the shutdown bound"
    );
    assert!(
        RaftDriverChirho::new_chirho(
            elector_chirho.clone(),
            vec![(0, "http://127.0.0.1:9".to_string())],
            Duration::from_secs(1),
        )
        .is_err(),
        "raft id zero is not a valid delivery target"
    );
    assert!(
        RaftDriverChirho::new_chirho(
            elector_chirho.clone(),
            vec![(2, "http://peer.internal-chirho:8300".to_string())],
            Duration::from_secs(1),
        )
        .is_err(),
        "hostname resolution must not escape the bounded numeric mesh transport"
    );
    let oversized_peer_set_chirho = (2..=18_u64)
        .map(|raft_id_chirho| (raft_id_chirho, "http://127.0.0.1:9".to_string()))
        .collect::<Vec<_>>();
    assert!(
        RaftDriverChirho::new_chirho(
            elector_chirho.clone(),
            oversized_peer_set_chirho,
            Duration::from_secs(1),
        )
        .is_err(),
        "one consistency group must not create an unbounded worker fleet"
    );
    assert!(
        RaftDriverChirho::new_chirho(
            elector_chirho,
            vec![
                (2, "http://127.0.0.1:9".to_string()),
                (2, "http://127.0.0.1:10".to_string()),
            ],
            Duration::from_secs(1),
        )
        .is_err(),
        "duplicate peer ids must not create ambiguous delivery workers"
    );
}

#[test]
fn stalled_peer_delivery_has_a_bounded_nonblocking_backlog_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-bounded-driver-chirho".to_string(),
    };
    let voters_chirho = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
    ];
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_cluster_node_chirho(group_chirho, 1, voters_chirho)
            .expect("build the local elector"),
    );
    let stalled_listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stalled_url_chirho = format!("http://{}", stalled_listener_chirho.local_addr().unwrap());
    let driver_chirho = RaftDriverChirho::new_chirho(
        elector_chirho,
        vec![(2, stalled_url_chirho)],
        Duration::from_millis(250),
    )
    .expect("start one bounded delivery worker");

    let oversized_report_chirho = driver_chirho.pump_chirho(vec![(
        2,
        vec![0_u8; MAX_RAFT_MESSAGE_BYTES_CHIRHO.saturating_add(1)],
    )]);
    assert_eq!(oversized_report_chirho.dropped_messages_chirho, 1);
    assert_eq!(
        driver_chirho.dropped_outbound_messages_chirho(),
        1,
        "an oversized message must not enter the bounded peer backlog"
    );

    let started_chirho = Instant::now();
    let saturation_report_chirho =
        driver_chirho.pump_chirho((0..256).map(|_| (2, vec![0_u8; 64])).collect::<Vec<_>>());

    assert!(
        started_chirho.elapsed() < Duration::from_secs(1),
        "enqueue must not wait on a stalled peer's network request"
    );
    assert!(
        driver_chirho.dropped_outbound_messages_chirho() > 0,
        "a saturated bounded backlog must drop retryable traffic instead of growing"
    );
    assert_eq!(
        saturation_report_chirho.enqueued_messages_chirho
            + saturation_report_chirho.dropped_messages_chirho,
        256,
        "every offered retryable message is explicitly classified"
    );
    assert!(
        saturation_report_chirho.dropped_messages_chirho > 0,
        "the caller observes saturation instead of receiving a silent success"
    );

    let shutdown_started_chirho = Instant::now();
    drop(driver_chirho);
    assert!(
        shutdown_started_chirho.elapsed() < Duration::from_secs(2),
        "a stalled numeric peer cannot hold driver shutdown beyond the bounded request window"
    );
    drop(stalled_listener_chirho);
}

async fn accept_required_control_chirho(
    State(received_chirho): State<Arc<AtomicU64>>,
    _body_chirho: Bytes,
) -> StatusCode {
    received_chirho.fetch_add(1, Ordering::Relaxed);
    StatusCode::OK
}

#[test]
fn required_control_delivery_is_acknowledged_and_unknown_targets_fail_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-required-control-chirho".to_string(),
    };
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(NodeIdChirho("1".repeat(64)), group_chirho)
            .expect("build the local elector"),
    );
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let received_chirho = Arc::new(AtomicU64::new(0));
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let server_received_chirho = received_chirho.clone();
    let server_stop_chirho = stop_chirho.clone();
    let server_handle_chirho = std::thread::spawn(move || {
        let router_chirho = Router::new()
            .route(RAFT_FIRE_PATH_CHIRHO, post(accept_required_control_chirho))
            .with_state(server_received_chirho);
        serve_router_blocking_with_shutdown_chirho(
            listener_chirho,
            router_chirho,
            server_stop_chirho,
        )
        .expect("serve the acknowledged control receiver");
    });
    let driver_chirho = RaftDriverChirho::new_chirho(
        elector_chirho,
        vec![(2, peer_url_chirho)],
        Duration::from_secs(1),
    )
    .expect("start the bounded driver");

    driver_chirho
        .deliver_required_control_chirho(vec![(2, vec![1_u8, 2, 3])])
        .expect("the required control message receives an HTTP acknowledgement");
    assert_eq!(
        received_chirho.load(Ordering::Relaxed),
        1,
        "the successful required-control result is backed by receiver execution"
    );
    assert!(
        driver_chirho
            .deliver_required_control_chirho(vec![(3, vec![4_u8])])
            .is_err(),
        "an unconfigured one-shot target is an explicit error, never a silent drop"
    );

    stop_chirho.store(true, Ordering::Relaxed);
    server_handle_chirho.join().unwrap();
}

#[test]
fn three_node_cluster_elects_a_stable_leader_via_async_drivers_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-async-driver-chirho".to_string(),
    };
    let voters_chirho: Vec<(u64, NodeIdChirho)> = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
        (3, NodeIdChirho("3".repeat(64))),
    ];

    // Bind every node's socket first so peer URLs are known before any driver starts sending.
    let listeners_chirho: Vec<std::net::TcpListener> = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let urls_chirho: Vec<String> = listeners_chirho
        .iter()
        .map(|listener_chirho| format!("http://{}", listener_chirho.local_addr().unwrap()))
        .collect();

    let electors_chirho: Vec<Arc<RaftWriterElectorChirho>> = (1..=3u64)
        .map(|raft_id_chirho| {
            Arc::new(
                RaftWriterElectorChirho::new_cluster_node_chirho(
                    group_chirho.clone(),
                    raft_id_chirho,
                    voters_chirho.clone(),
                )
                .expect("build a cluster-member elector"),
            )
        })
        .collect();

    // Each driver knows its PEERS (every voter except itself) by URL.
    let drivers_chirho: Vec<Arc<RaftDriverChirho>> = (0..3usize)
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
            Arc::new(
                RaftDriverChirho::new_chirho(
                    electors_chirho[index_chirho].clone(),
                    peers_chirho,
                    Duration::from_secs(2),
                )
                .expect("start bounded peer delivery workers"),
            )
        })
        .collect();

    // Serve each node's fire endpoint over its bound socket.
    for (index_chirho, listener_chirho) in listeners_chirho.into_iter().enumerate() {
        let router_chirho = raft_fire_router_chirho(drivers_chirho[index_chirho].clone());
        std::thread::spawn(move || {
            let _ = serve_router_blocking_chirho(listener_chirho, router_chirho);
        });
    }

    // Start each node's timer loop: tick, pump, sleep. Elections start from the tick timeout alone.
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let mut tick_handles_chirho = Vec::new();
    for driver_chirho in &drivers_chirho {
        let driver_chirho = driver_chirho.clone();
        let stop_chirho = stop_chirho.clone();
        tick_handles_chirho.push(std::thread::spawn(move || {
            while !stop_chirho.load(Ordering::Relaxed) {
                driver_chirho.tick_once_chirho();
                std::thread::sleep(Duration::from_millis(50));
            }
        }));
    }

    // Poll (up to ~20s) for a SINGLE leader that is the same across two consecutive observations — the
    // settled state, not a transient mid-election glimpse.
    let single_leader_chirho = |group_chirho: &ConsistencyGroupIdChirho| -> Option<NodeIdChirho> {
        let leaders_chirho: Vec<NodeIdChirho> = electors_chirho
            .iter()
            .filter_map(|elector_chirho| {
                let leadership_chirho = elector_chirho.leadership_chirho(group_chirho);
                leadership_chirho
                    .is_leader_chirho
                    .then_some(leadership_chirho.leader_id_chirho)
                    .flatten()
            })
            .collect();
        (leaders_chirho.len() == 1).then(|| leaders_chirho[0].clone())
    };

    let mut stable_leader_chirho: Option<NodeIdChirho> = None;
    let mut previous_chirho: Option<NodeIdChirho> = None;
    for _poll_chirho in 0..200 {
        std::thread::sleep(Duration::from_millis(100));
        match single_leader_chirho(&group_chirho) {
            Some(leader_chirho) if previous_chirho.as_ref() == Some(&leader_chirho) => {
                stable_leader_chirho = Some(leader_chirho);
                break;
            }
            other_chirho => previous_chirho = other_chirho,
        }
    }

    stop_chirho.store(true, Ordering::Relaxed);
    for handle_chirho in tick_handles_chirho {
        let _ = handle_chirho.join();
    }

    let leader_chirho = stable_leader_chirho
        .expect("a stable single leader emerges via async drivers over sockets");
    // Every node agrees on that leader.
    for elector_chirho in &electors_chirho {
        assert_eq!(
            elector_chirho
                .leadership_chirho(&group_chirho)
                .leader_id_chirho
                .as_ref(),
            Some(&leader_chirho),
            "all nodes agree on the async-elected leader"
        );
    }
}
