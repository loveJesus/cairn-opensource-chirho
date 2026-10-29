// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 failover end-to-end: a 3-node async-driver cluster elects a leader over real sockets, then the
//! leader is "killed" (its timer loop stops, so it stops heartbeating), and the survivors detect the
//! silence, time out, and elect a NEW leader — automatically, with no operator and no explicit campaign.
//! This is the "master hops geos on downtime" story, proven over loopback. Timing is generous and the
//! assertions are on the settled state, so it is robust rather than a race.

use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::driver_chirho::RaftDriverChirho;
use cairn_writer_elector_http_chirho::{raft_fire_router_chirho, serve_router_blocking_chirho};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Poll (up to ~25s) for a single leader — optionally excluding one node index (the killed one) — that is
/// the same across two consecutive observations. Returns the node index of that stable leader.
fn wait_for_stable_leader_chirho(
    electors_chirho: &[Arc<RaftWriterElectorChirho>],
    group_chirho: &ConsistencyGroupIdChirho,
    exclude_index_chirho: Option<usize>,
) -> Option<usize> {
    let mut previous_chirho: Option<usize> = None;
    for _poll_chirho in 0..250 {
        std::thread::sleep(Duration::from_millis(100));
        let leaders_chirho: Vec<usize> = electors_chirho
            .iter()
            .enumerate()
            .filter(|(index_chirho, elector_chirho)| {
                Some(*index_chirho) != exclude_index_chirho
                    && elector_chirho
                        .leadership_chirho(group_chirho)
                        .is_leader_chirho
            })
            .map(|(index_chirho, _)| index_chirho)
            .collect();
        match leaders_chirho.as_slice() {
            [only_chirho] if previous_chirho == Some(*only_chirho) => return Some(*only_chirho),
            [only_chirho] => previous_chirho = Some(*only_chirho),
            _ => previous_chirho = None,
        }
    }
    None
}

#[test]
fn a_killed_leader_fails_over_to_a_survivor_over_sockets_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-failover-chirho".to_string(),
    };
    let voters_chirho: Vec<(u64, NodeIdChirho)> = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
        (3, NodeIdChirho("3".repeat(64))),
    ];

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

    for (index_chirho, listener_chirho) in listeners_chirho.into_iter().enumerate() {
        let router_chirho = raft_fire_router_chirho(drivers_chirho[index_chirho].clone());
        std::thread::spawn(move || {
            let _ = serve_router_blocking_chirho(listener_chirho, router_chirho);
        });
    }

    // Each node's timer loop checks its OWN stop flag, so we can "kill" one node's progress on demand.
    let stops_chirho: Vec<Arc<AtomicBool>> =
        (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
    for index_chirho in 0..3 {
        let driver_chirho = drivers_chirho[index_chirho].clone();
        let stop_chirho = stops_chirho[index_chirho].clone();
        std::thread::spawn(move || {
            while !stop_chirho.load(Ordering::Relaxed) {
                driver_chirho.tick_once_chirho();
                std::thread::sleep(Duration::from_millis(50));
            }
        });
    }

    // A leader emerges.
    let first_leader_index_chirho =
        wait_for_stable_leader_chirho(&electors_chirho, &group_chirho, None)
            .expect("an initial leader is elected");

    // KILL the leader: stop its timer loop, so it stops heartbeating (its server keeps running, so this
    // is the "leader hung / stopped making progress" failure the survivors must ride out).
    stops_chirho[first_leader_index_chirho].store(true, Ordering::Relaxed);

    // The survivors detect the silence, time out, and elect a NEW leader — a different, surviving node.
    let new_leader_index_chirho = wait_for_stable_leader_chirho(
        &electors_chirho,
        &group_chirho,
        Some(first_leader_index_chirho),
    )
    .expect("the survivors fail over to a new leader");

    assert_ne!(
        new_leader_index_chirho, first_leader_index_chirho,
        "failover elected a different, surviving node"
    );

    // Every surviving node agrees on the new leader.
    let new_leader_id_chirho = electors_chirho[new_leader_index_chirho]
        .leadership_chirho(&group_chirho)
        .leader_id_chirho;
    assert!(new_leader_id_chirho.is_some());
    for (index_chirho, elector_chirho) in electors_chirho.iter().enumerate() {
        if index_chirho == first_leader_index_chirho {
            continue; // the killed node is frozen; we do not require its view
        }
        assert_eq!(
            elector_chirho
                .leadership_chirho(&group_chirho)
                .leader_id_chirho,
            new_leader_id_chirho,
            "a surviving node agrees on the failed-over leader"
        );
    }

    for stop_chirho in &stops_chirho {
        stop_chirho.store(true, Ordering::Relaxed);
    }
}
