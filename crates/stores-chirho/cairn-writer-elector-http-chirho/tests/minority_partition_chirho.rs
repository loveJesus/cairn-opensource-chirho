// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 split-brain safety: the property that makes automatic failover SAFE. One node of three is
//! partitioned away (it can reach no peer and no peer can reach it) while the other two form a majority.
//! The isolated node — a minority of one — can NEVER elect itself (pre-vote fails with no quorum), so it
//! cannot become a second master; meanwhile the majority side elects a leader without it. Proven over
//! real sockets. This is why a home region that loses contact fails CLOSED instead of splitting brain.

use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::driver_chirho::RaftDriverChirho;
use cairn_writer_elector_http_chirho::{raft_fire_router_chirho, serve_router_blocking_chirho};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn a_partitioned_minority_node_cannot_elect_itself_over_sockets_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-partition-chirho".to_string(),
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

    // The PARTITION, expressed as peer lists: node 0 <-> node 1 can reach each other; node 2 (the
    // minority) has NO peers and is named by neither of them, so no message ever crosses to or from it.
    let peer_lists_chirho: Vec<Vec<(u64, String)>> = vec![
        vec![(2, urls_chirho[1].clone())], // node 0 (raft id 1) -> node 1 only
        vec![(1, urls_chirho[0].clone())], // node 1 (raft id 2) -> node 0 only
        Vec::new(),                        // node 2 (raft id 3) -> isolated
    ];

    let drivers_chirho: Vec<Arc<RaftDriverChirho>> = (0..3usize)
        .map(|index_chirho| {
            Arc::new(
                RaftDriverChirho::new_chirho(
                    electors_chirho[index_chirho].clone(),
                    peer_lists_chirho[index_chirho].clone(),
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

    let stop_chirho = Arc::new(AtomicBool::new(false));
    let mut handles_chirho = Vec::new();
    for driver_chirho in &drivers_chirho {
        let driver_chirho = driver_chirho.clone();
        let stop_chirho = stop_chirho.clone();
        handles_chirho.push(std::thread::spawn(move || {
            while !stop_chirho.load(Ordering::Relaxed) {
                driver_chirho.tick_once_chirho();
                std::thread::sleep(Duration::from_millis(50));
            }
        }));
    }

    // The majority side (nodes 0 and 1) elects a leader; poll for it to settle.
    let mut majority_leader_chirho: Option<usize> = None;
    for _poll_chirho in 0..200 {
        std::thread::sleep(Duration::from_millis(100));
        let majority_leaders_chirho: Vec<usize> = [0usize, 1usize]
            .into_iter()
            .filter(|index_chirho| {
                electors_chirho[*index_chirho]
                    .leadership_chirho(&group_chirho)
                    .is_leader_chirho
            })
            .collect();
        if let [only_chirho] = majority_leaders_chirho.as_slice() {
            if majority_leader_chirho == Some(*only_chirho) {
                break;
            }
            majority_leader_chirho = Some(*only_chirho);
        } else {
            majority_leader_chirho = None;
        }
    }
    assert!(
        majority_leader_chirho.is_some(),
        "the two-node majority elects a leader without the partitioned node"
    );

    // THE SAFETY ASSERTION: the isolated minority node NEVER became leader — no split brain.
    assert!(
        !electors_chirho[2]
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "a partitioned minority node must never elect itself (split-brain prevented)"
    );
    // Give it extra time in isolation and re-check — it still cannot self-elect.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !electors_chirho[2]
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "the partitioned node stays unable to become a second master"
    );

    stop_chirho.store(true, Ordering::Relaxed);
    for handle_chirho in handles_chirho {
        let _ = handle_chirho.join();
    }
}
