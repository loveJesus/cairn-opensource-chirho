// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 slice 3b end-to-end: a 3-node Raft cluster elects one stable leader with every message crossing a
//! REAL loopback HTTP socket. Each node runs a Raft-message endpoint over its elector; a synchronous
//! router POSTs each encoded message to its target and re-routes the encoded replies until the election
//! settles. This proves the proven consensus carries over the transport — deterministically, no async
//! tick timers, so there are no races to make it flaky.

use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::{
    post_raft_message_chirho, raft_message_router_chirho, serve_router_blocking_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::sync::Arc;
use std::time::Duration;

/// Bind an ephemeral loopback port and serve the node's Raft-message endpoint on a detached thread;
/// return the base URL. The socket is bound before the thread starts, so a POST queues in the listen
/// backlog and succeeds once axum begins accepting — no startup sleep needed.
fn start_raft_server_chirho(elector_chirho: Arc<RaftWriterElectorChirho>) -> String {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let router_chirho = raft_message_router_chirho(elector_chirho);
    std::thread::spawn(move || {
        let _ = serve_router_blocking_chirho(listener_chirho, router_chirho);
    });
    base_url_chirho
}

#[test]
fn three_node_cluster_elects_over_real_http_sockets_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-http-3node-chirho".to_string(),
    };
    let voters_chirho: Vec<(u64, NodeIdChirho)> = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
        (3, NodeIdChirho("3".repeat(64))),
    ];
    let electors_chirho: Vec<Arc<RaftWriterElectorChirho>> = (1..=3)
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

    // Each node serves its Raft-message endpoint; the endpoint holds the SAME Arc elector we read below.
    let urls_chirho: Vec<(u64, String)> = electors_chirho
        .iter()
        .map(|elector_chirho| {
            (
                elector_chirho.local_raft_id_chirho(),
                start_raft_server_chirho(elector_chirho.clone()),
            )
        })
        .collect();
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();

    // Node 1 campaigns locally to start the election; every message thereafter crosses a real socket.
    let mut bus_chirho: Vec<(u64, Vec<u8>)> = electors_chirho[0]
        .campaign_encoded_chirho()
        .expect("node 1 campaigns");
    for _round_chirho in 0..1000 {
        if bus_chirho.is_empty() {
            break;
        }
        let mut next_chirho: Vec<(u64, Vec<u8>)> = Vec::new();
        for (to_chirho, message_bytes_chirho) in bus_chirho.drain(..) {
            let base_url_chirho = &urls_chirho
                .iter()
                .find(|(raft_id_chirho, _)| *raft_id_chirho == to_chirho)
                .expect("target node has a server")
                .1;
            next_chirho.extend(
                post_raft_message_chirho(&agent_chirho, base_url_chirho, &message_bytes_chirho)
                    .expect("POST the raft message over http"),
            );
        }
        bus_chirho = next_chirho;
    }

    // Exactly one leader emerged over the sockets, and every node agrees on it.
    let leaders_chirho: Vec<&Arc<RaftWriterElectorChirho>> = electors_chirho
        .iter()
        .filter(|elector_chirho| {
            elector_chirho
                .leadership_chirho(&group_chirho)
                .is_leader_chirho
        })
        .collect();
    assert_eq!(
        leaders_chirho.len(),
        1,
        "exactly one leader emerges over real http sockets"
    );
    let leader_id_chirho = leaders_chirho[0]
        .leadership_chirho(&group_chirho)
        .leader_id_chirho;
    assert!(leader_id_chirho.is_some());
    for elector_chirho in &electors_chirho {
        let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
        assert_eq!(
            leadership_chirho.leader_id_chirho, leader_id_chirho,
            "all nodes agree on the leader elected over http"
        );
        assert!(leadership_chirho.term_chirho >= 1);
    }
}
