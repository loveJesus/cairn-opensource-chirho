// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 leader discovery: a client GETs `/leader-chirho` on any node and learns who the current elected
//! writer (master) is for that node's group — the routing read that lets a client send writes to the
//! right place, and that follows the election on failover. Proven over a real loopback socket.

use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::driver_chirho::RaftDriverChirho;
use cairn_writer_elector_http_chirho::{
    discover_leader_chirho, raft_fire_router_chirho, serve_router_blocking_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn leader_discovery_reports_the_elected_master_over_http_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-discovery-chirho".to_string(),
    };
    let node_id_chirho = NodeIdChirho("a".repeat(64));
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(
            node_id_chirho.clone(),
            group_chirho.clone(),
        )
        .expect("build a single-node elector"),
    );
    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");

    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();
    let driver_chirho = Arc::new(
        RaftDriverChirho::new_chirho(elector_chirho, Vec::new(), Duration::from_secs(5))
            .expect("start an empty bounded delivery worker set"),
    );

    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let router_chirho = raft_fire_router_chirho(driver_chirho);
    std::thread::spawn(move || {
        let _ = serve_router_blocking_chirho(listener_chirho, router_chirho);
    });

    let info_chirho = discover_leader_chirho(&agent_chirho, &base_url_chirho)
        .expect("discover the leader over http");
    assert!(
        info_chirho.is_local_leader_chirho,
        "the sole node is the current leader"
    );
    assert_eq!(
        info_chirho.leader_node_id_chirho.as_deref(),
        Some(node_id_chirho.0.as_str()),
        "discovery reports the elected leader's node id"
    );
    assert!(info_chirho.term_chirho >= 1, "the leader holds a real term");
}
