// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 transport-auth end-to-end: a 3-node Raft cluster elects one leader with every message crossing a
//! REAL loopback HTTP socket AS A SIGNED ENVELOPE. Each node has its own ed25519 key; the roster maps
//! each raft id to that node's pubkey; each elector runs with authentication on, so every message it
//! emits is signed and every message it receives is verified against the roster before `step`. This
//! proves the authenticated transport still elects, and that garbage that is not a valid signed envelope
//! is rejected at the endpoint — the transport-auth BLOCKER fix, over real sockets.

use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::{
    post_raft_message_chirho, raft_message_router_chirho, serve_router_blocking_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-authhttp-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    dir_chirho
}

/// Provision a signing root with a fresh node key and return `(root, node_id=pubkey)`.
fn provision_node_chirho(tag_chirho: &str) -> (PathBuf, NodeIdChirho) {
    let root_chirho = temp_root_chirho(tag_chirho);
    sign_message_chirho(&root_chirho, b"provision node key").unwrap();
    let pubkey_chirho = pubkey_hex_chirho(&root_chirho).unwrap();
    (root_chirho, NodeIdChirho(pubkey_chirho))
}

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
fn three_authenticated_nodes_elect_over_real_http_sockets_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-authhttp-3node-chirho".to_string(),
    };
    // Real per-node keys; the roster identity IS each node's pubkey.
    let (root1_chirho, node1_chirho) = provision_node_chirho("n1");
    let (root2_chirho, node2_chirho) = provision_node_chirho("n2");
    let (root3_chirho, node3_chirho) = provision_node_chirho("n3");
    let roots_chirho = [
        root1_chirho.clone(),
        root2_chirho.clone(),
        root3_chirho.clone(),
    ];
    let voters_chirho: Vec<(u64, NodeIdChirho)> =
        vec![(1, node1_chirho), (2, node2_chirho), (3, node3_chirho)];

    let electors_chirho: Vec<Arc<RaftWriterElectorChirho>> = (1..=3u64)
        .map(|raft_id_chirho| {
            let elector_chirho = RaftWriterElectorChirho::new_cluster_node_chirho(
                group_chirho.clone(),
                raft_id_chirho,
                voters_chirho.clone(),
            )
            .expect("build a cluster-member elector")
            .with_message_authentication_chirho(
                roots_chirho[(raft_id_chirho - 1) as usize].clone(),
            );
            Arc::new(elector_chirho)
        })
        .collect();

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

    // Node 1 campaigns; every message thereafter crosses a real socket AS A SIGNED ENVELOPE.
    let mut bus_chirho: Vec<(u64, Vec<u8>)> = electors_chirho[0]
        .campaign_encoded_chirho()
        .expect("node 1 campaigns (signed)");
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
                    .expect("POST the signed raft message over http"),
            );
        }
        bus_chirho = next_chirho;
    }

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
        "exactly one leader emerges over authenticated http sockets"
    );
    let leader_id_chirho = leaders_chirho[0]
        .leadership_chirho(&group_chirho)
        .leader_id_chirho;
    assert!(leader_id_chirho.is_some());
    for elector_chirho in &electors_chirho {
        assert_eq!(
            elector_chirho
                .leadership_chirho(&group_chirho)
                .leader_id_chirho,
            leader_id_chirho,
            "all authenticated nodes agree on the leader"
        );
    }

    // An unauthenticated body (not a signed envelope) is rejected by an authenticated endpoint: the POST
    // gets a non-2xx, so the client call errors rather than the node stepping unverified input.
    let node1_url_chirho = &urls_chirho
        .iter()
        .find(|(raft_id_chirho, _)| *raft_id_chirho == 1)
        .unwrap()
        .1;
    let garbage_chirho =
        post_raft_message_chirho(&agent_chirho, node1_url_chirho, b"not-an-envelope");
    assert!(
        garbage_chirho.is_err(),
        "an authenticated endpoint rejects a body that is not a signed envelope"
    );

    for root_chirho in &roots_chirho {
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}
