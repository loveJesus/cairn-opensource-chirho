// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 network transport, server-security + object-plane over a REAL socket, self-contained (no
//! head-mutation crate, so the P3 no-write-authority guard stays strict): the source's signing key is
//! refused with 403 at the wire (allowlist enforced server-side) while the public anchor log is served;
//! a bearer token gates who may pull; and objects round-trip through the client adapter and re-hash.
//! The full roster→pull→log-copy→fold end-to-end (which needs real signed anchors) lives in the root
//! crate's `tests/p3_http_transport_chirho.rs`.

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::ContentStoreChirho;
use cairn_model_gate1_chirho::GATE1_LOG_ANCHORS_FILE_CHIRHO;
use cairn_replication_chirho::ReplicationSourceChirho;
use cairn_replication_http_chirho::client_chirho::HttpReplicationSourceChirho;
use cairn_replication_http_chirho::server_chirho::{
    replication_router_chirho, serve_router_blocking_chirho,
};
use cairn_replication_http_chirho::{
    log_by_name_url_chirho, object_by_hash_url_chirho, objects_list_url_chirho,
};
use cairn_replication_localfs_chirho::LocalFsReplicationSourceChirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-p3-http-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// Bind an ephemeral loopback port and serve the replication router over the source root on a detached
/// thread; return the base URL. The socket is bound before the thread starts, so a client connect
/// queues in the listen backlog and succeeds once axum begins accepting — no startup sleep needed.
fn start_server_chirho(source_root_chirho: &Path, bearer_chirho: Option<String>) -> String {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let source_chirho: Arc<dyn ReplicationSourceChirho + Send + Sync> = Arc::new(
        LocalFsReplicationSourceChirho::new_chirho(source_root_chirho),
    );
    let router_chirho = replication_router_chirho(source_chirho, bearer_chirho);
    std::thread::spawn(move || {
        let _ = serve_router_blocking_chirho(listener_chirho, router_chirho);
    });
    base_url_chirho
}

#[test]
fn signing_key_is_refused_over_the_wire_chirho() {
    let source_chirho = tmp_root_chirho("hostile-src");
    // Plant a private-key-shaped file and a public anchor log at the source root.
    std::fs::write(
        source_chirho.join("signing-key-chirho.bin"),
        b"PRIVATE-ED25519-SEED-DO-NOT-REPLICATE",
    )
    .unwrap();
    std::fs::write(
        source_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
        b"{\"anchor\":1}\n",
    )
    .unwrap();
    let base_url_chirho = start_server_chirho(&source_chirho, None);
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();

    // A hostile replica names the private key directly — the server allowlist must refuse it (403),
    // and no key bytes may cross the wire.
    let key_url_chirho = log_by_name_url_chirho(&base_url_chirho, "signing-key-chirho.bin");
    match agent_chirho.get(&key_url_chirho).call() {
        Err(ureq::Error::Status(403, _)) => {}
        other_chirho => {
            panic!("the signing key must be refused with 403 over the wire: {other_chirho:?}")
        }
    }

    // The allowlisted anchor log IS served, byte-for-byte.
    let anchor_url_chirho = log_by_name_url_chirho(&base_url_chirho, GATE1_LOG_ANCHORS_FILE_CHIRHO);
    let anchor_resp_chirho = agent_chirho
        .get(&anchor_url_chirho)
        .call()
        .expect("the public anchor log is served");
    assert_eq!(anchor_resp_chirho.status(), 200);
    let mut body_chirho = String::new();
    use std::io::Read;
    anchor_resp_chirho
        .into_reader()
        .read_to_string(&mut body_chirho)
        .unwrap();
    assert_eq!(body_chirho, "{\"anchor\":1}\n");

    let _ = std::fs::remove_dir_all(source_chirho);
}

#[test]
fn bearer_token_gates_who_may_pull_chirho() {
    let source_chirho = tmp_root_chirho("auth-src");
    let token_chirho = "s3cr3t-replica-token-chirho";
    let base_url_chirho = start_server_chirho(&source_chirho, Some(token_chirho.to_string()));
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let list_url_chirho = objects_list_url_chirho(&base_url_chirho);

    // No token -> 401.
    match agent_chirho.get(&list_url_chirho).call() {
        Err(ureq::Error::Status(401, _)) => {}
        other_chirho => panic!("a missing bearer must be 401: {other_chirho:?}"),
    }
    // Wrong token -> 401.
    match agent_chirho
        .get(&list_url_chirho)
        .set("Authorization", "Bearer wrong-token-chirho")
        .call()
    {
        Err(ureq::Error::Status(401, _)) => {}
        other_chirho => panic!("a wrong bearer must be 401: {other_chirho:?}"),
    }
    // Correct token -> 200.
    let ok_chirho = agent_chirho
        .get(&list_url_chirho)
        .set("Authorization", &format!("Bearer {token_chirho}"))
        .call()
        .expect("a valid bearer is accepted");
    assert_eq!(ok_chirho.status(), 200);

    let _ = std::fs::remove_dir_all(source_chirho);
}

#[test]
fn objects_round_trip_through_the_client_adapter_chirho() {
    let source_chirho = tmp_root_chirho("obj-src");
    let source_store_chirho = FsContentStoreChirho::new_chirho(&source_chirho);
    let bodies_chirho: [&[u8]; 2] = [b"http-object-alpha-chirho", b"http-object-beta-chirho"];
    let addrs_chirho: Vec<HashChirho> = bodies_chirho
        .iter()
        .map(|b_chirho| source_store_chirho.put_chirho(b_chirho).unwrap())
        .collect();

    let base_url_chirho = start_server_chirho(&source_chirho, None);
    let client_chirho = HttpReplicationSourceChirho::new_chirho(&base_url_chirho, None);

    // The client lists and fetches the objects over the socket; each fetched body re-hashes to the
    // address the server offered.
    let listed_chirho = client_chirho.list_object_addrs_chirho().unwrap();
    assert_eq!(listed_chirho.len(), 2);
    for (addr_chirho, body_chirho) in addrs_chirho.iter().zip(bodies_chirho.iter()) {
        // The address came from a content-addressing put, so a body that matches proves the wire
        // round-trip; hash-verification-on-receipt is proven by the receiver in the root end-to-end.
        let fetched_chirho = client_chirho.fetch_object_chirho(addr_chirho).unwrap();
        assert_eq!(fetched_chirho.as_deref(), Some(*body_chirho));
    }
    // A missing object is None over the wire, not an error.
    let absent_chirho = HashChirho("0".repeat(64));
    assert!(client_chirho
        .fetch_object_chirho(&absent_chirho)
        .unwrap()
        .is_none());

    let _ = std::fs::remove_dir_all(source_chirho);
}

#[test]
fn malformed_object_hash_and_non_allowlisted_log_rejected_at_the_wire_chirho() {
    let source_chirho = tmp_root_chirho("wire-neg-src");
    std::fs::write(
        source_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
        b"{\"anchor\":1}\n",
    )
    .unwrap();
    let base_url_chirho = start_server_chirho(&source_chirho, None);
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();

    // A non-hex or wrong-length object address is rejected (400) before any store touch — a route
    // param can never become a path or oversized key.
    for bad_hash_chirho in [
        "g".repeat(64),  // 64 chars, non-hex
        "a".repeat(63),  // too short
        "a".repeat(65),  // too long
        "AB".repeat(32), // uppercase
    ] {
        let url_chirho = object_by_hash_url_chirho(&base_url_chirho, &bad_hash_chirho);
        match agent_chirho.get(&url_chirho).call() {
            Err(ureq::Error::Status(400, _)) => {}
            other_chirho => panic!(
                "a malformed object address must be 400: {bad_hash_chirho} -> {other_chirho:?}"
            ),
        }
    }

    // A log name outside the allowlist is refused (403), even a plausible-looking one.
    for bad_name_chirho in [
        "not-allowlisted-chirho.jsonl",
        "refs-chirho.json",
        "config-chirho.toml",
    ] {
        let url_chirho = log_by_name_url_chirho(&base_url_chirho, bad_name_chirho);
        match agent_chirho.get(&url_chirho).call() {
            Err(ureq::Error::Status(403, _)) => {}
            other_chirho => {
                panic!("a non-allowlisted log must be 403: {bad_name_chirho} -> {other_chirho:?}")
            }
        }
    }

    let _ = std::fs::remove_dir_all(source_chirho);
}

#[test]
fn client_does_not_follow_redirects_chirho() {
    use std::io::{Read, Write};
    // A hostile source that 302-redirects every request (an SSRF lever, and a way to replay the
    // bearer to another host). The client must NOT follow it, and must NOT read the redirect as an
    // empty/absent object.
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream_chirho in listener_chirho.incoming() {
            let Ok(mut stream_chirho) = stream_chirho else {
                continue;
            };
            let mut buf_chirho = [0u8; 1024];
            let _ = stream_chirho.read(&mut buf_chirho);
            let _ = stream_chirho.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n",
            );
        }
    });

    let client_chirho = HttpReplicationSourceChirho::new_chirho(&base_url_chirho, None);
    let addr_chirho = HashChirho("a".repeat(64));
    let result_chirho = client_chirho.fetch_object_chirho(&addr_chirho);
    assert!(
        result_chirho.is_err(),
        "a 302 from a hostile source must be an error, not a followed or empty fetch: {result_chirho:?}"
    );
}
