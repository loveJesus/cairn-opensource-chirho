// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 network transport, full end-to-end over a REAL socket: a rostered source with real signed Ring-A
//! anchors and seeded objects is served by the axum replication server, and a replica syncs it THROUGH
//! the `ureq` client adapter — objects hash-verify into the served store, the Ring-A logs copy, and the
//! fold reproduces the five CLSD digests, all over the wire, with no head advanced. (The server's
//! allowlist + bearer security lives in the http crate's own `tests/http_transport_chirho.rs`.)

use cairn_chirho::gate1_anchor_chirho::{
    append_gate1_ring_a_anchors_chirho, export_gate1_anchor_head_replication_chirho,
};
use cairn_core_chirho::model_chirho::RefsChirho;
use cairn_core_chirho::ports_chirho::{ContentReadChirho, ContentStoreChirho};
use cairn_core_chirho::refs_chirho::save_refs_chirho;
use cairn_replication_chirho::membership_chirho::{
    unsigned_membership_roster_message_chirho, MembershipActionChirho,
    MembershipRosterRecordChirho, MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
};
use cairn_replication_chirho::ref_snapshot_chirho::{
    export_ref_snapshot_chirho, REF_SNAPSHOT_LOG_FILE_CHIRHO,
};
use cairn_replication_chirho::ReplicationSourceChirho;
use cairn_replication_http_chirho::pull_chirho::{
    pull_and_verify_http_replica_chirho, HttpReplicaPullConfigChirho,
};
use cairn_replication_http_chirho::server_chirho::{
    replication_router_chirho, serve_router_blocking_chirho,
};
use cairn_replication_localfs_chirho::LocalFsReplicationSourceChirho;
use cairn_signer_chirho::signer_chirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-p3-httpe2e-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn add_node_roster_line_chirho(operator_root_chirho: &Path, node_pubkey_chirho: &str) -> Vec<u8> {
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap();
    let mut record_chirho = MembershipRosterRecordChirho {
        schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 0,
        action_chirho: MembershipActionChirho::AddNodeChirho,
        node_pubkey_hex_chirho: node_pubkey_chirho.to_string(),
        region_label_chirho: "us-east-chirho".to_string(),
        at_ms_chirho: 1,
        operator_key_id_chirho: operator_pubkey_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_membership_roster_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(operator_root_chirho, &message_chirho).unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

/// Bind an ephemeral loopback port and serve the replication router over the source root on a detached
/// thread; return the base URL. The socket is bound before the thread starts, so a client connect
/// queues in the listen backlog and succeeds once axum begins accepting — no startup sleep needed.
fn start_server_chirho(source_root_chirho: &Path) -> String {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let source_chirho: Arc<dyn ReplicationSourceChirho + Send + Sync> = Arc::new(
        LocalFsReplicationSourceChirho::new_chirho(source_root_chirho),
    );
    let router_chirho = replication_router_chirho(source_chirho, None);
    std::thread::spawn(move || {
        let _ = serve_router_blocking_chirho(listener_chirho, router_chirho);
    });
    base_url_chirho
}

#[test]
fn replica_syncs_over_real_http_and_verifies_chirho() {
    let source_chirho = tmp_root_chirho("src");
    append_gate1_ring_a_anchors_chirho(&source_chirho).unwrap();
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_chirho).unwrap();
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();
    let head_bytes_chirho = serde_json::to_vec(&head_chirho).unwrap();

    // Seed content-addressed objects so the object plane is exercised over the wire.
    let source_store_chirho = FsContentStoreChirho::new_chirho(&source_chirho);
    let obj_a_chirho = source_store_chirho
        .put_chirho(b"http-replica-object-alpha-chirho")
        .unwrap();
    let obj_b_chirho = source_store_chirho
        .put_chirho(b"http-replica-object-beta-chirho")
        .unwrap();
    let mut branches_chirho = BTreeMap::new();
    branches_chirho.insert("app/http-replica-chirho".to_string(), obj_a_chirho.clone());
    branches_chirho.insert(
        "app-route/http-replica-chirho/root-chirho".to_string(),
        obj_b_chirho.clone(),
    );
    save_refs_chirho(
        &source_chirho,
        &RefsChirho {
            branches_chirho,
            tags_chirho: BTreeMap::new(),
            head_chirho: "app/http-replica-chirho".to_string(),
        },
    )
    .unwrap();
    export_ref_snapshot_chirho(&source_chirho, 1_000).unwrap();

    let operator_chirho = tmp_root_chirho("op");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let roster_chirho = [add_node_roster_line_chirho(
        &operator_chirho,
        &source_pubkey_chirho,
    )];
    let roster_path_chirho = operator_chirho.join("membership-roster-chirho.jsonl");
    let mut roster_bytes_chirho = roster_chirho[0].clone();
    roster_bytes_chirho.push(b'\n');
    std::fs::write(&roster_path_chirho, roster_bytes_chirho).unwrap();
    let head_path_chirho = operator_chirho.join("gate1-anchor-head-chirho.json");
    std::fs::write(&head_path_chirho, &head_bytes_chirho).unwrap();

    let base_url_chirho = start_server_chirho(&source_chirho);

    // The deployable pull composition syncs both independent verified planes through a real socket.
    let replica_chirho = tmp_root_chirho("rep");
    let report_chirho = pull_and_verify_http_replica_chirho(
        &HttpReplicaPullConfigChirho {
            source_url_chirho: base_url_chirho,
            bearer_env_chirho: None,
            replica_root_chirho: replica_chirho.clone(),
            roster_lines_path_chirho: roster_path_chirho,
            head_path_chirho,
            operator_pubkey_hex_chirho: operator_pubkey_chirho,
            source_pubkey_hex_chirho: source_pubkey_chirho,
        },
        2_000,
    )
    .expect("a rostered source must sync and verify over real HTTP");

    assert_eq!(
        report_chirho
            .sync_chirho
            .verified_fold_chirho
            .verified_group_count_chirho,
        4
    );
    assert!(report_chirho.sync_chirho.object_pull_chirho.stored_chirho >= 2);
    assert_eq!(
        report_chirho
            .sync_chirho
            .object_pull_chirho
            .quarantined_chirho,
        0
    );
    assert!(report_chirho.ref_snapshot_log_bytes_chirho > 0);
    assert_eq!(report_chirho.ref_snapshot_mount_chirho.ref_count_chirho, 2);
    assert!(replica_chirho.join(REF_SNAPSHOT_LOG_FILE_CHIRHO).is_file());
    // The objects pulled over the wire are served on the replica AND re-hash (get verifies address).
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_chirho);
    assert_eq!(
        served_chirho.get_chirho(&obj_a_chirho).unwrap().as_deref(),
        Some(&b"http-replica-object-alpha-chirho"[..])
    );
    assert_eq!(
        served_chirho.get_chirho(&obj_b_chirho).unwrap().as_deref(),
        Some(&b"http-replica-object-beta-chirho"[..])
    );
    // No head advanced on the replica.
    assert!(!replica_chirho.join("refs-chirho.json").exists());

    let _ = std::fs::remove_dir_all(source_chirho);
    let _ = std::fs::remove_dir_all(operator_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn replica_pull_names_a_missing_ref_snapshot_without_mounting_refs_chirho() {
    let source_chirho = tmp_root_chirho("missing-snapshot-src");
    append_gate1_ring_a_anchors_chirho(&source_chirho).unwrap();
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_chirho).unwrap();
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();

    let operator_chirho = tmp_root_chirho("missing-snapshot-op");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let roster_path_chirho = operator_chirho.join("membership-roster-chirho.jsonl");
    let mut roster_line_chirho =
        add_node_roster_line_chirho(&operator_chirho, &source_pubkey_chirho);
    roster_line_chirho.push(b'\n');
    std::fs::write(&roster_path_chirho, roster_line_chirho).unwrap();
    let head_path_chirho = operator_chirho.join("gate1-anchor-head-chirho.json");
    std::fs::write(&head_path_chirho, serde_json::to_vec(&head_chirho).unwrap()).unwrap();

    let replica_chirho = tmp_root_chirho("missing-snapshot-rep");
    let error_chirho = pull_and_verify_http_replica_chirho(
        &HttpReplicaPullConfigChirho {
            source_url_chirho: start_server_chirho(&source_chirho),
            bearer_env_chirho: None,
            replica_root_chirho: replica_chirho.clone(),
            roster_lines_path_chirho: roster_path_chirho,
            head_path_chirho,
            operator_pubkey_hex_chirho: operator_pubkey_chirho,
            source_pubkey_hex_chirho: source_pubkey_chirho,
        },
        2_000,
    )
    .expect_err("Gate1 alone must not make a replica usable without a signed ref snapshot");
    let message_chirho = format!("{error_chirho:#}");
    assert!(
        message_chirho.contains("HttpReplicaSnapshotMissingChirho"),
        "a missing snapshot must preserve its refusal identity: {message_chirho}"
    );
    assert!(
        !message_chirho.contains("HttpReplicaSnapshotEmptyChirho"),
        "a missing snapshot must not be mislabeled as an empty snapshot: {message_chirho}"
    );
    assert!(
        !replica_chirho.join("refs-chirho.json").exists(),
        "a failed snapshot pull must not mount or advance mutable refs"
    );

    let _ = std::fs::remove_dir_all(source_chirho);
    let _ = std::fs::remove_dir_all(operator_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}
