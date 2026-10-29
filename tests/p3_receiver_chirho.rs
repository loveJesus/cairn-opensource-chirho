// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 full replica sync: an operator-rostered source is verified end to end — objects hash-verify
//! into the served store, the Gate 1 authority logs copy and verify against the source-signed head,
//! and the five Ring-A CLSD digests are independently reproduced. A source absent from the roster
//! fails closed before any trust.

use cairn_chirho::gate1_anchor_chirho::{
    append_gate1_ring_a_anchors_chirho, export_gate1_anchor_head_replication_chirho,
};
use cairn_core_chirho::ports_chirho::{ContentReadChirho, ContentStoreChirho};
use cairn_replication_chirho::membership_chirho::{
    unsigned_membership_roster_message_chirho, MembershipActionChirho,
    MembershipRosterRecordChirho, MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
};
use cairn_replication_chirho::receiver_chirho::receive_and_verify_replica_chirho;
use cairn_replication_localfs_chirho::{FsReplicaQuarantineChirho, LocalFsReplicationSourceChirho};
use cairn_signer_chirho::signer_chirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-p3-recv-{label_chirho}-{}-{n_chirho}",
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

#[test]
fn rostered_source_syncs_and_verifies_end_to_end_chirho() {
    let source_chirho = tmp_root_chirho("src");
    // Seed real signed Ring-A anchors + a signed head, and a couple of immutable objects.
    append_gate1_ring_a_anchors_chirho(&source_chirho).unwrap();
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_chirho).unwrap();
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();
    let head_bytes_chirho = serde_json::to_vec(&head_chirho).unwrap();
    let source_store_chirho = FsContentStoreChirho::new_chirho(&source_chirho);
    let obj_a_chirho = source_store_chirho
        .put_chirho(b"replica-object-alpha-chirho")
        .unwrap();
    let obj_b_chirho = source_store_chirho
        .put_chirho(b"replica-object-beta-chirho")
        .unwrap();

    // The operator signs a roster listing the source node.
    let operator_chirho = tmp_root_chirho("op");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let roster_chirho = vec![add_node_roster_line_chirho(
        &operator_chirho,
        &source_pubkey_chirho,
    )];

    // The replica syncs.
    let replica_chirho = tmp_root_chirho("rep");
    let source_port_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_chirho);
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_chirho);
    let report_chirho = receive_and_verify_replica_chirho(
        &source_port_chirho,
        &served_chirho,
        &quarantine_chirho,
        &replica_chirho,
        &roster_chirho,
        &operator_pubkey_chirho,
        &source_pubkey_chirho,
        &head_bytes_chirho,
        None,
    )
    .expect("a rostered source with a valid signed head must sync and verify");

    assert_eq!(report_chirho.source_region_chirho, "us-east-chirho");
    assert_eq!(
        report_chirho
            .verified_fold_chirho
            .verified_group_count_chirho,
        4
    );
    assert_eq!(report_chirho.object_pull_chirho.quarantined_chirho, 0);
    assert!(report_chirho.object_pull_chirho.stored_chirho >= 2);
    // The objects are served and re-hash.
    assert_eq!(
        served_chirho.get_chirho(&obj_a_chirho).unwrap().as_deref(),
        Some(&b"replica-object-alpha-chirho"[..])
    );
    assert_eq!(
        served_chirho.get_chirho(&obj_b_chirho).unwrap().as_deref(),
        Some(&b"replica-object-beta-chirho"[..])
    );
    // No head was advanced on the replica.
    assert!(!replica_chirho.join("refs-chirho.json").exists());

    let _ = std::fs::remove_dir_all(source_chirho);
    let _ = std::fs::remove_dir_all(operator_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn source_absent_from_roster_fails_closed_chirho() {
    let source_chirho = tmp_root_chirho("src2");
    append_gate1_ring_a_anchors_chirho(&source_chirho).unwrap();
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_chirho).unwrap();
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();
    let head_bytes_chirho = serde_json::to_vec(&head_chirho).unwrap();

    // Roster lists a DIFFERENT node, not the source.
    let operator_chirho = tmp_root_chirho("op2");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let other_node_chirho = "c".repeat(64);
    let roster_chirho = vec![add_node_roster_line_chirho(
        &operator_chirho,
        &other_node_chirho,
    )];

    let replica_chirho = tmp_root_chirho("rep2");
    let source_port_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_chirho);
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_chirho);
    let error_chirho = receive_and_verify_replica_chirho(
        &source_port_chirho,
        &served_chirho,
        &quarantine_chirho,
        &replica_chirho,
        &roster_chirho,
        &operator_pubkey_chirho,
        &source_pubkey_chirho,
        &head_bytes_chirho,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("not an active member"),
        "a source absent from the roster must fail closed before trust: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(source_chirho);
    let _ = std::fs::remove_dir_all(operator_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn rostered_source_below_anti_rollback_floor_fails_closed_chirho() {
    let source_chirho = tmp_root_chirho("src3");
    append_gate1_ring_a_anchors_chirho(&source_chirho).unwrap();
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_chirho).unwrap();
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();
    let anchor_count_chirho = head_chirho.anchor_record_count_chirho;
    let head_bytes_chirho = serde_json::to_vec(&head_chirho).unwrap();

    let operator_chirho = tmp_root_chirho("op3");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let roster_chirho = vec![add_node_roster_line_chirho(
        &operator_chirho,
        &source_pubkey_chirho,
    )];

    // The replica already verified a later head, so it passes a floor ABOVE this head's count. The
    // sync must fail closed as a rollback even though the source is rostered and the head is valid.
    let replica_chirho = tmp_root_chirho("rep3");
    let source_port_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_chirho);
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_chirho);
    let error_chirho = receive_and_verify_replica_chirho(
        &source_port_chirho,
        &served_chirho,
        &quarantine_chirho,
        &replica_chirho,
        &roster_chirho,
        &operator_pubkey_chirho,
        &source_pubkey_chirho,
        &head_bytes_chirho,
        Some(anchor_count_chirho + 1),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("anti-rollback floor"),
        "a stale head below the caller's floor must fail closed: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(source_chirho);
    let _ = std::fs::remove_dir_all(operator_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}
