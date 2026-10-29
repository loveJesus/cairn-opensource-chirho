// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 object-plane evidence bar over the local-fs transport: copied bytes re-hash to their source
//! identities, a corrupted object is quarantined and never served, and the pull advances no head.

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{ContentReadChirho, ContentStoreChirho};
use cairn_model_gate1_chirho::{GATE1_LEDGER_FAMILY_CHIRHO, GATE1_LOG_ANCHORS_FILE_CHIRHO};
use cairn_replication_chirho::{
    receive_objects_chirho, ObjectReceiptChirho, ReplicationSourceChirho,
};
use cairn_replication_localfs_chirho::{FsReplicaQuarantineChirho, LocalFsReplicationSourceChirho};
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-p3-object-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn seed_source_chirho(root_chirho: &Path, bodies_chirho: &[&[u8]]) -> Vec<HashChirho> {
    let store_chirho = FsContentStoreChirho::new_chirho(root_chirho);
    bodies_chirho
        .iter()
        .map(|body_chirho| store_chirho.put_chirho(body_chirho).unwrap())
        .collect()
}

fn sharded_object_path_chirho(root_chirho: &Path, addr_chirho: &HashChirho) -> PathBuf {
    let hex_chirho = &addr_chirho.0;
    root_chirho
        .join("objects-chirho")
        .join(&hex_chirho[0..2])
        .join(&hex_chirho[2..])
}

#[test]
fn honest_source_replicates_all_objects_and_they_all_rehash_chirho() {
    let source_chirho = tmp_root_chirho("src");
    let replica_chirho = tmp_root_chirho("rep");
    let bodies_chirho: [&[u8]; 3] = [
        b"alpha-object-chirho",
        b"beta-object-chirho",
        b"gamma-chirho",
    ];
    let addrs_chirho = seed_source_chirho(&source_chirho, &bodies_chirho);

    let source_port_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_chirho);
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_chirho);

    let (report_chirho, receipts_chirho) =
        receive_objects_chirho(&source_port_chirho, &served_chirho, &quarantine_chirho).unwrap();

    assert_eq!(report_chirho.listed_chirho, 3);
    assert_eq!(report_chirho.stored_chirho, 3);
    assert_eq!(report_chirho.quarantined_chirho, 0);
    assert_eq!(report_chirho.missing_chirho, 0);
    assert!(receipts_chirho
        .iter()
        .all(|r_chirho| matches!(r_chirho, ObjectReceiptChirho::StoredChirho { .. })));

    // Every replicated object is present in the served store AND re-hashes (get verifies address).
    for (addr_chirho, body_chirho) in addrs_chirho.iter().zip(bodies_chirho.iter()) {
        assert_eq!(
            served_chirho.get_chirho(addr_chirho).unwrap().as_deref(),
            Some(*body_chirho)
        );
    }
    // No head was advanced: the pull wrote only objects, never a ref or reflog.
    assert!(!replica_chirho.join("refs-chirho.json").exists());
    assert!(!replica_chirho.join("reflog-chirho.jsonl").exists());
    let _ = std::fs::remove_dir_all(source_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn corrupted_source_object_is_quarantined_and_never_served_chirho() {
    let source_chirho = tmp_root_chirho("src-tamper");
    let replica_chirho = tmp_root_chirho("rep-tamper");
    let bodies_chirho: [&[u8]; 3] = [b"keep-one-chirho", b"tamper-me-chirho", b"keep-two-chirho"];
    let addrs_chirho = seed_source_chirho(&source_chirho, &bodies_chirho);
    let tampered_addr_chirho = addrs_chirho[1].clone();

    // Corrupt the source object's bytes in place — its filename still claims the honest address, so
    // the transport hands the receiver bytes that do NOT re-hash to that address.
    let path_chirho = sharded_object_path_chirho(&source_chirho, &tampered_addr_chirho);
    std::fs::write(&path_chirho, b"forged-substituted-body-chirho").unwrap();

    let source_port_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_chirho);
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_chirho);
    let (report_chirho, _receipts_chirho) =
        receive_objects_chirho(&source_port_chirho, &served_chirho, &quarantine_chirho).unwrap();

    assert_eq!(
        report_chirho.stored_chirho, 2,
        "the two honest objects still replicate"
    );
    assert_eq!(
        report_chirho.quarantined_chirho, 1,
        "the substituted object is quarantined"
    );
    // The forged object is NEVER served: the served store has nothing at the claimed address.
    assert!(
        served_chirho
            .get_chirho(&tampered_addr_chirho)
            .unwrap()
            .is_none(),
        "a quarantined object must never reach the served store"
    );
    // It landed in quarantine under its TRUE (forged) blake3, not the claimed address.
    let forged_true_chirho = HashChirho(
        blake3::hash(b"forged-substituted-body-chirho")
            .to_hex()
            .to_string(),
    );
    assert!(quarantine_chirho
        .quarantine_dir_chirho()
        .join(&forged_true_chirho.0)
        .exists());
    // The two honest objects are still served and re-hash.
    assert_eq!(
        served_chirho
            .get_chirho(&addrs_chirho[0])
            .unwrap()
            .as_deref(),
        Some(bodies_chirho[0])
    );
    assert_eq!(
        served_chirho
            .get_chirho(&addrs_chirho[2])
            .unwrap()
            .as_deref(),
        Some(bodies_chirho[2])
    );
    let _ = std::fs::remove_dir_all(source_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn empty_or_absent_source_yields_empty_pull_chirho() {
    let source_chirho = tmp_root_chirho("src-empty");
    let replica_chirho = tmp_root_chirho("rep-empty");
    let source_port_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_chirho);
    let served_chirho = FsContentStoreChirho::new_chirho(&replica_chirho);
    let quarantine_chirho = FsReplicaQuarantineChirho::new_chirho(&replica_chirho);
    let (report_chirho, receipts_chirho) =
        receive_objects_chirho(&source_port_chirho, &served_chirho, &quarantine_chirho).unwrap();
    assert_eq!(report_chirho.listed_chirho, 0);
    assert!(receipts_chirho.is_empty());
    let _ = std::fs::remove_dir_all(source_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn fetch_named_log_allowlists_public_logs_and_refuses_the_signing_key_chirho() {
    let source_chirho = tmp_root_chirho("src-allowlist");
    // Plant a private-key-shaped file (the real key file name) and public logs at the source root.
    std::fs::write(
        source_chirho.join("signing-key-chirho.bin"),
        b"PRIVATE-ED25519-SEED-DO-NOT-REPLICATE",
    )
    .unwrap();
    std::fs::write(source_chirho.join("pubkey-chirho.hex"), b"deadbeef").unwrap();
    std::fs::write(source_chirho.join("refs-chirho.json"), b"{}").unwrap();
    std::fs::write(
        source_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
        b"{\"anchor\":1}\n",
    )
    .unwrap();
    std::fs::write(
        source_chirho.join(GATE1_LEDGER_FAMILY_CHIRHO),
        b"{\"ledger\":1}\n",
    )
    .unwrap();
    let port_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_chirho);

    // The private signing key is a plain file name with no traversal characters — an allowlist (not a
    // denylist) is what refuses it. This is the invariant that keys never leave the writer region.
    let key_err_chirho = port_chirho
        .fetch_named_log_chirho("signing-key-chirho.bin")
        .unwrap_err()
        .to_string();
    assert!(
        key_err_chirho.contains("not an allowlisted public log"),
        "the source signing key must never be served by name: {key_err_chirho}"
    );
    for name_chirho in [
        "pubkey-chirho.hex",
        "refs-chirho.json",
        "anything-chirho.txt",
    ] {
        assert!(
            port_chirho.fetch_named_log_chirho(name_chirho).is_err(),
            "a non-allowlisted name must be refused: {name_chirho}"
        );
    }

    // The public anchor log and Ring-A family logs ARE served.
    assert_eq!(
        port_chirho
            .fetch_named_log_chirho(GATE1_LOG_ANCHORS_FILE_CHIRHO)
            .unwrap()
            .as_deref(),
        Some(&b"{\"anchor\":1}\n"[..])
    );
    assert_eq!(
        port_chirho
            .fetch_named_log_chirho(GATE1_LEDGER_FAMILY_CHIRHO)
            .unwrap()
            .as_deref(),
        Some(&b"{\"ledger\":1}\n"[..])
    );
    let _ = std::fs::remove_dir_all(source_chirho);
}

#[cfg(unix)]
#[test]
fn fetch_object_refuses_a_symlink_escaping_the_store_chirho() {
    let source_chirho = tmp_root_chirho("src-objsymlink");
    // A secret outside objects-chirho.
    std::fs::write(
        source_chirho.join("signing-key-chirho.bin"),
        b"PRIVATE-ED25519-SEED-DO-NOT-SERVE",
    )
    .unwrap();
    // Plant a valid-content-address-named symlink INSIDE objects-chirho pointing at the secret. The
    // 64-hex name passes the object route's shape check, so only store-side containment can stop it.
    let hex_chirho = "a".repeat(64);
    let shard_dir_chirho = source_chirho.join("objects-chirho").join(&hex_chirho[0..2]);
    std::fs::create_dir_all(&shard_dir_chirho).unwrap();
    std::os::unix::fs::symlink(
        source_chirho.join("signing-key-chirho.bin"),
        shard_dir_chirho.join(&hex_chirho[2..]),
    )
    .unwrap();

    let port_chirho = LocalFsReplicationSourceChirho::new_chirho(&source_chirho);
    // The symlink resolves outside objects-chirho, so it is treated as absent — the secret is NEVER
    // returned as if it were a content-addressed object.
    assert!(
        port_chirho
            .fetch_object_chirho(&HashChirho(hex_chirho))
            .unwrap()
            .is_none(),
        "a symlink escaping objects-chirho must not serve the target's bytes"
    );
    let _ = std::fs::remove_dir_all(source_chirho);
}
