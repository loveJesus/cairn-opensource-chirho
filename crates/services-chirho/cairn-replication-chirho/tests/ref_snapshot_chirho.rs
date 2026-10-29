// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! B2.1 ref-snapshot plane: export selects/signs only the app families idempotently; the replica
//! mount verifies every row against the pinned key and binds stone↔head; the A2 floor semantics
//! hold — restart re-mounts idempotently, stale heads roll back closed, and equivocation (one
//! source key, two stones, one seq) fails LOUDLY naming both hashes.

use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::{HashChirho, RefsChirho};
use cairn_core_chirho::ports_chirho::{ContentReadChirho, ContentStoreChirho};
use cairn_core_chirho::refs_chirho::save_refs_chirho;
use cairn_model_gate1_chirho::{GATE1_LOG_ANCHORS_FILE_CHIRHO, GATE1_RING_A_ANCHOR_TARGETS_CHIRHO};
use cairn_replication_chirho::is_replicable_log_name_chirho;
use cairn_replication_chirho::ref_snapshot_chirho::{
    check_head_against_floor_chirho, export_ref_snapshot_chirho, is_snapshot_ref_name_chirho,
    mount_latest_verified_snapshot_chirho, mount_ref_snapshot_chirho,
    read_ref_snapshot_floor_chirho, read_verified_snapshot_heads_chirho,
    unsigned_ref_snapshot_head_message_chirho, validate_ref_snapshot_head_chirho,
    FloorDecisionChirho, RefSnapshotChirho, RefSnapshotHeadRecordChirho,
    REF_SNAPSHOT_HEAD_SCHEMA_CHIRHO, REF_SNAPSHOT_LOG_FILE_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-refsnap-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// Seed a source root: store one target object per ref name and save a refs file that ALSO
/// carries non-app families the export must refuse to carry.
fn seed_source_chirho(
    source_root_chirho: &Path,
    app_names_chirho: &[&str],
) -> BTreeMap<String, HashChirho> {
    let store_chirho = FsContentStoreChirho::new_chirho(source_root_chirho);
    let mut branches_chirho: BTreeMap<String, HashChirho> = BTreeMap::new();
    for name_chirho in app_names_chirho {
        let target_chirho = store_chirho
            .put_chirho(format!("target stone for {name_chirho}").as_bytes())
            .unwrap();
        branches_chirho.insert(name_chirho.to_string(), target_chirho);
    }
    // Families that must NEVER cross: a money-ish branch and a bare working branch.
    let foreign_chirho = store_chirho.put_chirho(b"ledger head stone").unwrap();
    branches_chirho.insert("ledger/main".to_string(), foreign_chirho.clone());
    branches_chirho.insert("main".to_string(), foreign_chirho);
    save_refs_chirho(
        source_root_chirho,
        &RefsChirho {
            branches_chirho: branches_chirho.clone(),
            tags_chirho: BTreeMap::new(),
            head_chirho: "main".to_string(),
        },
    )
    .unwrap();
    branches_chirho
}

/// Copy the snapshot stone + every app-family target object into a replica store (the real pull
/// path is covered by the localfs/http object-plane suites; here the mount logic is under test).
fn copy_closure_to_replica_chirho(
    source_root_chirho: &Path,
    replica_root_chirho: &Path,
    head_chirho: &RefSnapshotHeadRecordChirho,
) {
    let source_store_chirho = FsContentStoreChirho::new_chirho(source_root_chirho);
    let replica_store_chirho = FsContentStoreChirho::new_chirho(replica_root_chirho);
    let stone_bytes_chirho = source_store_chirho
        .get_chirho(&head_chirho.snapshot_hash_chirho)
        .unwrap()
        .unwrap();
    let snapshot_chirho: RefSnapshotChirho = serde_json::from_slice(&stone_bytes_chirho).unwrap();
    for target_chirho in snapshot_chirho.refs_chirho.values() {
        let bytes_chirho = source_store_chirho
            .get_chirho(target_chirho)
            .unwrap()
            .unwrap();
        replica_store_chirho.put_chirho(&bytes_chirho).unwrap();
    }
    replica_store_chirho
        .put_chirho(&stone_bytes_chirho)
        .unwrap();
}

fn source_log_bytes_chirho(source_root_chirho: &Path) -> Vec<u8> {
    std::fs::read(source_root_chirho.join(REF_SNAPSHOT_LOG_FILE_CHIRHO)).unwrap()
}

#[test]
fn snapshot_ref_name_matrix_chirho() {
    for good_chirho in ["app/contact", "app/x1", "app-route/contact/submit"] {
        assert!(is_snapshot_ref_name_chirho(good_chirho), "{good_chirho}");
    }
    for bad_chirho in [
        "app/",
        "app//x",
        "app/x/y",
        "app-route/x",
        "app-route/x/",
        "app-route//y",
        "app-route/x/y/z",
        "ledger/main",
        "main",
        "HEAD",
        "gate1-authority-mode",
        "app/..",
        "app/with space",
    ] {
        assert!(!is_snapshot_ref_name_chirho(bad_chirho), "{bad_chirho}");
    }
    // The new log name is allowlisted; the signing key and refs file names stay refused.
    assert!(is_replicable_log_name_chirho(REF_SNAPSHOT_LOG_FILE_CHIRHO));
    assert!(!is_replicable_log_name_chirho("signing-key-chirho.bin"));
    assert!(!is_replicable_log_name_chirho("refs-chirho.json"));
}

#[test]
fn export_selects_only_app_families_signs_and_is_idempotent_chirho() {
    let source_root_chirho = tmp_root_chirho("export");
    seed_source_chirho(
        &source_root_chirho,
        &["app/contact", "app-route/contact/submit"],
    );
    let export_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    assert!(export_chirho.appended_chirho);
    assert_eq!(export_chirho.head_chirho.seq_chirho, 1);
    assert_eq!(export_chirho.head_chirho.ref_count_chirho, 2);
    assert_eq!(
        export_chirho.head_chirho.key_id_chirho,
        pubkey_hex_chirho(&source_root_chirho).unwrap()
    );
    validate_ref_snapshot_head_chirho(&export_chirho.head_chirho).unwrap();
    // The stone carries ONLY the app families (the ledger/main + main branches were refused).
    let store_chirho = FsContentStoreChirho::new_chirho(&source_root_chirho);
    let stone_chirho: RefSnapshotChirho = serde_json::from_slice(
        &store_chirho
            .get_chirho(&export_chirho.head_chirho.snapshot_hash_chirho)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let names_chirho: Vec<&str> = stone_chirho
        .refs_chirho
        .keys()
        .map(|name_chirho| name_chirho.as_str())
        .collect();
    assert_eq!(
        names_chirho,
        vec!["app-route/contact/submit", "app/contact"]
    );
    // Idempotent re-export: unchanged refs mint no seq and append no row.
    let again_chirho = export_ref_snapshot_chirho(&source_root_chirho, 2_000).unwrap();
    assert!(!again_chirho.appended_chirho);
    assert_eq!(again_chirho.head_chirho, export_chirho.head_chirho);
    let heads_chirho = read_verified_snapshot_heads_chirho(
        &source_log_bytes_chirho(&source_root_chirho),
        &export_chirho.head_chirho.key_id_chirho,
    )
    .unwrap();
    assert_eq!(heads_chirho.len(), 1);
}

#[test]
fn export_mints_next_seq_on_changed_refs_chirho() {
    let source_root_chirho = tmp_root_chirho("export-next");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let first_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    seed_source_chirho(
        &source_root_chirho,
        &["app/contact", "app-route/contact/list"],
    );
    let second_chirho = export_ref_snapshot_chirho(&source_root_chirho, 2_000).unwrap();
    assert!(second_chirho.appended_chirho);
    assert_eq!(second_chirho.head_chirho.seq_chirho, 2);
    assert_ne!(
        first_chirho.head_chirho.refs_digest_chirho,
        second_chirho.head_chirho.refs_digest_chirho
    );
}

#[test]
fn replica_mounts_fresh_then_remounts_idempotently_after_restart_chirho() {
    let source_root_chirho = tmp_root_chirho("mount-src");
    seed_source_chirho(
        &source_root_chirho,
        &["app/contact", "app-route/contact/submit"],
    );
    let export_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let replica_root_chirho = tmp_root_chirho("mount-replica");
    copy_closure_to_replica_chirho(
        &source_root_chirho,
        &replica_root_chirho,
        &export_chirho.head_chirho,
    );
    let replica_store_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let log_chirho = source_log_bytes_chirho(&source_root_chirho);
    let pinned_chirho = export_chirho.head_chirho.key_id_chirho.clone();

    let (view_chirho, report_chirho) = mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &log_chirho,
        &pinned_chirho,
        7_777,
    )
    .unwrap();
    assert_eq!(
        report_chirho.decision_chirho,
        FloorDecisionChirho::FreshMountChirho
    );
    assert_eq!(report_chirho.seq_chirho, 1);
    assert_eq!(report_chirho.source_time_unix_chirho, 1_000);
    assert_eq!(report_chirho.verified_at_unix_chirho, 7_777);
    assert!(view_chirho.ref_hash_chirho("app/contact").is_some());
    assert!(view_chirho.ref_hash_chirho("ledger/main").is_none());
    let floor_chirho = read_ref_snapshot_floor_chirho(&replica_root_chirho)
        .unwrap()
        .expect("floor persisted after fresh mount");
    assert_eq!(floor_chirho.seq_chirho, 1);

    // A2 regression 1 (restart-replay): a restarted replica re-reads floor {seq 1, stone X} and
    // the newest row is STILL seq 1 stone X — it must re-mount and serve, not brick.
    let (view2_chirho, report2_chirho) = mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &log_chirho,
        &pinned_chirho,
        8_888,
    )
    .unwrap();
    assert_eq!(
        report2_chirho.decision_chirho,
        FloorDecisionChirho::IdempotentRemountChirho
    );
    assert_eq!(
        view2_chirho.ref_hash_chirho("app/contact"),
        view_chirho.ref_hash_chirho("app/contact")
    );
}

/// Craft a validly-signed head row for an arbitrary stone (the equivocation/tamper tool).
fn signed_head_for_stone_chirho(
    source_root_chirho: &Path,
    stone_chirho: &RefSnapshotChirho,
    stone_hash_chirho: HashChirho,
) -> RefSnapshotHeadRecordChirho {
    let mut head_chirho = RefSnapshotHeadRecordChirho {
        schema_chirho: REF_SNAPSHOT_HEAD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: stone_chirho.seq_chirho,
        source_time_unix_chirho: stone_chirho.source_time_unix_chirho,
        snapshot_hash_chirho: stone_hash_chirho,
        refs_digest_chirho: stone_chirho.refs_digest_chirho().unwrap(),
        ref_count_chirho: stone_chirho.refs_chirho.len() as u64,
        key_id_chirho: pubkey_hex_chirho(source_root_chirho).unwrap(),
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_ref_snapshot_head_message_chirho(&head_chirho).unwrap();
    head_chirho.sig_chirho = sign_message_chirho(source_root_chirho, &message_chirho).unwrap();
    head_chirho
}

#[test]
fn equivocation_at_the_floor_fails_loudly_naming_both_stones_chirho() {
    let source_root_chirho = tmp_root_chirho("equiv-src");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let export_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let replica_root_chirho = tmp_root_chirho("equiv-replica");
    copy_closure_to_replica_chirho(
        &source_root_chirho,
        &replica_root_chirho,
        &export_chirho.head_chirho,
    );
    let replica_store_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let pinned_chirho = export_chirho.head_chirho.key_id_chirho.clone();
    mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &source_log_bytes_chirho(&source_root_chirho),
        &pinned_chirho,
        7_777,
    )
    .unwrap();

    // A2 regression 2: the same source key signs a DIFFERENT stone at the SAME seq — a restarted
    // replica offered that log must refuse LOUDLY, naming both stone hashes as evidence.
    let source_store_chirho = FsContentStoreChirho::new_chirho(&source_root_chirho);
    let other_target_chirho = source_store_chirho
        .put_chirho(b"a different target")
        .unwrap();
    let mut other_refs_chirho = BTreeMap::new();
    other_refs_chirho.insert("app/contact".to_string(), other_target_chirho.clone());
    let other_stone_chirho = RefSnapshotChirho::new_chirho(other_refs_chirho, 1, 1_500).unwrap();
    let other_bytes_chirho = other_stone_chirho.canonical_bytes_chirho().unwrap();
    let other_hash_chirho = replica_store_chirho
        .put_chirho(&other_bytes_chirho)
        .unwrap();
    replica_store_chirho
        .put_chirho(
            &source_store_chirho
                .get_chirho(&other_target_chirho)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    let equivocating_head_chirho = signed_head_for_stone_chirho(
        &source_root_chirho,
        &other_stone_chirho,
        other_hash_chirho.clone(),
    );
    let forged_log_chirho = serde_json::to_vec(&equivocating_head_chirho).unwrap();
    let message_chirho = mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &forged_log_chirho,
        &pinned_chirho,
        9_999,
    )
    .unwrap_err()
    .to_string();
    assert!(message_chirho.contains("EQUIVOCATION"), "{message_chirho}");
    assert!(
        message_chirho.contains(&export_chirho.head_chirho.snapshot_hash_chirho.0),
        "{message_chirho}"
    );
    assert!(
        message_chirho.contains(&other_hash_chirho.0),
        "{message_chirho}"
    );
}

#[test]
fn stale_head_below_the_floor_is_rollback_chirho() {
    let source_root_chirho = tmp_root_chirho("stale-src");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let first_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let first_log_chirho = source_log_bytes_chirho(&source_root_chirho);
    seed_source_chirho(
        &source_root_chirho,
        &["app/contact", "app-route/contact/list"],
    );
    let second_chirho = export_ref_snapshot_chirho(&source_root_chirho, 2_000).unwrap();
    let replica_root_chirho = tmp_root_chirho("stale-replica");
    copy_closure_to_replica_chirho(
        &source_root_chirho,
        &replica_root_chirho,
        &first_chirho.head_chirho,
    );
    copy_closure_to_replica_chirho(
        &source_root_chirho,
        &replica_root_chirho,
        &second_chirho.head_chirho,
    );
    let replica_store_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let pinned_chirho = second_chirho.head_chirho.key_id_chirho.clone();
    mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &source_log_bytes_chirho(&source_root_chirho),
        &pinned_chirho,
        7_777,
    )
    .unwrap();
    // Now the replica is at floor seq 2; a truncated log whose newest row is seq 1 must refuse.
    let message_chirho = mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &first_log_chirho,
        &pinned_chirho,
        9_999,
    )
    .unwrap_err()
    .to_string();
    assert!(
        message_chirho.contains("stale-head rollback"),
        "{message_chirho}"
    );
}

#[test]
fn log_verification_fails_closed_on_forgery_and_disorder_chirho() {
    let source_root_chirho = tmp_root_chirho("log-src");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let export_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let pinned_chirho = export_chirho.head_chirho.key_id_chirho.clone();
    let good_row_chirho = source_log_bytes_chirho(&source_root_chirho);

    // Forged signature: flip the last hex digit of the sig.
    let mut forged_chirho: RefSnapshotHeadRecordChirho =
        serde_json::from_slice(&good_row_chirho).unwrap();
    let mut sig_chirho = forged_chirho.sig_chirho.clone();
    let last_chirho = if sig_chirho.pop() == Some('0') {
        '1'
    } else {
        '0'
    };
    sig_chirho.push(last_chirho);
    forged_chirho.sig_chirho = sig_chirho;
    let forged_log_chirho = serde_json::to_vec(&forged_chirho).unwrap();
    assert!(
        read_verified_snapshot_heads_chirho(&forged_log_chirho, &pinned_chirho)
            .unwrap_err()
            .to_string()
            .contains("signature is invalid"),
    );

    // Foreign key id (a different root's key signs a row): refused by the pin.
    let other_root_chirho = tmp_root_chirho("other-signer");
    let stone_chirho = RefSnapshotChirho::new_chirho(
        BTreeMap::from([("app/contact".to_string(), hash_chirho(b"any target"))]),
        1,
        1_000,
    )
    .unwrap();
    let other_head_chirho = signed_head_for_stone_chirho(
        &other_root_chirho,
        &stone_chirho,
        hash_chirho(&stone_chirho.canonical_bytes_chirho().unwrap()),
    );
    let other_log_chirho = serde_json::to_vec(&other_head_chirho).unwrap();
    assert!(
        read_verified_snapshot_heads_chirho(&other_log_chirho, &pinned_chirho)
            .unwrap_err()
            .to_string()
            .contains("does not match the pinned source key"),
    );

    // Malformed middle row fails the WHOLE log closed (no display-lenience here).
    let mut two_rows_chirho = good_row_chirho.clone();
    two_rows_chirho.extend_from_slice(b"{not json}\n");
    assert!(read_verified_snapshot_heads_chirho(&two_rows_chirho, &pinned_chirho).is_err());

    // Backwards / duplicate seq: replay the same row twice -> duplicate export row error.
    let mut doubled_chirho = good_row_chirho.clone();
    doubled_chirho.extend_from_slice(&good_row_chirho);
    assert!(
        read_verified_snapshot_heads_chirho(&doubled_chirho, &pinned_chirho)
            .unwrap_err()
            .to_string()
            .contains("repeats seq"),
    );
}

#[test]
fn mount_binds_stone_to_head_and_requires_the_closure_chirho() {
    let source_root_chirho = tmp_root_chirho("bind-src");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let export_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let replica_root_chirho = tmp_root_chirho("bind-replica");
    let replica_store_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);

    // Stone absent from the replica store: mount refuses (pull it first).
    let message_chirho =
        mount_ref_snapshot_chirho(&replica_store_chirho, &export_chirho.head_chirho)
            .unwrap_err()
            .to_string();
    assert!(
        message_chirho.contains("not in the replica store"),
        "{message_chirho}"
    );

    // Stone present but a ref target missing: the closure check refuses the mount.
    let source_store_chirho = FsContentStoreChirho::new_chirho(&source_root_chirho);
    let stone_bytes_chirho = source_store_chirho
        .get_chirho(&export_chirho.head_chirho.snapshot_hash_chirho)
        .unwrap()
        .unwrap();
    replica_store_chirho
        .put_chirho(&stone_bytes_chirho)
        .unwrap();
    let message_chirho =
        mount_ref_snapshot_chirho(&replica_store_chirho, &export_chirho.head_chirho)
            .unwrap_err()
            .to_string();
    assert!(
        message_chirho.contains("closure object missing"),
        "{message_chirho}"
    );

    // A head whose seq disagrees with the stone it names: binding refuses.
    copy_closure_to_replica_chirho(
        &source_root_chirho,
        &replica_root_chirho,
        &export_chirho.head_chirho,
    );
    let mut rebound_chirho = export_chirho.head_chirho.clone();
    rebound_chirho.seq_chirho = 9;
    let message_chirho = unsigned_ref_snapshot_head_message_chirho(&rebound_chirho).unwrap();
    rebound_chirho.sig_chirho = sign_message_chirho(&source_root_chirho, &message_chirho).unwrap();
    let rendered_chirho = mount_ref_snapshot_chirho(&replica_store_chirho, &rebound_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        rendered_chirho.contains("does not match the signed head seq"),
        "{rendered_chirho}"
    );

    // A smuggled foreign ref name inside a hand-built stone: mount validation refuses it.
    let smuggled_json_chirho = format!(
        "{{\"schema_chirho\":\"ref-snapshot-v1-chirho\",\"seq_chirho\":1,\
         \"source_time_unix_chirho\":1000,\"refs_chirho\":{{\"ledger/main\":\"{}\"}}}}",
        "a".repeat(64)
    );
    let smuggled_hash_chirho = replica_store_chirho
        .put_chirho(smuggled_json_chirho.as_bytes())
        .unwrap();
    let smuggled_stone_chirho: RefSnapshotChirho =
        serde_json::from_str(&smuggled_json_chirho).unwrap();
    let smuggled_head_chirho = signed_head_for_stone_chirho(
        &source_root_chirho,
        &smuggled_stone_chirho,
        smuggled_hash_chirho,
    );
    let rendered_chirho = mount_ref_snapshot_chirho(&replica_store_chirho, &smuggled_head_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        rendered_chirho.contains("non-app/app-route ref name"),
        "{rendered_chirho}"
    );

    // And the constructor refuses the same name at EXPORT side (both ends fail closed).
    assert!(RefSnapshotChirho::new_chirho(
        BTreeMap::from([("ledger/main".to_string(), hash_chirho(b"x"))]),
        1,
        1_000
    )
    .is_err());

    // Floor decision unit coverage for the rollback arm (mount-level tests cover the rest).
    let floor_chirho = cairn_replication_chirho::ref_snapshot_chirho::RefSnapshotFloorChirho {
        schema_chirho: "ref-snapshot-floor-v1-chirho".to_string(),
        seq_chirho: 5,
        snapshot_hash_chirho: export_chirho.head_chirho.snapshot_hash_chirho.clone(),
    };
    let mut low_chirho = export_chirho.head_chirho.clone();
    low_chirho.seq_chirho = 4;
    assert!(check_head_against_floor_chirho(&low_chirho, Some(&floor_chirho)).is_err());
    assert_eq!(
        check_head_against_floor_chirho(&export_chirho.head_chirho, None).unwrap(),
        FloorDecisionChirho::FreshMountChirho
    );
}

/// B2.1 audit follow-up M1: the allowlist's EXACT membership is pinned — the Gate 1 anchor log,
/// the eight surviving Ring-A family logs, and the ref-snapshot log, ten distinct names and
/// nothing else.
/// A name silently ADDED to `is_replicable_log_name_chirho` (the audit's green mutant was
/// `pubkey-chirho.hex`) must die here, not ride out on an unchanged suite.
#[test]
fn replicable_log_allowlist_membership_is_exact_chirho() {
    let mut expected_chirho: BTreeSet<&str> = BTreeSet::new();
    expected_chirho.insert(GATE1_LOG_ANCHORS_FILE_CHIRHO);
    expected_chirho.extend(GATE1_RING_A_ANCHOR_TARGETS_CHIRHO);
    expected_chirho.insert(REF_SNAPSHOT_LOG_FILE_CHIRHO);
    assert_eq!(
        expected_chirho.len(),
        10,
        "the documented allowlist is anchor + eight Ring-A + ref-snapshot = 10 distinct names; a \
         membership change must be a conscious, audited edit HERE as well as in the fn"
    );
    for name_chirho in &expected_chirho {
        assert!(
            is_replicable_log_name_chirho(name_chirho),
            "allowlisted name refused: {name_chirho}"
        );
    }
    // Names that must NEVER replicate: key material, refs, replica-local floors, private-blob
    // key stores — plus exact-match discipline (no path forms, case variants, or suffixes).
    let anchor_upper_chirho = GATE1_LOG_ANCHORS_FILE_CHIRHO.to_ascii_uppercase();
    let snapshot_dotted_chirho = format!("./{REF_SNAPSHOT_LOG_FILE_CHIRHO}");
    let snapshot_suffixed_chirho = format!("{REF_SNAPSHOT_LOG_FILE_CHIRHO}.bak");
    let forbidden_chirho: [&str; 12] = [
        "pubkey-chirho.hex",
        "signing-key-chirho.bin",
        "refs-chirho.json",
        "reflog-chirho.jsonl",
        "ref-snapshot-floor-chirho.json",
        "replica-sync-floor-chirho.json",
        "private-blob-keys-chirho.jsonl",
        "runseals-chirho",
        "",
        anchor_upper_chirho.as_str(),
        snapshot_dotted_chirho.as_str(),
        snapshot_suffixed_chirho.as_str(),
    ];
    for name_chirho in forbidden_chirho {
        assert!(
            !expected_chirho.contains(name_chirho),
            "test battery collides with a real allowlisted name: {name_chirho}"
        );
        assert!(
            !is_replicable_log_name_chirho(name_chirho),
            "forbidden name accepted by the allowlist: {name_chirho:?}"
        );
    }
}

/// B2.1 audit follow-up M10 (pre-commitment b): the durable floor is raised ONLY after the full
/// mount verified. A mount that fails AFTER the floor check passes must leave the floor exactly
/// as it was — absent on a failed first mount, and at the old `{seq, stone}` when a newer valid
/// head's closure was never pulled. Reordering raise-before-mount dies here.
#[test]
fn mount_failure_after_the_floor_check_leaves_the_floor_unchanged_chirho() {
    let source_root_chirho = tmp_root_chirho("floor-order-src");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let first_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let replica_root_chirho = tmp_root_chirho("floor-order-replica");
    let replica_store_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let pinned_chirho = first_chirho.head_chirho.key_id_chirho.clone();

    // Failed FIRST mount (stone never pulled): no floor may be minted.
    let message_chirho = mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &source_log_bytes_chirho(&source_root_chirho),
        &pinned_chirho,
        7_777,
    )
    .unwrap_err()
    .to_string();
    assert!(
        message_chirho.contains("not in the replica store"),
        "{message_chirho}"
    );
    assert!(
        read_ref_snapshot_floor_chirho(&replica_root_chirho)
            .unwrap()
            .is_none(),
        "a failed first mount must not mint a floor"
    );

    // Real mount at seq 1 raises the floor…
    copy_closure_to_replica_chirho(
        &source_root_chirho,
        &replica_root_chirho,
        &first_chirho.head_chirho,
    );
    mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &source_log_bytes_chirho(&source_root_chirho),
        &pinned_chirho,
        7_778,
    )
    .unwrap();

    // …then seq 2 exports but its stone is NEVER pulled: row verify and the floor check both
    // pass (seq 2 > floor 1), the mount fails on the missing stone, and the durable floor must
    // still read {seq 1, first stone} — not 2, not corrupt, not gone.
    seed_source_chirho(
        &source_root_chirho,
        &["app/contact", "app-route/contact/list"],
    );
    let second_chirho = export_ref_snapshot_chirho(&source_root_chirho, 2_000).unwrap();
    assert_eq!(second_chirho.head_chirho.seq_chirho, 2);
    let message_chirho = mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &source_log_bytes_chirho(&source_root_chirho),
        &pinned_chirho,
        9_999,
    )
    .unwrap_err()
    .to_string();
    assert!(
        message_chirho.contains("not in the replica store"),
        "{message_chirho}"
    );
    let floor_chirho = read_ref_snapshot_floor_chirho(&replica_root_chirho)
        .unwrap()
        .expect("the seq-1 floor must survive the failed seq-2 mount");
    assert_eq!(floor_chirho.seq_chirho, 1);
    assert_eq!(
        floor_chirho.snapshot_hash_chirho,
        first_chirho.head_chirho.snapshot_hash_chirho
    );
}

/// B2.1 audit follow-up M5: a validly-SIGNED head whose `refs_digest` disagrees with the stone it
/// names is refused at mount. On a verifying store this is defense-in-depth; the module is
/// generic over `C: ContentStoreChirho`, so on a non-verifying adapter this binding is the ONLY
/// thing tying the served refs to what the source signed.
#[test]
fn mount_refuses_a_signed_head_whose_refs_digest_mismatches_the_stone_chirho() {
    let source_root_chirho = tmp_root_chirho("digest-bind-src");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let export_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let replica_root_chirho = tmp_root_chirho("digest-bind-replica");
    copy_closure_to_replica_chirho(
        &source_root_chirho,
        &replica_root_chirho,
        &export_chirho.head_chirho,
    );
    let replica_store_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let pinned_chirho = export_chirho.head_chirho.key_id_chirho.clone();

    let mut lying_head_chirho = export_chirho.head_chirho.clone();
    lying_head_chirho.refs_digest_chirho = hash_chirho(b"a different refs map entirely");
    let message_bytes_chirho =
        unsigned_ref_snapshot_head_message_chirho(&lying_head_chirho).unwrap();
    lying_head_chirho.sig_chirho =
        sign_message_chirho(&source_root_chirho, &message_bytes_chirho).unwrap();
    let mut lying_log_chirho = serde_json::to_vec(&lying_head_chirho).unwrap();
    lying_log_chirho.push(b'\n');

    let message_chirho = mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &lying_log_chirho,
        &pinned_chirho,
        7_777,
    )
    .unwrap_err()
    .to_string();
    assert!(
        message_chirho.contains("refs digest does not match the signed head"),
        "{message_chirho}"
    );
    assert!(
        read_ref_snapshot_floor_chirho(&replica_root_chirho)
            .unwrap()
            .is_none(),
        "a refused mount must not mint a floor"
    );
}

/// B2.1 audit follow-up M6: same binding, `ref_count` leg — a validly-signed head whose count
/// disagrees with the stone is refused, and no floor is minted.
#[test]
fn mount_refuses_a_signed_head_whose_ref_count_mismatches_the_stone_chirho() {
    let source_root_chirho = tmp_root_chirho("count-bind-src");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let export_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let replica_root_chirho = tmp_root_chirho("count-bind-replica");
    copy_closure_to_replica_chirho(
        &source_root_chirho,
        &replica_root_chirho,
        &export_chirho.head_chirho,
    );
    let replica_store_chirho = FsContentStoreChirho::new_chirho(&replica_root_chirho);
    let pinned_chirho = export_chirho.head_chirho.key_id_chirho.clone();

    let mut lying_head_chirho = export_chirho.head_chirho.clone();
    lying_head_chirho.ref_count_chirho = 41;
    let message_bytes_chirho =
        unsigned_ref_snapshot_head_message_chirho(&lying_head_chirho).unwrap();
    lying_head_chirho.sig_chirho =
        sign_message_chirho(&source_root_chirho, &message_bytes_chirho).unwrap();
    let mut lying_log_chirho = serde_json::to_vec(&lying_head_chirho).unwrap();
    lying_log_chirho.push(b'\n');

    let message_chirho = mount_latest_verified_snapshot_chirho(
        &replica_store_chirho,
        &replica_root_chirho,
        &lying_log_chirho,
        &pinned_chirho,
        7_777,
    )
    .unwrap_err()
    .to_string();
    assert!(
        message_chirho.contains("ref count does not match the signed head"),
        "{message_chirho}"
    );
    assert!(
        read_ref_snapshot_floor_chirho(&replica_root_chirho)
            .unwrap()
            .is_none(),
        "a refused mount must not mint a floor"
    );
}

/// B2.1 audit follow-up M13: equivocation INSIDE one log (two validly-signed rows at one seq for
/// two different stones) fails loudly naming BOTH stone hashes — the specific evidence-bearing
/// branch, not the generic duplicate-row bail, which names neither.
#[test]
fn equivocation_inside_one_log_fails_loudly_naming_both_stones_chirho() {
    let source_root_chirho = tmp_root_chirho("inlog-equiv-src");
    seed_source_chirho(&source_root_chirho, &["app/contact"]);
    let export_chirho = export_ref_snapshot_chirho(&source_root_chirho, 1_000).unwrap();
    let pinned_chirho = export_chirho.head_chirho.key_id_chirho.clone();

    let other_stone_chirho = RefSnapshotChirho::new_chirho(
        BTreeMap::from([("app/other".to_string(), hash_chirho(b"another target"))]),
        1,
        1_500,
    )
    .unwrap();
    let other_hash_chirho = hash_chirho(&other_stone_chirho.canonical_bytes_chirho().unwrap());
    let other_head_chirho = signed_head_for_stone_chirho(
        &source_root_chirho,
        &other_stone_chirho,
        other_hash_chirho.clone(),
    );
    let mut log_chirho = source_log_bytes_chirho(&source_root_chirho);
    log_chirho.extend_from_slice(&serde_json::to_vec(&other_head_chirho).unwrap());
    log_chirho.push(b'\n');

    let message_chirho = read_verified_snapshot_heads_chirho(&log_chirho, &pinned_chirho)
        .unwrap_err()
        .to_string();
    assert!(message_chirho.contains("EQUIVOCATION"), "{message_chirho}");
    assert!(
        message_chirho.contains(&export_chirho.head_chirho.snapshot_hash_chirho.0),
        "{message_chirho}"
    );
    assert!(
        message_chirho.contains(&other_hash_chirho.0),
        "{message_chirho}"
    );
}
