// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::temp_root_chirho;
use crate::storage_chirho::{
    FsLedgerStorageChirho, FsMonitorEvidenceSinkChirho, HostLedgerStorageRefusalChirho,
    StableLedgerNamespaceSnapshotChirho, STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_seqlog_chirho::seqlog_chirho::{named_lock_storage_key_chirho, with_named_lock_chirho};
use cairn_writer_head_chirho::writer_head_chirho::WRITER_FENCE_LOCK_CHIRHO;
use std::fs;

#[cfg(unix)]
fn prepare_mutable_target_chirho(
    root_chirho: &std::path::Path,
    bytes_chirho: &[u8],
) -> std::path::PathBuf {
    let journals_chirho = root_chirho.join("journals-chirho");
    fs::create_dir_all(&journals_chirho).unwrap();
    let target_chirho = journals_chirho.join("active-chirho.jsonl");
    fs::write(&target_chirho, bytes_chirho).unwrap();
    target_chirho
}

#[cfg(unix)]
fn active_coordinate_chirho() -> StoragePathChirho {
    StoragePathChirho::new_chirho("journals-chirho/active-chirho.jsonl")
}

#[cfg(all(unix, not(target_os = "solaris")))]
fn provision_writer_lock_chirho(root_chirho: &std::path::Path) {
    with_named_lock_chirho(
        root_chirho,
        WRITER_FENCE_LOCK_CHIRHO,
        || -> anyhow::Result<()> { Ok(()) },
    )
    .unwrap();
}

#[cfg(all(unix, not(target_os = "solaris")))]
fn writer_lock_coordinate_chirho() -> StoragePathChirho {
    StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO))
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn descriptor_lock_provisioning_is_empty_idempotent_and_fail_closed_chirho() {
    let fixture_root_chirho = temp_root_chirho("descriptor-lock-provision");
    fs::create_dir_all(&fixture_root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&fixture_root_chirho).unwrap();
    let coordinate_chirho = writer_lock_coordinate_chirho();
    let first_handle_chirho = storage_chirho
        .provision_exclusive_lock_handle_chirho(&coordinate_chirho)
        .unwrap();
    let second_handle_chirho = storage_chirho
        .provision_exclusive_lock_handle_chirho(&coordinate_chirho)
        .unwrap();
    let lock_path_chirho = fixture_root_chirho.join(coordinate_chirho.key_chirho());
    assert_eq!(fs::metadata(&lock_path_chirho).unwrap().len(), 0);
    drop(first_handle_chirho);
    drop(second_handle_chirho);

    fs::write(&lock_path_chirho, b"not-a-lock-marker-chirho").unwrap();
    let nonempty_error_chirho = storage_chirho
        .provision_exclusive_lock_handle_chirho(&coordinate_chirho)
        .unwrap_err();
    assert_eq!(
        nonempty_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho)
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn descriptor_lock_provisioning_stays_on_the_retained_root_inode_chirho() {
    let fixture_root_chirho = temp_root_chirho("descriptor-lock-provision-replacement");
    let original_root_chirho = fixture_root_chirho.join("ledger-root-chirho");
    let parked_root_chirho = fixture_root_chirho.join("parked-root-chirho");
    fs::create_dir_all(&original_root_chirho).unwrap();
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&original_root_chirho).unwrap();
    fs::rename(&original_root_chirho, &parked_root_chirho).unwrap();
    fs::create_dir(&original_root_chirho).unwrap();

    let coordinate_chirho = writer_lock_coordinate_chirho();
    let _handle_chirho = storage_chirho
        .provision_exclusive_lock_handle_chirho(&coordinate_chirho)
        .unwrap();
    assert_eq!(
        fs::metadata(parked_root_chirho.join(coordinate_chirho.key_chirho()))
            .unwrap()
            .len(),
        0
    );
    assert!(!original_root_chirho
        .join(coordinate_chirho.key_chirho())
        .exists());
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn descriptor_and_legacy_named_locks_exclude_each_other_both_directions_chirho() {
    use std::sync::mpsc;
    use std::time::Duration;

    let fixture_root_chirho = temp_root_chirho("descriptor-lock-interoperability");
    fs::create_dir_all(&fixture_root_chirho).unwrap();
    provision_writer_lock_chirho(&fixture_root_chirho);
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&fixture_root_chirho).unwrap();
    let mut handle_chirho = storage_chirho
        .open_existing_exclusive_lock_handle_chirho(&writer_lock_coordinate_chirho())
        .unwrap();

    let legacy_root_chirho = fixture_root_chirho.clone();
    let (legacy_held_sender_chirho, legacy_held_receiver_chirho) = mpsc::channel();
    let (legacy_release_sender_chirho, legacy_release_receiver_chirho) = mpsc::channel();
    let legacy_thread_chirho = std::thread::spawn(move || {
        with_named_lock_chirho(
            &legacy_root_chirho,
            WRITER_FENCE_LOCK_CHIRHO,
            || -> anyhow::Result<()> {
                legacy_held_sender_chirho.send(()).unwrap();
                legacy_release_receiver_chirho.recv().unwrap();
                Ok(())
            },
        )
        .unwrap();
    });
    legacy_held_receiver_chirho.recv().unwrap();
    let busy_error_chirho = handle_chirho.try_acquire_chirho().unwrap_err();
    assert_eq!(
        busy_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::ExclusiveLockBusyChirho)
    );
    legacy_release_sender_chirho.send(()).unwrap();
    legacy_thread_chirho.join().unwrap();

    let descriptor_guard_chirho = handle_chirho.try_acquire_chirho().unwrap();
    let second_root_chirho = fixture_root_chirho.clone();
    let (attempt_sender_chirho, attempt_receiver_chirho) = mpsc::channel();
    let (entered_sender_chirho, entered_receiver_chirho) = mpsc::channel();
    let second_legacy_thread_chirho = std::thread::spawn(move || {
        attempt_sender_chirho.send(()).unwrap();
        with_named_lock_chirho(
            &second_root_chirho,
            WRITER_FENCE_LOCK_CHIRHO,
            || -> anyhow::Result<()> {
                entered_sender_chirho.send(()).unwrap();
                Ok(())
            },
        )
        .unwrap();
    });
    attempt_receiver_chirho.recv().unwrap();
    assert!(entered_receiver_chirho
        .recv_timeout(Duration::from_millis(100))
        .is_err());
    drop(descriptor_guard_chirho);
    entered_receiver_chirho
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    second_legacy_thread_chirho.join().unwrap();
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn descriptor_lock_requires_preprovisioned_single_link_inode_and_detects_replacement_chirho() {
    use std::os::unix::fs::PermissionsExt;

    let fixture_root_chirho = temp_root_chirho("descriptor-lock-custody");
    fs::create_dir_all(&fixture_root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&fixture_root_chirho).unwrap();
    let coordinate_chirho = writer_lock_coordinate_chirho();
    let missing_error_chirho = storage_chirho
        .open_existing_exclusive_lock_handle_chirho(&coordinate_chirho)
        .unwrap_err();
    assert_eq!(
        missing_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::MissingObjectChirho)
    );

    provision_writer_lock_chirho(&fixture_root_chirho);
    let lock_path_chirho = fixture_root_chirho.join(coordinate_chirho.key_chirho());
    let alias_path_chirho = fixture_root_chirho.join("lock-alias-chirho");
    fs::hard_link(&lock_path_chirho, &alias_path_chirho).unwrap();
    let alias_error_chirho = storage_chirho
        .open_existing_exclusive_lock_handle_chirho(&coordinate_chirho)
        .unwrap_err();
    assert_eq!(
        alias_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::MutableTargetAliasedChirho)
    );
    fs::remove_file(alias_path_chirho).unwrap();

    let mut handle_chirho = storage_chirho
        .open_existing_exclusive_lock_handle_chirho(&coordinate_chirho)
        .unwrap();
    let parked_path_chirho = fixture_root_chirho.join("parked-lock-chirho");
    fs::rename(&lock_path_chirho, &parked_path_chirho).unwrap();
    fs::write(&lock_path_chirho, b"").unwrap();
    fs::set_permissions(&lock_path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
    let replacement_error_chirho = handle_chirho.try_acquire_chirho().unwrap_err();
    assert_eq!(
        replacement_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho)
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn descriptor_bounded_read_is_one_open_and_enforces_the_fixed_limit_chirho() {
    let fixture_root_chirho = temp_root_chirho("descriptor-bounded-read");
    fs::create_dir_all(&fixture_root_chirho).unwrap();
    fs::write(
        fixture_root_chirho.join("state-chirho.json"),
        b"complete-chirho",
    )
    .unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&fixture_root_chirho).unwrap();
    let coordinate_chirho = StoragePathChirho::new_chirho("state-chirho.json");
    assert_eq!(
        storage_chirho
            .read_bounded_object_chirho(&coordinate_chirho, 32)
            .unwrap(),
        Some(b"complete-chirho".to_vec())
    );
    let oversized_error_chirho = storage_chirho
        .read_bounded_object_chirho(&coordinate_chirho, 4)
        .unwrap_err();
    assert_eq!(
        oversized_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho)
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn descriptor_storage_keeps_all_primitives_on_the_opened_root_chirho() {
    let fixture_root_chirho = temp_root_chirho("descriptor-storage-root");
    let original_root_chirho = fixture_root_chirho.join("ledger-root-chirho");
    fs::create_dir_all(&original_root_chirho).unwrap();
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&original_root_chirho).unwrap();
    let cloned_storage_chirho = storage_chirho.clone();
    let snapshot_chirho = storage_chirho.stable_namespace_snapshot_chirho().unwrap();
    let opened_identity_chirho = snapshot_chirho.identity_chirho().unwrap();

    let moved_root_chirho = fixture_root_chirho.join("moved-ledger-root-chirho");
    fs::rename(&original_root_chirho, &moved_root_chirho).unwrap();
    fs::create_dir_all(&original_root_chirho).unwrap();

    let born_chirho = StoragePathChirho::new_chirho("journals-chirho/born-chirho.jsonl");
    assert_eq!(
        storage_chirho
            .create_durable_chirho(&born_chirho, b"genesis-chirho\n")
            .unwrap(),
        CreateDurableOutcomeChirho::CreatedChirho
    );
    assert_eq!(
        cloned_storage_chirho
            .create_durable_chirho(&born_chirho, b"foreign-chirho\n")
            .unwrap(),
        CreateDurableOutcomeChirho::AlreadyExistsChirho
    );

    let active_chirho = active_coordinate_chirho();
    storage_chirho
        .append_durable_chirho(&active_chirho, b"abcdef")
        .unwrap();
    assert_eq!(
        storage_chirho.object_len_chirho(&active_chirho).unwrap(),
        Some(6)
    );
    assert_eq!(
        cloned_storage_chirho
            .read_exact_range_chirho(&active_chirho, 1, 3)
            .unwrap(),
        b"bcd"
    );
    storage_chirho
        .atomic_write_chirho(&active_chirho, b"abcdefgh")
        .unwrap();
    storage_chirho
        .truncate_durable_chirho(&active_chirho, 4)
        .unwrap();
    assert_eq!(
        storage_chirho.read_all_chirho(&active_chirho).unwrap(),
        Some(b"abcd".to_vec())
    );

    let sealed_chirho = StoragePathChirho::new_chirho("sealed-chirho/segment-0001-chirho");
    storage_chirho
        .rename_chirho(&active_chirho, &sealed_chirho)
        .unwrap();
    assert!(!storage_chirho.exists_chirho(&active_chirho).unwrap());
    assert_eq!(
        storage_chirho
            .list_chirho(&StoragePathChirho::new_chirho("sealed-chirho/"))
            .unwrap(),
        vec![sealed_chirho.clone()]
    );
    storage_chirho.remove_chirho(&sealed_chirho).unwrap();
    storage_chirho.remove_chirho(&sealed_chirho).unwrap();
    assert!(!storage_chirho.exists_chirho(&sealed_chirho).unwrap());

    assert!(moved_root_chirho
        .join("journals-chirho/born-chirho.jsonl")
        .is_file());
    assert!(fs::read_dir(&original_root_chirho)
        .unwrap()
        .next()
        .is_none());
    assert_eq!(
        snapshot_chirho.identity_chirho().unwrap(),
        opened_identity_chirho
    );
    let replaced_path_error_chirho = snapshot_chirho
        .verify_current_path_chirho(&original_root_chirho)
        .unwrap_err();
    assert_eq!(
        replaced_path_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho)
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn descriptor_storage_tolerates_concurrent_parent_claim_chirho() {
    use std::sync::{Arc, Barrier};

    const WRITERS_CHIRHO: usize = 32;
    let fixture_root_chirho = temp_root_chirho("descriptor-concurrent-parent");
    fs::create_dir_all(&fixture_root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&fixture_root_chirho).unwrap();
    let barrier_chirho = Arc::new(Barrier::new(WRITERS_CHIRHO));
    let mut threads_chirho = Vec::with_capacity(WRITERS_CHIRHO);
    for writer_chirho in 0..WRITERS_CHIRHO {
        let storage_chirho = storage_chirho.clone();
        let barrier_chirho = Arc::clone(&barrier_chirho);
        threads_chirho.push(std::thread::spawn(move || {
            let path_chirho = StoragePathChirho::new_chirho(format!(
                "shared-chirho/nested-chirho/writer-{writer_chirho:02}-chirho.jsonl"
            ));
            barrier_chirho.wait();
            storage_chirho
                .append_durable_chirho(&path_chirho, b"one-chirho\n")
                .map(|()| path_chirho)
        }));
    }
    let mut written_chirho = threads_chirho
        .into_iter()
        .map(|thread_chirho| thread_chirho.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    written_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.key_chirho().cmp(right_chirho.key_chirho())
    });

    assert_eq!(
        storage_chirho
            .list_chirho(&StoragePathChirho::new_chirho(
                "shared-chirho/nested-chirho/"
            ))
            .unwrap(),
        written_chirho
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn descriptor_monitor_sink_keeps_evidence_on_the_opened_root_chirho() {
    let fixture_root_chirho = temp_root_chirho("descriptor-monitor-root");
    let ledger_root_chirho = fixture_root_chirho.join("ledger-chirho");
    let evidence_root_chirho = fixture_root_chirho.join("evidence-chirho");
    fs::create_dir_all(&ledger_root_chirho).unwrap();
    fs::create_dir_all(&evidence_root_chirho).unwrap();
    let ledger_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&ledger_root_chirho).unwrap();
    let evidence_sink_chirho = FsMonitorEvidenceSinkChirho::open_existing_disjoint_chirho(
        &ledger_storage_chirho,
        &evidence_root_chirho,
    )
    .unwrap();

    let moved_evidence_chirho = fixture_root_chirho.join("moved-evidence-chirho");
    fs::rename(&evidence_root_chirho, &moved_evidence_chirho).unwrap();
    fs::create_dir_all(&evidence_root_chirho).unwrap();
    evidence_sink_chirho
        .append_operational_row_chirho(
            "cycles-chirho/cycle-chirho.jsonl",
            br#"{"schema_chirho":"descriptor-monitor-v1-chirho"}"#,
        )
        .unwrap();

    assert_eq!(
        fs::read(moved_evidence_chirho.join("cycles-chirho/cycle-chirho.jsonl")).unwrap(),
        b"{\"schema_chirho\":\"descriptor-monitor-v1-chirho\"}\n"
    );
    assert!(fs::read_dir(&evidence_root_chirho)
        .unwrap()
        .next()
        .is_none());
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn descriptor_storage_lists_only_the_selected_prefix_subtree_chirho() {
    use std::os::unix::fs::symlink;

    let fixture_root_chirho = temp_root_chirho("descriptor-prefix-list");
    let namespace_root_chirho = fixture_root_chirho.join("ledger-root-chirho");
    fs::create_dir_all(namespace_root_chirho.join("sealed-chirho")).unwrap();
    fs::create_dir_all(namespace_root_chirho.join("unrelated-chirho")).unwrap();
    fs::write(
        namespace_root_chirho.join("sealed-chirho/segment-0001-chirho"),
        b"segment-chirho",
    )
    .unwrap();
    let outside_chirho = fixture_root_chirho.join("outside-chirho");
    fs::create_dir_all(&outside_chirho).unwrap();
    symlink(
        &outside_chirho,
        namespace_root_chirho.join("unrelated-chirho/hostile-link-chirho"),
    )
    .unwrap();
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&namespace_root_chirho).unwrap();

    assert_eq!(
        storage_chirho
            .list_chirho(&StoragePathChirho::new_chirho("sealed-chirho/"))
            .unwrap(),
        vec![StoragePathChirho::new_chirho(
            "sealed-chirho/segment-0001-chirho"
        )]
    );
    let unrelated_error_chirho = storage_chirho
        .list_chirho(&StoragePathChirho::new_chirho("unrelated-chirho/"))
        .unwrap_err();
    assert_eq!(
        unrelated_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho)
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn descriptor_storage_refuses_hardlink_aliases_before_mutation_chirho() {
    let fixture_root_chirho = temp_root_chirho("descriptor-hardlink");
    fs::create_dir_all(&fixture_root_chirho).unwrap();
    let target_path_chirho = fixture_root_chirho.join("active-chirho.jsonl");
    let alias_path_chirho = fixture_root_chirho.join("active-alias-chirho.jsonl");
    fs::write(&target_path_chirho, b"unchanged-chirho").unwrap();
    fs::hard_link(&target_path_chirho, &alias_path_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&fixture_root_chirho).unwrap();
    let coordinate_chirho = StoragePathChirho::new_chirho("active-chirho.jsonl");

    for error_chirho in [
        storage_chirho
            .append_durable_chirho(&coordinate_chirho, b"must-not-append-chirho")
            .unwrap_err(),
        storage_chirho
            .atomic_write_chirho(&coordinate_chirho, b"must-not-replace-chirho")
            .unwrap_err(),
    ] {
        assert_eq!(
            error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
            Some(&HostLedgerStorageRefusalChirho::MutableTargetAliasedChirho)
        );
    }
    assert_eq!(fs::read(&target_path_chirho).unwrap(), b"unchanged-chirho");
    assert_eq!(fs::read(&alias_path_chirho).unwrap(), b"unchanged-chirho");
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn stable_snapshot_survives_ancestor_rename_without_redirect_chirho() {
    let fixture_root_chirho = temp_root_chirho("stable-ancestor");
    let original_ancestor_chirho = fixture_root_chirho.join("original-ancestor-chirho");
    let original_root_chirho = original_ancestor_chirho.join("ledger-root-chirho");
    prepare_mutable_target_chirho(&original_root_chirho, b"resident-before-chirho");
    let snapshot_chirho =
        StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&original_root_chirho)
            .unwrap();

    let moved_ancestor_chirho = fixture_root_chirho.join("moved-ancestor-chirho");
    fs::rename(&original_ancestor_chirho, &moved_ancestor_chirho).unwrap();
    let replacement_target_chirho =
        prepare_mutable_target_chirho(&original_root_chirho, b"replacement-unchanged-chirho");

    let mut target_chirho = snapshot_chirho
        .open_mutable_target_chirho(&active_coordinate_chirho())
        .unwrap();
    assert_eq!(
        target_chirho.read_bounded_chirho().unwrap(),
        b"resident-before-chirho"
    );
    target_chirho
        .overwrite_bounded_chirho(b"resident-after-chirho")
        .unwrap();

    assert_eq!(
        fs::read(
            moved_ancestor_chirho.join("ledger-root-chirho/journals-chirho/active-chirho.jsonl")
        )
        .unwrap(),
        b"resident-after-chirho"
    );
    assert_eq!(
        fs::read(replacement_target_chirho).unwrap(),
        b"replacement-unchanged-chirho"
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn stable_snapshot_survives_root_rename_without_redirect_chirho() {
    let fixture_root_chirho = temp_root_chirho("stable-root");
    let original_root_chirho = fixture_root_chirho.join("ledger-root-chirho");
    prepare_mutable_target_chirho(&original_root_chirho, b"resident-before-chirho");
    let snapshot_chirho =
        StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&original_root_chirho)
            .unwrap();

    let moved_root_chirho = fixture_root_chirho.join("moved-root-chirho");
    fs::rename(&original_root_chirho, &moved_root_chirho).unwrap();
    let replacement_target_chirho =
        prepare_mutable_target_chirho(&original_root_chirho, b"replacement-unchanged-chirho");

    let mut target_chirho = snapshot_chirho
        .open_mutable_target_chirho(&active_coordinate_chirho())
        .unwrap();
    target_chirho
        .overwrite_bounded_chirho(b"resident-after-chirho")
        .unwrap();
    assert_eq!(
        fs::read(moved_root_chirho.join("journals-chirho/active-chirho.jsonl")).unwrap(),
        b"resident-after-chirho"
    );
    assert_eq!(
        fs::read(replacement_target_chirho).unwrap(),
        b"replacement-unchanged-chirho"
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn stable_target_refuses_hardlink_custody_before_mutation_chirho() {
    let fixture_root_chirho = temp_root_chirho("stable-hardlink");
    let target_path_chirho =
        prepare_mutable_target_chirho(&fixture_root_chirho, b"unchanged-chirho");
    let snapshot_chirho =
        StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&fixture_root_chirho).unwrap();
    let mut target_chirho = snapshot_chirho
        .open_mutable_target_chirho(&active_coordinate_chirho())
        .unwrap();
    let alias_path_chirho = fixture_root_chirho.join("hardlink-alias-chirho");
    fs::hard_link(&target_path_chirho, &alias_path_chirho).unwrap();

    let error_chirho = target_chirho
        .overwrite_bounded_chirho(b"must-not-land-chirho")
        .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::MutableTargetAliasedChirho)
    );
    assert_eq!(fs::read(&target_path_chirho).unwrap(), b"unchanged-chirho");
    assert_eq!(fs::read(alias_path_chirho).unwrap(), b"unchanged-chirho");
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn stable_snapshot_refuses_parent_and_leaf_symlinks_chirho() {
    use std::os::unix::fs::symlink;

    let fixture_root_chirho = temp_root_chirho("stable-symlinks");
    let namespace_root_chirho = fixture_root_chirho.join("ledger-root-chirho");
    fs::create_dir_all(&namespace_root_chirho).unwrap();
    let outside_root_chirho = fixture_root_chirho.join("outside-root-chirho");
    let outside_target_chirho =
        prepare_mutable_target_chirho(&outside_root_chirho, b"outside-unchanged-chirho");
    let snapshot_chirho =
        StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&namespace_root_chirho)
            .unwrap();

    symlink(
        outside_root_chirho.join("journals-chirho"),
        namespace_root_chirho.join("journals-chirho"),
    )
    .unwrap();
    let parent_error_chirho = snapshot_chirho
        .open_mutable_target_chirho(&active_coordinate_chirho())
        .unwrap_err();
    assert_eq!(
        parent_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho)
    );
    fs::remove_file(namespace_root_chirho.join("journals-chirho")).unwrap();
    fs::create_dir(namespace_root_chirho.join("journals-chirho")).unwrap();
    symlink(
        &outside_target_chirho,
        namespace_root_chirho.join("journals-chirho/active-chirho.jsonl"),
    )
    .unwrap();
    let leaf_error_chirho = snapshot_chirho
        .open_mutable_target_chirho(&active_coordinate_chirho())
        .unwrap_err();
    assert_eq!(
        leaf_error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho)
    );
    assert_eq!(
        fs::read(outside_target_chirho).unwrap(),
        b"outside-unchanged-chirho"
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn stable_target_refuses_replaced_directory_entry_without_mutation_chirho() {
    let fixture_root_chirho = temp_root_chirho("stable-entry-replacement");
    let target_path_chirho =
        prepare_mutable_target_chirho(&fixture_root_chirho, b"original-unchanged-chirho");
    let snapshot_chirho =
        StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&fixture_root_chirho).unwrap();
    let mut target_chirho = snapshot_chirho
        .open_mutable_target_chirho(&active_coordinate_chirho())
        .unwrap();
    let displaced_path_chirho =
        fixture_root_chirho.join("journals-chirho/displaced-original-chirho.jsonl");
    fs::rename(&target_path_chirho, &displaced_path_chirho).unwrap();
    fs::write(&target_path_chirho, b"replacement-unchanged-chirho").unwrap();

    let error_chirho = target_chirho
        .overwrite_bounded_chirho(b"must-not-land-chirho")
        .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::NamespaceIdentityChangedChirho)
    );
    assert_eq!(
        fs::read(displaced_path_chirho).unwrap(),
        b"original-unchanged-chirho"
    );
    assert_eq!(
        fs::read(target_path_chirho).unwrap(),
        b"replacement-unchanged-chirho"
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(unix)]
#[test]
fn stable_target_refuses_objects_above_fixed_read_bound_chirho() {
    let fixture_root_chirho = temp_root_chirho("stable-bound");
    prepare_mutable_target_chirho(
        &fixture_root_chirho,
        &vec![b'x'; STABLE_MUTABLE_TARGET_MAX_BYTES_CHIRHO + 1],
    );
    let snapshot_chirho =
        StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&fixture_root_chirho).unwrap();
    let error_chirho = snapshot_chirho
        .open_mutable_target_chirho(&active_coordinate_chirho())
        .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::ObjectExceedsBoundChirho)
    );
    let _ = fs::remove_dir_all(fixture_root_chirho);
}

#[cfg(not(unix))]
#[test]
fn stable_snapshot_refuses_non_unix_authority_chirho() {
    let root_chirho = temp_root_chirho("stable-non-unix");
    let error_chirho =
        StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&root_chirho).unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::UnsupportedAuthorityPlatformChirho)
    );
}
