// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use std::fs::{self, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CROSS_PROCESS_MATRIX_TEST_CHIRHO: &str =
    "cas_lifecycle_chirho::tests_chirho::separate_process_shared_matrix_chirho";
const EXTERNAL_EXCLUSIVE_PROBE_MARKER_CHIRHO: &str = "external-exclusive-probe-executed-chirho";

pub(super) fn temp_parent_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-lifecycle-{label_chirho}-{nanos_chirho}-{}-{counter_chirho}",
        std::process::id()
    ))
}

fn bootstrapped_root_chirho(label_chirho: &str) -> (PathBuf, CasLifecycleRootChirho) {
    let root_chirho = temp_parent_chirho(label_chirho);
    fs::create_dir_all(&root_chirho).unwrap();
    let lifecycle_chirho = bootstrap_cas_lifecycle_chirho(&root_chirho).unwrap();
    (root_chirho, lifecycle_chirho)
}

pub(super) fn object_path_chirho(root_chirho: &Path, address_hex_chirho: &str) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&address_hex_chirho[..2])
        .join(&address_hex_chirho[2..])
}

fn raw_anchor_chirho(root_chirho: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            root_chirho
                .join(CAS_LIFECYCLE_DIR_CHIRHO)
                .join(CAS_LIFECYCLE_ANCHOR_CHIRHO),
        )
        .unwrap()
}

fn run_external_exclusive_probe_chirho(
    root_chirho: &Path,
    expect_busy_chirho: bool,
) -> std::process::Output {
    let mut command_chirho = Command::new(std::env::current_exe().unwrap());
    command_chirho
        .arg("--exact")
        .arg(CROSS_PROCESS_MATRIX_TEST_CHIRHO)
        .arg("--nocapture")
        .env("CAIRN_CROSS_PROCESS_ROOT_CHIRHO", root_chirho)
        .env("CAIRN_CROSS_PROCESS_MODE_CHIRHO", "exclusive-probe-chirho");
    if expect_busy_chirho {
        command_chirho.env("CAIRN_EXPECT_BUSY_CHIRHO", "1");
    }
    let output_chirho = command_chirho.output().unwrap();
    assert!(
        String::from_utf8_lossy(&output_chirho.stdout)
            .contains(EXTERNAL_EXCLUSIVE_PROBE_MARKER_CHIRHO),
        "external EXCLUSIVE probe command did not execute its exact test: {output_chirho:?}"
    );
    output_chirho
}

fn wait_for_path_chirho(path_chirho: &Path, timeout_chirho: Duration) -> bool {
    let deadline_chirho = Instant::now() + timeout_chirho;
    while Instant::now() < deadline_chirho {
        if path_chirho.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    path_chirho.exists()
}

#[test]
fn fresh_bootstrap_and_explicit_legacy_migration_are_distinct_chirho() {
    let root_chirho = temp_parent_chirho("bootstrap-distinct");
    fs::create_dir_all(&root_chirho).unwrap();
    fs::write(root_chirho.join("legacy-chirho.jsonl"), b"legacy\n").unwrap();

    let error_chirho = bootstrap_cas_lifecycle_chirho(&root_chirho).unwrap_err();
    assert_eq!(
        error_chirho.kind_chirho(),
        CasLifecycleErrorKindChirho::UnavailableChirho
    );
    assert!(error_chirho
        .to_string()
        .contains("LegacyRootRequiresOfflineMigration"));

    let lifecycle_chirho = migrate_cas_lifecycle_offline_chirho(&root_chirho).unwrap();
    assert_eq!(
        lifecycle_chirho
            .snapshot_chirho()
            .unwrap()
            .deletion_generation_chirho(),
        0
    );
    assert!(bootstrap_cas_lifecycle_chirho(&root_chirho).is_err());
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn each_local_guard_keeps_os_shared_until_last_drop_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("shared-aggregate");
    let first_chirho = lifecycle_chirho.try_shared_chirho().unwrap();
    let second_chirho = lifecycle_chirho.try_shared_chirho().unwrap();
    assert_eq!(
        lifecycle_chirho
            .try_exclusive_chirho()
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::BusyChirho,
        "same-process EXCLUSIVE entered while both local SHARED guards were live"
    );
    let both_live_chirho = run_external_exclusive_probe_chirho(&root_chirho, true);
    assert!(
        both_live_chirho.status.success(),
        "external EXCLUSIVE entered while both local SHARED guards were live: {both_live_chirho:?}"
    );
    drop(first_chirho);
    assert_eq!(
        lifecycle_chirho
            .try_exclusive_chirho()
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::BusyChirho,
        "same-process EXCLUSIVE entered while one local SHARED guard remained"
    );
    let one_live_chirho = run_external_exclusive_probe_chirho(&root_chirho, true);
    assert!(
        one_live_chirho.status.success(),
        "dropping one local guard released the OS SHARED lock while another guard remained: \
         {one_live_chirho:?}"
    );
    drop(second_chirho);
    drop(
        lifecycle_chirho
            .try_exclusive_chirho()
            .expect("same-process EXCLUSIVE stayed blocked after both local SHARED guards dropped"),
    );
    let none_live_chirho = run_external_exclusive_probe_chirho(&root_chirho, false);
    assert!(
        none_live_chirho.status.success(),
        "external EXCLUSIVE stayed blocked after the last local SHARED guard dropped: \
         {none_live_chirho:?}"
    );
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn failed_first_shared_acquire_rolls_back_local_state_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("first-failure");
    let raw_anchor_chirho = raw_anchor_chirho(&root_chirho);
    raw_anchor_chirho.try_lock_exclusive().unwrap();

    for _attempt_chirho in 0..2 {
        assert_eq!(
            lifecycle_chirho
                .try_shared_chirho()
                .unwrap_err()
                .kind_chirho(),
            CasLifecycleErrorKindChirho::BusyChirho
        );
        let state_chirho = lifecycle_chirho
            .inner_chirho
            .registry_entry_chirho
            .state_chirho
            .lock()
            .unwrap();
        assert_eq!(
            state_chirho.shared_readers_chirho, 0,
            "failed first OS SHARED acquisition did not roll the local reader count back"
        );
        assert!(
            state_chirho.shared_file_chirho.is_none(),
            "failed first OS SHARED acquisition retained a local lock descriptor"
        );
    }

    FileExt::unlock(&raw_anchor_chirho).unwrap();
    drop(lifecycle_chirho.try_shared_chirho().unwrap());
    drop(raw_anchor_chirho);
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn new_first_reader_cannot_cross_delayed_last_reader_unlock_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("last-reader-race");
    let first_chirho = lifecycle_chirho.try_shared_chirho().unwrap();
    let second_chirho = lifecycle_chirho.try_shared_chirho().unwrap();
    drop(first_chirho);

    let entered_chirho = Arc::new(Barrier::new(2));
    let release_chirho = Arc::new(Barrier::new(2));
    *lifecycle_chirho
        .inner_chirho
        .registry_entry_chirho
        .before_last_shared_unlock_chirho
        .lock()
        .unwrap() = Some(Arc::new({
        let entered_chirho = Arc::clone(&entered_chirho);
        let release_chirho = Arc::clone(&release_chirho);
        move || {
            entered_chirho.wait();
            release_chirho.wait();
        }
    }));

    let dropper_chirho = thread::spawn(move || drop(second_chirho));
    entered_chirho.wait();
    let (sender_chirho, receiver_chirho) = mpsc::channel();
    let lifecycle_for_reader_chirho = lifecycle_chirho.clone();
    let reader_chirho = thread::spawn(move || {
        let guard_chirho = lifecycle_for_reader_chirho.try_shared_chirho().unwrap();
        sender_chirho.send(()).unwrap();
        drop(guard_chirho);
    });
    assert!(
        receiver_chirho
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "a new first reader crossed the delayed last-reader OS unlock"
    );
    release_chirho.wait();
    receiver_chirho
        .recv_timeout(Duration::from_secs(2))
        .expect("new first reader did not acquire after the delayed last-reader unlock completed");
    dropper_chirho.join().unwrap();
    reader_chirho.join().unwrap();
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn active_gc_refuses_snapshot_and_gc_after_snapshot_stales_promotion_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("generation-schedule");
    let mut exclusive_chirho = lifecycle_chirho.try_exclusive_chirho().unwrap();
    assert_eq!(
        lifecycle_chirho
            .snapshot_chirho()
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::BusyChirho
    );
    exclusive_chirho
        .advance_generation_before_roots_chirho()
        .unwrap();
    drop(exclusive_chirho);

    let snapshot_chirho = lifecycle_chirho.snapshot_chirho().unwrap();
    let mut later_gc_chirho = lifecycle_chirho.try_exclusive_chirho().unwrap();
    later_gc_chirho
        .advance_generation_before_roots_chirho()
        .unwrap();
    drop(later_gc_chirho);
    assert_eq!(
        lifecycle_chirho
            .promote_chirho(snapshot_chirho)
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::StaleChirho
    );
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn fresh_state_reread_rejects_while_retained_old_fd_still_reads_old_generation_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("fresh-state");
    let snapshot_chirho = lifecycle_chirho.snapshot_chirho().unwrap();
    let old_state_chirho = OpenOptions::new()
        .read(true)
        .open(
            root_chirho
                .join(CAS_LIFECYCLE_DIR_CHIRHO)
                .join(CAS_LIFECYCLE_STATE_CHIRHO),
        )
        .unwrap();

    let mut gc_chirho = lifecycle_chirho.try_exclusive_chirho().unwrap();
    let advanced_chirho = gc_chirho
        .advance_generation_before_roots_chirho()
        .unwrap()
        .clone();
    drop(gc_chirho);

    let mut retained_bytes_chirho = [0_u8; CAS_LIFECYCLE_STATE_BYTES_CHIRHO];
    old_state_chirho
        .read_exact_at(&mut retained_bytes_chirho, 0)
        .unwrap();
    let retained_chirho = decode_state_chirho(
        &retained_bytes_chirho,
        lifecycle_chirho.inner_chirho.root_identity_chirho,
    )
    .unwrap();
    assert_eq!(retained_chirho, snapshot_chirho);
    assert_ne!(retained_chirho, advanced_chirho);
    assert_eq!(
        lifecycle_chirho
            .promote_chirho(snapshot_chirho)
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::StaleChirho
    );
    drop(old_state_chirho);
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn state_corruption_wrong_root_and_generation_exhaustion_fail_closed_chirho() {
    let (first_root_chirho, first_lifecycle_chirho) = bootstrapped_root_chirho("state-first");
    let (second_root_chirho, second_lifecycle_chirho) = bootstrapped_root_chirho("state-second");
    let first_state_path_chirho = first_root_chirho
        .join(CAS_LIFECYCLE_DIR_CHIRHO)
        .join(CAS_LIFECYCLE_STATE_CHIRHO);
    let second_state_path_chirho = second_root_chirho
        .join(CAS_LIFECYCLE_DIR_CHIRHO)
        .join(CAS_LIFECYCLE_STATE_CHIRHO);
    let first_state_bytes_chirho = fs::read(&first_state_path_chirho).unwrap();
    fs::write(&second_state_path_chirho, &first_state_bytes_chirho).unwrap();
    assert_eq!(
        CasLifecycleRootChirho::open_chirho(&second_root_chirho)
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::UnavailableChirho
    );

    let mut corrupt_bytes_chirho = first_state_bytes_chirho.clone();
    corrupt_bytes_chirho[40] ^= 0x80;
    fs::write(&first_state_path_chirho, corrupt_bytes_chirho).unwrap();
    assert_eq!(
        first_lifecycle_chirho
            .snapshot_chirho()
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::UnavailableChirho
    );

    let exhausted_chirho = CasLifecycleSnapshotChirho {
        deletion_generation_chirho: u64::MAX,
        ..decode_state_chirho(
            &first_state_bytes_chirho.try_into().unwrap(),
            first_lifecycle_chirho.inner_chirho.root_identity_chirho,
        )
        .unwrap()
    };
    let mut exclusive_chirho = first_lifecycle_chirho.try_exclusive_chirho().unwrap();
    first_lifecycle_chirho
        .inner_chirho
        .replace_state_chirho(&exhausted_chirho)
        .unwrap();
    assert_eq!(
        exclusive_chirho
            .advance_generation_before_roots_chirho()
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::UnavailableChirho
    );
    drop(exclusive_chirho);

    drop(second_lifecycle_chirho);
    drop(first_lifecycle_chirho);
    fs::remove_dir_all(first_root_chirho).unwrap();
    fs::remove_dir_all(second_root_chirho).unwrap();
}

#[test]
fn anchor_replacement_is_detected_and_never_adopted_online_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("anchor-replacement");
    let lifecycle_dir_chirho = root_chirho.join(CAS_LIFECYCLE_DIR_CHIRHO);
    let anchor_chirho = lifecycle_dir_chirho.join(CAS_LIFECYCLE_ANCHOR_CHIRHO);
    let old_anchor_chirho = lifecycle_dir_chirho.join("old-anchor-chirho");
    fs::rename(&anchor_chirho, &old_anchor_chirho).unwrap();
    fs::write(&anchor_chirho, b"").unwrap();

    assert_eq!(
        lifecycle_chirho
            .try_shared_chirho()
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::UnavailableChirho
    );
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn registry_key_uses_root_and_anchor_identity_not_display_path_chirho() {
    let parent_chirho = temp_parent_chirho("alias-registry-parent");
    let root_chirho = parent_chirho.join("root-chirho");
    let moved_root_chirho = parent_chirho.join("different-length-moved-root-chirho");
    fs::create_dir_all(&root_chirho).unwrap();
    let first_lifecycle_chirho = bootstrap_cas_lifecycle_chirho(&root_chirho).unwrap();
    fs::rename(&root_chirho, &moved_root_chirho).unwrap();
    assert_ne!(
        root_chirho.as_os_str().len(),
        moved_root_chirho.as_os_str().len(),
        "fixture paths must differ so a pathname-derived registry key is observable"
    );
    let moved_root_directory_chirho = File::open(&moved_root_chirho).unwrap();
    let moved_root_custody_chirho = DescriptorRootCustodyChirho::from_retained_directory_chirho(
        moved_root_chirho.clone(),
        moved_root_directory_chirho,
    )
    .unwrap();
    let second_lifecycle_chirho = open_from_custody_chirho(moved_root_custody_chirho).unwrap();
    assert_ne!(
        first_lifecycle_chirho.canonical_root_chirho(),
        second_lifecycle_chirho.canonical_root_chirho(),
        "fixture must retain two display coordinates for the same root inode"
    );
    assert!(
        Arc::ptr_eq(
            &first_lifecycle_chirho.inner_chirho.registry_entry_chirho,
            &second_lifecycle_chirho.inner_chirho.registry_entry_chirho
        ),
        "one root and lock-anchor identity produced two pathname-keyed local registry entries"
    );
    let first_chirho = first_lifecycle_chirho.try_shared_chirho().unwrap();
    let second_chirho = second_lifecycle_chirho.try_shared_chirho().unwrap();
    drop(first_chirho);
    assert_eq!(
        first_lifecycle_chirho
            .try_exclusive_chirho()
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::BusyChirho
    );
    drop(second_chirho);
    drop(first_lifecycle_chirho.try_exclusive_chirho().unwrap());
    drop(second_lifecycle_chirho);
    drop(first_lifecycle_chirho);
    fs::remove_dir_all(parent_chirho).unwrap();
}

#[test]
fn publication_guard_excludes_gc_until_guard_release_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("promotion-window");
    let snapshot_chirho = lifecycle_chirho.snapshot_chirho().unwrap();
    let publication_chirho = lifecycle_chirho.promote_chirho(snapshot_chirho).unwrap();
    assert_eq!(
        lifecycle_chirho
            .try_exclusive_chirho()
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::BusyChirho
    );
    drop(publication_chirho);
    drop(lifecycle_chirho.try_exclusive_chirho().unwrap());
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn no_replace_publication_preserves_winner_inode_and_rejects_corruption_chirho() {
    let root_chirho = temp_parent_chirho("no-replace");
    fs::create_dir_all(&root_chirho).unwrap();
    let bytes_chirho = b"immutable memorial stone chirho";
    let address_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    publish_content_addressed_file_at_root_no_replace_chirho(
        &root_chirho,
        &address_chirho,
        bytes_chirho,
    )
    .unwrap();
    let object_chirho = object_path_chirho(&root_chirho, &address_chirho);
    let first_metadata_chirho = fs::metadata(&object_chirho).unwrap();
    publish_content_addressed_file_at_root_no_replace_chirho(
        &root_chirho,
        &address_chirho,
        bytes_chirho,
    )
    .unwrap();
    let second_metadata_chirho = fs::metadata(&object_chirho).unwrap();
    assert_eq!(first_metadata_chirho.ino(), second_metadata_chirho.ino());

    let corrupt_root_chirho = temp_parent_chirho("corrupt-winner");
    let corrupt_object_chirho = object_path_chirho(&corrupt_root_chirho, &address_chirho);
    fs::create_dir_all(corrupt_object_chirho.parent().unwrap()).unwrap();
    fs::write(&corrupt_object_chirho, b"wrong bytes chirho").unwrap();
    let error_chirho = publish_content_addressed_file_at_root_no_replace_chirho(
        &corrupt_root_chirho,
        &address_chirho,
        bytes_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.kind_chirho(),
        CasLifecycleErrorKindChirho::CorruptWinnerChirho
    );
    assert_eq!(
        fs::read(&corrupt_object_chirho).unwrap(),
        b"wrong bytes chirho"
    );

    fs::remove_dir_all(root_chirho).unwrap();
    fs::remove_dir_all(corrupt_root_chirho).unwrap();
}

#[test]
fn same_hash_publishers_converge_without_temp_leaks_chirho() {
    let root_chirho = temp_parent_chirho("publisher-race");
    fs::create_dir_all(&root_chirho).unwrap();
    let bytes_chirho = Arc::new(b"same hash concurrent publication chirho".to_vec());
    let address_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
    let barrier_chirho = Arc::new(Barrier::new(9));
    let mut publishers_chirho = Vec::new();
    for _publisher_index_chirho in 0..8 {
        let root_chirho = root_chirho.clone();
        let bytes_chirho = Arc::clone(&bytes_chirho);
        let address_chirho = address_chirho.clone();
        let barrier_chirho = Arc::clone(&barrier_chirho);
        publishers_chirho.push(thread::spawn(move || {
            barrier_chirho.wait();
            publish_content_addressed_file_at_root_no_replace_chirho(
                &root_chirho,
                &address_chirho,
                &bytes_chirho,
            )
            .unwrap();
        }));
    }
    barrier_chirho.wait();
    for publisher_chirho in publishers_chirho {
        publisher_chirho.join().unwrap();
    }
    assert_eq!(
        fs::read(object_path_chirho(&root_chirho, &address_chirho)).unwrap(),
        bytes_chirho.as_slice()
    );
    let shard_chirho = object_path_chirho(&root_chirho, &address_chirho)
        .parent()
        .unwrap()
        .to_path_buf();
    assert!(fs::read_dir(shard_chirho).unwrap().all(|entry_chirho| {
        !entry_chirho
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".object.tmp-chirho")
    }));
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn typed_child_deleted_by_intervening_gc_makes_promotion_stale_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("typed-child");
    let child_bytes_chirho = b"typed semantic child chirho";
    let child_chirho = blake3::hash(child_bytes_chirho).to_hex().to_string();
    publish_content_addressed_file_no_replace_chirho(
        &lifecycle_chirho,
        &child_chirho,
        child_bytes_chirho,
    )
    .unwrap();
    let target_bytes_chirho = format!("{{\"child_chirho\":\"{child_chirho}\"}}").into_bytes();
    let target_chirho = blake3::hash(&target_bytes_chirho).to_hex().to_string();
    publish_content_addressed_file_no_replace_chirho(
        &lifecycle_chirho,
        &target_chirho,
        &target_bytes_chirho,
    )
    .unwrap();

    let snapshot_chirho = lifecycle_chirho.snapshot_chirho().unwrap();
    assert_eq!(
        fs::read(object_path_chirho(&root_chirho, &child_chirho)).unwrap(),
        child_bytes_chirho
    );
    let mut gc_chirho = lifecycle_chirho.try_exclusive_chirho().unwrap();
    assert!(gc_chirho
        .delete_content_addressed_object_chirho(&child_chirho)
        .is_err());
    gc_chirho.advance_generation_before_roots_chirho().unwrap();
    assert!(gc_chirho
        .delete_content_addressed_object_chirho(&child_chirho)
        .unwrap());
    drop(gc_chirho);
    assert_eq!(
        lifecycle_chirho
            .promote_chirho(snapshot_chirho)
            .unwrap_err()
            .kind_chirho(),
        CasLifecycleErrorKindChirho::StaleChirho
    );
    assert!(object_path_chirho(&root_chirho, &target_chirho).is_file());
    assert!(!object_path_chirho(&root_chirho, &child_chirho).exists());
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn root_recreation_refuses_before_replacement_root_mutation_chirho() {
    let parent_chirho = temp_parent_chirho("root-rebound-parent");
    let root_chirho = parent_chirho.join("root-chirho");
    let moved_chirho = parent_chirho.join("moved-chirho");
    fs::create_dir_all(&root_chirho).unwrap();
    let lifecycle_chirho = bootstrap_cas_lifecycle_chirho(&root_chirho).unwrap();
    let snapshot_chirho = lifecycle_chirho.snapshot_chirho().unwrap();
    fs::rename(&root_chirho, &moved_chirho).unwrap();
    fs::create_dir(&root_chirho).unwrap();

    let error_chirho = lifecycle_chirho
        .promote_chirho(snapshot_chirho)
        .unwrap_err();
    assert_eq!(
        error_chirho.kind_chirho(),
        CasLifecycleErrorKindChirho::RootReboundChirho
    );
    assert_eq!(fs::read_dir(&root_chirho).unwrap().count(), 0);
    drop(lifecycle_chirho);
    fs::remove_dir_all(parent_chirho).unwrap();
}

#[test]
fn anchor_and_state_descriptors_are_cloexec_across_real_exec_chirho() {
    if std::env::var_os("CAIRN_FD_CLOSED_PROBE_CHIRHO").is_some() {
        let anchor_fd_chirho: RawFd = std::env::var("CAIRN_ANCHOR_FD_CHIRHO")
            .unwrap()
            .parse()
            .unwrap();
        let state_fd_chirho: RawFd = std::env::var("CAIRN_STATE_FD_CHIRHO")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::fcntl(anchor_fd_chirho, libc::F_GETFD) }, -1);
        assert_eq!(unsafe { libc::fcntl(state_fd_chirho, libc::F_GETFD) }, -1);
        return;
    }

    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("cloexec");
    let anchor_chirho = lifecycle_chirho
        .inner_chirho
        .open_verified_anchor_chirho()
        .unwrap();
    let state_chirho = open_verified_regular_at_chirho(
        &lifecycle_chirho.inner_chirho.lifecycle_directory_chirho,
        CAS_LIFECYCLE_STATE_CHIRHO,
        lifecycle_chirho.inner_chirho.owner_uid_chirho,
        OFlags::RDONLY,
    )
    .unwrap();
    assert_ne!(
        unsafe { libc::fcntl(anchor_chirho.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert_ne!(
        unsafe { libc::fcntl(state_chirho.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let anchor_probe_fd_chirho =
        unsafe { libc::fcntl(anchor_chirho.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 200) };
    let state_probe_fd_chirho =
        unsafe { libc::fcntl(state_chirho.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 201) };
    assert!(anchor_probe_fd_chirho >= 200);
    assert!(state_probe_fd_chirho >= 201);
    let output_chirho = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("cas_lifecycle_chirho::tests_chirho::anchor_and_state_descriptors_are_cloexec_across_real_exec_chirho")
        .arg("--nocapture")
        .env("CAIRN_FD_CLOSED_PROBE_CHIRHO", "1")
        .env("CAIRN_ANCHOR_FD_CHIRHO", anchor_probe_fd_chirho.to_string())
        .env("CAIRN_STATE_FD_CHIRHO", state_probe_fd_chirho.to_string())
        .output()
        .unwrap();
    unsafe {
        libc::close(anchor_probe_fd_chirho);
        libc::close(state_probe_fd_chirho);
    }
    assert!(output_chirho.status.success(), "{output_chirho:?}");
    drop(state_chirho);
    drop(anchor_chirho);
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn separate_process_shared_matrix_chirho() {
    if let Some(root_chirho) = std::env::var_os("CAIRN_CROSS_PROCESS_ROOT_CHIRHO") {
        let lifecycle_chirho =
            CasLifecycleRootChirho::open_chirho(Path::new(&root_chirho)).unwrap();
        match std::env::var("CAIRN_CROSS_PROCESS_MODE_CHIRHO")
            .unwrap()
            .as_str()
        {
            "exclusive-probe-chirho" => {
                println!("{EXTERNAL_EXCLUSIVE_PROBE_MARKER_CHIRHO}");
                let expect_busy_chirho = std::env::var_os("CAIRN_EXPECT_BUSY_CHIRHO").is_some();
                let outcome_chirho = lifecycle_chirho.try_exclusive_chirho();
                assert_eq!(
                    outcome_chirho.is_err(),
                    expect_busy_chirho,
                    "external EXCLUSIVE outcome did not match the live SHARED population"
                );
                if let Err(error_chirho) = outcome_chirho {
                    assert_eq!(
                        error_chirho.kind_chirho(),
                        CasLifecycleErrorKindChirho::BusyChirho
                    );
                }
            }
            "shared-holder-chirho" => {
                let ready_chirho =
                    PathBuf::from(std::env::var_os("CAIRN_SHARED_READY_CHIRHO").unwrap());
                let release_chirho =
                    PathBuf::from(std::env::var_os("CAIRN_SHARED_RELEASE_CHIRHO").unwrap());
                let shared_chirho = lifecycle_chirho.try_shared_chirho().unwrap();
                fs::write(&ready_chirho, b"shared-held-chirho").unwrap();
                assert!(
                    wait_for_path_chirho(&release_chirho, Duration::from_secs(10)),
                    "parent never released the separate-process SHARED holder"
                );
                drop(shared_chirho);
            }
            mode_chirho => panic!("unknown cross-process probe mode: {mode_chirho}"),
        }
        return;
    }

    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("cross-process-matrix");
    let parent_shared_chirho = lifecycle_chirho.try_shared_chirho().unwrap();
    let ready_chirho = root_chirho.join("shared-holder-ready-chirho");
    let release_chirho = root_chirho.join("shared-holder-release-chirho");
    let mut child_shared_chirho = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(CROSS_PROCESS_MATRIX_TEST_CHIRHO)
        .arg("--nocapture")
        .env("CAIRN_CROSS_PROCESS_ROOT_CHIRHO", &root_chirho)
        .env("CAIRN_CROSS_PROCESS_MODE_CHIRHO", "shared-holder-chirho")
        .env("CAIRN_SHARED_READY_CHIRHO", &ready_chirho)
        .env("CAIRN_SHARED_RELEASE_CHIRHO", &release_chirho)
        .spawn()
        .unwrap();
    if !wait_for_path_chirho(&ready_chirho, Duration::from_secs(5)) {
        let _kill_chirho = child_shared_chirho.kill();
        let output_chirho = child_shared_chirho.wait_with_output().unwrap();
        panic!("separate-process SHARED did not coexist with parent SHARED: {output_chirho:?}");
    }
    assert!(
        child_shared_chirho.try_wait().unwrap().is_none(),
        "separate-process SHARED holder exited before the release signal"
    );

    let both_live_chirho = run_external_exclusive_probe_chirho(&root_chirho, true);
    assert!(
        both_live_chirho.status.success(),
        "EXCLUSIVE entered while both process SHARED guards were live: {both_live_chirho:?}"
    );
    drop(parent_shared_chirho);
    let child_only_chirho = run_external_exclusive_probe_chirho(&root_chirho, true);
    assert!(
        child_only_chirho.status.success(),
        "EXCLUSIVE entered after only the parent SHARED guard released: {child_only_chirho:?}"
    );

    fs::write(&release_chirho, b"release-chirho").unwrap();
    let child_output_chirho = child_shared_chirho.wait_with_output().unwrap();
    assert!(
        child_output_chirho.status.success(),
        "separate-process SHARED holder failed: {child_output_chirho:?}"
    );
    let released_chirho = run_external_exclusive_probe_chirho(&root_chirho, false);
    assert!(
        released_chirho.status.success(),
        "EXCLUSIVE stayed blocked after both process SHARED guards released: {released_chirho:?}"
    );
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn hostile_noncanonical_address_encodings_are_refused_chirho() {
    let root_chirho = temp_parent_chirho("hostile-address");
    fs::create_dir_all(&root_chirho).unwrap();
    let bytes_chirho = b"canonical address boundary chirho";
    let canonical_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    for hostile_chirho in [
        canonical_chirho.to_uppercase(),
        format!("{canonical_chirho}aa"),
        format!("{canonical_chirho}{canonical_chirho}"),
    ] {
        assert_eq!(
            publish_content_addressed_file_at_root_no_replace_chirho(
                &root_chirho,
                &hostile_chirho,
                bytes_chirho,
            )
            .unwrap_err()
            .kind_chirho(),
            CasLifecycleErrorKindChirho::CorruptWinnerChirho
        );
    }
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn fork_without_exec_can_release_parent_lock_and_remains_a_blocker_chirho() {
    let (root_chirho, lifecycle_chirho) = bootstrapped_root_chirho("fork-blocker");
    let shared_chirho = lifecycle_chirho.try_shared_chirho().unwrap();
    let inherited_fd_chirho = lifecycle_chirho
        .inner_chirho
        .registry_entry_chirho
        .state_chirho
        .lock()
        .unwrap()
        .shared_file_chirho
        .as_ref()
        .unwrap()
        .as_raw_fd();
    let child_chirho = unsafe { libc::fork() };
    assert!(child_chirho >= 0);
    if child_chirho == 0 {
        let result_chirho = unsafe { libc::flock(inherited_fd_chirho, libc::LOCK_UN) };
        unsafe { libc::_exit(if result_chirho == 0 { 0 } else { 71 }) };
    }
    let mut status_chirho = 0;
    assert_eq!(
        unsafe { libc::waitpid(child_chirho, &mut status_chirho, 0) },
        child_chirho
    );
    assert!(libc::WIFEXITED(status_chirho));
    assert_eq!(libc::WEXITSTATUS(status_chirho), 0);

    let external_chirho = raw_anchor_chirho(&root_chirho);
    external_chirho.try_lock_exclusive().unwrap();
    FileExt::unlock(&external_chirho).unwrap();
    drop(external_chirho);
    drop(shared_chirho);
    drop(lifecycle_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}
