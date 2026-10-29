// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TEST_IDENTITY_KIND_CHIRHO: &str = "test-resident-writer-chirho";
const TEST_PENDING_IDENTITY_CHIRHO: &[u8] =
    br#"{"schema_chirho":"test-resident-v1-chirho","state_chirho":"pending","coordinate_chirho":"alpha"}"#;
const TEST_BOUND_IDENTITY_CHIRHO: &[u8] =
    br#"{"schema_chirho":"test-resident-v1-chirho","state_chirho":"bound","coordinate_chirho":"alpha"}"#;
const CHILD_ROOT_ENV_CHIRHO: &str = "CAIRN_RESIDENT_CHILD_ROOT_CHIRHO";
const CHILD_READY_ENV_CHIRHO: &str = "CAIRN_RESIDENT_CHILD_READY_CHIRHO";
const CHILD_RELEASE_ENV_CHIRHO: &str = "CAIRN_RESIDENT_CHILD_RELEASE_CHIRHO";
const CHILD_ACTION_ENV_CHIRHO: &str = "CAIRN_RESIDENT_CHILD_ACTION_CHIRHO";
const CHILD_EVIDENCE_ENV_CHIRHO: &str = "CAIRN_RESIDENT_CHILD_EVIDENCE_CHIRHO";
const CHILD_RESERVE_ACTION_CHIRHO: &str = "reserve-pending-chirho";
const CHILD_OPEN_ACTION_CHIRHO: &str = "open-bound-chirho";

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must be after Unix epoch")
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-resident-writer-{label_chirho}-{}-{nanos_chirho}-{counter_chirho}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn pending_binding_chirho(root_chirho: &Path) -> ResidentWriterBindingChirho<'_> {
    ResidentWriterBindingChirho {
        root_chirho,
        identity_kind_chirho: TEST_IDENTITY_KIND_CHIRHO,
        canonical_identity_chirho: TEST_PENDING_IDENTITY_CHIRHO,
    }
}

fn bound_binding_chirho(root_chirho: &Path) -> ResidentWriterBindingChirho<'_> {
    ResidentWriterBindingChirho {
        root_chirho,
        identity_kind_chirho: TEST_IDENTITY_KIND_CHIRHO,
        canonical_identity_chirho: TEST_BOUND_IDENTITY_CHIRHO,
    }
}

fn create_bound_resident_chirho(root_chirho: &Path) -> ResidentWriterLeaseChirho {
    let (provisioning_chirho, outcome_chirho) =
        reserve_resident_writer_chirho(&pending_binding_chirho(root_chirho)).unwrap();
    assert_eq!(
        outcome_chirho,
        ResidentWriterReservationOutcomeChirho::CreatedPendingChirho
    );
    provisioning_chirho
        .bind_resident_writer_chirho(&bound_binding_chirho(root_chirho))
        .unwrap()
}

fn initialize_bound_chirho(root_chirho: &Path) {
    drop(create_bound_resident_chirho(root_chirho));
}

fn wait_for_path_chirho(path_chirho: &Path) {
    for _attempt_chirho in 0..500 {
        if path_chirho.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", path_chirho.display());
}

fn assert_already_held_chirho<T: fmt::Debug>(result_chirho: Result<T>) {
    let error_chirho = format!("{:#}", result_chirho.unwrap_err());
    assert!(
        error_chirho.contains("ResidentWriterAlreadyHeldChirho"),
        "{error_chirho}"
    );
}

fn assert_child_refused_chirho(root_chirho: &Path, action_chirho: &str) {
    let evidence_chirho = root_chirho.join(format!("child-refusal-{action_chirho}.txt"));
    let output_chirho = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(
            "resident_writer_chirho::tests_chirho::resident_writer_cross_process_refusal_helper_chirho",
        )
        .arg("--nocapture")
        .env(CHILD_ROOT_ENV_CHIRHO, root_chirho)
        .env(CHILD_ACTION_ENV_CHIRHO, action_chirho)
        .env(CHILD_EVIDENCE_ENV_CHIRHO, &evidence_chirho)
        .output()
        .unwrap();
    assert!(
        output_chirho.status.success(),
        "{}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&evidence_chirho).unwrap(),
        action_chirho,
        "the exact child helper must execute and publish its refusal evidence"
    );
}

#[test]
fn pending_crash_recovery_binds_without_ownership_gap_chirho() {
    let root_chirho = temp_root_chirho("pending-recovery");
    let before_chirho = open_resident_writer_chirho(&bound_binding_chirho(&root_chirho))
        .unwrap_err()
        .to_string();
    assert!(
        before_chirho.contains("ResidentWriterReservationMissingChirho"),
        "{before_chirho}"
    );

    let (provisioning_chirho, created_chirho) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    assert_eq!(
        created_chirho,
        ResidentWriterReservationOutcomeChirho::CreatedPendingChirho
    );
    let identity_path_chirho = resident_writer_identity_path_chirho(&root_chirho).unwrap();
    let pending_record_chirho =
        PreparedResidentWriterBindingChirho::new_chirho(&pending_binding_chirho(&root_chirho))
            .unwrap()
            .record_chirho;
    assert_eq!(
        read_validated_identity_record_chirho(&identity_path_chirho).unwrap(),
        pending_record_chirho
    );

    drop(provisioning_chirho);
    let (recovered_chirho, recovered_outcome_chirho) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    assert_eq!(
        recovered_outcome_chirho,
        ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho
    );
    let resident_chirho = recovered_chirho
        .bind_resident_writer_chirho(&bound_binding_chirho(&root_chirho))
        .unwrap();
    assert_already_held_chirho(open_resident_writer_chirho(&bound_binding_chirho(
        &root_chirho,
    )));
    drop(resident_chirho);
    let reopened_chirho = open_resident_writer_chirho(&bound_binding_chirho(&root_chirho)).unwrap();
    drop(reopened_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn interrupted_first_reservation_recovers_empty_dir_and_marker_only_chirho() {
    let empty_dir_root_chirho = temp_root_chirho("empty-control-dir");
    let empty_dir_chirho = empty_dir_root_chirho.join(RESIDENT_WRITER_DIR_CHIRHO);
    std::fs::create_dir(&empty_dir_chirho).unwrap();
    fsync_dir_chirho(&empty_dir_root_chirho).unwrap();
    let (empty_dir_lease_chirho, empty_dir_outcome_chirho) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&empty_dir_root_chirho)).unwrap();
    assert_eq!(
        empty_dir_outcome_chirho,
        ResidentWriterReservationOutcomeChirho::CompletedPendingReservationChirho
    );
    drop(empty_dir_lease_chirho);
    assert!(empty_dir_chirho
        .join(RESIDENT_WRITER_LOCK_FILE_CHIRHO)
        .is_file());
    assert!(empty_dir_chirho
        .join(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO)
        .is_file());
    std::fs::remove_dir_all(empty_dir_root_chirho).unwrap();

    let marker_root_chirho = temp_root_chirho("marker-only");
    let marker_dir_chirho = marker_root_chirho.join(RESIDENT_WRITER_DIR_CHIRHO);
    std::fs::create_dir(&marker_dir_chirho).unwrap();
    fsync_dir_chirho(&marker_root_chirho).unwrap();
    let marker_path_chirho = marker_dir_chirho.join(RESIDENT_WRITER_LOCK_FILE_CHIRHO);
    let marker_file_chirho = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&marker_path_chirho)
        .unwrap();
    marker_file_chirho.sync_all().unwrap();
    fsync_dir_chirho(&marker_dir_chirho).unwrap();
    drop(marker_file_chirho);
    let (marker_lease_chirho, marker_outcome_chirho) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&marker_root_chirho)).unwrap();
    assert_eq!(
        marker_outcome_chirho,
        ResidentWriterReservationOutcomeChirho::CompletedPendingReservationChirho
    );
    assert!(marker_dir_chirho
        .join(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO)
        .is_file());
    drop(marker_lease_chirho);
    std::fs::remove_dir_all(marker_root_chirho).unwrap();
}

#[test]
fn provisioning_and_bound_resident_hold_local_and_process_exclusion_chirho() {
    let root_chirho = temp_root_chirho("continuous");
    let (provisioning_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();

    assert_already_held_chirho(reserve_resident_writer_chirho(&pending_binding_chirho(
        &root_chirho,
    )));
    assert_already_held_chirho(open_resident_writer_chirho(&bound_binding_chirho(
        &root_chirho,
    )));
    assert_child_refused_chirho(&root_chirho, CHILD_RESERVE_ACTION_CHIRHO);
    assert_child_refused_chirho(&root_chirho, CHILD_OPEN_ACTION_CHIRHO);

    let resident_chirho = provisioning_chirho
        .bind_resident_writer_chirho(&bound_binding_chirho(&root_chirho))
        .unwrap();
    assert_already_held_chirho(reserve_resident_writer_chirho(&pending_binding_chirho(
        &root_chirho,
    )));
    assert_already_held_chirho(open_resident_writer_chirho(&bound_binding_chirho(
        &root_chirho,
    )));
    assert_child_refused_chirho(&root_chirho, CHILD_RESERVE_ACTION_CHIRHO);
    assert_child_refused_chirho(&root_chirho, CHILD_OPEN_ACTION_CHIRHO);

    drop(resident_chirho);
    let reopened_chirho = open_resident_writer_chirho(&bound_binding_chirho(&root_chirho)).unwrap();
    drop(reopened_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn resident_writer_debug_views_redact_canonical_root_chirho() {
    let root_chirho = temp_root_chirho("debug-redaction");
    let root_text_chirho = root_chirho.to_string_lossy().into_owned();
    let pending_binding_chirho = pending_binding_chirho(&root_chirho);
    assert!(!format!("{pending_binding_chirho:?}").contains(&root_text_chirho));
    assert!(!format!("{pending_binding_chirho:?}")
        .contains(std::str::from_utf8(TEST_PENDING_IDENTITY_CHIRHO).unwrap()));
    let (provisioning_chirho, _) = reserve_resident_writer_chirho(&pending_binding_chirho).unwrap();
    assert!(!format!("{provisioning_chirho:?}").contains(&root_text_chirho));
    let inspection_chirho = inspect_resident_writer_identity_chirho(&root_chirho).unwrap();
    assert!(!format!("{inspection_chirho:?}").contains(&root_text_chirho));
    let resident_chirho = provisioning_chirho
        .bind_resident_writer_chirho(&bound_binding_chirho(&root_chirho))
        .unwrap();
    assert!(!format!("{resident_chirho:?}").contains(&root_text_chirho));
    drop(resident_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn overlapping_process_local_resident_is_refused_and_registry_retires_chirho() {
    let root_chirho = temp_root_chirho("overlap");
    let first_chirho = create_bound_resident_chirho(&root_chirho);
    let lock_path_chirho = root_chirho
        .join(RESIDENT_WRITER_DIR_CHIRHO)
        .join(RESIDENT_WRITER_LOCK_FILE_CHIRHO)
        .canonicalize()
        .unwrap();
    assert!(resident_writer_local_registry_chirho().contains_chirho(&lock_path_chirho));
    assert_already_held_chirho(open_resident_writer_chirho(&bound_binding_chirho(
        &root_chirho,
    )));
    drop(first_chirho);
    assert!(!resident_writer_local_registry_chirho().contains_chirho(&lock_path_chirho));
    let reopened_chirho = open_resident_writer_chirho(&bound_binding_chirho(&root_chirho)).unwrap();
    drop(reopened_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn retired_roots_do_not_accumulate_process_registry_memory_chirho() {
    let parent_chirho = temp_root_chirho("retired-roots");
    for index_chirho in 0..2048 {
        let root_chirho = parent_chirho.join(format!("root-{index_chirho:04}-chirho"));
        std::fs::create_dir(&root_chirho).unwrap();
        let (provisioning_chirho, _) =
            reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
        if index_chirho % 2 == 0 {
            drop(provisioning_chirho);
        } else {
            drop(
                provisioning_chirho
                    .bind_resident_writer_chirho(&bound_binding_chirho(&root_chirho))
                    .unwrap(),
            );
        }
        std::fs::remove_dir_all(root_chirho).unwrap();
    }

    let mut metrics_chirho = resident_writer_local_registry_chirho().metrics_chirho();
    for _attempt_chirho in 0..500 {
        if metrics_chirho.active_entries_chirho == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        metrics_chirho = resident_writer_local_registry_chirho().metrics_chirho();
    }
    assert_eq!(
        metrics_chirho.active_entries_chirho, 0,
        "{metrics_chirho:?}"
    );
    assert!(
        metrics_chirho.maximum_shard_capacity_chirho
            <= RESIDENT_WRITER_IDLE_CAPACITY_PER_SHARD_CHIRHO,
        "{metrics_chirho:?}"
    );
    assert!(
        metrics_chirho.total_capacity_chirho
            <= RESIDENT_WRITER_LOCAL_SHARD_COUNT_CHIRHO
                * RESIDENT_WRITER_IDLE_CAPACITY_PER_SHARD_CHIRHO,
        "{metrics_chirho:?}"
    );
    std::fs::remove_dir_all(parent_chirho).unwrap();
}

#[test]
fn one_long_lived_slot_cannot_anchor_historical_peak_registry_capacity_chirho() {
    let registry_chirho = Box::leak(Box::new(ResidentWriterLocalRegistryChirho::new_chirho()));
    let target_key_chirho = synthetic_local_key_chirho(0);
    let target_shard_chirho = registry_chirho.shard_index_chirho(&target_key_chirho);
    let mut slots_chirho = Vec::new();
    for index_chirho in 0..1_000_000_u64 {
        let key_chirho = synthetic_local_key_chirho(index_chirho);
        if registry_chirho.shard_index_chirho(&key_chirho) == target_shard_chirho {
            slots_chirho.push(registry_chirho.acquire_chirho(&key_chirho).unwrap());
            if slots_chirho.len() == 512 {
                break;
            }
        }
    }
    assert_eq!(
        slots_chirho.len(),
        512,
        "the fixed search budget must populate one randomized shard"
    );

    let anchor_chirho = slots_chirho.pop().unwrap();
    drop(slots_chirho);
    let anchored_metrics_chirho = registry_chirho.metrics_chirho();
    assert_eq!(anchored_metrics_chirho.active_entries_chirho, 1);
    assert!(
        anchored_metrics_chirho.maximum_shard_capacity_chirho
            <= RESIDENT_WRITER_IDLE_CAPACITY_PER_SHARD_CHIRHO,
        "{anchored_metrics_chirho:?}"
    );

    drop(anchor_chirho);
    let retired_metrics_chirho = registry_chirho.metrics_chirho();
    assert_eq!(retired_metrics_chirho.active_entries_chirho, 0);
    assert!(
        retired_metrics_chirho.maximum_shard_capacity_chirho
            <= RESIDENT_WRITER_IDLE_CAPACITY_PER_SHARD_CHIRHO,
        "{retired_metrics_chirho:?}"
    );
}

#[cfg(unix)]
fn synthetic_local_key_chirho(index_chirho: u64) -> ResidentWriterLocalKeyChirho {
    ResidentWriterLocalKeyChirho::UnixFileChirho {
        device_chirho: u64::MAX,
        inode_chirho: index_chirho,
    }
}

#[cfg(not(unix))]
fn synthetic_local_key_chirho(index_chirho: u64) -> ResidentWriterLocalKeyChirho {
    ResidentWriterLocalKeyChirho::CanonicalPathChirho(PathBuf::from(format!(
        "/synthetic-resident-writer-{index_chirho}-chirho"
    )))
}

#[cfg(unix)]
#[test]
fn canonical_root_aliases_share_one_resident_slot_chirho() {
    use std::os::unix::fs::symlink;

    let parent_chirho = temp_root_chirho("alias-parent");
    let root_chirho = parent_chirho.join("root-chirho");
    let alias_chirho = parent_chirho.join("root-alias-chirho");
    std::fs::create_dir(&root_chirho).unwrap();
    symlink(&root_chirho, &alias_chirho).unwrap();
    let (provisioning_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    let resident_chirho = provisioning_chirho
        .bind_resident_writer_chirho(&bound_binding_chirho(&alias_chirho))
        .unwrap();
    assert_eq!(
        resident_chirho.canonical_root_chirho(),
        root_chirho.canonicalize().unwrap()
    );
    assert_already_held_chirho(open_resident_writer_chirho(&bound_binding_chirho(
        &root_chirho,
    )));
    drop(resident_chirho);
    std::fs::remove_dir_all(parent_chirho).unwrap();
}

#[cfg(unix)]
#[test]
fn renamed_root_cannot_bypass_process_local_resident_identity_chirho() {
    let parent_chirho = temp_root_chirho("rename-parent");
    let original_root_chirho = parent_chirho.join("original-root-chirho");
    let renamed_root_chirho = parent_chirho.join("renamed-root-chirho");
    std::fs::create_dir(&original_root_chirho).unwrap();
    let resident_chirho = create_bound_resident_chirho(&original_root_chirho);
    std::fs::rename(&original_root_chirho, &renamed_root_chirho).unwrap();
    assert_already_held_chirho(open_resident_writer_chirho(&bound_binding_chirho(
        &renamed_root_chirho,
    )));
    drop(resident_chirho);
    let reopened_chirho =
        open_resident_writer_chirho(&bound_binding_chirho(&renamed_root_chirho)).unwrap();
    drop(reopened_chirho);
    std::fs::remove_dir_all(parent_chirho).unwrap();
}

#[cfg(unix)]
#[test]
fn retained_root_descriptor_keeps_pending_bound_and_probe_on_original_inode_chirho() {
    let parent_chirho = temp_root_chirho("retained-root-replacement");
    let root_chirho = parent_chirho.join("authority-root-chirho");
    let moved_root_chirho = parent_chirho.join("authority-root-moved-chirho");
    std::fs::create_dir(&root_chirho).unwrap();
    let canonical_root_chirho = root_chirho.canonicalize().unwrap();
    let retained_root_chirho = File::open(&canonical_root_chirho).unwrap();
    let custody_chirho = ResidentWriterRootCustodyChirho::from_retained_directory_chirho(
        &canonical_root_chirho,
        retained_root_chirho,
    )
    .unwrap();

    std::fs::rename(&root_chirho, &moved_root_chirho).unwrap();
    std::fs::create_dir(&root_chirho).unwrap();
    let pending_chirho = pending_binding_chirho(&canonical_root_chirho);
    let (provisioning_chirho, outcome_chirho) =
        reserve_resident_writer_in_custody_chirho(&custody_chirho, &pending_chirho).unwrap();
    assert_eq!(
        outcome_chirho,
        ResidentWriterReservationOutcomeChirho::CreatedPendingChirho
    );
    assert!(moved_root_chirho
        .join(RESIDENT_WRITER_DIR_CHIRHO)
        .join(RESIDENT_WRITER_IDENTITY_FILE_CHIRHO)
        .is_file());
    assert!(!root_chirho.join(RESIDENT_WRITER_DIR_CHIRHO).exists());

    let resident_chirho = provisioning_chirho
        .bind_resident_writer_chirho(&bound_binding_chirho(&canonical_root_chirho))
        .unwrap();
    let inspection_chirho = resident_chirho.inspect_identity_chirho().unwrap();
    assert_eq!(
        inspection_chirho.canonical_identity_chirho(),
        TEST_BOUND_IDENTITY_CHIRHO
    );
    assert!(!root_chirho.join(RESIDENT_WRITER_DIR_CHIRHO).exists());
    drop(resident_chirho);
    std::fs::remove_dir_all(parent_chirho).unwrap();
}

#[cfg(unix)]
#[test]
fn competing_first_lock_provision_reuses_one_durable_inode_chirho() {
    use std::os::unix::fs::MetadataExt;

    let root_chirho = temp_root_chirho("first-lock-race");
    let canonical_root_chirho = root_chirho.canonicalize().unwrap();
    let descriptor_root_chirho =
        DescriptorResidentWriterRootChirho::from_retained_directory_chirho(
            canonical_root_chirho,
            File::open(&root_chirho).unwrap(),
        )
        .unwrap();
    let (control_chirho, created_directory_chirho) =
        descriptor_root_chirho.prepare_control_chirho().unwrap();
    assert!(created_directory_chirho);

    let (first_lock_chirho, first_created_chirho) = control_chirho.provision_lock_chirho().unwrap();
    let (second_lock_chirho, second_created_chirho) =
        control_chirho.provision_lock_chirho().unwrap();
    assert!(first_created_chirho);
    assert!(!second_created_chirho);
    let first_metadata_chirho = first_lock_chirho.metadata().unwrap();
    let second_metadata_chirho = second_lock_chirho.metadata().unwrap();
    assert_eq!(
        (first_metadata_chirho.dev(), first_metadata_chirho.ino()),
        (second_metadata_chirho.dev(), second_metadata_chirho.ino())
    );

    let first_guard_chirho = acquire_descriptor_resident_writer_lock_chirho(
        first_lock_chirho,
        Arc::clone(&control_chirho),
    )
    .unwrap();
    let second_error_chirho = acquire_descriptor_resident_writer_lock_chirho(
        second_lock_chirho,
        Arc::clone(&control_chirho),
    )
    .err()
    .expect("the second descriptor for one lock inode must be refused");
    assert!(
        format!("{second_error_chirho:#}").contains("ResidentWriterAlreadyHeldChirho"),
        "{second_error_chirho:#}"
    );
    drop(first_guard_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[cfg(unix)]
#[test]
fn replaced_control_directory_is_detected_by_lifetime_probe_chirho() {
    let root_chirho = temp_root_chirho("control-replacement");
    let resident_chirho = create_bound_resident_chirho(&root_chirho);
    let control_chirho = root_chirho.join(RESIDENT_WRITER_DIR_CHIRHO);
    let moved_control_chirho = root_chirho.join("resident-writer-moved-chirho");
    std::fs::rename(&control_chirho, &moved_control_chirho).unwrap();
    std::fs::create_dir(&control_chirho).unwrap();

    let error_chirho = resident_chirho.inspect_identity_chirho().unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterControlCustodyChangedChirho"),
        "{error_chirho:#}"
    );
    assert!(std::fs::read_dir(&control_chirho).unwrap().next().is_none());
    drop(resident_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[cfg(unix)]
#[test]
fn resident_control_hard_link_aliases_fail_closed_chirho() {
    for target_chirho in [
        RESIDENT_WRITER_LOCK_FILE_CHIRHO,
        RESIDENT_WRITER_IDENTITY_FILE_CHIRHO,
    ] {
        let root_chirho = temp_root_chirho(target_chirho);
        let (provisioning_chirho, _) =
            reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
        drop(provisioning_chirho);
        let target_path_chirho = root_chirho
            .join(RESIDENT_WRITER_DIR_CHIRHO)
            .join(target_chirho);
        let alias_path_chirho = root_chirho.join(format!("{target_chirho}.alias-chirho"));
        std::fs::hard_link(&target_path_chirho, &alias_path_chirho).unwrap();

        let error_chirho =
            reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap_err();
        assert!(
            format!("{error_chirho:#}").contains("ResidentWriterControlFileUnsafeChirho"),
            "{target_chirho}: {error_chirho:#}"
        );
        std::fs::remove_dir_all(root_chirho).unwrap();
    }
}

#[test]
fn alternate_pending_and_bound_identities_are_refused_without_rebinding_chirho() {
    let root_chirho = temp_root_chirho("alternate");
    let (provisioning_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    drop(provisioning_chirho);

    let alternate_pending_identity_chirho =
        br#"{"schema_chirho":"test-resident-v1-chirho","state_chirho":"pending","coordinate_chirho":"beta"}"#;
    let alternate_pending_chirho = ResidentWriterBindingChirho {
        root_chirho: &root_chirho,
        identity_kind_chirho: TEST_IDENTITY_KIND_CHIRHO,
        canonical_identity_chirho: alternate_pending_identity_chirho,
    };
    let error_chirho = reserve_resident_writer_chirho(&alternate_pending_chirho).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterIdentityMismatchChirho"),
        "{error_chirho:#}"
    );

    let (recovered_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    let resident_chirho = recovered_chirho
        .bind_resident_writer_chirho(&bound_binding_chirho(&root_chirho))
        .unwrap();
    drop(resident_chirho);
    let alternate_bound_identity_chirho =
        br#"{"schema_chirho":"test-resident-v1-chirho","state_chirho":"bound","coordinate_chirho":"beta"}"#;
    let alternate_bound_chirho = ResidentWriterBindingChirho {
        root_chirho: &root_chirho,
        identity_kind_chirho: TEST_IDENTITY_KIND_CHIRHO,
        canonical_identity_chirho: alternate_bound_identity_chirho,
    };
    let error_chirho = open_resident_writer_chirho(&alternate_bound_chirho).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterIdentityMismatchChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn pending_to_bound_transition_is_an_exact_compare_and_swap_chirho() {
    let root_chirho = temp_root_chirho("exact-cas");
    let (provisioning_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    let foreign_pending_identity_chirho =
        br#"{"schema_chirho":"test-resident-v1-chirho","state_chirho":"pending","coordinate_chirho":"foreign"}"#;
    let foreign_pending_chirho = ResidentWriterBindingChirho {
        root_chirho: &root_chirho,
        identity_kind_chirho: TEST_IDENTITY_KIND_CHIRHO,
        canonical_identity_chirho: foreign_pending_identity_chirho,
    };
    let foreign_record_chirho =
        PreparedResidentWriterBindingChirho::new_chirho(&foreign_pending_chirho)
            .unwrap()
            .record_chirho;
    let identity_path_chirho = resident_writer_identity_path_chirho(&root_chirho).unwrap();
    write_identity_record_chirho(&identity_path_chirho, &foreign_record_chirho).unwrap();

    let error_chirho = provisioning_chirho
        .bind_resident_writer_chirho(&bound_binding_chirho(&root_chirho))
        .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterPendingIdentityMismatchChirho"),
        "{error_chirho:#}"
    );
    let error_chirho =
        open_resident_writer_chirho(&bound_binding_chirho(&root_chirho)).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterIdentityMismatchChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn inspected_bound_identity_changed_before_exact_open_is_refused_chirho() {
    let root_chirho = temp_root_chirho("inspect-race");
    initialize_bound_chirho(&root_chirho);
    let inspected_chirho = inspect_resident_writer_identity_chirho(&root_chirho).unwrap();
    assert_eq!(
        inspected_chirho.canonical_identity_chirho(),
        TEST_BOUND_IDENTITY_CHIRHO
    );

    let replacement_identity_chirho =
        br#"{"schema_chirho":"test-resident-v1-chirho","state_chirho":"bound","coordinate_chirho":"replacement"}"#;
    let replacement_chirho = ResidentWriterBindingChirho {
        root_chirho: &root_chirho,
        identity_kind_chirho: TEST_IDENTITY_KIND_CHIRHO,
        canonical_identity_chirho: replacement_identity_chirho,
    };
    let replacement_record_chirho =
        PreparedResidentWriterBindingChirho::new_chirho(&replacement_chirho)
            .unwrap()
            .record_chirho;
    let identity_path_chirho = resident_writer_identity_path_chirho(&root_chirho).unwrap();
    write_identity_record_chirho(&identity_path_chirho, &replacement_record_chirho).unwrap();

    let error_chirho =
        open_resident_writer_chirho(&inspected_chirho.as_binding_chirho()).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterIdentityMismatchChirho"),
        "{error_chirho:#}"
    );
    let replacement_resident_chirho = open_resident_writer_chirho(&replacement_chirho).unwrap();
    drop(replacement_resident_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn bound_inspect_and_open_never_repair_a_missing_identity_chirho() {
    let root_chirho = temp_root_chirho("bound-missing");
    initialize_bound_chirho(&root_chirho);
    let identity_path_chirho = resident_writer_identity_path_chirho(&root_chirho).unwrap();
    std::fs::remove_file(&identity_path_chirho).unwrap();

    let inspect_error_chirho = inspect_resident_writer_identity_chirho(&root_chirho).unwrap_err();
    assert!(
        format!("{inspect_error_chirho:#}")
            .contains("ResidentWriterIdentityMissingOrUnreadableChirho"),
        "{inspect_error_chirho:#}"
    );
    let open_error_chirho =
        open_resident_writer_chirho(&bound_binding_chirho(&root_chirho)).unwrap_err();
    assert!(
        format!("{open_error_chirho:#}")
            .contains("ResidentWriterIdentityMissingOrUnreadableChirho"),
        "{open_error_chirho:#}"
    );
    assert!(!identity_path_chirho.exists());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn truncated_corrupt_bound_and_identity_without_marker_fail_closed_chirho() {
    for (label_chirho, replacement_chirho) in [
        ("truncated", br#"{"schema_chirho":"#.as_slice()),
        (
            "corrupt-digest",
            br#"{"schema_chirho":"resident-writer-identity-v1-chirho","identity_kind_chirho":"test-resident-writer-chirho","canonical_identity_hex_chirho":"00","identity_digest_chirho":"resident-writer-identity-blake3-v1-chirho:bad"}"#
                .as_slice(),
        ),
    ] {
        let root_chirho = temp_root_chirho(label_chirho);
        let (provisioning_chirho, _) =
            reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
        drop(provisioning_chirho);
        let identity_path_chirho = resident_writer_identity_path_chirho(&root_chirho).unwrap();
        std::fs::write(&identity_path_chirho, replacement_chirho).unwrap();
        let error_chirho =
            reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap_err();
        assert!(
            format!("{error_chirho:#}").contains("ResidentWriterIdentity"),
            "{label_chirho}: {error_chirho:#}"
        );
        std::fs::remove_dir_all(root_chirho).unwrap();
    }

    let root_chirho = temp_root_chirho("bound-not-pending");
    initialize_bound_chirho(&root_chirho);
    let error_chirho =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterIdentityMismatchChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();

    let root_chirho = temp_root_chirho("missing-marker");
    let (provisioning_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    drop(provisioning_chirho);
    let lock_path_chirho = root_chirho
        .join(RESIDENT_WRITER_DIR_CHIRHO)
        .join(RESIDENT_WRITER_LOCK_FILE_CHIRHO);
    std::fs::remove_file(&lock_path_chirho).unwrap();
    let error_chirho =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap_err();
    assert!(
        format!("{error_chirho:#}")
            .contains("ResidentWriterIdentityWithoutReservationMarkerChirho"),
        "{error_chirho:#}"
    );
    assert!(!lock_path_chirho.exists());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn identity_input_and_record_reads_are_bounded_chirho() {
    let root_chirho = temp_root_chirho("bounds");
    let oversized_chirho = vec![b'x'; MAX_RESIDENT_WRITER_IDENTITY_BYTES_CHIRHO + 1];
    let oversized_binding_chirho = ResidentWriterBindingChirho {
        root_chirho: &root_chirho,
        identity_kind_chirho: TEST_IDENTITY_KIND_CHIRHO,
        canonical_identity_chirho: &oversized_chirho,
    };
    assert!(reserve_resident_writer_chirho(&oversized_binding_chirho)
        .unwrap_err()
        .to_string()
        .contains("ResidentWriterIdentityBoundsChirho"));

    let (provisioning_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    drop(provisioning_chirho);
    let identity_path_chirho = resident_writer_identity_path_chirho(&root_chirho).unwrap();
    std::fs::write(
        &identity_path_chirho,
        vec![b'x'; MAX_RESIDENT_WRITER_RECORD_BYTES_CHIRHO + 1],
    )
    .unwrap();
    let error_chirho =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("record exceeds byte cap"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[cfg(unix)]
#[test]
fn control_directory_and_filesystem_symlinks_fail_closed_chirho() {
    use std::os::unix::fs::symlink;

    let root_chirho = temp_root_chirho("control-dir-symlink");
    let outside_chirho = temp_root_chirho("control-dir-outside");
    symlink(
        &outside_chirho,
        root_chirho.join(RESIDENT_WRITER_DIR_CHIRHO),
    )
    .unwrap();
    let error_chirho =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterControlDirectoryUnsafeChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(&root_chirho).unwrap();
    std::fs::remove_dir_all(&outside_chirho).unwrap();

    let root_chirho = temp_root_chirho("identity-symlink");
    let (provisioning_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    drop(provisioning_chirho);
    let identity_path_chirho = resident_writer_identity_path_chirho(&root_chirho).unwrap();
    let outside_file_chirho = root_chirho.join("outside-identity-chirho");
    std::fs::write(&outside_file_chirho, b"outside-chirho").unwrap();
    std::fs::remove_file(&identity_path_chirho).unwrap();
    symlink(&outside_file_chirho, &identity_path_chirho).unwrap();
    let error_chirho =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterControlFileUnsafeChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();

    let root_chirho = temp_root_chirho("lock-symlink");
    let (provisioning_chirho, _) =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap();
    drop(provisioning_chirho);
    let lock_path_chirho = root_chirho
        .join(RESIDENT_WRITER_DIR_CHIRHO)
        .join(RESIDENT_WRITER_LOCK_FILE_CHIRHO);
    let outside_file_chirho = root_chirho.join("outside-lock-chirho");
    std::fs::write(&outside_file_chirho, b"outside-chirho").unwrap();
    std::fs::remove_file(&lock_path_chirho).unwrap();
    symlink(&outside_file_chirho, &lock_path_chirho).unwrap();
    let error_chirho =
        reserve_resident_writer_chirho(&pending_binding_chirho(&root_chirho)).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterControlFileUnsafeChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn resident_writer_cross_process_refusal_helper_chirho() {
    let (Ok(root_chirho), Ok(action_chirho), Ok(evidence_chirho)) = (
        std::env::var(CHILD_ROOT_ENV_CHIRHO),
        std::env::var(CHILD_ACTION_ENV_CHIRHO),
        std::env::var(CHILD_EVIDENCE_ENV_CHIRHO),
    ) else {
        return;
    };
    let root_chirho = Path::new(&root_chirho);
    let error_chirho = match action_chirho.as_str() {
        CHILD_RESERVE_ACTION_CHIRHO => {
            reserve_resident_writer_chirho(&pending_binding_chirho(root_chirho)).unwrap_err()
        }
        CHILD_OPEN_ACTION_CHIRHO => {
            open_resident_writer_chirho(&bound_binding_chirho(root_chirho)).unwrap_err()
        }
        _ => panic!("unknown child action {action_chirho}"),
    };
    assert!(
        format!("{error_chirho:#}").contains("ResidentWriterAlreadyHeldChirho"),
        "{error_chirho:#}"
    );
    std::fs::write(evidence_chirho, action_chirho).unwrap();
}

#[test]
fn resident_writer_cross_process_holder_helper_chirho() {
    let (Ok(root_chirho), Ok(ready_chirho), Ok(release_chirho)) = (
        std::env::var(CHILD_ROOT_ENV_CHIRHO),
        std::env::var(CHILD_READY_ENV_CHIRHO),
        std::env::var(CHILD_RELEASE_ENV_CHIRHO),
    ) else {
        return;
    };
    let resident_chirho =
        open_resident_writer_chirho(&bound_binding_chirho(Path::new(&root_chirho))).unwrap();
    std::fs::write(&ready_chirho, b"ready-chirho").unwrap();
    wait_for_path_chirho(Path::new(&release_chirho));
    drop(resident_chirho);
}

#[test]
fn lifetime_file_lock_refuses_another_process_chirho() {
    let root_chirho = temp_root_chirho("cross-process");
    initialize_bound_chirho(&root_chirho);
    let ready_chirho = root_chirho.join("child-ready-chirho");
    let release_chirho = root_chirho.join("child-release-chirho");
    let child_chirho = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(
            "resident_writer_chirho::tests_chirho::resident_writer_cross_process_holder_helper_chirho",
        )
        .arg("--nocapture")
        .env(CHILD_ROOT_ENV_CHIRHO, &root_chirho)
        .env(CHILD_READY_ENV_CHIRHO, &ready_chirho)
        .env(CHILD_RELEASE_ENV_CHIRHO, &release_chirho)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_path_chirho(&ready_chirho);
    assert_already_held_chirho(open_resident_writer_chirho(&bound_binding_chirho(
        &root_chirho,
    )));
    std::fs::write(&release_chirho, b"release-chirho").unwrap();
    let output_chirho = child_chirho.wait_with_output().unwrap();
    assert!(
        output_chirho.status.success(),
        "{}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    let reopened_chirho = open_resident_writer_chirho(&bound_binding_chirho(&root_chirho)).unwrap();
    drop(reopened_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}
