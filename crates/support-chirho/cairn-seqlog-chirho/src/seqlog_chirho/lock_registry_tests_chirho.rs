// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must follow the Unix epoch")
        .as_nanos();
    let sequence_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-seqlog-lock-registry-{label_chirho}-{}-{nanos_chirho}-{sequence_chirho}",
        std::process::id()
    ))
}

#[test]
fn live_entries_share_one_lock_and_final_arc_evicts_chirho() {
    let registry_chirho = Arc::new(LocalLockRegistryChirho::new_chirho());
    let path_chirho = PathBuf::from("/virtual-chirho/live-entry-chirho.lock");
    let first_chirho = registry_chirho.lock_for_path_chirho(&path_chirho).unwrap();
    let second_chirho = registry_chirho.lock_for_path_chirho(&path_chirho).unwrap();
    let entry_weak_chirho = Arc::downgrade(&first_chirho);

    assert!(Arc::ptr_eq(&first_chirho, &second_chirho));
    assert!(registry_chirho
        .weak_for_path_chirho(&path_chirho)
        .is_some_and(|current_chirho| Weak::ptr_eq(&current_chirho, &entry_weak_chirho)));

    drop(first_chirho);
    assert!(entry_weak_chirho.upgrade().is_some());
    drop(second_chirho);

    assert!(entry_weak_chirho.upgrade().is_none());
    assert!(registry_chirho.weak_for_path_chirho(&path_chirho).is_none());
}

#[test]
fn waiting_owner_prevents_eviction_and_reuses_exact_entry_chirho() {
    let registry_chirho = Arc::new(LocalLockRegistryChirho::new_chirho());
    let path_chirho = PathBuf::from("/virtual-chirho/waiter-entry-chirho.lock");
    let first_chirho = registry_chirho.lock_for_path_chirho(&path_chirho).unwrap();
    let first_guard_chirho = first_chirho.lock_chirho.lock().unwrap();
    let (acquired_sender_chirho, acquired_receiver_chirho) = mpsc::channel();
    let (entered_sender_chirho, entered_receiver_chirho) = mpsc::channel();
    let (release_sender_chirho, release_receiver_chirho) = mpsc::channel();
    let contender_registry_chirho = Arc::clone(&registry_chirho);
    let contender_path_chirho = path_chirho.clone();

    let contender_thread_chirho = thread::spawn(move || {
        let contender_chirho = contender_registry_chirho
            .lock_for_path_chirho(&contender_path_chirho)
            .unwrap();
        acquired_sender_chirho
            .send(Arc::downgrade(&contender_chirho))
            .unwrap();
        let _contender_guard_chirho = contender_chirho.lock_chirho.lock().unwrap();
        entered_sender_chirho.send(()).unwrap();
        release_receiver_chirho.recv().unwrap();
    });

    let contender_weak_chirho = acquired_receiver_chirho.recv().unwrap();
    let contender_snapshot_chirho = contender_weak_chirho.upgrade().unwrap();
    assert!(Arc::ptr_eq(&first_chirho, &contender_snapshot_chirho));
    drop(contender_snapshot_chirho);

    drop(first_guard_chirho);
    drop(first_chirho);
    entered_receiver_chirho.recv().unwrap();

    let active_contender_chirho = contender_weak_chirho.upgrade().unwrap();
    let third_chirho = registry_chirho.lock_for_path_chirho(&path_chirho).unwrap();
    assert!(Arc::ptr_eq(&active_contender_chirho, &third_chirho));
    drop(active_contender_chirho);
    drop(third_chirho);

    release_sender_chirho.send(()).unwrap();
    contender_thread_chirho.join().unwrap();
    assert!(contender_weak_chirho.upgrade().is_none());
    assert!(registry_chirho.weak_for_path_chirho(&path_chirho).is_none());
}

#[test]
fn stale_entry_drop_cannot_remove_replacement_chirho() {
    let registry_chirho = Arc::new(LocalLockRegistryChirho::new_chirho());
    let path_chirho = PathBuf::from("/virtual-chirho/replacement-entry-chirho.lock");
    let old_entry_chirho = registry_chirho.lock_for_path_chirho(&path_chirho).unwrap();
    let old_weak_chirho = Arc::downgrade(&old_entry_chirho);
    let shard_index_chirho = registry_chirho.shard_index_chirho(&path_chirho);
    let replacement_entry_chirho = Arc::new(LocalPathLockEntryChirho {
        registry_chirho: Arc::downgrade(&registry_chirho),
        path_chirho: path_chirho.clone(),
        shard_index_chirho,
        lock_chirho: Mutex::new(()),
    });
    registry_chirho.shards_chirho[shard_index_chirho]
        .lock()
        .unwrap()
        .insert(
            path_chirho.clone(),
            Arc::downgrade(&replacement_entry_chirho),
        );

    drop(old_entry_chirho);
    assert!(old_weak_chirho.upgrade().is_none());
    let current_entry_chirho = registry_chirho
        .weak_for_path_chirho(&path_chirho)
        .and_then(|current_chirho| current_chirho.upgrade())
        .unwrap();
    assert!(Arc::ptr_eq(
        &current_entry_chirho,
        &replacement_entry_chirho
    ));

    drop(current_entry_chirho);
    drop(replacement_entry_chirho);
    assert!(registry_chirho.weak_for_path_chirho(&path_chirho).is_none());
}

#[test]
fn historical_paths_evict_and_empty_shards_bound_idle_capacity_chirho() {
    let registry_chirho = Arc::new(LocalLockRegistryChirho::new_chirho());
    let target_shard_chirho =
        registry_chirho.shard_index_chirho(Path::new("/virtual-chirho/target-shard-chirho.lock"));
    let desired_entries_chirho = LOCAL_LOCK_IDLE_CAPACITY_PER_SHARD_CHIRHO + 65;
    let mut candidate_index_chirho = 0_u64;
    let mut target_paths_chirho = Vec::new();
    while target_paths_chirho.len() < desired_entries_chirho {
        let path_chirho = PathBuf::from(format!(
            "/virtual-chirho/high-cardinality-{candidate_index_chirho}.lock"
        ));
        if registry_chirho.shard_index_chirho(&path_chirho) == target_shard_chirho {
            target_paths_chirho.push(path_chirho);
        }
        candidate_index_chirho += 1;
        assert!(
            candidate_index_chirho < 1_000_000,
            "fixed-shard test failed to find enough paths"
        );
    }

    let mut live_entries_chirho = Vec::new();
    for path_chirho in &target_paths_chirho {
        live_entries_chirho.push(registry_chirho.lock_for_path_chirho(path_chirho).unwrap());
    }
    assert_eq!(
        registry_chirho.shard_shape_chirho(target_shard_chirho).0,
        desired_entries_chirho
    );
    drop(live_entries_chirho);

    let (idle_entries_chirho, idle_capacity_chirho) =
        registry_chirho.shard_shape_chirho(target_shard_chirho);
    assert_eq!(idle_entries_chirho, 0);
    assert!(idle_capacity_chirho <= LOCAL_LOCK_IDLE_CAPACITY_PER_SHARD_CHIRHO);

    for historical_index_chirho in 0..2_048_u64 {
        let path_chirho = PathBuf::from(format!(
            "/virtual-chirho/historical-{historical_index_chirho}.lock"
        ));
        let entry_chirho = registry_chirho.lock_for_path_chirho(&path_chirho).unwrap();
        drop(entry_chirho);
        assert!(registry_chirho.weak_for_path_chirho(&path_chirho).is_none());
    }
    for shard_index_chirho in 0..LOCAL_LOCK_SHARD_COUNT_CHIRHO {
        let (entries_chirho, capacity_chirho) =
            registry_chirho.shard_shape_chirho(shard_index_chirho);
        assert_eq!(entries_chirho, 0);
        assert!(capacity_chirho <= LOCAL_LOCK_IDLE_CAPACITY_PER_SHARD_CHIRHO);
    }
}

#[test]
fn canonical_lock_paths_collapse_dot_aliases_chirho() {
    let root_chirho = temp_root_chirho("alias");
    let alias_root_chirho = root_chirho.join(".");
    let direct_path_chirho = canonical_lock_path_chirho(&root_chirho, "alias-lock-chirho").unwrap();
    let alias_path_chirho =
        canonical_lock_path_chirho(&alias_root_chirho, "alias-lock-chirho").unwrap();
    assert_eq!(direct_path_chirho, alias_path_chirho);

    let direct_entry_chirho = local_lock_for_path_chirho(&direct_path_chirho).unwrap();
    let alias_entry_chirho = local_lock_for_path_chirho(&alias_path_chirho).unwrap();
    assert!(Arc::ptr_eq(&direct_entry_chirho, &alias_entry_chirho));
    drop(direct_entry_chirho);
    drop(alias_entry_chirho);
    assert!(local_lock_registry_chirho()
        .weak_for_path_chirho(&direct_path_chirho)
        .is_none());

    let _cleanup_chirho = std::fs::remove_dir_all(root_chirho);
}

#[cfg(unix)]
#[test]
fn canonical_lock_paths_collapse_symlink_aliases_chirho() {
    use std::os::unix::fs::symlink;

    let parent_chirho = temp_root_chirho("symlink-alias");
    let root_chirho = parent_chirho.join("root-chirho");
    let alias_root_chirho = parent_chirho.join("root-alias-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    symlink(&root_chirho, &alias_root_chirho).unwrap();

    let direct_path_chirho = canonical_lock_path_chirho(&root_chirho, "alias-lock-chirho").unwrap();
    let alias_path_chirho =
        canonical_lock_path_chirho(&alias_root_chirho, "alias-lock-chirho").unwrap();
    assert_eq!(direct_path_chirho, alias_path_chirho);

    let direct_entry_chirho = local_lock_for_path_chirho(&direct_path_chirho).unwrap();
    let alias_entry_chirho = local_lock_for_path_chirho(&alias_path_chirho).unwrap();
    assert!(Arc::ptr_eq(&direct_entry_chirho, &alias_entry_chirho));
    drop(direct_entry_chirho);
    drop(alias_entry_chirho);
    assert!(local_lock_registry_chirho()
        .weak_for_path_chirho(&direct_path_chirho)
        .is_none());

    let _cleanup_chirho = std::fs::remove_dir_all(parent_chirho);
}

#[test]
fn panic_unwind_evicts_poisoned_entry_and_allows_fresh_lock_chirho() {
    let root_chirho = temp_root_chirho("panic");
    let lock_name_chirho = "panic-lock-chirho";
    let lock_path_chirho = canonical_lock_path_chirho(&root_chirho, lock_name_chirho).unwrap();
    let panic_result_chirho = catch_unwind(AssertUnwindSafe(|| {
        let _result_chirho: Result<()> =
            with_named_lock_chirho(&root_chirho, lock_name_chirho, || -> Result<()> {
                panic!("intentional named-lock test panic")
            });
    }));
    assert!(panic_result_chirho.is_err());
    assert!(local_lock_registry_chirho()
        .weak_for_path_chirho(&lock_path_chirho)
        .is_none());

    with_named_lock_chirho(&root_chirho, lock_name_chirho, || Ok(())).unwrap();
    assert!(local_lock_registry_chirho()
        .weak_for_path_chirho(&lock_path_chirho)
        .is_none());
    let _cleanup_chirho = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn existing_read_lock_never_creates_missing_lock_state_chirho() {
    let root_chirho = temp_root_chirho("existing-read");
    let lock_name_chirho = "existing-read-lock-chirho";
    with_named_lock_chirho(&root_chirho, lock_name_chirho, || Ok(())).unwrap();

    let value_chirho =
        with_existing_named_read_lock_chirho(&root_chirho, lock_name_chirho, || Ok(42_u64))
            .unwrap();
    assert_eq!(value_chirho, 42);

    let locks_dir_chirho = locks_dir_chirho(&root_chirho);
    std::fs::remove_dir_all(&locks_dir_chirho).unwrap();
    assert!(
        with_existing_named_read_lock_chirho(&root_chirho, lock_name_chirho, || Ok(())).is_err()
    );
    assert!(
        !locks_dir_chirho.exists(),
        "an existing-only read lock must refuse rather than recreate synchronization state"
    );
    let _cleanup_chirho = std::fs::remove_dir_all(root_chirho);
}
