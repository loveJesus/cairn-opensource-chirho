// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The in-process open lock: concurrent opens of one store serialize instead of colliding, a nested open on the same
//! thread refuses by name instead of hanging, other paths are untouched, and the wait is bounded.

use super::StoreOpenGuardChirho;
use crate::versioned_chirho::VersionedStoreChirho;
use crate::viewer_state_chirho::ViewerStateStoreChirho;
use crate::RedbStateAuditStoreChirho;
use std::sync::{Arc, Barrier};
use std::time::Duration;

/// THE COLLISION THIS PREVENTS. Eight threads open the same versioned store at the same instant and each writes; every
/// open succeeds (they take turns), where redb's own lock refused all but one with `DatabaseAlreadyOpen`.
///
/// MIGRATION PATH: an error naming `DatabaseAlreadyOpen` means the constructors no longer take the open lock.
#[test]
fn concurrent_opens_of_one_store_take_turns_instead_of_colliding_chirho() {
    let dir_chirho = tempfile::tempdir().unwrap();
    let path_chirho = dir_chirho.path().join("versioned-chirho.redb");
    VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
    let start_chirho = Arc::new(Barrier::new(8));
    let handles_chirho: Vec<_> = (0..8)
        .map(|index_chirho| {
            let path_chirho = path_chirho.clone();
            let start_chirho = Arc::clone(&start_chirho);
            std::thread::spawn(move || {
                start_chirho.wait();
                let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho)
                    .map_err(|error_chirho| format!("{error_chirho:#}"))?;
                store_chirho
                    .put_chirho(&format!("key-{index_chirho}"), b"value")
                    .map_err(|error_chirho| format!("{error_chirho:#}"))?;
                Ok::<(), String>(())
            })
        })
        .collect();
    for handle_chirho in handles_chirho {
        handle_chirho
            .join()
            .unwrap()
            .expect("every concurrent open takes its turn");
    }
    let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
    for index_chirho in 0..8 {
        assert_eq!(
            store_chirho
                .get_chirho(&format!("key-{index_chirho}"))
                .unwrap()
                .as_deref(),
            Some(&b"value"[..]),
            "every thread's write landed"
        );
    }
}

/// A second open while the first handle is held, on another thread, WAITS for it to drop and then proceeds.
#[test]
fn an_open_waits_for_the_held_handle_then_proceeds_chirho() {
    let dir_chirho = tempfile::tempdir().unwrap();
    let path_chirho = dir_chirho.path().join("viewer-state-chirho.redb");
    let first_chirho = ViewerStateStoreChirho::open_chirho(&path_chirho).unwrap();
    let (opened_tx_chirho, opened_rx_chirho) = std::sync::mpsc::channel();
    let waiter_path_chirho = path_chirho.clone();
    let waiter_chirho = std::thread::spawn(move || {
        let store_chirho = ViewerStateStoreChirho::open_chirho(&waiter_path_chirho);
        opened_tx_chirho.send(()).unwrap();
        store_chirho
            .map(|_| ())
            .map_err(|error_chirho| format!("{error_chirho:#}"))
    });
    assert!(
        opened_rx_chirho
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "the second open must wait while the first handle is held"
    );
    drop(first_chirho);
    opened_rx_chirho
        .recv_timeout(Duration::from_secs(10))
        .expect("the second open proceeds once the first handle drops");
    waiter_chirho.join().unwrap().expect("and it succeeds");
}

/// A nested open of the same store on the SAME thread refuses by name. It failed before with redb's lock; it must
/// not become a hang.
#[test]
fn a_nested_open_on_the_same_thread_refuses_instead_of_hanging_chirho() {
    let dir_chirho = tempfile::tempdir().unwrap();
    let path_chirho = dir_chirho.path().join("state-audit-chirho.redb");
    let _first_chirho = RedbStateAuditStoreChirho::open_chirho(&path_chirho).unwrap();
    let refusal_chirho = RedbStateAuditStoreChirho::open_chirho(&path_chirho)
        .err()
        .expect("a nested open on the same thread must refuse");
    assert!(
        format!("{refusal_chirho:#}").contains("already open on this thread"),
        "the refusal names the nesting: {refusal_chirho:#}"
    );
}

/// Different store files do not serialize: holding one leaves another free.
#[test]
fn different_store_paths_do_not_wait_on_each_other_chirho() {
    let dir_chirho = tempfile::tempdir().unwrap();
    let _held_chirho =
        VersionedStoreChirho::open_chirho(&dir_chirho.path().join("a-chirho.redb")).unwrap();
    let other_path_chirho = dir_chirho.path().join("b-chirho.redb");
    let other_chirho = std::thread::spawn(move || {
        VersionedStoreChirho::open_chirho(&other_path_chirho).map(|_| ())
    });
    other_chirho
        .join()
        .unwrap()
        .expect("another store path opens while the first is held");
}

/// Two spellings of one file are one lock: a path through a symlinked directory waits on the canonical path's holder.
#[test]
fn two_spellings_of_one_store_share_one_lock_chirho() {
    let dir_chirho = tempfile::tempdir().unwrap();
    let real_chirho = dir_chirho.path().join("real-chirho");
    std::fs::create_dir_all(&real_chirho).unwrap();
    let link_chirho = dir_chirho.path().join("link-chirho");
    std::os::unix::fs::symlink(&real_chirho, &link_chirho).unwrap();
    let _held_chirho =
        StoreOpenGuardChirho::acquire_chirho(&real_chirho.join("s-chirho.redb")).unwrap();
    let refusal_chirho = StoreOpenGuardChirho::acquire_chirho(&link_chirho.join("s-chirho.redb"))
        .err()
        .expect("the same file through a symlinked directory is the same lock");
    assert!(format!("{refusal_chirho:#}").contains("already open on this thread"));
}

/// The wait is bounded: a holder that never drops makes the next open refuse after the limit, never hang.
#[test]
fn the_wait_for_a_held_store_is_bounded_chirho() {
    let dir_chirho = tempfile::tempdir().unwrap();
    let path_chirho = dir_chirho.path().join("held-chirho.redb");
    std::fs::write(&path_chirho, b"").unwrap();
    let _held_chirho = StoreOpenGuardChirho::acquire_chirho(&path_chirho).unwrap();
    let waiter_path_chirho = path_chirho.clone();
    let refusal_chirho = std::thread::spawn(move || {
        StoreOpenGuardChirho::acquire_within_chirho(&waiter_path_chirho, Duration::from_millis(200))
            .err()
            .map(|error_chirho| format!("{error_chirho:#}"))
    })
    .join()
    .unwrap()
    .expect("a held store refuses the waiter after the limit");
    assert!(
        refusal_chirho.contains("stayed open elsewhere in this process"),
        "the refusal names the wait: {refusal_chirho}"
    );
}
