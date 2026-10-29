// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for publication's fast path: a present, verified object is returned with nothing written,
//! and every other case keeps the outcome today's full path gives, including races at the moment
//! between the look and the open.

use super::tests_chirho::{object_path_chirho, temp_parent_chirho};
use super::*;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

fn shard_listing_chirho(shard_chirho: &Path) -> Vec<String> {
    let mut names_chirho: Vec<String> = fs::read_dir(shard_chirho)
        .unwrap()
        .map(|entry_chirho| {
            entry_chirho
                .unwrap()
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names_chirho.sort();
    names_chirho
}

fn published_root_chirho(label_chirho: &str, bytes_chirho: &[u8]) -> (PathBuf, String, PathBuf) {
    let root_chirho = temp_parent_chirho(label_chirho);
    fs::create_dir_all(&root_chirho).unwrap();
    let address_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    publish_content_addressed_file_at_root_no_replace_chirho(
        &root_chirho,
        &address_chirho,
        bytes_chirho,
    )
    .unwrap();
    let object_chirho = object_path_chirho(&root_chirho, &address_chirho);
    (root_chirho, address_chirho, object_chirho)
}

/// Publishes once with `between_chirho` run at the hold point between the look and the open, and
/// reports whether the hold point fired.
fn publish_with_hold_point_chirho(
    root_chirho: &Path,
    address_chirho: &str,
    bytes_chirho: &[u8],
    between_chirho: impl Fn() + 'static,
) -> (CasLifecycleResultChirho<()>, bool) {
    let fired_chirho = std::rc::Rc::new(std::cell::Cell::new(false));
    let hook_fired_chirho = std::rc::Rc::clone(&fired_chirho);
    AFTER_EXISTING_OBJECT_LOOK_CHIRHO.with(|hook_chirho| {
        *hook_chirho.borrow_mut() = Some(Box::new(move || {
            between_chirho();
            hook_fired_chirho.set(true);
        }));
    });
    let result_chirho = publish_content_addressed_file_at_root_no_replace_chirho(
        root_chirho,
        address_chirho,
        bytes_chirho,
    );
    AFTER_EXISTING_OBJECT_LOOK_CHIRHO.with(|hook_chirho| *hook_chirho.borrow_mut() = None);
    (result_chirho, fired_chirho.get())
}

#[test]
fn repeat_publication_of_a_present_object_writes_nothing_chirho() {
    let bytes_chirho = b"a stone already in the cairn chirho";
    let (root_chirho, address_chirho, object_chirho) =
        published_root_chirho("repeat-writes-nothing", bytes_chirho);
    let shard_chirho = object_chirho.parent().unwrap().to_path_buf();
    let object_before_chirho = fs::metadata(&object_chirho).unwrap();
    let shard_before_chirho = fs::metadata(&shard_chirho).unwrap();
    let listing_before_chirho = shard_listing_chirho(&shard_chirho);
    // A temp made and unlinked in the shard would move its modification time; give the clock room
    // to show it.
    thread::sleep(Duration::from_millis(20));
    publish_content_addressed_file_at_root_no_replace_chirho(
        &root_chirho,
        &address_chirho,
        bytes_chirho,
    )
    .unwrap();
    let shard_after_chirho = fs::metadata(&shard_chirho).unwrap();
    assert_eq!(
        object_before_chirho.ino(),
        fs::metadata(&object_chirho).unwrap().ino()
    );
    assert_eq!(
        (
            shard_before_chirho.mtime(),
            shard_before_chirho.mtime_nsec()
        ),
        (shard_after_chirho.mtime(), shard_after_chirho.mtime_nsec()),
        "a repeat publish of a present, verified object must not touch its shard"
    );
    assert_eq!(listing_before_chirho, shard_listing_chirho(&shard_chirho));
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_unreadable_object_in_place_refuses_and_is_not_replaced_chirho() {
    let root_chirho = temp_parent_chirho("unreadable-in-place");
    let bytes_chirho = b"a stone that cannot be read chirho";
    let address_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    let object_chirho = object_path_chirho(&root_chirho, &address_chirho);
    fs::create_dir_all(&object_chirho).unwrap();
    let error_chirho = publish_content_addressed_file_at_root_no_replace_chirho(
        &root_chirho,
        &address_chirho,
        bytes_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.kind_chirho(),
        CasLifecycleErrorKindChirho::UnavailableChirho
    );
    assert!(
        fs::metadata(&object_chirho).unwrap().is_dir(),
        "the directory in its place stays"
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_object_gone_between_the_look_and_the_open_is_published_chirho() {
    let bytes_chirho = b"a stone carried off by a collector chirho";
    let (root_chirho, address_chirho, object_chirho) =
        published_root_chirho("gone-between", bytes_chirho);
    let hook_object_chirho = object_chirho.clone();
    let (result_chirho, fired_chirho) =
        publish_with_hold_point_chirho(&root_chirho, &address_chirho, bytes_chirho, move || {
            fs::remove_file(&hook_object_chirho).unwrap();
        });
    assert!(
        fired_chirho,
        "the hold point fired between the look and the open"
    );
    result_chirho.unwrap();
    assert_eq!(fs::read(&object_chirho).unwrap(), bytes_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_object_recreated_between_the_look_and_the_open_is_verified_chirho() {
    let bytes_chirho = b"a stone set back by another hand chirho";
    let (root_chirho, address_chirho, object_chirho) =
        published_root_chirho("recreated-between", bytes_chirho);
    let hook_object_chirho = object_chirho.clone();
    let hook_bytes_chirho = bytes_chirho.to_vec();
    let (result_chirho, fired_chirho) =
        publish_with_hold_point_chirho(&root_chirho, &address_chirho, bytes_chirho, move || {
            fs::remove_file(&hook_object_chirho).unwrap();
            fs::write(&hook_object_chirho, &hook_bytes_chirho).unwrap();
        });
    assert!(fired_chirho);
    result_chirho.unwrap();
    assert_eq!(fs::read(&object_chirho).unwrap(), bytes_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn wrong_bytes_put_between_the_look_and_the_open_refuse_as_a_corrupt_winner_chirho() {
    let bytes_chirho = b"a stone swapped for a false one chirho";
    let (root_chirho, address_chirho, object_chirho) =
        published_root_chirho("wrong-between", bytes_chirho);
    let hook_object_chirho = object_chirho.clone();
    let (result_chirho, fired_chirho) =
        publish_with_hold_point_chirho(&root_chirho, &address_chirho, bytes_chirho, move || {
            fs::remove_file(&hook_object_chirho).unwrap();
            fs::write(&hook_object_chirho, b"false stone chirho").unwrap();
        });
    assert!(fired_chirho);
    assert_eq!(
        result_chirho.unwrap_err().kind_chirho(),
        CasLifecycleErrorKindChirho::CorruptWinnerChirho
    );
    assert_eq!(
        fs::read(&object_chirho).unwrap(),
        b"false stone chirho",
        "a corrupt winner is never overwritten"
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_directory_put_between_the_look_and_the_open_refuses_and_stays_chirho() {
    let bytes_chirho = b"a stone whose place was taken chirho";
    let (root_chirho, address_chirho, object_chirho) =
        published_root_chirho("directory-between", bytes_chirho);
    let hook_object_chirho = object_chirho.clone();
    let (result_chirho, fired_chirho) =
        publish_with_hold_point_chirho(&root_chirho, &address_chirho, bytes_chirho, move || {
            fs::remove_file(&hook_object_chirho).unwrap();
            fs::create_dir(&hook_object_chirho).unwrap();
        });
    assert!(fired_chirho);
    assert_eq!(
        result_chirho.unwrap_err().kind_chirho(),
        CasLifecycleErrorKindChirho::UnavailableChirho
    );
    assert!(fs::metadata(&object_chirho).unwrap().is_dir());
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn concurrent_repeat_publishers_of_a_present_object_write_nothing_chirho() {
    let bytes_chirho: &'static [u8] = b"a stone many hands lay at once chirho";
    let (root_chirho, address_chirho, object_chirho) =
        published_root_chirho("concurrent-present", bytes_chirho);
    let shard_chirho = object_chirho.parent().unwrap().to_path_buf();
    let inode_chirho = fs::metadata(&object_chirho).unwrap().ino();
    let shard_before_chirho = fs::metadata(&shard_chirho).unwrap();
    thread::sleep(Duration::from_millis(20));
    let workers_chirho: Vec<_> = (0..8)
        .map(|_| {
            let root_chirho = root_chirho.clone();
            let address_chirho = address_chirho.clone();
            thread::spawn(move || {
                for _ in 0..25 {
                    publish_content_addressed_file_at_root_no_replace_chirho(
                        &root_chirho,
                        &address_chirho,
                        bytes_chirho,
                    )
                    .unwrap();
                }
            })
        })
        .collect();
    for worker_chirho in workers_chirho {
        worker_chirho.join().unwrap();
    }
    let shard_after_chirho = fs::metadata(&shard_chirho).unwrap();
    assert_eq!(inode_chirho, fs::metadata(&object_chirho).unwrap().ino());
    assert_eq!(
        (
            shard_before_chirho.mtime(),
            shard_before_chirho.mtime_nsec()
        ),
        (shard_after_chirho.mtime(), shard_after_chirho.mtime_nsec())
    );
    assert_eq!(
        shard_listing_chirho(&shard_chirho),
        vec![address_chirho[2..].to_string()]
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn publishers_racing_a_collector_never_leave_wrong_bytes_or_temps_chirho() {
    let bytes_chirho: &'static [u8] = b"a stone a collector keeps taking chirho";
    let (root_chirho, address_chirho, object_chirho) =
        published_root_chirho("racing-collector", bytes_chirho);
    let shard_chirho = object_chirho.parent().unwrap().to_path_buf();
    let done_chirho = std::sync::Arc::new(AtomicBool::new(false));
    let deletions_chirho = std::sync::Arc::new(AtomicU64::new(0));
    let collector_chirho = {
        let object_chirho = object_chirho.clone();
        let done_chirho = std::sync::Arc::clone(&done_chirho);
        let deletions_chirho = std::sync::Arc::clone(&deletions_chirho);
        thread::spawn(move || {
            while !done_chirho.load(Ordering::SeqCst) {
                if fs::remove_file(&object_chirho).is_ok() {
                    deletions_chirho.fetch_add(1, Ordering::SeqCst);
                }
                thread::yield_now();
            }
        })
    };
    let publishers_chirho: Vec<_> = (0..4)
        .map(|_| {
            let root_chirho = root_chirho.clone();
            let address_chirho = address_chirho.clone();
            thread::spawn(move || {
                let mut kinds_chirho = Vec::new();
                for _ in 0..50 {
                    if let Err(error_chirho) =
                        publish_content_addressed_file_at_root_no_replace_chirho(
                            &root_chirho,
                            &address_chirho,
                            bytes_chirho,
                        )
                    {
                        kinds_chirho.push(error_chirho.kind_chirho());
                    }
                }
                kinds_chirho
            })
        })
        .collect();
    let mut kinds_chirho = Vec::new();
    for publisher_chirho in publishers_chirho {
        kinds_chirho.extend(publisher_chirho.join().unwrap());
    }
    done_chirho.store(true, Ordering::SeqCst);
    collector_chirho.join().unwrap();
    assert!(
        deletions_chirho.load(Ordering::SeqCst) > 0,
        "the collector raced the publishers"
    );
    // A deletion racing the verify is answered as a corrupt winner ("pathname disappeared after
    // hashing", or the path now names another file). That is today's conservative answer, not the
    // fast path's: measured 2026-10-08 over five runs each, 5 to 14 such answers per run with the
    // fast path and 5 to 10 with it switched off. So the arm pins what a race must never do: leave
    // wrong bytes or a temp, or fail any other way.
    assert!(
        kinds_chirho.iter().all(|kind_chirho| matches!(
            kind_chirho,
            CasLifecycleErrorKindChirho::UnavailableChirho
                | CasLifecycleErrorKindChirho::CorruptWinnerChirho
        )),
        "a race may only answer unavailable or corrupt winner: {kinds_chirho:?}"
    );
    let listing_chirho = shard_listing_chirho(&shard_chirho);
    assert!(
        listing_chirho
            .iter()
            .all(|name_chirho| *name_chirho == address_chirho[2..]),
        "no temp is left: {listing_chirho:?}"
    );
    if let Ok(present_chirho) = fs::read(&object_chirho) {
        assert_eq!(present_chirho, bytes_chirho);
    }
    fs::remove_dir_all(root_chirho).unwrap();
}
