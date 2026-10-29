// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the identity-stable bounded reader: it reads one regular, single-link file within its
//! bound, and refuses, without following or blocking, a symlink or FIFO in place or swapped in
//! between its path check and its open.

use super::*;
use std::os::unix::fs::symlink;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEADLINE_CHIRHO: Duration = Duration::from_secs(10);
const STONE_CHIRHO: &[u8] = b"ten bytes!";

fn temp_dir_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-bounded-read-{label_chirho}-{nanos_chirho}-{}-{}",
        std::process::id(),
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir_chirho).unwrap();
    dir_chirho
}

fn mkfifo_chirho(path_chirho: &Path) {
    let status_chirho = std::process::Command::new("mkfifo")
        .arg(path_chirho)
        .status()
        .unwrap();
    assert!(status_chirho.success(), "mkfifo failed");
}

/// Reads `path_chirho` on a worker thread, with `between_chirho` run at the hold point between the
/// path check and the open, and fails if the read does not return within the deadline.
fn read_with_hold_point_chirho(
    path_chirho: PathBuf,
    max_bytes_chirho: u64,
    between_chirho: impl Fn() + Send + 'static,
) -> (io::Result<Vec<u8>>, bool) {
    let (sender_chirho, receiver_chirho) = mpsc::channel();
    std::thread::spawn(move || {
        let fired_chirho = std::rc::Rc::new(std::cell::Cell::new(false));
        let hook_fired_chirho = std::rc::Rc::clone(&fired_chirho);
        BEFORE_BOUNDED_OPEN_CHIRHO.with(|hook_chirho| {
            *hook_chirho.borrow_mut() = Some(Box::new(move || {
                between_chirho();
                hook_fired_chirho.set(true);
            }));
        });
        let result_chirho =
            read_identity_stable_bounded_regular_file_chirho(&path_chirho, max_bytes_chirho);
        BEFORE_BOUNDED_OPEN_CHIRHO.with(|hook_chirho| *hook_chirho.borrow_mut() = None);
        let _sent_chirho = sender_chirho.send((result_chirho, fired_chirho.get()));
    });
    receiver_chirho
        .recv_timeout(DEADLINE_CHIRHO)
        .expect("the bounded read blocked past its deadline")
}

fn read_within_deadline_chirho(path_chirho: PathBuf, max_bytes_chirho: u64) -> io::Result<Vec<u8>> {
    read_with_hold_point_chirho(path_chirho, max_bytes_chirho, || {}).0
}

#[test]
fn a_regular_file_within_its_bound_is_read_chirho() {
    let dir_chirho = temp_dir_chirho("regular");
    let path_chirho = dir_chirho.join("stone");
    fs::write(&path_chirho, STONE_CHIRHO).unwrap();
    let read_chirho = read_within_deadline_chirho(path_chirho, STONE_CHIRHO.len() as u64).unwrap();
    assert_eq!(read_chirho, STONE_CHIRHO);
    fs::remove_dir_all(dir_chirho).unwrap();
}

#[test]
fn a_longer_file_is_refused_chirho() {
    let dir_chirho = temp_dir_chirho("longer");
    let path_chirho = dir_chirho.join("stone");
    fs::write(&path_chirho, b"eleven bytes").unwrap();
    assert!(read_within_deadline_chirho(path_chirho, STONE_CHIRHO.len() as u64).is_err());
    fs::remove_dir_all(dir_chirho).unwrap();
}

#[test]
fn a_hard_linked_file_is_refused_chirho() {
    let dir_chirho = temp_dir_chirho("hard-link");
    let path_chirho = dir_chirho.join("stone");
    fs::write(&path_chirho, STONE_CHIRHO).unwrap();
    fs::hard_link(&path_chirho, dir_chirho.join("second-name")).unwrap();
    assert!(read_within_deadline_chirho(path_chirho, STONE_CHIRHO.len() as u64).is_err());
    fs::remove_dir_all(dir_chirho).unwrap();
}

#[test]
fn a_symlink_in_place_is_refused_and_its_target_left_alone_chirho() {
    let dir_chirho = temp_dir_chirho("symlink-in-place");
    let target_chirho = dir_chirho.join("target");
    fs::write(&target_chirho, STONE_CHIRHO).unwrap();
    let path_chirho = dir_chirho.join("stone");
    symlink(&target_chirho, &path_chirho).unwrap();
    assert!(read_within_deadline_chirho(path_chirho, STONE_CHIRHO.len() as u64).is_err());
    assert_eq!(fs::read(&target_chirho).unwrap(), STONE_CHIRHO);
    fs::remove_dir_all(dir_chirho).unwrap();
}

#[test]
fn a_fifo_in_place_is_refused_without_blocking_chirho() {
    let dir_chirho = temp_dir_chirho("fifo-in-place");
    let path_chirho = dir_chirho.join("stone");
    mkfifo_chirho(&path_chirho);
    assert!(read_within_deadline_chirho(path_chirho, STONE_CHIRHO.len() as u64).is_err());
    fs::remove_dir_all(dir_chirho).unwrap();
}

#[test]
fn a_symlink_to_the_same_file_swapped_in_at_the_open_is_refused_chirho() {
    // The file itself moves aside and a symlink to it takes its name: following the link would open
    // the very inode the path check saw, so only a no-follow open and the after-read path check
    // tell this apart.
    let dir_chirho = temp_dir_chirho("swap-symlink");
    let path_chirho = dir_chirho.join("stone");
    let aside_chirho = dir_chirho.join("aside");
    fs::write(&path_chirho, STONE_CHIRHO).unwrap();
    let (hook_path_chirho, hook_aside_chirho) = (path_chirho.clone(), aside_chirho.clone());
    let (result_chirho, fired_chirho) =
        read_with_hold_point_chirho(path_chirho.clone(), STONE_CHIRHO.len() as u64, move || {
            fs::rename(&hook_path_chirho, &hook_aside_chirho).unwrap();
            symlink(&hook_aside_chirho, &hook_path_chirho).unwrap();
        });
    assert!(
        fired_chirho,
        "the hold point fired between the path check and the open"
    );
    assert!(
        result_chirho.is_err(),
        "a symlink swapped in is never read through"
    );
    assert!(fs::symlink_metadata(&path_chirho)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read(&aside_chirho).unwrap(),
        STONE_CHIRHO,
        "the symlink's target is unchanged"
    );
    fs::remove_dir_all(dir_chirho).unwrap();
}

#[test]
fn a_fifo_swapped_in_at_the_open_is_refused_without_blocking_chirho() {
    let dir_chirho = temp_dir_chirho("swap-fifo");
    let path_chirho = dir_chirho.join("stone");
    fs::write(&path_chirho, STONE_CHIRHO).unwrap();
    let hook_path_chirho = path_chirho.clone();
    let (result_chirho, fired_chirho) =
        read_with_hold_point_chirho(path_chirho, STONE_CHIRHO.len() as u64, move || {
            fs::remove_file(&hook_path_chirho).unwrap();
            mkfifo_chirho(&hook_path_chirho);
        });
    assert!(
        fired_chirho,
        "the hold point fired between the path check and the open"
    );
    assert!(
        result_chirho.is_err(),
        "a FIFO swapped in is refused, and the open did not block"
    );
    fs::remove_dir_all(dir_chirho).unwrap();
}
