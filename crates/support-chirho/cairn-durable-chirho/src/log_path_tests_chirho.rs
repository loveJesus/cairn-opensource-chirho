// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the shared log classifier and opener: only a genuine absence reads as no log, and a link (looping,
//! dangling or to a valid log), a directory, a pipe, an unreadable log, a denied parent and a file where a directory
//! belongs each refuse, by their own error.

use super::log_path_chirho::{
    classify_log_path_chirho, open_existing_log_for_write_chirho, open_log_no_follow_chirho,
    LogPathChirho,
};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_DIR_CHIRHO: AtomicU64 = AtomicU64::new(0);

/// A directory of this arm's own: named by process and a process-wide counter, and created exclusively.
fn own_dir_chirho(label_chirho: &str) -> PathBuf {
    let number_chirho = NEXT_DIR_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-log-path-{label_chirho}-{}-{number_chirho}-chirho",
        std::process::id()
    ));
    std::fs::create_dir(&dir_chirho).unwrap();
    dir_chirho
}

/// Run `call_chirho` on its own thread with a deadline: a call that waits on a pipe fails the arm instead of hanging it.
fn promptly_chirho<T: Send + 'static>(call_chirho: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender_chirho, receiver_chirho) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender_chirho.send(call_chirho());
    });
    receiver_chirho
        .recv_timeout(Duration::from_secs(5))
        .expect("the call returned promptly, never waiting on a pipe")
}

/// A refusal whose message names what the path holds.
fn assert_refuses_naming_chirho(error_chirho: io::Error, kind_chirho: &str, what_chirho: &str) {
    assert!(
        error_chirho
            .to_string()
            .contains(&format!("is a {kind_chirho}, not a regular log file")),
        "{what_chirho}: the refusal names a {kind_chirho}: {error_chirho}"
    );
}

/// THE ONE ABSENCE: NotFound at the path, or at a directory above it. The control: a regular log is present and reads.
#[test]
fn a_genuine_absence_is_the_only_absence_chirho() {
    let dir_chirho = own_dir_chirho("absent");
    let log_chirho = dir_chirho.join("log-chirho.jsonl");
    assert!(matches!(
        classify_log_path_chirho(&log_chirho).unwrap(),
        LogPathChirho::AbsentChirho
    ));
    assert!(open_log_no_follow_chirho(&log_chirho).unwrap().is_none());
    let deeper_chirho = dir_chirho.join("missing-chirho").join("log-chirho.jsonl");
    assert!(matches!(
        classify_log_path_chirho(&deeper_chirho).unwrap(),
        LogPathChirho::AbsentChirho
    ));
    assert!(open_log_no_follow_chirho(&deeper_chirho).unwrap().is_none());

    std::fs::write(&log_chirho, b"{\"seq_chirho\":0}\n").unwrap();
    assert!(matches!(
        classify_log_path_chirho(&log_chirho).unwrap(),
        LogPathChirho::PresentChirho(_)
    ));
    let mut text_chirho = String::new();
    open_log_no_follow_chirho(&log_chirho)
        .unwrap()
        .expect("a regular log opens")
        .read_to_string(&mut text_chirho)
        .unwrap();
    assert_eq!(text_chirho, "{\"seq_chirho\":0}\n");
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// EVERY LINK REFUSES, whatever it points to: a loop, nothing, or a valid log. The classifier names it a link, and the
/// open fails on the link itself (`ELOOP`), so a dangling link is never an absence and a valid one is never read
/// through. Nothing is created at the dangling link's target.
#[test]
fn every_link_refuses_whatever_it_points_to_chirho() {
    let dir_chirho = own_dir_chirho("links");
    let valid_chirho = dir_chirho.join("valid-chirho.jsonl");
    std::fs::write(&valid_chirho, b"{\"seq_chirho\":0}\n").unwrap();
    for (name_chirho, target_chirho) in [
        ("loop-chirho.jsonl", PathBuf::from("loop-chirho.jsonl")),
        (
            "dangling-chirho.jsonl",
            PathBuf::from("nothing-here-chirho.jsonl"),
        ),
        ("to-valid-chirho.jsonl", valid_chirho.clone()),
    ] {
        let link_chirho = dir_chirho.join(name_chirho);
        std::os::unix::fs::symlink(&target_chirho, &link_chirho).unwrap();
        assert_refuses_naming_chirho(
            classify_log_path_chirho(&link_chirho).unwrap_err(),
            "link",
            name_chirho,
        );
        let error_chirho = open_log_no_follow_chirho(&link_chirho).unwrap_err();
        assert_eq!(
            error_chirho.raw_os_error(),
            Some(libc::ELOOP),
            "{name_chirho}: the open refuses the link itself: {error_chirho}"
        );
    }
    assert!(
        std::fs::symlink_metadata(dir_chirho.join("nothing-here-chirho.jsonl")).is_err(),
        "nothing appeared at the dangling link's target"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// A DIRECTORY REFUSES, at the classifier and at the open (which opens it, then refuses its kind).
#[test]
fn a_directory_refuses_chirho() {
    let dir_chirho = own_dir_chirho("directory");
    let log_chirho = dir_chirho.join("log-chirho.jsonl");
    std::fs::create_dir(&log_chirho).unwrap();
    assert_refuses_naming_chirho(
        classify_log_path_chirho(&log_chirho).unwrap_err(),
        "directory",
        "the classifier",
    );
    assert_refuses_naming_chirho(
        open_log_no_follow_chirho(&log_chirho).unwrap_err(),
        "directory",
        "the open",
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// A PIPE REFUSES WITHOUT WAITING: the classifier never opens it, and the open neither blocks on it nor reads it.
///
/// MIGRATION PATH: a deadline failure here means the open waits on a pipe, which held a served request's own thread
/// past eleven minutes in the brick's measurement.
#[test]
fn a_pipe_refuses_without_waiting_chirho() {
    let dir_chirho = own_dir_chirho("pipe");
    let log_chirho = dir_chirho.join("log-chirho.jsonl");
    assert!(std::process::Command::new("mkfifo")
        .arg(&log_chirho)
        .status()
        .unwrap()
        .success());
    assert_refuses_naming_chirho(
        classify_log_path_chirho(&log_chirho).unwrap_err(),
        "pipe",
        "the classifier",
    );
    let opened_log_chirho = log_chirho.clone();
    let error_chirho = promptly_chirho(move || {
        open_log_no_follow_chirho(&opened_log_chirho).map(|file_chirho| file_chirho.is_some())
    })
    .unwrap_err();
    assert_refuses_naming_chirho(error_chirho, "pipe", "the open");
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// AN UNREADABLE LOG IS PRESENT, AND ITS OPEN REFUSES: its metadata reads, so the classifier finds it present, and the
/// open fails with the permission error. A log seen present whose read fails is never read as empty.
#[test]
fn an_unreadable_log_is_present_and_its_open_refuses_chirho() {
    let dir_chirho = own_dir_chirho("unreadable");
    let log_chirho = dir_chirho.join("log-chirho.jsonl");
    std::fs::write(&log_chirho, b"{\"seq_chirho\":0}\n").unwrap();
    std::fs::set_permissions(&log_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(matches!(
        classify_log_path_chirho(&log_chirho).unwrap(),
        LogPathChirho::PresentChirho(_)
    ));
    assert_eq!(
        open_log_no_follow_chirho(&log_chirho).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    std::fs::set_permissions(&log_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// A DENIED PARENT REFUSES WITH ITS PERMISSION ERROR, proven real before anything is classified: a log under a
/// mode-000 directory is neither absent nor present.
#[test]
fn a_denied_parent_refuses_with_its_permission_error_chirho() {
    let dir_chirho = own_dir_chirho("denied-parent");
    let inner_chirho = dir_chirho.join("inner-chirho");
    std::fs::create_dir(&inner_chirho).unwrap();
    let log_chirho = inner_chirho.join("log-chirho.jsonl");
    std::fs::write(&log_chirho, b"{\"seq_chirho\":0}\n").unwrap();
    std::fs::set_permissions(&inner_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied_chirho = |path_chirho: &Path| std::fs::symlink_metadata(path_chirho).map(|_| ());
    assert_eq!(
        denied_chirho(&log_chirho).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied,
        "the fault must actually deny"
    );
    assert_eq!(
        classify_log_path_chirho(&log_chirho).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        open_log_no_follow_chirho(&log_chirho).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    std::fs::set_permissions(&inner_chirho, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// A FILE WHERE A DIRECTORY BELONGS REFUSES: the lookup fails with `ENOTDIR`, which is not an absence.
#[test]
fn a_file_where_a_directory_belongs_refuses_chirho() {
    let dir_chirho = own_dir_chirho("not-a-directory");
    let plain_chirho = dir_chirho.join("plain-chirho");
    std::fs::write(&plain_chirho, b"").unwrap();
    let log_chirho = plain_chirho.join("log-chirho.jsonl");
    assert_eq!(
        classify_log_path_chirho(&log_chirho)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTDIR)
    );
    assert_eq!(
        open_log_no_follow_chirho(&log_chirho)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTDIR)
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// A SWAP AFTER CLASSIFICATION IS CAUGHT BY THE OPEN: a log classified present, then replaced by a link to a valid log
/// or by a pipe, is refused by the read open and by the write open alike, promptly.
#[test]
fn a_swap_after_classification_is_caught_by_the_open_chirho() {
    let dir_chirho = own_dir_chirho("swap");
    let valid_chirho = dir_chirho.join("valid-chirho.jsonl");
    std::fs::write(&valid_chirho, b"{\"seq_chirho\":0}\n").unwrap();
    for swap_chirho in ["link", "pipe"] {
        let log_chirho = dir_chirho.join(format!("log-{swap_chirho}-chirho.jsonl"));
        std::fs::write(&log_chirho, b"{\"seq_chirho\":0}\n").unwrap();
        assert!(matches!(
            classify_log_path_chirho(&log_chirho).unwrap(),
            LogPathChirho::PresentChirho(_)
        ));
        std::fs::remove_file(&log_chirho).unwrap();
        if swap_chirho == "link" {
            std::os::unix::fs::symlink(&valid_chirho, &log_chirho).unwrap();
        } else {
            assert!(std::process::Command::new("mkfifo")
                .arg(&log_chirho)
                .status()
                .unwrap()
                .success());
        }
        let read_log_chirho = log_chirho.clone();
        let read_chirho = promptly_chirho(move || {
            open_log_no_follow_chirho(&read_log_chirho).map(|file_chirho| file_chirho.is_some())
        });
        assert!(read_chirho.is_err(), "{swap_chirho}: the read open refuses");
        let write_log_chirho = log_chirho.clone();
        let write_chirho = promptly_chirho(move || {
            open_existing_log_for_write_chirho(&write_log_chirho, true).map(|_| ())
        });
        assert!(
            write_chirho.is_err(),
            "{swap_chirho}: the write open refuses"
        );
    }
    assert_eq!(
        std::fs::read(&valid_chirho).unwrap(),
        b"{\"seq_chirho\":0}\n",
        "the link's target is unchanged"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// THE APPEND NEVER WRITES THROUGH A FAULT, at its real seam: with a link to a valid log, a dangling link, a looping
/// link, a pipe or a directory at the log's path, `append_durable_line_chirho` refuses, promptly, and writes nothing:
/// the valid link's target keeps its bytes, nothing appears at the dangling link's target, and the directory stays
/// empty. The controls: a genuinely absent log is created with the line, and a regular log gains it.
#[test]
fn the_append_never_writes_through_a_fault_chirho() {
    let dir_chirho = own_dir_chirho("append-seam");
    let valid_chirho = dir_chirho.join("valid-chirho.jsonl");
    let valid_bytes_chirho = b"{\"seq_chirho\":0}\n".to_vec();
    std::fs::write(&valid_chirho, &valid_bytes_chirho).unwrap();
    let line_chirho = b"{\"seq_chirho\":1}\n".to_vec();
    for fault_chirho in ["to-valid", "dangling", "loop", "pipe", "directory"] {
        let log_chirho = dir_chirho.join(format!("log-{fault_chirho}-chirho.jsonl"));
        match fault_chirho {
            "to-valid" => std::os::unix::fs::symlink(&valid_chirho, &log_chirho).unwrap(),
            "dangling" => {
                std::os::unix::fs::symlink("nothing-here-chirho.jsonl", &log_chirho).unwrap()
            }
            "loop" => {
                std::os::unix::fs::symlink(log_chirho.file_name().unwrap(), &log_chirho).unwrap()
            }
            "pipe" => assert!(std::process::Command::new("mkfifo")
                .arg(&log_chirho)
                .status()
                .unwrap()
                .success()),
            _ => std::fs::create_dir(&log_chirho).unwrap(),
        }
        let append_log_chirho = log_chirho.clone();
        let append_line_chirho = line_chirho.clone();
        let error_chirho = promptly_chirho(move || {
            super::append_durable_line_chirho(&append_log_chirho, &append_line_chirho)
        })
        .expect_err("the append refuses a fault at the log's path");
        assert!(
            !super::io_error_is_resource_exhaustion_chirho(&error_chirho),
            "{fault_chirho}: a fault is never a capacity claim: {error_chirho}"
        );
    }
    assert_eq!(
        std::fs::read(&valid_chirho).unwrap(),
        valid_bytes_chirho,
        "the valid link's target is unchanged"
    );
    assert!(
        std::fs::symlink_metadata(dir_chirho.join("nothing-here-chirho.jsonl")).is_err(),
        "nothing appeared at the dangling link's target"
    );
    assert_eq!(
        std::fs::read_dir(dir_chirho.join("log-directory-chirho.jsonl"))
            .unwrap()
            .count(),
        0,
        "the directory stays empty"
    );

    let created_chirho = dir_chirho.join("created-chirho.jsonl");
    super::append_durable_line_chirho(&created_chirho, &line_chirho).unwrap();
    assert_eq!(
        std::fs::read(&created_chirho).unwrap(),
        line_chirho,
        "the creation control"
    );
    super::append_durable_line_chirho(&valid_chirho, &line_chirho).unwrap();
    assert_eq!(
        std::fs::read(&valid_chirho).unwrap(),
        [valid_bytes_chirho.as_slice(), line_chirho.as_slice()].concat(),
        "the ordinary append control"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// PERMISSION LOSS IN PLACE: a regular log that opened is then made unreadable on the same inode, with the same length
/// and modification time. Its metadata still reads, so it is present, but its read open now refuses with the
/// permission error, and its write open too. The denied open is proven first, so the arm measures a real denial.
#[test]
fn permission_lost_in_place_refuses_the_open_chirho() {
    use std::os::unix::fs::MetadataExt;
    let dir_chirho = own_dir_chirho("permission-in-place");
    let log_chirho = dir_chirho.join("log-chirho.jsonl");
    std::fs::write(&log_chirho, b"{\"seq_chirho\":0}\n").unwrap();
    assert!(
        open_log_no_follow_chirho(&log_chirho).unwrap().is_some(),
        "the control opens"
    );
    let before_chirho = std::fs::symlink_metadata(&log_chirho).unwrap();
    std::fs::set_permissions(&log_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
    let after_chirho = std::fs::symlink_metadata(&log_chirho).unwrap();
    assert_eq!(
        (
            before_chirho.ino(),
            before_chirho.len(),
            before_chirho.mtime(),
            before_chirho.mtime_nsec()
        ),
        (
            after_chirho.ino(),
            after_chirho.len(),
            after_chirho.mtime(),
            after_chirho.mtime_nsec()
        ),
        "the same inode, length and modification time"
    );
    assert_eq!(
        std::fs::File::open(&log_chirho).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied,
        "the fault must actually deny the open"
    );
    assert!(matches!(
        classify_log_path_chirho(&log_chirho).unwrap(),
        LogPathChirho::PresentChirho(_)
    ));
    let read_error_chirho = open_log_no_follow_chirho(&log_chirho).unwrap_err();
    assert_eq!(read_error_chirho.kind(), io::ErrorKind::PermissionDenied);
    assert!(!super::io_error_is_resource_exhaustion_chirho(
        &read_error_chirho
    ));
    assert_eq!(
        open_existing_log_for_write_chirho(&log_chirho, true)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    std::fs::set_permissions(&log_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}
