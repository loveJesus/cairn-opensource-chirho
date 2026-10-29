// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The shared JSONL absence brick's arms for the seqlog: an append, a truncation, a newline repair and the head
//! checkpoint's reads and reseeds never write through a log the engine cannot examine, and never wait on a pipe; a
//! faulted head is only a miss. Genuine creation, an ordinary append, the torn-tail and newline repairs of a regular log,
//! and the head's fast path are the controls.
//! Tasklist: `spec-chirho/tasklists-chirho/26-10-08_23-20-tasklist-jsonl_absence_cache_door-chirho.md`.

use super::*;
use crate::seqlog_head_chirho::{
    reseed_seqlog_head_chirho, seqlog_head_path_chirho, set_before_log_open_hook_chirho,
    LogOpenStageChirho,
};
use serde::Deserialize;
use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct FaultRecordChirho {
    seq_chirho: u64,
}

const FAULTS_CHIRHO: [&str; 5] = ["to-valid", "dangling", "loop", "pipe", "directory"];
const VALID_BYTES_CHIRHO: &[u8] = b"{\"seq_chirho\":0}\n";

static NEXT_DIR_CHIRHO: AtomicU64 = AtomicU64::new(0);

/// A directory of this arm's own: named by process and a process-wide counter, and created exclusively.
fn own_dir_chirho(label_chirho: &str) -> PathBuf {
    let number_chirho = NEXT_DIR_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-seqlog-fault-{label_chirho}-{}-{number_chirho}-chirho",
        std::process::id()
    ));
    std::fs::create_dir(&dir_chirho).unwrap();
    dir_chirho
}

/// Run `call_chirho` on its own thread with a deadline: `None` when it waited past it (on a pipe), never a hung arm.
fn within_deadline_chirho<T: Send + 'static>(
    call_chirho: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (sender_chirho, receiver_chirho) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender_chirho.send(call_chirho());
    });
    receiver_chirho.recv_timeout(Duration::from_secs(5)).ok()
}

/// Run `call_chirho` on its own thread with a deadline: a call that waits on a pipe fails the arm instead of hanging it.
fn promptly_chirho<T: Send + 'static>(call_chirho: impl FnOnce() -> T + Send + 'static) -> T {
    within_deadline_chirho(call_chirho)
        .expect("the call returned promptly, never waiting on a pipe")
}

/// Put `fault_chirho` at `log_chirho`; a valid log for the link to point at sits beside it.
fn plant_fault_chirho(dir_chirho: &Path, log_chirho: &Path, fault_chirho: &str) {
    let valid_chirho = dir_chirho.join("valid-chirho.jsonl");
    match fault_chirho {
        "to-valid" => std::os::unix::fs::symlink(&valid_chirho, log_chirho).unwrap(),
        "dangling" => std::os::unix::fs::symlink("nothing-here-chirho.jsonl", log_chirho).unwrap(),
        "loop" => std::os::unix::fs::symlink(log_chirho.file_name().unwrap(), log_chirho).unwrap(),
        "pipe" => assert!(std::process::Command::new("mkfifo")
            .arg(log_chirho)
            .status()
            .unwrap()
            .success()),
        _ => std::fs::create_dir(log_chirho).unwrap(),
    }
}

/// Nothing was written through any fault: the valid link's target keeps its bytes, nothing appeared at the dangling
/// link's target, and the directory fault stays empty.
fn assert_nothing_written_through_chirho(dir_chirho: &Path, what_chirho: &str) {
    assert_eq!(
        std::fs::read(dir_chirho.join("valid-chirho.jsonl")).unwrap(),
        VALID_BYTES_CHIRHO,
        "{what_chirho}: the valid link's target is unchanged"
    );
    assert!(
        std::fs::symlink_metadata(dir_chirho.join("nothing-here-chirho.jsonl")).is_err(),
        "{what_chirho}: nothing appeared at the dangling link's target"
    );
    // Only the planted directory fault is checked: the append's own lock directory sits beside it.
    assert_eq!(
        std::fs::read_dir(dir_chirho.join("log-directory-chirho.jsonl"))
            .unwrap()
            .count(),
        0,
        "{what_chirho}: the directory fault stays empty"
    );
}

/// AN APPEND NEVER WRITES THROUGH A FAULT: with a link to a valid log, a dangling link, a looping link, a pipe or a
/// directory at the log's path, the seqlog append refuses, promptly, and writes nothing. The controls: a genuinely
/// absent log is created at seq 0, and a regular log gains its next record.
#[test]
fn an_append_to_a_faulted_log_refuses_and_writes_nothing_chirho() {
    let dir_chirho = own_dir_chirho("append");
    std::fs::write(dir_chirho.join("valid-chirho.jsonl"), VALID_BYTES_CHIRHO).unwrap();
    for fault_chirho in FAULTS_CHIRHO {
        let log_chirho = dir_chirho.join(format!("log-{fault_chirho}-chirho.jsonl"));
        plant_fault_chirho(&dir_chirho, &log_chirho, fault_chirho);
        let append_dir_chirho = dir_chirho.clone();
        let append_log_chirho = log_chirho.clone();
        let outcome_chirho = promptly_chirho(move || {
            append_serialized_jsonl_chirho(&append_dir_chirho, &append_log_chirho, |seq_chirho| {
                Ok(FaultRecordChirho { seq_chirho })
            })
            .map(|_| ())
        });
        assert!(
            outcome_chirho.is_err(),
            "{fault_chirho}: the append refuses a fault at the log's path"
        );
    }
    assert_nothing_written_through_chirho(&dir_chirho, "the appends");

    let created_chirho = dir_chirho.join("created-chirho.jsonl");
    let first_chirho = append_serialized_jsonl_chirho(&dir_chirho, &created_chirho, |seq_chirho| {
        Ok(FaultRecordChirho { seq_chirho })
    })
    .unwrap();
    assert_eq!(
        first_chirho,
        FaultRecordChirho { seq_chirho: 0 },
        "the creation control"
    );
    let regular_chirho = dir_chirho.join("valid-chirho.jsonl");
    let next_chirho = append_serialized_jsonl_chirho(&dir_chirho, &regular_chirho, |seq_chirho| {
        Ok(FaultRecordChirho { seq_chirho })
    })
    .unwrap();
    assert_eq!(
        next_chirho,
        FaultRecordChirho { seq_chirho: 1 },
        "the ordinary append control"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// THE REPAIR OPENS NEVER FOLLOW A FAULT: a recovery truncation and a newline repair, aimed at a link to a valid log, a
/// dangling link, a looping link, a pipe or a directory, refuse promptly and write nothing through it. The controls: a
/// regular log truncates to its valid prefix, and gains its missing newline.
#[test]
fn the_repair_opens_never_follow_a_fault_chirho() {
    let dir_chirho = own_dir_chirho("repair");
    std::fs::write(dir_chirho.join("valid-chirho.jsonl"), VALID_BYTES_CHIRHO).unwrap();
    for fault_chirho in FAULTS_CHIRHO {
        let log_chirho = dir_chirho.join(format!("log-{fault_chirho}-chirho.jsonl"));
        plant_fault_chirho(&dir_chirho, &log_chirho, fault_chirho);
        let truncate_log_chirho = log_chirho.clone();
        let truncated_chirho = promptly_chirho(move || {
            truncate_jsonl_to_chirho(&truncate_log_chirho, 0, b"torn tail")
        });
        assert!(
            truncated_chirho.is_err(),
            "{fault_chirho}: the truncation refuses"
        );
        let repair_log_chirho = log_chirho.clone();
        let repaired_chirho =
            promptly_chirho(move || append_missing_jsonl_newline_chirho(&repair_log_chirho));
        assert!(
            repaired_chirho.is_err(),
            "{fault_chirho}: the newline repair refuses"
        );
    }
    assert_nothing_written_through_chirho(&dir_chirho, "the repairs");

    let torn_chirho = dir_chirho.join("torn-chirho.jsonl");
    std::fs::write(&torn_chirho, b"{\"seq_chirho\":0}\n{\"seq_ch").unwrap();
    truncate_jsonl_to_chirho(&torn_chirho, 17, b"{\"seq_ch").unwrap();
    assert_eq!(
        std::fs::read(&torn_chirho).unwrap(),
        VALID_BYTES_CHIRHO,
        "the truncation control"
    );
    let unterminated_chirho = dir_chirho.join("unterminated-chirho.jsonl");
    std::fs::write(&unterminated_chirho, b"{\"seq_chirho\":0}").unwrap();
    append_missing_jsonl_newline_chirho(&unterminated_chirho).unwrap();
    assert_eq!(
        std::fs::read(&unterminated_chirho).unwrap(),
        VALID_BYTES_CHIRHO,
        "the newline repair control"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// THE SHARED LOADER, ALONE (the load door, kept apart from the cache door): only a genuine absence reads as no records.
/// A link to a valid log, a dangling or looping link, a pipe and a directory each refuse, promptly. The controls: a
/// missing log is empty, and a regular log reads its records.
#[test]
fn the_shared_loader_reads_only_a_genuine_absence_as_empty_chirho() {
    use crate::jsonl_read_chirho::load_serialized_jsonl_chirho;
    let dir_chirho = own_dir_chirho("loader");
    std::fs::write(dir_chirho.join("valid-chirho.jsonl"), VALID_BYTES_CHIRHO).unwrap();
    for fault_chirho in FAULTS_CHIRHO {
        let log_chirho = dir_chirho.join(format!("log-{fault_chirho}-chirho.jsonl"));
        plant_fault_chirho(&dir_chirho, &log_chirho, fault_chirho);
        let loaded_log_chirho = log_chirho.clone();
        let loaded_chirho = promptly_chirho(move || {
            load_serialized_jsonl_chirho::<FaultRecordChirho>(&loaded_log_chirho)
                .map(|records_chirho| records_chirho.len())
        });
        assert!(
            loaded_chirho.is_err(),
            "{fault_chirho}: the loader refuses, never an empty log: {loaded_chirho:?}"
        );
    }
    assert!(
        load_serialized_jsonl_chirho::<FaultRecordChirho>(&dir_chirho.join("absent-chirho.jsonl"))
            .unwrap()
            .is_empty(),
        "a genuine absence is empty"
    );
    assert_eq!(
        load_serialized_jsonl_chirho::<FaultRecordChirho>(&dir_chirho.join("valid-chirho.jsonl"))
            .unwrap(),
        vec![FaultRecordChirho { seq_chirho: 0 }],
        "a regular log reads its records"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// Three records: the log the head and tail arms recover.
const THREE_RECORDS_CHIRHO: &[u8] = b"{\"seq_chirho\":0}\n{\"seq_chirho\":1}\n{\"seq_chirho\":2}\n";

const HEAD_FAULTS_CHIRHO: [&str; 7] = [
    "to-forged",
    "dangling",
    "loop",
    "pipe",
    "directory",
    "unreadable",
    "oversize",
];

/// Recover `log_chirho` within the deadline: the outcome, and how many whole-file reads recovery made (none means the
/// head's fast path answered). `None` when recovery waited past the deadline.
fn recover_within_chirho(log_chirho: &Path) -> Option<(Result<u64, String>, u64)> {
    let log_chirho = log_chirho.to_path_buf();
    within_deadline_chirho(move || {
        reset_recover_counts_chirho();
        let outcome_chirho = recover_jsonl_len_unlocked_chirho(&log_chirho)
            .map_err(|error_chirho| format!("{error_chirho:#}"));
        (outcome_chirho, recover_full_read_count_chirho())
    })
}

/// A recovery, in words a row can compare: its outcome, and whether the fast path or the full scan answered.
fn describe_recovery_chirho(recovery_chirho: Option<(Result<u64, String>, u64)>) -> String {
    match recovery_chirho {
        None => "waited past the deadline".to_string(),
        Some((outcome_chirho, 0)) => format!("{outcome_chirho:?} on the fast path"),
        Some((outcome_chirho, _)) => format!("{outcome_chirho:?} by the full scan"),
    }
}

/// Remove whatever an arm left at `path_chirho`: a directory (which must be empty: nothing was written into it), or any
/// other entry.
fn clear_path_chirho(path_chirho: &Path) {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) if metadata_chirho.is_dir() => std::fs::remove_dir(path_chirho)
            .unwrap_or_else(|error_chirho| {
                panic!("the directory fault stays empty: {error_chirho}")
            }),
        Ok(_) => std::fs::remove_file(path_chirho).unwrap(),
        Err(_) => {}
    }
}

/// Put `fault_chirho` at the head path. `forged_chirho` is a checkpoint naming the log's true length and tail with a
/// wrong count, so a head read that followed a link, or read past the bound, would trust it: only a miss returns the
/// true count.
fn plant_head_fault_chirho(
    dir_chirho: &Path,
    head_chirho: &Path,
    forged_chirho: &Path,
    fault_chirho: &str,
) {
    match fault_chirho {
        "to-forged" => std::os::unix::fs::symlink(forged_chirho, head_chirho).unwrap(),
        "unreadable" => {
            std::fs::copy(forged_chirho, head_chirho).unwrap();
            std::fs::set_permissions(head_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        "oversize" => {
            // JSON accepts trailing whitespace, so this is the forged checkpoint, merely past the read bound.
            let mut bytes_chirho = std::fs::read(forged_chirho).unwrap();
            bytes_chirho.resize(8192, b' ');
            std::fs::write(head_chirho, bytes_chirho).unwrap();
        }
        other_chirho => plant_fault_chirho(dir_chirho, head_chirho, other_chirho),
    }
}

/// Nothing appeared at the dangling link's target: no open created it.
fn assert_dangling_target_absent_chirho(dir_chirho: &Path) {
    assert!(
        std::fs::symlink_metadata(dir_chirho.join("nothing-here-chirho.jsonl")).is_err(),
        "nothing appeared at the dangling link's target"
    );
}

/// THE HEAD IS ADVISORY, AND READING IT NEVER WAITS OR FOLLOWS (PFE #26732): a head checkpoint replaced by a link to a
/// forged checkpoint (right tail, wrong count), a dangling or looping link, a pipe, a directory, an unreadable file or an
/// oversize one is a miss. Recovery returns the true count from the full scan, promptly, and nothing is written through
/// the fault. One row per fault, so a failure shows every fault's outcome. The controls: an absent head is a miss, and
/// an ordinary head answers on the fast path with no full read.
#[test]
fn a_faulted_head_is_a_miss_that_never_waits_or_follows_chirho() {
    let dir_chirho = own_dir_chirho("head");
    let log_chirho = dir_chirho.join("log-chirho.jsonl");
    std::fs::write(&log_chirho, THREE_RECORDS_CHIRHO).unwrap();
    let head_chirho = seqlog_head_path_chirho(&log_chirho);
    let forged_chirho = dir_chirho.join("forged-chirho.head");
    reseed_seqlog_head_chirho(&log_chirho, 999).unwrap();
    std::fs::rename(&head_chirho, &forged_chirho).unwrap();
    let forged_bytes_chirho = std::fs::read(&forged_chirho).unwrap();

    let rows_chirho: Vec<String> = HEAD_FAULTS_CHIRHO
        .iter()
        .map(|fault_chirho| {
            clear_path_chirho(&head_chirho);
            plant_head_fault_chirho(&dir_chirho, &head_chirho, &forged_chirho, fault_chirho);
            format!(
                "{fault_chirho}: {}",
                describe_recovery_chirho(recover_within_chirho(&log_chirho))
            )
        })
        .collect();
    let expected_chirho: Vec<String> = HEAD_FAULTS_CHIRHO
        .iter()
        .map(|fault_chirho| format!("{fault_chirho}: Ok(3) by the full scan"))
        .collect();
    assert_eq!(
        rows_chirho, expected_chirho,
        "every faulted head is a prompt miss: the true count, from the full scan"
    );
    clear_path_chirho(&head_chirho);
    assert_eq!(
        std::fs::read(&forged_chirho).unwrap(),
        forged_bytes_chirho,
        "nothing was written through the link to the forged checkpoint"
    );
    assert_dangling_target_absent_chirho(&dir_chirho);

    assert_eq!(
        describe_recovery_chirho(recover_within_chirho(&log_chirho)),
        "Ok(3) by the full scan",
        "the absent-head control is a miss"
    );
    assert_eq!(
        describe_recovery_chirho(recover_within_chirho(&log_chirho)),
        "Ok(3) on the fast path",
        "the ordinary-head control: the head the miss reseeded answers, with no full read"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// Run `call_chirho` within the deadline, with a hook that, the first time the log is opened at `stage_chirho`, moves
/// the log to `aside_chirho` and plants `fault_chirho` in its place: the swap lands after recovery examined the path, at
/// the real seam. Returns the call's outcome and whether the swap ran; `None` when the call waited past the deadline.
fn swap_within_chirho<T: Send + 'static>(
    stage_chirho: LogOpenStageChirho,
    dir_chirho: &Path,
    aside_chirho: &Path,
    fault_chirho: &'static str,
    call_chirho: impl FnOnce() -> T + Send + 'static,
) -> Option<(T, bool)> {
    let dir_chirho = dir_chirho.to_path_buf();
    let aside_chirho = aside_chirho.to_path_buf();
    within_deadline_chirho(move || {
        let swapped_chirho = Rc::new(Cell::new(false));
        let hook_swapped_chirho = Rc::clone(&swapped_chirho);
        set_before_log_open_hook_chirho(move |at_chirho, path_chirho| {
            if at_chirho == stage_chirho && !hook_swapped_chirho.get() {
                std::fs::rename(path_chirho, &aside_chirho).unwrap();
                plant_fault_chirho(&dir_chirho, path_chirho, fault_chirho);
                hook_swapped_chirho.set(true);
            }
        });
        let outcome_chirho = call_chirho();
        (outcome_chirho, swapped_chirho.get())
    })
}

/// Undo a swap: the planted fault goes (a directory fault must still be empty), and the real log comes back.
fn restore_swapped_log_chirho(log_chirho: &Path, aside_chirho: &Path) {
    clear_path_chirho(log_chirho);
    std::fs::rename(aside_chirho, log_chirho).unwrap();
}

/// THE TAIL CHECK NEVER FOLLOWS OR WAITS (PFE #26732): with an ordinary head, so recovery takes the fast path, a log
/// swapped after recovery examined it, for a link to a log with the same bytes, a dangling or looping link, a pipe or a
/// directory, is refused promptly at the tail check's own open, and nothing is written through. One row per fault. The
/// controls: each restored log recovers on the fast path, and an unswapped log answers there with no full read.
#[test]
fn a_log_swapped_before_the_tail_check_refuses_promptly_chirho() {
    let dir_chirho = own_dir_chirho("tail");
    std::fs::write(dir_chirho.join("valid-chirho.jsonl"), THREE_RECORDS_CHIRHO).unwrap();
    let rows_chirho: Vec<String> = FAULTS_CHIRHO
        .iter()
        .map(|fault_chirho| {
            let log_chirho = dir_chirho.join(format!("log-{fault_chirho}-chirho.jsonl"));
            let aside_chirho = dir_chirho.join(format!("aside-{fault_chirho}-chirho.jsonl"));
            std::fs::write(&log_chirho, THREE_RECORDS_CHIRHO).unwrap();
            reseed_seqlog_head_chirho(&log_chirho, 3).unwrap();
            let recovered_log_chirho = log_chirho.clone();
            let call_chirho = match swap_within_chirho(
                LogOpenStageChirho::TailCheckChirho,
                &dir_chirho,
                &aside_chirho,
                fault_chirho,
                move || recover_jsonl_len_unlocked_chirho(&recovered_log_chirho).is_ok(),
            ) {
                None => "waited past the deadline",
                Some((_, false)) => "the swap never ran",
                Some((true, true)) => "answered",
                Some((false, true)) => "refused",
            };
            restore_swapped_log_chirho(&log_chirho, &aside_chirho);
            format!(
                "{fault_chirho}: {call_chirho}; restored: {}",
                describe_recovery_chirho(recover_within_chirho(&log_chirho))
            )
        })
        .collect();
    let expected_chirho: Vec<String> = FAULTS_CHIRHO
        .iter()
        .map(|fault_chirho| format!("{fault_chirho}: refused; restored: Ok(3) on the fast path"))
        .collect();
    assert_eq!(
        rows_chirho, expected_chirho,
        "every log swapped before the tail check is refused, promptly, and recovers once restored"
    );
    assert_eq!(
        std::fs::read(dir_chirho.join("valid-chirho.jsonl")).unwrap(),
        THREE_RECORDS_CHIRHO,
        "the link's target is unchanged"
    );
    assert_dangling_target_absent_chirho(&dir_chirho);

    let control_chirho = dir_chirho.join("control-chirho.jsonl");
    std::fs::write(&control_chirho, THREE_RECORDS_CHIRHO).unwrap();
    reseed_seqlog_head_chirho(&control_chirho, 3).unwrap();
    assert_eq!(
        describe_recovery_chirho(recover_within_chirho(&control_chirho)),
        "Ok(3) on the fast path",
        "the control: unswapped, the fast path answers with no full read"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}

/// A FAILED RESEED NEVER UN-COMMITS AN APPEND, AND NEVER WAITS (PFE #26732): with the log swapped after its new line is
/// committed, for a link to a valid log, a dangling or looping link, a pipe or a directory, the reseed's open refuses and
/// the append still reports committed, promptly. Nothing is written through, the committed line is in the log, and the
/// restored log recovers the new count past its stale head. One row per fault. The control: with no swap the reseed
/// lands, and the next recovery is on the fast path.
#[test]
fn a_failed_reseed_never_uncommits_an_append_or_waits_chirho() {
    let dir_chirho = own_dir_chirho("reseed");
    std::fs::write(dir_chirho.join("valid-chirho.jsonl"), VALID_BYTES_CHIRHO).unwrap();
    let appended_chirho: &[u8] = b"{\"seq_chirho\":0}\n{\"seq_chirho\":1}\n";
    let rows_chirho: Vec<String> = FAULTS_CHIRHO
        .iter()
        .map(|fault_chirho| {
            let log_chirho = dir_chirho.join(format!("log-{fault_chirho}-chirho.jsonl"));
            let aside_chirho = dir_chirho.join(format!("aside-{fault_chirho}-chirho.jsonl"));
            std::fs::write(&log_chirho, VALID_BYTES_CHIRHO).unwrap();
            reseed_seqlog_head_chirho(&log_chirho, 1).unwrap();
            let appended_log_chirho = log_chirho.clone();
            let call_chirho = match swap_within_chirho(
                LogOpenStageChirho::ReseedChirho,
                &dir_chirho,
                &aside_chirho,
                fault_chirho,
                move || {
                    append_recovered_jsonl_unlocked_chirho(
                        &appended_log_chirho,
                        1,
                        &FaultRecordChirho { seq_chirho: 1 },
                    )
                    .is_ok()
                },
            ) {
                None => "waited past the deadline",
                Some((_, false)) => "the swap never ran",
                Some((true, true)) => "committed",
                Some((false, true)) => "reported uncommitted",
            };
            restore_swapped_log_chirho(&log_chirho, &aside_chirho);
            let line_chirho = if std::fs::read(&log_chirho).unwrap() == appended_chirho {
                "the line is in the log"
            } else {
                "the log lacks the line"
            };
            format!(
                "{fault_chirho}: {call_chirho}; {line_chirho}; restored: {}",
                describe_recovery_chirho(recover_within_chirho(&log_chirho))
            )
        })
        .collect();
    let expected_chirho: Vec<String> = FAULTS_CHIRHO
        .iter()
        .map(|fault_chirho| {
            format!("{fault_chirho}: committed; the line is in the log; restored: Ok(2) by the full scan")
        })
        .collect();
    assert_eq!(
        rows_chirho, expected_chirho,
        "every refused reseed leaves its committed append committed, promptly, and the stale head a miss"
    );
    assert_eq!(
        std::fs::read(dir_chirho.join("valid-chirho.jsonl")).unwrap(),
        VALID_BYTES_CHIRHO,
        "the link's target is unchanged"
    );
    assert_dangling_target_absent_chirho(&dir_chirho);

    let control_chirho = dir_chirho.join("control-chirho.jsonl");
    std::fs::write(&control_chirho, VALID_BYTES_CHIRHO).unwrap();
    reseed_seqlog_head_chirho(&control_chirho, 1).unwrap();
    append_recovered_jsonl_unlocked_chirho(
        &control_chirho,
        1,
        &FaultRecordChirho { seq_chirho: 1 },
    )
    .unwrap();
    assert_eq!(
        describe_recovery_chirho(recover_within_chirho(&control_chirho)),
        "Ok(2) on the fast path",
        "the control: unswapped, the reseed lands and recovery takes the fast path"
    );
    std::fs::remove_dir_all(&dir_chirho).unwrap();
}
