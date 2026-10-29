// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proves every change the view cannot extend verifies the whole log again with its own cause, bad records fail
//! closed and keep failing, the threat boundary holds only until the hourly integrity pass, torn and newline-less
//! final lines behave as stated, concurrent writers and readers never double count, a panic is recovered once, and
//! eviction drops the least recently used slot.

use crate::test_log_chirho::{
    full_scan_count_chirho, TestLogChirho, FULL_EVERY_MS_CHIRHO, RULES_CHIRHO, START_MS_CHIRHO,
};
use crate::{
    join_background_job_chirho, recent_failures_chirho, verify_current_chirho, BackgroundJobChirho,
    BackgroundOutcomeChirho, FallbackCauseChirho, PathTakenChirho,
};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

const T_CHIRHO: u64 = START_MS_CHIRHO;

fn seeded_log_chirho(name_chirho: &str, records_chirho: u64) -> TestLogChirho {
    let log_chirho = TestLogChirho::new_chirho(name_chirho);
    for seq_chirho in 0..records_chirho {
        log_chirho.append_chirho(
            seq_chirho,
            "alice",
            "login-chirho",
            false,
            T_CHIRHO + seq_chirho,
        );
    }
    log_chirho
}

fn path_at_chirho(log_chirho: &TestLogChirho, now_chirho: u64) -> PathTakenChirho {
    verify_current_chirho(log_chirho, &RULES_CHIRHO, || now_chirho)
        .unwrap_or_else(|error_chirho| panic!("unexpected refusal: {error_chirho:#}"))
        .path_chirho
}

fn error_at_chirho(log_chirho: &TestLogChirho, now_chirho: u64) -> String {
    verify_current_chirho(log_chirho, &RULES_CHIRHO, || now_chirho)
        .expect_err("the view must refuse this log")
        .to_string()
}

fn full_chirho(cause_chirho: FallbackCauseChirho, verified_chirho: u64) -> PathTakenChirho {
    PathTakenChirho::FullFromFallbackChirho {
        cause_chirho,
        verified_chirho,
    }
}

fn first_load_chirho(verified_chirho: u64) -> PathTakenChirho {
    full_chirho(FallbackCauseChirho::FirstLoadChirho, verified_chirho)
}

/// Rewrite the file through the same inode, then move its mtime to a distinct time, so the change shows however
/// coarse the filesystem's timestamps are.
fn rewrite_in_place_chirho(log_chirho: &TestLogChirho, edit_chirho: impl FnOnce(&mut Vec<u8>)) {
    let mut bytes_chirho = std::fs::read(&log_chirho.path_chirho).unwrap();
    edit_chirho(&mut bytes_chirho);
    let mut file_chirho = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log_chirho.path_chirho)
        .unwrap();
    file_chirho.write_all(&bytes_chirho).unwrap();
    file_chirho
        .set_modified(SystemTime::now() + Duration::from_secs(7))
        .unwrap();
}

/// Replace the file with a new inode holding `bytes_chirho`.
fn swap_inode_chirho(log_chirho: &TestLogChirho, bytes_chirho: &[u8]) {
    let staged_chirho = log_chirho.path_chirho.with_extension("staged-chirho");
    std::fs::write(&staged_chirho, bytes_chirho).unwrap();
    std::fs::rename(&staged_chirho, &log_chirho.path_chirho).unwrap();
}

/// The byte range of the `index_chirho`-th line, newline included.
fn line_range_chirho(bytes_chirho: &[u8], index_chirho: usize) -> std::ops::Range<usize> {
    let mut start_chirho = 0usize;
    for _ in 0..index_chirho {
        start_chirho += bytes_chirho[start_chirho..]
            .iter()
            .position(|b_chirho| *b_chirho == b'\n')
            .unwrap()
            + 1;
    }
    let len_chirho = bytes_chirho[start_chirho..]
        .iter()
        .position(|b_chirho| *b_chirho == b'\n')
        .unwrap()
        + 1;
    start_chirho..start_chirho + len_chirho
}

/// Flip a failure to a success in the `index_chirho`-th line, without re-signing it. The length is unchanged.
fn flip_outcome_chirho(bytes_chirho: &mut [u8], index_chirho: usize) {
    let range_chirho = line_range_chirho(bytes_chirho, index_chirho);
    let line_chirho = &mut bytes_chirho[range_chirho];
    let at_chirho = line_chirho
        .windows(3)
        .position(|window_chirho| window_chirho == b" F ")
        .expect("fixture: the line records a failure");
    line_chirho[at_chirho + 1] = b'S';
}

#[test]
fn a_bad_signature_in_the_delta_fails_closed_until_the_record_is_gone_chirho() {
    let log_chirho = seeded_log_chirho("bad-signature", 5);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(5)
    );
    let good_len_chirho = std::fs::metadata(&log_chirho.path_chirho).unwrap().len();
    let forged_chirho = log_chirho
        .line_chirho(5, "alice", "login-chirho", false, T_CHIRHO + 11)
        .replacen(" F ", " S ", 1);
    log_chirho.append_raw_chirho(forged_chirho.as_bytes());
    let error_chirho = error_at_chirho(&log_chirho, T_CHIRHO + 12);
    assert!(
        error_chirho.contains("test attempt 5 signature invalid"),
        "{error_chirho}"
    );
    // The refusal dropped the view, so the next call verifies everything, and refuses again.
    let error_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            T_CHIRHO + 13
        })
        .expect_err("the forged record is still there")
        .to_string();
    assert!(
        error_chirho.contains("test attempt 5 signature invalid"),
        "{error_chirho}"
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(&log_chirho.path_chirho)
        .unwrap()
        .set_len(good_len_chirho)
        .unwrap();
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 14),
        first_load_chirho(5)
    );
}

#[test]
fn a_seq_gap_in_the_delta_fails_closed_chirho() {
    let log_chirho = seeded_log_chirho("seq-gap", 5);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(5)
    );
    log_chirho.append_chirho(6, "alice", "login-chirho", false, T_CHIRHO + 11);
    let error_chirho = error_at_chirho(&log_chirho, T_CHIRHO + 12);
    assert!(
        error_chirho.contains("seq gap at index 5: entry seq is 6"),
        "{error_chirho}"
    );
}

#[test]
fn a_changed_anchor_line_verifies_everything_again_chirho() {
    let log_chirho = seeded_log_chirho("anchor", 5);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(5)
    );
    // A benign change to the last verified line (a space before its newline), plus a valid append.
    let appended_chirho = log_chirho.line_chirho(5, "alice", "login-chirho", false, T_CHIRHO + 11);
    rewrite_in_place_chirho(&log_chirho, |bytes_chirho| {
        let end_chirho = line_range_chirho(bytes_chirho, 4).end;
        bytes_chirho.insert(end_chirho - 1, b' ');
        bytes_chirho.extend_from_slice(appended_chirho.as_bytes());
    });
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 12),
        full_chirho(FallbackCauseChirho::AnchorChangedChirho, 6)
    );
    // A forged change to the last verified line, plus a valid append: the full pass refuses it.
    let appended_chirho = log_chirho.line_chirho(6, "alice", "login-chirho", false, T_CHIRHO + 13);
    rewrite_in_place_chirho(&log_chirho, |bytes_chirho| {
        flip_outcome_chirho(bytes_chirho, 5);
        bytes_chirho.extend_from_slice(appended_chirho.as_bytes());
    });
    let error_chirho = error_at_chirho(&log_chirho, T_CHIRHO + 14);
    assert!(
        error_chirho.contains("test attempt 5 signature invalid"),
        "{error_chirho}"
    );
}

#[test]
fn a_same_length_change_in_place_verifies_everything_again_chirho() {
    let log_chirho = TestLogChirho::new_chirho("same-length");
    for seq_chirho in 0..5u64 {
        let line_chirho = log_chirho.line_chirho(
            seq_chirho,
            "alice",
            "login-chirho",
            false,
            T_CHIRHO + seq_chirho,
        );
        // Two trailing spaces on every line leave room for a benign same-length edit.
        log_chirho.append_raw_chirho(line_chirho.replace('\n', "  \n").as_bytes());
    }
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(5)
    );
    // Benign: a space becomes a tab in an older line. Same length, same records.
    rewrite_in_place_chirho(&log_chirho, |bytes_chirho| {
        let end_chirho = line_range_chirho(bytes_chirho, 1).end;
        bytes_chirho[end_chirho - 3] = b'\t';
    });
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 11),
        full_chirho(FallbackCauseChirho::RewrittenInPlaceChirho, 5)
    );
    // Forged: an older failure becomes a success. Same length; the full pass refuses it.
    rewrite_in_place_chirho(&log_chirho, |bytes_chirho| {
        flip_outcome_chirho(bytes_chirho, 1)
    });
    let error_chirho = error_at_chirho(&log_chirho, T_CHIRHO + 12);
    assert!(
        error_chirho.contains("test attempt 1 signature invalid"),
        "{error_chirho}"
    );
}

#[test]
fn a_shrink_below_the_verified_prefix_verifies_everything_again_chirho() {
    let log_chirho = seeded_log_chirho("shrink", 5);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(5)
    );
    let bytes_chirho = std::fs::read(&log_chirho.path_chirho).unwrap();
    let file_chirho = std::fs::OpenOptions::new()
        .write(true)
        .open(&log_chirho.path_chirho)
        .unwrap();
    file_chirho
        .set_len(line_range_chirho(&bytes_chirho, 3).end as u64)
        .unwrap();
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            T_CHIRHO + 11
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        full_chirho(FallbackCauseChirho::ShrunkChirho, 4)
    );
    assert_eq!(decision_chirho.recent_failures_chirho, 4);
    assert_eq!(
        full_scan_count_chirho(&log_chirho, "alice", "login-chirho", T_CHIRHO + 11).unwrap(),
        4
    );
    // Cut inside record 2: the torn tail is left out. Today's full scan refuses the torn line instead.
    file_chirho
        .set_len(line_range_chirho(&bytes_chirho, 2).start as u64 + 5)
        .unwrap();
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 12),
        full_chirho(FallbackCauseChirho::ShrunkChirho, 2)
    );
    assert!(full_scan_count_chirho(&log_chirho, "alice", "login-chirho", T_CHIRHO + 12).is_err());
}

#[test]
fn a_new_inode_verifies_everything_again_even_with_the_anchor_intact_chirho() {
    let log_chirho = seeded_log_chirho("inode", 5);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(5)
    );
    let mut bytes_chirho = std::fs::read(&log_chirho.path_chirho).unwrap();
    bytes_chirho.extend_from_slice(
        log_chirho
            .line_chirho(5, "alice", "login-chirho", false, T_CHIRHO + 11)
            .as_bytes(),
    );
    swap_inode_chirho(&log_chirho, &bytes_chirho);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 12),
        full_chirho(FallbackCauseChirho::IdentityChangedChirho, 6)
    );
    // Forged: an older record edited, the anchor line untouched and at the same offset, the file longer. Only the
    // inode says it is a different file.
    flip_outcome_chirho(&mut bytes_chirho, 1);
    bytes_chirho.extend_from_slice(
        log_chirho
            .line_chirho(6, "alice", "login-chirho", false, T_CHIRHO + 13)
            .as_bytes(),
    );
    swap_inode_chirho(&log_chirho, &bytes_chirho);
    let error_chirho = error_at_chirho(&log_chirho, T_CHIRHO + 14);
    assert!(
        error_chirho.contains("test attempt 1 signature invalid"),
        "{error_chirho}"
    );
}

#[test]
fn a_new_verification_key_verifies_everything_again_chirho() {
    let log_chirho = seeded_log_chirho("verifier", 5);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(5)
    );
    let rotated_chirho = log_chirho.handle_chirho("key-b-chirho");
    // Records signed by the old key do not verify under the new one.
    let error_chirho = error_at_chirho(&rotated_chirho, T_CHIRHO + 11);
    assert!(
        error_chirho.contains("test attempt 0 signature invalid"),
        "{error_chirho}"
    );
    // Re-signed under the new key: the change of key alone forces the full pass.
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 12),
        first_load_chirho(5)
    );
    let resigned_chirho: String = (0..5u64)
        .map(|seq_chirho| {
            rotated_chirho.line_chirho(
                seq_chirho,
                "alice",
                "login-chirho",
                false,
                T_CHIRHO + seq_chirho,
            )
        })
        .collect();
    rewrite_in_place_chirho(&log_chirho, |bytes_chirho| {
        *bytes_chirho = resigned_chirho.into_bytes()
    });
    assert_eq!(
        path_at_chirho(&rotated_chirho, T_CHIRHO + 13),
        full_chirho(FallbackCauseChirho::VerifierChangedChirho, 5)
    );
}

#[test]
fn a_missing_log_is_empty_and_its_first_records_load_fully_chirho() {
    let log_chirho = TestLogChirho::new_chirho("missing");
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            T_CHIRHO
        })
        .unwrap();
    assert_eq!(decision_chirho.recent_failures_chirho, 0);
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::MissingLogChirho
    );
    log_chirho.append_chirho(0, "alice", "login-chirho", false, T_CHIRHO);
    log_chirho.append_chirho(1, "alice", "login-chirho", false, T_CHIRHO + 1);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 2),
        first_load_chirho(2)
    );
    // A log seen present that disappears is refused, never read as empty again (the shared absence brick): deleting
    // the attempt log must not reset the sign-in window.
    std::fs::remove_file(&log_chirho.path_chirho).unwrap();
    assert!(error_at_chirho(&log_chirho, T_CHIRHO + 3).contains("was present and is now missing"));
    // Once a regular log is back, the view recovers with a full load.
    log_chirho.append_chirho(0, "alice", "login-chirho", false, T_CHIRHO + 4);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 5),
        first_load_chirho(1)
    );
}

/// The threat boundary and its bound: an edit to an older record that keeps the anchor and grows the file is not
/// seen by the fast path, decisions keep using the verified original, and the hourly integrity pass refuses the log.
/// That pass runs in the background: past the hour, the check that starts it still reads only new bytes, and the
/// pass's failure drops the view so the next call refuses.
#[test]
fn an_unseen_older_edit_keeps_verified_decisions_until_the_hourly_pass_chirho() {
    let log_chirho = seeded_log_chirho("boundary", 5);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(5)
    );
    let appended_chirho = log_chirho.line_chirho(5, "alice", "login-chirho", false, T_CHIRHO + 11);
    rewrite_in_place_chirho(&log_chirho, |bytes_chirho| {
        flip_outcome_chirho(bytes_chirho, 1);
        bytes_chirho.extend_from_slice(appended_chirho.as_bytes());
    });
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            T_CHIRHO + 12
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::IncrementalChirho { folded_chirho: 1 }
    );
    assert_eq!(
        decision_chirho.recent_failures_chirho, 6,
        "the verified original still counts the edited failure"
    );
    assert!(
        full_scan_count_chirho(&log_chirho, "alice", "login-chirho", T_CHIRHO + 12).is_err(),
        "control: today's full scan refuses the edited log"
    );
    let within_chirho = T_CHIRHO + 10 + FULL_EVERY_MS_CHIRHO - 1;
    assert_eq!(
        path_at_chirho(&log_chirho, within_chirho),
        PathTakenChirho::UnchangedChirho
    );
    let past_the_hour_chirho = T_CHIRHO + 10 + FULL_EVERY_MS_CHIRHO;
    let before_chirho = log_chirho.verified_chirho();
    let status_chirho =
        verify_current_chirho(&log_chirho, &RULES_CHIRHO, || past_the_hour_chirho).unwrap();
    assert_eq!(status_chirho.path_chirho, PathTakenChirho::UnchangedChirho);
    assert_eq!(
        status_chirho.started_chirho,
        Some(BackgroundJobChirho::IntegrityPassChirho)
    );
    assert_eq!(
        log_chirho.verified_chirho(),
        before_chirho,
        "the request itself verifies nothing; the pass runs on its own thread"
    );
    assert_eq!(
        join_background_job_chirho(&log_chirho.path_chirho),
        Some(BackgroundOutcomeChirho::RefusedChirho)
    );
    let error_chirho = error_at_chirho(&log_chirho, past_the_hour_chirho + 1);
    assert!(
        error_chirho.contains("test attempt 1 signature invalid"),
        "{error_chirho}"
    );
}

#[test]
fn a_final_line_without_its_newline_counts_once_it_parses_chirho() {
    let log_chirho = TestLogChirho::new_chirho("no-newline");
    let line_chirho = log_chirho.line_chirho(0, "alice", "login-chirho", false, T_CHIRHO);
    log_chirho.append_raw_chirho(line_chirho.trim_end_matches('\n').as_bytes());
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            T_CHIRHO + 1
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        first_load_chirho(1)
    );
    assert_eq!(decision_chirho.recent_failures_chirho, 1);
    assert_eq!(
        full_scan_count_chirho(&log_chirho, "alice", "login-chirho", T_CHIRHO + 1).unwrap(),
        1
    );
    // The newline arrives (as seqlog recovery would add it), then the next record.
    log_chirho.append_raw_chirho(b"\n");
    log_chirho.append_chirho(1, "alice", "login-chirho", false, T_CHIRHO + 2);
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            T_CHIRHO + 3
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::IncrementalChirho { folded_chirho: 1 }
    );
    assert_eq!(decision_chirho.recent_failures_chirho, 2);
    assert_eq!(
        full_scan_count_chirho(&log_chirho, "alice", "login-chirho", T_CHIRHO + 3).unwrap(),
        2
    );
}

#[test]
fn a_torn_final_line_waits_until_it_is_complete_chirho() {
    let log_chirho = seeded_log_chirho("torn", 3);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(3)
    );
    let line_chirho = log_chirho.line_chirho(3, "alice", "login-chirho", false, T_CHIRHO + 11);
    let (head_chirho, tail_chirho) = line_chirho.as_bytes().split_at(line_chirho.len() / 2);
    log_chirho.append_raw_chirho(head_chirho);
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            T_CHIRHO + 12
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::IncrementalChirho { folded_chirho: 0 }
    );
    assert_eq!(decision_chirho.recent_failures_chirho, 3);
    assert!(
        full_scan_count_chirho(&log_chirho, "alice", "login-chirho", T_CHIRHO + 12).is_err(),
        "today's full scan refuses a torn final line; the view leaves it for later"
    );
    log_chirho.append_raw_chirho(tail_chirho);
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            T_CHIRHO + 13
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::IncrementalChirho { folded_chirho: 1 }
    );
    assert_eq!(decision_chirho.recent_failures_chirho, 4);
    assert_eq!(
        full_scan_count_chirho(&log_chirho, "alice", "login-chirho", T_CHIRHO + 13).unwrap(),
        4
    );
}

/// Two writers (separate handles, as two processes would have) and two readers sharing one slot: no reader is ever
/// refused, nothing is counted twice, and with the clock read inside the lock no call looks like a regression.
#[test]
fn concurrent_writers_and_readers_never_double_count_chirho() {
    const PER_WRITER_CHIRHO: u64 = 300;
    let log_chirho = TestLogChirho::new_chirho("concurrent");
    let next_seq_chirho = Mutex::new(0u64);
    let clock_chirho = AtomicU64::new(T_CHIRHO);
    let writers_done_chirho = AtomicU64::new(0);
    let paths_chirho: Mutex<Vec<PathTakenChirho>> = Mutex::new(Vec::new());
    std::thread::scope(|scope_chirho| {
        for writer_chirho in 0..2u64 {
            let writer_log_chirho = log_chirho.handle_chirho(&log_chirho.verifier_chirho);
            let next_seq_chirho = &next_seq_chirho;
            let writers_done_chirho = &writers_done_chirho;
            scope_chirho.spawn(move || {
                for _ in 0..PER_WRITER_CHIRHO {
                    // The seq lock stands in for the appenders' shared file lock.
                    let mut seq_chirho = next_seq_chirho.lock().unwrap();
                    writer_log_chirho.append_chirho(
                        *seq_chirho,
                        &format!("w{writer_chirho}"),
                        "login-chirho",
                        false,
                        T_CHIRHO,
                    );
                    *seq_chirho += 1;
                }
                writers_done_chirho.fetch_add(1, Ordering::SeqCst);
            });
        }
        for _ in 0..2 {
            let reader_chirho = log_chirho.handle_chirho(&log_chirho.verifier_chirho);
            let (clock_chirho, writers_done_chirho, paths_chirho) =
                (&clock_chirho, &writers_done_chirho, &paths_chirho);
            scope_chirho.spawn(move || {
                // Bounded, so the test clock (one millisecond per call) stays inside the window and the hour.
                for _ in 0..20_000 {
                    if writers_done_chirho.load(Ordering::SeqCst) == 2 {
                        break;
                    }
                    let decision_chirho = recent_failures_chirho(
                        &reader_chirho,
                        &RULES_CHIRHO,
                        "w0",
                        "login-chirho",
                        || clock_chirho.fetch_add(1, Ordering::SeqCst),
                    )
                    .unwrap_or_else(|error_chirho| {
                        panic!("a reader was refused mid-write: {error_chirho:#}")
                    });
                    paths_chirho
                        .lock()
                        .unwrap()
                        .push(decision_chirho.status_chirho.path_chirho);
                }
            });
        }
    });
    let now_chirho = clock_chirho.fetch_add(1, Ordering::SeqCst);
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "w0", "login-chirho", || {
            now_chirho
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.verified_records_chirho,
        2 * PER_WRITER_CHIRHO
    );
    assert_eq!(decision_chirho.recent_failures_chirho, PER_WRITER_CHIRHO);
    assert_eq!(
        full_scan_count_chirho(&log_chirho, "w0", "login-chirho", now_chirho).unwrap(),
        PER_WRITER_CHIRHO
    );
    let paths_chirho = paths_chirho.into_inner().unwrap();
    let first_loads_chirho = paths_chirho
        .iter()
        .filter(|path_chirho| {
            matches!(
                path_chirho,
                PathTakenChirho::FullFromFallbackChirho {
                    cause_chirho: FallbackCauseChirho::FirstLoadChirho,
                    ..
                }
            )
        })
        .count();
    let other_full_chirho = paths_chirho
        .iter()
        .filter(|path_chirho| matches!(path_chirho, PathTakenChirho::FullFromFallbackChirho { .. }))
        .count()
        - first_loads_chirho;
    assert!(
        first_loads_chirho <= 1,
        "the shared slot loaded {first_loads_chirho} times"
    );
    assert_eq!(
        other_full_chirho, 0,
        "a concurrent reader fell back: {paths_chirho:?}"
    );
}

#[test]
fn a_panic_inside_an_update_drops_the_view_once_then_recovers_chirho() {
    let log_chirho = seeded_log_chirho("panic", 3);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 10),
        first_load_chirho(3)
    );
    log_chirho.append_chirho(3, "alice", "login-chirho", false, T_CHIRHO + 11);
    let panicking_chirho = log_chirho.panicking_handle_chirho(3);
    let caught_chirho = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_current_chirho(&panicking_chirho, &RULES_CHIRHO, || T_CHIRHO + 12)
    }));
    assert!(caught_chirho.is_err(), "fixture: the planted panic fired");
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 13),
        first_load_chirho(4)
    );
    log_chirho.append_chirho(4, "alice", "login-chirho", false, T_CHIRHO + 14);
    assert_eq!(
        path_at_chirho(&log_chirho, T_CHIRHO + 15),
        PathTakenChirho::IncrementalChirho { folded_chirho: 1 },
        "the poison must be cleared, or every later call would verify everything"
    );
}
