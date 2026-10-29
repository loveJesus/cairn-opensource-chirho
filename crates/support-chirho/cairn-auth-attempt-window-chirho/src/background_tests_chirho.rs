// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proves the background jobs keep history-length work off the request: the integrity pass verifies nothing on the
//! request that starts it, runs once at a time and reschedules itself an hour on; an index rebuild that meets a bad
//! record drops the view, so the next call refuses; a job whose view was replaced while it ran is discarded; and a job
//! never waits on a pipe swapped in before its open.

use crate::test_log_chirho::{
    TestLogChirho, FULL_EVERY_MS_CHIRHO, RULES_CHIRHO, START_MS_CHIRHO, TOLERANCE_MS_CHIRHO,
};
use crate::{
    hold_background_jobs_before_open_chirho, hold_background_jobs_chirho,
    join_background_job_chirho, recent_failures_chirho, verify_current_chirho, BackgroundJobChirho,
    BackgroundOutcomeChirho, FallbackCauseChirho, PathTakenChirho,
};
use std::io::Write;

const T_CHIRHO: u64 = START_MS_CHIRHO;

fn started_at_chirho(log_chirho: &TestLogChirho, now_chirho: u64) -> Option<BackgroundJobChirho> {
    verify_current_chirho(log_chirho, &RULES_CHIRHO, || now_chirho)
        .unwrap()
        .started_chirho
}

#[test]
fn the_integrity_pass_runs_off_the_request_once_at_a_time_chirho() {
    // Large enough that the pass is still running when the second call arrives, so the once-at-a-time guard is
    // what keeps that call from starting another.
    const RECORDS_CHIRHO: u64 = 20_000;
    let log_chirho = TestLogChirho::new_chirho("integrity-pass");
    for seq_chirho in 0..RECORDS_CHIRHO {
        log_chirho.append_chirho(
            seq_chirho,
            "alice",
            "login-chirho",
            false,
            T_CHIRHO + seq_chirho,
        );
    }
    let first_chirho = verify_current_chirho(&log_chirho, &RULES_CHIRHO, || {
        T_CHIRHO + RECORDS_CHIRHO + 100
    })
    .unwrap();
    assert_eq!(
        first_chirho.path_chirho,
        PathTakenChirho::FullFromFallbackChirho {
            cause_chirho: FallbackCauseChirho::FirstLoadChirho,
            verified_chirho: RECORDS_CHIRHO,
        }
    );
    let due_chirho = T_CHIRHO + RECORDS_CHIRHO + 100 + FULL_EVERY_MS_CHIRHO;
    let before_chirho = log_chirho.verified_chirho();
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "alice", "login-chirho", || {
            due_chirho
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::UnchangedChirho
    );
    assert_eq!(
        decision_chirho.status_chirho.started_chirho,
        Some(BackgroundJobChirho::IntegrityPassChirho)
    );
    assert_eq!(
        log_chirho.verified_chirho(),
        before_chirho,
        "the request that starts the pass verifies nothing itself"
    );
    // Whether the pass is still running or already done, a second call starts nothing.
    assert_eq!(started_at_chirho(&log_chirho, due_chirho + 1), None);
    assert_eq!(
        join_background_job_chirho(&log_chirho.path_chirho),
        Some(BackgroundOutcomeChirho::IntegrityConfirmedChirho {
            verified_chirho: RECORDS_CHIRHO
        })
    );
    // The confirmed pass moved the next one an hour on.
    assert_eq!(
        started_at_chirho(&log_chirho, due_chirho + FULL_EVERY_MS_CHIRHO - 1),
        None
    );
    assert_eq!(
        started_at_chirho(&log_chirho, due_chirho + FULL_EVERY_MS_CHIRHO),
        Some(BackgroundJobChirho::IntegrityPassChirho)
    );
    assert_eq!(
        join_background_job_chirho(&log_chirho.path_chirho),
        Some(BackgroundOutcomeChirho::IntegrityConfirmedChirho {
            verified_chirho: RECORDS_CHIRHO
        })
    );
}

#[test]
fn an_index_rebuild_that_meets_a_bad_record_drops_the_view_chirho() {
    let log_chirho = TestLogChirho::new_chirho("rebuild-refuses");
    for seq_chirho in 0..5u64 {
        log_chirho.append_chirho(
            seq_chirho,
            "alice",
            "login-chirho",
            false,
            T_CHIRHO + seq_chirho,
        );
    }
    assert_eq!(
        verify_current_chirho(&log_chirho, &RULES_CHIRHO, || T_CHIRHO + 10)
            .unwrap()
            .path_chirho,
        PathTakenChirho::FullFromFallbackChirho {
            cause_chirho: FallbackCauseChirho::FirstLoadChirho,
            verified_chirho: 5,
        }
    );
    // An edit the fast path cannot see: record 1 flipped in place (same length), plus a valid append.
    let mut bytes_chirho = std::fs::read(&log_chirho.path_chirho).unwrap();
    let second_line_chirho = bytes_chirho
        .iter()
        .position(|b_chirho| *b_chirho == b'\n')
        .unwrap()
        + 1;
    let flip_chirho = second_line_chirho
        + bytes_chirho[second_line_chirho..]
            .windows(3)
            .position(|window_chirho| window_chirho == b" F ")
            .expect("fixture: record 1 is a failure")
        + 1;
    bytes_chirho[flip_chirho] = b'S';
    bytes_chirho.extend_from_slice(
        log_chirho
            .line_chirho(5, "alice", "login-chirho", false, T_CHIRHO + 11)
            .as_bytes(),
    );
    let mut file_chirho = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log_chirho.path_chirho)
        .unwrap();
    file_chirho.write_all(&bytes_chirho).unwrap();
    assert_eq!(
        verify_current_chirho(&log_chirho, &RULES_CHIRHO, || T_CHIRHO + 12)
            .unwrap()
            .path_chirho,
        PathTakenChirho::IncrementalChirho { folded_chirho: 1 },
        "fixture: the fast path does not see the edit"
    );
    // A step back beyond the tolerance starts a rebuild, which verifies every record and meets the edit.
    let far_back_chirho = T_CHIRHO + 12 - TOLERANCE_MS_CHIRHO - 1_000;
    assert_eq!(
        started_at_chirho(&log_chirho, far_back_chirho),
        Some(BackgroundJobChirho::IndexRebuildChirho)
    );
    assert_eq!(
        join_background_job_chirho(&log_chirho.path_chirho),
        Some(BackgroundOutcomeChirho::RefusedChirho)
    );
    let error_chirho = verify_current_chirho(&log_chirho, &RULES_CHIRHO, || far_back_chirho + 1)
        .expect_err("the dropped view is rebuilt on the next call, which refuses the edited record")
        .to_string();
    assert!(
        error_chirho.contains("test attempt 1 signature invalid"),
        "{error_chirho}"
    );
}

/// The view-id check discards a job whose view was replaced while it ran (claude2 #25643: a check against a race is
/// pinned only by a fixture that creates the race). The race is forced, not hoped for. The rebuild job finishes
/// reading the OLD file and is held before it applies. The request path then replaces the view: a new inode, which a
/// new view verifies in full. On release the job must be abandoned, and the next call must find the request path's
/// view. Without the check, the stale index lands and the next call has to verify everything again on a request.
#[test]
fn a_job_whose_view_was_replaced_while_it_ran_is_discarded_chirho() {
    let log_chirho = TestLogChirho::new_chirho("stale-job");
    for seq_chirho in 0..5u64 {
        log_chirho.append_chirho(
            seq_chirho,
            "alice",
            "login-chirho",
            false,
            T_CHIRHO + seq_chirho,
        );
    }
    assert_eq!(
        verify_current_chirho(&log_chirho, &RULES_CHIRHO, || T_CHIRHO + 10)
            .unwrap()
            .path_chirho,
        PathTakenChirho::FullFromFallbackChirho {
            cause_chirho: FallbackCauseChirho::FirstLoadChirho,
            verified_chirho: 5,
        }
    );
    let hold_chirho = hold_background_jobs_chirho(&log_chirho.path_chirho);
    let far_back_chirho = T_CHIRHO + 10 - TOLERANCE_MS_CHIRHO - 1_000;
    assert_eq!(
        started_at_chirho(&log_chirho, far_back_chirho),
        Some(BackgroundJobChirho::IndexRebuildChirho)
    );
    hold_chirho.wait_until_held_chirho();
    // The job now holds an index of the old file. Replace the file with a new inode carrying one more record.
    let mut bytes_chirho = std::fs::read(&log_chirho.path_chirho).unwrap();
    bytes_chirho.extend_from_slice(
        log_chirho
            .line_chirho(5, "alice", "login-chirho", false, T_CHIRHO + 11)
            .as_bytes(),
    );
    let staged_chirho = log_chirho.path_chirho.with_extension("staged-chirho");
    std::fs::write(&staged_chirho, &bytes_chirho).unwrap();
    std::fs::rename(&staged_chirho, &log_chirho.path_chirho).unwrap();
    assert_eq!(
        verify_current_chirho(&log_chirho, &RULES_CHIRHO, || far_back_chirho + 1)
            .unwrap()
            .path_chirho,
        PathTakenChirho::FullFromFallbackChirho {
            cause_chirho: FallbackCauseChirho::IdentityChangedChirho,
            verified_chirho: 6,
        },
        "fixture: the request path really replaced the view while the job was held"
    );
    drop(hold_chirho);
    assert_eq!(
        join_background_job_chirho(&log_chirho.path_chirho),
        Some(BackgroundOutcomeChirho::AbandonedChirho)
    );
    assert_eq!(
        verify_current_chirho(&log_chirho, &RULES_CHIRHO, || far_back_chirho + 2)
            .unwrap()
            .path_chirho,
        PathTakenChirho::UnchangedChirho,
        "a stale job's index must not replace the request path's view"
    );
}

/// A JOB NEVER WAITS ON A PIPE (the shared absence brick): a background rebuild held just before it opens the log,
/// while the log is swapped for a pipe, finishes promptly when released, abandoned with nothing applied, because its
/// open neither follows nor blocks. The request path then refuses the pipe itself, and once the regular log is back
/// the view recovers with a full load.
///
/// MIGRATION PATH: a deadline failure means the job's open waits on a pipe; a job thread stuck there never finishes,
/// and a request that waits on it hangs with it.
#[test]
fn a_background_job_never_waits_on_a_pipe_swapped_in_before_its_open_chirho() {
    let log_chirho = TestLogChirho::new_chirho("job-pipe");
    for seq_chirho in 0..5u64 {
        log_chirho.append_chirho(
            seq_chirho,
            "alice",
            "login-chirho",
            false,
            T_CHIRHO + seq_chirho,
        );
    }
    assert_eq!(
        verify_current_chirho(&log_chirho, &RULES_CHIRHO, || T_CHIRHO + 10)
            .unwrap()
            .path_chirho,
        PathTakenChirho::FullFromFallbackChirho {
            cause_chirho: FallbackCauseChirho::FirstLoadChirho,
            verified_chirho: 5,
        }
    );
    let hold_chirho = hold_background_jobs_before_open_chirho(&log_chirho.path_chirho);
    let far_back_chirho = T_CHIRHO + 10 - TOLERANCE_MS_CHIRHO - 1_000;
    assert_eq!(
        started_at_chirho(&log_chirho, far_back_chirho),
        Some(BackgroundJobChirho::IndexRebuildChirho)
    );
    hold_chirho.wait_until_held_chirho();
    let saved_chirho = std::fs::read(&log_chirho.path_chirho).unwrap();
    std::fs::remove_file(&log_chirho.path_chirho).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(&log_chirho.path_chirho)
        .status()
        .unwrap()
        .success());
    drop(hold_chirho);
    let joined_path_chirho = log_chirho.path_chirho.clone();
    let (sender_chirho, receiver_chirho) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender_chirho.send(join_background_job_chirho(&joined_path_chirho));
    });
    let outcome_chirho = receiver_chirho
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the job finished promptly, never waiting on the pipe");
    assert_eq!(
        outcome_chirho,
        Some(BackgroundOutcomeChirho::AbandonedChirho)
    );
    let refusal_chirho = verify_current_chirho(&log_chirho, &RULES_CHIRHO, || far_back_chirho + 1)
        .expect_err("the request path refuses the pipe itself");
    assert!(
        format!("{refusal_chirho:#}").contains("is a pipe"),
        "{refusal_chirho:#}"
    );
    std::fs::remove_file(&log_chirho.path_chirho).unwrap();
    std::fs::write(&log_chirho.path_chirho, &saved_chirho).unwrap();
    assert!(matches!(
        verify_current_chirho(&log_chirho, &RULES_CHIRHO, || far_back_chirho + 2)
            .unwrap()
            .path_chirho,
        PathTakenChirho::FullFromFallbackChirho {
            verified_chirho: 5,
            ..
        }
    ));
}
