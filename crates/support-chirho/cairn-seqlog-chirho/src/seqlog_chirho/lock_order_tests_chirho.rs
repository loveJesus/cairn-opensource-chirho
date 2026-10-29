// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The named-lock funnel refuses, by name and before blocking, a lock re-entered on its own thread and a nesting that inverts the lock order around account attribution.

use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ATTRIBUTION_CHIRHO: &str = "privacy-account-attribution-chirho";
const SUBJECT_RIGHTS_CHIRHO: &str = "privacy-subject-rights-chirho";
const APPEND_LOG_CHIRHO: &str = "append-log-chirho";
const BLOB_RECORDS_CHIRHO: &str = "privacy-blob-records-chirho";
const ERASURE_RECORDS_CHIRHO: &str = "privacy-erasure-records-chirho";

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must follow the Unix epoch")
        .as_nanos();
    let sequence_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-seqlog-lock-order-{label_chirho}-{}-{nanos_chirho}-{sequence_chirho}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// Runs `action_chirho` on its own thread and fails the test, rather than hanging it, if the action blocks:
/// without the refusal, re-entering a named lock deadlocks on the process-local mutex.
fn within_seconds_chirho(
    action_chirho: impl FnOnce() -> Result<()> + Send + 'static,
) -> Result<()> {
    let (sender_chirho, receiver_chirho) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender_chirho.send(action_chirho());
    });
    receiver_chirho
        .recv_timeout(Duration::from_secs(10))
        .expect("the nested named lock blocked instead of refusing")
}

fn order_error_chirho(result_chirho: Result<()>) -> NamedLockOrderErrorChirho {
    let error_chirho = result_chirho.expect_err("the nested named lock was granted");
    error_chirho
        .downcast_ref::<NamedLockOrderErrorChirho>()
        .unwrap_or_else(|| panic!("not a named lock-order refusal: {error_chirho}"))
        .clone()
}

#[test]
fn a_named_lock_re_entered_on_its_own_thread_refuses_instead_of_deadlocking_chirho() {
    let root_chirho = temp_root_chirho("reentry");
    let inner_root_chirho = root_chirho.clone();
    let refusal_chirho = order_error_chirho(within_seconds_chirho(move || {
        with_named_lock_chirho(&inner_root_chirho, BLOB_RECORDS_CHIRHO, || {
            with_named_lock_chirho(&inner_root_chirho, BLOB_RECORDS_CHIRHO, || Ok(()))
        })
    }));
    assert_eq!(
        refusal_chirho,
        NamedLockOrderErrorChirho {
            held_chirho: BLOB_RECORDS_CHIRHO.to_string(),
            requested_chirho: BLOB_RECORDS_CHIRHO.to_string(),
            reentry_chirho: true,
        }
    );
    // The read-lock funnel refuses re-entry the same way.
    let inner_root_chirho = root_chirho.clone();
    let refusal_chirho = order_error_chirho(within_seconds_chirho(move || {
        with_named_lock_chirho(&inner_root_chirho, BLOB_RECORDS_CHIRHO, || {
            with_existing_named_read_lock_chirho(&inner_root_chirho, BLOB_RECORDS_CHIRHO, || Ok(()))
        })
    }));
    assert!(refusal_chirho.reentry_chirho);
    // After a refusal the outer lock was released normally: the same thread takes it again.
    with_named_lock_chirho(&root_chirho, BLOB_RECORDS_CHIRHO, || Ok(())).unwrap();
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

#[test]
fn a_nesting_that_inverts_the_attribution_order_refuses_by_name_chirho() {
    let root_chirho = temp_root_chirho("forbidden");
    for (held_chirho, requested_chirho) in [
        (ATTRIBUTION_CHIRHO, SUBJECT_RIGHTS_CHIRHO),
        (ATTRIBUTION_CHIRHO, APPEND_LOG_CHIRHO),
        (BLOB_RECORDS_CHIRHO, ATTRIBUTION_CHIRHO),
        (ERASURE_RECORDS_CHIRHO, ATTRIBUTION_CHIRHO),
    ] {
        let inner_root_chirho = root_chirho.clone();
        let refusal_chirho = order_error_chirho(within_seconds_chirho(move || {
            with_named_lock_chirho(&inner_root_chirho, held_chirho, || {
                with_named_lock_chirho(&inner_root_chirho, requested_chirho, || Ok(()))
            })
        }));
        assert_eq!(
            refusal_chirho,
            NamedLockOrderErrorChirho {
                held_chirho: held_chirho.to_string(),
                requested_chirho: requested_chirho.to_string(),
                reentry_chirho: false,
            }
        );
    }
    // A forbidden pair stays forbidden with another lock between them.
    let inner_root_chirho = root_chirho.clone();
    let refusal_chirho = order_error_chirho(within_seconds_chirho(move || {
        with_named_lock_chirho(&inner_root_chirho, ATTRIBUTION_CHIRHO, || {
            with_named_lock_chirho(&inner_root_chirho, BLOB_RECORDS_CHIRHO, || {
                with_named_lock_chirho(&inner_root_chirho, SUBJECT_RIGHTS_CHIRHO, || Ok(()))
            })
        })
    }));
    assert_eq!(refusal_chirho.held_chirho, ATTRIBUTION_CHIRHO);
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

#[test]
fn the_declared_order_and_other_roots_are_granted_chirho() {
    let root_chirho = temp_root_chirho("granted");
    let other_root_chirho = temp_root_chirho("granted-other");
    with_named_lock_chirho(&root_chirho, SUBJECT_RIGHTS_CHIRHO, || {
        with_named_lock_chirho(&root_chirho, ATTRIBUTION_CHIRHO, || {
            with_named_lock_chirho(&root_chirho, ERASURE_RECORDS_CHIRHO, || Ok(()))
        })
    })
    .unwrap();
    with_named_lock_chirho(&root_chirho, APPEND_LOG_CHIRHO, || {
        with_named_lock_chirho(&root_chirho, ATTRIBUTION_CHIRHO, || {
            with_named_lock_chirho(&root_chirho, BLOB_RECORDS_CHIRHO, || Ok(()))
        })
    })
    .unwrap();
    // The order is per root: attribution on one root does not order another root's locks.
    with_named_lock_chirho(&root_chirho, ATTRIBUTION_CHIRHO, || {
        with_named_lock_chirho(&other_root_chirho, SUBJECT_RIGHTS_CHIRHO, || Ok(()))
    })
    .unwrap();
    std::fs::remove_dir_all(&root_chirho).unwrap();
    std::fs::remove_dir_all(&other_root_chirho).unwrap();
}

#[test]
fn a_panicking_action_forgets_its_lock_chirho() {
    let root_chirho = temp_root_chirho("panic");
    let panicked_chirho = catch_unwind(AssertUnwindSafe(|| {
        let _ = with_named_lock_chirho(&root_chirho, ATTRIBUTION_CHIRHO, || -> Result<()> {
            panic!("an action panicked while holding the attribution lock")
        });
    }));
    assert!(panicked_chirho.is_err());
    // The unwound lock is no longer recorded as held, so the order it forbade is open again.
    with_named_lock_chirho(&root_chirho, SUBJECT_RIGHTS_CHIRHO, || Ok(())).unwrap();
    std::fs::remove_dir_all(&root_chirho).unwrap();
}
