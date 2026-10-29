// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! One redb file is held by at most one handle in this process at a time: a second open of the same path WAITS for
//! the first handle to drop, instead of colliding on redb's exclusive file lock (`DatabaseAlreadyOpen`).
//!
//! Why: redb takes `flock(LOCK_EX | LOCK_NB)` on every open, and the stores are opened per call. Two concurrent
//! requests on one tenant store, two principals saving at once, made the second open fail. PFE measured 6 of 24
//! simultaneous saves refused (#25853), and a refusal inside an effect records its run as FAILED, which refuses every
//! retry of that exact request (CAIRN #25854).
//! - A second open on the SAME thread REFUSES rather than waits. A nested open of the same file failed before; a plain
//!   lock would turn that error into a hang.
//! - The wait is bounded, so an unforeseen cycle between two stores becomes an error, never a hang.
//! - Other processes (operator commands) still meet redb's own file lock: this serializes this process only.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

/// How long an open waits for another handle on the same path to drop before it refuses.
const OPEN_WAIT_LIMIT_CHIRHO: Duration = Duration::from_secs(30);

struct PathLockChirho {
    holder_chirho: Mutex<Option<ThreadId>>,
    released_chirho: Condvar,
}

fn path_locks_chirho() -> &'static Mutex<HashMap<PathBuf, Arc<PathLockChirho>>> {
    static PATH_LOCKS_CHIRHO: OnceLock<Mutex<HashMap<PathBuf, Arc<PathLockChirho>>>> =
        OnceLock::new();
    PATH_LOCKS_CHIRHO.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The same file under one key however its path was spelled: the parent directory canonicalized (it exists by now,
/// since every constructor creates it first) and the file name joined back. The file itself may not exist yet.
fn lock_key_chirho(path_chirho: &Path) -> PathBuf {
    match (path_chirho.parent(), path_chirho.file_name()) {
        (Some(parent_chirho), Some(name_chirho)) => std::fs::canonicalize(parent_chirho)
            .map(|parent_chirho| parent_chirho.join(name_chirho))
            .unwrap_or_else(|_| path_chirho.to_path_buf()),
        _ => path_chirho.to_path_buf(),
    }
}

/// Held for a store handle's whole life. Declared AFTER the handle's `Database` field, so the file lock is released
/// first; dropping it then lets the next opener of the same path in.
pub(crate) struct StoreOpenGuardChirho {
    lock_chirho: Arc<PathLockChirho>,
}

impl StoreOpenGuardChirho {
    /// Wait until no other handle in this process holds `path`, then hold it.
    pub(crate) fn acquire_chirho(path_chirho: &Path) -> Result<Self> {
        Self::acquire_within_chirho(path_chirho, OPEN_WAIT_LIMIT_CHIRHO)
    }

    pub(crate) fn acquire_within_chirho(
        path_chirho: &Path,
        limit_chirho: Duration,
    ) -> Result<Self> {
        let lock_chirho = path_locks_chirho()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(lock_key_chirho(path_chirho))
            .or_insert_with(|| {
                Arc::new(PathLockChirho {
                    holder_chirho: Mutex::new(None),
                    released_chirho: Condvar::new(),
                })
            })
            .clone();
        let current_chirho = thread::current().id();
        let deadline_chirho = Instant::now() + limit_chirho;
        let mut holder_chirho = lock_chirho
            .holder_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            match *holder_chirho {
                None => {
                    *holder_chirho = Some(current_chirho);
                    break;
                }
                Some(owner_chirho) if owner_chirho == current_chirho => {
                    bail!(
                        "redb store at {} is already open on this thread",
                        path_chirho.display()
                    );
                }
                Some(_) => {
                    let remaining_chirho =
                        deadline_chirho.saturating_duration_since(Instant::now());
                    if remaining_chirho.is_zero() {
                        bail!(
                            "redb store at {} stayed open elsewhere in this process for {} s",
                            path_chirho.display(),
                            limit_chirho.as_secs()
                        );
                    }
                    holder_chirho = lock_chirho
                        .released_chirho
                        .wait_timeout(holder_chirho, remaining_chirho)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
        drop(holder_chirho);
        Ok(Self { lock_chirho })
    }
}

impl Drop for StoreOpenGuardChirho {
    fn drop(&mut self) {
        *self
            .lock_chirho
            .holder_chirho
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        self.lock_chirho.released_chirho.notify_one();
    }
}

#[cfg(test)]
#[path = "open_lock_tests_chirho.rs"]
mod open_lock_tests_chirho;
