// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The holder's one directory durability barrier, with a test-only ordered log of syncs, writes and unlinks and a sync failpoint, so an arm can prove a barrier runs before the next side effect.
//!
//! A durable write renames before it fsyncs the parent, and an unlink is durable only once its
//! directory is fsynced. So after a crashed attempt, state can be VISIBLE without being durable, and
//! a retry that skips work because the visible state already matches must still pass this barrier at
//! every ordering point (gpt #29353). Every holder directory sync goes through here.

use std::io;
use std::path::Path;

/// Fsync one directory.
pub(crate) fn sync_dir_chirho(dir_chirho: &Path) -> io::Result<()> {
    #[cfg(test)]
    {
        test_hooks_chirho::record_chirho(
            test_hooks_chirho::EventKindChirho::SyncChirho,
            dir_chirho,
        );
        if test_hooks_chirho::sync_fails_chirho(dir_chirho) {
            return Err(io::Error::other("injected directory sync failure"));
        }
    }
    cairn_durable_chirho::fsync_dir_chirho(dir_chirho)
}

/// Test-only: the ordered events on this thread, and directories whose sync is made to fail.
#[cfg(test)]
pub(crate) mod test_hooks_chirho {
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum EventKindChirho {
        SyncChirho,
        WriteChirho,
        UnlinkChirho,
    }

    thread_local! {
        static EVENTS_CHIRHO: RefCell<Vec<(EventKindChirho, PathBuf)>> = const { RefCell::new(Vec::new()) };
        static FAILING_CHIRHO: RefCell<BTreeSet<PathBuf>> = const { RefCell::new(BTreeSet::new()) };
    }

    pub(crate) fn record_chirho(kind_chirho: EventKindChirho, path_chirho: &Path) {
        EVENTS_CHIRHO.with(|events_chirho| {
            events_chirho
                .borrow_mut()
                .push((kind_chirho, path_chirho.to_path_buf()))
        });
    }

    pub(crate) fn take_events_chirho() -> Vec<(EventKindChirho, PathBuf)> {
        EVENTS_CHIRHO.with(|events_chirho| std::mem::take(&mut *events_chirho.borrow_mut()))
    }

    pub(crate) fn fail_syncs_of_chirho(dir_chirho: &Path) {
        FAILING_CHIRHO
            .with(|failing_chirho| failing_chirho.borrow_mut().insert(dir_chirho.to_path_buf()));
    }

    pub(crate) fn clear_failing_chirho() {
        FAILING_CHIRHO.with(|failing_chirho| failing_chirho.borrow_mut().clear());
    }

    pub(super) fn sync_fails_chirho(dir_chirho: &Path) -> bool {
        FAILING_CHIRHO.with(|failing_chirho| failing_chirho.borrow().contains(dir_chirho))
    }
}
