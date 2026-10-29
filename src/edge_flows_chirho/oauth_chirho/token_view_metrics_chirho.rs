// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! How many token records this thread checked, how many use records it folded and how many times it parsed the client
//! log, for the growth arms: a bearer request checks no token and folds one use, and a sign-in parses no client log,
//! however long the logs (brick 4a-2). K4 adds the connection client view's folds and the whole reads of the connection
//! key and use logs, for the connection growth witness, and the index entries the daily limit visits (Part 3).

use std::cell::Cell;

thread_local! {
    static TOKEN_CHECKS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    static USE_FOLDS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    static CLIENT_READS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    static CONNECTION_CLIENT_FOLDS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    static CONNECTION_LOG_READS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    static DAILY_ENTRIES_CHIRHO: Cell<u64> = const { Cell::new(0) };
}

/// One index entry the daily limit's read visited (K4 Part 3): its population is the keys that can fall in the window.
pub(super) fn note_daily_entry_chirho() {
    DAILY_ENTRIES_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
}

/// How many index entries this thread's daily-limit reads visited (K4 Part 3).
pub(super) fn daily_entries_chirho() -> u64 {
    DAILY_ENTRIES_CHIRHO.with(Cell::get)
}

pub(super) fn note_token_check_chirho() {
    TOKEN_CHECKS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
}

pub(super) fn note_use_fold_chirho() {
    USE_FOLDS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
}

pub(super) fn note_client_read_chirho() {
    CLIENT_READS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
}

pub(super) fn note_connection_client_fold_chirho() {
    CONNECTION_CLIENT_FOLDS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
}

pub(super) fn note_connection_log_read_chirho() {
    CONNECTION_LOG_READS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
}

/// How many connection clients this thread folded into the connection client view (K4).
pub(super) fn connection_client_folds_chirho() -> u64 {
    CONNECTION_CLIENT_FOLDS_CHIRHO.with(Cell::get)
}

/// How many times this thread read the whole connection key or use log (K4).
pub(super) fn connection_log_reads_chirho() -> u64 {
    CONNECTION_LOG_READS_CHIRHO.with(Cell::get)
}

/// How many times this thread parsed the client log, for the sign-in and recover roads' growth arms.
pub(crate) fn client_reads_chirho() -> u64 {
    CLIENT_READS_CHIRHO.with(Cell::get)
}

/// (token records checked, use records folded) on this thread so far.
pub(super) fn counts_chirho() -> (u64, u64) {
    (
        TOKEN_CHECKS_CHIRHO.with(Cell::get),
        USE_FOLDS_CHIRHO.with(Cell::get),
    )
}
