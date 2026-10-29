// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! How a log's path is examined and opened: only a genuine absence reads as no log, and anything the engine cannot
//! examine (a link, a directory, a pipe, any other non-regular file, or a metadata error) refuses, never read as empty.
//! Workflow: the shared JSONL absence brick,
//! `spec-chirho/tasklists-chirho/26-10-08_23-20-tasklist-jsonl_absence_cache_door-chirho.md`.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// What sits at a log's path, read without following a link or opening anything.
#[derive(Debug)]
pub enum LogPathChirho {
    /// Nothing: the path's own lookup answered NotFound.
    AbsentChirho,
    /// A regular file, with its metadata.
    PresentChirho(Metadata),
}

/// What the path holds, named for a refusal.
fn kind_name_chirho(metadata_chirho: &Metadata) -> &'static str {
    let kind_chirho = metadata_chirho.file_type();
    if kind_chirho.is_symlink() {
        return "link";
    }
    if kind_chirho.is_dir() {
        return "directory";
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if kind_chirho.is_fifo() {
            return "pipe";
        }
        if kind_chirho.is_socket() {
            return "socket";
        }
        if kind_chirho.is_block_device() || kind_chirho.is_char_device() {
            return "device";
        }
    }
    "non-regular file"
}

/// The refusal for a path holding something other than a regular file.
fn not_a_regular_log_chirho(path_chirho: &Path, metadata_chirho: &Metadata) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{} is a {}, not a regular log file: a log the engine cannot examine is refused, never read as empty",
            path_chirho.display(),
            kind_name_chirho(metadata_chirho)
        ),
    )
}

/// Examine a log's path without following a link or opening it. Only NotFound is an absence and a regular file is
/// present. A link (whatever it points to), a directory, a pipe, any other non-regular file, and every other error, a
/// denied parent among them, refuse.
pub fn classify_log_path_chirho(path_chirho: &Path) -> io::Result<LogPathChirho> {
    match fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) if metadata_chirho.file_type().is_file() => {
            Ok(LogPathChirho::PresentChirho(metadata_chirho))
        }
        Ok(metadata_chirho) => Err(not_a_regular_log_chirho(path_chirho, &metadata_chirho)),
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
            Ok(LogPathChirho::AbsentChirho)
        }
        Err(error_chirho) => Err(error_chirho),
    }
}

/// Open a log for reading: `None` only for a genuine absence. The open refuses a link at the path (`O_NOFOLLOW`, so a
/// dangling or looping link fails rather than reading as absent), never waits on a pipe (`O_NONBLOCK`), and the opened
/// handle itself must be a regular file, so a path swapped after any earlier check is still caught.
pub fn open_log_no_follow_chirho(path_chirho: &Path) -> io::Result<Option<File>> {
    let mut options_chirho = OpenOptions::new();
    options_chirho.read(true);
    #[cfg(unix)]
    options_chirho.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file_chirho = match options_chirho.open(path_chirho) {
        Ok(file_chirho) => file_chirho,
        // The path, or a directory above it, is absent.
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error_chirho) => return Err(error_chirho),
    };
    let metadata_chirho = file_chirho.metadata()?;
    if !metadata_chirho.file_type().is_file() {
        return Err(not_a_regular_log_chirho(path_chirho, &metadata_chirho));
    }
    Ok(Some(file_chirho))
}

/// Open an existing log for writing in place, appending (`append_chirho`) or at its start, as a truncation or a repair
/// does. The open refuses a link at the path (`O_NOFOLLOW`, so a write never lands in a link's target), never waits on
/// a pipe (`O_NONBLOCK`: a pipe with no reader fails at once), and the opened handle itself must be a regular file. A
/// missing log is an error here: creating one is the caller's own exclusive create.
pub fn open_existing_log_for_write_chirho(
    path_chirho: &Path,
    append_chirho: bool,
) -> io::Result<File> {
    let mut options_chirho = OpenOptions::new();
    if append_chirho {
        options_chirho.append(true);
    } else {
        options_chirho.write(true);
    }
    #[cfg(unix)]
    options_chirho.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file_chirho = options_chirho.open(path_chirho)?;
    let metadata_chirho = file_chirho.metadata()?;
    if !metadata_chirho.file_type().is_file() {
        return Err(not_a_regular_log_chirho(path_chirho, &metadata_chirho));
    }
    Ok(file_chirho)
}
