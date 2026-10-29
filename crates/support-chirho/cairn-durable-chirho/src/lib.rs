// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Crash-safe filesystem write primitives.
//!
//! `write_file_durable_chirho` is the Stage 0a primitive for full-file replacements:
//! write a sibling temp file, fsync it, rename it over the destination, then fsync the parent
//! directory. After a power loss, readers should see either the old complete file or the new
//! complete file, not a torn destination.

#[cfg(unix)]
pub mod cas_lifecycle_chirho;
#[cfg(unix)]
pub mod content_addressed_namespace_chirho;
#[cfg(unix)]
mod descriptor_root_chirho;
pub mod log_path_chirho;

#[cfg(unix)]
pub use descriptor_root_chirho::{
    DescriptorResidentWriterControlChirho, DescriptorRootCustodyChirho,
};

pub const RESIDENT_WRITER_DIR_CHIRHO: &str = "resident-writer-chirho";
pub const RESIDENT_WRITER_LOCK_FILE_CHIRHO: &str = "resident-writer.lock";
pub const RESIDENT_WRITER_IDENTITY_FILE_CHIRHO: &str = "resident-writer-identity.json";
pub const MAX_CANONICAL_FILESYSTEM_PATH_BYTES_CHIRHO: usize = 4 * 1024;

#[cfg(unix)]
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

/// The atomic nonexistence-claim outcome of [`create_file_durable_chirho`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateFileDurableOutcomeChirho {
    CreatedChirho,
    AlreadyExistsChirho,
}

/// Create one new file with exact bytes and make both the file and its directory entry durable.
///
/// This is deliberately distinct from append: `create_new(true)` is the authoritative
/// nonexistence claim, so a concurrent winner is never modified. An I/O failure after this caller
/// wins the claim may leave a partial file; callers must treat that object as forensic/recovery
/// state and must not blindly append or recreate it.
pub fn create_file_durable_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
) -> io::Result<CreateFileDurableOutcomeChirho> {
    let parent_chirho = path_chirho.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no parent: {}", path_chirho.display()),
        )
    })?;
    fs::create_dir_all(parent_chirho)?;
    let mut file_chirho = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path_chirho)
    {
        Ok(file_chirho) => file_chirho,
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::AlreadyExists => {
            return Ok(CreateFileDurableOutcomeChirho::AlreadyExistsChirho);
        }
        Err(error_chirho) => return Err(error_chirho),
    };
    file_chirho.write_all(bytes_chirho)?;
    file_chirho.sync_all()?;
    fsync_dir_chirho(parent_chirho)?;
    Ok(CreateFileDurableOutcomeChirho::CreatedChirho)
}

/// Publish one complete new file with an exact Unix mode without replacing a concurrent winner.
///
/// The bytes are written and synced under a private sibling temp name before an atomic no-replace
/// rename claims the final path. The parent directory is synced after either successful publication
/// or cleanup of a losing temp file. Platforms without a kernel no-replace rename refuse.
pub fn create_complete_file_durable_with_mode_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
    mode_chirho: u32,
) -> io::Result<CreateFileDurableOutcomeChirho> {
    let parent_chirho = path_chirho.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no parent: {}", path_chirho.display()),
        )
    })?;
    fs::create_dir_all(parent_chirho)?;
    let file_name_chirho = path_chirho.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no file name: {}", path_chirho.display()),
        )
    })?;
    let temp_path_chirho = next_temp_path_chirho(parent_chirho, file_name_chirho);
    let publish_result_chirho = (|| {
        let mut file_chirho = open_temp_file_chirho(&temp_path_chirho, Some(mode_chirho))?;
        file_chirho.write_all(bytes_chirho)?;
        file_chirho.sync_all()?;
        drop(file_chirho);
        match rename_no_replace_chirho(&temp_path_chirho, path_chirho) {
            Ok(()) => {
                fsync_dir_chirho(parent_chirho)?;
                Ok(CreateFileDurableOutcomeChirho::CreatedChirho)
            }
            Err(error_chirho) if error_chirho.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temp_path_chirho)?;
                fsync_dir_chirho(parent_chirho)?;
                Ok(CreateFileDurableOutcomeChirho::AlreadyExistsChirho)
            }
            Err(error_chirho) => Err(error_chirho),
        }
    })();
    if publish_result_chirho.is_err() && temp_path_chirho.exists() {
        let _ = fs::remove_file(&temp_path_chirho);
    }
    publish_result_chirho
}

/// Durably replace `path_chirho` with `bytes_chirho`.
pub fn write_file_durable_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> io::Result<()> {
    write_file_durable_inner_chirho(
        path_chirho,
        bytes_chirho,
        None,
        DurableInjectionChirho::None,
    )
}

/// Append one already-framed line or record durably.
///
/// If this call creates the file, the parent directory is fsynced after the file itself is synced.
/// Creation detection uses `create_new(true)` first so concurrent creators cannot both miss the
/// parent-fsync responsibility through a racy pre-check.
pub fn append_durable_line_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> io::Result<()> {
    let parent_chirho = path_chirho.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no parent: {}", path_chirho.display()),
        )
    })?;
    fs::create_dir_all(parent_chirho)?;
    match OpenOptions::new()
        .append(true)
        .create_new(true)
        .open(path_chirho)
    {
        Ok(mut file_chirho) => {
            file_chirho.write_all(bytes_chirho)?;
            file_chirho.sync_all()?;
            fsync_dir_chirho(parent_chirho)
        }
        // The exclusive create never follows a link or opens a pipe; the existing file is opened no-follow and
        // non-blocking and must be a regular file, so an append never lands in a link's target or waits on a pipe.
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::AlreadyExists => {
            let mut file_chirho =
                log_path_chirho::open_existing_log_for_write_chirho(path_chirho, true)?;
            file_chirho.write_all(bytes_chirho)?;
            file_chirho.sync_all()
        }
        Err(error_chirho) => Err(error_chirho),
    }
}

#[cfg(test)]
thread_local! {
    /// A test-only hold point between the bounded reader's path check and its open.
    static BEFORE_BOUNDED_OPEN_CHIRHO: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Read one identity-stable regular file without allocating or consuming more than `max_bytes`.
///
/// The final path component may not be a symlink or multiply linked file. Metadata is checked
/// before open, after open, and after the bounded read so replacement or growth cannot turn a
/// small reviewed object into an unbounded allocation.
pub fn read_identity_stable_bounded_regular_file_chirho(
    path_chirho: &Path,
    max_bytes_chirho: u64,
) -> io::Result<Vec<u8>> {
    let path_metadata_chirho = fs::symlink_metadata(path_chirho)?;
    if !bounded_single_link_regular_file_chirho(&path_metadata_chirho, max_bytes_chirho) {
        return Err(invalid_bounded_file_chirho());
    }
    #[cfg(test)]
    BEFORE_BOUNDED_OPEN_CHIRHO.with(|hook_chirho| {
        if let Some(hook_chirho) = hook_chirho.borrow().as_ref() {
            hook_chirho();
        }
    });

    let mut options_chirho = OpenOptions::new();
    options_chirho.read(true);
    #[cfg(unix)]
    options_chirho.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file_chirho = options_chirho.open(path_chirho)?;
    let opened_metadata_chirho = file_chirho.metadata()?;
    if !bounded_single_link_regular_file_chirho(&opened_metadata_chirho, max_bytes_chirho)
        || opened_metadata_chirho.len() != path_metadata_chirho.len()
        || !same_file_identity_chirho(&opened_metadata_chirho, &path_metadata_chirho)
    {
        return Err(invalid_bounded_file_chirho());
    }

    let capacity_chirho = usize::try_from(opened_metadata_chirho.len())
        .map_err(|_error_chirho| invalid_bounded_file_chirho())?;
    let mut bytes_chirho = Vec::with_capacity(capacity_chirho);
    (&mut file_chirho)
        .take(max_bytes_chirho.saturating_add(1))
        .read_to_end(&mut bytes_chirho)?;

    let final_opened_metadata_chirho = file_chirho.metadata()?;
    let final_path_metadata_chirho = fs::symlink_metadata(path_chirho)?;
    if u64::try_from(bytes_chirho.len()).ok() != Some(opened_metadata_chirho.len())
        || !bounded_single_link_regular_file_chirho(&final_opened_metadata_chirho, max_bytes_chirho)
        || !bounded_single_link_regular_file_chirho(&final_path_metadata_chirho, max_bytes_chirho)
        || final_opened_metadata_chirho.len() != opened_metadata_chirho.len()
        || final_path_metadata_chirho.len() != opened_metadata_chirho.len()
        || !same_file_identity_chirho(&final_opened_metadata_chirho, &opened_metadata_chirho)
        || !same_file_identity_chirho(&final_path_metadata_chirho, &opened_metadata_chirho)
    {
        return Err(invalid_bounded_file_chirho());
    }
    Ok(bytes_chirho)
}

/// Whether an I/O error is the host running out of a resource, read from its raw OS code alone: too
/// many open files in the process or the system, no space left, or try again. Permission, a wrong
/// file type, absence and integrity failures are never resource exhaustion, and an error without an
/// OS code (one already flattened into text) is not either.
/// Workflow: spec-chirho/workflows-chirho/served-request-admission-chirho/public-error-bodies-chirho/README-chirho.md.
pub fn io_error_is_resource_exhaustion_chirho(error_chirho: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            error_chirho.raw_os_error(),
            Some(code_chirho) if code_chirho == libc::EMFILE
                || code_chirho == libc::ENFILE
                || code_chirho == libc::ENOSPC
                || code_chirho == libc::EAGAIN
                || code_chirho == libc::EWOULDBLOCK
        )
    }
    #[cfg(not(unix))]
    {
        let _ = error_chirho;
        false
    }
}

/// Atomically move one existing path to an unclaimed destination without replacing a winner.
///
/// The caller remains responsible for syncing the destination directory after success. Platforms
/// without a kernel no-replace primitive refuse rather than emulate the nonexistence claim.
#[cfg(target_os = "macos")]
pub fn rename_no_replace_chirho(from_chirho: &Path, to_chirho: &Path) -> io::Result<()> {
    let from_chirho = path_cstring_chirho(from_chirho)?;
    let to_chirho = path_cstring_chirho(to_chirho)?;
    // SAFETY: both pointers reference live NUL-terminated path buffers for the call.
    let result_chirho =
        unsafe { libc::renamex_np(from_chirho.as_ptr(), to_chirho.as_ptr(), libc::RENAME_EXCL) };
    if result_chirho == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Atomically move one existing path to an unclaimed destination without replacing a winner.
#[cfg(target_os = "linux")]
pub fn rename_no_replace_chirho(from_chirho: &Path, to_chirho: &Path) -> io::Result<()> {
    let from_chirho = path_cstring_chirho(from_chirho)?;
    let to_chirho = path_cstring_chirho(to_chirho)?;
    // SAFETY: both pointers reference live NUL-terminated path buffers and `AT_FDCWD` preserves
    // process-relative path semantics while `RENAME_NOREPLACE` closes the nonexistence race.
    let result_chirho = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from_chirho.as_ptr(),
            libc::AT_FDCWD,
            to_chirho.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result_chirho == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Refuse no-replace publication where the kernel primitive is unavailable.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn rename_no_replace_chirho(_from_chirho: &Path, _to_chirho: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace rename unavailable",
    ))
}

#[cfg(unix)]
fn path_cstring_chirho(path_chirho: &Path) -> io::Result<CString> {
    CString::new(path_chirho.as_os_str().as_bytes())
        .map_err(|_error_chirho| io::Error::from(io::ErrorKind::InvalidInput))
}

fn bounded_single_link_regular_file_chirho(
    metadata_chirho: &fs::Metadata,
    max_bytes_chirho: u64,
) -> bool {
    metadata_chirho.file_type().is_file()
        && metadata_chirho.len() <= max_bytes_chirho
        && has_one_link_chirho(metadata_chirho)
}

#[cfg(unix)]
fn has_one_link_chirho(metadata_chirho: &fs::Metadata) -> bool {
    metadata_chirho.nlink() == 1
}

#[cfg(not(unix))]
fn has_one_link_chirho(_metadata_chirho: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_file_identity_chirho(left_chirho: &fs::Metadata, right_chirho: &fs::Metadata) -> bool {
    left_chirho.dev() == right_chirho.dev() && left_chirho.ino() == right_chirho.ino()
}

#[cfg(not(unix))]
fn same_file_identity_chirho(_left_chirho: &fs::Metadata, _right_chirho: &fs::Metadata) -> bool {
    false
}

fn invalid_bounded_file_chirho() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "file is not one identity-stable bounded regular file",
    )
}

/// Durably replace `path_chirho` with Unix mode `mode_chirho` for the temp file.
#[cfg(unix)]
pub fn write_file_durable_with_mode_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
    mode_chirho: u32,
) -> io::Result<()> {
    write_file_durable_inner_chirho(
        path_chirho,
        bytes_chirho,
        Some(mode_chirho),
        DurableInjectionChirho::None,
    )
}

/// Durably replace `path_chirho` on platforms without Unix mode support.
#[cfg(not(unix))]
pub fn write_file_durable_with_mode_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
    _mode_chirho: u32,
) -> io::Result<()> {
    write_file_durable_inner_chirho(
        path_chirho,
        bytes_chirho,
        None,
        DurableInjectionChirho::None,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableInjectionChirho {
    None,
    #[cfg(test)]
    BeforeRenameChirho,
}

fn write_file_durable_inner_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
    mode_chirho: Option<u32>,
    injection_chirho: DurableInjectionChirho,
) -> io::Result<()> {
    #[cfg(not(test))]
    let _ = injection_chirho;

    let parent_chirho = path_chirho.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no parent: {}", path_chirho.display()),
        )
    })?;
    fs::create_dir_all(parent_chirho)?;
    let file_name_chirho = path_chirho.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no file name: {}", path_chirho.display()),
        )
    })?;
    let temp_path_chirho = next_temp_path_chirho(parent_chirho, file_name_chirho);
    let write_result_chirho = (|| {
        let mut file_chirho = open_temp_file_chirho(&temp_path_chirho, mode_chirho)?;
        file_chirho.write_all(bytes_chirho)?;
        file_chirho.sync_all()?;
        drop(file_chirho);
        #[cfg(test)]
        if injection_chirho == DurableInjectionChirho::BeforeRenameChirho {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "injected durable-write stop before rename",
            ));
        }
        fs::rename(&temp_path_chirho, path_chirho)?;
        fsync_dir_chirho(parent_chirho)?;
        Ok(())
    })();
    if write_result_chirho.is_err() && temp_path_chirho.exists() {
        let _ = fs::remove_file(&temp_path_chirho);
    }
    write_result_chirho
}

fn next_temp_path_chirho(parent_chirho: &Path, file_name_chirho: &std::ffi::OsStr) -> PathBuf {
    let counter_chirho = TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let mut name_chirho = std::ffi::OsString::from(".");
    name_chirho.push(file_name_chirho);
    name_chirho.push(format!(
        ".tmp-chirho-{}-{counter_chirho}",
        std::process::id()
    ));
    parent_chirho.join(name_chirho)
}

fn open_temp_file_chirho(path_chirho: &Path, mode_chirho: Option<u32>) -> io::Result<File> {
    let mut options_chirho = OpenOptions::new();
    options_chirho.write(true).create_new(true).truncate(false);
    #[cfg(unix)]
    if let Some(mode_chirho) = mode_chirho {
        use std::os::unix::fs::OpenOptionsExt;
        options_chirho.mode(mode_chirho);
    }
    let file_chirho = options_chirho.open(path_chirho)?;
    #[cfg(unix)]
    if let Some(mode_chirho) = mode_chirho {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path_chirho, fs::Permissions::from_mode(mode_chirho))?;
    }
    Ok(file_chirho)
}

pub fn fsync_dir_chirho(dir_chirho: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir_chirho)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir_chirho;
        Ok(())
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-durable-test-{nanos_chirho}-{n_chirho}"))
    }

    fn hash_chirho(bytes_chirho: &[u8]) -> String {
        format!("{:x}", fnv64_for_test_chirho(bytes_chirho))
    }

    fn fnv64_for_test_chirho(bytes_chirho: &[u8]) -> u64 {
        bytes_chirho
            .iter()
            .fold(0xcbf2_9ce4_8422_2325, |hash_chirho, byte_chirho| {
                (hash_chirho ^ u64::from(*byte_chirho)).wrapping_mul(0x100_0000_01b3)
            })
    }

    #[test]
    fn durable_create_never_changes_a_preexisting_object_chirho() {
        let root_chirho = temp_root_chirho();
        let path_chirho = root_chirho.join("born-once-chirho.jsonl");
        fs::create_dir_all(&root_chirho).unwrap();
        fs::write(&path_chirho, b"foreign bytes chirho\n").unwrap();

        assert_eq!(
            create_file_durable_chirho(&path_chirho, b"attempted genesis chirho\n").unwrap(),
            CreateFileDurableOutcomeChirho::AlreadyExistsChirho
        );
        assert_eq!(fs::read(&path_chirho).unwrap(), b"foreign bytes chirho\n");
        fs::remove_dir_all(root_chirho).unwrap();
    }

    #[test]
    fn simultaneous_durable_creators_have_exactly_one_winner_chirho() {
        let root_chirho = temp_root_chirho();
        let path_chirho = root_chirho.join("contended-create-chirho.jsonl");
        let barrier_chirho = Arc::new(Barrier::new(3));
        let contenders_chirho = [
            b"alpha genesis chirho\n".to_vec(),
            b"beta genesis chirho\n".to_vec(),
        ];
        let handles_chirho = contenders_chirho
            .into_iter()
            .map(|bytes_chirho| {
                let path_chirho = path_chirho.clone();
                let barrier_chirho = Arc::clone(&barrier_chirho);
                thread::spawn(move || {
                    barrier_chirho.wait();
                    let outcome_chirho =
                        create_file_durable_chirho(&path_chirho, &bytes_chirho).unwrap();
                    (outcome_chirho, bytes_chirho)
                })
            })
            .collect::<Vec<_>>();
        barrier_chirho.wait();
        let outcomes_chirho = handles_chirho
            .into_iter()
            .map(|handle_chirho| handle_chirho.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            outcomes_chirho
                .iter()
                .filter(|(outcome_chirho, _bytes_chirho)| {
                    *outcome_chirho == CreateFileDurableOutcomeChirho::CreatedChirho
                })
                .count(),
            1
        );
        let winning_bytes_chirho = outcomes_chirho
            .iter()
            .find_map(|(outcome_chirho, bytes_chirho)| {
                (*outcome_chirho == CreateFileDurableOutcomeChirho::CreatedChirho)
                    .then_some(bytes_chirho)
            })
            .unwrap();
        assert_eq!(&fs::read(&path_chirho).unwrap(), winning_bytes_chirho);
        fs::remove_dir_all(root_chirho).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn simultaneous_complete_private_creators_have_exactly_one_winner_chirho() {
        use std::os::unix::fs::PermissionsExt;

        let root_chirho = temp_root_chirho();
        let path_chirho = root_chirho.join("contended-private-create-chirho.json");
        let barrier_chirho = Arc::new(Barrier::new(3));
        let contenders_chirho = [
            b"alpha complete chirho\n".to_vec(),
            b"beta complete chirho\n".to_vec(),
        ];
        let handles_chirho = contenders_chirho
            .into_iter()
            .map(|bytes_chirho| {
                let path_chirho = path_chirho.clone();
                let barrier_chirho = Arc::clone(&barrier_chirho);
                thread::spawn(move || {
                    barrier_chirho.wait();
                    let outcome_chirho = create_complete_file_durable_with_mode_chirho(
                        &path_chirho,
                        &bytes_chirho,
                        0o600,
                    )
                    .unwrap();
                    (outcome_chirho, bytes_chirho)
                })
            })
            .collect::<Vec<_>>();
        barrier_chirho.wait();
        let outcomes_chirho = handles_chirho
            .into_iter()
            .map(|handle_chirho| handle_chirho.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            outcomes_chirho
                .iter()
                .filter(|(outcome_chirho, _bytes_chirho)| {
                    *outcome_chirho == CreateFileDurableOutcomeChirho::CreatedChirho
                })
                .count(),
            1
        );
        let winning_bytes_chirho = outcomes_chirho
            .iter()
            .find_map(|(outcome_chirho, bytes_chirho)| {
                (*outcome_chirho == CreateFileDurableOutcomeChirho::CreatedChirho)
                    .then_some(bytes_chirho)
            })
            .unwrap();
        assert_eq!(&fs::read(&path_chirho).unwrap(), winning_bytes_chirho);
        assert_eq!(
            fs::metadata(&path_chirho).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(&root_chirho)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry_chirho| {
                    entry_chirho
                        .file_name()
                        .to_string_lossy()
                        .contains(".tmp-chirho-")
                })
                .count(),
            0
        );
        fs::remove_dir_all(root_chirho).unwrap();
    }

    #[test]
    fn durable_write_replaces_with_exact_new_bytes_chirho() {
        let root_chirho = temp_root_chirho();
        let path_chirho = root_chirho.join("state-chirho.json");
        write_file_durable_chirho(&path_chirho, b"old complete bytes").unwrap();
        let old_hash_chirho = hash_chirho(&fs::read(&path_chirho).unwrap());

        write_file_durable_chirho(&path_chirho, b"new complete bytes").unwrap();

        let bytes_chirho = fs::read(&path_chirho).unwrap();
        assert_eq!(bytes_chirho, b"new complete bytes");
        assert_ne!(hash_chirho(&bytes_chirho), old_hash_chirho);
        let temp_leftovers_chirho: Vec<_> = fs::read_dir(&root_chirho)
            .unwrap()
            .map(|entry_chirho| entry_chirho.unwrap().file_name())
            .filter(|name_chirho| name_chirho.to_string_lossy().contains(".tmp-chirho-"))
            .collect();
        assert!(temp_leftovers_chirho.is_empty());

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn injected_stop_before_rename_leaves_old_complete_file_chirho() {
        let root_chirho = temp_root_chirho();
        let path_chirho = root_chirho.join("head-chirho");
        write_file_durable_chirho(&path_chirho, b"old-head").unwrap();
        let old_hash_chirho = hash_chirho(&fs::read(&path_chirho).unwrap());

        let error_chirho = write_file_durable_inner_chirho(
            &path_chirho,
            b"new-head",
            None,
            DurableInjectionChirho::BeforeRenameChirho,
        )
        .unwrap_err();

        assert_eq!(error_chirho.kind(), io::ErrorKind::Interrupted);
        let bytes_chirho = fs::read(&path_chirho).unwrap();
        assert_eq!(bytes_chirho, b"old-head");
        assert_eq!(hash_chirho(&bytes_chirho), old_hash_chirho);

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn durable_write_never_exposes_torn_file_to_concurrent_readers_chirho() {
        let root_chirho = temp_root_chirho();
        let path_chirho = root_chirho.join("rotating-state-chirho.bin");
        let old_chirho = vec![b'a'; 64 * 1024];
        let new_chirho = vec![b'b'; 64 * 1024];
        write_file_durable_chirho(&path_chirho, &old_chirho).unwrap();

        let stop_chirho = Arc::new(AtomicBool::new(false));
        let mut readers_chirho = Vec::new();
        for _ in 0..4 {
            let stop_chirho = Arc::clone(&stop_chirho);
            let path_chirho = path_chirho.clone();
            readers_chirho.push(thread::spawn(move || {
                while !stop_chirho.load(Ordering::SeqCst) {
                    let bytes_chirho = fs::read(&path_chirho).unwrap();
                    assert!(
                        bytes_chirho.iter().all(|byte_chirho| *byte_chirho == b'a')
                            || bytes_chirho.iter().all(|byte_chirho| *byte_chirho == b'b'),
                        "reader saw torn durable replacement"
                    );
                    assert_eq!(bytes_chirho.len(), 64 * 1024);
                }
            }));
        }

        for idx_chirho in 0..64 {
            let bytes_chirho = if idx_chirho % 2 == 0 {
                &new_chirho
            } else {
                &old_chirho
            };
            write_file_durable_chirho(&path_chirho, bytes_chirho).unwrap();
        }
        stop_chirho.store(true, Ordering::SeqCst);
        for reader_chirho in readers_chirho {
            reader_chirho.join().unwrap();
        }

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn append_durable_line_is_byte_identical_chirho() {
        let root_chirho = temp_root_chirho();
        let path_chirho = root_chirho.join("append-chirho.jsonl");

        append_durable_line_chirho(&path_chirho, b"{\"seq_chirho\":0}\n").unwrap();
        append_durable_line_chirho(&path_chirho, b"{\"seq_chirho\":1}\n").unwrap();

        assert_eq!(
            fs::read(&path_chirho).unwrap(),
            b"{\"seq_chirho\":0}\n{\"seq_chirho\":1}\n"
        );
        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn append_durable_line_handles_parallel_first_create_chirho() {
        let root_chirho = temp_root_chirho();
        let path_chirho = root_chirho.join("parallel-create-chirho.jsonl");
        let mut writers_chirho = Vec::new();
        for idx_chirho in 0..16 {
            let path_chirho = path_chirho.clone();
            writers_chirho.push(thread::spawn(move || {
                append_durable_line_chirho(&path_chirho, format!("{idx_chirho}\n").as_bytes())
                    .unwrap();
            }));
        }
        for writer_chirho in writers_chirho {
            writer_chirho.join().unwrap();
        }

        let text_chirho = fs::read_to_string(&path_chirho).unwrap();
        let mut values_chirho: Vec<_> = text_chirho
            .lines()
            .map(|line_chirho| line_chirho.parse::<u64>().unwrap())
            .collect();
        values_chirho.sort_unstable();
        assert_eq!(values_chirho, (0..16).collect::<Vec<_>>());

        let _ = fs::remove_dir_all(&root_chirho);
    }
}

#[cfg(all(test, unix))]
mod bounded_read_tests_chirho;

#[cfg(all(test, unix))]
mod resource_exhaustion_tests_chirho;

#[cfg(all(test, unix))]
mod log_path_tests_chirho;
