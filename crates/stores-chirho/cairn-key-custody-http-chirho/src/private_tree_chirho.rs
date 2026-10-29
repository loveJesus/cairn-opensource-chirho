// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A private directory tree a key-custody store owns: 0700 directories made one component at a time, each one's entry made durable in its parent, with a bounded memory of the ones already made durable.
//!
//! A component's parent is fsynced when the component is created AND when the tree finds it already
//! present, because a crashed earlier process may have created it without that sync (gpt #29353).
//! Components are only ever created, so a component shallower than the tree's remembered depth is
//! remembered after one sync. Deeper components are never remembered, so what a tree remembers stays
//! bounded by its shallow levels, however many subjects it stores (gpt #29372). The holder and the
//! leader's propagation store each own one, at their own depths.

use crate::barrier_chirho::sync_dir_chirho;
use cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) const PRIVATE_FILE_MODE_CHIRHO: u32 = 0o600;
const PRIVATE_DIR_MODE_CHIRHO: u32 = 0o700;
/// The marker `cairn-durable-chirho` puts in a durable write's sibling temp name.
const TEMP_MARKER_CHIRHO: &str = ".tmp-chirho-";

#[derive(Debug)]
pub(crate) struct PrivateTreeChirho {
    dir_chirho: PathBuf,
    /// Components at this depth below the tree's directory, or deeper, are never remembered.
    remembered_depth_chirho: usize,
    /// Shallow directories whose entry in their parent this tree has made durable.
    synced_chirho: Mutex<BTreeSet<PathBuf>>,
}

impl PrivateTreeChirho {
    /// Open the tree's directory, creating it private if it is absent. Its parent belongs to the caller
    /// and must exist; an existing directory must be a private real directory. Either way the parent is
    /// fsynced, so a directory a crashed process created is durable before use.
    pub(crate) fn open_chirho(
        dir_chirho: &Path,
        remembered_depth_chirho: usize,
    ) -> io::Result<Self> {
        let parent_chirho = dir_chirho
            .parent()
            .ok_or_else(|| invalid_chirho("the store directory has no parent"))?;
        match fs::symlink_metadata(dir_chirho) {
            Ok(metadata_chirho) => check_private_dir_chirho(&metadata_chirho)?,
            Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
                create_private_dir_chirho(dir_chirho)?;
            }
            Err(error_chirho) => return Err(error_chirho),
        }
        sync_dir_chirho(parent_chirho)?;
        Ok(Self {
            dir_chirho: dir_chirho.to_path_buf(),
            remembered_depth_chirho,
            synced_chirho: Mutex::new(BTreeSet::new()),
        })
    }

    pub(crate) fn dir_chirho(&self) -> &Path {
        &self.dir_chirho
    }

    /// Make every missing directory from the tree's directory down to `path_chirho` private, and make
    /// every component's entry in its parent durable: a new one always, an existing one unless this tree
    /// already synced it (only components shallower than the remembered depth are remembered).
    pub(crate) fn ensure_private_dir_chirho(&self, path_chirho: &Path) -> io::Result<()> {
        let relative_chirho = path_chirho
            .strip_prefix(&self.dir_chirho)
            .map_err(|_| invalid_chirho("a store path is outside the store directory"))?;
        let mut synced_chirho = self
            .synced_chirho
            .lock()
            .map_err(|_| invalid_chirho("the store's directory-sync record is poisoned"))?;
        let mut current_chirho = self.dir_chirho.clone();
        for (depth_chirho, component_chirho) in relative_chirho.components().enumerate() {
            let parent_chirho = current_chirho.clone();
            current_chirho.push(component_chirho);
            match fs::symlink_metadata(&current_chirho) {
                Ok(metadata_chirho) => check_private_dir_chirho(&metadata_chirho)?,
                Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
                    create_private_dir_chirho(&current_chirho)?;
                }
                Err(error_chirho) => return Err(error_chirho),
            }
            let remembered_chirho = depth_chirho < self.remembered_depth_chirho;
            if !remembered_chirho || !synced_chirho.contains(&current_chirho) {
                sync_dir_chirho(&parent_chirho)?;
                if remembered_chirho {
                    synced_chirho.insert(current_chirho.clone());
                }
            }
        }
        Ok(())
    }

    /// Whether `path_chirho`, below the tree's directory, exists as a chain of private real directories. It is
    /// read-only: nothing is created or synced. The tree's own directory must still be a private real
    /// directory. Each component is examined without following a link, and a missing one reads as absent
    /// only after its parent was verified. A link, a non-directory, a non-private mode or any other failure
    /// is an error, never "absent" (gpt #29898). Between this probe and a later read the chain could still
    /// be swapped; that window is named, not closed.
    pub(crate) fn existing_private_dir_chirho(&self, path_chirho: &Path) -> io::Result<bool> {
        let relative_chirho = path_chirho
            .strip_prefix(&self.dir_chirho)
            .map_err(|_| invalid_chirho("a store path is outside the store directory"))?;
        check_private_dir_chirho(&fs::symlink_metadata(&self.dir_chirho)?)?;
        let mut current_chirho = self.dir_chirho.clone();
        for component_chirho in relative_chirho.components() {
            current_chirho.push(component_chirho);
            match fs::symlink_metadata(&current_chirho) {
                Ok(metadata_chirho) => check_private_dir_chirho(&metadata_chirho)?,
                Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
                    return Ok(false);
                }
                Err(error_chirho) => return Err(error_chirho),
            }
        }
        Ok(true)
    }

    /// Test-only: how many directories this tree remembers as synced.
    #[cfg(test)]
    pub(crate) fn remembered_directory_count_chirho(&self) -> usize {
        self.synced_chirho
            .lock()
            .map(|synced_chirho| synced_chirho.len())
            .unwrap_or(0)
    }
}

/// One stored file: absent, present and in form, or present but unreadable or out of form.
pub(crate) enum StoredChirho<TChirho> {
    AbsentChirho,
    PresentChirho(TChirho),
    UnreadableChirho,
}

/// Read one stored file, bounded and single-linked: absent only on "not found", and unreadable on any
/// other failure, a link, or more than `max_bytes_chirho` bytes.
pub(crate) fn read_stored_chirho(
    path_chirho: &Path,
    max_bytes_chirho: u64,
) -> StoredChirho<Vec<u8>> {
    match fs::symlink_metadata(path_chirho) {
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
            StoredChirho::AbsentChirho
        }
        Err(_) => StoredChirho::UnreadableChirho,
        Ok(_) => {
            match read_identity_stable_bounded_regular_file_chirho(path_chirho, max_bytes_chirho) {
                Ok(bytes_chirho) => StoredChirho::PresentChirho(bytes_chirho),
                Err(_) => StoredChirho::UnreadableChirho,
            }
        }
    }
}

/// The final name a `cairn-durable-chirho` temp `.<final name>.tmp-chirho-<pid>-<counter>` was being
/// written for, or `None` for any other name.
pub(crate) fn durable_temp_final_name_chirho(name_chirho: &str) -> Option<&str> {
    let rest_chirho = name_chirho.strip_prefix('.')?;
    let (final_chirho, tail_chirho) = rest_chirho.split_once(TEMP_MARKER_CHIRHO)?;
    if tail_chirho.is_empty()
        || !tail_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || byte_chirho == b'-')
    {
        return None;
    }
    Some(final_chirho)
}

pub(crate) fn hex_chirho(value_chirho: &str, len_chirho: usize) -> io::Result<&str> {
    let in_form_chirho = value_chirho.len() == len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| matches!(byte_chirho, b'0'..=b'9' | b'a'..=b'f'));
    if in_form_chirho {
        Ok(value_chirho)
    } else {
        Err(invalid_chirho(
            "a store path value is not lowercase hex of its length",
        ))
    }
}

fn create_private_dir_chirho(path_chirho: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .mode(PRIVATE_DIR_MODE_CHIRHO)
        .create(path_chirho)?;
    fs::set_permissions(
        path_chirho,
        fs::Permissions::from_mode(PRIVATE_DIR_MODE_CHIRHO),
    )
}

fn check_private_dir_chirho(metadata_chirho: &fs::Metadata) -> io::Result<()> {
    if !metadata_chirho.file_type().is_dir() || metadata_chirho.mode() & 0o077 != 0 {
        return Err(invalid_chirho(
            "a store directory is not a private real directory",
        ));
    }
    Ok(())
}

pub(crate) fn invalid_chirho(message_chirho: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message_chirho)
}
