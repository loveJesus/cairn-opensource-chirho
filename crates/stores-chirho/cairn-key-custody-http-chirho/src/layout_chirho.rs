// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Where a key-custody holder keeps each durable thing, built only from validated lowercase hex, inside private directories it creates itself.
//!
//! Every path component below the holder directory is a fixed name or a validated digest or key id, so
//! no frame value can name a path outside it. The directories are a private tree (see
//! `private_tree_chirho`) that remembers depth 0, a fixed family directory, and depth 1, its two-hex
//! shard, after one sync. A subject's own directory is never remembered, so what this holder remembers
//! stays bounded by construction (gpt #29372).

use crate::private_tree_chirho::{durable_temp_final_name_chirho, hex_chirho, PrivateTreeChirho};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) use crate::private_tree_chirho::PRIVATE_FILE_MODE_CHIRHO;

const DIGEST_HEX_LEN_CHIRHO: usize = 64;
const KEY_ID_HEX_LEN_CHIRHO: usize = 32;
const KEY_SUFFIX_CHIRHO: &str = ".key.json";
const BINDING_SUFFIX_CHIRHO: &str = ".binding.json";
/// Components below the holder directory at this depth or deeper are never remembered as synced: depth
/// 0 is a fixed family directory and depth 1 its two-hex shard, so at most the families plus 256 shards
/// each are remembered, however many subjects the holder ever stores.
const REMEMBERED_DEPTH_CHIRHO: usize = 2;

/// What one file in a subject's key directory is, by the key id it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubjectEntryKindChirho {
    KeyChirho,
    BindingChirho,
    /// A durable write of a key file that never reached its rename; it may hold key bytes.
    KeyTempChirho,
    BindingTempChirho,
}

#[derive(Debug)]
pub(crate) struct HolderLayoutChirho {
    tree_chirho: PrivateTreeChirho,
}

impl HolderLayoutChirho {
    /// Open the holder directory, creating it private if it is absent. Its parent belongs to the
    /// caller and must exist; an existing holder directory must be a private real directory. Either
    /// way the parent is fsynced, so a directory a crashed process created is durable before use.
    pub(crate) fn open_chirho(dir_chirho: &Path) -> io::Result<Self> {
        Ok(Self {
            tree_chirho: PrivateTreeChirho::open_chirho(dir_chirho, REMEMBERED_DEPTH_CHIRHO)?,
        })
    }

    pub(crate) fn term_path_chirho(&self, group_digest_chirho: &str) -> io::Result<PathBuf> {
        let group_chirho = hex_chirho(group_digest_chirho, DIGEST_HEX_LEN_CHIRHO)?;
        Ok(self
            .tree_chirho
            .dir_chirho()
            .join("terms-chirho")
            .join(format!("{group_chirho}.json")))
    }

    pub(crate) fn tombstone_path_chirho(&self, subject_digest_chirho: &str) -> io::Result<PathBuf> {
        let subject_chirho = hex_chirho(subject_digest_chirho, DIGEST_HEX_LEN_CHIRHO)?;
        Ok(self
            .tree_chirho
            .dir_chirho()
            .join("tombstones-chirho")
            .join(&subject_chirho[..2])
            .join(format!("{subject_chirho}.json")))
    }

    /// One subject's key directory: the only place an erasure of that subject scans or removes.
    pub(crate) fn subject_keys_dir_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> io::Result<PathBuf> {
        let subject_chirho = hex_chirho(subject_digest_chirho, DIGEST_HEX_LEN_CHIRHO)?;
        Ok(self
            .tree_chirho
            .dir_chirho()
            .join("keys-chirho")
            .join(&subject_chirho[..2])
            .join(subject_chirho))
    }

    pub(crate) fn key_path_chirho(
        &self,
        subject_digest_chirho: &str,
        key_id_chirho: &str,
    ) -> io::Result<PathBuf> {
        let key_id_chirho = hex_chirho(key_id_chirho, KEY_ID_HEX_LEN_CHIRHO)?;
        Ok(self
            .subject_keys_dir_chirho(subject_digest_chirho)?
            .join(format!("{key_id_chirho}{KEY_SUFFIX_CHIRHO}")))
    }

    pub(crate) fn binding_path_chirho(
        &self,
        subject_digest_chirho: &str,
        key_id_chirho: &str,
    ) -> io::Result<PathBuf> {
        let key_id_chirho = hex_chirho(key_id_chirho, KEY_ID_HEX_LEN_CHIRHO)?;
        Ok(self
            .subject_keys_dir_chirho(subject_digest_chirho)?
            .join(format!("{key_id_chirho}{BINDING_SUFFIX_CHIRHO}")))
    }

    pub(crate) fn erasure_record_path_chirho(
        &self,
        frame_digest_chirho: &str,
    ) -> io::Result<PathBuf> {
        let frame_chirho = hex_chirho(frame_digest_chirho, DIGEST_HEX_LEN_CHIRHO)?;
        Ok(self
            .tree_chirho
            .dir_chirho()
            .join("erasures-chirho")
            .join(&frame_chirho[..2])
            .join(format!("{frame_chirho}.json")))
    }

    /// Make every missing directory from the holder directory down to `path_chirho` private, and make
    /// every component's entry in its parent durable (see `private_tree_chirho`).
    pub(crate) fn ensure_private_dir_chirho(&self, path_chirho: &Path) -> io::Result<()> {
        self.tree_chirho.ensure_private_dir_chirho(path_chirho)
    }

    /// Test-only: how many directories this holder remembers as synced.
    #[cfg(test)]
    pub(crate) fn remembered_directory_count_chirho(&self) -> usize {
        self.tree_chirho.remembered_directory_count_chirho()
    }
}

/// Classify one file name in a subject's key directory; `None` for any name this crate never writes.
pub(crate) fn classify_subject_entry_chirho(
    name_chirho: &str,
) -> Option<(String, SubjectEntryKindChirho)> {
    if name_chirho.starts_with('.') {
        return match classify_final_chirho(durable_temp_final_name_chirho(name_chirho)?)? {
            (key_id_chirho, SubjectEntryKindChirho::KeyChirho) => {
                Some((key_id_chirho, SubjectEntryKindChirho::KeyTempChirho))
            }
            (key_id_chirho, SubjectEntryKindChirho::BindingChirho) => {
                Some((key_id_chirho, SubjectEntryKindChirho::BindingTempChirho))
            }
            _ => None,
        };
    }
    classify_final_chirho(name_chirho)
}

fn classify_final_chirho(name_chirho: &str) -> Option<(String, SubjectEntryKindChirho)> {
    let (key_id_chirho, kind_chirho) =
        if let Some(id_chirho) = name_chirho.strip_suffix(KEY_SUFFIX_CHIRHO) {
            (id_chirho, SubjectEntryKindChirho::KeyChirho)
        } else {
            (
                name_chirho.strip_suffix(BINDING_SUFFIX_CHIRHO)?,
                SubjectEntryKindChirho::BindingChirho,
            )
        };
    hex_chirho(key_id_chirho, KEY_ID_HEX_LEN_CHIRHO).ok()?;
    Some((key_id_chirho.to_string(), kind_chirho))
}
