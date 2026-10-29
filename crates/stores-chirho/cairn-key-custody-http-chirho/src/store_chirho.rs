// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A key-custody holder's durable state: per-group term high-waters, per-subject tombstones, each key beside its binding, and per-frame erasure records.
//!
//! Every file is private (0600 under 0700 directories), written by a durable replace and read back
//! bounded, single-linked and validated against where it sits: a file moved under another group,
//! subject or frame reads as unreadable, never as that other thing's state. The holder calls this only
//! while it holds its admission lock, so nothing here races another admission.

use crate::barrier_chirho::sync_dir_chirho;
use crate::layout_chirho::{
    classify_subject_entry_chirho, HolderLayoutChirho, SubjectEntryKindChirho,
    PRIVATE_FILE_MODE_CHIRHO,
};
use crate::private_tree_chirho::{read_stored_chirho, StoredChirho};
use crate::refusal_chirho::{HolderRefusalChirho, HolderRefusalIdentityChirho};
use cairn_durable_chirho::write_file_durable_with_mode_chirho;
use cairn_key_custody_chirho::{
    AuthorizedErasureFrameChirho, CustodyBindingChirho, HolderTombstonesChirho,
    OpenedCustodyKeyChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use zeroize::Zeroizing;

const TERM_SCHEMA_V1_CHIRHO: &str = "key-custody-holder-term-v1-chirho";
const TOMBSTONES_SCHEMA_V1_CHIRHO: &str = "key-custody-holder-tombstones-v1-chirho";
const ERASURE_RECORD_SCHEMA_V1_CHIRHO: &str = "key-custody-holder-erasure-v1-chirho";
const SMALL_FILE_MAX_BYTES_CHIRHO: u64 = 16 * 1024;
const LARGE_FILE_MAX_BYTES_CHIRHO: u64 = 8 * 1024 * 1024;
/// The most entries one erasure scans in one subject's key directory (up to four files per key).
pub(crate) const SUBJECT_SCAN_MAX_ENTRIES_CHIRHO: usize = 4 * 65_536;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TermHighWaterChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    highest_term_chirho: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TombstoneShardChirho {
    schema_chirho: String,
    subject_digest_chirho: String,
    tombstones_chirho: HolderTombstonesChirho,
}

#[derive(Serialize)]
struct TombstoneShardRefChirho<'a> {
    schema_chirho: &'a str,
    subject_digest_chirho: &'a str,
    tombstones_chirho: &'a HolderTombstonesChirho,
}

/// What one erasure frame removes on this holder, fixed before anything is unlinked so a retry after a
/// crash reports exactly the same keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErasureRecordChirho {
    schema_chirho: String,
    erasure_frame_digest_chirho: String,
    pub(crate) subject_digest_chirho: String,
    /// Listed ids whose key material this holder held.
    pub(crate) removed_key_ids_chirho: BTreeSet<String>,
    /// Listed ids this holder never held under the frame's subject.
    pub(crate) already_absent_key_ids_chirho: BTreeSet<String>,
    /// Unlisted keys of the subject whose stored blob seq is below the frame's bound.
    pub(crate) removed_by_subject_key_ids_chirho: BTreeSet<String>,
    /// Unlisted keys of the subject whose stored binding is missing or unreadable.
    pub(crate) unverifiable_key_ids_chirho: BTreeSet<String>,
}

impl ErasureRecordChirho {
    fn empty_for_chirho(frame_chirho: &AuthorizedErasureFrameChirho) -> Self {
        Self {
            schema_chirho: ERASURE_RECORD_SCHEMA_V1_CHIRHO.to_string(),
            erasure_frame_digest_chirho: frame_chirho.frame_digest_chirho().to_string(),
            subject_digest_chirho: frame_chirho.subject_digest_chirho().to_string(),
            removed_key_ids_chirho: BTreeSet::new(),
            already_absent_key_ids_chirho: BTreeSet::new(),
            removed_by_subject_key_ids_chirho: BTreeSet::new(),
            unverifiable_key_ids_chirho: BTreeSet::new(),
        }
    }

    /// Whether a stored record is this frame's and splits it the way classification would.
    fn fits_frame_chirho(&self, frame_chirho: &AuthorizedErasureFrameChirho) -> bool {
        let listed_chirho = frame_chirho
            .key_ids_chirho()
            .iter()
            .collect::<BTreeSet<_>>();
        let accounted_chirho = self
            .removed_key_ids_chirho
            .iter()
            .chain(&self.already_absent_key_ids_chirho)
            .collect::<BTreeSet<_>>();
        let unlisted_chirho = self
            .removed_by_subject_key_ids_chirho
            .iter()
            .chain(&self.unverifiable_key_ids_chirho)
            .collect::<Vec<_>>();
        let disjoint_chirho = self
            .removed_key_ids_chirho
            .is_disjoint(&self.already_absent_key_ids_chirho)
            && self
                .removed_by_subject_key_ids_chirho
                .is_disjoint(&self.unverifiable_key_ids_chirho);
        self.schema_chirho == ERASURE_RECORD_SCHEMA_V1_CHIRHO
            && self.erasure_frame_digest_chirho == frame_chirho.frame_digest_chirho()
            && self.subject_digest_chirho == frame_chirho.subject_digest_chirho()
            && disjoint_chirho
            && accounted_chirho == listed_chirho
            && unlisted_chirho
                .iter()
                .all(|key_id_chirho| !listed_chirho.contains(key_id_chirho))
            && self.erased_key_ids_chirho().all(|key_id_chirho| {
                classify_subject_entry_chirho(&format!("{key_id_chirho}.key.json")).is_some()
            })
    }

    /// Every key id whose files this erasure removes.
    pub(crate) fn erased_key_ids_chirho(&self) -> impl Iterator<Item = &String> {
        self.removed_key_ids_chirho
            .iter()
            .chain(&self.already_absent_key_ids_chirho)
            .chain(&self.removed_by_subject_key_ids_chirho)
            .chain(&self.unverifiable_key_ids_chirho)
    }
}

/// The files one key id has in its subject's directory.
#[derive(Debug, Default)]
pub(crate) struct KeyFilesChirho {
    key_chirho: bool,
    binding_chirho: bool,
    key_temp_chirho: bool,
    temp_names_chirho: Vec<OsString>,
}

impl KeyFilesChirho {
    /// A key file, or a key file's stranded temp, may hold the key's bytes.
    fn holds_key_material_chirho(&self) -> bool {
        self.key_chirho || self.key_temp_chirho
    }
}

pub(crate) struct HolderStoreChirho {
    layout_chirho: HolderLayoutChirho,
}

impl HolderStoreChirho {
    pub(crate) fn open_chirho(dir_chirho: &Path) -> Result<Self, HolderRefusalChirho> {
        Ok(Self {
            layout_chirho: HolderLayoutChirho::open_chirho(dir_chirho)
                .map_err(|_| unreadable_chirho())?,
        })
    }

    /// The highest term this holder accepted for the group, or 0 before its first admission.
    pub(crate) fn term_high_water_chirho(
        &self,
        group_digest_chirho: &str,
    ) -> Result<u64, HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .term_path_chirho(group_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        let bytes_chirho = match read_stored_chirho(&path_chirho, SMALL_FILE_MAX_BYTES_CHIRHO) {
            StoredChirho::AbsentChirho => return Ok(0),
            StoredChirho::PresentChirho(bytes_chirho) => bytes_chirho,
            StoredChirho::UnreadableChirho => return Err(unreadable_chirho()),
        };
        let stored_chirho: TermHighWaterChirho =
            serde_json::from_slice(&bytes_chirho).map_err(|_| unreadable_chirho())?;
        if stored_chirho.schema_chirho != TERM_SCHEMA_V1_CHIRHO
            || stored_chirho.consistency_group_digest_chirho != group_digest_chirho
        {
            return Err(unreadable_chirho());
        }
        Ok(stored_chirho.highest_term_chirho)
    }

    pub(crate) fn raise_term_high_water_chirho(
        &self,
        group_digest_chirho: &str,
        term_chirho: u64,
    ) -> Result<(), HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .term_path_chirho(group_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        let bytes_chirho = serde_json::to_vec(&TermHighWaterChirho {
            schema_chirho: TERM_SCHEMA_V1_CHIRHO.to_string(),
            consistency_group_digest_chirho: group_digest_chirho.to_string(),
            highest_term_chirho: term_chirho,
        })
        .map_err(|_| write_failed_chirho())?;
        self.write_private_chirho(&path_chirho, &bytes_chirho)
    }

    /// The subject's folded tombstones, or none before its first erasure.
    pub(crate) fn subject_tombstones_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> Result<HolderTombstonesChirho, HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .tombstone_path_chirho(subject_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        let bytes_chirho = match read_stored_chirho(&path_chirho, LARGE_FILE_MAX_BYTES_CHIRHO) {
            StoredChirho::AbsentChirho => return Ok(HolderTombstonesChirho::new_chirho()),
            StoredChirho::PresentChirho(bytes_chirho) => bytes_chirho,
            StoredChirho::UnreadableChirho => return Err(unreadable_chirho()),
        };
        let shard_chirho: TombstoneShardChirho =
            serde_json::from_slice(&bytes_chirho).map_err(|_| unreadable_chirho())?;
        if shard_chirho.schema_chirho != TOMBSTONES_SCHEMA_V1_CHIRHO
            || shard_chirho.subject_digest_chirho != subject_digest_chirho
        {
            return Err(unreadable_chirho());
        }
        shard_chirho
            .tombstones_chirho
            .validate_chirho()
            .map_err(|_| unreadable_chirho())?;
        Ok(shard_chirho.tombstones_chirho)
    }

    pub(crate) fn store_subject_tombstones_chirho(
        &self,
        subject_digest_chirho: &str,
        tombstones_chirho: &HolderTombstonesChirho,
    ) -> Result<(), HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .tombstone_path_chirho(subject_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        let bytes_chirho = serde_json::to_vec(&TombstoneShardRefChirho {
            schema_chirho: TOMBSTONES_SCHEMA_V1_CHIRHO,
            subject_digest_chirho,
            tombstones_chirho,
        })
        .map_err(|_| write_failed_chirho())?;
        self.write_private_chirho(&path_chirho, &bytes_chirho)
    }

    /// The stored binding for a key, in form and bound to this subject and key id, or not.
    pub(crate) fn stored_binding_chirho(
        &self,
        subject_digest_chirho: &str,
        key_id_chirho: &str,
    ) -> Result<StoredChirho<CustodyBindingChirho>, HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .binding_path_chirho(subject_digest_chirho, key_id_chirho)
            .map_err(|_| unreadable_chirho())?;
        Ok(
            match read_stored_chirho(&path_chirho, SMALL_FILE_MAX_BYTES_CHIRHO) {
                StoredChirho::AbsentChirho => StoredChirho::AbsentChirho,
                StoredChirho::UnreadableChirho => StoredChirho::UnreadableChirho,
                StoredChirho::PresentChirho(bytes_chirho) => {
                    match serde_json::from_slice::<CustodyBindingChirho>(&bytes_chirho) {
                        Ok(binding_chirho)
                            if binding_chirho.validate_chirho().is_ok()
                                && binding_chirho.subject_digest_chirho
                                    == subject_digest_chirho
                                && binding_chirho.key_id_chirho == key_id_chirho =>
                        {
                            StoredChirho::PresentChirho(binding_chirho)
                        }
                        _ => StoredChirho::UnreadableChirho,
                    }
                }
            },
        )
    }

    fn stored_key_bytes_chirho(
        &self,
        subject_digest_chirho: &str,
        key_id_chirho: &str,
    ) -> Result<StoredChirho<Zeroizing<Vec<u8>>>, HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .key_path_chirho(subject_digest_chirho, key_id_chirho)
            .map_err(|_| unreadable_chirho())?;
        Ok(
            match read_stored_chirho(&path_chirho, SMALL_FILE_MAX_BYTES_CHIRHO) {
                StoredChirho::AbsentChirho => StoredChirho::AbsentChirho,
                StoredChirho::UnreadableChirho => StoredChirho::UnreadableChirho,
                StoredChirho::PresentChirho(bytes_chirho) => {
                    StoredChirho::PresentChirho(Zeroizing::new(bytes_chirho))
                }
            },
        )
    }

    /// Store an opened key durably: its binding first, then the key in the root's own key-file bytes
    /// (agy B2-B), so a crash never leaves a key without its binding. A retry for a key already stored
    /// must carry the same coordinates and the same key bytes, or it refuses (agy B2-C).
    pub(crate) fn store_custody_key_chirho(
        &self,
        opened_chirho: &OpenedCustodyKeyChirho,
    ) -> Result<(), HolderRefusalChirho> {
        let binding_chirho = opened_chirho.binding_chirho();
        let subject_chirho = &binding_chirho.subject_digest_chirho;
        let key_id_chirho = &binding_chirho.key_id_chirho;
        let key_bytes_chirho = opened_chirho.record_chirho().to_key_file_bytes_chirho()?;
        match self.stored_binding_chirho(subject_chirho, key_id_chirho)? {
            StoredChirho::PresentChirho(stored_chirho) => {
                if !same_key_coordinates_chirho(&stored_chirho, binding_chirho) {
                    return Err(HolderRefusalIdentityChirho::HolderCustodyConflictChirho.into());
                }
            }
            StoredChirho::UnreadableChirho => return Err(unreadable_chirho()),
            StoredChirho::AbsentChirho => {
                if !matches!(
                    self.stored_key_bytes_chirho(subject_chirho, key_id_chirho)?,
                    StoredChirho::AbsentChirho
                ) {
                    return Err(HolderRefusalIdentityChirho::HolderKeyWithoutBindingChirho.into());
                }
                let binding_bytes_chirho =
                    serde_json::to_vec_pretty(binding_chirho).map_err(|_| write_failed_chirho())?;
                let path_chirho = self
                    .layout_chirho
                    .binding_path_chirho(subject_chirho, key_id_chirho)
                    .map_err(|_| unreadable_chirho())?;
                self.write_private_chirho(&path_chirho, &binding_bytes_chirho)?;
            }
        }
        match self.stored_key_bytes_chirho(subject_chirho, key_id_chirho)? {
            StoredChirho::PresentChirho(stored_chirho) => {
                if stored_chirho.as_slice() != key_bytes_chirho.as_slice() {
                    return Err(HolderRefusalIdentityChirho::HolderCustodyConflictChirho.into());
                }
            }
            StoredChirho::UnreadableChirho => return Err(unreadable_chirho()),
            StoredChirho::AbsentChirho => {
                let path_chirho = self
                    .layout_chirho
                    .key_path_chirho(subject_chirho, key_id_chirho)
                    .map_err(|_| unreadable_chirho())?;
                self.write_private_chirho(&path_chirho, &key_bytes_chirho)?;
            }
        }
        // A retry whose binding and key already match wrote nothing, but an earlier crashed attempt may
        // have left them visible and not yet durable: sync before the receipt either way (gpt #29353).
        self.sync_subject_dir_chirho(subject_chirho)
    }

    /// Barrier: the group's term file is durable, even when this attempt wrote nothing.
    pub(crate) fn sync_term_dir_chirho(
        &self,
        group_digest_chirho: &str,
    ) -> Result<(), HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .term_path_chirho(group_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        self.sync_parent_if_present_chirho(&path_chirho)
    }

    /// Barrier: the subject's tombstone shard is durable, even when this attempt wrote nothing.
    pub(crate) fn sync_tombstone_dir_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> Result<(), HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .tombstone_path_chirho(subject_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        self.sync_parent_if_present_chirho(&path_chirho)
    }

    /// Barrier: an erasure record an earlier attempt stored is durable before anything is unlinked.
    pub(crate) fn sync_erasure_record_dir_chirho(
        &self,
        frame_digest_chirho: &str,
    ) -> Result<(), HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .erasure_record_path_chirho(frame_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        self.sync_parent_if_present_chirho(&path_chirho)
    }

    /// Barrier: every write and unlink in the subject's key directory is durable.
    fn sync_subject_dir_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> Result<(), HolderRefusalChirho> {
        let dir_chirho = self
            .layout_chirho
            .subject_keys_dir_chirho(subject_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        self.sync_dir_if_present_chirho(&dir_chirho)
    }

    /// The stored record of this frame's erasure, if an earlier attempt fixed one.
    pub(crate) fn erasure_record_chirho(
        &self,
        frame_chirho: &AuthorizedErasureFrameChirho,
    ) -> Result<Option<ErasureRecordChirho>, HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .erasure_record_path_chirho(frame_chirho.frame_digest_chirho())
            .map_err(|_| unreadable_chirho())?;
        let bytes_chirho = match read_stored_chirho(&path_chirho, LARGE_FILE_MAX_BYTES_CHIRHO) {
            StoredChirho::AbsentChirho => return Ok(None),
            StoredChirho::PresentChirho(bytes_chirho) => bytes_chirho,
            StoredChirho::UnreadableChirho => return Err(unreadable_chirho()),
        };
        let record_chirho: ErasureRecordChirho =
            serde_json::from_slice(&bytes_chirho).map_err(|_| unreadable_chirho())?;
        if !record_chirho.fits_frame_chirho(frame_chirho) {
            return Err(unreadable_chirho());
        }
        Ok(Some(record_chirho))
    }

    pub(crate) fn store_erasure_record_chirho(
        &self,
        record_chirho: &ErasureRecordChirho,
    ) -> Result<(), HolderRefusalChirho> {
        let path_chirho = self
            .layout_chirho
            .erasure_record_path_chirho(&record_chirho.erasure_frame_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        let bytes_chirho = serde_json::to_vec(record_chirho).map_err(|_| write_failed_chirho())?;
        self.write_private_chirho(&path_chirho, &bytes_chirho)
    }

    /// Classify every key under the frame's subject, scanning only that subject's directory (agy
    /// B2-C): a listed id is removed or already absent; an unlisted key is removed by the subject rule
    /// when its stored blob seq is below the bound, unverifiable when its binding cannot be read, and
    /// kept otherwise.
    pub(crate) fn classify_erasure_chirho(
        &self,
        frame_chirho: &AuthorizedErasureFrameChirho,
    ) -> Result<ErasureRecordChirho, HolderRefusalChirho> {
        let subject_chirho = frame_chirho.subject_digest_chirho();
        let files_chirho = self.subject_key_files_chirho(subject_chirho)?;
        let listed_chirho = frame_chirho
            .key_ids_chirho()
            .iter()
            .collect::<BTreeSet<_>>();
        let mut record_chirho = ErasureRecordChirho::empty_for_chirho(frame_chirho);
        for key_id_chirho in &listed_chirho {
            let held_chirho = files_chirho
                .get(*key_id_chirho)
                .is_some_and(KeyFilesChirho::holds_key_material_chirho);
            let into_chirho = if held_chirho {
                &mut record_chirho.removed_key_ids_chirho
            } else {
                &mut record_chirho.already_absent_key_ids_chirho
            };
            into_chirho.insert((*key_id_chirho).clone());
        }
        for (key_id_chirho, key_files_chirho) in &files_chirho {
            if listed_chirho.contains(key_id_chirho)
                || !key_files_chirho.holds_key_material_chirho()
            {
                continue;
            }
            match self.stored_binding_chirho(subject_chirho, key_id_chirho)? {
                StoredChirho::PresentChirho(binding_chirho) => {
                    if frame_chirho.covers_stored_key_chirho(&binding_chirho) {
                        record_chirho
                            .removed_by_subject_key_ids_chirho
                            .insert(key_id_chirho.clone());
                    }
                }
                StoredChirho::AbsentChirho | StoredChirho::UnreadableChirho => {
                    record_chirho
                        .unverifiable_key_ids_chirho
                        .insert(key_id_chirho.clone());
                }
            }
        }
        Ok(record_chirho)
    }

    /// Remove every file of the record's key ids from the subject's directory, key material before its
    /// binding, then fsync the directory. Repeating it after a crash finishes what is left.
    pub(crate) fn remove_erased_keys_chirho(
        &self,
        record_chirho: &ErasureRecordChirho,
    ) -> Result<(), HolderRefusalChirho> {
        let subject_chirho = &record_chirho.subject_digest_chirho;
        let dir_chirho = self
            .layout_chirho
            .subject_keys_dir_chirho(subject_chirho)
            .map_err(|_| unreadable_chirho())?;
        let erased_chirho = record_chirho
            .erased_key_ids_chirho()
            .collect::<BTreeSet<_>>();
        for (key_id_chirho, key_files_chirho) in self.subject_key_files_chirho(subject_chirho)? {
            if !erased_chirho.contains(&key_id_chirho) {
                continue;
            }
            if key_files_chirho.key_chirho {
                remove_file_if_present_chirho(
                    &self
                        .layout_chirho
                        .key_path_chirho(subject_chirho, &key_id_chirho)
                        .map_err(|_| unreadable_chirho())?,
                )?;
            }
            for temp_name_chirho in &key_files_chirho.temp_names_chirho {
                remove_file_if_present_chirho(&dir_chirho.join(temp_name_chirho))?;
            }
            if key_files_chirho.binding_chirho {
                remove_file_if_present_chirho(
                    &self
                        .layout_chirho
                        .binding_path_chirho(subject_chirho, &key_id_chirho)
                        .map_err(|_| unreadable_chirho())?,
                )?;
            }
        }
        // Unconditional: a retry that finds nothing left to remove still syncs, because an earlier
        // attempt's unlinks may be visible and not yet durable (gpt #29353).
        self.sync_dir_if_present_chirho(&dir_chirho)
    }

    /// Every key id with files in the subject's directory. A name this crate never writes, a symlink or
    /// a directory there refuses, and so does a directory larger than one erasure may scan.
    fn subject_key_files_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> Result<BTreeMap<String, KeyFilesChirho>, HolderRefusalChirho> {
        let dir_chirho = self
            .layout_chirho
            .subject_keys_dir_chirho(subject_digest_chirho)
            .map_err(|_| unreadable_chirho())?;
        let entries_chirho = match fs::read_dir(&dir_chirho) {
            Ok(entries_chirho) => entries_chirho,
            Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(_) => return Err(unreadable_chirho()),
        };
        let mut files_chirho = BTreeMap::<String, KeyFilesChirho>::new();
        for (index_chirho, entry_chirho) in entries_chirho.enumerate() {
            if index_chirho >= SUBJECT_SCAN_MAX_ENTRIES_CHIRHO {
                return Err(HolderRefusalIdentityChirho::HolderErasureScanTooLargeChirho.into());
            }
            let entry_chirho = entry_chirho.map_err(|_| unreadable_chirho())?;
            if !entry_chirho
                .file_type()
                .map_err(|_| unreadable_chirho())?
                .is_file()
            {
                return Err(unreadable_chirho());
            }
            let name_chirho = entry_chirho.file_name();
            let (key_id_chirho, kind_chirho) = name_chirho
                .to_str()
                .and_then(classify_subject_entry_chirho)
                .ok_or_else(unreadable_chirho)?;
            let slot_chirho = files_chirho.entry(key_id_chirho).or_default();
            match kind_chirho {
                SubjectEntryKindChirho::KeyChirho => slot_chirho.key_chirho = true,
                SubjectEntryKindChirho::BindingChirho => slot_chirho.binding_chirho = true,
                SubjectEntryKindChirho::KeyTempChirho => {
                    slot_chirho.key_temp_chirho = true;
                    slot_chirho.temp_names_chirho.push(name_chirho);
                }
                SubjectEntryKindChirho::BindingTempChirho => {
                    slot_chirho.temp_names_chirho.push(name_chirho);
                }
            }
        }
        Ok(files_chirho)
    }

    fn sync_parent_if_present_chirho(&self, path_chirho: &Path) -> Result<(), HolderRefusalChirho> {
        self.sync_dir_if_present_chirho(path_chirho.parent().ok_or_else(unreadable_chirho)?)
    }

    /// Sync a directory that exists, after making its ancestors' entries durable through the layout,
    /// which also re-checks that each is a private real directory: a reopened holder's retry may write
    /// nothing, yet a crashed process may have created that chain without its syncs (agy #29374). An
    /// absent directory holds nothing to make durable.
    fn sync_dir_if_present_chirho(&self, dir_chirho: &Path) -> Result<(), HolderRefusalChirho> {
        match fs::symlink_metadata(dir_chirho) {
            Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(unreadable_chirho()),
            Ok(_) => {
                self.layout_chirho
                    .ensure_private_dir_chirho(dir_chirho)
                    .map_err(|_| write_failed_chirho())?;
                sync_dir_chirho(dir_chirho).map_err(|_| write_failed_chirho())
            }
        }
    }

    /// Test-only: how many directories the layout remembers as synced.
    #[cfg(test)]
    pub(crate) fn remembered_directory_count_chirho(&self) -> usize {
        self.layout_chirho.remembered_directory_count_chirho()
    }

    fn write_private_chirho(
        &self,
        path_chirho: &Path,
        bytes_chirho: &[u8],
    ) -> Result<(), HolderRefusalChirho> {
        let parent_chirho = path_chirho.parent().ok_or_else(unreadable_chirho)?;
        self.layout_chirho
            .ensure_private_dir_chirho(parent_chirho)
            .map_err(|_| write_failed_chirho())?;
        write_file_durable_with_mode_chirho(path_chirho, bytes_chirho, PRIVATE_FILE_MODE_CHIRHO)
            .map_err(|_| write_failed_chirho())?;
        #[cfg(test)]
        crate::barrier_chirho::test_hooks_chirho::record_chirho(
            crate::barrier_chirho::test_hooks_chirho::EventKindChirho::WriteChirho,
            path_chirho,
        );
        Ok(())
    }
}

/// The coordinates that never change for one key: a retry under a new term, view or leader may differ
/// only in those.
fn same_key_coordinates_chirho(
    stored_chirho: &CustodyBindingChirho,
    incoming_chirho: &CustodyBindingChirho,
) -> bool {
    stored_chirho.consistency_group_digest_chirho == incoming_chirho.consistency_group_digest_chirho
        && stored_chirho.holder_node_id_chirho == incoming_chirho.holder_node_id_chirho
        && stored_chirho.key_id_chirho == incoming_chirho.key_id_chirho
        && stored_chirho.subject_digest_chirho == incoming_chirho.subject_digest_chirho
        && stored_chirho.ciphertext_addr_chirho == incoming_chirho.ciphertext_addr_chirho
        && stored_chirho.blob_seq_chirho == incoming_chirho.blob_seq_chirho
}

fn remove_file_if_present_chirho(path_chirho: &Path) -> Result<(), HolderRefusalChirho> {
    match fs::remove_file(path_chirho) {
        Ok(()) => {
            #[cfg(test)]
            crate::barrier_chirho::test_hooks_chirho::record_chirho(
                crate::barrier_chirho::test_hooks_chirho::EventKindChirho::UnlinkChirho,
                path_chirho,
            );
            Ok(())
        }
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(write_failed_chirho()),
    }
}

fn unreadable_chirho() -> HolderRefusalChirho {
    HolderRefusalIdentityChirho::HolderStoreUnreadableChirho.into()
}

fn write_failed_chirho() -> HolderRefusalChirho {
    HolderRefusalIdentityChirho::HolderStoreWriteFailedChirho.into()
}
