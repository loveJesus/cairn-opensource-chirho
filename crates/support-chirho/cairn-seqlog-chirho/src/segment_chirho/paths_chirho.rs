// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Sibling path derivation for a segmented log — one place that names every on-disk artifact.
//!
//! All artifacts hang off the active `<name>.jsonl` path so a family only ever passes that one path:
//! the append-only manifest, its advisory head checkpoint, the sealed-segments directory (with each
//! sealed segment content-named by its full digest), and the crash-recovery rotation marker. Each
//! accessor returns a storage-agnostic `SegmentPathChirho` string KEY (not a filesystem `Path`), so
//! the same code drives the filesystem storage or a future in-memory store.

use crate::segment_chirho::storage_chirho::{SegmentPathChirho, SegmentStorageChirho};
use anyhow::{anyhow, Result};

/// Filename suffix for a content-named sealed segment: `<segment-digest>.seg-chirho`.
pub const SEALED_SEGMENT_SUFFIX_CHIRHO: &str = ".seg-chirho";

const MANIFEST_SUFFIX_CHIRHO: &str = ".segment-manifest-chirho";
const MANIFEST_HEAD_SUFFIX_CHIRHO: &str = ".segment-manifest-chirho.mhead-chirho";
const PREDECESSOR_INDEX_DIR_SUFFIX_CHIRHO: &str = ".segment-predecessors-chirho";
const PREDECESSOR_INDEX_ENTRY_SUFFIX_CHIRHO: &str = ".predecessor-chirho";
const SEGMENTS_DIR_SUFFIX_CHIRHO: &str = ".segments-chirho";
const ROTATION_MARKER_SUFFIX_CHIRHO: &str = ".segment-rotation-chirho";

/// Every sibling artifact a segmented log derives from its active `<name>.jsonl` file path. The active
/// path is held as a UTF-8 `String` (the storage coordinate), so every child key is derived by pure
/// string operations — total, non-lossy, and injective — with NO `&Path` conversion on this path.
#[derive(Clone, Debug)]
pub struct SegmentPathsChirho {
    active_chirho: String,
}

impl SegmentPathsChirho {
    /// Build the path set for a log whose active file is `active_log_path_chirho`. Takes a UTF-8
    /// `String` coordinate (the journal already holds one via `StoragePathChirho`); child paths are
    /// then derived by string append/join, reproducing the exact same on-disk layout as before.
    pub fn new_chirho(active_log_path_chirho: impl Into<String>) -> Self {
        Self {
            active_chirho: active_log_path_chirho.into(),
        }
    }

    /// The active `<name>.jsonl` file (the existing hot log, unchanged).
    pub fn active_chirho(&self) -> SegmentPathChirho {
        SegmentPathChirho(self.active_chirho.clone())
    }

    /// The append-only signed segment manifest.
    pub fn manifest_chirho(&self) -> SegmentPathChirho {
        SegmentPathChirho(format!("{}{}", self.active_chirho, MANIFEST_SUFFIX_CHIRHO))
    }

    /// The advisory O(1) manifest-head checkpoint.
    pub fn manifest_head_chirho(&self) -> SegmentPathChirho {
        SegmentPathChirho(format!(
            "{}{}",
            self.active_chirho, MANIFEST_HEAD_SUFFIX_CHIRHO
        ))
    }

    /// The directory holding authenticated digest-addressed manifest-entry predecessors.
    pub fn predecessor_index_dir_chirho(&self) -> SegmentPathChirho {
        SegmentPathChirho(format!(
            "{}{}",
            self.active_chirho, PREDECESSOR_INDEX_DIR_SUFFIX_CHIRHO
        ))
    }

    /// The authenticated manifest-entry object named by its canonical entry digest.
    ///
    /// Digest grammar is checked by the predecessor-index module before this pure path derivation;
    /// keeping that validation at the I/O boundary prevents path-like caller text from reaching
    /// here. Two digest-prefix levels bound practical directory fanout as history grows.
    pub fn predecessor_index_entry_chirho(
        &self,
        manifest_entry_digest_chirho: &str,
    ) -> SegmentPathChirho {
        let first_shard_chirho = manifest_entry_digest_chirho.get(0..2).unwrap_or("invalid");
        let second_shard_chirho = manifest_entry_digest_chirho.get(2..4).unwrap_or("invalid");
        SegmentPathChirho(format!(
            "{}{}/{}/{}/{}{}",
            self.active_chirho,
            PREDECESSOR_INDEX_DIR_SUFFIX_CHIRHO,
            first_shard_chirho,
            second_shard_chirho,
            manifest_entry_digest_chirho,
            PREDECESSOR_INDEX_ENTRY_SUFFIX_CHIRHO
        ))
    }

    /// The directory holding content-named sealed segment files.
    pub fn segments_dir_chirho(&self) -> SegmentPathChirho {
        SegmentPathChirho(format!(
            "{}{}",
            self.active_chirho, SEGMENTS_DIR_SUFFIX_CHIRHO
        ))
    }

    /// The sealed segment file for `segment_digest_chirho` (content-addressed, so seal is idempotent).
    /// On the deployed Unix targets, BYTE-IDENTICAL to the previous
    /// `<segments-dir>.join("<digest>.seg-chirho")`: `/` is the Unix path separator, so segments dir
    /// (active + suffix) + `/` + content-named sealed file reproduce `PathBuf::join` exactly. (Scoped
    /// to Unix/deployed: on Windows `join` renders `\` — filesystem-equivalent but not string-byte-
    /// identical; cairn has no Windows deployment contract, so the fixed `/` is correct here.)
    pub fn sealed_segment_chirho(&self, segment_digest_chirho: &str) -> SegmentPathChirho {
        SegmentPathChirho(format!(
            "{}{}/{}{}",
            self.active_chirho,
            SEGMENTS_DIR_SUFFIX_CHIRHO,
            segment_digest_chirho,
            SEALED_SEGMENT_SUFFIX_CHIRHO
        ))
    }

    /// The durable rotation-intent marker; its presence means a rotation is mid-flight and the next
    /// locked recovery must finish or refuse it before deriving a sequence.
    pub fn rotation_marker_chirho(&self) -> SegmentPathChirho {
        SegmentPathChirho(format!(
            "{}{}",
            self.active_chirho, ROTATION_MARKER_SUFFIX_CHIRHO
        ))
    }

    /// Fail closed if a rotation is mid-flight (its marker is present), so seq derivation and reads
    /// never proceed over a half-rotated log — where the active file can still hold records already
    /// sealed into a segment. The caller must run `recover_pending_rotation_chirho` under the lock
    /// first. Enforced at the base-seq mint point (`derive_base_seq_chirho`), so even a direct caller
    /// of that function is guarded.
    pub(crate) fn refuse_if_pending_rotation_chirho(
        &self,
        storage_chirho: &dyn SegmentStorageChirho,
    ) -> Result<()> {
        if storage_chirho.exists_chirho(&self.rotation_marker_chirho())? {
            return Err(anyhow!(
                "segmented log has a pending rotation; recover before reading or deriving — fail closed"
            ));
        }
        Ok(())
    }
}
