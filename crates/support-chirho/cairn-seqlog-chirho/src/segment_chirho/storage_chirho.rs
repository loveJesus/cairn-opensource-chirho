// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The seqlog-owned storage boundary the segment module routes ALL of its I/O through.
//!
//! One string-keyed trait plus a thin filesystem implementation, so the SAME rotation / base-seq /
//! reader code can be driven by production filesystem storage today AND (later) an in-memory store
//! for crash-matrix testing. A `SegmentPathChirho` is a plain string key (NOT a filesystem `Path`),
//! so a non-fs store keys its objects by the same string the fs impl maps to a real path. Every
//! op is a SEPARATE method on purpose: the rotation cuts must be independently interruptible so a
//! future fault injector can land BETWEEN two cuts, never bundle two into one op.

use anyhow::{anyhow, Context, Result};
use cairn_durable_chirho::{append_durable_line_chirho, write_file_durable_chirho};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// A storage-agnostic path KEY: a plain string, NOT a filesystem `Path`. The fs impl maps it to a
/// real path at the edge; an in-memory store keys its blobs by the same string, so identical segment
/// code drives either backend. The key is the storage/authority coordinate, so it MUST be injective:
/// distinct paths must never collapse to one key — hence the `&Path` conversion is fail-closed on
/// non-UTF-8 (never lossy), and the invariant "`SegmentPathChirho.0` is always valid UTF-8" holds.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SegmentPathChirho(pub String);

impl SegmentPathChirho {
    /// The raw string key.
    pub fn as_str_chirho(&self) -> &str {
        &self.0
    }

    /// Build a key from a filesystem path, FAIL-CLOSED on non-UTF-8. This is the single `&Path`→key
    /// conversion chokepoint, so it must never be lossy: two distinct non-UTF-8 paths would otherwise
    /// collapse to the same replacement-character key and silently alias artifacts — and the key feeds
    /// the money-relevant base-seq derivation. A non-UTF-8 path is refused, never coerced.
    pub fn from_path_chirho(path_chirho: &Path) -> Result<Self> {
        path_chirho
            .to_str()
            .map(|utf8_chirho| Self(utf8_chirho.to_string()))
            .ok_or_else(|| anyhow!("non-UTF-8 segment path {path_chirho:?}"))
    }

    /// The parent-directory key, mirroring `Path::parent` (`None` at a root/empty key). Used where the
    /// original code created an artifact's parent directory before writing it. `self.0` is already
    /// valid UTF-8, so its parent (a byte-prefix) is always UTF-8 too — this String→String derivation
    /// is total and never lossy (uses `to_str`, not `to_string_lossy`).
    pub fn parent_chirho(&self) -> Option<SegmentPathChirho> {
        Path::new(&self.0)
            .parent()
            .and_then(Path::to_str)
            .map(|parent_chirho| SegmentPathChirho(parent_chirho.to_string()))
    }
}

impl std::fmt::Display for SegmentPathChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str(&self.0)
    }
}

/// The seqlog-owned storage boundary for the segment module. Each op is one indivisible unit of
/// I/O; the segment code composes rotation out of these ops so a fault can land between any two.
///
/// Durability distinction (preserved byte-for-byte from the pre-extraction code):
/// - `write_durable_chirho` is an ATOMIC full-file replace (temp + rename + fsync) — for the advisory
///   sidecar, the rotation marker, a sealed segment, and the active-file reset.
/// - `append_durable_chirho` is a PLAIN durable append (O_APPEND + write + fsync) that is torn-able on
///   crash — for the manifest line. The manifest and the active file append with the same plain
///   primitive but have OPPOSITE recovery (manifest recovery fails closed on a torn tail; active-file
///   recovery repairs it), so the manifest append must NEVER be routed to the atomic op.
pub trait SegmentStorageChirho {
    /// The whole object, or `None` if it is absent.
    fn read_all_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<Vec<u8>>>;

    /// The object's byte length, or `None` if it is absent.
    fn object_len_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<u64>>;

    /// Exactly `len_chirho` bytes starting at `offset_chirho`; the caller guarantees the range is in
    /// bounds (a short object is an error, matching `read_exact`).
    fn read_range_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>>;

    /// Atomically replace the object with `bytes_chirho` (temp + rename + fsync).
    fn write_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()>;

    /// Durably APPEND `bytes_chirho` to the object (plain O_APPEND + fsync; torn-able on crash). A
    /// DISTINCT op from `write_durable_chirho` — never atomize it.
    fn append_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()>;

    /// Rename `from_chirho` to `to_chirho`.
    fn rename_chirho(
        &self,
        from_chirho: &SegmentPathChirho,
        to_chirho: &SegmentPathChirho,
    ) -> Result<()>;

    /// Remove the object; a missing object is a no-op (idempotent).
    fn remove_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<()>;

    /// Direct child regular files of `dir_chirho` (empty if the dir is absent). Only files are
    /// returned — matching the sealed-segment scan's `is_file` filter, and matching how an in-memory
    /// store, which holds only file-like blobs, would enumerate a prefix.
    fn list_dir_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<Vec<SegmentPathChirho>>;

    /// Whether the object exists.
    fn exists_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<bool>;

    /// Create `dir_chirho` and every missing parent.
    fn create_dir_all_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<()>;
}

/// The production filesystem storage: a THIN 1:1 pass-through over `std::fs` with NO buffering, so
/// each op is exactly one real filesystem operation and an injected fault would hit the real op.
pub struct FsSegmentStorageChirho;

impl FsSegmentStorageChirho {
    /// Map a string key to a real path at the filesystem edge.
    fn path_chirho(key_chirho: &SegmentPathChirho) -> &Path {
        Path::new(key_chirho.as_str_chirho())
    }
}

impl SegmentStorageChirho for FsSegmentStorageChirho {
    fn read_all_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<Vec<u8>>> {
        let fs_path_chirho = Self::path_chirho(path_chirho);
        match std::fs::read(fs_path_chirho) {
            Ok(bytes_chirho) => Ok(Some(bytes_chirho)),
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error_chirho) => {
                Err(error_chirho).with_context(|| format!("read {}", fs_path_chirho.display()))
            }
        }
    }

    fn object_len_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<u64>> {
        let fs_path_chirho = Self::path_chirho(path_chirho);
        match std::fs::metadata(fs_path_chirho) {
            Ok(metadata_chirho) => Ok(Some(metadata_chirho.len())),
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error_chirho) => {
                Err(error_chirho).with_context(|| format!("stat {}", fs_path_chirho.display()))
            }
        }
    }

    fn read_range_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        let fs_path_chirho = Self::path_chirho(path_chirho);
        let mut file_chirho = File::open(fs_path_chirho)
            .with_context(|| format!("open {}", fs_path_chirho.display()))?;
        file_chirho
            .seek(SeekFrom::Start(offset_chirho))
            .with_context(|| format!("seek {}", fs_path_chirho.display()))?;
        let mut buffer_chirho = vec![0u8; len_chirho as usize];
        file_chirho
            .read_exact(&mut buffer_chirho)
            .with_context(|| format!("read range {}", fs_path_chirho.display()))?;
        Ok(buffer_chirho)
    }

    fn write_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        let fs_path_chirho = Self::path_chirho(path_chirho);
        write_file_durable_chirho(fs_path_chirho, bytes_chirho)
            .with_context(|| format!("durable write {}", fs_path_chirho.display()))
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        let fs_path_chirho = Self::path_chirho(path_chirho);
        // The plain, torn-able durable-append primitive — the exact primitive the manifest line used
        // before extraction (via `append_jsonl_unlocked_chirho`). NOT atomized.
        append_durable_line_chirho(fs_path_chirho, bytes_chirho)
            .with_context(|| format!("durable append {}", fs_path_chirho.display()))
    }

    fn rename_chirho(
        &self,
        from_chirho: &SegmentPathChirho,
        to_chirho: &SegmentPathChirho,
    ) -> Result<()> {
        let from_path_chirho = Self::path_chirho(from_chirho);
        let to_path_chirho = Self::path_chirho(to_chirho);
        std::fs::rename(from_path_chirho, to_path_chirho).with_context(|| {
            format!(
                "rename {} -> {}",
                from_path_chirho.display(),
                to_path_chirho.display()
            )
        })
    }

    fn remove_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<()> {
        let fs_path_chirho = Self::path_chirho(path_chirho);
        match std::fs::remove_file(fs_path_chirho) {
            Ok(()) => Ok(()),
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error_chirho) => {
                Err(error_chirho).with_context(|| format!("remove {}", fs_path_chirho.display()))
            }
        }
    }

    fn list_dir_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<Vec<SegmentPathChirho>> {
        let fs_dir_chirho = Self::path_chirho(dir_chirho);
        let read_dir_chirho = match std::fs::read_dir(fs_dir_chirho) {
            Ok(read_dir_chirho) => read_dir_chirho,
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error_chirho) => {
                return Err(error_chirho)
                    .with_context(|| format!("read dir {}", fs_dir_chirho.display()));
            }
        };
        let mut children_chirho = Vec::new();
        for entry_chirho in read_dir_chirho {
            let entry_chirho = entry_chirho
                .with_context(|| format!("read dir entry in {}", fs_dir_chirho.display()))?;
            if entry_chirho.path().is_file() {
                // Fail closed on a non-UTF-8 child: never a lossy suffix-match "hit". A non-UTF-8
                // sealed-dir entry makes this scan (and `segments_dir_has_sealed_files_chirho`) error.
                children_chirho.push(SegmentPathChirho::from_path_chirho(&entry_chirho.path())?);
            }
        }
        Ok(children_chirho)
    }

    fn exists_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<bool> {
        Ok(Self::path_chirho(path_chirho).exists())
    }

    fn create_dir_all_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<()> {
        let fs_dir_chirho = Self::path_chirho(dir_chirho);
        std::fs::create_dir_all(fs_dir_chirho)
            .with_context(|| format!("create dir {}", fs_dir_chirho.display()))
    }
}
