// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! An in-memory `SegmentStorageChirho` proven byte-for-byte equivalent to the filesystem impl, so the
//! storage-agnostic seqlog segment machinery can (later) be crash-tested without a real disk.
//!
//! `MemSegmentStorageChirho` is a faithful, op-by-op mirror of `FsSegmentStorageChirho` over a string
//! keyed `BTreeMap` (the same key the fs impl maps to a real path). The tests below run the SAME
//! scenario through BOTH backends and assert identical observable results: the money-critical
//! `derive_base_seq_chirho` (cold AND warm) is fully storage-routed and therefore driven end-to-end
//! through mem, and `rotate_segment_chirho`'s sealed-artifact writes are proven identical too — the
//! one fs coupling (rotation's active-file torn-tail repair) is the expected deviation-#4 boundary,
//! documented at the rotation test.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};

use cairn_seqlog_chirho::segment_chirho::continuity_chirho::{
    sign_manifest_entry_chirho, SegmentContinuityPortChirho, SegmentSignatureChirho,
};
use cairn_seqlog_chirho::segment_chirho::manifest_chirho::{
    append_signed_manifest_line_chirho, derive_base_seq_chirho, load_manifest_lines_chirho,
    new_segment_manifest_entry_chirho, BaseSeqChirho,
};
use cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho;
use cairn_seqlog_chirho::segment_chirho::rotation_chirho::{
    rotate_segment_chirho, RotationOutcomeChirho,
};
use cairn_seqlog_chirho::segment_chirho::storage_chirho::{
    FsSegmentStorageChirho, SegmentPathChirho, SegmentStorageChirho,
};
use cairn_seqlog_chirho::segment_chirho::LogIdentityChirho;
use cairn_seqlog_chirho::seqlog_chirho::with_append_log_lock_chirho;

// ================================================================================================
// The in-memory adapter — a faithful, op-by-op mirror of `FsSegmentStorageChirho`.
// ================================================================================================

/// A `SegmentStorageChirho` backed by an in-memory string-keyed blob map. Single-threaded (interior
/// mutability via `RefCell`) exactly like the sim's other adapters: the whole harness is one
/// deterministic schedule. Each op is one indivisible map mutation/read, mirroring the fs impl's
/// "one op = one real filesystem operation" so a future fault injector can land between any two.
pub struct MemSegmentStorageChirho {
    store_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl MemSegmentStorageChirho {
    /// A fresh empty in-memory segment store.
    pub fn new_chirho() -> Self {
        Self {
            store_chirho: RefCell::new(BTreeMap::new()),
        }
    }

    /// A clone of the durable map as it stands — the bytes that would survive a crash right now (the
    /// snapshot a future crash matrix restores from).
    pub fn snapshot_chirho(&self) -> BTreeMap<String, Vec<u8>> {
        self.store_chirho.borrow().clone()
    }
}

impl SegmentStorageChirho for MemSegmentStorageChirho {
    fn read_all_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<Vec<u8>>> {
        // `Some(bytes)` iff the key exists, else `None` — exactly the fs impl's read + NotFound→None.
        Ok(self
            .store_chirho
            .borrow()
            .get(path_chirho.as_str_chirho())
            .cloned())
    }

    fn object_len_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<u64>> {
        // `Some(len)` iff present, else `None` — the fs impl's metadata + NotFound→None.
        Ok(self
            .store_chirho
            .borrow()
            .get(path_chirho.as_str_chirho())
            .map(|bytes_chirho| bytes_chirho.len() as u64))
    }

    fn read_range_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        // Fail-closed like `File::seek` + `File::read_exact`: absent object, offset+len overflow, or a
        // range past the object's length is an ERROR — a short read is never a truncated prefix.
        let store_chirho = self.store_chirho.borrow();
        let bytes_chirho = store_chirho
            .get(path_chirho.as_str_chirho())
            .ok_or_else(|| anyhow!("mem read range: object {path_chirho} absent"))?;
        let end_chirho = offset_chirho.checked_add(len_chirho).ok_or_else(|| {
            anyhow!("mem read range: offset {offset_chirho} + len {len_chirho} overflows u64 for {path_chirho}")
        })?;
        if end_chirho > bytes_chirho.len() as u64 {
            return Err(anyhow!(
                "mem read range [{offset_chirho}, {end_chirho}) past object length {} for {path_chirho}",
                bytes_chirho.len()
            ));
        }
        Ok(bytes_chirho[offset_chirho as usize..end_chirho as usize].to_vec())
    }

    fn write_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        // Atomic full-object replace — the observable end state of the fs impl's temp+rename+fsync.
        self.store_chirho.borrow_mut().insert(
            path_chirho.as_str_chirho().to_string(),
            bytes_chirho.to_vec(),
        );
        Ok(())
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        // Plain durable append: extend the existing value, or create it — the fs impl's O_APPEND. A
        // DISTINCT op from `write_durable_chirho` (never atomized), matching the manifest's plain append.
        self.store_chirho
            .borrow_mut()
            .entry(path_chirho.as_str_chirho().to_string())
            .or_default()
            .extend_from_slice(bytes_chirho);
        Ok(())
    }

    fn rename_chirho(
        &self,
        from_chirho: &SegmentPathChirho,
        to_chirho: &SegmentPathChirho,
    ) -> Result<()> {
        // Move from→to; a missing source is an ERROR, exactly like a real `std::fs::rename` ENOENT (a
        // silent no-op would be more permissive than the fs and hide a bug that fails in production).
        let mut store_chirho = self.store_chirho.borrow_mut();
        match store_chirho.remove(from_chirho.as_str_chirho()) {
            Some(bytes_chirho) => {
                store_chirho.insert(to_chirho.as_str_chirho().to_string(), bytes_chirho);
                Ok(())
            }
            None => Err(anyhow!("mem rename: source {from_chirho} does not exist")),
        }
    }

    fn remove_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<()> {
        // Idempotent: a missing object is a no-op, mirroring the fs impl's NotFound-is-Ok remove.
        self.store_chirho
            .borrow_mut()
            .remove(path_chirho.as_str_chirho());
        Ok(())
    }

    fn list_dir_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<Vec<SegmentPathChirho>> {
        // Direct child regular files only, mirroring the fs impl's `read_dir` + `is_file` filter: a key
        // `"{dir}/{child}"` whose `child` contains no further `/`. A remainder with a `/` names a file
        // inside a sub-dir (fs would return the sub-DIR entry, dropped by `is_file`, never the deep
        // file), so it is excluded here too. An absent dir yields an empty vec (no keys under it).
        let prefix_chirho = format!("{}/", dir_chirho.as_str_chirho());
        let mut children_chirho = Vec::new();
        for key_chirho in self.store_chirho.borrow().keys() {
            if let Some(rest_chirho) = key_chirho.strip_prefix(&prefix_chirho) {
                if !rest_chirho.contains('/') {
                    children_chirho.push(SegmentPathChirho(key_chirho.clone()));
                }
            }
        }
        // Order is unspecified by the trait (the fs `read_dir` order is arbitrary); the only consumer
        // asks "any sealed file?", so sorted BTreeMap order is fine and deterministic.
        Ok(children_chirho)
    }

    fn exists_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<bool> {
        Ok(self
            .store_chirho
            .borrow()
            .contains_key(path_chirho.as_str_chirho()))
    }

    fn create_dir_all_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<()> {
        // Directories are IMPLICIT in the map: an object exists iff its exact key is written, so there
        // is no directory to materialize. A no-op — the fs impl only needs create_dir_all to make a
        // parent path the in-memory store does not model.
        let _ = dir_chirho;
        Ok(())
    }
}

// ================================================================================================
// Local test scaffolding — a keyed-blake3 continuity port + storage-routed synthetic sealing.
// ================================================================================================

/// A test continuity port: a keyed-blake3 MAC over the canonical entry bytes (a real signer would use
/// ed25519). Mirrors the seqlog module's own `TestContinuityPortChirho`, which is private to that
/// crate; a single instance is shared across BOTH backends so signatures compare byte-for-byte.
pub(crate) struct TestSegmentContinuityPortChirho {
    key_chirho: [u8; 32],
    key_id_chirho: String,
}

impl TestSegmentContinuityPortChirho {
    pub(crate) fn new_chirho() -> Self {
        Self {
            key_chirho: *blake3::hash(b"cairn-mem-segment-sim-continuity-key-chirho").as_bytes(),
            key_id_chirho: "sim-key-1-chirho".to_string(),
        }
    }
}

impl SegmentContinuityPortChirho for TestSegmentContinuityPortChirho {
    fn sign_canonical_chirho(
        &self,
        canonical_bytes_chirho: &[u8],
    ) -> Result<SegmentSignatureChirho> {
        Ok(SegmentSignatureChirho(
            blake3::keyed_hash(&self.key_chirho, canonical_bytes_chirho)
                .to_hex()
                .to_string(),
        ))
    }

    fn verify_canonical_chirho(
        &self,
        canonical_bytes_chirho: &[u8],
        signature_chirho: &SegmentSignatureChirho,
    ) -> Result<()> {
        let expected_chirho = blake3::keyed_hash(&self.key_chirho, canonical_bytes_chirho)
            .to_hex()
            .to_string();
        if expected_chirho == signature_chirho.0 {
            Ok(())
        } else {
            Err(anyhow!("sim continuity signature mismatch"))
        }
    }

    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
}

/// The final physical line (record plus its trailing newline) of a raw JSONL body; empty for empty.
/// A local mirror of seqlog's `pub(crate)` `final_physical_line_chirho`, which is not reachable across
/// the crate boundary — copied verbatim so a sealed segment's final-line digest is computed one way.
fn final_physical_line_local_chirho(raw_chirho: &[u8]) -> &[u8] {
    if raw_chirho.is_empty() {
        return raw_chirho;
    }
    let trimmed_chirho = raw_chirho.strip_suffix(b"\n").unwrap_or(raw_chirho);
    let start_chirho = trimmed_chirho
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map(|position_chirho| position_chirho + 1)
        .unwrap_or(0);
    &raw_chirho[start_chirho..]
}

/// One record line, byte-identical to `serde_json::to_string(&SegTestRecordChirho { seq, value })`
/// for the seqlog test record shape plus a trailing newline. Hand-formatted so the sim crate keeps no
/// serde_json dependency; the field order (`seq_chirho`, then `value_chirho`) matches serde's.
fn record_line_bytes_chirho(seq_chirho: u64) -> String {
    format!(
        "{{\"seq_chirho\":{seq_chirho},\"value_chirho\":{}}}\n",
        1000 + seq_chirho
    )
}

/// The raw JSONL bytes of `count_chirho` records starting at `first_seq_chirho`.
fn active_bytes_for_records_chirho(first_seq_chirho: u64, count_chirho: u64) -> Vec<u8> {
    let mut body_chirho = String::new();
    for offset_chirho in 0..count_chirho {
        body_chirho.push_str(&record_line_bytes_chirho(first_seq_chirho + offset_chirho));
    }
    body_chirho.into_bytes()
}

/// Write a synthetic sealed segment AND append its signed manifest entry, routing every write through
/// the storage trait — the storage-parameterized twin of the seqlog test helper `seal_synthetic_
/// segment_chirho` (which hard-codes `std::fs`). Returns the new entry's digest so the next call can
/// chain to it. Mirrors rotation's own `write_sealed_segment_chirho` (create parent dir → durable
/// write) so the fs and mem backends take the identical trait-op path.
// Mirrors `new_segment_manifest_entry_chirho`'s parameter set (which seqlog annotates the same way).
#[allow(clippy::too_many_arguments)]
fn seal_synthetic_segment_via_storage_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    identity_chirho: &LogIdentityChirho,
    generation_chirho: u64,
    first_seq_chirho: u64,
    count_chirho: u64,
    prev_entry_digest_chirho: Option<String>,
) -> Result<String> {
    let raw_chirho = active_bytes_for_records_chirho(first_seq_chirho, count_chirho);
    let segment_digest_chirho = blake3::hash(&raw_chirho).to_hex().to_string();
    let final_line_digest_chirho = blake3::hash(final_physical_line_local_chirho(&raw_chirho))
        .to_hex()
        .to_string();
    let sealed_path_chirho = paths_chirho.sealed_segment_chirho(&segment_digest_chirho);
    if let Some(parent_chirho) = sealed_path_chirho.parent_chirho() {
        storage_chirho.create_dir_all_chirho(&parent_chirho)?;
    }
    storage_chirho.write_durable_chirho(&sealed_path_chirho, &raw_chirho)?;
    let last_seq_chirho = first_seq_chirho + count_chirho - 1;
    let entry_chirho = new_segment_manifest_entry_chirho(
        identity_chirho,
        generation_chirho,
        first_seq_chirho,
        last_seq_chirho,
        raw_chirho.len() as u64,
        segment_digest_chirho,
        final_line_digest_chirho,
        prev_entry_digest_chirho,
    );
    let line_chirho = sign_manifest_entry_chirho(port_chirho, &entry_chirho)?;
    append_signed_manifest_line_chirho(storage_chirho, paths_chirho, &line_chirho)?;
    entry_chirho.entry_digest_chirho()
}

/// A unique temp root per call (nanos ⊕ process-shifted counter), mirroring the seqlog tests.
pub(crate) fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-mem-seg-diff-{nanos_chirho}-{n_chirho}"))
}

// ================================================================================================
// Op-by-op fidelity: run the SAME op sequence through a fresh fs store and a fresh mem store and
// assert identical observable results, one trait method at a time.
// ================================================================================================

#[test]
fn read_write_append_len_exists_match_fs_and_mem_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let key_chirho = SegmentPathChirho::from_path_chirho(&root_chirho.join("obj-chirho")).unwrap();
    let absent_chirho =
        SegmentPathChirho::from_path_chirho(&root_chirho.join("absent-chirho")).unwrap();

    let fs_chirho = FsSegmentStorageChirho;
    let mem_chirho = MemSegmentStorageChirho::new_chirho();
    for storage_chirho in [&fs_chirho as &dyn SegmentStorageChirho, &mem_chirho] {
        // Absent object: read_all None, object_len None, exists false.
        assert_eq!(
            storage_chirho.read_all_chirho(&absent_chirho).unwrap(),
            None
        );
        assert_eq!(
            storage_chirho.object_len_chirho(&absent_chirho).unwrap(),
            None
        );
        assert!(!storage_chirho.exists_chirho(&absent_chirho).unwrap());

        // write_durable then read back.
        storage_chirho
            .write_durable_chirho(&key_chirho, b"abc")
            .unwrap();
        assert_eq!(
            storage_chirho
                .read_all_chirho(&key_chirho)
                .unwrap()
                .as_deref(),
            Some(b"abc".as_slice())
        );
        assert_eq!(
            storage_chirho.object_len_chirho(&key_chirho).unwrap(),
            Some(3)
        );
        assert!(storage_chirho.exists_chirho(&key_chirho).unwrap());

        // write_durable is an atomic REPLACE, not an append.
        storage_chirho
            .write_durable_chirho(&key_chirho, b"wxyz")
            .unwrap();
        assert_eq!(
            storage_chirho
                .read_all_chirho(&key_chirho)
                .unwrap()
                .as_deref(),
            Some(b"wxyz".as_slice())
        );

        // append_durable extends the existing value.
        storage_chirho
            .append_durable_chirho(&key_chirho, b"!!")
            .unwrap();
        assert_eq!(
            storage_chirho
                .read_all_chirho(&key_chirho)
                .unwrap()
                .as_deref(),
            Some(b"wxyz!!".as_slice())
        );
        assert_eq!(
            storage_chirho.object_len_chirho(&key_chirho).unwrap(),
            Some(6)
        );

        // append_durable to a fresh key CREATES it.
        let created_chirho =
            SegmentPathChirho::from_path_chirho(&root_chirho.join("created-chirho")).unwrap();
        storage_chirho
            .append_durable_chirho(&created_chirho, b"new")
            .unwrap();
        assert_eq!(
            storage_chirho
                .read_all_chirho(&created_chirho)
                .unwrap()
                .as_deref(),
            Some(b"new".as_slice())
        );
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn read_range_matches_read_exact_and_short_read_is_error_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let key_chirho =
        SegmentPathChirho::from_path_chirho(&root_chirho.join("range-chirho")).unwrap();
    let absent_chirho =
        SegmentPathChirho::from_path_chirho(&root_chirho.join("absent-chirho")).unwrap();

    let fs_chirho = FsSegmentStorageChirho;
    let mem_chirho = MemSegmentStorageChirho::new_chirho();
    for storage_chirho in [&fs_chirho as &dyn SegmentStorageChirho, &mem_chirho] {
        storage_chirho
            .write_durable_chirho(&key_chirho, b"abcdefghij")
            .unwrap();
        // Exact windows.
        assert_eq!(
            storage_chirho.read_range_chirho(&key_chirho, 2, 3).unwrap(),
            b"cde"
        );
        assert_eq!(
            storage_chirho
                .read_range_chirho(&key_chirho, 0, 10)
                .unwrap(),
            b"abcdefghij"
        );
        // A range past the end is a short read → ERROR (never a truncated prefix).
        assert!(storage_chirho.read_range_chirho(&key_chirho, 8, 5).is_err());
        assert!(storage_chirho
            .read_range_chirho(&key_chirho, 10, 1)
            .is_err());
        // An absent object is an error, not an empty Ok.
        assert!(storage_chirho
            .read_range_chirho(&absent_chirho, 0, 1)
            .is_err());
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rename_moves_value_and_missing_source_errors_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let from_chirho =
        SegmentPathChirho::from_path_chirho(&root_chirho.join("from-chirho")).unwrap();
    let to_chirho = SegmentPathChirho::from_path_chirho(&root_chirho.join("to-chirho")).unwrap();
    let missing_chirho =
        SegmentPathChirho::from_path_chirho(&root_chirho.join("missing-chirho")).unwrap();

    let fs_chirho = FsSegmentStorageChirho;
    let mem_chirho = MemSegmentStorageChirho::new_chirho();
    for storage_chirho in [&fs_chirho as &dyn SegmentStorageChirho, &mem_chirho] {
        storage_chirho
            .write_durable_chirho(&from_chirho, b"payload")
            .unwrap();
        storage_chirho
            .rename_chirho(&from_chirho, &to_chirho)
            .unwrap();
        assert_eq!(storage_chirho.read_all_chirho(&from_chirho).unwrap(), None);
        assert_eq!(
            storage_chirho
                .read_all_chirho(&to_chirho)
                .unwrap()
                .as_deref(),
            Some(b"payload".as_slice())
        );
        // Renaming an absent source fails closed like fs ENOENT.
        assert!(storage_chirho
            .rename_chirho(&missing_chirho, &to_chirho)
            .is_err());
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn remove_is_idempotent_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let key_chirho = SegmentPathChirho::from_path_chirho(&root_chirho.join("rm-chirho")).unwrap();

    let fs_chirho = FsSegmentStorageChirho;
    let mem_chirho = MemSegmentStorageChirho::new_chirho();
    for storage_chirho in [&fs_chirho as &dyn SegmentStorageChirho, &mem_chirho] {
        storage_chirho
            .write_durable_chirho(&key_chirho, b"x")
            .unwrap();
        storage_chirho.remove_chirho(&key_chirho).unwrap();
        assert!(!storage_chirho.exists_chirho(&key_chirho).unwrap());
        // Removing an already-absent object is a no-op, not an error.
        storage_chirho.remove_chirho(&key_chirho).unwrap();
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn list_dir_returns_direct_child_files_only_match_fs_and_mem_chirho() {
    let root_chirho = tmp_root_chirho();
    let dir_path_chirho = root_chirho.join("seg-dir-chirho");
    let dir_chirho = SegmentPathChirho::from_path_chirho(&dir_path_chirho).unwrap();
    let absent_dir_chirho =
        SegmentPathChirho::from_path_chirho(&root_chirho.join("absent-dir-chirho")).unwrap();
    // Two direct-child files and one file nested inside a sub-dir, keyed by identical strings on both
    // backends (fs renders `read_dir` entries with the same path join).
    let child_a_chirho =
        SegmentPathChirho::from_path_chirho(&dir_path_chirho.join("a.seg-chirho")).unwrap();
    let child_b_chirho =
        SegmentPathChirho::from_path_chirho(&dir_path_chirho.join("b.seg-chirho")).unwrap();
    let deep_chirho = SegmentPathChirho::from_path_chirho(
        &dir_path_chirho.join("sub-chirho").join("deep-chirho"),
    )
    .unwrap();

    let fs_chirho = FsSegmentStorageChirho;
    let mem_chirho = MemSegmentStorageChirho::new_chirho();

    let sorted_children_chirho = |storage_chirho: &dyn SegmentStorageChirho| -> Vec<String> {
        let mut listed_chirho: Vec<String> = storage_chirho
            .list_dir_chirho(&dir_chirho)
            .unwrap()
            .into_iter()
            .map(|path_chirho| path_chirho.0)
            .collect();
        listed_chirho.sort();
        listed_chirho
    };

    // fs: real dirs/files; the deep file lives under a real sub-dir.
    std::fs::create_dir_all(&dir_path_chirho).unwrap();
    std::fs::create_dir_all(dir_path_chirho.join("sub-chirho")).unwrap();
    fs_chirho
        .write_durable_chirho(&child_a_chirho, b"a")
        .unwrap();
    fs_chirho
        .write_durable_chirho(&child_b_chirho, b"b")
        .unwrap();
    fs_chirho
        .write_durable_chirho(&deep_chirho, b"deep")
        .unwrap();
    // mem: the identical keys (create_dir_all is a no-op).
    mem_chirho
        .write_durable_chirho(&child_a_chirho, b"a")
        .unwrap();
    mem_chirho
        .write_durable_chirho(&child_b_chirho, b"b")
        .unwrap();
    mem_chirho
        .write_durable_chirho(&deep_chirho, b"deep")
        .unwrap();

    let expected_chirho = vec![child_a_chirho.0.clone(), child_b_chirho.0.clone()];
    // Only the two DIRECT child files are returned (the sub-dir and its deep file are excluded), and
    // fs and mem return the identical set.
    assert_eq!(sorted_children_chirho(&fs_chirho), expected_chirho);
    assert_eq!(sorted_children_chirho(&mem_chirho), expected_chirho);
    // An absent directory yields an empty listing on both.
    assert!(fs_chirho
        .list_dir_chirho(&absent_dir_chirho)
        .unwrap()
        .is_empty());
    assert!(mem_chirho
        .list_dir_chirho(&absent_dir_chirho)
        .unwrap()
        .is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn create_dir_all_is_a_noop_with_no_phantom_key_chirho() {
    let mem_chirho = MemSegmentStorageChirho::new_chirho();
    let dir_chirho = SegmentPathChirho("/any/mem/dir-chirho".to_string());
    mem_chirho.create_dir_all_chirho(&dir_chirho).unwrap();
    // The no-op neither errors nor invents a key: the dir does not "exist" as an object.
    assert!(!mem_chirho.exists_chirho(&dir_chirho).unwrap());
    assert!(mem_chirho.snapshot_chirho().is_empty());
}

// ================================================================================================
// fs ≡ mem DIFFERENTIAL — the same scenario through both backends, asserting identical results.
// ================================================================================================

/// Seal two chained synthetic segments (gen0 = seq 0..3, gen1 = seq 3..5) through `storage_chirho`,
/// then derive the base sequence cold (no checkpoint) and warm (checkpoint seeded). Both derives use
/// only the storage trait — `derive_base_seq_chirho` reads the manifest + advisory sidecar and never
/// touches the active file — so this whole scenario is driven end-to-end through either backend.
pub(crate) fn run_derive_scenario_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    identity_chirho: &LogIdentityChirho,
) -> (BaseSeqChirho, BaseSeqChirho) {
    let digest0_chirho = seal_synthetic_segment_via_storage_chirho(
        storage_chirho,
        paths_chirho,
        port_chirho,
        identity_chirho,
        0,
        0,
        3,
        None,
    )
    .unwrap();
    seal_synthetic_segment_via_storage_chirho(
        storage_chirho,
        paths_chirho,
        port_chirho,
        identity_chirho,
        1,
        3,
        2,
        Some(digest0_chirho),
    )
    .unwrap();
    let identity_digest_chirho = identity_chirho.digest_chirho();
    // Cold: no checkpoint yet → full manifest verify, then re-seed the head.
    let cold_chirho = derive_base_seq_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        &identity_digest_chirho,
    )
    .unwrap();
    // Warm: the re-seeded head makes this an O(1) fast-path hit (still verifying the signed tail line).
    let warm_chirho = derive_base_seq_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        &identity_digest_chirho,
    )
    .unwrap();
    (cold_chirho, warm_chirho)
}

#[test]
fn derive_base_seq_is_identical_fs_and_mem_cold_and_warm_chirho() {
    // The money-critical base-seq derivation, proven storage-agnostic AND sim-driveable: identical
    // `BaseSeqChirho` over the filesystem and the in-memory store, cold AND warm.
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("derive-diff-chirho.jsonl");
    // ONE path set for both backends: the fs impl writes real files under `root`, the mem impl keys its
    // own map by the identical strings. Nothing in `BaseSeqChirho` depends on the path (log identity is
    // path-free), so identical keys just make the scenario literally the same on both.
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let port_chirho = TestSegmentContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:mem-derive-diff-chirho");

    let fs_storage_chirho = FsSegmentStorageChirho;
    let mem_storage_chirho = MemSegmentStorageChirho::new_chirho();
    let (fs_cold_chirho, fs_warm_chirho) = run_derive_scenario_chirho(
        &fs_storage_chirho,
        &paths_chirho,
        &port_chirho,
        &identity_chirho,
    );
    let (mem_cold_chirho, mem_warm_chirho) = run_derive_scenario_chirho(
        &mem_storage_chirho,
        &paths_chirho,
        &port_chirho,
        &identity_chirho,
    );

    // Each backend is internally consistent: the warm O(1) head path agrees with the cold verify.
    assert_eq!(fs_cold_chirho, fs_warm_chirho);
    assert_eq!(mem_cold_chirho, mem_warm_chirho);
    // THE differential: base-seq derivation is byte-identical over fs and mem, cold AND warm.
    assert_eq!(
        fs_cold_chirho, mem_cold_chirho,
        "cold derive must be identical fs≡mem"
    );
    assert_eq!(
        fs_warm_chirho, mem_warm_chirho,
        "warm derive must be identical fs≡mem"
    );
    // …and the derived facts are exactly what the two sealed segments imply: base = 3 + 2 = 5.
    assert_eq!(mem_cold_chirho.base_seq_chirho, 5);
    assert_eq!(mem_cold_chirho.sealed_segment_count_chirho, 2);
    assert!(mem_cold_chirho.last_entry_digest_chirho.is_some());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_seals_identical_segment_and_manifest_fs_and_mem_chirho() {
    // Rotation DIFFERENTIAL, scoped to the SEGMENT-ARTIFACT writes (deviation #4). `rotate_segment_
    // chirho` reads the active file TWICE: once via `recover_jsonl_len_unlocked_chirho` — the torn-tail
    // REPAIR, deliberately still on the real filesystem — and once via the storage trait. So BOTH
    // backends are given the same real active file on disk (for the repair read); the mem backend ALSO
    // holds the active bytes in its map (for the trait read). What we assert is identical: the sealed
    // segment artifact and the appended signed manifest line, which is all that rotation writes through
    // storage. The active-file fs coupling is the expected, ruled deviation-#4 boundary.
    let active_records_chirho = active_bytes_for_records_chirho(0, 3);
    let expected_digest_chirho = blake3::hash(&active_records_chirho).to_hex().to_string();
    let port_chirho = TestSegmentContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:mem-rotate-diff-chirho");

    // fs backend: its own real root; rotation writes real sealed/manifest files there.
    let fs_root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&fs_root_chirho).unwrap();
    let fs_active_chirho = fs_root_chirho.join("rotate-diff-chirho.jsonl");
    let fs_paths_chirho = SegmentPathsChirho::new_chirho(fs_active_chirho.to_str().unwrap());
    std::fs::write(&fs_active_chirho, &active_records_chirho).unwrap();
    let fs_storage_chirho = FsSegmentStorageChirho;

    // mem backend: rotation is now PORT-CLEAN (deviation #4 fixed — it counts + seals the active
    // through the storage port, never the filesystem), so the mem backend needs NO real active FILE:
    // the active read, the sealed segment, and the manifest ALL go through the in-memory store. This is
    // the proof the fs coupling is gone — the whole seal path is sim-fault-injectable. (The root dir
    // still exists only to host the append lock.)
    let mem_root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&mem_root_chirho).unwrap();
    let mem_active_chirho = mem_root_chirho.join("rotate-diff-chirho.jsonl");
    let mem_paths_chirho = SegmentPathsChirho::new_chirho(mem_active_chirho.to_str().unwrap());
    let mem_storage_chirho = MemSegmentStorageChirho::new_chirho();
    mem_storage_chirho
        .write_durable_chirho(&mem_paths_chirho.active_chirho(), &active_records_chirho)
        .unwrap();

    // Rotate each backend under its own append lock (mirrors the seqlog rotation tests).
    let fs_outcome_chirho = with_append_log_lock_chirho(&fs_root_chirho, || {
        rotate_segment_chirho(
            &fs_storage_chirho,
            &port_chirho,
            &fs_paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    let mem_outcome_chirho = with_append_log_lock_chirho(&mem_root_chirho, || {
        rotate_segment_chirho(
            &mem_storage_chirho,
            &port_chirho,
            &mem_paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();

    // Same outcome: one segment sealed, generation 0, seq 0..2.
    assert_eq!(
        fs_outcome_chirho,
        RotationOutcomeChirho::Rotated {
            generation_chirho: 0,
            first_seq_chirho: 0,
            last_seq_chirho: 2,
        }
    );
    assert_eq!(fs_outcome_chirho, mem_outcome_chirho);

    // The sealed segment artifact is byte-identical (content-addressed) in both stores.
    let fs_sealed_chirho = fs_storage_chirho
        .read_all_chirho(&fs_paths_chirho.sealed_segment_chirho(&expected_digest_chirho))
        .unwrap();
    let mem_sealed_chirho = mem_storage_chirho
        .read_all_chirho(&mem_paths_chirho.sealed_segment_chirho(&expected_digest_chirho))
        .unwrap();
    assert_eq!(
        fs_sealed_chirho.as_deref(),
        Some(active_records_chirho.as_slice())
    );
    assert_eq!(
        fs_sealed_chirho, mem_sealed_chirho,
        "sealed segment bytes must be identical fs≡mem"
    );

    // The appended signed manifest line is identical (path-free entry → same canonical bytes → same
    // signature), and binds exactly the sealed content digest.
    let fs_lines_chirho = load_manifest_lines_chirho(&fs_storage_chirho, &fs_paths_chirho).unwrap();
    let mem_lines_chirho =
        load_manifest_lines_chirho(&mem_storage_chirho, &mem_paths_chirho).unwrap();
    assert_eq!(fs_lines_chirho.len(), 1);
    assert_eq!(
        fs_lines_chirho, mem_lines_chirho,
        "appended manifest line must be identical fs≡mem"
    );
    assert_eq!(
        fs_lines_chirho[0].entry_chirho.segment_digest_chirho,
        expected_digest_chirho
    );
    assert_eq!(fs_lines_chirho[0].entry_chirho.generation_chirho, 0);

    // The active file within each STORE is reset to empty by the rotation (its trait-routed cut C).
    assert_eq!(
        mem_storage_chirho
            .read_all_chirho(&mem_paths_chirho.active_chirho())
            .unwrap()
            .as_deref(),
        Some(b"".as_slice())
    );

    let _ = std::fs::remove_dir_all(&fs_root_chirho);
    let _ = std::fs::remove_dir_all(&mem_root_chirho);
}
