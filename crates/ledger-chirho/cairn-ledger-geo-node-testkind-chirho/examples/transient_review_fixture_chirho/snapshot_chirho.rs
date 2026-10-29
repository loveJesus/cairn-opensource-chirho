// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Hashes a bounded complete descriptor-owned platform tree without emitting private paths or bytes.

use anyhow::{ensure, Result};
use serde::Serialize;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) const SENTINEL_CHIRHO: &[u8] = b"\0transient-fixture-sentinel-chirho\xff";
pub(super) const SENTINEL_PATH_CHIRHO: &str = "snapshot-sentinel-chirho";
const MAX_ENTRIES_CHIRHO: u64 = 16_384;
const MAX_BYTES_CHIRHO: u64 = 256 * 1024 * 1024;

#[derive(Serialize, PartialEq, Eq)]
pub(super) struct SnapshotChirho {
    pub(super) digest_chirho: String,
    pub(super) entries_chirho: u64,
    pub(super) bytes_chirho: u64,
    pub(super) sentinel_seen_chirho: bool,
    pub(super) unreadable_entries_chirho: u64,
}

fn field_chirho(hash_chirho: &mut blake3::Hasher, bytes_chirho: &[u8]) {
    hash_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
    hash_chirho.update(bytes_chirho);
}

pub(super) fn snapshot_chirho(root_chirho: &Path) -> Result<SnapshotChirho> {
    let mut hash_chirho = blake3::Hasher::new_derive_key("transient-review-tree-v1-chirho");
    let mut snapshot_chirho = SnapshotChirho {
        digest_chirho: String::new(),
        entries_chirho: 0,
        bytes_chirho: 0,
        sentinel_seen_chirho: false,
        unreadable_entries_chirho: 0,
    };
    walk_chirho(
        root_chirho,
        root_chirho,
        0,
        &mut hash_chirho,
        &mut snapshot_chirho,
    )?;
    ensure!(
        snapshot_chirho.sentinel_seen_chirho,
        "snapshot sentinel missing"
    );
    snapshot_chirho.digest_chirho = hash_chirho.finalize().to_hex().to_string();
    Ok(snapshot_chirho)
}

fn walk_chirho(
    root_chirho: &Path,
    path_chirho: &Path,
    depth_chirho: usize,
    hash_chirho: &mut blake3::Hasher,
    snapshot_chirho: &mut SnapshotChirho,
) -> Result<()> {
    ensure!(
        depth_chirho <= 24 && snapshot_chirho.entries_chirho < MAX_ENTRIES_CHIRHO,
        "snapshot bound"
    );
    // The initial "." is the retained platform descriptor via fchdir, not a tree symlink.
    let meta_chirho = if depth_chirho == 0 {
        std::fs::metadata(path_chirho)?
    } else {
        std::fs::symlink_metadata(path_chirho)?
    };
    let relative_chirho = path_chirho.strip_prefix(root_chirho)?;
    field_chirho(hash_chirho, relative_chirho.as_os_str().as_bytes());
    field_chirho(hash_chirho, &(meta_chirho.mode() & 0o7777).to_le_bytes());
    snapshot_chirho.entries_chirho += 1;
    if meta_chirho.is_dir() {
        field_chirho(hash_chirho, b"directory-chirho");
        let mut entries_chirho = std::fs::read_dir(path_chirho)?
            .take(MAX_ENTRIES_CHIRHO as usize + 1)
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(
            entries_chirho.len() <= MAX_ENTRIES_CHIRHO as usize,
            "snapshot directory bound"
        );
        entries_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
        for entry_chirho in entries_chirho {
            walk_chirho(
                root_chirho,
                &entry_chirho.path(),
                depth_chirho + 1,
                hash_chirho,
                snapshot_chirho,
            )?;
        }
    } else if meta_chirho.is_file() {
        field_chirho(hash_chirho, b"file-chirho");
        ensure!(
            meta_chirho.len() <= 64 * 1024 * 1024
                && snapshot_chirho.bytes_chirho + meta_chirho.len() <= MAX_BYTES_CHIRHO,
            "snapshot bytes bound"
        );
        let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
            path_chirho,
            64 * 1024 * 1024,
        )?;
        snapshot_chirho.bytes_chirho += bytes_chirho.len() as u64;
        if relative_chirho == Path::new(SENTINEL_PATH_CHIRHO) {
            ensure!(bytes_chirho == SENTINEL_CHIRHO, "snapshot sentinel changed");
            snapshot_chirho.sentinel_seen_chirho = true;
        }
        field_chirho(hash_chirho, &bytes_chirho);
    } else if meta_chirho.file_type().is_symlink() {
        field_chirho(hash_chirho, b"symlink-chirho");
        let target_chirho = std::fs::read_link(path_chirho)?;
        ensure!(
            target_chirho.as_os_str().len() <= 4096,
            "snapshot link bound"
        );
        field_chirho(hash_chirho, target_chirho.as_os_str().as_bytes());
    } else {
        anyhow::bail!("snapshot file type");
    }
    let after_chirho = if depth_chirho == 0 {
        std::fs::metadata(path_chirho)?
    } else {
        std::fs::symlink_metadata(path_chirho)?
    };
    ensure!(
        meta_chirho.dev() == after_chirho.dev()
            && meta_chirho.ino() == after_chirho.ino()
            && meta_chirho.len() == after_chirho.len()
            && meta_chirho.modified()? == after_chirho.modified()?
            && meta_chirho.mode() == after_chirho.mode(),
        "snapshot entry changed while reading"
    );
    Ok(())
}
