// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Serializes signed JSONL appends so each log assigns `seq_chirho` under one store-wide lock.

use crate::seqlog_head_chirho::{reseed_seqlog_head_chirho, try_seqlog_head_fast_path_chirho};
use anyhow::{anyhow, Context, Result};
use cairn_durable_chirho::log_path_chirho::{
    classify_log_path_chirho, open_existing_log_for_write_chirho, open_log_no_follow_chirho,
    LogPathChirho,
};
use cairn_durable_chirho::{append_durable_line_chirho, write_file_durable_chirho};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{hash_map::RandomState, HashMap};
use std::hash::BuildHasher;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// Process-local exclusion is sharded for expected O(1) lookup and keeps only weak entries. The final
/// holder/waiter removes its exact entry, so memory follows concurrent lock use instead of historical
/// roots. The durable zero-byte lock files intentionally remain until whole-root offline retirement:
/// unlinking one while another process holds its inode could split cross-process exclusion.
const LOCAL_LOCK_SHARD_COUNT_CHIRHO: usize = 64;
const LOCAL_LOCK_IDLE_CAPACITY_PER_SHARD_CHIRHO: usize = 64;

type LocalLockMapChirho = HashMap<PathBuf, Weak<LocalPathLockEntryChirho>>;

struct LocalPathLockEntryChirho {
    registry_chirho: Weak<LocalLockRegistryChirho>,
    path_chirho: PathBuf,
    shard_index_chirho: usize,
    lock_chirho: Mutex<()>,
}

impl Drop for LocalPathLockEntryChirho {
    fn drop(&mut self) {
        let Some(registry_chirho) = self.registry_chirho.upgrade() else {
            return;
        };
        registry_chirho.remove_if_current_chirho(self);
    }
}

struct LocalLockRegistryChirho {
    shard_hasher_chirho: RandomState,
    shards_chirho: [Mutex<LocalLockMapChirho>; LOCAL_LOCK_SHARD_COUNT_CHIRHO],
}

impl LocalLockRegistryChirho {
    fn new_chirho() -> Self {
        Self {
            shard_hasher_chirho: RandomState::new(),
            shards_chirho: std::array::from_fn(|_shard_index_chirho| Mutex::new(HashMap::new())),
        }
    }

    fn shard_index_chirho(&self, path_chirho: &Path) -> usize {
        (self.shard_hasher_chirho.hash_one(path_chirho) as usize) % LOCAL_LOCK_SHARD_COUNT_CHIRHO
    }

    fn lock_for_path_chirho(
        self: &Arc<Self>,
        path_chirho: &Path,
    ) -> Result<Arc<LocalPathLockEntryChirho>> {
        let shard_index_chirho = self.shard_index_chirho(path_chirho);
        let mut locks_chirho = self.shards_chirho[shard_index_chirho]
            .lock()
            .map_err(|_| anyhow!("seqlog local lock shard {shard_index_chirho} poisoned"))?;
        if let Some(entry_chirho) = locks_chirho.get(path_chirho).and_then(Weak::upgrade) {
            return Ok(entry_chirho);
        }

        let entry_chirho = Arc::new(LocalPathLockEntryChirho {
            registry_chirho: Arc::downgrade(self),
            path_chirho: path_chirho.to_path_buf(),
            shard_index_chirho,
            lock_chirho: Mutex::new(()),
        });
        locks_chirho.insert(path_chirho.to_path_buf(), Arc::downgrade(&entry_chirho));
        Ok(entry_chirho)
    }

    fn remove_if_current_chirho(&self, entry_chirho: &LocalPathLockEntryChirho) {
        let Ok(mut locks_chirho) = self.shards_chirho[entry_chirho.shard_index_chirho].lock()
        else {
            return;
        };
        let current_chirho = locks_chirho
            .get(&entry_chirho.path_chirho)
            .is_some_and(|current_chirho| std::ptr::eq(current_chirho.as_ptr(), entry_chirho));
        if !current_chirho {
            return;
        }

        locks_chirho.remove(&entry_chirho.path_chirho);
        if locks_chirho.is_empty()
            && locks_chirho.capacity() > LOCAL_LOCK_IDLE_CAPACITY_PER_SHARD_CHIRHO
        {
            *locks_chirho = HashMap::new();
        }
    }

    #[cfg(test)]
    fn weak_for_path_chirho(&self, path_chirho: &Path) -> Option<Weak<LocalPathLockEntryChirho>> {
        let shard_index_chirho = self.shard_index_chirho(path_chirho);
        self.shards_chirho[shard_index_chirho]
            .lock()
            .ok()
            .and_then(|locks_chirho| locks_chirho.get(path_chirho).cloned())
    }

    #[cfg(test)]
    fn shard_shape_chirho(&self, shard_index_chirho: usize) -> (usize, usize) {
        let locks_chirho = self.shards_chirho[shard_index_chirho]
            .lock()
            .expect("local lock test shard must not be poisoned");
        (locks_chirho.len(), locks_chirho.capacity())
    }
}

pub const SEQLOG_SCAN_REPORT_SCHEMA_CHIRHO: &str = "seqlog-scan-report-v1-chirho";
pub const SEQLOG_QUARANTINE_DIR_CHIRHO: &str = "seqlog-quarantine-chirho";

static LOCAL_LOCKS_CHIRHO: OnceLock<Arc<LocalLockRegistryChirho>> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlogScanReportChirho {
    pub schema_chirho: String,
    pub scanned_surfaces_chirho: usize,
    pub total_surfaces_chirho: usize,
    pub checked_records_chirho: u64,
    pub findings_chirho: Vec<SeqlogScanFindingChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlogScanFindingChirho {
    pub surface_chirho: String,
    pub kind_chirho: String,
    pub line_chirho: u64,
    pub byte_offset_chirho: u64,
    pub detail_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JsonlScanSummaryChirho {
    checked_records_chirho: u64,
    findings_chirho: Vec<SeqlogScanFindingChirho>,
}

fn local_lock_registry_chirho() -> &'static Arc<LocalLockRegistryChirho> {
    LOCAL_LOCKS_CHIRHO.get_or_init(|| Arc::new(LocalLockRegistryChirho::new_chirho()))
}

fn local_lock_for_path_chirho(path_chirho: &Path) -> Result<Arc<LocalPathLockEntryChirho>> {
    local_lock_registry_chirho().lock_for_path_chirho(path_chirho)
}

fn locks_dir_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("locks-chirho")
}

fn lock_path_in_dir_chirho(locks_dir_chirho: &Path, name_chirho: &str) -> PathBuf {
    locks_dir_chirho.join(named_lock_file_name_chirho(name_chirho))
}

fn named_lock_file_name_chirho(name_chirho: &str) -> String {
    let hash_chirho = blake3::hash(name_chirho.as_bytes()).to_hex().to_string();
    format!("{hash_chirho}.lock")
}

/// The fixed logical key used by descriptor-owned users of the same named-lock inode.
pub fn named_lock_storage_key_chirho(name_chirho: &str) -> String {
    format!("locks-chirho/{}", named_lock_file_name_chirho(name_chirho))
}

fn canonical_lock_path_chirho(root_chirho: &Path, name_chirho: &str) -> Result<PathBuf> {
    let locks_dir_chirho = locks_dir_chirho(root_chirho);
    std::fs::create_dir_all(&locks_dir_chirho)?;
    let canonical_locks_dir_chirho = std::fs::canonicalize(&locks_dir_chirho)
        .with_context(|| format!("canonicalize lock dir {}", locks_dir_chirho.display()))?;
    Ok(lock_path_in_dir_chirho(
        &canonical_locks_dir_chirho,
        name_chirho,
    ))
}

fn existing_canonical_lock_path_chirho(root_chirho: &Path, name_chirho: &str) -> Result<PathBuf> {
    let locks_dir_chirho = locks_dir_chirho(root_chirho);
    let locks_metadata_chirho = std::fs::symlink_metadata(&locks_dir_chirho)
        .with_context(|| format!("inspect existing lock dir {}", locks_dir_chirho.display()))?;
    if !locks_metadata_chirho.file_type().is_dir() || locks_metadata_chirho.file_type().is_symlink()
    {
        return Err(anyhow!(
            "existing named-lock directory is not a regular directory"
        ));
    }
    let canonical_locks_dir_chirho = std::fs::canonicalize(&locks_dir_chirho)
        .with_context(|| format!("canonicalize lock dir {}", locks_dir_chirho.display()))?;
    let lock_path_chirho = lock_path_in_dir_chirho(&canonical_locks_dir_chirho, name_chirho);
    let lock_metadata_chirho = std::fs::symlink_metadata(&lock_path_chirho)
        .with_context(|| format!("inspect existing lock {}", lock_path_chirho.display()))?;
    if !lock_metadata_chirho.file_type().is_file() || lock_metadata_chirho.file_type().is_symlink()
    {
        return Err(anyhow!("existing named lock is not a regular file"));
    }
    Ok(lock_path_chirho)
}

thread_local! {
    /// The named locks this thread holds through this funnel, innermost last: (canonical path, name).
    static HELD_NAMED_LOCKS_CHIRHO: RefCell<Vec<(PathBuf, String)>> = const { RefCell::new(Vec::new()) };
}

/// Nestings that would invert the root's lock order, as (held, then requested). Around account
/// attribution: `[subject-rights | append-log] -> account-attribution -> [blob-records | erasure-records]`.
/// And the control-plane law lock is outermost: it is never taken inside the writer-fence lock or the
/// append-log lock, because a write holds it from before its signature until its commit (C2.1 1b-1a). The erasure-propagation
/// store's lock is innermost: the erasure takes it inside the erasure-records lock (C5 B3-a2). Each is refused by name before the thread can block, so a deadlock that tests
/// would otherwise only hit by timing is a named error on the first run that takes the wrong order.
const FORBIDDEN_LOCK_NESTINGS_CHIRHO: &[(&str, &str)] = &[
    (
        "privacy-account-attribution-chirho",
        "privacy-subject-rights-chirho",
    ),
    ("privacy-account-attribution-chirho", "append-log-chirho"),
    (
        "privacy-blob-records-chirho",
        "privacy-account-attribution-chirho",
    ),
    (
        "privacy-erasure-records-chirho",
        "privacy-account-attribution-chirho",
    ),
    ("writer-fence-chirho", "control-plane-law-chirho"),
    ("append-log-chirho", "control-plane-law-chirho"),
    (
        "erasure-propagation-store-chirho",
        "privacy-erasure-records-chirho",
    ),
    (
        "erasure-propagation-store-chirho",
        "privacy-account-attribution-chirho",
    ),
    (
        "erasure-propagation-store-chirho",
        "privacy-subject-rights-chirho",
    ),
];

/// A named lock refused before blocking: re-entered on the same thread, which would otherwise deadlock on
/// the process-local mutex, or nested in a forbidden order on the same root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedLockOrderErrorChirho {
    pub held_chirho: String,
    pub requested_chirho: String,
    pub reentry_chirho: bool,
}

impl std::fmt::Display for NamedLockOrderErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter_chirho,
            "NamedLockOrderChirho: named lock '{}' requested while '{}' is held on this thread ({})",
            self.requested_chirho,
            self.held_chirho,
            if self.reentry_chirho {
                "re-entry would deadlock"
            } else {
                "this nesting inverts the lock order"
            }
        )
    }
}

impl std::error::Error for NamedLockOrderErrorChirho {}

fn refuse_named_lock_order_chirho(lock_path_chirho: &Path, name_chirho: &str) -> Result<()> {
    HELD_NAMED_LOCKS_CHIRHO.with(|held_chirho| {
        for (held_path_chirho, held_name_chirho) in held_chirho.borrow().iter() {
            let reentry_chirho = held_path_chirho == lock_path_chirho;
            let forbidden_chirho = held_path_chirho.parent() == lock_path_chirho.parent()
                && FORBIDDEN_LOCK_NESTINGS_CHIRHO
                    .contains(&(held_name_chirho.as_str(), name_chirho));
            if reentry_chirho || forbidden_chirho {
                return Err(anyhow::Error::new(NamedLockOrderErrorChirho {
                    held_chirho: held_name_chirho.clone(),
                    requested_chirho: name_chirho.to_string(),
                    reentry_chirho,
                }));
            }
        }
        Ok(())
    })
}

/// Records a held named lock for this thread and forgets it on drop, even when the action panics.
struct HeldNamedLockChirho;

impl HeldNamedLockChirho {
    fn enter_chirho(lock_path_chirho: &Path, name_chirho: &str) -> Self {
        HELD_NAMED_LOCKS_CHIRHO.with(|held_chirho| {
            held_chirho
                .borrow_mut()
                .push((lock_path_chirho.to_path_buf(), name_chirho.to_string()))
        });
        Self
    }
}

impl Drop for HeldNamedLockChirho {
    fn drop(&mut self) {
        HELD_NAMED_LOCKS_CHIRHO.with(|held_chirho| {
            held_chirho.borrow_mut().pop();
        });
    }
}

pub fn with_named_lock_chirho<T, F>(
    root_chirho: &Path,
    name_chirho: &str,
    action_chirho: F,
) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let lock_path_chirho = canonical_lock_path_chirho(root_chirho, name_chirho)?;
    refuse_named_lock_order_chirho(&lock_path_chirho, name_chirho)?;
    let local_lock_chirho = local_lock_for_path_chirho(&lock_path_chirho)?;
    let _local_guard_chirho = local_lock_chirho
        .lock_chirho
        .lock()
        .map_err(|_| anyhow!("seqlog local lock poisoned for {name_chirho}"))?;
    let lock_file_chirho = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path_chirho)
        .with_context(|| format!("open lock {}", lock_path_chirho.display()))?;
    lock_file_chirho
        .lock_exclusive()
        .with_context(|| format!("lock {}", lock_path_chirho.display()))?;
    let held_chirho = HeldNamedLockChirho::enter_chirho(&lock_path_chirho, name_chirho);
    let result_chirho = action_chirho();
    drop(held_chirho);
    let unlock_result_chirho = lock_file_chirho.unlock();
    match (result_chirho, unlock_result_chirho) {
        (Ok(value_chirho), Ok(())) => Ok(value_chirho),
        (Err(error_chirho), Ok(())) => Err(error_chirho),
        (Ok(_), Err(error_chirho)) => {
            Err(error_chirho).with_context(|| format!("unlock {}", lock_path_chirho.display()))
        }
        (Err(error_chirho), Err(unlock_error_chirho)) => Err(error_chirho).with_context(|| {
            format!(
                "also failed to unlock {}: {unlock_error_chirho}",
                lock_path_chirho.display()
            )
        }),
    }
}

/// Run a read-only inspection under an already-created named lock.
///
/// Unlike [`with_named_lock_chirho`], this path never creates the lock directory or lock file. It
/// fails closed when either artifact is absent or not regular, allowing immutable publication
/// verifiers to synchronize with writers without changing the inspected tree.
pub fn with_existing_named_read_lock_chirho<T, F>(
    root_chirho: &Path,
    name_chirho: &str,
    action_chirho: F,
) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let lock_path_chirho = existing_canonical_lock_path_chirho(root_chirho, name_chirho)?;
    refuse_named_lock_order_chirho(&lock_path_chirho, name_chirho)?;
    let local_lock_chirho = local_lock_for_path_chirho(&lock_path_chirho)?;
    let _local_guard_chirho = local_lock_chirho
        .lock_chirho
        .lock()
        .map_err(|_| anyhow!("seqlog local lock poisoned for {name_chirho}"))?;
    let lock_file_chirho = std::fs::OpenOptions::new()
        .read(true)
        .open(&lock_path_chirho)
        .with_context(|| format!("open existing lock {}", lock_path_chirho.display()))?;
    FileExt::lock_shared(&lock_file_chirho)
        .with_context(|| format!("read-lock {}", lock_path_chirho.display()))?;
    let held_chirho = HeldNamedLockChirho::enter_chirho(&lock_path_chirho, name_chirho);
    let result_chirho = action_chirho();
    drop(held_chirho);
    let unlock_result_chirho = FileExt::unlock(&lock_file_chirho);
    match (result_chirho, unlock_result_chirho) {
        (Ok(value_chirho), Ok(())) => Ok(value_chirho),
        (Err(error_chirho), Ok(())) => Err(error_chirho),
        (Ok(_), Err(error_chirho)) => {
            Err(error_chirho).with_context(|| format!("unlock {}", lock_path_chirho.display()))
        }
        (Err(error_chirho), Err(unlock_error_chirho)) => Err(error_chirho).with_context(|| {
            format!(
                "also failed to unlock {}: {unlock_error_chirho}",
                lock_path_chirho.display()
            )
        }),
    }
}

pub fn seqlog_quarantine_sidecar_paths_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    if !root_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    collect_seqlog_quarantine_sidecars_chirho(root_chirho, root_chirho, &mut paths_chirho)?;
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn collect_seqlog_quarantine_sidecars_chirho(
    root_chirho: &Path,
    dir_chirho: &Path,
    paths_chirho: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry_chirho in std::fs::read_dir(dir_chirho)
        .with_context(|| format!("read dir {}", dir_chirho.display()))?
    {
        let path_chirho = entry_chirho?.path();
        if !path_chirho.is_dir() {
            continue;
        }
        if seqlog_quarantine_skip_dir_chirho(root_chirho, &path_chirho) {
            continue;
        }
        if path_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
            == Some(SEQLOG_QUARANTINE_DIR_CHIRHO)
        {
            collect_regular_files_chirho(&path_chirho, paths_chirho)?;
            continue;
        }
        collect_seqlog_quarantine_sidecars_chirho(root_chirho, &path_chirho, paths_chirho)?;
    }
    Ok(())
}

fn seqlog_quarantine_skip_dir_chirho(root_chirho: &Path, path_chirho: &Path) -> bool {
    let relative_chirho = path_chirho.strip_prefix(root_chirho).unwrap_or(path_chirho);
    let first_chirho = relative_chirho
        .components()
        .next()
        .and_then(|component_chirho| component_chirho.as_os_str().to_str())
        .unwrap_or("");
    matches!(
        first_chirho,
        "identity-keys-chirho"
            | "locks-chirho"
            | "native-workers-chirho"
            | "objects-chirho"
            | "privacy-keys-chirho"
            | "writer-fences-chirho"
            | "gate1-authority-head-chirho"
    )
}

fn collect_regular_files_chirho(dir_chirho: &Path, paths_chirho: &mut Vec<PathBuf>) -> Result<()> {
    for entry_chirho in std::fs::read_dir(dir_chirho)
        .with_context(|| format!("read dir {}", dir_chirho.display()))?
    {
        let path_chirho = entry_chirho?.path();
        if path_chirho.is_dir() {
            collect_regular_files_chirho(&path_chirho, paths_chirho)?;
        } else if path_chirho.is_file() {
            paths_chirho.push(path_chirho);
        }
    }
    Ok(())
}

pub fn with_append_log_lock_chirho<T, F>(root_chirho: &Path, action_chirho: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    with_named_lock_chirho(root_chirho, "append-log-chirho", action_chirho)
}

pub fn append_serialized_jsonl_chirho<T, F>(
    root_chirho: &Path,
    path_chirho: &Path,
    prepare_chirho: F,
) -> Result<T>
where
    T: Serialize,
    F: FnOnce(u64) -> Result<T>,
{
    with_append_log_lock_chirho(root_chirho, || {
        append_serialized_jsonl_unlocked_chirho(path_chirho, prepare_chirho)
    })
}

pub fn append_serialized_jsonl_unlocked_chirho<T, F>(
    path_chirho: &Path,
    prepare_chirho: F,
) -> Result<T>
where
    T: Serialize,
    F: FnOnce(u64) -> Result<T>,
{
    let seq_chirho = recover_jsonl_len_unlocked_chirho(path_chirho)?;
    let record_chirho = prepare_chirho(seq_chirho)?;
    append_recovered_jsonl_unlocked_chirho(path_chirho, seq_chirho, &record_chirho)?;
    Ok(record_chirho)
}

/// Recover a JSONL log and return the next sequence while the caller already holds the store-wide
/// append lock. Use this before any typed loader reads the file, so a torn tail is repaired before
/// loader length drives a new `seq_chirho`.
pub fn recover_jsonl_len_unlocked_chirho(path_chirho: &Path) -> Result<u64> {
    recover_jsonl_len_chirho(path_chirho)
}

/// Append a JSONL record after a prior locked recovery call. Rechecking the recovered length keeps
/// callers from accidentally appending against a stale sequence after additional in-lock work.
///
/// This is the single funnel every serialized/recovered append passes through, so the O(1) head
/// checkpoint (F1) is re-seeded here — AFTER the line is durably appended and fsynced. The
/// checkpoint therefore only ever lags the durable tail; a crash before it lands is recovered by
/// the next `recover_jsonl_len_chirho` full rescan. `append_jsonl_unlocked_chirho` stays raw so
/// Gate 1, which maintains its own head, gains no stray sidecar.
pub fn append_recovered_jsonl_unlocked_chirho<T: Serialize>(
    path_chirho: &Path,
    expected_seq_chirho: u64,
    record_chirho: &T,
) -> Result<()> {
    let current_seq_chirho = recover_jsonl_len_chirho(path_chirho)?;
    if current_seq_chirho != expected_seq_chirho {
        return Err(anyhow!(
            "JSONL recovered sequence changed for {}: expected {}, current {}",
            path_chirho.display(),
            expected_seq_chirho,
            current_seq_chirho
        ));
    }
    append_jsonl_unlocked_chirho(path_chirho, record_chirho)?;
    // The line above is durably committed. The head checkpoint is ADVISORY (behind-never-ahead: a
    // missing/stale sidecar only costs the next recover one full rescan), so a reseed failure must
    // not turn the committed append into an Err — on an authority/money log a caller retrying "the
    // failed append" would double-emit. Self-heals on the next recover.
    let _ = reseed_seqlog_head_chirho(path_chirho, expected_seq_chirho + 1);
    Ok(())
}

/// Append one JSONL record WITHOUT taking the lock — the caller must already hold it (via
/// `with_append_log_lock_chirho` / `with_named_lock_chirho`). `pub` rather than `pub(crate)`
/// so the prototype crate can reach it now that this primitive lives in `cairn-seqlog-chirho`;
/// it is workspace-internal API, not an application surface.
pub fn append_jsonl_unlocked_chirho<T: Serialize>(
    path_chirho: &Path,
    record_chirho: &T,
) -> Result<()> {
    let line_chirho = format!("{}\n", serde_json::to_string(record_chirho)?);
    append_durable_line_chirho(path_chirho, line_chirho.as_bytes())
        .with_context(|| format!("append log {}", path_chirho.display()))?;
    Ok(())
}

pub fn scan_jsonl_manifest_chirho(
    root_chirho: &Path,
    surfaces_chirho: &[&str],
) -> Result<SeqlogScanReportChirho> {
    let mut report_chirho = SeqlogScanReportChirho {
        schema_chirho: SEQLOG_SCAN_REPORT_SCHEMA_CHIRHO.to_string(),
        scanned_surfaces_chirho: 0,
        total_surfaces_chirho: surfaces_chirho.len(),
        checked_records_chirho: 0,
        findings_chirho: Vec::new(),
    };
    for surface_chirho in surfaces_chirho {
        let path_chirho = root_chirho.join(surface_chirho);
        if !path_chirho.exists() {
            continue;
        }
        report_chirho.scanned_surfaces_chirho += 1;
        let summary_chirho = scan_jsonl_file_chirho(&path_chirho, surface_chirho)?;
        report_chirho.checked_records_chirho += summary_chirho.checked_records_chirho;
        report_chirho
            .findings_chirho
            .extend(summary_chirho.findings_chirho);
    }
    Ok(report_chirho)
}

fn scan_jsonl_file_chirho(
    path_chirho: &Path,
    surface_chirho: &str,
) -> Result<JsonlScanSummaryChirho> {
    if !path_chirho.exists() {
        return Ok(JsonlScanSummaryChirho {
            checked_records_chirho: 0,
            findings_chirho: Vec::new(),
        });
    }
    let bytes_chirho =
        std::fs::read(path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(scan_jsonl_bytes_chirho(&bytes_chirho, surface_chirho))
}

// F1 count-based scaling-guard hooks. Thread-local so parallel tests never pollute each other's
// counts; no-ops in production so the hot path pays nothing. They count whole-file work inside the
// full rescan, proving warm appends do zero full reads and per-append work is independent of length.
#[cfg(test)]
thread_local! {
    static RECOVER_PARSE_COUNT_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static RECOVER_FULL_READ_COUNT_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Count one line inspected by the full-file rescan parser.
#[cfg(test)]
fn note_recover_parse_chirho() {
    RECOVER_PARSE_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
}
#[cfg(not(test))]
#[inline(always)]
fn note_recover_parse_chirho() {}

/// Count one whole-file read performed by the full rescan.
#[cfg(test)]
fn note_recover_full_read_chirho() {
    RECOVER_FULL_READ_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
}
#[cfg(not(test))]
#[inline(always)]
fn note_recover_full_read_chirho() {}

#[cfg(test)]
fn reset_recover_counts_chirho() {
    RECOVER_PARSE_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(0));
    RECOVER_FULL_READ_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(0));
}

#[cfg(test)]
fn recover_parse_count_chirho() -> u64 {
    RECOVER_PARSE_COUNT_CHIRHO.with(|count_chirho| count_chirho.get())
}

#[cfg(test)]
fn recover_full_read_count_chirho() -> u64 {
    RECOVER_FULL_READ_COUNT_CHIRHO.with(|count_chirho| count_chirho.get())
}

/// Derive the next `seq_chirho` for a log. F1 fast path: when the durable `<log>.head-chirho`
/// checkpoint proves the tail is unchanged, return its record count in O(1). On any miss (missing,
/// torn, stale, ahead, or tail-mismatched checkpoint) fall through to the full rescan — retained
/// verbatim so torn-tail quarantine, malformed-middle fail-closed, and newline repair are unchanged
/// — and then re-seed the checkpoint from the post-repair state.
fn recover_jsonl_len_chirho(path_chirho: &Path) -> Result<u64> {
    // Only a genuine absence starts a log at zero; a log that cannot be examined refuses the append.
    if let LogPathChirho::AbsentChirho = classify_log_path_chirho(path_chirho)
        .with_context(|| format!("examine {} before appending", path_chirho.display()))?
    {
        return Ok(0);
    }
    if let Some(seq_chirho) = try_seqlog_head_fast_path_chirho(path_chirho)? {
        return Ok(seq_chirho);
    }
    let seq_chirho = recover_jsonl_len_full_scan_chirho(path_chirho)?;
    // Advisory in this direction too: the rescan above is the authority, so an unwritable sidecar
    // (ENOSPC/EISDIR/perms) degrades to O(n)-per-op — it must never fail reads or appends.
    let _ = reseed_seqlog_head_chirho(path_chirho, seq_chirho);
    Ok(seq_chirho)
}

/// The full-file recover scan, retained verbatim from the pre-checkpoint implementation: read the
/// whole log, count valid records, and repair a torn or newline-less tail. Reached only on a
/// checkpoint miss; `recover_jsonl_len_chirho` re-seeds the checkpoint afterward. The `note_recover_*`
/// calls are `#[cfg(test)]` counters (no-ops in production) that make the O(1) invariant executable.
fn recover_jsonl_len_full_scan_chirho(path_chirho: &Path) -> Result<u64> {
    let mut bytes_chirho = Vec::new();
    open_log_no_follow_chirho(path_chirho)
        .with_context(|| format!("open {} for recovery", path_chirho.display()))?
        .ok_or_else(|| anyhow!("{} disappeared during recovery", path_chirho.display()))?
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    note_recover_full_read_chirho();
    let mut line_start_chirho = 0usize;
    let mut valid_records_chirho = 0u64;

    while line_start_chirho < bytes_chirho.len() {
        note_recover_parse_chirho();
        let remaining_chirho = &bytes_chirho[line_start_chirho..];
        let newline_relative_chirho = remaining_chirho
            .iter()
            .position(|byte_chirho| *byte_chirho == b'\n');
        let (line_chirho, next_start_chirho, has_newline_chirho) =
            if let Some(newline_relative_chirho) = newline_relative_chirho {
                let newline_index_chirho = line_start_chirho + newline_relative_chirho;
                (
                    &bytes_chirho[line_start_chirho..newline_index_chirho],
                    newline_index_chirho + 1,
                    true,
                )
            } else {
                (remaining_chirho, bytes_chirho.len(), false)
            };

        let trimmed_chirho = trim_ascii_whitespace_chirho(line_chirho);
        if !trimmed_chirho.is_empty() {
            if serde_json::from_slice::<serde_json::Value>(trimmed_chirho).is_err() {
                if has_following_json_record_chirho(&bytes_chirho[next_start_chirho..]) {
                    return Err(anyhow!(
                        "malformed non-tail JSONL row in {}; refusing to truncate later valid records",
                        path_chirho.display()
                    ));
                }
                let removed_bytes_chirho = &bytes_chirho[line_start_chirho..];
                truncate_jsonl_to_chirho(
                    path_chirho,
                    line_start_chirho as u64,
                    removed_bytes_chirho,
                )?;
                return Ok(valid_records_chirho);
            }
            valid_records_chirho += 1;
        }

        if !has_newline_chirho {
            append_missing_jsonl_newline_chirho(path_chirho)?;
        }
        line_start_chirho = next_start_chirho;
    }

    Ok(valid_records_chirho)
}

fn scan_jsonl_bytes_chirho(bytes_chirho: &[u8], surface_chirho: &str) -> JsonlScanSummaryChirho {
    let mut line_start_chirho = 0usize;
    let mut line_number_chirho = 1u64;
    let mut checked_records_chirho = 0u64;
    let mut findings_chirho = Vec::new();

    while line_start_chirho < bytes_chirho.len() {
        let remaining_chirho = &bytes_chirho[line_start_chirho..];
        let newline_relative_chirho = remaining_chirho
            .iter()
            .position(|byte_chirho| *byte_chirho == b'\n');
        let (line_chirho, next_start_chirho, has_newline_chirho) =
            if let Some(newline_relative_chirho) = newline_relative_chirho {
                let newline_index_chirho = line_start_chirho + newline_relative_chirho;
                (
                    &bytes_chirho[line_start_chirho..newline_index_chirho],
                    newline_index_chirho + 1,
                    true,
                )
            } else {
                (remaining_chirho, bytes_chirho.len(), false)
            };

        let trimmed_chirho = trim_ascii_whitespace_chirho(line_chirho);
        if !trimmed_chirho.is_empty() {
            if serde_json::from_slice::<serde_json::Value>(trimmed_chirho).is_ok() {
                checked_records_chirho += 1;
            } else {
                let kind_chirho =
                    if has_following_json_record_chirho(&bytes_chirho[next_start_chirho..]) {
                        "malformed-middle-chirho"
                    } else if has_newline_chirho {
                        "malformed-tail-chirho"
                    } else {
                        "torn-tail-chirho"
                    };
                findings_chirho.push(SeqlogScanFindingChirho {
                    surface_chirho: surface_chirho.to_string(),
                    kind_chirho: kind_chirho.to_string(),
                    line_chirho: line_number_chirho,
                    byte_offset_chirho: line_start_chirho as u64,
                    detail_chirho: if kind_chirho == "malformed-middle-chirho" {
                        "malformed JSONL row has a later valid JSON row; recovery must not truncate"
                            .to_string()
                    } else {
                        "malformed JSONL suffix would be quarantined before recovery truncation"
                            .to_string()
                    },
                });
            }
        }

        line_start_chirho = next_start_chirho;
        line_number_chirho += 1;
    }

    JsonlScanSummaryChirho {
        checked_records_chirho,
        findings_chirho,
    }
}

fn has_following_json_record_chirho(bytes_chirho: &[u8]) -> bool {
    bytes_chirho
        .split(|byte_chirho| *byte_chirho == b'\n')
        .filter_map(|line_chirho| {
            let trimmed_chirho = trim_ascii_whitespace_chirho(line_chirho);
            (!trimmed_chirho.is_empty()).then_some(trimmed_chirho)
        })
        .any(|trimmed_chirho| serde_json::from_slice::<serde_json::Value>(trimmed_chirho).is_ok())
}

fn trim_ascii_whitespace_chirho(bytes_chirho: &[u8]) -> &[u8] {
    let mut start_chirho = 0usize;
    let mut end_chirho = bytes_chirho.len();
    while start_chirho < end_chirho && bytes_chirho[start_chirho].is_ascii_whitespace() {
        start_chirho += 1;
    }
    while end_chirho > start_chirho && bytes_chirho[end_chirho - 1].is_ascii_whitespace() {
        end_chirho -= 1;
    }
    &bytes_chirho[start_chirho..end_chirho]
}

fn truncate_jsonl_to_chirho(
    path_chirho: &Path,
    len_chirho: u64,
    removed_chirho: &[u8],
) -> Result<()> {
    quarantine_removed_jsonl_bytes_chirho(path_chirho, removed_chirho)?;
    let file_chirho = open_existing_log_for_write_chirho(path_chirho, false)
        .with_context(|| format!("open {} for recovery truncation", path_chirho.display()))?;
    file_chirho
        .set_len(len_chirho)
        .with_context(|| format!("truncate {} to valid JSONL prefix", path_chirho.display()))?;
    file_chirho
        .sync_all()
        .with_context(|| format!("sync recovered {}", path_chirho.display()))?;
    Ok(())
}

fn quarantine_removed_jsonl_bytes_chirho(path_chirho: &Path, removed_chirho: &[u8]) -> Result<()> {
    let quarantine_path_chirho =
        quarantine_path_for_removed_bytes_chirho(path_chirho, removed_chirho)?;
    write_file_durable_chirho(&quarantine_path_chirho, removed_chirho).with_context(|| {
        format!(
            "write seqlog recovery quarantine {}",
            quarantine_path_chirho.display()
        )
    })
}

fn quarantine_path_for_removed_bytes_chirho(
    path_chirho: &Path,
    removed_chirho: &[u8],
) -> Result<PathBuf> {
    let parent_chirho = path_chirho.parent().ok_or_else(|| {
        anyhow!(
            "seqlog path has no parent for quarantine: {}",
            path_chirho.display()
        )
    })?;
    let hash_chirho = blake3::hash(removed_chirho).to_hex().to_string();
    Ok(parent_chirho
        .join(SEQLOG_QUARANTINE_DIR_CHIRHO)
        .join(format!("{hash_chirho}.jsonl-fragment-chirho")))
}

fn append_missing_jsonl_newline_chirho(path_chirho: &Path) -> Result<()> {
    let mut file_chirho = open_existing_log_for_write_chirho(path_chirho, true)
        .with_context(|| format!("open {} for JSONL newline repair", path_chirho.display()))?;
    file_chirho
        .write_all(b"\n")
        .with_context(|| format!("repair JSONL newline {}", path_chirho.display()))?;
    file_chirho
        .sync_all()
        .with_context(|| format!("sync newline-repaired {}", path_chirho.display()))?;
    Ok(())
}

#[cfg(test)]
mod lock_registry_tests_chirho;

#[cfg(test)]
mod tests_chirho;

#[cfg(test)]
mod log_fault_tests_chirho;

#[cfg(test)]
mod lock_order_tests_chirho;
