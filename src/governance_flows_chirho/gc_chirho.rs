// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! GC — conservative mark-and-sweep over the content-addressed object store.
//!
//! Roots: refs, runtime records, and signed JSONL logs. Marking is **conservative**: an
//! object's bytes are scanned for 64-char blake3-hex tokens, each treated as a reference and
//! followed. This may over-approximate (keep a little garbage) but never collects something
//! reachable. Sweep deletes any object in `objects-chirho/` that was not marked.

use crate::model_chirho::HashChirho;
// Moved to the core crate: it is an object-graph primitive, not a collection concern.
// Re-exported so this module's own callers and any external one keep a stable path.
use crate::{cas_chirho, refs_chirho, seqlog_chirho};
use anyhow::{Context, Result};
pub use cairn_core_chirho::object_graph_chirho::scan_hashes_chirho;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const RUNTIME_RECORD_DIRS_CHIRHO: &[&str] = &[
    "runs-chirho",
    "effects-chirho",
    "runkeys-chirho",
    "runseals-chirho",
];

/// What a GC pass did.
#[derive(Debug)]
pub struct GcReportChirho {
    pub kept_chirho: usize,
    pub collected_chirho: usize,
}

/// The refusal every mark-phase failure carries. Named so a caller and a test can identify WHY the
/// pass refused, rather than matching on some incidental I/O string.
pub const GC_MARK_REFUSAL_CHIRHO: &str =
    "gc refuses to sweep: the mark phase could not be completed";

/// Mark from the roots, then sweep `objects-chirho/`.
///
/// **FAIL-CLOSED: a mark-phase read error refuses the whole pass rather than sweeping.** Marking
/// decides what stays alive, so anything that shrinks the marked set shrinks it toward DELETION. If a
/// root surface or a stored object cannot be read, the honest answer is "I do not know what is
/// reachable" — and the only safe action then is to collect nothing.
///
/// **Absence is fine; failure is fatal.** The scanner is deliberately conservative and produces
/// 64-hex tokens that resolve to no stored object; those are `NotFound` and stay exactly as before —
/// marked, retaining nothing, not an error. What refuses: I/O failure reading enumerated root
/// material, and any non-`NotFound` failure from the CAS getter, which includes `InvalidData` from a
/// content-address mismatch. A corrupt object that silently stopped marking its children is precisely
/// the case this closes.
pub fn gc_chirho(root_chirho: &Path) -> Result<GcReportChirho> {
    let mut marked_chirho: HashSet<HashChirho> = HashSet::new();

    // Roots: ref values (branches + tags).
    let refs_val_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    for hash_chirho in refs_val_chirho
        .branches_chirho
        .values()
        .chain(refs_val_chirho.tags_chirho.values())
    {
        mark_chirho(root_chirho, hash_chirho, &mut marked_chirho)?;
    }

    // Roots: runtime files and signed logs (objects they reference are kept).
    for dir_chirho in RUNTIME_RECORD_DIRS_CHIRHO {
        mark_dir_blobs_chirho(
            &root_chirho.join(dir_chirho),
            root_chirho,
            &mut marked_chirho,
        )?;
    }
    for path_chirho in root_jsonl_and_quarantine_paths_chirho(root_chirho)? {
        // Intentional raw inventory read: signed logs are scanned as root material, while
        // content-addressed objects reached from them are loaded through the verifying CAS getter.
        // This path came from enumeration, so it exists; a read failure here is real and refuses.
        let bytes_chirho = fs::read(&path_chirho).with_context(|| {
            format!(
                "{GC_MARK_REFUSAL_CHIRHO}: root log {}",
                path_chirho.display()
            )
        })?;
        for child_chirho in scan_hashes_chirho(&bytes_chirho) {
            mark_chirho(root_chirho, &child_chirho, &mut marked_chirho)?;
        }
    }

    sweep_chirho(root_chirho, &marked_chirho)
}

/// Scan every file directly under `dir` (a flat blob dir) for hash references and mark them.
///
/// A MISSING dir is absence and is fine — not every root has every runtime-record dir. Any other
/// failure to enumerate or read is fatal, because the entries were listed and then could not be read.
fn mark_dir_blobs_chirho(
    dir_chirho: &Path,
    root_chirho: &Path,
    marked_chirho: &mut HashSet<HashChirho>,
) -> Result<()> {
    let entries_chirho = match fs::read_dir(dir_chirho) {
        Ok(entries_chirho) => entries_chirho,
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error_chirho) => {
            return Err(anyhow::Error::new(error_chirho).context(format!(
                "{GC_MARK_REFUSAL_CHIRHO}: runtime record dir {}",
                dir_chirho.display()
            )));
        }
    };
    for entry_chirho in entries_chirho {
        let entry_chirho = entry_chirho.with_context(|| {
            format!(
                "{GC_MARK_REFUSAL_CHIRHO}: runtime record entry under {}",
                dir_chirho.display()
            )
        })?;
        // Intentional raw inventory read: runtime records are roots, not requested CAS objects.
        let bytes_chirho = fs::read(entry_chirho.path()).with_context(|| {
            format!(
                "{GC_MARK_REFUSAL_CHIRHO}: runtime record {}",
                entry_chirho.path().display()
            )
        })?;
        for child_chirho in scan_hashes_chirho(&bytes_chirho) {
            mark_chirho(root_chirho, &child_chirho, marked_chirho)?;
        }
    }
    Ok(())
}

fn root_jsonl_and_quarantine_paths_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    let mut paths_chirho = root_jsonl_paths_chirho(root_chirho)?;
    paths_chirho.extend(root_seqlog_quarantine_paths_chirho(root_chirho)?);
    paths_chirho.sort();
    paths_chirho.dedup();
    Ok(paths_chirho)
}

fn root_jsonl_paths_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    if !root_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    collect_jsonl_paths_chirho(root_chirho, root_chirho, &mut paths_chirho)?;
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn collect_jsonl_paths_chirho(
    root_chirho: &Path,
    dir_chirho: &Path,
    paths_chirho: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry_chirho in fs::read_dir(dir_chirho)? {
        let path_chirho = entry_chirho?.path();
        if path_chirho.is_dir() {
            if gc_skip_dir_chirho(root_chirho, &path_chirho) {
                continue;
            }
            collect_jsonl_paths_chirho(root_chirho, &path_chirho, paths_chirho)?;
            continue;
        }
        if path_chirho
            .extension()
            .and_then(|ext_chirho| ext_chirho.to_str())
            == Some("jsonl")
        {
            paths_chirho.push(path_chirho);
        }
    }
    Ok(())
}

fn root_seqlog_quarantine_paths_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    seqlog_chirho::seqlog_quarantine_sidecar_paths_chirho(root_chirho)
}

fn gc_skip_dir_chirho(root_chirho: &Path, path_chirho: &Path) -> bool {
    let relative_chirho = path_chirho.strip_prefix(root_chirho).unwrap_or(path_chirho);
    let first_chirho = relative_chirho
        .components()
        .next()
        .and_then(|component_chirho| component_chirho.as_os_str().to_str())
        .unwrap_or("");
    matches!(
        first_chirho,
        "locks-chirho"
            | "native-workers-chirho"
            | "objects-chirho"
            | "privacy-keys-chirho"
            | "identity-keys-chirho"
            | "writer-fences-chirho"
            | "gate1-authority-head-chirho"
    )
}
/// Mark a hash reachable; if it is a stored object, recurse into the hashes it references.
///
/// **`AbsentChirho` is ABSENCE and is fine.** The scanner is conservative: it yields 64-hex tokens
/// that are not stored objects at all, and those simply retain nothing. **Every other outcome is
/// FAILURE and refuses the pass** — `TamperedChirho`, because an object that fails verification
/// would otherwise stop marking its children while they stay live, and `UnreadableChirho`, because
/// a read that could not happen says nothing about whether children are still reachable.
fn mark_chirho(
    root_chirho: &Path,
    hash_chirho: &HashChirho,
    marked_chirho: &mut HashSet<HashChirho>,
) -> Result<()> {
    if !marked_chirho.insert(hash_chirho.clone()) {
        return Ok(());
    }
    // The four outcomes are read from `read_verified_chirho` rather than inferred from an error
    // KIND. Keying the pass on `NotFound` was CORRECT — the collapsing getter does return the
    // original error, so absence really did arrive as `NotFound` — but it was correct by an
    // invariant nothing stated and no check enforced, which is the shape being removed rather than
    // a behaviour being fixed. Refusals here are unchanged; only genuine absence retains nothing.
    let bytes_chirho = match cas_chirho::read_verified_chirho(root_chirho, hash_chirho) {
        cas_chirho::CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => bytes_chirho,
        // Absence: a scanner false positive, or a token that was never a stored object.
        cas_chirho::CasReadOutcomeChirho::AbsentChirho(_absent_chirho) => return Ok(()),
        cas_chirho::CasReadOutcomeChirho::TamperedChirho { actual_chirho, .. } => {
            return Err(anyhow::Error::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "content address mismatch: requested {}, actual {}",
                    hash_chirho.0, actual_chirho.0
                ),
            ))
            .context(format!(
                "{GC_MARK_REFUSAL_CHIRHO}: stored object {}",
                hash_chirho.0
            )));
        }
        cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => {
            return Err(anyhow::Error::new(error_chirho).context(format!(
                "{GC_MARK_REFUSAL_CHIRHO}: stored object {}",
                hash_chirho.0
            )));
        }
    };
    for child_chirho in scan_hashes_chirho(&bytes_chirho) {
        mark_chirho(root_chirho, &child_chirho, marked_chirho)?;
    }
    Ok(())
}

/// Delete every object not in `marked`; count kept vs collected.
fn sweep_chirho(root_chirho: &Path, marked_chirho: &HashSet<HashChirho>) -> Result<GcReportChirho> {
    let objects_dir_chirho = root_chirho.join("objects-chirho");
    let mut kept_chirho = 0usize;
    let mut collected_chirho = 0usize;
    let shards_chirho = match fs::read_dir(&objects_dir_chirho) {
        Ok(d_chirho) => d_chirho,
        Err(_) => {
            return Ok(GcReportChirho {
                kept_chirho: 0,
                collected_chirho: 0,
            });
        }
    };
    for shard_chirho in shards_chirho.flatten() {
        let shard_path_chirho = shard_chirho.path();
        if !shard_path_chirho.is_dir() {
            continue;
        }
        let shard_name_chirho = shard_chirho.file_name().to_string_lossy().to_string();
        if let Ok(objs_chirho) = fs::read_dir(&shard_path_chirho) {
            for obj_chirho in objs_chirho.flatten() {
                let rest_chirho = obj_chirho.file_name().to_string_lossy().to_string();
                let hash_chirho = HashChirho(format!("{shard_name_chirho}{rest_chirho}"));
                if marked_chirho.contains(&hash_chirho) {
                    kept_chirho += 1;
                } else {
                    fs::remove_file(obj_chirho.path())
                        .with_context(|| format!("gc remove {}", hash_chirho.0))?;
                    collected_chirho += 1;
                }
            }
        }
    }
    Ok(GcReportChirho {
        kept_chirho,
        collected_chirho,
    })
}
