// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Nothing may enumerate the CAS object plane with a flat `read_dir` written inline at the call.
//!
//! The CAS shards by hash prefix — `cas_chirho::object_path_chirho` writes
//! `objects-chirho/<ab>/<rest>`, and the publisher's temp files live inside the shard too — so
//! EVERY entry directly under `objects-chirho` is a shard DIRECTORY. A loop of the form
//!
//! ```text
//! for entry in read_dir(root.join("objects-chirho")) {
//!     if !entry.path().is_file() { continue; }
//!     …assert the needle is absent…
//! }
//! ```
//!
//! therefore visits only directories, `continue`s on every one, and never executes its body at
//! all. A leak sweep written that way reports CLEAN without reading a single object. That exact
//! shape shipped in a landed, two-seat-reviewed test and was measured vacuous on 2026-08-09:
//! against a needle planted through the real `cas_chirho::add_chirho`, the flat form visited 1
//! entry, read 0 files and found 0 hits, while a recursive walk over the same directory read 1
//! file and found 1 hit.
//!
//! HONEST BOUND, because this guard is easy to over-read: it is a LINE-scoped text check. It sees
//! only the INLINE idiom, where the literal `objects-chirho` and the `read_dir(` sit on ONE line.
//! It does NOT see `let dir = root.join("objects-chirho"); … read_dir(&dir)` — which is how the
//! shard-aware production walkers in `gc_chirho::sweep_chirho` and
//! `privacy_chirho::scan_chirho::object_paths_for_scan_chirho` are written, and how a future FLAT
//! walk could be written too. This guard stops the vacuous idiom from being pasted again. It is
//! NOT a proof that no flat CAS walk exists anywhere.

use super::super::*;
use std::path::{Path, PathBuf};

/// The line predicate, isolated so it can be controlled in both directions before it is trusted.
fn line_walks_object_plane_inline_chirho(line_chirho: &str) -> bool {
    line_chirho.contains("read_dir(") && line_chirho.contains("objects-chirho")
}

fn collect_rs_files_under_chirho(dir_chirho: &Path, files_chirho: &mut Vec<PathBuf>) {
    let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if path_chirho.is_dir() {
            collect_rs_files_under_chirho(&path_chirho, files_chirho);
        } else if path_chirho
            .extension()
            .and_then(|e_chirho| e_chirho.to_str())
            == Some("rs")
        {
            files_chirho.push(path_chirho);
        }
    }
}

/// `src/`, `crates/` AND the root `tests/` dir — the last is outside
/// `workspace_all_rs_files_chirho`, and an integration test is exactly where such a sweep lives.
fn scanned_rs_files_chirho() -> Vec<PathBuf> {
    let root_chirho = workspace_root_chirho();
    let mut files_chirho = workspace_all_rs_files_chirho();
    collect_rs_files_under_chirho(&root_chirho.join("tests"), &mut files_chirho);
    files_chirho.sort();
    files_chirho.dedup();
    files_chirho
}

#[test]
fn cas_object_plane_is_never_enumerated_by_an_inline_flat_read_dir_chirho() {
    // Positive control on the PREDICATE, against the exact line that was landed and vacuous.
    const VACUOUS_LINE_CHIRHO: &str =
        "    for entry_chirho in std::fs::read_dir(root_chirho.join(\"objects-chirho\")).unwrap() {";
    assert!(
        line_walks_object_plane_inline_chirho(VACUOUS_LINE_CHIRHO),
        "this guard's own predicate no longer recognises the vacuous idiom it exists to stop"
    );
    // Negative control: the shard-aware replacement must NOT trip it, or the guard would simply
    // forbid the fix and every author would route around it.
    assert!(
        !line_walks_object_plane_inline_chirho(
            "    walk_chirho(&root_chirho.join(\"objects-chirho\"), &mut files_chirho);"
        ),
        "this guard's predicate flags a shard-aware walk; it would fire on the correct code"
    );

    let files_chirho = scanned_rs_files_chirho();
    // Corpus sanity, paired with the absence below: a zero here would make a clean result a
    // statement about the scanner rather than about the code.
    assert!(
        files_chirho.len() > 500,
        "the source corpus collapsed to {} files; the absence below would be vacuous",
        files_chirho.len()
    );

    // THIS file is the one legitimate exclusion: a guard that names the idiom it forbids must be
    // allowed to write the idiom down. The exclusion is asserted to match EXACTLY ONE file, so a
    // rename or a second copy is loud rather than a silent widening — an exclusion list is the one
    // part of a guard that its own assertions otherwise never reach.
    const SELF_FILE_CHIRHO: &str = "cas_object_plane_walk_guard_tests_chirho.rs";
    let mut self_excluded_chirho = 0usize;
    let mut read_dir_files_chirho = 0usize;
    let mut object_plane_files_chirho = 0usize;
    let mut offenders_chirho = Vec::new();
    for path_chirho in &files_chirho {
        if path_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
            == Some(SELF_FILE_CHIRHO)
        {
            self_excluded_chirho += 1;
            continue;
        }
        let Ok(text_chirho) = std::fs::read_to_string(path_chirho) else {
            continue;
        };
        if text_chirho.contains("read_dir(") {
            read_dir_files_chirho += 1;
        }
        if text_chirho.contains("objects-chirho") {
            object_plane_files_chirho += 1;
        }
        for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
            if line_walks_object_plane_inline_chirho(line_chirho) {
                offenders_chirho.push(format!(
                    "{}:{}: {}",
                    path_chirho.display(),
                    index_chirho + 1,
                    line_chirho.trim()
                ));
            }
        }
    }

    assert_eq!(
        self_excluded_chirho, 1,
        "the self-exclusion matched {self_excluded_chirho} files, not exactly this guard. If this \
         file was renamed, update SELF_FILE_CHIRHO; if a second file took the name, the exclusion \
         is now hiding real code from the scan."
    );

    // Both families this guard intersects must be non-empty, or the intersection is empty for a
    // reason that has nothing to do with the property.
    assert!(
        read_dir_files_chirho > 10,
        "only {read_dir_files_chirho} files contain read_dir(; the scanner is reading the wrong tree"
    );
    assert!(
        object_plane_files_chirho > 5,
        "only {object_plane_files_chirho} files mention objects-chirho; the scanner is reading the \
         wrong tree"
    );

    assert!(
        offenders_chirho.is_empty(),
        "an inline flat read_dir over the CAS object plane: {offenders_chirho:?}. Objects live at \
         objects-chirho/<ab>/<rest>, so every entry here is a shard DIRECTORY and an is_file() \
         filter skips all of them. Walk the shards (a recursive walk, or read_dir the shard dir \
         inside the outer loop), and pair any absence assertion with a needle planted through the \
         real cas_chirho::add_chirho. If you genuinely want the DIRECT CHILDREN only — counting \
         shards, or checking the plane is empty — say so here with the reason, because this guard \
         cannot tell the two apart."
    );
}
