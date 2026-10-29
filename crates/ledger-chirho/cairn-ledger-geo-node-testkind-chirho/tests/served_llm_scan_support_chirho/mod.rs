// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Shared test support for the served-LLM a2b loopback HTTP e2e proof: the fail-closed plaintext CAS
//! scanner, reused instead of hand-rolling a `.flatten()` walk that silently skips an unreadable
//! surface (the 2026-08-09 vacuous-walk defect). SCOPE (gpt recert): a2b uses this extracted walker; the
//! a2 direct-call test (`served_llm_dev_composition_e2e_chirho.rs`) STILL DEFINES ITS OWN copy -- the
//! recorded extraction loan migrates a2 onto this module later; do not claim both reuse one walker yet.
//! Lives in a `tests/` SUBDIRECTORY, so cargo does not compile it as its own test binary; the a2b e2e
//! file `#[path]`-includes it. The armed self-test below runs in every binary that includes it, proving
//! the instrument fails CLOSED (not skip) on an unreadable surface (a broken symlink) and, where
//! permissions are enforced, an unreadable DIRECTORY (a directory-OPEN error -- which is a different
//! instrument from an injected iterator-entry error; the walker's `?` on each iterator result carries
//! the entry-error path).

use std::path::Path;

/// True iff `needle_chirho` appears as a contiguous byte subslice of `haystack_chirho`.
pub fn contains_subslice_chirho(haystack_chirho: &[u8], needle_chirho: &[u8]) -> bool {
    !needle_chirho.is_empty()
        && haystack_chirho.len() >= needle_chirho.len()
        && haystack_chirho
            .windows(needle_chirho.len())
            .any(|window_chirho| window_chirho == needle_chirho)
}

/// Walk the WHOLE tree rooted at `root_chirho` for a plaintext needle, failing CLOSED: EVERY enumerated
/// path must be read successfully, so a `read_dir`, directory-entry, file-type, or file-read error
/// REFUSES the scan (`Err`) rather than silently reporting "no plaintext". Returns `(found, read_count)`
/// only when the entire tree was read; the caller may assert `!found` (no PII at rest) ONLY on that
/// complete-coverage `Ok`, never on a partial read that skipped the surface holding the secret. The
/// short-circuit is `Ok(true)` on the first match, so only an `Ok(false)` implies complete coverage.
pub fn scan_root_for_needle_chirho(
    root_chirho: &Path,
    needle_chirho: &[u8],
) -> std::io::Result<(bool, u64)> {
    fn walk_chirho(
        dir_chirho: &Path,
        needle_chirho: &[u8],
        read_count_chirho: &mut u64,
    ) -> std::io::Result<bool> {
        for entry_chirho in std::fs::read_dir(dir_chirho)? {
            let entry_chirho = entry_chirho?;
            let path_chirho = entry_chirho.path();
            if entry_chirho.file_type()?.is_dir() {
                if walk_chirho(&path_chirho, needle_chirho, read_count_chirho)? {
                    return Ok(true);
                }
            } else {
                let bytes_chirho = std::fs::read(&path_chirho)?;
                *read_count_chirho += 1;
                if contains_subslice_chirho(&bytes_chirho, needle_chirho) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    let mut read_count_chirho = 0;
    let found_chirho = walk_chirho(root_chirho, needle_chirho, &mut read_count_chirho)?;
    Ok((found_chirho, read_count_chirho))
}

/// A self-contained temp dir for the self-test (no dependency on either e2e file's own root helper).
#[cfg(unix)]
fn scan_support_temp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-scan-support-{label_chirho}-{}-{counter_chirho}-{nanos_chirho}-chirho",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir_chirho).unwrap();
    dir_chirho
}

/// POSITIVE CONTROLS + FAIL-CLOSED PROOF for the scanner. On a fully readable tree the scan completes
/// (`Ok`), reads every file, MISSES an absent needle and FINDS a planted one (liveness — the instrument
/// can fire). Then TWO independent unreadable surfaces each make the SAME scan REFUSE (`Err`) instead of
/// silently reporting "clean": (1) a broken symlink, whose `std::fs::read` returns `NotFound` (the old
/// `is_file()==false` skip); and (2) an unreadable directory, whose `read_dir` fails (the old
/// `entries.flatten()` entry-error drop). The fail-closed scans use an ABSENT needle so the walk cannot
/// early-return `Ok(true)` before it must reach the unreadable surface (order-independent).
#[cfg(unix)]
#[test]
fn the_plaintext_scanner_refuses_unreadable_surfaces_chirho() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root_chirho = scan_support_temp_root_chirho("fail-closed");
    std::fs::create_dir_all(root_chirho.join("nested-chirho")).unwrap();
    std::fs::write(root_chirho.join("a-chirho.bin"), b"harmless-chirho").unwrap();
    std::fs::write(
        root_chirho.join("nested-chirho/b-chirho.bin"),
        b"also-harmless-chirho",
    )
    .unwrap();

    // Liveness 1: a fully readable tree scans to completion, reads every file, misses an absent needle.
    let (found_chirho, read_count_chirho) =
        scan_root_for_needle_chirho(&root_chirho, b"absent-needle-chirho")
            .expect("a fully readable tree must scan to completion");
    assert!(!found_chirho, "the control tree holds no needle yet");
    assert_eq!(
        read_count_chirho, 2,
        "the scan must read BOTH planted files"
    );

    // Liveness 2: the instrument must be able to FIRE — a planted needle is found.
    std::fs::write(
        root_chirho.join("nested-chirho/c-chirho.bin"),
        b"prefix-present-needle-chirho-suffix",
    )
    .unwrap();
    let (found_chirho, _read_count_chirho) =
        scan_root_for_needle_chirho(&root_chirho, b"present-needle-chirho")
            .expect("a fully readable tree must scan to completion");
    assert!(found_chirho, "the scan must find a planted needle");

    // FAIL-CLOSED mechanism 1: a BROKEN SYMLINK (target does not exist). `file_type()` reports a
    // symlink (never followed), so the walker reads it; `std::fs::read` follows the link and returns
    // `NotFound`, which REFUSES the scan. Root-robust (ENOENT applies regardless of uid). This is the
    // surface the old `is_file()==false` predicate silently skipped.
    let broken_symlink_chirho = root_chirho.join("broken-link-chirho.bin");
    symlink(
        root_chirho.join("does-not-exist-chirho"),
        &broken_symlink_chirho,
    )
    .unwrap();
    assert!(
        scan_root_for_needle_chirho(&root_chirho, b"absent-needle-chirho").is_err(),
        "a broken symlink must REFUSE the scan (fail-closed), never silently report clean"
    );
    std::fs::remove_file(&broken_symlink_chirho).unwrap();

    // FAIL-CLOSED mechanism 2: an UNREADABLE DIRECTORY (mode 000) makes `read_dir` fail during
    // traversal (a directory-OPEN error), which REFUSES the scan. This is a DIFFERENT instrument from an
    // injected iterator-entry error (the old `entries.flatten()` drop); the walker's `?` on each
    // iterator result carries that entry-error path (inspected in source, not injected here). Skipped
    // only when the process can still read a mode-000 dir (root), where permission bits do not apply.
    let locked_dir_chirho = root_chirho.join("locked-chirho");
    std::fs::create_dir(&locked_dir_chirho).unwrap();
    std::fs::write(locked_dir_chirho.join("inner-chirho.bin"), b"inner-chirho").unwrap();
    std::fs::set_permissions(&locked_dir_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();
    let root_bypasses_perms_chirho = std::fs::read_dir(&locked_dir_chirho).is_ok();
    if !root_bypasses_perms_chirho {
        assert!(
            scan_root_for_needle_chirho(&root_chirho, b"absent-needle-chirho").is_err(),
            "an unreadable directory must REFUSE the scan (fail-closed traversal), never skip it"
        );
    }

    // Restore perms so cleanup can remove the tree.
    let _restored_chirho =
        std::fs::set_permissions(&locked_dir_chirho, std::fs::Permissions::from_mode(0o755));
    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}
