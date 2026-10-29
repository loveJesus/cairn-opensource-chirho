// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Embeds the source commit in a crate's binaries, so a hash found on a host resolves to a tree.
//!
//! CF8 acceptance[12] wants deploy evidence binding source commit, target triple, architecture and
//! binary hash. The first of those was structurally unobtainable before this: every node answered
//! `cairn-chirho 0.1.0` -- the crate version, identical across provably different binaries -- so
//! binding a hash to a commit depended on someone remembering which build went where.
//!
//! Reports `unknown` rather than failing the build when git is absent or the tree is not a
//! repository, because a source tarball is a legitimate way to build and a build script that refused
//! it would trade one problem for a worse one. **A dirty tree is marked**, since a commit id alone
//! would otherwise claim a provenance the bytes do not have.

use crate::{DIRTY_SUFFIX_CHIRHO, UNKNOWN_COMMIT_CHIRHO};
use std::process::Command;

fn git_chirho(args_chirho: &[&str]) -> Option<String> {
    let out_chirho = Command::new("git").args(args_chirho).output().ok()?;
    if !out_chirho.status.success() {
        return None;
    }
    let text_chirho = String::from_utf8(out_chirho.stdout).ok()?;
    let text_chirho = text_chirho.trim().to_string();
    if text_chirho.is_empty() {
        None
    } else {
        Some(text_chirho)
    }
}

/// Call this from a crate's `build.rs`. Emits `CAIRN_BUILD_COMMIT_CHIRHO` for that crate's own
/// compilation, which the [`version_line_chirho!`](crate::version_line_chirho) macro then reads.
pub fn emit_build_commit_chirho() {
    // An EXPLICIT commit from the caller wins over anything derived, and that ordering is the point
    // rather than a convenience. The container build path cannot ask git at all -- the repo is
    // bind-mounted under a different uid and git refuses with "dubious ownership" -- so a build
    // script that only derives produces `unknown` in exactly the build that ships. Passing the
    // commit in also matches how every hosted step here already works: the reviewed commit is
    // supplied and compared, never inferred.
    let commit_chirho = std::env::var("CAIRN_BUILD_COMMIT_CHIRHO")
        .ok()
        .filter(|value_chirho| !value_chirho.trim().is_empty())
        .or_else(|| git_chirho(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| UNKNOWN_COMMIT_CHIRHO.to_string());
    println!("cargo:rerun-if-env-changed=CAIRN_BUILD_COMMIT_CHIRHO");

    // `unknown` is legitimate for a source tarball and NEVER legitimate for something being shipped.
    // Warn rather than fail: refusing would break tarball builds, and this is loud enough that a
    // release binary cannot acquire an unprovable identity in silence -- which is what happened the
    // first time this ran in a container and produced `0.1.0 (unknown)`.
    if commit_chirho == UNKNOWN_COMMIT_CHIRHO {
        let package_chirho =
            std::env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "this crate".to_string());
        println!(
            "cargo:warning={package_chirho} is being built with NO source commit. \
             Set CAIRN_BUILD_COMMIT_CHIRHO=<sha> -- a shipped binary that cannot name its own tree \
             is the exact gap the freshness state machine exists to close."
        );
    }
    // `--untracked-files=no` is load-bearing, not a tidy-up. Plain `--porcelain` counts UNTRACKED
    // files, and this repo always has some -- editor dirs, scratch tasklists, a stray filename from
    // a mis-quoted shell command. None of them was compiled into the binary, so counting them marked
    // EVERY build `-dirty` and the flag stopped distinguishing anything. Caught by committing and
    // watching the suffix fail to clear.
    let dirty_chirho = git_chirho(&["status", "--porcelain", "--untracked-files=no"]).is_some();
    let suffix_chirho = if dirty_chirho {
        DIRTY_SUFFIX_CHIRHO
    } else {
        ""
    };
    println!("cargo:rustc-env=CAIRN_BUILD_COMMIT_CHIRHO={commit_chirho}{suffix_chirho}");

    // Rebuild when the checked-out commit moves. Without these the embedded id goes stale silently,
    // which is the same class of wrong as having no id at all. The paths are RESOLVED rather than
    // written relative to the package: crates sit at different depths, and in a git WORKTREE `.git`
    // is a file rather than a directory, so a hardcoded `../../.git/HEAD` names nothing at all --
    // a rebuild trigger that silently never fires. HEAD is per-worktree; `refs` lives in the common
    // dir. When git cannot answer, there is no commit to go stale, so emitting nothing is correct.
    if let Some(git_dir_chirho) = git_chirho(&["rev-parse", "--git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir_chirho}/HEAD");
    }
    if let Some(common_dir_chirho) = git_chirho(&["rev-parse", "--git-common-dir"]) {
        println!("cargo:rerun-if-changed={common_dir_chirho}/refs");
    }
}
