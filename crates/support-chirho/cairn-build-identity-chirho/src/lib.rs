// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! One mechanism by which any cairn binary can name the source tree that produced its bytes.
//!
//! A shipped binary must be able to name its own source, **because nothing at the destination can
//! derive it** -- a hash on a host resolves to a tree only if the bytes carry the commit. The root
//! CLI proved this shape first (its own `build.rs` plus a `--version` string); the elector and the
//! composed geo nodes had no version surface at all, so their only on-host identity handle was a
//! sha256 nobody could resolve back to source. This crate is that mechanism made reusable, so a
//! fourth binary inherits it instead of re-deriving it (or, as happened, inheriting nothing).
//!
//! Two halves, deliberately separated:
//! - the **build-script** half ([`build_script_chirho`], behind `build-script-chirho`) accepts a
//!   SUPPLIED commit first and derives one from git only as a fallback;
//! - the **runtime** half ([`version_line_chirho!`] / [`is_version_request_chirho`]) prints it.

#[cfg(feature = "build-script-chirho")]
pub mod build_script_chirho;

/// What the commit reads as when the build could neither be told one nor derive one.
///
/// Honest and legitimate for a source tarball; never legitimate for something being shipped. A
/// FABRICATED or stale value would be worse than this, because it would resolve to the wrong tree
/// with no way for a reader to tell.
pub const UNKNOWN_COMMIT_CHIRHO: &str = "unknown";

/// The suffix marking a tree that had uncommitted tracked changes when the bytes were built.
pub const DIRTY_SUFFIX_CHIRHO: &str = "-dirty";

/// The exact arguments that ask a binary which tree it came from.
///
/// EXACT match, never a prefix or substring: these binaries take a config PATH in the same
/// position, and a path is free-form. Matching loosely would let a file called `version.json`
/// silently become a version request instead of the config the operator meant.
pub const VERSION_REQUEST_FLAGS_CHIRHO: [&str; 2] = ["--version", "-V"];

/// Is this first argument a version request?
///
/// Callers check this BEFORE their positional parse. These binaries read `argv[1]` as a config path
/// (or a subcommand), so a version request reaching the positional parse is read as a FILENAME and
/// fails with `No such file or directory` -- which is exactly how the gap was found.
pub fn is_version_request_chirho(first_arg_chirho: Option<&str>) -> bool {
    match first_arg_chirho {
        Some(arg_chirho) => VERSION_REQUEST_FLAGS_CHIRHO.contains(&arg_chirho),
        None => false,
    }
}

/// Does this `--version` line actually name a resolvable source tree?
///
/// Accepts a 40-hex commit (optionally `-dirty`) or the honest [`UNKNOWN_COMMIT_CHIRHO`] marker, and
/// nothing else -- a bare `name 0.1.0` is the pre-fix shape and must not pass.
pub fn version_line_names_a_tree_chirho(line_chirho: &str) -> bool {
    let trimmed_chirho = line_chirho.trim_end();
    let Some(open_chirho) = trimmed_chirho.rfind(" (") else {
        return false;
    };
    let Some(inside_chirho) = trimmed_chirho[open_chirho + 2..].strip_suffix(')') else {
        return false;
    };
    let commit_chirho = inside_chirho
        .strip_suffix(DIRTY_SUFFIX_CHIRHO)
        .unwrap_or(inside_chirho);
    if commit_chirho == UNKNOWN_COMMIT_CHIRHO {
        return true;
    }
    commit_chirho.len() == 40
        && commit_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
}

/// `<crate version> (<source commit>)` for THIS crate -- the form clap wants, since clap already
/// prints the binary name itself.
///
/// A macro rather than a function because `env!` must expand while the CALLING crate compiles: the
/// commit is a `rustc-env` its own build script emitted, so a value read here would be this crate's,
/// not the caller's.
#[macro_export]
macro_rules! version_with_commit_chirho {
    () => {
        concat!(
            env!("CARGO_PKG_VERSION"),
            " (",
            env!("CAIRN_BUILD_COMMIT_CHIRHO"),
            ")"
        )
    };
}

/// The whole `--version` line: `<name> <crate version> (<source commit>)`.
///
/// The name is passed rather than taken from `CARGO_PKG_NAME` because a package can carry several
/// binaries, and because what an operator finds on a host is an INSTALLED name -- the caller is the
/// only one that knows which of its binaries this is.
#[macro_export]
macro_rules! version_line_chirho {
    ($name_chirho:literal) => {
        concat!(
            $name_chirho,
            " ",
            env!("CARGO_PKG_VERSION"),
            " (",
            env!("CAIRN_BUILD_COMMIT_CHIRHO"),
            ")"
        )
    };
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn only_the_exact_flags_are_version_requests_chirho() {
        assert!(is_version_request_chirho(Some("--version")));
        assert!(is_version_request_chirho(Some("-V")));
        // The negative half is the load-bearing one: argv[1] is otherwise a config PATH, so a
        // loose match would hijack an operator's real file.
        assert!(!is_version_request_chirho(Some("version.json")));
        assert!(!is_version_request_chirho(Some("--version=1")));
        assert!(!is_version_request_chirho(Some("-v")));
        assert!(!is_version_request_chirho(Some("keygen")));
        assert!(!is_version_request_chirho(Some("/etc/cairn/config.json")));
        assert!(!is_version_request_chirho(None));
    }

    #[test]
    fn a_version_line_must_carry_a_commit_or_the_honest_marker_chirho() {
        let commit_chirho = "83d6d61835b5814f72f213ffd02f01b52f518a33";
        assert!(version_line_names_a_tree_chirho(&format!(
            "cairn-chirho 0.1.0 ({commit_chirho})"
        )));
        assert!(version_line_names_a_tree_chirho(&format!(
            "cairn-chirho 0.1.0 ({commit_chirho}-dirty)"
        )));
        assert!(version_line_names_a_tree_chirho(
            "cairn-chirho 0.1.0 (unknown)"
        ));
        assert!(version_line_names_a_tree_chirho(&format!(
            "cairn-chirho 0.1.0 ({commit_chirho})\n"
        )));
    }

    #[test]
    fn a_version_line_naming_no_tree_is_rejected_chirho() {
        // The pre-fix shape: a crate version identical across provably different binaries.
        assert!(!version_line_names_a_tree_chirho("cairn-chirho 0.1.0"));
        // A truncated / non-hex / empty commit resolves to nothing, so it must not pass either.
        assert!(!version_line_names_a_tree_chirho(
            "cairn-chirho 0.1.0 (83d6d618)"
        ));
        assert!(!version_line_names_a_tree_chirho(
            "cairn-chirho 0.1.0 (zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz)"
        ));
        assert!(!version_line_names_a_tree_chirho("cairn-chirho 0.1.0 ()"));
        assert!(!version_line_names_a_tree_chirho(
            "cairn-chirho 0.1.0 (-dirty)"
        ));
        assert!(!version_line_names_a_tree_chirho(""));
    }
}
