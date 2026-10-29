// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Read one reviewed ledger-host authoring document off disk, optionally binding it to the digest
//! the operator pasted from review — and still without checking a single money-policy law.
//!
//! Brick #6 of the generic ledger-host authoring program
//! (`spec-chirho/workstream-state-chirho/ledger-host-config-authoring-design-chirho.md` §5). The
//! program's earlier bricks are deliberately IO-free: brick #1 is types plus validation over BYTES,
//! and bricks #2-#5 take an already-parsed document. Somebody has to turn a path into those bytes,
//! and this is that somebody.
//!
//! **Why the IO lives here rather than in the CLI that needs it.** The bounded, identity-stable read
//! this module uses is `pub(crate)` in this crate, wrapping the shared reader that refuses a
//! symlink, a hard link, a non-regular file, and a file that GREW between stat and read. A CLI
//! reaching for a plain `fs::read` instead would lose all four refusals on a money-authority
//! artifact, and exporting the bounded reader to let it keep them would widen this crate's API for
//! one caller's convenience. So the read stays beside the plan's, which applies the same four laws
//! at `plan_chirho::load_verified_plan_chirho`.
//!
//! **BOTH FUNCTIONS BELOW CARRY `money_policy_unchecked` IN THEIR NAMES, AND THAT IS THE POINT.**
//! They return a well-formed set of coordinates, never a sound money statement: a document that
//! mints 10,000 against a max supply of 2,000 passes both in full, because the money-policy law
//! lives with `validate_plan_policy_chirho` and runs only when a plan is DERIVED. An operator
//! surface that PRINTS or REPORTS on a document must therefore derive first, or it shows a reader
//! something that looks validated and is not. The shorter name misled a reader once already; the
//! warning travels with every road that can hand the document out.
//!
//! **Why the digest binding is a SEPARATE function rather than an `Option` parameter.** An
//! `Option<&str>` that silently skips a money-authority check when it is `None` is the shape where a
//! forgotten argument decides a money question — the same shape M140 removed for runtime body modes
//! and the same reason the authoring mode has no `Default`. Two names instead: the unbound read is
//! for a road that writes nothing and asserts nothing, and the bound read is for the road that
//! authors artifacts.
//!
//! No key is read, derived, or created anywhere in this module.

use crate::bounded_file_chirho::read_bounded_regular_file_chirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::ledger_host_authoring_inputs_chirho::{
    ledger_host_authoring_inputs_digest_chirho,
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho,
    LedgerHostAuthoringInputsV1Chirho,
};
use std::path::Path;

/// The same 64 KiB ceiling the reviewed plan carries. The two documents describe one deployment and
/// the plan is the larger of the pair, so a bound that is right for it is right for this.
const MAX_LEDGER_HOST_AUTHORING_INPUTS_BYTES_CHIRHO: u64 = 64 * 1024;

/// One reviewed document and the digest of the exact bytes it was read from.
///
/// The digest travels with the document rather than being recomputed by callers: a caller that
/// re-derived it from the parsed value would be digesting a re-serialization, and the whole review
/// binding is about the bytes on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedLedgerHostAuthoringInputsChirho {
    pub inputs_chirho: LedgerHostAuthoringInputsV1Chirho,
    pub inputs_digest_chirho: String,
}

/// Read a reviewed document and parse it, with NO review binding.
///
/// Refuses, in order: a file that is absent or unreadable; a file that is not one stable regular
/// file within the ceiling; and then everything
/// [`parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho`] refuses — foreign schema,
/// non-canonical encoding, key-material-shaped runs, and every coordinate law.
///
/// It refuses NOTHING about money policy. Use it only where nothing is authored and no authority is
/// asserted; the emitting road takes the digest-bound sibling below.
pub fn read_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
    inputs_path_chirho: &Path,
) -> LedgerRegenesisResultChirho<LoadedLedgerHostAuthoringInputsChirho> {
    let raw_bytes_chirho = read_bounded_regular_file_chirho(
        inputs_path_chirho,
        MAX_LEDGER_HOST_AUTHORING_INPUTS_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            LedgerRegenesisRefusalChirho::AuthoringInputsUnavailableChirho
        }
        _ => LedgerRegenesisRefusalChirho::AuthoringInputsNotRegularChirho,
    })?;
    let inputs_chirho =
        parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(&raw_bytes_chirho)?;
    Ok(LoadedLedgerHostAuthoringInputsChirho {
        // Digested from the RAW bytes. The parse above already proved they are byte-identical to
        // this document's one canonical encoding, so this is the reviewed artifact's own digest and
        // not a digest of whatever a re-serialization would produce.
        inputs_digest_chirho: ledger_host_authoring_inputs_digest_chirho(&raw_bytes_chirho),
        inputs_chirho,
    })
}

/// Read a reviewed document and refuse unless its bytes digest to the value the operator pasted
/// from review.
///
/// This is the `--expected-plan-digest-chirho` law applied to the other reviewed artifact: without
/// it, an operator can review document A and author from document B, and nothing anywhere notices.
/// The digest SHAPE is checked before the file is opened, so a mistyped argument refuses with its
/// own identity rather than as a mismatch against whatever happened to be on disk.
pub fn read_digest_bound_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
    inputs_path_chirho: &Path,
    expected_inputs_digest_chirho: &str,
) -> LedgerRegenesisResultChirho<LoadedLedgerHostAuthoringInputsChirho> {
    validate_expected_inputs_digest_shape_chirho(expected_inputs_digest_chirho)?;
    let loaded_chirho =
        read_ledger_host_authoring_inputs_money_policy_unchecked_chirho(inputs_path_chirho)?;
    if loaded_chirho.inputs_digest_chirho != expected_inputs_digest_chirho {
        return Err(LedgerRegenesisRefusalChirho::AuthoringInputsDigestMismatchChirho);
    }
    Ok(loaded_chirho)
}

/// A blake3 hex digest is 64 lowercase hex characters. Uppercase is refused rather than folded: the
/// digest functions in this crate emit lowercase, so an uppercase argument was not copied from a
/// report this program produced, and quietly accepting it would hide that.
fn validate_expected_inputs_digest_shape_chirho(
    digest_chirho: &str,
) -> LedgerRegenesisResultChirho<()> {
    if digest_chirho.len() != 64
        || !digest_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
    {
        return Err(LedgerRegenesisRefusalChirho::AuthoringInputsDigestInvalidChirho);
    }
    Ok(())
}
