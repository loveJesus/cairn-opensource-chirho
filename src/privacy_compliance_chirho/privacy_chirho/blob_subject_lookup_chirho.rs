// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Resolves a private blob ref to the subject the privacy blob log names for it.
//!
//! Before checkpoint brick S1 each resolution read the whole blob log and opened every shred-key file, so a verifier
//! held one lookup object per pass to pay that once per pass. Resolution now asks the blob log's verified view
//! (`blob_view_chirho`): O(1) plus the records appended since the last call, with this ref's own key file
//! re-checked. One call costs the same as a call inside a pass, so there is no lookup object to hold.
//!
//! Same order, same refusals as before: the ref's own shape and ciphertext first, then the log and its key namespace
//! (now: the newly appended records), then the first log record carrying exactly this ref, compared with the ref's
//! own `==`.

use super::{
    blob_view_chirho, validate_private_blob_ref_shape_chirho, validate_subject_chirho,
    PrivateBlobRefChirho,
};
use anyhow::{anyhow, bail, Result};
use std::path::Path;

/// The subject named by the FIRST privacy blob record that carries exactly this ref.
pub(crate) fn private_blob_ref_subject_from_log_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
) -> Result<String> {
    validate_private_blob_ref_shape_chirho(root_chirho, blob_chirho)?;
    blob_view_chirho::logged_blob_subject_chirho(root_chirho, blob_chirho)
}

/// One ref's subject binding: the ref must be logged, and logged for `expected_subject_chirho`.
pub fn verify_private_blob_ref_subject_chirho(
    root_chirho: &Path,
    context_chirho: &str,
    blob_chirho: &PrivateBlobRefChirho,
    expected_subject_chirho: &str,
) -> Result<()> {
    validate_subject_chirho(expected_subject_chirho)?;
    let actual_subject_chirho = private_blob_ref_subject_from_log_chirho(root_chirho, blob_chirho)
        .map_err(|error_chirho| {
            anyhow!("{context_chirho} private blob ref invalid: {error_chirho}")
        })?;
    if actual_subject_chirho != expected_subject_chirho {
        bail!(
            "{context_chirho} key {} belongs to subject '{}', not '{}'",
            blob_chirho.key_id_chirho,
            actual_subject_chirho,
            expected_subject_chirho
        );
    }
    Ok(())
}
