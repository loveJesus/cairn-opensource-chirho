// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The injected, root-pinned signing boundary for segment continuity — seqlog itself stays signer-free.
//!
//! seqlog carries no signature dependency, so a family that wants signed sealed-segment continuity
//! MUST inject an implementation of `SegmentContinuityPortChirho` (it holds the root-pinned key). The
//! port only signs and verifies raw canonical bytes; this module owns the canonicalisation and is the
//! ONLY place that mints a `VerifiedSegmentContinuityChirho` — so a verified token can exist only
//! downstream of a real, root-pinned signature check. There is deliberately NO no-op / unsigned
//! default: an unsigned log is honestly a different, non-evidence path, never a hollow "signed" one.
//! Continuity is MECHANISM evidence (these bytes are a signed, contiguous segment); it is NOT a
//! substitute for a family's own record-chain authority (e.g. a money log's own prev-digest law).

use crate::segment_chirho::manifest_chirho::{
    canonical_manifest_entry_bytes_chirho, SegmentManifestEntryChirho,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A signature over a canonical manifest entry, produced by an injected continuity port. Opaque hex;
/// its meaning is entirely the port's (a keyed MAC, an ed25519 signature, ...).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentSignatureChirho(pub String);

/// One signed line of the append-only segment manifest: the entry plus the port's signature and an
/// informational key id. The `key_id_chirho` is a LABEL for humans / key rotation only —
/// verification root-pins the trusted key inside the port and never lets this embedded value select
/// trust.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSegmentManifestLineChirho {
    pub entry_chirho: SegmentManifestEntryChirho,
    pub key_id_chirho: String,
    pub signature_chirho: SegmentSignatureChirho,
}

/// The narrow, injected signing boundary. NOT a sealed trait: external families implement it so they
/// can carry their own root-pinned key while seqlog keeps zero crypto dependencies. Implementations
/// MUST verify against a root-pinned key of their own and ignore any caller-supplied key id.
pub trait SegmentContinuityPortChirho {
    /// Sign canonical entry bytes with the port's root-pinned key.
    fn sign_canonical_chirho(
        &self,
        canonical_bytes_chirho: &[u8],
    ) -> Result<SegmentSignatureChirho>;

    /// Verify a signature over canonical entry bytes against the port's root-pinned key. Returns
    /// `Err` for any invalid signature — the caller treats that as a hard reject (fail closed).
    fn verify_canonical_chirho(
        &self,
        canonical_bytes_chirho: &[u8],
        signature_chirho: &SegmentSignatureChirho,
    ) -> Result<()>;

    /// An informational key id recorded on signed lines. NEVER consulted to select a verifying key.
    fn key_id_chirho(&self) -> String;
}

/// Evidence that a manifest line was verified against a root-pinned continuity key. It has no public
/// constructor — the ONLY way to obtain one is `verify_manifest_line_chirho`, so holding a value of
/// this type is proof a real signature check passed. Sibling modules cannot forge it; the private
/// field is minted solely by verification.
#[derive(Clone, Debug)]
pub struct VerifiedSegmentContinuityChirho {
    entry_chirho: SegmentManifestEntryChirho,
}

impl VerifiedSegmentContinuityChirho {
    /// The verified entry. Read-only; the token cannot be forged, only minted by verification.
    pub fn entry_chirho(&self) -> &SegmentManifestEntryChirho {
        &self.entry_chirho
    }
}

/// Sign one manifest entry, producing the line appended to the manifest.
pub fn sign_manifest_entry_chirho(
    port_chirho: &dyn SegmentContinuityPortChirho,
    entry_chirho: &SegmentManifestEntryChirho,
) -> Result<SignedSegmentManifestLineChirho> {
    let canonical_chirho = canonical_manifest_entry_bytes_chirho(entry_chirho)?;
    let signature_chirho = port_chirho.sign_canonical_chirho(&canonical_chirho)?;
    Ok(SignedSegmentManifestLineChirho {
        entry_chirho: entry_chirho.clone(),
        key_id_chirho: port_chirho.key_id_chirho(),
        signature_chirho,
    })
}

/// Verify one signed manifest line against the port's root-pinned key and mint the nonconstructible
/// verified-continuity token. The embedded `key_id_chirho` is ignored for trust selection.
pub fn verify_manifest_line_chirho(
    port_chirho: &dyn SegmentContinuityPortChirho,
    line_chirho: &SignedSegmentManifestLineChirho,
) -> Result<VerifiedSegmentContinuityChirho> {
    let canonical_chirho = canonical_manifest_entry_bytes_chirho(&line_chirho.entry_chirho)?;
    port_chirho.verify_canonical_chirho(&canonical_chirho, &line_chirho.signature_chirho)?;
    Ok(VerifiedSegmentContinuityChirho {
        entry_chirho: line_chirho.entry_chirho.clone(),
    })
}
