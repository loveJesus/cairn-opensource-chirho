// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Self-delimiting field framing for domain-separated digests. A `0x00`-DELIMITER scheme is
//! collision-safe only if every field is delimiter-free; the id newtypes here are unvalidated
//! `String`s, so a field containing `0x00` could collapse two different field-splits to the same
//! digest (the A1 money-audit finding, claude2 #4418). Length-prefix framing — `u64_le(len) || bytes`
//! per field, uniform for strings AND fixed-width integers — is unambiguous regardless of content, so
//! no unchecked delimiter invariant remains (gpt #4419).
//!
//! Severity was NOT uniform (gpt #4431): a nullifier collision is LIVENESS-only (a legitimate
//! cross-cluster mint falsely refused — the burn/equality checks still bind conservation), but a
//! [`LogIdChirho`](crate::LogIdChirho) collision would be account-identity ALIASING (a
//! conservation/authority hazard) if a downstream trusted the digest for path/index authority. Both
//! are closed HERE, PRE-B, so no exploit remains — but the combined defect is not categorically
//! liveness-only.

/// Update `hasher` with one length-framed field: `u64_le(bytes.len()) || bytes`. Composing these gives
/// a self-delimiting grammar — different field boundaries can never produce the same byte stream.
pub(crate) fn frame_field_chirho(hasher_chirho: &mut blake3::Hasher, bytes_chirho: &[u8]) {
    hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(bytes_chirho);
}
