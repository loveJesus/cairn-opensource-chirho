// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Segmented seqlog foundation: recompose sealed segments plus the active file as one virtual log.
//!
//! RC4 slice 1A — an INERT synthetic foundation. Nothing here rotates a production log; a family opts
//! in later (slice 1B) by routing its append AND every authoritative reader through this module. The
//! active `<name>.jsonl` file and its F1 head sidecar are UNCHANGED; this layer sits above them and
//! adds a base sequence drawn from an append-only signed manifest of sealed segments. With zero
//! sealed segments the whole thing reduces, byte-for-byte, to today's single-file behaviour.

pub mod continuity_chirho;
pub mod manifest_chirho;
pub mod manifest_head_chirho;
pub mod paths_chirho;
pub mod predecessor_index_chirho;
pub mod reader_chirho;
pub mod rotation_chirho;
pub mod storage_chirho;

#[cfg(test)]
mod reader_tests_chirho;
#[cfg(test)]
mod rotation_reader_tests_chirho;
#[cfg(test)]
mod test_support_chirho;
#[cfg(test)]
mod tests_chirho;

use serde::{Deserialize, Serialize};

/// Domain separator so a log-identity digest can never collide with another blake3 use.
const LOG_IDENTITY_DOMAIN_CHIRHO: &str = "cairn-segment-log-identity-v1-chirho";

/// A path-free, domain-separated logical identity for a segmented log. Every manifest entry binds
/// this digest, so the same sealed bytes can never be replayed under a different log's manifest, and
/// moving the store on disk never changes a log's identity (the file path is NOT part of it). The
/// caller owns uniqueness across distinct logs; this type only guarantees a stable, separated digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogIdentityChirho {
    logical_id_chirho: String,
}

impl LogIdentityChirho {
    /// Build an identity from a caller-chosen stable logical id (e.g. "ledger:tenant-a:v1-chirho").
    pub fn new_chirho(logical_id_chirho: impl Into<String>) -> Self {
        Self {
            logical_id_chirho: logical_id_chirho.into(),
        }
    }

    /// The stable logical id string.
    pub fn logical_id_chirho(&self) -> &str {
        &self.logical_id_chirho
    }

    /// The domain-separated blake3 digest bound into every manifest entry for this log.
    pub fn digest_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(LOG_IDENTITY_DOMAIN_CHIRHO.as_bytes());
        hasher_chirho.update(&[0u8]); // unambiguous boundary between domain and id
        hasher_chirho.update(self.logical_id_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

/// The final physical line (record plus its trailing newline) of a raw JSONL body; empty for empty.
/// Shared by rotation (to bind a segment's final-line digest) so the seam fact is computed one way.
pub(crate) fn final_physical_line_chirho(raw_chirho: &[u8]) -> &[u8] {
    if raw_chirho.is_empty() {
        return raw_chirho;
    }
    let trimmed_chirho = raw_chirho.strip_suffix(b"\n").unwrap_or(raw_chirho);
    let start_chirho = trimmed_chirho
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map(|position_chirho| position_chirho + 1)
        .unwrap_or(0);
    &raw_chirho[start_chirho..]
}

// ---- test-only count hooks that make the O(1)-warm base-seq invariant executable (mirror the F1
// seqlog-head scaling guards). Thread-local so parallel tests never pollute each other; compiled to
// no-ops in production so the hot path pays nothing. A WARM base-seq derivation must perform ZERO
// full manifest scans and ZERO sealed-segment reads regardless of how many segments exist; a COLD
// derivation registers exactly one manifest scan (its liveness twin). ----
#[cfg(test)]
thread_local! {
    static MANIFEST_SCAN_COUNT_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static SEGMENT_READ_COUNT_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Count one full manifest load+verify (the cold base-seq path).
#[cfg(test)]
pub(crate) fn note_manifest_scan_chirho() {
    MANIFEST_SCAN_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
}
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn note_manifest_scan_chirho() {}

/// Count one sealed segment file read (the segmented reader).
#[cfg(test)]
pub(crate) fn note_segment_read_chirho() {
    SEGMENT_READ_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
}
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn note_segment_read_chirho() {}

#[cfg(test)]
pub(crate) fn reset_segment_counts_chirho() {
    MANIFEST_SCAN_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(0));
    SEGMENT_READ_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(0));
}

#[cfg(test)]
pub(crate) fn manifest_scan_count_chirho() -> u64 {
    MANIFEST_SCAN_COUNT_CHIRHO.with(|count_chirho| count_chirho.get())
}

#[cfg(test)]
pub(crate) fn segment_read_count_chirho() -> u64 {
    SEGMENT_READ_COUNT_CHIRHO.with(|count_chirho| count_chirho.get())
}
