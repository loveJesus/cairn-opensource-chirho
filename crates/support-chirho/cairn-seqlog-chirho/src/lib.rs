// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Shared store-wide JSONL append serialization helpers.

pub mod jsonl_read_chirho;
pub mod segment_chirho;
pub mod seqlog_chirho;
mod seqlog_head_chirho;

/// Re-exported for the migration disposition model, which DERIVES a head sidecar's disposition from
/// its log's. Only the suffix is exported — the sidecar's read/write path stays private, so nothing
/// outside this crate gains a way to author or trust a head.
pub use seqlog_head_chirho::SEQLOG_HEAD_SUFFIX_CHIRHO;
