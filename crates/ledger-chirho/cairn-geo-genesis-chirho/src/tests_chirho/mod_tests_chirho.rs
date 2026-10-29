// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Sharded fixture arms for the geo-genesis vocabulary and records.

#[path = "vocabulary_tests_chirho.rs"]
mod vocabulary_tests_chirho;

#[path = "plan_tests_chirho.rs"]
mod plan_tests_chirho;

#[path = "record_tests_chirho.rs"]
mod record_tests_chirho;

#[path = "authority_tests_chirho.rs"]
mod authority_tests_chirho;

#[path = "custody_tests_chirho.rs"]
mod custody_tests_chirho;

// `pub(crate)` (test-only, this whole tree is `#[cfg(test)]`) so the intent-guard backstop unit
// test — a child of `intent_guard_chirho`, where it reaches the private `write_marker_no_replace_chirho`
// — can reuse the verified-plan fixtures instead of rebuilding a whole verified plan inline.
#[path = "fixtures_chirho.rs"]
pub(crate) mod fixtures_chirho;

#[path = "acceptance_tests_chirho.rs"]
mod acceptance_tests_chirho;

#[path = "intent_guard_tests_chirho.rs"]
mod intent_guard_tests_chirho;

#[path = "custody_presence_tests_chirho.rs"]
mod custody_presence_tests_chirho;

#[path = "config_cross_bind_tests_chirho.rs"]
mod config_cross_bind_tests_chirho;

#[path = "dry_run_packet_tests_chirho.rs"]
mod dry_run_packet_tests_chirho;
