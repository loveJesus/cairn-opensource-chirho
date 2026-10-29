// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The CF2 saga coordinator: a root-signed saga LOG (the third chain-core consumer) that
//! SEQUENCES two-phase escrow across real ledger journals — holds acquired in ascending canonical
//! order, then finalize-all or release-all — while the journals' admission fences stay the only
//! money gates (#4901: the coordinator is a CLIENT; its log never mints money authority).

pub mod coordinator_chirho;
pub mod log_chirho;
pub mod record_chirho;
pub mod shard_chirho;

#[cfg(test)]
mod coordinator_tests_chirho;
#[cfg(test)]
mod finality_e2e_tests_chirho;
#[cfg(test)]
mod record_tests_chirho;
#[cfg(test)]
mod shard_tests_chirho;
