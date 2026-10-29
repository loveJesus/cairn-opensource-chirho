// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The signed append-only asset-kind registry log (CF1 deliverable): the records that PARAMETERIZE
//! money law — kind registration and prospective policy amendment — with the full chain core
//! (dense seq + prev binding + issuer AND registry signatures) and J0a wire rigor. K1 = records +
//! wire; the chain append/load, projection, and the production `KindRegistryViewChirho` follow.

pub mod chain_chirho;
pub mod record_chirho;
pub mod view_chirho;
pub mod wire_chirho;

#[cfg(test)]
mod chain_tests_chirho;
#[cfg(test)]
mod composition_tests_chirho;
#[cfg(test)]
mod wire_tests_chirho;
