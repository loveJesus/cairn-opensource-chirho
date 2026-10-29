// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Capacity accounting: what a node has, what is already promised, and whether the numbers are fresh.
//!
//! Grouped because they answer one question between them and are useless apart. Attestation says
//! where the node's allocatable figure came from and whether it was GRANTED rather than self-declared,
//! dominance says whether a node is big enough, reserved capacity says how much of it is already
//! spoken for, and measurement freshness says whether either number can be believed — CF8 clause 7
//! requires the three capacity sources kept distinct, and keeping them in one directory is how a
//! reader finds the rest after meeting the first.

pub mod capacity_attestation_chirho;
pub mod capacity_dominance_chirho;
pub mod measurement_freshness_chirho;
pub mod reserved_capacity_chirho;
pub mod usage_measurement_attestation_chirho;
