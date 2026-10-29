// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The desired-state plan: what bounds it, what produces it, and what names it uniquely.
//!
//! Grouped because a plan is meaningless without them all. The grant is the authority a plan must stay
//! inside, the grant ATTESTATION is the signature that makes that authority somebody else's rather than
//! the planner's own, the planner is what refuses a plan that does not stay inside, and the plan hash is
//! what stops evidence for one plan being presented as evidence for another. CF8 clauses 9 and 10 read
//! as one story, and this is where that story lives.

pub mod plan_hash_chirho;
pub mod topology_grant_attestation_chirho;
pub mod topology_grant_chirho;
pub mod topology_planner_chirho;
