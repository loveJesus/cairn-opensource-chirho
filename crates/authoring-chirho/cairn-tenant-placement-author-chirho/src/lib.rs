// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Local authoring for the three-stage tenant-placement authority flow.
//!
//! Intent authoring and final placement signing belong on the placement operator machine. Readiness
//! authoring runs on each assigned host against its actual tenant root, bounded custody-checked
//! cluster config, and existing node identity key. Its attenuated config reader carries no operator
//! token or elector handle. Runtime nodes consume only the signed output; they never receive
//! placement minting custody.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/tenant-placement-authority-chirho.md`.

pub mod authoring_chirho;
pub mod capacity_expectation_authoring_chirho;

#[cfg(test)]
mod tests_chirho;
