// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Tenant root validation and store-key scoping for cairn-chirho hosts.

pub mod capacity_admission_chirho;
pub mod migration_completeness_chirho;
pub mod migration_eligibility_chirho;
#[cfg(test)]
#[path = "migration_eligibility_tests_chirho.rs"]
mod migration_eligibility_tests_chirho;
pub mod move_chirho;
pub mod root_surfaces_chirho;
pub mod self_containment_chirho;
pub mod single_customer_app_chirho;
pub mod surface_disposition_chirho;
pub mod tenant_chirho;
