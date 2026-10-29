// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Durable source-fence control for one tenant-ledger migration attempt.
//!
//! Signed checkpoints contain ordinary request coordinates only. Recovery re-verifies those
//! coordinates through the migration contract before they can become authority. Public code may
//! inspect and restore the startup barrier. Source-fence operations require a scoped session bound
//! to the exact mutable store and attenuated marker controller; the resident actor is the only
//! production owner that holds both.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

mod coordinator_chirho;
mod destination_authority_chirho;
mod model_chirho;
mod store_chirho;

pub use coordinator_chirho::{
    restore_tenant_migration_startup_chirho, AbortedTenantMigrationChirho,
    ActivatedTenantMigrationChirho, PreparedTenantMigrationChirho,
    TenantMigrationActivationInputsChirho, TenantMigrationCoordinatorRefusalChirho,
    TenantMigrationOperationInputsChirho, TenantMigrationOperationSessionChirho,
    TenantMigrationStartupBarrierChirho,
};
pub use destination_authority_chirho::{
    tenant_migration_destination_intent_digest_chirho,
    unsigned_tenant_migration_destination_message_chirho,
    verify_tenant_migration_destination_record_chirho,
    TenantMigrationDestinationAuthorityPortChirho, TenantMigrationDestinationIntentChirho,
    TenantMigrationDestinationRecordChirho, TenantMigrationDestinationRefusalChirho,
    VerifiedTenantMigrationDestinationChirho, MAX_TENANT_MIGRATION_DESTINATION_RECORD_BYTES_CHIRHO,
    TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO,
};
pub use model_chirho::{
    ActiveTenantMigrationChirho, TenantMigrationCheckpointChirho,
    TenantMigrationCommitOutcomeChirho, TenantMigrationControlSignerPortChirho,
    TenantMigrationCutClaimChirho, TenantMigrationHeadChirho,
    TenantMigrationOperationAuthorityBindingChirho, TenantMigrationOperationAuthorityRefusalChirho,
    TenantMigrationPhaseChirho, TenantMigrationStoreRefusalChirho,
    TENANT_MIGRATION_CHECKPOINT_SCHEMA_V1_CHIRHO, TENANT_MIGRATION_CHECKPOINT_SCHEMA_V2_CHIRHO,
    TENANT_MIGRATION_CONTROL_DOMAIN_V1_CHIRHO, TENANT_MIGRATION_HEAD_SCHEMA_V1_CHIRHO,
};
pub use store_chirho::TenantMigrationStoreChirho;

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
