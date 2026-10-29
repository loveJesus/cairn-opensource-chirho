// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Two-party reviewed expectations for one capacity-driven tenant migration.
//!
//! The population digest cannot live in the cluster config whose exact hash every placement receipt
//! binds: the population digest depends on those receipts, so putting it there creates the fixed
//! point `population -> config hash -> placement record -> population`. This record is a signed
//! statement ABOUT the config instead. The config binds only a locator and an operator-authored
//! expectation revision; it never binds this record's bytes or digest.
//!
//! Two signatures preserve independent review. The placement authority selects the exact placement
//! population, while the distinct topology-grant authority approves the aggregate infrastructure
//! snapshot used for admission. A locator selects bytes; these signatures grant authority.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

use cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho;
use cairn_tenant_chirho::tenant_chirho::validate_tenant_id_chirho;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

pub const TENANT_MIGRATION_CAPACITY_EXPECTATION_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-capacity-expectation-v1-chirho";
pub const TENANT_MIGRATION_CAPACITY_EXPECTATION_PLACEMENT_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-capacity-expectation-placement-signature-v1-chirho";
pub const TENANT_MIGRATION_CAPACITY_EXPECTATION_TOPOLOGY_GRANT_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-capacity-expectation-topology-grant-signature-v1-chirho";
pub const TENANT_MIGRATION_CAPACITY_EXPECTATION_MAX_BYTES_CHIRHO: u64 = 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationCapacityExpectationChirho {
    pub schema_chirho: String,
    pub placement_signature_domain_chirho: String,
    pub topology_grant_signature_domain_chirho: String,
    /// Operator-authored before placement receipts. Changing it moves the exact config hash and
    /// therefore requires a fresh multi-party placement generation without depending on P or S.
    pub expectation_revision_chirho: u64,
    pub cluster_config_blake3_chirho: String,
    pub tenant_id_chirho: String,
    pub placement_revision_chirho: u64,
    pub current_assignment_digest_chirho: String,
    pub expected_placement_population_digest_chirho: String,
    pub expected_capacity_load_snapshot_digest_chirho: String,
    pub placement_key_id_chirho: String,
    pub topology_grant_key_id_chirho: String,
    pub placement_sig_chirho: String,
    pub topology_grant_sig_chirho: String,
}

#[derive(Clone, Copy, Debug)]
pub struct TenantMigrationCapacityExpectationContextChirho<'context_chirho> {
    pub expectation_revision_chirho: u64,
    pub cluster_config_blake3_chirho: &'context_chirho str,
    pub tenant_id_chirho: &'context_chirho str,
    pub placement_revision_chirho: u64,
    pub current_assignment_digest_chirho: &'context_chirho str,
    pub placement_key_id_chirho: &'context_chirho str,
    pub topology_grant_key_id_chirho: &'context_chirho str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantMigrationCapacityExpectationRefusalChirho {
    RecordAbsentChirho,
    RecordUnreadableChirho,
    RecordEntryTypeChirho,
    RecordTooLargeChirho,
    RecordIdentityUnstableChirho,
    RecordCustodyChirho,
    RecordInsideEvidenceRootChirho,
    RecordMalformedChirho,
    SchemaChirho,
    PlacementSignatureDomainChirho,
    TopologyGrantSignatureDomainChirho,
    ExpectationRevisionChirho,
    ConfigBindingChirho,
    TenantBindingChirho,
    PlacementRevisionBindingChirho,
    CurrentAssignmentBindingChirho,
    PopulationDigestChirho,
    CapacityLoadSnapshotDigestChirho,
    PlacementKeyChirho,
    TopologyGrantKeyChirho,
    AuthorityKeySeparationChirho,
    PlacementSignatureChirho,
    TopologyGrantSignatureChirho,
}

impl fmt::Display for TenantMigrationCapacityExpectationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{self:?}")
    }
}

impl std::error::Error for TenantMigrationCapacityExpectationRefusalChirho {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTenantMigrationCapacityExpectationChirho {
    record_chirho: TenantMigrationCapacityExpectationChirho,
}

impl VerifiedTenantMigrationCapacityExpectationChirho {
    pub fn record_chirho(&self) -> &TenantMigrationCapacityExpectationChirho {
        &self.record_chirho
    }

    pub fn expected_placement_population_digest_chirho(&self) -> &str {
        &self
            .record_chirho
            .expected_placement_population_digest_chirho
    }

    pub fn expected_capacity_load_snapshot_digest_chirho(&self) -> &str {
        &self
            .record_chirho
            .expected_capacity_load_snapshot_digest_chirho
    }

    pub fn expectation_revision_chirho(&self) -> u64 {
        self.record_chirho.expectation_revision_chirho
    }
}

/// Canonical payload both independent authorities approve. Both signatures are cleared, so signing
/// order cannot change the payload and neither signature recursively contains the other.
pub fn canonical_tenant_migration_capacity_expectation_payload_chirho(
    record_chirho: &TenantMigrationCapacityExpectationChirho,
) -> Result<Vec<u8>, TenantMigrationCapacityExpectationRefusalChirho> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.placement_sig_chirho.clear();
    unsigned_chirho.topology_grant_sig_chirho.clear();
    serde_json::to_vec(&unsigned_chirho).map_err(|_error_chirho| {
        TenantMigrationCapacityExpectationRefusalChirho::RecordMalformedChirho
    })
}

pub fn unsigned_placement_capacity_expectation_message_chirho(
    record_chirho: &TenantMigrationCapacityExpectationChirho,
) -> Result<Vec<u8>, TenantMigrationCapacityExpectationRefusalChirho> {
    role_separated_message_chirho(
        TENANT_MIGRATION_CAPACITY_EXPECTATION_PLACEMENT_DOMAIN_V1_CHIRHO,
        &canonical_tenant_migration_capacity_expectation_payload_chirho(record_chirho)?,
    )
}

pub fn unsigned_topology_grant_capacity_expectation_message_chirho(
    record_chirho: &TenantMigrationCapacityExpectationChirho,
) -> Result<Vec<u8>, TenantMigrationCapacityExpectationRefusalChirho> {
    role_separated_message_chirho(
        TENANT_MIGRATION_CAPACITY_EXPECTATION_TOPOLOGY_GRANT_DOMAIN_V1_CHIRHO,
        &canonical_tenant_migration_capacity_expectation_payload_chirho(record_chirho)?,
    )
}

fn role_separated_message_chirho(
    domain_chirho: &str,
    canonical_payload_chirho: &[u8],
) -> Result<Vec<u8>, TenantMigrationCapacityExpectationRefusalChirho> {
    let mut message_chirho =
        Vec::with_capacity(domain_chirho.len() + 1 + canonical_payload_chirho.len());
    message_chirho.extend_from_slice(domain_chirho.as_bytes());
    message_chirho.push(0);
    message_chirho.extend_from_slice(canonical_payload_chirho);
    Ok(message_chirho)
}

pub fn tenant_migration_capacity_expectation_digest_chirho(
    record_chirho: &TenantMigrationCapacityExpectationChirho,
) -> Result<String, TenantMigrationCapacityExpectationRefusalChirho> {
    serde_json::to_vec(record_chirho)
        .map(|bytes_chirho| blake3::hash(&bytes_chirho).to_hex().to_string())
        .map_err(|_error_chirho| {
            TenantMigrationCapacityExpectationRefusalChirho::RecordMalformedChirho
        })
}

/// Read one private partial or final expectation for offline custody-separated authoring.
///
/// This proves only bounded identity-stable file input and decoding. Callers must run the matching
/// signature/context verifier before trusting any field.
pub fn load_tenant_migration_capacity_expectation_record_for_authoring_chirho(
    path_chirho: &Path,
) -> Result<TenantMigrationCapacityExpectationChirho, TenantMigrationCapacityExpectationRefusalChirho>
{
    let metadata_chirho = expectation_record_metadata_chirho(path_chirho)?;
    if !private_mode_chirho(&metadata_chirho) {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::RecordCustodyChirho);
    }
    read_and_decode_expectation_record_chirho(path_chirho)
}

/// Verify the first custody step before the topology-grant holder sees or co-signs the record.
pub fn verify_placement_signed_tenant_migration_capacity_expectation_chirho(
    record_chirho: &TenantMigrationCapacityExpectationChirho,
    context_chirho: TenantMigrationCapacityExpectationContextChirho<'_>,
) -> Result<(), TenantMigrationCapacityExpectationRefusalChirho> {
    validate_tenant_migration_capacity_expectation_context_chirho(record_chirho, context_chirho)?;
    let unsigned_chirho = unsigned_placement_capacity_expectation_message_chirho(record_chirho)?;
    if !verify_with_pubkey_chirho(
        context_chirho.placement_key_id_chirho,
        &unsigned_chirho,
        &record_chirho.placement_sig_chirho,
    )
    .unwrap_or(false)
    {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::PlacementSignatureChirho);
    }
    Ok(())
}

pub fn verify_tenant_migration_capacity_expectation_chirho(
    record_chirho: TenantMigrationCapacityExpectationChirho,
    context_chirho: TenantMigrationCapacityExpectationContextChirho<'_>,
) -> Result<
    VerifiedTenantMigrationCapacityExpectationChirho,
    TenantMigrationCapacityExpectationRefusalChirho,
> {
    verify_placement_signed_tenant_migration_capacity_expectation_chirho(
        &record_chirho,
        context_chirho,
    )?;
    let unsigned_chirho =
        unsigned_topology_grant_capacity_expectation_message_chirho(&record_chirho)?;
    if !verify_with_pubkey_chirho(
        context_chirho.topology_grant_key_id_chirho,
        &unsigned_chirho,
        &record_chirho.topology_grant_sig_chirho,
    )
    .unwrap_or(false)
    {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::TopologyGrantSignatureChirho);
    }
    Ok(VerifiedTenantMigrationCapacityExpectationChirho { record_chirho })
}

pub fn load_and_verify_tenant_migration_capacity_expectation_chirho(
    path_chirho: &Path,
    evidence_root_chirho: &Path,
    context_chirho: TenantMigrationCapacityExpectationContextChirho<'_>,
) -> Result<
    VerifiedTenantMigrationCapacityExpectationChirho,
    TenantMigrationCapacityExpectationRefusalChirho,
> {
    let metadata_chirho = expectation_record_metadata_chirho(path_chirho)?;
    if !private_mode_chirho(&metadata_chirho) {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::RecordCustodyChirho);
    }
    let root_metadata_chirho =
        std::fs::symlink_metadata(evidence_root_chirho).map_err(|_error_chirho| {
            TenantMigrationCapacityExpectationRefusalChirho::RecordUnreadableChirho
        })?;
    if !same_owner_chirho(&metadata_chirho, &root_metadata_chirho) {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::RecordCustodyChirho);
    }
    let canonical_root_chirho =
        std::fs::canonicalize(evidence_root_chirho).map_err(|_error_chirho| {
            TenantMigrationCapacityExpectationRefusalChirho::RecordUnreadableChirho
        })?;
    let canonical_record_chirho = std::fs::canonicalize(path_chirho).map_err(|_error_chirho| {
        TenantMigrationCapacityExpectationRefusalChirho::RecordUnreadableChirho
    })?;
    if canonical_record_chirho.starts_with(&canonical_root_chirho) {
        return Err(
            TenantMigrationCapacityExpectationRefusalChirho::RecordInsideEvidenceRootChirho,
        );
    }
    let record_chirho = read_and_decode_expectation_record_chirho(path_chirho)?;
    verify_tenant_migration_capacity_expectation_chirho(record_chirho, context_chirho)
}

fn expectation_record_metadata_chirho(
    path_chirho: &Path,
) -> Result<std::fs::Metadata, TenantMigrationCapacityExpectationRefusalChirho> {
    let metadata_chirho = match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) => metadata_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Err(TenantMigrationCapacityExpectationRefusalChirho::RecordAbsentChirho)
        }
        Err(_error_chirho) => {
            return Err(TenantMigrationCapacityExpectationRefusalChirho::RecordUnreadableChirho)
        }
    };
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::RecordEntryTypeChirho);
    }
    if metadata_chirho.len() > TENANT_MIGRATION_CAPACITY_EXPECTATION_MAX_BYTES_CHIRHO {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::RecordTooLargeChirho);
    }
    Ok(metadata_chirho)
}

fn read_and_decode_expectation_record_chirho(
    path_chirho: &Path,
) -> Result<TenantMigrationCapacityExpectationChirho, TenantMigrationCapacityExpectationRefusalChirho>
{
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        path_chirho,
        TENANT_MIGRATION_CAPACITY_EXPECTATION_MAX_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| {
        if error_chirho.kind() == std::io::ErrorKind::InvalidData {
            TenantMigrationCapacityExpectationRefusalChirho::RecordIdentityUnstableChirho
        } else {
            TenantMigrationCapacityExpectationRefusalChirho::RecordUnreadableChirho
        }
    })?;
    serde_json::from_slice(&bytes_chirho).map_err(|_error_chirho| {
        TenantMigrationCapacityExpectationRefusalChirho::RecordMalformedChirho
    })
}

/// Validate every unsigned field against externally supplied config and resident-placement context.
/// Authoring calls this before any authority signs; runtime verification calls it before signatures.
pub fn validate_tenant_migration_capacity_expectation_context_chirho(
    record_chirho: &TenantMigrationCapacityExpectationChirho,
    context_chirho: TenantMigrationCapacityExpectationContextChirho<'_>,
) -> Result<(), TenantMigrationCapacityExpectationRefusalChirho> {
    if record_chirho.schema_chirho != TENANT_MIGRATION_CAPACITY_EXPECTATION_SCHEMA_V1_CHIRHO {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::SchemaChirho);
    }
    if record_chirho.placement_signature_domain_chirho
        != TENANT_MIGRATION_CAPACITY_EXPECTATION_PLACEMENT_DOMAIN_V1_CHIRHO
    {
        return Err(
            TenantMigrationCapacityExpectationRefusalChirho::PlacementSignatureDomainChirho,
        );
    }
    if record_chirho.topology_grant_signature_domain_chirho
        != TENANT_MIGRATION_CAPACITY_EXPECTATION_TOPOLOGY_GRANT_DOMAIN_V1_CHIRHO
    {
        return Err(
            TenantMigrationCapacityExpectationRefusalChirho::TopologyGrantSignatureDomainChirho,
        );
    }
    if record_chirho.expectation_revision_chirho == 0
        || record_chirho.expectation_revision_chirho != context_chirho.expectation_revision_chirho
    {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::ExpectationRevisionChirho);
    }
    if !nonzero_lower_hex_digest_chirho(&record_chirho.cluster_config_blake3_chirho)
        || record_chirho.cluster_config_blake3_chirho != context_chirho.cluster_config_blake3_chirho
    {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::ConfigBindingChirho);
    }
    if validate_tenant_id_chirho(&record_chirho.tenant_id_chirho).is_err()
        || record_chirho.tenant_id_chirho != context_chirho.tenant_id_chirho
    {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::TenantBindingChirho);
    }
    if record_chirho.placement_revision_chirho != context_chirho.placement_revision_chirho {
        return Err(
            TenantMigrationCapacityExpectationRefusalChirho::PlacementRevisionBindingChirho,
        );
    }
    if !nonzero_lower_hex_digest_chirho(&record_chirho.current_assignment_digest_chirho)
        || record_chirho.current_assignment_digest_chirho
            != context_chirho.current_assignment_digest_chirho
    {
        return Err(
            TenantMigrationCapacityExpectationRefusalChirho::CurrentAssignmentBindingChirho,
        );
    }
    if !nonzero_lower_hex_digest_chirho(&record_chirho.expected_placement_population_digest_chirho)
    {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::PopulationDigestChirho);
    }
    if !nonzero_lower_hex_digest_chirho(
        &record_chirho.expected_capacity_load_snapshot_digest_chirho,
    ) {
        return Err(
            TenantMigrationCapacityExpectationRefusalChirho::CapacityLoadSnapshotDigestChirho,
        );
    }
    if !nonzero_lower_hex_digest_chirho(context_chirho.placement_key_id_chirho)
        || record_chirho.placement_key_id_chirho != context_chirho.placement_key_id_chirho
    {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::PlacementKeyChirho);
    }
    if !nonzero_lower_hex_digest_chirho(context_chirho.topology_grant_key_id_chirho)
        || record_chirho.topology_grant_key_id_chirho != context_chirho.topology_grant_key_id_chirho
    {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::TopologyGrantKeyChirho);
    }
    if context_chirho.placement_key_id_chirho == context_chirho.topology_grant_key_id_chirho {
        return Err(TenantMigrationCapacityExpectationRefusalChirho::AuthorityKeySeparationChirho);
    }
    Ok(())
}

fn nonzero_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
        && value_chirho.bytes().any(|byte_chirho| byte_chirho != b'0')
}

#[cfg(unix)]
fn private_mode_chirho(metadata_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata_chirho.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_mode_chirho(_metadata_chirho: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn same_owner_chirho(left_chirho: &std::fs::Metadata, right_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left_chirho.uid() == right_chirho.uid()
}

#[cfg(not(unix))]
fn same_owner_chirho(_left_chirho: &std::fs::Metadata, _right_chirho: &std::fs::Metadata) -> bool {
    true
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
