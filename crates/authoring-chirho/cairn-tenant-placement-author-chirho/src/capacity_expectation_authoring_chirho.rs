// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Custody-separated authoring for one reviewed capacity/load admission generation.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/tenant-placement-authority-chirho.md`.

use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho::{
    existing_keypair_pubkey_hex_chirho, sign_with_existing_key_possession_chirho,
};
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::capacity_admission_expectation_chirho::{
    load_and_verify_tenant_migration_capacity_expectation_chirho,
    load_tenant_migration_capacity_expectation_record_for_authoring_chirho,
    tenant_migration_capacity_expectation_digest_chirho,
    unsigned_placement_capacity_expectation_message_chirho,
    unsigned_topology_grant_capacity_expectation_message_chirho,
    validate_tenant_migration_capacity_expectation_context_chirho,
    verify_placement_signed_tenant_migration_capacity_expectation_chirho,
    verify_tenant_migration_capacity_expectation_chirho,
    TenantMigrationCapacityExpectationChirho, TenantMigrationCapacityExpectationContextChirho,
    TENANT_MIGRATION_CAPACITY_EXPECTATION_PLACEMENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_CAPACITY_EXPECTATION_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_CAPACITY_EXPECTATION_TOPOLOGY_GRANT_DOMAIN_V1_CHIRHO,
};
use cairn_tenant_placement_authority_chirho::{
    load_and_verify_tenant_placement_record_chirho, VerifiedTenantPlacementChirho,
};
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::{
    load_tenant_migration_capacity_expectation_authoring_config_chirho,
    LoadedTenantMigrationCapacityExpectationAuthoringConfigChirho,
};
use std::path::{Path, PathBuf};

pub struct FinalTenantMigrationCapacityExpectationChirho {
    pub record_chirho: TenantMigrationCapacityExpectationChirho,
    pub configured_output_path_chirho: PathBuf,
}

pub fn author_placement_capacity_expectation_partial_chirho(
    cluster_config_path_chirho: &Path,
    expected_placement_population_digest_chirho: String,
    expected_capacity_load_snapshot_digest_chirho: String,
    placement_sign_root_chirho: &Path,
) -> Result<TenantMigrationCapacityExpectationChirho> {
    let config_chirho = load_tenant_migration_capacity_expectation_authoring_config_chirho(
        cluster_config_path_chirho,
    )
    .context("TenantMigrationCapacityExpectationConfigRefusedChirho")?;
    let placement_chirho = load_current_placement_chirho(&config_chirho)?;
    let mut record_chirho = TenantMigrationCapacityExpectationChirho {
        schema_chirho: TENANT_MIGRATION_CAPACITY_EXPECTATION_SCHEMA_V1_CHIRHO.to_string(),
        placement_signature_domain_chirho:
            TENANT_MIGRATION_CAPACITY_EXPECTATION_PLACEMENT_DOMAIN_V1_CHIRHO.to_string(),
        topology_grant_signature_domain_chirho:
            TENANT_MIGRATION_CAPACITY_EXPECTATION_TOPOLOGY_GRANT_DOMAIN_V1_CHIRHO.to_string(),
        expectation_revision_chirho: config_chirho.expectation_revision_chirho,
        cluster_config_blake3_chirho: config_chirho.config_blake3_chirho.clone(),
        tenant_id_chirho: config_chirho.tenant_id_chirho.clone(),
        placement_revision_chirho: placement_chirho.intent_chirho().revision_chirho,
        current_assignment_digest_chirho: placement_chirho.assignment_digest_chirho().to_string(),
        expected_placement_population_digest_chirho,
        expected_capacity_load_snapshot_digest_chirho,
        placement_key_id_chirho: config_chirho.placement_pubkey_hex_chirho.clone(),
        topology_grant_key_id_chirho: config_chirho.topology_grant_pubkey_hex_chirho.clone(),
        placement_sig_chirho: String::new(),
        topology_grant_sig_chirho: String::new(),
    };
    let context_chirho = expectation_context_chirho(&config_chirho, &placement_chirho);
    validate_tenant_migration_capacity_expectation_context_chirho(&record_chirho, context_chirho)
        .context("TenantMigrationCapacityExpectationMaterialRefusedChirho")?;
    require_signing_key_chirho(
        placement_sign_root_chirho,
        &config_chirho.placement_pubkey_hex_chirho,
        "TenantMigrationCapacityExpectationPlacementCustodyRefusedChirho",
    )?;
    let possession_chirho = sign_with_existing_key_possession_chirho(
        placement_sign_root_chirho,
        &unsigned_placement_capacity_expectation_message_chirho(&record_chirho)
            .context("TenantMigrationCapacityExpectationPlacementMessageRefusedChirho")?,
    )
    .context("TenantMigrationCapacityExpectationPlacementSignRefusedChirho")?;
    if possession_chirho.key_id_chirho() != config_chirho.placement_pubkey_hex_chirho {
        bail!("TenantMigrationCapacityExpectationPlacementCustodyChangedChirho");
    }
    record_chirho.placement_sig_chirho = possession_chirho.into_signature_hex_chirho();
    verify_placement_signed_tenant_migration_capacity_expectation_chirho(
        &record_chirho,
        context_chirho,
    )
    .context("TenantMigrationCapacityExpectationPlacementVerificationRefusedChirho")?;
    Ok(record_chirho)
}

pub fn cosign_topology_grant_capacity_expectation_chirho(
    cluster_config_path_chirho: &Path,
    partial_record_path_chirho: &Path,
    topology_grant_sign_root_chirho: &Path,
) -> Result<FinalTenantMigrationCapacityExpectationChirho> {
    let config_chirho = load_tenant_migration_capacity_expectation_authoring_config_chirho(
        cluster_config_path_chirho,
    )
    .context("TenantMigrationCapacityExpectationConfigRefusedChirho")?;
    let placement_chirho = load_current_placement_chirho(&config_chirho)?;
    let mut record_chirho = load_tenant_migration_capacity_expectation_record_for_authoring_chirho(
        partial_record_path_chirho,
    )
    .context("TenantMigrationCapacityExpectationPartialReadRefusedChirho")?;
    if !record_chirho.topology_grant_sig_chirho.is_empty() {
        bail!("TenantMigrationCapacityExpectationPartialAlreadyFinalChirho");
    }
    let context_chirho = expectation_context_chirho(&config_chirho, &placement_chirho);
    verify_placement_signed_tenant_migration_capacity_expectation_chirho(
        &record_chirho,
        context_chirho,
    )
    .context("TenantMigrationCapacityExpectationPlacementVerificationRefusedChirho")?;
    require_signing_key_chirho(
        topology_grant_sign_root_chirho,
        &config_chirho.topology_grant_pubkey_hex_chirho,
        "TenantMigrationCapacityExpectationTopologyCustodyRefusedChirho",
    )?;
    let possession_chirho = sign_with_existing_key_possession_chirho(
        topology_grant_sign_root_chirho,
        &unsigned_topology_grant_capacity_expectation_message_chirho(&record_chirho)
            .context("TenantMigrationCapacityExpectationTopologyMessageRefusedChirho")?,
    )
    .context("TenantMigrationCapacityExpectationTopologySignRefusedChirho")?;
    if possession_chirho.key_id_chirho() != config_chirho.topology_grant_pubkey_hex_chirho {
        bail!("TenantMigrationCapacityExpectationTopologyCustodyChangedChirho");
    }
    record_chirho.topology_grant_sig_chirho = possession_chirho.into_signature_hex_chirho();
    verify_tenant_migration_capacity_expectation_chirho(record_chirho.clone(), context_chirho)
        .context("TenantMigrationCapacityExpectationFinalVerificationRefusedChirho")?;
    Ok(FinalTenantMigrationCapacityExpectationChirho {
        record_chirho,
        configured_output_path_chirho: config_chirho.expectation_record_path_chirho,
    })
}

/// Reload and verify the private placement-signed partial without exercising second custody.
///
/// Workflow:
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.
pub fn verify_placement_signed_capacity_expectation_partial_chirho(
    cluster_config_path_chirho: &Path,
    partial_record_path_chirho: &Path,
) -> Result<TenantMigrationCapacityExpectationChirho> {
    let config_chirho = load_tenant_migration_capacity_expectation_authoring_config_chirho(
        cluster_config_path_chirho,
    )
    .context("TenantMigrationCapacityExpectationConfigRefusedChirho")?;
    let placement_chirho = load_current_placement_chirho(&config_chirho)?;
    let record_chirho = load_tenant_migration_capacity_expectation_record_for_authoring_chirho(
        partial_record_path_chirho,
    )
    .context("TenantMigrationCapacityExpectationPartialReadRefusedChirho")?;
    if !record_chirho.topology_grant_sig_chirho.is_empty() {
        bail!("TenantMigrationCapacityExpectationPartialAlreadyFinalChirho");
    }
    verify_placement_signed_tenant_migration_capacity_expectation_chirho(
        &record_chirho,
        expectation_context_chirho(&config_chirho, &placement_chirho),
    )
    .context("TenantMigrationCapacityExpectationPlacementVerificationRefusedChirho")?;
    Ok(record_chirho)
}

/// Reload the configured final expectation through the same ownership, path, context, and signature
/// verifier used by runtime composition.
///
/// Workflow:
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.
pub fn verify_configured_capacity_expectation_chirho(
    cluster_config_path_chirho: &Path,
) -> Result<FinalTenantMigrationCapacityExpectationChirho> {
    let config_chirho = load_tenant_migration_capacity_expectation_authoring_config_chirho(
        cluster_config_path_chirho,
    )
    .context("TenantMigrationCapacityExpectationConfigRefusedChirho")?;
    let placement_chirho = load_current_placement_chirho(&config_chirho)?;
    let verified_chirho = load_and_verify_tenant_migration_capacity_expectation_chirho(
        &config_chirho.expectation_record_path_chirho,
        &config_chirho.evidence_root_chirho,
        expectation_context_chirho(&config_chirho, &placement_chirho),
    )
    .context("TenantMigrationCapacityExpectationConfiguredVerificationRefusedChirho")?;
    Ok(FinalTenantMigrationCapacityExpectationChirho {
        record_chirho: verified_chirho.record_chirho().clone(),
        configured_output_path_chirho: config_chirho.expectation_record_path_chirho,
    })
}

pub fn capacity_expectation_digest_chirho(
    record_chirho: &TenantMigrationCapacityExpectationChirho,
) -> Result<String> {
    tenant_migration_capacity_expectation_digest_chirho(record_chirho)
        .context("TenantMigrationCapacityExpectationDigestRefusedChirho")
}

fn load_current_placement_chirho(
    config_chirho: &LoadedTenantMigrationCapacityExpectationAuthoringConfigChirho,
) -> Result<VerifiedTenantPlacementChirho> {
    let placement_chirho = load_and_verify_tenant_placement_record_chirho(
        &config_chirho.placement_record_path_chirho,
        &config_chirho.placement_pubkey_hex_chirho,
        &config_chirho.roster_operator_pubkey_hex_chirho,
        &config_chirho.geo_plan_pubkey_hex_chirho,
    )
    .context("TenantMigrationCapacityExpectationPlacementRefusedChirho")?;
    if placement_chirho.intent_chirho().tenant_id_chirho != config_chirho.tenant_id_chirho {
        bail!("TenantMigrationCapacityExpectationTenantRefusedChirho");
    }
    let local_binding_chirho = placement_chirho
        .assigned_node_chirho(&config_chirho.local_node_id_chirho)
        .ok_or_else(|| {
            anyhow::anyhow!("TenantMigrationCapacityExpectationLocalServingNodeRefusedChirho")
        })?;
    if local_binding_chirho.expected_cluster_config_blake3_chirho
        != config_chirho.config_blake3_chirho
    {
        bail!("TenantMigrationCapacityExpectationLocalPlacementBindingRefusedChirho");
    }
    Ok(placement_chirho)
}

fn expectation_context_chirho<'context_chirho>(
    config_chirho: &'context_chirho LoadedTenantMigrationCapacityExpectationAuthoringConfigChirho,
    placement_chirho: &'context_chirho VerifiedTenantPlacementChirho,
) -> TenantMigrationCapacityExpectationContextChirho<'context_chirho> {
    TenantMigrationCapacityExpectationContextChirho {
        expectation_revision_chirho: config_chirho.expectation_revision_chirho,
        cluster_config_blake3_chirho: &config_chirho.config_blake3_chirho,
        tenant_id_chirho: &config_chirho.tenant_id_chirho,
        placement_revision_chirho: placement_chirho.intent_chirho().revision_chirho,
        current_assignment_digest_chirho: placement_chirho.assignment_digest_chirho(),
        placement_key_id_chirho: &config_chirho.placement_pubkey_hex_chirho,
        topology_grant_key_id_chirho: &config_chirho.topology_grant_pubkey_hex_chirho,
    }
}

fn require_signing_key_chirho(
    sign_root_chirho: &Path,
    expected_key_chirho: &str,
    refusal_chirho: &str,
) -> Result<()> {
    let actual_key_chirho = existing_keypair_pubkey_hex_chirho(sign_root_chirho)
        .with_context(|| refusal_chirho.to_string())?;
    if actual_key_chirho != expected_key_chirho {
        bail!(refusal_chirho.to_string());
    }
    Ok(())
}
