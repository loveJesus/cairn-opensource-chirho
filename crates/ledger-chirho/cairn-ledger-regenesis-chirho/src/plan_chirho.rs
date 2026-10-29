// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Canonical H3 plan loading. Raw bytes, canonical bytes, the required review digest, and the H2
//! host coordinates all converge before any namespace can be created.

use crate::bounded_file_chirho::read_bounded_regular_file_chirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use cairn_config_chirho::config_chirho::{
    load_config_chirho, validate_ledger_account_owner_chirho, LedgerHostConfigChirho,
    LedgerHostProjectionRouteConfigChirho,
};
use cairn_kind_registry_chirho::record_chirho::{KindPolicyBodyChirho, MintAuthorityRecordChirho};
use cairn_kind_registry_chirho::wire_chirho::derive_policy_ref_chirho;
use cairn_ledger_host_chirho::verify_host_ledger_config_custody_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub const LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO: &str = "ledger-regenesis-plan-v1-chirho";
const MAX_PLAN_IDENTIFIER_BYTES_CHIRHO: usize = 128;
const MAX_LEDGER_REGENESIS_PLAN_BYTES_CHIRHO: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisProjectionRoutePlanChirho {
    pub projection_name_chirho: String,
    pub head_path_chirho: String,
}

/// The complete reviewed coordinate set. Money amounts and timestamps live only here, never in
/// CLI flags; H3-B will consume the already-bound projection and monitor coordinates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisPlanV1Chirho {
    pub schema_chirho: String,
    pub fresh_parent_chirho: String,
    pub staging_parent_chirho: String,
    pub storage_namespace_chirho: String,
    pub monitor_evidence_namespace_chirho: String,
    pub monitor_evidence_path_chirho: String,
    pub money_group_id_chirho: String,
    pub cluster_id_chirho: String,
    pub journal_path_chirho: String,
    pub local_epoch_chirho: u64,
    pub kind_registry_path_chirho: String,
    pub kind_registry_id_chirho: String,
    pub projection_registry_path_chirho: String,
    pub projection_registry_id_chirho: String,
    pub source_registry_path_chirho: String,
    pub source_registry_id_chirho: String,
    pub projection_routes_chirho: Vec<LedgerRegenesisProjectionRoutePlanChirho>,
    pub monitor_cadence_ms_chirho: u64,
    pub issuer_principal_chirho: String,
    pub initial_owner_chirho: String,
    pub kind_id_chirho: String,
    pub initial_policy_chirho: KindPolicyBodyChirho,
    pub amended_policy_chirho: KindPolicyBodyChirho,
    pub initial_mint_amount_chirho: u64,
    pub genesis_physical_ms_chirho: u64,
    pub mint_physical_ms_chirho: u64,
}

pub fn canonical_plan_bytes_chirho(
    plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> LedgerRegenesisResultChirho<Vec<u8>> {
    serde_json::to_vec(plan_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PlanInvalidChirho)
}

pub fn plan_digest_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

pub(crate) struct VerifiedLedgerRegenesisPlanChirho {
    pub(crate) plan_chirho: LedgerRegenesisPlanV1Chirho,
    pub(crate) config_chirho: LedgerHostConfigChirho,
    pub(crate) selected_root_chirho: PathBuf,
    pub(crate) final_parent_chirho: PathBuf,
    pub(crate) staging_parent_chirho: PathBuf,
    pub(crate) storage_child_chirho: String,
    pub(crate) monitor_child_chirho: String,
    pub(crate) plan_digest_chirho: String,
}

impl fmt::Debug for VerifiedLedgerRegenesisPlanChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("VerifiedLedgerRegenesisPlanChirho")
            .field("schema_chirho", &self.plan_chirho.schema_chirho)
            .field("plan_digest_chirho", &self.plan_digest_chirho)
            .field("paths_chirho", &"<operator-paths-redacted-chirho>")
            .finish()
    }
}

pub(crate) fn load_verified_plan_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    plan_path_chirho: &Path,
    expected_plan_digest_chirho: &str,
) -> LedgerRegenesisResultChirho<VerifiedLedgerRegenesisPlanChirho> {
    let root_metadata_chirho = fs::symlink_metadata(selected_root_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::SelectedRootUnavailableChirho)?;
    if root_metadata_chirho.file_type().is_symlink() || !root_metadata_chirho.is_dir() {
        return Err(LedgerRegenesisRefusalChirho::SelectedRootUnavailableChirho);
    }
    verify_host_ledger_config_custody_chirho(selected_root_chirho, config_path_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigCustodyRefusedChirho)?;
    let runtime_config_chirho = load_config_chirho(config_path_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
    let config_chirho = runtime_config_chirho
        .ledger_host_chirho
        .ok_or(LedgerRegenesisRefusalChirho::ConfigUncomposedChirho)?;
    config_chirho
        .validate_chirho()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;

    validate_expected_digest_chirho(expected_plan_digest_chirho)?;
    let raw_plan_bytes_chirho =
        read_bounded_regular_file_chirho(plan_path_chirho, MAX_LEDGER_REGENESIS_PLAN_BYTES_CHIRHO)
            .map_err(|error_chirho| match error_chirho.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
                    LedgerRegenesisRefusalChirho::PlanUnavailableChirho
                }
                _ => LedgerRegenesisRefusalChirho::PlanNotRegularChirho,
            })?;
    let plan_chirho: LedgerRegenesisPlanV1Chirho =
        serde_json::from_slice(&raw_plan_bytes_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PlanInvalidChirho)?;
    if plan_chirho.schema_chirho != LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO {
        return Err(LedgerRegenesisRefusalChirho::PlanSchemaRefusedChirho);
    }
    let canonical_plan_bytes_chirho = canonical_plan_bytes_chirho(&plan_chirho)?;
    if raw_plan_bytes_chirho != canonical_plan_bytes_chirho {
        return Err(LedgerRegenesisRefusalChirho::PlanNonCanonicalChirho);
    }
    let raw_digest_chirho = plan_digest_chirho(&raw_plan_bytes_chirho);
    let canonical_digest_chirho = plan_digest_chirho(&canonical_plan_bytes_chirho);
    if raw_digest_chirho != canonical_digest_chirho
        || raw_digest_chirho != expected_plan_digest_chirho
    {
        return Err(LedgerRegenesisRefusalChirho::PlanDigestMismatchChirho);
    }

    validate_plan_coordinates_chirho(&plan_chirho)?;
    validate_plan_policy_chirho(&plan_chirho)?;
    validate_config_binding_chirho(&plan_chirho, &config_chirho)?;
    let (storage_child_chirho, monitor_child_chirho) =
        validate_namespace_layout_chirho(&plan_chirho)?;
    let selected_root_chirho = selected_root_chirho
        .canonicalize()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::SelectedRootUnavailableChirho)?;
    let final_parent_chirho = selected_root_chirho.join(&plan_chirho.fresh_parent_chirho);
    let staging_parent_chirho = selected_root_chirho.join(&plan_chirho.staging_parent_chirho);

    Ok(VerifiedLedgerRegenesisPlanChirho {
        plan_chirho,
        config_chirho,
        selected_root_chirho,
        final_parent_chirho,
        staging_parent_chirho,
        storage_child_chirho,
        monitor_child_chirho,
        plan_digest_chirho: raw_digest_chirho,
    })
}

fn validate_expected_digest_chirho(digest_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    if digest_chirho.len() != 64
        || !digest_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
    {
        return Err(LedgerRegenesisRefusalChirho::PlanDigestInvalidChirho);
    }
    Ok(())
}

/// Visible to the crate so the generic authoring path can RUN this law on a plan it derives
/// instead of growing a second copy that could drift away from what regenesis actually enforces.
pub(crate) fn validate_plan_coordinates_chirho(
    plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> LedgerRegenesisResultChirho<()> {
    for value_chirho in [
        &plan_chirho.fresh_parent_chirho,
        &plan_chirho.staging_parent_chirho,
        &plan_chirho.money_group_id_chirho,
        &plan_chirho.cluster_id_chirho,
        &plan_chirho.kind_registry_id_chirho,
        &plan_chirho.projection_registry_id_chirho,
        &plan_chirho.source_registry_id_chirho,
        &plan_chirho.issuer_principal_chirho,
        &plan_chirho.kind_id_chirho,
    ] {
        validate_lower_token_chirho(value_chirho)?;
    }
    validate_ledger_account_owner_chirho(&plan_chirho.initial_owner_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho)?;
    for value_chirho in [
        &plan_chirho.storage_namespace_chirho,
        &plan_chirho.monitor_evidence_namespace_chirho,
        &plan_chirho.monitor_evidence_path_chirho,
        &plan_chirho.journal_path_chirho,
        &plan_chirho.kind_registry_path_chirho,
        &plan_chirho.projection_registry_path_chirho,
        &plan_chirho.source_registry_path_chirho,
    ] {
        validate_logical_path_chirho(value_chirho)?;
    }
    if plan_chirho.projection_routes_chirho.is_empty() {
        return Err(LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho);
    }
    let mut projection_names_chirho = BTreeSet::new();
    let mut storage_paths_chirho = BTreeSet::from([
        plan_chirho.journal_path_chirho.as_str(),
        plan_chirho.kind_registry_path_chirho.as_str(),
        plan_chirho.projection_registry_path_chirho.as_str(),
        plan_chirho.source_registry_path_chirho.as_str(),
    ]);
    if storage_paths_chirho.len() != 4 {
        return Err(LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho);
    }
    for route_chirho in &plan_chirho.projection_routes_chirho {
        validate_lower_token_chirho(&route_chirho.projection_name_chirho)?;
        validate_logical_path_chirho(&route_chirho.head_path_chirho)?;
        if !projection_names_chirho.insert(route_chirho.projection_name_chirho.as_str())
            || !storage_paths_chirho.insert(route_chirho.head_path_chirho.as_str())
        {
            return Err(LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho);
        }
    }
    if plan_chirho.initial_mint_amount_chirho == 0
        || plan_chirho.genesis_physical_ms_chirho == 0
        || plan_chirho.mint_physical_ms_chirho <= plan_chirho.genesis_physical_ms_chirho
    {
        return Err(LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho);
    }
    Ok(())
}

/// The money-policy law's ONE home. The reviewed authoring document deliberately does not
/// re-implement it; the authoring path runs this function on the plan it derives.
pub(crate) fn validate_plan_policy_chirho(
    plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> LedgerRegenesisResultChirho<()> {
    for policy_chirho in [
        &plan_chirho.initial_policy_chirho,
        &plan_chirho.amended_policy_chirho,
    ] {
        validate_cf4_identifier_chirho(&policy_chirho.unit_chirho)?;
        validate_cf4_identifier_chirho(&policy_chirho.shard_attachment_chirho)?;
        if let Some(owner_chirho) = &policy_chirho.settlement_owner_chirho {
            validate_cf4_identifier_chirho(owner_chirho)?;
        }
        if !matches!(
            &policy_chirho.mint_authority_chirho,
            MintAuthorityRecordChirho::PlatformPolicyChirho { .. }
        ) {
            return Err(LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho);
        }
        if let Some(window_chirho) = policy_chirho.idempotency_window_chirho {
            if window_chirho.idempotency_horizon_ms_chirho
                < window_chirho.retry_finality_horizon_ms_chirho
            {
                return Err(LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho);
            }
        }
    }
    if plan_chirho.initial_policy_chirho == plan_chirho.amended_policy_chirho {
        return Err(LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho);
    }
    let initial_ref_chirho = derive_policy_ref_chirho(&plan_chirho.initial_policy_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho)?;
    let amended_ref_chirho = derive_policy_ref_chirho(&plan_chirho.amended_policy_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho)?;
    if initial_ref_chirho == amended_ref_chirho {
        return Err(LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho);
    }
    if let MintAuthorityRecordChirho::PlatformPolicyChirho {
        max_supply_chirho: Some(max_supply_chirho),
    } = &plan_chirho.initial_policy_chirho.mint_authority_chirho
    {
        if plan_chirho.initial_mint_amount_chirho > *max_supply_chirho {
            return Err(LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho);
        }
    }
    if let (Some(initial_window_chirho), Some(amended_window_chirho)) = (
        plan_chirho.initial_policy_chirho.idempotency_window_chirho,
        plan_chirho.amended_policy_chirho.idempotency_window_chirho,
    ) {
        if amended_window_chirho.idempotency_horizon_ms_chirho
            < initial_window_chirho.idempotency_horizon_ms_chirho
            || amended_window_chirho.retry_finality_horizon_ms_chirho
                < initial_window_chirho.retry_finality_horizon_ms_chirho
        {
            return Err(LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho);
        }
    }
    if plan_chirho
        .initial_policy_chirho
        .idempotency_window_chirho
        .is_some()
        && plan_chirho
            .amended_policy_chirho
            .idempotency_window_chirho
            .is_none()
    {
        return Err(LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho);
    }
    Ok(())
}

/// Run by the authoring path on the pair it derives, which is what turns "both artifacts come from
/// one document" from a claim into a checked property.
pub(crate) fn validate_config_binding_chirho(
    plan_chirho: &LedgerRegenesisPlanV1Chirho,
    config_chirho: &LedgerHostConfigChirho,
) -> LedgerRegenesisResultChirho<()> {
    let scalar_match_chirho = plan_chirho.storage_namespace_chirho
        == config_chirho.storage_namespace_chirho
        && plan_chirho.monitor_evidence_namespace_chirho
            == config_chirho.monitor_evidence_namespace_chirho
        && plan_chirho.monitor_evidence_path_chirho == config_chirho.monitor_evidence_path_chirho
        && plan_chirho.money_group_id_chirho == config_chirho.money_group_id_chirho
        && plan_chirho.cluster_id_chirho == config_chirho.cluster_id_chirho
        && plan_chirho.journal_path_chirho == config_chirho.journal_path_chirho
        && plan_chirho.local_epoch_chirho == config_chirho.local_epoch_chirho
        && plan_chirho.kind_registry_path_chirho == config_chirho.kind_registry_path_chirho
        && plan_chirho.kind_registry_id_chirho == config_chirho.kind_registry_id_chirho
        && plan_chirho.projection_registry_path_chirho
            == config_chirho.projection_registry_path_chirho
        && plan_chirho.projection_registry_id_chirho == config_chirho.projection_registry_id_chirho
        && plan_chirho.source_registry_path_chirho == config_chirho.source_registry_path_chirho
        && plan_chirho.source_registry_id_chirho == config_chirho.source_registry_id_chirho
        && plan_chirho.monitor_cadence_ms_chirho == config_chirho.monitor_cadence_ms_chirho
        && plan_chirho.issuer_principal_chirho == config_chirho.kind_issuer_chirho.principal_chirho;
    if !scalar_match_chirho
        || !routes_match_chirho(
            &plan_chirho.projection_routes_chirho,
            &config_chirho.projection_routes_chirho,
        )
    {
        return Err(LedgerRegenesisRefusalChirho::ConfigPlanMismatchChirho);
    }
    Ok(())
}

fn routes_match_chirho(
    plan_routes_chirho: &[LedgerRegenesisProjectionRoutePlanChirho],
    config_routes_chirho: &[LedgerHostProjectionRouteConfigChirho],
) -> bool {
    plan_routes_chirho.len() == config_routes_chirho.len()
        && plan_routes_chirho.iter().zip(config_routes_chirho).all(
            |(plan_route_chirho, config_route_chirho)| {
                plan_route_chirho.projection_name_chirho
                    == config_route_chirho.projection_name_chirho
                    && plan_route_chirho.head_path_chirho == config_route_chirho.head_path_chirho
            },
        )
}

pub(crate) fn validate_namespace_layout_chirho(
    plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> LedgerRegenesisResultChirho<(String, String)> {
    if plan_chirho.fresh_parent_chirho == plan_chirho.staging_parent_chirho
        || plan_chirho.fresh_parent_chirho.contains('/')
        || plan_chirho.staging_parent_chirho.contains('/')
    {
        return Err(LedgerRegenesisRefusalChirho::NamespaceLayoutRefusedChirho);
    }
    let storage_parts_chirho = plan_chirho
        .storage_namespace_chirho
        .split('/')
        .collect::<Vec<_>>();
    let monitor_parts_chirho = plan_chirho
        .monitor_evidence_namespace_chirho
        .split('/')
        .collect::<Vec<_>>();
    if storage_parts_chirho.len() != 2
        || monitor_parts_chirho.len() != 2
        || storage_parts_chirho[0] != plan_chirho.fresh_parent_chirho
        || monitor_parts_chirho[0] != plan_chirho.fresh_parent_chirho
        || storage_parts_chirho[1] == monitor_parts_chirho[1]
    {
        return Err(LedgerRegenesisRefusalChirho::NamespaceLayoutRefusedChirho);
    }
    Ok((
        storage_parts_chirho[1].to_owned(),
        monitor_parts_chirho[1].to_owned(),
    ))
}

fn validate_logical_path_chirho(value_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    if value_chirho.starts_with('/')
        || value_chirho
            .split('/')
            .any(|part_chirho| part_chirho.is_empty() || part_chirho == "." || part_chirho == "..")
    {
        return Err(LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho);
    }
    for part_chirho in value_chirho.split('/') {
        validate_lower_token_chirho(part_chirho)?;
    }
    Ok(())
}

fn validate_lower_token_chirho(value_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    validate_cf4_identifier_chirho(value_chirho)?;
    if !value_chirho.bytes().all(|byte_chirho| {
        byte_chirho.is_ascii_lowercase()
            || byte_chirho.is_ascii_digit()
            || matches!(byte_chirho, b'-' | b'_' | b':' | b'.')
    }) {
        return Err(LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho);
    }
    Ok(())
}

fn validate_cf4_identifier_chirho(value_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    if value_chirho.is_empty()
        || value_chirho.len() > MAX_PLAN_IDENTIFIER_BYTES_CHIRHO
        || value_chirho.chars().any(|char_chirho| {
            char_chirho.is_control() || char_chirho.is_whitespace() || char_chirho == '@'
        })
    {
        return Err(LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho);
    }
    Ok(())
}
