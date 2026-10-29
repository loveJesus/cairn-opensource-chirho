// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fail-closed production join between tenant placement, roster, local root identity, and geo role.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/tenant-placement-authority-chirho.md`.

use anyhow::{bail, Context, Result};
use cairn_ledger_host_chirho::TenantMigrationCapacityAdmissionCompositionChirho;
use cairn_ledger_tenant_migration_chirho::VerifiedTenantMigrationRootChirho;
use cairn_roster_config_chirho::derive_tenant_placement_elector_config_chirho;
use cairn_tenant_chirho::capacity_admission_chirho::TenantCapacityDemandChirho;
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::capacity_admission_expectation_chirho::{
    load_and_verify_tenant_migration_capacity_expectation_chirho,
    TenantMigrationCapacityExpectationContextChirho,
};
use cairn_tenant_placement_authority_chirho::capacity_admission_impl_chirho::{
    TenantCapacityEvidenceConfigChirho, VerifiedTenantCapacityAdmissionChirho,
};
use cairn_tenant_placement_authority_chirho::{
    load_and_verify_tenant_placement_record_chirho, TenantPlacementNodeBindingChirho,
    VerifiedTenantPlacementChirho, TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO,
};
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::LoadedClusterNodeConfigChirho;
use cairn_writer_elector_http_chirho::membership_control_chirho::{
    MembershipTargetAuthorityChirho, TenantPlacementAuthorityConfigChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::path::Path;
use std::sync::Arc;

/// Compose the signed-evidence gate in the tenant-migration authority workflow:
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.
pub(super) fn compose_tenant_migration_capacity_admission_chirho(
    loaded_cluster_chirho: &LoadedClusterNodeConfigChirho,
    resident_placement_chirho: Option<Arc<VerifiedTenantPlacementChirho>>,
) -> Result<Option<TenantMigrationCapacityAdmissionCompositionChirho>> {
    let Some(capacity_config_chirho) = loaded_cluster_chirho
        .tenant_migration_capacity_chirho
        .as_ref()
    else {
        return Ok(None);
    };
    let Some(resident_placement_chirho) = resident_placement_chirho else {
        return Ok(None);
    };
    let placement_config_chirho = loaded_cluster_chirho
        .tenant_placement_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TenantMigrationCapacityPlacementAuthorityMissingChirho"))?;
    let roster_config_chirho = loaded_cluster_chirho
        .roster_authority_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TenantMigrationCapacityRosterAuthorityMissingChirho"))?;
    let expectation_chirho = load_and_verify_tenant_migration_capacity_expectation_chirho(
        &capacity_config_chirho.expectation_record_path_chirho,
        &capacity_config_chirho.evidence_root_chirho,
        TenantMigrationCapacityExpectationContextChirho {
            expectation_revision_chirho: capacity_config_chirho.expectation_revision_chirho,
            cluster_config_blake3_chirho: &loaded_cluster_chirho.config_blake3_chirho,
            tenant_id_chirho: &resident_placement_chirho.intent_chirho().tenant_id_chirho,
            placement_revision_chirho: resident_placement_chirho.intent_chirho().revision_chirho,
            current_assignment_digest_chirho: resident_placement_chirho.assignment_digest_chirho(),
            placement_key_id_chirho: &placement_config_chirho.placement_pubkey_hex_chirho,
            topology_grant_key_id_chirho: &capacity_config_chirho.topology_grant_pubkey_hex_chirho,
        },
    )
    .map_err(|refusal_chirho| {
        anyhow::anyhow!("TenantMigrationCapacityExpectationRefusedChirho:{refusal_chirho:?}")
    })?;
    let demand_chirho = TenantCapacityDemandChirho {
        cpu_millicores_chirho: resident_placement_chirho
            .intent_chirho()
            .demand_chirho
            .cpu_millicores_chirho,
        memory_bytes_chirho: resident_placement_chirho
            .intent_chirho()
            .demand_chirho
            .memory_bytes_chirho,
        durable_bytes_chirho: resident_placement_chirho
            .intent_chirho()
            .demand_chirho
            .durable_bytes_chirho,
    };
    let headroom_chirho = TenantCapacityDemandChirho {
        cpu_millicores_chirho: capacity_config_chirho.headroom_chirho.cpu_millicores_chirho,
        memory_bytes_chirho: capacity_config_chirho.headroom_chirho.memory_bytes_chirho,
        durable_bytes_chirho: capacity_config_chirho.headroom_chirho.durable_bytes_chirho,
    };
    let adapter_chirho = VerifiedTenantCapacityAdmissionChirho::new_chirho(
        TenantCapacityEvidenceConfigChirho {
            evidence_root_chirho: capacity_config_chirho.evidence_root_chirho.clone(),
            expected_placement_population_digest_chirho: expectation_chirho
                .expected_placement_population_digest_chirho()
                .to_string(),
            expected_capacity_load_snapshot_digest_chirho: expectation_chirho
                .expected_capacity_load_snapshot_digest_chirho()
                .to_string(),
            placement_pubkey_hex_chirho: placement_config_chirho
                .placement_pubkey_hex_chirho
                .clone(),
            roster_operator_pubkey_hex_chirho: roster_config_chirho
                .operator_pubkey_hex_chirho
                .clone(),
            geo_plan_pubkey_hex_chirho: placement_config_chirho.geo_plan_pubkey_hex_chirho.clone(),
            capacity_registrar_pubkey_hex_chirho: capacity_config_chirho
                .capacity_registrar_pubkey_hex_chirho
                .clone(),
            lifecycle_pubkey_hex_chirho: capacity_config_chirho.lifecycle_pubkey_hex_chirho.clone(),
            topology_grant_pubkey_hex_chirho: capacity_config_chirho
                .topology_grant_pubkey_hex_chirho
                .clone(),
            budget_pubkey_hex_chirho: capacity_config_chirho.budget_pubkey_hex_chirho.clone(),
            node_measurement_pubkeys_chirho: capacity_config_chirho
                .node_measurement_pubkeys_chirho
                .clone(),
        },
        resident_placement_chirho,
    )
    .map_err(|refusal_chirho| {
        anyhow::anyhow!("TenantMigrationCapacityAdapterRefusedChirho:{refusal_chirho:?}")
    })?;
    TenantMigrationCapacityAdmissionCompositionChirho::new_chirho(
        Arc::new(adapter_chirho),
        demand_chirho,
        headroom_chirho,
    )
    .map(Some)
    .map_err(|refusal_chirho| {
        anyhow::anyhow!("TenantMigrationCapacityCompositionRefusedChirho:{refusal_chirho:?}")
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GeoTenantPlacementRoleChirho {
    VoterChirho,
    HeldObserverChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GeoVoterPlacementAdmissionChirho {
    ProductionRequiredChirho,
    ExplicitTestkindRosterWideChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeoVoterStartupRolePolicyChirho {
    PreserveElectedRoleChirho,
    RetiringTransportOnlyChirho,
}

#[derive(Debug)]
pub(super) struct VerifiedGeoVoterStartupPolicyChirho {
    role_policy_chirho: GeoVoterStartupRolePolicyChirho,
    placement_chirho: Option<Arc<VerifiedTenantPlacementChirho>>,
}

impl VerifiedGeoVoterStartupPolicyChirho {
    fn without_placement_chirho(role_policy_chirho: GeoVoterStartupRolePolicyChirho) -> Self {
        Self {
            role_policy_chirho,
            placement_chirho: None,
        }
    }

    pub(super) fn select_voter_startup_role_chirho(
        &self,
        elected_role_chirho: super::GeoVoterStartupRoleChirho,
    ) -> super::GeoVoterStartupRoleChirho {
        match self.role_policy_chirho {
            GeoVoterStartupRolePolicyChirho::PreserveElectedRoleChirho => elected_role_chirho,
            GeoVoterStartupRolePolicyChirho::RetiringTransportOnlyChirho => {
                super::GeoVoterStartupRoleChirho::NonResidentChirho(
                    super::GeoNonResidentVoterRoleChirho::RetiringTransportOnlyChirho,
                )
            }
        }
    }

    pub(super) fn permits_local_resident_chirho(&self) -> bool {
        self.role_policy_chirho == GeoVoterStartupRolePolicyChirho::PreserveElectedRoleChirho
    }

    /// Only an assigned production tenant voter can reach the mirror composition. Retiring voters
    /// remain transport participants, and root-wide/test-kind admissions carry no placement.
    pub(super) fn resident_placement_chirho(&self) -> Option<Arc<VerifiedTenantPlacementChirho>> {
        if self.role_policy_chirho != GeoVoterStartupRolePolicyChirho::PreserveElectedRoleChirho {
            return None;
        }
        self.placement_chirho.as_ref().map(Arc::clone)
    }
}

/// Opaque result of the signed placement/roster/local-role join.
///
/// An unassigned voter may retain election transport long enough to converge itself out, but this
/// value ensures the elector's temporary local-owner result can never mint a resident actor for it.
#[derive(Debug)]
pub(super) enum VerifiedGeoTenantPlacementStartupChirho {
    VoterChirho {
        local_node_assigned_chirho: bool,
        placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    },
    HeldObserverChirho,
}

impl VerifiedGeoTenantPlacementStartupChirho {
    fn into_voter_policy_chirho(self) -> Result<VerifiedGeoVoterStartupPolicyChirho> {
        match self {
            Self::VoterChirho {
                local_node_assigned_chirho: true,
                placement_chirho,
            } => Ok(VerifiedGeoVoterStartupPolicyChirho {
                role_policy_chirho: GeoVoterStartupRolePolicyChirho::PreserveElectedRoleChirho,
                placement_chirho: Some(placement_chirho),
            }),
            Self::VoterChirho {
                local_node_assigned_chirho: false,
                placement_chirho,
            } => Ok(VerifiedGeoVoterStartupPolicyChirho {
                role_policy_chirho: GeoVoterStartupRolePolicyChirho::RetiringTransportOnlyChirho,
                placement_chirho: Some(placement_chirho),
            }),
            Self::HeldObserverChirho => {
                bail!("GeoTenantPlacementVoterPolicyUnavailableChirho")
            }
        }
    }
}

pub(super) fn verify_geo_voter_startup_policy_chirho(
    loaded_chirho: &LoadedClusterNodeConfigChirho,
    selected_root_chirho: &Path,
    admission_chirho: GeoVoterPlacementAdmissionChirho,
) -> Result<VerifiedGeoVoterStartupPolicyChirho> {
    require_local_cluster_role_chirho(loaded_chirho, GeoTenantPlacementRoleChirho::VoterChirho)?;
    let control_chirho = loaded_chirho
        .cluster_chirho
        .membership_control_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("GeoTenantPlacementControlUnavailableChirho"))?;
    match (
        &loaded_chirho.cluster_chirho.group_chirho,
        &control_chirho.target_authority_chirho,
    ) {
        (
            ConsistencyGroupIdChirho::TenantChirho { .. },
            MembershipTargetAuthorityChirho::TenantPlacementChirho(_),
        ) => verify_geo_tenant_placement_startup_chirho(
            loaded_chirho,
            selected_root_chirho,
            GeoTenantPlacementRoleChirho::VoterChirho,
        )?
        .into_voter_policy_chirho(),
        (
            ConsistencyGroupIdChirho::TenantChirho { .. },
            MembershipTargetAuthorityChirho::RosterWideChirho,
        ) if admission_chirho
            == GeoVoterPlacementAdmissionChirho::ExplicitTestkindRosterWideChirho =>
        {
            Ok(
                VerifiedGeoVoterStartupPolicyChirho::without_placement_chirho(
                    GeoVoterStartupRolePolicyChirho::PreserveElectedRoleChirho,
                ),
            )
        }
        (
            ConsistencyGroupIdChirho::RootPathChirho { .. },
            MembershipTargetAuthorityChirho::RosterWideChirho,
        ) if admission_chirho
            == GeoVoterPlacementAdmissionChirho::ExplicitTestkindRosterWideChirho =>
        {
            Ok(
                VerifiedGeoVoterStartupPolicyChirho::without_placement_chirho(
                    GeoVoterStartupRolePolicyChirho::PreserveElectedRoleChirho,
                ),
            )
        }
        (
            ConsistencyGroupIdChirho::RootPathChirho { .. },
            MembershipTargetAuthorityChirho::RosterWideChirho,
        ) => bail!("GeoRootWideRequiresExplicitTestkindRosterWideAdmissionChirho"),
        _ => bail!("GeoTenantPlacementTargetSelectorRefusedChirho"),
    }
}

pub(super) fn verify_geo_held_startup_chirho(
    loaded_chirho: &LoadedClusterNodeConfigChirho,
    selected_root_chirho: &Path,
) -> Result<()> {
    match &loaded_chirho.cluster_chirho.group_chirho {
        ConsistencyGroupIdChirho::TenantChirho { .. } => {
            verify_geo_tenant_placement_startup_chirho(
                loaded_chirho,
                selected_root_chirho,
                GeoTenantPlacementRoleChirho::HeldObserverChirho,
            )?;
        }
        ConsistencyGroupIdChirho::RootPathChirho { .. } => {
            if loaded_chirho
                .cluster_chirho
                .membership_control_chirho
                .is_some()
            {
                bail!("GeoTenantPlacementHeldObserverControlRefusedChirho");
            }
            require_local_cluster_role_chirho(
                loaded_chirho,
                GeoTenantPlacementRoleChirho::HeldObserverChirho,
            )?;
        }
    }
    Ok(())
}

/// Verify the complete placement/roster join and this process's local binding before any listener,
/// elector, resident actor, or held coordinator opens.
///
/// A voter outside the new assignment may still start long enough to converge itself out. It receives
/// no readiness credit. A held process has no membership-control capability and must be the exact held
/// observer named by the placement.
pub(super) fn verify_geo_tenant_placement_startup_chirho(
    loaded_chirho: &LoadedClusterNodeConfigChirho,
    selected_root_chirho: &Path,
    role_chirho: GeoTenantPlacementRoleChirho,
) -> Result<VerifiedGeoTenantPlacementStartupChirho> {
    let tenant_id_chirho = match &loaded_chirho.cluster_chirho.group_chirho {
        ConsistencyGroupIdChirho::TenantChirho { tenant_id_chirho } => tenant_id_chirho,
        ConsistencyGroupIdChirho::RootPathChirho { .. } => {
            bail!("GeoTenantPlacementTenantGroupRequiredChirho")
        }
    };
    if role_chirho == GeoTenantPlacementRoleChirho::HeldObserverChirho
        && loaded_chirho
            .cluster_chirho
            .membership_control_chirho
            .is_some()
    {
        bail!("GeoTenantPlacementHeldObserverControlRefusedChirho");
    }
    let roster_authority_chirho = loaded_chirho
        .roster_authority_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("GeoTenantPlacementRosterAuthorityUnavailableChirho"))?;
    let placement_authority_chirho = loaded_chirho
        .tenant_placement_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("GeoTenantPlacementAuthorityUnavailableChirho"))?;
    if role_chirho == GeoTenantPlacementRoleChirho::VoterChirho {
        let control_chirho = loaded_chirho
            .cluster_chirho
            .membership_control_chirho
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("GeoTenantPlacementControlUnavailableChirho"))?;
        let MembershipTargetAuthorityChirho::TenantPlacementChirho(control_placement_chirho) =
            &control_chirho.target_authority_chirho
        else {
            bail!("GeoTenantPlacementTargetSelectorRefusedChirho")
        };
        require_same_placement_config_chirho(placement_authority_chirho, control_placement_chirho)?;
    }

    let placement_chirho = load_and_verify_tenant_placement_record_chirho(
        &placement_authority_chirho.placement_record_path_chirho,
        &placement_authority_chirho.placement_pubkey_hex_chirho,
        &roster_authority_chirho.operator_pubkey_hex_chirho,
        &placement_authority_chirho.geo_plan_pubkey_hex_chirho,
    )
    .context("GeoTenantPlacementAuthorityRefusedChirho")?;
    if placement_chirho.intent_chirho().tenant_id_chirho != *tenant_id_chirho {
        bail!("GeoTenantPlacementTenantIdentityRefusedChirho");
    }
    if placement_chirho.intent_chirho().consistency_group_id_chirho
        != loaded_chirho
            .cluster_chirho
            .group_chirho
            .canonical_id_chirho()
    {
        bail!("GeoTenantPlacementGroupIdentityRefusedChirho");
    }

    let local_node_chirho = require_local_cluster_role_chirho(loaded_chirho, role_chirho)?;
    let (roster_lines_chirho, roster_head_chirho) = roster_authority_chirho
        .load_bounded_inputs_chirho()
        .context("GeoTenantPlacementRosterInputsRefusedChirho")?;
    let (_derived_chirho, join_chirho) = derive_tenant_placement_elector_config_chirho(
        &roster_lines_chirho,
        &roster_head_chirho,
        &roster_authority_chirho.operator_pubkey_hex_chirho,
        &local_node_chirho.0,
        &placement_chirho,
    )
    .context("GeoTenantPlacementRosterJoinRefusedChirho")?;

    let (local_binding_chirho, local_node_assigned_chirho) = match role_chirho {
        GeoTenantPlacementRoleChirho::VoterChirho => {
            if join_chirho.local_node_held_observer_chirho {
                bail!("GeoTenantPlacementVoterRoleRefusedChirho");
            }
            let local_binding_chirho = placement_chirho.assigned_node_chirho(&local_node_chirho.0);
            let local_node_assigned_chirho = local_binding_chirho.is_some();
            (local_binding_chirho, local_node_assigned_chirho)
        }
        GeoTenantPlacementRoleChirho::HeldObserverChirho => {
            if !join_chirho.local_node_held_observer_chirho {
                bail!("GeoTenantPlacementHeldObserverRoleRefusedChirho");
            }
            (Some(placement_chirho.held_observer_node_chirho()), false)
        }
    };
    if let Some(local_binding_chirho) = local_binding_chirho {
        verify_local_binding_chirho(
            local_binding_chirho,
            tenant_id_chirho,
            loaded_chirho,
            selected_root_chirho,
        )?;
    }
    let placement_chirho = Arc::new(placement_chirho);
    Ok(match role_chirho {
        GeoTenantPlacementRoleChirho::VoterChirho => {
            VerifiedGeoTenantPlacementStartupChirho::VoterChirho {
                local_node_assigned_chirho,
                placement_chirho,
            }
        }
        GeoTenantPlacementRoleChirho::HeldObserverChirho => {
            let _placement_chirho = placement_chirho;
            VerifiedGeoTenantPlacementStartupChirho::HeldObserverChirho
        }
    })
}

fn require_local_cluster_role_chirho(
    loaded_chirho: &LoadedClusterNodeConfigChirho,
    role_chirho: GeoTenantPlacementRoleChirho,
) -> Result<cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho> {
    let local_node_chirho =
        super::configured_local_cluster_node_chirho(&loaded_chirho.cluster_chirho)?;
    let local_is_voter_chirho =
        loaded_chirho
            .cluster_chirho
            .voters_chirho
            .iter()
            .any(|(raft_id_chirho, node_chirho)| {
                *raft_id_chirho == loaded_chirho.cluster_chirho.local_raft_id_chirho
                    && node_chirho == &local_node_chirho
            });
    match role_chirho {
        GeoTenantPlacementRoleChirho::VoterChirho if !local_is_voter_chirho => {
            bail!("GeoTenantPlacementVoterConfigRoleRefusedChirho")
        }
        GeoTenantPlacementRoleChirho::HeldObserverChirho if local_is_voter_chirho => {
            bail!("GeoTenantPlacementHeldObserverConfigRoleRefusedChirho")
        }
        _ => Ok(local_node_chirho),
    }
}

fn require_same_placement_config_chirho(
    top_level_chirho: &TenantPlacementAuthorityConfigChirho,
    control_chirho: &TenantPlacementAuthorityConfigChirho,
) -> Result<()> {
    if top_level_chirho.placement_record_path_chirho != control_chirho.placement_record_path_chirho
        || top_level_chirho.placement_pubkey_hex_chirho
            != control_chirho.placement_pubkey_hex_chirho
        || top_level_chirho.geo_plan_pubkey_hex_chirho != control_chirho.geo_plan_pubkey_hex_chirho
    {
        bail!("GeoTenantPlacementControlConfigDivergenceChirho");
    }
    Ok(())
}

fn verify_local_binding_chirho(
    binding_chirho: &TenantPlacementNodeBindingChirho,
    tenant_id_chirho: &str,
    loaded_chirho: &LoadedClusterNodeConfigChirho,
    selected_root_chirho: &Path,
) -> Result<()> {
    let verified_root_chirho =
        VerifiedTenantMigrationRootChirho::open_existing_chirho(selected_root_chirho)
            .context("GeoTenantPlacementLocalRootRefusedChirho")?;
    if verified_root_chirho.tenant_id_chirho() != tenant_id_chirho {
        bail!("GeoTenantPlacementLocalTenantRefusedChirho");
    }
    let actual_root_binding_chirho = format!(
        "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
        verified_root_chirho
            .binding_identity_digest_hex_chirho()
            .context("GeoTenantPlacementLocalRootRefusedChirho")?
    );
    if actual_root_binding_chirho != binding_chirho.expected_root_binding_chirho {
        bail!("GeoTenantPlacementLocalRootBindingRefusedChirho");
    }
    if loaded_chirho.config_blake3_chirho != binding_chirho.expected_cluster_config_blake3_chirho {
        bail!("GeoTenantPlacementLocalClusterConfigRefusedChirho");
    }
    Ok(())
}
