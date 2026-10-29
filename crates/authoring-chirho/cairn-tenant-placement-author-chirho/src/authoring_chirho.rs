// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use anyhow::{bail, Context, Result};
use cairn_config_chirho::config_chirho::load_config_chirho;
use cairn_durable_chirho::{
    create_complete_file_durable_with_mode_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_ledger_tenant_migration_chirho::VerifiedTenantMigrationRootChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_signer_chirho::signer_chirho::{
    existing_keypair_pubkey_hex_chirho, sign_with_existing_key_possession_chirho,
};
use cairn_tenant_chirho::tenant_chirho::tenant_root_chirho;
use cairn_tenant_placement_authority_chirho::{
    load_and_verify_tenant_placement_record_chirho, tenant_placement_intent_digest_chirho,
    unsigned_tenant_placement_held_observer_readiness_message_chirho,
    unsigned_tenant_placement_readiness_message_chirho,
    unsigned_tenant_placement_record_message_chirho, verify_tenant_placement_record_chirho,
    TenantPlacementHeldObserverReadinessReceiptChirho, TenantPlacementIntentChirho,
    TenantPlacementNodeBindingChirho, TenantPlacementNodeReadinessReceiptChirho,
    TenantPlacementRecordChirho, TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V2_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V2_CHIRHO, TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_RECORD_DOMAIN_V2_CHIRHO, TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO,
    TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO, TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO,
    TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::shadow_canary_activation_anchor_chirho::load_required_shadow_canary_activation_anchor_chirho;
use cairn_writer_elector_chirho::shadow_canary_chirho::SHADOW_CANARY_EVIDENCE_DIR_CHIRHO;
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::{
    ShadowCanaryGenerationStoreChirho, VerifiedShadowCanaryCurrentGenerationChirho,
};
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::{
    load_cluster_node_readiness_config_chirho, verify_cluster_node_file_config_custody_chirho,
    ClusterNodeReadinessRoleChirho, LoadedClusterNodeReadinessConfigChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho;
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn write_tenant_placement_intent_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    output_path_chirho: &Path,
) -> Result<String> {
    let digest_chirho = tenant_placement_intent_digest_chirho(intent_chirho)
        .context("TenantPlacementIntentAuthoringRefusedChirho")?;
    write_new_json_chirho(output_path_chirho, intent_chirho)?;
    Ok(digest_chirho)
}

pub fn author_tenant_placement_readiness_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    tenant_root_chirho: &Path,
    cluster_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    prepared_at_ms_chirho: u64,
) -> Result<TenantPlacementNodeReadinessReceiptChirho> {
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(intent_chirho)
        .context("TenantPlacementReadinessIntentRefusedChirho")?;
    let node_id_chirho = existing_keypair_pubkey_hex_chirho(node_sign_root_chirho)
        .context("TenantPlacementReadinessNodeCustodyRefusedChirho")?;
    let assigned_chirho = intent_chirho
        .assigned_nodes_chirho
        .iter()
        .find(|assigned_chirho| assigned_chirho.node_id_chirho == node_id_chirho)
        .ok_or_else(|| anyhow::anyhow!("TenantPlacementReadinessNodeNotAssignedChirho"))?;
    let prepared_chirho = verify_prepared_node_binding_chirho(
        intent_chirho,
        assigned_chirho,
        tenant_root_chirho,
        cluster_config_path_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
        PreparedNodeRoleChirho::ServingChirho,
    )?;
    let mut receipt_chirho = TenantPlacementNodeReadinessReceiptChirho {
        schema_chirho: TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho,
        node_id_chirho: prepared_chirho.node_id_chirho.clone(),
        failure_domain_chirho: assigned_chirho.failure_domain_chirho.clone(),
        root_binding_chirho: prepared_chirho.root_binding_chirho,
        cluster_config_blake3_chirho: prepared_chirho.cluster_config_blake3_chirho,
        activation_anchor_digest_chirho: None,
        prepared_at_ms_chirho,
        signer_key_id_chirho: prepared_chirho.node_id_chirho,
        sig_chirho: String::new(),
    };
    let unsigned_chirho = unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho)
        .context("TenantPlacementReadinessRenderRefusedChirho")?;
    let possession_chirho =
        sign_with_existing_key_possession_chirho(node_sign_root_chirho, &unsigned_chirho)
            .context("TenantPlacementReadinessNodeCustodyRefusedChirho")?;
    if possession_chirho.key_id_chirho() != receipt_chirho.signer_key_id_chirho {
        bail!("TenantPlacementReadinessNodeCustodyChangedChirho");
    }
    receipt_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    Ok(receipt_chirho)
}

/// Author one serving-readiness receipt bound to the exact activation incarnation under the
/// selected runtime root. The caller supplies a config coordinate, never an anchor value.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/\
/// cf8-canary-window-loss-sequence-chirho.md`.
pub fn author_tenant_placement_readiness_v2_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    tenant_root_path_chirho: &Path,
    cluster_config_path_chirho: &Path,
    runtime_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    prepared_at_ms_chirho: u64,
) -> Result<TenantPlacementNodeReadinessReceiptChirho> {
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(intent_chirho)
        .context("TenantPlacementReadinessIntentRefusedChirho")?;
    let node_id_chirho = existing_keypair_pubkey_hex_chirho(node_sign_root_chirho)
        .context("TenantPlacementReadinessNodeCustodyRefusedChirho")?;
    let assigned_chirho = intent_chirho
        .assigned_nodes_chirho
        .iter()
        .find(|assigned_chirho| assigned_chirho.node_id_chirho == node_id_chirho)
        .ok_or_else(|| anyhow::anyhow!("TenantPlacementReadinessNodeNotAssignedChirho"))?;
    let prepared_chirho = verify_prepared_node_binding_chirho(
        intent_chirho,
        assigned_chirho,
        tenant_root_path_chirho,
        cluster_config_path_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
        PreparedNodeRoleChirho::ServingChirho,
    )?;
    let activation_lineage_chirho = verify_runtime_activation_lineage_chirho(
        tenant_root_path_chirho,
        runtime_config_path_chirho,
        node_sign_root_chirho,
        &node_id_chirho,
    )?;
    let activation_window_chirho = activation_lineage_chirho
        .current_generation_chirho
        .require_generation_zero_window_chirho()
        .context("TenantPlacementReadinessActivationAnchorRefusedChirho")?;
    if activation_window_chirho.window_len_chirho != 1
        || activation_window_chirho.permit_count_chirho != 1
        || activation_window_chirho.refusal_count_chirho != 0
        || activation_window_chirho.latest_append_cut_chirho
            != activation_lineage_chirho.activation_append_cut_chirho
    {
        bail!("TenantPlacementReadinessActivationAnchorRefusedChirho");
    }
    sign_tenant_placement_readiness_v2_chirho(
        intent_digest_chirho,
        assigned_chirho,
        prepared_chirho,
        activation_lineage_chirho.anchor_digest_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
    )
}

/// Author a V2 readiness receipt for a contiguous placement successor without pretending that the
/// carried canary is still at its one-observation activation instant.
///
/// The operator-supplied exact current cluster config supplies the predecessor record and all three
/// public authority pins, and its digest is carried into the receipt for independent consumer
/// verification. The predecessor must be V2, the new intent must name its exact assignment digest
/// and next revision, and this node's fully verified current canary lineage must carry the same
/// activation anchor its predecessor receipt signed. This preserves the activation incarnation
/// across root migration or later placement refresh while refusing an unrelated or recreated
/// lineage. The anchor's resident-identity field remains historical source-incarnation
/// corroboration and is deliberately not re-bound to `tenant_root_path_chirho`.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/\
/// authority-contract-chirho.md`.
pub fn author_tenant_placement_successor_readiness_v2_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    tenant_root_path_chirho: &Path,
    cluster_config_path_chirho: &Path,
    runtime_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    prepared_at_ms_chirho: u64,
) -> Result<TenantPlacementNodeReadinessReceiptChirho> {
    let successor_chirho = prepare_tenant_placement_successor_readiness_chirho(
        intent_chirho,
        tenant_root_path_chirho,
        cluster_config_path_chirho,
        runtime_config_path_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
    )?;
    if successor_chirho.predecessor_anchor_chirho
        != successor_chirho
            .activation_lineage_chirho
            .anchor_digest_chirho
    {
        bail!("TenantPlacementSuccessorReadinessActivationAnchorRefusedChirho");
    }
    sign_tenant_placement_readiness_v2_chirho(
        successor_chirho.intent_digest_chirho,
        &successor_chirho.assigned_chirho,
        successor_chirho.prepared_chirho,
        successor_chirho
            .activation_lineage_chirho
            .anchor_digest_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
    )
}

/// Author one V2 successor receipt after a deliberately replaced evidence root has completed one
/// verified F1 recovery adoption under the predecessor placement assignment.
///
/// Invoking this road is an explicit operator assertion that replacing the evidence root was
/// authorized; placement artifacts cannot derive that historical fact. The author independently
/// requires an unchanged root binding, a non-vacuously changed anchor, an exact generation-one V3
/// adoption from generation zero, and the predecessor's verified assignment digest. The operation
/// record must retain the V3 adoption report/projection that justified the assertion. A moved root,
/// direct generation-zero reactivation, intact anchor, or later adoption generation refuses.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/\
/// authority-contract-chirho.md`.
pub fn author_tenant_placement_adopted_successor_readiness_v2_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    tenant_root_path_chirho: &Path,
    cluster_config_path_chirho: &Path,
    runtime_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    prepared_at_ms_chirho: u64,
) -> Result<TenantPlacementNodeReadinessReceiptChirho> {
    let successor_chirho = prepare_tenant_placement_successor_readiness_chirho(
        intent_chirho,
        tenant_root_path_chirho,
        cluster_config_path_chirho,
        runtime_config_path_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
    )?;
    if successor_chirho.predecessor_root_binding_chirho
        != successor_chirho
            .assigned_chirho
            .expected_root_binding_chirho
    {
        bail!("TenantPlacementAdoptedSuccessorReadinessRootContinuityRefusedChirho");
    }
    if successor_chirho.predecessor_anchor_chirho
        == successor_chirho
            .activation_lineage_chirho
            .anchor_digest_chirho
    {
        bail!("TenantPlacementAdoptedSuccessorReadinessReactivationRequiredChirho");
    }
    let current_generation_chirho = &successor_chirho
        .activation_lineage_chirho
        .current_generation_chirho;
    let adoption_chirho = current_generation_chirho.adoption_chirho().ok_or_else(|| {
        anyhow::anyhow!("TenantPlacementAdoptedSuccessorReadinessAdoptionProofRefusedChirho")
    })?;
    if current_generation_chirho.generation_chirho() != 1
        || current_generation_chirho.prior_generation_chirho() != Some(0)
        || adoption_chirho.adoption_proof_projection_chirho().is_none()
        || adoption_chirho.assignment_digest_chirho()
            != successor_chirho.predecessor_assignment_digest_chirho
    {
        bail!("TenantPlacementAdoptedSuccessorReadinessAdoptionProofRefusedChirho");
    }
    sign_tenant_placement_readiness_v2_chirho(
        successor_chirho.intent_digest_chirho,
        &successor_chirho.assigned_chirho,
        successor_chirho.prepared_chirho,
        successor_chirho
            .activation_lineage_chirho
            .anchor_digest_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
    )
}

struct PreparedTenantPlacementSuccessorReadinessChirho {
    intent_digest_chirho: String,
    assigned_chirho: TenantPlacementNodeBindingChirho,
    prepared_chirho: PreparedNodeBindingChirho,
    predecessor_anchor_chirho: String,
    predecessor_root_binding_chirho: String,
    predecessor_assignment_digest_chirho: String,
    activation_lineage_chirho: VerifiedReadinessActivationLineageChirho,
}

fn prepare_tenant_placement_successor_readiness_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    tenant_root_path_chirho: &Path,
    cluster_config_path_chirho: &Path,
    runtime_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    prepared_at_ms_chirho: u64,
) -> Result<PreparedTenantPlacementSuccessorReadinessChirho> {
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(intent_chirho)
        .context("TenantPlacementSuccessorReadinessIntentRefusedChirho")?;
    let node_id_chirho = existing_keypair_pubkey_hex_chirho(node_sign_root_chirho)
        .context("TenantPlacementSuccessorReadinessNodeCustodyRefusedChirho")?;
    let assigned_chirho = intent_chirho
        .assigned_nodes_chirho
        .iter()
        .find(|assigned_chirho| assigned_chirho.node_id_chirho == node_id_chirho)
        .ok_or_else(|| anyhow::anyhow!("TenantPlacementSuccessorReadinessNodeNotAssignedChirho"))?;
    let prepared_chirho = verify_prepared_node_binding_chirho(
        intent_chirho,
        assigned_chirho,
        tenant_root_path_chirho,
        cluster_config_path_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
        PreparedNodeRoleChirho::ServingChirho,
    )?;
    let authority_chirho = load_cluster_node_readiness_config_chirho(cluster_config_path_chirho)
        .context("TenantPlacementSuccessorReadinessAuthorityRefusedChirho")?;
    if authority_chirho.config_blake3_chirho != prepared_chirho.cluster_config_blake3_chirho {
        bail!("TenantPlacementSuccessorReadinessAuthorityRefusedChirho");
    }
    let predecessor_path_chirho = authority_chirho
        .placement_record_path_chirho
        .as_deref()
        .ok_or_else(|| {
            anyhow::anyhow!("TenantPlacementSuccessorReadinessAuthorityRefusedChirho")
        })?;
    let placement_key_chirho = authority_chirho
        .placement_pubkey_hex_chirho
        .as_deref()
        .ok_or_else(|| {
            anyhow::anyhow!("TenantPlacementSuccessorReadinessAuthorityRefusedChirho")
        })?;
    let roster_key_chirho = authority_chirho
        .roster_operator_pubkey_hex_chirho
        .as_deref()
        .ok_or_else(|| {
            anyhow::anyhow!("TenantPlacementSuccessorReadinessAuthorityRefusedChirho")
        })?;
    let geo_plan_key_chirho = authority_chirho
        .geo_plan_pubkey_hex_chirho
        .as_deref()
        .ok_or_else(|| {
            anyhow::anyhow!("TenantPlacementSuccessorReadinessAuthorityRefusedChirho")
        })?;
    let predecessor_chirho = load_and_verify_tenant_placement_record_chirho(
        predecessor_path_chirho,
        placement_key_chirho,
        roster_key_chirho,
        geo_plan_key_chirho,
    )
    .context("TenantPlacementSuccessorReadinessPredecessorRefusedChirho")?;
    let expected_revision_chirho = predecessor_chirho
        .intent_chirho()
        .revision_chirho
        .checked_add(1)
        .ok_or_else(|| {
            anyhow::anyhow!("TenantPlacementSuccessorReadinessPredecessorRefusedChirho")
        })?;
    if predecessor_chirho.record_schema_chirho() != TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO
        || intent_chirho.revision_chirho != expected_revision_chirho
        || intent_chirho.previous_assignment_digest_chirho.as_deref()
            != Some(predecessor_chirho.assignment_digest_chirho())
        || intent_chirho.tenant_id_chirho != predecessor_chirho.intent_chirho().tenant_id_chirho
        || intent_chirho.consistency_group_id_chirho
            != predecessor_chirho
                .intent_chirho()
                .consistency_group_id_chirho
    {
        bail!("TenantPlacementSuccessorReadinessPredecessorRefusedChirho");
    }
    let predecessor_anchor_chirho = predecessor_chirho
        .activation_anchor_digest_for_node_chirho(&node_id_chirho)
        .ok_or_else(|| {
            anyhow::anyhow!("TenantPlacementSuccessorReadinessPredecessorRefusedChirho")
        })?
        .to_string();
    let predecessor_root_binding_chirho = predecessor_chirho
        .assigned_node_chirho(&node_id_chirho)
        .ok_or_else(|| {
            anyhow::anyhow!("TenantPlacementSuccessorReadinessPredecessorRefusedChirho")
        })?
        .expected_root_binding_chirho
        .clone();
    let predecessor_assignment_digest_chirho =
        predecessor_chirho.assignment_digest_chirho().to_string();
    let activation_lineage_chirho = verify_runtime_activation_lineage_chirho(
        tenant_root_path_chirho,
        runtime_config_path_chirho,
        node_sign_root_chirho,
        &node_id_chirho,
    )?;
    Ok(PreparedTenantPlacementSuccessorReadinessChirho {
        intent_digest_chirho,
        assigned_chirho: assigned_chirho.clone(),
        prepared_chirho,
        predecessor_anchor_chirho,
        predecessor_root_binding_chirho,
        predecessor_assignment_digest_chirho,
        activation_lineage_chirho,
    })
}

struct VerifiedReadinessActivationLineageChirho {
    anchor_digest_chirho: String,
    activation_append_cut_chirho:
        cairn_writer_elector_chirho::shadow_canary_chirho::ShadowCanaryAppendCutChirho,
    current_generation_chirho: VerifiedShadowCanaryCurrentGenerationChirho,
}

fn verify_runtime_activation_lineage_chirho(
    tenant_root_path_chirho: &Path,
    runtime_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    node_id_chirho: &str,
) -> Result<VerifiedReadinessActivationLineageChirho> {
    let canonical_root_chirho = tenant_root_path_chirho
        .canonicalize()
        .context("TenantPlacementReadinessRuntimeRootBindingRefusedChirho")?;
    let runtime_config_chirho = load_config_chirho(runtime_config_path_chirho)
        .context("TenantPlacementReadinessRuntimeConfigRefusedChirho")?;
    let configured_root_chirho = PathBuf::from(&runtime_config_chirho.root_chirho);
    let effective_root_chirho = match runtime_config_chirho
        .tenant_chirho
        .as_deref()
        .filter(|tenant_chirho| !tenant_chirho.trim().is_empty())
    {
        Some(tenant_chirho) => tenant_root_chirho(&configured_root_chirho, tenant_chirho)
            .context("TenantPlacementReadinessRuntimeRootBindingRefusedChirho")?,
        None => configured_root_chirho,
    };
    if effective_root_chirho
        .canonicalize()
        .context("TenantPlacementReadinessRuntimeRootBindingRefusedChirho")?
        != canonical_root_chirho
    {
        bail!("TenantPlacementReadinessRuntimeRootBindingRefusedChirho");
    }
    let ledger_config_chirho = runtime_config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TenantPlacementReadinessRuntimeConfigRefusedChirho"))?;
    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)
        .context("TenantPlacementReadinessActivationAnchorRefusedChirho")?;
    let canary_root_chirho = canonical_root_chirho
        .join(&ledger_config_chirho.monitor_evidence_namespace_chirho)
        .join(SHADOW_CANARY_EVIDENCE_DIR_CHIRHO);
    let anchor_chirho = load_required_shadow_canary_activation_anchor_chirho(
        &canary_root_chirho,
        node_sign_root_chirho,
        &group_chirho,
        &NodeIdChirho(node_id_chirho.to_string()),
    )
    .context("TenantPlacementReadinessActivationAnchorRefusedChirho")?;
    let generation_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &canary_root_chirho,
        node_sign_root_chirho,
        group_chirho,
        NodeIdChirho(node_id_chirho.to_string()),
    )
    .context("TenantPlacementReadinessActivationAnchorRefusedChirho")?;
    let current_generation_chirho = generation_store_chirho
        .verify_current_read_only_chirho()
        .context("TenantPlacementReadinessActivationAnchorRefusedChirho")?;
    let current_anchor_chirho = current_generation_chirho
        .adoption_chirho()
        .and_then(|adoption_chirho| adoption_chirho.activation_anchor_digest_chirho())
        .or_else(|| {
            current_generation_chirho
                .window_chirho()
                .and_then(|window_chirho| window_chirho.activation_anchor_digest_chirho.as_deref())
        });
    if current_anchor_chirho != Some(anchor_chirho.digest_chirho()) {
        bail!("TenantPlacementReadinessActivationAnchorRefusedChirho");
    }
    Ok(VerifiedReadinessActivationLineageChirho {
        anchor_digest_chirho: anchor_chirho.digest_chirho().to_string(),
        activation_append_cut_chirho: anchor_chirho
            .anchor_chirho()
            .activation_append_cut_chirho
            .clone(),
        current_generation_chirho,
    })
}

fn sign_tenant_placement_readiness_v2_chirho(
    intent_digest_chirho: String,
    assigned_chirho: &TenantPlacementNodeBindingChirho,
    prepared_chirho: PreparedNodeBindingChirho,
    activation_anchor_digest_chirho: String,
    node_sign_root_chirho: &Path,
    prepared_at_ms_chirho: u64,
) -> Result<TenantPlacementNodeReadinessReceiptChirho> {
    let mut receipt_chirho = TenantPlacementNodeReadinessReceiptChirho {
        schema_chirho: TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V2_CHIRHO.to_string(),
        intent_digest_chirho,
        node_id_chirho: prepared_chirho.node_id_chirho.clone(),
        failure_domain_chirho: assigned_chirho.failure_domain_chirho.clone(),
        root_binding_chirho: prepared_chirho.root_binding_chirho,
        cluster_config_blake3_chirho: prepared_chirho.cluster_config_blake3_chirho,
        activation_anchor_digest_chirho: Some(activation_anchor_digest_chirho),
        prepared_at_ms_chirho,
        signer_key_id_chirho: prepared_chirho.node_id_chirho,
        sig_chirho: String::new(),
    };
    let unsigned_chirho = unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho)
        .context("TenantPlacementReadinessRenderRefusedChirho")?;
    let possession_chirho =
        sign_with_existing_key_possession_chirho(node_sign_root_chirho, &unsigned_chirho)
            .context("TenantPlacementReadinessNodeCustodyRefusedChirho")?;
    if possession_chirho.key_id_chirho() != receipt_chirho.signer_key_id_chirho {
        bail!("TenantPlacementReadinessNodeCustodyChangedChirho");
    }
    receipt_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    Ok(receipt_chirho)
}

pub fn author_tenant_placement_held_observer_readiness_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    tenant_root_chirho: &Path,
    cluster_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    prepared_at_ms_chirho: u64,
) -> Result<TenantPlacementHeldObserverReadinessReceiptChirho> {
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(intent_chirho)
        .context("TenantPlacementHeldObserverReadinessIntentRefusedChirho")?;
    let prepared_chirho = verify_prepared_node_binding_chirho(
        intent_chirho,
        &intent_chirho.held_observer_node_chirho,
        tenant_root_chirho,
        cluster_config_path_chirho,
        node_sign_root_chirho,
        prepared_at_ms_chirho,
        PreparedNodeRoleChirho::HeldObserverChirho,
    )?;
    let mut receipt_chirho = TenantPlacementHeldObserverReadinessReceiptChirho {
        schema_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO
            .to_string(),
        intent_digest_chirho,
        node_id_chirho: prepared_chirho.node_id_chirho.clone(),
        failure_domain_chirho: intent_chirho
            .held_observer_node_chirho
            .failure_domain_chirho
            .clone(),
        root_binding_chirho: prepared_chirho.root_binding_chirho,
        cluster_config_blake3_chirho: prepared_chirho.cluster_config_blake3_chirho,
        prepared_at_ms_chirho,
        signer_key_id_chirho: prepared_chirho.node_id_chirho,
        sig_chirho: String::new(),
    };
    let unsigned_chirho =
        unsigned_tenant_placement_held_observer_readiness_message_chirho(&receipt_chirho)
            .context("TenantPlacementHeldObserverReadinessRenderRefusedChirho")?;
    let possession_chirho =
        sign_with_existing_key_possession_chirho(node_sign_root_chirho, &unsigned_chirho)
            .context("TenantPlacementHeldObserverReadinessNodeCustodyRefusedChirho")?;
    if possession_chirho.key_id_chirho() != receipt_chirho.signer_key_id_chirho {
        bail!("TenantPlacementHeldObserverReadinessNodeCustodyChangedChirho");
    }
    receipt_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    Ok(receipt_chirho)
}

/// Inspect one prepared node and derive the exact receipt-free placement binding it can attest.
///
/// This is read-only and grants no placement authority. The later readiness command independently
/// re-opens and verifies every coordinate against the reviewed intent before signing it.
pub fn inspect_tenant_placement_node_binding_chirho(
    tenant_root_chirho: &Path,
    cluster_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    failure_domain_chirho: FailureDomainChirho,
) -> Result<TenantPlacementNodeBindingChirho> {
    verify_failure_domain_token_chirho(&failure_domain_chirho.provider_chirho)?;
    verify_failure_domain_token_chirho(&failure_domain_chirho.region_chirho)?;
    let (prepared_chirho, _loaded_chirho) = inspect_prepared_node_binding_chirho(
        tenant_root_chirho,
        cluster_config_path_chirho,
        node_sign_root_chirho,
    )?;
    Ok(TenantPlacementNodeBindingChirho {
        node_id_chirho: prepared_chirho.node_id_chirho,
        failure_domain_chirho,
        expected_root_binding_chirho: prepared_chirho.root_binding_chirho,
        expected_cluster_config_blake3_chirho: prepared_chirho.cluster_config_blake3_chirho,
    })
}

struct PreparedNodeBindingChirho {
    node_id_chirho: String,
    tenant_id_chirho: String,
    root_binding_chirho: String,
    cluster_config_blake3_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedNodeRoleChirho {
    ServingChirho,
    HeldObserverChirho,
}

fn verify_prepared_node_binding_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    expected_node_chirho: &TenantPlacementNodeBindingChirho,
    tenant_root_chirho: &Path,
    cluster_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
    prepared_at_ms_chirho: u64,
    role_chirho: PreparedNodeRoleChirho,
) -> Result<PreparedNodeBindingChirho> {
    let (prepared_chirho, loaded_chirho) = inspect_prepared_node_binding_chirho(
        tenant_root_chirho,
        cluster_config_path_chirho,
        node_sign_root_chirho,
    )?;
    if prepared_chirho.node_id_chirho != expected_node_chirho.node_id_chirho {
        bail!("TenantPlacementReadinessNodeBindingRefusedChirho");
    }
    if prepared_chirho.tenant_id_chirho != intent_chirho.tenant_id_chirho {
        bail!("TenantPlacementReadinessTenantRefusedChirho");
    }
    if prepared_chirho.root_binding_chirho != expected_node_chirho.expected_root_binding_chirho {
        bail!("TenantPlacementReadinessRootBindingRefusedChirho");
    }
    verify_prepared_cluster_config_chirho(
        intent_chirho,
        &prepared_chirho.node_id_chirho,
        node_sign_root_chirho,
        &loaded_chirho,
        role_chirho,
    )?;
    if prepared_chirho.cluster_config_blake3_chirho
        != expected_node_chirho.expected_cluster_config_blake3_chirho
    {
        bail!("TenantPlacementReadinessClusterConfigBindingRefusedChirho");
    }
    if prepared_at_ms_chirho == 0 {
        bail!("TenantPlacementReadinessTimestampRefusedChirho");
    }
    Ok(prepared_chirho)
}

fn inspect_prepared_node_binding_chirho(
    tenant_root_chirho: &Path,
    cluster_config_path_chirho: &Path,
    node_sign_root_chirho: &Path,
) -> Result<(
    PreparedNodeBindingChirho,
    LoadedClusterNodeReadinessConfigChirho,
)> {
    let node_id_chirho = existing_keypair_pubkey_hex_chirho(node_sign_root_chirho)
        .context("TenantPlacementReadinessNodeCustodyRefusedChirho")?;
    let verified_root_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(
        tenant_root_chirho,
    )
    .map_err(|error_chirho| {
        anyhow::anyhow!("TenantPlacementReadinessRootRefusedChirho: {error_chirho}")
    })?;
    verify_cluster_node_file_config_custody_chirho(tenant_root_chirho, cluster_config_path_chirho)
        .context("TenantPlacementReadinessClusterConfigCustodyRefusedChirho")?;
    let loaded_chirho = load_cluster_node_readiness_config_chirho(cluster_config_path_chirho)
        .context("TenantPlacementReadinessClusterConfigRefusedChirho")?;
    let expected_group_chirho =
        format!("tenant-chirho:{}", verified_root_chirho.tenant_id_chirho());
    if loaded_chirho.group_chirho.canonical_id_chirho() != expected_group_chirho {
        bail!("TenantPlacementReadinessTenantGroupRefusedChirho");
    }
    let configured_signer_chirho =
        existing_keypair_pubkey_hex_chirho(&loaded_chirho.sign_root_chirho)
            .context("TenantPlacementReadinessConfiguredNodeCustodyRefusedChirho")?;
    if configured_signer_chirho != node_id_chirho {
        bail!("TenantPlacementReadinessLocalNodeKeyRefusedChirho");
    }
    let local_nodes_chirho = loaded_chirho
        .voters_chirho
        .iter()
        .chain(&loaded_chirho.learners_chirho)
        .filter(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == loaded_chirho.local_raft_id_chirho
        })
        .map(|(_raft_id_chirho, local_node_chirho)| local_node_chirho)
        .collect::<Vec<_>>();
    let [local_node_chirho] = local_nodes_chirho.as_slice() else {
        bail!("TenantPlacementReadinessLocalNodePopulationRefusedChirho")
    };
    if local_node_chirho.as_str() != node_id_chirho {
        bail!("TenantPlacementReadinessLocalNodeKeyRefusedChirho");
    }
    if !loaded_chirho.roster_authority_configured_chirho
        || !loaded_chirho.tenant_placement_configured_chirho
    {
        bail!("TenantPlacementReadinessAuthorityReadsRefusedChirho");
    }
    let root_binding_chirho = format!(
        "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
        verified_root_chirho
            .binding_identity_digest_hex_chirho()
            .map_err(|error_chirho| anyhow::anyhow!(
                "TenantPlacementReadinessRootRefusedChirho: {error_chirho}"
            ))?
    );
    Ok((
        PreparedNodeBindingChirho {
            node_id_chirho,
            tenant_id_chirho: verified_root_chirho.tenant_id_chirho().to_string(),
            root_binding_chirho,
            cluster_config_blake3_chirho: loaded_chirho.config_blake3_chirho.clone(),
        },
        loaded_chirho,
    ))
}

fn verify_failure_domain_token_chirho(value_chirho: &str) -> Result<()> {
    if value_chirho.is_empty()
        || value_chirho.len() > 64
        || value_chirho.starts_with('-')
        || value_chirho.ends_with('-')
        || !value_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase() || byte_chirho.is_ascii_digit() || byte_chirho == b'-'
        })
    {
        bail!("TenantPlacementBindingFailureDomainRefusedChirho");
    }
    Ok(())
}

fn verify_prepared_cluster_config_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
    expected_node_id_chirho: &str,
    node_sign_root_chirho: &Path,
    loaded_chirho: &LoadedClusterNodeReadinessConfigChirho,
    role_chirho: PreparedNodeRoleChirho,
) -> Result<()> {
    if loaded_chirho.group_chirho.canonical_id_chirho() != intent_chirho.consistency_group_id_chirho
    {
        bail!("TenantPlacementReadinessTenantGroupRefusedChirho");
    }
    let configured_signer_chirho =
        existing_keypair_pubkey_hex_chirho(&loaded_chirho.sign_root_chirho)
            .context("TenantPlacementReadinessConfiguredNodeCustodyRefusedChirho")?;
    let supplied_signer_chirho = existing_keypair_pubkey_hex_chirho(node_sign_root_chirho)
        .context("TenantPlacementReadinessNodeCustodyRefusedChirho")?;
    if configured_signer_chirho != *expected_node_id_chirho
        || supplied_signer_chirho != *expected_node_id_chirho
    {
        bail!("TenantPlacementReadinessLocalNodeKeyRefusedChirho");
    }
    let local_nodes_chirho = loaded_chirho
        .voters_chirho
        .iter()
        .chain(&loaded_chirho.learners_chirho)
        .filter(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == loaded_chirho.local_raft_id_chirho
        })
        .map(|(_raft_id_chirho, node_chirho)| node_chirho)
        .collect::<Vec<_>>();
    let [local_node_chirho] = local_nodes_chirho.as_slice() else {
        bail!("TenantPlacementReadinessLocalNodePopulationRefusedChirho")
    };
    if local_node_chirho.as_str() != expected_node_id_chirho {
        bail!("TenantPlacementReadinessLocalNodeKeyRefusedChirho");
    }
    if !loaded_chirho.roster_authority_configured_chirho
        || !loaded_chirho.tenant_placement_configured_chirho
    {
        bail!("TenantPlacementReadinessAuthorityReadsRefusedChirho");
    }
    match role_chirho {
        PreparedNodeRoleChirho::ServingChirho => {
            let local_voter_count_chirho = loaded_chirho
                .voters_chirho
                .iter()
                .filter(|(raft_id_chirho, node_chirho)| {
                    *raft_id_chirho == loaded_chirho.local_raft_id_chirho
                        && node_chirho == expected_node_id_chirho
                })
                .count();
            if local_voter_count_chirho != 1
                || loaded_chirho.role_chirho
                    != ClusterNodeReadinessRoleChirho::TenantPlacementServingChirho
            {
                bail!("TenantPlacementReadinessServingRoleRefusedChirho");
            }
        }
        PreparedNodeRoleChirho::HeldObserverChirho => {
            let local_held_count_chirho = loaded_chirho
                .learners_chirho
                .iter()
                .filter(|(raft_id_chirho, node_chirho)| {
                    *raft_id_chirho == loaded_chirho.local_raft_id_chirho
                        && node_chirho == expected_node_id_chirho
                })
                .count();
            if local_held_count_chirho != 1
                || loaded_chirho.role_chirho
                    != ClusterNodeReadinessRoleChirho::NoMembershipControlChirho
            {
                bail!("TenantPlacementReadinessHeldObserverRoleRefusedChirho");
            }
        }
    }
    Ok(())
}

pub fn author_tenant_placement_record_chirho(
    intent_chirho: TenantPlacementIntentChirho,
    serving_readiness_receipts_chirho: Vec<TenantPlacementNodeReadinessReceiptChirho>,
    held_observer_readiness_receipt_chirho: TenantPlacementHeldObserverReadinessReceiptChirho,
    placement_sign_root_chirho: &Path,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> Result<TenantPlacementRecordChirho> {
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(&intent_chirho)
        .context("TenantPlacementRecordIntentRefusedChirho")?;
    let placement_key_chirho = existing_keypair_pubkey_hex_chirho(placement_sign_root_chirho)
        .context("TenantPlacementRecordCustodyRefusedChirho")?;
    let v2_receipt_count_chirho = serving_readiness_receipts_chirho
        .iter()
        .filter(|receipt_chirho| {
            receipt_chirho.schema_chirho == TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V2_CHIRHO
                && receipt_chirho.signature_domain_chirho
                    == TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V2_CHIRHO
                && receipt_chirho.activation_anchor_digest_chirho.is_some()
        })
        .count();
    if v2_receipt_count_chirho != 0
        && v2_receipt_count_chirho != serving_readiness_receipts_chirho.len()
    {
        bail!("TenantPlacementRecordReadinessVersionRefusedChirho");
    }
    let record_v2_chirho = v2_receipt_count_chirho == serving_readiness_receipts_chirho.len();
    let mut record_chirho = TenantPlacementRecordChirho {
        schema_chirho: if record_v2_chirho {
            TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO.to_string()
        } else {
            TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO.to_string()
        },
        signature_domain_chirho: if record_v2_chirho {
            TENANT_PLACEMENT_RECORD_DOMAIN_V2_CHIRHO.to_string()
        } else {
            TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO.to_string()
        },
        intent_chirho,
        intent_digest_chirho,
        serving_readiness_receipts_chirho,
        held_observer_readiness_receipt_chirho,
        placement_key_id_chirho: placement_key_chirho.clone(),
        sig_chirho: String::new(),
    };
    let unsigned_chirho = unsigned_tenant_placement_record_message_chirho(&record_chirho)
        .context("TenantPlacementRecordRenderRefusedChirho")?;
    let possession_chirho =
        sign_with_existing_key_possession_chirho(placement_sign_root_chirho, &unsigned_chirho)
            .context("TenantPlacementRecordCustodyRefusedChirho")?;
    if possession_chirho.key_id_chirho() != placement_key_chirho {
        bail!("TenantPlacementRecordCustodyChangedChirho");
    }
    record_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    verify_tenant_placement_record_chirho(
        record_chirho.clone(),
        &placement_key_chirho,
        roster_operator_key_chirho,
        geo_plan_authority_key_chirho,
    )
    .context("TenantPlacementRecordVerificationRefusedChirho")?;
    Ok(record_chirho)
}

pub fn read_json_chirho<ValueChirho: serde::de::DeserializeOwned>(
    path_chirho: &Path,
) -> Result<ValueChirho> {
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .with_context(|| format!("inspect {}", path_chirho.display()))?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        bail!("TenantPlacementAuthoringInputTypeRefusedChirho");
    }
    if metadata_chirho.len() > TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO {
        bail!("TenantPlacementAuthoringInputSizeRefusedChirho");
    }
    let mut bytes_chirho = Vec::new();
    File::open(path_chirho)
        .with_context(|| format!("open {}", path_chirho.display()))?
        .take(TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    if bytes_chirho.len() as u64 > TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO {
        bail!("TenantPlacementAuthoringInputSizeRefusedChirho");
    }
    serde_json::from_slice(&bytes_chirho)
        .with_context(|| format!("parse {}", path_chirho.display()))
}

pub fn write_new_json_chirho<ValueChirho: Serialize>(
    output_path_chirho: &Path,
    value_chirho: &ValueChirho,
) -> Result<()> {
    let parent_chirho: PathBuf = output_path_chirho
        .parent()
        .ok_or_else(|| anyhow::anyhow!("TenantPlacementAuthoringOutputParentRefusedChirho"))?
        .to_path_buf();
    std::fs::create_dir_all(&parent_chirho)
        .context("TenantPlacementAuthoringOutputDirectoryRefusedChirho")?;
    let mut bytes_chirho = serde_json::to_vec_pretty(value_chirho)
        .context("TenantPlacementAuthoringRenderRefusedChirho")?;
    bytes_chirho.push(b'\n');
    match create_complete_file_durable_with_mode_chirho(output_path_chirho, &bytes_chirho, 0o600)
        .context("TenantPlacementAuthoringWriteRefusedChirho")?
    {
        CreateFileDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
            bail!("TenantPlacementAuthoringOutputAlreadyExistsChirho")
        }
    }
}
