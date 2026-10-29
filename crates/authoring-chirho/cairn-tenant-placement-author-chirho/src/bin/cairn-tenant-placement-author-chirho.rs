// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use anyhow::{anyhow, Context, Result};
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::*;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::*;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::*;
use cairn_placement_chirho::node_lifecycle_chirho::{
    LifecycleTransitionChirho, NodeLifecycleStateChirho,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_author_chirho::authoring_chirho::{
    author_tenant_placement_adopted_successor_readiness_v2_chirho,
    author_tenant_placement_held_observer_readiness_chirho,
    author_tenant_placement_readiness_v2_chirho, author_tenant_placement_record_chirho,
    author_tenant_placement_successor_readiness_v2_chirho,
    inspect_tenant_placement_node_binding_chirho, read_json_chirho, write_new_json_chirho,
    write_tenant_placement_intent_chirho,
};
use cairn_tenant_placement_author_chirho::capacity_expectation_authoring_chirho::{
    author_placement_capacity_expectation_partial_chirho, capacity_expectation_digest_chirho,
    cosign_topology_grant_capacity_expectation_chirho,
    verify_configured_capacity_expectation_chirho,
    verify_placement_signed_capacity_expectation_partial_chirho,
};
use cairn_tenant_placement_authority_chirho::{
    tenant_placement_assignment_digest_chirho, TenantPlacementHeldObserverReadinessReceiptChirho,
    TenantPlacementIntentChirho, TenantPlacementNodeReadinessReceiptChirho,
};
use serde::Serialize;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE_CHIRHO: &str = "usage:\n  cairn-tenant-placement-author-chirho binding <tenant-root> <cluster-config.json> <node-sign-root> <provider> <region> <binding-output.json>\n  cairn-tenant-placement-author-chirho intent <intent-input.json> <intent-output.json>\n  cairn-tenant-placement-author-chirho readiness <intent.json> <tenant-root> <cluster-config.json> <runtime-config.toml> <node-sign-root> <receipt-output.json>\n  cairn-tenant-placement-author-chirho successor-readiness <intent.json> <tenant-root> <cluster-config.json> <runtime-config.toml> <node-sign-root> <receipt-output.json>\n  cairn-tenant-placement-author-chirho adopted-successor-readiness <intent.json> <tenant-root> <cluster-config.json> <runtime-config.toml> <node-sign-root> <receipt-output.json>\n  cairn-tenant-placement-author-chirho held-observer-readiness <intent.json> <tenant-root> <cluster-config.json> <node-sign-root> <receipt-output.json>\n  cairn-tenant-placement-author-chirho record <intent.json> <serving-receipt-1.json> <serving-receipt-2.json> <serving-receipt-3.json> <held-observer-receipt.json> <placement-sign-root> <roster-operator-pubkey> <geo-plan-pubkey> <record-output.json>\n  cairn-tenant-placement-author-chirho capacity <node-id> <provider> <region> <cpu-millicores> <memory-bytes> <durable-bytes> <registration-seq> <registrar-sign-root> <output.json>\n  cairn-tenant-placement-author-chirho lifecycle <node-id> <from-state> <transition> <holds-leadership> <ownership-proven> <resident-placements> <transition-seq> <lifecycle-sign-root> <output.json>\n  cairn-tenant-placement-author-chirho usage <node-id> <cpu-millicores> <memory-bytes> <durable-bytes> <hlc-millis> <sequence> <node-sign-root> <output.json>\n  cairn-tenant-placement-author-chirho capacity-expectation <cluster-config.json> <placement-population-digest> <capacity-load-snapshot-digest> <placement-sign-root> <partial-output.json>\n  cairn-tenant-placement-author-chirho capacity-expectation-partial-verify <cluster-config.json> <partial.json>\n  cairn-tenant-placement-author-chirho capacity-expectation-cosign <cluster-config.json> <partial.json> <topology-grant-sign-root>\n  cairn-tenant-placement-author-chirho capacity-expectation-verify <cluster-config.json>";

#[derive(Serialize)]
struct AuthoringReportChirho {
    operation_chirho: String,
    output_path_chirho: String,
    digest_chirho: String,
}

fn main() -> Result<()> {
    let mut args_chirho = std::env::args_os();
    let _program_chirho = args_chirho.next();
    let operation_chirho = args_chirho
        .next()
        .and_then(|value_chirho| value_chirho.into_string().ok())
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    let report_chirho = match operation_chirho.as_str() {
        "binding" => inspect_binding_chirho(&mut args_chirho)?,
        "intent" => author_intent_chirho(&mut args_chirho)?,
        "readiness" => author_readiness_chirho(&mut args_chirho)?,
        "successor-readiness" => author_successor_readiness_chirho(&mut args_chirho)?,
        "adopted-successor-readiness" => {
            author_adopted_successor_readiness_chirho(&mut args_chirho)?
        }
        "held-observer-readiness" => author_held_observer_readiness_chirho(&mut args_chirho)?,
        "record" => author_record_chirho(&mut args_chirho)?,
        "capacity" => author_node_capacity_grant_chirho(&mut args_chirho)?,
        "lifecycle" => author_node_lifecycle_transition_chirho(&mut args_chirho)?,
        "usage" => author_node_usage_measurement_chirho(&mut args_chirho)?,
        "capacity-expectation" => author_capacity_expectation_partial_chirho(&mut args_chirho)?,
        "capacity-expectation-partial-verify" => {
            verify_partial_capacity_expectation_chirho(&mut args_chirho)?
        }
        "capacity-expectation-cosign" => cosign_capacity_expectation_chirho(&mut args_chirho)?,
        "capacity-expectation-verify" => verify_capacity_expectation_chirho(&mut args_chirho)?,
        _ => return Err(anyhow!(USAGE_CHIRHO)),
    };
    if args_chirho.next().is_some() {
        return Err(anyhow!(USAGE_CHIRHO));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&report_chirho)
            .context("TenantPlacementAuthoringReportRenderRefusedChirho")?
    );
    Ok(())
}

fn author_capacity_expectation_partial_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let cluster_config_path_chirho = next_path_chirho(args_chirho)?;
    let population_digest_chirho = next_string_chirho(args_chirho)?;
    let snapshot_digest_chirho = next_string_chirho(args_chirho)?;
    let placement_sign_root_chirho = next_path_chirho(args_chirho)?;
    let output_path_chirho = next_path_chirho(args_chirho)?;
    let record_chirho = author_placement_capacity_expectation_partial_chirho(
        &cluster_config_path_chirho,
        population_digest_chirho,
        snapshot_digest_chirho,
        &placement_sign_root_chirho,
    )?;
    write_new_json_chirho(&output_path_chirho, &record_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "capacity-expectation-chirho".to_string(),
        output_path_chirho: output_path_chirho.display().to_string(),
        digest_chirho: capacity_expectation_digest_chirho(&record_chirho)?,
    })
}

fn cosign_capacity_expectation_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let cluster_config_path_chirho = next_path_chirho(args_chirho)?;
    let partial_path_chirho = next_path_chirho(args_chirho)?;
    let topology_grant_sign_root_chirho = next_path_chirho(args_chirho)?;
    let final_chirho = cosign_topology_grant_capacity_expectation_chirho(
        &cluster_config_path_chirho,
        &partial_path_chirho,
        &topology_grant_sign_root_chirho,
    )?;
    write_new_json_chirho(
        &final_chirho.configured_output_path_chirho,
        &final_chirho.record_chirho,
    )?;
    Ok(AuthoringReportChirho {
        operation_chirho: "capacity-expectation-cosign-chirho".to_string(),
        output_path_chirho: final_chirho
            .configured_output_path_chirho
            .display()
            .to_string(),
        digest_chirho: capacity_expectation_digest_chirho(&final_chirho.record_chirho)?,
    })
}

fn verify_partial_capacity_expectation_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let cluster_config_path_chirho = next_path_chirho(args_chirho)?;
    let partial_path_chirho = next_path_chirho(args_chirho)?;
    let record_chirho = verify_placement_signed_capacity_expectation_partial_chirho(
        &cluster_config_path_chirho,
        &partial_path_chirho,
    )?;
    Ok(AuthoringReportChirho {
        operation_chirho: "capacity-expectation-partial-verify-chirho".to_string(),
        output_path_chirho: partial_path_chirho.display().to_string(),
        digest_chirho: capacity_expectation_digest_chirho(&record_chirho)?,
    })
}

fn verify_capacity_expectation_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let cluster_config_path_chirho = next_path_chirho(args_chirho)?;
    let final_chirho = verify_configured_capacity_expectation_chirho(&cluster_config_path_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "capacity-expectation-verify-chirho".to_string(),
        output_path_chirho: final_chirho
            .configured_output_path_chirho
            .display()
            .to_string(),
        digest_chirho: capacity_expectation_digest_chirho(&final_chirho.record_chirho)?,
    })
}

fn inspect_binding_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let tenant_root_chirho = next_path_chirho(args_chirho)?;
    let cluster_config_chirho = next_path_chirho(args_chirho)?;
    let node_sign_root_chirho = next_path_chirho(args_chirho)?;
    let provider_chirho = next_string_chirho(args_chirho)?;
    let region_chirho = next_string_chirho(args_chirho)?;
    let output_path_chirho = next_path_chirho(args_chirho)?;
    let binding_chirho = inspect_tenant_placement_node_binding_chirho(
        &tenant_root_chirho,
        &cluster_config_chirho,
        &node_sign_root_chirho,
        FailureDomainChirho {
            provider_chirho,
            region_chirho,
        },
    )?;
    write_new_json_chirho(&output_path_chirho, &binding_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "binding-chirho".to_string(),
        output_path_chirho: output_path_chirho.display().to_string(),
        digest_chirho: blake3::hash(&serde_json::to_vec(&binding_chirho)?)
            .to_hex()
            .to_string(),
    })
}

fn author_held_observer_readiness_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let intent_path_chirho = next_path_chirho(args_chirho)?;
    let tenant_root_chirho = next_path_chirho(args_chirho)?;
    let cluster_config_chirho = next_path_chirho(args_chirho)?;
    let node_sign_root_chirho = next_path_chirho(args_chirho)?;
    let output_path_chirho = next_path_chirho(args_chirho)?;
    let intent_chirho: TenantPlacementIntentChirho = read_json_chirho(&intent_path_chirho)?;
    let prepared_at_ms_chirho = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("TenantPlacementAuthoringClockRefusedChirho")?
            .as_millis(),
    )
    .context("TenantPlacementAuthoringClockRefusedChirho")?;
    let receipt_chirho = author_tenant_placement_held_observer_readiness_chirho(
        &intent_chirho,
        &tenant_root_chirho,
        &cluster_config_chirho,
        &node_sign_root_chirho,
        prepared_at_ms_chirho,
    )?;
    write_new_json_chirho(&output_path_chirho, &receipt_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "held-observer-readiness-chirho".to_string(),
        output_path_chirho: output_path_chirho.display().to_string(),
        digest_chirho: blake3::hash(&serde_json::to_vec(&receipt_chirho)?)
            .to_hex()
            .to_string(),
    })
}

fn next_path_chirho(args_chirho: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<PathBuf> {
    args_chirho
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))
}

fn next_string_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<String> {
    args_chirho
        .next()
        .and_then(|value_chirho| value_chirho.into_string().ok())
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))
}

fn author_intent_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let input_path_chirho = next_path_chirho(args_chirho)?;
    let output_path_chirho = next_path_chirho(args_chirho)?;
    let intent_chirho: TenantPlacementIntentChirho = read_json_chirho(&input_path_chirho)?;
    let digest_chirho = write_tenant_placement_intent_chirho(&intent_chirho, &output_path_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "intent-chirho".to_string(),
        output_path_chirho: output_path_chirho.display().to_string(),
        digest_chirho,
    })
}

fn author_readiness_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let intent_path_chirho = next_path_chirho(args_chirho)?;
    let tenant_root_chirho = next_path_chirho(args_chirho)?;
    let cluster_config_chirho = next_path_chirho(args_chirho)?;
    let runtime_config_chirho = next_path_chirho(args_chirho)?;
    let node_sign_root_chirho = next_path_chirho(args_chirho)?;
    let output_path_chirho = next_path_chirho(args_chirho)?;
    let intent_chirho: TenantPlacementIntentChirho = read_json_chirho(&intent_path_chirho)?;
    let prepared_at_ms_chirho = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("TenantPlacementAuthoringClockRefusedChirho")?
            .as_millis(),
    )
    .context("TenantPlacementAuthoringClockRefusedChirho")?;
    let receipt_chirho = author_tenant_placement_readiness_v2_chirho(
        &intent_chirho,
        &tenant_root_chirho,
        &cluster_config_chirho,
        &runtime_config_chirho,
        &node_sign_root_chirho,
        prepared_at_ms_chirho,
    )?;
    write_new_json_chirho(&output_path_chirho, &receipt_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "readiness-chirho".to_string(),
        output_path_chirho: output_path_chirho.display().to_string(),
        digest_chirho: blake3::hash(&serde_json::to_vec(&receipt_chirho)?)
            .to_hex()
            .to_string(),
    })
}

fn author_successor_readiness_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let intent_path_chirho = next_path_chirho(args_chirho)?;
    let tenant_root_chirho = next_path_chirho(args_chirho)?;
    let cluster_config_chirho = next_path_chirho(args_chirho)?;
    let runtime_config_chirho = next_path_chirho(args_chirho)?;
    let node_sign_root_chirho = next_path_chirho(args_chirho)?;
    let output_path_chirho = next_path_chirho(args_chirho)?;
    let intent_chirho: TenantPlacementIntentChirho = read_json_chirho(&intent_path_chirho)?;
    let prepared_at_ms_chirho = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("TenantPlacementAuthoringClockRefusedChirho")?
            .as_millis(),
    )
    .context("TenantPlacementAuthoringClockRefusedChirho")?;
    let receipt_chirho = author_tenant_placement_successor_readiness_v2_chirho(
        &intent_chirho,
        &tenant_root_chirho,
        &cluster_config_chirho,
        &runtime_config_chirho,
        &node_sign_root_chirho,
        prepared_at_ms_chirho,
    )?;
    write_new_json_chirho(&output_path_chirho, &receipt_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "successor-readiness-chirho".to_string(),
        output_path_chirho: output_path_chirho.display().to_string(),
        digest_chirho: blake3::hash(&serde_json::to_vec(&receipt_chirho)?)
            .to_hex()
            .to_string(),
    })
}

fn author_adopted_successor_readiness_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let intent_path_chirho = next_path_chirho(args_chirho)?;
    let tenant_root_chirho = next_path_chirho(args_chirho)?;
    let cluster_config_chirho = next_path_chirho(args_chirho)?;
    let runtime_config_chirho = next_path_chirho(args_chirho)?;
    let node_sign_root_chirho = next_path_chirho(args_chirho)?;
    let output_path_chirho = next_path_chirho(args_chirho)?;
    let intent_chirho: TenantPlacementIntentChirho = read_json_chirho(&intent_path_chirho)?;
    let prepared_at_ms_chirho = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("TenantPlacementAuthoringClockRefusedChirho")?
            .as_millis(),
    )
    .context("TenantPlacementAuthoringClockRefusedChirho")?;
    let receipt_chirho = author_tenant_placement_adopted_successor_readiness_v2_chirho(
        &intent_chirho,
        &tenant_root_chirho,
        &cluster_config_chirho,
        &runtime_config_chirho,
        &node_sign_root_chirho,
        prepared_at_ms_chirho,
    )?;
    write_new_json_chirho(&output_path_chirho, &receipt_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "adopted-successor-readiness-chirho".to_string(),
        output_path_chirho: output_path_chirho.display().to_string(),
        digest_chirho: blake3::hash(&serde_json::to_vec(&receipt_chirho)?)
            .to_hex()
            .to_string(),
    })
}

fn author_record_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let intent_path_chirho = next_path_chirho(args_chirho)?;
    let receipt_paths_chirho = [
        next_path_chirho(args_chirho)?,
        next_path_chirho(args_chirho)?,
        next_path_chirho(args_chirho)?,
    ];
    let held_observer_receipt_path_chirho = next_path_chirho(args_chirho)?;
    let placement_sign_root_chirho = next_path_chirho(args_chirho)?;
    let roster_operator_key_chirho = next_string_chirho(args_chirho)?;
    let geo_plan_authority_key_chirho = next_string_chirho(args_chirho)?;
    let output_path_chirho = next_path_chirho(args_chirho)?;
    let intent_chirho: TenantPlacementIntentChirho = read_json_chirho(&intent_path_chirho)?;
    let readiness_receipts_chirho = receipt_paths_chirho
        .iter()
        .map(|path_chirho| {
            read_json_chirho::<TenantPlacementNodeReadinessReceiptChirho>(path_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    let held_observer_readiness_receipt_chirho: TenantPlacementHeldObserverReadinessReceiptChirho =
        read_json_chirho(&held_observer_receipt_path_chirho)?;
    let record_chirho = author_tenant_placement_record_chirho(
        intent_chirho,
        readiness_receipts_chirho,
        held_observer_readiness_receipt_chirho,
        &placement_sign_root_chirho,
        &roster_operator_key_chirho,
        &geo_plan_authority_key_chirho,
    )?;
    let digest_chirho = tenant_placement_assignment_digest_chirho(&record_chirho)
        .context("TenantPlacementRecordDigestRefusedChirho")?;
    write_new_json_chirho(&output_path_chirho, &record_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "record-chirho".to_string(),
        output_path_chirho: output_path_chirho.display().to_string(),
        digest_chirho,
    })
}

// ---------------------------------------------------------------------------------------------
// NODE EVIDENCE AUTHORING
//
// The capacity, lifecycle and usage records had no operator authoring path at all: each
// unsigned-message builder had exactly one production caller — its own module — and every other
// mention was a test. So an operator could not PRODUCE a signed grant, only verify one, and a host
// survey found the corresponding logs absent for that reason rather than through neglect.
//
// These live in the existing authoring binary rather than a new tool because this binary already
// owns signing-key custody and its argv conventions. A second signing tool would be a second place
// where key custody is handled, and a second place is where a distinction gets laundered.
//
// Each emits a signed record and NOTHING ELSE — no append, no store, no decision. The matching
// appender consumes them.
// ---------------------------------------------------------------------------------------------

fn author_node_capacity_grant_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let node_id_chirho = next_string_chirho(args_chirho)?;
    let provider_chirho = next_string_chirho(args_chirho)?;
    let region_chirho = next_string_chirho(args_chirho)?;
    let cpu_chirho = next_u64_chirho(args_chirho)?;
    let memory_chirho = next_u64_chirho(args_chirho)?;
    let durable_chirho = next_u64_chirho(args_chirho)?;
    let registration_seq_chirho = next_u64_chirho(args_chirho)?;
    let sign_root_chirho = next_path_chirho(args_chirho)?;
    let output_chirho = next_path_chirho(args_chirho)?;

    let intent_chirho = NodeCapacityIntentChirho {
        schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho,
        domain_chirho: FailureDomainChirho {
            provider_chirho,
            region_chirho,
        },
        allocatable_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: cpu_chirho,
            memory_bytes_chirho: memory_chirho,
            durable_bytes_chirho: durable_chirho,
        },
        registration_seq_chirho,
    };
    let mut record_chirho = NodeCapacityAttestationChirho {
        schema_chirho: NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: node_capacity_intent_digest_chirho(&intent_chirho).map_err(
            |refusal_chirho| anyhow!("NodeCapacityIntentDigestRefusedChirho: {refusal_chirho:?}"),
        )?,
        intent_chirho,
        authority_key_id_chirho: pubkey_hex_chirho(&sign_root_chirho)
            .context("NodeCapacityRegistrarPubkeyRefusedChirho")?,
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        &sign_root_chirho,
        unsigned_node_capacity_message_chirho(&record_chirho).as_bytes(),
    )
    .context("NodeCapacityAttestationSignRefusedChirho")?;
    write_new_json_chirho(&output_chirho, &record_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "capacity".to_string(),
        output_path_chirho: output_chirho.display().to_string(),
        digest_chirho: record_chirho.intent_digest_chirho.clone(),
    })
}

fn author_node_lifecycle_transition_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let node_id_chirho = next_string_chirho(args_chirho)?;
    let from_state_chirho = next_lifecycle_state_chirho(args_chirho)?;
    let transition_chirho = next_lifecycle_transition_chirho(args_chirho)?;
    let holds_leadership_chirho = next_bool_chirho(args_chirho)?;
    let ownership_proven_chirho = next_bool_chirho(args_chirho)?;
    let resident_placements_chirho = u32::try_from(next_u64_chirho(args_chirho)?)
        .map_err(|_error_chirho| anyhow!("LifecycleResidentPlacementsOutOfRangeChirho"))?;
    let transition_seq_chirho = next_u64_chirho(args_chirho)?;
    let sign_root_chirho = next_path_chirho(args_chirho)?;
    let output_chirho = next_path_chirho(args_chirho)?;

    let intent_chirho = LifecycleTransitionIntentChirho {
        schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho,
        from_state_chirho,
        transition_chirho,
        asserted_facts_chirho: AssertedLifecycleFactsChirho {
            holds_leadership_chirho,
            ownership_proven_chirho,
            resident_placements_chirho,
        },
        transition_seq_chirho,
    };
    let mut record_chirho = LifecycleTransitionAttestationChirho {
        schema_chirho: LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: lifecycle_intent_digest_chirho(&intent_chirho).map_err(
            |refusal_chirho| anyhow!("LifecycleIntentDigestRefusedChirho: {refusal_chirho:?}"),
        )?,
        intent_chirho,
        authority_key_id_chirho: pubkey_hex_chirho(&sign_root_chirho)
            .context("LifecycleAuthorityPubkeyRefusedChirho")?,
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        &sign_root_chirho,
        unsigned_lifecycle_message_chirho(&record_chirho).as_bytes(),
    )
    .context("LifecycleAttestationSignRefusedChirho")?;
    write_new_json_chirho(&output_chirho, &record_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "lifecycle".to_string(),
        output_path_chirho: output_chirho.display().to_string(),
        digest_chirho: record_chirho.intent_digest_chirho.clone(),
    })
}

fn author_node_usage_measurement_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<AuthoringReportChirho> {
    let node_id_chirho = next_string_chirho(args_chirho)?;
    let cpu_chirho = next_u64_chirho(args_chirho)?;
    let memory_chirho = next_u64_chirho(args_chirho)?;
    let durable_chirho = next_u64_chirho(args_chirho)?;
    let hlc_millis_chirho = next_u64_chirho(args_chirho)?;
    let sequence_chirho = next_u64_chirho(args_chirho)?;
    let sign_root_chirho = next_path_chirho(args_chirho)?;
    let output_chirho = next_path_chirho(args_chirho)?;

    let intent_chirho = UsageMeasurementIntentChirho {
        schema_chirho: USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho,
        stamp_chirho: MeasurementStampChirho {
            hlc_millis_chirho,
            sequence_chirho,
        },
        observed_usage_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: cpu_chirho,
            memory_bytes_chirho: memory_chirho,
            durable_bytes_chirho: durable_chirho,
        },
    };
    let mut record_chirho = UsageMeasurementAttestationChirho {
        schema_chirho: USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: usage_intent_digest_chirho(&intent_chirho).map_err(
            |refusal_chirho| {
                anyhow!("UsageMeasurementIntentDigestRefusedChirho: {refusal_chirho:?}")
            },
        )?,
        intent_chirho,
        node_key_id_chirho: pubkey_hex_chirho(&sign_root_chirho)
            .context("UsageMeasurementNodePubkeyRefusedChirho")?,
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        &sign_root_chirho,
        unsigned_usage_message_chirho(&record_chirho).as_bytes(),
    )
    .context("UsageMeasurementSignRefusedChirho")?;
    write_new_json_chirho(&output_chirho, &record_chirho)?;
    Ok(AuthoringReportChirho {
        operation_chirho: "usage".to_string(),
        output_path_chirho: output_chirho.display().to_string(),
        digest_chirho: record_chirho.intent_digest_chirho.clone(),
    })
}

fn next_u64_chirho(args_chirho: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<u64> {
    next_string_chirho(args_chirho)?
        .parse()
        .map_err(|_error_chirho| anyhow!(USAGE_CHIRHO))
}

/// Explicit `true` / `false` only. A bare presence flag would let a typo assert leadership.
fn next_bool_chirho(args_chirho: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<bool> {
    match next_string_chirho(args_chirho)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(anyhow!(USAGE_CHIRHO)),
    }
}

fn next_lifecycle_state_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<NodeLifecycleStateChirho> {
    let value_chirho = next_string_chirho(args_chirho)?;
    serde_json::from_str(&format!("\"{value_chirho}\""))
        .map_err(|_error_chirho| anyhow!(USAGE_CHIRHO))
}

fn next_lifecycle_transition_chirho(
    args_chirho: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<LifecycleTransitionChirho> {
    let value_chirho = next_string_chirho(args_chirho)?;
    serde_json::from_str(&format!("\"{value_chirho}\""))
        .map_err(|_error_chirho| anyhow!(USAGE_CHIRHO))
}
