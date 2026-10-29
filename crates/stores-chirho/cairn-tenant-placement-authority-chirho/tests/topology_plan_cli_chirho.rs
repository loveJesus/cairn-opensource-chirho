// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proof by EXECUTION of the shipped `cairn-topology-plan-verify-chirho` binary.
//!
//! Every helper here carries a `topology_cli_` prefix on purpose. A workspace census propagates
//! function names defined EXACTLY ONCE, so a test-local helper sharing a name with a production entry
//! point silently drops unrelated files out of a security guard — which is exactly what happened when
//! a helper in the sibling CLI test was called `run_cli_chirho`, the name of the main CLI dispatch.

use cairn_placement_chirho::topology_chirho::topology_grant_attestation_chirho::*;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::{
    DesiredTopologyPlanChirho, NodeRoleChirho, PlannedNodeChirho, TopologyGrantChirho,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::single_role_verifier_chirho;
use cairn_tenant_placement_authority_chirho::topology_chirho::grant_store_chirho::append_verified_topology_grant_chirho;
use cairn_tenant_placement_authority_chirho::topology_chirho::plan_store_chirho::store_topology_plan_chirho;
use std::path::Path;
use std::process::Command;

const TOPOLOGY_CLI_PRINCIPAL_CHIRHO: &str = "planner-principal-chirho";

struct TopologyCliWorldChirho {
    root_chirho: tempfile::TempDir,
    key_root_chirho: tempfile::TempDir,
    pubkey_chirho: String,
}

fn topology_cli_world_chirho() -> TopologyCliWorldChirho {
    let key_root_chirho = tempfile::tempdir().expect("key root");
    let pubkey_chirho = pubkey_hex_chirho(key_root_chirho.path()).expect("pubkey");
    TopologyCliWorldChirho {
        root_chirho: tempfile::tempdir().expect("root"),
        key_root_chirho,
        pubkey_chirho,
    }
}

fn topology_cli_seed_grant_chirho(world_chirho: &TopologyCliWorldChirho, max_nodes_chirho: u32) {
    let intent_chirho = TopologyGrantIntentChirho {
        schema_chirho: TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        principal_chirho: TOPOLOGY_CLI_PRINCIPAL_CHIRHO.to_string(),
        grant_chirho: TopologyGrantChirho {
            grant_id_chirho: "grant-a-chirho".to_string(),
            max_nodes_chirho,
            max_spend_rate_micros_per_hour_chirho: 1_000_000,
            allowed_providers_chirho: ["hetzner-chirho".to_string()].into_iter().collect(),
            minimum_control_nodes_chirho: 1,
            minimum_storage_nodes_chirho: 1,
        },
        issued_seq_chirho: 1,
    };
    let mut record_chirho = TopologyGrantAttestationChirho {
        schema_chirho: TOPOLOGY_GRANT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TOPOLOGY_GRANT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: topology_grant_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: world_chirho.pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        world_chirho.key_root_chirho.path(),
        unsigned_topology_grant_message_chirho(&record_chirho).as_bytes(),
    )
    .expect("sign");
    append_verified_topology_grant_chirho(
        world_chirho.root_chirho.path(),
        &record_chirho,
        &single_role_verifier_chirho(&world_chirho.pubkey_chirho).expect("verifier"),
    )
    .expect("seed grant");
}

fn topology_cli_plan_chirho(node_count_chirho: usize) -> DesiredTopologyPlanChirho {
    let mut nodes_chirho = vec![
        PlannedNodeChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            role_chirho: NodeRoleChirho::ControlChirho,
        },
        PlannedNodeChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            role_chirho: NodeRoleChirho::StorageChirho,
        },
    ];
    while nodes_chirho.len() < node_count_chirho {
        nodes_chirho.push(PlannedNodeChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            role_chirho: NodeRoleChirho::WorkerChirho,
        });
    }
    DesiredTopologyPlanChirho {
        cited_grant_id_chirho: "grant-a-chirho".to_string(),
        nodes_chirho,
        spend_rate_micros_per_hour_chirho: 500_000,
        proposed_grant_chirho: None,
    }
}

fn topology_cli_run_chirho(
    root_chirho: &Path,
    key_chirho: &str,
    digest_chirho: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cairn-topology-plan-verify-chirho"))
        .arg(root_chirho)
        .arg(key_chirho)
        .arg(TOPOLOGY_CLI_PRINCIPAL_CHIRHO)
        .arg(digest_chirho)
        .output()
        .expect("run the shipped binary")
}

#[test]
fn the_shipped_binary_permits_a_plan_inside_a_real_signed_grant_chirho() {
    // POSITIVE CONTROL. Everything below is a refusal, and a binary that refused everything would
    // satisfy all of them.
    let world_chirho = topology_cli_world_chirho();
    topology_cli_seed_grant_chirho(&world_chirho, 10);
    let digest_chirho = store_topology_plan_chirho(
        world_chirho.root_chirho.path(),
        &topology_cli_plan_chirho(3),
    )
    .expect("store plan");

    let output_chirho = topology_cli_run_chirho(
        world_chirho.root_chirho.path(),
        &world_chirho.pubkey_chirho,
        &digest_chirho,
    );
    assert!(
        output_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(stdout_chirho.contains("topology-plan-authority-report-v1-chirho"));
    assert!(
        stdout_chirho.contains("\"permitted_chirho\":true"),
        "{stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("\"planned_nodes_chirho\":3"),
        "{stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("\"max_nodes_chirho\":10"),
        "the ceiling comes from the SIGNED grant on disk: {stdout_chirho}"
    );
}

#[test]
fn the_shipped_binary_reports_an_over_bound_plan_without_failing_chirho() {
    // Over-bound REPORTS rather than errors: refusing to answer would hide the reason, and the reason
    // is what an operator came for.
    let world_chirho = topology_cli_world_chirho();
    topology_cli_seed_grant_chirho(&world_chirho, 3);
    let digest_chirho = store_topology_plan_chirho(
        world_chirho.root_chirho.path(),
        &topology_cli_plan_chirho(9),
    )
    .expect("store plan");

    let output_chirho = topology_cli_run_chirho(
        world_chirho.root_chirho.path(),
        &world_chirho.pubkey_chirho,
        &digest_chirho,
    );
    assert!(output_chirho.status.success());
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(
        stdout_chirho.contains("\"permitted_chirho\":false"),
        "{stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("NodeCountOverBoundChirho"),
        "{stdout_chirho}"
    );
}

#[test]
fn a_missing_grant_exits_nonzero_and_is_not_a_bounds_verdict_chirho() {
    // NOTHING WAS CHECKED. Reporting this as `permitted: false` would read as "we looked, and no".
    let world_chirho = topology_cli_world_chirho();
    let digest_chirho = store_topology_plan_chirho(
        world_chirho.root_chirho.path(),
        &topology_cli_plan_chirho(3),
    )
    .expect("store plan");

    let output_chirho = topology_cli_run_chirho(
        world_chirho.root_chirho.path(),
        &world_chirho.pubkey_chirho,
        &digest_chirho,
    );
    assert!(!output_chirho.status.success());
    let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr);
    assert!(
        stderr_chirho.contains("NoGrantForPrincipalChirho"),
        "{stderr_chirho}"
    );
    assert!(
        !String::from_utf8_lossy(&output_chirho.stdout).contains("permitted_chirho"),
        "no report should be printed at all"
    );
}

#[test]
fn a_dangling_plan_digest_exits_nonzero_as_a_reference_refusal_chirho() {
    // Clause 9's point, at the shipped surface: a hash resolving to nothing is evidence of nothing.
    let world_chirho = topology_cli_world_chirho();
    topology_cli_seed_grant_chirho(&world_chirho, 10);
    let output_chirho = topology_cli_run_chirho(
        world_chirho.root_chirho.path(),
        &world_chirho.pubkey_chirho,
        &"b".repeat(64),
    );
    assert!(!output_chirho.status.success());
    let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr);
    assert!(
        stderr_chirho.contains("PlanReferenceChirho"),
        "{stderr_chirho}"
    );
    assert!(
        stderr_chirho.contains("PlanAbsentChirho"),
        "{stderr_chirho}"
    );
}

#[test]
fn the_topology_report_prints_no_key_material_or_paths_chirho() {
    let world_chirho = topology_cli_world_chirho();
    topology_cli_seed_grant_chirho(&world_chirho, 10);
    let digest_chirho = store_topology_plan_chirho(
        world_chirho.root_chirho.path(),
        &topology_cli_plan_chirho(3),
    )
    .expect("store plan");
    let output_chirho = topology_cli_run_chirho(
        world_chirho.root_chirho.path(),
        &world_chirho.pubkey_chirho,
        &digest_chirho,
    );
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(!stdout_chirho.contains(world_chirho.pubkey_chirho.as_str()));
    assert!(!stdout_chirho.contains(&*world_chirho.root_chirho.path().to_string_lossy()));
}
