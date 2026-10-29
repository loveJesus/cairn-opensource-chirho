// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proof by EXECUTION that the three node-evidence authoring subcommands emit VERIFIABLE records.
//!
//! An authoring tool has a failure mode a file check cannot see: it can write a well-formed record
//! that does not verify. "It wrote a file" and "it wrote something the production verifier accepts"
//! are different claims, and only the second is worth anything to an operator staging evidence for a
//! migration admission.
//!
//! So each positive control here runs the shipped binary, reads the artifact back off disk, and puts
//! it through **the same verifier the stores use** — not a re-implementation. A signing bug, a wrong
//! domain constant, or a digest computed over the wrong bytes fails these arms.
//!
//! Helpers carry `..._authoring_cli_..._chirho` names because a workspace guard censuses by
//! propagating function names defined exactly once.

use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::{
    verify_node_capacity_attestation_chirho, NodeCapacityAttestationChirho,
};
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::{
    verify_usage_measurement_chirho, UsageMeasurementAttestationChirho,
};
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::{
    verify_lifecycle_attestation_chirho, LifecycleTransitionAttestationChirho,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_author_chirho::authoring_chirho::author_tenant_placement_record_chirho;
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::capacity_admission_expectation_chirho::{
    load_and_verify_tenant_migration_capacity_expectation_chirho,
    tenant_migration_capacity_expectation_digest_chirho,
    verify_placement_signed_tenant_migration_capacity_expectation_chirho,
    TenantMigrationCapacityExpectationChirho, TenantMigrationCapacityExpectationContextChirho,
};
use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::single_role_verifier_chirho;
use cairn_tenant_placement_authority_chirho::{
    tenant_placement_assignment_digest_chirho, tenant_placement_intent_digest_chirho,
    unsigned_tenant_placement_held_observer_readiness_message_chirho,
    unsigned_tenant_placement_readiness_message_chirho,
    TenantPlacementHeldObserverReadinessReceiptChirho, TenantPlacementIntentChirho,
    TenantPlacementNodeBindingChirho, TenantPlacementNodeReadinessReceiptChirho,
    TenantPlacementResidencyChirho, TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO, TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO, TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

const AUTHORING_CLI_NODE_CHIRHO: &str = "authoring-cli-node-chirho";

fn authoring_cli_key_chirho(root_chirho: &Path) -> String {
    sign_message_chirho(root_chirho, b"provision-authoring-cli-chirho").expect("provision");
    pubkey_hex_chirho(root_chirho).expect("pubkey")
}

fn run_authoring_cli_chirho(arguments_chirho: &[&str]) -> (bool, String, String) {
    let output_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-tenant-placement-author-chirho"))
        .args(arguments_chirho)
        .output()
        .expect("the shipped authoring binary runs");
    (
        output_chirho.status.success(),
        String::from_utf8_lossy(&output_chirho.stdout).to_string(),
        String::from_utf8_lossy(&output_chirho.stderr).to_string(),
    )
}

fn read_authored_chirho<RecordChirho: serde::de::DeserializeOwned>(
    path_chirho: &PathBuf,
) -> RecordChirho {
    serde_json::from_slice(&std::fs::read(path_chirho).expect("the artifact exists"))
        .expect("the artifact decodes")
}

/// CAPACITY — authored, then accepted by the production verifier.
#[test]
fn an_authored_capacity_grant_verifies_through_the_production_verifier_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let sign_root_chirho = temp_chirho.path().join("registrar-chirho");
    let key_chirho = authoring_cli_key_chirho(&sign_root_chirho);
    let output_chirho = temp_chirho.path().join("grant-chirho.json");

    let (ok_chirho, stdout_chirho, stderr_chirho) = run_authoring_cli_chirho(&[
        "capacity",
        AUTHORING_CLI_NODE_CHIRHO,
        "hetzner-chirho",
        "fsn1-chirho",
        "8000",
        "34359738368",
        "1099511627776",
        "1",
        sign_root_chirho.to_str().unwrap(),
        output_chirho.to_str().unwrap(),
    ]);
    assert!(ok_chirho, "authoring must succeed: {stderr_chirho}");
    assert!(stdout_chirho.contains("capacity"), "{stdout_chirho}");

    let record_chirho: NodeCapacityAttestationChirho = read_authored_chirho(&output_chirho);
    let authority_chirho = single_role_verifier_chirho(&key_chirho).expect("verifier");
    verify_node_capacity_attestation_chirho(
        &record_chirho,
        &authority_chirho,
        AUTHORING_CLI_NODE_CHIRHO,
    )
    .expect("THE POINT: the emitted artifact must verify, not merely exist");
    assert_eq!(record_chirho.intent_chirho.registration_seq_chirho, 1);
    assert_eq!(
        record_chirho
            .intent_chirho
            .allocatable_chirho
            .cpu_millicores_chirho,
        8000
    );
}

/// LIFECYCLE — authored, then accepted by the production verifier.
#[test]
fn an_authored_lifecycle_transition_verifies_through_the_production_verifier_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let sign_root_chirho = temp_chirho.path().join("lifecycle-chirho");
    let key_chirho = authoring_cli_key_chirho(&sign_root_chirho);
    let output_chirho = temp_chirho.path().join("transition-chirho.json");

    let (ok_chirho, _stdout_chirho, stderr_chirho) = run_authoring_cli_chirho(&[
        "lifecycle",
        AUTHORING_CLI_NODE_CHIRHO,
        "ProvisionedChirho",
        "InspectChirho",
        "false",
        "true",
        "0",
        "1",
        sign_root_chirho.to_str().unwrap(),
        output_chirho.to_str().unwrap(),
    ]);
    assert!(ok_chirho, "authoring must succeed: {stderr_chirho}");

    let record_chirho: LifecycleTransitionAttestationChirho = read_authored_chirho(&output_chirho);
    let authority_chirho = single_role_verifier_chirho(&key_chirho).expect("verifier");
    verify_lifecycle_attestation_chirho(
        &record_chirho,
        &authority_chirho,
        AUTHORING_CLI_NODE_CHIRHO,
    )
    .expect("THE POINT: the emitted artifact must verify, not merely exist");
    assert_eq!(record_chirho.intent_chirho.transition_seq_chirho, 1);
}

/// USAGE — authored, then accepted by the production verifier.
#[test]
fn an_authored_usage_measurement_verifies_through_the_production_verifier_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let sign_root_chirho = temp_chirho.path().join("node-chirho");
    let key_chirho = authoring_cli_key_chirho(&sign_root_chirho);
    let output_chirho = temp_chirho.path().join("usage-chirho.json");

    let (ok_chirho, _stdout_chirho, stderr_chirho) = run_authoring_cli_chirho(&[
        "usage",
        AUTHORING_CLI_NODE_CHIRHO,
        "3000",
        "1073741824",
        "10737418240",
        "1786542000000",
        "1",
        sign_root_chirho.to_str().unwrap(),
        output_chirho.to_str().unwrap(),
    ]);
    assert!(ok_chirho, "authoring must succeed: {stderr_chirho}");

    let record_chirho: UsageMeasurementAttestationChirho = read_authored_chirho(&output_chirho);
    let authority_chirho = single_role_verifier_chirho(&key_chirho).expect("verifier");
    verify_usage_measurement_chirho(&record_chirho, &authority_chirho, AUTHORING_CLI_NODE_CHIRHO)
        .expect("THE POINT: the emitted artifact must verify, not merely exist");
    assert_eq!(record_chirho.intent_chirho.stamp_chirho.sequence_chirho, 1);
    assert_eq!(
        record_chirho
            .intent_chirho
            .observed_usage_chirho
            .cpu_millicores_chirho,
        3000
    );
}

/// A lifecycle fact must be spelled `true` or `false`, never asserted by a typo.
#[test]
fn an_unspellable_lifecycle_fact_refuses_rather_than_defaulting_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let sign_root_chirho = temp_chirho.path().join("lifecycle-chirho");
    authoring_cli_key_chirho(&sign_root_chirho);
    let output_chirho = temp_chirho.path().join("never-chirho.json");

    let (ok_chirho, _stdout_chirho, _stderr_chirho) = run_authoring_cli_chirho(&[
        "lifecycle",
        AUTHORING_CLI_NODE_CHIRHO,
        "ProvisionedChirho",
        "InspectChirho",
        "yes",
        "true",
        "0",
        "1",
        sign_root_chirho.to_str().unwrap(),
        output_chirho.to_str().unwrap(),
    ]);
    assert!(!ok_chirho, "\"yes\" is not a bool and must refuse");
    assert!(
        !output_chirho.exists(),
        "a refused authoring run writes no artifact"
    );
}

struct CapacityExpectationCliFixtureChirho {
    _temp_chirho: tempfile::TempDir,
    cluster_config_path_chirho: PathBuf,
    evidence_root_chirho: PathBuf,
    partial_path_chirho: PathBuf,
    final_path_chirho: PathBuf,
    placement_sign_root_chirho: PathBuf,
    topology_grant_sign_root_chirho: PathBuf,
    wrong_topology_sign_root_chirho: PathBuf,
    cluster_config_blake3_chirho: String,
    tenant_id_chirho: String,
    placement_revision_chirho: u64,
    assignment_digest_chirho: String,
    placement_key_chirho: String,
    topology_grant_key_chirho: String,
}

fn write_private_authoring_cli_file_chirho(path_chirho: &Path, bytes_chirho: &[u8]) {
    std::fs::write(path_chirho, bytes_chirho).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn capacity_expectation_cli_fixture_chirho() -> CapacityExpectationCliFixtureChirho {
    let temp_chirho = tempfile::tempdir().unwrap();
    let tenant_id_chirho = "credits-demo-chirho".to_string();
    let placement_sign_root_chirho = temp_chirho.path().join("placement-sign-chirho");
    let roster_sign_root_chirho = temp_chirho.path().join("roster-sign-chirho");
    let geo_plan_sign_root_chirho = temp_chirho.path().join("geo-plan-sign-chirho");
    let topology_grant_sign_root_chirho = temp_chirho.path().join("topology-grant-sign-chirho");
    let wrong_topology_sign_root_chirho = temp_chirho.path().join("wrong-topology-sign-chirho");
    let capacity_sign_root_chirho = temp_chirho.path().join("capacity-sign-chirho");
    let lifecycle_sign_root_chirho = temp_chirho.path().join("lifecycle-sign-chirho");
    let budget_sign_root_chirho = temp_chirho.path().join("budget-sign-chirho");
    let placement_key_chirho = authoring_cli_key_chirho(&placement_sign_root_chirho);
    let roster_key_chirho = authoring_cli_key_chirho(&roster_sign_root_chirho);
    let geo_plan_key_chirho = authoring_cli_key_chirho(&geo_plan_sign_root_chirho);
    let topology_grant_key_chirho = authoring_cli_key_chirho(&topology_grant_sign_root_chirho);
    authoring_cli_key_chirho(&wrong_topology_sign_root_chirho);
    let capacity_key_chirho = authoring_cli_key_chirho(&capacity_sign_root_chirho);
    let lifecycle_key_chirho = authoring_cli_key_chirho(&lifecycle_sign_root_chirho);
    let budget_key_chirho = authoring_cli_key_chirho(&budget_sign_root_chirho);

    let mut node_roots_chirho = (0..4)
        .map(|index_chirho| {
            let root_chirho = temp_chirho
                .path()
                .join(format!("expectation-node-{index_chirho}-chirho"));
            let key_chirho = authoring_cli_key_chirho(&root_chirho);
            (key_chirho, root_chirho)
        })
        .collect::<Vec<_>>();
    node_roots_chirho.sort_by(|left_chirho, right_chirho| left_chirho.0.cmp(&right_chirho.0));
    let held_observer_chirho = node_roots_chirho.pop().unwrap();
    let measurement_keys_chirho = (0..3)
        .map(|index_chirho| {
            authoring_cli_key_chirho(
                &temp_chirho
                    .path()
                    .join(format!("measurement-{index_chirho}-chirho")),
            )
        })
        .collect::<Vec<_>>();

    let evidence_root_chirho = temp_chirho.path().join("capacity-evidence-root-chirho");
    std::fs::create_dir(&evidence_root_chirho).unwrap();
    let partial_path_chirho = temp_chirho.path().join("expectation-partial-chirho.json");
    let final_path_chirho = temp_chirho.path().join("expectation-final-chirho.json");
    let placement_record_path_chirho = temp_chirho.path().join("placement-record-chirho.json");
    let cluster_config_path_chirho = temp_chirho.path().join("cluster-config-chirho.json");
    let node_measurement_pubkeys_chirho = node_roots_chirho
        .iter()
        .zip(&measurement_keys_chirho)
        .map(|((node_id_chirho, _root_chirho), measurement_key_chirho)| {
            (node_id_chirho.clone(), measurement_key_chirho.clone())
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let config_chirho = json!({
        "group_chirho": {
            "kind_chirho": "tenant",
            "tenant_id_chirho": tenant_id_chirho
        },
        "local_raft_id_chirho": 1,
        "members_chirho": [{
            "raft_id_chirho": 1,
            "pubkey_chirho": node_roots_chirho[0].0,
            "url_chirho": "http://127.0.0.1:19300",
            "learner_chirho": false
        }],
        "durable_dir_chirho": temp_chirho.path().join("raft-chirho"),
        "sign_root_chirho": node_roots_chirho[0].1,
        "listen_addr_chirho": "127.0.0.1:19300",
        "tick_ms_chirho": 50,
        "roster_authority_chirho": {
            "roster_path_chirho": temp_chirho.path().join("roster-chirho.jsonl"),
            "roster_head_path_chirho": temp_chirho.path().join("roster-head-chirho.json"),
            "operator_pubkey_hex_chirho": roster_key_chirho
        },
        "tenant_placement_chirho": {
            "placement_record_path_chirho": placement_record_path_chirho,
            "placement_pubkey_hex_chirho": placement_key_chirho,
            "geo_plan_pubkey_hex_chirho": geo_plan_key_chirho
        },
        "tenant_migration_capacity_chirho": {
            "schema_chirho": "tenant-migration-capacity-config-v2-chirho",
            "evidence_root_chirho": evidence_root_chirho,
            "expectation_record_path_chirho": final_path_chirho,
            "expectation_revision_chirho": 7,
            "capacity_registrar_pubkey_hex_chirho": capacity_key_chirho,
            "lifecycle_pubkey_hex_chirho": lifecycle_key_chirho,
            "topology_grant_pubkey_hex_chirho": topology_grant_key_chirho,
            "budget_pubkey_hex_chirho": budget_key_chirho,
            "node_measurement_pubkeys_chirho": node_measurement_pubkeys_chirho,
            "headroom_chirho": {
                "cpu_millicores_chirho": 500,
                "memory_bytes_chirho": 1048576,
                "durable_bytes_chirho": 10485760
            }
        }
    });
    let config_bytes_chirho = serde_json::to_vec(&config_chirho).unwrap();
    write_private_authoring_cli_file_chirho(&cluster_config_path_chirho, &config_bytes_chirho);
    let cluster_config_blake3_chirho = blake3::hash(&config_bytes_chirho).to_hex().to_string();

    let domains_chirho = [
        FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "de-fsn-chirho".to_string(),
        },
        FailureDomainChirho {
            provider_chirho: "ovh-chirho".to_string(),
            region_chirho: "fr-gra-chirho".to_string(),
        },
        FailureDomainChirho {
            provider_chirho: "ovh-chirho".to_string(),
            region_chirho: "fr-rbx-chirho".to_string(),
        },
    ];
    let assigned_nodes_chirho = node_roots_chirho
        .iter()
        .enumerate()
        .map(
            |(index_chirho, (node_id_chirho, _root_chirho))| TenantPlacementNodeBindingChirho {
                node_id_chirho: node_id_chirho.clone(),
                failure_domain_chirho: domains_chirho[index_chirho].clone(),
                expected_root_binding_chirho: format!(
                    "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
                    char::from(b'a' + u8::try_from(index_chirho).unwrap())
                        .to_string()
                        .repeat(64)
                ),
                expected_cluster_config_blake3_chirho: if index_chirho == 0 {
                    cluster_config_blake3_chirho.clone()
                } else {
                    char::from(b'd' + u8::try_from(index_chirho).unwrap())
                        .to_string()
                        .repeat(64)
                },
            },
        )
        .collect::<Vec<_>>();
    let held_observer_node_chirho = TenantPlacementNodeBindingChirho {
        node_id_chirho: held_observer_chirho.0.clone(),
        failure_domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fi-hel-chirho".to_string(),
        },
        expected_root_binding_chirho: format!(
            "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
            "1".repeat(64)
        ),
        expected_cluster_config_blake3_chirho: "2".repeat(64),
    };
    let mut allowed_domains_chirho = domains_chirho.to_vec();
    allowed_domains_chirho.sort();
    let intent_chirho = TenantPlacementIntentChirho {
        schema_chirho: TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        digest_domain_chirho: TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO.to_string(),
        revision_chirho: 0,
        previous_assignment_digest_chirho: None,
        tenant_id_chirho: tenant_id_chirho.clone(),
        consistency_group_id_chirho: format!("tenant-chirho:{tenant_id_chirho}"),
        preferred_node_chirho: assigned_nodes_chirho[0].node_id_chirho.clone(),
        assigned_nodes_chirho,
        held_observer_node_chirho,
        demand_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 500,
            memory_bytes_chirho: 512 * 1024 * 1024,
            durable_bytes_chirho: 10 * 1024 * 1024 * 1024,
        },
        residency_chirho: TenantPlacementResidencyChirho {
            allowed_domains_chirho,
        },
        topology_plan_digest_chirho: "9".repeat(64),
    };
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(&intent_chirho).unwrap();
    let serving_receipts_chirho = node_roots_chirho
        .iter()
        .zip(&intent_chirho.assigned_nodes_chirho)
        .enumerate()
        .map(
            |(index_chirho, ((node_id_chirho, root_chirho), binding_chirho))| {
                let mut receipt_chirho = TenantPlacementNodeReadinessReceiptChirho {
                    schema_chirho: TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO.to_string(),
                    signature_domain_chirho: TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO
                        .to_string(),
                    intent_digest_chirho: intent_digest_chirho.clone(),
                    node_id_chirho: node_id_chirho.clone(),
                    failure_domain_chirho: binding_chirho.failure_domain_chirho.clone(),
                    root_binding_chirho: binding_chirho.expected_root_binding_chirho.clone(),
                    cluster_config_blake3_chirho: binding_chirho
                        .expected_cluster_config_blake3_chirho
                        .clone(),
                    activation_anchor_digest_chirho: None,
                    prepared_at_ms_chirho: 1_786_542_000_000 + index_chirho as u64,
                    signer_key_id_chirho: node_id_chirho.clone(),
                    sig_chirho: String::new(),
                };
                receipt_chirho.sig_chirho = sign_message_chirho(
                    root_chirho,
                    &unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho).unwrap(),
                )
                .unwrap();
                receipt_chirho
            },
        )
        .collect::<Vec<_>>();
    let mut held_receipt_chirho = TenantPlacementHeldObserverReadinessReceiptChirho {
        schema_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO
            .to_string(),
        intent_digest_chirho: intent_digest_chirho.clone(),
        node_id_chirho: held_observer_chirho.0.clone(),
        failure_domain_chirho: intent_chirho
            .held_observer_node_chirho
            .failure_domain_chirho
            .clone(),
        root_binding_chirho: intent_chirho
            .held_observer_node_chirho
            .expected_root_binding_chirho
            .clone(),
        cluster_config_blake3_chirho: intent_chirho
            .held_observer_node_chirho
            .expected_cluster_config_blake3_chirho
            .clone(),
        prepared_at_ms_chirho: 1_786_542_000_100,
        signer_key_id_chirho: held_observer_chirho.0.clone(),
        sig_chirho: String::new(),
    };
    held_receipt_chirho.sig_chirho = sign_message_chirho(
        &held_observer_chirho.1,
        &unsigned_tenant_placement_held_observer_readiness_message_chirho(&held_receipt_chirho)
            .unwrap(),
    )
    .unwrap();
    let placement_record_chirho = author_tenant_placement_record_chirho(
        intent_chirho,
        serving_receipts_chirho,
        held_receipt_chirho,
        &placement_sign_root_chirho,
        &roster_key_chirho,
        &geo_plan_key_chirho,
    )
    .unwrap();
    let assignment_digest_chirho =
        tenant_placement_assignment_digest_chirho(&placement_record_chirho).unwrap();
    write_private_authoring_cli_file_chirho(
        &placement_record_path_chirho,
        &serde_json::to_vec(&placement_record_chirho).unwrap(),
    );

    CapacityExpectationCliFixtureChirho {
        _temp_chirho: temp_chirho,
        cluster_config_path_chirho,
        evidence_root_chirho,
        partial_path_chirho,
        final_path_chirho,
        placement_sign_root_chirho,
        topology_grant_sign_root_chirho,
        wrong_topology_sign_root_chirho,
        cluster_config_blake3_chirho,
        tenant_id_chirho,
        placement_revision_chirho: placement_record_chirho.intent_chirho.revision_chirho,
        assignment_digest_chirho,
        placement_key_chirho,
        topology_grant_key_chirho,
    }
}

/// The two shipped commands must preserve distinct custody and produce the exact runtime-verifiable
/// final record. Refusal-only checks cannot distinguish these commands from tools that never work.
#[test]
fn custody_separated_capacity_expectation_commands_emit_one_runtime_verified_final_chirho() {
    let fixture_chirho = capacity_expectation_cli_fixture_chirho();
    let population_digest_chirho = "a".repeat(64);
    let snapshot_digest_chirho = "b".repeat(64);
    let (partial_ok_chirho, partial_stdout_chirho, partial_stderr_chirho) =
        run_authoring_cli_chirho(&[
            "capacity-expectation",
            fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
            &population_digest_chirho,
            &snapshot_digest_chirho,
            fixture_chirho.placement_sign_root_chirho.to_str().unwrap(),
            fixture_chirho.partial_path_chirho.to_str().unwrap(),
        ]);
    assert!(
        partial_ok_chirho,
        "placement custody must author the partial: {partial_stderr_chirho}"
    );
    assert!(partial_stdout_chirho.contains("capacity-expectation-chirho"));
    let partial_chirho: TenantMigrationCapacityExpectationChirho =
        read_authored_chirho(&fixture_chirho.partial_path_chirho);
    let context_chirho = TenantMigrationCapacityExpectationContextChirho {
        expectation_revision_chirho: 7,
        cluster_config_blake3_chirho: &fixture_chirho.cluster_config_blake3_chirho,
        tenant_id_chirho: &fixture_chirho.tenant_id_chirho,
        placement_revision_chirho: fixture_chirho.placement_revision_chirho,
        current_assignment_digest_chirho: &fixture_chirho.assignment_digest_chirho,
        placement_key_id_chirho: &fixture_chirho.placement_key_chirho,
        topology_grant_key_id_chirho: &fixture_chirho.topology_grant_key_chirho,
    };
    verify_placement_signed_tenant_migration_capacity_expectation_chirho(
        &partial_chirho,
        context_chirho,
    )
    .expect("the first command must emit a placement-verified partial");
    assert!(partial_chirho.topology_grant_sig_chirho.is_empty());

    let (partial_verify_ok_chirho, partial_verify_stdout_chirho, partial_verify_stderr_chirho) =
        run_authoring_cli_chirho(&[
            "capacity-expectation-partial-verify",
            fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
            fixture_chirho.partial_path_chirho.to_str().unwrap(),
        ]);
    assert!(
        partial_verify_ok_chirho,
        "the private partial must verify without exercising second custody: {partial_verify_stderr_chirho}"
    );
    let partial_verify_report_chirho: serde_json::Value =
        serde_json::from_str(&partial_verify_stdout_chirho)
            .expect("partial verification report decodes");
    assert_eq!(
        partial_verify_report_chirho["operation_chirho"],
        "capacity-expectation-partial-verify-chirho"
    );
    assert_eq!(
        partial_verify_report_chirho["digest_chirho"],
        tenant_migration_capacity_expectation_digest_chirho(&partial_chirho).unwrap()
    );

    let tampered_partial_path_chirho = fixture_chirho
        ._temp_chirho
        .path()
        .join("tampered-expectation-partial-chirho.json");
    let mut tampered_partial_chirho = partial_chirho.clone();
    tampered_partial_chirho.placement_sig_chirho = "0".repeat(128);
    write_private_authoring_cli_file_chirho(
        &tampered_partial_path_chirho,
        &serde_json::to_vec_pretty(&tampered_partial_chirho).unwrap(),
    );
    let (
        tampered_partial_ok_chirho,
        _tampered_partial_stdout_chirho,
        tampered_partial_stderr_chirho,
    ) = run_authoring_cli_chirho(&[
        "capacity-expectation-partial-verify",
        fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
        tampered_partial_path_chirho.to_str().unwrap(),
    ]);
    assert!(
        !tampered_partial_ok_chirho,
        "a partial with a forged placement signature must refuse"
    );
    assert!(
        tampered_partial_stderr_chirho
            .contains("TenantMigrationCapacityExpectationPlacementVerificationRefusedChirho")
            && tampered_partial_stderr_chirho.contains("PlacementSignatureChirho"),
        "the partial verifier must name the invalid first signature: {tampered_partial_stderr_chirho}"
    );

    let (wrong_ok_chirho, _wrong_stdout_chirho, wrong_stderr_chirho) = run_authoring_cli_chirho(&[
        "capacity-expectation-cosign",
        fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
        fixture_chirho.partial_path_chirho.to_str().unwrap(),
        fixture_chirho
            .wrong_topology_sign_root_chirho
            .to_str()
            .unwrap(),
    ]);
    assert!(!wrong_ok_chirho, "a foreign topology holder must refuse");
    assert!(
        wrong_stderr_chirho
            .contains("TenantMigrationCapacityExpectationTopologyCustodyRefusedChirho"),
        "the refusal must identify the wrong custody: {wrong_stderr_chirho}"
    );
    assert!(
        !fixture_chirho.final_path_chirho.exists(),
        "a refused co-sign writes no final record"
    );

    let (final_ok_chirho, final_stdout_chirho, final_stderr_chirho) = run_authoring_cli_chirho(&[
        "capacity-expectation-cosign",
        fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
        fixture_chirho.partial_path_chirho.to_str().unwrap(),
        fixture_chirho
            .topology_grant_sign_root_chirho
            .to_str()
            .unwrap(),
    ]);
    assert!(
        final_ok_chirho,
        "the configured topology holder must co-sign: {final_stderr_chirho}"
    );
    assert!(final_stdout_chirho.contains("capacity-expectation-cosign-chirho"));
    let verified_chirho = load_and_verify_tenant_migration_capacity_expectation_chirho(
        &fixture_chirho.final_path_chirho,
        &fixture_chirho.evidence_root_chirho,
        context_chirho,
    )
    .expect("THE POINT: runtime must accept the artifact emitted by both shipped commands");
    assert_eq!(
        verified_chirho.expected_placement_population_digest_chirho(),
        population_digest_chirho
    );
    assert_eq!(
        verified_chirho.expected_capacity_load_snapshot_digest_chirho(),
        snapshot_digest_chirho
    );

    let (verify_ok_chirho, verify_stdout_chirho, verify_stderr_chirho) =
        run_authoring_cli_chirho(&[
            "capacity-expectation-verify",
            fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
        ]);
    assert!(
        verify_ok_chirho,
        "the configured final record must reload through the runtime verifier: {verify_stderr_chirho}"
    );
    let verify_report_chirho: serde_json::Value =
        serde_json::from_str(&verify_stdout_chirho).expect("verification report decodes");
    assert_eq!(
        verify_report_chirho["operation_chirho"],
        "capacity-expectation-verify-chirho"
    );
    assert_eq!(
        verify_report_chirho["output_path_chirho"],
        fixture_chirho.final_path_chirho.to_str().unwrap()
    );
    assert_eq!(
        verify_report_chirho["digest_chirho"],
        tenant_migration_capacity_expectation_digest_chirho(verified_chirho.record_chirho())
            .unwrap()
    );

    let final_bytes_chirho = std::fs::read(&fixture_chirho.final_path_chirho).unwrap();
    let (replay_ok_chirho, _replay_stdout_chirho, replay_stderr_chirho) =
        run_authoring_cli_chirho(&[
            "capacity-expectation-cosign",
            fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
            fixture_chirho.partial_path_chirho.to_str().unwrap(),
            fixture_chirho
                .topology_grant_sign_root_chirho
                .to_str()
                .unwrap(),
        ]);
    assert!(!replay_ok_chirho, "the final locator is create-new");
    assert!(
        replay_stderr_chirho.contains("TenantPlacementAuthoringOutputAlreadyExistsChirho"),
        "replacement must refuse by its own identity: {replay_stderr_chirho}"
    );
    assert_eq!(
        std::fs::read(&fixture_chirho.final_path_chirho).unwrap(),
        final_bytes_chirho,
        "a refused replay must not replace the reviewed final bytes"
    );

    let mut tampered_final_chirho: TenantMigrationCapacityExpectationChirho =
        read_authored_chirho(&fixture_chirho.final_path_chirho);
    tampered_final_chirho.topology_grant_sig_chirho = "0".repeat(128);
    std::fs::write(
        &fixture_chirho.final_path_chirho,
        serde_json::to_vec_pretty(&tampered_final_chirho).unwrap(),
    )
    .unwrap();
    let (tampered_ok_chirho, _tampered_stdout_chirho, tampered_stderr_chirho) =
        run_authoring_cli_chirho(&[
            "capacity-expectation-verify",
            fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
        ]);
    assert!(!tampered_ok_chirho, "a tampered final record must refuse");
    assert!(
        tampered_stderr_chirho
            .contains("TenantMigrationCapacityExpectationConfiguredVerificationRefusedChirho")
            && tampered_stderr_chirho.contains("TopologyGrantSignatureChirho"),
        "the runtime verifier must name the invalid second signature: {tampered_stderr_chirho}"
    );

    let drift_partial_path_chirho = fixture_chirho
        ._temp_chirho
        .path()
        .join("expectation-after-config-drift-chirho.json");
    let mut drifted_config_bytes_chirho =
        std::fs::read(&fixture_chirho.cluster_config_path_chirho).unwrap();
    drifted_config_bytes_chirho.push(b'\n');
    write_private_authoring_cli_file_chirho(
        &fixture_chirho.cluster_config_path_chirho,
        &drifted_config_bytes_chirho,
    );
    let (drift_ok_chirho, _drift_stdout_chirho, drift_stderr_chirho) = run_authoring_cli_chirho(&[
        "capacity-expectation",
        fixture_chirho.cluster_config_path_chirho.to_str().unwrap(),
        &population_digest_chirho,
        &snapshot_digest_chirho,
        fixture_chirho.placement_sign_root_chirho.to_str().unwrap(),
        drift_partial_path_chirho.to_str().unwrap(),
    ]);
    assert!(
        !drift_ok_chirho,
        "config bytes not bound by the resident placement must refuse before signing"
    );
    assert!(
        drift_stderr_chirho
            .contains("TenantMigrationCapacityExpectationLocalPlacementBindingRefusedChirho"),
        "config/placement generation skew must have its own identity: {drift_stderr_chirho}"
    );
    assert!(
        !drift_partial_path_chirho.exists(),
        "generation skew writes no partial"
    );
}
