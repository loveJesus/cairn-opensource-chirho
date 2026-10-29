// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::authoring_chirho::{
    author_tenant_placement_adopted_successor_readiness_v2_chirho,
    author_tenant_placement_held_observer_readiness_chirho,
    author_tenant_placement_readiness_chirho, author_tenant_placement_readiness_v2_chirho,
    author_tenant_placement_record_chirho, author_tenant_placement_successor_readiness_v2_chirho,
    inspect_tenant_placement_node_binding_chirho, read_json_chirho, write_new_json_chirho,
};
use cairn_config_chirho::config_chirho::{
    serialize_config_chirho, ConfigChirho, LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho,
    LedgerHostMemberConfigChirho, LedgerHostProjectionRouteConfigChirho,
    LedgerHostSignerRefsConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_tenant_migration_chirho::VerifiedTenantMigrationRootChirho;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_tenant_placement_authority_chirho::{
    population_projection_chirho::project_tenant_placement_population_bytes_chirho,
    tenant_placement_assignment_digest_chirho, unsigned_tenant_placement_readiness_message_chirho,
    unsigned_tenant_placement_record_message_chirho, verify_tenant_placement_record_chirho,
    TenantPlacementIntentChirho, TenantPlacementNodeBindingChirho,
    TenantPlacementNodeReadinessReceiptChirho, TenantPlacementResidencyChirho,
    TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO, TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO, TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::shadow_canary_activation_anchor_chirho::{
    load_required_shadow_canary_activation_anchor_chirho, ShadowCanaryActivationAnchorInputChirho,
};
use cairn_writer_elector_chirho::shadow_canary_chirho::{
    ShadowCanaryAppendCutChirho, ShadowCanaryChirho, ShadowCanaryEvidenceStoreChirho,
    SHADOW_CANARY_EVIDENCE_DIR_CHIRHO, SHADOW_CANARY_SCHEMA_CHIRHO,
};
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::{
    ShadowCanaryAdoptionGenerationInputChirho, ShadowCanaryGenerationStoreChirho,
    ShadowCanaryLedgerCutChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho,
};
use serde_json::{json, Value};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

struct AuthoringNodeFixtureChirho {
    node_id_chirho: String,
    sign_root_chirho: PathBuf,
    tenant_root_chirho: PathBuf,
    cluster_config_path_chirho: PathBuf,
    root_binding_chirho: String,
    cluster_config_digest_chirho: String,
    raft_id_chirho: u64,
}

#[test]
fn binding_inspector_derives_exact_prepared_node_coordinates_chirho() {
    let fixture_chirho = authoring_fixture_chirho();
    for (index_chirho, node_chirho) in fixture_chirho.nodes_chirho.iter().enumerate() {
        let expected_chirho = if index_chirho < 3 {
            fixture_chirho.intent_chirho.assigned_nodes_chirho[index_chirho].clone()
        } else {
            fixture_chirho
                .intent_chirho
                .held_observer_node_chirho
                .clone()
        };
        let actual_chirho = inspect_tenant_placement_node_binding_chirho(
            &node_chirho.tenant_root_chirho,
            &node_chirho.cluster_config_path_chirho,
            &node_chirho.sign_root_chirho,
            expected_chirho.failure_domain_chirho.clone(),
        )
        .unwrap();
        assert_eq!(actual_chirho, expected_chirho);
    }
}

#[test]
fn dangling_output_coordinate_is_existing_and_never_replaced_chirho() {
    let fixture_chirho = authoring_fixture_chirho();
    let output_path_chirho = fixture_chirho
        ._temp_chirho
        .path()
        .join("dangling-output-chirho.json");
    let target_chirho = fixture_chirho
        ._temp_chirho
        .path()
        .join("missing-output-target-chirho.json");
    symlink(&target_chirho, &output_path_chirho).unwrap();

    let refusal_chirho = write_new_json_chirho(
        &output_path_chirho,
        &json!({"result_chirho": "must-not-write-chirho"}),
    )
    .unwrap_err();

    assert_eq!(
        refusal_chirho.to_string(),
        "TenantPlacementAuthoringOutputAlreadyExistsChirho"
    );
    assert!(std::fs::symlink_metadata(&output_path_chirho)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read_link(&output_path_chirho).unwrap(),
        target_chirho
    );
}

struct AuthoringFixtureChirho {
    _temp_chirho: tempfile::TempDir,
    intent_chirho: TenantPlacementIntentChirho,
    nodes_chirho: Vec<AuthoringNodeFixtureChirho>,
    placement_sign_root_chirho: PathBuf,
    placement_key_chirho: String,
    roster_key_chirho: String,
    plan_key_chirho: String,
}

fn provision_key_chirho(path_chirho: &Path) -> String {
    sign_message_chirho(path_chirho, b"provision-authoring-fixture-chirho").unwrap();
    pubkey_hex_chirho(path_chirho).unwrap()
}

fn write_private_chirho(path_chirho: &Path, bytes_chirho: &[u8]) {
    std::fs::write(path_chirho, bytes_chirho).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn authoring_fixture_chirho() -> AuthoringFixtureChirho {
    let temp_chirho = tempfile::tempdir().unwrap();
    let tenant_id_chirho = "credits-demo-chirho";
    let placement_sign_root_chirho = temp_chirho.path().join("placement-sign-chirho");
    let roster_sign_root_chirho = temp_chirho.path().join("roster-sign-chirho");
    let plan_sign_root_chirho = temp_chirho.path().join("plan-sign-chirho");
    let placement_key_chirho = provision_key_chirho(&placement_sign_root_chirho);
    let roster_key_chirho = provision_key_chirho(&roster_sign_root_chirho);
    let plan_key_chirho = provision_key_chirho(&plan_sign_root_chirho);
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
        FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fi-hel-chirho".to_string(),
        },
    ];
    let mut nodes_chirho = (0..4)
        .map(|index_chirho| {
            let platform_root_chirho = temp_chirho
                .path()
                .join(format!("platform-{index_chirho}-chirho"));
            let tenant_root_chirho =
                prepare_tenant_root_chirho(&platform_root_chirho, tenant_id_chirho).unwrap();
            let sign_root_chirho = temp_chirho
                .path()
                .join(format!("node-sign-{index_chirho}-chirho"));
            let node_id_chirho = provision_key_chirho(&sign_root_chirho);
            let verified_root_chirho =
                VerifiedTenantMigrationRootChirho::open_existing_chirho(&tenant_root_chirho)
                    .unwrap();
            AuthoringNodeFixtureChirho {
                node_id_chirho,
                sign_root_chirho,
                tenant_root_chirho,
                cluster_config_path_chirho: PathBuf::new(),
                root_binding_chirho: format!(
                    "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
                    verified_root_chirho
                        .binding_identity_digest_hex_chirho()
                        .unwrap()
                ),
                cluster_config_digest_chirho: String::new(),
                raft_id_chirho: 0,
            }
        })
        .collect::<Vec<_>>();
    nodes_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.node_id_chirho.cmp(&right_chirho.node_id_chirho)
    });
    for (index_chirho, node_chirho) in nodes_chirho.iter_mut().enumerate() {
        node_chirho.raft_id_chirho = u64::try_from(index_chirho).unwrap() + 1;
    }
    let members_chirho = nodes_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, node_chirho)| {
            json!({
                "raft_id_chirho": node_chirho.raft_id_chirho,
                "pubkey_chirho": node_chirho.node_id_chirho,
                "url_chirho": format!("http://127.0.0.1:{}", 19_300 + index_chirho),
                "learner_chirho": index_chirho == 3
            })
        })
        .collect::<Vec<_>>();
    for (index_chirho, node_chirho) in nodes_chirho.iter_mut().enumerate() {
        let cluster_config_path_chirho = temp_chirho
            .path()
            .join(format!("cluster-{index_chirho}-chirho.json"));
        let mut config_chirho = json!({
            "group_chirho": {
                "kind_chirho": "tenant",
                "tenant_id_chirho": tenant_id_chirho
            },
            "local_raft_id_chirho": node_chirho.raft_id_chirho,
            "members_chirho": members_chirho,
            "durable_dir_chirho": temp_chirho.path().join(format!("raft-{index_chirho}-chirho")),
            "sign_root_chirho": node_chirho.sign_root_chirho,
            "listen_addr_chirho": format!("127.0.0.1:{}", 19_300 + index_chirho),
            "tick_ms_chirho": 50,
            "roster_authority_chirho": {
                "roster_path_chirho": temp_chirho.path().join("roster-chirho.jsonl"),
                "roster_head_path_chirho": temp_chirho.path().join("roster-head-chirho.json"),
                "operator_pubkey_hex_chirho": roster_key_chirho
            },
            "tenant_placement_chirho": {
                "placement_record_path_chirho": temp_chirho.path().join("placement-record-chirho.json"),
                "placement_pubkey_hex_chirho": placement_key_chirho,
                "geo_plan_pubkey_hex_chirho": plan_key_chirho
            }
        });
        if index_chirho != 3 {
            config_chirho["membership_control_chirho"] = json!({
                "operator_token_env_chirho": "MISSING_AUTHORING_TEST_TOKEN_CHIRHO",
                "target_authority_chirho": {"kind_chirho": "tenant_placement"}
            });
        }
        let bytes_chirho = serde_json::to_vec(&config_chirho).unwrap();
        write_private_chirho(&cluster_config_path_chirho, &bytes_chirho);
        node_chirho.cluster_config_path_chirho = cluster_config_path_chirho;
        node_chirho.cluster_config_digest_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
    }
    let assigned_nodes_chirho = nodes_chirho[..3]
        .iter()
        .enumerate()
        .map(
            |(index_chirho, node_chirho)| TenantPlacementNodeBindingChirho {
                node_id_chirho: node_chirho.node_id_chirho.clone(),
                failure_domain_chirho: domains_chirho[index_chirho].clone(),
                expected_root_binding_chirho: node_chirho.root_binding_chirho.clone(),
                expected_cluster_config_blake3_chirho: node_chirho
                    .cluster_config_digest_chirho
                    .clone(),
            },
        )
        .collect::<Vec<_>>();
    let held_observer_node_chirho = TenantPlacementNodeBindingChirho {
        node_id_chirho: nodes_chirho[3].node_id_chirho.clone(),
        failure_domain_chirho: domains_chirho[3].clone(),
        expected_root_binding_chirho: nodes_chirho[3].root_binding_chirho.clone(),
        expected_cluster_config_blake3_chirho: nodes_chirho[3].cluster_config_digest_chirho.clone(),
    };
    let mut allowed_domains_chirho = domains_chirho[..3].to_vec();
    allowed_domains_chirho.sort();
    let intent_chirho = TenantPlacementIntentChirho {
        schema_chirho: TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        digest_domain_chirho: TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO.to_string(),
        revision_chirho: 0,
        previous_assignment_digest_chirho: None,
        tenant_id_chirho: tenant_id_chirho.to_string(),
        consistency_group_id_chirho: format!("tenant-chirho:{tenant_id_chirho}"),
        preferred_node_chirho: assigned_nodes_chirho[0].node_id_chirho.clone(),
        assigned_nodes_chirho,
        held_observer_node_chirho,
        demand_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 500,
            memory_bytes_chirho: 1_024,
            durable_bytes_chirho: 4_096,
        },
        residency_chirho: TenantPlacementResidencyChirho {
            allowed_domains_chirho,
        },
        topology_plan_digest_chirho: "a".repeat(64),
    };
    AuthoringFixtureChirho {
        _temp_chirho: temp_chirho,
        intent_chirho,
        nodes_chirho,
        placement_sign_root_chirho,
        placement_key_chirho,
        roster_key_chirho,
        plan_key_chirho,
    }
}

fn rewrite_config_and_rebind_chirho(
    fixture_chirho: &mut AuthoringFixtureChirho,
    node_index_chirho: usize,
    mutate_chirho: impl FnOnce(&mut Value),
) {
    let node_chirho = &fixture_chirho.nodes_chirho[node_index_chirho];
    let mut config_chirho: Value =
        serde_json::from_slice(&std::fs::read(&node_chirho.cluster_config_path_chirho).unwrap())
            .unwrap();
    mutate_chirho(&mut config_chirho);
    let bytes_chirho = serde_json::to_vec(&config_chirho).unwrap();
    write_private_chirho(&node_chirho.cluster_config_path_chirho, &bytes_chirho);
    let digest_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
    let node_id_chirho = node_chirho.node_id_chirho.clone();
    fixture_chirho.nodes_chirho[node_index_chirho].cluster_config_digest_chirho =
        digest_chirho.clone();
    if let Some(binding_chirho) = fixture_chirho
        .intent_chirho
        .assigned_nodes_chirho
        .iter_mut()
        .find(|binding_chirho| binding_chirho.node_id_chirho == node_id_chirho)
    {
        binding_chirho.expected_cluster_config_blake3_chirho = digest_chirho;
    } else {
        fixture_chirho
            .intent_chirho
            .held_observer_node_chirho
            .expected_cluster_config_blake3_chirho = digest_chirho;
    }
}

fn runtime_host_config_chirho() -> LedgerHostConfigChirho {
    LedgerHostConfigChirho {
        schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO.to_owned(),
        storage_namespace_chirho: "ledger-storage-chirho".to_owned(),
        monitor_evidence_namespace_chirho: "monitor-evidence-chirho".to_owned(),
        monitor_evidence_path_chirho: "cycles/conservation-chirho.jsonl".to_owned(),
        money_group_id_chirho: "money-group-chirho".to_owned(),
        cluster_id_chirho: "cluster-chirho".to_owned(),
        journal_path_chirho: "journals/money-chirho.jsonl".to_owned(),
        local_epoch_chirho: 1,
        members_chirho: vec![LedgerHostMemberConfigChirho {
            owner_chirho: "platform-owner-chirho".to_owned(),
            kind_id_chirho: "credits-chirho".to_owned(),
        }],
        kind_registry_path_chirho: "registries/kinds-chirho.jsonl".to_owned(),
        kind_registry_id_chirho: "kind-registry-chirho".to_owned(),
        kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
            principal_chirho: "kind-issuer-chirho".to_owned(),
            verifying_key_hex_chirho: "9".repeat(64),
        },
        activation_authority_chirho: None,
        projection_registry_path_chirho: "registries/projections-chirho.jsonl".to_owned(),
        projection_registry_id_chirho: "projection-registry-chirho".to_owned(),
        source_registry_path_chirho: "registries/sources-chirho.jsonl".to_owned(),
        source_registry_id_chirho: "source-registry-chirho".to_owned(),
        projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
            projection_name_chirho: "account-net-chirho".to_owned(),
            head_path_chirho: "projection-heads/account-net-chirho.json".to_owned(),
        }],
        signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
            journal_chirho: "journal-secret-chirho".to_owned(),
            config_chirho: "config-secret-chirho".to_owned(),
            feeder_chirho: "feeder-secret-chirho".to_owned(),
            kind_root_chirho: "kind-root-secret-chirho".to_owned(),
            effect_intent_chirho: "effect-intent-secret-chirho".to_owned(),
            effect_terminal_chirho: "effect-terminal-secret-chirho".to_owned(),
        },
        held_verifier_pins_chirho: None,
        migration_destination_authority_chirho: None,
        monitor_cadence_ms_chirho: 5_000,
        postgres_effect_chirho: None,
        control_plane_chirho: None,
        test_kind_chirho: None,
        adopt_migrated_root_chirho: false,
    }
}

fn write_runtime_config_for_root_chirho(
    node_chirho: &AuthoringNodeFixtureChirho,
    tenant_root_chirho: &Path,
    suffix_chirho: &str,
) -> PathBuf {
    let runtime_config_path_chirho = node_chirho
        .cluster_config_path_chirho
        .with_extension(suffix_chirho);
    let runtime_config_chirho = ConfigChirho {
        root_chirho: tenant_root_chirho.to_string_lossy().into_owned(),
        ledger_host_chirho: Some(runtime_host_config_chirho()),
        ..ConfigChirho::default()
    };
    write_private_chirho(
        &runtime_config_path_chirho,
        serialize_config_chirho(&runtime_config_chirho)
            .unwrap()
            .as_bytes(),
    );
    runtime_config_path_chirho
}

fn canary_append_cut_chirho(
    group_chirho: &cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho,
    sequence_chirho: u64,
) -> ShadowCanaryAppendCutChirho {
    ShadowCanaryAppendCutChirho {
        append_seq_chirho: sequence_chirho,
        append_record_digest_chirho: format!("{sequence_chirho:064x}"),
        append_hlc_physical_ms_chirho: 10_000 + sequence_chirho,
        append_hlc_logical_chirho: 0,
        process_generation_chirho: 1,
        durable_term_chirho: 1,
        fence_epoch_chirho: 1,
        fence_group_digest_chirho: consistency_group_digest_chirho(group_chirho).unwrap(),
    }
}

fn canary_observation_chirho(
    node_chirho: &AuthoringNodeFixtureChirho,
    group_chirho: &cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho,
    sequence_chirho: u64,
) -> ShadowCanaryChirho {
    ShadowCanaryChirho {
        schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_owned(),
        group_chirho: group_chirho.clone(),
        minter_node_id_chirho: NodeIdChirho(node_chirho.node_id_chirho.clone()),
        append_cut_chirho: canary_append_cut_chirho(group_chirho, sequence_chirho),
        raft_leader_id_chirho: Some(NodeIdChirho(node_chirho.node_id_chirho.clone())),
        raft_term_chirho: 1,
        raft_lease_valid_chirho: true,
        cutover_would_permit_chirho: true,
        at_ms_chirho: 20_000 + sequence_chirho,
    }
}

fn canary_adoption_input_chirho(
    group_chirho: &cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho,
    assignment_digest_chirho: String,
    adopted_sequence_chirho: u64,
) -> ShadowCanaryAdoptionGenerationInputChirho {
    ShadowCanaryAdoptionGenerationInputChirho {
        adopted_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
            adopted_sequence_chirho,
            format!("{adopted_sequence_chirho:064x}"),
            30_000 + adopted_sequence_chirho,
            0,
            7,
            group_chirho,
        )
        .unwrap(),
        cluster_id_chirho: "placement-successor-cluster-chirho".to_string(),
        journal_genesis_digest_chirho: "9".repeat(64),
        assignment_digest_chirho,
        historical_leader_node_id_chirho: "8".repeat(64),
        holder_node_ids_chirho: ["6".repeat(64), "7".repeat(64)],
        historical_term_chirho: 5,
        historical_membership_view_digest_chirho: "1".repeat(64),
        elected_term_chirho: 7,
        membership_view_digest_chirho: "b".repeat(64),
        holder_receipt_digests_chirho: ["c".repeat(64), "d".repeat(64)],
        holder_receipt_wires_chirho: [
            br#"{"holder_chirho":"first-chirho"}"#.to_vec(),
            br#"{"holder_chirho":"second-chirho"}"#.to_vec(),
        ],
        candidate_journal_binding_digest_chirho: "e".repeat(64),
        candidate_journal_digest_chirho: "f".repeat(64),
    }
}

fn initialize_v2_readiness_chirho(
    fixture_chirho: &AuthoringFixtureChirho,
    node_index_chirho: usize,
    runtime_config_path_chirho: &Path,
) -> (
    TenantPlacementNodeReadinessReceiptChirho,
    ShadowCanaryEvidenceStoreChirho,
) {
    let node_chirho = &fixture_chirho.nodes_chirho[node_index_chirho];
    let group_chirho = consistency_group_for_root_chirho(&node_chirho.tenant_root_chirho).unwrap();
    let canary_root_chirho = node_chirho
        .tenant_root_chirho
        .join("monitor-evidence-chirho")
        .join(SHADOW_CANARY_EVIDENCE_DIR_CHIRHO);
    std::fs::create_dir_all(canary_root_chirho.parent().unwrap()).unwrap();
    let store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &canary_root_chirho,
        &node_chirho.sign_root_chirho,
        group_chirho.clone(),
        NodeIdChirho(node_chirho.node_id_chirho.clone()),
        ShadowCanaryActivationAnchorInputChirho {
            activation_authorization_digest_chirho: format!(
                "activation-authorization-v1-chirho:{}",
                "a".repeat(64)
            ),
            activation_plan_digest_chirho: "b".repeat(64),
            resident_identity_digest_chirho: format!(
                "resident-identity-v1-chirho:{}",
                "c".repeat(64)
            ),
            activation_append_cut_chirho: canary_append_cut_chirho(&group_chirho, 1),
        },
    )
    .unwrap();
    store_chirho
        .append_observation_chirho(canary_observation_chirho(node_chirho, &group_chirho, 1))
        .unwrap();
    let receipt_chirho = author_tenant_placement_readiness_v2_chirho(
        &fixture_chirho.intent_chirho,
        &node_chirho.tenant_root_chirho,
        &node_chirho.cluster_config_path_chirho,
        runtime_config_path_chirho,
        &node_chirho.sign_root_chirho,
        100 + u64::try_from(node_index_chirho).unwrap(),
    )
    .unwrap();
    (receipt_chirho, store_chirho)
}

fn copy_directory_chirho(source_chirho: &Path, target_chirho: &Path) {
    std::fs::create_dir_all(target_chirho).unwrap();
    for entry_chirho in std::fs::read_dir(source_chirho).unwrap() {
        let entry_chirho = entry_chirho.unwrap();
        let source_entry_chirho = entry_chirho.path();
        let target_entry_chirho = target_chirho.join(entry_chirho.file_name());
        if entry_chirho.file_type().unwrap().is_dir() {
            copy_directory_chirho(&source_entry_chirho, &target_entry_chirho);
        } else {
            std::fs::copy(&source_entry_chirho, &target_entry_chirho).unwrap();
        }
    }
}

#[test]
fn v2_readiness_derives_the_anchor_only_after_the_exact_activation_observation_chirho() {
    let fixture_chirho = authoring_fixture_chirho();
    let node_chirho = &fixture_chirho.nodes_chirho[0];
    let runtime_config_path_chirho = node_chirho
        .cluster_config_path_chirho
        .with_extension("runtime-chirho.toml");
    let runtime_config_chirho = ConfigChirho {
        root_chirho: node_chirho
            .tenant_root_chirho
            .to_string_lossy()
            .into_owned(),
        ledger_host_chirho: Some(runtime_host_config_chirho()),
        ..ConfigChirho::default()
    };
    write_private_chirho(
        &runtime_config_path_chirho,
        serialize_config_chirho(&runtime_config_chirho)
            .unwrap()
            .as_bytes(),
    );
    let group_chirho = consistency_group_for_root_chirho(&node_chirho.tenant_root_chirho).unwrap();
    let activation_cut_chirho = ShadowCanaryAppendCutChirho {
        append_seq_chirho: 1,
        append_record_digest_chirho: "1".repeat(64),
        append_hlc_physical_ms_chirho: 10_001,
        append_hlc_logical_chirho: 0,
        process_generation_chirho: 1,
        durable_term_chirho: 1,
        fence_epoch_chirho: 1,
        fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
    };
    let canary_root_chirho = node_chirho
        .tenant_root_chirho
        .join("monitor-evidence-chirho")
        .join(SHADOW_CANARY_EVIDENCE_DIR_CHIRHO);
    std::fs::create_dir_all(canary_root_chirho.parent().unwrap()).unwrap();
    let store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &canary_root_chirho,
        &node_chirho.sign_root_chirho,
        group_chirho.clone(),
        NodeIdChirho(node_chirho.node_id_chirho.clone()),
        ShadowCanaryActivationAnchorInputChirho {
            activation_authorization_digest_chirho: format!(
                "activation-authorization-v1-chirho:{}",
                "a".repeat(64)
            ),
            activation_plan_digest_chirho: "b".repeat(64),
            resident_identity_digest_chirho: format!(
                "resident-identity-v1-chirho:{}",
                "c".repeat(64)
            ),
            activation_append_cut_chirho: activation_cut_chirho.clone(),
        },
    )
    .unwrap();
    let decoy_root_chirho = node_chirho
        .tenant_root_chirho
        .with_file_name("foreign-root-chirho");
    std::fs::create_dir_all(&decoy_root_chirho).unwrap();
    let canonical_root_chirho = node_chirho.tenant_root_chirho.canonicalize().unwrap();
    let canonical_decoy_chirho = decoy_root_chirho.canonicalize().unwrap();
    assert_ne!(canonical_root_chirho, canonical_decoy_chirho);
    assert_eq!(
        canonical_root_chirho.to_string_lossy().len(),
        canonical_decoy_chirho.to_string_lossy().len(),
    );
    let decoy_runtime_config_path_chirho = node_chirho
        .cluster_config_path_chirho
        .with_extension("decoy-runtime-chirho.toml");
    let decoy_runtime_config_chirho = ConfigChirho {
        root_chirho: decoy_root_chirho.to_string_lossy().into_owned(),
        ledger_host_chirho: Some(runtime_host_config_chirho()),
        ..ConfigChirho::default()
    };
    write_private_chirho(
        &decoy_runtime_config_path_chirho,
        serialize_config_chirho(&decoy_runtime_config_chirho)
            .unwrap()
            .as_bytes(),
    );
    let decoy_refusal_chirho = author_tenant_placement_readiness_v2_chirho(
        &fixture_chirho.intent_chirho,
        &node_chirho.tenant_root_chirho,
        &node_chirho.cluster_config_path_chirho,
        &decoy_runtime_config_path_chirho,
        &node_chirho.sign_root_chirho,
        100,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        decoy_refusal_chirho,
        "TenantPlacementReadinessRuntimeRootBindingRefusedChirho"
    );
    for neighboring_refusal_chirho in [
        "TenantPlacementReadinessNodeCustodyRefusedChirho",
        "TenantPlacementReadinessNodeNotAssignedChirho",
        "TenantPlacementReadinessTenantGroupRefusedChirho",
        "TenantPlacementReadinessActivationAnchorRefusedChirho",
    ] {
        assert_ne!(decoy_refusal_chirho, neighboring_refusal_chirho);
    }
    assert_eq!(
        author_tenant_placement_readiness_v2_chirho(
            &fixture_chirho.intent_chirho,
            &node_chirho.tenant_root_chirho,
            &node_chirho.cluster_config_path_chirho,
            &runtime_config_path_chirho,
            &node_chirho.sign_root_chirho,
            100,
        )
        .unwrap_err()
        .to_string(),
        "TenantPlacementReadinessActivationAnchorRefusedChirho"
    );

    store_chirho
        .append_observation_chirho(ShadowCanaryChirho {
            schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_owned(),
            group_chirho: group_chirho.clone(),
            minter_node_id_chirho: NodeIdChirho(node_chirho.node_id_chirho.clone()),
            append_cut_chirho: activation_cut_chirho,
            raft_leader_id_chirho: Some(NodeIdChirho(node_chirho.node_id_chirho.clone())),
            raft_term_chirho: 1,
            raft_lease_valid_chirho: true,
            cutover_would_permit_chirho: true,
            at_ms_chirho: 20_001,
        })
        .unwrap();
    let receipt_chirho = author_tenant_placement_readiness_v2_chirho(
        &fixture_chirho.intent_chirho,
        &node_chirho.tenant_root_chirho,
        &node_chirho.cluster_config_path_chirho,
        &runtime_config_path_chirho,
        &node_chirho.sign_root_chirho,
        100,
    )
    .unwrap();
    let anchor_chirho = load_required_shadow_canary_activation_anchor_chirho(
        &canary_root_chirho,
        &node_chirho.sign_root_chirho,
        &group_chirho,
        &NodeIdChirho(node_chirho.node_id_chirho.clone()),
    )
    .unwrap();
    assert_eq!(
        receipt_chirho.activation_anchor_digest_chirho.as_deref(),
        Some(anchor_chirho.digest_chirho())
    );
    assert_eq!(
        receipt_chirho.schema_chirho,
        "tenant-placement-node-readiness-v2-chirho"
    );
}

#[test]
fn v2_successor_readiness_preserves_carried_and_authorizes_one_adopted_lineage_chirho() {
    let fixture_chirho = authoring_fixture_chirho();
    let runtime_paths_chirho = fixture_chirho.nodes_chirho[..3]
        .iter()
        .enumerate()
        .map(|(index_chirho, node_chirho)| {
            write_runtime_config_for_root_chirho(
                node_chirho,
                &node_chirho.tenant_root_chirho,
                &format!("runtime-{index_chirho}-chirho.toml"),
            )
        })
        .collect::<Vec<_>>();
    let (initial_pairs_chirho, initial_stores_chirho): (Vec<_>, Vec<_>) = runtime_paths_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, runtime_path_chirho)| {
            initialize_v2_readiness_chirho(&fixture_chirho, index_chirho, runtime_path_chirho)
        })
        .unzip();
    let held_chirho = &fixture_chirho.nodes_chirho[3];
    let initial_held_chirho = author_tenant_placement_held_observer_readiness_chirho(
        &fixture_chirho.intent_chirho,
        &held_chirho.tenant_root_chirho,
        &held_chirho.cluster_config_path_chirho,
        &held_chirho.sign_root_chirho,
        104,
    )
    .unwrap();
    let initial_record_chirho = author_tenant_placement_record_chirho(
        fixture_chirho.intent_chirho.clone(),
        initial_pairs_chirho,
        initial_held_chirho,
        &fixture_chirho.placement_sign_root_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    let initial_assignment_chirho =
        tenant_placement_assignment_digest_chirho(&initial_record_chirho).unwrap();
    let predecessor_path_chirho = fixture_chirho
        ._temp_chirho
        .path()
        .join("placement-record-chirho.json");
    write_private_chirho(
        &predecessor_path_chirho,
        &serde_json::to_vec(&initial_record_chirho).unwrap(),
    );

    let source_node_chirho = &fixture_chirho.nodes_chirho[0];
    let source_group_chirho =
        consistency_group_for_root_chirho(&source_node_chirho.tenant_root_chirho).unwrap();
    for sequence_chirho in 2..=3 {
        initial_stores_chirho[0]
            .append_observation_chirho(canary_observation_chirho(
                source_node_chirho,
                &source_group_chirho,
                sequence_chirho,
            ))
            .unwrap();
    }

    let adopted_node_chirho = &fixture_chirho.nodes_chirho[1];
    let adopted_group_chirho =
        consistency_group_for_root_chirho(&adopted_node_chirho.tenant_root_chirho).unwrap();
    let adopted_canary_root_chirho = adopted_node_chirho
        .tenant_root_chirho
        .join("monitor-evidence-chirho")
        .join(SHADOW_CANARY_EVIDENCE_DIR_CHIRHO);
    std::fs::remove_dir_all(&adopted_canary_root_chirho).unwrap();
    let (_replacement_receipt_chirho, _replacement_store_chirho) =
        initialize_v2_readiness_chirho(&fixture_chirho, 1, &runtime_paths_chirho[1]);
    let replacement_anchor_chirho = load_required_shadow_canary_activation_anchor_chirho(
        &adopted_canary_root_chirho,
        &adopted_node_chirho.sign_root_chirho,
        &adopted_group_chirho,
        &NodeIdChirho(adopted_node_chirho.node_id_chirho.clone()),
    )
    .unwrap()
    .digest_chirho()
    .to_string();
    let adopted_generation_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &adopted_canary_root_chirho,
        &adopted_node_chirho.sign_root_chirho,
        adopted_group_chirho.clone(),
        NodeIdChirho(adopted_node_chirho.node_id_chirho.clone()),
    )
    .unwrap();
    let adopted_generation_chirho = adopted_generation_store_chirho
        .commit_adoption_generation_chirho(canary_adoption_input_chirho(
            &adopted_group_chirho,
            initial_assignment_chirho.clone(),
            5,
        ))
        .unwrap();
    assert_eq!(adopted_generation_chirho.generation_chirho(), 1);
    assert_eq!(adopted_generation_chirho.prior_generation_chirho(), 0);
    assert_eq!(
        adopted_generation_chirho.assignment_digest_chirho(),
        initial_assignment_chirho
    );
    assert!(adopted_generation_chirho
        .adoption_proof_projection_chirho()
        .is_some());

    let target_platform_chirho = fixture_chirho
        ._temp_chirho
        .path()
        .join("target-platform-chirho");
    let target_root_chirho =
        prepare_tenant_root_chirho(&target_platform_chirho, "credits-demo-chirho").unwrap();
    copy_directory_chirho(
        &source_node_chirho
            .tenant_root_chirho
            .join("monitor-evidence-chirho"),
        &target_root_chirho.join("monitor-evidence-chirho"),
    );
    let mut successor_intent_chirho = fixture_chirho.intent_chirho.clone();
    successor_intent_chirho.revision_chirho = 1;
    successor_intent_chirho.previous_assignment_digest_chirho =
        Some(initial_assignment_chirho.clone());
    let target_binding_chirho = format!(
        "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
        VerifiedTenantMigrationRootChirho::open_existing_chirho(&target_root_chirho)
            .unwrap()
            .binding_identity_digest_hex_chirho()
            .unwrap()
    );
    successor_intent_chirho
        .assigned_nodes_chirho
        .iter_mut()
        .find(|binding_chirho| binding_chirho.node_id_chirho == source_node_chirho.node_id_chirho)
        .unwrap()
        .expected_root_binding_chirho = target_binding_chirho;
    let target_runtime_path_chirho = write_runtime_config_for_root_chirho(
        source_node_chirho,
        &target_root_chirho,
        "target-runtime-chirho.toml",
    );

    assert_eq!(
        author_tenant_placement_successor_readiness_v2_chirho(
            &successor_intent_chirho,
            &adopted_node_chirho.tenant_root_chirho,
            &adopted_node_chirho.cluster_config_path_chirho,
            &runtime_paths_chirho[1],
            &adopted_node_chirho.sign_root_chirho,
            499,
        )
        .unwrap_err()
        .to_string(),
        "TenantPlacementSuccessorReadinessActivationAnchorRefusedChirho"
    );

    let successor_receipts_chirho = fixture_chirho.nodes_chirho[..3]
        .iter()
        .enumerate()
        .map(|(index_chirho, node_chirho)| {
            let (root_chirho, runtime_path_chirho) = if index_chirho == 0 {
                (&target_root_chirho, &target_runtime_path_chirho)
            } else {
                (
                    &node_chirho.tenant_root_chirho,
                    &runtime_paths_chirho[index_chirho],
                )
            };
            if index_chirho == 1 {
                author_tenant_placement_adopted_successor_readiness_v2_chirho(
                    &successor_intent_chirho,
                    root_chirho,
                    &node_chirho.cluster_config_path_chirho,
                    runtime_path_chirho,
                    &node_chirho.sign_root_chirho,
                    500 + u64::try_from(index_chirho).unwrap(),
                )
                .unwrap()
            } else {
                author_tenant_placement_successor_readiness_v2_chirho(
                    &successor_intent_chirho,
                    root_chirho,
                    &node_chirho.cluster_config_path_chirho,
                    runtime_path_chirho,
                    &node_chirho.sign_root_chirho,
                    500 + u64::try_from(index_chirho).unwrap(),
                )
                .unwrap()
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        successor_receipts_chirho[0].activation_anchor_digest_chirho,
        initial_record_chirho.serving_readiness_receipts_chirho[0].activation_anchor_digest_chirho
    );
    assert_eq!(
        successor_receipts_chirho[1]
            .activation_anchor_digest_chirho
            .as_deref(),
        Some(replacement_anchor_chirho.as_str())
    );
    assert_ne!(
        successor_receipts_chirho[1].activation_anchor_digest_chirho,
        initial_record_chirho.serving_readiness_receipts_chirho[1].activation_anchor_digest_chirho
    );
    assert_eq!(
        successor_receipts_chirho[2].activation_anchor_digest_chirho,
        initial_record_chirho.serving_readiness_receipts_chirho[2].activation_anchor_digest_chirho
    );
    assert_eq!(
        successor_receipts_chirho[0].root_binding_chirho,
        successor_intent_chirho.assigned_nodes_chirho[0].expected_root_binding_chirho
    );
    assert_ne!(
        successor_receipts_chirho[0].root_binding_chirho,
        initial_record_chirho.serving_readiness_receipts_chirho[0].root_binding_chirho
    );
    assert_eq!(
        author_tenant_placement_adopted_successor_readiness_v2_chirho(
            &successor_intent_chirho,
            &fixture_chirho.nodes_chirho[2].tenant_root_chirho,
            &fixture_chirho.nodes_chirho[2].cluster_config_path_chirho,
            &runtime_paths_chirho[2],
            &fixture_chirho.nodes_chirho[2].sign_root_chirho,
            503,
        )
        .unwrap_err()
        .to_string(),
        "TenantPlacementAdoptedSuccessorReadinessReactivationRequiredChirho"
    );

    let adopted_target_platform_chirho = fixture_chirho
        ._temp_chirho
        .path()
        .join("adopted-target-platform-chirho");
    let adopted_target_root_chirho =
        prepare_tenant_root_chirho(&adopted_target_platform_chirho, "credits-demo-chirho").unwrap();
    copy_directory_chirho(
        &adopted_node_chirho
            .tenant_root_chirho
            .join("monitor-evidence-chirho"),
        &adopted_target_root_chirho.join("monitor-evidence-chirho"),
    );
    let adopted_target_binding_chirho = format!(
        "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
        VerifiedTenantMigrationRootChirho::open_existing_chirho(&adopted_target_root_chirho)
            .unwrap()
            .binding_identity_digest_hex_chirho()
            .unwrap()
    );
    let mut moved_adopted_intent_chirho = successor_intent_chirho.clone();
    moved_adopted_intent_chirho
        .assigned_nodes_chirho
        .iter_mut()
        .find(|binding_chirho| binding_chirho.node_id_chirho == adopted_node_chirho.node_id_chirho)
        .unwrap()
        .expected_root_binding_chirho = adopted_target_binding_chirho;
    let adopted_target_runtime_path_chirho = write_runtime_config_for_root_chirho(
        adopted_node_chirho,
        &adopted_target_root_chirho,
        "adopted-target-runtime-chirho.toml",
    );
    assert_eq!(
        author_tenant_placement_adopted_successor_readiness_v2_chirho(
            &moved_adopted_intent_chirho,
            &adopted_target_root_chirho,
            &adopted_node_chirho.cluster_config_path_chirho,
            &adopted_target_runtime_path_chirho,
            &adopted_node_chirho.sign_root_chirho,
            504,
        )
        .unwrap_err()
        .to_string(),
        "TenantPlacementAdoptedSuccessorReadinessRootContinuityRefusedChirho"
    );
    let successor_held_chirho = author_tenant_placement_held_observer_readiness_chirho(
        &successor_intent_chirho,
        &held_chirho.tenant_root_chirho,
        &held_chirho.cluster_config_path_chirho,
        &held_chirho.sign_root_chirho,
        505,
    )
    .unwrap();
    let successor_anchor_digests_chirho = successor_receipts_chirho
        .iter()
        .map(|receipt_chirho| {
            receipt_chirho
                .activation_anchor_digest_chirho
                .clone()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let successor_record_chirho = author_tenant_placement_record_chirho(
        successor_intent_chirho.clone(),
        successor_receipts_chirho,
        successor_held_chirho,
        &fixture_chirho.placement_sign_root_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    let successor_bytes_chirho = serde_json::to_vec(&successor_record_chirho).unwrap();
    let successor_projection_chirho = project_tenant_placement_population_bytes_chirho(
        &successor_bytes_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    assert_eq!(
        successor_projection_chirho.ordered_activation_anchor_digests_chirho,
        successor_anchor_digests_chirho
    );

    let generation_zero_node_chirho = &fixture_chirho.nodes_chirho[2];
    let generation_zero_group_chirho =
        consistency_group_for_root_chirho(&generation_zero_node_chirho.tenant_root_chirho).unwrap();
    let generation_zero_canary_root_chirho = generation_zero_node_chirho
        .tenant_root_chirho
        .join("monitor-evidence-chirho")
        .join(SHADOW_CANARY_EVIDENCE_DIR_CHIRHO);
    std::fs::remove_dir_all(&generation_zero_canary_root_chirho).unwrap();
    let (_generation_zero_initial_receipt_chirho, _generation_zero_store_chirho) =
        initialize_v2_readiness_chirho(&fixture_chirho, 2, &runtime_paths_chirho[2]);
    let generation_zero_successor_chirho = author_tenant_placement_readiness_v2_chirho(
        &successor_intent_chirho,
        &generation_zero_node_chirho.tenant_root_chirho,
        &generation_zero_node_chirho.cluster_config_path_chirho,
        &runtime_paths_chirho[2],
        &generation_zero_node_chirho.sign_root_chirho,
        550,
    )
    .unwrap();
    assert_ne!(
        generation_zero_successor_chirho.activation_anchor_digest_chirho,
        initial_record_chirho.serving_readiness_receipts_chirho[2].activation_anchor_digest_chirho
    );
    assert_eq!(
        author_tenant_placement_adopted_successor_readiness_v2_chirho(
            &successor_intent_chirho,
            &generation_zero_node_chirho.tenant_root_chirho,
            &generation_zero_node_chirho.cluster_config_path_chirho,
            &runtime_paths_chirho[2],
            &generation_zero_node_chirho.sign_root_chirho,
            551,
        )
        .unwrap_err()
        .to_string(),
        "TenantPlacementAdoptedSuccessorReadinessAdoptionProofRefusedChirho"
    );
    let wrong_assignment_generation_store_chirho =
        ShadowCanaryGenerationStoreChirho::open_existing_chirho(
            &generation_zero_canary_root_chirho,
            &generation_zero_node_chirho.sign_root_chirho,
            generation_zero_group_chirho.clone(),
            NodeIdChirho(generation_zero_node_chirho.node_id_chirho.clone()),
        )
        .unwrap();
    wrong_assignment_generation_store_chirho
        .commit_adoption_generation_chirho(canary_adoption_input_chirho(
            &generation_zero_group_chirho,
            "0".repeat(64),
            5,
        ))
        .unwrap();
    assert_eq!(
        author_tenant_placement_adopted_successor_readiness_v2_chirho(
            &successor_intent_chirho,
            &generation_zero_node_chirho.tenant_root_chirho,
            &generation_zero_node_chirho.cluster_config_path_chirho,
            &runtime_paths_chirho[2],
            &generation_zero_node_chirho.sign_root_chirho,
            552,
        )
        .unwrap_err()
        .to_string(),
        "TenantPlacementAdoptedSuccessorReadinessAdoptionProofRefusedChirho"
    );

    let mut wrong_predecessor_intent_chirho = successor_intent_chirho.clone();
    wrong_predecessor_intent_chirho.previous_assignment_digest_chirho = Some("e".repeat(64));
    assert_eq!(
        author_tenant_placement_successor_readiness_v2_chirho(
            &wrong_predecessor_intent_chirho,
            &target_root_chirho,
            &source_node_chirho.cluster_config_path_chirho,
            &target_runtime_path_chirho,
            &source_node_chirho.sign_root_chirho,
            600,
        )
        .unwrap_err()
        .to_string(),
        "TenantPlacementSuccessorReadinessPredecessorRefusedChirho"
    );

    let mut foreign_anchor_record_chirho = initial_record_chirho.clone();
    let foreign_receipt_chirho =
        &mut foreign_anchor_record_chirho.serving_readiness_receipts_chirho[0];
    foreign_receipt_chirho.activation_anchor_digest_chirho = Some("f".repeat(64));
    foreign_receipt_chirho.sig_chirho.clear();
    foreign_receipt_chirho.sig_chirho = sign_message_chirho(
        &source_node_chirho.sign_root_chirho,
        &unsigned_tenant_placement_readiness_message_chirho(foreign_receipt_chirho).unwrap(),
    )
    .unwrap();
    foreign_anchor_record_chirho.sig_chirho.clear();
    foreign_anchor_record_chirho.sig_chirho = sign_message_chirho(
        &fixture_chirho.placement_sign_root_chirho,
        &unsigned_tenant_placement_record_message_chirho(&foreign_anchor_record_chirho).unwrap(),
    )
    .unwrap();
    verify_tenant_placement_record_chirho(
        foreign_anchor_record_chirho.clone(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    let foreign_assignment_chirho =
        tenant_placement_assignment_digest_chirho(&foreign_anchor_record_chirho).unwrap();
    std::fs::remove_file(&predecessor_path_chirho).unwrap();
    write_private_chirho(
        &predecessor_path_chirho,
        &serde_json::to_vec(&foreign_anchor_record_chirho).unwrap(),
    );
    let mut foreign_anchor_intent_chirho = successor_intent_chirho;
    foreign_anchor_intent_chirho.previous_assignment_digest_chirho =
        Some(foreign_assignment_chirho);
    assert_eq!(
        author_tenant_placement_successor_readiness_v2_chirho(
            &foreign_anchor_intent_chirho,
            &target_root_chirho,
            &source_node_chirho.cluster_config_path_chirho,
            &target_runtime_path_chirho,
            &source_node_chirho.sign_root_chirho,
            601,
        )
        .unwrap_err()
        .to_string(),
        "TenantPlacementSuccessorReadinessActivationAnchorRefusedChirho"
    );
}

#[test]
fn real_cluster_configs_author_three_serving_receipts_one_observer_and_one_record_chirho() {
    let fixture_chirho = authoring_fixture_chirho();
    let receipts_chirho = fixture_chirho.nodes_chirho[..3]
        .iter()
        .enumerate()
        .map(|(index_chirho, node_chirho)| {
            author_tenant_placement_readiness_chirho(
                &fixture_chirho.intent_chirho,
                &node_chirho.tenant_root_chirho,
                &node_chirho.cluster_config_path_chirho,
                &node_chirho.sign_root_chirho,
                100 + u64::try_from(index_chirho).unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let held_chirho = &fixture_chirho.nodes_chirho[3];
    let held_receipt_chirho = author_tenant_placement_held_observer_readiness_chirho(
        &fixture_chirho.intent_chirho,
        &held_chirho.tenant_root_chirho,
        &held_chirho.cluster_config_path_chirho,
        &held_chirho.sign_root_chirho,
        104,
    )
    .unwrap();
    let record_chirho = author_tenant_placement_record_chirho(
        fixture_chirho.intent_chirho,
        receipts_chirho,
        held_receipt_chirho,
        &fixture_chirho.placement_sign_root_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    let verified_chirho = verify_tenant_placement_record_chirho(
        record_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    assert_eq!(verified_chirho.assigned_nodes_chirho().len(), 3);
    assert_eq!(
        verified_chirho.held_observer_node_chirho().node_id_chirho,
        held_chirho.node_id_chirho
    );
}

#[test]
fn readiness_refuses_wrong_tenant_group_by_identity_chirho() {
    let mut fixture_chirho = authoring_fixture_chirho();
    rewrite_config_and_rebind_chirho(&mut fixture_chirho, 0, |config_chirho| {
        config_chirho["group_chirho"]["tenant_id_chirho"] =
            Value::String("foreign-tenant-chirho".to_string());
    });
    let node_chirho = &fixture_chirho.nodes_chirho[0];
    let error_chirho = author_tenant_placement_readiness_chirho(
        &fixture_chirho.intent_chirho,
        &node_chirho.tenant_root_chirho,
        &node_chirho.cluster_config_path_chirho,
        &node_chirho.sign_root_chirho,
        100,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "TenantPlacementReadinessTenantGroupRefusedChirho"
    );
}

#[test]
fn readiness_refuses_wrong_local_node_key_by_identity_chirho() {
    let mut fixture_chirho = authoring_fixture_chirho();
    let foreign_raft_id_chirho = fixture_chirho.nodes_chirho[1].raft_id_chirho;
    rewrite_config_and_rebind_chirho(&mut fixture_chirho, 0, |config_chirho| {
        config_chirho["local_raft_id_chirho"] = Value::from(foreign_raft_id_chirho);
    });
    let node_chirho = &fixture_chirho.nodes_chirho[0];
    let error_chirho = author_tenant_placement_readiness_chirho(
        &fixture_chirho.intent_chirho,
        &node_chirho.tenant_root_chirho,
        &node_chirho.cluster_config_path_chirho,
        &node_chirho.sign_root_chirho,
        100,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "TenantPlacementReadinessLocalNodeKeyRefusedChirho"
    );
}

#[test]
fn serving_readiness_refuses_a_held_observer_config_by_identity_chirho() {
    let mut fixture_chirho = authoring_fixture_chirho();
    let local_raft_id_chirho = fixture_chirho.nodes_chirho[0].raft_id_chirho;
    rewrite_config_and_rebind_chirho(&mut fixture_chirho, 0, |config_chirho| {
        config_chirho
            .as_object_mut()
            .unwrap()
            .remove("membership_control_chirho");
        for member_chirho in config_chirho["members_chirho"].as_array_mut().unwrap() {
            if member_chirho["raft_id_chirho"].as_u64() == Some(local_raft_id_chirho) {
                member_chirho["learner_chirho"] = Value::Bool(true);
            }
        }
    });
    let node_chirho = &fixture_chirho.nodes_chirho[0];
    let error_chirho = author_tenant_placement_readiness_chirho(
        &fixture_chirho.intent_chirho,
        &node_chirho.tenant_root_chirho,
        &node_chirho.cluster_config_path_chirho,
        &node_chirho.sign_root_chirho,
        100,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "TenantPlacementReadinessServingRoleRefusedChirho"
    );
}

#[test]
fn serving_readiness_refuses_a_local_learner_even_with_control_chirho() {
    let mut fixture_chirho = authoring_fixture_chirho();
    let local_raft_id_chirho = fixture_chirho.nodes_chirho[0].raft_id_chirho;
    rewrite_config_and_rebind_chirho(&mut fixture_chirho, 0, |config_chirho| {
        for member_chirho in config_chirho["members_chirho"].as_array_mut().unwrap() {
            if member_chirho["raft_id_chirho"].as_u64() == Some(local_raft_id_chirho) {
                member_chirho["learner_chirho"] = Value::Bool(true);
            }
        }
    });
    let node_chirho = &fixture_chirho.nodes_chirho[0];
    let error_chirho = author_tenant_placement_readiness_chirho(
        &fixture_chirho.intent_chirho,
        &node_chirho.tenant_root_chirho,
        &node_chirho.cluster_config_path_chirho,
        &node_chirho.sign_root_chirho,
        100,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "TenantPlacementReadinessServingRoleRefusedChirho"
    );
}

#[test]
fn generic_authoring_input_is_bounded_before_json_allocation_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let input_path_chirho = temp_chirho.path().join("oversized-input-chirho.json");
    std::fs::write(
        &input_path_chirho,
        vec![b' '; TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO as usize + 1],
    )
    .unwrap();
    let error_chirho = read_json_chirho::<Value>(&input_path_chirho).unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "TenantPlacementAuthoringInputSizeRefusedChirho"
    );
}
