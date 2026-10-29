// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::tenant_placement_chirho::{
    verify_geo_tenant_placement_startup_chirho, verify_geo_voter_startup_policy_chirho,
    GeoTenantPlacementRoleChirho,
};
use crate::{
    serve_resident_gd7_held_geo_node_chirho, serve_resident_gd7_voter_geo_node_chirho,
    GeoNonResidentVoterRoleChirho, GeoVoterPlacementAdmissionChirho, GeoVoterStartupRoleChirho,
};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_ledger_tenant_migration_chirho::VerifiedTenantMigrationRootChirho;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_roster_author_chirho::roster_authoring_chirho::{
    author_signed_roster_bundle_chirho, RosterAuthoringInputChirho, RosterAuthoringMemberChirho,
    ROSTER_AUTHORING_INPUT_SCHEMA_CHIRHO, ROSTER_HEAD_OUTPUT_FILE_CHIRHO,
    ROSTER_OUTPUT_FILE_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_tenant_placement_author_chirho::authoring_chirho::{
    author_tenant_placement_held_observer_readiness_chirho,
    author_tenant_placement_readiness_chirho, author_tenant_placement_record_chirho,
};
use cairn_tenant_placement_authority_chirho::{
    TenantPlacementIntentChirho, TenantPlacementNodeBindingChirho, TenantPlacementResidencyChirho,
    TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO, TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO,
};
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::{
    parse_cluster_node_file_config_chirho, LoadedClusterNodeConfigChirho,
};
use cairn_writer_elector_http_chirho::membership_control_chirho::{
    MembershipControlConfigChirho, MembershipTargetAuthorityChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct PlacementNodeFixtureChirho {
    node_id_chirho: String,
    sign_root_chirho: PathBuf,
    tenant_root_chirho: PathBuf,
    config_path_chirho: PathBuf,
    root_binding_chirho: String,
    config_digest_chirho: String,
    failure_domain_chirho: FailureDomainChirho,
    raft_id_chirho: u64,
}

struct PlacementStartupFixtureChirho {
    _temp_chirho: tempfile::TempDir,
    loaded_chirho: LoadedClusterNodeConfigChirho,
    selected_root_chirho: PathBuf,
    cluster_config_path_chirho: PathBuf,
    placement_record_path_chirho: PathBuf,
}

#[derive(Clone, Copy)]
enum PlacementLocalRoleFixtureChirho {
    VoterChirho { assigned_chirho: bool },
    HeldObserverChirho,
}

fn provision_key_chirho(path_chirho: &Path) -> String {
    sign_message_chirho(path_chirho, b"provision-placement-fixture-chirho").unwrap();
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

fn placement_startup_fixture_chirho(
    local_role_chirho: PlacementLocalRoleFixtureChirho,
) -> PlacementStartupFixtureChirho {
    let temp_chirho = tempfile::tempdir().unwrap();
    let tenant_id_chirho = "geo-placement-startup-chirho";
    let placement_sign_root_chirho = temp_chirho.path().join("placement-sign-chirho");
    let roster_sign_root_chirho = temp_chirho.path().join("roster-sign-chirho");
    let plan_sign_root_chirho = temp_chirho.path().join("plan-sign-chirho");
    let placement_pubkey_chirho = provision_key_chirho(&placement_sign_root_chirho);
    let roster_pubkey_chirho = provision_key_chirho(&roster_sign_root_chirho);
    let plan_pubkey_chirho = provision_key_chirho(&plan_sign_root_chirho);
    let roster_bundle_chirho = temp_chirho.path().join("roster-bundle-chirho");
    let roster_path_chirho = roster_bundle_chirho.join(ROSTER_OUTPUT_FILE_CHIRHO);
    let roster_head_path_chirho = roster_bundle_chirho.join(ROSTER_HEAD_OUTPUT_FILE_CHIRHO);
    let placement_record_path_chirho = temp_chirho.path().join("placement-record-chirho.json");
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
        FailureDomainChirho {
            provider_chirho: "scaleway-chirho".to_string(),
            region_chirho: "nl-ams-chirho".to_string(),
        },
    ];
    let mut nodes_chirho = (0..5)
        .map(|index_chirho| {
            let node_sign_root_chirho = temp_chirho
                .path()
                .join(format!("node-sign-{index_chirho}-chirho"));
            let node_id_chirho = provision_key_chirho(&node_sign_root_chirho);
            let platform_root_chirho = temp_chirho
                .path()
                .join(format!("platform-{index_chirho}-chirho"));
            let tenant_root_chirho =
                prepare_tenant_root_chirho(&platform_root_chirho, tenant_id_chirho).unwrap();
            PlacementNodeFixtureChirho {
                node_id_chirho,
                sign_root_chirho: node_sign_root_chirho,
                tenant_root_chirho,
                config_path_chirho: PathBuf::new(),
                root_binding_chirho: String::new(),
                config_digest_chirho: String::new(),
                failure_domain_chirho: domains_chirho[index_chirho].clone(),
                raft_id_chirho: 0,
            }
        })
        .collect::<Vec<_>>();
    nodes_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.node_id_chirho.cmp(&right_chirho.node_id_chirho)
    });
    for (index_chirho, node_chirho) in nodes_chirho.iter_mut().enumerate() {
        node_chirho.raft_id_chirho = index_chirho as u64 + 1;
        node_chirho.failure_domain_chirho = domains_chirho[index_chirho].clone();
    }
    let members_chirho = nodes_chirho
        .iter()
        .enumerate()
        .map(|(index_chirho, node_chirho)| {
            json!({
                "raft_id_chirho": node_chirho.raft_id_chirho,
                "pubkey_chirho": node_chirho.node_id_chirho,
                "url_chirho": format!("http://127.0.0.1:{}", 18_300 + index_chirho),
                "learner_chirho": index_chirho == 3
            })
        })
        .collect::<Vec<_>>();
    for (index_chirho, node_chirho) in nodes_chirho.iter_mut().enumerate() {
        let config_path_chirho = temp_chirho
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
            "listen_addr_chirho": format!("127.0.0.1:{}", 18_300 + index_chirho),
            "tick_ms_chirho": 50,
            "roster_authority_chirho": {
                "roster_path_chirho": roster_path_chirho,
                "roster_head_path_chirho": roster_head_path_chirho,
                "operator_pubkey_hex_chirho": roster_pubkey_chirho
            },
            "tenant_placement_chirho": {
                "placement_record_path_chirho": placement_record_path_chirho,
                "placement_pubkey_hex_chirho": placement_pubkey_chirho,
                "geo_plan_pubkey_hex_chirho": plan_pubkey_chirho
            }
        });
        if index_chirho != 3 {
            config_chirho["membership_control_chirho"] = json!({
                "operator_token_env_chirho": "MISSING_PLACEMENT_TEST_TOKEN_CHIRHO",
                "target_authority_chirho": {"kind_chirho": "tenant_placement"}
            });
        }
        let config_bytes_chirho = serde_json::to_vec(&config_chirho).unwrap();
        write_private_chirho(&config_path_chirho, &config_bytes_chirho);
        let verified_root_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(
            &node_chirho.tenant_root_chirho,
        )
        .unwrap();
        node_chirho.root_binding_chirho = format!(
            "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
            verified_root_chirho
                .binding_identity_digest_hex_chirho()
                .unwrap()
        );
        node_chirho.config_digest_chirho = blake3::hash(&config_bytes_chirho).to_hex().to_string();
        node_chirho.config_path_chirho = config_path_chirho;
    }

    let roster_input_chirho = RosterAuthoringInputChirho {
        schema_chirho: ROSTER_AUTHORING_INPUT_SCHEMA_CHIRHO.to_string(),
        at_ms_chirho: 1,
        members_chirho: nodes_chirho
            .iter()
            .enumerate()
            .map(|(index_chirho, node_chirho)| RosterAuthoringMemberChirho {
                node_pubkey_hex_chirho: node_chirho.node_id_chirho.clone(),
                region_label_chirho: node_chirho.failure_domain_chirho.region_chirho.clone(),
                raft_id_chirho: node_chirho.raft_id_chirho,
                wg_pubkey_chirho: BASE64_CHIRHO.encode([index_chirho as u8 + 1; 32]),
                mesh_ip_chirho: format!("10.88.0.{}", index_chirho + 1),
                endpoint_chirho: format!("node-{index_chirho}-chirho.example:51820"),
            })
            .collect(),
        preferred_leaders_chirho: Vec::new(),
    };
    let roster_input_path_chirho = temp_chirho.path().join("roster-input-chirho.json");
    write_private_chirho(
        &roster_input_path_chirho,
        &serde_json::to_vec(&roster_input_chirho).unwrap(),
    );
    author_signed_roster_bundle_chirho(
        &roster_input_path_chirho,
        &roster_sign_root_chirho,
        &roster_bundle_chirho,
    )
    .unwrap();

    let assigned_nodes_chirho = nodes_chirho[..3]
        .iter()
        .map(|node_chirho| TenantPlacementNodeBindingChirho {
            node_id_chirho: node_chirho.node_id_chirho.clone(),
            failure_domain_chirho: node_chirho.failure_domain_chirho.clone(),
            expected_root_binding_chirho: node_chirho.root_binding_chirho.clone(),
            expected_cluster_config_blake3_chirho: node_chirho.config_digest_chirho.clone(),
        })
        .collect::<Vec<_>>();
    let held_chirho = &nodes_chirho[3];
    let mut allowed_domains_chirho = nodes_chirho[..3]
        .iter()
        .map(|node_chirho| node_chirho.failure_domain_chirho.clone())
        .collect::<Vec<_>>();
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
        held_observer_node_chirho: TenantPlacementNodeBindingChirho {
            node_id_chirho: held_chirho.node_id_chirho.clone(),
            failure_domain_chirho: held_chirho.failure_domain_chirho.clone(),
            expected_root_binding_chirho: held_chirho.root_binding_chirho.clone(),
            expected_cluster_config_blake3_chirho: held_chirho.config_digest_chirho.clone(),
        },
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
    let serving_receipts_chirho = nodes_chirho[..3]
        .iter()
        .map(|node_chirho| {
            author_tenant_placement_readiness_chirho(
                &intent_chirho,
                &node_chirho.tenant_root_chirho,
                &node_chirho.config_path_chirho,
                &node_chirho.sign_root_chirho,
                1,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let held_receipt_chirho = author_tenant_placement_held_observer_readiness_chirho(
        &intent_chirho,
        &held_chirho.tenant_root_chirho,
        &held_chirho.config_path_chirho,
        &held_chirho.sign_root_chirho,
        1,
    )
    .unwrap();
    let record_chirho = author_tenant_placement_record_chirho(
        intent_chirho,
        serving_receipts_chirho,
        held_receipt_chirho,
        &placement_sign_root_chirho,
        &roster_pubkey_chirho,
        &plan_pubkey_chirho,
    )
    .unwrap();
    write_private_chirho(
        &placement_record_path_chirho,
        &serde_json::to_vec(&record_chirho).unwrap(),
    );

    let local_index_chirho = match local_role_chirho {
        PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: true,
        } => 0,
        PlacementLocalRoleFixtureChirho::HeldObserverChirho => 3,
        PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: false,
        } => 4,
    };
    let local_chirho = &nodes_chirho[local_index_chirho];
    let loaded_chirho = parse_cluster_node_file_config_chirho(
        &std::fs::read(&local_chirho.config_path_chirho).unwrap(),
    )
    .unwrap();
    PlacementStartupFixtureChirho {
        _temp_chirho: temp_chirho,
        loaded_chirho,
        selected_root_chirho: local_chirho.tenant_root_chirho.clone(),
        cluster_config_path_chirho: local_chirho.config_path_chirho.clone(),
        placement_record_path_chirho,
    }
}

#[test]
fn voter_and_held_startup_join_the_same_authorities_without_sharing_control_chirho() {
    let voter_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: true,
        });
    let voter_policy_chirho = verify_geo_voter_startup_policy_chirho(
        &voter_chirho.loaded_chirho,
        &voter_chirho.selected_root_chirho,
        GeoVoterPlacementAdmissionChirho::ProductionRequiredChirho,
    )
    .unwrap();
    assert_eq!(
        voter_policy_chirho
            .select_voter_startup_role_chirho(GeoVoterStartupRoleChirho::LocalWarmOwnerChirho),
        GeoVoterStartupRoleChirho::LocalWarmOwnerChirho
    );
    assert!(voter_chirho
        .loaded_chirho
        .cluster_chirho
        .membership_control_chirho
        .is_some());

    let held_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::HeldObserverChirho);
    verify_geo_tenant_placement_startup_chirho(
        &held_chirho.loaded_chirho,
        &held_chirho.selected_root_chirho,
        GeoTenantPlacementRoleChirho::HeldObserverChirho,
    )
    .unwrap();
    assert!(held_chirho.loaded_chirho.roster_authority_chirho.is_some());
    assert!(held_chirho.loaded_chirho.tenant_placement_chirho.is_some());
    assert!(held_chirho
        .loaded_chirho
        .cluster_chirho
        .membership_control_chirho
        .is_none());
}

#[test]
fn held_observer_runtime_refuses_membership_control_even_with_valid_signed_binding_chirho() {
    let mut held_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::HeldObserverChirho);
    let local_raft_id_chirho = held_chirho
        .loaded_chirho
        .cluster_chirho
        .local_raft_id_chirho;
    let local_node_id_chirho = held_chirho
        .loaded_chirho
        .cluster_chirho
        .learners_chirho
        .iter()
        .find(|(raft_id_chirho, _node_chirho)| *raft_id_chirho == local_raft_id_chirho)
        .unwrap()
        .1
         .0
        .clone();
    held_chirho
        .loaded_chirho
        .cluster_chirho
        .membership_control_chirho = Some(MembershipControlConfigChirho {
        roster_authority_chirho: held_chirho
            .loaded_chirho
            .roster_authority_chirho
            .clone()
            .unwrap(),
        local_node_pubkey_hex_chirho: local_node_id_chirho,
        group_id_chirho: held_chirho
            .loaded_chirho
            .cluster_chirho
            .group_chirho
            .canonical_id_chirho(),
        target_authority_chirho: MembershipTargetAuthorityChirho::TenantPlacementChirho(
            held_chirho
                .loaded_chirho
                .tenant_placement_chirho
                .clone()
                .unwrap(),
        ),
        operator_token_chirho: None,
        fixpoint_step_sleep_chirho: Duration::from_millis(1),
        fixpoint_max_steps_chirho: 1,
    });

    let error_chirho = verify_geo_tenant_placement_startup_chirho(
        &held_chirho.loaded_chirho,
        &held_chirho.selected_root_chirho,
        GeoTenantPlacementRoleChirho::HeldObserverChirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "GeoTenantPlacementHeldObserverControlRefusedChirho"
    );
}

#[test]
fn production_runtime_refuses_local_voter_and_learner_role_drift_chirho() {
    let mut voter_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: true,
        });
    let voter_raft_id_chirho = voter_chirho
        .loaded_chirho
        .cluster_chirho
        .local_raft_id_chirho;
    let voter_position_chirho = voter_chirho
        .loaded_chirho
        .cluster_chirho
        .voters_chirho
        .iter()
        .position(|(raft_id_chirho, _node_chirho)| *raft_id_chirho == voter_raft_id_chirho)
        .unwrap();
    let voter_member_chirho = voter_chirho
        .loaded_chirho
        .cluster_chirho
        .voters_chirho
        .remove(voter_position_chirho);
    voter_chirho
        .loaded_chirho
        .cluster_chirho
        .learners_chirho
        .push(voter_member_chirho);
    let voter_error_chirho = verify_geo_tenant_placement_startup_chirho(
        &voter_chirho.loaded_chirho,
        &voter_chirho.selected_root_chirho,
        GeoTenantPlacementRoleChirho::VoterChirho,
    )
    .unwrap_err();
    assert_eq!(
        voter_error_chirho.to_string(),
        "GeoTenantPlacementVoterConfigRoleRefusedChirho"
    );

    let mut held_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::HeldObserverChirho);
    let held_raft_id_chirho = held_chirho
        .loaded_chirho
        .cluster_chirho
        .local_raft_id_chirho;
    let held_position_chirho = held_chirho
        .loaded_chirho
        .cluster_chirho
        .learners_chirho
        .iter()
        .position(|(raft_id_chirho, _node_chirho)| *raft_id_chirho == held_raft_id_chirho)
        .unwrap();
    let held_member_chirho = held_chirho
        .loaded_chirho
        .cluster_chirho
        .learners_chirho
        .remove(held_position_chirho);
    held_chirho
        .loaded_chirho
        .cluster_chirho
        .voters_chirho
        .push(held_member_chirho);
    let held_error_chirho = verify_geo_tenant_placement_startup_chirho(
        &held_chirho.loaded_chirho,
        &held_chirho.selected_root_chirho,
        GeoTenantPlacementRoleChirho::HeldObserverChirho,
    )
    .unwrap_err();
    assert_eq!(
        held_error_chirho.to_string(),
        "GeoTenantPlacementHeldObserverConfigRoleRefusedChirho"
    );
}

#[test]
fn unassigned_warm_owner_is_transport_only_until_re_home_completes_chirho() {
    let retiring_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: false,
        });
    let retiring_policy_chirho = verify_geo_voter_startup_policy_chirho(
        &retiring_chirho.loaded_chirho,
        &retiring_chirho.selected_root_chirho,
        GeoVoterPlacementAdmissionChirho::ProductionRequiredChirho,
    )
    .unwrap();

    for elected_role_chirho in [
        GeoVoterStartupRoleChirho::LocalWarmOwnerChirho,
        GeoVoterStartupRoleChirho::NonResidentChirho(
            GeoNonResidentVoterRoleChirho::RemoteOwnerChirho,
        ),
    ] {
        assert_eq!(
            retiring_policy_chirho.select_voter_startup_role_chirho(elected_role_chirho),
            GeoVoterStartupRoleChirho::NonResidentChirho(
                GeoNonResidentVoterRoleChirho::RetiringTransportOnlyChirho,
            ),
            "an unassigned voter may retain election transport but must never compose a resident"
        );
    }
}

#[test]
fn assigned_non_owner_retains_mirror_placement_while_unassigned_voter_does_not_chirho() {
    let assigned_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: true,
        });
    let assigned_policy_chirho = verify_geo_voter_startup_policy_chirho(
        &assigned_chirho.loaded_chirho,
        &assigned_chirho.selected_root_chirho,
        GeoVoterPlacementAdmissionChirho::ProductionRequiredChirho,
    )
    .unwrap();
    let remote_owner_chirho = GeoVoterStartupRoleChirho::NonResidentChirho(
        GeoNonResidentVoterRoleChirho::RemoteOwnerChirho,
    );
    assert_eq!(
        assigned_policy_chirho.select_voter_startup_role_chirho(remote_owner_chirho),
        remote_owner_chirho,
        "an assigned follower must retain its elected non-owner posture"
    );
    assert!(
        assigned_policy_chirho.resident_placement_chirho().is_some(),
        "mirror-router composition is assigned-voter authority, not local-owner authority"
    );

    let unassigned_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: false,
        });
    let unassigned_policy_chirho = verify_geo_voter_startup_policy_chirho(
        &unassigned_chirho.loaded_chirho,
        &unassigned_chirho.selected_root_chirho,
        GeoVoterPlacementAdmissionChirho::ProductionRequiredChirho,
    )
    .unwrap();
    assert!(
        unassigned_policy_chirho
            .resident_placement_chirho()
            .is_none(),
        "an unassigned transport participant must not reach mirror-router composition"
    );
}

#[test]
fn tenant_roster_wide_is_testkind_explicit_and_production_refused_chirho() {
    let mut voter_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: true,
        });
    voter_chirho
        .loaded_chirho
        .cluster_chirho
        .membership_control_chirho
        .as_mut()
        .unwrap()
        .target_authority_chirho = MembershipTargetAuthorityChirho::RosterWideChirho;

    let production_error_chirho = verify_geo_voter_startup_policy_chirho(
        &voter_chirho.loaded_chirho,
        &voter_chirho.selected_root_chirho,
        GeoVoterPlacementAdmissionChirho::ProductionRequiredChirho,
    )
    .unwrap_err();
    assert_eq!(
        production_error_chirho.to_string(),
        "GeoTenantPlacementTargetSelectorRefusedChirho"
    );

    let testkind_policy_chirho = verify_geo_voter_startup_policy_chirho(
        &voter_chirho.loaded_chirho,
        &voter_chirho.selected_root_chirho,
        GeoVoterPlacementAdmissionChirho::ExplicitTestkindRosterWideChirho,
    )
    .unwrap();
    assert_eq!(
        testkind_policy_chirho
            .select_voter_startup_role_chirho(GeoVoterStartupRoleChirho::LocalWarmOwnerChirho),
        GeoVoterStartupRoleChirho::LocalWarmOwnerChirho
    );
}

#[test]
fn root_wide_is_testkind_explicit_and_production_refuses_before_transport_chirho() {
    let mut voter_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: true,
        });
    let root_group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: voter_chirho.selected_root_chirho.display().to_string(),
    };
    voter_chirho.loaded_chirho.cluster_chirho.group_chirho = root_group_chirho.clone();
    let control_chirho = voter_chirho
        .loaded_chirho
        .cluster_chirho
        .membership_control_chirho
        .as_mut()
        .unwrap();
    control_chirho.group_id_chirho = root_group_chirho.canonical_id_chirho();
    control_chirho.target_authority_chirho = MembershipTargetAuthorityChirho::RosterWideChirho;

    let production_error_chirho = verify_geo_voter_startup_policy_chirho(
        &voter_chirho.loaded_chirho,
        &voter_chirho.selected_root_chirho,
        GeoVoterPlacementAdmissionChirho::ProductionRequiredChirho,
    )
    .unwrap_err();
    assert_eq!(
        production_error_chirho.to_string(),
        "GeoRootWideRequiresExplicitTestkindRosterWideAdmissionChirho"
    );

    let testkind_policy_chirho = verify_geo_voter_startup_policy_chirho(
        &voter_chirho.loaded_chirho,
        &voter_chirho.selected_root_chirho,
        GeoVoterPlacementAdmissionChirho::ExplicitTestkindRosterWideChirho,
    )
    .unwrap();
    assert_eq!(
        testkind_policy_chirho
            .select_voter_startup_role_chirho(GeoVoterStartupRoleChirho::LocalWarmOwnerChirho),
        GeoVoterStartupRoleChirho::LocalWarmOwnerChirho
    );
}

#[test]
fn local_role_root_and_exact_cluster_bytes_are_load_bearing_chirho() {
    let mut voter_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: true,
        });
    let membership_control_chirho = voter_chirho
        .loaded_chirho
        .cluster_chirho
        .membership_control_chirho
        .take();
    let wrong_role_chirho = verify_geo_tenant_placement_startup_chirho(
        &voter_chirho.loaded_chirho,
        &voter_chirho.selected_root_chirho,
        GeoTenantPlacementRoleChirho::HeldObserverChirho,
    )
    .unwrap_err();
    assert!(wrong_role_chirho
        .to_string()
        .contains("GeoTenantPlacementHeldObserverConfigRoleRefusedChirho"));
    voter_chirho
        .loaded_chirho
        .cluster_chirho
        .membership_control_chirho = membership_control_chirho;

    let foreign_temp_chirho = tempfile::tempdir().unwrap();
    let foreign_root_chirho =
        prepare_tenant_root_chirho(foreign_temp_chirho.path(), "geo-placement-startup-chirho")
            .unwrap();
    let wrong_root_chirho = verify_geo_tenant_placement_startup_chirho(
        &voter_chirho.loaded_chirho,
        &foreign_root_chirho,
        GeoTenantPlacementRoleChirho::VoterChirho,
    )
    .unwrap_err();
    assert!(wrong_root_chirho
        .to_string()
        .contains("GeoTenantPlacementLocalRootBindingRefusedChirho"));

    voter_chirho.loaded_chirho.config_blake3_chirho = "f".repeat(64);
    let wrong_config_chirho = verify_geo_tenant_placement_startup_chirho(
        &voter_chirho.loaded_chirho,
        &voter_chirho.selected_root_chirho,
        GeoTenantPlacementRoleChirho::VoterChirho,
    )
    .unwrap_err();
    assert!(wrong_config_chirho
        .to_string()
        .contains("GeoTenantPlacementLocalClusterConfigRefusedChirho"));
}

#[test]
fn production_voter_and_held_entrypoints_authenticate_config_before_placement_chirho() {
    let voter_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::VoterChirho {
            assigned_chirho: true,
        });
    let voter_ledger_config_path_chirho = voter_chirho
        ._temp_chirho
        .path()
        .join("ledger-voter-chirho.toml");
    std::fs::write(&voter_ledger_config_path_chirho, b"").unwrap();
    let empty_config_digest_chirho = blake3::hash(b"").to_hex().to_string();
    std::fs::remove_file(&voter_chirho.placement_record_path_chirho).unwrap();
    let voter_digest_error_chirho = serve_resident_gd7_voter_geo_node_chirho(
        &voter_chirho.cluster_config_path_chirho,
        &voter_ledger_config_path_chirho,
        &"00".repeat(32),
        &voter_chirho.selected_root_chirho,
    )
    .unwrap_err();
    assert!(
        format!("{voter_digest_error_chirho:#}").contains("LedgerHostConfigDigestMismatchChirho"),
        "config authentication must precede placement and root access: {voter_digest_error_chirho:#}"
    );
    let voter_error_chirho = serve_resident_gd7_voter_geo_node_chirho(
        &voter_chirho.cluster_config_path_chirho,
        &voter_ledger_config_path_chirho,
        &empty_config_digest_chirho,
        &voter_chirho.selected_root_chirho,
    )
    .unwrap_err();
    assert!(format!("{voter_error_chirho:#}").contains("GeoTenantPlacementAuthorityRefusedChirho"));

    let held_chirho =
        placement_startup_fixture_chirho(PlacementLocalRoleFixtureChirho::HeldObserverChirho);
    let held_ledger_config_path_chirho = held_chirho
        ._temp_chirho
        .path()
        .join("ledger-held-chirho.toml");
    std::fs::write(&held_ledger_config_path_chirho, b"").unwrap();
    std::fs::remove_file(&held_chirho.placement_record_path_chirho).unwrap();
    let held_digest_error_chirho = serve_resident_gd7_held_geo_node_chirho(
        &held_chirho.cluster_config_path_chirho,
        &held_ledger_config_path_chirho,
        &"00".repeat(32),
        &held_chirho.selected_root_chirho,
    )
    .unwrap_err();
    assert!(
        format!("{held_digest_error_chirho:#}").contains("LedgerHostConfigDigestMismatchChirho"),
        "held config authentication must precede placement and root access: {held_digest_error_chirho:#}"
    );
    let held_error_chirho = serve_resident_gd7_held_geo_node_chirho(
        &held_chirho.cluster_config_path_chirho,
        &held_ledger_config_path_chirho,
        &empty_config_digest_chirho,
        &held_chirho.selected_root_chirho,
    )
    .unwrap_err();
    assert!(format!("{held_error_chirho:#}").contains("GeoTenantPlacementAuthorityRefusedChirho"));
}
