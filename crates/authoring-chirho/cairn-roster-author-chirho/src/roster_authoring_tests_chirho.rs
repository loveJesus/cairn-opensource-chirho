// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::roster_authoring_chirho::{
    author_signed_roster_bundle_chirho, RosterAuthoringInputChirho, RosterAuthoringMemberChirho,
    RosterAuthoringPreferredLeaderChirho, ROSTER_AUTHORING_INPUT_SCHEMA_CHIRHO,
    ROSTER_HEAD_OUTPUT_FILE_CHIRHO, ROSTER_OUTPUT_FILE_CHIRHO,
};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_replication_chirho::membership_chirho::read_membership_roster_lines_chirho;
use cairn_roster_config_chirho::{derive_elector_config_chirho, derive_preferred_leader_chirho};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use std::path::Path;

fn provision_key_chirho(root_chirho: &Path) -> String {
    sign_message_chirho(root_chirho, b"provision operator key chirho").unwrap();
    pubkey_hex_chirho(root_chirho).unwrap()
}

fn provision_node_key_chirho(root_chirho: &Path, tag_chirho: &str) -> String {
    sign_message_chirho(root_chirho, tag_chirho.as_bytes()).unwrap();
    pubkey_hex_chirho(root_chirho).unwrap()
}

fn input_chirho(root_chirho: &Path) -> RosterAuthoringInputChirho {
    let node_one_chirho = provision_node_key_chirho(&root_chirho.join("node-one-chirho"), "one");
    let node_two_chirho = provision_node_key_chirho(&root_chirho.join("node-two-chirho"), "two");
    RosterAuthoringInputChirho {
        schema_chirho: ROSTER_AUTHORING_INPUT_SCHEMA_CHIRHO.to_string(),
        at_ms_chirho: 1_785_383_000_000,
        members_chirho: vec![
            RosterAuthoringMemberChirho {
                node_pubkey_hex_chirho: node_one_chirho,
                region_label_chirho: "hetzner-de-chirho".to_string(),
                raft_id_chirho: 1,
                wg_pubkey_chirho: BASE64_CHIRHO.encode([1_u8; 32]),
                mesh_ip_chirho: "10.100.0.7".to_string(),
                endpoint_chirho: "192.0.2.7:51820".to_string(),
            },
            RosterAuthoringMemberChirho {
                node_pubkey_hex_chirho: node_two_chirho,
                region_label_chirho: "ovh-fr-chirho".to_string(),
                raft_id_chirho: 2,
                wg_pubkey_chirho: BASE64_CHIRHO.encode([2_u8; 32]),
                mesh_ip_chirho: "10.100.0.2".to_string(),
                endpoint_chirho: "192.0.2.2:51820".to_string(),
            },
        ],
        preferred_leaders_chirho: vec![RosterAuthoringPreferredLeaderChirho {
            group_id_chirho: "tenant-chirho:r2-4-synthetic-chirho".to_string(),
            preferred_leader_raft_id_chirho: 1,
        }],
    }
}

fn write_private_input_chirho(path_chirho: &Path, input_chirho: &RosterAuthoringInputChirho) {
    std::fs::write(path_chirho, serde_json::to_vec(input_chirho).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn authoring_emits_one_self_verified_private_bundle_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let operator_root_chirho = root_chirho.path().join("operator-chirho");
    let operator_key_chirho = provision_key_chirho(&operator_root_chirho);
    let input_chirho = input_chirho(root_chirho.path());
    let input_path_chirho = root_chirho.path().join("input-chirho.json");
    let output_dir_chirho = root_chirho.path().join("bundle-chirho");
    write_private_input_chirho(&input_path_chirho, &input_chirho);

    let report_chirho = author_signed_roster_bundle_chirho(
        &input_path_chirho,
        &operator_root_chirho,
        &output_dir_chirho,
    )
    .unwrap();
    assert_eq!(report_chirho.operator_key_id_chirho, operator_key_chirho);
    assert_eq!(report_chirho.member_count_chirho, 2);
    assert_eq!(report_chirho.preferred_leader_count_chirho, 1);
    assert_eq!(report_chirho.roster_record_count_chirho, 5);

    let roster_path_chirho = output_dir_chirho.join(ROSTER_OUTPUT_FILE_CHIRHO);
    let head_path_chirho = output_dir_chirho.join(ROSTER_HEAD_OUTPUT_FILE_CHIRHO);
    let lines_chirho = read_membership_roster_lines_chirho(&roster_path_chirho).unwrap();
    let head_chirho = std::fs::read(&head_path_chirho).unwrap();
    for member_chirho in &input_chirho.members_chirho {
        let (derived_chirho, evidence_chirho) = derive_elector_config_chirho(
            &lines_chirho,
            &head_chirho,
            &operator_key_chirho,
            &member_chirho.node_pubkey_hex_chirho,
        )
        .unwrap();
        assert_eq!(
            derived_chirho.local_raft_id_chirho,
            member_chirho.raft_id_chirho
        );
        assert_eq!(evidence_chirho.member_count_chirho, 2);
    }
    assert_eq!(
        derive_preferred_leader_chirho(
            &lines_chirho,
            &head_chirho,
            &operator_key_chirho,
            &input_chirho.members_chirho[0].node_pubkey_hex_chirho,
            "tenant-chirho:r2-4-synthetic-chirho",
        )
        .unwrap(),
        Some(1)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output_dir_chirho)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&roster_path_chirho)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&head_path_chirho)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn authoring_refuses_coordinate_collision_without_leaving_a_bundle_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let operator_root_chirho = root_chirho.path().join("operator-chirho");
    provision_key_chirho(&operator_root_chirho);
    let mut input_chirho = input_chirho(root_chirho.path());
    input_chirho.members_chirho[1].mesh_ip_chirho =
        input_chirho.members_chirho[0].mesh_ip_chirho.clone();
    let input_path_chirho = root_chirho.path().join("input-chirho.json");
    let output_dir_chirho = root_chirho.path().join("bundle-chirho");
    write_private_input_chirho(&input_path_chirho, &input_chirho);

    let error_chirho = author_signed_roster_bundle_chirho(
        &input_path_chirho,
        &operator_root_chirho,
        &output_dir_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("RosterAuthoringCoordinateCollisionRefusedChirho"));
    assert!(!output_dir_chirho.exists());
}

#[test]
fn authoring_never_replaces_an_existing_bundle_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let operator_root_chirho = root_chirho.path().join("operator-chirho");
    provision_key_chirho(&operator_root_chirho);
    let input_chirho = input_chirho(root_chirho.path());
    let input_path_chirho = root_chirho.path().join("input-chirho.json");
    let output_dir_chirho = root_chirho.path().join("bundle-chirho");
    write_private_input_chirho(&input_path_chirho, &input_chirho);
    std::fs::create_dir(&output_dir_chirho).unwrap();
    let sentinel_chirho = output_dir_chirho.join("sentinel-chirho");
    std::fs::write(&sentinel_chirho, b"keep").unwrap();

    let error_chirho = author_signed_roster_bundle_chirho(
        &input_path_chirho,
        &operator_root_chirho,
        &output_dir_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("RosterAuthoringOutputAlreadyExistsChirho"));
    assert_eq!(std::fs::read(&sentinel_chirho).unwrap(), b"keep");
}
