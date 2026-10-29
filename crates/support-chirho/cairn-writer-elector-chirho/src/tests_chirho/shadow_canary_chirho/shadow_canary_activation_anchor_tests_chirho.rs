// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::elector_port_chirho::NodeIdChirho;
use crate::shadow_canary_activation_anchor_chirho::{
    create_new_shadow_canary_activation_anchor_with_fixed_entropy_chirho,
    ShadowCanaryActivationAnchorInputChirho,
};
use crate::shadow_canary_chirho::{
    ShadowCanaryAppendCutChirho, ShadowCanaryChirho, ShadowCanaryEvidenceStoreChirho,
    SignedShadowCanaryEvidenceHeadChirho, SHADOW_CANARY_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::{
    pubkey_hex_chirho, sign_message_chirho, sign_message_with_existing_key_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let unique_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-shadow-canary-anchor-{tag_chirho}-{}-{unique_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    let _ = std::fs::remove_file(&root_chirho);
    root_chirho
}

fn group_chirho() -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-activation-anchor-chirho".to_owned(),
    }
}

fn append_cut_chirho(append_seq_chirho: u64) -> ShadowCanaryAppendCutChirho {
    ShadowCanaryAppendCutChirho {
        append_seq_chirho,
        append_record_digest_chirho: format!("{append_seq_chirho:064x}"),
        append_hlc_physical_ms_chirho: 1_786_500_000_000,
        append_hlc_logical_chirho: 0,
        process_generation_chirho: 1,
        durable_term_chirho: 1,
        fence_epoch_chirho: 1,
        fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho()).unwrap(),
    }
}

fn anchor_input_chirho() -> ShadowCanaryActivationAnchorInputChirho {
    ShadowCanaryActivationAnchorInputChirho {
        activation_authorization_digest_chirho: format!(
            "activation-authorization-v1-chirho:{}",
            "a".repeat(64)
        ),
        activation_plan_digest_chirho: "b".repeat(64),
        resident_identity_digest_chirho: format!("resident-identity-v1-chirho:{}", "c".repeat(64)),
        activation_append_cut_chirho: append_cut_chirho(1),
    }
}

fn signing_identity_chirho(root_chirho: &Path) -> (PathBuf, NodeIdChirho) {
    let sign_root_chirho = root_chirho.join("signing-chirho");
    sign_message_chirho(&sign_root_chirho, b"provision activation anchor signer").unwrap();
    let node_chirho = NodeIdChirho(pubkey_hex_chirho(&sign_root_chirho).unwrap());
    (sign_root_chirho, node_chirho)
}

fn observation_chirho(
    node_chirho: &NodeIdChirho,
    append_cut_chirho: ShadowCanaryAppendCutChirho,
) -> ShadowCanaryChirho {
    ShadowCanaryChirho {
        schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_owned(),
        group_chirho: group_chirho(),
        minter_node_id_chirho: node_chirho.clone(),
        append_cut_chirho,
        raft_leader_id_chirho: Some(node_chirho.clone()),
        raft_term_chirho: 1,
        raft_lease_valid_chirho: true,
        cutover_would_permit_chirho: true,
        at_ms_chirho: 1_786_500_000_000,
    }
}

#[test]
fn fixed_entropy_is_the_load_bearing_activation_incarnation_chirho() {
    let root_chirho = temp_root_chirho("fixed-entropy");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let (sign_root_chirho, node_chirho) = signing_identity_chirho(&root_chirho);
    let first_root_chirho = root_chirho.join("first-evidence-chirho");
    let second_root_chirho = root_chirho.join("second-evidence-chirho");
    let fixed_incarnation_chirho = [0x5a; 32];
    let first_chirho = create_new_shadow_canary_activation_anchor_with_fixed_entropy_chirho(
        &first_root_chirho,
        &sign_root_chirho,
        &group_chirho(),
        &node_chirho,
        anchor_input_chirho(),
        &fixed_incarnation_chirho,
    )
    .unwrap();
    let second_chirho = create_new_shadow_canary_activation_anchor_with_fixed_entropy_chirho(
        &second_root_chirho,
        &sign_root_chirho,
        &group_chirho(),
        &node_chirho,
        anchor_input_chirho(),
        &fixed_incarnation_chirho,
    )
    .unwrap();
    assert_eq!(
        first_chirho.anchor_chirho().incarnation_chirho,
        second_chirho.anchor_chirho().incarnation_chirho
    );
    assert_eq!(first_chirho.digest_chirho(), second_chirho.digest_chirho());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn all_256_incarnation_bits_are_bound_into_the_signed_anchor_chirho() {
    let root_chirho = temp_root_chirho("all-incarnation-bits");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let (sign_root_chirho, node_chirho) = signing_identity_chirho(&root_chirho);
    let first_root_chirho = root_chirho.join("first-evidence-chirho");
    let second_root_chirho = root_chirho.join("second-evidence-chirho");
    let first_incarnation_chirho = [0x5a; 32];
    let mut second_incarnation_chirho = first_incarnation_chirho;
    second_incarnation_chirho[31] = 0x5b;
    let first_chirho = create_new_shadow_canary_activation_anchor_with_fixed_entropy_chirho(
        &first_root_chirho,
        &sign_root_chirho,
        &group_chirho(),
        &node_chirho,
        anchor_input_chirho(),
        &first_incarnation_chirho,
    )
    .unwrap();
    let second_chirho = create_new_shadow_canary_activation_anchor_with_fixed_entropy_chirho(
        &second_root_chirho,
        &sign_root_chirho,
        &group_chirho(),
        &node_chirho,
        anchor_input_chirho(),
        &second_incarnation_chirho,
    )
    .unwrap();
    assert_eq!(
        first_chirho.anchor_chirho().incarnation_chirho,
        "5a".repeat(32)
    );
    assert_eq!(
        second_chirho.anchor_chirho().incarnation_chirho,
        format!("{}5b", "5a".repeat(31))
    );
    assert_ne!(first_chirho.digest_chirho(), second_chirho.digest_chirho());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn fresh_reopen_recreate_and_collision_are_distinct_worlds_chirho() {
    let root_chirho = temp_root_chirho("lifecycle");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let (sign_root_chirho, node_chirho) = signing_identity_chirho(&root_chirho);
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    let store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
        anchor_input_chirho(),
    )
    .unwrap();
    let original_digest_chirho = store_chirho
        .activation_anchor_digest_chirho()
        .unwrap()
        .to_owned();

    let reopened_chirho = ShadowCanaryEvidenceStoreChirho::open_existing_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
    )
    .unwrap();
    assert_eq!(
        reopened_chirho.activation_anchor_digest_chirho(),
        Some(original_digest_chirho.as_str())
    );

    let collision_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
        anchor_input_chirho(),
    )
    .err()
    .expect("a retained activation anchor must collide");
    assert_eq!(
        collision_chirho.to_string(),
        "ShadowCanaryActivationAnchorCollisionRefusedChirho"
    );

    std::fs::remove_dir_all(&evidence_root_chirho).unwrap();
    let recreated_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho,
        anchor_input_chirho(),
    )
    .unwrap();
    assert_ne!(
        recreated_chirho.activation_anchor_digest_chirho(),
        Some(original_digest_chirho.as_str())
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

fn assert_store_coordinate_collision_chirho(
    evidence_root_chirho: &Path,
    sign_root_chirho: &Path,
    node_chirho: &NodeIdChirho,
) {
    let collision_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        evidence_root_chirho,
        sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
        anchor_input_chirho(),
    )
    .err()
    .expect("any retained store coordinate must collide");
    assert_eq!(
        collision_chirho.to_string(),
        "ShadowCanaryActivationAnchorCollisionRefusedChirho"
    );
    assert_ne!(
        collision_chirho.to_string(),
        "ShadowCanaryActivationAnchorCutBindingRefusedChirho"
    );
    assert_ne!(
        collision_chirho.to_string(),
        "ShadowCanaryActivationAnchorCreateRefusedChirho"
    );
}

#[test]
fn only_genuine_not_found_can_create_an_activation_incarnation_chirho() {
    let root_chirho = temp_root_chirho("coordinate-collisions");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let (sign_root_chirho, node_chirho) = signing_identity_chirho(&root_chirho);

    let retained_directory_chirho = root_chirho.join("retained-directory-chirho");
    std::fs::create_dir(&retained_directory_chirho).unwrap();
    assert_store_coordinate_collision_chirho(
        &retained_directory_chirho,
        &sign_root_chirho,
        &node_chirho,
    );

    let wrong_kind_file_chirho = root_chirho.join("wrong-kind-file-chirho");
    std::fs::write(&wrong_kind_file_chirho, b"retained authority").unwrap();
    assert_store_coordinate_collision_chirho(
        &wrong_kind_file_chirho,
        &sign_root_chirho,
        &node_chirho,
    );

    let dangling_symlink_chirho = root_chirho.join("dangling-symlink-chirho");
    symlink(
        root_chirho.join("missing-target-chirho"),
        &dangling_symlink_chirho,
    )
    .unwrap();
    assert_store_coordinate_collision_chirho(
        &dangling_symlink_chirho,
        &sign_root_chirho,
        &node_chirho,
    );

    let unreadable_parent_chirho = root_chirho.join("unreadable-parent-chirho");
    std::fs::create_dir(&unreadable_parent_chirho).unwrap();
    let denied_coordinate_chirho = unreadable_parent_chirho.join("retained-anchor-chirho");
    let mut unreadable_permissions_chirho = std::fs::metadata(&unreadable_parent_chirho)
        .unwrap()
        .permissions();
    unreadable_permissions_chirho.set_mode(0o000);
    std::fs::set_permissions(&unreadable_parent_chirho, unreadable_permissions_chirho).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&denied_coordinate_chirho)
            .expect_err("the fixture must causally produce an unreadable coordinate")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_store_coordinate_collision_chirho(
        &denied_coordinate_chirho,
        &sign_root_chirho,
        &node_chirho,
    );
    let mut cleanup_permissions_chirho = std::fs::metadata(&unreadable_parent_chirho)
        .unwrap()
        .permissions();
    cleanup_permissions_chirho.set_mode(0o700);
    std::fs::set_permissions(&unreadable_parent_chirho, cleanup_permissions_chirho).unwrap();

    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn first_canary_append_must_equal_the_anchored_activation_cut_chirho() {
    let root_chirho = temp_root_chirho("first-cut");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let (sign_root_chirho, node_chirho) = signing_identity_chirho(&root_chirho);
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    let store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
        anchor_input_chirho(),
    )
    .unwrap();
    let wrong_cut_chirho = store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, append_cut_chirho(2)))
        .unwrap_err();
    assert_eq!(
        wrong_cut_chirho.to_string(),
        "ShadowCanaryActivationAnchorCutBindingRefusedChirho"
    );
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, append_cut_chirho(1)))
        .unwrap();
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn same_seq_wrong_digest_cannot_satisfy_the_anchored_activation_cut_chirho() {
    let root_chirho = temp_root_chirho("same-seq-wrong-digest");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let (sign_root_chirho, node_chirho) = signing_identity_chirho(&root_chirho);
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    let store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
        anchor_input_chirho(),
    )
    .unwrap();
    let mut wrong_digest_cut_chirho = append_cut_chirho(1);
    wrong_digest_cut_chirho.append_record_digest_chirho = "d".repeat(64);
    assert_eq!(wrong_digest_cut_chirho.append_seq_chirho, 1);
    assert_ne!(
        wrong_digest_cut_chirho.append_record_digest_chirho,
        append_cut_chirho(1).append_record_digest_chirho
    );
    let wrong_cut_chirho = store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, wrong_digest_cut_chirho))
        .unwrap_err();
    assert_eq!(
        wrong_cut_chirho.to_string(),
        "ShadowCanaryActivationAnchorCutBindingRefusedChirho"
    );
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, append_cut_chirho(1)))
        .unwrap();
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn same_shape_wrong_anchor_cannot_relabel_a_signed_evidence_head_chirho() {
    let root_chirho = temp_root_chirho("same-shape-wrong-head-anchor");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let (sign_root_chirho, node_chirho) = signing_identity_chirho(&root_chirho);
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    let store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
        anchor_input_chirho(),
    )
    .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, append_cut_chirho(1)))
        .unwrap();
    store_chirho.verify_window_chirho().unwrap().unwrap();

    let head_path_chirho = evidence_root_chirho.join("head-chirho.json");
    let mut head_chirho: SignedShadowCanaryEvidenceHeadChirho =
        serde_json::from_slice(&std::fs::read(&head_path_chirho).unwrap()).unwrap();
    let original_head_chirho = head_chirho.clone();
    let original_anchor_digest_chirho = head_chirho
        .activation_anchor_digest_chirho
        .as_ref()
        .unwrap()
        .clone();
    let wrong_anchor_digest_chirho = if original_anchor_digest_chirho == "d".repeat(64) {
        "e".repeat(64)
    } else {
        "d".repeat(64)
    };
    assert_eq!(wrong_anchor_digest_chirho.len(), 64);
    assert_ne!(wrong_anchor_digest_chirho, original_anchor_digest_chirho);
    head_chirho.activation_anchor_digest_chirho = Some(wrong_anchor_digest_chirho);
    head_chirho.sig_chirho.clear();
    head_chirho.sig_chirho = sign_message_with_existing_key_chirho(
        &sign_root_chirho,
        &serde_json::to_vec(&head_chirho).unwrap(),
    )
    .unwrap();
    let mut expected_head_chirho = original_head_chirho;
    expected_head_chirho.activation_anchor_digest_chirho =
        head_chirho.activation_anchor_digest_chirho.clone();
    expected_head_chirho.sig_chirho = head_chirho.sig_chirho.clone();
    assert_eq!(head_chirho, expected_head_chirho);
    std::fs::write(&head_path_chirho, serde_json::to_vec(&head_chirho).unwrap()).unwrap();

    let refusal_chirho = store_chirho.verify_window_chirho().unwrap_err();
    assert_eq!(
        refusal_chirho.to_string(),
        "shadow canary evidence head has an invalid shape"
    );
    assert_ne!(
        refusal_chirho.to_string(),
        "shadow canary evidence head signature invalid"
    );
    assert_ne!(
        refusal_chirho.to_string(),
        "shadow canary evidence chain does not terminate at the signed head"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}
