// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::elector_port_chirho::NodeIdChirho;
use crate::shadow_canary_activation_anchor_chirho::ShadowCanaryActivationAnchorInputChirho;
use crate::shadow_canary_chirho::{
    optional_shadow_canary_path_metadata_chirho, ShadowCanaryAppendCutChirho, ShadowCanaryChirho,
    ShadowCanaryEvidenceStoreChirho, SHADOW_CANARY_SCHEMA_CHIRHO,
    SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO,
};
use crate::shadow_canary_generation_chirho::{
    ShadowCanaryAdoptionGenerationInputChirho, ShadowCanaryGenerationStoreChirho,
    ShadowCanaryLedgerCutChirho,
};
use crate::shadow_canary_proof_chirho::{
    verify_shadow_canary_adoption_proof_projection_chirho,
    verify_shadow_canary_window_proof_chirho, ShadowCanaryAdoptionProofProjectionRefusalChirho,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn group_chirho() -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-canary-generation-chirho".to_string(),
    }
}

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let unique_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-shadow-canary-generation-{tag_chirho}-{}-{unique_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    root_chirho
}

fn append_cut_chirho(append_seq_chirho: u64) -> ShadowCanaryAppendCutChirho {
    ShadowCanaryAppendCutChirho {
        append_seq_chirho,
        append_record_digest_chirho: format!("{append_seq_chirho:064x}"),
        append_hlc_physical_ms_chirho: 10_000 + append_seq_chirho,
        append_hlc_logical_chirho: 0,
        process_generation_chirho: 1,
        durable_term_chirho: 7,
        fence_epoch_chirho: append_seq_chirho,
        fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho()).unwrap(),
    }
}

fn observation_chirho(node_chirho: &NodeIdChirho, append_seq_chirho: u64) -> ShadowCanaryChirho {
    ShadowCanaryChirho {
        schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_string(),
        group_chirho: group_chirho(),
        minter_node_id_chirho: node_chirho.clone(),
        append_cut_chirho: append_cut_chirho(append_seq_chirho),
        raft_leader_id_chirho: Some(node_chirho.clone()),
        raft_term_chirho: 7,
        raft_lease_valid_chirho: true,
        cutover_would_permit_chirho: true,
        at_ms_chirho: 20_000 + append_seq_chirho,
    }
}

fn activation_anchor_input_chirho() -> ShadowCanaryActivationAnchorInputChirho {
    ShadowCanaryActivationAnchorInputChirho {
        activation_authorization_digest_chirho: format!(
            "activation-authorization-v1-chirho:{}",
            "1".repeat(64)
        ),
        activation_plan_digest_chirho: "2".repeat(64),
        resident_identity_digest_chirho: format!("resident-identity-v1-chirho:{}", "3".repeat(64)),
        activation_append_cut_chirho: append_cut_chirho(1),
    }
}

fn adoption_input_chirho(adopted_seq_chirho: u64) -> ShadowCanaryAdoptionGenerationInputChirho {
    ShadowCanaryAdoptionGenerationInputChirho {
        adopted_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
            adopted_seq_chirho,
            format!("{adopted_seq_chirho:064x}"),
            10_000 + adopted_seq_chirho,
            0,
            7,
            &group_chirho(),
        )
        .unwrap(),
        cluster_id_chirho: "canary-generation-cluster-chirho".to_owned(),
        journal_genesis_digest_chirho: "9".repeat(64),
        assignment_digest_chirho: "a".repeat(64),
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

fn generation_store_chirho(
    tag_chirho: &str,
) -> (
    PathBuf,
    PathBuf,
    PathBuf,
    NodeIdChirho,
    ShadowCanaryGenerationStoreChirho,
) {
    let root_chirho = temp_root_chirho(tag_chirho);
    let sign_root_chirho = root_chirho.join("signing-chirho");
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    sign_message_chirho(&sign_root_chirho, b"provision canary generation signer").unwrap();
    let node_chirho = NodeIdChirho(pubkey_hex_chirho(&sign_root_chirho).unwrap());
    let base_store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
        activation_anchor_input_chirho(),
    )
    .unwrap();
    base_store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 1))
        .unwrap();
    let store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
    )
    .unwrap();
    (
        root_chirho,
        evidence_root_chirho,
        sign_root_chirho,
        node_chirho,
        store_chirho,
    )
}

fn generation_root_chirho(
    evidence_root_chirho: &std::path::Path,
    generation_chirho: u64,
) -> PathBuf {
    evidence_root_chirho
        .join("generations-chirho")
        .join(format!("generation-{generation_chirho:020}-chirho"))
}

#[test]
fn signed_head_preserves_anchor_after_activation_member_ages_out_chirho() {
    let (root_chirho, _, _, node_chirho, store_chirho) = generation_store_chirho("anchor-aged-out");
    let original_anchor_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap()
        .activation_anchor_digest_chirho
        .unwrap();
    for append_seq_chirho in 2..=SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 3 {
        store_chirho
            .append_observation_chirho(observation_chirho(&node_chirho, append_seq_chirho))
            .unwrap();
    }
    let proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    let verified_chirho = verify_shadow_canary_window_proof_chirho(&proof_chirho).unwrap();
    assert_eq!(
        proof_chirho.activation_anchor_digest_chirho.as_deref(),
        Some(original_anchor_chirho.as_str())
    );
    assert_eq!(
        verified_chirho.activation_anchor_digest_chirho.as_deref(),
        Some(original_anchor_chirho.as_str())
    );
    assert!(proof_chirho
        .records_chirho
        .iter()
        .all(|record_chirho| record_chirho.append_seq_chirho > 1));
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn adoption_descriptor_preserves_anchor_after_generation_rollover_chirho() {
    let (root_chirho, _, _, node_chirho, store_chirho) = generation_store_chirho("anchor-adoption");
    let original_anchor_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap()
        .activation_anchor_digest_chirho
        .unwrap();
    let adoption_chirho = store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    assert_eq!(
        adoption_chirho.activation_anchor_digest_chirho(),
        Some(original_anchor_chirho.as_str())
    );
    let projection_chirho = adoption_chirho.adoption_proof_projection_chirho().unwrap();
    verify_shadow_canary_adoption_proof_projection_chirho(projection_chirho).unwrap();
    assert_eq!(projection_chirho.historical_term_chirho, 5);
    assert_eq!(projection_chirho.elected_term_chirho, 7);
    assert_eq!(
        projection_chirho.historical_membership_view_digest_chirho,
        "1".repeat(64)
    );
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 6))
        .unwrap();
    let proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    let verified_chirho = verify_shadow_canary_window_proof_chirho(&proof_chirho).unwrap();
    assert_eq!(proof_chirho.generation_chirho, 1);
    assert_eq!(
        proof_chirho.schema_chirho,
        "writer-elector-shadow-canary-window-proof-v3-chirho"
    );
    assert!(verified_chirho.adoption_proof_projection_chirho.is_some());
    let proof_text_chirho = serde_json::to_string(&proof_chirho).unwrap();
    assert!(!proof_text_chirho.contains("first-chirho"));
    assert!(!proof_text_chirho.contains("second-chirho"));
    assert_eq!(
        proof_chirho.activation_anchor_digest_chirho.as_deref(),
        Some(original_anchor_chirho.as_str())
    );
    assert_eq!(
        verified_chirho.activation_anchor_digest_chirho.as_deref(),
        Some(original_anchor_chirho.as_str())
    );
    assert!(proof_chirho
        .records_chirho
        .iter()
        .all(|record_chirho| record_chirho.append_seq_chirho >= 6));
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn same_shape_wrong_anchor_cannot_relabel_a_generation_rollover_chirho() {
    let (root_chirho, evidence_root_chirho, sign_root_chirho, _, store_chirho) =
        generation_store_chirho("wrong-anchor-adoption");
    let adoption_chirho = store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    let original_anchor_chirho = adoption_chirho
        .activation_anchor_digest_chirho()
        .unwrap()
        .to_owned();
    assert_eq!(
        store_chirho
            .export_current_window_proof_read_only_chirho()
            .unwrap()
            .activation_anchor_digest_chirho
            .as_deref(),
        Some(original_anchor_chirho.as_str())
    );

    let selector_path_chirho = evidence_root_chirho.join("generation-head-chirho.json");
    let descriptor_path_chirho =
        generation_root_chirho(&evidence_root_chirho, 1).join("adoption-generation-chirho.json");
    let original_bytes_chirho = std::fs::read_to_string(&selector_path_chirho).unwrap();
    assert_eq!(
        original_bytes_chirho,
        std::fs::read_to_string(&descriptor_path_chirho).unwrap()
    );
    let original_value_chirho: serde_json::Value =
        serde_json::from_str(&original_bytes_chirho).unwrap();
    let original_sig_chirho = original_value_chirho["sig_chirho"].as_str().unwrap();
    let wrong_anchor_chirho = if original_anchor_chirho == "f".repeat(64) {
        "e".repeat(64)
    } else {
        "f".repeat(64)
    };
    assert_eq!(wrong_anchor_chirho.len(), original_anchor_chirho.len());
    assert_ne!(wrong_anchor_chirho, original_anchor_chirho);

    let wrong_anchor_bytes_chirho = original_bytes_chirho.replacen(
        &format!("\"activation_anchor_digest_chirho\":\"{original_anchor_chirho}\""),
        &format!("\"activation_anchor_digest_chirho\":\"{wrong_anchor_chirho}\""),
        1,
    );
    assert_ne!(wrong_anchor_bytes_chirho, original_bytes_chirho);
    let unsigned_bytes_chirho = wrong_anchor_bytes_chirho.replacen(
        &format!("\"sig_chirho\":\"{original_sig_chirho}\""),
        "\"sig_chirho\":\"\"",
        1,
    );
    let replacement_sig_chirho =
        sign_message_chirho(&sign_root_chirho, unsigned_bytes_chirho.as_bytes()).unwrap();
    let resigned_bytes_chirho = unsigned_bytes_chirho.replacen(
        "\"sig_chirho\":\"\"",
        &format!("\"sig_chirho\":\"{replacement_sig_chirho}\""),
        1,
    );
    let mut original_neighbours_chirho = original_value_chirho;
    let mut resigned_neighbours_chirho: serde_json::Value =
        serde_json::from_str(&resigned_bytes_chirho).unwrap();
    for field_chirho in ["activation_anchor_digest_chirho", "sig_chirho"] {
        original_neighbours_chirho
            .as_object_mut()
            .unwrap()
            .remove(field_chirho);
        resigned_neighbours_chirho
            .as_object_mut()
            .unwrap()
            .remove(field_chirho);
    }
    assert_eq!(original_neighbours_chirho, resigned_neighbours_chirho);
    std::fs::write(&selector_path_chirho, &resigned_bytes_chirho).unwrap();
    std::fs::write(&descriptor_path_chirho, &resigned_bytes_chirho).unwrap();

    let refusal_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap_err()
        .to_string();
    assert_eq!(
        refusal_chirho,
        "ShadowCanaryAdoptionProjectionBindingRefusedChirho"
    );
    for neighbour_chirho in [
        "ShadowCanaryGenerationIdentityShapeRefusedChirho",
        "shadow canary selector does not match its immutable generation",
        "shadow canary generation signature invalid",
    ] {
        assert_ne!(refusal_chirho, neighbour_chirho);
    }
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn equal_term_adoption_refuses_before_a_descriptor_can_commit_chirho() {
    let (root_chirho, _, _, _, store_chirho) = generation_store_chirho("equal-term-adoption");
    let mut input_chirho = adoption_input_chirho(5);
    input_chirho.elected_term_chirho = input_chirho.historical_term_chirho;
    let refusal_chirho = store_chirho
        .commit_adoption_generation_chirho(input_chirho)
        .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<ShadowCanaryAdoptionProofProjectionRefusalChirho>(),
        Some(&ShadowCanaryAdoptionProofProjectionRefusalChirho::TermStrictnessRefusedChirho)
    );
    assert!(store_chirho
        .verify_current_read_only_chirho()
        .unwrap()
        .adoption_chirho()
        .is_none());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn dangling_generation_selector_never_falls_back_to_generation_zero_chirho() {
    let (root_chirho, evidence_root_chirho, _, _, store_chirho) =
        generation_store_chirho("dangling-selector");
    symlink(
        root_chirho.join("missing-generation-selector-target-chirho"),
        evidence_root_chirho.join("generation-head-chirho.json"),
    )
    .unwrap();

    assert!(store_chirho
        .export_current_window_proof_read_only_chirho()
        .is_err());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn permission_denied_optional_path_is_never_reported_absent_chirho() {
    let (root_chirho, evidence_root_chirho, _, _, _store_chirho) =
        generation_store_chirho("permission-denied-selector");
    let original_permissions_chirho = std::fs::metadata(&evidence_root_chirho)
        .unwrap()
        .permissions();
    let mut denied_permissions_chirho = original_permissions_chirho.clone();
    denied_permissions_chirho.set_mode(0o000);
    std::fs::set_permissions(&evidence_root_chirho, denied_permissions_chirho).unwrap();

    let result_chirho = optional_shadow_canary_path_metadata_chirho(
        &evidence_root_chirho.join("generation-head-chirho.json"),
        "inspect shadow canary generation head",
    );

    std::fs::set_permissions(&evidence_root_chirho, original_permissions_chirho).unwrap();
    assert_eq!(
        result_chirho.unwrap_err().to_string(),
        "inspect shadow canary generation head"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn dangling_current_evidence_head_never_becomes_an_empty_adopted_proof_chirho() {
    let (root_chirho, evidence_root_chirho, _, _, store_chirho) =
        generation_store_chirho("dangling-current-head");
    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    symlink(
        root_chirho.join("missing-current-evidence-head-target-chirho"),
        generation_root_chirho(&evidence_root_chirho, 1).join("head-chirho.json"),
    )
    .unwrap();

    assert!(store_chirho
        .export_current_window_proof_read_only_chirho()
        .is_err());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn dangling_adoption_descriptor_is_never_overwritten_as_absent_chirho() {
    let (root_chirho, evidence_root_chirho, _, _, store_chirho) =
        generation_store_chirho("dangling-descriptor");
    let generation_root_chirho = generation_root_chirho(&evidence_root_chirho, 1);
    std::fs::create_dir_all(&generation_root_chirho).unwrap();
    let descriptor_path_chirho = generation_root_chirho.join("adoption-generation-chirho.json");
    symlink(
        root_chirho.join("missing-adoption-descriptor-target-chirho"),
        &descriptor_path_chirho,
    )
    .unwrap();

    assert!(store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .is_err());
    assert!(std::fs::symlink_metadata(descriptor_path_chirho)
        .unwrap()
        .file_type()
        .is_symlink());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn adoption_starts_an_explicit_empty_generation_without_fabricating_a_mint_chirho() {
    let (root_chirho, evidence_root_chirho, sign_root_chirho, node_chirho, store_chirho) =
        generation_store_chirho("empty-successor");
    let base_before_chirho = ShadowCanaryEvidenceStoreChirho::open_existing_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
    )
    .unwrap()
    .verify_existing_window_read_only_chirho()
    .unwrap()
    .unwrap();

    let committed_chirho = store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    let current_chirho = store_chirho.verify_current_read_only_chirho().unwrap();
    let base_after_chirho = ShadowCanaryEvidenceStoreChirho::open_existing_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho,
    )
    .unwrap()
    .verify_existing_window_read_only_chirho()
    .unwrap()
    .unwrap();

    assert_eq!(committed_chirho.generation_chirho(), 1);
    assert_eq!(current_chirho.generation_chirho(), 1);
    assert_eq!(current_chirho.prior_generation_chirho(), Some(0));
    assert!(current_chirho.window_chirho().is_none());
    assert_eq!(
        current_chirho
            .latest_ledger_cut_chirho()
            .append_seq_chirho(),
        5
    );
    assert_eq!(base_before_chirho, base_after_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn generation_zero_cutover_window_refuses_an_adopted_chain_chirho() {
    let (root_chirho, _, _, _, store_chirho) =
        generation_store_chirho("generation-zero-cutover-only");
    let generation_zero_chirho = store_chirho.verify_current_read_only_chirho().unwrap();
    assert_eq!(
        generation_zero_chirho
            .require_generation_zero_window_chirho()
            .unwrap()
            .window_len_chirho,
        1
    );

    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    let adopted_chirho = store_chirho.verify_current_read_only_chirho().unwrap();
    let refusal_chirho = adopted_chirho
        .require_generation_zero_window_chirho()
        .expect_err("an adopted canary generation is not lifetime cutover evidence")
        .to_string();
    assert!(refusal_chirho.contains("ShadowCanaryGenerationZeroRequiredChirho"));
    assert!(!refusal_chirho.contains("shadow canary generation zero is empty"));
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn current_generation_window_contains_only_the_dense_post_adoption_observation_chirho() {
    let (root_chirho, _, _, node_chirho, store_chirho) =
        generation_store_chirho("dense-first-observation");
    let prior_chirho = store_chirho.verify_current_read_only_chirho().unwrap();
    assert_eq!(prior_chirho.window_chirho().unwrap().window_len_chirho, 1);
    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();

    let refusal_chirho = store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 7))
        .unwrap_err();
    assert!(
        refusal_chirho
            .to_string()
            .contains("shadow canary first post-adoption observation is not dense"),
        "unexpected refusal: {refusal_chirho:#}"
    );
    assert!(store_chirho
        .verify_current_read_only_chirho()
        .unwrap()
        .window_chirho()
        .is_none());

    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 6))
        .unwrap();
    let current_chirho = store_chirho.verify_current_read_only_chirho().unwrap();
    let current_window_chirho = current_chirho.window_chirho().unwrap();
    assert_eq!(current_window_chirho.latest_seq_chirho, 1);
    assert_eq!(current_window_chirho.window_len_chirho, 1);
    assert_eq!(current_window_chirho.permit_count_chirho, 1);
    assert_eq!(current_window_chirho.refusal_count_chirho, 0);
    assert_eq!(
        current_window_chirho
            .latest_append_cut_chirho
            .append_seq_chirho,
        6
    );
    assert_eq!(
        current_chirho
            .latest_ledger_cut_chirho()
            .append_seq_chirho(),
        6
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn adoption_retry_is_idempotent_only_for_the_exact_authority_binding_chirho() {
    let (root_chirho, _, _, _, store_chirho) = generation_store_chirho("exact-retry");
    let first_chirho = store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    let retry_chirho = store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    assert_eq!(first_chirho, retry_chirho);

    let mut foreign_chirho = adoption_input_chirho(5);
    foreign_chirho.membership_view_digest_chirho = "f".repeat(64);
    let refusal_chirho = store_chirho
        .commit_adoption_generation_chirho(foreign_chirho)
        .unwrap_err();
    assert!(
        refusal_chirho
            .to_string()
            .contains("shadow canary adoption retry does not match the committed generation"),
        "unexpected refusal: {refusal_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_second_adoption_can_follow_an_empty_prior_generation_chirho() {
    let (root_chirho, _, _, node_chirho, store_chirho) =
        generation_store_chirho("second-after-empty");
    let first_chirho = store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    assert!(store_chirho
        .verify_current_read_only_chirho()
        .unwrap()
        .window_chirho()
        .is_none());

    let second_chirho = store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(9))
        .unwrap();
    let current_chirho = store_chirho.verify_current_read_only_chirho().unwrap();

    assert_eq!(first_chirho.generation_chirho(), 1);
    assert_eq!(second_chirho.generation_chirho(), 2);
    assert_eq!(second_chirho.prior_generation_chirho(), 1);
    assert!(second_chirho
        .prior_generation_descriptor_digest_chirho()
        .is_some());
    assert_eq!(second_chirho.prior_latest_evidence_digest_chirho(), None);
    assert_eq!(
        second_chirho
            .prior_latest_ledger_cut_chirho()
            .append_seq_chirho(),
        5
    );
    assert_eq!(current_chirho.generation_chirho(), 2);
    assert_eq!(current_chirho.prior_generation_chirho(), Some(1));
    assert_eq!(
        current_chirho
            .latest_ledger_cut_chirho()
            .append_seq_chirho(),
        9
    );
    assert!(current_chirho.window_chirho().is_none());

    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 10))
        .unwrap();
    assert_eq!(
        store_chirho
            .verify_current_read_only_chirho()
            .unwrap()
            .latest_ledger_cut_chirho()
            .append_seq_chirho(),
        10
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_second_adoption_binds_the_prior_generations_latest_real_observation_chirho() {
    let (root_chirho, _, _, node_chirho, store_chirho) =
        generation_store_chirho("second-after-observation");
    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 6))
        .unwrap();

    let second_chirho = store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(9))
        .unwrap();
    assert!(second_chirho
        .prior_latest_evidence_digest_chirho()
        .is_some());
    assert_eq!(
        second_chirho
            .prior_latest_ledger_cut_chirho()
            .append_seq_chirho(),
        6
    );
    assert_eq!(
        store_chirho
            .verify_current_read_only_chirho()
            .unwrap()
            .generation_chirho(),
        2
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn post_adoption_observation_refuses_a_prior_leader_minter_identity_chirho() {
    let (root_chirho, _, _, node_chirho, store_chirho) =
        generation_store_chirho("prior-leader-minter");
    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    let mut observation_chirho = observation_chirho(&node_chirho, 6);
    observation_chirho.minter_node_id_chirho = NodeIdChirho("8".repeat(64));

    let refusal_chirho = store_chirho
        .append_observation_chirho(observation_chirho)
        .expect_err("the prior leader cannot mint into the adopter's new canary chain")
        .to_string();
    assert!(refusal_chirho.contains("ShadowCanaryObservationMinterIdentityRefusedChirho"));
    assert!(!refusal_chirho.contains("shadow canary first post-adoption observation is not dense"));
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn adoption_generation_refuses_missing_holder_provenance_chirho() {
    let (root_chirho, _, _, _, store_chirho) = generation_store_chirho("missing-provenance");
    let mut input_chirho = adoption_input_chirho(5);
    input_chirho.holder_receipt_wires_chirho[1].clear();

    let refusal_chirho = store_chirho
        .commit_adoption_generation_chirho(input_chirho)
        .expect_err("an adoption genesis without both holder receipts must refuse")
        .to_string();
    assert!(refusal_chirho.contains("ShadowCanaryHolderReceiptPopulationShapeRefusedChirho"));
    assert!(!refusal_chirho.contains("ShadowCanaryAdoptedCutBindingShapeRefusedChirho"));
    std::fs::remove_dir_all(root_chirho).unwrap();
}
