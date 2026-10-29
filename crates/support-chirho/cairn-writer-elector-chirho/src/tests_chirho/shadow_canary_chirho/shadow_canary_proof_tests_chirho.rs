// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::elector_port_chirho::NodeIdChirho;
use crate::shadow_canary_activation_anchor_chirho::ShadowCanaryActivationAnchorInputChirho;
use crate::shadow_canary_chirho::{
    ShadowCanaryAppendCutChirho, ShadowCanaryChirho, ShadowCanaryEvidenceStoreChirho,
    SHADOW_CANARY_SCHEMA_CHIRHO,
};
use crate::shadow_canary_generation_chirho::{
    ShadowCanaryAdoptionGenerationInputChirho, ShadowCanaryGenerationStoreChirho,
    ShadowCanaryLedgerCutChirho,
};
use crate::shadow_canary_proof_chirho::{
    build_signed_shadow_canary_window_proof_chirho, projected_record_digest_chirho,
    require_green_shadow_canary_writer_window_chirho, shadow_canary_window_proof_bytes_chirho,
    unsigned_proof_message_chirho, verify_shadow_canary_window_proof_bytes_chirho,
    ShadowCanaryAdoptionProofProjectionRefusalChirho, ShadowCanaryWindowProofInputChirho,
    ShadowCanaryWindowProofRefusalChirho, ShadowCanaryWriterWindowRequirementsChirho,
    SignedShadowCanaryWindowProofChirho, MAX_SHADOW_CANARY_WINDOW_PROOF_BYTES_CHIRHO,
    SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V2_CHIRHO, SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V3_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::{
    pubkey_hex_chirho, sign_message_chirho, sign_message_with_existing_key_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn group_chirho() -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/private/canary-proof-root-chirho".to_owned(),
    }
}

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let unique_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-canary-proof-{tag_chirho}-{}-{unique_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    root_chirho
}

fn observation_chirho(node_chirho: &NodeIdChirho, append_seq_chirho: u64) -> ShadowCanaryChirho {
    ShadowCanaryChirho {
        schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_owned(),
        group_chirho: group_chirho(),
        minter_node_id_chirho: node_chirho.clone(),
        append_cut_chirho: ShadowCanaryAppendCutChirho {
            append_seq_chirho,
            append_record_digest_chirho: format!("{append_seq_chirho:064x}"),
            append_hlc_physical_ms_chirho: 10_000 + append_seq_chirho,
            append_hlc_logical_chirho: 0,
            process_generation_chirho: 1,
            durable_term_chirho: 7,
            fence_epoch_chirho: 11,
            fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho()).unwrap(),
        },
        raft_leader_id_chirho: Some(node_chirho.clone()),
        raft_term_chirho: 7,
        raft_lease_valid_chirho: true,
        cutover_would_permit_chirho: true,
        at_ms_chirho: 20_000 + append_seq_chirho,
    }
}

fn proof_store_chirho(
    tag_chirho: &str,
    observation_count_chirho: u64,
) -> (
    PathBuf,
    PathBuf,
    NodeIdChirho,
    ShadowCanaryGenerationStoreChirho,
) {
    let root_chirho = temp_root_chirho(tag_chirho);
    let sign_root_chirho = root_chirho.join("signing-chirho");
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    sign_message_chirho(&sign_root_chirho, b"provision proof signer").unwrap();
    let node_chirho = NodeIdChirho(pubkey_hex_chirho(&sign_root_chirho).unwrap());
    let evidence_store_chirho = ShadowCanaryEvidenceStoreChirho::open_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
    )
    .unwrap();
    for append_seq_chirho in 1..=observation_count_chirho {
        evidence_store_chirho
            .append_observation_chirho(observation_chirho(&node_chirho, append_seq_chirho))
            .unwrap();
    }
    let generation_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
    )
    .unwrap();
    (
        root_chirho,
        sign_root_chirho,
        node_chirho,
        generation_store_chirho,
    )
}

fn anchored_proof_store_chirho(
    tag_chirho: &str,
    observation_count_chirho: u64,
) -> (
    PathBuf,
    PathBuf,
    NodeIdChirho,
    ShadowCanaryGenerationStoreChirho,
) {
    let root_chirho = temp_root_chirho(tag_chirho);
    let sign_root_chirho = root_chirho.join("signing-chirho");
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    sign_message_chirho(&sign_root_chirho, b"provision anchored proof signer").unwrap();
    let node_chirho = NodeIdChirho(pubkey_hex_chirho(&sign_root_chirho).unwrap());
    let evidence_store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
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
            activation_append_cut_chirho: observation_chirho(&node_chirho, 1).append_cut_chirho,
        },
    )
    .unwrap();
    for append_seq_chirho in 1..=observation_count_chirho {
        evidence_store_chirho
            .append_observation_chirho(observation_chirho(&node_chirho, append_seq_chirho))
            .unwrap();
    }
    let generation_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
    )
    .unwrap();
    (
        root_chirho,
        sign_root_chirho,
        node_chirho,
        generation_store_chirho,
    )
}

fn adoption_input_chirho(adopted_seq_chirho: u64) -> ShadowCanaryAdoptionGenerationInputChirho {
    ShadowCanaryAdoptionGenerationInputChirho {
        adopted_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
            adopted_seq_chirho,
            format!("{adopted_seq_chirho:064x}"),
            30_000 + adopted_seq_chirho,
            0,
            11,
            &group_chirho(),
        )
        .unwrap(),
        cluster_id_chirho: "proof-cluster-chirho".to_owned(),
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
            br#"{"receipt_chirho":"first-chirho"}"#.to_vec(),
            br#"{"receipt_chirho":"second-chirho"}"#.to_vec(),
        ],
        candidate_journal_binding_digest_chirho: "e".repeat(64),
        candidate_journal_digest_chirho: "f".repeat(64),
    }
}

fn resign_chirho(
    proof_chirho: &mut SignedShadowCanaryWindowProofChirho,
    sign_root_chirho: &std::path::Path,
) {
    proof_chirho.sig_chirho.clear();
    proof_chirho.sig_chirho = sign_message_with_existing_key_chirho(
        sign_root_chirho,
        &unsigned_proof_message_chirho(proof_chirho).unwrap(),
    )
    .unwrap();
}

fn unchecked_proof_bytes_chirho(proof_chirho: &SignedShadowCanaryWindowProofChirho) -> Vec<u8> {
    serde_json::to_vec(proof_chirho).unwrap()
}

#[test]
fn same_shape_wrong_anchor_cannot_relabel_a_window_proof_chirho() {
    let root_chirho = temp_root_chirho("wrong-anchor-export");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let sign_root_chirho = root_chirho.join("signing-chirho");
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    sign_message_chirho(&sign_root_chirho, b"provision anchored proof signer").unwrap();
    let node_chirho = NodeIdChirho(pubkey_hex_chirho(&sign_root_chirho).unwrap());
    let append_cut_chirho = observation_chirho(&node_chirho, 1).append_cut_chirho;
    let store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &evidence_root_chirho,
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
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
            activation_append_cut_chirho: append_cut_chirho.clone(),
        },
    )
    .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 1))
        .unwrap();
    let activation_anchor_digest_chirho = store_chirho
        .activation_anchor_digest_chirho()
        .unwrap()
        .to_owned();
    let latest_ledger_cut_chirho =
        ShadowCanaryLedgerCutChirho::from_append_cut_chirho(&append_cut_chirho, &group_chirho())
            .unwrap();

    let matching_proof_chirho = build_signed_shadow_canary_window_proof_chirho(
        ShadowCanaryWindowProofInputChirho {
            node_id_chirho: node_chirho.clone(),
            group_chirho: group_chirho(),
            generation_chirho: 0,
            activation_anchor_digest_chirho: Some(activation_anchor_digest_chirho.clone()),
            prior_generation_chirho: None,
            generation_descriptor_digest_chirho: None,
            prior_latest_evidence_digest_chirho: None,
            adopted_ledger_cut_chirho: None,
            adoption_proof_projection_chirho: None,
            latest_ledger_cut_chirho: latest_ledger_cut_chirho.clone(),
            window_source_chirho: store_chirho
                .verified_window_source_read_only_chirho()
                .unwrap(),
        },
        &sign_root_chirho,
    )
    .unwrap();
    assert_eq!(
        matching_proof_chirho.activation_anchor_digest_chirho,
        Some(activation_anchor_digest_chirho.clone())
    );

    let wrong_anchor_digest_chirho = if activation_anchor_digest_chirho == "d".repeat(64) {
        "e".repeat(64)
    } else {
        "d".repeat(64)
    };
    assert_eq!(wrong_anchor_digest_chirho.len(), 64);
    assert_ne!(wrong_anchor_digest_chirho, activation_anchor_digest_chirho);
    let refusal_chirho = build_signed_shadow_canary_window_proof_chirho(
        ShadowCanaryWindowProofInputChirho {
            node_id_chirho: node_chirho,
            group_chirho: group_chirho(),
            generation_chirho: 0,
            activation_anchor_digest_chirho: Some(wrong_anchor_digest_chirho),
            prior_generation_chirho: None,
            generation_descriptor_digest_chirho: None,
            prior_latest_evidence_digest_chirho: None,
            adopted_ledger_cut_chirho: None,
            adoption_proof_projection_chirho: None,
            latest_ledger_cut_chirho,
            window_source_chirho: store_chirho
                .verified_window_source_read_only_chirho()
                .unwrap(),
        },
        &sign_root_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<ShadowCanaryWindowProofRefusalChirho>(),
        Some(&ShadowCanaryWindowProofRefusalChirho::ActivationAnchorRefusedChirho)
    );
    assert_ne!(
        refusal_chirho.downcast_ref::<ShadowCanaryWindowProofRefusalChirho>(),
        Some(&ShadowCanaryWindowProofRefusalChirho::ShapeRefusedChirho)
    );
    assert_ne!(
        refusal_chirho.downcast_ref::<ShadowCanaryWindowProofRefusalChirho>(),
        Some(&ShadowCanaryWindowProofRefusalChirho::GenerationRefusedChirho)
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

fn reproject_members_chirho(
    proof_chirho: &mut SignedShadowCanaryWindowProofChirho,
    mut previous_projection_digest_chirho: String,
) {
    for record_chirho in &mut proof_chirho.records_chirho {
        record_chirho.previous_projection_digest_chirho = previous_projection_digest_chirho;
        record_chirho.projection_digest_chirho =
            projected_record_digest_chirho(record_chirho).unwrap();
        previous_projection_digest_chirho = record_chirho.projection_digest_chirho.clone();
    }
    proof_chirho
        .head_chirho
        .as_mut()
        .unwrap()
        .latest_projection_digest_chirho = previous_projection_digest_chirho;
}

#[test]
fn offline_proof_derives_the_green_window_and_contains_no_raw_path_chirho() {
    let (root_chirho, _, node_chirho, store_chirho) = proof_store_chirho("green", 2);
    let proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    let bytes_chirho = shadow_canary_window_proof_bytes_chirho(&proof_chirho).unwrap();
    let verified_chirho = verify_shadow_canary_window_proof_bytes_chirho(&bytes_chirho).unwrap();
    let qualified_chirho = require_green_shadow_canary_writer_window_chirho(
        &verified_chirho,
        ShadowCanaryWriterWindowRequirementsChirho {
            minimum_observation_count_chirho: 2,
            minimum_interval_millis_chirho: 1,
        },
    )
    .unwrap();

    assert_eq!(verified_chirho.node_id_chirho, node_chirho.0);
    assert_eq!(qualified_chirho.observation_count_chirho, 2);
    assert_eq!(qualified_chirho.interval_millis_chirho, 1);
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    assert!(!text_chirho.contains("/private/canary-proof-root-chirho"));
    assert!(!text_chirho.contains("receipt_chirho"));
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn member_counts_override_a_validly_resigned_false_summary_chirho() {
    let (root_chirho, sign_root_chirho, _, store_chirho) = proof_store_chirho("summary", 2);
    let mut proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    let head_chirho = proof_chirho.head_chirho.as_mut().unwrap();
    head_chirho.permit_count_chirho = 1;
    head_chirho.refusal_count_chirho = 1;
    resign_chirho(&mut proof_chirho, &sign_root_chirho);

    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &proof_chirho
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::CountRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_validly_resigned_suffix_cannot_hide_an_earlier_refusal_chirho() {
    let (root_chirho, sign_root_chirho, node_chirho, store_chirho) =
        proof_store_chirho("prefix-truncation", 0);
    let mut refusal_chirho = observation_chirho(&node_chirho, 1);
    refusal_chirho.raft_lease_valid_chirho = false;
    refusal_chirho.cutover_would_permit_chirho = false;
    store_chirho
        .append_observation_chirho(refusal_chirho)
        .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 2))
        .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 3))
        .unwrap();
    let mut proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    assert_eq!(
        proof_chirho
            .head_chirho
            .as_ref()
            .unwrap()
            .refusal_count_chirho,
        1
    );
    verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(&proof_chirho))
        .unwrap();

    let projection_genesis_chirho = proof_chirho.records_chirho[0]
        .previous_projection_digest_chirho
        .clone();
    proof_chirho.records_chirho.remove(0);
    reproject_members_chirho(&mut proof_chirho, projection_genesis_chirho);
    let head_chirho = proof_chirho.head_chirho.as_mut().unwrap();
    head_chirho.window_len_chirho = 2;
    head_chirho.permit_count_chirho = 2;
    head_chirho.refusal_count_chirho = 0;
    resign_chirho(&mut proof_chirho, &sign_root_chirho);

    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &proof_chirho
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::PopulationRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_validly_resigned_summary_without_members_never_becomes_a_window_chirho() {
    let (root_chirho, sign_root_chirho, _, store_chirho) =
        proof_store_chirho("summary-without-members", 2);
    let mut proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    proof_chirho.records_chirho.clear();
    resign_chirho(&mut proof_chirho, &sign_root_chirho);

    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &proof_chirho
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::PopulationRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn every_projected_member_digest_is_recomputed_after_outer_resigning_chirho() {
    let (root_chirho, sign_root_chirho, _, store_chirho) =
        proof_store_chirho("projected-member", 2);
    let mut proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    proof_chirho.records_chirho[0].observed_at_ms_chirho += 100;
    resign_chirho(&mut proof_chirho, &sign_root_chirho);

    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &proof_chirho
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::ChainRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn supported_serialization_refuses_secret_shaped_member_text_chirho() {
    let (root_chirho, sign_root_chirho, _, store_chirho) = proof_store_chirho("secret-shaped", 2);
    let mut proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    proof_chirho.records_chirho[0].append_record_digest_chirho =
        "operator-secret-value-chirho".to_owned();
    resign_chirho(&mut proof_chirho, &sign_root_chirho);

    let refusal_chirho = shadow_canary_window_proof_bytes_chirho(&proof_chirho).unwrap_err();
    assert_eq!(
        refusal_chirho,
        ShadowCanaryWindowProofRefusalChirho::CoordinateRefusedChirho
    );
    assert!(!refusal_chirho
        .as_str_chirho()
        .contains("operator-secret-value-chirho"));
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn current_generation_members_cannot_be_padded_with_generation_zero_chirho() {
    let (root_chirho, sign_root_chirho, node_chirho, store_chirho) =
        proof_store_chirho("generation", 2);
    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 6))
        .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 7))
        .unwrap();
    let mut proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    assert_eq!(proof_chirho.generation_chirho, 1);
    proof_chirho.records_chirho[0].generation_chirho = 0;
    resign_chirho(&mut proof_chirho, &sign_root_chirho);

    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &proof_chirho
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::GenerationRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_validly_resigned_post_adoption_window_cannot_skip_the_first_append_chirho() {
    let (root_chirho, sign_root_chirho, node_chirho, store_chirho) =
        proof_store_chirho("post-adoption-density", 2);
    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 6))
        .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 7))
        .unwrap();
    let mut proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(&proof_chirho))
        .unwrap();

    let projection_genesis_chirho = proof_chirho.records_chirho[0]
        .previous_projection_digest_chirho
        .clone();
    for record_chirho in &mut proof_chirho.records_chirho {
        record_chirho.append_seq_chirho += 1;
        record_chirho.append_record_digest_chirho =
            format!("{:064x}", record_chirho.append_seq_chirho);
        record_chirho.append_hlc_physical_ms_chirho = 10_000 + record_chirho.append_seq_chirho;
    }
    reproject_members_chirho(&mut proof_chirho, projection_genesis_chirho);
    let last_chirho = proof_chirho.records_chirho.last().unwrap().clone();
    proof_chirho.latest_ledger_cut_chirho.append_seq_chirho = last_chirho.append_seq_chirho;
    proof_chirho
        .latest_ledger_cut_chirho
        .append_record_digest_chirho = last_chirho.append_record_digest_chirho;
    proof_chirho
        .latest_ledger_cut_chirho
        .append_hlc_physical_ms_chirho = last_chirho.append_hlc_physical_ms_chirho;
    resign_chirho(&mut proof_chirho, &sign_root_chirho);

    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &proof_chirho
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::GenerationRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn v3_requires_the_inner_signed_adoption_projection_chirho() {
    let (root_chirho, sign_root_chirho, node_chirho, store_chirho) =
        anchored_proof_store_chirho("v3-adoption-projection", 2);
    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    store_chirho
        .append_observation_chirho(observation_chirho(&node_chirho, 6))
        .unwrap();
    let proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    assert_eq!(
        proof_chirho.schema_chirho,
        SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V3_CHIRHO
    );
    let projection_chirho = proof_chirho
        .adoption_proof_projection_chirho
        .as_ref()
        .unwrap();
    assert_eq!(projection_chirho.historical_term_chirho, 5);
    assert_eq!(projection_chirho.elected_term_chirho, 7);

    let mut missing_projection_chirho = proof_chirho.clone();
    missing_projection_chirho.adoption_proof_projection_chirho = None;
    resign_chirho(&mut missing_projection_chirho, &sign_root_chirho);
    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &missing_projection_chirho,
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::ShapeRefusedChirho
    );

    let mut legacy_schema_chirho = proof_chirho.clone();
    legacy_schema_chirho.schema_chirho = SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V2_CHIRHO.to_owned();
    resign_chirho(&mut legacy_schema_chirho, &sign_root_chirho);
    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &legacy_schema_chirho,
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::ShapeRefusedChirho
    );

    let mut inner_tamper_chirho = proof_chirho;
    inner_tamper_chirho
        .adoption_proof_projection_chirho
        .as_mut()
        .unwrap()
        .historical_term_chirho = 4;
    resign_chirho(&mut inner_tamper_chirho, &sign_root_chirho);
    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &inner_tamper_chirho,
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::AdoptionProjectionRefusedChirho(
            ShadowCanaryAdoptionProofProjectionRefusalChirho::SignatureRefusedChirho,
        )
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_activation_only_observation_is_present_but_not_a_window_chirho() {
    let (root_chirho, _, _, store_chirho) = proof_store_chirho("single", 1);
    let proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    let verified_chirho = verify_shadow_canary_window_proof_bytes_chirho(
        &shadow_canary_window_proof_bytes_chirho(&proof_chirho).unwrap(),
    )
    .unwrap();
    assert_eq!(verified_chirho.window_chirho.unwrap().window_len_chirho, 1);
    assert_eq!(
        require_green_shadow_canary_writer_window_chirho(
            &verify_shadow_canary_window_proof_bytes_chirho(
                &shadow_canary_window_proof_bytes_chirho(&proof_chirho).unwrap()
            )
            .unwrap(),
            ShadowCanaryWriterWindowRequirementsChirho {
                minimum_observation_count_chirho: 2,
                minimum_interval_millis_chirho: 1,
            },
        )
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::WriterPopulationRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_empty_adopted_generation_is_present_but_not_window_qualified_chirho() {
    let (root_chirho, _, _, store_chirho) = proof_store_chirho("empty-adopted", 1);
    store_chirho
        .commit_adoption_generation_chirho(adoption_input_chirho(5))
        .unwrap();
    let proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    let verified_chirho = verify_shadow_canary_window_proof_bytes_chirho(
        &shadow_canary_window_proof_bytes_chirho(&proof_chirho).unwrap(),
    )
    .unwrap();
    assert_eq!(verified_chirho.generation_chirho, 1);
    assert!(verified_chirho.window_chirho.is_none());
    assert_eq!(
        require_green_shadow_canary_writer_window_chirho(
            &verified_chirho,
            ShadowCanaryWriterWindowRequirementsChirho {
                minimum_observation_count_chirho: 2,
                minimum_interval_millis_chirho: 1,
            },
        )
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::WriterPopulationRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_interior_member_gap_refuses_even_when_the_summary_is_resigned_chirho() {
    let (root_chirho, sign_root_chirho, _, store_chirho) = proof_store_chirho("gap", 3);
    let mut proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    proof_chirho.records_chirho.remove(1);
    let head_chirho = proof_chirho.head_chirho.as_mut().unwrap();
    head_chirho.window_len_chirho = 2;
    head_chirho.permit_count_chirho = 2;
    resign_chirho(&mut proof_chirho, &sign_root_chirho);

    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&unchecked_proof_bytes_chirho(
            &proof_chirho
        ))
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::ChainRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn writer_requirements_cannot_define_one_observation_or_zero_time_as_a_window_chirho() {
    let (root_chirho, _, _, store_chirho) = proof_store_chirho("requirements", 2);
    let proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    let verified_chirho = verify_shadow_canary_window_proof_bytes_chirho(
        &shadow_canary_window_proof_bytes_chirho(&proof_chirho).unwrap(),
    )
    .unwrap();
    for requirements_chirho in [
        ShadowCanaryWriterWindowRequirementsChirho {
            minimum_observation_count_chirho: 1,
            minimum_interval_millis_chirho: 1,
        },
        ShadowCanaryWriterWindowRequirementsChirho {
            minimum_observation_count_chirho: 2,
            minimum_interval_millis_chirho: 0,
        },
    ] {
        assert_eq!(
            require_green_shadow_canary_writer_window_chirho(
                &verified_chirho,
                requirements_chirho,
            )
            .unwrap_err(),
            ShadowCanaryWindowProofRefusalChirho::WriterRequirementRefusedChirho
        );
    }
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_actual_interval_shorter_than_the_declared_minimum_refuses_chirho() {
    let (root_chirho, _, _, store_chirho) = proof_store_chirho("short-interval", 2);
    let proof_chirho = store_chirho
        .export_current_window_proof_read_only_chirho()
        .unwrap();
    let verified_chirho = verify_shadow_canary_window_proof_bytes_chirho(
        &shadow_canary_window_proof_bytes_chirho(&proof_chirho).unwrap(),
    )
    .unwrap();
    assert_eq!(
        require_green_shadow_canary_writer_window_chirho(
            &verified_chirho,
            ShadowCanaryWriterWindowRequirementsChirho {
                minimum_observation_count_chirho: 2,
                minimum_interval_millis_chirho: 2,
            },
        )
        .unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::WriterIntervalRefusedChirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn oversized_proof_bytes_refuse_before_decode_chirho() {
    let oversized_chirho = vec![b' '; MAX_SHADOW_CANARY_WINDOW_PROOF_BYTES_CHIRHO + 1];
    assert_eq!(
        verify_shadow_canary_window_proof_bytes_chirho(&oversized_chirho).unwrap_err(),
        ShadowCanaryWindowProofRefusalChirho::BytesRefusedChirho
    );
}
