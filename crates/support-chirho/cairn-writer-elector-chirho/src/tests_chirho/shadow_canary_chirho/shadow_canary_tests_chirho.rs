// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The shadow canary permits a mint only when the minter is the Raft-elected leader with a valid lease,
//! and flags a divergence (a would-be-blocked mint) when the minter is not the elected leader — over the
//! trivial single-node baseline and over a real raft-elected leader.

use crate::elector_port_chirho::{NodeIdChirho, SingleNodeWriterElectorChirho};
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use crate::shadow_canary_chirho::{
    observe_shadow_canary_chirho, ShadowCanaryAppendCutChirho, ShadowCanaryChirho,
    ShadowCanaryEvidenceStoreChirho, SignedShadowCanaryEvidenceChirho,
    SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V1_CHIRHO, SHADOW_CANARY_EVIDENCE_SCHEMA_CHIRHO,
    SHADOW_CANARY_SCHEMA_CHIRHO, SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn group_chirho() -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-canary-chirho".to_string(),
    }
}

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let unique_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-shadow-canary-{tag_chirho}-{}-{unique_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    root_chirho
}

fn evidence_store_chirho(
    tag_chirho: &str,
) -> (PathBuf, ShadowCanaryEvidenceStoreChirho, NodeIdChirho) {
    let root_chirho = temp_root_chirho(tag_chirho);
    let sign_root_chirho = root_chirho.join("signing-chirho");
    sign_message_chirho(&sign_root_chirho, b"provision shadow canary signer").unwrap();
    let node_chirho = NodeIdChirho(pubkey_hex_chirho(&sign_root_chirho).unwrap());
    let store_chirho = ShadowCanaryEvidenceStoreChirho::open_chirho(
        &root_chirho.join("evidence-chirho"),
        &sign_root_chirho,
        group_chirho(),
        node_chirho.clone(),
    )
    .unwrap();
    (root_chirho, store_chirho, node_chirho)
}

fn evidence_observation_chirho(
    node_chirho: &NodeIdChirho,
    fence_epoch_chirho: u64,
    permit_chirho: bool,
) -> ShadowCanaryChirho {
    ShadowCanaryChirho {
        schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_string(),
        group_chirho: group_chirho(),
        minter_node_id_chirho: node_chirho.clone(),
        append_cut_chirho: append_cut_chirho(fence_epoch_chirho, 7),
        raft_leader_id_chirho: permit_chirho.then(|| node_chirho.clone()),
        raft_term_chirho: 7,
        raft_lease_valid_chirho: permit_chirho,
        cutover_would_permit_chirho: permit_chirho,
        at_ms_chirho: 1_000 + fence_epoch_chirho,
    }
}

fn append_cut_chirho(
    fence_epoch_chirho: u64,
    durable_term_chirho: u64,
) -> ShadowCanaryAppendCutChirho {
    append_cut_at_seq_chirho(fence_epoch_chirho, fence_epoch_chirho, durable_term_chirho)
}

fn append_cut_at_seq_chirho(
    append_seq_chirho: u64,
    fence_epoch_chirho: u64,
    durable_term_chirho: u64,
) -> ShadowCanaryAppendCutChirho {
    ShadowCanaryAppendCutChirho {
        append_seq_chirho,
        append_record_digest_chirho: format!("{append_seq_chirho:064x}"),
        append_hlc_physical_ms_chirho: 1_000 + append_seq_chirho,
        append_hlc_logical_chirho: 0,
        process_generation_chirho: 1,
        durable_term_chirho,
        fence_epoch_chirho,
        fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho()).unwrap(),
    }
}

fn evidence_observation_at_cut_chirho(
    node_chirho: &NodeIdChirho,
    append_seq_chirho: u64,
    fence_epoch_chirho: u64,
    permit_chirho: bool,
) -> ShadowCanaryChirho {
    let mut observation_chirho =
        evidence_observation_chirho(node_chirho, fence_epoch_chirho, permit_chirho);
    observation_chirho.append_cut_chirho =
        append_cut_at_seq_chirho(append_seq_chirho, fence_epoch_chirho, 7);
    observation_chirho.at_ms_chirho = 1_000 + append_seq_chirho;
    observation_chirho
}

#[test]
fn canary_permits_when_minter_is_the_elected_leader_chirho() {
    let node_chirho = NodeIdChirho("a".repeat(64));
    let elector_chirho = SingleNodeWriterElectorChirho::new_chirho(node_chirho.clone());
    let group_chirho = group_chirho();

    let canary_chirho = observe_shadow_canary_chirho(
        &elector_chirho,
        &group_chirho,
        &node_chirho,
        append_cut_chirho(7, 1),
        1234,
    );
    assert_eq!(canary_chirho.schema_chirho, SHADOW_CANARY_SCHEMA_CHIRHO);
    assert_eq!(canary_chirho.append_cut_chirho.fence_epoch_chirho, 7);
    assert_eq!(
        canary_chirho.raft_leader_id_chirho.as_ref(),
        Some(&node_chirho)
    );
    assert!(canary_chirho.raft_lease_valid_chirho);
    assert!(
        canary_chirho.cutover_would_permit_chirho,
        "the minter IS the elected leader — a cutover would permit this mint"
    );
}

#[test]
fn canary_flags_when_minter_is_not_the_elected_leader_chirho() {
    let leader_chirho = NodeIdChirho("a".repeat(64));
    let other_minter_chirho = NodeIdChirho("b".repeat(64));
    let elector_chirho = SingleNodeWriterElectorChirho::new_chirho(leader_chirho.clone());
    let group_chirho = group_chirho();

    // A node that is NOT the elected leader minted the fence — a cutover would have blocked it.
    let canary_chirho = observe_shadow_canary_chirho(
        &elector_chirho,
        &group_chirho,
        &other_minter_chirho,
        append_cut_chirho(7, 1),
        1234,
    );
    assert_eq!(
        canary_chirho.raft_leader_id_chirho.as_ref(),
        Some(&leader_chirho)
    );
    assert_eq!(
        canary_chirho.minter_node_id_chirho, other_minter_chirho,
        "the minter is not the leader"
    );
    assert!(
        !canary_chirho.cutover_would_permit_chirho,
        "the minter is not the elected leader — a cutover would BLOCK this mint (flagged for review)"
    );
}

#[test]
fn canary_over_a_real_raft_leader_permits_chirho() {
    let node_chirho = NodeIdChirho("c".repeat(64));
    let group_chirho = group_chirho();
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_chirho(node_chirho.clone(), group_chirho.clone())
            .expect("build a raft elector");
    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");

    let raft_term_chirho = elector_chirho.current_leadership_chirho().term_chirho;
    let canary_chirho = observe_shadow_canary_chirho(
        &elector_chirho,
        &group_chirho,
        &node_chirho,
        append_cut_chirho(42, raft_term_chirho),
        5678,
    );
    assert_eq!(
        canary_chirho.raft_leader_id_chirho.as_ref(),
        Some(&node_chirho)
    );
    assert!(canary_chirho.raft_term_chirho >= 1);
    assert!(
        canary_chirho.cutover_would_permit_chirho,
        "the real raft leader minting is cutover-safe"
    );
}

#[test]
fn canary_reflects_the_warmup_lease_so_a_just_elected_leader_is_not_yet_permitted_chirho() {
    // With the warm-up lease (Option A) enabled on the observed elector, the canary's cutover-readiness
    // is HONEST about leadership freshness: a leader that just won the election holds the role but not yet
    // a valid lease, so a mint then would NOT be cutover-permitted — exactly the divergence a shadow run
    // must surface before P5.
    let node_chirho = NodeIdChirho("e".repeat(64));
    let group_chirho = group_chirho();
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_chirho(node_chirho.clone(), group_chirho.clone())
            .expect("build a raft elector")
            .with_leadership_warmup_lease_chirho();
    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");

    let fresh_term_chirho = elector_chirho.current_leadership_chirho().term_chirho;
    let fresh_chirho = observe_shadow_canary_chirho(
        &elector_chirho,
        &group_chirho,
        &node_chirho,
        append_cut_chirho(1, fresh_term_chirho),
        100,
    );
    assert!(!fresh_chirho.raft_lease_valid_chirho);
    assert!(
        !fresh_chirho.cutover_would_permit_chirho,
        "a just-elected leader is not yet lease-valid, so the canary flags a mint as not-yet-permitted"
    );

    // After a full election timeout of continuous leadership the warm-up completes and the canary permits.
    for _tick_chirho in 0..ELECTION_TIMEOUT_TICKS_FOR_WARMUP_CHIRHO {
        elector_chirho.tick_chirho();
    }
    let warmed_term_chirho = elector_chirho.current_leadership_chirho().term_chirho;
    let warmed_chirho = observe_shadow_canary_chirho(
        &elector_chirho,
        &group_chirho,
        &node_chirho,
        append_cut_chirho(2, warmed_term_chirho),
        200,
    );
    assert!(warmed_chirho.raft_lease_valid_chirho);
    assert!(
        warmed_chirho.cutover_would_permit_chirho,
        "after the warm-up the elected leader is cutover-permitted"
    );
}

#[test]
fn signed_canary_evidence_keeps_an_exact_fixed_window_and_file_bound_chirho() {
    let (root_chirho, store_chirho, node_chirho) = evidence_store_chirho("bounded-window");
    for fence_epoch_chirho in 1..=SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 2 {
        store_chirho
            .append_observation_chirho(evidence_observation_chirho(
                &node_chirho,
                fence_epoch_chirho,
                fence_epoch_chirho % 2 == 0,
            ))
            .unwrap();
    }

    let window_chirho = store_chirho.verify_window_chirho().unwrap().unwrap();
    assert_eq!(
        window_chirho.latest_seq_chirho,
        SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 2
    );
    assert_eq!(
        window_chirho.window_len_chirho,
        SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO
    );
    assert_eq!(window_chirho.oldest_fence_epoch_chirho, 3);
    assert_eq!(
        window_chirho.latest_fence_epoch_chirho,
        SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 2
    );
    assert_eq!(window_chirho.permit_count_chirho, 128);
    assert_eq!(window_chirho.refusal_count_chirho, 128);

    let slot_count_chirho =
        std::fs::read_dir(root_chirho.join("evidence-chirho").join("records-chirho"))
            .unwrap()
            .count() as u64;
    assert_eq!(
        slot_count_chirho,
        SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 1,
        "the evidence ring must stay at W+1 files regardless of lifetime history"
    );

    let future_seq_chirho = SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 3;
    let future_slot_chirho = root_chirho
        .join("evidence-chirho")
        .join("records-chirho")
        .join(format!(
            "slot-{:04}-chirho.json",
            future_seq_chirho % (SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 1)
        ));
    std::fs::write(&future_slot_chirho, b"orphaned-before-head-chirho").unwrap();
    assert_eq!(
        store_chirho
            .verify_window_chirho()
            .unwrap()
            .unwrap()
            .latest_seq_chirho,
        SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 2,
        "an orphan write in the extra slot must leave the prior full signed window valid"
    );
    store_chirho
        .append_observation_chirho(evidence_observation_chirho(
            &node_chirho,
            future_seq_chirho,
            false,
        ))
        .unwrap();
    let recovered_chirho = store_chirho.verify_window_chirho().unwrap().unwrap();
    assert_eq!(recovered_chirho.latest_seq_chirho, future_seq_chirho);
    assert_eq!(recovered_chirho.oldest_fence_epoch_chirho, 4);
    assert_eq!(
        recovered_chirho.latest_append_cut_chirho,
        append_cut_chirho(future_seq_chirho, 7)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn signed_canary_reuses_one_fence_for_many_appends_and_replays_exactly_chirho() {
    let (root_chirho, store_chirho, node_chirho) = evidence_store_chirho("reused-fence");
    let first_chirho = evidence_observation_at_cut_chirho(&node_chirho, 10, 3, true);
    let second_chirho = evidence_observation_at_cut_chirho(&node_chirho, 11, 3, true);
    let first_evidence_chirho = store_chirho
        .append_observation_chirho(first_chirho)
        .unwrap();
    let second_evidence_chirho = store_chirho
        .append_observation_chirho(second_chirho.clone())
        .unwrap();
    let replayed_chirho = store_chirho
        .append_observation_chirho(second_chirho.clone())
        .unwrap();
    assert_eq!(first_evidence_chirho.seq_chirho, 1);
    assert_eq!(second_evidence_chirho.seq_chirho, 2);
    assert_eq!(replayed_chirho, second_evidence_chirho);

    let window_chirho = store_chirho.verify_window_chirho().unwrap().unwrap();
    assert_eq!(window_chirho.window_len_chirho, 2);
    assert_eq!(window_chirho.oldest_fence_epoch_chirho, 3);
    assert_eq!(window_chirho.latest_fence_epoch_chirho, 3);
    assert_eq!(window_chirho.latest_append_cut_chirho.append_seq_chirho, 11);

    let mut conflicting_retry_chirho = second_chirho;
    conflicting_retry_chirho
        .append_cut_chirho
        .append_record_digest_chirho = "ff".repeat(32);
    assert!(store_chirho
        .append_observation_chirho(conflicting_retry_chirho)
        .unwrap_err()
        .to_string()
        .contains("append sequence did not advance"));
    assert!(store_chirho
        .append_observation_chirho(evidence_observation_at_cut_chirho(
            &node_chirho,
            13,
            3,
            true,
        ))
        .unwrap_err()
        .to_string()
        .contains("append sequence is not dense"));
    assert!(store_chirho
        .append_observation_chirho(evidence_observation_at_cut_chirho(
            &node_chirho,
            12,
            2,
            true,
        ))
        .unwrap_err()
        .to_string()
        .contains("fence epoch regressed"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn existing_canary_verification_is_byte_stable_and_never_repairs_locks_chirho() {
    let (root_chirho, store_chirho, node_chirho) = evidence_store_chirho("read-only-window");
    store_chirho
        .append_observation_chirho(evidence_observation_chirho(&node_chirho, 1, true))
        .unwrap();
    let evidence_root_chirho = root_chirho.join("evidence-chirho");
    let head_path_chirho = evidence_root_chirho.join("head-chirho.json");
    let record_path_chirho = evidence_root_chirho
        .join("records-chirho")
        .join("slot-0001-chirho.json");
    let head_before_chirho = std::fs::read(&head_path_chirho).unwrap();
    let record_before_chirho = std::fs::read(&record_path_chirho).unwrap();

    let window_chirho = store_chirho
        .verify_existing_window_read_only_chirho()
        .unwrap()
        .unwrap();
    assert_eq!(window_chirho.latest_seq_chirho, 1);
    assert_eq!(
        std::fs::read(&head_path_chirho).unwrap(),
        head_before_chirho
    );
    assert_eq!(
        std::fs::read(&record_path_chirho).unwrap(),
        record_before_chirho
    );

    let locks_dir_chirho = evidence_root_chirho.join("locks-chirho");
    std::fs::remove_dir_all(&locks_dir_chirho).unwrap();
    assert!(store_chirho
        .verify_existing_window_read_only_chirho()
        .is_err());
    assert!(
        !locks_dir_chirho.exists(),
        "publication verification must not recreate missing canary lock state"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn signed_canary_evidence_rejects_semantic_forgery_and_tampering_chirho() {
    let (root_chirho, store_chirho, node_chirho) = evidence_store_chirho("tamper");
    let mut false_permit_chirho = evidence_observation_chirho(&node_chirho, 1, false);
    false_permit_chirho.cutover_would_permit_chirho = true;
    assert!(store_chirho
        .append_observation_chirho(false_permit_chirho)
        .is_err());
    let mut leaderless_lease_chirho = evidence_observation_chirho(&node_chirho, 1, false);
    leaderless_lease_chirho.raft_lease_valid_chirho = true;
    assert!(store_chirho
        .append_observation_chirho(leaderless_lease_chirho)
        .is_err());

    let first_evidence_chirho = store_chirho
        .append_observation_chirho(evidence_observation_chirho(&node_chirho, 1, true))
        .unwrap();
    assert_eq!(
        SHADOW_CANARY_EVIDENCE_SCHEMA_CHIRHO,
        "writer-elector-shadow-canary-evidence-v2-chirho"
    );
    assert_eq!(
        first_evidence_chirho.schema_chirho,
        SHADOW_CANARY_EVIDENCE_SCHEMA_CHIRHO
    );
    let head_chirho: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root_chirho.join("evidence-chirho").join("head-chirho.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        head_chirho["schema_chirho"].as_str(),
        Some(SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V1_CHIRHO)
    );
    assert_eq!(
        SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V1_CHIRHO,
        "writer-elector-shadow-canary-evidence-head-v1-chirho"
    );
    let mut regressed_term_chirho = evidence_observation_chirho(&node_chirho, 2, true);
    regressed_term_chirho.raft_term_chirho = 6;
    assert!(store_chirho
        .append_observation_chirho(regressed_term_chirho)
        .is_err());
    let mut regressed_time_chirho = evidence_observation_chirho(&node_chirho, 2, true);
    regressed_time_chirho.at_ms_chirho = 999;
    assert!(store_chirho
        .append_observation_chirho(regressed_time_chirho)
        .is_err());
    let record_path_chirho = root_chirho
        .join("evidence-chirho")
        .join("records-chirho")
        .join("slot-0001-chirho.json");
    let mut record_chirho: SignedShadowCanaryEvidenceChirho =
        serde_json::from_slice(&std::fs::read(&record_path_chirho).unwrap()).unwrap();
    record_chirho.observation_chirho.at_ms_chirho += 1;
    std::fs::write(
        &record_path_chirho,
        serde_json::to_vec(&record_chirho).unwrap(),
    )
    .unwrap();
    let error_chirho = store_chirho.verify_window_chirho().unwrap_err();
    assert!(error_chirho.to_string().contains("signature invalid"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn signed_canary_record_rejects_an_unknown_observation_field_chirho() {
    let (root_chirho, store_chirho, node_chirho) =
        evidence_store_chirho("unknown-observation-field");
    store_chirho
        .append_observation_chirho(evidence_observation_chirho(&node_chirho, 1, true))
        .unwrap();
    let record_path_chirho = root_chirho
        .join("evidence-chirho")
        .join("records-chirho")
        .join("slot-0001-chirho.json");
    let mut record_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path_chirho).unwrap()).unwrap();
    record_chirho["observation_chirho"]
        .as_object_mut()
        .unwrap()
        .insert(
            "unexpected_observation_field_chirho".to_string(),
            serde_json::json!("must-not-be-dropped-chirho"),
        );
    std::fs::write(
        &record_path_chirho,
        serde_json::to_vec(&record_chirho).unwrap(),
    )
    .unwrap();

    let error_chirho = store_chirho.verify_window_chirho().unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("unexpected_observation_field_chirho"),
        "the persisted canary record must reject, not drop, an unknown field: {error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn signed_canary_evidence_rejects_an_unknown_envelope_field_chirho() {
    let (root_chirho, store_chirho, node_chirho) = evidence_store_chirho("unknown-evidence-field");
    store_chirho
        .append_observation_chirho(evidence_observation_chirho(&node_chirho, 1, true))
        .unwrap();
    let record_path_chirho = root_chirho
        .join("evidence-chirho")
        .join("records-chirho")
        .join("slot-0001-chirho.json");
    let mut evidence_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path_chirho).unwrap()).unwrap();
    evidence_chirho.as_object_mut().unwrap().insert(
        "unexpected_evidence_field_chirho".to_string(),
        serde_json::json!("must-not-be-dropped-chirho"),
    );
    std::fs::write(
        &record_path_chirho,
        serde_json::to_vec(&evidence_chirho).unwrap(),
    )
    .unwrap();

    let error_chirho = store_chirho.verify_window_chirho().unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("unexpected_evidence_field_chirho"),
        "the signed evidence envelope must reject, not drop, an unknown field: {error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn signed_canary_evidence_head_rejects_an_unknown_field_chirho() {
    let (root_chirho, store_chirho, node_chirho) = evidence_store_chirho("unknown-head-field");
    store_chirho
        .append_observation_chirho(evidence_observation_chirho(&node_chirho, 1, true))
        .unwrap();
    let head_path_chirho = root_chirho.join("evidence-chirho").join("head-chirho.json");
    let mut head_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&head_path_chirho).unwrap()).unwrap();
    head_chirho.as_object_mut().unwrap().insert(
        "unexpected_head_field_chirho".to_string(),
        serde_json::json!("must-not-be-dropped-chirho"),
    );
    std::fs::write(&head_path_chirho, serde_json::to_vec(&head_chirho).unwrap()).unwrap();

    let error_chirho = store_chirho.verify_window_chirho().unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("unexpected_head_field_chirho"),
        "the signed evidence head must reject, not drop, an unknown field: {error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn signed_canary_evidence_rejects_an_oversized_head_before_parsing_chirho() {
    let (root_chirho, store_chirho, node_chirho) = evidence_store_chirho("oversized-head");
    store_chirho
        .append_observation_chirho(evidence_observation_chirho(&node_chirho, 1, true))
        .unwrap();
    std::fs::write(
        root_chirho.join("evidence-chirho").join("head-chirho.json"),
        vec![b'x'; 70_000],
    )
    .unwrap();
    let error_chirho = store_chirho.verify_window_chirho().unwrap_err();
    assert!(error_chirho.to_string().contains("bounded regular file"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// The election-timeout ticks the single-node warm-up lease needs (matches the elector's election_tick).
const ELECTION_TIMEOUT_TICKS_FOR_WARMUP_CHIRHO: usize = 10;
