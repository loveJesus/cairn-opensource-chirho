// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::writer_head_chirho::{
    issue_elected_writer_fence_for_root_chirho, issue_writer_fence_for_root_chirho,
    observe_prepared_fence_lower_bound_chirho, with_head_transition_scope_chirho,
};
use cairn_core_chirho::{cas_chirho, model_chirho::RefsChirho};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-head-transition-{label_chirho}-{nanos_chirho}-{}-{counter_chirho}",
        std::process::id()
    ))
}

fn provision_signer_chirho(root_chirho: &Path) {
    signer_chirho::sign_message_chirho(root_chirho, b"provision head transition signer").unwrap();
}

fn current_head_chirho(root_chirho: &Path, branch_chirho: &str) -> Option<HashChirho> {
    refs_chirho::load_refs_chirho(root_chirho)
        .unwrap()
        .branches_chirho
        .get(branch_chirho)
        .cloned()
}

fn synthetic_prepared_chirho(
    fence_chirho: &WriterFenceTokenChirho,
    previous_chirho: &Option<HashChirho>,
    next_chirho: &HashChirho,
    family_seq_chirho: u64,
    operation_chirho: &[u8],
) -> PreparedHeadTransitionChirho {
    let input_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: "synthetic-head-records-chirho.jsonl",
        family_seq_chirho,
        branch_chirho: "synthetic/app-chirho",
        previous_chirho,
        next_chirho,
        reason_chirho: "synthetic-positive-head",
        operation_bytes_chirho: operation_chirho,
        prepared_fence_chirho: fence_chirho,
        at_ms_chirho: 10_000 + family_seq_chirho,
    };
    let transition_id_chirho = derive_head_transition_id_chirho(&input_chirho).unwrap();
    let signed_line_chirho = format!(
        "{{\"seq_chirho\":{family_seq_chirho},\"transition_id_chirho\":\"{transition_id_chirho}\",\"sig_chirho\":\"synthetic-caller-verified\"}}"
    );
    bind_caller_verified_head_transition_chirho(
        &input_chirho,
        &transition_id_chirho,
        signed_line_chirho.as_bytes(),
    )
    .unwrap()
}

fn prepared_from_elected_observation_chirho(
    root_chirho: &Path,
    next_chirho: &HashChirho,
) -> PreparedHeadTransitionChirho {
    let group_chirho = crate::writer_head_chirho::consistency_group_for_root_chirho(root_chirho)
        .expect("derive elected group");
    let evidence_chirho = observe_prepared_fence_lower_bound_chirho(root_chirho, &group_chirho)
        .expect("observe elected lower bound");
    let input_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: "synthetic-head-records-chirho.jsonl",
        family_seq_chirho: 0,
        branch_chirho: "synthetic/elected-app-chirho",
        previous_chirho: &None,
        next_chirho,
        reason_chirho: "synthetic-elected-positive-head",
        operation_bytes_chirho: b"elected operation",
        prepared_fence_chirho: &evidence_chirho,
        at_ms_chirho: 20_000,
    };
    let transition_id_chirho = derive_head_transition_id_from_prepared_fence_chirho(&input_chirho)
        .expect("derive evidence-bound transition");
    bind_caller_verified_head_transition_from_prepared_fence_chirho(
        &input_chirho,
        &transition_id_chirho,
        b"{\"sig_chirho\":\"caller-verified\"}",
    )
    .expect("bind evidence-bound transition")
}

fn prepare_without_apply_chirho(
    root_chirho: &Path,
    previous_chirho: Option<HashChirho>,
    next_chirho: &HashChirho,
    family_seq_chirho: u64,
    operation_chirho: &[u8],
) -> (PreparedHeadTransitionChirho, WriterFenceTokenChirho) {
    let mut prepared_chirho = None;
    let mut fence_chirho = None;
    with_head_transition_scope_chirho(root_chirho, |token_chirho| {
        prepared_chirho = Some(synthetic_prepared_chirho(
            token_chirho,
            &previous_chirho,
            next_chirho,
            family_seq_chirho,
            operation_chirho,
        ));
        fence_chirho = Some(token_chirho.clone());
        Ok(())
    })
    .unwrap();
    (prepared_chirho.unwrap(), fence_chirho.unwrap())
}

fn receipts_for_transition_chirho(
    root_chirho: &Path,
    transition_id_chirho: &str,
) -> Vec<ReflogEntryChirho> {
    refs_chirho::reflog_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|entry_chirho| entry_chirho.transition_id_chirho == transition_id_chirho)
        .collect()
}

#[test]
fn clean_apply_uses_prepared_fence_and_records_one_valid_receipt_chirho() {
    let root_chirho = temp_root_chirho("clean");
    provision_signer_chirho(&root_chirho);
    let next_chirho = cas_chirho::add_chirho(&root_chirho, b"clean next").unwrap();
    let mut prepared_chirho = None;
    let mut prepared_epoch_chirho = 0;
    with_head_transition_scope_chirho(&root_chirho, |fence_chirho| {
        prepared_epoch_chirho = fence_chirho.epoch_chirho;
        let transition_chirho =
            synthetic_prepared_chirho(fence_chirho, &None, &next_chirho, 0, b"clean operation");
        assert_eq!(
            complete_head_transition_unlocked_chirho(
                &root_chirho,
                &transition_chirho,
                fence_chirho,
            )
            .unwrap(),
            HeadTransitionRecoveryOutcomeChirho::AppliedChirho
        );
        prepared_chirho = Some(transition_chirho);
        Ok(())
    })
    .unwrap();

    let prepared_chirho = prepared_chirho.unwrap();
    let receipts_chirho =
        receipts_for_transition_chirho(&root_chirho, prepared_chirho.transition_id_chirho());
    assert_eq!(receipts_chirho.len(), 1);
    assert_eq!(
        receipts_chirho[0].prepared_writer_fence_epoch_chirho,
        Some(prepared_epoch_chirho)
    );
    assert_eq!(
        receipts_chirho[0].applied_writer_fence_epoch_chirho,
        Some(prepared_epoch_chirho)
    );
    assert_eq!(
        current_head_chirho(&root_chirho, "synthetic/app-chirho"),
        Some(next_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn crash_before_ref_recovers_with_later_epoch_and_stable_receipt_core_chirho() {
    let root_chirho = temp_root_chirho("before-ref");
    provision_signer_chirho(&root_chirho);
    let next_chirho = cas_chirho::add_chirho(&root_chirho, b"before ref next").unwrap();
    let (prepared_chirho, prepared_fence_chirho) =
        prepare_without_apply_chirho(&root_chirho, None, &next_chirho, 0, b"before ref operation");
    let clean_receipt_chirho =
        signed_receipt_chirho(&root_chirho, &prepared_chirho, &prepared_fence_chirho).unwrap();
    let clean_core_chirho =
        head_transition_receipt_core_digest_chirho(&clean_receipt_chirho).unwrap();

    assert_eq!(
        recover_head_transition_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadTransitionRecoveryOutcomeChirho::AppliedChirho
    );
    let receipts_chirho =
        receipts_for_transition_chirho(&root_chirho, prepared_chirho.transition_id_chirho());
    assert_eq!(receipts_chirho.len(), 1);
    assert_eq!(
        head_transition_receipt_core_digest_chirho(&receipts_chirho[0]).unwrap(),
        clean_core_chirho
    );
    assert!(
        receipts_chirho[0]
            .applied_writer_fence_epoch_chirho
            .unwrap()
            > receipts_chirho[0]
                .prepared_writer_fence_epoch_chirho
                .unwrap()
    );
    assert_ne!(receipts_chirho[0], clean_receipt_chirho);
    assert_eq!(
        current_head_chirho(&root_chirho, "synthetic/app-chirho"),
        Some(next_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn crash_after_ref_before_reflog_repairs_exactly_once_chirho() {
    let root_chirho = temp_root_chirho("after-ref");
    provision_signer_chirho(&root_chirho);
    let next_chirho = cas_chirho::add_chirho(&root_chirho, b"after ref next").unwrap();
    let (prepared_chirho, _prepared_fence_chirho) =
        prepare_without_apply_chirho(&root_chirho, None, &next_chirho, 0, b"after ref operation");
    refs_chirho::save_refs_chirho(
        &root_chirho,
        &RefsChirho {
            branches_chirho: [("synthetic/app-chirho".to_string(), next_chirho.clone())]
                .into_iter()
                .collect(),
            head_chirho: "main".to_string(),
            tags_chirho: Default::default(),
        },
    )
    .unwrap();

    assert_eq!(
        recover_head_transition_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadTransitionRecoveryOutcomeChirho::RepairedReflogChirho
    );
    assert_eq!(
        recover_head_transition_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadTransitionRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(
        receipts_for_transition_chirho(&root_chirho, prepared_chirho.transition_id_chirho()).len(),
        1
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn torn_recovery_receipt_is_truncated_then_completed_once_at_a_later_epoch_chirho() {
    let root_chirho = temp_root_chirho("torn-receipt");
    provision_signer_chirho(&root_chirho);
    let next_chirho = cas_chirho::add_chirho(&root_chirho, b"torn next").unwrap();
    let (prepared_chirho, _prepared_fence_chirho) = prepare_without_apply_chirho(
        &root_chirho,
        None,
        &next_chirho,
        0,
        b"torn receipt operation",
    );
    let mut torn_epoch_chirho = 0;
    with_head_transition_scope_chirho(&root_chirho, |fence_chirho| {
        torn_epoch_chirho = fence_chirho.epoch_chirho;
        let receipt_chirho = signed_receipt_chirho(&root_chirho, &prepared_chirho, fence_chirho)?;
        refs_chirho::save_refs_chirho(
            &root_chirho,
            &RefsChirho {
                branches_chirho: [("synthetic/app-chirho".to_string(), next_chirho.clone())]
                    .into_iter()
                    .collect(),
                head_chirho: "main".to_string(),
                tags_chirho: Default::default(),
            },
        )?;
        let mut bytes_chirho = serde_json::to_vec(&receipt_chirho)?;
        bytes_chirho.truncate(bytes_chirho.len() / 2);
        std::fs::write(refs_chirho::reflog_path_chirho(&root_chirho), bytes_chirho)?;
        Ok(())
    })
    .unwrap();

    assert_eq!(
        recover_head_transition_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadTransitionRecoveryOutcomeChirho::RepairedReflogChirho
    );
    let receipts_chirho =
        receipts_for_transition_chirho(&root_chirho, prepared_chirho.transition_id_chirho());
    assert_eq!(receipts_chirho.len(), 1);
    assert!(
        receipts_chirho[0]
            .applied_writer_fence_epoch_chirho
            .unwrap()
            > torn_epoch_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn applied_receipt_prevents_deliberate_rollback_resurrection_chirho() {
    let root_chirho = temp_root_chirho("rollback");
    provision_signer_chirho(&root_chirho);
    let first_chirho = cas_chirho::add_chirho(&root_chirho, b"version A").unwrap();
    let second_chirho = cas_chirho::add_chirho(&root_chirho, b"version B").unwrap();

    let first_prepared_chirho = {
        let mut prepared_chirho = None;
        with_head_transition_scope_chirho(&root_chirho, |fence_chirho| {
            let transition_chirho = synthetic_prepared_chirho(
                fence_chirho,
                &None,
                &first_chirho,
                0,
                b"version A operation",
            );
            complete_head_transition_unlocked_chirho(
                &root_chirho,
                &transition_chirho,
                fence_chirho,
            )?;
            prepared_chirho = Some(transition_chirho);
            Ok(())
        })
        .unwrap();
        prepared_chirho.unwrap()
    };
    let second_prepared_chirho = {
        let mut prepared_chirho = None;
        with_head_transition_scope_chirho(&root_chirho, |fence_chirho| {
            let transition_chirho = synthetic_prepared_chirho(
                fence_chirho,
                &Some(first_chirho.clone()),
                &second_chirho,
                1,
                b"version B operation",
            );
            complete_head_transition_unlocked_chirho(
                &root_chirho,
                &transition_chirho,
                fence_chirho,
            )?;
            prepared_chirho = Some(transition_chirho);
            Ok(())
        })
        .unwrap();
        prepared_chirho.unwrap()
    };
    assert_ne!(
        first_prepared_chirho.transition_id_chirho(),
        second_prepared_chirho.transition_id_chirho()
    );
    refs_chirho::rollback_chirho(&root_chirho, "synthetic/app-chirho", first_chirho.clone())
        .unwrap();
    let before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();

    assert_eq!(
        recover_head_transition_chirho(&root_chirho, &second_prepared_chirho).unwrap(),
        HeadTransitionRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        before_chirho
    );
    assert_eq!(
        current_head_chirho(&root_chirho, "synthetic/app-chirho"),
        Some(first_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn stale_preparer_cannot_complete_after_recovery_advances_fence_chirho() {
    let root_chirho = temp_root_chirho("zombie");
    provision_signer_chirho(&root_chirho);
    let next_chirho = cas_chirho::add_chirho(&root_chirho, b"zombie next").unwrap();
    let (prepared_chirho, stale_fence_chirho) =
        prepare_without_apply_chirho(&root_chirho, None, &next_chirho, 0, b"zombie operation");
    recover_head_transition_chirho(&root_chirho, &prepared_chirho).unwrap();
    let before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();

    let error_chirho = seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        complete_head_transition_unlocked_chirho(
            &root_chirho,
            &prepared_chirho,
            &stale_fence_chirho,
        )
    })
    .unwrap_err();
    let error_chirho = format!("{error_chirho:#}");
    assert!(
        error_chirho.contains("StaleWriterFenceChirho"),
        "{error_chirho}"
    );
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        before_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn forged_or_duplicate_receipts_fail_closed_chirho() {
    let root_chirho = temp_root_chirho("forged");
    provision_signer_chirho(&root_chirho);
    let next_chirho = cas_chirho::add_chirho(&root_chirho, b"forged next").unwrap();
    let (prepared_chirho, prepared_fence_chirho) =
        prepare_without_apply_chirho(&root_chirho, None, &next_chirho, 0, b"forged operation");
    let valid_chirho =
        signed_receipt_chirho(&root_chirho, &prepared_chirho, &prepared_fence_chirho).unwrap();
    let mut tampered_id_chirho = valid_chirho.clone();
    tampered_id_chirho.transition_id_chirho =
        format!("{HEAD_TRANSITION_ID_PREFIX_CHIRHO}{}", "1".repeat(64));
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        seqlog_chirho::append_jsonl_unlocked_chirho(
            &refs_chirho::reflog_path_chirho(&root_chirho),
            &tampered_id_chirho,
        )
    })
    .unwrap();
    let before_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let error_chirho = recover_head_transition_chirho(&root_chirho, &prepared_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("does not match the caller-verified prepared transition"),
        "{error_chirho}"
    );
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
        before_chirho
    );

    std::fs::remove_file(refs_chirho::reflog_path_chirho(&root_chirho)).unwrap();
    let mut forged_chirho = valid_chirho;
    forged_chirho.sig_chirho = "00".repeat(64);
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        seqlog_chirho::append_jsonl_unlocked_chirho(
            &refs_chirho::reflog_path_chirho(&root_chirho),
            &forged_chirho,
        )
    })
    .unwrap();
    let before_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let error_chirho = recover_head_transition_chirho(&root_chirho, &prepared_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("signature invalid"), "{error_chirho}");
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
        before_chirho
    );

    std::fs::remove_file(refs_chirho::reflog_path_chirho(&root_chirho)).unwrap();
    recover_head_transition_chirho(&root_chirho, &prepared_chirho).unwrap();
    let receipt_chirho =
        receipts_for_transition_chirho(&root_chirho, prepared_chirho.transition_id_chirho())
            .pop()
            .unwrap();
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        seqlog_chirho::append_jsonl_unlocked_chirho(
            &refs_chirho::reflog_path_chirho(&root_chirho),
            &receipt_chirho,
        )
    })
    .unwrap();
    assert!(
        recover_head_transition_chirho(&root_chirho, &prepared_chirho)
            .unwrap_err()
            .to_string()
            .contains("duplicate reflog receipts")
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn multiple_unapplied_candidates_fail_closed_chirho() {
    let root_chirho = temp_root_chirho("ambiguous");
    provision_signer_chirho(&root_chirho);
    let left_chirho = cas_chirho::add_chirho(&root_chirho, b"left").unwrap();
    let right_chirho = cas_chirho::add_chirho(&root_chirho, b"right").unwrap();
    with_head_transition_scope_chirho(&root_chirho, |fence_chirho| {
        let candidates_chirho = vec![
            synthetic_prepared_chirho(fence_chirho, &None, &left_chirho, 0, b"left op"),
            synthetic_prepared_chirho(fence_chirho, &None, &right_chirho, 1, b"right op"),
        ];
        assert!(pending_head_transition_index_unlocked_chirho(
            &root_chirho,
            &None,
            &candidates_chirho
        )
        .unwrap_err()
        .to_string()
        .contains("multiple unapplied"));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        current_head_chirho(&root_chirho, "synthetic/app-chirho"),
        None
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn concurrent_positive_head_scopes_serialize_into_one_ordered_chain_chirho() {
    let root_chirho = Arc::new(temp_root_chirho("concurrent-chain"));
    provision_signer_chirho(root_chirho.as_ref());
    let left_chirho = cas_chirho::add_chirho(root_chirho.as_ref(), b"left chain value").unwrap();
    let right_chirho = cas_chirho::add_chirho(root_chirho.as_ref(), b"right chain value").unwrap();
    let barrier_chirho = Arc::new(Barrier::new(2));
    let mut handles_chirho = Vec::new();
    for (family_seq_chirho, next_chirho) in [(0_u64, left_chirho), (1_u64, right_chirho)] {
        let root_chirho = Arc::clone(&root_chirho);
        let barrier_chirho = Arc::clone(&barrier_chirho);
        handles_chirho.push(std::thread::spawn(move || {
            barrier_chirho.wait();
            with_head_transition_scope_chirho(root_chirho.as_ref(), |fence_chirho| {
                let previous_chirho =
                    current_head_chirho(root_chirho.as_ref(), "synthetic/app-chirho");
                let prepared_chirho = synthetic_prepared_chirho(
                    fence_chirho,
                    &previous_chirho,
                    &next_chirho,
                    family_seq_chirho,
                    format!("concurrent operation {family_seq_chirho}").as_bytes(),
                );
                complete_head_transition_unlocked_chirho(
                    root_chirho.as_ref(),
                    &prepared_chirho,
                    fence_chirho,
                )
            })
        }));
    }
    for handle_chirho in handles_chirho {
        assert_eq!(
            handle_chirho.join().unwrap().unwrap(),
            HeadTransitionRecoveryOutcomeChirho::AppliedChirho
        );
    }
    let receipts_chirho = refs_chirho::reflog_chirho(root_chirho.as_ref())
        .unwrap()
        .into_iter()
        .filter(|entry_chirho| entry_chirho.schema_chirho == HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO)
        .collect::<Vec<_>>();
    assert_eq!(receipts_chirho.len(), 2);
    assert_eq!(
        receipts_chirho[1].from_chirho,
        Some(receipts_chirho[0].to_chirho.clone())
    );
    assert_eq!(
        current_head_chirho(root_chirho.as_ref(), "synthetic/app-chirho"),
        Some(receipts_chirho[1].to_chirho.clone())
    );
    let _ = std::fs::remove_dir_all(root_chirho.as_ref());
}

#[test]
fn receipt_reconstruction_is_stable_for_one_chosen_applied_epoch_chirho() {
    let root_chirho = temp_root_chirho("stable-receipt");
    provision_signer_chirho(&root_chirho);
    let next_chirho = cas_chirho::add_chirho(&root_chirho, b"stable next").unwrap();
    let (prepared_chirho, _prepared_fence_chirho) =
        prepare_without_apply_chirho(&root_chirho, None, &next_chirho, 0, b"stable operation");
    let chosen_fence_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let left_chirho =
        signed_receipt_chirho(&root_chirho, &prepared_chirho, &chosen_fence_chirho).unwrap();
    let right_chirho =
        signed_receipt_chirho(&root_chirho, &prepared_chirho, &chosen_fence_chirho).unwrap();
    assert_eq!(left_chirho, right_chirho);
    assert_eq!(
        serde_json::to_vec(&left_chirho).unwrap(),
        serde_json::to_vec(&right_chirho).unwrap()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn prepared_fence_identity_stays_byte_stable_for_equal_group_and_epoch_chirho() {
    let root_chirho = temp_root_chirho("prepared-identity");
    let token_chirho =
        issue_elected_writer_fence_for_root_chirho(&root_chirho, 7).expect("issue elected fence");
    let evidence_chirho =
        observe_prepared_fence_lower_bound_chirho(&root_chirho, &token_chirho.group_chirho)
            .expect("observe elected lower bound");
    let next_chirho =
        cas_chirho::add_chirho(&root_chirho, b"prepared identity next").expect("add next object");
    let previous_chirho = None;
    let token_input_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: "synthetic-head-records-chirho.jsonl",
        family_seq_chirho: 3,
        branch_chirho: "synthetic/identity-chirho",
        previous_chirho: &previous_chirho,
        next_chirho: &next_chirho,
        reason_chirho: "identity-stability",
        operation_bytes_chirho: b"same operation bytes",
        prepared_fence_chirho: &token_chirho,
        at_ms_chirho: 42,
    };
    let evidence_input_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: token_input_chirho.family_log_chirho,
        family_seq_chirho: token_input_chirho.family_seq_chirho,
        branch_chirho: token_input_chirho.branch_chirho,
        previous_chirho: token_input_chirho.previous_chirho,
        next_chirho: token_input_chirho.next_chirho,
        reason_chirho: token_input_chirho.reason_chirho,
        operation_bytes_chirho: token_input_chirho.operation_bytes_chirho,
        prepared_fence_chirho: &evidence_chirho,
        at_ms_chirho: token_input_chirho.at_ms_chirho,
    };

    assert_eq!(
        derive_head_transition_id_chirho(&token_input_chirho).expect("derive token identity"),
        derive_head_transition_id_from_prepared_fence_chirho(&evidence_input_chirho)
            .expect("derive evidence identity"),
        "the evidence-accepting input must not fork serialized transition identity"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn later_elected_epoch_may_apply_an_older_prepared_lower_bound_chirho() {
    let root_chirho = temp_root_chirho("prepared-lower-bound");
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 7)
        .expect("issue prepared elected fence");
    let next_chirho =
        cas_chirho::add_chirho(&root_chirho, b"lower-bound next").expect("add next object");
    let prepared_chirho = prepared_from_elected_observation_chirho(&root_chirho, &next_chirho);
    let later_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 8)
        .expect("issue later elected fence");

    preflight_head_transition_commit_chirho(&root_chirho, &prepared_chirho, &later_chirho)
        .expect("a later elected writer may finish an older prepared operation");
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn prepared_root_binding_refuses_path_substitution_before_group_chirho() {
    let root_chirho = temp_root_chirho("prepared-root");
    let other_root_chirho = temp_root_chirho("prepared-other-root");
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 9)
        .expect("issue prepared elected fence");
    let next_chirho =
        cas_chirho::add_chirho(&root_chirho, b"root-bound next").expect("add next object");
    let prepared_chirho = prepared_from_elected_observation_chirho(&root_chirho, &next_chirho);
    std::fs::create_dir_all(&other_root_chirho).expect("create substituted root");
    let applier_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 10)
        .expect("issue current applier fence");

    let error_chirho = preflight_head_transition_commit_chirho(
        &other_root_chirho,
        &prepared_chirho,
        &applier_chirho,
    )
    .expect_err("root substitution must refuse")
    .to_string();

    assert!(error_chirho.contains("HeadTransitionWrongRootChirho"));
    assert!(!error_chirho.contains("HeadTransitionWrongGroupChirho"));
    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(other_root_chirho);
}

#[test]
fn prepared_root_binding_keeps_named_refusal_when_the_path_disappears_chirho() {
    let root_chirho = temp_root_chirho("prepared-missing-root");
    let parked_root_chirho = temp_root_chirho("prepared-parked-root");
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 9)
        .expect("issue prepared elected fence");
    let next_chirho =
        cas_chirho::add_chirho(&root_chirho, b"missing root next").expect("add next object");
    let prepared_chirho = prepared_from_elected_observation_chirho(&root_chirho, &next_chirho);
    let applier_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 10)
        .expect("issue current applier fence");
    std::fs::rename(&root_chirho, &parked_root_chirho)
        .expect("remove the prepared pathname without deleting its inode");

    let error_chirho =
        preflight_head_transition_commit_chirho(&root_chirho, &prepared_chirho, &applier_chirho)
            .expect_err("a missing COMMIT root must retain the wrong-root refusal identity")
            .to_string();

    assert!(error_chirho.contains("HeadTransitionWrongRootChirho"));
    assert!(!error_chirho.contains("HeadTransitionWrongGroupChirho"));
    let _ = std::fs::remove_dir_all(parked_root_chirho);
}
