// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Receipted positive-transition proofs for resource-policy sets: crash windows, receipt-gated
//! reads, latest-event recovery gating, and the pinned legacy v1 read residual.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-policy-transition-ha2-{}-{}-{counter_chirho}",
        now_ms_chirho(),
        std::process::id()
    ))
}

fn deploy_owned_app_chirho(root_chirho: &Path, app_chirho: &str) -> String {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho =
        crate::cas_chirho::add_chirho(root_chirho, b"policy transition ha2 marker").unwrap();
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(root_chirho, app_chirho, dag_chirho, &owner_chirho).unwrap();
    owner_chirho
}

fn demo_meters_chirho(per_user_limit_chirho: i64) -> Vec<ResourceMeterChirho> {
    vec![ResourceMeterChirho {
        resource_chirho: "labs_credit_chirho".to_string(),
        unit_chirho: "credit".to_string(),
        stack_chirho: None,
        per_user_limit_chirho: Some(per_user_limit_chirho),
        app_limit_chirho: None,
        window_ms_chirho: None,
        overage_chirho: ResourceOverageChirho::FailClosedChirho,
    }]
}

fn demo_actions_chirho() -> Vec<ResourceActionPolicyChirho> {
    vec![ResourceActionPolicyChirho {
        section_chirho: "builder".to_string(),
        action_chirho: "submit".to_string(),
        effect_chirho: None,
        allow_anonymous_chirho: false,
        charges_chirho: vec![ResourceChargeChirho {
            resource_chirho: "labs_credit_chirho".to_string(),
            amount_chirho: 1,
        }],
    }]
}

fn branch_head_chirho(root_chirho: &Path, app_chirho: &str) -> Option<HashChirho> {
    refs_chirho::load_refs_chirho(root_chirho)
        .unwrap()
        .branches_chirho
        .get(&resource_policy_ref_chirho(app_chirho))
        .cloned()
}

/// Crash-shaped fixture: append the signed v2 record (old road + gate1 envelope) and stop before
/// the head transition completes — production's exact window between record append and completion.
fn torn_set_without_completion_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    per_user_limit_chirho: i64,
) -> (HashChirho, ResourcePolicyRecordChirho) {
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |writer_fence_chirho| {
        let previous_chirho = branch_head_chirho(root_chirho, app_chirho);
        let policy_chirho = resource_policy_chirho::propose_resource_policy_chirho(
            app_chirho,
            owner_chirho,
            demo_meters_chirho(per_user_limit_chirho),
            demo_actions_chirho(),
            previous_chirho.clone(),
            now_ms_chirho(),
        )?;
        let hash_chirho = store_chirho::put_object_chirho(root_chirho, &policy_chirho)?;
        let record_chirho = gate1_authority_chirho::append_resource_policy_record_unlocked_chirho(
            root_chirho,
            writer_fence_chirho,
            app_chirho,
            owner_chirho,
            hash_chirho.clone(),
            previous_chirho,
            0,
        )?;
        Ok((hash_chirho, record_chirho))
    })
    .unwrap()
}

/// Build a pending v2 transition and return its prepared record plus the fence that prepared it,
/// so a later writer can advance the epoch and the stale preparer can be proven unable to complete.
fn pending_transition_with_fence_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> (
    cairn_writer_head_chirho::head_transition_chirho::PreparedHeadTransitionChirho,
    writer_head_chirho::WriterFenceTokenChirho,
) {
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |writer_fence_chirho| {
        let policy_chirho = resource_policy_chirho::propose_resource_policy_chirho(
            app_chirho,
            owner_chirho,
            demo_meters_chirho(3),
            demo_actions_chirho(),
            None,
            now_ms_chirho(),
        )?;
        let hash_chirho = store_chirho::put_object_chirho(root_chirho, &policy_chirho)?;
        let record_chirho = gate1_authority_chirho::append_resource_policy_record_unlocked_chirho(
            root_chirho,
            writer_fence_chirho,
            app_chirho,
            owner_chirho,
            hash_chirho,
            None,
            0,
        )?;
        let prepared_chirho =
            policy_head_transition_chirho::prepared_from_verified_policy_record_chirho(
                root_chirho,
                &record_chirho,
            )?;
        Ok((prepared_chirho, writer_fence_chirho.clone()))
    })
    .unwrap()
}

#[test]
fn resource_policy_stale_preparer_cannot_complete_after_recovery_chirho() {
    // P0 item 7 (zombie-writer proof) for the newly-adopted resource-policy transition: a preparer
    // that captured fence epoch N cannot complete the head after a later writer issued epoch N+1.
    // Mirrors the billing/pricebook/onboarding zombie proofs; the fence is validated at the shared
    // transition sink, this pins it for resource policy and proves refs/reflog stay untouched.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "zombieres");
    let (prepared_chirho, stale_fence_chirho) =
        pending_transition_with_fence_chirho(&root_chirho, "zombieres", &owner_chirho);
    // A later writer scope issues a newer fence epoch AND completes the pending transition.
    with_resource_policy_authority_scope_chirho(&root_chirho, "zombieres", |writer_fence_chirho| {
        policy_head_transition_chirho::recover_resource_policy_head_transition_unlocked_chirho(
            &root_chirho,
            "zombieres",
            writer_fence_chirho,
        )
    })
    .unwrap();
    let refs_before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();
    let reflog_before_chirho =
        std::fs::read(refs_chirho::reflog_path_chirho(&root_chirho)).unwrap();
    let error_chirho = seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            &root_chirho,
            &prepared_chirho,
            &stale_fence_chirho,
        )
    })
    .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("StaleWriterFenceChirho"),
        "a stale preparer must be rejected at the transition sink: {error_chirho:#}"
    );
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho,
        "the rejected zombie writer must not move any ref"
    );
    assert_eq!(
        std::fs::read(refs_chirho::reflog_path_chirho(&root_chirho)).unwrap(),
        reflog_before_chirho,
        "the rejected zombie writer must not append a reflog row"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn set_completes_with_applied_receipt_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "receiptset");
    let (hash_chirho, _, record_chirho) = set_resource_policy_chirho(
        &root_chirho,
        "receiptset",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    assert_eq!(
        record_chirho.schema_chirho,
        RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO
    );
    assert!(record_chirho.prepared_writer_fence_epoch_chirho.is_some());
    assert!(!record_chirho.transition_id_chirho.is_empty());
    let prepared_chirho =
        policy_head_transition_chirho::prepared_from_verified_policy_record_chirho(
            &root_chirho,
            &record_chirho,
        )
        .unwrap();
    assert!(
        head_transition_chirho::verified_head_transition_receipt_chirho(
            &root_chirho,
            &prepared_chirho,
        )
        .unwrap()
    );
    assert_eq!(
        branch_head_chirho(&root_chirho, "receiptset"),
        Some(hash_chirho.clone())
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "receiptset").unwrap(),
        Some(hash_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn torn_set_read_fails_closed_and_retry_set_completes_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "tornset");
    let (torn_hash_chirho, torn_record_chirho) =
        torn_set_without_completion_chirho(&root_chirho, "tornset", &owner_chirho, 3);
    assert_eq!(branch_head_chirho(&root_chirho, "tornset"), None);
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "tornset")
            .unwrap_err()
            .to_string()
            .contains("refusing to read unreceipted absence"),
        "a torn first set must fail reads closed, not read as no-limits"
    );
    let (second_hash_chirho, _, second_record_chirho) = set_resource_policy_chirho(
        &root_chirho,
        "tornset",
        &owner_chirho,
        demo_meters_chirho(9),
        demo_actions_chirho(),
    )
    .unwrap();
    assert_eq!(
        second_record_chirho.seq_chirho,
        torn_record_chirho.seq_chirho + 1
    );
    assert_eq!(
        second_record_chirho.previous_chirho,
        Some(torn_hash_chirho.clone()),
        "the retry set must recover-complete the torn transition before deriving previous"
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "tornset").unwrap(),
        Some(second_hash_chirho)
    );
    for record_chirho in load_resource_policy_records_chirho(&root_chirho).unwrap() {
        let prepared_chirho =
            policy_head_transition_chirho::prepared_from_verified_policy_record_chirho(
                &root_chirho,
                &record_chirho,
            )
            .unwrap();
        assert!(
            head_transition_chirho::verified_head_transition_receipt_chirho(
                &root_chirho,
                &prepared_chirho,
            )
            .unwrap()
        );
    }
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn unset_after_torn_set_recovers_positive_first_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "tornunset");
    set_resource_policy_chirho(
        &root_chirho,
        "tornunset",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let (torn_hash_chirho, _) =
        torn_set_without_completion_chirho(&root_chirho, "tornunset", &owner_chirho, 7);
    std::thread::sleep(std::time::Duration::from_millis(2));
    let unset_chirho = unset_resource_policy_chirho(&root_chirho, "tornunset", &owner_chirho)
        .unwrap()
        .expect("unset after torn set must settle the recovered head");
    assert_eq!(
        unset_chirho.previous_chirho, torn_hash_chirho,
        "the unset must remove the recovered torn head, not the stale earlier head"
    );
    assert_eq!(branch_head_chirho(&root_chirho, "tornunset"), None);
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "tornunset").unwrap(),
        None
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn unrecorded_policy_head_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "forgedset");
    set_resource_policy_chirho(
        &root_chirho,
        "forgedset",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    let forged_chirho = crate::cas_chirho::add_chirho(&root_chirho, b"forged-policy-head").unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &resource_policy_ref_chirho("forgedset"),
        forged_chirho,
    )
    .unwrap();
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "forgedset")
            .unwrap_err()
            .to_string()
            .contains("does not match the verified latest set event"),
        "a raw head with no selecting signed record must fail closed"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn resurrected_head_after_receipted_unset_fails_closed_chirho() {
    // Re-audit BLOCKER: after a receipted unset removes the ref, a no-key adversary who re-creates
    // the ref pointing at the old (still receipted) policy must NOT resurrect it — the app's verified
    // latest event is the unset, not a set, so the read gate fails closed and metered usage stays
    // revoked. This is where resource must be stricter than billing (billing has no unset protocol).
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resurrect");
    let (policy_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "resurrect",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    unset_resource_policy_chirho(&root_chirho, "resurrect", &owner_chirho)
        .unwrap()
        .expect("receipted unset removes the ref");
    assert_eq!(branch_head_chirho(&root_chirho, "resurrect"), None);
    // Adversary re-creates the ref at the old receipted policy head (no signing key needed).
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &resource_policy_ref_chirho("resurrect"),
        policy_hash_chirho,
    )
    .unwrap();
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "resurrect")
            .unwrap_err()
            .to_string()
            .contains("does not match the verified latest set event"),
        "a policy resurrected after a receipted unset must fail closed, not re-authorize usage"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn resource_status_fails_closed_on_resurrected_head_chirho() {
    // Re-audit finding 18: resource-status once rendered limit/usage rows from raw policy refs
    // without the verified gate. It now routes through current_resource_policy_chirho, so a policy
    // resurrected after a receipted unset fails the status listing closed instead of displaying a
    // revoked policy's balances.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "statusresurrect");
    let (policy_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "statusresurrect",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    // A legit current policy lists without error (row count depends on meter/usage shape).
    resource_status_chirho(&root_chirho, Some("statusresurrect"), None).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    unset_resource_policy_chirho(&root_chirho, "statusresurrect", &owner_chirho)
        .unwrap()
        .expect("receipted unset");
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &resource_policy_ref_chirho("statusresurrect"),
        policy_hash_chirho,
    )
    .unwrap();
    assert!(
        resource_status_chirho(&root_chirho, Some("statusresurrect"), None)
            .unwrap_err()
            .to_string()
            .contains("does not match the verified latest set event"),
        "status must fail closed on a resurrected ref, not display a revoked policy's balances"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn set_at_ms_floor_keeps_set_after_unset_current_chirho() {
    // Re-audit finding 17: a set whose wall-clock at_ms lands at or below the latest unset's at_ms
    // must still rank as the latest event (the floor bumps it strictly above), so the just-completed
    // set reads current instead of wedging behind the prior unset. Tight loop, no sleeps, so the
    // set/unset at_ms collide on the same millisecond and only the floor separates them.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "floorset");
    for round_chirho in 0..12 {
        let (set_hash_chirho, _, _) = set_resource_policy_chirho(
            &root_chirho,
            "floorset",
            &owner_chirho,
            demo_meters_chirho(round_chirho + 1),
            demo_actions_chirho(),
        )
        .unwrap();
        assert_eq!(
            current_resource_policy_hash_chirho(&root_chirho, "floorset").unwrap(),
            Some(set_hash_chirho),
            "round {round_chirho}: the just-set policy must read current, not wedge behind a same-ms unset"
        );
        unset_resource_policy_chirho(&root_chirho, "floorset", &owner_chirho)
            .unwrap()
            .expect("receipted unset");
        assert!(
            current_resource_policy_hash_chirho(&root_chirho, "floorset")
                .unwrap()
                .is_none(),
            "round {round_chirho}: after the receipted unset the policy must read absent (None)"
        );
    }
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn set_record_at_ms_strictly_exceeds_latest_unset_chirho() {
    // Pin the floor layer directly, independent of the cross-log tie rule (which alone would mask a
    // regressed floor): a fresh set's record at_ms must be strictly greater than the latest unset's,
    // in a no-sleep loop where the wall clock ties.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "floorunit");
    for round_chirho in 0..8 {
        set_resource_policy_chirho(
            &root_chirho,
            "floorunit",
            &owner_chirho,
            demo_meters_chirho(round_chirho + 1),
            demo_actions_chirho(),
        )
        .unwrap();
        let unset_chirho = unset_resource_policy_chirho(&root_chirho, "floorunit", &owner_chirho)
            .unwrap()
            .expect("receipted unset");
        let (set_hash_chirho, _, set_record_chirho) = set_resource_policy_chirho(
            &root_chirho,
            "floorunit",
            &owner_chirho,
            demo_meters_chirho(round_chirho + 100),
            demo_actions_chirho(),
        )
        .unwrap();
        assert!(
            set_record_chirho.at_ms_chirho > unset_chirho.at_ms_chirho,
            "round {round_chirho}: set at_ms {} must strictly exceed latest unset at_ms {}",
            set_record_chirho.at_ms_chirho,
            unset_chirho.at_ms_chirho
        );
        assert_eq!(
            current_resource_policy_hash_chirho(&root_chirho, "floorunit").unwrap(),
            Some(set_hash_chirho)
        );
    }
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn raw_rollback_to_superseded_set_fails_closed_chirho() {
    // Re-audit verify follow-up: a raw ref rollback to an older still-receipted set (no later unset)
    // must fail closed — that older head is not the verified latest set event. Resource is stricter
    // than billing here on purpose; a policy change must go through a new signed set, not a raw ref
    // move. Pins the latest-event guard against a surgical set-selection regression.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "rollbackset");
    let (old_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "rollbackset",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let (new_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "rollbackset",
        &owner_chirho,
        demo_meters_chirho(9),
        demo_actions_chirho(),
    )
    .unwrap();
    assert_ne!(old_hash_chirho, new_hash_chirho);
    // Raw-roll the ref back to the older set head (no signed set event moves the latest event).
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &resource_policy_ref_chirho("rollbackset"),
        old_hash_chirho,
    )
    .unwrap();
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "rollbackset")
            .unwrap_err()
            .to_string()
            .contains("does not match the verified latest set event"),
        "a raw rollback to a superseded set must fail closed; policy changes go through signed sets"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn v2_selected_head_without_receipt_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "noreceipt");
    let (torn_hash_chirho, _) =
        torn_set_without_completion_chirho(&root_chirho, "noreceipt", &owner_chirho, 3);
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &resource_policy_ref_chirho("noreceipt"),
        torn_hash_chirho,
    )
    .unwrap();
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "noreceipt")
            .unwrap_err()
            .to_string()
            .contains("no valid Applied receipt"),
        "a v2-selected head without its Applied receipt must fail closed"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn torn_unset_log_tail_self_heals_on_next_write_chirho() {
    // Re-audit finding 6: unconditional positive recovery reads the unset family log through the
    // strict typed loader, so a crash-torn unset-log tail must be repaired first or every retry
    // fails to parse. Pin that the next write recovers the torn tail instead of wedging.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "tornunsetlog");
    set_resource_policy_chirho(
        &root_chirho,
        "tornunsetlog",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    // Simulate a crash mid-write of an unset family line: a partial, unterminated tail.
    let unset_log_chirho = root_chirho.join("resource-policy-unset-records-chirho.jsonl");
    std::fs::write(
        &unset_log_chirho,
        b"{\"seq_chirho\":0,\"app_chirho\":\"torn",
    )
    .unwrap();
    // The next write must recover the torn tail (trim it) before the strict loader runs, not error.
    let (second_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "tornunsetlog",
        &owner_chirho,
        demo_meters_chirho(9),
        demo_actions_chirho(),
    )
    .unwrap();
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "tornunsetlog").unwrap(),
        Some(second_hash_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn torn_completion_window_recovers_on_next_write_chirho() {
    // The adversarial-fleet BLOCKER: a crash after the ref durably moves to the new head but before
    // the Applied receipt is appended leaves head==record-hash with no receipt. A parse-only probe
    // false-negatives there (head equals the latest record), so recovery must run UNCONDITIONALLY
    // on the next write — this pins that it does and un-wedges the app.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "tornmid");
    let (torn_hash_chirho, torn_record_chirho) =
        torn_set_without_completion_chirho(&root_chirho, "tornmid", &owner_chirho, 3);
    // Simulate the crash window: the ref reached the new head but the receipt was never appended.
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &resource_policy_ref_chirho("tornmid"),
        torn_hash_chirho.clone(),
    )
    .unwrap();
    assert!(
        current_resource_policy_hash_chirho(&root_chirho, "tornmid")
            .unwrap_err()
            .to_string()
            .contains("no valid Applied receipt"),
        "the torn-completion state must read fail-closed before recovery"
    );
    // The next honest write must recover the pending completion first, then proceed — no wedge.
    let (second_hash_chirho, _, second_record_chirho) = set_resource_policy_chirho(
        &root_chirho,
        "tornmid",
        &owner_chirho,
        demo_meters_chirho(9),
        demo_actions_chirho(),
    )
    .unwrap();
    assert_eq!(
        second_record_chirho.previous_chirho,
        Some(torn_hash_chirho.clone())
    );
    assert_eq!(
        second_record_chirho.seq_chirho,
        torn_record_chirho.seq_chirho + 1
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "tornmid").unwrap(),
        Some(second_hash_chirho)
    );
    for record_chirho in load_resource_policy_records_chirho(&root_chirho).unwrap() {
        let prepared_chirho =
            policy_head_transition_chirho::prepared_from_verified_policy_record_chirho(
                &root_chirho,
                &record_chirho,
            )
            .unwrap();
        assert!(
            head_transition_chirho::verified_head_transition_receipt_chirho(
                &root_chirho,
                &prepared_chirho,
            )
            .unwrap(),
            "both the recovered torn transition and the new set must carry Applied receipts"
        );
    }
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn receipted_unset_never_recompleted_by_stale_positive_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "staleset");
    set_resource_policy_chirho(
        &root_chirho,
        "staleset",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    unset_resource_policy_chirho(&root_chirho, "staleset", &owner_chirho)
        .unwrap()
        .expect("receipted unset");
    // Unconditional recovery runs on every write now; on a receipted-unset-latest store it must
    // find no pending positive to complete — the stale earlier set must never re-complete.
    let outcome_chirho = with_resource_policy_authority_scope_chirho(
        &root_chirho,
        "staleset",
        |writer_fence_chirho| {
            policy_head_transition_chirho::recover_resource_policy_head_transition_unlocked_chirho(
                &root_chirho,
                "staleset",
                writer_fence_chirho,
            )
        },
    )
    .unwrap();
    assert!(
        outcome_chirho.is_none(),
        "a receipted unset is the latest event; the stale set must never re-complete"
    );
    assert_eq!(branch_head_chirho(&root_chirho, "staleset"), None);
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "staleset").unwrap(),
        None
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn legacy_v1_head_reads_without_receipt_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "legacyread");
    let policy_chirho = resource_policy_chirho::propose_resource_policy_chirho(
        "legacyread",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
        None,
        now_ms_chirho(),
    )
    .unwrap();
    let hash_chirho = store_chirho::put_object_chirho(&root_chirho, &policy_chirho).unwrap();
    with_resource_policy_authority_scope_chirho(&root_chirho, "legacyread", |_fence_chirho| {
        seqlog_chirho::append_serialized_jsonl_unlocked_chirho(
            &policy_records_path_chirho(&root_chirho),
            |seq_chirho| {
                let mut record_chirho = ResourcePolicyRecordChirho {
                    seq_chirho,
                    schema_chirho: RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
                    app_chirho: "legacyread".to_string(),
                    owner_principal_chirho: owner_chirho.clone(),
                    resource_policy_chirho: hash_chirho.clone(),
                    previous_chirho: None,
                    at_ms_chirho: now_ms_chirho(),
                    transition_id_chirho: String::new(),
                    prepared_writer_fence_epoch_chirho: None,
                    sig_chirho: String::new(),
                };
                let message_chirho = resource_policy_record_message_chirho(&record_chirho)?;
                record_chirho.sig_chirho =
                    signer_chirho::sign_message_chirho(&root_chirho, &message_chirho)?;
                Ok(record_chirho)
            },
        )?;
        refs_chirho::set_branch_chirho(
            &root_chirho,
            &resource_policy_ref_chirho("legacyread"),
            hash_chirho.clone(),
        )
    })
    .unwrap();
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "legacyread").unwrap(),
        Some(hash_chirho),
        "a v1-era selecting row keeps today's legacy read cost until the watermark arc"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
