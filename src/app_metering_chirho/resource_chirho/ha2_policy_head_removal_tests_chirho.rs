// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! HA2 Brick D proofs: last-event current-policy semantics and receipted policy removals.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-policy-removal-ha2-{}-{}-{counter_chirho}",
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
        crate::cas_chirho::add_chirho(root_chirho, b"policy removal ha2 marker").unwrap();
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

fn separate_event_clock_chirho() {
    std::thread::sleep(Duration::from_millis(2));
}

/// Fixture-only v1-era policy row appender: production writes only v2 rows now, so legacy
/// last-event coverage hand-builds the v1 shape it exercises.
fn append_v1_policy_record_old_road_for_test_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    policy_hash_chirho: HashChirho,
    previous_chirho: Option<HashChirho>,
) -> Result<ResourcePolicyRecordChirho> {
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(
        &policy_records_path_chirho(root_chirho),
        |seq_chirho| {
            let mut record_chirho = ResourcePolicyRecordChirho {
                seq_chirho,
                schema_chirho: RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
                app_chirho: app_chirho.to_string(),
                owner_principal_chirho: owner_chirho.to_string(),
                resource_policy_chirho: policy_hash_chirho.clone(),
                previous_chirho: previous_chirho.clone(),
                at_ms_chirho: now_ms_chirho(),
                transition_id_chirho: String::new(),
                prepared_writer_fence_epoch_chirho: None,
                sig_chirho: String::new(),
            };
            let message_chirho = resource_policy_record_message_chirho(&record_chirho)?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
            Ok(record_chirho)
        },
    )
}

fn branch_head_chirho(root_chirho: &Path, app_chirho: &str) -> Option<HashChirho> {
    refs_chirho::load_refs_chirho(root_chirho)
        .unwrap()
        .branches_chirho
        .get(&resource_policy_ref_chirho(app_chirho))
        .cloned()
}

#[test]
fn unset_clears_superseded_policy_chain_chirho() {
    // RETARGETED AT WAVE-1, the second retarget for this arm, and it is a MOVE rather than a
    // deletion on purpose. It used to flip the root and pin the ACTIVE road's property. Wave-1
    // deleted that road -- but the two roads always shared one projection and differed only in
    // where the records came from, so the property survives and only its SOURCE changed. Deleting
    // the arm with the road would have dropped a live pin on the surviving road.
    //
    // If this goes red: the projection changed, not the road. The road is already gone.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "chainapp");

    let (first_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "chainapp",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    separate_event_clock_chirho();
    let (second_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "chainapp",
        &owner_chirho,
        demo_meters_chirho(5),
        demo_actions_chirho(),
    )
    .unwrap();
    assert_ne!(first_hash_chirho, second_hash_chirho);
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "chainapp").unwrap(),
        Some(second_hash_chirho.clone()),
        "the read must select the latest set, not the earliest unmasked one"
    );

    separate_event_clock_chirho();
    assert!(
        unset_resource_policy_chirho(&root_chirho, "chainapp", &owner_chirho)
            .unwrap()
            .is_some()
    );
    assert_eq!(branch_head_chirho(&root_chirho, "chainapp"), None);
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "chainapp").unwrap(),
        None,
        "an unset must clear the whole policy chain, not just the exact hash"
    );
}

#[test]
fn reset_same_hash_restores_metering_chirho() {
    // RETARGETED AT WAVE-1, the second retarget for this arm, and it is a MOVE rather than a
    // deletion on purpose. It used to flip the root and pin the ACTIVE road's property. Wave-1
    // deleted that road -- but the two roads always shared one projection and differed only in
    // where the records came from, so the property survives and only its SOURCE changed. Deleting
    // the arm with the road would have dropped a live pin on the surviving road.
    //
    // If this goes red: the projection changed, not the road. The road is already gone.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resetapp");

    let input_chirho = || ResourcePolicyInputChirho {
        meters_chirho: demo_meters_chirho(3),
        actions_chirho: demo_actions_chirho(),
    };
    let policy_at_ms_chirho = 1_234_567;
    let (previewed_chirho, _) = preview_resource_policy_from_input_chirho(
        &root_chirho,
        "resetapp",
        &owner_chirho,
        input_chirho(),
        policy_at_ms_chirho,
    )
    .unwrap();
    let (first_hash_chirho, _, _) = set_resource_policy_from_input_checked_chirho(
        &root_chirho,
        "resetapp",
        &owner_chirho,
        input_chirho(),
        None,
        previewed_chirho.clone(),
        policy_at_ms_chirho,
    )
    .unwrap();
    assert_eq!(first_hash_chirho, previewed_chirho);

    separate_event_clock_chirho();
    assert!(
        unset_resource_policy_chirho(&root_chirho, "resetapp", &owner_chirho)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "resetapp").unwrap(),
        None
    );

    separate_event_clock_chirho();
    let (reset_hash_chirho, _, _) = set_resource_policy_from_input_checked_chirho(
        &root_chirho,
        "resetapp",
        &owner_chirho,
        input_chirho(),
        None,
        previewed_chirho.clone(),
        policy_at_ms_chirho,
    )
    .unwrap();
    assert_eq!(
        reset_hash_chirho, first_hash_chirho,
        "re-applying the identical reviewed policy must reuse the content-addressed hash"
    );
    assert_eq!(
        branch_head_chirho(&root_chirho, "resetapp"),
        Some(first_hash_chirho.clone())
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "resetapp").unwrap(),
        Some(first_hash_chirho.clone()),
        "a re-set of the same policy hash must turn the gate back on"
    );

    separate_event_clock_chirho();
    let second_unset_chirho = unset_resource_policy_chirho(&root_chirho, "resetapp", &owner_chirho)
        .unwrap()
        .expect("second unset must append a fresh signed unset event");
    assert_eq!(
        second_unset_chirho.seq_chirho, 1,
        "a repeat unset must record a new domain event instead of resurrecting stale evidence"
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "resetapp").unwrap(),
        None,
        "unsetting the re-set policy must clear it again"
    );
    assert_eq!(branch_head_chirho(&root_chirho, "resetapp"), None);
}

#[test]
fn crashed_domain_row_retry_completes_without_duplicate_unset_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "domaincrash");
    set_resource_policy_chirho(
        &root_chirho,
        "domaincrash",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    separate_event_clock_chirho();
    head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        head_removal_chirho::HeadRemovalStepChirho::AfterDomainRecordChirho,
    );
    assert!(
        unset_resource_policy_chirho(&root_chirho, "domaincrash", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    assert_eq!(
        load_resource_policy_unset_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert!(branch_head_chirho(&root_chirho, "domaincrash").is_some());

    let recovered_chirho = unset_resource_policy_chirho(&root_chirho, "domaincrash", &owner_chirho)
        .unwrap()
        .expect("the retry must complete the crashed unset");
    assert_eq!(recovered_chirho.seq_chirho, 0);
    assert_eq!(
        load_resource_policy_unset_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1,
        "the retry must reuse the crashed domain row instead of double-appending"
    );
    assert_eq!(branch_head_chirho(&root_chirho, "domaincrash"), None);
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "domaincrash").unwrap(),
        None
    );
    assert_eq!(
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap()
        .len(),
        2
    );
}

#[test]
fn crashed_after_branch_remove_retry_reads_honest_none_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "removecrash");
    set_resource_policy_chirho(
        &root_chirho,
        "removecrash",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    separate_event_clock_chirho();
    head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        head_removal_chirho::HeadRemovalStepChirho::AfterBranchRemoveChirho,
    );
    assert!(
        unset_resource_policy_chirho(&root_chirho, "removecrash", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    assert_eq!(branch_head_chirho(&root_chirho, "removecrash"), None);

    assert!(
        unset_resource_policy_chirho(&root_chirho, "removecrash", &owner_chirho)
            .unwrap()
            .is_none(),
        "a settled removal retry must report honest receipted absence"
    );
    assert_eq!(
        load_resource_policy_unset_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap()
        .len(),
        2,
        "a settled retry must not append duplicate removal evidence"
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "removecrash").unwrap(),
        None
    );
}

#[test]
fn unset_record_at_ms_floors_above_latest_set_event_chirho() {
    let root_chirho = tmp_root_chirho();
    let _ = deploy_owned_app_chirho(&root_chirho, "floorapp");
    let future_ms_chirho = now_ms_chirho() + 60_000;
    let record_chirho = resource_policy_unset_record_for_seq_chirho(
        0,
        "floorapp",
        "owner/floor",
        HashChirho("f".repeat(64)),
        &root_chirho,
        future_ms_chirho,
    )
    .unwrap();
    assert_eq!(
        record_chirho.at_ms_chirho, future_ms_chirho,
        "a fresh unset row must stamp at least the floor so it strictly out-orders the set"
    );
}

#[test]
fn unset_immediately_after_set_stays_receipted_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "tightloop");
    for round_chirho in 0..20 {
        set_resource_policy_chirho(
            &root_chirho,
            "tightloop",
            &owner_chirho,
            demo_meters_chirho(3),
            demo_actions_chirho(),
        )
        .unwrap();
        let unset_chirho = unset_resource_policy_chirho(&root_chirho, "tightloop", &owner_chirho)
            .unwrap()
            .unwrap_or_else(|| {
                panic!("round {round_chirho}: immediate unset must append a fresh event")
            });
        assert_eq!(unset_chirho.seq_chirho, round_chirho);
        assert_eq!(
            current_resource_policy_hash_chirho(&root_chirho, "tightloop").unwrap(),
            None,
            "round {round_chirho}: a same-millisecond set/unset pair must never leave a \
             completed receipted removal reading as still set"
        );
    }
}

#[test]
fn unreceipted_branch_absence_fails_closed_everywhere_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "tamperabsent");
    set_resource_policy_chirho(
        &root_chirho,
        "tamperabsent",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    assert!(refs_chirho::remove_branch_chirho(
        &root_chirho,
        &resource_policy_ref_chirho("tamperabsent")
    )
    .unwrap());

    let read_error_chirho = current_resource_policy_hash_chirho(&root_chirho, "tamperabsent")
        .unwrap_err()
        .to_string();
    assert!(read_error_chirho.contains("absent without removal evidence"));
    let unset_error_chirho =
        unset_resource_policy_chirho(&root_chirho, "tamperabsent", &owner_chirho)
            .unwrap_err()
            .to_string();
    assert!(unset_error_chirho.contains("absent without removal evidence"));
    assert!(load_resource_policy_unset_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    let usage_error_chirho = record_resource_usage_chirho(
        &root_chirho,
        ResourceUsageInputChirho {
            app_chirho: "tamperabsent".to_string(),
            user_chirho: "user/tamper".to_string(),
            actor_chirho: None,
            section_chirho: "builder".to_string(),
            action_chirho: "submit".to_string(),
            effect_chirho: None,
            run_chirho: None,
            bridges_chirho: Vec::new(),
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        usage_error_chirho.contains("absent without removal evidence"),
        "usage metering must fail closed rather than read tampered absence as no limits"
    );
}

#[test]
fn forged_branch_target_fails_closed_before_domain_append_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "forgedhead");
    set_resource_policy_chirho(
        &root_chirho,
        "forgedhead",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    let forged_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, b"forged resource policy head").unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &resource_policy_ref_chirho("forgedhead"),
        forged_chirho.clone(),
    )
    .unwrap();

    let error_chirho = unset_resource_policy_chirho(&root_chirho, "forgedhead", &owner_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("not exact verified set history"));
    assert!(
        load_resource_policy_unset_records_chirho(&root_chirho)
            .unwrap()
            .is_empty(),
        "a forged head must not mint a domain unset row"
    );
    assert!(
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        branch_head_chirho(&root_chirho, "forgedhead"),
        Some(forged_chirho)
    );
}

#[test]
fn stale_domain_only_unset_cannot_delete_later_set_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "stalemint");
    let (policy_hash_chirho, _, _) = set_resource_policy_chirho(
        &root_chirho,
        "stalemint",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    separate_event_clock_chirho();
    head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        head_removal_chirho::HeadRemovalStepChirho::AfterDomainRecordChirho,
    );
    assert!(
        unset_resource_policy_chirho(&root_chirho, "stalemint", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    separate_event_clock_chirho();
    append_v1_policy_record_old_road_for_test_chirho(
        &root_chirho,
        "stalemint",
        &owner_chirho,
        policy_hash_chirho.clone(),
        None,
    )
    .unwrap();

    assert!(
        recover_resource_policy_head_removal_chirho(&root_chirho, "stalemint")
            .unwrap()
            .is_none(),
        "a set recorded after the unset must make the stale domain-only mint refuse"
    );
    assert_eq!(
        branch_head_chirho(&root_chirho, "stalemint"),
        Some(policy_hash_chirho),
        "the stale unset must not delete the later set's head"
    );
    assert!(
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn set_recovers_crashed_unset_before_deriving_previous_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "interlock");
    set_resource_policy_chirho(
        &root_chirho,
        "interlock",
        &owner_chirho,
        demo_meters_chirho(3),
        demo_actions_chirho(),
    )
    .unwrap();
    separate_event_clock_chirho();
    head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        head_removal_chirho::HeadRemovalStepChirho::AfterDomainRecordChirho,
    );
    assert!(
        unset_resource_policy_chirho(&root_chirho, "interlock", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    separate_event_clock_chirho();

    let (second_hash_chirho, _, second_record_chirho) = set_resource_policy_chirho(
        &root_chirho,
        "interlock",
        &owner_chirho,
        demo_meters_chirho(7),
        demo_actions_chirho(),
    )
    .unwrap();
    assert_eq!(
        second_record_chirho.previous_chirho, None,
        "the set must recover the crashed unset first and chain from the cleared state"
    );
    assert_eq!(
        branch_head_chirho(&root_chirho, "interlock"),
        Some(second_hash_chirho.clone())
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "interlock").unwrap(),
        Some(second_hash_chirho)
    );
    assert_eq!(
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap()
        .len(),
        2,
        "the crashed unset must settle as Prepared plus Applied before the new set"
    );
}

#[test]
fn legacy_v1_pending_completes_byte_identical_and_stale_v1_never_resurrects_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "legacyv1");
    let input_chirho = || ResourcePolicyInputChirho {
        meters_chirho: demo_meters_chirho(3),
        actions_chirho: demo_actions_chirho(),
    };
    let policy_at_ms_chirho = 7_654_321;
    let (previewed_chirho, _) = preview_resource_policy_from_input_chirho(
        &root_chirho,
        "legacyv1",
        &owner_chirho,
        input_chirho(),
        policy_at_ms_chirho,
    )
    .unwrap();
    let (policy_hash_chirho, _, _) = set_resource_policy_from_input_checked_chirho(
        &root_chirho,
        "legacyv1",
        &owner_chirho,
        input_chirho(),
        None,
        previewed_chirho.clone(),
        policy_at_ms_chirho,
    )
    .unwrap();
    separate_event_clock_chirho();
    let unset_chirho = append_resource_policy_unset_record_old_road_unlocked_chirho(
        &root_chirho,
        "legacyv1",
        &owner_chirho,
        policy_hash_chirho.clone(),
        0,
    )
    .unwrap();
    head_removal_chirho::append_head_removal_record_unlocked_chirho(
        &root_chirho,
        head_removal_chirho::HeadRemovalEvidenceInputChirho {
            branch_chirho: &resource_policy_ref_chirho("legacyv1"),
            from_chirho: &policy_hash_chirho,
            kind_chirho: head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho,
            app_chirho: "legacyv1",
            route_chirho: None,
            owner_principal_chirho: &owner_chirho,
            domain_log_chirho: RESOURCE_POLICY_UNSET_RECORDS_LOG_CHIRHO,
            domain_seq_chirho: unset_chirho.seq_chirho,
        },
    )
    .unwrap();
    let removal_log_path_chirho = root_chirho.join("head-removals-chirho.jsonl");
    let before_bytes_chirho = std::fs::read(&removal_log_path_chirho).unwrap();

    let outcome_chirho = recover_resource_policy_head_removal_chirho(&root_chirho, "legacyv1")
        .unwrap()
        .expect("legacy v1 pending removal must complete");
    assert_eq!(
        outcome_chirho,
        PolicyHeadRemovalRecoveryOutcomeChirho::LegacyV1AppliedChirho {
            domain_seq_chirho: 0
        }
    );
    assert_eq!(branch_head_chirho(&root_chirho, "legacyv1"), None);
    assert_eq!(
        std::fs::read(&removal_log_path_chirho).unwrap(),
        before_bytes_chirho,
        "legacy v1 completion must leave the removal log byte-identical with no v2 conversion"
    );
    assert_eq!(
        current_resource_policy_hash_chirho(&root_chirho, "legacyv1").unwrap(),
        None
    );

    separate_event_clock_chirho();
    let (reset_hash_chirho, _, _) = set_resource_policy_from_input_checked_chirho(
        &root_chirho,
        "legacyv1",
        &owner_chirho,
        input_chirho(),
        None,
        previewed_chirho,
        policy_at_ms_chirho,
    )
    .unwrap();
    assert_eq!(reset_hash_chirho, policy_hash_chirho);
    separate_event_clock_chirho();
    assert!(
        recover_resource_policy_head_removal_chirho(&root_chirho, "legacyv1")
            .unwrap()
            .is_none(),
        "a completed v1 row whose target was re-set must never resurrect"
    );
    assert_eq!(
        branch_head_chirho(&root_chirho, "legacyv1"),
        Some(policy_hash_chirho),
        "the stale v1 row must not delete the re-set head"
    );
    assert_eq!(
        std::fs::read(&removal_log_path_chirho).unwrap(),
        before_bytes_chirho
    );
}
