// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_model_app_chirho::app_route_head_transition_chirho::app_route_ref_target_from_record_chirho;

fn route_removal_owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho
}

fn deploy_route_parent_chirho(root_chirho: &Path, owner_chirho: &str, app_chirho: &str) {
    deploy_app_chirho(
        root_chirho,
        app_chirho,
        fake_dag_chirho(root_chirho, format!("parent {app_chirho}").as_bytes()),
        owner_chirho,
    )
    .unwrap();
}

fn route_head_chirho(root_chirho: &Path, app_chirho: &str, route_chirho: &str) -> HashChirho {
    refs_chirho::load_refs_chirho(root_chirho)
        .unwrap()
        .branches_chirho[&format!("app-route/{app_chirho}/{route_chirho}")]
        .clone()
}

fn deploy_legacy_route_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_chirho: &str,
    dag_chirho: HashChirho,
) -> AppRouteRecordChirho {
    let record_chirho =
        writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |_fence_chirho| {
            append_app_route_record_unlocked_chirho(
                root_chirho,
                app_chirho,
                route_chirho,
                owner_chirho,
                Some(dag_chirho.clone()),
                None,
                AppRouteActionChirho::DeployRouteChirho,
            )
        })
        .unwrap();
    refs_chirho::set_branch_chirho(
        root_chirho,
        &format!("app-route/{app_chirho}/{route_chirho}"),
        dag_chirho,
    )
    .unwrap();
    record_chirho
}

fn route_removal_values_chirho(root_chirho: &Path) -> Vec<serde_json::Value> {
    crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(root_chirho)
        .unwrap()
}

fn prepared_for_route_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
) -> crate::head_removal_transition_chirho::PreparedHeadRemovalChirho {
    let stored_chirho =
        crate::head_removal_transition_chirho::root_signed_prepared_head_removal_records_chirho(
            root_chirho,
        )
        .unwrap()
        .into_iter()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho.as_deref() == Some(route_chirho)
        })
        .unwrap();
    let domain_chirho = verified_app_route_records_chirho(root_chirho).unwrap()
        [stored_chirho.domain_seq_chirho as usize]
        .clone();
    crate::head_removal_transition_chirho::bind_caller_verified_prepared_head_removal_chirho(
        root_chirho,
        &stored_chirho,
        &serde_json::to_vec(&domain_chirho).unwrap(),
    )
    .unwrap()
}

#[test]
fn route_domain_only_removal_recovers_v1_and_v2_authority_targets_chirho() {
    for legacy_chirho in [true, false] {
        let root_chirho = tmp_root_chirho();
        let owner_chirho = route_removal_owner_chirho(&root_chirho);
        deploy_route_parent_chirho(&root_chirho, &owner_chirho, "domainroute");
        let dag_chirho = fake_dag_chirho(&root_chirho, b"route domain target");
        if legacy_chirho {
            deploy_legacy_route_chirho(
                &root_chirho,
                "domainroute",
                "status",
                &owner_chirho,
                dag_chirho,
            );
        } else {
            deploy_app_route_chirho(
                &root_chirho,
                "domainroute",
                "status",
                dag_chirho,
                &owner_chirho,
            )
            .unwrap();
        }
        crate::head_removal_chirho::set_head_removal_failpoint_chirho(
            &root_chirho,
            crate::head_removal_chirho::HeadRemovalStepChirho::AfterDomainRecordChirho,
        );
        assert!(
            undeploy_app_route_chirho(&root_chirho, "domainroute", "status", &owner_chirho,)
                .is_err()
        );
        assert!(route_removal_values_chirho(&root_chirho).is_empty());
        assert!(
            recover_app_route_head_removal_chirho(&root_chirho, "domainroute", "status")
                .unwrap()
                .is_some()
        );
        assert_eq!(route_removal_values_chirho(&root_chirho).len(), 2);
        assert!(!refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .contains_key("app-route/domainroute/status"));
    }
}

#[test]
fn route_domain_only_removal_rejects_forged_v1_and_v2_raw_targets_chirho() {
    for legacy_chirho in [true, false] {
        let root_chirho = tmp_root_chirho();
        let owner_chirho = route_removal_owner_chirho(&root_chirho);
        deploy_route_parent_chirho(&root_chirho, &owner_chirho, "forgedroute");
        let dag_chirho = fake_dag_chirho(&root_chirho, b"route forged original");
        if legacy_chirho {
            deploy_legacy_route_chirho(
                &root_chirho,
                "forgedroute",
                "status",
                &owner_chirho,
                dag_chirho,
            );
        } else {
            deploy_app_route_chirho(
                &root_chirho,
                "forgedroute",
                "status",
                dag_chirho,
                &owner_chirho,
            )
            .unwrap();
        }
        crate::head_removal_chirho::set_head_removal_failpoint_chirho(
            &root_chirho,
            crate::head_removal_chirho::HeadRemovalStepChirho::AfterDomainRecordChirho,
        );
        assert!(
            undeploy_app_route_chirho(&root_chirho, "forgedroute", "status", &owner_chirho,)
                .is_err()
        );
        let forged_chirho = fake_dag_chirho(&root_chirho, b"forged route raw target");
        refs_chirho::set_branch_chirho(
            &root_chirho,
            "app-route/forgedroute/status",
            forged_chirho.clone(),
        )
        .unwrap();
        assert!(
            recover_app_route_head_removal_chirho(&root_chirho, "forgedroute", "status")
                .unwrap_err()
                .to_string()
                .contains("not exact verified route authority history")
        );
        assert!(route_removal_values_chirho(&root_chirho).is_empty());
        assert_eq!(
            route_head_chirho(&root_chirho, "forgedroute", "status"),
            forged_chirho
        );
    }
}

#[test]
fn route_direct_undeploy_rejects_forged_raw_target_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_removal_owner_chirho(&root_chirho);
    deploy_route_parent_chirho(&root_chirho, &owner_chirho, "forgedirect");
    deploy_app_route_chirho(
        &root_chirho,
        "forgedirect",
        "status",
        fake_dag_chirho(&root_chirho, b"route direct original"),
        &owner_chirho,
    )
    .unwrap();
    let forged_chirho = fake_dag_chirho(&root_chirho, b"route direct forged");
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app-route/forgedirect/status",
        forged_chirho.clone(),
    )
    .unwrap();
    let error_chirho =
        undeploy_app_route_chirho(&root_chirho, "forgedirect", "status", &owner_chirho)
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("not exact verified route authority history"));
    assert!(route_removal_values_chirho(&root_chirho).is_empty());
    assert_eq!(
        route_head_chirho(&root_chirho, "forgedirect", "status"),
        forged_chirho
    );
    assert_eq!(
        verified_app_route_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1,
        "forged direct undeploy must not append a domain row"
    );
}

#[test]
fn route_removal_receipt_prevents_same_state_stale_delete_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_removal_owner_chirho(&root_chirho);
    deploy_route_parent_chirho(&root_chirho, &owner_chirho, "recreateroute");
    let dag_chirho = fake_dag_chirho(&root_chirho, b"route same state");
    let first_chirho = deploy_app_route_with_request_body_policy_chirho(
        &root_chirho,
        "recreateroute",
        "submit",
        dag_chirho.clone(),
        &owner_chirho,
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
        false,
    )
    .unwrap();
    let first_target_chirho = app_route_ref_target_from_record_chirho(&first_chirho).unwrap();
    assert!(
        undeploy_app_route_chirho(&root_chirho, "recreateroute", "submit", &owner_chirho,).unwrap()
    );
    let prepared_chirho = prepared_for_route_chirho(&root_chirho, "recreateroute", "submit");
    let recreated_chirho = deploy_app_route_with_request_body_policy_chirho(
        &root_chirho,
        "recreateroute",
        "submit",
        dag_chirho,
        &owner_chirho,
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
        false,
    )
    .unwrap();
    assert_eq!(
        app_route_ref_target_from_record_chirho(&recreated_chirho).unwrap(),
        first_target_chirho
    );
    assert_eq!(
        crate::head_removal_transition_chirho::recover_head_removal_chirho(
            &root_chirho,
            &prepared_chirho,
        )
        .unwrap(),
        crate::head_removal_transition_chirho::HeadRemovalRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(
        route_head_chirho(&root_chirho, "recreateroute", "submit"),
        first_target_chirho
    );
}

#[test]
fn same_dag_policy_change_remains_distinct_through_remove_and_recreate_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_removal_owner_chirho(&root_chirho);
    deploy_route_parent_chirho(&root_chirho, &owner_chirho, "policyremoval");
    let dag_chirho = fake_dag_chirho(&root_chirho, b"same DAG route policy removal");
    let first_chirho = deploy_app_route_with_request_body_policy_chirho(
        &root_chirho,
        "policyremoval",
        "submit",
        dag_chirho.clone(),
        &owner_chirho,
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
        false,
    )
    .unwrap();
    assert!(
        undeploy_app_route_chirho(&root_chirho, "policyremoval", "submit", &owner_chirho,).unwrap()
    );
    let prepared_chirho = prepared_for_route_chirho(&root_chirho, "policyremoval", "submit");
    let second_chirho = deploy_app_route_with_request_body_policy_chirho(
        &root_chirho,
        "policyremoval",
        "submit",
        dag_chirho,
        &owner_chirho,
        Some(AppRouteRequestBodyPolicyChirho::AcceptBodyChirho),
        false,
    )
    .unwrap();
    let first_target_chirho = app_route_ref_target_from_record_chirho(&first_chirho).unwrap();
    let second_target_chirho = app_route_ref_target_from_record_chirho(&second_chirho).unwrap();
    assert_ne!(first_target_chirho, second_target_chirho);
    assert_eq!(
        crate::head_removal_transition_chirho::recover_head_removal_chirho(
            &root_chirho,
            &prepared_chirho,
        )
        .unwrap(),
        crate::head_removal_transition_chirho::HeadRemovalRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(
        route_head_chirho(&root_chirho, "policyremoval", "submit"),
        second_target_chirho
    );
    assert_eq!(
        verified_app_route_request_body_policy_chirho(
            &root_chirho,
            "policyremoval",
            "submit",
            &owner_chirho,
            second_chirho.dag_chirho.as_ref().unwrap(),
        )
        .unwrap(),
        Some(AppRouteRequestBodyPolicyChirho::AcceptBodyChirho)
    );
}

#[test]
fn route_deploy_recovers_pending_removal_before_recreate_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_removal_owner_chirho(&root_chirho);
    deploy_route_parent_chirho(&root_chirho, &owner_chirho, "composeroute");
    deploy_app_route_chirho(
        &root_chirho,
        "composeroute",
        "submit",
        fake_dag_chirho(&root_chirho, b"route removal A"),
        &owner_chirho,
    )
    .unwrap();
    crate::head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        crate::head_removal_chirho::HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );
    assert!(
        undeploy_app_route_chirho(&root_chirho, "composeroute", "submit", &owner_chirho,).is_err()
    );
    let recreated_chirho = deploy_app_route_chirho(
        &root_chirho,
        "composeroute",
        "submit",
        fake_dag_chirho(&root_chirho, b"route removal B"),
        &owner_chirho,
    )
    .unwrap();
    assert!(recreated_chirho.previous_chirho.is_none());
    assert_eq!(route_removal_values_chirho(&root_chirho).len(), 2);
}

#[test]
fn route_removal_current_other_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_removal_owner_chirho(&root_chirho);
    deploy_route_parent_chirho(&root_chirho, &owner_chirho, "divergeroute");
    deploy_app_route_chirho(
        &root_chirho,
        "divergeroute",
        "status",
        fake_dag_chirho(&root_chirho, b"route current A"),
        &owner_chirho,
    )
    .unwrap();
    crate::head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        crate::head_removal_chirho::HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );
    assert!(
        undeploy_app_route_chirho(&root_chirho, "divergeroute", "status", &owner_chirho,).is_err()
    );
    let other_chirho = fake_dag_chirho(&root_chirho, b"route current other");
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app-route/divergeroute/status",
        other_chirho.clone(),
    )
    .unwrap();
    assert!(recover_app_route_head_removal_chirho(&root_chirho, "divergeroute", "status").is_err());
    assert_eq!(
        route_head_chirho(&root_chirho, "divergeroute", "status"),
        other_chirho
    );
}

#[test]
fn route_removal_absent_branch_repairs_applied_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_removal_owner_chirho(&root_chirho);
    deploy_route_parent_chirho(&root_chirho, &owner_chirho, "absentroute");
    deploy_app_route_chirho(
        &root_chirho,
        "absentroute",
        "status",
        fake_dag_chirho(&root_chirho, b"route absent repair"),
        &owner_chirho,
    )
    .unwrap();
    crate::head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        crate::head_removal_chirho::HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );
    assert!(
        undeploy_app_route_chirho(&root_chirho, "absentroute", "status", &owner_chirho,).is_err()
    );
    refs_chirho::remove_branch_chirho(&root_chirho, "app-route/absentroute/status").unwrap();

    assert!(
        recover_app_route_head_removal_chirho(&root_chirho, "absentroute", "status")
            .unwrap()
            .is_some()
    );
    assert_eq!(route_removal_values_chirho(&root_chirho).len(), 2);
    assert!(
        recover_app_route_head_removal_chirho(&root_chirho, "absentroute", "status")
            .unwrap()
            .is_none()
    );
    assert_eq!(route_removal_values_chirho(&root_chirho).len(), 2);
}

#[test]
fn different_route_pending_removals_recover_independently_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_removal_owner_chirho(&root_chirho);
    deploy_route_parent_chirho(&root_chirho, &owner_chirho, "removalroutes");
    for (route_chirho, marker_chirho) in [
        ("first", b"route removal branch A".as_slice()),
        ("second", b"route removal branch B".as_slice()),
    ] {
        deploy_app_route_chirho(
            &root_chirho,
            "removalroutes",
            route_chirho,
            fake_dag_chirho(&root_chirho, marker_chirho),
            &owner_chirho,
        )
        .unwrap();
        crate::head_removal_chirho::set_head_removal_failpoint_chirho(
            &root_chirho,
            crate::head_removal_chirho::HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
        );
        assert!(undeploy_app_route_chirho(
            &root_chirho,
            "removalroutes",
            route_chirho,
            &owner_chirho,
        )
        .is_err());
    }

    assert!(
        recover_app_route_head_removal_chirho(&root_chirho, "removalroutes", "first")
            .unwrap()
            .is_some()
    );
    assert!(refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app-route/removalroutes/second"));
    assert!(
        recover_app_route_head_removal_chirho(&root_chirho, "removalroutes", "second")
            .unwrap()
            .is_some()
    );
    assert_eq!(route_removal_values_chirho(&root_chirho).len(), 4);
}

#[test]
fn legacy_route_removal_recovers_without_v2_conversion_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_removal_owner_chirho(&root_chirho);
    deploy_route_parent_chirho(&root_chirho, &owner_chirho, "legacyroute");
    let dag_chirho = fake_dag_chirho(&root_chirho, b"legacy route removal");
    deploy_legacy_route_chirho(
        &root_chirho,
        "legacyroute",
        "status",
        &owner_chirho,
        dag_chirho.clone(),
    );
    writer_head_chirho::with_head_transition_scope_chirho(&root_chirho, |_fence_chirho| {
        let domain_chirho = append_app_route_record_unlocked_chirho(
            &root_chirho,
            "legacyroute",
            "status",
            &owner_chirho,
            None,
            None,
            AppRouteActionChirho::UndeployRouteChirho,
        )?;
        crate::head_removal_chirho::append_head_removal_record_unlocked_chirho(
            &root_chirho,
            crate::head_removal_chirho::HeadRemovalEvidenceInputChirho {
                branch_chirho: "app-route/legacyroute/status",
                from_chirho: &dag_chirho,
                kind_chirho:
                    crate::head_removal_chirho::HeadRemovalKindChirho::AppRouteUndeployChirho,
                app_chirho: "legacyroute",
                route_chirho: Some("status"),
                owner_principal_chirho: &owner_chirho,
                domain_log_chirho: "app-route-records-chirho.jsonl",
                domain_seq_chirho: domain_chirho.seq_chirho,
            },
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        recover_app_route_head_removal_chirho(&root_chirho, "legacyroute", "status")
            .unwrap(),
        Some(cairn_app_control_chirho::app_route_head_removal_chirho::AppRouteHeadRemovalRecoveryOutcomeChirho::LegacyV1AppliedChirho)
    );
    let values_chirho = route_removal_values_chirho(&root_chirho);
    assert_eq!(values_chirho.len(), 1, "{values_chirho:#?}");
    assert_eq!(
        values_chirho[0]["schema_chirho"],
        crate::head_removal_chirho::HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO
    );
}
