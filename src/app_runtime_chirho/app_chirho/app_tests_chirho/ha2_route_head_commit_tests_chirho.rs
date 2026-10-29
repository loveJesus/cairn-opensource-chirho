// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_model_app_chirho::app_route_head_transition_chirho::app_route_authority_state_hash_chirho;
use cairn_writer_head_chirho::writer_head_chirho::WriterFenceTokenChirho;

fn route_owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho
}

fn deploy_parent_app_chirho(root_chirho: &Path, owner_chirho: &str, app_chirho: &str) {
    deploy_app_chirho(
        root_chirho,
        app_chirho,
        fake_dag_chirho(root_chirho, format!("parent {app_chirho}").as_bytes()),
        owner_chirho,
    )
    .unwrap();
}

fn route_state_chirho(
    app_chirho: &str,
    route_chirho: &str,
    owner_chirho: &str,
    dag_chirho: HashChirho,
    policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
) -> AppRouteAuthorityStateChirho {
    AppRouteAuthorityStateChirho {
        schema_chirho: APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        route_chirho: route_chirho.to_string(),
        owner_principal_chirho: owner_chirho.to_string(),
        dag_chirho,
        action_chirho: AppRouteActionChirho::DeployRouteChirho,
        request_body_policy_chirho: policy_chirho,
    }
}

fn append_pending_route_chirho(
    root_chirho: &Path,
    state_chirho: &AppRouteAuthorityStateChirho,
    previous_chirho: Option<HashChirho>,
) -> (AppRouteRecordChirho, HashChirho, WriterFenceTokenChirho) {
    cairn_app_control_chirho::append_pending_app_route_for_test_chirho(
        &RootAppRouteAuthorityPortChirho,
        root_chirho,
        state_chirho,
        previous_chirho,
    )
    .unwrap()
}

fn route_ref_chirho(root_chirho: &Path, app_chirho: &str, route_chirho: &str) -> HashChirho {
    refs_chirho::load_refs_chirho(root_chirho)
        .unwrap()
        .branches_chirho[&format!("app-route/{app_chirho}/{route_chirho}")]
        .clone()
}

#[test]
fn same_dag_policy_change_moves_state_and_rollback_restores_exact_policy_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    deploy_parent_app_chirho(&root_chirho, &owner_chirho, "policyapp");
    let dag_chirho = fake_dag_chirho(&root_chirho, b"same route DAG");
    let first_chirho = deploy_app_route_with_request_body_policy_chirho(
        &root_chirho,
        "policyapp",
        "submit",
        dag_chirho.clone(),
        &owner_chirho,
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
        false,
    )
    .unwrap();
    let state_a_chirho = route_ref_chirho(&root_chirho, "policyapp", "submit");

    let second_chirho = deploy_app_route_with_request_body_policy_chirho(
        &root_chirho,
        "policyapp",
        "submit",
        dag_chirho.clone(),
        &owner_chirho,
        Some(AppRouteRequestBodyPolicyChirho::AcceptBodyChirho),
        false,
    )
    .unwrap();
    let state_b_chirho = route_ref_chirho(&root_chirho, "policyapp", "submit");
    assert_ne!(state_a_chirho, state_b_chirho);
    assert_eq!(second_chirho.previous_chirho, Some(state_a_chirho.clone()));
    assert_eq!(
        resolve_app_route_chirho(
            &root_chirho,
            &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
            "policyapp",
            "submit",
            &owner_chirho,
        )
        .unwrap(),
        dag_chirho
    );
    assert_eq!(
        verified_app_route_request_body_policy_chirho(
            &root_chirho,
            "policyapp",
            "submit",
            &owner_chirho,
            second_chirho.dag_chirho.as_ref().unwrap(),
        )
        .unwrap(),
        Some(AppRouteRequestBodyPolicyChirho::AcceptBodyChirho)
    );

    refs_chirho::rollback_chirho(&root_chirho, "app-route/policyapp/submit", state_a_chirho)
        .unwrap();
    assert_eq!(
        verified_app_route_request_body_policy_chirho(
            &root_chirho,
            "policyapp",
            "submit",
            &owner_chirho,
            first_chirho.dag_chirho.as_ref().unwrap(),
        )
        .unwrap(),
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho)
    );
    assert_eq!(
        recover_app_route_head_chirho(&root_chirho, "policyapp", "submit").unwrap(),
        None
    );
    let record_count_chirho = verified_app_route_records_chirho(&root_chirho)
        .unwrap()
        .len();
    let reflog_count_chirho = refs_chirho::reflog_chirho(&root_chirho).unwrap().len();
    let repeated_chirho = deploy_app_route_with_request_body_policy_chirho(
        &root_chirho,
        "policyapp",
        "submit",
        first_chirho.dag_chirho.clone().unwrap(),
        &owner_chirho,
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
        false,
    )
    .unwrap();
    assert_eq!(repeated_chirho, first_chirho);
    assert_eq!(
        verified_app_route_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        record_count_chirho
    );
    assert_eq!(
        refs_chirho::reflog_chirho(&root_chirho).unwrap().len(),
        reflog_count_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn route_ref_before_receipt_fails_closed_then_repairs_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    deploy_parent_app_chirho(&root_chirho, &owner_chirho, "routereceipt");
    let state_chirho = route_state_chirho(
        "routereceipt",
        "status",
        &owner_chirho,
        fake_dag_chirho(&root_chirho, b"route receipt"),
        None,
    );
    let (_record_chirho, state_hash_chirho, _) =
        append_pending_route_chirho(&root_chirho, &state_chirho, None);
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app-route/routereceipt/status",
        state_hash_chirho,
    )
    .unwrap();
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    assert!(resolve_app_route_chirho(
        &root_chirho,
        &refs_chirho,
        "routereceipt",
        "status",
        &owner_chirho,
    )
    .unwrap_err()
    .to_string()
    .contains("no valid Applied receipt"));
    assert!(matches!(
        recover_app_route_head_chirho(&root_chirho, "routereceipt", "status").unwrap(),
        Some(cairn_writer_head_chirho::head_transition_chirho::HeadTransitionRecoveryOutcomeChirho::RepairedReflogChirho)
    ));
    assert!(resolve_app_route_chirho(
        &root_chirho,
        &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
        "routereceipt",
        "status",
        &owner_chirho,
    )
    .is_ok());
    assert_eq!(
        recover_app_route_head_chirho(&root_chirho, "routereceipt", "status").unwrap(),
        None
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn route_pending_transitions_settle_before_undeploy_chirho() {
    for existing_chirho in [false, true] {
        let root_chirho = tmp_root_chirho();
        let owner_chirho = route_owner_chirho(&root_chirho);
        deploy_parent_app_chirho(&root_chirho, &owner_chirho, "removeapp");
        let previous_chirho = if existing_chirho {
            deploy_app_route_chirho(
                &root_chirho,
                "removeapp",
                "remove",
                fake_dag_chirho(&root_chirho, b"route previous"),
                &owner_chirho,
            )
            .unwrap();
            Some(route_ref_chirho(&root_chirho, "removeapp", "remove"))
        } else {
            None
        };
        let state_chirho = route_state_chirho(
            "removeapp",
            "remove",
            &owner_chirho,
            fake_dag_chirho(&root_chirho, b"route pending removal"),
            None,
        );
        let (_, state_hash_chirho, _) =
            append_pending_route_chirho(&root_chirho, &state_chirho, previous_chirho);
        assert!(
            undeploy_app_route_chirho(&root_chirho, "removeapp", "remove", &owner_chirho,).unwrap()
        );
        let removals_chirho =
            crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
                &root_chirho,
            )
            .unwrap();
        assert_eq!(removals_chirho.len(), 2);
        assert_eq!(removals_chirho[0]["from_chirho"], state_hash_chirho.0);
        assert_eq!(
            recover_app_route_head_chirho(&root_chirho, "removeapp", "remove").unwrap(),
            None
        );
        assert!(!refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .contains_key("app-route/removeapp/remove"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

#[test]
fn raw_route_state_outside_verified_history_cannot_resolve_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    deploy_parent_app_chirho(&root_chirho, &owner_chirho, "forgedroute");
    deploy_app_route_chirho(
        &root_chirho,
        "forgedroute",
        "status",
        fake_dag_chirho(&root_chirho, b"verified route state"),
        &owner_chirho,
    )
    .unwrap();
    let state_chirho = route_state_chirho(
        "forgedroute",
        "status",
        &owner_chirho,
        fake_dag_chirho(&root_chirho, b"forged route state"),
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
    );
    let state_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &state_chirho).unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app-route/forgedroute/status",
        state_hash_chirho,
    )
    .unwrap();
    let error_chirho = resolve_app_route_chirho(
        &root_chirho,
        &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
        "forgedroute",
        "status",
        &owner_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("ref does not match verified signed route history"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn different_route_pending_transitions_recover_independently_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    deploy_parent_app_chirho(&root_chirho, &owner_chirho, "independentroute");
    let state_a_chirho = route_state_chirho(
        "independentroute",
        "a",
        &owner_chirho,
        fake_dag_chirho(&root_chirho, b"independent route A"),
        None,
    );
    let state_b_chirho = route_state_chirho(
        "independentroute",
        "b",
        &owner_chirho,
        fake_dag_chirho(&root_chirho, b"independent route B"),
        None,
    );
    append_pending_route_chirho(&root_chirho, &state_a_chirho, None);
    append_pending_route_chirho(&root_chirho, &state_b_chirho, None);
    recover_app_route_head_chirho(&root_chirho, "independentroute", "a")
        .unwrap()
        .unwrap();
    assert!(refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app-route/independentroute/a"));
    assert!(!refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app-route/independentroute/b"));
    recover_app_route_head_chirho(&root_chirho, "independentroute", "b")
        .unwrap()
        .unwrap();
    assert!(refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app-route/independentroute/b"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn same_route_write_recovers_pending_transition_before_next_append_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    deploy_parent_app_chirho(&root_chirho, &owner_chirho, "samependingroute");
    let state_a_chirho = route_state_chirho(
        "samependingroute",
        "status",
        &owner_chirho,
        fake_dag_chirho(&root_chirho, b"same pending route A"),
        None,
    );
    let (_, state_a_hash_chirho, _) =
        append_pending_route_chirho(&root_chirho, &state_a_chirho, None);
    let next_chirho = deploy_app_route_chirho(
        &root_chirho,
        "samependingroute",
        "status",
        fake_dag_chirho(&root_chirho, b"same pending route B"),
        &owner_chirho,
    )
    .unwrap();
    assert_eq!(next_chirho.previous_chirho, Some(state_a_hash_chirho));
    assert_eq!(
        verified_app_route_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        2
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn stale_route_preparer_cannot_complete_after_recovery_advances_fence_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    deploy_parent_app_chirho(&root_chirho, &owner_chirho, "staleroute");
    let state_chirho = route_state_chirho(
        "staleroute",
        "status",
        &owner_chirho,
        fake_dag_chirho(&root_chirho, b"stale route preparer"),
        None,
    );
    let (record_chirho, _, stale_fence_chirho) =
        append_pending_route_chirho(&root_chirho, &state_chirho, None);
    recover_app_route_head_chirho(&root_chirho, "staleroute", "status")
        .unwrap()
        .unwrap();
    let error_chirho = cairn_app_control_chirho::complete_app_route_record_for_test_chirho(
        &root_chirho,
        &record_chirho,
        &stale_fence_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .chain()
        .any(|cause_chirho| cause_chirho.to_string().contains("StaleWriterFenceChirho")));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn route_state_ref_keeps_state_and_dag_reachable_without_log_scan_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = route_owner_chirho(&root_chirho);
    deploy_parent_app_chirho(&root_chirho, &owner_chirho, "gcroute");
    let dag_chirho = fake_dag_chirho(&root_chirho, b"route GC DAG");
    let record_chirho = deploy_app_route_chirho(
        &root_chirho,
        "gcroute",
        "status",
        dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    let state_hash_chirho = route_ref_chirho(&root_chirho, "gcroute", "status");
    std::fs::remove_file(app_route_records_path_chirho(&root_chirho)).unwrap();
    crate::gc_chirho::gc_chirho(&root_chirho).unwrap();
    let state_chirho: AppRouteAuthorityStateChirho =
        store_chirho::get_object_chirho(&root_chirho, &state_hash_chirho).unwrap();
    let _dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &dag_chirho).unwrap();
    assert_eq!(
        app_route_authority_state_hash_chirho(&state_chirho).unwrap(),
        state_hash_chirho
    );
    assert_eq!(state_chirho.dag_chirho, record_chirho.dag_chirho.unwrap());
    let state_json_chirho = serde_json::to_string(&state_chirho).unwrap();
    assert!(!state_json_chirho.contains("root_chirho"));
    assert!(!state_json_chirho.contains("private"));
    let _ = std::fs::remove_dir_all(root_chirho);
}
