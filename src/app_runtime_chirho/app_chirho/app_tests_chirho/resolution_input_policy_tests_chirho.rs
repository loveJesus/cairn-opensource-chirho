// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

#[test]
fn owner_gates_app_route_modules_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_a_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let owner_b_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let app_dag_chirho = fake_dag_chirho(&root_chirho, b"app dag");
    let route_dag_chirho = fake_dag_chirho(&root_chirho, b"route dag");
    let route_dag_b_chirho = fake_dag_chirho(&root_chirho, b"route dag b");
    deploy_app_chirho(
        &root_chirho,
        "myapp",
        app_dag_chirho,
        &owner_a_chirho.principal_chirho,
    )
    .unwrap();

    deploy_app_route_chirho(
        &root_chirho,
        "myapp",
        "lite",
        route_dag_chirho.clone(),
        &owner_a_chirho.principal_chirho,
    )
    .unwrap();
    let route_state_a_chirho = refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho["app-route/myapp/lite"]
        .clone();
    assert!(deploy_app_route_chirho(
        &root_chirho,
        "myapp",
        "other",
        route_dag_chirho.clone(),
        &owner_b_chirho.principal_chirho,
    )
    .is_err());
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    assert_eq!(
        resolve_app_route_chirho(
            &root_chirho,
            &refs_chirho,
            "myapp",
            "lite",
            &owner_a_chirho.principal_chirho,
        )
        .unwrap(),
        route_dag_chirho
    );
    let status_chirho = app_status_chirho(&root_chirho, "myapp").unwrap();
    assert_eq!(status_chirho.routes_chirho.len(), 1);
    assert!(status_chirho.routes_chirho.contains_key("lite"));
    deploy_app_route_chirho(
        &root_chirho,
        "myapp",
        "lite",
        route_dag_b_chirho.clone(),
        &owner_a_chirho.principal_chirho,
    )
    .unwrap();
    assert_ne!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho["app-route/myapp/lite"],
        route_state_a_chirho
    );
    refs_chirho::rollback_chirho(&root_chirho, "app-route/myapp/lite", route_state_a_chirho)
        .unwrap();
    assert_eq!(
        resolve_app_route_chirho(
            &root_chirho,
            &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
            "myapp",
            "lite",
            &owner_a_chirho.principal_chirho,
        )
        .unwrap(),
        route_dag_chirho
    );

    assert!(undeploy_app_route_chirho(
        &root_chirho,
        "myapp",
        "lite",
        &owner_a_chirho.principal_chirho,
    )
    .unwrap());
    assert!(resolve_app_route_chirho(
        &root_chirho,
        &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
        "myapp",
        "lite",
        &owner_a_chirho.principal_chirho,
    )
    .is_err());
    assert_eq!(verify_app_routes_chirho(&root_chirho).unwrap(), 3);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_status_requires_verified_app_ref_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "statusguard",
        fake_dag_chirho(&root_chirho, b"status signed dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app/statusguard",
        fake_dag_chirho(&root_chirho, b"status forged dag"),
    )
    .unwrap();

    let status_error_chirho = app_status_chirho(&root_chirho, "statusguard")
        .unwrap_err()
        .to_string();
    assert!(status_error_chirho.contains("ref does not match any signed app deploy record"));
    let list_error_chirho = verified_deployed_apps_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(list_error_chirho.contains("ref does not match any signed app deploy record"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_status_requires_verified_route_ref_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "routeguard",
        fake_dag_chirho(&root_chirho, b"routeguard app dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    deploy_app_route_chirho(
        &root_chirho,
        "routeguard",
        "contact",
        fake_dag_chirho(&root_chirho, b"routeguard signed route dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app-route/routeguard/contact",
        fake_dag_chirho(&root_chirho, b"routeguard forged route dag"),
    )
    .unwrap();

    let status_error_chirho = app_status_chirho(&root_chirho, "routeguard")
        .unwrap_err()
        .to_string();
    assert!(status_error_chirho.contains("ref does not match verified signed route history"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_ref_resolution_requires_signed_deploy_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let app_dag_chirho = fake_dag_chirho(&root_chirho, b"app signed dag");
    let forged_dag_chirho = fake_dag_chirho(&root_chirho, b"app forged dag");
    deploy_app_chirho(
        &root_chirho,
        "tamperref",
        app_dag_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    refs_chirho::set_branch_chirho(&root_chirho, "app/tamperref", forged_dag_chirho).unwrap();
    let error_chirho = resolve_app_dag_chirho(
        &root_chirho,
        &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
        "tamperref",
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("ref does not match any signed app deploy record"));
    let route_error_chirho = deploy_app_route_chirho(
        &root_chirho,
        "tamperref",
        "contact",
        fake_dag_chirho(&root_chirho, b"route after forged app ref"),
        &owner_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(route_error_chirho.contains("ref does not match any signed app deploy record"));

    refs_chirho::rollback_chirho(&root_chirho, "app/tamperref", app_dag_chirho.clone()).unwrap();
    assert_eq!(
        resolve_app_dag_chirho(
            &root_chirho,
            &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
            "tamperref",
        )
        .unwrap()
        .dag_chirho,
        app_dag_chirho
    );

    assert!(
        undeploy_app_chirho(&root_chirho, "tamperref", &owner_chirho.principal_chirho).unwrap()
    );
    refs_chirho::set_branch_chirho(&root_chirho, "app/tamperref", app_dag_chirho).unwrap();
    let error_chirho = resolve_app_dag_chirho(
        &root_chirho,
        &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
        "tamperref",
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("no deployed app 'tamperref'"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn route_ref_resolution_verifies_signed_route_records_before_trusting_ref_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "routetamper",
        fake_dag_chirho(&root_chirho, b"app dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    deploy_app_route_chirho(
        &root_chirho,
        "routetamper",
        "contact",
        fake_dag_chirho(&root_chirho, b"route signed dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let forged_route_chirho = fake_dag_chirho(&root_chirho, b"route forged dag");
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app-route/routetamper/contact",
        forged_route_chirho.clone(),
    )
    .unwrap();
    let mut route_records_chirho = load_app_route_records_chirho(&root_chirho).unwrap();
    route_records_chirho[0].dag_chirho = Some(forged_route_chirho);
    write_jsonl_chirho(
        &app_route_records_path_chirho(&root_chirho),
        &route_records_chirho,
    );

    let error_chirho = resolve_app_route_chirho(
        &root_chirho,
        &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
        "routetamper",
        "contact",
        &owner_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("app route record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_input_mode_verifies_policy_signature_before_plaintext_handling_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "policytamper",
        fake_dag_chirho(&root_chirho, b"policy app dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "policytamper",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/policytamper/contact".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    assert!(matches!(
        app_input_mode_chirho(
            &root_chirho,
            "policytamper",
            None,
            &owner_chirho.principal_chirho,
        )
        .unwrap(),
        AppInputModeChirho::PrivateBlobRefChirho { .. }
    ));

    let mut policy_records_chirho = load_app_input_policy_records_chirho(&root_chirho).unwrap();
    policy_records_chirho[0].mode_chirho = AppInputModeChirho::PlainChirho;
    write_jsonl_chirho(
        &app_input_policy_records_path_chirho(&root_chirho),
        &policy_records_chirho,
    );
    let error_chirho = app_input_mode_chirho(
        &root_chirho,
        "policytamper",
        None,
        &owner_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("app input policy record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_input_mode_missing_private_policy_fails_closed_for_generic_surface_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "intake7",
        fake_dag_chirho(&root_chirho, b"intake7 app dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "intake7",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/intake7/body".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    std::fs::write(app_input_policy_records_path_chirho(&root_chirho), "").unwrap();

    let error_chirho = app_input_mode_chirho(
        &root_chirho,
        "intake7",
        None,
        &owner_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("needs a signed input policy"));
    let warnings_chirho = app_input_policy_warnings_chirho(&root_chirho).unwrap();
    assert!(warnings_chirho.is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn route_input_mode_missing_private_policy_does_not_inherit_plain_for_generic_route_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "portal",
        fake_dag_chirho(&root_chirho, b"portal app dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "portal",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    deploy_app_route_chirho(
        &root_chirho,
        "portal",
        "flow7",
        fake_dag_chirho(&root_chirho, b"portal flow7 route dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "portal",
        Some("flow7"),
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/portal/flow7".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();

    let mut policy_records_chirho = load_app_input_policy_records_chirho(&root_chirho).unwrap();
    policy_records_chirho.retain(|record_chirho| record_chirho.route_chirho.is_none());
    write_jsonl_chirho(
        &app_input_policy_records_path_chirho(&root_chirho),
        &policy_records_chirho,
    );
    let error_chirho = app_input_mode_chirho(
        &root_chirho,
        "portal",
        Some("flow7"),
        &owner_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("needs a signed route input policy"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_input_mode_plain_after_private_history_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "intake7",
        fake_dag_chirho(&root_chirho, b"sticky-private app dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "intake7",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/intake7/body".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "intake7",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .unwrap();

    let error_chirho = app_input_mode_chirho(
        &root_chirho,
        "intake7",
        None,
        &owner_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("cannot downgrade to PlainChirho"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn route_input_mode_plain_after_route_private_history_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "portal",
        fake_dag_chirho(&root_chirho, b"sticky-private route app dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    deploy_app_route_chirho(
        &root_chirho,
        "portal",
        "flow7",
        fake_dag_chirho(&root_chirho, b"sticky-private route dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "portal",
        Some("flow7"),
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/portal/flow7".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "portal",
        Some("flow7"),
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .unwrap();

    let error_chirho = app_input_mode_chirho(
        &root_chirho,
        "portal",
        Some("flow7"),
        &owner_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("cannot downgrade to PlainChirho"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn route_plain_policy_after_root_private_history_is_allowed_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "portal",
        fake_dag_chirho(&root_chirho, b"sticky-private route app dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "portal",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/portal/root".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    deploy_app_route_chirho(
        &root_chirho,
        "portal",
        "flow7",
        fake_dag_chirho(&root_chirho, b"sticky-private route dag"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "portal",
        Some("flow7"),
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .unwrap();

    assert_eq!(
        app_input_mode_chirho(
            &root_chirho,
            "portal",
            Some("flow7"),
            &owner_chirho.principal_chirho,
        )
        .unwrap(),
        AppInputModeChirho::PlainChirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn root_no_body_policy_survives_mode_only_rows_and_refuses_reopening_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "sticky-body-policy",
        fake_dag_chirho(&root_chirho, b"sticky body policy app"),
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    set_app_root_input_policy_with_request_body_policy_chirho(
        &root_chirho,
        "sticky-body-policy",
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PlainChirho,
        AppRouteRequestBodyPolicyChirho::NoBodyChirho,
    )
    .unwrap();
    set_app_input_policy_chirho(
        &root_chirho,
        "sticky-body-policy",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PlainChirho,
    )
    .unwrap();

    assert_eq!(
        app_root_request_body_policy_chirho(
            &root_chirho,
            "sticky-body-policy",
            &owner_chirho.principal_chirho,
        )
        .unwrap(),
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho)
    );
    assert_eq!(verify_app_input_policies_chirho(&root_chirho).unwrap(), 2);

    let error_chirho = set_app_root_input_policy_with_request_body_policy_chirho(
        &root_chirho,
        "sticky-body-policy",
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PlainChirho,
        AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho
        .contains("cannot downgrade to AcceptBodyChirho after a signed NoBodyChirho policy"));
    assert_eq!(
        load_app_input_policy_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        2
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_verify_warns_plain_pii_shaped_input_surfaces_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let contact_dag_chirho = fake_dag_chirho(&root_chirho, b"contact dag");
    deploy_app_chirho(
        &root_chirho,
        "contact",
        contact_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    let warnings_chirho = app_input_policy_warnings_chirho(&root_chirho).unwrap();
    assert_eq!(warnings_chirho.len(), 1);
    assert_eq!(warnings_chirho[0].app_chirho, "contact");
    assert_eq!(warnings_chirho[0].route_chirho, None);
    assert_eq!(
        warnings_chirho[0].mode_chirho,
        AppInputModeChirho::PlainChirho
    );

    set_app_input_policy_chirho(
        &root_chirho,
        "contact",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact/inbox".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    assert!(app_input_policy_warnings_chirho(&root_chirho)
        .unwrap()
        .is_empty());

    let portal_dag_chirho = fake_dag_chirho(&root_chirho, b"portal dag");
    let support_dag_chirho = fake_dag_chirho(&root_chirho, b"support dag");
    deploy_app_chirho(
        &root_chirho,
        "portal",
        portal_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    deploy_app_route_chirho(
        &root_chirho,
        "portal",
        "support",
        support_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    let warnings_chirho = app_input_policy_warnings_chirho(&root_chirho).unwrap();
    assert_eq!(warnings_chirho.len(), 1);
    assert_eq!(warnings_chirho[0].app_chirho, "portal");
    assert_eq!(warnings_chirho[0].route_chirho.as_deref(), Some("support"));

    set_app_input_policy_chirho(
        &root_chirho,
        "portal",
        Some("support"),
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/portal/support".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    assert!(app_input_policy_warnings_chirho(&root_chirho)
        .unwrap()
        .is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}
