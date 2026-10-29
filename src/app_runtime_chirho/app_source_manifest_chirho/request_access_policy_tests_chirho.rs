// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn source_review_promote_binds_access_and_request_body_policies_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_path_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples-chirho/agent-authored-backend-source-manifest-chirho.example.json");
    let (base_chirho, mut manifest_chirho) =
        load_app_source_manifest_from_path_chirho(&manifest_path_chirho).unwrap();
    manifest_chirho.app_chirho = "body-policy-review".to_string();
    manifest_chirho.owner_chirho = owner_chirho.clone();
    manifest_chirho.deploy_chirho.request_access_policy_chirho =
        Some(app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho);
    manifest_chirho.deploy_chirho.input_mode_chirho =
        Some(app_chirho::AppInputModeChirho::PlainChirho);
    manifest_chirho.deploy_chirho.request_body_policy_chirho =
        Some(app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho);
    manifest_chirho.deploy_chirho.routes_chirho = vec![AppSourceDeployRouteManifestChirho {
        route_chirho: "status".to_string(),
        source_chirho: AppSourceDeploySourceChirho::ModuleIdChirho {
            id_chirho: "agent_backend_module".to_string(),
        },
        input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
        request_body_policy_chirho: Some(app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho),
        response_content_type_chirho: None,
        params_chirho: None,
        key_access_chirho: None,
    }];

    let review_chirho =
        build_app_source_review_chirho(&root_chirho, &base_chirho, &manifest_chirho).unwrap();
    assert_eq!(
        review_chirho.candidate_chirho.request_access_policy_chirho,
        Some(app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho)
    );
    assert_eq!(
        review_chirho.candidate_chirho.request_body_policy_chirho,
        Some(app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho)
    );
    assert_eq!(
        review_chirho.candidate_chirho.routes_chirho[0].request_body_policy_chirho,
        Some(app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho)
    );
    assert_source_candidate_left_no_authoritative_surface_chirho(
        &root_chirho,
        &manifest_chirho.app_chirho,
    );
    review_chirho::promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        &manifest_chirho.app_chirho,
        &owner_chirho,
        review_chirho.candidate_chirho.root_dag_chirho.clone(),
        false,
        false,
        review_chirho.source_review_report_chirho.clone(),
    )
    .unwrap();
    install_reviewed_app_source_report_chirho(&root_chirho, &owner_chirho, &review_chirho).unwrap();

    let status_chirho =
        app_chirho::app_status_chirho(&root_chirho, &manifest_chirho.app_chirho).unwrap();
    assert_eq!(
        app_chirho::app_request_access_policy_chirho(&root_chirho, &manifest_chirho.app_chirho,)
            .unwrap(),
        app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho
    );
    assert_eq!(
        app_chirho::app_root_request_body_policy_chirho(
            &root_chirho,
            &manifest_chirho.app_chirho,
            &owner_chirho,
        )
        .unwrap(),
        Some(app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho)
    );
    let route_dag_chirho = status_chirho.routes_chirho.get("status").unwrap();
    assert_eq!(
        app_chirho::verified_app_route_request_body_policy_chirho(
            &root_chirho,
            &manifest_chirho.app_chirho,
            "status",
            &owner_chirho,
            route_dag_chirho,
        )
        .unwrap(),
        Some(app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
