// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn authenticated_policy_is_dormant_until_its_exact_dag_is_applied_then_sticky_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let public_dag_chirho = fake_dag_chirho(&root_chirho, b"public access-policy dag");
    let protected_dag_chirho = fake_dag_chirho(&root_chirho, b"protected access-policy dag");
    deploy_app_chirho(
        &root_chirho,
        "workspace-chirho",
        public_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    let future_record_chirho = set_app_request_access_policy_chirho(
        &root_chirho,
        "workspace-chirho",
        &owner_chirho.principal_chirho,
        protected_dag_chirho.clone(),
        AppRequestAccessPolicyChirho::AuthenticatedChirho,
    )
    .unwrap();
    assert_eq!(future_record_chirho.seq_chirho, 0);
    assert_eq!(
        app_request_access_policy_chirho(&root_chirho, "workspace-chirho").unwrap(),
        AppRequestAccessPolicyChirho::PublicChirho,
        "a policy for a DAG that never became authoritative must stay dormant"
    );

    deploy_app_chirho(
        &root_chirho,
        "workspace-chirho",
        protected_dag_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    assert_eq!(
        app_request_access_policy_chirho(&root_chirho, "workspace-chirho").unwrap(),
        AppRequestAccessPolicyChirho::AuthenticatedChirho
    );
    let duplicate_chirho = set_app_request_access_policy_chirho(
        &root_chirho,
        "workspace-chirho",
        &owner_chirho.principal_chirho,
        protected_dag_chirho.clone(),
        AppRequestAccessPolicyChirho::AuthenticatedChirho,
    )
    .unwrap();
    assert_eq!(duplicate_chirho, future_record_chirho);
    assert_eq!(
        load_app_request_access_policy_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );

    let downgrade_error_chirho = set_app_request_access_policy_chirho(
        &root_chirho,
        "workspace-chirho",
        &owner_chirho.principal_chirho,
        protected_dag_chirho,
        AppRequestAccessPolicyChirho::PublicChirho,
    )
    .unwrap_err();
    assert!(downgrade_error_chirho
        .to_string()
        .contains("cannot downgrade to PublicChirho"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn access_policy_record_tamper_fails_authoritative_verification_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let dag_chirho = fake_dag_chirho(&root_chirho, b"tamper access-policy dag");
    deploy_app_chirho(
        &root_chirho,
        "workspace-chirho",
        dag_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    set_app_request_access_policy_chirho(
        &root_chirho,
        "workspace-chirho",
        &owner_chirho.principal_chirho,
        dag_chirho,
        AppRequestAccessPolicyChirho::AuthenticatedChirho,
    )
    .unwrap();

    let mut records_chirho = load_app_request_access_policy_records_chirho(&root_chirho).unwrap();
    records_chirho[0].policy_chirho = AppRequestAccessPolicyChirho::PublicChirho;
    write_jsonl_chirho(
        &app_request_access_policy_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let error_chirho = verify_app_request_access_policies_chirho(&root_chirho).unwrap_err();
    assert!(error_chirho.to_string().contains("signature invalid"));
    let _ = std::fs::remove_dir_all(root_chirho);
}
