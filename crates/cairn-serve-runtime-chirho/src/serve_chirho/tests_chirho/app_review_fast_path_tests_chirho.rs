// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn app_review_promote_reject_record_does_not_unlock_exact_current_fast_path_chirho() {
    let root_chirho = temp_root_chirho("app-review-fast-path-reject");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-fast-path-reject-secret",
    )
    .unwrap();
    let (kind_chirho, id_chirho) =
        split_owner_principal_for_path_chirho(&owner_chirho.principal_chirho);
    let headers_chirho = owner_bearer_headers_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-fast-path-reject-secret",
    );
    let app_name_chirho = "review-fast-path-reject-app-chirho";
    let (_initial_source_review_report_chirho, _initial_candidate_chirho, report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            "preview-chirho",
            &owner_chirho.principal_chirho,
            "app/review-fast-path-reject-app-chirho/input",
        );
    app_source_manifest_chirho::install_reviewed_app_source_report_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        &report_chirho,
    )
    .unwrap();
    let (source_review_report_chirho, candidate_chirho, _current_report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            "preview-chirho",
            &owner_chirho.principal_chirho,
            "app/review-fast-path-reject-app-chirho/input",
        );
    review_chirho::reject_candidate_with_source_review_report_chirho(
        &root_chirho,
        app_name_chirho,
        &owner_chirho.principal_chirho,
        candidate_chirho.clone(),
        "reject evidence must not authorize retry fast path",
        Some(source_review_report_chirho.clone()),
    )
    .unwrap();
    assert_eq!(
        review_chirho::verify_review_records_chirho(&root_chirho).unwrap(),
        1
    );

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_review_promote_post_chirho(
            State(state_chirho),
            headers_chirho,
            AxPath((kind_chirho, id_chirho, app_name_chirho.to_string())),
            Form(AppReviewPromoteRequestChirho {
                candidate_chirho: candidate_chirho.0.clone(),
                source_review_report_chirho: source_review_report_chirho.0.clone(),
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
            }),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
        assert!(body_text_chirho.contains("<h1>review promoted</h1>"));
        assert!(!body_text_chirho.contains("<h1>review already promoted</h1>"));
    });

    let records_chirho = review_chirho::load_review_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 2);
    assert!(matches!(
        records_chirho[0].decision_chirho,
        review_chirho::ReviewDecisionChirho::RejectChirho
    ));
    assert!(matches!(
        records_chirho[1].decision_chirho,
        review_chirho::ReviewDecisionChirho::PromoteChirho
    ));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_review_promote_other_candidate_record_does_not_unlock_exact_current_fast_path_chirho() {
    let root_chirho = temp_root_chirho("app-review-fast-path-other-candidate");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-fast-path-other-secret",
    )
    .unwrap();
    let (kind_chirho, id_chirho) =
        split_owner_principal_for_path_chirho(&owner_chirho.principal_chirho);
    let headers_chirho = owner_bearer_headers_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-fast-path-other-secret",
    );
    let app_name_chirho = "review-fast-path-other-app-chirho";
    let (_initial_source_review_report_chirho, _initial_candidate_chirho, report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            "preview-chirho",
            &owner_chirho.principal_chirho,
            "app/review-fast-path-other-app-chirho/input",
        );
    let other_candidate_chirho = store_empty_dag_chirho(&root_chirho);
    review_chirho::promote_candidate_with_review_evidence_chirho(
        &root_chirho,
        review_chirho::PromoteCandidateReviewEvidenceInputChirho {
            app_chirho: app_name_chirho,
            owner_principal_chirho: &owner_chirho.principal_chirho,
            candidate_chirho: other_candidate_chirho,
            accept_capability_escalation_chirho: false,
            accept_cost_increase_chirho: false,
            require_review_policy_envelope_chirho: false,
            source_evidence_chirho: review_chirho::ReviewSourceEvidenceChirho::default(),
        },
    )
    .unwrap();
    app_source_manifest_chirho::install_reviewed_app_source_report_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        &report_chirho,
    )
    .unwrap();
    let (source_review_report_chirho, candidate_chirho, _current_report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            "preview-chirho",
            &owner_chirho.principal_chirho,
            "app/review-fast-path-other-app-chirho/input",
        );
    assert_eq!(
        review_chirho::verify_review_records_chirho(&root_chirho).unwrap(),
        1
    );

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_review_promote_post_chirho(
            State(state_chirho),
            headers_chirho,
            AxPath((kind_chirho, id_chirho, app_name_chirho.to_string())),
            Form(AppReviewPromoteRequestChirho {
                candidate_chirho: candidate_chirho.0.clone(),
                source_review_report_chirho: source_review_report_chirho.0.clone(),
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
            }),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
        assert!(body_text_chirho.contains("<h1>review promoted</h1>"));
        assert!(!body_text_chirho.contains("<h1>review already promoted</h1>"));
    });

    let records_chirho = review_chirho::load_review_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 2);
    assert!(matches!(
        records_chirho[0].decision_chirho,
        review_chirho::ReviewDecisionChirho::PromoteChirho
    ));
    assert_ne!(records_chirho[0].candidate_chirho, candidate_chirho);
    assert!(matches!(
        records_chirho[1].decision_chirho,
        review_chirho::ReviewDecisionChirho::PromoteChirho
    ));
    assert_eq!(
        records_chirho[1].source_review_report_chirho.as_ref(),
        Some(&source_review_report_chirho)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
