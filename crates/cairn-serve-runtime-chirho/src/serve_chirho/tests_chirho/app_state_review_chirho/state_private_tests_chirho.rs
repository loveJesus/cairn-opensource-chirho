// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::super::*;

#[test]
fn owner_app_state_rolls_back_safe_contact_rows_chirho() {
    let root_chirho = temp_root_chirho("owner-app-state-rollback");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-state-secret",
    )
    .unwrap();
    let (kind_chirho, id_chirho) = owner_chirho
        .principal_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-state-secret",
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", login_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "contact",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let v1_chirho = store_chirho
        .put_chirho(
            "contacts-chirho/submission-001",
            br#"{"schema_chirho":"contact-record-v1-chirho","status_chirho":"received"}"#,
        )
        .unwrap();
    let v2_chirho = store_chirho
        .put_chirho(
            "contacts-chirho/submission-002",
            br#"{"schema_chirho":"contact-record-v1-chirho","status_chirho":"received"}"#,
        )
        .unwrap();
    assert!(v2_chirho > v1_chirho);
    drop(store_chirho);
    query_chirho::project_chirho(&root_chirho).unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_state_get_chirho(
            State(state_chirho.clone()),
            headers_chirho.clone(),
            AxPath((
                kind_chirho.clone(),
                id_chirho.clone(),
                "contact".to_string(),
            )),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
        assert!(body_text_chirho.contains(&format!("v{v2_chirho}")));
        assert!(body_text_chirho.contains("contacts-chirho/submission-002"));
        assert!(!body_text_chirho.contains("alice@example.com"));

        let rollback_chirho = app_state_rollback_post_chirho(
            State(state_chirho.clone()),
            headers_chirho.clone(),
            AxPath((
                kind_chirho.clone(),
                id_chirho.clone(),
                "contact".to_string(),
            )),
            Form(AppStateRollbackRequestChirho {
                to_chirho: v1_chirho,
            }),
        )
        .await;
        assert_eq!(rollback_chirho.status(), StatusCode::SEE_OTHER);

        let response_chirho = app_state_get_chirho(
            State(state_chirho),
            headers_chirho,
            AxPath((kind_chirho, id_chirho, "contact".to_string())),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
        assert!(body_text_chirho.contains(&format!("v{v1_chirho}")));
        assert!(body_text_chirho.contains("contacts-chirho/submission-001"));
        assert!(!body_text_chirho.contains("contacts-chirho/submission-002"));
    });

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert_eq!(store_chirho.current_view_chirho().unwrap(), v1_chirho);
    let rows_chirho =
        query_chirho::query_prefix_chirho(&root_chirho, "contacts-chirho", 10).unwrap();
    assert_eq!(rows_chirho.len(), 1);
    assert_eq!(rows_chirho[0].key_chirho, "contacts-chirho/submission-001");

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn owner_app_state_reveals_private_contact_body_chirho() {
    let root_chirho = temp_root_chirho("owner-app-state-reveal");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-reveal-secret",
    )
    .unwrap();
    let (kind_chirho, id_chirho) = owner_chirho
        .principal_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-reveal-secret",
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", login_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "contact",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );

    let raw_body_chirho =
        br#"{"name_chirho":"Alice Example","email_chirho":"alice@example.com","message_chirho":"Apartment above the bakery near the river"}"#;
    let blob_chirho = privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        // The contact app's own container: its owner holds the subject.
        &privacy_chirho::PrivateBlobAttributionChirho::app_container_chirho(
            &owner_chirho.principal_chirho,
            None,
        )
        .unwrap(),
        "app/contact/inbox",
        raw_body_chirho,
    )
    .unwrap();
    let record_chirho = serde_json::to_vec(&serde_json::json!({
        "schema_chirho": "contact-record-v1-chirho",
        "status_chirho": "received",
        "subject_chirho": "app/contact/inbox",
        "blob_chirho": blob_chirho,
    }))
    .unwrap();
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    store_chirho
        .put_chirho("contacts-chirho/submission-001", &record_chirho)
        .unwrap();
    drop(store_chirho);

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let state_response_chirho = app_state_get_chirho(
            State(state_chirho.clone()),
            headers_chirho.clone(),
            AxPath((
                kind_chirho.clone(),
                id_chirho.clone(),
                "contact".to_string(),
            )),
        )
        .await;
        assert_eq!(state_response_chirho.status(), StatusCode::OK);
        let state_body_chirho = axum::body::to_bytes(state_response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let state_text_chirho = String::from_utf8(state_body_chirho.to_vec()).unwrap();
        assert!(state_text_chirho.contains("Reveal private body"));
        assert!(!state_text_chirho.contains("Alice Example"));
        assert!(!state_text_chirho.contains("alice@example.com"));
        assert!(!state_text_chirho.contains("bakery"));

        let rejected_chirho = app_state_reveal_post_chirho(
            State(state_chirho.clone()),
            HeaderMap::new(),
            AxPath((
                kind_chirho.clone(),
                id_chirho.clone(),
                "contact".to_string(),
            )),
            Form(AppStateRevealRequestChirho {
                key_chirho: "contacts-chirho/submission-001".to_string(),
            }),
        )
        .await;
        assert_eq!(rejected_chirho.status(), StatusCode::UNAUTHORIZED);

        let reveal_chirho = app_state_reveal_post_chirho(
            State(state_chirho),
            headers_chirho,
            AxPath((kind_chirho, id_chirho, "contact".to_string())),
            Form(AppStateRevealRequestChirho {
                key_chirho: "contacts-chirho/submission-001".to_string(),
            }),
        )
        .await;
        assert_eq!(reveal_chirho.status(), StatusCode::OK);
        let reveal_body_chirho = axum::body::to_bytes(reveal_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let reveal_text_chirho = String::from_utf8(reveal_body_chirho.to_vec()).unwrap();
        assert!(reveal_text_chirho.contains("governed private blob reveal"));
        assert!(reveal_text_chirho.contains("Alice Example"));
        assert!(reveal_text_chirho.contains("alice@example.com"));
        assert!(reveal_text_chirho.contains("Apartment above the bakery near the river"));
    });

    let access_records_chirho =
        privacy_chirho::load_privacy_access_records_chirho(&root_chirho).unwrap();
    assert_eq!(access_records_chirho.len(), 1);
    assert_eq!(
        access_records_chirho[0].accessed_by_chirho,
        owner_chirho.principal_chirho
    );
    assert_eq!(access_records_chirho[0].app_chirho, "contact");
    assert_eq!(
        access_records_chirho[0].row_key_chirho,
        "contacts-chirho/submission-001"
    );
    assert_eq!(
        access_records_chirho[0].purpose_chirho,
        "owner-contact-reveal-chirho"
    );
    assert_eq!(
        privacy_chirho::verify_privacy_logs_chirho(&root_chirho)
            .unwrap()
            .access_records_chirho,
        1
    );
    let access_log_chirho =
        std::fs::read_to_string(root_chirho.join("privacy-access-records-chirho.jsonl")).unwrap();
    assert!(!access_log_chirho.contains("Alice Example"));
    assert!(!access_log_chirho.contains("alice@example.com"));
    assert!(!access_log_chirho.contains("bakery"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn owner_app_state_reveal_requires_privacy_log_covered_contact_blob_chirho() {
    let root_chirho = temp_root_chirho("owner-app-state-reveal-log-covered");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-reveal-log-secret",
    )
    .unwrap();
    let (kind_chirho, id_chirho) = owner_chirho
        .principal_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-reveal-log-secret",
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", login_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "contact",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );

    let raw_body_chirho = b"decryptable body whose signed blob row was removed";
    let blob_chirho = privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        // The contact app's own container: its owner holds the subject.
        &privacy_chirho::PrivateBlobAttributionChirho::app_container_chirho(
            &owner_chirho.principal_chirho,
            None,
        )
        .unwrap(),
        "app/contact/inbox",
        raw_body_chirho,
    )
    .unwrap();
    std::fs::write(root_chirho.join("privacy-blob-records-chirho.jsonl"), "").unwrap();
    let record_chirho = serde_json::to_vec(&serde_json::json!({
        "schema_chirho": "contact-record-v1-chirho",
        "status_chirho": "received",
        "subject_chirho": "app/contact/inbox",
        "blob_chirho": blob_chirho,
    }))
    .unwrap();
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    store_chirho
        .put_chirho("contacts-chirho/submission-001", &record_chirho)
        .unwrap();
    drop(store_chirho);

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let state_response_chirho = app_state_get_chirho(
            State(state_chirho.clone()),
            headers_chirho.clone(),
            AxPath((
                kind_chirho.clone(),
                id_chirho.clone(),
                "contact".to_string(),
            )),
        )
        .await;
        assert_eq!(state_response_chirho.status(), StatusCode::OK);
        let state_body_chirho = axum::body::to_bytes(state_response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let state_text_chirho = String::from_utf8(state_body_chirho.to_vec()).unwrap();
        assert!(!state_text_chirho.contains("Reveal private body"));

        let reveal_chirho = app_state_reveal_post_chirho(
            State(state_chirho),
            headers_chirho,
            AxPath((kind_chirho, id_chirho, "contact".to_string())),
            Form(AppStateRevealRequestChirho {
                key_chirho: "contacts-chirho/submission-001".to_string(),
            }),
        )
        .await;
        assert_eq!(reveal_chirho.status(), StatusCode::BAD_REQUEST);
        let reveal_body_chirho = axum::body::to_bytes(reveal_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let reveal_text_chirho = String::from_utf8(reveal_body_chirho.to_vec()).unwrap();
        assert!(reveal_text_chirho.contains("not represented in the privacy blob log"));
    });

    assert_eq!(
        privacy_chirho::load_private_blob_chirho(&root_chirho, &blob_chirho).unwrap(),
        raw_body_chirho
    );
    assert!(
        privacy_chirho::load_privacy_access_records_chirho(&root_chirho)
            .unwrap()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn owner_app_state_reveal_requires_contact_row_subject_match_chirho() {
    let root_chirho = temp_root_chirho("owner-app-state-reveal-subject");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-reveal-subject-secret",
    )
    .unwrap();
    let (kind_chirho, id_chirho) = owner_chirho
        .principal_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-reveal-subject-secret",
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", login_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "contact",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );

    let foreign_body_chirho = b"foreign subject body should not reveal";
    let foreign_blob_chirho = privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        // The contact app's own container: its owner holds the subject.
        &privacy_chirho::PrivateBlobAttributionChirho::app_container_chirho(
            &owner_chirho.principal_chirho,
            None,
        )
        .unwrap(),
        "app/contact/foreign",
        foreign_body_chirho,
    )
    .unwrap();
    let record_chirho = serde_json::to_vec(&serde_json::json!({
        "schema_chirho": "contact-record-v1-chirho",
        "status_chirho": "received",
        "subject_chirho": "app/contact/inbox",
        "blob_chirho": foreign_blob_chirho,
    }))
    .unwrap();
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    store_chirho
        .put_chirho("contacts-chirho/submission-001", &record_chirho)
        .unwrap();
    drop(store_chirho);

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let state_response_chirho = app_state_get_chirho(
            State(state_chirho.clone()),
            headers_chirho.clone(),
            AxPath((
                kind_chirho.clone(),
                id_chirho.clone(),
                "contact".to_string(),
            )),
        )
        .await;
        assert_eq!(state_response_chirho.status(), StatusCode::OK);
        let state_body_chirho = axum::body::to_bytes(state_response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let state_text_chirho = String::from_utf8(state_body_chirho.to_vec()).unwrap();
        assert!(!state_text_chirho.contains("Reveal private body"));
        assert!(!state_text_chirho.contains("foreign subject body"));

        let reveal_chirho = app_state_reveal_post_chirho(
            State(state_chirho),
            headers_chirho,
            AxPath((kind_chirho, id_chirho, "contact".to_string())),
            Form(AppStateRevealRequestChirho {
                key_chirho: "contacts-chirho/submission-001".to_string(),
            }),
        )
        .await;
        assert_eq!(reveal_chirho.status(), StatusCode::BAD_REQUEST);
        let reveal_body_chirho = axum::body::to_bytes(reveal_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let reveal_text_chirho = String::from_utf8(reveal_body_chirho.to_vec()).unwrap();
        assert!(reveal_text_chirho.contains("belongs to subject"));
        assert!(reveal_text_chirho.contains("app/contact/foreign"));
        assert!(reveal_text_chirho.contains("app/contact/inbox"));
        assert!(!reveal_text_chirho.contains("foreign subject body"));
    });

    assert_eq!(
        privacy_chirho::load_private_blob_chirho(&root_chirho, &foreign_blob_chirho).unwrap(),
        foreign_body_chirho
    );
    assert!(
        privacy_chirho::load_privacy_access_records_chirho(&root_chirho)
            .unwrap()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
