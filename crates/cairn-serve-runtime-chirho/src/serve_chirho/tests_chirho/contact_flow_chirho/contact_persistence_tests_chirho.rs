// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

fn public_object_path_for_contact_test_chirho(
    root_chirho: &std::path::Path,
    hash_chirho: &cairn_chirho::model_chirho::HashChirho,
) -> std::path::PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&hash_chirho.0[0..2])
        .join(&hash_chirho.0[2..])
}

fn panic_text_for_contact_test_chirho(panic_chirho: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text_chirho) = panic_chirho.downcast_ref::<String>() {
        return text_chirho.clone();
    }
    if let Some(text_chirho) = panic_chirho.downcast_ref::<&str>() {
        return (*text_chirho).to_string();
    }
    "non-string panic".to_string()
}

fn assert_contact_privacy_helper_refuses_chirho(
    root_chirho: &std::path::Path,
    write_view_chirho: u64,
    needles_chirho: &[&str],
    expected_chirho: &str,
    forbidden_chirho: &[&str],
) {
    let panic_chirho = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_contact_persisted_surfaces_no_pii_chirho(
            root_chirho,
            &[write_view_chirho],
            needles_chirho,
        );
    }))
    .expect_err("contact-flow privacy regression passed a broken response object");
    let panic_text_chirho = panic_text_for_contact_test_chirho(panic_chirho);
    assert!(
        panic_text_chirho.contains(expected_chirho),
        "privacy helper did not refuse by the expected identity '{expected_chirho}': {panic_text_chirho}"
    );
    for forbidden_chirho in forbidden_chirho {
        assert!(
            !panic_text_chirho.contains(forbidden_chirho),
            "privacy helper confused the refusal with '{forbidden_chirho}': {panic_text_chirho}"
        );
    }
}

#[test]
fn contact_lifecycle_keeps_pii_out_of_persisted_surfaces_chirho() {
    let root_chirho = tenant_root_for_test_chirho("contact-lifecycle-pii-surfaces");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-contact-lifecycle-secret",
    )
    .unwrap();
    let (owner_kind_chirho, owner_id_chirho) = owner_chirho
        .principal_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap();
    let query_caller_chirho = "contact-lifecycle-query-caller";
    let write_dag_chirho = store_write_effect_dag_chirho(&root_chirho, "contacts-chirho/latest");
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact",
        write_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "contact",
        None,
        &owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact/lifecycle-proof".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();

    let query_dag_chirho =
        store_query_effect_dag_chirho(&root_chirho, "contacts-chirho", query_caller_chirho, 10);
    cairn_chirho::app_chirho::deploy_app_route_chirho(
        &root_chirho,
        "contact",
        "contact-list",
        query_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "contact",
        Some("contact-list"),
        &owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let raw_body_chirho =
        br#"{"name_chirho":"Alice Example","email_chirho":"alice@example.com","message_chirho":"Apartment above the bakery near the river"}"#;
    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(raw_body_chirho);
    let pii_needles_chirho = [
        "Alice Example",
        "alice@example.com",
        "Apartment above the bakery near the river",
    ];
    let query_request_chirho = cairn_chirho::effect_chirho::ScopedQueryRequestChirho {
        prefix_chirho: "contacts-chirho".to_string(),
        limit_chirho: Some(10),
    };
    let query_request_bytes_chirho = serde_json::to_vec(&query_request_chirho).unwrap();

    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let write_response_chirho = app_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath("contact".to_string()),
            Bytes::from_static(raw_body_chirho),
        )
        .await;
        let write_status_chirho = write_response_chirho.status();
        let write_body_chirho = axum::body::to_bytes(write_response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let write_text_chirho = String::from_utf8(write_body_chirho.to_vec()).unwrap();
        assert_eq!(write_status_chirho, StatusCode::OK, "{write_text_chirho}");
        assert!(write_text_chirho.contains("app-private-input-ref-v1-chirho"));
        assert_no_contact_pii_chirho(
            "write response",
            write_text_chirho.as_bytes(),
            &pii_needles_chirho,
        );

        let unauth_list_response_chirho = app_route_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(("contact".to_string(), "contact-list".to_string())),
            Bytes::from(query_request_bytes_chirho.clone()),
        )
        .await;
        let unauth_list_body_chirho = assert_fixed_app_execution_http_refusal_chirho(
            unauth_list_response_chirho,
            "QueryEffectChirho",
        )
        .await;
        assert_no_contact_pii_chirho(
            "pre-rollback query refusal",
            &unauth_list_body_chirho,
            &pii_needles_chirho,
        );
    });
    let operator_rows_chirho =
        cairn_chirho::query_chirho::query_prefix_chirho(&root_chirho, "contacts-chirho", 10)
            .unwrap();
    assert_eq!(operator_rows_chirho.len(), 1);
    assert_eq!(operator_rows_chirho[0].key_chirho, "contacts-chirho/latest");
    assert!(operator_rows_chirho[0]
        .value_chirho
        .contains("app-private-input-ref-v1-chirho"));

    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &raw_hash_chirho).is_err());
    // Exactly ONE person blob still holds the submitted body. The other two records are F4
    // store-seal artifacts under the disjoint `app-store/` namespace: the row's own seal and the
    // write effect's now-private response copy. This is the representative site, so it pins the
    // total as well as the roles.
    let blob_records_chirho =
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        non_store_seal_blob_subjects_chirho(&root_chirho),
        vec!["app/contact/lifecycle-proof".to_string()]
    );
    assert_eq!(blob_records_chirho.len(), 3);
    let person_blob_chirho = blob_records_chirho
        .iter()
        .find(|record_chirho| record_chirho.subject_chirho == "app/contact/lifecycle-proof")
        .unwrap();
    assert_eq!(
        cairn_chirho::privacy_chirho::load_private_blob_chirho(
            &root_chirho,
            &person_blob_chirho.blob_chirho,
        )
        .unwrap(),
        raw_body_chirho
    );

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let write_view_chirho = store_chirho.current_view_chirho().unwrap();
    assert!(write_view_chirho > 0);
    let stored_contact_chirho = store_chirho
        .get_chirho("contacts-chirho/latest")
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&stored_contact_chirho).contains("app-private-input-ref-v1-chirho")
    );
    assert_no_contact_pii_chirho(
        "versioned contact row",
        &stored_contact_chirho,
        &pii_needles_chirho,
    );
    drop(store_chirho);

    let reveal_html_chirho = app_state_reveal_html_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        &owner_kind_chirho,
        &owner_id_chirho,
        "contact",
        "contacts-chirho/latest",
    )
    .unwrap();
    assert!(reveal_html_chirho.contains("governed private blob reveal"));
    assert!(reveal_html_chirho.contains("Alice Example"));
    assert!(reveal_html_chirho.contains("alice@example.com"));
    assert!(reveal_html_chirho.contains("Apartment above the bakery near the river"));

    rollback_app_state_view_chirho(&root_chirho, &owner_chirho.principal_chirho, "contact", 0)
        .unwrap();
    let rows_after_rollback_chirho =
        cairn_chirho::query_chirho::query_prefix_chirho(&root_chirho, "contacts-chirho", 10)
            .unwrap();
    assert!(rows_after_rollback_chirho.is_empty());

    runtime_chirho.block_on(async {
        let list_response_chirho = app_route_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath(("contact".to_string(), "contact-list".to_string())),
            Bytes::from(query_request_bytes_chirho),
        )
        .await;
        let list_status_chirho = list_response_chirho.status();
        let list_body_chirho = axum::body::to_bytes(list_response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_text_chirho = String::from_utf8_lossy(&list_body_chirho);
        assert_eq!(
            list_status_chirho,
            StatusCode::BAD_REQUEST,
            "{list_text_chirho}"
        );
        assert!(
            crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(
                &list_text_chirho
            )
            .is_some(),
            "{list_text_chirho}"
        );
        assert!(!list_text_chirho.contains("requires manual review"));
        assert_no_contact_pii_chirho(
            "post-rollback query refusal",
            &list_body_chirho,
            &pii_needles_chirho,
        );
    });

    let volatile_report_chirho =
        cairn_chirho::verify_chirho::verify_volatile_effect_records_chirho(&root_chirho).unwrap();
    assert_eq!(volatile_report_chirho.records_chirho, 0);
    assert_eq!(volatile_report_chirho.objects_chirho, 0);

    // Add one real scoped contact write after the lifecycle assertions above. Unlike the legacy
    // write used by the app fixture, its request and response have distinct hashes, so the response
    // is genuinely absent from public CAS while its verified private record remains. That gives
    // the assertion helper all three public-plane states without weakening the contact-flow setup.
    let privacy_probe_context_chirho = cairn_chirho::model_chirho::RequestContextChirho {
        user_principal_chirho: owner_chirho.principal_chirho.clone(),
        app_chirho: "contact".to_string(),
        owner_principal_chirho: owner_chirho.principal_chirho.clone(),
        client_id_chirho: "contact-privacy-helper-client-chirho".to_string(),
        token_hash_chirho: "contact-privacy-helper-token-hash-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let privacy_probe_value_chirho = b"contact privacy helper safe response chirho";
    let privacy_probe_request_chirho = cairn_chirho::effect_chirho::ScopedWriteStoreRequestChirho {
        schema_chirho: cairn_chirho::effect_chirho::SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "contacts-chirho/privacy-helper-probe".to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(privacy_probe_value_chirho),
    };
    let privacy_probe_effect_chirho = cairn_chirho::effect_chirho::run_effect_with_context_chirho(
        &root_chirho,
        1,
        cairn_chirho::cas_chirho::hash_chirho(b"contact-privacy-helper-idem-chirho"),
        cairn_chirho::model_chirho::CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contacts-chirho".to_string(),
        },
        &serde_json::to_vec(&privacy_probe_request_chirho).unwrap(),
        Some(&privacy_probe_context_chirho),
    )
    .unwrap();
    let private_response_chirho = privacy_probe_effect_chirho.response_chirho.unwrap();
    assert!(
        cairn_chirho::dag_private_value_chirho::verified_private_dag_value_record_chirho(
            &root_chirho,
            &private_response_chirho,
        )
        .unwrap()
        .is_some(),
        "fixture: the real scoped write did not leave a verified private response record"
    );
    assert_contact_persisted_surfaces_no_pii_chirho(
        &root_chirho,
        &[write_view_chirho],
        &pii_needles_chirho,
    );

    // The contact-flow privacy regression itself must distinguish all three public-CAS outcomes.
    // A two-case arm misses the near-fix that rescues UNREADABLE alongside ABSENT. The response's
    // real verified private record stays intact throughout, removing every refusal except the
    // planted public-plane condition from the tamper and unreadable cases.
    assert!(
        matches!(
            cairn_chirho::cas_chirho::read_verified_chirho(&root_chirho, &private_response_chirho),
            cairn_chirho::cas_chirho::CasReadOutcomeChirho::AbsentChirho(_)
        ),
        "control: the sealed response must begin genuinely absent from public CAS"
    );

    let response_path_chirho =
        public_object_path_for_contact_test_chirho(&root_chirho, &private_response_chirho);
    std::fs::create_dir_all(response_path_chirho.parent().unwrap()).unwrap();
    std::fs::write(&response_path_chirho, b"tampered response bytes chirho").unwrap();
    assert!(
        matches!(
            cairn_chirho::cas_chirho::read_verified_chirho(&root_chirho, &private_response_chirho),
            cairn_chirho::cas_chirho::CasReadOutcomeChirho::TamperedChirho { .. }
        ),
        "fixture: the planted bytes did not produce TAMPERED"
    );
    assert_contact_privacy_helper_refuses_chirho(
        &root_chirho,
        write_view_chirho,
        &pii_needles_chirho,
        "re-hashes to",
        &["neither in public CAS", "could not be read"],
    );

    std::fs::remove_file(&response_path_chirho).unwrap();
    std::fs::create_dir(&response_path_chirho).unwrap();
    assert!(
        matches!(
            cairn_chirho::cas_chirho::read_verified_chirho(&root_chirho, &private_response_chirho),
            cairn_chirho::cas_chirho::CasReadOutcomeChirho::UnreadableChirho(_)
        ),
        "fixture: a directory at the object path did not produce UNREADABLE"
    );
    assert_contact_privacy_helper_refuses_chirho(
        &root_chirho,
        write_view_chirho,
        &pii_needles_chirho,
        "could not be read",
        &["neither in public CAS", "re-hashes to"],
    );

    std::fs::remove_dir(&response_path_chirho).unwrap();
    let records_path_chirho = root_chirho.join("private-dag-values-chirho.jsonl");
    let mut private_records_chirho =
        cairn_chirho::dag_private_value_chirho::load_private_dag_value_records_chirho(&root_chirho)
            .unwrap();
    let response_record_chirho = private_records_chirho
        .iter_mut()
        .find(|record_chirho| record_chirho.value_hash_chirho == private_response_chirho)
        .expect("fixture: private response record missing");
    response_record_chirho.sig_chirho = "00".repeat(64);
    let mut private_records_text_chirho = String::new();
    for record_chirho in private_records_chirho {
        private_records_text_chirho.push_str(&serde_json::to_string(&record_chirho).unwrap());
        private_records_text_chirho.push('\n');
    }
    std::fs::write(&records_path_chirho, private_records_text_chirho).unwrap();
    assert_contact_privacy_helper_refuses_chirho(
        &root_chirho,
        write_view_chirho,
        &pii_needles_chirho,
        "signature invalid",
        &["neither in public CAS", "re-hashes to", "could not be read"],
    );

    let access_records_chirho =
        cairn_chirho::privacy_chirho::load_privacy_access_records_chirho(&root_chirho).unwrap();
    assert_eq!(access_records_chirho.len(), 1);
    assert_eq!(
        access_records_chirho[0].accessed_by_chirho,
        owner_chirho.principal_chirho
    );
    assert_eq!(access_records_chirho[0].app_chirho, "contact");
    assert_eq!(
        access_records_chirho[0].row_key_chirho,
        "contacts-chirho/latest"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The structural closure this workstream exists for: an app whose author never sealed anything —
/// PLAIN input mode, the submitted body written straight through the blessed write door — still
/// cannot rest that body in the versioned store.
///
/// The oracle reads the real `.redb` FILE. That matters: every other check in this suite asks our
/// own types what the store holds, and a seal that silently fell through a branch would answer
/// those checks correctly while the bytes sat on disk. This one reads the disk.
#[test]
fn a_plain_mode_app_cannot_rest_its_submitted_body_in_the_redb_file_chirho() {
    let root_chirho = tenant_root_for_test_chirho("plain-mode-redb-file-oracle");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let store_key_chirho = "plainapp-chirho/latest";
    let dag_hash_chirho = store_write_effect_dag_chirho(&root_chirho, store_key_chirho);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "plainapp",
        dag_hash_chirho,
        &owner_chirho,
    )
    .unwrap();
    // PLAIN mode: no private input policy, no F12 envelope, nothing the author did to protect it.
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "plainapp", &owner_chirho);

    let raw_body_chirho = br#"{"schema_chirho":"plainapp-order-v1-chirho","customer_chirho":"Zebediah Planted-Needle chirho","address_chirho":"14 Riverbank Row, Apartment above the bakery"}"#;
    let pii_needles_chirho = [
        "Zebediah Planted-Needle chirho",
        "14 Riverbank Row, Apartment above the bakery",
    ];

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath("plainapp".to_string()),
            Bytes::from_static(raw_body_chirho),
        )
        .await;
        let status_chirho = response_chirho.status();
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&body_chirho)
        );
        // The guest contract is untouched: the write still returns exactly what it wrote.
        assert_eq!(&body_chirho[..], raw_body_chirho);
    });

    // Precondition, so a clean scan below cannot be clean by emptiness: the row really is there,
    // and it really does unseal back to the submitted body.
    assert_eq!(
        sealed_row_plaintext_chirho(&root_chirho, store_key_chirho).unwrap(),
        raw_body_chirho
    );

    // Positive control for the instrument: the same needle IS findable in a file written plainly,
    // so a clean `.redb` scan means the seal worked rather than that the scanner is blind.
    let control_path_chirho = root_chirho.join("planted-control-chirho.txt");
    std::fs::write(&control_path_chirho, raw_body_chirho).unwrap();
    let control_bytes_chirho = std::fs::read(&control_path_chirho).unwrap();
    for needle_chirho in &pii_needles_chirho {
        assert!(control_bytes_chirho
            .windows(needle_chirho.len())
            .any(|window_chirho| window_chirho == needle_chirho.as_bytes()));
    }
    std::fs::remove_file(&control_path_chirho).unwrap();

    // THE ORACLE — raw bytes of the real store file, and of the disposable readmodel beside it.
    cairn_chirho::query_chirho::project_chirho(&root_chirho).unwrap();
    assert_store_files_have_no_contact_pii_chirho(&root_chirho, &pii_needles_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_manifest_contact_list_route_refuses_legacy_query_chirho() {
    let root_chirho = temp_root_chirho("source-manifest-contact-list-route");
    let artifact_dir_chirho = root_chirho.join("artifacts-chirho");
    std::fs::create_dir_all(&artifact_dir_chirho).unwrap();
    let root_artifact_chirho = artifact_dir_chirho.join("root-identity-chirho.wat");
    let request_artifact_chirho = artifact_dir_chirho.join("contact-list-request-chirho.wat");
    let query_artifact_chirho = artifact_dir_chirho.join("query-placeholder-chirho.wat");
    let list_artifact_chirho = artifact_dir_chirho.join("contact-list-render-chirho.wat");
    std::fs::write(
        &root_artifact_chirho,
        include_str!("../../../../../../examples-chirho/node-template-chirho.wat"),
    )
    .unwrap();
    std::fs::write(&request_artifact_chirho, CONTACT_LIST_REQUEST_WAT_CHIRHO).unwrap();
    std::fs::write(
        &query_artifact_chirho,
        include_str!("../../../../../../examples-chirho/node-template-chirho.wat"),
    )
    .unwrap();
    std::fs::write(&list_artifact_chirho, CONTACT_LIST_ROUTE_RENDER_WAT_CHIRHO).unwrap();

    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let query_caller_chirho = "contact-source-query-caller";
    let manifest_chirho = cairn_chirho::app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: cairn_chirho::app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO
            .to_string(),
        app_chirho: "contact".to_string(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho: vec![
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "contact_root".to_string(),
                name_chirho: "contact_root_chirho".to_string(),
                entry_chirho: Some("node_chirho".to_string()),
                fuel_chirho: 1_000_000,
                capabilities_chirho: Vec::new(),
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: root_artifact_chirho,
                    },
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "contact_list_request".to_string(),
                name_chirho: "contact_list_request_chirho".to_string(),
                entry_chirho: Some("contact_list_request_chirho".to_string()),
                fuel_chirho: 1_000_000,
                capabilities_chirho: Vec::new(),
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: request_artifact_chirho,
                    },
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "query_contacts".to_string(),
                name_chirho: "query_contacts_chirho".to_string(),
                entry_chirho: Some("node_chirho".to_string()),
                fuel_chirho: 0,
                capabilities_chirho: vec![
                    format!("query:contacts-chirho:{query_caller_chirho}:50"),
                    format!(
                        "identity:{query_caller_chirho}:source-manifest-client-chirho:source-manifest-token-chirho"
                    ),
                ],
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: query_artifact_chirho,
                    },
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "contact_list_render".to_string(),
                name_chirho: "contact_list_render_chirho".to_string(),
                entry_chirho: Some("contact_list_chirho".to_string()),
                fuel_chirho: 1_000_000,
                capabilities_chirho: Vec::new(),
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: list_artifact_chirho,
                    },
            },
        ],
        dags_chirho: vec![
            cairn_chirho::app_source_manifest_chirho::AppSourceDagManifestChirho {
                id_chirho: "contact_root_dag".to_string(),
                nodes_chirho: vec!["contact_root".to_string()],
                edges_chirho: Vec::new(),
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceDagManifestChirho {
                id_chirho: "contact_list_dag".to_string(),
                nodes_chirho: vec![
                    "contact_list_request".to_string(),
                    "query_contacts".to_string(),
                    "contact_list_render".to_string(),
                ],
                edges_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceDagEdgeManifestChirho {
                        from_node_chirho: "contact_list_request".to_string(),
                        from_port_chirho: "out".to_string(),
                        to_node_chirho: "query_contacts".to_string(),
                        to_port_chirho: "in".to_string(),
                        privacy_chirho: None,
                    },
                    cairn_chirho::app_source_manifest_chirho::AppSourceDagEdgeManifestChirho {
                        from_node_chirho: "query_contacts".to_string(),
                        from_port_chirho: "out".to_string(),
                        to_node_chirho: "contact_list_render".to_string(),
                        to_port_chirho: "in".to_string(),
                        privacy_chirho: None,
                    },
                ],
            },
        ],
        modules_chirho: vec![
            cairn_chirho::app_source_manifest_chirho::AppSourceModuleManifestChirho {
                id_chirho: "contact_root_module".to_string(),
                dag_chirho: "contact_root_dag".to_string(),
                name_chirho: "contact_root_chirho".to_string(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                        public_name_chirho: "request_chirho".to_string(),
                        node_chirho: "contact_root".to_string(),
                        node_port_chirho: "in".to_string(),
                    },
                ],
                output_bindings_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                        public_name_chirho: "response_chirho".to_string(),
                        node_chirho: "contact_root".to_string(),
                        node_port_chirho: "out".to_string(),
                    },
                ],
                route_labels_chirho: vec!["contact-chirho".to_string()],
                metadata_chirho: std::collections::BTreeMap::new(),
                subscription_views_chirho: Vec::new(),
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceModuleManifestChirho {
                id_chirho: "contact_list_module".to_string(),
                dag_chirho: "contact_list_dag".to_string(),
                name_chirho: "contact_list_chirho".to_string(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                        public_name_chirho: "request_chirho".to_string(),
                        node_chirho: "contact_list_request".to_string(),
                        node_port_chirho: "in".to_string(),
                    },
                ],
                output_bindings_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                        public_name_chirho: "response_chirho".to_string(),
                        node_chirho: "contact_list_render".to_string(),
                        node_port_chirho: "out".to_string(),
                    },
                ],
                route_labels_chirho: vec!["contact-list-chirho".to_string()],
                metadata_chirho: std::collections::BTreeMap::new(),
                subscription_views_chirho: Vec::new(),
            },
        ],
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: cairn_chirho::app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                cairn_chirho::app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "contact_root_module".to_string(),
                },
            ),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: vec![
                cairn_chirho::app_source_manifest_chirho::AppSourceDeployRouteManifestChirho {
                    route_chirho: "contact-list".to_string(),
                    source_chirho:
                        cairn_chirho::app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                            id_chirho: "contact_list_module".to_string(),
                        },
                    input_mode_chirho: Some(
                        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
                    ),
                    request_body_policy_chirho: None,
                    response_content_type_chirho: None,
                    params_chirho: None,
                    key_access_chirho: None,
                },
            ],
            runtime_packages_chirho: Vec::new(),
            target_chirho:
                cairn_chirho::app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let report_chirho =
        cairn_chirho::app_source_manifest_chirho::deploy_app_source_manifest_chirho(
            &root_chirho,
            std::path::Path::new("."),
            &manifest_chirho,
        )
        .unwrap();
    let status_chirho =
        cairn_chirho::app_chirho::app_status_chirho(&root_chirho, "contact").unwrap();
    assert_eq!(
        status_chirho.routes_chirho.get("contact-list"),
        Some(&report_chirho.modules_chirho[1].dag_chirho)
    );
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    store_chirho
        .put_chirho(
            "contacts-chirho/submission-001",
            br#"{"schema_chirho":"contact-record-v1-chirho","status_chirho":"received"}"#,
        )
        .unwrap();
    store_chirho
        .put_chirho(
            "contacts-chirho/submission-002",
            br#"{"schema_chirho":"contact-record-v1-chirho","status_chirho":"received"}"#,
        )
        .unwrap();
    drop(store_chirho);
    cairn_chirho::query_chirho::project_chirho(&root_chirho).unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let unauth_response_chirho = app_route_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(("contact".to_string(), "contact-list".to_string())),
            Bytes::new(),
        )
        .await;
        assert_fixed_app_execution_http_refusal_chirho(unauth_response_chirho, "QueryEffectChirho")
            .await;
    });

    assert!(!root_chirho.join("effects-chirho").exists());
    assert!(
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_manifest_contact_app_persists_private_ref_and_refuses_legacy_list_chirho() {
    let root_chirho = tenant_root_for_test_chirho("persisting-contact-app");
    let artifact_dir_chirho = root_chirho.join("artifacts-chirho");
    std::fs::create_dir_all(&artifact_dir_chirho).unwrap();
    let identity_artifact_chirho = artifact_dir_chirho.join("identity-chirho.wat");
    let reify_artifact_chirho = artifact_dir_chirho.join("reify-placeholder-chirho.wat");
    let render_artifact_chirho = artifact_dir_chirho.join("contact-render-chirho.wat");
    let list_request_artifact_chirho = artifact_dir_chirho.join("contact-list-request-chirho.wat");
    let query_artifact_chirho = artifact_dir_chirho.join("query-placeholder-chirho.wat");
    let list_render_artifact_chirho = artifact_dir_chirho.join("contact-list-render-chirho.wat");
    std::fs::write(
        &identity_artifact_chirho,
        include_str!("../../../../../../examples-chirho/node-template-chirho.wat"),
    )
    .unwrap();
    std::fs::write(
        &reify_artifact_chirho,
        include_str!("../../../../../../examples-chirho/node-template-chirho.wat"),
    )
    .unwrap();
    std::fs::write(&render_artifact_chirho, CONTACT_RENDER_PARTIAL_WAT_CHIRHO).unwrap();
    std::fs::write(
        &list_request_artifact_chirho,
        CONTACT_LIST_REQUEST_WAT_CHIRHO,
    )
    .unwrap();
    std::fs::write(
        &query_artifact_chirho,
        include_str!("../../../../../../examples-chirho/node-template-chirho.wat"),
    )
    .unwrap();
    std::fs::write(
        &list_render_artifact_chirho,
        CONTACT_LIST_ROUTE_RENDER_WAT_CHIRHO,
    )
    .unwrap();

    let owner_registration_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-contact-proof-secret",
    )
    .unwrap();
    let owner_chirho = owner_registration_chirho.principal_chirho;
    let (owner_kind_chirho, owner_id_chirho) = owner_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap();
    let owner_login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho,
        "owner-contact-proof-secret",
    )
    .unwrap();
    let mut owner_headers_chirho = HeaderMap::new();
    owner_headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", owner_login_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    let query_caller_chirho = "contact-query-caller";
    let manifest_chirho = cairn_chirho::app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: cairn_chirho::app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO
            .to_string(),
        app_chirho: "contact".to_string(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho: vec![
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "contact_record".to_string(),
                name_chirho: "contact_record_chirho".to_string(),
                entry_chirho: Some("node_chirho".to_string()),
                fuel_chirho: 1_000_000,
                capabilities_chirho: Vec::new(),
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: identity_artifact_chirho,
                    },
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "store_contact".to_string(),
                name_chirho: "store_contact_chirho".to_string(),
                entry_chirho: Some("node_chirho".to_string()),
                fuel_chirho: 0,
                capabilities_chirho: vec![
                    "write-store:contacts-chirho/latest".to_string()
                ],
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: reify_artifact_chirho,
                    },
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "contact_render".to_string(),
                name_chirho: "contact_render_chirho".to_string(),
                entry_chirho: Some("contact_render_chirho".to_string()),
                fuel_chirho: 1_000_000,
                capabilities_chirho: Vec::new(),
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: render_artifact_chirho,
                    },
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "contact_list_request".to_string(),
                name_chirho: "contact_list_request_chirho".to_string(),
                entry_chirho: Some("contact_list_request_chirho".to_string()),
                fuel_chirho: 1_000_000,
                capabilities_chirho: Vec::new(),
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: list_request_artifact_chirho,
                    },
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "query_contacts".to_string(),
                name_chirho: "query_contacts_chirho".to_string(),
                entry_chirho: Some("node_chirho".to_string()),
                fuel_chirho: 0,
                capabilities_chirho: vec![
                    format!("query:contacts-chirho:{query_caller_chirho}:50"),
                    format!(
                        "identity:{query_caller_chirho}:contact-proof-client-chirho:contact-proof-token-chirho"
                    ),
                ],
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: query_artifact_chirho,
                    },
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceNodeManifestChirho {
                id_chirho: "contact_list_render".to_string(),
                name_chirho: "contact_list_render_chirho".to_string(),
                entry_chirho: Some("contact_list_chirho".to_string()),
                fuel_chirho: 1_000_000,
                capabilities_chirho: Vec::new(),
                source_chirho:
                    cairn_chirho::app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                        path_chirho: list_render_artifact_chirho,
                    },
            },
        ],
        dags_chirho: vec![
            cairn_chirho::app_source_manifest_chirho::AppSourceDagManifestChirho {
                id_chirho: "contact_dag".to_string(),
                nodes_chirho: vec![
                    "contact_record".to_string(),
                    "store_contact".to_string(),
                    "contact_render".to_string(),
                ],
                edges_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceDagEdgeManifestChirho {
                        from_node_chirho: "contact_record".to_string(),
                        from_port_chirho: "out".to_string(),
                        to_node_chirho: "store_contact".to_string(),
                        to_port_chirho: "in".to_string(),
                        privacy_chirho: None,
                    },
                    cairn_chirho::app_source_manifest_chirho::AppSourceDagEdgeManifestChirho {
                        from_node_chirho: "store_contact".to_string(),
                        from_port_chirho: "out".to_string(),
                        to_node_chirho: "contact_render".to_string(),
                        to_port_chirho: "in".to_string(),
                        privacy_chirho: None,
                    },
                ],
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceDagManifestChirho {
                id_chirho: "contact_list_dag".to_string(),
                nodes_chirho: vec![
                    "contact_list_request".to_string(),
                    "query_contacts".to_string(),
                    "contact_list_render".to_string(),
                ],
                edges_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceDagEdgeManifestChirho {
                        from_node_chirho: "contact_list_request".to_string(),
                        from_port_chirho: "out".to_string(),
                        to_node_chirho: "query_contacts".to_string(),
                        to_port_chirho: "in".to_string(),
                        privacy_chirho: None,
                    },
                    cairn_chirho::app_source_manifest_chirho::AppSourceDagEdgeManifestChirho {
                        from_node_chirho: "query_contacts".to_string(),
                        from_port_chirho: "out".to_string(),
                        to_node_chirho: "contact_list_render".to_string(),
                        to_port_chirho: "in".to_string(),
                        privacy_chirho: None,
                    },
                ],
            },
        ],
        modules_chirho: vec![
            cairn_chirho::app_source_manifest_chirho::AppSourceModuleManifestChirho {
                id_chirho: "contact_module".to_string(),
                dag_chirho: "contact_dag".to_string(),
                name_chirho: "contact_chirho".to_string(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                        public_name_chirho: "request_chirho".to_string(),
                        node_chirho: "contact_record".to_string(),
                        node_port_chirho: "in".to_string(),
                    },
                ],
                output_bindings_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                        public_name_chirho: "response_chirho".to_string(),
                        node_chirho: "contact_render".to_string(),
                        node_port_chirho: "out".to_string(),
                    },
                ],
                route_labels_chirho: vec!["contact-chirho".to_string()],
                metadata_chirho: std::collections::BTreeMap::new(),
                subscription_views_chirho: Vec::new(),
            },
            cairn_chirho::app_source_manifest_chirho::AppSourceModuleManifestChirho {
                id_chirho: "contact_list_module".to_string(),
                dag_chirho: "contact_list_dag".to_string(),
                name_chirho: "contact_list_chirho".to_string(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                        public_name_chirho: "request_chirho".to_string(),
                        node_chirho: "contact_list_request".to_string(),
                        node_port_chirho: "in".to_string(),
                    },
                ],
                output_bindings_chirho: vec![
                    cairn_chirho::app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                        public_name_chirho: "response_chirho".to_string(),
                        node_chirho: "contact_list_render".to_string(),
                        node_port_chirho: "out".to_string(),
                    },
                ],
                route_labels_chirho: vec!["contact-list-chirho".to_string()],
                metadata_chirho: std::collections::BTreeMap::new(),
                subscription_views_chirho: Vec::new(),
            },
        ],
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: cairn_chirho::app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                cairn_chirho::app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "contact_module".to_string(),
                },
            ),
            input_mode_chirho: Some(
                cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                    subject_chirho: "app/contact/inbox".to_string(),
                    safe_metadata_chirho: Vec::new(),
                },
            ),
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: vec![
                cairn_chirho::app_source_manifest_chirho::AppSourceDeployRouteManifestChirho {
                    route_chirho: "contact-list".to_string(),
                    source_chirho:
                        cairn_chirho::app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                            id_chirho: "contact_list_module".to_string(),
                    },
                    input_mode_chirho: None,
                    request_body_policy_chirho: None,
                    response_content_type_chirho: None,
                    params_chirho: None,
                    key_access_chirho: None,
                },
            ],
            runtime_packages_chirho: Vec::new(),
            target_chirho:
                cairn_chirho::app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let report_chirho =
        cairn_chirho::app_source_manifest_chirho::deploy_app_source_manifest_chirho(
            &root_chirho,
            std::path::Path::new("."),
            &manifest_chirho,
        )
        .unwrap();
    let dag_hash_chirho = report_chirho.modules_chirho[0].dag_chirho.clone();
    let status_chirho =
        cairn_chirho::app_chirho::app_status_chirho(&root_chirho, "contact").unwrap();
    assert_eq!(
        status_chirho.routes_chirho.get("contact-list"),
        Some(&report_chirho.modules_chirho[1].dag_chirho)
    );
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let raw_body_chirho =
        br#"{"name_chirho":"Alice Example","email_chirho":"alice@example.com","message_chirho":"Apartment above the bakery near the river"}"#;
    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(raw_body_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath("contact".to_string()),
            Bytes::from_static(raw_body_chirho),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
        assert!(body_text_chirho.contains("data-contact-chirho=\"received\""));
        assert!(!body_text_chirho.contains("Alice"));
        assert!(!body_text_chirho.contains("alice@example.com"));
        assert!(!body_text_chirho.contains("bakery"));
    });

    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &raw_hash_chirho).is_err());
    // One person blob; the rest are F4 store-seal artifacts under `app-store/`.
    let blob_records_chirho =
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        non_store_seal_blob_subjects_chirho(&root_chirho),
        vec!["app/contact/inbox".to_string()]
    );
    let person_blob_chirho = blob_records_chirho
        .iter()
        .find(|record_chirho| record_chirho.subject_chirho == "app/contact/inbox")
        .unwrap();
    assert_eq!(
        cairn_chirho::privacy_chirho::load_private_blob_chirho(
            &root_chirho,
            &person_blob_chirho.blob_chirho,
        )
        .unwrap(),
        raw_body_chirho
    );

    // The DAG's own value — what the guest wrote and what the effect log references. After F4
    // sealing the row itself is the envelope, so the record is recovered by unsealing it.
    let stored_contact_chirho =
        sealed_row_plaintext_chirho(&root_chirho, "contacts-chirho/latest").unwrap();
    let stored_text_chirho = String::from_utf8(stored_contact_chirho.clone()).unwrap();
    assert!(stored_text_chirho.contains("app-private-input-ref-v1-chirho"));
    assert!(stored_text_chirho.contains("app/contact/inbox"));
    assert!(!stored_text_chirho.contains("Alice"));
    assert!(!stored_text_chirho.contains("alice@example.com"));
    assert!(!stored_text_chirho.contains("bakery"));

    // The at-rest row keeps the labels the console and reveal path read, and nothing else.
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let row_chirho = store_chirho
        .get_chirho("contacts-chirho/latest")
        .unwrap()
        .unwrap();
    drop(store_chirho);
    let cairn_chirho::store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) =
        cairn_chirho::store_seal_chirho::detect_sealed_store_value_chirho(&row_chirho).unwrap()
    else {
        panic!("the served write door left an unsealed contact row");
    };
    assert_eq!(
        sealed_chirho.safe_metadata_chirho.get("schema_chirho"),
        Some(&"app-private-input-ref-v1-chirho".to_string())
    );
    assert_eq!(
        sealed_chirho.safe_metadata_chirho.get("subject_chirho"),
        Some(&"app/contact/inbox".to_string())
    );

    let effects_dir_chirho = root_chirho.join("effects-chirho");
    let effect_paths_chirho = std::fs::read_dir(&effects_dir_chirho)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(effect_paths_chirho.len(), 1);
    let effect_bytes_chirho = std::fs::read(effect_paths_chirho[0].path()).unwrap();
    let effect_text_chirho = String::from_utf8(effect_bytes_chirho.clone()).unwrap();
    assert!(!effect_text_chirho.contains("Alice"));
    assert!(!effect_text_chirho.contains("alice@example.com"));
    assert!(!effect_text_chirho.contains("bakery"));
    let effect_chirho: cairn_chirho::model_chirho::EffectChirho =
        serde_json::from_slice(&effect_bytes_chirho).unwrap();
    cairn_chirho::effect_chirho::verify_effect_chirho(&root_chirho, &effect_chirho).unwrap();
    assert!(matches!(
        effect_chirho.capability_chirho,
        cairn_chirho::model_chirho::CapabilityChirho::WriteStoreChirho {
            ref prefix_chirho
        } if prefix_chirho == "contacts-chirho/latest"
    ));
    assert_eq!(
        cairn_chirho::cas_chirho::get_chirho(&root_chirho, &effect_chirho.request_chirho).unwrap(),
        stored_contact_chirho
    );
    assert_eq!(
        cairn_chirho::cas_chirho::get_chirho(
            &root_chirho,
            effect_chirho.response_chirho.as_ref().unwrap(),
        )
        .unwrap(),
        stored_contact_chirho
    );

    let state_for_rerun_chirho = app_state_for_root_chirho(&root_chirho);
    let admission_chirho = served_admission_for_state_chirho(&state_for_rerun_chirho, 0);
    let rerun_payload_chirho = try_run_chirho(
        &state_for_rerun_chirho,
        &admission_chirho,
        &dag_hash_chirho.0,
        &stored_contact_chirho,
    )
    .unwrap();
    assert!(String::from_utf8(rerun_payload_chirho)
        .unwrap()
        .contains("data-contact-chirho=\"received\""));
    let effect_count_after_rerun_chirho = std::fs::read_dir(&effects_dir_chirho).unwrap().count();
    assert_eq!(effect_count_after_rerun_chirho, 1);

    cairn_chirho::query_chirho::project_chirho(&root_chirho).unwrap();
    runtime_chirho.block_on(async {
        let unauth_list_response_chirho = app_route_post_chirho(
            State(state_for_rerun_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(("contact".to_string(), "contact-list".to_string())),
            Bytes::new(),
        )
        .await;
        let unauth_list_body_chirho = assert_fixed_app_execution_http_refusal_chirho(
            unauth_list_response_chirho,
            "QueryEffectChirho",
        )
        .await;
        assert_no_contact_pii_chirho(
            "source-manifest list refusal",
            &unauth_list_body_chirho,
            &["Alice", "alice@example.com", "bakery"],
        );

        let app_state_response_chirho = app_state_get_chirho(
            State(state_for_rerun_chirho.clone()),
            owner_headers_chirho.clone(),
            AxPath((
                owner_kind_chirho.clone(),
                owner_id_chirho.clone(),
                "contact".to_string(),
            )),
        )
        .await;
        assert_eq!(app_state_response_chirho.status(), StatusCode::OK);
        let app_state_body_chirho =
            axum::body::to_bytes(app_state_response_chirho.into_body(), usize::MAX)
                .await
                .unwrap();
        let app_state_text_chirho = String::from_utf8(app_state_body_chirho.to_vec()).unwrap();
        assert!(app_state_text_chirho.contains("Reveal private body"));
        assert!(app_state_text_chirho.contains("contacts-chirho/latest"));
        assert!(!app_state_text_chirho.contains("Alice"));
        assert!(!app_state_text_chirho.contains("alice@example.com"));
        assert!(!app_state_text_chirho.contains("bakery"));

        let rejected_reveal_chirho = app_state_reveal_post_chirho(
            State(state_for_rerun_chirho.clone()),
            HeaderMap::new(),
            AxPath((
                owner_kind_chirho.clone(),
                owner_id_chirho.clone(),
                "contact".to_string(),
            )),
            Form(AppStateRevealRequestChirho {
                key_chirho: "contacts-chirho/latest".to_string(),
            }),
        )
        .await;
        assert_eq!(rejected_reveal_chirho.status(), StatusCode::UNAUTHORIZED);

        let reveal_chirho = app_state_reveal_post_chirho(
            State(state_for_rerun_chirho.clone()),
            owner_headers_chirho.clone(),
            AxPath((
                owner_kind_chirho.clone(),
                owner_id_chirho.clone(),
                "contact".to_string(),
            )),
            Form(AppStateRevealRequestChirho {
                key_chirho: "contacts-chirho/latest".to_string(),
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

    let mut query_effects_chirho = 0;
    let all_effect_paths_chirho = std::fs::read_dir(&effects_dir_chirho)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(all_effect_paths_chirho.len(), 1);
    for effect_path_chirho in all_effect_paths_chirho {
        let effect_bytes_chirho = std::fs::read(effect_path_chirho.path()).unwrap();
        let effect_text_chirho = String::from_utf8(effect_bytes_chirho.clone()).unwrap();
        assert!(!effect_text_chirho.contains("Alice"));
        assert!(!effect_text_chirho.contains("alice@example.com"));
        assert!(!effect_text_chirho.contains("bakery"));
        let effect_chirho: cairn_chirho::model_chirho::EffectChirho =
            serde_json::from_slice(&effect_bytes_chirho).unwrap();
        cairn_chirho::effect_chirho::verify_effect_chirho(&root_chirho, &effect_chirho).unwrap();
        if matches!(
            effect_chirho.capability_chirho,
            cairn_chirho::model_chirho::CapabilityChirho::QueryChirho { .. }
        ) {
            query_effects_chirho += 1;
            let query_request_chirho =
                cairn_chirho::cas_chirho::get_chirho(&root_chirho, &effect_chirho.request_chirho)
                    .unwrap();
            assert_eq!(
                String::from_utf8(query_request_chirho).unwrap(),
                r#"{"prefix_chirho":"contacts-chirho","limit_chirho":50}"#
            );
        }
    }
    assert_eq!(query_effects_chirho, 0);
    assert!(
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );

    let access_records_chirho =
        privacy_chirho::load_privacy_access_records_chirho(&root_chirho).unwrap();
    assert_eq!(access_records_chirho.len(), 1);
    assert_eq!(access_records_chirho[0].accessed_by_chirho, owner_chirho);
    assert_eq!(access_records_chirho[0].app_chirho, "contact");
    assert_eq!(
        access_records_chirho[0].row_key_chirho,
        "contacts-chirho/latest"
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
    assert!(!access_log_chirho.contains("Alice"));
    assert!(!access_log_chirho.contains("alice@example.com"));
    assert!(!access_log_chirho.contains("bakery"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
