// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
#[cfg_attr(
    not(feature = "operator-smoke-tests-chirho"),
    ignore = "operator smoke: builds wasm32 cargo examples and runs live contact source-manifest HTTP flow; enable with --features operator-smoke-tests-chirho"
)]
fn contact_example_source_manifest_serves_live_contact_page_chirho() {
    let root_chirho = tenant_root_for_test_chirho("contact-example-source-manifest-live");
    let owner_registration_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-contact-example-secret",
    )
    .unwrap();
    let owner_chirho = owner_registration_chirho.principal_chirho;
    let owner_login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho,
        "owner-contact-example-secret",
    )
    .unwrap();
    let (owner_kind_chirho, owner_id_chirho) = owner_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap();
    let manifest_path_chirho = contact_example_manifest_path_chirho();
    let manifest_base_chirho = manifest_path_chirho.parent().unwrap().to_path_buf();
    let manifest_chirho = contact_example_manifest_for_owner_chirho(&owner_chirho);
    let report_chirho =
        cairn_chirho::app_source_manifest_chirho::deploy_app_source_manifest_chirho(
            &root_chirho,
            &manifest_base_chirho,
            &manifest_chirho,
        )
        .unwrap();
    assert_eq!(
        report_chirho.schema_chirho,
        cairn_chirho::app_source_manifest_chirho::APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_chirho.nodes_chirho.len(), 6);
    assert_eq!(report_chirho.modules_chirho.len(), 2);
    let status_chirho =
        cairn_chirho::app_chirho::app_status_chirho(&root_chirho, "contact").unwrap();
    assert_eq!(
        status_chirho.routes_chirho.get("contact-list"),
        Some(&report_chirho.modules_chirho[1].dag_chirho)
    );

    let raw_body_chirho =
        b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Apartment+above+the+bakery";
    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(raw_body_chirho);
    let pii_needles_chirho = ["Alice", "alice@example.com", "bakery"];
    let owner_bearer_chirho = format!("Bearer {}", owner_login_chirho.token_chirho);
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let contact_key_chirho = runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let page_response_chirho = http_get_for_smoke_chirho(&addr_chirho, "/contact-demo-chirho");
        assert_eq!(page_response_chirho.status_chirho, 200);
        let page_html_chirho = http_body_text_chirho(&page_response_chirho);
        assert!(page_html_chirho.contains("hx-post=\"/app-chirho/contact\""));
        assert!(page_html_chirho.contains("hx-post=\"/app-chirho/contact/contact-list\""));
        assert!(!page_html_chirho.contains("https://"));

        let htmx_smoke_ran_chirho =
            htmx_lite_real_server_smoke_chirho(&format!("http://{addr_chirho}"));
        if !htmx_smoke_ran_chirho {
            let submit_response_chirho = http_request_for_smoke_chirho(
                &addr_chirho,
                "POST",
                "/app-chirho/contact",
                &[(
                    "content-type",
                    "application/x-www-form-urlencoded;charset=UTF-8",
                )],
                raw_body_chirho,
            );
            assert_eq!(submit_response_chirho.status_chirho, 200);
            let submit_text_chirho = http_body_text_chirho(&submit_response_chirho);
            assert!(submit_text_chirho.contains("data-contact-chirho=\"received\""));
            assert_no_contact_pii_chirho(
                "source-manifest HTTP submit response",
                submit_text_chirho.as_bytes(),
                &pii_needles_chirho,
            );

            let list_response_chirho = http_request_for_smoke_chirho(
                &addr_chirho,
                "POST",
                "/app-chirho/contact/contact-list",
                &[],
                b"",
            );
            assert_eq!(list_response_chirho.status_chirho, 400);
            let list_text_chirho = http_body_text_chirho(&list_response_chirho);
            assert!(
                crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(
                    &list_text_chirho
                )
                .is_some(),
                "{list_text_chirho}"
            );
            assert_no_contact_pii_chirho(
                "source-manifest HTTP list response",
                list_text_chirho.as_bytes(),
                &pii_needles_chirho,
            );
        }

        let rows_chirho =
            cairn_chirho::query_chirho::query_prefix_chirho(&root_chirho, "contacts-chirho", 50)
                .unwrap();
        assert_eq!(rows_chirho.len(), 1);
        let contact_key_chirho = rows_chirho[0].key_chirho.clone();
        assert!(contact_key_chirho.starts_with("contacts-chirho/"));
        assert_ne!(contact_key_chirho, "contacts-chirho/latest");
        assert!(rows_chirho[0]
            .value_chirho
            .contains("contact-record-v1-chirho"));
        assert_no_contact_pii_chirho(
            "source-manifest query row",
            rows_chirho[0].value_chirho.as_bytes(),
            &pii_needles_chirho,
        );

        let app_state_path_chirho =
            format!("/app-state-chirho/{owner_kind_chirho}/{owner_id_chirho}/contact");
        let missing_owner_session_chirho =
            http_request_for_smoke_chirho(&addr_chirho, "GET", &app_state_path_chirho, &[], b"");
        assert_eq!(missing_owner_session_chirho.status_chirho, 401);

        let app_state_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &app_state_path_chirho,
            &[("authorization", owner_bearer_chirho.as_str())],
            b"",
        );
        assert_eq!(app_state_response_chirho.status_chirho, 200);
        let app_state_text_chirho = http_body_text_chirho(&app_state_response_chirho);
        assert!(app_state_text_chirho.contains("Reveal private body"));
        assert!(app_state_text_chirho.contains(&contact_key_chirho));
        assert_no_contact_pii_chirho(
            "source-manifest app-state response",
            app_state_text_chirho.as_bytes(),
            &pii_needles_chirho,
        );

        let reveal_body_chirho = format!("key_chirho={contact_key_chirho}");
        let reveal_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{app_state_path_chirho}/reveal-chirho"),
            &[
                ("authorization", owner_bearer_chirho.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            reveal_body_chirho.as_bytes(),
        );
        assert_eq!(reveal_response_chirho.status_chirho, 200);
        let reveal_text_chirho = http_body_text_chirho(&reveal_response_chirho);
        assert!(reveal_text_chirho.contains("governed private blob reveal"));
        assert!(reveal_text_chirho.contains("name_chirho=Alice+Example"));
        assert!(reveal_text_chirho.contains("email_chirho=alice%40example.com"));
        assert!(reveal_text_chirho.contains("message_chirho=Apartment+above+the+bakery"));

        server_chirho.abort();
        contact_key_chirho
    });

    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &raw_hash_chirho).is_err());
    let blob_records_chirho =
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        non_store_seal_blob_subjects_chirho(&root_chirho),
        vec!["app/contact/inbox".to_string()],
        "the contact flow must persist exactly one non-store private subject"
    );
    let contact_blob_records_chirho: Vec<_> = blob_records_chirho
        .iter()
        .filter(|record_chirho| record_chirho.subject_chirho == "app/contact/inbox")
        .collect();
    assert_eq!(contact_blob_records_chirho.len(), 1);
    assert_eq!(
        contact_blob_records_chirho[0].subject_chirho,
        "app/contact/inbox"
    );
    assert_eq!(
        cairn_chirho::privacy_chirho::load_private_blob_chirho(
            &root_chirho,
            &contact_blob_records_chirho[0].blob_chirho,
        )
        .unwrap(),
        raw_body_chirho
    );

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let contact_view_chirho = store_chirho.current_view_chirho().unwrap();
    let stored_contact_chirho = store_chirho
        .get_chirho(&contact_key_chirho)
        .unwrap()
        .unwrap();
    let stored_contact_text_chirho = String::from_utf8(stored_contact_chirho).unwrap();
    assert!(stored_contact_text_chirho.contains("contact-record-v1-chirho"));
    assert!(stored_contact_text_chirho.contains("app/contact/inbox"));
    assert!(stored_contact_text_chirho.contains("ciphertext_chirho"));
    assert_no_contact_pii_chirho(
        "source-manifest versioned row",
        stored_contact_text_chirho.as_bytes(),
        &pii_needles_chirho,
    );
    drop(store_chirho);

    let effects_dir_chirho = root_chirho.join("effects-chirho");
    for effect_path_chirho in std::fs::read_dir(&effects_dir_chirho).unwrap() {
        let effect_path_chirho = effect_path_chirho.unwrap().path();
        let effect_bytes_chirho = std::fs::read(&effect_path_chirho).unwrap();
        assert_no_contact_pii_chirho(
            &format!("source-manifest effect {}", effect_path_chirho.display()),
            &effect_bytes_chirho,
            &pii_needles_chirho,
        );
        let effect_chirho: cairn_chirho::model_chirho::EffectChirho =
            serde_json::from_slice(&effect_bytes_chirho).unwrap();
        cairn_chirho::effect_chirho::verify_effect_chirho(&root_chirho, &effect_chirho).unwrap();
    }
    let volatile_report_chirho =
        cairn_chirho::verify_chirho::verify_volatile_effect_records_chirho(&root_chirho).unwrap();
    assert_eq!(volatile_report_chirho.records_chirho, 0);
    let volatile_rows_chirho =
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho).unwrap();
    assert!(volatile_rows_chirho.is_empty());
    for record_chirho in &volatile_rows_chirho {
        let record_text_chirho = serde_json::to_string(record_chirho).unwrap();
        assert_no_contact_pii_chirho(
            "source-manifest volatile effect row",
            record_text_chirho.as_bytes(),
            &pii_needles_chirho,
        );
    }

    let access_records_chirho =
        privacy_chirho::load_privacy_access_records_chirho(&root_chirho).unwrap();
    assert_eq!(access_records_chirho.len(), 1);
    assert_eq!(access_records_chirho[0].accessed_by_chirho, owner_chirho);
    assert_eq!(access_records_chirho[0].app_chirho, "contact");
    assert_eq!(access_records_chirho[0].row_key_chirho, contact_key_chirho);
    assert_eq!(
        access_records_chirho[0].purpose_chirho,
        "owner-contact-reveal-chirho"
    );
    let access_log_chirho =
        std::fs::read_to_string(root_chirho.join("privacy-access-records-chirho.jsonl")).unwrap();
    assert_no_contact_pii_chirho(
        "source-manifest access log",
        access_log_chirho.as_bytes(),
        &pii_needles_chirho,
    );
    assert_contact_persisted_surfaces_no_pii_chirho(
        &root_chirho,
        &[contact_view_chirho],
        &pii_needles_chirho,
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
#[cfg_attr(
    not(feature = "operator-smoke-tests-chirho"),
    ignore = "operator smoke: builds wasm32 cargo examples and runs live perffection intake source-manifest HTTP flow; enable with --features operator-smoke-tests-chirho"
)]
fn perffection_intake_source_manifest_serves_private_dogfood_path_chirho() {
    let root_chirho = tenant_root_for_test_chirho("perffection-intake-source-manifest-live");
    let owner_registration_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-perffection-intake-secret",
    )
    .unwrap();
    let owner_chirho = owner_registration_chirho.principal_chirho;
    let owner_login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho,
        "owner-perffection-intake-secret",
    )
    .unwrap();
    let (owner_kind_chirho, owner_id_chirho) = owner_chirho
        .split_once('/')
        .map(|(kind_chirho, id_chirho)| (kind_chirho.to_string(), id_chirho.to_string()))
        .unwrap();
    let manifest_path_chirho = perffection_intake_manifest_path_chirho();
    let manifest_bytes_chirho = std::fs::read(&manifest_path_chirho).unwrap();
    let manifest_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(&manifest_bytes_chirho);
    let deploy_chirho =
        cairn_chirho::app_source_manifest_chirho::deploy_app_source_manifest_from_path_for_owner_chirho(
            &root_chirho,
            &manifest_path_chirho,
            &owner_chirho,
        )
        .unwrap();
    assert_eq!(
        deploy_chirho.schema_chirho,
        cairn_chirho::app_source_manifest_chirho::APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(deploy_chirho.app_chirho, "perffection");
    assert_eq!(deploy_chirho.nodes_chirho.len(), 6);
    assert_eq!(deploy_chirho.modules_chirho.len(), 2);
    let status_chirho =
        cairn_chirho::app_chirho::app_status_chirho(&root_chirho, "perffection").unwrap();
    assert_eq!(
        status_chirho.routes_chirho.get("intake-list"),
        Some(&deploy_chirho.modules_chirho[1].dag_chirho)
    );

    let raw_body_chirho =
        b"business_name_chirho=Covenant+Cakes&owner_name_chirho=Miriam+Grace&email_chirho=miriam%40gracecakes.example&notes_chirho=Blue+awning+needs+calendar";
    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(raw_body_chirho);
    let pii_needles_chirho = ["Covenant", "Miriam", "miriam@gracecakes.example", "Blue"];
    let owner_bearer_chirho = format!("Bearer {}", owner_login_chirho.token_chirho);
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let perffection_key_chirho = runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let index_response_chirho = http_get_for_smoke_chirho(&addr_chirho, "/");
        assert_eq!(index_response_chirho.status_chirho, 200);
        let index_html_chirho = http_body_text_chirho(&index_response_chirho);
        assert!(index_html_chirho.contains("/perffection-intake-demo-chirho"));

        let page_response_chirho =
            http_get_for_smoke_chirho(&addr_chirho, "/perffection-intake-demo-chirho");
        assert_eq!(page_response_chirho.status_chirho, 200);
        let page_html_chirho = http_body_text_chirho(&page_response_chirho);
        assert!(page_html_chirho.contains("/htmx-lite-chirho.js"));
        assert!(page_html_chirho.contains("hx-post=\"/app-chirho/perffection\""));
        assert!(page_html_chirho.contains("hx-post=\"/app-chirho/perffection/intake-list\""));
        assert!(!page_html_chirho.contains("unpkg.com"));
        assert!(!page_html_chirho.contains("https://"));
        assert_no_contact_pii_chirho(
            "perffection intake page",
            page_html_chirho.as_bytes(),
            &pii_needles_chirho,
        );

        let submit_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/perffection",
            &[(
                "content-type",
                "application/x-www-form-urlencoded;charset=UTF-8",
            )],
            raw_body_chirho,
        );
        assert_eq!(submit_response_chirho.status_chirho, 200);
        let submit_text_chirho = http_body_text_chirho(&submit_response_chirho);
        assert!(submit_text_chirho.contains("data-perffection-intake-chirho=\"received\""));
        assert_no_contact_pii_chirho(
            "perffection intake submit response",
            submit_text_chirho.as_bytes(),
            &pii_needles_chirho,
        );

        let list_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/perffection/intake-list",
            &[],
            b"",
        );
        assert_eq!(list_response_chirho.status_chirho, 400);
        let list_text_chirho = http_body_text_chirho(&list_response_chirho);
        assert!(
            crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(
                &list_text_chirho
            )
            .is_some(),
            "{list_text_chirho}"
        );
        assert_no_contact_pii_chirho(
            "perffection intake list response",
            list_text_chirho.as_bytes(),
            &pii_needles_chirho,
        );

        let rows_chirho = cairn_chirho::query_chirho::query_prefix_chirho(
            &root_chirho,
            "perffection-intake-chirho",
            50,
        )
        .unwrap();
        assert_eq!(rows_chirho.len(), 1);
        let perffection_key_chirho = rows_chirho[0].key_chirho.clone();
        assert!(perffection_key_chirho.starts_with("perffection-intake-chirho/"));
        assert!(rows_chirho[0]
            .value_chirho
            .contains("perffection-intake-record-v1-chirho"));
        assert_no_contact_pii_chirho(
            "perffection intake query row",
            rows_chirho[0].value_chirho.as_bytes(),
            &pii_needles_chirho,
        );

        let app_state_path_chirho =
            format!("/app-state-chirho/{owner_kind_chirho}/{owner_id_chirho}/perffection");
        let missing_owner_session_chirho =
            http_request_for_smoke_chirho(&addr_chirho, "GET", &app_state_path_chirho, &[], b"");
        assert_eq!(missing_owner_session_chirho.status_chirho, 401);

        let app_state_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &app_state_path_chirho,
            &[("authorization", owner_bearer_chirho.as_str())],
            b"",
        );
        assert_eq!(app_state_response_chirho.status_chirho, 200);
        let app_state_text_chirho = http_body_text_chirho(&app_state_response_chirho);
        assert!(app_state_text_chirho.contains("Safe app rows"));
        assert!(app_state_text_chirho.contains("Reveal private body"));
        assert!(app_state_text_chirho.contains(&perffection_key_chirho));
        assert_no_contact_pii_chirho(
            "perffection intake app-state response",
            app_state_text_chirho.as_bytes(),
            &pii_needles_chirho,
        );

        let reveal_body_chirho = format!("key_chirho={perffection_key_chirho}");
        let reveal_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{app_state_path_chirho}/reveal-chirho"),
            &[
                ("authorization", owner_bearer_chirho.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            reveal_body_chirho.as_bytes(),
        );
        assert_eq!(reveal_response_chirho.status_chirho, 200);
        let reveal_text_chirho = http_body_text_chirho(&reveal_response_chirho);
        assert!(reveal_text_chirho.contains("governed private blob reveal"));
        assert!(reveal_text_chirho.contains("business_name_chirho=Covenant+Cakes"));
        assert!(reveal_text_chirho.contains("owner_name_chirho=Miriam+Grace"));
        assert!(reveal_text_chirho.contains("email_chirho=miriam%40gracecakes.example"));
        assert!(reveal_text_chirho.contains("notes_chirho=Blue+awning+needs+calendar"));

        server_chirho.abort();
        perffection_key_chirho
    });

    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &raw_hash_chirho).is_err());
    let blob_records_chirho =
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    // F4 store sealing mints one key per row version, so a root-wide count also includes the
    // disjoint `app-store/` and `operator-store/` lifecycle subjects. Count this flow's person blob
    // at its own erasure coordinate while checking the whole non-store population first, so a new
    // unexpected subject remains visible even when the cardinality assertion fails.
    let non_store_subjects_chirho = non_store_seal_blob_subjects_chirho(&root_chirho);
    assert_eq!(
        non_store_subjects_chirho,
        vec!["app/perffection/intake".to_string()],
        "the intake flow must persist exactly one non-store private subject"
    );
    let intake_blob_records_chirho: Vec<_> = blob_records_chirho
        .iter()
        .filter(|record_chirho| record_chirho.subject_chirho == "app/perffection/intake")
        .collect();
    assert_eq!(intake_blob_records_chirho.len(), 1);
    assert_eq!(
        intake_blob_records_chirho[0].subject_chirho,
        "app/perffection/intake"
    );
    assert_eq!(
        cairn_chirho::privacy_chirho::load_private_blob_chirho(
            &root_chirho,
            &intake_blob_records_chirho[0].blob_chirho,
        )
        .unwrap(),
        raw_body_chirho
    );

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let perffection_view_chirho = store_chirho.current_view_chirho().unwrap();
    let stored_chirho = store_chirho
        .get_chirho(&perffection_key_chirho)
        .unwrap()
        .unwrap();
    let stored_text_chirho = String::from_utf8(stored_chirho).unwrap();
    assert!(stored_text_chirho.contains("perffection-intake-record-v1-chirho"));
    assert!(stored_text_chirho.contains("app/perffection/intake"));
    assert!(stored_text_chirho.contains("ciphertext_chirho"));
    assert_no_contact_pii_chirho(
        "perffection intake versioned row",
        stored_text_chirho.as_bytes(),
        &pii_needles_chirho,
    );
    drop(store_chirho);

    assert_contact_persisted_surfaces_no_pii_chirho(
        &root_chirho,
        &[perffection_view_chirho],
        &pii_needles_chirho,
    );
    let perffection_rows_chirho = cairn_chirho::query_chirho::query_prefix_chirho(
        &root_chirho,
        "perffection-intake-chirho",
        50,
    )
    .unwrap();
    assert_eq!(perffection_rows_chirho.len(), 1);
    assert_no_contact_pii_chirho(
        "perffection read model key",
        perffection_rows_chirho[0].key_chirho.as_bytes(),
        &pii_needles_chirho,
    );
    assert_no_contact_pii_chirho(
        "perffection read model value",
        perffection_rows_chirho[0].value_chirho.as_bytes(),
        &pii_needles_chirho,
    );

    let volatile_report_chirho =
        cairn_chirho::verify_chirho::verify_volatile_effect_records_chirho(&root_chirho).unwrap();
    assert_eq!(volatile_report_chirho.records_chirho, 0);
    assert!(
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap()
            .is_empty()
    );

    let access_records_chirho =
        privacy_chirho::load_privacy_access_records_chirho(&root_chirho).unwrap();
    assert_eq!(access_records_chirho.len(), 1);
    assert_eq!(access_records_chirho[0].accessed_by_chirho, owner_chirho);
    assert_eq!(access_records_chirho[0].app_chirho, "perffection");
    assert_eq!(
        access_records_chirho[0].row_key_chirho,
        perffection_key_chirho
    );
    assert_eq!(
        access_records_chirho[0].purpose_chirho,
        "owner-app-state-reveal-chirho"
    );
    assert_no_contact_pii_chirho(
        "perffection access record",
        serde_json::to_string(&access_records_chirho[0])
            .unwrap()
            .as_bytes(),
        &pii_needles_chirho,
    );
    assert_eq!(
        privacy_chirho::verify_privacy_logs_chirho(&root_chirho)
            .unwrap()
            .access_records_chirho,
        1
    );
    let privacy_scan_chirho = privacy_chirho::scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(
        privacy_scan_chirho.findings_chirho.is_empty(),
        "perffection intake privacy scan findings: {:?}",
        privacy_scan_chirho.findings_chirho
    );
    assert!(!manifest_hash_chirho.0.is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn served_app_control_plane_tamper_fails_before_side_effects_chirho() {
    let raw_body_chirho =
        b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Apartment+above+the+bakery";
    let pii_needles_chirho = ["Alice", "alice@example.com", "bakery"];

    let baseline_chirho =
        contact_control_plane_http_fixture_chirho("served-control-plane-baseline");
    let baseline_response_chirho =
        post_contact_app_over_http_chirho(&baseline_chirho.root_chirho, raw_body_chirho);
    assert_eq!(baseline_response_chirho.status_chirho, 200);
    assert_no_contact_pii_chirho(
        "baseline submit response",
        &baseline_response_chirho.body_chirho,
        &pii_needles_chirho,
    );
    // One person blob; F4 store-seal artifacts live in the disjoint `app-store/` namespace.
    assert_eq!(
        non_store_seal_blob_subjects_chirho(&baseline_chirho.root_chirho).len(),
        1
    );
    let baseline_store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &baseline_chirho.root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert!(baseline_store_chirho
        .get_chirho("contacts-chirho/latest")
        .unwrap()
        .is_some());
    drop(baseline_store_chirho);
    let baseline_list_response_chirho = post_contact_route_over_http_chirho(
        &baseline_chirho.root_chirho,
        "/app-chirho/contact/contact-list",
        b"",
    );
    assert_eq!(
        baseline_list_response_chirho.status_chirho,
        400,
        "{}",
        String::from_utf8_lossy(&baseline_list_response_chirho.body_chirho)
    );
    assert_no_contact_pii_chirho(
        "baseline list refusal",
        &baseline_list_response_chirho.body_chirho,
        &pii_needles_chirho,
    );
    assert!(
        crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(
            &String::from_utf8_lossy(&baseline_list_response_chirho.body_chirho)
        )
        .is_some()
    );
    assert!(
        !std::fs::read_dir(baseline_chirho.root_chirho.join("runs-chirho"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(&baseline_chirho.root_chirho);

    let forged_app_ref_chirho =
        contact_control_plane_http_fixture_chirho("served-control-plane-forged-app-ref");
    refs_chirho::set_branch_chirho(
        &forged_app_ref_chirho.root_chirho,
        "app/contact",
        store_empty_dag_chirho(&forged_app_ref_chirho.root_chirho),
    )
    .unwrap();
    let forged_app_response_chirho =
        post_contact_app_over_http_chirho(&forged_app_ref_chirho.root_chirho, raw_body_chirho);
    assert_served_control_plane_attack_blocked_chirho(
        &forged_app_ref_chirho.root_chirho,
        &forged_app_response_chirho,
        raw_body_chirho,
        &pii_needles_chirho,
        400,
        Some("app-selection-refused-chirho"),
    );
    assert_verifier_names_chirho(
        cairn_chirho::app_chirho::resolve_app_dag_chirho(
            &forged_app_ref_chirho.root_chirho,
            &refs_chirho::load_refs_chirho(&forged_app_ref_chirho.root_chirho).unwrap(),
            "contact",
        )
        .map(|_resolved_chirho| ()),
        "ref does not match any signed app deploy record",
    );
    let _ = std::fs::remove_dir_all(&forged_app_ref_chirho.root_chirho);

    let forged_route_ref_chirho =
        contact_control_plane_http_fixture_chirho("served-control-plane-forged-route-ref");
    refs_chirho::set_branch_chirho(
        &forged_route_ref_chirho.root_chirho,
        "app-route/contact/contact-list",
        store_empty_dag_chirho(&forged_route_ref_chirho.root_chirho),
    )
    .unwrap();
    let forged_route_response_chirho = post_contact_route_over_http_chirho(
        &forged_route_ref_chirho.root_chirho,
        "/app-chirho/contact/contact-list",
        raw_body_chirho,
    );
    assert_served_control_plane_attack_blocked_chirho(
        &forged_route_ref_chirho.root_chirho,
        &forged_route_response_chirho,
        raw_body_chirho,
        &pii_needles_chirho,
        405,
        None,
    );
    let _ = std::fs::remove_dir_all(&forged_route_ref_chirho.root_chirho);

    let tampered_policy_chirho =
        contact_control_plane_http_fixture_chirho("served-control-plane-tampered-policy");
    let mut policy_records_chirho = cairn_chirho::app_chirho::load_app_input_policy_records_chirho(
        &tampered_policy_chirho.root_chirho,
    )
    .unwrap();
    policy_records_chirho[0].mode_chirho =
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho;
    write_jsonl_rows_chirho(
        &tampered_policy_chirho
            .root_chirho
            .join("app-input-policy-records-chirho.jsonl"),
        &policy_records_chirho,
    );
    let tampered_policy_response_chirho =
        post_contact_app_over_http_chirho(&tampered_policy_chirho.root_chirho, raw_body_chirho);
    assert_served_control_plane_attack_blocked_chirho(
        &tampered_policy_chirho.root_chirho,
        &tampered_policy_response_chirho,
        raw_body_chirho,
        &pii_needles_chirho,
        400,
        Some("app-selection-refused-chirho"),
    );
    assert_verifier_names_chirho(
        contact_input_mode_chirho(&tampered_policy_chirho.root_chirho),
        "app input policy record 0 signature invalid",
    );
    let _ = std::fs::remove_dir_all(&tampered_policy_chirho.root_chirho);

    let missing_policy_chirho =
        contact_control_plane_http_fixture_chirho("served-control-plane-missing-policy");
    std::fs::write(
        missing_policy_chirho
            .root_chirho
            .join("app-input-policy-records-chirho.jsonl"),
        "",
    )
    .unwrap();
    let missing_policy_response_chirho =
        post_contact_app_over_http_chirho(&missing_policy_chirho.root_chirho, raw_body_chirho);
    assert_served_control_plane_attack_blocked_chirho(
        &missing_policy_chirho.root_chirho,
        &missing_policy_response_chirho,
        raw_body_chirho,
        &pii_needles_chirho,
        400,
        Some("app-input-refused-chirho"),
    );
    assert_verifier_names_chirho(
        contact_input_mode_chirho(&missing_policy_chirho.root_chirho),
        "needs a signed input policy",
    );
    let _ = std::fs::remove_dir_all(&missing_policy_chirho.root_chirho);
}

/// Warm-cache twin of `served_app_control_plane_tamper_fails_before_side_effects_chirho`. Every cold
/// negative above attacks a FRESH root, so the very first verify IS the attack — none prove a WARM
/// verified-view cache (crates/support-chirho/cairn-verified-view-cache-chirho, consumed through the
/// root `app_chirho` glue) is dropped the instant a signed record changes on disk. Here one real
/// successful serve WARMS that cache, then a signed app record is tampered, and the next request
/// through the same path must fail closed: no stale payload from the warm view, and no new
/// blob/run/effect/stored row.
#[test]
fn served_app_control_plane_tamper_fails_after_warm_serve_chirho() {
    let raw_body_chirho =
        b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Apartment+above+the+bakery";
    let pii_needles_chirho = ["Alice", "alice@example.com", "bakery"];

    let fixture_chirho =
        contact_control_plane_http_fixture_chirho("served-control-plane-warm-tamper");
    let root_chirho = fixture_chirho.root_chirho.clone();

    let count_dir_entries_chirho = |path_chirho: &std::path::Path| -> usize {
        std::fs::read_dir(path_chirho)
            .map(|entries_chirho| entries_chirho.count())
            .unwrap_or(0)
    };

    // (2) One real successful serve populates the process-global verified-view cache for this root.
    let warm_response_chirho = post_contact_app_over_http_chirho(&root_chirho, raw_body_chirho);
    assert_eq!(
        warm_response_chirho.status_chirho,
        200,
        "warm serve must succeed before the tamper: {}",
        String::from_utf8_lossy(&warm_response_chirho.body_chirho)
    );
    assert!(
        String::from_utf8_lossy(&warm_response_chirho.body_chirho)
            .contains("data-contact-chirho=\"received\""),
        "warm serve must return the rendered contact partial"
    );
    assert_no_contact_pii_chirho(
        "warm submit response",
        &warm_response_chirho.body_chirho,
        &pii_needles_chirho,
    );

    // (3) Baselines AFTER the successful serve: exactly one private blob, the stored contact row, and
    // a non-empty runs dir. A warm-cache bypass on the next (tampered) request would grow one of them.
    let blob_baseline_chirho =
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
            .unwrap()
            .len();
    // The growth check below is what this baseline is for, so it stays a TOTAL. Its person-blob
    // half is asserted separately: one submitted body, the rest F4 store-seal artifacts.
    assert_eq!(
        non_store_seal_blob_subjects_chirho(&root_chirho).len(),
        1,
        "warm serve must persist exactly one person blob"
    );
    // The exact number of private intermediate/store-seal artifacts is an implementation detail.
    // The person-blob assertion above and the no-growth equality below carry the privacy claim.
    let runs_baseline_chirho = count_dir_entries_chirho(&root_chirho.join("runs-chirho"));
    assert!(
        runs_baseline_chirho > 0,
        "warm serve must record at least one run"
    );
    let effects_baseline_chirho = count_dir_entries_chirho(&root_chirho.join("effects-chirho"));
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let contact_latest_baseline_chirho = store_chirho.get_chirho("contacts-chirho/latest").unwrap();
    assert!(
        contact_latest_baseline_chirho.is_some(),
        "warm serve must store contacts-chirho/latest"
    );
    let entries_baseline_chirho = store_chirho.current_entries_chirho().unwrap().len();
    drop(store_chirho);

    // (4) Tamper the signed app deploy record so its Ed25519 signature no longer matches — the same
    // class of on-disk control-plane tamper as
    // `verified_app_owner_rejects_tampered_last_record_chirho`. We mutate `at_ms_chirho` (a signed
    // field the verifier checks only via the signature, after the owner-exists/schema/seq checks) so
    // the failure is a clean "app record 0 signature invalid" rather than an owner-lookup error. We
    // change the record's byte LENGTH on purpose: the verified-view cache invalidates on a stat
    // fingerprint (dev, ino, len, mtime_ns, mode, ctime_ns); a same-length signature-byte flip would
    // invalidate only through the mtime and ctime slots, subject to the filesystem's timestamp
    // granularity (a documented same-length design trade in that cache), whereas a length change trips
    // the len slot regardless of timestamp resolution, making this invalidation deterministic.
    let app_records_path_chirho = root_chirho.join("app-records-chirho.jsonl");
    let before_len_chirho = std::fs::metadata(&app_records_path_chirho).unwrap().len();
    let mut app_records_chirho =
        cairn_chirho::app_chirho::load_app_records_chirho(&root_chirho).unwrap();
    let last_chirho = app_records_chirho.len() - 1;
    app_records_chirho[last_chirho].at_ms_chirho = 1;
    write_jsonl_rows_chirho(&app_records_path_chirho, &app_records_chirho);
    let after_len_chirho = std::fs::metadata(&app_records_path_chirho).unwrap().len();
    assert_ne!(
        before_len_chirho, after_len_chirho,
        "the tamper must change the record file length so the cache fingerprint's len slot \
         invalidates deterministically, not only through mtime granularity"
    );

    // (5) The next request through the same warm path must fail closed with no served payload.
    let tampered_response_chirho = post_contact_app_over_http_chirho(&root_chirho, raw_body_chirho);
    let tampered_text_chirho = String::from_utf8_lossy(&tampered_response_chirho.body_chirho);
    assert_eq!(
        tampered_response_chirho.status_chirho, 400,
        "warm cache must fail closed on a tampered control plane, not serve the stale view: \
         {tampered_text_chirho}"
    );
    // The public body names only the selection refusal, with no verifier detail, so the tamper is
    // attributed by the verifier's own answer: the warm serve passed, and this tamper is the one change.
    assert!(
        tampered_text_chirho.starts_with("error: app-selection-refused-chirho\n")
            && !tampered_text_chirho.contains("signature")
            && !tampered_text_chirho.contains("app record"),
        "tampered warm serve must refuse at app selection with no detail: {tampered_text_chirho}"
    );
    let verifier_error_chirho = cairn_chirho::app_chirho::verified_app_records_chirho(&root_chirho)
        .expect_err("the tampered record must fail the verifier");
    assert!(
        format!("{verifier_error_chirho:#}").contains("app record 0 signature invalid"),
        "the verifier names the tamper: {verifier_error_chirho:#}"
    );
    assert!(
        !tampered_text_chirho.contains("data-contact-chirho=\"received\""),
        "no stale contact partial may be served from the warm view after tamper"
    );
    assert_no_contact_pii_chirho(
        "warm-then-tampered submit response",
        &tampered_response_chirho.body_chirho,
        &pii_needles_chirho,
    );

    // Baselines unchanged: the failed request added no blob, run, effect, or stored row.
    assert_eq!(
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        blob_baseline_chirho,
        "tampered warm request must not persist another private blob"
    );
    assert_eq!(
        count_dir_entries_chirho(&root_chirho.join("runs-chirho")),
        runs_baseline_chirho,
        "tampered warm request must not record a new run"
    );
    assert_eq!(
        count_dir_entries_chirho(&root_chirho.join("effects-chirho")),
        effects_baseline_chirho,
        "tampered warm request must not append a new effect"
    );
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert_eq!(
        store_chirho.get_chirho("contacts-chirho/latest").unwrap(),
        contact_latest_baseline_chirho,
        "tampered warm request must not mutate the stored contact row"
    );
    assert_eq!(
        store_chirho.current_entries_chirho().unwrap().len(),
        entries_baseline_chirho,
        "tampered warm request must not add a stored entry"
    );
    drop(store_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}
