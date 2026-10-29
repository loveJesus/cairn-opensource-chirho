// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn app_route_can_reify_through_blessed_write_effect_chirho() {
    let root_chirho = tenant_root_for_test_chirho("app-route-write-effect");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let store_key_chirho = "app-contact/latest";
    let dag_hash_chirho = store_write_effect_dag_chirho(&root_chirho, store_key_chirho);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact-write",
        dag_hash_chirho,
        &owner_chirho,
    )
    .unwrap();
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "contact-write", &owner_chirho);

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    // An app-authored record shape. It deliberately does NOT claim one of cairn's own reviewed
    // safe-envelope schemas: this arm is about reify through the blessed write effect, and a value
    // that falsely claims a reviewed schema is refused at the write door — pinned on its own in
    // `a_value_falsely_claiming_a_reviewed_schema_is_refused_at_the_write_door_chirho`.
    let payload_chirho = br#"{"schema_chirho":"app-note-v1-chirho","note_chirho":"reified"}"#;
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath("contact-write".to_string()),
            Bytes::from_static(payload_chirho),
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
        assert_eq!(&body_chirho[..], payload_chirho);
    });

    assert_eq!(
        sealed_row_plaintext_chirho(&root_chirho, store_key_chirho).as_deref(),
        Some(&payload_chirho[..])
    );

    let effects_dir_chirho = root_chirho.join("effects-chirho");
    let effect_paths_chirho = std::fs::read_dir(&effects_dir_chirho)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(effect_paths_chirho.len(), 1);
    let effect_bytes_chirho = std::fs::read(effect_paths_chirho[0].path()).unwrap();
    let effect_chirho: cairn_chirho::model_chirho::EffectChirho =
        serde_json::from_slice(&effect_bytes_chirho).unwrap();
    cairn_chirho::effect_chirho::verify_effect_chirho(&root_chirho, &effect_chirho).unwrap();
    assert!(matches!(
        effect_chirho.capability_chirho,
        cairn_chirho::model_chirho::CapabilityChirho::WriteStoreChirho { .. }
    ));
    assert_eq!(
        cairn_chirho::cas_chirho::get_chirho(&root_chirho, &effect_chirho.request_chirho).unwrap(),
        payload_chirho
    );
    assert_eq!(
        cairn_chirho::cas_chirho::get_chirho(
            &root_chirho,
            effect_chirho.response_chirho.as_ref().unwrap()
        )
        .unwrap(),
        payload_chirho
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_route_can_reify_scoped_contact_key_chirho() {
    let root_chirho = tenant_root_for_test_chirho("app-route-scoped-write-effect");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let dag_hash_chirho = store_write_effect_dag_chirho(&root_chirho, "contacts-chirho");
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact-scoped-write",
        dag_hash_chirho,
        &owner_chirho,
    )
    .unwrap();
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "contact-scoped-write", &owner_chirho);

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let safe_record_chirho =
        br#"{"schema_chirho":"contact-record-v1-chirho","status_chirho":"received"}"#;
    let request_chirho = cairn_chirho::effect_chirho::ScopedWriteStoreRequestChirho {
        schema_chirho: cairn_chirho::effect_chirho::SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "contacts-chirho/submission-001".to_string(),
        value_base64_chirho:
            "eyJzY2hlbWFfY2hpcmhvIjoiY29udGFjdC1yZWNvcmQtdjEtY2hpcmhvIiwic3RhdHVzX2NoaXJobyI6InJlY2VpdmVkIn0="
                .to_string(),
    };
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath("contact-scoped-write".to_string()),
            Bytes::from(serde_json::to_vec(&request_chirho).unwrap()),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body_chirho[..], safe_record_chirho);
    });

    assert_eq!(
        sealed_row_plaintext_chirho(&root_chirho, "contacts-chirho/submission-001").as_deref(),
        Some(&safe_record_chirho[..])
    );
    assert!(sealed_row_plaintext_chirho(&root_chirho, "contacts-chirho").is_none());

    let effects_dir_chirho = root_chirho.join("effects-chirho");
    let effect_paths_chirho = std::fs::read_dir(&effects_dir_chirho)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(effect_paths_chirho.len(), 1);
    let effect_bytes_chirho = std::fs::read(effect_paths_chirho[0].path()).unwrap();
    let effect_chirho: cairn_chirho::model_chirho::EffectChirho =
        serde_json::from_slice(&effect_bytes_chirho).unwrap();
    cairn_chirho::effect_chirho::verify_effect_chirho(&root_chirho, &effect_chirho).unwrap();
    assert!(matches!(
        effect_chirho.capability_chirho,
        cairn_chirho::model_chirho::CapabilityChirho::WriteStoreChirho {
            ref prefix_chirho
        } if prefix_chirho == "contacts-chirho"
    ));
    // Response identity is unchanged — the hash is still blake3 of the written record — while the
    // F4 seal moved that copy off the public plane into a private DAG value.
    let response_hash_chirho = effect_chirho.response_chirho.clone().unwrap();
    assert_eq!(
        response_hash_chirho,
        cairn_chirho::cas_chirho::hash_chirho(safe_record_chirho)
    );
    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &response_hash_chirho).is_err());
    assert!(
        cairn_chirho::dag_private_value_chirho::private_dag_value_recorded_chirho(
            &root_chirho,
            &response_hash_chirho
        )
        .unwrap()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_route_refuses_legacy_query_before_read_or_billing_chirho() {
    let root_chirho = tenant_root_for_test_chirho("app-route-query-contact");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let query_caller_chirho = "contact-query-caller";
    let write_dag_chirho = store_write_effect_dag_chirho(&root_chirho, "contacts-chirho/latest");
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact-write-query",
        write_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "contact-write-query", &owner_chirho);

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    // App-authored record shape; see the note on `payload_chirho` above for why this arm does not
    // impersonate one of cairn's reviewed safe-envelope schemas.
    let safe_contact_chirho = br#"{"schema_chirho":"app-note-v1-chirho","subject_chirho":"app/contact/inbox","bytes_chirho":123}"#;
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath("contact-write-query".to_string()),
            Bytes::from_static(safe_contact_chirho),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
    });
    cairn_chirho::query_chirho::project_chirho(&root_chirho).unwrap();

    let query_dag_chirho =
        store_query_effect_dag_chirho(&root_chirho, "contacts-chirho", query_caller_chirho, 10);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact-list",
        query_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "contact-list", &owner_chirho);
    let (_query_user_chirho, query_headers_chirho) = verified_query_headers_for_app_chirho(
        &root_chirho,
        "contact-list",
        &owner_chirho,
        "contact-list-query-secret",
    );
    let request_chirho = cairn_chirho::effect_chirho::ScopedQueryRequestChirho {
        prefix_chirho: "contacts-chirho".to_string(),
        limit_chirho: Some(10),
    };
    let request_bytes_chirho = serde_json::to_vec(&request_chirho).unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath("contact-list".to_string()),
            Bytes::from(request_bytes_chirho.clone()),
        )
        .await;
        assert_fixed_app_execution_http_refusal_chirho(response_chirho, "QueryEffectChirho").await;
    });
    assert_eq!(
        cairn_chirho::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .len(),
        0
    );
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho),
            None,
            query_headers_chirho,
            AxPath("contact-list".to_string()),
            Bytes::from(request_bytes_chirho),
        )
        .await;
        assert_fixed_app_execution_http_refusal_chirho(response_chirho, "QueryEffectChirho").await;
    });
    assert_eq!(
        cairn_chirho::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .len(),
        0
    );

    let effects_chirho = std::fs::read_dir(root_chirho.join("effects-chirho"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(effects_chirho.len(), 1);
    let query_effects_chirho = effects_chirho
        .iter()
        .filter_map(|entry_chirho| {
            let bytes_chirho = std::fs::read(entry_chirho.path()).ok()?;
            let effect_chirho: cairn_chirho::model_chirho::EffectChirho =
                serde_json::from_slice(&bytes_chirho).ok()?;
            matches!(
                effect_chirho.capability_chirho,
                cairn_chirho::model_chirho::CapabilityChirho::QueryChirho { .. }
            )
            .then_some(effect_chirho)
        })
        .collect::<Vec<_>>();
    assert!(query_effects_chirho.is_empty());
    assert!(
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_route_refuses_scoped_legacy_query_before_read_or_billing_chirho() {
    let root_chirho = tenant_root_for_test_chirho("app-route-query-scoped-contact-rows");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let query_caller_chirho = "contact-scoped-query-caller";
    let write_dag_chirho = store_write_effect_dag_chirho(&root_chirho, "contacts-chirho");
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact-write-scoped-list",
        write_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    set_plain_app_input_policy_for_test_chirho(
        &root_chirho,
        "contact-write-scoped-list",
        &owner_chirho,
    );

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let safe_record_one_chirho =
        br#"{"schema_chirho":"contact-record-v1-chirho","status_chirho":"received"}"#;
    let safe_record_two_chirho =
        br#"{"schema_chirho":"contact-record-v1-chirho","status_chirho":"received"}"#;
    let write_one_chirho = cairn_chirho::effect_chirho::ScopedWriteStoreRequestChirho {
        schema_chirho: cairn_chirho::effect_chirho::SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "contacts-chirho/submission-001".to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(safe_record_one_chirho),
    };
    let write_two_chirho = cairn_chirho::effect_chirho::ScopedWriteStoreRequestChirho {
        schema_chirho: cairn_chirho::effect_chirho::SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "contacts-chirho/submission-002".to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(safe_record_two_chirho),
    };
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        for request_chirho in [write_one_chirho, write_two_chirho] {
            let response_chirho = app_post_chirho(
                State(state_chirho.clone()),
                None,
                HeaderMap::new(),
                AxPath("contact-write-scoped-list".to_string()),
                Bytes::from(serde_json::to_vec(&request_chirho).unwrap()),
            )
            .await;
            assert_eq!(response_chirho.status(), StatusCode::OK);
        }
    });

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert!(store_chirho
        .get_chirho("contacts-chirho")
        .unwrap()
        .is_none());
    assert!(store_chirho
        .get_chirho("contacts-chirho/submission-001")
        .unwrap()
        .is_some());
    assert!(store_chirho
        .get_chirho("contacts-chirho/submission-002")
        .unwrap()
        .is_some());
    drop(store_chirho);
    cairn_chirho::query_chirho::project_chirho(&root_chirho).unwrap();

    let query_dag_chirho =
        store_query_effect_dag_chirho(&root_chirho, "contacts-chirho", query_caller_chirho, 10);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact-list-scoped",
        query_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "contact-list-scoped", &owner_chirho);
    let (_query_user_chirho, query_headers_chirho) = verified_query_headers_for_app_chirho(
        &root_chirho,
        "contact-list-scoped",
        &owner_chirho,
        "contact-list-scoped-query-secret",
    );
    let request_chirho = cairn_chirho::effect_chirho::ScopedQueryRequestChirho {
        prefix_chirho: "contacts-chirho".to_string(),
        limit_chirho: Some(10),
    };
    let request_bytes_chirho = serde_json::to_vec(&request_chirho).unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath("contact-list-scoped".to_string()),
            Bytes::from(request_bytes_chirho.clone()),
        )
        .await;
        assert_fixed_app_execution_http_refusal_chirho(response_chirho, "QueryEffectChirho").await;
    });
    assert_eq!(
        cairn_chirho::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .len(),
        0
    );
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho),
            None,
            query_headers_chirho,
            AxPath("contact-list-scoped".to_string()),
            Bytes::from(request_bytes_chirho),
        )
        .await;
        assert_fixed_app_execution_http_refusal_chirho(response_chirho, "QueryEffectChirho").await;
    });
    assert_eq!(
        cairn_chirho::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .len(),
        0
    );

    let query_effects_chirho = std::fs::read_dir(root_chirho.join("effects-chirho"))
        .unwrap()
        .filter_map(|entry_chirho| {
            let bytes_chirho = std::fs::read(entry_chirho.ok()?.path()).ok()?;
            let effect_chirho: cairn_chirho::model_chirho::EffectChirho =
                serde_json::from_slice(&bytes_chirho).ok()?;
            matches!(
                effect_chirho.capability_chirho,
                cairn_chirho::model_chirho::CapabilityChirho::QueryChirho { .. }
            )
            .then_some(effect_chirho)
        })
        .collect::<Vec<_>>();
    assert!(query_effects_chirho.is_empty());
    assert!(
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The read model holds the versioned store's current value at `key_chirho`, lossy-decoded as the projection writes
/// it. Read-only: the read model must already exist, so the query never rebuilds it; and the store handle drops
/// before this returns, so no server open waits on it.
fn projection_holds_current_value_chirho(root_chirho: &std::path::Path, key_chirho: &str) -> bool {
    assert!(
        root_chirho.join("readmodel-chirho.sqlite").is_file(),
        "the read model exists, so the query below cannot rebuild it"
    );
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let current_chirho = store_chirho
        .get_chirho(key_chirho)
        .unwrap()
        .expect("the key was written");
    drop(store_chirho);
    let (prefix_chirho, _) = key_chirho.rsplit_once('/').unwrap();
    cairn_chirho::query_chirho::query_prefix_chirho(root_chirho, prefix_chirho, 10)
        .unwrap()
        .iter()
        .any(|row_chirho| {
            row_chirho.key_chirho == key_chirho
                && row_chirho.value_chirho == String::from_utf8_lossy(&current_chirho)
        })
}

async fn post_contact_write_chirho(
    state_chirho: &AppStateChirho,
    payload_chirho: &'static [u8],
) -> (StatusCode, Vec<u8>) {
    let response_chirho = app_post_chirho(
        State(state_chirho.clone()),
        None,
        HeaderMap::new(),
        AxPath("contact-write".to_string()),
        Bytes::from_static(payload_chirho),
    )
    .await;
    let status_chirho = response_chirho.status();
    let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
        .await
        .unwrap();
    (status_chirho, body_chirho.to_vec())
}

/// A write that lands while a reader holds the read model (as a concurrent operator `query` would) is answered as
/// SAVED. The read model sets no busy timeout, so the refresh after the write fails its commit with SQLITE_BUSY at
/// once; the projection is then BEHIND the store. It heals at the next successful refresh, here the identical
/// retry's, which replays: no second write effect and no run-intent record (PFE #25858; CAIRN #25867).
///
/// MIGRATION PATH: a 500 means a landed write is answered as failed again. A failing "behind" check means the reader
/// no longer fails the refresh (a busy timeout, say): fail it another way, or this arm proves nothing about catch-up.
#[test]
fn a_write_whose_projection_refresh_fails_is_saved_and_the_projection_catches_up_chirho() {
    let root_chirho = tenant_root_for_test_chirho("app-route-write-refresh-fails");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let store_key_chirho = "app-contact/latest";
    let dag_hash_chirho = store_write_effect_dag_chirho(&root_chirho, store_key_chirho);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact-write",
        dag_hash_chirho,
        &owner_chirho,
    )
    .unwrap();
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "contact-write", &owner_chirho);
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let first_chirho: &'static [u8] =
        br#"{"schema_chirho":"app-note-v1-chirho","note_chirho":"first"}"#;
    let second_chirho: &'static [u8] =
        br#"{"schema_chirho":"app-note-v1-chirho","note_chirho":"second"}"#;
    let effect_count_chirho = || {
        std::fs::read_dir(root_chirho.join("effects-chirho"))
            .map(|entries_chirho| entries_chirho.count())
            .unwrap_or(0)
    };
    let run_intent_count_chirho = || {
        std::fs::read_to_string(root_chirho.join("run-intents-chirho.jsonl"))
            .map(|text_chirho| text_chirho.lines().count())
            .unwrap_or(0)
    };
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let (status_chirho, body_chirho) =
            post_contact_write_chirho(&state_chirho, first_chirho).await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&body_chirho)
        );
        assert!(
            projection_holds_current_value_chirho(&root_chirho, store_key_chirho),
            "with no reader, the refresh after the write keeps the projection current"
        );

        let reader_chirho =
            rusqlite::Connection::open(root_chirho.join("readmodel-chirho.sqlite")).unwrap();
        reader_chirho.execute_batch("BEGIN").unwrap();
        let _rows_seen_chirho: i64 = reader_chirho
            .query_row("SELECT COUNT(*) FROM entries_chirho", [], |row_chirho| {
                row_chirho.get(0)
            })
            .unwrap();
        let (status_chirho, body_chirho) =
            post_contact_write_chirho(&state_chirho, second_chirho).await;
        reader_chirho.execute_batch("COMMIT").unwrap();
        drop(reader_chirho);
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "a landed write is answered as saved: {}",
            String::from_utf8_lossy(&body_chirho)
        );
        assert_eq!(
            &body_chirho[..],
            second_chirho,
            "the answer is the saved result"
        );
        assert!(
            !projection_holds_current_value_chirho(&root_chirho, store_key_chirho),
            "the reader made the refresh fail, so the projection is behind the store"
        );

        let (effects_chirho, run_intents_chirho) =
            (effect_count_chirho(), run_intent_count_chirho());
        let (status_chirho, body_chirho) =
            post_contact_write_chirho(&state_chirho, second_chirho).await;
        assert_eq!(
            status_chirho,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&body_chirho)
        );
        assert_eq!(
            &body_chirho[..],
            second_chirho,
            "the identical retry replays the saved result"
        );
        assert_eq!(
            effect_count_chirho(),
            effects_chirho,
            "the retry writes nothing again"
        );
        assert_eq!(
            run_intent_count_chirho(),
            run_intents_chirho,
            "the retry is a replay: no run-intent record"
        );
        assert!(
            projection_holds_current_value_chirho(&root_chirho, store_key_chirho),
            "the retry's refresh caught the projection up"
        );
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}
