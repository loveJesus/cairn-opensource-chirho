// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

fn current_effect_contract_set_chirho() -> HashChirho {
    cairn_chirho::blessed_chirho::inert_authoring_registry_v2_message_chirho()
        .unwrap()
        .contract_set_digest_chirho
}

/// An UNCOMPOSED served-LLM effect (serve injects no LlmServedRuntimePortChirho) refuses at the
/// ladder's pre-effect composition check -- BEFORE any work, billing, or usage. Since S2b/S2c the
/// served LLM subtype has its own money road, so it no longer falls to the legacy money road; the
/// refuse-before-work + no-billing property this arm has always pinned is unchanged, only the
/// refusal identity moved. MIGRATION: if this now says "legacy money road", the LLM subtype stopped
/// routing to its ladder; if it charges or writes usage, the pre-effect guarantee regressed.
#[test]
fn app_request_context_refuses_uncomposed_llm_effect_before_work_chirho() {
    let root_chirho = temp_root_chirho("request-context");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let app_dag_chirho = deploy_llm_effect_test_app_chirho(
        &root_chirho,
        "ctxapp",
        &owner_chirho.principal_chirho,
        "demo/static-caller",
    );
    let mut prices_chirho = std::collections::BTreeMap::new();
    prices_chirho.insert("llm_chirho".to_string(), 17);
    let (price_book_chirho, _, _) = effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "ctxapp",
        &owner_chirho.principal_chirho,
        None,
        prices_chirho,
        0,
    )
    .unwrap();
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "request-secret-value",
    )
    .unwrap();
    let client_chirho = oauth_chirho::register_client_chirho(
        &root_chirho,
        "ctxapp",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_chirho = oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &user_chirho.principal_chirho,
        "request-secret-value",
        &client_chirho.client_id_chirho,
        vec!["invoke".to_string()],
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", token_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    let context_chirho = request_context_for_app_chirho(&root_chirho, &headers_chirho, "ctxapp")
        .unwrap()
        .unwrap();
    assert_eq!(
        context_chirho.user_principal_chirho,
        user_chirho.principal_chirho
    );
    assert_eq!(context_chirho.app_chirho, "ctxapp");
    assert_eq!(
        context_chirho.owner_principal_chirho,
        owner_chirho.principal_chirho
    );
    assert_eq!(context_chirho.price_book_chirho, Some(price_book_chirho));

    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &app_dag_chirho).unwrap();
    let refusal_chirho = dag_chirho::run_dag_with_context_chirho(
        &root_chirho,
        &dag_chirho,
        br#"{"prompt_chirho":"hello","max_tokens_chirho":1,"max_price_per_token_chirho":17}"#,
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    assert!(
        refusal_chirho.contains("served LLM provider composition is not installed"),
        "an uncomposed served-LLM effect refuses at the ladder's composition check: {refusal_chirho}"
    );
    assert!(
        cairn_chirho::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    assert!(!root_chirho.join("external-usage-chirho.jsonl").exists());

    let mut bad_headers_chirho = HeaderMap::new();
    bad_headers_chirho.insert(AUTHORIZATION, "Bearer wrong-token".parse().unwrap());
    assert!(request_context_for_app_chirho(&root_chirho, &bad_headers_chirho, "ctxapp").is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn deploy_llm_effect_test_app_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    owner_chirho: &str,
    caller_chirho: &str,
) -> cairn_chirho::model_chirho::HashChirho {
    let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let paid_node_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &NodeDefChirho {
            name_chirho: "paid_llm_chirho".to_string(),
            impl_wasm_chirho: cas_chirho::add_chirho(root_chirho, b"builtin:paid_effect").unwrap(),
            entry_chirho: "paid_effect_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho,
            }],
            capabilities_chirho: vec![
                CapabilityChirho::PaidEffectChirho {
                    effect_chirho: "llm_chirho".to_string(),
                    caller_chirho: caller_chirho.to_string(),
                },
                CapabilityChirho::UserIdentityChirho {
                    principal_chirho: caller_chirho.to_string(),
                    client_id_chirho: "billing-runtime-test-client-chirho".to_string(),
                    token_hash_chirho: "billing-runtime-test-token-hash-chirho".to_string(),
                },
            ],
            fuel_limit_chirho: 0,
            effect_contract_set_chirho: Some(current_effect_contract_set_chirho()),
            ..Default::default()
        },
    )
    .unwrap();
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![paid_node_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(root_chirho, app_chirho, dag_chirho.clone(), owner_chirho)
        .unwrap();
    dag_chirho
}

/// An UNCOMPOSED served-LLM effect refuses at the ladder's pre-effect composition check on BOTH the
/// first and a byte-identical second call -- no provider, no cache reuse, no billing usage, no
/// external-usage log. Since S2b/S2c the served LLM subtype routes to its own money road, not the
/// legacy money road; the refuse-before-provider/cache + idempotent-no-charge property is unchanged.
/// MIGRATION: "legacy money road" here would mean the LLM subtype stopped routing to its ladder.
#[test]
fn app_user_pays_uncomposed_llm_refuses_before_provider_or_cache_chirho() {
    let root_chirho = temp_root_chirho("m17-user-pays-llm");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let schema_chirho = cas_chirho::add_chirho(&root_chirho, b"bytes").unwrap();
    let paid_node_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &NodeDefChirho {
            name_chirho: "bounded_llm_chirho".to_string(),
            impl_wasm_chirho: cas_chirho::add_chirho(&root_chirho, b"builtin:paid_effect").unwrap(),
            entry_chirho: "paid_effect_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho,
            }],
            capabilities_chirho: vec![
                CapabilityChirho::PaidEffectChirho {
                    effect_chirho: "llm_chirho".to_string(),
                    caller_chirho: "demo/static-caller".to_string(),
                },
                CapabilityChirho::UserIdentityChirho {
                    principal_chirho: "demo/static-caller".to_string(),
                    client_id_chirho: "demo-client-chirho".to_string(),
                    token_hash_chirho: "demo-token-hash-chirho".to_string(),
                },
            ],
            fuel_limit_chirho: 0,
            effect_contract_set_chirho: Some(current_effect_contract_set_chirho()),
            ..Default::default()
        },
    )
    .unwrap();
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![paid_node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(
        &root_chirho,
        "billapp",
        dag_hash_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let mut prices_chirho = std::collections::BTreeMap::new();
    prices_chirho.insert("llm_chirho".to_string(), 17);
    effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "billapp",
        &owner_chirho.principal_chirho,
        None,
        prices_chirho,
        0,
    )
    .unwrap();
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "llm-secret-value",
    )
    .unwrap();
    let client_chirho = oauth_chirho::register_client_chirho(
        &root_chirho,
        "billapp",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_chirho = oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &user_chirho.principal_chirho,
        "llm-secret-value",
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", token_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    let context_chirho = request_context_for_app_chirho(&root_chirho, &headers_chirho, "billapp")
        .unwrap()
        .unwrap();
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &dag_hash_chirho).unwrap();
    let request_chirho =
        br#"{"prompt_chirho":"summarize this","max_tokens_chirho":5,"max_price_per_token_chirho":4}"#
            .to_vec();

    let first_refusal_chirho = dag_chirho::run_dag_with_context_chirho(
        &root_chirho,
        &dag_chirho,
        &request_chirho,
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    assert!(
        first_refusal_chirho.contains("served LLM provider composition is not installed"),
        "an uncomposed served-LLM effect refuses at the composition check: {first_refusal_chirho}"
    );

    let second_refusal_chirho = dag_chirho::run_dag_with_context_chirho(
        &root_chirho,
        &dag_chirho,
        &request_chirho,
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    assert!(
        second_refusal_chirho.contains("served LLM provider composition is not installed"),
        "a byte-identical resend refuses the same way, still charging nothing: {second_refusal_chirho}"
    );
    assert!(
        cairn_chirho::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    assert!(!root_chirho.join("external-usage-chirho.jsonl").exists());
    assert!(!root_chirho.join("effects-chirho").exists());

    let _ = std::fs::remove_dir_all(&root_chirho);
}
