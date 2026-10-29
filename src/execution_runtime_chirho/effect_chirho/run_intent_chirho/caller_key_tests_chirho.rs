// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::{EdgeChirho, NodeDefChirho, PortChirho};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

fn caller_key_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let count_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-run-intent-caller-key-{label_chirho}-{}-{count_chirho}",
        std::process::id()
    ))
}

fn caller_key_test_dag_chirho(root_chirho: &Path) -> HashChirho {
    let wasm_chirho = include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes();
    let impl_hash_chirho = cas_chirho::add_chirho(root_chirho, wasm_chirho).unwrap();
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_hash_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &NodeDefChirho {
            name_chirho: "caller_key_upcase_chirho".to_string(),
            impl_wasm_chirho: impl_hash_chirho,
            entry_chirho: "upcase_chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho,
            }],
            capabilities_chirho: Vec::new(),
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        },
    )
    .unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: Vec::<EdgeChirho>::new(),
        },
    )
    .unwrap()
}

#[derive(Serialize)]
struct LegacyRunIntentIdempotencyContextChirho {
    schema_chirho: String,
    dag_chirho: HashChirho,
    request_chirho: HashChirho,
    scope_chirho: RunIntentScopeChirho,
}

#[test]
fn absent_caller_key_preserves_the_v1_context_hash_byte_for_byte_chirho() {
    let dag_chirho = HashChirho("a".repeat(64));
    let request_chirho = HashChirho("b".repeat(64));
    let scope_chirho = RunIntentScopeChirho {
        kind_chirho: "public-run-chirho".to_string(),
        app_hash_chirho: None,
        user_principal_hash_chirho: None,
        owner_principal_hash_chirho: None,
        client_id_hash_chirho: None,
        token_hash_chirho: None,
        price_book_chirho: None,
        billing_policy_chirho: None,
    };
    let expected_chirho =
        store_chirho::hash_object_chirho(&LegacyRunIntentIdempotencyContextChirho {
            schema_chirho: "run-intent-idempotency-context-v1-chirho".to_string(),
            dag_chirho: dag_chirho.clone(),
            request_chirho: request_chirho.clone(),
            scope_chirho: scope_chirho.clone(),
        })
        .unwrap();
    let actual_chirho =
        run_intent_context_hash_chirho(&dag_chirho, &request_chirho, &scope_chirho).unwrap();
    assert_eq!(
        actual_chirho, expected_chirho,
        "adding the optional caller key must not move any legacy no-key run identity"
    );
}

#[test]
fn keyed_identity_ignores_rotating_auth_evidence_but_binds_caller_and_private_subject_chirho() {
    let dag_chirho = HashChirho("a".repeat(64));
    let request_chirho = HashChirho("b".repeat(64));
    let caller_key_chirho =
        CallerIdempotencyKeyChirho::new_chirho("logical-operation-scope-0001-chirho").unwrap();
    let caller_key_digest_chirho = HashChirho(caller_key_chirho.digest_hex_chirho());
    let first_scope_chirho = RunIntentScopeChirho {
        kind_chirho: "app-run-chirho".to_string(),
        app_hash_chirho: Some("app-stable-chirho".to_string()),
        user_principal_hash_chirho: Some("caller-stable-chirho".to_string()),
        owner_principal_hash_chirho: Some("owner-first-chirho".to_string()),
        client_id_hash_chirho: Some("client-first-chirho".to_string()),
        token_hash_chirho: Some("token-first-chirho".to_string()),
        price_book_chirho: Some(HashChirho("c".repeat(64))),
        billing_policy_chirho: Some(HashChirho("d".repeat(64))),
    };
    let mut rotated_scope_chirho = first_scope_chirho.clone();
    rotated_scope_chirho.owner_principal_hash_chirho = Some("owner-rotated-chirho".to_string());
    rotated_scope_chirho.client_id_hash_chirho = Some("client-rotated-chirho".to_string());
    rotated_scope_chirho.token_hash_chirho = Some("token-rotated-chirho".to_string());
    rotated_scope_chirho.price_book_chirho = Some(HashChirho("e".repeat(64)));
    rotated_scope_chirho.billing_policy_chirho = Some(HashChirho("f".repeat(64)));

    let first_chirho = run_intent_context_hash_from_digest_chirho(
        &dag_chirho,
        &request_chirho,
        &first_scope_chirho,
        Some("app/demo/private-chirho"),
        Some(&caller_key_digest_chirho),
        None,
    )
    .unwrap();
    let rotated_chirho = run_intent_context_hash_from_digest_chirho(
        &dag_chirho,
        &request_chirho,
        &rotated_scope_chirho,
        Some("app/demo/private-chirho"),
        Some(&caller_key_digest_chirho),
        None,
    )
    .unwrap();
    assert_eq!(
        first_chirho, rotated_chirho,
        "token, client, owner, and pricing refreshes must not strand a caller-key retry"
    );

    rotated_scope_chirho.user_principal_hash_chirho = Some("different-caller-chirho".to_string());
    let different_caller_chirho = run_intent_context_hash_from_digest_chirho(
        &dag_chirho,
        &request_chirho,
        &rotated_scope_chirho,
        Some("app/demo/private-chirho"),
        Some(&caller_key_digest_chirho),
        None,
    )
    .unwrap();
    assert_ne!(first_chirho, different_caller_chirho);
    let different_subject_chirho = run_intent_context_hash_from_digest_chirho(
        &dag_chirho,
        &request_chirho,
        &first_scope_chirho,
        Some("app/demo/other-private-chirho"),
        Some(&caller_key_digest_chirho),
        None,
    )
    .unwrap();
    assert_ne!(first_chirho, different_subject_chirho);
}

#[test]
fn same_caller_key_replays_one_durable_run_without_persisting_the_raw_key_chirho() {
    let root_chirho = caller_key_root_chirho("same");
    let dag_chirho = caller_key_test_dag_chirho(&root_chirho);
    let raw_key_chirho = "logical-operation-same-0001-chirho";
    let caller_key_chirho = CallerIdempotencyKeyChirho::new_chirho(raw_key_chirho).unwrap();

    let first_chirho = run_dag_with_intent_and_caller_key_chirho(
        &root_chirho,
        &dag_chirho,
        b"same",
        None,
        &caller_key_chirho,
    )
    .unwrap();
    let second_chirho = run_dag_with_intent_and_caller_key_chirho(
        &root_chirho,
        &dag_chirho,
        b"same",
        None,
        &caller_key_chirho,
    )
    .unwrap();
    assert_eq!(first_chirho.payload_chirho, second_chirho.payload_chirho);

    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert!(records_chirho
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho == RUN_INTENT_RECORD_SCHEMA_V2_CHIRHO));
    assert!(records_chirho.iter().all(|record_chirho| {
        record_chirho.caller_idempotency_key_digest_chirho
            == Some(HashChirho(caller_key_chirho.digest_hex_chirho()))
    }));
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let durable_bytes_chirho = std::fs::read(run_intent_records_path_chirho(&root_chirho)).unwrap();
    assert!(
        !durable_bytes_chirho
            .windows(raw_key_chirho.len())
            .any(|window_chirho| window_chirho == raw_key_chirho.as_bytes()),
        "raw caller idempotency key entered the durable run-intent log"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn caller_key_binds_one_exact_http_operation_without_persisting_raw_coordinates_chirho() {
    let root_chirho = caller_key_root_chirho("operation");
    let dag_chirho = caller_key_test_dag_chirho(&root_chirho);
    let raw_key_chirho = "logical-http-operation-0001-chirho";
    let raw_uri_chirho = "/app-chirho/credits-demo-chirho/spend-chirho?bounded=1";
    let caller_key_chirho = CallerIdempotencyKeyChirho::new_chirho(raw_key_chirho).unwrap();
    let operation_chirho =
        CallerOperationBindingChirho::new_chirho("POST", raw_uri_chirho).unwrap();
    let runtime_ports_chirho = super::super::DagEffectRuntimePortsChirho {
        projection_read_chirho: None,
        postgres_reversible_chirho: None,
        llm_served_chirho: None,
        private_attribution_chirho: None,
    };

    let first_chirho = run_dag_with_intent_and_effect_runtime_and_caller_operation_chirho(
        &root_chirho,
        &dag_chirho,
        b"same",
        None,
        runtime_ports_chirho,
        &caller_key_chirho,
        &operation_chirho,
    )
    .unwrap();
    let second_chirho = run_dag_with_intent_and_effect_runtime_and_caller_operation_chirho(
        &root_chirho,
        &dag_chirho,
        b"same",
        None,
        super::super::DagEffectRuntimePortsChirho {
            projection_read_chirho: None,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
        &caller_key_chirho,
        &operation_chirho,
    )
    .unwrap();
    assert_eq!(first_chirho.payload_chirho, second_chirho.payload_chirho);

    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert!(records_chirho.iter().all(|record_chirho| {
        record_chirho.schema_chirho == RUN_INTENT_RECORD_SCHEMA_V3_CHIRHO
            && record_chirho.caller_operation_digest_chirho
                == Some(HashChirho(operation_chirho.digest_hex_chirho()))
    }));
    let durable_bytes_chirho = std::fs::read(run_intent_records_path_chirho(&root_chirho)).unwrap();
    for forbidden_chirho in [raw_key_chirho.as_bytes(), raw_uri_chirho.as_bytes()] {
        assert!(
            !durable_bytes_chirho
                .windows(forbidden_chirho.len())
                .any(|window_chirho| window_chirho == forbidden_chirho),
            "raw caller operation coordinate entered the durable run-intent log"
        );
    }

    for changed_operation_chirho in [
        CallerOperationBindingChirho::new_chirho("GET", raw_uri_chirho).unwrap(),
        CallerOperationBindingChirho::new_chirho(
            "POST",
            "/app-chirho/credits-demo-chirho/other-spend-chirho?bounded=1",
        )
        .unwrap(),
    ] {
        let error_chirho = run_dag_with_intent_and_effect_runtime_and_caller_operation_chirho(
            &root_chirho,
            &dag_chirho,
            b"same",
            None,
            super::super::DagEffectRuntimePortsChirho {
                projection_read_chirho: None,
                postgres_reversible_chirho: None,
                llm_served_chirho: None,
                private_attribution_chirho: None,
            },
            &caller_key_chirho,
            &changed_operation_chirho,
        )
        .unwrap_err();
        assert!(
            error_chirho
                .to_string()
                .contains("RelayCallerKeyCollisionChirho"),
            "{error_chirho}"
        );
        assert_eq!(
            load_run_intent_records_chirho(&root_chirho).unwrap().len(),
            3,
            "a changed method or URI must refuse before a second durable run"
        );
    }
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn same_caller_key_with_changed_request_refuses_before_a_second_run_chirho() {
    let root_chirho = caller_key_root_chirho("collision");
    let dag_chirho = caller_key_test_dag_chirho(&root_chirho);
    let changed_request_chirho = cas_chirho::hash_chirho(b"changed");
    let caller_key_chirho =
        CallerIdempotencyKeyChirho::new_chirho("logical-operation-collision-0001-chirho").unwrap();
    run_dag_with_intent_and_caller_key_chirho(
        &root_chirho,
        &dag_chirho,
        b"first",
        None,
        &caller_key_chirho,
    )
    .unwrap();
    let error_chirho = run_dag_with_intent_and_caller_key_chirho(
        &root_chirho,
        &dag_chirho,
        b"changed",
        None,
        &caller_key_chirho,
    )
    .unwrap_err();
    let rendered_chirho = error_chirho.to_string();
    assert!(rendered_chirho.contains("RelayCallerKeyCollisionChirho"));
    assert!(!rendered_chirho.contains("RelayCallerKeyInvalidChirho"));
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        3
    );
    assert!(
        cas_chirho::get_chirho(&root_chirho, &changed_request_chirho).is_err(),
        "a caller-key collision must refuse before publishing the changed request stone"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn concurrent_changed_requests_under_one_key_cannot_both_enter_chirho() {
    let root_chirho = caller_key_root_chirho("race");
    let dag_chirho = caller_key_test_dag_chirho(&root_chirho);
    let caller_key_chirho =
        CallerIdempotencyKeyChirho::new_chirho("logical-operation-race-0001-chirho").unwrap();
    let mut workers_chirho = Vec::new();
    for body_chirho in [b"first".to_vec(), b"second".to_vec()] {
        let root_chirho = root_chirho.clone();
        let dag_chirho = dag_chirho.clone();
        let caller_key_chirho = caller_key_chirho.clone();
        workers_chirho.push(std::thread::spawn(move || {
            run_dag_with_intent_and_caller_key_chirho(
                &root_chirho,
                &dag_chirho,
                &body_chirho,
                None,
                &caller_key_chirho,
            )
        }));
    }
    let outcomes_chirho = workers_chirho
        .into_iter()
        .map(|worker_chirho| worker_chirho.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes_chirho
            .iter()
            .filter(|outcome_chirho| outcome_chirho.is_ok())
            .count(),
        1
    );
    let refusal_chirho = outcomes_chirho
        .iter()
        .find_map(|outcome_chirho| outcome_chirho.as_ref().err())
        .unwrap()
        .to_string();
    assert!(refusal_chirho.contains("RelayCallerKeyCollisionChirho"));
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        3
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn distinct_caller_keys_create_distinct_logical_runs_chirho() {
    let root_chirho = caller_key_root_chirho("distinct");
    let dag_chirho = caller_key_test_dag_chirho(&root_chirho);
    let first_key_chirho =
        CallerIdempotencyKeyChirho::new_chirho("logical-operation-distinct-0001-chirho").unwrap();
    let second_key_chirho =
        CallerIdempotencyKeyChirho::new_chirho("logical-operation-distinct-0002-chirho").unwrap();
    run_dag_with_intent_and_caller_key_chirho(
        &root_chirho,
        &dag_chirho,
        b"same",
        None,
        &first_key_chirho,
    )
    .unwrap();
    run_dag_with_intent_and_caller_key_chirho(
        &root_chirho,
        &dag_chirho,
        b"same",
        None,
        &second_key_chirho,
    )
    .unwrap();
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 6);
    let runs_chirho = records_chirho
        .iter()
        .map(|record_chirho| record_chirho.run_chirho.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(runs_chirho.len(), 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}
