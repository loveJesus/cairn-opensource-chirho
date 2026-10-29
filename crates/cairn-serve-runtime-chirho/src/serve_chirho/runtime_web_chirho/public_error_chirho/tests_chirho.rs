// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Unit arms for the public error answers: the typed pre-run classification, the knowledge guidance,
//! the witness's typed fields, and the negotiated bodies.

use super::*;
use anyhow::Context;
use axum::http::header::{ACCEPT, RETRY_AFTER};

const NEEDLE_PATH_CHIRHO: &str =
    "/root-chirho/tenants-chirho/needle-tenant-chirho/refs-chirho.json";

fn io_error_chirho(code_chirho: i32) -> anyhow::Error {
    Err::<(), _>(std::io::Error::from_raw_os_error(code_chirho))
        .with_context(|| format!("read {NEEDLE_PATH_CHIRHO}"))
        .unwrap_err()
}

async fn body_chirho(response_chirho: Response) -> (StatusCode, Option<String>, bool, String) {
    let status_chirho = response_chirho.status();
    let content_type_chirho = response_chirho
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .map(str::to_string);
    let retry_after_chirho = response_chirho.headers().contains_key(RETRY_AFTER);
    let bytes_chirho = axum::body::to_bytes(response_chirho.into_body(), 64 * 1024)
        .await
        .unwrap();
    (
        status_chirho,
        content_type_chirho,
        retry_after_chirho,
        String::from_utf8(bytes_chirho.to_vec()).unwrap(),
    )
}

fn json_headers_chirho() -> HeaderMap {
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers_chirho
}

#[test]
fn a_typed_resource_exhaustion_before_the_run_is_a_resource_failure_chirho() {
    for code_chirho in [24, 23, 28] {
        assert_eq!(
            classify_pre_run_chirho(
                &io_error_chirho(code_chirho),
                StatusCode::INTERNAL_SERVER_ERROR,
                "x-chirho"
            ),
            PublicFailureChirho::PreRunResourceChirho {
                os_code_chirho: code_chirho
            }
        );
    }
}

#[test]
fn a_directory_or_permission_failure_is_not_a_resource_failure_chirho() {
    for code_chirho in [21, 13, 2] {
        assert_eq!(
            classify_pre_run_chirho(
                &io_error_chirho(code_chirho),
                StatusCode::INTERNAL_SERVER_ERROR,
                "x-chirho"
            ),
            PublicFailureChirho::FixedRefusalChirho {
                status_chirho: StatusCode::INTERNAL_SERVER_ERROR,
                identity_chirho: "x-chirho",
            }
        );
    }
}

#[test]
fn a_cause_flattened_into_text_is_not_a_resource_failure_chirho() {
    let flattened_chirho =
        anyhow::anyhow!("read {NEEDLE_PATH_CHIRHO}: Too many open files (os error 24)");
    assert_eq!(
        classify_pre_run_chirho(&flattened_chirho, StatusCode::BAD_REQUEST, "x-chirho"),
        PublicFailureChirho::FixedRefusalChirho {
            status_chirho: StatusCode::BAD_REQUEST,
            identity_chirho: "x-chirho",
        }
    );
}

#[test]
fn an_unclassified_execution_error_is_unknown_never_definitely_not_executed_chirho() {
    let PublicFailureChirho::ExecutionRefusalChirho(observation_chirho) =
        classify_execution_chirho(&anyhow::anyhow!("raw run failure at {NEEDLE_PATH_CHIRHO}"))
    else {
        panic!("an execution error classifies as an execution refusal");
    };
    assert_eq!(
        observation_chirho.execution_knowledge_chirho(),
        DagExecutionKnowledgeChirho::UnknownChirho
    );
}

#[test]
fn each_knowledge_value_has_its_own_guidance_and_none_authorizes_a_retry_chirho() {
    let values_chirho = [
        DagExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        DagExecutionKnowledgeChirho::MayHaveExecutedChirho,
        DagExecutionKnowledgeChirho::PriorAttemptFailedChirho,
        DagExecutionKnowledgeChirho::UnknownChirho,
    ];
    let guidance_chirho: Vec<&str> = values_chirho
        .iter()
        .map(|k_chirho| execution_guidance_chirho(*k_chirho))
        .collect();
    for (index_chirho, text_chirho) in guidance_chirho.iter().enumerate() {
        assert!(
            !text_chirho.to_lowercase().contains("try again"),
            "no guidance invites a retry: {text_chirho}"
        );
        assert_eq!(
            guidance_chirho
                .iter()
                .filter(|other_chirho| *other_chirho == text_chirho)
                .count(),
            1,
            "value {index_chirho}"
        );
    }
    assert!(
        guidance_chirho[2].contains("cannot be used again"),
        "a failed earlier attempt is not a fresh start"
    );
}

#[test]
fn the_witness_carries_typed_fields_only_chirho() {
    assert_eq!(
        witness_line_chirho("app-refs-load-chirho", PublicFailureChirho::PreRunResourceChirho { os_code_chirho: 24 }),
        "CairnPublicErrorChirho:site_chirho=app-refs-load-chirho:class_chirho=pre-run-resource-chirho:os_code_chirho=24"
    );
    assert_eq!(
        witness_line_chirho(
            "app-selection-chirho",
            PublicFailureChirho::FixedRefusalChirho { status_chirho: StatusCode::NOT_FOUND, identity_chirho: "app-not-found-chirho" }
        ),
        "CairnPublicErrorChirho:site_chirho=app-selection-chirho:class_chirho=fixed-refusal-chirho:status_chirho=404:identity_chirho=app-not-found-chirho"
    );
    let execution_chirho = witness_line_chirho(
        "app-execution-chirho",
        classify_execution_chirho(&anyhow::anyhow!("x")),
    );
    assert!(
        execution_chirho
            .ends_with(":knowledge_chirho=unknown-chirho:attempt_chirho=unclassified-chirho"),
        "{execution_chirho}"
    );
}

#[tokio::test]
async fn a_pre_run_resource_failure_answers_503_without_retry_or_detail_chirho() {
    let failure_chirho = classify_pre_run_chirho(
        &io_error_chirho(24),
        StatusCode::INTERNAL_SERVER_ERROR,
        "x-chirho",
    );
    let (status_chirho, type_chirho, retry_chirho, plain_chirho) = body_chirho(
        public_error_response_chirho("test-chirho", failure_chirho, &HeaderMap::new(), None),
    )
    .await;
    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(type_chirho.as_deref(), Some("text/plain; charset=utf-8"));
    assert!(
        !retry_chirho,
        "no Retry-After: nothing here authorizes a retry"
    );
    assert!(plain_chirho.starts_with("error: served-request-pre-run-unavailable-chirho\n"));
    assert!(
        plain_chirho.contains("DAG was not started")
            && plain_chirho.contains("may already be kept")
    );
    assert!(
        !plain_chirho.contains("needle-tenant-chirho")
            && !plain_chirho.contains("refs-chirho.json")
    );
    let (_, json_type_chirho, _, json_chirho) = body_chirho(public_error_response_chirho(
        "test-chirho",
        failure_chirho,
        &json_headers_chirho(),
        None,
    ))
    .await;
    assert_eq!(json_type_chirho.as_deref(), Some("application/json"));
    let value_chirho: serde_json::Value = serde_json::from_str(&json_chirho).unwrap();
    assert_eq!(value_chirho["boundary_chirho"], "pre-run-chirho");
    assert_eq!(
        value_chirho.as_object().unwrap().len(),
        3,
        "bounded fields: {json_chirho}"
    );
}

#[tokio::test]
async fn an_execution_refusal_keeps_its_first_line_and_states_its_knowledge_chirho() {
    let failure_chirho =
        classify_execution_chirho(&anyhow::anyhow!("raw run failure at {NEEDLE_PATH_CHIRHO}"));
    let (status_chirho, _, retry_chirho, plain_chirho) = body_chirho(public_error_response_chirho(
        "test-chirho",
        failure_chirho,
        &HeaderMap::new(),
        None,
    ))
    .await;
    assert_eq!(status_chirho, StatusCode::BAD_REQUEST);
    assert!(!retry_chirho);
    assert!(
        plain_chirho.starts_with("error: CairnAppExecutionRefusedChirho\n"),
        "the first line is kept"
    );
    assert!(plain_chirho.contains(
        "knowledge: unknown-chirho\nattempt: unclassified-chirho\nscope: dag-effects-chirho\n"
    ));
    assert!(
        !plain_chirho.contains("needle-tenant-chirho") && !plain_chirho.contains("raw run failure")
    );
    let (_, _, _, json_chirho) = body_chirho(public_error_response_chirho(
        "test-chirho",
        failure_chirho,
        &json_headers_chirho(),
        None,
    ))
    .await;
    let value_chirho: serde_json::Value = serde_json::from_str(&json_chirho).unwrap();
    assert_eq!(value_chirho["knowledge_chirho"], "unknown-chirho");
    assert_eq!(value_chirho["scope_chirho"], "dag-effects-chirho");
    assert_eq!(
        value_chirho.as_object().unwrap().len(),
        5,
        "bounded fields: {json_chirho}"
    );
}

#[tokio::test]
async fn a_route_declaring_json_answers_json_without_an_accept_header_chirho() {
    let failure_chirho = PublicFailureChirho::FixedRefusalChirho {
        status_chirho: StatusCode::NOT_FOUND,
        identity_chirho: "app-not-found-chirho",
    };
    let (status_chirho, type_chirho, _, json_chirho) = body_chirho(public_error_response_chirho(
        "test-chirho",
        failure_chirho,
        &HeaderMap::new(),
        Some("application/json; charset=utf-8"),
    ))
    .await;
    assert_eq!(status_chirho, StatusCode::NOT_FOUND);
    assert_eq!(type_chirho.as_deref(), Some("application/json"));
    let value_chirho: serde_json::Value = serde_json::from_str(&json_chirho).unwrap();
    assert_eq!(
        value_chirho,
        serde_json::json!({ "ok_chirho": false, "error_chirho": "app-not-found-chirho" })
    );
}

#[tokio::test]
async fn a_resource_exhaustion_on_a_route_with_no_dag_is_unavailable_not_pre_run_chirho() {
    let failure_chirho =
        classify_non_dag_chirho(&io_error_chirho(24), StatusCode::NOT_FOUND, "x-chirho");
    assert_eq!(
        failure_chirho,
        PublicFailureChirho::UnavailableChirho { os_code_chirho: 24 }
    );
    let (status_chirho, _, retry_chirho, plain_chirho) = body_chirho(public_error_response_chirho(
        "test-chirho",
        failure_chirho,
        &HeaderMap::new(),
        None,
    ))
    .await;
    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!retry_chirho);
    assert!(plain_chirho.starts_with("error: served-request-resource-unavailable-chirho\n"));
    assert!(
        !plain_chirho.contains("DAG"),
        "a route with no DAG says nothing about one: {plain_chirho}"
    );
    assert_eq!(
        classify_non_dag_chirho(&io_error_chirho(13), StatusCode::NOT_FOUND, "x-chirho"),
        PublicFailureChirho::FixedRefusalChirho {
            status_chirho: StatusCode::NOT_FOUND,
            identity_chirho: "x-chirho",
        }
    );
}

#[tokio::test]
async fn the_no_dag_unavailable_answer_never_reuses_the_served_gates_refusal_token_chirho() {
    // The served gate's 429 carries an admission wait hint (Retry-After) under its token. This 503 carries no hint and
    // authorizes no retry, so it must never share that token; compared with the gate's ACTUAL JSON constant.
    let gate_chirho: serde_json::Value =
        serde_json::from_str(super::super::SERVED_REQUEST_UNAVAILABLE_JSON_CHIRHO).unwrap();
    let failure_chirho =
        classify_non_dag_chirho(&io_error_chirho(24), StatusCode::NOT_FOUND, "x-chirho");
    let (status_chirho, type_chirho, retry_chirho, json_chirho) = body_chirho(
        public_error_response_chirho("test-chirho", failure_chirho, &json_headers_chirho(), None),
    )
    .await;
    assert_eq!(status_chirho, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !retry_chirho,
        "no Retry-After: no wait hint and no retry authorization"
    );
    assert_eq!(type_chirho.as_deref(), Some("application/json"));
    let emitted_chirho: serde_json::Value = serde_json::from_str(&json_chirho).unwrap();
    assert_ne!(emitted_chirho["error_chirho"], gate_chirho["error_chirho"]);
    assert_eq!(
        emitted_chirho["error_chirho"],
        "served-request-resource-unavailable-chirho"
    );
}
