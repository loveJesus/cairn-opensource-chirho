// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use axum::body::{Body, HttpBody};
use axum::extract::{OriginalUri, Request};
use axum::http::Method;
use http_body::Frame;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

struct ObservedBodyChirho {
    polled_chirho: Arc<AtomicBool>,
    emitted_chirho: bool,
}

impl HttpBody for ObservedBodyChirho {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context_chirho: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polled_chirho.store(true, Ordering::SeqCst);
        if self.emitted_chirho {
            return Poll::Ready(None);
        }
        self.emitted_chirho = true;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
            b"body-must-not-be-polled-before-auth-chirho",
        )))))
    }
}

pub(super) fn observed_request_chirho(polled_chirho: Arc<AtomicBool>) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/app-chirho/protected-chirho/change-chirho")
        .body(Body::new(ObservedBodyChirho {
            polled_chirho,
            emitted_chirho: false,
        }))
        .unwrap()
}

async fn body_text_chirho(response_chirho: Response) -> (StatusCode, String) {
    let status_chirho = response_chirho.status();
    let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status_chirho,
        String::from_utf8(body_chirho.to_vec()).unwrap(),
    )
}

#[test]
fn authenticated_app_refuses_before_body_poll_and_hides_route_existence_chirho() {
    let root_chirho = temp_root_chirho("request-access-pre-body");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let root_dag_chirho = deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "protected-chirho",
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        "protected-chirho",
        "change-chirho",
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "protected-chirho",
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "protected-chirho",
        Some("change-chirho"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_request_access_policy_chirho(
        &root_chirho,
        "protected-chirho",
        &owner_chirho,
        root_dag_chirho,
        cairn_chirho::app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho,
    )
    .unwrap();
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let before_chirho = runtime_tree_snapshot_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let polled_chirho = Arc::new(AtomicBool::new(false));
        let response_chirho = app_http_chirho::app_route_post_request_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(("protected-chirho".to_string(), "change-chirho".to_string())),
            observed_request_chirho(polled_chirho.clone()),
        )
        .await;
        let (status_chirho, body_chirho) = body_text_chirho(response_chirho).await;
        assert_eq!(status_chirho, StatusCode::UNAUTHORIZED);
        assert_eq!(body_chirho, "authentication required\n");
        assert!(!polled_chirho.load(Ordering::SeqCst));
        assert_eq!(runtime_tree_snapshot_chirho(&root_chirho), before_chirho);

        let missing_route_chirho = app_http_chirho::app_route_get_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(("protected-chirho".to_string(), "missing-chirho".to_string())),
            OriginalUri(
                "/app-chirho/protected-chirho/missing-chirho"
                    .parse()
                    .unwrap(),
            ),
        )
        .await;
        let (missing_status_chirho, missing_body_chirho) =
            body_text_chirho(missing_route_chirho).await;
        assert_eq!(missing_status_chirho, StatusCode::UNAUTHORIZED);
        assert_eq!(missing_body_chirho, "authentication required\n");
    });
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn authenticated_session_reaches_the_same_protected_route_chirho() {
    let root_chirho = temp_root_chirho("request-access-session");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let root_dag_chirho = deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "protected-chirho",
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        "protected-chirho",
        "change-chirho",
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "protected-chirho",
        Some("change-chirho"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_request_access_policy_chirho(
        &root_chirho,
        "protected-chirho",
        &owner_chirho,
        root_dag_chirho,
        cairn_chirho::app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho,
    )
    .unwrap();
    let identity_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "protected-session-secret-chirho",
    )
    .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "protected-session-secret-chirho",
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        COOKIE,
        format!(
            "{AUTH_SESSION_COOKIE_CHIRHO}={}:{}",
            identity_chirho.principal_chirho, login_chirho.token_chirho
        )
        .parse()
        .unwrap(),
    );

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let polled_chirho = Arc::new(AtomicBool::new(false));
        let response_chirho = app_http_chirho::app_route_post_request_chirho(
            State(state_chirho),
            None,
            headers_chirho,
            AxPath(("protected-chirho".to_string(), "change-chirho".to_string())),
            observed_request_chirho(polled_chirho.clone()),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        assert!(polled_chirho.load(Ordering::SeqCst));
    });
    let _ = std::fs::remove_dir_all(root_chirho);
}
