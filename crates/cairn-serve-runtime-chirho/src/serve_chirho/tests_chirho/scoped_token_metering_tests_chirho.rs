// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! One served POST is ONE scoped-token use, and an exhausted bearer answers its real refusal (429, with a reason). Before
//! this, the pre-body check resolved and CHARGED the caller, and the final recheck charged it again, so one save cost
//! three uses, and the bearer's own refusal was masked as an empty 405 (PFE #25731, CAIRN #25732, agy #25733). Route
//! and app errors stay a generic denial on purpose: served routes must not reveal route details. Driven through the
//! real POST handler.

use super::*;

pub(super) const METERED_APP_CHIRHO: &str = "meterapp";
pub(super) const METERED_ROUTE_CHIRHO: &str = "save";

/// An app whose `save` route accepts a body, and a user's scoped bearer for it allowing `max_invokes_chirho` uses.
pub(super) fn metered_route_fixture_chirho(
    label_chirho: &str,
    max_invokes_chirho: u64,
) -> (std::path::PathBuf, HeaderMap) {
    let root_chirho = temp_root_chirho(label_chirho);
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-secret-value",
    )
    .unwrap();
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "user-secret-value",
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        METERED_APP_CHIRHO,
        &owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        METERED_APP_CHIRHO,
        METERED_ROUTE_CHIRHO,
        &owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        METERED_APP_CHIRHO,
        Some(METERED_ROUTE_CHIRHO),
        &owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let client_chirho = oauth_chirho::register_client_chirho(
        &root_chirho,
        METERED_APP_CHIRHO,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_chirho = oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
        &root_chirho,
        &user_chirho.principal_chirho,
        "user-secret-value",
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
        Some(oauth_chirho::ScopedTokenRateLimitChirho {
            window_ms_chirho: 60_000,
            max_invokes_chirho,
            device_id_chirho: Some("metering-test-chirho".to_string()),
        }),
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", token_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    (root_chirho, headers_chirho)
}

/// The real POST handler a caller reaches. Returns (status, body).
fn post_metered_route_chirho(
    root_chirho: &std::path::Path,
    headers_chirho: &HeaderMap,
    route_chirho: &str,
) -> (StatusCode, String) {
    let state_chirho = app_state_for_root_chirho(root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_route_post_chirho(
            State(state_chirho),
            None,
            headers_chirho.clone(),
            AxPath((METERED_APP_CHIRHO.to_string(), route_chirho.to_string())),
            Bytes::from_static(b"draft"),
        )
        .await;
        let status_chirho = response_chirho.status();
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status_chirho,
            String::from_utf8_lossy(&body_chirho).into_owned(),
        )
    })
}

pub(super) fn scoped_token_uses_chirho(root_chirho: &std::path::Path) -> usize {
    oauth_chirho::load_scoped_token_uses_chirho(root_chirho)
        .unwrap()
        .len()
}

#[test]
fn one_served_post_records_exactly_one_scoped_token_use_chirho() {
    let (root_chirho, headers_chirho) = metered_route_fixture_chirho("metering-one-use", 10);
    let before_chirho = scoped_token_uses_chirho(&root_chirho);
    let (status_chirho, body_chirho) =
        post_metered_route_chirho(&root_chirho, &headers_chirho, METERED_ROUTE_CHIRHO);
    assert_eq!(status_chirho, StatusCode::OK, "{body_chirho}");
    assert_eq!(
        scoped_token_uses_chirho(&root_chirho) - before_chirho,
        1,
        "one POST must charge the bearer once, at its execution, not once per pre-check"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn an_exhausted_bearer_post_answers_its_refusal_not_a_bare_405_chirho() {
    let (root_chirho, headers_chirho) = metered_route_fixture_chirho("metering-exhausted", 1);
    let (status_chirho, body_chirho) =
        post_metered_route_chirho(&root_chirho, &headers_chirho, METERED_ROUTE_CHIRHO);
    assert_eq!(
        status_chirho,
        StatusCode::OK,
        "a one-use bearer must buy one POST: {body_chirho}"
    );
    let (status_chirho, body_chirho) =
        post_metered_route_chirho(&root_chirho, &headers_chirho, METERED_ROUTE_CHIRHO);
    assert_eq!(
        status_chirho,
        StatusCode::TOO_MANY_REQUESTS,
        "{body_chirho}"
    );
    assert!(!body_chirho.is_empty(), "a refusal carries its reason");
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// An unknown route stays a GENERIC denial (served routes must not reveal route details), and a POST refused before
/// execution charges the bearer nothing. Before the fix the pre-check charged it.
#[test]
fn a_post_refused_before_execution_charges_nothing_and_discloses_nothing_chirho() {
    let (root_chirho, headers_chirho) = metered_route_fixture_chirho("metering-unknown-route", 10);
    let before_chirho = scoped_token_uses_chirho(&root_chirho);
    let (status_chirho, body_chirho) =
        post_metered_route_chirho(&root_chirho, &headers_chirho, "not-deployed-chirho");
    assert_eq!(
        status_chirho,
        StatusCode::METHOD_NOT_ALLOWED,
        "{body_chirho}"
    );
    assert!(
        body_chirho.is_empty(),
        "a generic served route denial reveals no route detail: {body_chirho}"
    );
    assert_eq!(
        scoped_token_uses_chirho(&root_chirho),
        before_chirho,
        "a POST refused before execution charges nothing"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
