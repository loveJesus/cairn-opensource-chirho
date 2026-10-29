// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn principal_session_gate_requires_matching_principal_token_chirho() {
    let root_chirho = temp_root_chirho("wallet-session-gate");
    let identity_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "session-secret-value",
    )
    .unwrap();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "session-secret-value",
    )
    .unwrap();

    let missing_headers_chirho = HeaderMap::new();
    let missing_chirho = require_principal_session_chirho(
        &root_chirho,
        &missing_headers_chirho,
        &identity_chirho.principal_chirho,
    )
    .unwrap();
    assert_eq!(missing_chirho.status(), StatusCode::UNAUTHORIZED);

    let mut wrong_headers_chirho = HeaderMap::new();
    wrong_headers_chirho.insert(AUTHORIZATION, "Bearer wrong-token".parse().unwrap());
    let wrong_chirho = require_principal_session_chirho(
        &root_chirho,
        &wrong_headers_chirho,
        &identity_chirho.principal_chirho,
    )
    .unwrap();
    assert_eq!(wrong_chirho.status(), StatusCode::FORBIDDEN);

    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", login_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    assert!(require_principal_session_chirho(
        &root_chirho,
        &headers_chirho,
        &identity_chirho.principal_chirho,
    )
    .is_none());
    let other_principal_chirho = "user/not-this-wallet";
    let other_chirho =
        require_principal_session_chirho(&root_chirho, &headers_chirho, other_principal_chirho)
            .unwrap();
    assert_eq!(other_chirho.status(), StatusCode::FORBIDDEN);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn retired_wallet_routes_are_not_served_chirho() {
    let root_chirho = temp_root_chirho("retired-wallet-routes");
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        for (method_chirho, path_chirho) in [
            ("GET", "/wallet-chirho/user/retired-chirho"),
            ("GET", "/wallet-chirho/user/retired-chirho/history-chirho"),
            ("POST", "/wallet-chirho/user/retired-chirho/convert-chirho"),
        ] {
            let response_chirho = http_request_for_smoke_chirho(
                &addr_chirho,
                method_chirho,
                path_chirho,
                &[("content-type", "application/json")],
                b"{}",
            );
            assert_eq!(response_chirho.status_chirho, 404, "{path_chirho}");
        }

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn auth_session_revoke_route_revokes_only_current_bearer_chirho() {
    let root_chirho = temp_root_chirho("auth-session-revoke-route");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "route-revoke-owner-secret",
    )
    .unwrap();
    let login_a_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "route-revoke-owner-secret",
    )
    .unwrap();
    let login_b_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "route-revoke-owner-secret",
    )
    .unwrap();
    let owner_id_chirho = owner_chirho
        .principal_chirho
        .strip_prefix("owner/")
        .unwrap()
        .to_string();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let auth_a_chirho = format!("Bearer {}", login_a_chirho.token_chirho);
        let headers_a_chirho = [("authorization", auth_a_chirho.as_str())];
        let revoke_path_chirho =
            format!("/auth-chirho/owner/{owner_id_chirho}/session-revoke-chirho");

        assert!(identity_chirho::validate_session_token_chirho(
            &root_chirho,
            &owner_chirho.principal_chirho,
            &login_a_chirho.token_chirho,
        )
        .unwrap()
        .is_some());
        assert!(identity_chirho::validate_session_token_chirho(
            &root_chirho,
            &owner_chirho.principal_chirho,
            &login_b_chirho.token_chirho,
        )
        .unwrap()
        .is_some());

        let ignored_body_chirho = b"ignored-session-revoke-body-secret@example.com";
        let revoke_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &revoke_path_chirho,
            &headers_a_chirho,
            ignored_body_chirho,
        );
        assert_eq!(revoke_chirho.status_chirho, 200);
        assert!(!http_body_text_chirho(&revoke_chirho).contains(&login_a_chirho.token_chirho));
        assert!(http_body_text_chirho(&revoke_chirho)
            .contains(&login_a_chirho.session_chirho.token_hash_chirho));
        assert_eq!(
            identity_chirho::verify_session_revocations_chirho(&root_chirho).unwrap(),
            1
        );

        assert!(identity_chirho::validate_session_token_chirho(
            &root_chirho,
            &owner_chirho.principal_chirho,
            &login_a_chirho.token_chirho,
        )
        .unwrap()
        .is_none());
        assert!(identity_chirho::validate_session_token_chirho(
            &root_chirho,
            &owner_chirho.principal_chirho,
            &login_b_chirho.token_chirho,
        )
        .unwrap()
        .is_some());
        assert_path_tree_has_no_contact_pii_chirho(
            &root_chirho,
            "session revoke ignored request body",
            &["ignored-session-revoke-body-secret@example.com"],
        );

        server_chirho.abort();
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn assert_registration_outer_gate_inert_chirho(
    root_chirho: &std::path::Path,
    before_chirho: &std::collections::BTreeMap<String, Vec<u8>>,
) {
    assert_eq!(&runtime_tree_snapshot_chirho(root_chirho), before_chirho);
    assert!(identity_chirho::load_identities_chirho(root_chirho)
        .unwrap()
        .is_empty());
    assert!(identity_chirho::load_sessions_chirho(root_chirho)
        .unwrap()
        .is_empty());
    assert!(identity_chirho::load_auth_attempts_chirho(root_chirho)
        .unwrap()
        .is_empty());
    assert!(
        cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(root_chirho)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn disabled_registration_surfaces_are_inert_before_body_or_challenge_chirho() {
    let root_chirho = temp_root_chirho("auth-registration-disabled-inert");
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let before_chirho = runtime_tree_snapshot_chirho(&root_chirho);

        for path_chirho in [
            "/auth-chirho/register-chirho",
            "/auth-chirho/human-check-chirho",
        ] {
            let response_chirho =
                http_request_for_smoke_chirho(&addr_chirho, "GET", path_chirho, &[], &[]);
            assert_eq!(response_chirho.status_chirho, 503);
            assert!(
                http_body_text_chirho(&response_chirho).contains("public registration is disabled")
            );
        }
        let malformed_post_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/register-chirho",
            &[("content-type", "application/json")],
            b"{not-json-chirho",
        );
        assert_eq!(malformed_post_chirho.status_chirho, 503);
        assert!(http_body_text_chirho(&malformed_post_chirho)
            .contains("public registration is disabled"));
        assert_registration_outer_gate_inert_chirho(&root_chirho, &before_chirho);

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn disabled_registration_keeps_browser_login_redirect_and_session_chirho() {
    let root_chirho = temp_root_chirho("auth-registration-disabled-login-live");
    let credential_chirho = "disabled-registration-login-secret-chirho";
    let identity_record_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        credential_chirho,
    )
    .unwrap();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let logout_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            "/auth-chirho/logout-chirho",
            &[],
            &[],
        );
        assert_eq!(logout_chirho.status_chirho, 303);
        assert_eq!(
            logout_chirho.headers_chirho.get("location").unwrap(),
            "/auth-chirho/login-chirho"
        );

        let login_page_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            "/auth-chirho/login-chirho",
            &[],
            &[],
        );
        assert_eq!(login_page_chirho.status_chirho, 200);
        assert!(http_body_text_chirho(&login_page_chirho)
            .contains("<form method=\"post\" action=\"/auth-chirho/login-chirho\""));

        let login_body_chirho = format!(
            "principal_chirho={}&credential_chirho={credential_chirho}",
            identity_record_chirho.principal_chirho
        );
        let login_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/login-chirho",
            &[("content-type", "application/x-www-form-urlencoded")],
            login_body_chirho.as_bytes(),
        );
        assert_eq!(login_chirho.status_chirho, 303);
        assert!(login_chirho
            .headers_chirho
            .get("set-cookie")
            .unwrap()
            .contains("cairn_session_chirho="));
        assert_eq!(
            identity_chirho::verify_sessions_chirho(&root_chirho).unwrap(),
            1
        );
        assert_eq!(
            http_request_for_smoke_chirho(
                &addr_chirho,
                "GET",
                "/auth-chirho/register-chirho",
                &[],
                &[],
            )
            .status_chirho,
            503
        );

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn absent_or_wrong_registration_token_is_inert_before_challenge_chirho() {
    let root_chirho = temp_root_chirho("auth-registration-wrong-token-inert");
    let configured_token_chirho = "configured-registration-token-secret-chirho";
    let wrong_token_chirho = "wrong-registration-token-secret-chirho";
    let absent_token_body_chirho = serde_json::to_vec(&serde_json::json!({
        "kind_chirho": "user",
        "credential_chirho": "outer-gate-credential-secret-chirho",
    }))
    .unwrap();
    let wrong_token_body_chirho = serde_json::to_vec(&serde_json::json!({
        "kind_chirho": "user",
        "credential_chirho": "outer-gate-credential-secret-chirho",
        "registration_token_chirho": wrong_token_chirho,
        "human_check_chirho": "not-an-answer-chirho",
        "human_check_token_chirho": "not-a-signed-token-chirho",
    }))
    .unwrap();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_with_registration_token_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                String::new(),
                configured_token_chirho.to_string(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let before_chirho = runtime_tree_snapshot_chirho(&root_chirho);
        for body_chirho in [&absent_token_body_chirho, &wrong_token_body_chirho] {
            let response_chirho = http_request_for_smoke_chirho(
                &addr_chirho,
                "POST",
                "/auth-chirho/register-chirho",
                &[("content-type", "application/json")],
                body_chirho,
            );
            assert_eq!(response_chirho.status_chirho, 400);
            let response_text_chirho = http_body_text_chirho(&response_chirho);
            assert!(response_text_chirho.contains("valid registration_token_chirho is required"));
            assert!(!response_text_chirho.contains(configured_token_chirho));
            assert!(!response_text_chirho.contains(wrong_token_chirho));
        }
        assert_registration_outer_gate_inert_chirho(&root_chirho, &before_chirho);

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn auth_http_routes_are_user_only_and_secret_safe_chirho() {
    let root_chirho = temp_root_chirho("auth-http-secret-safe");
    let registration_token_chirho = "m191-registration-token-secret-chirho";
    let owner_credential_chirho = "m191-owner-credential-secret@example.com";
    let grant_credential_chirho = "m191-grant-credential-secret@example.com";
    let user_credential_chirho = "m191-user-credential-secret@example.com";
    let credential_needles_chirho = [
        registration_token_chirho,
        owner_credential_chirho,
        grant_credential_chirho,
        user_credential_chirho,
    ];
    let challenge_chirho =
        identity_chirho::issue_auth_human_check_challenge_chirho(&root_chirho).unwrap();
    let answer_chirho = (0..=40)
        .map(|answer_chirho| answer_chirho.to_string())
        .find(|answer_chirho| {
            identity_chirho::verify_auth_human_check_chirho(
                &root_chirho,
                &challenge_chirho.token_chirho,
                answer_chirho,
            )
            .is_ok()
        })
        .unwrap();
    let json_headers_chirho = [("content-type", "application/json")];
    let missing_gate_register_body_chirho = serde_json::to_vec(&serde_json::json!({
        "kind_chirho": "user",
        "credential_chirho": user_credential_chirho,
        "registration_token_chirho": registration_token_chirho,
    }))
    .unwrap();
    let wrong_gate_register_body_chirho = serde_json::to_vec(&serde_json::json!({
        "kind_chirho": "user",
        "credential_chirho": user_credential_chirho,
        "registration_token_chirho": registration_token_chirho,
        "human_check_chirho": "0",
        "human_check_token_chirho": &challenge_chirho.token_chirho,
    }))
    .unwrap();
    let owner_register_body_chirho = serde_json::to_vec(&serde_json::json!({
        "kind_chirho": "owner",
        "credential_chirho": owner_credential_chirho,
        "registration_token_chirho": registration_token_chirho,
        "human_check_chirho": &answer_chirho,
        "human_check_token_chirho": &challenge_chirho.token_chirho,
    }))
    .unwrap();
    let grant_register_body_chirho = serde_json::to_vec(&serde_json::json!({
        "kind_chirho": "user",
        "grant_chirho": 100,
        "credential_chirho": grant_credential_chirho,
        "registration_token_chirho": registration_token_chirho,
        "human_check_chirho": &answer_chirho,
        "human_check_token_chirho": &challenge_chirho.token_chirho,
    }))
    .unwrap();
    let form_headers_chirho = [("content-type", "application/x-www-form-urlencoded")];
    let user_register_body_chirho = format!(
            "kind_chirho=user&credential_chirho={user_credential_chirho}&registration_token_chirho={registration_token_chirho}&human_check_chirho={answer_chirho}&human_check_token_chirho={}",
            challenge_chirho.token_chirho
        )
        .into_bytes();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_with_registration_token_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                String::new(),
                registration_token_chirho.to_string(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let missing_gate_register_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/register-chirho",
            &json_headers_chirho,
            &missing_gate_register_body_chirho,
        );
        assert_eq!(missing_gate_register_chirho.status_chirho, 400);
        assert!(http_body_text_chirho(&missing_gate_register_chirho)
            .contains("valid human-check challenge is required"));
        assert_no_contact_pii_chirho(
            "auth missing-gate registration denial response",
            &missing_gate_register_chirho.body_chirho,
            &credential_needles_chirho,
        );

        let wrong_gate_register_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/register-chirho",
            &json_headers_chirho,
            &wrong_gate_register_body_chirho,
        );
        assert_eq!(wrong_gate_register_chirho.status_chirho, 400);
        assert!(http_body_text_chirho(&wrong_gate_register_chirho)
            .contains("auth human-check answer invalid"));
        assert_no_contact_pii_chirho(
            "auth wrong-gate registration denial response",
            &wrong_gate_register_chirho.body_chirho,
            &credential_needles_chirho,
        );
        let owner_register_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/register-chirho",
            &json_headers_chirho,
            &owner_register_body_chirho,
        );
        assert_eq!(owner_register_chirho.status_chirho, 400);
        assert!(http_body_text_chirho(&owner_register_chirho)
            .contains("owner registration is CLI/admin-only"));
        assert_no_contact_pii_chirho(
            "auth owner-registration denial response",
            &owner_register_chirho.body_chirho,
            &credential_needles_chirho,
        );
        let identities_before_grant_probe_chirho =
            identity_chirho::load_identities_chirho(&root_chirho)
                .unwrap()
                .len();
        let sessions_before_grant_probe_chirho =
            identity_chirho::load_sessions_chirho(&root_chirho)
                .unwrap()
                .len();
        let attempts_before_grant_probe_chirho =
            identity_chirho::load_auth_attempts_chirho(&root_chirho)
                .unwrap()
                .len();
        let ledger_before_grant_probe_chirho =
            cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
                .unwrap()
                .len();
        let grant_register_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/register-chirho",
            &json_headers_chirho,
            &grant_register_body_chirho,
        );
        assert_eq!(grant_register_chirho.status_chirho, 400);
        assert!(http_body_text_chirho(&grant_register_chirho)
            .contains("grant_chirho is unavailable after CF6"));
        assert_no_contact_pii_chirho(
            "auth grant-registration denial response",
            &grant_register_chirho.body_chirho,
            &credential_needles_chirho,
        );
        assert_eq!(
            identity_chirho::load_identities_chirho(&root_chirho)
                .unwrap()
                .len(),
            identities_before_grant_probe_chirho
        );
        assert_eq!(
            identity_chirho::load_sessions_chirho(&root_chirho)
                .unwrap()
                .len(),
            sessions_before_grant_probe_chirho
        );
        assert_eq!(
            cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
                .unwrap()
                .len(),
            ledger_before_grant_probe_chirho
        );
        let attempts_after_grant_probe_chirho =
            identity_chirho::load_auth_attempts_chirho(&root_chirho).unwrap();
        assert_eq!(
            attempts_after_grant_probe_chirho.len(),
            attempts_before_grant_probe_chirho + 1
        );
        assert_eq!(
            attempts_after_grant_probe_chirho
                .last()
                .unwrap()
                .outcome_chirho,
            identity_chirho::IdentityAuthAttemptOutcomeChirho::FailureChirho
        );

        let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            owner_credential_chirho,
        )
        .unwrap();
        let user_register_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/register-chirho",
            &form_headers_chirho,
            &user_register_body_chirho,
        );
        assert_eq!(user_register_chirho.status_chirho, 200);
        assert!(http_body_text_chirho(&user_register_chirho).contains("registration complete"));
        assert_no_contact_pii_chirho(
            "auth user-registration response",
            &user_register_chirho.body_chirho,
            &credential_needles_chirho,
        );
        let user_principal_chirho = identity_chirho::load_identities_chirho(&root_chirho)
            .unwrap()
            .into_iter()
            .find(|record_chirho| {
                record_chirho.kind_chirho == identity_chirho::PrincipalKindChirho::UserChirho
            })
            .unwrap()
            .principal_chirho;
        assert!(user_principal_chirho.starts_with("user/"));
        assert_eq!(
            identity_chirho::verify_identities_chirho(&root_chirho).unwrap(),
            2
        );
        assert_eq!(
            identity_chirho::load_sessions_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );
        assert!(cas_chirho::get_chirho(
            &root_chirho,
            &cas_chirho::hash_chirho(&user_register_body_chirho)
        )
        .is_err());
        assert_path_tree_has_no_contact_pii_chirho(
            &root_chirho,
            "auth user-registration persisted surfaces",
            &credential_needles_chirho,
        );
        let auth_attempts_after_register_chirho =
            identity_chirho::load_auth_attempts_chirho(&root_chirho).unwrap();
        assert_eq!(auth_attempts_after_register_chirho.len(), 5);
        assert_eq!(
            auth_attempts_after_register_chirho
                .iter()
                .filter(|record_chirho| {
                    record_chirho.endpoint_chirho == identity_chirho::AUTH_ENDPOINT_REGISTER_CHIRHO
                        && record_chirho.outcome_chirho
                            == identity_chirho::IdentityAuthAttemptOutcomeChirho::SuccessChirho
                })
                .count(),
            1
        );
        assert_eq!(
            identity_chirho::verify_auth_attempts_chirho(&root_chirho).unwrap(),
            5
        );
        assert_path_tree_has_no_contact_pii_chirho(
            &root_chirho,
            "auth registration-attempt evidence",
            &credential_needles_chirho,
        );

        let correct_login_body_chirho = serde_json::to_vec(&serde_json::json!({
            "principal_chirho": user_principal_chirho,
            "credential_chirho": user_credential_chirho,
        }))
        .unwrap();
        let correct_login_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/login-chirho",
            &json_headers_chirho,
            &correct_login_body_chirho,
        );
        assert_eq!(correct_login_chirho.status_chirho, 200);
        assert_no_contact_pii_chirho(
            "auth login response",
            &correct_login_chirho.body_chirho,
            &credential_needles_chirho,
        );
        let login_json_chirho: serde_json::Value =
            serde_json::from_slice(&correct_login_chirho.body_chirho).unwrap();
        let login_token_chirho = login_json_chirho["token_chirho"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!login_token_chirho.is_empty());
        assert_eq!(
            identity_chirho::verify_sessions_chirho(&root_chirho).unwrap(),
            1
        );
        assert!(cas_chirho::get_chirho(
            &root_chirho,
            &cas_chirho::hash_chirho(&correct_login_body_chirho)
        )
        .is_err());
        assert_path_tree_has_no_contact_pii_chirho(
            &root_chirho,
            "auth login persisted credential surfaces",
            &credential_needles_chirho,
        );
        let login_token_needles_chirho = vec![login_token_chirho.as_str()];
        assert_path_tree_has_no_contact_pii_chirho(
            &root_chirho,
            "auth login persisted token surfaces",
            &login_token_needles_chirho,
        );

        let owner_login_body_chirho = format!(
            "principal_chirho={}&credential_chirho={owner_credential_chirho}",
            owner_chirho.principal_chirho
        );
        let owner_login_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/login-chirho",
            &form_headers_chirho,
            owner_login_body_chirho.as_bytes(),
        );
        assert_eq!(owner_login_chirho.status_chirho, 303);
        let set_cookie_chirho = owner_login_chirho
            .headers_chirho
            .get("set-cookie")
            .expect("login sets cookie");
        assert!(set_cookie_chirho.contains("cairn_session_chirho="));
        assert!(set_cookie_chirho.contains("HttpOnly"));
        assert!(set_cookie_chirho.contains("SameSite=Lax"));
        assert!(set_cookie_chirho.contains("Secure"));
        assert_eq!(
            owner_login_chirho.headers_chirho.get("location").unwrap(),
            "/"
        );
        let cookie_pair_chirho = set_cookie_chirho.split(';').next().unwrap();
        let cookie_header_chirho = [("cookie", cookie_pair_chirho)];
        let home_chirho =
            http_request_for_smoke_chirho(&addr_chirho, "GET", "/", &cookie_header_chirho, &[]);
        assert_eq!(home_chirho.status_chirho, 200);
        assert_no_contact_pii_chirho(
            "auth owner-cookie home response",
            &home_chirho.body_chirho,
            &credential_needles_chirho,
        );

        server_chirho.abort();
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn auth_registration_failure_records_failure_not_success_chirho() {
    let root_chirho = temp_root_chirho("auth-http-registration-failure");
    let registration_token_chirho = "m208-registration-token-secret-chirho";
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("identity-keys-chirho"),
        b"blocked-key-dir-chirho",
    )
    .unwrap();
    let credential_chirho = "m208-user-credential-secret@example.com";
    let credential_needles_chirho = [registration_token_chirho, credential_chirho];
    let challenge_chirho =
        identity_chirho::issue_auth_human_check_challenge_chirho(&root_chirho).unwrap();
    let answer_chirho = (0..=40)
        .map(|answer_chirho| answer_chirho.to_string())
        .find(|answer_chirho| {
            identity_chirho::verify_auth_human_check_chirho(
                &root_chirho,
                &challenge_chirho.token_chirho,
                answer_chirho,
            )
            .is_ok()
        })
        .unwrap();
    let register_body_chirho = serde_json::to_vec(&serde_json::json!({
        "kind_chirho": "user",
        "credential_chirho": credential_chirho,
        "registration_token_chirho": registration_token_chirho,
        "human_check_chirho": answer_chirho,
        "human_check_token_chirho": challenge_chirho.token_chirho,
    }))
    .unwrap();
    let json_headers_chirho = [("content-type", "application/json")];
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_with_registration_token_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                String::new(),
                registration_token_chirho.to_string(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let register_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/register-chirho",
            &json_headers_chirho,
            &register_body_chirho,
        );
        assert_eq!(register_chirho.status_chirho, 400);
        assert_no_contact_pii_chirho(
            "auth registration failure response",
            &register_chirho.body_chirho,
            &credential_needles_chirho,
        );
        assert_eq!(
            identity_chirho::load_identities_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            identity_chirho::load_sessions_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );
        let attempts_chirho =
            identity_chirho::load_auth_attempts_chirho(&root_chirho).expect("load auth attempts");
        assert_eq!(attempts_chirho.len(), 1);
        assert_eq!(
            attempts_chirho[0].endpoint_chirho,
            identity_chirho::AUTH_ENDPOINT_REGISTER_CHIRHO
        );
        assert_eq!(
            attempts_chirho[0].outcome_chirho,
            identity_chirho::IdentityAuthAttemptOutcomeChirho::FailureChirho
        );
        assert_eq!(
            identity_chirho::verify_auth_attempts_chirho(&root_chirho).unwrap(),
            1
        );
        assert_path_tree_has_no_contact_pii_chirho(
            &root_chirho,
            "auth registration failure persisted surfaces",
            &credential_needles_chirho,
        );
        assert!(cas_chirho::get_chirho(
            &root_chirho,
            &cas_chirho::hash_chirho(&register_body_chirho)
        )
        .is_err());

        server_chirho.abort();
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn auth_http_login_and_token_are_attempt_limited_chirho() {
    let root_chirho = temp_root_chirho("auth-http-rate-limit");
    let credential_chirho = "m193-user-credential-secret@example.com";
    let wrong_credential_chirho = "m193-wrong-credential-secret@example.com";
    let attempted_principal_chirho = "victim-m193-http@example.com";
    let credential_needles_chirho = [
        credential_chirho,
        wrong_credential_chirho,
        attempted_principal_chirho,
    ];
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        credential_chirho,
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let client_chirho = oauth_chirho::register_client_chirho(
        &root_chirho,
        "m193-auth-app",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let json_headers_chirho = [("content-type", "application/json")];
    let wrong_login_body_chirho = serde_json::to_vec(&serde_json::json!({
        "principal_chirho": user_chirho.principal_chirho,
        "credential_chirho": wrong_credential_chirho,
    }))
    .unwrap();
    let correct_login_body_chirho = serde_json::to_vec(&serde_json::json!({
        "principal_chirho": user_chirho.principal_chirho,
        "credential_chirho": credential_chirho,
    }))
    .unwrap();
    let attempted_email_login_body_chirho = serde_json::to_vec(&serde_json::json!({
        "principal_chirho": attempted_principal_chirho,
        "credential_chirho": wrong_credential_chirho,
    }))
    .unwrap();
    let wrong_token_body_chirho = serde_json::to_vec(&serde_json::json!({
        "principal_chirho": user_chirho.principal_chirho,
        "credential_chirho": wrong_credential_chirho,
        "client_id_chirho": client_chirho.client_id_chirho,
        "scopes_chirho": ["invoke_chirho"],
    }))
    .unwrap();
    let correct_token_body_chirho = serde_json::to_vec(&serde_json::json!({
        "principal_chirho": user_chirho.principal_chirho,
        "credential_chirho": credential_chirho,
        "client_id_chirho": client_chirho.client_id_chirho,
        "scopes_chirho": ["invoke_chirho"],
    }))
    .unwrap();

    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let attempted_email_login_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/login-chirho",
            &json_headers_chirho,
            &attempted_email_login_body_chirho,
        );
        assert_eq!(attempted_email_login_chirho.status_chirho, 400);
        assert_no_contact_pii_chirho(
            "auth email-shaped attempted-principal response",
            &attempted_email_login_chirho.body_chirho,
            &credential_needles_chirho,
        );

        for _ in 0..identity_chirho::PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
            let wrong_login_chirho = http_request_for_smoke_chirho(
                &addr_chirho,
                "POST",
                "/auth-chirho/login-chirho",
                &json_headers_chirho,
                &wrong_login_body_chirho,
            );
            assert_eq!(wrong_login_chirho.status_chirho, 400);
            assert_no_contact_pii_chirho(
                "auth limited wrong-login response",
                &wrong_login_chirho.body_chirho,
                &credential_needles_chirho,
            );
        }
        let limited_login_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/login-chirho",
            &json_headers_chirho,
            &correct_login_body_chirho,
        );
        assert_eq!(limited_login_chirho.status_chirho, 429);
        assert!(http_body_text_chirho(&limited_login_chirho)
            .contains("credential auth rate limit exceeded"));
        assert_no_contact_pii_chirho(
            "auth limited-login response",
            &limited_login_chirho.body_chirho,
            &credential_needles_chirho,
        );
        assert_eq!(
            identity_chirho::load_sessions_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );

        for _ in 0..identity_chirho::PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
            let wrong_token_chirho = http_request_for_smoke_chirho(
                &addr_chirho,
                "POST",
                "/auth-chirho/token-chirho",
                &json_headers_chirho,
                &wrong_token_body_chirho,
            );
            assert_eq!(wrong_token_chirho.status_chirho, 400);
            assert_no_contact_pii_chirho(
                "auth limited wrong-token response",
                &wrong_token_chirho.body_chirho,
                &credential_needles_chirho,
            );
        }
        let limited_token_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/token-chirho",
            &json_headers_chirho,
            &correct_token_body_chirho,
        );
        assert_eq!(limited_token_chirho.status_chirho, 429);
        assert!(http_body_text_chirho(&limited_token_chirho)
            .contains("credential auth rate limit exceeded"));
        assert_no_contact_pii_chirho(
            "auth limited-token response",
            &limited_token_chirho.body_chirho,
            &credential_needles_chirho,
        );
        assert_eq!(
            identity_chirho::load_sessions_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            oauth_chirho::load_scoped_tokens_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            identity_chirho::verify_auth_attempts_chirho(&root_chirho).unwrap(),
            identity_chirho::PUBLIC_AUTH_MAX_FAILURES_CHIRHO as usize * 2 + 1
        );
        for body_chirho in [
            &attempted_email_login_body_chirho,
            &wrong_login_body_chirho,
            &correct_login_body_chirho,
            &wrong_token_body_chirho,
            &correct_token_body_chirho,
        ] {
            assert!(
                cas_chirho::get_chirho(&root_chirho, &cas_chirho::hash_chirho(body_chirho))
                    .is_err()
            );
        }
        assert_path_tree_has_no_contact_pii_chirho(
            &root_chirho,
            "auth attempt-limited persisted credential surfaces",
            &credential_needles_chirho,
        );

        server_chirho.abort();
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A refused BROWSER login returns her to the canonical login page with a fixed, non-enumerating
/// token fragment instead of stranding her on a generic 400 body (PFE gpt #22916/#22919).
///
/// Four properties in one served run, each asserted separately so a failure names which one broke:
///   1. a wrong credential redirects (303) to the canonical login route with `invalid-credential-chirho`
///   2. an UNKNOWN principal produces the BYTE-IDENTICAL fragment -- no user-enumeration oracle
///   3. a caller-supplied `redirect_chirho` is IGNORED on failure: it is the post-success destination,
///      and honouring it on a refusal would bounce refusals to a page of the caller's choosing. The
///      one exception, the connection form's own accepted target while that road is open, returns to
///      the connection sign-in page rather than to the target (PFE unit 330); its arms are in
///      `connection_sign_in_http_tests_chirho.rs`. This server's road is closed.
///   4. the JSON road's status and body are UNCHANGED by this seam
///
/// Then the limiter transition proves the second token, `auth-rate-limited-chirho`.
#[test]
fn refused_browser_login_returns_to_login_with_a_fixed_nonenumerating_fragment_chirho() {
    let root_chirho = temp_root_chirho("auth-login-form-refusal-fragment");
    let credential_chirho = "login-form-refusal-secret-chirho";
    let identity_record_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        credential_chirho,
    )
    .unwrap();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let form_post_chirho = |body_chirho: String| {
            http_request_for_smoke_chirho(
                &addr_chirho,
                "POST",
                "/auth-chirho/login-chirho",
                &[("content-type", "application/x-www-form-urlencoded")],
                body_chirho.as_bytes(),
            )
        };

        // 1. WRONG CREDENTIAL on the form road -> back to the canonical login page with the token.
        let wrong_chirho = form_post_chirho(format!(
            "principal_chirho={}&credential_chirho=not-her-secret-chirho",
            identity_record_chirho.principal_chirho
        ));
        assert_eq!(
            wrong_chirho.status_chirho, 303,
            "a refused browser login must redirect, not render a generic error body"
        );
        let wrong_location_chirho = wrong_chirho.headers_chirho.get("location").unwrap().clone();
        assert_eq!(
            wrong_location_chirho, "/auth-chirho/login-chirho#refusal-invalid-credential-chirho",
            "the refusal lands on the canonical login route carrying the fixed token"
        );

        // 2. UNKNOWN PRINCIPAL -> the SAME fragment, byte for byte. A difference here would be an
        //    enumeration oracle: it would tell an attacker the name exists.
        let unknown_chirho = form_post_chirho(
            "principal_chirho=nobody-by-this-name-chirho&credential_chirho=not-her-secret-chirho"
                .to_string(),
        );
        assert_eq!(unknown_chirho.status_chirho, 303);
        assert_eq!(
            unknown_chirho.headers_chirho.get("location").unwrap(),
            &wrong_location_chirho,
            "an unknown principal and a wrong credential must be INDISTINGUISHABLE to the caller"
        );

        // 3. A supplied redirect target is the POST-SUCCESS destination and must not steer a FAILURE.
        let steered_chirho = form_post_chirho(format!(
            "principal_chirho={}&credential_chirho=not-her-secret-chirho&redirect_chirho=%2Fapp-chirho%2Fchosen-by-caller-chirho",
            identity_record_chirho.principal_chirho
        ));
        assert_eq!(steered_chirho.status_chirho, 303);
        assert_eq!(
            steered_chirho.headers_chirho.get("location").unwrap(),
            &wrong_location_chirho,
            "a failure must NOT be steered to a caller-supplied page, same-origin or not"
        );

        // 4. The JSON road is untouched: status and body exactly as before this seam existed.
        let json_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/login-chirho",
            &[("content-type", "application/json")],
            format!(
                "{{\"principal_chirho\":\"{}\",\"credential_chirho\":\"not-her-secret-chirho\"}}",
                identity_record_chirho.principal_chirho
            )
            .as_bytes(),
        );
        assert_eq!(
            json_chirho.status_chirho, 400,
            "the JSON status is unchanged by the form-road seam"
        );
        assert!(
            http_body_text_chirho(&json_chirho).contains("invalid credential_chirho or principal_chirho"),
            "the JSON sentence is unchanged by the form-road seam"
        );
        assert!(
            !json_chirho.headers_chirho.contains_key("location"),
            "the JSON road must not have acquired a redirect"
        );

        // The SECOND token: keep refusing until the public limiter trips, and prove the fragment
        // changes identity rather than staying invalid-credential. This also shows the two tokens
        // come from ONE predicate -- the same one that already moves the status to 429.
        let mut rate_limited_location_chirho = None;
        for _ in 0..12 {
            let attempt_chirho = form_post_chirho(format!(
                "principal_chirho={}&credential_chirho=not-her-secret-chirho",
                identity_record_chirho.principal_chirho
            ));
            let location_chirho = attempt_chirho.headers_chirho.get("location").unwrap().clone();
            if location_chirho != wrong_location_chirho {
                rate_limited_location_chirho = Some(location_chirho);
                break;
            }
        }
        assert_eq!(
            rate_limited_location_chirho.as_deref(),
            Some("/auth-chirho/login-chirho#refusal-auth-rate-limited-chirho"),
            "once the limiter trips the fragment must name the rate refusal, not invalid-credential"
        );

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}
