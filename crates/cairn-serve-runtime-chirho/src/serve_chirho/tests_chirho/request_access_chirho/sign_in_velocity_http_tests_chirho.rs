// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! THE SIGN-IN VELOCITY LIMITS over real HTTP (brick 4a; PFE #25922, agy #25924, #25938): past the principal's limit
//! or the source's, a right and a wrong password get byte-identical answers (429, one body, `Retry-After: 900`), with
//! no attempt recorded and no session made. R12 adds the source's FAILURE limit across login, token and recover (PFE
//! #26068, part D): failures reach it on every door, past it every door refuses before any write, only a recorded
//! failure charges it, and its refusal is the same bytes as the success limit's. Sources come from X-Forwarded-For,
//! which the test client's loopback peer makes trusted, exactly as behind the host's proxy.

use super::*;

const SECRET_CHIRHO: &str = "velocity-http-secret-chirho";
const WRONG_CHIRHO: &str = "velocity-http-wrong-chirho";

fn login_body_chirho(principal_chirho: &str, credential_chirho: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "principal_chirho": principal_chirho,
        "credential_chirho": credential_chirho,
    }))
    .unwrap()
}

fn login_from_chirho(
    addr_chirho: &str,
    source_chirho: &str,
    principal_chirho: &str,
    credential_chirho: &str,
) -> HttpSmokeResponseChirho {
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/login-chirho",
        &[
            ("content-type", "application/json"),
            ("x-forwarded-for", source_chirho),
        ],
        &login_body_chirho(principal_chirho, credential_chirho),
    )
}

/// The two refusals must be the same bytes: status, body, and every header but the per-second `date`.
fn assert_identical_rate_refusals_chirho(
    right_chirho: &HttpSmokeResponseChirho,
    wrong_chirho: &HttpSmokeResponseChirho,
) {
    assert_eq!(right_chirho.status_chirho, 429);
    assert_eq!(wrong_chirho.status_chirho, 429);
    assert_eq!(
        right_chirho
            .headers_chirho
            .get("retry-after")
            .map(String::as_str),
        Some(
            cairn_chirho::identity_chirho::AUTH_RATE_LIMIT_RETRY_AFTER_SECS_CHIRHO
                .to_string()
                .as_str()
        ),
        "the one constant Retry-After"
    );
    let without_date_chirho = |response_chirho: &HttpSmokeResponseChirho| {
        let mut headers_chirho = response_chirho.headers_chirho.clone();
        headers_chirho.remove("date");
        headers_chirho
    };
    assert_eq!(
        without_date_chirho(right_chirho),
        without_date_chirho(wrong_chirho),
        "the same headers for a right and a wrong password"
    );
    assert_eq!(
        right_chirho.body_chirho, wrong_chirho.body_chirho,
        "the same body for a right and a wrong password"
    );
}

fn register_user_chirho(root_chirho: &std::path::Path) -> String {
    cairn_chirho::identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho
}

/// A served runtime on a fresh root with the given limits, for the body's requests (shared with R2b's recover arms).
pub(super) fn with_limited_server_chirho(
    label_chirho: &str,
    limits_chirho: ServedRequestAbuseLimitsChirho,
    body_chirho: impl FnOnce(&std::path::Path, &str),
) {
    let root_chirho = temp_root_chirho(label_chirho);
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_with_configured_request_limits_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                String::new(),
                String::new(),
                false,
                limits_chirho,
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        body_chirho(&root_chirho, &addr_chirho);
        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Past the PRINCIPAL's limit, a right and a wrong password are refused alike, before any credential work: no attempt
/// is recorded and no session is made. From a fresh source, so only the principal's limit applies.
#[test]
fn past_the_principal_limit_a_right_and_a_wrong_password_get_the_same_http_answer_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_principal_successes_per_hour_chirho: 2,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "velocity-http-principal",
        limits_chirho,
        |root_chirho, addr_chirho| {
            let principal_chirho = register_user_chirho(root_chirho);
            for _ in 0..2 {
                let signed_in_chirho = login_from_chirho(
                    addr_chirho,
                    "198.51.100.1",
                    &principal_chirho,
                    SECRET_CHIRHO,
                );
                assert_eq!(signed_in_chirho.status_chirho, 200, "under the limit");
            }
            let attempts_before_chirho =
                cairn_chirho::identity_chirho::load_auth_attempts_chirho(root_chirho)
                    .unwrap()
                    .len();
            let sessions_before_chirho =
                cairn_chirho::identity_chirho::load_sessions_chirho(root_chirho)
                    .unwrap()
                    .len();
            let right_chirho = login_from_chirho(
                addr_chirho,
                "198.51.100.2",
                &principal_chirho,
                SECRET_CHIRHO,
            );
            let wrong_chirho =
                login_from_chirho(addr_chirho, "198.51.100.2", &principal_chirho, WRONG_CHIRHO);
            assert_identical_rate_refusals_chirho(&right_chirho, &wrong_chirho);
            assert_eq!(
                cairn_chirho::identity_chirho::load_auth_attempts_chirho(root_chirho)
                    .unwrap()
                    .len(),
                attempts_before_chirho,
                "no credential was checked, so no attempt was recorded"
            );
            assert_eq!(
                cairn_chirho::identity_chirho::load_sessions_chirho(root_chirho)
                    .unwrap()
                    .len(),
                sessions_before_chirho
            );
        },
    );
}

/// Past a SOURCE's limit, every sign-in from it is refused alike, right or wrong password, before any credential
/// work, on the token road as on login; the same principal signs in from another source. A wrong password first
/// shows a failure is never charged to the source's SUCCESS limit (it charges R12's failure limit, far above one).
#[test]
fn past_the_source_limit_a_right_and_a_wrong_password_get_the_same_http_answer_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_successes_per_hour_chirho: 2,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "velocity-http-source",
        limits_chirho,
        |root_chirho, addr_chirho| {
            let guessed_chirho = register_user_chirho(root_chirho);
            let failed_chirho =
                login_from_chirho(addr_chirho, "198.51.100.7", &guessed_chirho, WRONG_CHIRHO);
            assert_eq!(
                failed_chirho.status_chirho, 400,
                "a wrong password is refused"
            );
            for _ in 0..2 {
                let other_chirho = register_user_chirho(root_chirho);
                let signed_in_chirho =
                    login_from_chirho(addr_chirho, "198.51.100.7", &other_chirho, SECRET_CHIRHO);
                assert_eq!(
                    signed_in_chirho.status_chirho, 200,
                    "under the source limit"
                );
            }
            let principal_chirho = register_user_chirho(root_chirho);
            let attempts_before_chirho =
                cairn_chirho::identity_chirho::load_auth_attempts_chirho(root_chirho)
                    .unwrap()
                    .len();
            let right_chirho = login_from_chirho(
                addr_chirho,
                "198.51.100.7",
                &principal_chirho,
                SECRET_CHIRHO,
            );
            let wrong_chirho =
                login_from_chirho(addr_chirho, "198.51.100.7", &principal_chirho, WRONG_CHIRHO);
            assert_identical_rate_refusals_chirho(&right_chirho, &wrong_chirho);
            assert_eq!(
                cairn_chirho::identity_chirho::load_auth_attempts_chirho(root_chirho)
                    .unwrap()
                    .len(),
                attempts_before_chirho,
                "no credential was checked, so no attempt was recorded"
            );
            let owner_chirho = cairn_chirho::identity_chirho::register_identity_chirho(
                root_chirho,
                cairn_chirho::identity_chirho::PrincipalKindChirho::OwnerChirho,
            )
            .unwrap();
            let client_chirho = cairn_chirho::oauth_chirho::register_client_chirho(
                root_chirho,
                "velocity-http-app",
                &owner_chirho.principal_chirho,
            )
            .unwrap();
            let token_chirho = http_request_for_smoke_chirho(
                addr_chirho,
                "POST",
                "/auth-chirho/token-chirho",
                &[
                    ("content-type", "application/json"),
                    ("x-forwarded-for", "198.51.100.7"),
                ],
                &serde_json::to_vec(&serde_json::json!({
                    "principal_chirho": principal_chirho,
                    "credential_chirho": SECRET_CHIRHO,
                    "client_id_chirho": client_chirho.client_id_chirho,
                    "scopes_chirho": ["invoke_chirho"],
                }))
                .unwrap(),
            );
            assert_eq!(
                token_chirho.status_chirho, 429,
                "the token road is limited too"
            );
            assert_eq!(
                token_chirho.headers_chirho.get("retry-after"),
                right_chirho.headers_chirho.get("retry-after")
            );
            let elsewhere_chirho = login_from_chirho(
                addr_chirho,
                "198.51.100.8",
                &principal_chirho,
                SECRET_CHIRHO,
            );
            assert_eq!(
                elsewhere_chirho.status_chirho, 200,
                "another source is not limited"
            );
        },
    );
}

fn body_text_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    String::from_utf8_lossy(&response_chirho.body_chirho).into_owned()
}

fn token_request_chirho(
    addr_chirho: &str,
    principal_chirho: &str,
    client_id_chirho: &str,
    rate_limit_chirho: Option<serde_json::Value>,
) -> HttpSmokeResponseChirho {
    let mut body_chirho = serde_json::json!({
        "principal_chirho": principal_chirho,
        "credential_chirho": SECRET_CHIRHO,
        "client_id_chirho": client_id_chirho,
        "scopes_chirho": ["invoke_chirho"],
    });
    if let Some(rate_limit_chirho) = rate_limit_chirho {
        body_chirho["rate_limit_chirho"] = rate_limit_chirho;
    }
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/token-chirho",
        &[
            ("content-type", "application/json"),
            ("x-forwarded-for", "198.51.100.21"),
        ],
        &serde_json::to_vec(&body_chirho).unwrap(),
    )
}

/// THE ISSUANCE POLICY over real HTTP (brick 4a-2b; PFE #25915): a key requested without a policy is issued with the
/// default and the response states it; a policy above the ceiling is a 400 naming the maximum; and a principal's
/// sixth live rate-limited key is a 409 with its own sentence, never the credential sentence.
#[test]
fn the_token_endpoint_states_the_policy_and_renders_the_ceiling_and_the_cap_chirho() {
    with_limited_server_chirho(
        "issuance-policy-http",
        ServedRequestAbuseLimitsChirho::default(),
        |root_chirho, addr_chirho| {
            let principal_chirho = register_user_chirho(root_chirho);
            let owner_chirho = cairn_chirho::identity_chirho::register_identity_chirho(
                root_chirho,
                cairn_chirho::identity_chirho::PrincipalKindChirho::OwnerChirho,
            )
            .unwrap();
            let client_chirho = cairn_chirho::oauth_chirho::register_client_chirho(
                root_chirho,
                "issuance-http-app",
                &owner_chirho.principal_chirho,
            )
            .unwrap();
            let client_id_chirho = &client_chirho.client_id_chirho;
            let issued_chirho =
                token_request_chirho(addr_chirho, &principal_chirho, client_id_chirho, None);
            assert_eq!(
                issued_chirho.status_chirho,
                200,
                "{}",
                body_text_chirho(&issued_chirho)
            );
            let body_chirho: serde_json::Value =
                serde_json::from_slice(&issued_chirho.body_chirho).unwrap();
            assert_eq!(
                (
                    body_chirho["rate_limit_chirho"]["window_ms_chirho"].as_u64(),
                    body_chirho["rate_limit_chirho"]["max_invokes_chirho"].as_u64()
                ),
                (
                    Some(cairn_chirho::oauth_chirho::PUBLIC_TOKEN_DEFAULT_WINDOW_MS_CHIRHO),
                    Some(cairn_chirho::oauth_chirho::PUBLIC_TOKEN_DEFAULT_MAX_INVOKES_CHIRHO)
                ),
                "the response states the default policy: {body_chirho}"
            );
            let above_chirho = token_request_chirho(
                addr_chirho,
                &principal_chirho,
                client_id_chirho,
                Some(serde_json::json!({"window_ms_chirho": 7_200_000, "max_invokes_chirho": 10})),
            );
            assert_eq!(above_chirho.status_chirho, 400);
            assert!(
                body_text_chirho(&above_chirho).contains("3600000")
                    && !body_text_chirho(&above_chirho).contains("invalid credential"),
                "the ceiling is named, not hidden behind the credential sentence: {}",
                body_text_chirho(&above_chirho)
            );
            for _ in 1..cairn_chirho::oauth_chirho::LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO {
                let more_chirho =
                    token_request_chirho(addr_chirho, &principal_chirho, client_id_chirho, None);
                assert_eq!(
                    more_chirho.status_chirho,
                    200,
                    "{}",
                    body_text_chirho(&more_chirho)
                );
            }
            let capped_chirho =
                token_request_chirho(addr_chirho, &principal_chirho, client_id_chirho, None);
            assert_eq!(
                capped_chirho.status_chirho,
                409,
                "{}",
                body_text_chirho(&capped_chirho)
            );
            assert!(
                body_text_chirho(&capped_chirho).contains("active rate-limited keys"),
                "the cap says what happened: {}",
                body_text_chirho(&capped_chirho)
            );
        },
    );
}

// ---------------------------------------------------------------- R12: the source's failure limit (PFE #26068, part D)

const NEW_VALUE_CHIRHO: &str = "failure-limit-new-value";
const INVENTED_CODE_CHIRHO: &str = "0000-0000-0000-0000-0000-0000";

/// A well-formed principal no one registered, a fresh one per number, so no principal's own limit ever applies.
fn invented_chirho(number_chirho: u64) -> String {
    format!("user/{:016x}", 0x7e12_0000_0000_0000_u64 + number_chirho)
}

fn attempt_count_chirho(root_chirho: &std::path::Path) -> usize {
    cairn_chirho::identity_chirho::load_auth_attempts_chirho(root_chirho)
        .unwrap()
        .len()
}

/// A registered client for the token road, owned by a fresh owner.
fn client_for_tests_chirho(root_chirho: &std::path::Path) -> String {
    let owner_chirho = cairn_chirho::identity_chirho::register_identity_chirho(
        root_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    cairn_chirho::oauth_chirho::register_client_chirho(
        root_chirho,
        "failure-limit-http-app",
        &owner_chirho.principal_chirho,
    )
    .unwrap()
    .client_id_chirho
}

fn json_post_from_chirho(
    addr_chirho: &str,
    route_chirho: &str,
    source_chirho: &str,
    body_chirho: &serde_json::Value,
) -> HttpSmokeResponseChirho {
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        route_chirho,
        &[
            ("content-type", "application/json"),
            ("x-forwarded-for", source_chirho),
        ],
        &serde_json::to_vec(body_chirho).unwrap(),
    )
}

fn token_from_chirho(
    addr_chirho: &str,
    source_chirho: &str,
    principal_chirho: &str,
    credential_chirho: &str,
    client_id_chirho: &str,
) -> HttpSmokeResponseChirho {
    json_post_from_chirho(
        addr_chirho,
        "/auth-chirho/token-chirho",
        source_chirho,
        &serde_json::json!({
            "principal_chirho": principal_chirho,
            "credential_chirho": credential_chirho,
            "client_id_chirho": client_id_chirho,
            "scopes_chirho": ["invoke_chirho"],
        }),
    )
}

fn recover_from_chirho(
    addr_chirho: &str,
    source_chirho: &str,
    principal_chirho: &str,
    code_chirho: &str,
    new_credential_chirho: &str,
) -> HttpSmokeResponseChirho {
    json_post_from_chirho(
        addr_chirho,
        "/auth-chirho/recover-chirho",
        source_chirho,
        &serde_json::json!({
            "principal_chirho": principal_chirho,
            "recovery_code_chirho": code_chirho,
            "new_credential_chirho": new_credential_chirho,
        }),
    )
}

/// R12, part D: failed attempts from ONE source, one on each door and each for an invented principal, reach the
/// source's failure limit. Past it login, token and recover all refuse with their rate answer BEFORE any work: a right
/// password and a right setup code are refused too, and the whole root is byte-unchanged (no attempt row, no session,
/// no reset). Another source is unaffected: the same password signs in and the same setup code sets a password.
#[test]
fn failures_on_every_door_reach_the_source_limit_and_then_every_door_refuses_before_any_write_chirho(
) {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_failures_per_window_chirho: 3,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "failure-limit-doors",
        limits_chirho,
        |root_chirho, addr_chirho| {
            const SOURCE_CHIRHO: &str = "198.51.100.61";
            let principal_chirho = register_user_chirho(root_chirho);
            let client_id_chirho = client_for_tests_chirho(root_chirho);
            let invited_chirho = cairn_chirho::identity_chirho::invite_identity_chirho(
                root_chirho,
                cairn_chirho::identity_chirho::PrincipalKindChirho::UserChirho,
            )
            .unwrap();
            let before_chirho = attempt_count_chirho(root_chirho);
            let login_chirho = login_from_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                &invented_chirho(1),
                WRONG_CHIRHO,
            );
            let token_chirho = token_from_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                &invented_chirho(2),
                WRONG_CHIRHO,
                &client_id_chirho,
            );
            let recover_chirho = recover_from_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                &invented_chirho(3),
                INVENTED_CODE_CHIRHO,
                NEW_VALUE_CHIRHO,
            );
            assert_eq!(
                (
                    login_chirho.status_chirho,
                    token_chirho.status_chirho,
                    recover_chirho.status_chirho
                ),
                (400, 400, 400),
                "under the limit every door does its work and refuses an invented principal"
            );
            assert_eq!(
                attempt_count_chirho(root_chirho),
                before_chirho + 3,
                "each door recorded exactly one failed attempt"
            );
            let snapshot_chirho = super::recover_http_tests_chirho::snapshot_chirho(root_chirho);
            let right_chirho =
                login_from_chirho(addr_chirho, SOURCE_CHIRHO, &principal_chirho, SECRET_CHIRHO);
            let wrong_chirho =
                login_from_chirho(addr_chirho, SOURCE_CHIRHO, &principal_chirho, WRONG_CHIRHO);
            assert_identical_rate_refusals_chirho(&right_chirho, &wrong_chirho);
            let token_chirho = token_from_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                &principal_chirho,
                SECRET_CHIRHO,
                &client_id_chirho,
            );
            let recover_chirho = recover_from_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                &invited_chirho.principal_chirho,
                &invited_chirho.recovery_code_chirho,
                NEW_VALUE_CHIRHO,
            );
            for (door_chirho, response_chirho) in
                [("token", &token_chirho), ("recover", &recover_chirho)]
            {
                assert_eq!(
                    response_chirho.status_chirho, 429,
                    "the {door_chirho} road is limited too, right credential or not"
                );
                assert_eq!(
                    response_chirho.headers_chirho.get("retry-after"),
                    right_chirho.headers_chirho.get("retry-after"),
                    "the {door_chirho} road gives the one Retry-After"
                );
            }
            assert!(
                snapshot_chirho == super::recover_http_tests_chirho::snapshot_chirho(root_chirho),
                "past the limit no door wrote anything: no attempt row, no session, no reset"
            );
            const ELSEWHERE_CHIRHO: &str = "198.51.100.62";
            let signed_in_chirho = login_from_chirho(
                addr_chirho,
                ELSEWHERE_CHIRHO,
                &principal_chirho,
                SECRET_CHIRHO,
            );
            let set_chirho = recover_from_chirho(
                addr_chirho,
                ELSEWHERE_CHIRHO,
                &invited_chirho.principal_chirho,
                &invited_chirho.recovery_code_chirho,
                NEW_VALUE_CHIRHO,
            );
            assert_eq!(
                (signed_in_chirho.status_chirho, set_chirho.status_chirho),
                (200, 200),
                "another source is not limited: the password signs in, and the code sets a password"
            );
        },
    );
}

/// R12: only an attempt that RECORDED a failed row charges the source. Five successes, a refusal by a principal's own
/// limit, and five refusals that record nothing (an unknown client, a policy above the ceiling, a weak new password, a
/// confirmation that differs, a malformed body) leave the budget untouched: at a limit of two, two failures are still
/// served, and the third attempt is refused.
#[test]
fn successes_and_refusals_that_record_nothing_never_charge_the_failure_limit_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_principal_successes_per_hour_chirho: 1,
        sign_in_source_failures_per_window_chirho: 2,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "failure-limit-charges",
        limits_chirho,
        |root_chirho, addr_chirho| {
            const SOURCE_CHIRHO: &str = "198.51.100.63";
            for _ in 0..5 {
                let fresh_chirho = register_user_chirho(root_chirho);
                let signed_in_chirho =
                    login_from_chirho(addr_chirho, SOURCE_CHIRHO, &fresh_chirho, SECRET_CHIRHO);
                assert_eq!(signed_in_chirho.status_chirho, 200, "a success is served");
            }
            let principal_chirho = register_user_chirho(root_chirho);
            let first_chirho = login_from_chirho(
                addr_chirho,
                "198.51.100.64",
                &principal_chirho,
                SECRET_CHIRHO,
            );
            assert_eq!(
                first_chirho.status_chirho, 200,
                "elsewhere, the principal's one success"
            );
            let client_id_chirho = client_for_tests_chirho(root_chirho);
            let before_chirho = attempt_count_chirho(root_chirho);
            let principal_limited_chirho =
                login_from_chirho(addr_chirho, SOURCE_CHIRHO, &principal_chirho, SECRET_CHIRHO);
            assert_eq!(
                principal_limited_chirho.status_chirho, 429,
                "the principal's own limit refuses"
            );
            let unknown_client_chirho = token_from_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                &invented_chirho(11),
                WRONG_CHIRHO,
                "client/unknown-chirho",
            );
            let mut above_chirho = serde_json::json!({
                "principal_chirho": invented_chirho(12),
                "credential_chirho": WRONG_CHIRHO,
                "client_id_chirho": client_id_chirho,
                "scopes_chirho": ["invoke_chirho"],
            });
            above_chirho["rate_limit_chirho"] =
                serde_json::json!({"window_ms_chirho": 7_200_000, "max_invokes_chirho": 10});
            let ceiling_chirho = json_post_from_chirho(
                addr_chirho,
                "/auth-chirho/token-chirho",
                SOURCE_CHIRHO,
                &above_chirho,
            );
            let weak_chirho = recover_from_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                &invented_chirho(13),
                INVENTED_CODE_CHIRHO,
                "short-chirho",
            );
            let mismatch_chirho = json_post_from_chirho(
                addr_chirho,
                "/auth-chirho/recover-chirho",
                SOURCE_CHIRHO,
                &serde_json::json!({
                    "principal_chirho": invented_chirho(14),
                    "recovery_code_chirho": INVENTED_CODE_CHIRHO,
                    "new_credential_chirho": NEW_VALUE_CHIRHO,
                    "new_credential_confirm_chirho": "failure-limit-other-value",
                }),
            );
            let malformed_chirho = http_request_for_smoke_chirho(
                addr_chirho,
                "POST",
                "/auth-chirho/login-chirho",
                &[
                    ("content-type", "application/json"),
                    ("x-forwarded-for", SOURCE_CHIRHO),
                ],
                b"{",
            );
            for (what_chirho, response_chirho) in [
                ("an unknown client", &unknown_client_chirho),
                ("a policy above the ceiling", &ceiling_chirho),
                ("a weak new password", &weak_chirho),
                ("a confirmation that differs", &mismatch_chirho),
                ("a malformed body", &malformed_chirho),
            ] {
                assert_eq!(
                    response_chirho.status_chirho,
                    400,
                    "{what_chirho} is refused: {}",
                    body_text_chirho(response_chirho)
                );
            }
            assert_eq!(
                attempt_count_chirho(root_chirho),
                before_chirho,
                "none of those refusals recorded an attempt"
            );
            for number_chirho in [15, 16] {
                let failed_chirho = login_from_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    &invented_chirho(number_chirho),
                    WRONG_CHIRHO,
                );
                assert_eq!(
                    failed_chirho.status_chirho, 400,
                    "failure {number_chirho} is still served: nothing before it was charged"
                );
            }
            let limited_chirho = login_from_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                &invented_chirho(17),
                WRONG_CHIRHO,
            );
            assert_eq!(
                limited_chirho.status_chirho, 429,
                "two recorded failures fill a limit of two"
            );
        },
    );
}

/// R12: a refusal at the failure limit is the same bytes as one at the success limit, on login and on recover, so a
/// client cannot tell which limit fired (PFE #25922's rule, kept for the new limit).
#[test]
fn the_failure_limit_answers_the_same_bytes_as_the_success_limit_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_successes_per_hour_chirho: 1,
        sign_in_source_failures_per_window_chirho: 1,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "failure-limit-same-bytes",
        limits_chirho,
        |root_chirho, addr_chirho| {
            const SUCCEEDED_CHIRHO: &str = "198.51.100.65";
            const FAILED_CHIRHO: &str = "198.51.100.66";
            let principal_chirho = register_user_chirho(root_chirho);
            let signed_in_chirho = login_from_chirho(
                addr_chirho,
                SUCCEEDED_CHIRHO,
                &principal_chirho,
                SECRET_CHIRHO,
            );
            let failed_chirho = login_from_chirho(
                addr_chirho,
                FAILED_CHIRHO,
                &invented_chirho(21),
                WRONG_CHIRHO,
            );
            assert_eq!(
                (signed_in_chirho.status_chirho, failed_chirho.status_chirho),
                (200, 400),
                "one source fills its success limit, the other its failure limit"
            );
            let other_chirho = register_user_chirho(root_chirho);
            assert_identical_rate_refusals_chirho(
                &login_from_chirho(addr_chirho, SUCCEEDED_CHIRHO, &other_chirho, SECRET_CHIRHO),
                &login_from_chirho(addr_chirho, FAILED_CHIRHO, &other_chirho, SECRET_CHIRHO),
            );
            assert_identical_rate_refusals_chirho(
                &recover_from_chirho(
                    addr_chirho,
                    SUCCEEDED_CHIRHO,
                    &invented_chirho(22),
                    INVENTED_CODE_CHIRHO,
                    NEW_VALUE_CHIRHO,
                ),
                &recover_from_chirho(
                    addr_chirho,
                    FAILED_CHIRHO,
                    &invented_chirho(22),
                    INVENTED_CODE_CHIRHO,
                    NEW_VALUE_CHIRHO,
                ),
            );
        },
    );
}

/// Open a connection and send a whole request, without reading the answer; the caller hangs up later.
fn send_and_hold_open_chirho(
    addr_chirho: &str,
    route_chirho: &str,
    source_chirho: &str,
    body_chirho: &serde_json::Value,
) -> std::net::TcpStream {
    use std::io::Write;
    let body_chirho = serde_json::to_vec(body_chirho).unwrap();
    let head_chirho = format!(
        "POST {route_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\ncontent-type: application/json\r\nx-forwarded-for: {source_chirho}\r\ncontent-length: {}\r\n\r\n",
        body_chirho.len()
    );
    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho).unwrap();
    stream_chirho.write_all(head_chirho.as_bytes()).unwrap();
    stream_chirho.write_all(&body_chirho).unwrap();
    stream_chirho
}

/// R12, a MEASUREMENT of a client that hangs up while its attempt's work runs (ignored: one wait, for the handlers to
/// reach the engine, is a generous fixed delay). The root's append lock is held, so each failed attempt's work parks
/// at its append; both clients then hang up; the lock is released, and the work appends its rows. The source must be
/// charged for both: a probe that records nothing (an unknown client) then meets the 429. Run by hand with
/// `--ignored`. The deterministic pins are the hold-and-release arms in `auth_blocking_tests_chirho.rs`.
#[test]
#[ignore = "R12 measurement: a fixed delay lets the handlers reach the engine; run by hand with --ignored"]
fn a_client_that_hangs_up_while_its_work_runs_is_still_charged_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_failures_per_window_chirho: 2,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "failure-limit-hang-up",
        limits_chirho,
        |root_chirho, addr_chirho| {
            const SOURCE_CHIRHO: &str = "198.51.100.67";
            let guessed_chirho: Vec<String> =
                (0..2).map(|_| register_user_chirho(root_chirho)).collect();
            let before_chirho = attempt_count_chirho(root_chirho);
            let (held_tx_chirho, held_rx_chirho) = std::sync::mpsc::channel::<()>();
            let (release_tx_chirho, release_rx_chirho) = std::sync::mpsc::channel::<()>();
            let lock_root_chirho = root_chirho.to_path_buf();
            let holder_chirho = std::thread::spawn(move || {
                cairn_chirho::seqlog_chirho::with_append_log_lock_chirho(&lock_root_chirho, || {
                    held_tx_chirho.send(()).unwrap();
                    release_rx_chirho.recv().unwrap();
                    Ok(())
                })
                .unwrap();
            });
            held_rx_chirho.recv().unwrap();
            let streams_chirho: Vec<std::net::TcpStream> = guessed_chirho
                .iter()
                .map(|principal_chirho| {
                    send_and_hold_open_chirho(
                        addr_chirho,
                        "/auth-chirho/login-chirho",
                        SOURCE_CHIRHO,
                        &serde_json::json!({
                            "principal_chirho": principal_chirho,
                            "credential_chirho": WRONG_CHIRHO,
                        }),
                    )
                })
                .collect();
            std::thread::sleep(std::time::Duration::from_secs(3));
            for stream_chirho in &streams_chirho {
                stream_chirho.shutdown(std::net::Shutdown::Both).unwrap();
            }
            drop(streams_chirho);
            std::thread::sleep(std::time::Duration::from_secs(1));
            release_tx_chirho.send(()).unwrap();
            holder_chirho.join().unwrap();
            let deadline_chirho = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while attempt_count_chirho(root_chirho) < before_chirho + 2 {
                assert!(
                    std::time::Instant::now() < deadline_chirho,
                    "the abandoned attempts never finished their work"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let deadline_chirho = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let probe_chirho = token_from_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    &invented_chirho(41),
                    WRONG_CHIRHO,
                    "client/unknown-chirho",
                );
                if probe_chirho.status_chirho == 429 {
                    break;
                }
                assert_eq!(
                    probe_chirho.status_chirho,
                    400,
                    "the probe records nothing: {}",
                    body_text_chirho(&probe_chirho)
                );
                assert!(
                    std::time::Instant::now() < deadline_chirho,
                    "two abandoned failures appended their rows but were never charged to their source"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        },
    );
}

/// Send `count_chirho` requests together, a thread each, released at one barrier, and return their answers in order.
fn burst_chirho(
    count_chirho: usize,
    request_chirho: impl Fn(usize) -> HttpSmokeResponseChirho + Sync,
) -> Vec<HttpSmokeResponseChirho> {
    let barrier_chirho = std::sync::Barrier::new(count_chirho);
    std::thread::scope(|scope_chirho| {
        let handles_chirho: Vec<_> = (0..count_chirho)
            .map(|index_chirho| {
                let barrier_chirho = &barrier_chirho;
                let request_chirho = &request_chirho;
                scope_chirho.spawn(move || {
                    barrier_chirho.wait();
                    request_chirho(index_chirho)
                })
            })
            .collect();
        handles_chirho
            .into_iter()
            .map(|handle_chirho| handle_chirho.join().unwrap())
            .collect()
    })
}

fn statuses_chirho(answers_chirho: &[HttpSmokeResponseChirho], status_chirho: u16) -> usize {
    answers_chirho
        .iter()
        .filter(|answer_chirho| answer_chirho.status_chirho == status_chirho)
        .count()
}

/// R12 (PFE #26081, item 4): a BURST of failed attempts from one source, all in flight together, appends exactly the
/// source's failure limit. Every attempt passes the handler's early check while the queue is empty, so the bound is the
/// admission inside each blocking task, which reserves its slot before the work: exact at any permit count.
///
/// MIGRATION PATH: more rows than the limit means the task trusts the handler's check (the whole burst gets through) or
/// checks without reserving (as many get through as there are permits).
#[test]
fn a_burst_of_failures_from_one_source_appends_exactly_its_limit_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_failures_per_window_chirho: 5,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "failure-limit-burst",
        limits_chirho,
        |root_chirho, addr_chirho| {
            const SOURCE_CHIRHO: &str = "198.51.100.71";
            let before_chirho = attempt_count_chirho(root_chirho);
            let answers_chirho = burst_chirho(20, |index_chirho| {
                login_from_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    &invented_chirho(100 + index_chirho as u64),
                    WRONG_CHIRHO,
                )
            });
            assert_eq!(
                (
                    statuses_chirho(&answers_chirho, 400),
                    statuses_chirho(&answers_chirho, 429)
                ),
                (5, 15),
                "five failures are served and fifteen refused"
            );
            assert_eq!(
                attempt_count_chirho(root_chirho),
                before_chirho + 5,
                "the burst appended exactly the limit's rows"
            );
        },
    );
}

/// R12: a BURST of right-password sign-ins from one source signs in exactly the source's success limit (4a-1's limit,
/// now admitted in the task as well): five sessions, and fifteen refused before any credential work.
#[test]
fn a_burst_of_sign_ins_from_one_source_signs_in_exactly_its_limit_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_successes_per_hour_chirho: 5,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "success-limit-burst",
        limits_chirho,
        |root_chirho, addr_chirho| {
            const SOURCE_CHIRHO: &str = "198.51.100.72";
            let principals_chirho: Vec<String> =
                (0..20).map(|_| register_user_chirho(root_chirho)).collect();
            let sessions_before_chirho =
                cairn_chirho::identity_chirho::load_sessions_chirho(root_chirho)
                    .unwrap()
                    .len();
            let answers_chirho = burst_chirho(20, |index_chirho| {
                login_from_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    &principals_chirho[index_chirho],
                    SECRET_CHIRHO,
                )
            });
            assert_eq!(
                (
                    statuses_chirho(&answers_chirho, 200),
                    statuses_chirho(&answers_chirho, 429)
                ),
                (5, 15),
                "five sign-ins are served and fifteen refused"
            );
            assert_eq!(
                cairn_chirho::identity_chirho::load_sessions_chirho(root_chirho)
                    .unwrap()
                    .len(),
                sessions_before_chirho + 5,
                "the burst made exactly the limit's sessions"
            );
        },
    );
}

/// A token issue is a sign-in (brick 4a): its success charges the source's success budget as login's does. Two keys
/// issued from one source fill a limit of two, and the source's next sign-in is refused. Found by R12's harness: no
/// arm pinned the token road's success charge (C8 survived).
#[test]
fn a_token_issue_counts_toward_the_source_success_limit_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_successes_per_hour_chirho: 2,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "token-success-charge",
        limits_chirho,
        |root_chirho, addr_chirho| {
            const SOURCE_CHIRHO: &str = "198.51.100.73";
            let client_id_chirho = client_for_tests_chirho(root_chirho);
            for _ in 0..2 {
                let principal_chirho = register_user_chirho(root_chirho);
                let issued_chirho = token_from_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    &principal_chirho,
                    SECRET_CHIRHO,
                    &client_id_chirho,
                );
                assert_eq!(
                    issued_chirho.status_chirho,
                    200,
                    "{}",
                    body_text_chirho(&issued_chirho)
                );
            }
            let principal_chirho = register_user_chirho(root_chirho);
            let refused_chirho =
                login_from_chirho(addr_chirho, SOURCE_CHIRHO, &principal_chirho, SECRET_CHIRHO);
            assert_eq!(
                refused_chirho.status_chirho, 429,
                "two token issues filled the source's success limit"
            );
        },
    );
}
