// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! R2b's served road over real HTTP: `POST /auth-chirho/recover-chirho`, form and JSON. An invitee sets her first
//! password and signs in; every refusal answers its one token and status; the uniform refusal is the same bytes for
//! every way a principal and code can be wrong; both rate limits answer the same bytes; the per-source gate only CHECKS
//! (PFE ruling (a)); and the steps before the limiter write nothing. Sources come from X-Forwarded-For, which the test
//! client's loopback peer makes trusted, exactly as behind the host's proxy.

use super::sign_in_velocity_http_tests_chirho::with_limited_server_chirho;
use super::*;
use cairn_chirho::identity_chirho;

const FIRST_CHIRHO: &str = "recover-http-first-value";
const SECOND_CHIRHO: &str = "recover-http-second-value";
const WRONG_CODE_CHIRHO: &str = "0000-0000-0000-0000-0000-0000";
const SOURCE_CHIRHO: &str = "198.51.100.40";

/// One recover POST, JSON or form, from a source. `None` fields are left out of the body.
struct RecoverPostChirho<'a> {
    principal_chirho: &'a str,
    code_chirho: &'a str,
    new_chirho: &'a str,
    confirm_chirho: Option<&'a str>,
    redirect_chirho: Option<&'a str>,
}

fn recover_chirho(
    addr_chirho: &str,
    source_chirho: &str,
    json_chirho: bool,
    post_chirho: &RecoverPostChirho,
) -> HttpSmokeResponseChirho {
    let mut fields_chirho = vec![
        ("principal_chirho", post_chirho.principal_chirho),
        ("recovery_code_chirho", post_chirho.code_chirho),
        ("new_credential_chirho", post_chirho.new_chirho),
    ];
    if let Some(confirm_chirho) = post_chirho.confirm_chirho {
        fields_chirho.push(("new_credential_confirm_chirho", confirm_chirho));
    }
    if let Some(redirect_chirho) = post_chirho.redirect_chirho {
        fields_chirho.push(("redirect_chirho", redirect_chirho));
    }
    let (content_type_chirho, body_chirho) = if json_chirho {
        let map_chirho: serde_json::Map<String, serde_json::Value> = fields_chirho
            .iter()
            .map(|(key_chirho, value_chirho)| {
                (key_chirho.to_string(), serde_json::json!(value_chirho))
            })
            .collect();
        ("application/json", serde_json::to_vec(&map_chirho).unwrap())
    } else {
        let mut serializer_chirho = url::form_urlencoded::Serializer::new(String::new());
        for (key_chirho, value_chirho) in &fields_chirho {
            serializer_chirho.append_pair(key_chirho, value_chirho);
        }
        (
            "application/x-www-form-urlencoded",
            serializer_chirho.finish().into_bytes(),
        )
    };
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/recover-chirho",
        &[
            ("content-type", content_type_chirho),
            ("x-forwarded-for", source_chirho),
        ],
        &body_chirho,
    )
}

fn post_chirho<'a>(
    principal_chirho: &'a str,
    code_chirho: &'a str,
    new_chirho: &'a str,
) -> RecoverPostChirho<'a> {
    RecoverPostChirho {
        principal_chirho,
        code_chirho,
        new_chirho,
        confirm_chirho: None,
        redirect_chirho: None,
    }
}

fn login_chirho(
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
        &serde_json::to_vec(&serde_json::json!({
            "principal_chirho": principal_chirho,
            "credential_chirho": credential_chirho,
        }))
        .unwrap(),
    )
}

fn json_body_chirho(response_chirho: &HttpSmokeResponseChirho) -> serde_json::Value {
    serde_json::from_slice(&response_chirho.body_chirho).unwrap()
}

fn error_token_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    let body_chirho = json_body_chirho(response_chirho);
    assert_eq!(
        body_chirho["ok_chirho"], false,
        "a refusal says ok_chirho: false"
    );
    body_chirho["error_chirho"].as_str().unwrap().to_string()
}

/// Two responses are the same bytes: status, body, and every header but the per-second `date`.
fn assert_same_bytes_chirho(
    a_chirho: &HttpSmokeResponseChirho,
    b_chirho: &HttpSmokeResponseChirho,
    what_chirho: &str,
) {
    let without_date_chirho = |response_chirho: &HttpSmokeResponseChirho| {
        let mut headers_chirho = response_chirho.headers_chirho.clone();
        headers_chirho.remove("date");
        (
            response_chirho.status_chirho,
            headers_chirho,
            response_chirho.body_chirho.clone(),
        )
    };
    assert_eq!(
        without_date_chirho(a_chirho),
        without_date_chirho(b_chirho),
        "{what_chirho}"
    );
}

/// Every file under the root with its bytes, so a step that must write nothing is checked by content (shared with R12's
/// failure-limit arms).
pub(super) fn snapshot_chirho(
    root_chirho: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut out_chirho = std::collections::BTreeMap::new();
    let mut stack_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = stack_chirho.pop() {
        for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap().flatten() {
            let path_chirho = entry_chirho.path();
            if path_chirho.is_dir() {
                stack_chirho.push(path_chirho);
            } else {
                out_chirho.insert(
                    path_chirho.clone(),
                    std::fs::read(&path_chirho).unwrap_or_default(),
                );
            }
        }
    }
    out_chirho
}

fn invite_chirho(root_chirho: &std::path::Path) -> identity_chirho::IssuedRecoveryCodeChirho {
    identity_chirho::invite_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
}

/// The invitation's whole road over HTTP: a browser form sets her first password and lands on the sign-in page's notice
/// with any session cookie cleared; she signs in with it; the code is refused after. The JSON shapes ride along.
#[test]
fn an_invitee_sets_her_first_password_signs_in_and_the_code_is_refused_after_chirho() {
    with_limited_server_chirho(
        "recover-http-invitee",
        ServedRequestAbuseLimitsChirho::default(),
        |root_chirho, addr_chirho| {
            let issued_chirho = invite_chirho(root_chirho);
            let set_chirho = recover_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                false,
                &post_chirho(
                    &issued_chirho.principal_chirho,
                    &issued_chirho.recovery_code_chirho,
                    FIRST_CHIRHO,
                ),
            );
            assert_eq!(set_chirho.status_chirho, 303);
            assert_eq!(
                set_chirho
                    .headers_chirho
                    .get("location")
                    .map(String::as_str),
                Some("/auth-chirho/login-chirho#notice-password-set-chirho")
            );
            assert!(set_chirho
                .headers_chirho
                .get("set-cookie")
                .is_some_and(
                    |cookie_chirho| cookie_chirho.starts_with("cairn_session_chirho=;")
                        && cookie_chirho.contains("Max-Age=0")
                ));
            assert_eq!(
                login_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    &issued_chirho.principal_chirho,
                    FIRST_CHIRHO
                )
                .status_chirho,
                200
            );
            let again_chirho = recover_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                true,
                &post_chirho(
                    &issued_chirho.principal_chirho,
                    &issued_chirho.recovery_code_chirho,
                    SECOND_CHIRHO,
                ),
            );
            assert_eq!(again_chirho.status_chirho, 400);
            assert_eq!(error_token_chirho(&again_chirho), "recovery-refused-chirho");
            // A re-minted code works over JSON, with the success shape.
            let reminted_chirho = identity_chirho::mint_operator_recovery_code_chirho(
                root_chirho,
                &issued_chirho.principal_chirho,
            )
            .unwrap();
            let json_set_chirho = recover_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                true,
                &post_chirho(
                    &issued_chirho.principal_chirho,
                    &reminted_chirho.recovery_code_chirho,
                    SECOND_CHIRHO,
                ),
            );
            assert_eq!(json_set_chirho.status_chirho, 200);
            assert_eq!(
                json_body_chirho(&json_set_chirho),
                serde_json::json!({ "ok_chirho": true })
            );
            assert_eq!(
                login_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    &issued_chirho.principal_chirho,
                    SECOND_CHIRHO
                )
                .status_chirho,
                200
            );
        },
    );
}

/// Each refusal answers its one token and status. The parse, confirmation and floor refusals come before the limiter
/// and write nothing at all: no attempt row, no lock, no key write.
#[test]
fn every_refusal_answers_its_token_and_status_and_the_steps_before_the_limiter_write_nothing_chirho(
) {
    with_limited_server_chirho(
        "recover-http-refusals",
        ServedRequestAbuseLimitsChirho::default(),
        |root_chirho, addr_chirho| {
            let issued_chirho = invite_chirho(root_chirho);
            let principal_chirho = issued_chirho.principal_chirho.as_str();
            let code_chirho = issued_chirho.recovery_code_chirho.as_str();
            let before_chirho = snapshot_chirho(root_chirho);
            let unknown_field_chirho = http_request_for_smoke_chirho(
            addr_chirho,
            "POST",
            "/auth-chirho/recover-chirho",
            &[("content-type", "application/json"), ("x-forwarded-for", SOURCE_CHIRHO)],
            br#"{"principal_chirho":"user/x","recovery_code_chirho":"x","new_credential_chirho":"x","admin_chirho":true}"#,
        );
            let cases_chirho = [
                (unknown_field_chirho, "request-invalid-chirho"),
                (
                    recover_chirho(
                        addr_chirho,
                        SOURCE_CHIRHO,
                        true,
                        &post_chirho("  ", code_chirho, FIRST_CHIRHO),
                    ),
                    "request-invalid-chirho",
                ),
                (
                    recover_chirho(
                        addr_chirho,
                        SOURCE_CHIRHO,
                        true,
                        &RecoverPostChirho {
                            confirm_chirho: Some(SECOND_CHIRHO),
                            ..post_chirho(principal_chirho, code_chirho, FIRST_CHIRHO)
                        },
                    ),
                    "credential-confirmation-mismatch-chirho",
                ),
                (
                    recover_chirho(
                        addr_chirho,
                        SOURCE_CHIRHO,
                        true,
                        &post_chirho(principal_chirho, code_chirho, "fourteen-chars"),
                    ),
                    "credential-too-weak-chirho",
                ),
            ];
            for (response_chirho, token_chirho) in &cases_chirho {
                assert_eq!(response_chirho.status_chirho, 400, "{token_chirho}");
                assert_eq!(error_token_chirho(response_chirho), *token_chirho);
            }
            assert_eq!(
                snapshot_chirho(root_chirho),
                before_chirho,
                "the steps before the limiter wrote nothing"
            );
            // A confirmation that matches passes the floor step, and the uniform refusal is 400, as login's is.
            let wrong_chirho = recover_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                true,
                &RecoverPostChirho {
                    confirm_chirho: Some(FIRST_CHIRHO),
                    ..post_chirho(principal_chirho, WRONG_CODE_CHIRHO, FIRST_CHIRHO)
                },
            );
            assert_eq!(wrong_chirho.status_chirho, 400);
            assert_eq!(error_token_chirho(&wrong_chirho), "recovery-refused-chirho");
            // Invalid key state (a code half present) fails inside the lock, BEFORE the code is compared, so the password
            // is not set: 500, credential-not-set-chirho (R13, PFE #26146, #26147).
            let key_path_chirho = root_chirho
                .join("identity-keys-chirho")
                .join(format!("{}.json", principal_chirho.replace('/', "__")));
            let mut key_chirho: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&key_path_chirho).unwrap()).unwrap();
            key_chirho
                .as_object_mut()
                .unwrap()
                .remove("recovery_code_hash_chirho")
                .unwrap();
            std::fs::write(&key_path_chirho, serde_json::to_vec(&key_chirho).unwrap()).unwrap();
            let failed_chirho = recover_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                true,
                &post_chirho(principal_chirho, code_chirho, FIRST_CHIRHO),
            );
            assert_eq!(failed_chirho.status_chirho, 500);
            assert_eq!(
                error_token_chirho(&failed_chirho),
                "credential-not-set-chirho"
            );
        },
    );
}

/// R13 (PFE #26146, #26147): an internal failure answers by where it stopped against the one commit point.
/// - Before it, a key record the service cannot read (PFE's measured root-owned case) answers 500
///   `credential-not-set-chirho`, and the same code then redeems.
/// - The write itself failing (the keys folder read-only) answers 500 `recovery-failed-chirho`, since a write's error
///   can follow its rename.
/// - After the write (the reset-record log read-only), it answers 500 `recovery-failed-chirho`, and the new password
///   DOES sign in.
///
/// Each mode change is first proven to take effect, so the arm cannot pass as root by accident.
#[cfg(unix)]
#[test]
fn an_internal_failure_answers_by_where_it_stopped_against_the_commit_point_chirho() {
    use std::os::unix::fs::PermissionsExt;
    let set_mode_chirho = |path_chirho: &std::path::Path, mode_chirho: u32| {
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(mode_chirho)).unwrap()
    };
    with_limited_server_chirho(
        "recover-http-not-set",
        ServedRequestAbuseLimitsChirho::default(),
        |root_chirho, addr_chirho| {
            let redeem_chirho = |issued_chirho: &identity_chirho::IssuedRecoveryCodeChirho| {
                recover_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    true,
                    &post_chirho(
                        &issued_chirho.principal_chirho,
                        &issued_chirho.recovery_code_chirho,
                        FIRST_CHIRHO,
                    ),
                )
            };
            // Before the commit point: the key record unreadable.
            let first_chirho = invite_chirho(root_chirho);
            let key_path_chirho = root_chirho.join("identity-keys-chirho").join(format!(
                "{}.json",
                first_chirho.principal_chirho.replace('/', "__")
            ));
            set_mode_chirho(&key_path_chirho, 0o000);
            assert!(
                std::fs::read(&key_path_chirho).is_err(),
                "the mode did not take effect: run this arm as a non-root user"
            );
            let not_set_chirho = redeem_chirho(&first_chirho);
            set_mode_chirho(&key_path_chirho, 0o600);
            assert_eq!(not_set_chirho.status_chirho, 500);
            assert_eq!(
                error_token_chirho(&not_set_chirho),
                "credential-not-set-chirho"
            );
            assert_eq!(
                redeem_chirho(&first_chirho).status_chirho,
                200,
                "the same code redeems"
            );
            // The write itself: the keys folder read-only.
            let second_chirho = invite_chirho(root_chirho);
            let keys_chirho = key_path_chirho.parent().unwrap().to_path_buf();
            set_mode_chirho(&keys_chirho, 0o555);
            assert!(
                std::fs::write(keys_chirho.join("probe-chirho"), b"x").is_err(),
                "the mode did not take effect: run this arm as a non-root user"
            );
            let write_failed_chirho = redeem_chirho(&second_chirho);
            set_mode_chirho(&keys_chirho, 0o755);
            assert_eq!(write_failed_chirho.status_chirho, 500);
            assert_eq!(
                error_token_chirho(&write_failed_chirho),
                "recovery-failed-chirho"
            );
            // After the write: the reset-record log read-only (the first redemption made it).
            let third_chirho = invite_chirho(root_chirho);
            let resets_chirho = root_chirho.join("identity-credential-resets-chirho.jsonl");
            set_mode_chirho(&resets_chirho, 0o444);
            assert!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&resets_chirho)
                    .is_err(),
                "the mode did not take effect: run this arm as a non-root user"
            );
            let after_chirho = redeem_chirho(&third_chirho);
            set_mode_chirho(&resets_chirho, 0o600);
            assert_eq!(after_chirho.status_chirho, 500);
            assert_eq!(error_token_chirho(&after_chirho), "recovery-failed-chirho");
            assert_eq!(
                login_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    &third_chirho.principal_chirho,
                    FIRST_CHIRHO
                )
                .status_chirho,
                200,
                "the new password IS set, so 'may have applied' is true"
            );
        },
    );
}

/// The uniform refusal is the same bytes for an unknown principal, a principal with no code, a wrong code and a burned
/// code (R2a's engine arms cover the expired one, which needs the clock).
#[test]
fn the_uniform_refusal_is_the_same_bytes_for_every_way_a_principal_or_code_is_wrong_chirho() {
    with_limited_server_chirho(
        "recover-http-uniform",
        ServedRequestAbuseLimitsChirho::default(),
        |root_chirho, addr_chirho| {
            let burned_chirho = invite_chirho(root_chirho);
            identity_chirho::mint_operator_recovery_code_chirho(
                root_chirho,
                &burned_chirho.principal_chirho,
            )
            .unwrap();
            let live_chirho = invite_chirho(root_chirho);
            let no_code_chirho = identity_chirho::register_identity_with_credential_chirho(
                root_chirho,
                identity_chirho::PrincipalKindChirho::UserChirho,
                FIRST_CHIRHO,
            )
            .unwrap();
            let refusals_chirho = [
                recover_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    true,
                    &post_chirho("user/0123456789abcdef", WRONG_CODE_CHIRHO, FIRST_CHIRHO),
                ),
                recover_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    true,
                    &post_chirho(
                        &no_code_chirho.principal_chirho,
                        WRONG_CODE_CHIRHO,
                        FIRST_CHIRHO,
                    ),
                ),
                recover_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    true,
                    &post_chirho(
                        &live_chirho.principal_chirho,
                        WRONG_CODE_CHIRHO,
                        FIRST_CHIRHO,
                    ),
                ),
                recover_chirho(
                    addr_chirho,
                    SOURCE_CHIRHO,
                    true,
                    &post_chirho(
                        &burned_chirho.principal_chirho,
                        &burned_chirho.recovery_code_chirho,
                        FIRST_CHIRHO,
                    ),
                ),
            ];
            assert_eq!(refusals_chirho[0].status_chirho, 400);
            assert_eq!(
                error_token_chirho(&refusals_chirho[0]),
                "recovery-refused-chirho"
            );
            for other_chirho in &refusals_chirho[1..] {
                assert_same_bytes_chirho(&refusals_chirho[0], other_chirho, "the uniform refusal");
            }
        },
    );
}

/// Five failures for a principal, real or invented, then the right code: the SAME bytes as the per-source refusal, 429
/// with the one Retry-After, whichever limit fired. The source's refusal is for a FRESH invitee with a live code, so
/// only the per-source gate can refuse it. No refused attempt writes anything.
#[test]
fn both_rate_limits_answer_the_same_bytes_for_real_and_invented_principals_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_successes_per_hour_chirho: 1,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "recover-http-rates",
        limits_chirho,
        |root_chirho, addr_chirho| {
            let issued_chirho = invite_chirho(root_chirho);
            let invented_chirho = "user/0123456789abcdef";
            for principal_chirho in [issued_chirho.principal_chirho.as_str(), invented_chirho] {
                for _ in 0..identity_chirho::PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
                    let wrong_chirho = recover_chirho(
                        addr_chirho,
                        "198.51.100.41",
                        true,
                        &post_chirho(principal_chirho, WRONG_CODE_CHIRHO, FIRST_CHIRHO),
                    );
                    assert_eq!(error_token_chirho(&wrong_chirho), "recovery-refused-chirho");
                }
            }
            // A source at its limit: one successful sign-in fills a one-per-hour bucket.
            let user_chirho = identity_chirho::register_identity_with_credential_chirho(
                root_chirho,
                identity_chirho::PrincipalKindChirho::UserChirho,
                FIRST_CHIRHO,
            )
            .unwrap();
            assert_eq!(
                login_chirho(
                    addr_chirho,
                    "198.51.100.42",
                    &user_chirho.principal_chirho,
                    FIRST_CHIRHO
                )
                .status_chirho,
                200
            );
            let fresh_chirho = invite_chirho(root_chirho);
            let before_chirho = snapshot_chirho(root_chirho);
            let real_chirho = recover_chirho(
                addr_chirho,
                "198.51.100.41",
                true,
                &post_chirho(
                    &issued_chirho.principal_chirho,
                    &issued_chirho.recovery_code_chirho,
                    FIRST_CHIRHO,
                ),
            );
            let invented_refusal_chirho = recover_chirho(
                addr_chirho,
                "198.51.100.41",
                true,
                &post_chirho(invented_chirho, WRONG_CODE_CHIRHO, FIRST_CHIRHO),
            );
            let source_chirho = recover_chirho(
                addr_chirho,
                "198.51.100.42",
                true,
                &post_chirho(
                    &fresh_chirho.principal_chirho,
                    &fresh_chirho.recovery_code_chirho,
                    FIRST_CHIRHO,
                ),
            );
            assert_eq!(
                snapshot_chirho(root_chirho),
                before_chirho,
                "a rate refusal writes nothing"
            );
            assert_eq!(real_chirho.status_chirho, 429);
            assert_eq!(error_token_chirho(&real_chirho), "rate-limited-chirho");
            assert_eq!(
                real_chirho
                    .headers_chirho
                    .get("retry-after")
                    .map(String::as_str),
                Some(
                    identity_chirho::AUTH_RATE_LIMIT_RETRY_AFTER_SECS_CHIRHO
                        .to_string()
                        .as_str()
                )
            );
            assert_same_bytes_chirho(
                &real_chirho,
                &invented_refusal_chirho,
                "a real and an invented principal at the limit",
            );
            assert_same_bytes_chirho(
                &real_chirho,
                &source_chirho,
                "the principal's limit and the source's",
            );
        },
    );
}

/// PFE ruling (a): the per-source gate CHECKS recover but a success never charges it. With one success allowed per
/// source and hour, a setup then a sign-in both pass from one source; the next sign-in is refused (the gate is live).
#[test]
fn the_source_gate_checks_recover_and_a_success_never_charges_it_chirho() {
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_source_successes_per_hour_chirho: 1,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_limited_server_chirho(
        "recover-http-source",
        limits_chirho,
        |root_chirho, addr_chirho| {
            let issued_chirho = invite_chirho(root_chirho);
            let set_chirho = recover_chirho(
                addr_chirho,
                "198.51.100.43",
                true,
                &post_chirho(
                    &issued_chirho.principal_chirho,
                    &issued_chirho.recovery_code_chirho,
                    FIRST_CHIRHO,
                ),
            );
            assert_eq!(set_chirho.status_chirho, 200, "the setup passes the gate");
            assert_eq!(
                login_chirho(
                    addr_chirho,
                    "198.51.100.43",
                    &issued_chirho.principal_chirho,
                    FIRST_CHIRHO
                )
                .status_chirho,
                200,
                "the setup did not charge the source"
            );
            let refused_chirho = login_chirho(
                addr_chirho,
                "198.51.100.43",
                &issued_chirho.principal_chirho,
                FIRST_CHIRHO,
            );
            assert_eq!(
                refused_chirho.status_chirho, 429,
                "the control: the sign-in charged the source to its limit"
            );
        },
    );
}

/// A browser form's refusal goes back to its own local page with `#refusal-<token>`; a foreign target becomes `/`.
#[test]
fn a_form_refusal_carries_its_token_to_a_local_page_and_a_foreign_target_becomes_root_chirho() {
    with_limited_server_chirho(
        "recover-http-carriers",
        ServedRequestAbuseLimitsChirho::default(),
        |root_chirho, addr_chirho| {
            let issued_chirho = invite_chirho(root_chirho);
            let local_chirho = recover_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                false,
                &RecoverPostChirho {
                    redirect_chirho: Some("/app-chirho/perffection/setup-chirho#old"),
                    ..post_chirho(
                        &issued_chirho.principal_chirho,
                        WRONG_CODE_CHIRHO,
                        FIRST_CHIRHO,
                    )
                },
            );
            assert_eq!(local_chirho.status_chirho, 303);
            assert_eq!(
                local_chirho
                    .headers_chirho
                    .get("location")
                    .map(String::as_str),
                Some("/app-chirho/perffection/setup-chirho#refusal-recovery-refused-chirho")
            );
            let foreign_chirho = recover_chirho(
                addr_chirho,
                SOURCE_CHIRHO,
                false,
                &RecoverPostChirho {
                    redirect_chirho: Some("https://elsewhere.example/steal"),
                    ..post_chirho(&issued_chirho.principal_chirho, "x", "short")
                },
            );
            assert_eq!(
                foreign_chirho
                    .headers_chirho
                    .get("location")
                    .map(String::as_str),
                Some("/#refusal-credential-too-weak-chirho")
            );
        },
    );
}
