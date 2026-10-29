// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::{
    auth_browser_redirect_path_chirho, auth_session_cookie_header_chirho, escape_html_chirho,
    session_token_for_principal_chirho, support_html_head_chirho, support_html_tail_chirho,
    AppStateChirho,
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path as AxPath, State},
    http::{
        header::{CONTENT_TYPE, LOCATION, RETRY_AFTER, SET_COOKIE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    Json,
};
use cairn_chirho::{identity_chirho, oauth_chirho};

// Workflow: spec-chirho/workflows-chirho/identity-auth-chirho/public-registration-gate-chirho.md
pub(super) async fn auth_register_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    let fallback_format_chirho = auth_request_format_chirho(&headers_chirho);
    if let Some(response_chirho) =
        public_registration_disabled_response_chirho(&state_chirho, fallback_format_chirho)
    {
        return response_chirho;
    }
    let runtime_chirho = &state_chirho.runtime_chirho;
    let (req_chirho, format_chirho, legacy_grant_present_chirho) =
        match parse_auth_register_request_chirho(&headers_chirho, request_chirho).await {
            Ok(parsed_chirho) => parsed_chirho,
            // The parser's text can quote the body back, so the refusal is fixed.
            Err(_e_chirho) => {
                return auth_web_error_response_chirho(
                    fallback_format_chirho,
                    StatusCode::BAD_REQUEST,
                    AUTH_REQUEST_BODY_INVALID_CHIRHO,
                )
            }
        };
    let registration_token_valid_chirho = req_chirho
        .registration_token_chirho
        .as_deref()
        .is_some_and(|request_token_chirho| {
            identity_chirho::public_registration_token_matches_chirho(
                state_chirho.registration_token_chirho.as_str(),
                request_token_chirho,
            )
        });
    if !registration_token_valid_chirho {
        return auth_web_error_response_chirho(
            format_chirho,
            StatusCode::BAD_REQUEST,
            "valid registration_token_chirho is required for public registration",
        );
    }
    if let Err(e_chirho) = identity_chirho::verify_auth_attempts_current_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
    ) {
        return auth_failure_response_chirho(
            format_chirho,
            "auth-register-evidence-chirho",
            &e_chirho,
            AUTH_EVIDENCE_UNAVAILABLE_CHIRHO,
        );
    }
    let register_error_chirho = |status_chirho: StatusCode, error_chirho: &str| {
        auth_register_error_response_chirho(
            runtime_chirho.root_path_chirho(),
            format_chirho,
            status_chirho,
            error_chirho,
        )
    };
    // An internal failure after the attempt began: recorded as a failed attempt like any other, then
    // answered by a fixed identity, with its witness in the server log.
    let register_failure_chirho =
        |site_chirho: &'static str, error_chirho: &anyhow::Error, identity_chirho: &'static str| {
            let failure_chirho = super::public_error_chirho::classify_non_dag_chirho(
                error_chirho,
                StatusCode::BAD_REQUEST,
                identity_chirho,
            );
            eprintln!(
                "{}",
                super::public_error_chirho::witness_line_chirho(site_chirho, failure_chirho)
            );
            register_error_chirho(
                failure_chirho.status_chirho(),
                failure_chirho.identity_chirho(),
            )
        };
    if let Err(e_chirho) = identity_chirho::ensure_public_registration_attempt_allowed_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
    ) {
        return register_error_chirho(
            auth_status_for_error_chirho(&e_chirho),
            &auth_public_error_message_chirho(&e_chirho),
        );
    }
    match (
        req_chirho.human_check_token_chirho.as_deref(),
        req_chirho.human_check_chirho.as_deref(),
    ) {
        (Some(token_chirho), Some(answer_chirho)) => {
            if let Err(e_chirho) = identity_chirho::verify_auth_human_check_chirho(
                state_chirho.runtime_chirho.root_path_chirho(),
                token_chirho,
                answer_chirho,
            ) {
                // The visitor's own refusal keeps its exact sentence; a malformed token or a signing-key
                // failure answers one fixed sentence, a resource exhaustion 503.
                let refusal_chirho = e_chirho.chain().find_map(|cause_chirho| {
                    cause_chirho.downcast_ref::<identity_chirho::AuthHumanCheckRefusalChirho>()
                });
                return match refusal_chirho {
                    Some(refusal_chirho) => register_error_chirho(
                        StatusCode::BAD_REQUEST,
                        refusal_chirho.message_chirho(),
                    ),
                    None => register_failure_chirho(
                        "auth-register-human-check-chirho",
                        &e_chirho,
                        "auth human-check token invalid",
                    ),
                };
            }
        }
        _ => {
            return register_error_chirho(
                StatusCode::BAD_REQUEST,
                "valid human-check challenge is required for public registration",
            );
        }
    }
    if legacy_grant_present_chirho {
        return register_error_chirho(
            StatusCode::BAD_REQUEST,
            "grant_chirho is unavailable after CF6; registration cannot mint tokens",
        );
    }
    if req_chirho.credential_chirho.is_empty() {
        return register_error_chirho(
            StatusCode::BAD_REQUEST,
            "credential_chirho is required for HTTP registration",
        );
    }
    if !identity_chirho::credential_meets_floor_chirho(&req_chirho.credential_chirho) {
        return register_error_chirho(
            StatusCode::BAD_REQUEST,
            identity_chirho::IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO,
        );
    }
    let kind_chirho =
        match identity_chirho::PrincipalKindChirho::parse_chirho(&req_chirho.kind_chirho) {
            Ok(kind_chirho) => kind_chirho,
            Err(_e_chirho) => {
                return register_error_chirho(
                    StatusCode::BAD_REQUEST,
                    "kind_chirho is not a known principal kind",
                )
            }
        };
    if kind_chirho != identity_chirho::PrincipalKindChirho::UserChirho {
        return register_error_chirho(
            StatusCode::BAD_REQUEST,
            "owner registration is CLI/admin-only; HTTP registration creates user principals only",
        );
    }
    match identity_chirho::register_identity_with_credential_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        kind_chirho,
        &req_chirho.credential_chirho,
    ) {
        Ok(record_chirho) => {
            if let Err(e_chirho) = identity_chirho::append_public_registration_attempt_chirho(
                state_chirho.runtime_chirho.root_path_chirho(),
                identity_chirho::IdentityAuthAttemptOutcomeChirho::SuccessChirho,
            ) {
                return auth_failure_response_chirho(
                    format_chirho,
                    "auth-register-evidence-chirho",
                    &e_chirho,
                    AUTH_EVIDENCE_UNAVAILABLE_CHIRHO,
                );
            }
            auth_register_success_response_chirho(format_chirho, &record_chirho)
        }
        Err(e_chirho) => register_failure_chirho(
            "auth-register-identity-chirho",
            &e_chirho,
            "registration did not complete",
        ),
    }
}

/// The fixed refusal for an auth body that cannot be parsed: no parser text, which can quote it back.
const AUTH_REQUEST_BODY_INVALID_CHIRHO: &str = "invalid auth request body";
/// The fixed sentence for auth attempt evidence that cannot be verified or appended.
const AUTH_EVIDENCE_UNAVAILABLE_CHIRHO: &str = "registration attempt evidence did not verify";

/// An internal auth failure's answer in the auth road's own shape: a fixed identity and its status, a
/// typed resource exhaustion answering 503, with the typed witness in the server log.
pub(super) fn auth_failure_response_chirho(
    format_chirho: AuthRequestFormatChirho,
    site_chirho: &'static str,
    error_chirho: &anyhow::Error,
    identity_chirho: &'static str,
) -> Response {
    let failure_chirho = super::public_error_chirho::classify_non_dag_chirho(
        error_chirho,
        StatusCode::BAD_REQUEST,
        identity_chirho,
    );
    eprintln!(
        "{}",
        super::public_error_chirho::witness_line_chirho(site_chirho, failure_chirho)
    );
    auth_web_error_response_chirho(
        format_chirho,
        failure_chirho.status_chirho(),
        failure_chirho.identity_chirho(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AuthRequestFormatChirho {
    JsonChirho,
    FormChirho,
}

// Workflow: spec-chirho/workflows-chirho/identity-auth-chirho/public-registration-gate-chirho.md
pub(super) fn public_registration_disabled_response_chirho(
    state_chirho: &AppStateChirho,
    format_chirho: AuthRequestFormatChirho,
) -> Option<Response> {
    state_chirho
        .registration_token_chirho
        .trim()
        .is_empty()
        .then(|| {
            auth_web_error_response_chirho(
                format_chirho,
                StatusCode::SERVICE_UNAVAILABLE,
                "public registration is disabled until registration_token_chirho is configured",
            )
        })
}

const MAX_AUTH_BODY_BYTES_CHIRHO: usize = 16 * 1024;

pub(super) async fn auth_body_bytes_chirho(
    request_chirho: axum::http::Request<axum::body::Body>,
) -> anyhow::Result<Bytes> {
    let bytes_chirho =
        axum::body::to_bytes(request_chirho.into_body(), MAX_AUTH_BODY_BYTES_CHIRHO + 1)
            .await
            .map_err(|_| anyhow::anyhow!("read auth body failed"))?;
    if bytes_chirho.len() > MAX_AUTH_BODY_BYTES_CHIRHO {
        anyhow::bail!("auth body too large");
    }
    Ok(bytes_chirho)
}

pub(super) fn auth_request_format_chirho(headers_chirho: &HeaderMap) -> AuthRequestFormatChirho {
    headers_chirho
        .get(CONTENT_TYPE)
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .map(|value_chirho| value_chirho.to_ascii_lowercase())
        .filter(|value_chirho| value_chirho.starts_with("application/x-www-form-urlencoded"))
        .map(|_| AuthRequestFormatChirho::FormChirho)
        .unwrap_or(AuthRequestFormatChirho::JsonChirho)
}

async fn parse_auth_register_request_chirho(
    headers_chirho: &HeaderMap,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> anyhow::Result<(
    identity_chirho::AuthRegisterRequestChirho,
    AuthRequestFormatChirho,
    bool,
)> {
    let format_chirho = auth_request_format_chirho(headers_chirho);
    let bytes_chirho = auth_body_bytes_chirho(request_chirho).await?;
    let (req_chirho, legacy_grant_present_chirho) = match format_chirho {
        AuthRequestFormatChirho::JsonChirho => {
            let value_chirho: serde_json::Value = serde_json::from_slice(&bytes_chirho)?;
            let legacy_grant_present_chirho = value_chirho
                .as_object()
                .is_some_and(|object_chirho| object_chirho.contains_key("grant_chirho"));
            (
                serde_json::from_value(value_chirho)?,
                legacy_grant_present_chirho,
            )
        }
        AuthRequestFormatChirho::FormChirho => {
            auth_register_request_from_form_chirho(&bytes_chirho)?
        }
    };
    Ok((req_chirho, format_chirho, legacy_grant_present_chirho))
}

fn auth_register_request_from_form_chirho(
    bytes_chirho: &[u8],
) -> anyhow::Result<(identity_chirho::AuthRegisterRequestChirho, bool)> {
    let mut req_chirho = identity_chirho::AuthRegisterRequestChirho {
        kind_chirho: "user".to_string(),
        ..Default::default()
    };
    let mut legacy_grant_present_chirho = false;
    for (key_chirho, value_chirho) in url::form_urlencoded::parse(bytes_chirho) {
        match key_chirho.as_ref() {
            "kind_chirho" => req_chirho.kind_chirho = value_chirho.into_owned(),
            "grant_chirho" => legacy_grant_present_chirho = true,
            "credential_chirho" => req_chirho.credential_chirho = value_chirho.into_owned(),
            "registration_token_chirho" => {
                req_chirho.registration_token_chirho = Some(value_chirho.into_owned())
            }
            "human_check_chirho" => req_chirho.human_check_chirho = Some(value_chirho.into_owned()),
            "human_check_token_chirho" => {
                req_chirho.human_check_token_chirho = Some(value_chirho.into_owned())
            }
            _ => {}
        }
    }
    Ok((req_chirho, legacy_grant_present_chirho))
}

pub(super) async fn parse_auth_login_request_chirho(
    headers_chirho: &HeaderMap,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> anyhow::Result<(
    identity_chirho::AuthLoginRequestChirho,
    AuthRequestFormatChirho,
)> {
    let format_chirho = auth_request_format_chirho(headers_chirho);
    let bytes_chirho = auth_body_bytes_chirho(request_chirho).await?;
    let req_chirho = match format_chirho {
        AuthRequestFormatChirho::JsonChirho => serde_json::from_slice(&bytes_chirho)?,
        AuthRequestFormatChirho::FormChirho => {
            let mut req_chirho = identity_chirho::AuthLoginRequestChirho::default();
            for (key_chirho, value_chirho) in url::form_urlencoded::parse(&bytes_chirho) {
                match key_chirho.as_ref() {
                    "principal_chirho" => req_chirho.principal_chirho = value_chirho.into_owned(),
                    "credential_chirho" => req_chirho.credential_chirho = value_chirho.into_owned(),
                    "redirect_chirho" => {
                        // A repeated target is malformed (PFE #27196): it refuses here, before any credential proof
                        // and any session or attempt append, so an ambiguous request never authenticates. Only this
                        // field is narrowed; a repeated principal or credential is a recorded residual (PFE #27203).
                        if req_chirho.redirect_chirho.is_some() {
                            anyhow::bail!("a form login repeated redirect_chirho");
                        }
                        req_chirho.redirect_chirho = Some(value_chirho.into_owned())
                    }
                    _ => {}
                }
            }
            req_chirho
        }
    };
    Ok((req_chirho, format_chirho))
}

fn auth_register_error_response_chirho(
    root_chirho: &std::path::Path,
    format_chirho: AuthRequestFormatChirho,
    status_chirho: StatusCode,
    error_chirho: &str,
) -> Response {
    match identity_chirho::append_public_registration_attempt_chirho(
        root_chirho,
        identity_chirho::IdentityAuthAttemptOutcomeChirho::FailureChirho,
    ) {
        Ok(_) => auth_web_error_response_chirho(format_chirho, status_chirho, error_chirho),
        Err(e_chirho) => auth_failure_response_chirho(
            format_chirho,
            "auth-register-evidence-chirho",
            &e_chirho,
            AUTH_EVIDENCE_UNAVAILABLE_CHIRHO,
        ),
    }
}

fn auth_register_success_response_chirho(
    format_chirho: AuthRequestFormatChirho,
    record_chirho: &identity_chirho::IdentityRecordChirho,
) -> Response {
    match format_chirho {
        AuthRequestFormatChirho::JsonChirho => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok_chirho": true,
                "principal_chirho": record_chirho.principal_chirho,
                "wallet_chirho": record_chirho.wallet_chirho,
                "pubkey_chirho": record_chirho.pubkey_chirho,
            })),
        )
            .into_response(),
        AuthRequestFormatChirho::FormChirho => (
            StatusCode::OK,
            [(CONTENT_TYPE, "text/html; charset=utf-8")],
            format!(
                "{}<h1>registration complete</h1><p>principal <code>{}</code></p><p><a href=\"/auth-chirho/login-chirho\">log in</a></p>{}",
                support_html_head_chirho("auth registration complete"),
                escape_html_chirho(&record_chirho.principal_chirho),
                support_html_tail_chirho()
            ),
        )
            .into_response(),
    }
}

pub(super) fn auth_web_error_response_chirho(
    format_chirho: AuthRequestFormatChirho,
    status_chirho: StatusCode,
    error_chirho: &str,
) -> Response {
    match format_chirho {
        AuthRequestFormatChirho::JsonChirho => (
            status_chirho,
            Json(serde_json::json!({"ok_chirho": false, "error_chirho": error_chirho})),
        )
            .into_response(),
        AuthRequestFormatChirho::FormChirho => (
            status_chirho,
            [(CONTENT_TYPE, "text/html; charset=utf-8")],
            format!(
                "{}<h1>auth error</h1><pre>{}</pre>{}",
                support_html_head_chirho("auth error"),
                escape_html_chirho(error_chirho),
                support_html_tail_chirho()
            ),
        )
            .into_response(),
    }
}

pub(super) fn auth_login_success_response_chirho(
    format_chirho: AuthRequestFormatChirho,
    login_chirho: &identity_chirho::IdentityLoginResultChirho,
    redirect_chirho: Option<&str>,
) -> Response {
    let cookie_chirho = auth_session_cookie_header_chirho(
        &login_chirho.session_chirho.principal_chirho,
        &login_chirho.token_chirho,
    );
    let mut response_chirho = match format_chirho {
        AuthRequestFormatChirho::JsonChirho => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok_chirho": true,
                "principal_chirho": login_chirho.session_chirho.principal_chirho,
                "token_chirho": login_chirho.token_chirho,
                "expires_ms_chirho": login_chirho.session_chirho.expires_ms_chirho,
                "session_seq_chirho": login_chirho.session_chirho.seq_chirho,
            })),
        )
            .into_response(),
        AuthRequestFormatChirho::FormChirho => {
            let mut response_chirho = StatusCode::SEE_OTHER.into_response();
            response_chirho.headers_mut().insert(
                LOCATION,
                HeaderValue::from_str(&auth_browser_redirect_path_chirho(
                    &login_chirho.session_chirho.principal_chirho,
                    redirect_chirho,
                ))
                .unwrap(),
            );
            response_chirho
        }
    };
    response_chirho
        .headers_mut()
        .insert(SET_COOKIE, HeaderValue::from_str(&cookie_chirho).unwrap());
    response_chirho
}

/// Every sign-in rate refusal carries ONE `Retry-After`, whichever limit refused (agy #25938): the status, the
/// sentence and this header all follow the one `is_auth_rate_limit_error_chirho` predicate.
fn auth_error_response_chirho(
    format_chirho: AuthRequestFormatChirho,
    e_chirho: anyhow::Error,
) -> Response {
    let status_chirho = auth_status_for_error_chirho(&e_chirho);
    let mut response_chirho = auth_web_error_response_chirho(
        format_chirho,
        status_chirho,
        &auth_public_error_message_chirho(&e_chirho),
    );
    if status_chirho == StatusCode::TOO_MANY_REQUESTS {
        response_chirho.headers_mut().insert(
            RETRY_AFTER,
            HeaderValue::from(identity_chirho::AUTH_RATE_LIMIT_RETRY_AFTER_SECS_CHIRHO),
        );
    }
    response_chirho
}

fn auth_status_for_error_chirho(e_chirho: &anyhow::Error) -> StatusCode {
    if identity_chirho::is_auth_rate_limit_error_chirho(e_chirho) {
        StatusCode::TOO_MANY_REQUESTS
    } else if e_chirho
        .downcast_ref::<oauth_chirho::ScopedTokenCapReachedChirho>()
        .is_some()
    {
        // Brick 4a-2b: only reachable after the credential is proved, so it tells nothing to a guesser.
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// The canonical login route. Must byte-match the `/auth-chirho/login-chirho` registration in
/// `serve_chirho.rs`; `auth_credential_change_chirho.rs` holds its own copy for the same string.
const LOGIN_ROUTE_CHIRHO: &str = "/auth-chirho/login-chirho";

/// The stable fragment token a REFUSED BROWSER LOGIN carries back to the login page.
///
/// Two values, decided by the SAME `is_auth_rate_limit_error_chirho` predicate that already decides
/// this road's status and its sentence -- so a refusal cannot end up with a token saying one thing
/// beside a sentence saying another, and there is no third enforcement point for one decision.
///
/// `InvalidCredentialChirho` deliberately covers BOTH an unknown principal and a wrong credential.
/// The public sentence already collapses them (`auth_public_error_message_chirho` returns one string
/// for both); a token that split them would put the user-enumeration oracle back that the collapsed
/// sentence exists to close. Never derive this from the message text -- one predicate, two outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginRefusalTokenChirho {
    InvalidCredentialChirho,
    AuthRateLimitedChirho,
}

impl LoginRefusalTokenChirho {
    fn for_error_chirho(e_chirho: &anyhow::Error) -> Self {
        if identity_chirho::is_auth_rate_limit_error_chirho(e_chirho) {
            Self::AuthRateLimitedChirho
        } else {
            Self::InvalidCredentialChirho
        }
    }

    fn token_chirho(self) -> &'static str {
        match self {
            Self::InvalidCredentialChirho => "invalid-credential-chirho",
            Self::AuthRateLimitedChirho => "auth-rate-limited-chirho",
        }
    }
}

/// A refused browser login lands back on a sign-in page carrying a fixed token fragment; a JSON
/// caller's status and body are byte-for-byte what they were before this function existed.
///
/// The FORM road never lets `redirect_chirho` steer a failure. That parameter is the post-SUCCESS
/// destination; honouring it on a FAILURE would let anyone craft a login form that bounces a refusal
/// to a page of their choosing, and `safe_auth_redirect_target_chirho` keeping it same-origin does
/// not make it the right destination for a failure. So every refusal goes to a fixed sign-in page:
/// the canonical login route, or, while the connection road is open and the one target is that
/// form's own accepted target, the connection sign-in page carrying it (PFE unit 330, #27196). A
/// failure never goes to the target itself, and no other target is kept.
///
/// Authority and abuse budget are untouched: this shapes the response AFTER the decision, at both
/// refusal exits (the source check and the blocking result), and charges nothing itself.
fn login_refusal_response_chirho(
    format_chirho: AuthRequestFormatChirho,
    e_chirho: anyhow::Error,
    connection_open_chirho: bool,
    redirect_chirho: Option<&str>,
) -> Response {
    match format_chirho {
        AuthRequestFormatChirho::FormChirho => {
            let token_chirho = LoginRefusalTokenChirho::for_error_chirho(&e_chirho).token_chirho();
            super::redirect_chirho(
                &super::auth_connection_new_chirho::sign_in_refusal_location_chirho(
                    connection_open_chirho,
                    redirect_chirho,
                    token_chirho,
                )
                .unwrap_or_else(|| format!("{LOGIN_ROUTE_CHIRHO}#refusal-{token_chirho}")),
            )
        }
        AuthRequestFormatChirho::JsonChirho => auth_error_response_chirho(format_chirho, e_chirho),
    }
}

fn auth_public_error_message_chirho(e_chirho: &anyhow::Error) -> String {
    if identity_chirho::is_auth_rate_limit_error_chirho(e_chirho) {
        "credential auth rate limit exceeded".to_string()
    } else if let Some(ceiling_chirho) =
        e_chirho.downcast_ref::<oauth_chirho::ScopedTokenPolicyAboveCeilingChirho>()
    {
        // Brick 4a-2b: checked before any credential work, so naming the maximum reveals nothing about an account.
        ceiling_chirho.to_string()
    } else if let Some(cap_chirho) =
        e_chirho.downcast_ref::<oauth_chirho::ScopedTokenCapReachedChirho>()
    {
        cap_chirho.to_string()
    } else if let Some(limited_chirho) =
        e_chirho.downcast_ref::<oauth_chirho::LegacyKeyForLimitedAppChirho>()
    {
        // K1: decided from the client's app before any credential work, so it names the app's key mode and nothing
        // about an account; a caller with a right credential is not told it is wrong.
        limited_chirho.to_string()
    } else {
        "invalid credential_chirho or principal_chirho".to_string()
    }
}

pub(super) async fn auth_login_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    let fallback_format_chirho = auth_request_format_chirho(&headers_chirho);
    let (req_chirho, format_chirho) =
        match parse_auth_login_request_chirho(&headers_chirho, request_chirho).await {
            Ok(parsed_chirho) => parsed_chirho,
            // The parser's text can quote the body back, so the refusal is fixed.
            Err(_e_chirho) => {
                return auth_web_error_response_chirho(
                    fallback_format_chirho,
                    StatusCode::BAD_REQUEST,
                    AUTH_REQUEST_BODY_INVALID_CHIRHO,
                )
            }
        };
    // The source's sign-in velocity, BEFORE any credential work (brick 4a); a refusal renders as every rate refusal,
    // and keeps the connection form's accepted target as the blocking refusal does (PFE unit 330).
    let connection_open_chirho = state_chirho.connection_issuance_enabled_chirho;
    let sign_in_gate_chirho = state_chirho.sign_in_gate_chirho.clone();
    let source_chirho = match sign_in_gate_chirho.check_source_chirho(
        connect_info_chirho.map(|ConnectInfo(peer_chirho)| peer_chirho),
        &headers_chirho,
        identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
    ) {
        Ok(source_chirho) => source_chirho,
        Err(e_chirho) => {
            return login_refusal_response_chirho(
                format_chirho,
                e_chirho,
                connection_open_chirho,
                req_chirho.redirect_chirho.as_deref(),
            )
        }
    };
    let velocity_chirho = sign_in_gate_chirho.velocity_chirho();
    // Sign-in work (log verification, Argon2id, signing, the locked append) runs off the async workers.
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho().to_path_buf();
    let principal_chirho = req_chirho.principal_chirho.clone();
    let credential_chirho = req_chirho.credential_chirho.clone();
    // R12: the gate meters this attempt inside its blocking task: admitted and reserved before the work, settled
    // after it, so neither a queued burst nor a client that hangs up mid-request can slip past the source's limits.
    let meter_chirho = sign_in_gate_chirho.meter_chirho(
        source_chirho,
        identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
        super::sign_in_gate_chirho::SignInChargesChirho::SuccessesAndFailuresChirho,
    );
    match super::auth_blocking_chirho::run_blocking_public_auth_chirho(meter_chirho, move || {
        identity_chirho::login_identity_with_public_auth_limit_outcome_chirho(
            &root_chirho,
            &principal_chirho,
            &credential_chirho,
            identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
            &velocity_chirho,
        )
    })
    .await
    {
        Ok(login_chirho) => auth_login_success_response_chirho(
            format_chirho,
            &login_chirho,
            req_chirho.redirect_chirho.as_deref(),
        ),
        Err(refusal_chirho) => login_refusal_response_chirho(
            format_chirho,
            refusal_chirho.error_chirho,
            connection_open_chirho,
            req_chirho.redirect_chirho.as_deref(),
        ),
    }
}

pub(super) async fn auth_token_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    Json(req_chirho): Json<oauth_chirho::ScopedTokenRequestChirho>,
) -> Response {
    // A token issue is a sign-in: the source's velocity first, BEFORE any credential work (brick 4a).
    let sign_in_gate_chirho = state_chirho.sign_in_gate_chirho.clone();
    let source_chirho = match sign_in_gate_chirho.check_source_chirho(
        connect_info_chirho.map(|ConnectInfo(peer_chirho)| peer_chirho),
        &headers_chirho,
        identity_chirho::AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
    ) {
        Ok(source_chirho) => source_chirho,
        Err(e_chirho) => {
            return auth_error_response_chirho(AuthRequestFormatChirho::JsonChirho, e_chirho)
        }
    };
    let velocity_chirho = sign_in_gate_chirho.velocity_chirho();
    // Token issuance tests a credential (Argon2id) and charges the attempt log: off the async workers too.
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho().to_path_buf();
    // R12: metered in the blocking task, as login's. Only a refused credential records a failed row; the policy,
    // client and cap refusals record none, so they release their reserved slots.
    let meter_chirho = sign_in_gate_chirho.meter_chirho(
        source_chirho,
        identity_chirho::AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
        super::sign_in_gate_chirho::SignInChargesChirho::SuccessesAndFailuresChirho,
    );
    match super::auth_blocking_chirho::run_blocking_public_auth_chirho(meter_chirho, move || {
        oauth_chirho::issue_scoped_token_with_public_auth_limit_outcome_chirho(
            &root_chirho,
            &req_chirho.principal_chirho,
            &req_chirho.credential_chirho,
            &req_chirho.client_id_chirho,
            req_chirho.scopes_chirho,
            req_chirho.rate_limit_chirho,
            &velocity_chirho,
        )
    })
    .await
    {
        Ok(issue_chirho) => issued_token_response_chirho(issue_chirho),
        Err(refusal_chirho) => auth_error_response_chirho(
            AuthRequestFormatChirho::JsonChirho,
            refusal_chirho.error_chirho,
        ),
    }
}

fn issued_token_response_chirho(issue_chirho: oauth_chirho::ScopedTokenIssueChirho) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok_chirho": true,
            "principal_chirho": issue_chirho.record_chirho.principal_chirho,
            "client_id_chirho": issue_chirho.record_chirho.client_id_chirho,
            "app_chirho": issue_chirho.record_chirho.app_chirho,
            "scopes_chirho": issue_chirho.record_chirho.scopes_chirho,
            "token_chirho": issue_chirho.token_chirho,
            "expires_ms_chirho": issue_chirho.record_chirho.expires_ms_chirho,
            // The policy the key was issued with, the public default included (brick 4a-2b).
            "rate_limit_chirho": issue_chirho.record_chirho.rate_limit_chirho,
        })),
    )
        .into_response()
}

pub(super) async fn auth_session_revoke_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath((kind_chirho, id_chirho)): AxPath<(String, String)>,
    _request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    let principal_chirho = format!("{kind_chirho}/{id_chirho}");
    let runtime_chirho = &state_chirho.runtime_chirho;
    if let Some(response_chirho) =
        runtime_chirho.require_principal_session_chirho(&headers_chirho, &principal_chirho)
    {
        return response_chirho;
    }
    let token_chirho = match session_token_for_principal_chirho(&headers_chirho, &principal_chirho)
    {
        Some(token_chirho) => token_chirho,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"ok_chirho": false, "error_chirho": "Authorization Bearer token or cairn_session_chirho cookie required"})),
            )
                .into_response()
        }
    };
    match identity_chirho::revoke_session_token_chirho(
        runtime_chirho.root_path_chirho(),
        &principal_chirho,
        &token_chirho,
        "owner-session-chirho",
        "owner-logout-chirho",
    ) {
        Ok(record_chirho) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok_chirho": true,
                "revocation_seq_chirho": record_chirho.seq_chirho,
                "session_seq_chirho": record_chirho.session_seq_chirho,
                "token_hash_chirho": record_chirho.token_hash_chirho,
            })),
        )
            .into_response(),
        Err(e_chirho) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok_chirho": false, "error_chirho": e_chirho.to_string()})),
        )
            .into_response(),
    }
}
