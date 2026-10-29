// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Composes private runtime state and shared served admission responses.

use super::*;

pub(super) fn app_state_for_runtime_root_with_effect_runtime_chirho(
    root_chirho: &std::path::Path,
    options_chirho: RuntimeAppStateOptionsChirho,
) -> Result<AppStateChirho> {
    let RuntimeAppStateOptionsChirho {
        inflight_limit_chirho,
        auth_tokens_chirho,
        domain_routing_enabled_chirho,
        served_request_limits_chirho,
        projection_read_chirho,
        postgres_effect_chirho,
        llm_served_chirho,
        write_dispatch_chirho,
        local_read_authority_chirho,
        write_destination_slot_chirho,
    } = options_chirho;
    let ServeAuthTokensChirho {
        publish_token_chirho,
        registration_token_chirho,
        connection_issuance_enabled_chirho,
    } = auth_tokens_chirho;
    let tenant_chirho = tenant_chirho::tenant_id_for_root_chirho(root_chirho)?;
    let relay_scope_chirho = write_dispatch_chirho
        .as_deref()
        .and_then(|dispatch_chirho| dispatch_chirho.ingress_scope_chirho());
    if let Some(scope_chirho) = &relay_scope_chirho {
        let tenant_chirho::TenantIdChirho::TenantChirho(tenant_id_chirho) = &tenant_chirho else {
            anyhow::bail!("RelayPlatformRootIdentityUnavailableChirho");
        };
        let group_chirho = cairn_write_relay_chirho::relay_tenant_consistency_group_digest_chirho(
            tenant_id_chirho,
        )?;
        if scope_chirho.consistency_group_digest_chirho() != group_chirho {
            anyhow::bail!("RelayConsistencyGroupMismatchChirho");
        }
    }
    let state_chirho = AppStateChirho {
        runtime_chirho: Arc::new(ServedRuntimeRootChirho::with_effect_runtime_chirho(
            root_chirho,
            projection_read_chirho,
            postgres_effect_chirho,
            llm_served_chirho,
        )),
        tenant_chirho,
        invoke_lock_chirho: Arc::new(tokio::sync::Mutex::new(())),
        inflight_chirho: Arc::new(tokio::sync::Semaphore::new(inflight_limit_chirho)),
        served_request_abuse_gate_chirho: Arc::new(
            ServedRequestAbuseGateChirho::with_relay_scope_chirho(
                served_request_limits_chirho,
                relay_scope_chirho,
            )?,
        ),
        sign_in_gate_chirho: Arc::new(SignInGateChirho::new_chirho(&served_request_limits_chirho)),
        publish_token_chirho: Arc::new(publish_token_chirho),
        registration_token_chirho: Arc::new(registration_token_chirho),
        connection_issuance_enabled_chirho,
        domain_routing_enabled_chirho,
        write_dispatch_chirho,
        local_read_authority_chirho,
    };
    if let Some(slot_chirho) = write_destination_slot_chirho {
        write_relay_chirho::install_relay_destination_chirho(&slot_chirho, state_chirho.clone())?;
    }
    Ok(state_chirho)
}

pub(super) fn admit_served_dag_request_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: Option<std::net::SocketAddr>,
    headers_chirho: &HeaderMap,
    request_context_chirho: Option<&RequestContextChirho>,
    body_bytes_chirho: usize,
) -> Result<ServedDagAdmissionChirho> {
    state_chirho.served_request_abuse_gate_chirho.admit_chirho(
        state_chirho.inflight_chirho.clone(),
        peer_chirho,
        headers_chirho,
        request_context_chirho.map(|context_chirho| context_chirho.user_principal_chirho.as_str()),
        body_bytes_chirho,
    )
}

/// The served gate's refusal body for a JSON client: ONE generic token, as a constant, so the refusal interpolates
/// nothing and cannot say which limit fired (R13 Part 8, PFE #26153, #26154).
pub(super) const SERVED_REQUEST_UNAVAILABLE_JSON_CHIRHO: &str =
    r#"{"ok_chirho":false,"error_chirho":"served-request-unavailable-chirho"}"#;

/// The served gate's ONE refusal for every reason (R13 Part 8): 429, ONE Retry-After (the rolling window's whole
/// seconds, rounded up), and one generic body. It is JSON when the route declares a JSON response, or when the request's
/// Accept names `application/json`; otherwise it is the plain text a page has always had. It takes no error, so nothing
/// in it says which limit fired.
pub(super) fn served_request_rejected_response_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    declared_content_type_chirho: Option<&str>,
) -> Response {
    let json_chirho = declared_content_type_chirho.is_some_and(media_type_is_json_chirho)
        || accept_names_json_chirho(headers_chirho);
    let mut response_chirho = if json_chirho {
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            SERVED_REQUEST_UNAVAILABLE_JSON_CHIRHO,
        )
            .into_response()
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "served request unavailable\n",
        )
            .into_response()
    };
    response_chirho.headers_mut().insert(
        RETRY_AFTER,
        HeaderValue::from(
            state_chirho
                .served_request_abuse_gate_chirho
                .retry_after_secs_chirho(),
        ),
    );
    response_chirho
}

/// A content type's media type is `application/json`, its parameters and case aside.
pub(super) fn media_type_is_json_chirho(content_type_chirho: &str) -> bool {
    content_type_chirho
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("application/json")
}

/// The request's Accept names `application/json` as a media range of its own, with no `q=0` refusing it. A wildcard
/// such as `*/*` is not a request for JSON; the route's declared type covers that case.
pub(super) fn accept_names_json_chirho(headers_chirho: &HeaderMap) -> bool {
    headers_chirho
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value_chirho| value_chirho.to_str().ok())
        .flat_map(|value_chirho| value_chirho.split(','))
        .any(|range_chirho| {
            let mut parts_chirho = range_chirho.split(';');
            media_type_is_json_chirho(parts_chirho.next().unwrap_or_default())
                && !parts_chirho.any(|param_chirho| {
                    param_chirho
                        .split_once('=')
                        .is_some_and(|(key_chirho, value_chirho)| {
                            key_chirho.trim().eq_ignore_ascii_case("q")
                                && value_chirho.trim().parse::<f32>() == Ok(0.0)
                        })
                })
        })
}
