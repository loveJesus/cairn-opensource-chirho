// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::{bearer_token_chirho, AUTH_SESSION_COOKIE_CHIRHO};
use anyhow::Result;
use axum::{
    extract::State,
    http::{
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
        HeaderMap, HeaderValue,
    },
    response::Response,
};
use cairn_chirho::model_chirho::{HashChirho, RequestContextChirho, RequestKeyLimitChirho};
use cairn_chirho::oauth_chirho::{KeyAdmissionChirho, KeyEntryChirho};
use cairn_chirho::{
    app_chirho, dag_chirho, effect_pricing_chirho, identity_chirho, oauth_chirho, privacy_chirho,
};
use std::{collections::BTreeMap, path::Path};

/// The engine's one browser-session client id, which the owner's-keys read checks (K3).
const APP_BROWSER_SESSION_CLIENT_CHIRHO: &str =
    cairn_chirho::oauth_chirho::BROWSER_SESSION_CLIENT_ID_CHIRHO;
pub(super) use cairn_model_app_chirho::app_request_input_chirho::REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO;

/// A refusal of the visitor's own input on the app input road, typed so its public answer names the
/// refusal without echoing the submitted value. The key in it is the owner's declared policy key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppInputRefusalChirho {
    SafeMetadataValueNotAllowedChirho { key_chirho: String },
    DuplicateSafeMetadataKeyChirho { key_chirho: String },
    SignedInSessionRequiredChirho,
}

impl AppInputRefusalChirho {
    /// The fixed public identity of this refusal.
    pub(crate) fn identity_chirho(&self) -> &'static str {
        match self {
            Self::SafeMetadataValueNotAllowedChirho { .. } => {
                "safe-metadata-value-not-allowed-chirho"
            }
            Self::DuplicateSafeMetadataKeyChirho { .. } => "duplicate-safe-metadata-key-chirho",
            Self::SignedInSessionRequiredChirho => "signed-in-session-required-chirho",
        }
    }
}

impl std::fmt::Display for AppInputRefusalChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SafeMetadataValueNotAllowedChirho { key_chirho } => write!(
                f,
                "private input safe metadata value is not allowed for key '{key_chirho}'"
            ),
            Self::DuplicateSafeMetadataKeyChirho { key_chirho } => {
                write!(
                    f,
                    "duplicate private input safe metadata key '{key_chirho}'"
                )
            }
            Self::SignedInSessionRequiredChirho => {
                f.write_str("request-user private input requires a signed-in session")
            }
        }
    }
}

impl std::error::Error for AppInputRefusalChirho {}

pub(super) struct PreparedAppRequestContextChirho {
    context_chirho: Option<RequestContextChirho>,
    scoped_token_use_chirho: Option<oauth_chirho::ScopedTokenRecordChirho>,
    key_binding_chirho: Option<KeyRouteBindingChirho>,
}

impl PreparedAppRequestContextChirho {
    pub(super) fn context_chirho(&self) -> Option<&RequestContextChirho> {
        self.context_chirho.as_ref()
    }

    pub(super) fn key_binding_chirho(&self) -> Option<&KeyRouteBindingChirho> {
        self.key_binding_chirho.as_ref()
    }
}

/// The route and DAG a limited key was admitted against. The request must still be running exactly these after route
/// selection: a resource-policy reroute or a redeploy in between refuses the key rather than running something it was
/// not checked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyRouteBindingChirho {
    pub(crate) route_chirho: String,
    pub(crate) dag_chirho: HashChirho,
}

/// A named route's request context: the context, and for a limited key the binding the selection must still match.
pub(super) struct AppRouteRequestContextChirho {
    pub(super) context_chirho: Option<RequestContextChirho>,
    pub(super) key_binding_chirho: Option<KeyRouteBindingChirho>,
}

/// The entry the app road was reached through: a named route, or the app root.
fn key_entry_for_route_chirho(route_chirho: Option<&str>) -> KeyEntryChirho<'_> {
    match route_chirho {
        Some(route_chirho) => KeyEntryChirho::NamedRouteChirho(route_chirho),
        None => KeyEntryChirho::OtherEntryChirho,
    }
}

/// A limited key's binding and limit, or none for a legacy key.
fn key_binding_and_limit_chirho(
    admission_chirho: &KeyAdmissionChirho,
) -> (Option<KeyRouteBindingChirho>, Option<RequestKeyLimitChirho>) {
    match admission_chirho {
        KeyAdmissionChirho::LegacyChirho(_) => (None, None),
        KeyAdmissionChirho::LimitedChirho {
            limit_chirho,
            route_chirho,
            dag_chirho,
            ..
        } => (
            Some(KeyRouteBindingChirho {
                route_chirho: route_chirho.clone(),
                dag_chirho: dag_chirho.clone(),
            }),
            Some(limit_chirho.clone()),
        ),
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PrivateAppInputRefChirho {
    schema_chirho: String,
    app_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_chirho: Option<String>,
    subject_chirho: String,
    bytes_chirho: usize,
    blob_chirho: serde_json::Value,
}

pub(super) fn app_dag_input_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    context_chirho: Option<&RequestContextChirho>,
    input_chirho: Vec<u8>,
) -> Result<Vec<u8>> {
    app_dag_input_with_headers_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        context_chirho,
        None,
        input_chirho,
    )
}

pub(super) fn app_http_dag_input_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    context_chirho: Option<&RequestContextChirho>,
    headers_chirho: &HeaderMap,
    input_chirho: Vec<u8>,
) -> Result<Vec<u8>> {
    app_dag_input_with_headers_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        context_chirho,
        Some(headers_chirho),
        input_chirho,
    )
}

pub(super) fn app_http_dag_input_value_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    context_chirho: Option<&RequestContextChirho>,
    headers_chirho: &HeaderMap,
    input_chirho: Vec<u8>,
) -> Result<dag_chirho::DagInputValueChirho> {
    let owner_principal_chirho = match context_chirho {
        Some(context_chirho) => context_chirho.owner_principal_chirho.clone(),
        None => app_chirho::verified_app_owner_chirho(root_chirho, app_chirho)?
            .ok_or_else(|| anyhow::anyhow!("app '{app_chirho}' has no signed owner record"))?,
    };
    let mode_chirho = app_chirho::app_input_mode_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        &owner_principal_chirho,
    )?;
    if input_chirho.is_empty()
        && matches!(
            mode_chirho,
            app_chirho::AppInputModeChirho::PrivateBlobRefChirho { .. }
        )
    {
        return Ok(dag_chirho::DagInputValueChirho::PublicBytesChirho(
            Vec::new(),
        ));
    }
    if let app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
        subject_chirho,
        safe_metadata_chirho,
    } = mode_chirho
    {
        if subject_chirho == REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO {
            if !safe_metadata_chirho.is_empty() {
                anyhow::bail!("request-user private input does not support safe metadata");
            }
            let context_chirho =
                context_chirho.ok_or(AppInputRefusalChirho::SignedInSessionRequiredChirho)?;
            return Ok(dag_chirho::DagInputValueChirho::PrivateBytesChirho {
                subject_chirho: context_chirho.user_principal_chirho.clone(),
                bytes_chirho: input_chirho,
            });
        }
    }
    Ok(dag_chirho::DagInputValueChirho::PublicBytesChirho(
        app_http_dag_input_chirho(
            root_chirho,
            app_chirho,
            route_chirho,
            context_chirho,
            headers_chirho,
            input_chirho,
        )?,
    ))
}

fn app_dag_input_with_headers_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    context_chirho: Option<&RequestContextChirho>,
    headers_chirho: Option<&HeaderMap>,
    input_chirho: Vec<u8>,
) -> Result<Vec<u8>> {
    let owner_principal_chirho = match context_chirho {
        Some(context_chirho) => context_chirho.owner_principal_chirho.clone(),
        None => app_chirho::verified_app_owner_chirho(root_chirho, app_chirho)?
            .ok_or_else(|| anyhow::anyhow!("app '{app_chirho}' has no signed owner record"))?,
    };
    let mode_chirho = app_chirho::app_input_mode_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        &owner_principal_chirho,
    )?;
    if input_chirho.is_empty()
        && matches!(
            mode_chirho,
            app_chirho::AppInputModeChirho::PrivateBlobRefChirho { .. }
        )
    {
        return Ok(Vec::new());
    }
    let app_params_chirho = app_chirho::app_params_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        &owner_principal_chirho,
    )?;
    match mode_chirho {
        app_chirho::AppInputModeChirho::PlainChirho => {
            let input_chirho = app_plain_http_input_chirho(headers_chirho, input_chirho)?;
            app_plain_input_with_verified_context_chirho(
                input_chirho,
                context_chirho,
                app_params_chirho
                    .as_ref()
                    .map(|params_chirho| &params_chirho.value_chirho),
            )
        }
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho,
            safe_metadata_chirho,
        } => {
            let metadata_chirho = app_private_input_safe_metadata_chirho(
                headers_chirho,
                &input_chirho,
                &safe_metadata_chirho,
            )?;
            let bytes_chirho = input_chirho.len();
            // The app declared this subject, so the input joins the app owner's container; a signed-in
            // submitter is its actor and keeps a contribution row (C5 2a, gpt #28929).
            let attribution_chirho =
                privacy_chirho::PrivateBlobAttributionChirho::app_container_chirho(
                    &owner_principal_chirho,
                    context_chirho
                        .map(|context_chirho| context_chirho.user_principal_chirho.as_str()),
                )?;
            let blob_ref_chirho = privacy_chirho::store_private_blob_chirho(
                root_chirho,
                &attribution_chirho,
                &subject_chirho,
                &input_chirho,
            )?;
            let mut blob_chirho = serde_json::to_value(&blob_ref_chirho)?;
            let blob_object_chirho = blob_chirho
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("private blob ref did not serialize as object"))?;
            for (key_chirho, value_chirho) in metadata_chirho {
                blob_object_chirho.insert(key_chirho, serde_json::Value::String(value_chirho));
            }
            Ok(serde_json::to_vec(&PrivateAppInputRefChirho {
                schema_chirho: "app-private-input-ref-v1-chirho".to_string(),
                app_chirho: app_chirho.to_string(),
                route_chirho: route_chirho.map(str::to_string),
                subject_chirho,
                bytes_chirho,
                blob_chirho,
            })?)
        }
    }
}

fn headers_are_form_urlencoded_chirho(headers_chirho: Option<&HeaderMap>) -> bool {
    cairn_model_app_chirho::app_request_input_chirho::request_input_is_form_urlencoded_chirho(
        headers_chirho
            .and_then(|headers_chirho| headers_chirho.get(CONTENT_TYPE))
            .and_then(|value_chirho| value_chirho.to_str().ok()),
    )
}

fn app_plain_http_input_chirho(
    headers_chirho: Option<&HeaderMap>,
    input_chirho: Vec<u8>,
) -> Result<Vec<u8>> {
    if !headers_are_form_urlencoded_chirho(headers_chirho) {
        return Ok(input_chirho);
    }
    let mut object_chirho = serde_json::Map::new();
    for (key_chirho, value_chirho) in url::form_urlencoded::parse(&input_chirho) {
        object_chirho.insert(
            key_chirho.into_owned(),
            serde_json::Value::String(value_chirho.into_owned()),
        );
    }
    Ok(serde_json::to_vec(&serde_json::Value::Object(
        object_chirho,
    ))?)
}

fn app_private_input_safe_metadata_chirho(
    headers_chirho: Option<&HeaderMap>,
    input_chirho: &[u8],
    policies_chirho: &[app_chirho::AppPrivateInputSafeMetadataChirho],
) -> Result<BTreeMap<String, String>> {
    if policies_chirho.is_empty() || !headers_are_form_urlencoded_chirho(headers_chirho) {
        return Ok(BTreeMap::new());
    }
    app_chirho::validate_app_private_input_safe_metadata_chirho(policies_chirho)?;
    let mut metadata_chirho = BTreeMap::new();
    for (key_chirho, value_chirho) in url::form_urlencoded::parse(input_chirho) {
        let Some(policy_chirho) = policies_chirho
            .iter()
            .find(|policy_chirho| policy_chirho.key_chirho == key_chirho.as_ref())
        else {
            continue;
        };
        let value_chirho = value_chirho.into_owned();
        // A malformed value and a value outside the policy's allowed set are one refusal to the visitor.
        let not_allowed_chirho = || AppInputRefusalChirho::SafeMetadataValueNotAllowedChirho {
            key_chirho: policy_chirho.key_chirho.clone(),
        };
        app_chirho::validate_app_private_input_safe_metadata_value_chirho(
            &policy_chirho.key_chirho,
            &value_chirho,
        )
        .map_err(|_malformed_chirho| not_allowed_chirho())?;
        if !app_chirho::app_private_input_safe_metadata_value_allowed_chirho(
            policies_chirho,
            &policy_chirho.key_chirho,
            &value_chirho,
        ) {
            return Err(not_allowed_chirho().into());
        }
        if metadata_chirho
            .insert(policy_chirho.key_chirho.clone(), value_chirho)
            .is_some()
        {
            return Err(AppInputRefusalChirho::DuplicateSafeMetadataKeyChirho {
                key_chirho: policy_chirho.key_chirho.clone(),
            }
            .into());
        }
    }
    Ok(metadata_chirho)
}

pub(super) async fn auth_logout_get_chirho(
    State(state_chirho): State<super::AppStateChirho>,
    headers_chirho: HeaderMap,
) -> Response {
    if let Ok(Some((principal_chirho, token_chirho))) =
        browser_session_cookie_pair_chirho(&headers_chirho)
    {
        let _ = identity_chirho::revoke_session_token_chirho(
            state_chirho.runtime_chirho.root_path_chirho(),
            &principal_chirho,
            &token_chirho,
            APP_BROWSER_SESSION_CLIENT_CHIRHO,
            "browser-logout-chirho",
        );
    }
    let mut response_chirho = super::redirect_chirho("/auth-chirho/login-chirho");
    response_chirho.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "cairn_session_chirho=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure",
        ),
    );
    response_chirho
}

/// The request context for an entry that is not a named route: the app root reached by SSR, `/invoke-chirho` or
/// `/ws-chirho`. No limited key is admitted there.
pub(super) fn request_context_for_app_chirho(
    root_chirho: &Path,
    headers_chirho: &HeaderMap,
    app_name_chirho: &str,
) -> Result<Option<RequestContextChirho>> {
    Ok(
        request_context_for_app_route_chirho(root_chirho, headers_chirho, app_name_chirho, None)?
            .context_chirho,
    )
}

/// The local-era request context for the app road: `route_chirho` is the named route asked for, or `None` for the app
/// root. A bearer is admitted through the key gate BEFORE its use is recorded, so a refused key appends nothing.
pub(super) fn request_context_for_app_route_chirho(
    root_chirho: &Path,
    headers_chirho: &HeaderMap,
    app_name_chirho: &str,
    route_chirho: Option<&str>,
) -> Result<AppRouteRequestContextChirho> {
    if let Some(token_chirho) = bearer_token_chirho(headers_chirho) {
        return scoped_bearer_request_context_chirho(
            root_chirho,
            app_name_chirho,
            key_entry_for_route_chirho(route_chirho),
            token_chirho,
        );
    }
    let Some((principal_chirho, token_chirho)) =
        browser_session_cookie_pair_chirho(headers_chirho)?
    else {
        return Ok(AppRouteRequestContextChirho {
            context_chirho: None,
            key_binding_chirho: None,
        });
    };
    Ok(AppRouteRequestContextChirho {
        context_chirho: browser_session_request_context_chirho(
            root_chirho,
            app_name_chirho,
            &principal_chirho,
            &token_chirho,
        )?,
        key_binding_chirho: None,
    })
}

/// Validate elected-era caller authentication without consuming the durable scoped-token use.
///
/// A relay origin may perform read-only authentication and admission, but only the destination
/// selected to execute may append rate-limit use. The existing local-era helper above intentionally
/// retains its original record-before-context ordering.
pub(super) fn prepare_app_request_context_chirho(
    root_chirho: &Path,
    headers_chirho: &HeaderMap,
    app_name_chirho: &str,
    route_chirho: Option<&str>,
) -> Result<PreparedAppRequestContextChirho> {
    if let Some(token_chirho) = bearer_token_chirho(headers_chirho) {
        let admission_chirho = oauth_chirho::admit_bearer_chirho(
            root_chirho,
            app_name_chirho,
            key_entry_for_route_chirho(route_chirho),
            token_chirho,
        )?
        .ok_or_else(|| anyhow::anyhow!("invalid scoped token for app '{app_name_chirho}'"))?;
        let (key_binding_chirho, key_limit_chirho) =
            key_binding_and_limit_chirho(&admission_chirho);
        let scoped_token_chirho = admission_chirho.record_chirho().clone();
        let owner_principal_chirho = app_owner_chirho(root_chirho, app_name_chirho)?;
        let context_chirho = request_context_chirho(
            root_chirho,
            app_name_chirho,
            scoped_token_chirho.principal_chirho.clone(),
            owner_principal_chirho,
            scoped_token_chirho.client_id_chirho.clone(),
            scoped_token_chirho.token_hash_chirho.clone(),
            key_limit_chirho,
        )?;
        return Ok(PreparedAppRequestContextChirho {
            context_chirho: Some(context_chirho),
            scoped_token_use_chirho: Some(scoped_token_chirho),
            key_binding_chirho,
        });
    }
    let Some((principal_chirho, token_chirho)) =
        browser_session_cookie_pair_chirho(headers_chirho)?
    else {
        return Ok(PreparedAppRequestContextChirho {
            context_chirho: None,
            scoped_token_use_chirho: None,
            key_binding_chirho: None,
        });
    };
    Ok(PreparedAppRequestContextChirho {
        context_chirho: browser_session_request_context_chirho(
            root_chirho,
            app_name_chirho,
            &principal_chirho,
            &token_chirho,
        )?,
        scoped_token_use_chirho: None,
        key_binding_chirho: None,
    })
}

pub(super) fn commit_prepared_app_request_context_chirho(
    root_chirho: &Path,
    prepared_chirho: PreparedAppRequestContextChirho,
) -> Result<Option<RequestContextChirho>> {
    if let Some(scoped_token_chirho) = prepared_chirho.scoped_token_use_chirho.as_ref() {
        oauth_chirho::record_scoped_token_use_chirho(root_chirho, scoped_token_chirho)?;
    }
    Ok(prepared_chirho.context_chirho)
}

pub(super) fn app_plain_input_with_verified_context_chirho(
    input_chirho: Vec<u8>,
    context_chirho: Option<&RequestContextChirho>,
    app_params_chirho: Option<&serde_json::Value>,
) -> Result<Vec<u8>> {
    cairn_model_app_chirho::app_request_input_chirho::app_plain_input_with_verified_context_chirho(
        input_chirho,
        context_chirho.map(|context_chirho| context_chirho.user_principal_chirho.as_str()),
        app_params_chirho,
    )
}

/// Admit the bearer through the key gate, then record its use: a key the gate refuses appends nothing.
fn scoped_bearer_request_context_chirho(
    root_chirho: &Path,
    app_name_chirho: &str,
    entry_chirho: KeyEntryChirho<'_>,
    token_chirho: &str,
) -> Result<AppRouteRequestContextChirho> {
    let admission_chirho = oauth_chirho::admit_bearer_chirho(
        root_chirho,
        app_name_chirho,
        entry_chirho,
        token_chirho,
    )?
    .ok_or_else(|| anyhow::anyhow!("invalid scoped token for app '{app_name_chirho}'"))?;
    let (key_binding_chirho, key_limit_chirho) = key_binding_and_limit_chirho(&admission_chirho);
    let scoped_token_chirho = admission_chirho.record_chirho();
    let owner_principal_chirho = app_owner_chirho(root_chirho, app_name_chirho)?;
    oauth_chirho::record_scoped_token_use_chirho(root_chirho, scoped_token_chirho)?;
    Ok(AppRouteRequestContextChirho {
        context_chirho: Some(request_context_chirho(
            root_chirho,
            app_name_chirho,
            scoped_token_chirho.principal_chirho.clone(),
            owner_principal_chirho,
            scoped_token_chirho.client_id_chirho.clone(),
            scoped_token_chirho.token_hash_chirho.clone(),
            key_limit_chirho,
        )?),
        key_binding_chirho,
    })
}

fn browser_session_request_context_chirho(
    root_chirho: &Path,
    app_name_chirho: &str,
    principal_chirho: &str,
    token_chirho: &str,
) -> Result<Option<RequestContextChirho>> {
    let session_chirho = identity_chirho::validate_session_token_chirho(
        root_chirho,
        principal_chirho,
        token_chirho,
    )?
    .ok_or_else(|| anyhow::anyhow!("invalid browser session for app request"))?;
    let owner_principal_chirho = app_owner_chirho(root_chirho, app_name_chirho)?;
    request_context_chirho(
        root_chirho,
        app_name_chirho,
        principal_chirho.to_string(),
        owner_principal_chirho,
        APP_BROWSER_SESSION_CLIENT_CHIRHO.to_string(),
        session_chirho.token_hash_chirho,
        None,
    )
    .map(Some)
}

fn request_context_chirho(
    root_chirho: &Path,
    app_name_chirho: &str,
    user_principal_chirho: String,
    owner_principal_chirho: String,
    client_id_chirho: String,
    token_hash_chirho: String,
    key_limit_chirho: Option<RequestKeyLimitChirho>,
) -> Result<RequestContextChirho> {
    Ok(RequestContextChirho {
        user_principal_chirho,
        app_chirho: app_name_chirho.to_string(),
        owner_principal_chirho,
        client_id_chirho,
        token_hash_chirho,
        price_book_chirho: effect_pricing_chirho::current_price_book_hash_chirho(
            root_chirho,
            app_name_chirho,
        )?,
        // Descriptor-D currently composes only the explicit UserPays policy. The injected
        // money-policy door independently checks this binding before it can mint an intent.
        billing_policy_chirho: None,
        key_limit_chirho,
    })
}

fn app_owner_chirho(root_chirho: &Path, app_name_chirho: &str) -> Result<String> {
    app_chirho::verified_app_owner_chirho(root_chirho, app_name_chirho)?
        .ok_or_else(|| anyhow::anyhow!("app '{app_name_chirho}' has no signed owner record"))
}

pub(super) fn auth_session_cookie_header_chirho(
    principal_chirho: &str,
    token_chirho: &str,
) -> String {
    format!(
        "{AUTH_SESSION_COOKIE_CHIRHO}={principal_chirho}:{token_chirho}; Path=/; HttpOnly; SameSite=Lax; Secure"
    )
}

pub(super) fn auth_browser_redirect_path_chirho(
    _principal_chirho: &str,
    redirect_chirho: Option<&str>,
) -> String {
    if let Some(redirect_chirho) = redirect_chirho.and_then(safe_auth_redirect_target_chirho) {
        return redirect_chirho;
    }
    "/".to_string()
}

pub(super) fn browser_session_cookie_pair_chirho(
    headers_chirho: &HeaderMap,
) -> Result<Option<(String, String)>> {
    let Some(cookie_header_chirho) = headers_chirho.get(COOKIE) else {
        return Ok(None);
    };
    let cookie_header_chirho = cookie_header_chirho
        .to_str()
        .map_err(|_| anyhow::anyhow!("invalid browser session cookie header"))?;
    for pair_chirho in cookie_header_chirho.split(';') {
        let pair_chirho = pair_chirho.trim();
        let Some((name_chirho, value_chirho)) = pair_chirho.split_once('=') else {
            continue;
        };
        if name_chirho.trim() != AUTH_SESSION_COOKIE_CHIRHO {
            continue;
        }
        let Some((principal_chirho, token_chirho)) = value_chirho.split_once(':') else {
            anyhow::bail!("invalid browser session cookie");
        };
        if !principal_chirho.trim().is_empty() && !token_chirho.trim().is_empty() {
            return Ok(Some((
                principal_chirho.to_string(),
                token_chirho.to_string(),
            )));
        }
        anyhow::bail!("invalid browser session cookie");
    }
    Ok(None)
}

pub(super) fn safe_auth_redirect_target_chirho(value_chirho: &str) -> Option<String> {
    let value_chirho = value_chirho.trim();
    if value_chirho.is_empty()
        || !value_chirho.starts_with('/')
        || value_chirho.starts_with("//")
        || value_chirho.contains('\\')
        || value_chirho.chars().any(char::is_control)
    {
        return None;
    }
    Some(value_chirho.to_string())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use axum::{
        body::Body,
        http::{
            header::{CONTENT_TYPE, LOCATION, SET_COOKIE},
            HeaderValue, Request, StatusCode,
        },
    };
    use cairn_chirho::model_chirho::{
        CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, PortChirho,
    };
    use std::collections::BTreeMap;

    #[test]
    fn browser_session_cookie_builds_app_request_context_chirho() {
        let root_chirho = temp_root_chirho("browser-session-context");
        let (owner_chirho, user_chirho, login_chirho) = provision_cookie_app_chirho(&root_chirho);
        let headers_chirho =
            cookie_headers_chirho(&user_chirho.principal_chirho, &login_chirho.token_chirho);

        let context_chirho =
            request_context_for_app_chirho(&root_chirho, &headers_chirho, "cookieapp")
                .unwrap()
                .unwrap();
        assert_eq!(
            context_chirho.user_principal_chirho,
            user_chirho.principal_chirho
        );
        assert_eq!(context_chirho.app_chirho, "cookieapp");
        assert_eq!(
            context_chirho.owner_principal_chirho,
            owner_chirho.principal_chirho
        );
        assert_eq!(
            context_chirho.client_id_chirho,
            APP_BROWSER_SESSION_CLIENT_CHIRHO
        );
        assert_eq!(
            context_chirho.token_hash_chirho,
            login_chirho.session_chirho.token_hash_chirho
        );
        assert!(context_chirho.price_book_chirho.is_some());
        assert_eq!(context_chirho.billing_policy_chirho, None);

        let empty_chirho =
            request_context_for_app_chirho(&root_chirho, &HeaderMap::new(), "cookieapp").unwrap();
        assert!(empty_chirho.is_none());

        let mut prefix_named_chirho = HeaderMap::new();
        prefix_named_chirho.insert(
            COOKIE,
            HeaderValue::from_static("cairn_session_chirho_extra=bad"),
        );
        assert!(
            request_context_for_app_chirho(&root_chirho, &prefix_named_chirho, "cookieapp")
                .unwrap()
                .is_none()
        );

        let mut malformed_chirho = HeaderMap::new();
        malformed_chirho.insert(COOKIE, HeaderValue::from_static("cairn_session_chirho=bad"));
        assert!(
            request_context_for_app_chirho(&root_chirho, &malformed_chirho, "cookieapp").is_err()
        );

        let stale_chirho = cookie_headers_chirho(&user_chirho.principal_chirho, "wrong-token");
        assert!(request_context_for_app_chirho(&root_chirho, &stale_chirho, "cookieapp").is_err());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn app_input_injects_cookie_principal_for_json_and_form_inputs_chirho() {
        let root_chirho = temp_root_chirho("browser-session-app-input");
        let (owner_chirho, user_chirho, login_chirho) = provision_cookie_app_chirho(&root_chirho);
        let params_value_chirho = serde_json::json!({
            "business_name_chirho": "Verified Bakery",
            "tagline_chirho": "fresh from signed params"
        });
        cairn_chirho::app_chirho::set_app_params_chirho(
            &root_chirho,
            "cookieapp",
            None,
            &owner_chirho.principal_chirho,
            &params_value_chirho,
            true,
        )
        .unwrap();
        let headers_chirho =
            cookie_headers_chirho(&user_chirho.principal_chirho, &login_chirho.token_chirho);
        let context_chirho =
            request_context_for_app_chirho(&root_chirho, &headers_chirho, "cookieapp")
                .unwrap()
                .unwrap();

        let empty_input_chirho = super::app_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            Some(&context_chirho),
            Vec::new(),
        )
        .unwrap();
        let empty_json_chirho: serde_json::Value =
            serde_json::from_slice(&empty_input_chirho).unwrap();
        assert_eq!(
            empty_json_chirho["user_principal_chirho"],
            user_chirho.principal_chirho
        );
        assert_eq!(empty_json_chirho["app_params_chirho"], params_value_chirho);

        let object_input_chirho = super::app_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            Some(&context_chirho),
            br#"{"route_chirho":"dashboard-chirho"}"#.to_vec(),
        )
        .unwrap();
        let object_json_chirho: serde_json::Value =
            serde_json::from_slice(&object_input_chirho).unwrap();
        assert_eq!(object_json_chirho["route_chirho"], "dashboard-chirho");
        assert_eq!(
            object_json_chirho["user_principal_chirho"],
            user_chirho.principal_chirho
        );
        assert_eq!(object_json_chirho["app_params_chirho"], params_value_chirho);

        let raw_input_chirho = super::app_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            Some(&context_chirho),
            b"raw bytes stay raw".to_vec(),
        )
        .unwrap();
        assert_eq!(raw_input_chirho, b"raw bytes stay raw");

        let mut form_headers_chirho = HeaderMap::new();
        form_headers_chirho.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded;charset=UTF-8"),
        );
        let form_input_chirho = super::app_http_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            Some(&context_chirho),
            &form_headers_chirho,
            b"description_chirho=First&description_chirho=Second+Value&extra_chirho=yes&user_principal_chirho=user%2Fspoof&app_params_chirho=spoof".to_vec(),
        )
        .unwrap();
        let form_json_chirho: serde_json::Value =
            serde_json::from_slice(&form_input_chirho).unwrap();
        assert_eq!(form_json_chirho["description_chirho"], "Second Value");
        assert_eq!(form_json_chirho["extra_chirho"], "yes");
        assert_eq!(
            form_json_chirho["user_principal_chirho"],
            user_chirho.principal_chirho
        );
        assert_eq!(form_json_chirho["app_params_chirho"], params_value_chirho);

        let non_form_http_input_chirho = super::app_http_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            Some(&context_chirho),
            &HeaderMap::new(),
            b"raw bytes stay raw".to_vec(),
        )
        .unwrap();
        assert_eq!(non_form_http_input_chirho, b"raw bytes stay raw");

        let anonymous_object_chirho = super::app_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            None,
            br#"{"route_chirho":"dashboard-chirho"}"#.to_vec(),
        )
        .unwrap();
        let anonymous_json_chirho: serde_json::Value =
            serde_json::from_slice(&anonymous_object_chirho).unwrap();
        assert!(anonymous_json_chirho.get("user_principal_chirho").is_none());
        assert_eq!(
            anonymous_json_chirho["app_params_chirho"],
            params_value_chirho
        );

        let spoofed_object_chirho = super::app_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            None,
            br#"{"route_chirho":"dashboard-chirho","user_principal_chirho":"user/spoof","app_params_chirho":{"business_name_chirho":"Spoof"}}"#.to_vec(),
        )
        .unwrap();
        let spoofed_json_chirho: serde_json::Value =
            serde_json::from_slice(&spoofed_object_chirho).unwrap();
        assert_eq!(spoofed_json_chirho["route_chirho"], "dashboard-chirho");
        assert!(spoofed_json_chirho.get("user_principal_chirho").is_none());
        assert_eq!(
            spoofed_json_chirho["app_params_chirho"],
            params_value_chirho
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn private_blob_ref_keeps_form_body_raw_chirho() {
        let root_chirho = temp_root_chirho("browser-session-private-form-raw");
        let (owner_chirho, _user_chirho, _login_chirho) = provision_cookie_app_chirho(&root_chirho);
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            "cookieapp",
            None,
            &owner_chirho.principal_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: "app/cookieapp/private-input".to_string(),
                safe_metadata_chirho: Vec::new(),
            },
        )
        .unwrap();
        let mut headers_chirho = HeaderMap::new();
        headers_chirho.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let raw_body_chirho =
            b"description_chirho=Private+Needle&user_principal_chirho=user%2Fspoof";
        let envelope_chirho = super::app_http_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            None,
            &headers_chirho,
            raw_body_chirho.to_vec(),
        )
        .unwrap();
        let private_ref_chirho: PrivateAppInputRefChirho =
            serde_json::from_slice(&envelope_chirho).unwrap();
        assert_eq!(private_ref_chirho.bytes_chirho, raw_body_chirho.len());
        assert!(!private_ref_chirho
            .blob_chirho
            .as_object()
            .unwrap()
            .contains_key("request_kind_chirho"));
        let blob_ref_chirho: privacy_chirho::PrivateBlobRefChirho =
            serde_json::from_value(private_ref_chirho.blob_chirho.clone()).unwrap();
        assert_eq!(
            privacy_chirho::load_private_blob_chirho(&root_chirho, &blob_ref_chirho).unwrap(),
            raw_body_chirho
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn private_blob_ref_passes_only_allowlisted_safe_metadata_chirho() {
        let root_chirho = temp_root_chirho("browser-session-private-metadata-passthrough");
        let (owner_chirho, _user_chirho, _login_chirho) = provision_cookie_app_chirho(&root_chirho);
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            "cookieapp",
            None,
            &owner_chirho.principal_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: "app/cookieapp/private-input".to_string(),
                safe_metadata_chirho:
                    vec![cairn_chirho::app_chirho::AppPrivateInputSafeMetadataChirho {
                    key_chirho:
                        cairn_chirho::app_chirho::APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO
                            .to_string(),
                    allowed_values_chirho: vec![
                        "visit_chirho".to_string(),
                        "prayer_chirho".to_string(),
                    ],
                }],
            },
        )
        .unwrap();

        let mut headers_form_chirho = HeaderMap::new();
        headers_form_chirho.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let form_body_chirho = b"request_kind_chirho=visit_chirho&prayer_chirho=Please+pray+for+me";
        let envelope_chirho = super::app_http_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            None,
            &headers_form_chirho,
            form_body_chirho.to_vec(),
        )
        .unwrap();
        let private_ref_chirho: PrivateAppInputRefChirho =
            serde_json::from_slice(&envelope_chirho).unwrap();
        assert_eq!(
            private_ref_chirho
                .blob_chirho
                .get("request_kind_chirho")
                .and_then(|value_chirho| value_chirho.as_str()),
            Some("visit_chirho")
        );
        assert!(!private_ref_chirho
            .blob_chirho
            .as_object()
            .unwrap()
            .contains_key("prayer_chirho"));
        let blob_ref_chirho: privacy_chirho::PrivateBlobRefChirho =
            serde_json::from_value(private_ref_chirho.blob_chirho.clone()).unwrap();
        assert_eq!(
            privacy_chirho::load_private_blob_chirho(&root_chirho, &blob_ref_chirho).unwrap(),
            form_body_chirho
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn private_blob_ref_rejects_unapproved_safe_metadata_before_blob_chirho() {
        let root_chirho = temp_root_chirho("browser-session-private-metadata-reject");
        let (owner_chirho, _user_chirho, _login_chirho) = provision_cookie_app_chirho(&root_chirho);
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            "cookieapp",
            None,
            &owner_chirho.principal_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: "app/cookieapp/private-input".to_string(),
                safe_metadata_chirho:
                    vec![cairn_chirho::app_chirho::AppPrivateInputSafeMetadataChirho {
                    key_chirho:
                        cairn_chirho::app_chirho::APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO
                            .to_string(),
                    allowed_values_chirho: vec!["visit_chirho".to_string()],
                }],
            },
        )
        .unwrap();
        let mut headers_chirho = HeaderMap::new();
        headers_chirho.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let error_chirho = super::app_http_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            None,
            &headers_chirho,
            b"request_kind_chirho=johnsmith_chirho&prayer_chirho=Help".to_vec(),
        )
        .unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("is not allowed for key 'request_kind_chirho'"));
        assert!(!root_chirho
            .join("privacy-blob-records-chirho.jsonl")
            .exists());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn request_user_private_input_requires_session_before_blob_persistence_chirho() {
        let root_chirho = temp_root_chirho("browser-session-request-user-private");
        let (owner_chirho, user_chirho, login_chirho) = provision_cookie_app_chirho(&root_chirho);
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            "cookieapp",
            None,
            &owner_chirho.principal_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: REQUEST_USER_PRIVATE_INPUT_SUBJECT_CHIRHO.to_string(),
                safe_metadata_chirho: Vec::new(),
            },
        )
        .unwrap();
        let body_chirho = b"description_chirho=Private+App";
        let anonymous_error_chirho = super::app_http_dag_input_value_chirho(
            &root_chirho,
            "cookieapp",
            None,
            None,
            &HeaderMap::new(),
            body_chirho.to_vec(),
        )
        .unwrap_err();
        assert!(anonymous_error_chirho
            .to_string()
            .contains("request-user private input requires a signed-in session"));
        assert!(!root_chirho
            .join("privacy-blob-records-chirho.jsonl")
            .exists());

        let headers_chirho =
            cookie_headers_chirho(&user_chirho.principal_chirho, &login_chirho.token_chirho);
        let context_chirho =
            request_context_for_app_chirho(&root_chirho, &headers_chirho, "cookieapp")
                .unwrap()
                .unwrap();
        let input_value_chirho = super::app_http_dag_input_value_chirho(
            &root_chirho,
            "cookieapp",
            None,
            Some(&context_chirho),
            &HeaderMap::new(),
            body_chirho.to_vec(),
        )
        .unwrap();
        match input_value_chirho {
            dag_chirho::DagInputValueChirho::PrivateBytesChirho {
                subject_chirho,
                bytes_chirho,
            } => {
                assert_eq!(subject_chirho, user_chirho.principal_chirho);
                assert_eq!(bytes_chirho, body_chirho);
            }
            dag_chirho::DagInputValueChirho::PublicBytesChirho(_bytes_chirho) => {
                panic!("request-user private input must not be public")
            }
        }

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn app_params_failure_happens_before_private_body_persistence_chirho() {
        let root_chirho = temp_root_chirho("browser-session-app-params-private-fail");
        let (owner_chirho, _user_chirho, _login_chirho) = provision_cookie_app_chirho(&root_chirho);
        let record_chirho = cairn_chirho::app_chirho::set_app_params_chirho(
            &root_chirho,
            "cookieapp",
            None,
            &owner_chirho.principal_chirho,
            &serde_json::json!({"business_name_chirho":"Broken Bakery"}),
            true,
        )
        .unwrap();
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            "cookieapp",
            None,
            &owner_chirho.principal_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: "app/cookieapp/private-input".to_string(),
                safe_metadata_chirho: Vec::new(),
            },
        )
        .unwrap();
        let object_path_chirho =
            object_path_for_hash_chirho(&root_chirho, &record_chirho.params_chirho);
        std::fs::remove_file(object_path_chirho).unwrap();

        let error_chirho = super::app_dag_input_chirho(
            &root_chirho,
            "cookieapp",
            None,
            None,
            b"private customer text".to_vec(),
        )
        .unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("app params record 0 points at missing params"));
        assert!(!root_chirho
            .join("privacy-blob-records-chirho.jsonl")
            .exists());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn login_redirect_targets_are_safe_and_logout_clears_session_chirho() {
        let root_chirho = temp_root_chirho("browser-session-logout");
        let (_owner_chirho, user_chirho, login_chirho) = provision_cookie_app_chirho(&root_chirho);
        let headers_chirho =
            cookie_headers_chirho(&user_chirho.principal_chirho, &login_chirho.token_chirho);

        assert_eq!(
            auth_browser_redirect_path_chirho(
                &user_chirho.principal_chirho,
                Some("/app-chirho/perffection/dashboard-chirho"),
            ),
            "/app-chirho/perffection/dashboard-chirho"
        );
        assert_eq!(
            auth_browser_redirect_path_chirho(&user_chirho.principal_chirho, None),
            "/"
        );
        assert_ne!(
            auth_browser_redirect_path_chirho(
                &user_chirho.principal_chirho,
                Some("//evil.example/chirho"),
            ),
            "//evil.example/chirho"
        );

        let state_chirho = super::super::app_state_for_runtime_root_chirho(
            &root_chirho,
            8,
            String::new(),
            false,
            super::super::ServedRequestAbuseLimitsChirho::default(),
        )
        .unwrap();
        let response_chirho = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(auth_logout_get_chirho(State(state_chirho), headers_chirho));
        assert_eq!(response_chirho.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response_chirho.headers().get(LOCATION).unwrap(),
            "/auth-chirho/login-chirho"
        );
        let clear_cookie_chirho = response_chirho
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(clear_cookie_chirho.contains("cairn_session_chirho="));
        assert!(clear_cookie_chirho.contains("Max-Age=0"));
        assert!(identity_chirho::validate_session_token_chirho(
            &root_chirho,
            &user_chirho.principal_chirho,
            &login_chirho.token_chirho,
        )
        .unwrap()
        .is_none());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn form_login_redirect_field_drives_safe_browser_location_chirho() {
        let root_chirho = temp_root_chirho("browser-session-form-redirect");
        let (_owner_chirho, user_chirho, login_chirho) = provision_cookie_app_chirho(&root_chirho);
        let mut headers_chirho = HeaderMap::new();
        headers_chirho.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let body_chirho = format!(
            "principal_chirho={}&credential_chirho=user-session-secret&redirect_chirho=%2Fapp-chirho%2Fperffection%2Fdashboard-chirho",
            user_chirho.principal_chirho
        );
        let request_chirho = Request::builder().body(Body::from(body_chirho)).unwrap();
        let (parsed_chirho, format_chirho) = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(
                super::super::auth_wallet_chirho::parse_auth_login_request_chirho(
                    &headers_chirho,
                    request_chirho,
                ),
            )
            .unwrap();
        assert_eq!(
            parsed_chirho.redirect_chirho.as_deref(),
            Some("/app-chirho/perffection/dashboard-chirho")
        );
        let response_chirho = super::super::auth_wallet_chirho::auth_login_success_response_chirho(
            format_chirho,
            &login_chirho,
            parsed_chirho.redirect_chirho.as_deref(),
        );
        assert_eq!(response_chirho.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response_chirho.headers().get(LOCATION).unwrap(),
            "/app-chirho/perffection/dashboard-chirho"
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn cookie_app_query_refuses_before_legacy_billing_chirho() {
        let root_chirho = temp_root_chirho("browser-session-app-run");
        let (_owner_chirho, user_chirho, login_chirho) = provision_cookie_app_chirho(&root_chirho);
        let headers_chirho =
            cookie_headers_chirho(&user_chirho.principal_chirho, &login_chirho.token_chirho);
        let state_chirho = super::super::app_state_for_runtime_root_chirho(
            &root_chirho,
            8,
            String::new(),
            false,
            super::super::ServedRequestAbuseLimitsChirho::default(),
        )
        .unwrap();
        let request_chirho = cairn_chirho::effect_chirho::ScopedQueryRequestChirho {
            prefix_chirho: "session-proof-chirho".to_string(),
            limit_chirho: Some(1),
        };
        let response_chirho = super::super::run_app_http_chirho(
            &state_chirho,
            None,
            &headers_chirho,
            "cookieapp",
            None,
            serde_json::to_vec(&request_chirho).unwrap(),
        );
        let status_chirho = response_chirho.status();
        let body_chirho = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(axum::body::to_bytes(
                response_chirho.into_body(),
                usize::MAX,
            ))
            .unwrap();
        let body_text_chirho = String::from_utf8_lossy(&body_chirho);
        assert_eq!(status_chirho, StatusCode::BAD_REQUEST, "{body_text_chirho}");
        assert!(
            crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(
                &body_text_chirho
            )
            .is_some(),
            "{body_text_chirho}"
        );
        assert!(!body_text_chirho.contains("legacy money road"));
        assert!(!body_text_chirho.contains("QueryEffectChirho"));

        assert!(
            cairn_chirho::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
                .unwrap_or_default()
                .is_empty()
        );
        assert!(
            cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
                .unwrap_or_default()
                .is_empty()
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    fn provision_cookie_app_chirho(
        root_chirho: &std::path::Path,
    ) -> (
        identity_chirho::IdentityRecordChirho,
        identity_chirho::IdentityRecordChirho,
        identity_chirho::IdentityLoginResultChirho,
    ) {
        let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
            root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            "owner-session-secret",
        )
        .unwrap();
        let user_chirho = identity_chirho::register_identity_with_credential_chirho(
            root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            "user-session-secret",
        )
        .unwrap();
        let query_dag_chirho = store_query_effect_dag_chirho(root_chirho);
        cairn_chirho::app_chirho::deploy_app_chirho(
            root_chirho,
            "cookieapp",
            query_dag_chirho,
            &owner_chirho.principal_chirho,
        )
        .unwrap();
        cairn_chirho::app_chirho::set_app_input_policy_chirho(
            root_chirho,
            "cookieapp",
            None,
            &owner_chirho.principal_chirho,
            cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
        )
        .unwrap();
        let mut prices_chirho = BTreeMap::new();
        prices_chirho.insert("query_chirho".to_string(), 1);
        cairn_chirho::effect_pricing_chirho::set_price_book_chirho(
            root_chirho,
            "cookieapp",
            &owner_chirho.principal_chirho,
            None,
            prices_chirho,
            0,
        )
        .unwrap();
        let login_chirho = identity_chirho::login_identity_with_credential_chirho(
            root_chirho,
            &user_chirho.principal_chirho,
            "user-session-secret",
        )
        .unwrap();
        (owner_chirho, user_chirho, login_chirho)
    }

    fn cookie_headers_chirho(principal_chirho: &str, token_chirho: &str) -> HeaderMap {
        let mut headers_chirho = HeaderMap::new();
        headers_chirho.insert(
            COOKIE,
            HeaderValue::from_str(&format!(
                "{AUTH_SESSION_COOKIE_CHIRHO}={principal_chirho}:{token_chirho}"
            ))
            .unwrap(),
        );
        headers_chirho
    }

    fn store_query_effect_dag_chirho(root_chirho: &std::path::Path) -> HashChirho {
        let schema_hash_chirho =
            cairn_chirho::cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
        let builtin_hash_chirho =
            cairn_chirho::cas_chirho::add_chirho(root_chirho, b"builtin:query-chirho").unwrap();
        let node_chirho = NodeDefChirho {
            name_chirho: "query_session_proof_chirho".to_string(),
            impl_wasm_chirho: builtin_hash_chirho,
            entry_chirho: "query_chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho,
            }],
            capabilities_chirho: vec![
                CapabilityChirho::QueryChirho {
                    prefix_chirho: "session-proof-chirho".to_string(),
                    caller_chirho: "placeholder-session-caller-chirho".to_string(),
                    max_rows_chirho: 1,
                },
                CapabilityChirho::UserIdentityChirho {
                    principal_chirho: "placeholder-session-caller-chirho".to_string(),
                    client_id_chirho: String::new(),
                    token_hash_chirho: String::new(),
                },
            ],
            fuel_limit_chirho: 0,
            ..Default::default()
        };
        let node_hash_chirho =
            cairn_chirho::store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
        cairn_chirho::store_chirho::put_object_chirho(
            root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_hash_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap()
    }

    fn object_path_for_hash_chirho(
        root_chirho: &std::path::Path,
        hash_chirho: &HashChirho,
    ) -> std::path::PathBuf {
        root_chirho
            .join("objects-chirho")
            .join(&hash_chirho.0[0..2])
            .join(&hash_chirho.0[2..])
    }

    fn temp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
        let unique_chirho = format!(
            "cairn-{label_chirho}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root_chirho = std::env::temp_dir().join(unique_chirho);
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }
}
