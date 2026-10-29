// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Elected-era served-write dispatch before ref/resource selection.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.

#[path = "write_relay_chirho/caller_key_carrier_chirho.rs"]
pub(super) mod caller_key_carrier_chirho;
#[path = "write_relay_chirho/pure_app_read_chirho.rs"]
pub(super) mod pure_app_read_chirho;

use super::served_request_abuse_gate_chirho::ServedIngressAdmissionChirho;
use super::{app_http_chirho, AppStateChirho};
use anyhow::{anyhow, Result};
use axum::{
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use cairn_tenant_chirho::tenant_chirho::TenantIdChirho;
use cairn_write_relay_chirho::{
    relay_request_header_name_is_allowed_chirho, relay_response_header_name_is_allowed_chirho,
    CallerIdempotencyKeyChirho, CallerOperationBindingChirho,
    RelayDestinationExecutionFutureChirho, RelayDestinationExecutionPortChirho,
    RelayDestinationResponseChirho, RelayEndToEndHeadersChirho, RelayExecutionKnowledgeChirho,
    RelayIngressAdmissionChirho, RelayOutcomeClassChirho, RelayRefusalIdentityChirho,
    ServedWriteDispatchInputChirho, ServedWriteDispatchOutcomeChirho,
    VerifiedServedWriteRelayRequestChirho, VerifiedServedWriteRelayResponseChirho,
    CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO, RELAY_RESPONSE_BODY_MAX_BYTES_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho;
use std::sync::{Arc, Mutex, OnceLock};

const CREDITS_APP_CHIRHO: &str = "credits-demo-chirho";
const CREDITS_SPEND_ROUTE_CHIRHO: &str = "spend-chirho";
const CREDITS_SPEND_PATH_CHIRHO: &str = "/app-chirho/credits-demo-chirho/spend-chirho";

pub(super) async fn relay_only_follower_route_guard_chirho(
    request_chirho: Request,
    next_chirho: Next,
) -> Response {
    if let Some(response_chirho) = relay_only_follower_route_refusal_chirho(
        request_chirho.method(),
        request_chirho.uri().path(),
    ) {
        return response_chirho;
    }
    next_chirho.run(request_chirho).await
}

fn relay_only_follower_route_refusal_chirho(
    method_chirho: &Method,
    path_chirho: &str,
) -> Option<Response> {
    let health_read_chirho = matches!(*method_chirho, Method::GET | Method::HEAD)
        && matches!(path_chirho, "/healthz-chirho" | "/healthz");
    let converted_credits_vertical_chirho = matches!(*method_chirho, Method::GET | Method::POST)
        && path_chirho == CREDITS_SPEND_PATH_CHIRHO;
    let pure_app_read_chirho = matches!(*method_chirho, Method::GET | Method::POST)
        && path_chirho
            .parse::<Uri>()
            .ok()
            .and_then(|uri_chirho| direct_app_route_from_uri_chirho(&uri_chirho))
            .is_some_and(|(app_chirho, route_chirho)| {
                pure_app_read_chirho::is_transient_app_candidate_chirho(
                    &app_chirho,
                    Some(&route_chirho),
                    method_chirho,
                )
            });
    if health_read_chirho || converted_credits_vertical_chirho || pure_app_read_chirho {
        return None;
    }
    Some(relay_named_refusal_response_chirho(
        RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
        RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
    ))
}

pub(super) struct RelayedRequestMarkerChirho {
    caller_operation_chirho: ServedCallerOperationChirho,
    ingress_chirho: Mutex<Option<ServedIngressAdmissionChirho>>,
}

impl RelayedRequestMarkerChirho {
    fn from_verified_chirho(
        request_chirho: &VerifiedServedWriteRelayRequestChirho,
        ingress_chirho: ServedIngressAdmissionChirho,
    ) -> Result<Self> {
        Ok(Self {
            ingress_chirho: Mutex::new(Some(ingress_chirho)),
            caller_operation_chirho: ServedCallerOperationChirho {
                caller_key_chirho: request_chirho.caller_idempotency_key_chirho().clone(),
                operation_chirho: CallerOperationBindingChirho::new_chirho(
                    request_chirho.method_chirho(),
                    request_chirho.uri_chirho(),
                )
                .map_err(anyhow::Error::from)?,
                // The source forwarded the stripped body, so re-entry runs the body it received.
                business_body_chirho: None,
            },
        })
    }

    pub(super) fn take_ingress_chirho(&self) -> Result<ServedIngressAdmissionChirho> {
        self.ingress_chirho
            .lock()
            .map_err(|_| anyhow!("relay admission lock poisoned"))?
            .take()
            .ok_or_else(|| anyhow!("relay ingress admission already consumed"))
    }
}

pub(super) struct RelayOriginRequestChirho<'a> {
    pub headers_chirho: &'a HeaderMap,
    pub app_chirho: &'a str,
    pub route_chirho: Option<&'a str>,
    pub method_chirho: &'a Method,
    pub uri_chirho: &'a Uri,
    pub body_chirho: &'a [u8],
}

pub(super) async fn dispatch_origin_with_custody_chirho(
    state_chirho: &AppStateChirho,
    request_chirho: RelayOriginRequestChirho<'_>,
    assertion_chirho: RelayIngressAdmissionChirho,
    permit_chirho: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> ServedWriteBeforeSelectionChirho {
    let dispatch_state_chirho = state_chirho.clone();
    let headers_chirho = request_chirho.headers_chirho.clone();
    let app_chirho = request_chirho.app_chirho.to_string();
    let route_chirho = request_chirho.route_chirho.map(str::to_string);
    let method_chirho = request_chirho.method_chirho.clone();
    let uri_chirho = request_chirho.uri_chirho.clone();
    let body_chirho = request_chirho.body_chirho.to_vec();
    match tokio::spawn(async move {
        let _permit_chirho = permit_chirho;
        dispatch_before_app_selection_chirho(
            &dispatch_state_chirho,
            &headers_chirho,
            &app_chirho,
            route_chirho.as_deref(),
            &method_chirho,
            &uri_chirho,
            &body_chirho,
            None,
            Some(assertion_chirho),
        )
        .await
    })
    .await
    {
        Ok(outcome_chirho) => outcome_chirho,
        Err(_) => ServedWriteBeforeSelectionChirho::RespondChirho(
            RequestRefusalChirho::new_chirho(
                state_chirho,
                request_chirho.headers_chirho,
                request_chirho.app_chirho,
                request_chirho.method_chirho,
                false,
            )
            .answer_chirho(
                RelayRefusalIdentityChirho::RelayResponseUnavailableAfterExecutionChirho,
                RelayExecutionKnowledgeChirho::MayHaveExecutedChirho,
            ),
        ),
    }
}

#[derive(Clone)]
pub(super) struct ServedCallerOperationChirho {
    caller_key_chirho: CallerIdempotencyKeyChirho,
    operation_chirho: CallerOperationBindingChirho,
    /// The body the run must see when the key came from a form: the carrier field removed. `None`
    /// runs the body as sent.
    business_body_chirho: Option<Vec<u8>>,
}

impl ServedCallerOperationChirho {
    /// The key, the operation it binds, and the body the run must see (`None` runs the body as sent).
    pub(super) fn into_parts_chirho(
        self,
    ) -> (
        CallerIdempotencyKeyChirho,
        CallerOperationBindingChirho,
        Option<Vec<u8>>,
    ) {
        (
            self.caller_key_chirho,
            self.operation_chirho,
            self.business_body_chirho,
        )
    }
}

/// Answers a served-write refusal in the shape its caller can read: a browser form submission gets
/// the 303 with its token, and every other caller, a relayed re-entry included, gets the relay's
/// named refusal. The relay's typed identity and execution knowledge choose the token.
struct RequestRefusalChirho<'a> {
    state_chirho: &'a AppStateChirho,
    headers_chirho: &'a HeaderMap,
    app_chirho: &'a str,
    browser_form_chirho: bool,
}

impl<'a> RequestRefusalChirho<'a> {
    fn new_chirho(
        state_chirho: &'a AppStateChirho,
        headers_chirho: &'a HeaderMap,
        app_chirho: &'a str,
        method_chirho: &Method,
        reentry_chirho: bool,
    ) -> Self {
        Self {
            state_chirho,
            headers_chirho,
            app_chirho,
            // The owner of a relayed request answers the source, never a browser.
            browser_form_chirho: *method_chirho == Method::POST
                && !reentry_chirho
                && caller_key_carrier_chirho::is_browser_form_submission_chirho(headers_chirho),
        }
    }

    fn answer_chirho(
        &self,
        identity_chirho: RelayRefusalIdentityChirho,
        knowledge_chirho: RelayExecutionKnowledgeChirho,
    ) -> Response {
        if !self.browser_form_chirho {
            return relay_named_refusal_response_chirho(identity_chirho, knowledge_chirho);
        }
        self.state_chirho
            .runtime_chirho
            .browser_form_refusal_on_app_chirho(
                self.headers_chirho,
                self.app_chirho,
                caller_key_carrier_chirho::form_refusal_token_chirho(
                    identity_chirho,
                    knowledge_chirho,
                ),
            )
    }
}

pub(super) enum ServedWriteBeforeSelectionChirho {
    ContinueChirho(Option<ServedCallerOperationChirho>),
    RespondChirho(Response),
}

pub(super) fn local_pre_body_route_policy_applies_chirho(state_chirho: &AppStateChirho) -> bool {
    matches!(
        state_chirho.runtime_chirho.writer_authority_era_chirho(),
        Ok(WriterAuthorityEraChirho::LocalChirho)
    )
}

pub(super) fn unconverted_elected_entrypoint_response_chirho(
    state_chirho: &AppStateChirho,
) -> Option<Response> {
    match state_chirho.runtime_chirho.writer_authority_era_chirho() {
        Ok(WriterAuthorityEraChirho::LocalChirho) => None,
        Ok(WriterAuthorityEraChirho::ElectedChirho) => Some(relay_named_refusal_response_chirho(
            RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        )),
        Err(_error_chirho) => Some(relay_named_refusal_response_chirho(
            RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        )),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "preselection dispatch binds the complete request before any durable route selection"
)]
pub(super) async fn dispatch_before_app_selection_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    app_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: &Method,
    uri_chirho: &Uri,
    body_chirho: &[u8],
    reentry_chirho: Option<&RelayedRequestMarkerChirho>,
    ingress_admission_chirho: Option<RelayIngressAdmissionChirho>,
) -> ServedWriteBeforeSelectionChirho {
    let refusal_chirho = RequestRefusalChirho::new_chirho(
        state_chirho,
        headers_chirho,
        app_chirho,
        method_chirho,
        reentry_chirho.is_some(),
    );
    let era_chirho = match state_chirho.runtime_chirho.writer_authority_era_chirho() {
        Ok(era_chirho) => era_chirho,
        Err(_error_chirho) => {
            return ServedWriteBeforeSelectionChirho::RespondChirho(refusal_chirho.answer_chirho(
                RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho,
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
            ))
        }
    };
    if era_chirho == WriterAuthorityEraChirho::LocalChirho {
        return ServedWriteBeforeSelectionChirho::ContinueChirho(None);
    }
    if !matches!(state_chirho.tenant_chirho, TenantIdChirho::TenantChirho(_)) {
        return ServedWriteBeforeSelectionChirho::RespondChirho(refusal_chirho.answer_chirho(
            RelayRefusalIdentityChirho::RelayPlatformRootIdentityUnavailableChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        ));
    }
    let credits_chirho =
        app_chirho == CREDITS_APP_CHIRHO && route_chirho == Some(CREDITS_SPEND_ROUTE_CHIRHO);
    let pure_read_chirho = pure_app_read_chirho::is_transient_app_candidate_chirho(
        app_chirho,
        route_chirho,
        method_chirho,
    );
    if !credits_chirho && !pure_read_chirho {
        return ServedWriteBeforeSelectionChirho::RespondChirho(refusal_chirho.answer_chirho(
            RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        ));
    }
    if let Some(reentry_chirho) = reentry_chirho {
        return ServedWriteBeforeSelectionChirho::ContinueChirho(Some(
            reentry_chirho.caller_operation_chirho.clone(),
        ));
    }
    // The key comes from the form field or the header, through the one shared reader; a form's field
    // is removed from the body that is forwarded and run (gpt #28889).
    let reading_chirho = match caller_key_carrier_chirho::read_caller_key_chirho(
        headers_chirho,
        body_chirho,
    ) {
        Ok(reading_chirho) => reading_chirho,
        Err(carrier_refusal_chirho) => {
            eprintln!(
                    "served write refused before any run: RelayCallerKeyInvalidChirho ({carrier_refusal_chirho:?})"
                );
            return ServedWriteBeforeSelectionChirho::RespondChirho(refusal_chirho.answer_chirho(
                RelayRefusalIdentityChirho::RelayCallerKeyInvalidChirho,
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
            ));
        }
    };
    let caller_key_chirho = reading_chirho.caller_key_chirho;
    let business_body_chirho = reading_chirho.business_body_chirho;
    let operation_chirho = match CallerOperationBindingChirho::new_chirho(
        method_chirho.as_str(),
        uri_chirho.to_string(),
    ) {
        Ok(operation_chirho) => operation_chirho,
        Err(error_chirho) => {
            return ServedWriteBeforeSelectionChirho::RespondChirho(refusal_chirho.answer_chirho(
                error_chirho.identity_chirho(),
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
            ))
        }
    };
    let Some(dispatch_chirho) = &state_chirho.write_dispatch_chirho else {
        return ServedWriteBeforeSelectionChirho::RespondChirho(refusal_chirho.answer_chirho(
            RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        ));
    };
    let request_headers_chirho = match relay_request_headers_chirho(headers_chirho) {
        Ok(headers_chirho) => headers_chirho,
        Err(_error_chirho) => {
            return ServedWriteBeforeSelectionChirho::RespondChirho(refusal_chirho.answer_chirho(
                RelayRefusalIdentityChirho::RelayHeaderInvalidChirho,
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
            ))
        }
    };
    match dispatch_chirho
        .dispatch_chirho(ServedWriteDispatchInputChirho {
            ingress_admission_chirho,
            caller_idempotency_key_chirho: caller_key_chirho.clone(),
            method_chirho: operation_chirho.method_chirho().to_string(),
            uri_chirho: operation_chirho.normalized_uri_chirho().to_string(),
            end_to_end_headers_chirho: request_headers_chirho,
            body_chirho: business_body_chirho
                .clone()
                .unwrap_or_else(|| body_chirho.to_vec()),
        })
        .await
    {
        Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho) => {
            ServedWriteBeforeSelectionChirho::ContinueChirho(Some(ServedCallerOperationChirho {
                caller_key_chirho,
                operation_chirho,
                business_body_chirho,
            }))
        }
        Ok(ServedWriteDispatchOutcomeChirho::RelayedChirho(response_chirho)) => {
            ServedWriteBeforeSelectionChirho::RespondChirho(verified_relay_response_chirho(
                *response_chirho,
                |identity_chirho, knowledge_chirho| {
                    refusal_chirho.answer_chirho(identity_chirho, knowledge_chirho)
                },
            ))
        }
        Err(error_chirho) => {
            ServedWriteBeforeSelectionChirho::RespondChirho(refusal_chirho.answer_chirho(
                error_chirho.identity_chirho(),
                error_chirho.execution_knowledge_chirho(),
            ))
        }
    }
}

fn relay_request_headers_chirho(headers_chirho: &HeaderMap) -> Result<RelayEndToEndHeadersChirho> {
    let mut selected_chirho = Vec::new();
    for (name_chirho, value_chirho) in headers_chirho {
        if relay_request_header_name_is_allowed_chirho(name_chirho.as_str()) {
            selected_chirho.push((
                name_chirho.as_str().to_string(),
                value_chirho
                    .to_str()
                    .map_err(|_| anyhow!("relay request header is not visible ASCII"))?
                    .to_string(),
            ));
        }
    }
    RelayEndToEndHeadersChirho::try_request_chirho(selected_chirho).map_err(anyhow::Error::from)
}

fn verified_relay_response_chirho(
    response_chirho: VerifiedServedWriteRelayResponseChirho,
    refuse_chirho: impl Fn(RelayRefusalIdentityChirho, RelayExecutionKnowledgeChirho) -> Response,
) -> Response {
    if response_chirho.outcome_class_chirho() == RelayOutcomeClassChirho::RelayRefusalChirho {
        let Some(identity_chirho) = response_chirho
            .outcome_identity_chirho()
            .and_then(RelayRefusalIdentityChirho::from_str_chirho)
        else {
            return refuse_chirho(
                RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
                RelayExecutionKnowledgeChirho::MayHaveExecutedChirho,
            );
        };
        return refuse_chirho(
            identity_chirho,
            identity_chirho.signed_outcome_execution_knowledge_chirho(),
        );
    }
    let status_chirho =
        StatusCode::from_u16(response_chirho.status_chirho()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers_chirho = HeaderMap::new();
    for (name_chirho, value_chirho) in response_chirho.end_to_end_headers_chirho().iter_chirho() {
        let (Ok(name_chirho), Ok(value_chirho)) = (
            HeaderName::from_bytes(name_chirho.as_bytes()),
            HeaderValue::from_str(value_chirho),
        ) else {
            return refuse_chirho(
                RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
                RelayExecutionKnowledgeChirho::MayHaveExecutedChirho,
            );
        };
        headers_chirho.append(name_chirho, value_chirho);
    }
    (
        status_chirho,
        headers_chirho,
        response_chirho.body_chirho().to_vec(),
    )
        .into_response()
}

// Process-local provenance, never an HTTP header or a value the guest can return. The transient
// destination uses it instead of classifying an untrusted WASM payload by its text.
#[derive(Clone)]
struct RelayHttpRefusalChirho(RelayRefusalIdentityChirho);

pub(super) fn relay_named_refusal_response_chirho(
    identity_chirho: RelayRefusalIdentityChirho,
    knowledge_chirho: RelayExecutionKnowledgeChirho,
) -> Response {
    let status_chirho = match (identity_chirho, knowledge_chirho) {
        (RelayRefusalIdentityChirho::RelayCallerKeyInvalidChirho, _) => StatusCode::BAD_REQUEST,
        (_, RelayExecutionKnowledgeChirho::MayHaveExecutedChirho) => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    let mut response_chirho = (
        status_chirho,
        format!("error: {}\n", identity_chirho.as_str_chirho()),
    )
        .into_response();
    response_chirho
        .extensions_mut()
        .insert(RelayHttpRefusalChirho(identity_chirho));
    response_chirho
}

#[derive(Clone, Default)]
pub struct ServedWriteRelayDestinationSlotChirho {
    destination_chirho: Arc<OnceLock<Arc<dyn RelayDestinationExecutionPortChirho>>>,
}

impl ServedWriteRelayDestinationSlotChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }

    fn install_chirho(
        &self,
        destination_chirho: Arc<dyn RelayDestinationExecutionPortChirho>,
    ) -> Result<()> {
        self.destination_chirho
            .set(destination_chirho)
            .map_err(|_| anyhow!("served write relay destination was installed more than once"))
    }
}

impl RelayDestinationExecutionPortChirho for ServedWriteRelayDestinationSlotChirho {
    fn execute_verified_chirho<'a>(
        &'a self,
        request_chirho: &'a VerifiedServedWriteRelayRequestChirho,
    ) -> RelayDestinationExecutionFutureChirho<'a> {
        match self.destination_chirho.get() {
            Some(destination_chirho) => destination_chirho.execute_verified_chirho(request_chirho),
            None => Box::pin(async {
                RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
                )
            }),
        }
    }
}

pub(super) fn install_relay_destination_chirho(
    slot_chirho: &ServedWriteRelayDestinationSlotChirho,
    state_chirho: AppStateChirho,
) -> Result<()> {
    slot_chirho.install_chirho(Arc::new(ServedWriteRelayDestinationChirho { state_chirho }))
}

struct ServedWriteRelayDestinationChirho {
    state_chirho: AppStateChirho,
}

impl RelayDestinationExecutionPortChirho for ServedWriteRelayDestinationChirho {
    fn execute_verified_chirho<'a>(
        &'a self,
        request_chirho: &'a VerifiedServedWriteRelayRequestChirho,
    ) -> RelayDestinationExecutionFutureChirho<'a> {
        Box::pin(async move {
            if !self
                .state_chirho
                .served_request_abuse_gate_chirho
                .accepts_relay_ingress_chirho(request_chirho)
            {
                return RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayIngressAdmissionInvalidChirho,
                );
            }
            let ingress_chirho = match self
                .state_chirho
                .served_request_abuse_gate_chirho
                .admit_relay_ingress_chirho(
                    Arc::clone(&self.state_chirho.inflight_chirho),
                    request_chirho,
                ) {
                Ok(ingress_chirho) => ingress_chirho,
                Err(_) => {
                    let headers_chirho =
                        axum_headers_from_relay_chirho(request_chirho.end_to_end_headers_chirho())
                            .unwrap_or_default();
                    return relay_destination_response_with_http_refusals_chirho(
                        super::served_request_rejected_response_chirho(
                            &self.state_chirho,
                            &headers_chirho,
                            None,
                        ),
                        true,
                    )
                    .await;
                }
            };
            let Ok(method_chirho) = Method::from_bytes(request_chirho.method_chirho().as_bytes())
            else {
                return RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayMethodInvalidChirho,
                );
            };
            let Ok(uri_chirho) = request_chirho.uri_chirho().parse::<Uri>() else {
                return RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayUriInvalidChirho,
                );
            };
            let Some((app_chirho, route_chirho)) = direct_app_route_from_uri_chirho(&uri_chirho)
            else {
                return RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
                );
            };
            let pure_read_chirho = pure_app_read_chirho::is_transient_app_candidate_chirho(
                &app_chirho,
                Some(&route_chirho),
                &method_chirho,
            );
            if pure_read_chirho
                && !matches!(
                    self.state_chirho
                        .runtime_chirho
                        .writer_authority_era_chirho(),
                    Ok(WriterAuthorityEraChirho::ElectedChirho)
                )
            {
                return RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho,
                );
            }
            if !pure_read_chirho
                && (app_chirho != CREDITS_APP_CHIRHO || route_chirho != CREDITS_SPEND_ROUTE_CHIRHO)
            {
                return RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
                );
            }
            let Ok(headers_chirho) =
                axum_headers_from_relay_chirho(request_chirho.end_to_end_headers_chirho())
            else {
                return RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayHeaderInvalidChirho,
                );
            };
            let Ok(marker_chirho) =
                RelayedRequestMarkerChirho::from_verified_chirho(request_chirho, ingress_chirho)
            else {
                return RelayDestinationResponseChirho::relay_refusal_chirho(
                    RelayRefusalIdentityChirho::RelayRequestDigestMismatchChirho,
                );
            };
            let response_chirho =
                app_http_chirho::run_app_http_with_method_for_relay_reentry_chirho(
                    &self.state_chirho,
                    &headers_chirho,
                    &app_chirho,
                    &route_chirho,
                    method_chirho,
                    uri_chirho,
                    request_chirho.body_chirho().to_vec(),
                    &marker_chirho,
                )
                .await;
            if pure_read_chirho {
                relay_destination_response_with_http_refusals_chirho(response_chirho, true).await
            } else {
                relay_destination_response_chirho(response_chirho).await
            }
        })
    }
}

fn direct_app_route_from_uri_chirho(uri_chirho: &Uri) -> Option<(String, String)> {
    let mut segments_chirho = uri_chirho.path().strip_prefix('/')?.split('/');
    if segments_chirho.next()? != "app-chirho" {
        return None;
    }
    let app_chirho = segments_chirho.next()?.to_string();
    let route_chirho = segments_chirho.next()?.to_string();
    if segments_chirho.next().is_some()
        || app_chirho.is_empty()
        || route_chirho.is_empty()
        || ![&app_chirho, &route_chirho].iter().all(|segment_chirho| {
            segment_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'-' | b'_')
            })
        })
    {
        return None;
    }
    Some((app_chirho, route_chirho))
}

fn axum_headers_from_relay_chirho(
    headers_chirho: &RelayEndToEndHeadersChirho,
) -> Result<HeaderMap> {
    let mut output_chirho = HeaderMap::new();
    for (name_chirho, value_chirho) in headers_chirho.iter_chirho() {
        output_chirho.append(
            HeaderName::from_bytes(name_chirho.as_bytes())?,
            HeaderValue::from_str(value_chirho)?,
        );
    }
    Ok(output_chirho)
}

async fn relay_destination_response_chirho(
    response_chirho: Response,
) -> RelayDestinationResponseChirho {
    relay_destination_response_with_http_refusals_chirho(response_chirho, false).await
}

async fn relay_destination_response_with_http_refusals_chirho(
    response_chirho: Response,
    pure_read_chirho: bool,
) -> RelayDestinationResponseChirho {
    if pure_read_chirho {
        if let Some(refusal_chirho) = response_chirho.extensions().get::<RelayHttpRefusalChirho>() {
            return RelayDestinationResponseChirho::relay_refusal_chirho(refusal_chirho.0);
        }
    }
    let status_chirho = response_chirho.status();
    let headers_chirho = match relay_response_headers_chirho(response_chirho.headers()) {
        Ok(headers_chirho) => headers_chirho,
        Err(_error_chirho) => {
            return RelayDestinationResponseChirho::relay_refusal_chirho(
                RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
            )
        }
    };
    let body_chirho = match to_bytes(
        response_chirho.into_body(),
        RELAY_RESPONSE_BODY_MAX_BYTES_CHIRHO,
    )
    .await
    {
        Ok(body_chirho) => body_chirho.to_vec(),
        Err(_error_chirho) => {
            return RelayDestinationResponseChirho::relay_refusal_chirho(
                RelayRefusalIdentityChirho::RelayResponseUnavailableAfterExecutionChirho,
            )
        }
    };
    // An engine relay refusal was classified above from process-local provenance. Other transient
    // answers (401, 405, JSON 429 and WASM output) preserve their HTTP shape, never text-classified.
    if !pure_read_chirho && (status_chirho.is_client_error() || status_chirho.is_server_error()) {
        let Some(identity_chirho) = refusal_identity_from_body_chirho(&body_chirho) else {
            return RelayDestinationResponseChirho::relay_refusal_chirho(
                RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
            );
        };
        return RelayDestinationResponseChirho::door_refusal_chirho(
            identity_chirho,
            status_chirho.as_u16(),
            headers_chirho,
            body_chirho,
        );
    }
    RelayDestinationResponseChirho::served_chirho(
        status_chirho.as_u16(),
        headers_chirho,
        body_chirho,
    )
}

fn relay_response_headers_chirho(headers_chirho: &HeaderMap) -> Result<RelayEndToEndHeadersChirho> {
    let mut selected_chirho = Vec::new();
    for (name_chirho, value_chirho) in headers_chirho {
        if relay_response_header_name_is_allowed_chirho(name_chirho.as_str()) {
            selected_chirho.push((
                name_chirho.as_str().to_string(),
                value_chirho
                    .to_str()
                    .map_err(|_| anyhow!("relay response header is not visible ASCII"))?
                    .to_string(),
            ));
        }
    }
    RelayEndToEndHeadersChirho::try_response_chirho(selected_chirho).map_err(anyhow::Error::from)
}

fn refusal_identity_from_body_chirho(body_chirho: &[u8]) -> Option<String> {
    let body_chirho = std::str::from_utf8(body_chirho).ok()?;
    let remainder_chirho = body_chirho.strip_prefix("error: ")?;
    let identity_chirho = remainder_chirho
        .split(|character_chirho: char| {
            character_chirho == ':' || character_chirho.is_ascii_whitespace()
        })
        .next()?;
    if identity_chirho.is_empty()
        || identity_chirho.len() > 128
        || !identity_chirho.ends_with("Chirho")
        || !identity_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(identity_chirho.to_string())
}

#[cfg(test)]
#[path = "write_relay_chirho/tests_chirho.rs"]
mod tests_chirho;
