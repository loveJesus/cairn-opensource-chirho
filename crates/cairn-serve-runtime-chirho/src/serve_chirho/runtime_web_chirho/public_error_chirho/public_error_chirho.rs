// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Detail-safe public error answers: one body per failure class, with execution knowledge from the
//! trusted refusal observation, and one diagnostic witness line of typed fields for the server log.
//!
//! No body carries a root, an object hash, a node or user name, a raw error chain or reflected input,
//! and the witness carries none of those, nor a credential, an Authorization or session value, or a
//! submitted body. Knowledge is never retry authorization (PFE #26446, #26451).
//! Workflow: spec-chirho/workflows-chirho/served-request-admission-chirho/public-error-bodies-chirho/README-chirho.md.

use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use cairn_chirho::dag_chirho::refusal_chirho::{
    dag_execution_refusal_observation_chirho, DagExecutionAttemptOrdinalChirho,
    DagExecutionKnowledgeChirho, DagExecutionRefusalObservationChirho,
};
use cairn_chirho::durable_chirho::io_error_is_resource_exhaustion_chirho;

/// The execution refusal's identity, the first line of its plain body, kept from before.
pub(crate) const EXECUTION_REFUSED_IDENTITY_CHIRHO: &str = "CairnAppExecutionRefusedChirho";
const PRE_RUN_UNAVAILABLE_IDENTITY_CHIRHO: &str = "served-request-pre-run-unavailable-chirho";
/// Never the served gate's refusal token: that 429 carries an admission wait hint (Retry-After); this 503 carries
/// none and authorizes no retry.
const UNAVAILABLE_IDENTITY_CHIRHO: &str = "served-request-resource-unavailable-chirho";
const UNAVAILABLE_GUIDANCE_CHIRHO: &str = "The server could not answer this request.";
const DAG_EFFECTS_SCOPE_CHIRHO: &str = "dag-effects-chirho";
const WITNESS_PREFIX_CHIRHO: &str = "CairnPublicErrorChirho";
/// A request-context refusal's identities: a rate limit, a use window catching up, anything else refused.
pub(crate) const RATE_LIMIT_EXCEEDED_IDENTITY_CHIRHO: &str = "rate-limit-exceeded-chirho";
pub(crate) const USE_WINDOW_CATCHING_UP_IDENTITY_CHIRHO: &str = "use-window-catching-up-chirho";
pub(crate) const REQUEST_NOT_AUTHORIZED_IDENTITY_CHIRHO: &str = "request-not-authorized-chirho";

/// One public failure, classified by the boundary it happened at and, before a run, by its typed cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicFailureChirho {
    /// Before any DAG run, from a typed resource exhaustion (out of files, out of space, try again).
    PreRunResourceChirho { os_code_chirho: i32 },
    /// On a route that runs no DAG, from a typed resource exhaustion: the server could not answer.
    UnavailableChirho { os_code_chirho: i32 },
    /// A refusal by a fixed identity, with the status its site has always used.
    FixedRefusalChirho {
        status_chirho: StatusCode,
        identity_chirho: &'static str,
    },
    /// An execution refusal, with its trusted observation.
    ExecutionRefusalChirho(DagExecutionRefusalObservationChirho),
}

/// Classifies a failure before any DAG run: a typed resource exhaustion anywhere in the chain, read
/// from an `io::Error`'s raw OS code alone, or else the site's fixed identity and status.
pub(crate) fn classify_pre_run_chirho(
    error_chirho: &anyhow::Error,
    status_chirho: StatusCode,
    identity_chirho: &'static str,
) -> PublicFailureChirho {
    for cause_chirho in error_chirho.chain() {
        if let Some(io_chirho) = cause_chirho.downcast_ref::<std::io::Error>() {
            if io_error_is_resource_exhaustion_chirho(io_chirho) {
                return PublicFailureChirho::PreRunResourceChirho {
                    os_code_chirho: io_chirho.raw_os_error().unwrap_or_default(),
                };
            }
        }
    }
    PublicFailureChirho::FixedRefusalChirho {
        status_chirho,
        identity_chirho,
    }
}

/// Classifies a failure on a route that runs no DAG: a typed resource exhaustion anywhere in the chain
/// is the unavailable class (503), and anything else the site's fixed identity and status.
pub(crate) fn classify_non_dag_chirho(
    error_chirho: &anyhow::Error,
    status_chirho: StatusCode,
    identity_chirho: &'static str,
) -> PublicFailureChirho {
    match classify_pre_run_chirho(error_chirho, status_chirho, identity_chirho) {
        PublicFailureChirho::PreRunResourceChirho { os_code_chirho } => {
            PublicFailureChirho::UnavailableChirho { os_code_chirho }
        }
        failure_chirho => failure_chirho,
    }
}

impl PublicFailureChirho {
    /// The status this failure answers.
    pub(crate) fn status_chirho(self) -> StatusCode {
        match self {
            Self::PreRunResourceChirho { .. } | Self::UnavailableChirho { .. } => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::FixedRefusalChirho { status_chirho, .. } => status_chirho,
            Self::ExecutionRefusalChirho(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// The fixed public identity this failure answers with.
    pub(crate) fn identity_chirho(self) -> &'static str {
        match self {
            Self::PreRunResourceChirho { .. } => PRE_RUN_UNAVAILABLE_IDENTITY_CHIRHO,
            Self::UnavailableChirho { .. } => UNAVAILABLE_IDENTITY_CHIRHO,
            Self::FixedRefusalChirho {
                identity_chirho, ..
            } => identity_chirho,
            Self::ExecutionRefusalChirho(_) => EXECUTION_REFUSED_IDENTITY_CHIRHO,
        }
    }
}

/// Classifies a request-context failure before any DAG run: a typed resource exhaustion first, then the
/// typed rate limit (429) and use window catching up (503), and any other a fixed 403, as before.
pub(crate) fn classify_request_context_chirho(error_chirho: &anyhow::Error) -> PublicFailureChirho {
    // A key the gate does not admit for this entry or route (K1): its own fixed identity, 403.
    if let Some(refusal_chirho) = error_chirho.chain().find_map(|cause_chirho| {
        cause_chirho
            .downcast_ref::<cairn_chirho::capability_key_grant_chirho::KeyRouteRefusalChirho>()
    }) {
        return PublicFailureChirho::FixedRefusalChirho {
            status_chirho: StatusCode::FORBIDDEN,
            identity_chirho: refusal_chirho.identity_chirho(),
        };
    }
    let status_chirho = super::request_context_error_status_chirho(error_chirho);
    let identity_chirho = match status_chirho {
        StatusCode::TOO_MANY_REQUESTS => RATE_LIMIT_EXCEEDED_IDENTITY_CHIRHO,
        StatusCode::SERVICE_UNAVAILABLE => USE_WINDOW_CATCHING_UP_IDENTITY_CHIRHO,
        _ => REQUEST_NOT_AUTHORIZED_IDENTITY_CHIRHO,
    };
    classify_pre_run_chirho(error_chirho, status_chirho, identity_chirho)
}

/// Classifies a failure preparing the app's input before any DAG run: the visitor's own typed input
/// refusal by its identity, then a typed resource exhaustion, and anything else one fixed identity, all
/// with the 400 this site has always used.
pub(crate) fn classify_app_input_chirho(error_chirho: &anyhow::Error) -> PublicFailureChirho {
    let refusal_chirho = error_chirho.chain().find_map(|cause_chirho| {
        cause_chirho.downcast_ref::<super::app_session_chirho::AppInputRefusalChirho>()
    });
    if let Some(refusal_chirho) = refusal_chirho {
        return PublicFailureChirho::FixedRefusalChirho {
            status_chirho: StatusCode::BAD_REQUEST,
            identity_chirho: refusal_chirho.identity_chirho(),
        };
    }
    classify_pre_run_chirho(
        error_chirho,
        StatusCode::BAD_REQUEST,
        "app-input-refused-chirho",
    )
}

/// Classifies an app selection failure before any DAG run: the typed scoped-bearer refusal keeps its
/// identity; an unknown app is 404, its text read for that status only, as before, and never echoed; a
/// typed resource exhaustion is 503; anything else a fixed 400.
pub(crate) fn classify_selection_chirho(error_chirho: &anyhow::Error) -> PublicFailureChirho {
    let bearer_required_chirho = error_chirho.chain().any(|cause_chirho| {
        cause_chirho
            .downcast_ref::<super::resource_gate_chirho::ScopedBearerRequiredChirho>()
            .is_some()
    });
    if bearer_required_chirho {
        return PublicFailureChirho::FixedRefusalChirho {
            status_chirho: StatusCode::BAD_REQUEST,
            identity_chirho: "scoped-bearer-required-chirho",
        };
    }
    let (status_chirho, identity_chirho) =
        if error_chirho.to_string().starts_with("no deployed app") {
            (StatusCode::NOT_FOUND, "app-not-found-chirho")
        } else {
            (StatusCode::BAD_REQUEST, "app-selection-refused-chirho")
        };
    classify_pre_run_chirho(error_chirho, status_chirho, identity_chirho)
}

/// The identities of a run's DAG policy refusals, shared by the public run and the preview.
pub(crate) const CAPABILITY_FREE_DAG_REQUIRED_IDENTITY_CHIRHO: &str =
    "capability-free-dag-required-chirho";
pub(crate) const WASM_DAG_REQUIRED_IDENTITY_CHIRHO: &str = "wasm-dag-required-chirho";

/// Classifies the public run's check before its run: a typed policy refusal by its identity, a typed
/// resource exhaustion as 503, and anything else (an unknown DAG among them) a fixed 403, as before.
pub(crate) fn classify_public_run_check_chirho(
    error_chirho: &anyhow::Error,
) -> PublicFailureChirho {
    let refusal_chirho = error_chirho.chain().find_map(|cause_chirho| {
        cause_chirho.downcast_ref::<super::public_run_chirho::PublicRunRefusalChirho>()
    });
    match refusal_chirho {
        Some(refusal_chirho) => PublicFailureChirho::FixedRefusalChirho {
            status_chirho: StatusCode::FORBIDDEN,
            identity_chirho: refusal_chirho.identity_chirho(),
        },
        None => classify_pre_run_chirho(
            error_chirho,
            StatusCode::FORBIDDEN,
            "public-run-refused-chirho",
        ),
    }
}

/// Classifies a preview failure: a typed policy refusal by its identity, anything else one fixed 400.
/// No resource class: the preview has no pre-run boundary apart from its in-memory run.
pub(crate) fn classify_preview_chirho(error_chirho: &anyhow::Error) -> PublicFailureChirho {
    use cairn_app_preview_chirho::PreviewRefusalChirho as RefusalChirho;
    let identity_chirho = match error_chirho
        .chain()
        .find_map(|cause_chirho| cause_chirho.downcast_ref::<RefusalChirho>())
    {
        Some(RefusalChirho::CapabilityBearingNodeChirho { .. }) => {
            CAPABILITY_FREE_DAG_REQUIRED_IDENTITY_CHIRHO
        }
        Some(RefusalChirho::NativeProgramNodeChirho { .. }) => WASM_DAG_REQUIRED_IDENTITY_CHIRHO,
        None => "preview-refused-chirho",
    };
    PublicFailureChirho::FixedRefusalChirho {
        status_chirho: StatusCode::BAD_REQUEST,
        identity_chirho,
    }
}

/// One line naming a failure, for a transport with no status or body of its own (the invoke
/// WebSocket frame): the identity, and an execution refusal's knowledge.
pub(crate) fn public_summary_chirho(failure_chirho: PublicFailureChirho) -> String {
    match failure_chirho {
        PublicFailureChirho::PreRunResourceChirho { .. } => {
            format!("error: {PRE_RUN_UNAVAILABLE_IDENTITY_CHIRHO}")
        }
        PublicFailureChirho::UnavailableChirho { .. } => {
            format!("error: {UNAVAILABLE_IDENTITY_CHIRHO}")
        }
        PublicFailureChirho::FixedRefusalChirho {
            identity_chirho, ..
        } => format!("error: {identity_chirho}"),
        PublicFailureChirho::ExecutionRefusalChirho(observation_chirho) => format!(
            "error: {EXECUTION_REFUSED_IDENTITY_CHIRHO} knowledge: {}",
            observation_chirho
                .execution_knowledge_chirho()
                .as_str_chirho()
        ),
    }
}

/// Classifies an execution refusal from its trusted observation; a missing or unclassified one is
/// unknown, never a fresh definitely-not-executed.
pub(crate) fn classify_execution_chirho(error_chirho: &anyhow::Error) -> PublicFailureChirho {
    PublicFailureChirho::ExecutionRefusalChirho(dag_execution_refusal_observation_chirho(
        error_chirho,
    ))
}

/// The one guidance sentence for each execution knowledge value.
pub(crate) fn execution_guidance_chirho(
    knowledge_chirho: DagExecutionKnowledgeChirho,
) -> &'static str {
    match knowledge_chirho {
        DagExecutionKnowledgeChirho::DefinitelyNotExecutedChirho => {
            "Its DAG effects did not run, though the request itself may have been recorded. Check the state of anything you were changing before you act again."
        }
        DagExecutionKnowledgeChirho::MayHaveExecutedChirho => {
            "Some of its DAG effects may have run. Check the state of anything you were changing; do not retry automatically or send it under a new key."
        }
        DagExecutionKnowledgeChirho::PriorAttemptFailedChirho => {
            "An earlier attempt with this key failed, and the key cannot be used again. Check that attempt's state, then use the documented recovery step."
        }
        DagExecutionKnowledgeChirho::UnknownChirho => {
            "Whether its DAG effects ran is unknown. Check the state of anything you were changing; do not retry automatically or send it under a new key."
        }
    }
}

const PRE_RUN_GUIDANCE_CHIRHO: &str =
    "The server could not prepare this request, so its DAG was not started. Records of the request, such as its admission or a use of an access token, may already be kept.";

/// The plain body of an execution refusal, built from its typed fields alone.
pub(crate) fn execution_refusal_plain_body_chirho(
    knowledge_chirho: DagExecutionKnowledgeChirho,
    attempt_chirho: DagExecutionAttemptOrdinalChirho,
) -> String {
    format!(
        "error: {EXECUTION_REFUSED_IDENTITY_CHIRHO}\nknowledge: {}\nattempt: {}\nscope: {DAG_EFFECTS_SCOPE_CHIRHO}\n{}\n",
        knowledge_chirho.as_str_chirho(),
        attempt_chirho.as_str_chirho(),
        execution_guidance_chirho(knowledge_chirho)
    )
}

/// For arms: the knowledge of a plain execution refusal body when the body is exactly one of the 20 fixed
/// bodies, and None for anything else, so no detail can ride along unseen.
#[cfg(test)]
pub(crate) fn fixed_execution_refusal_knowledge_chirho(
    text_chirho: &str,
) -> Option<DagExecutionKnowledgeChirho> {
    use DagExecutionAttemptOrdinalChirho as AttemptChirho;
    use DagExecutionKnowledgeChirho as KnowledgeChirho;
    let knowledge_values_chirho = [
        KnowledgeChirho::DefinitelyNotExecutedChirho,
        KnowledgeChirho::MayHaveExecutedChirho,
        KnowledgeChirho::PriorAttemptFailedChirho,
        KnowledgeChirho::UnknownChirho,
    ];
    let attempt_values_chirho = [
        AttemptChirho::FirstChirho,
        AttemptChirho::ResumeChirho,
        AttemptChirho::CompletedReplayChirho,
        AttemptChirho::FailedReplayChirho,
        AttemptChirho::UnclassifiedChirho,
    ];
    knowledge_values_chirho
        .into_iter()
        .find(|knowledge_chirho| {
            attempt_values_chirho.into_iter().any(|attempt_chirho| {
                text_chirho
                    == execution_refusal_plain_body_chirho(*knowledge_chirho, attempt_chirho)
            })
        })
}

/// The witness line for the server log: typed fields only, never error text.
pub(crate) fn witness_line_chirho(
    site_chirho: &'static str,
    failure_chirho: PublicFailureChirho,
) -> String {
    match failure_chirho {
        PublicFailureChirho::PreRunResourceChirho { os_code_chirho } => format!(
            "{WITNESS_PREFIX_CHIRHO}:site_chirho={site_chirho}:class_chirho=pre-run-resource-chirho:os_code_chirho={os_code_chirho}"
        ),
        PublicFailureChirho::UnavailableChirho { os_code_chirho } => format!(
            "{WITNESS_PREFIX_CHIRHO}:site_chirho={site_chirho}:class_chirho=unavailable-chirho:os_code_chirho={os_code_chirho}"
        ),
        PublicFailureChirho::FixedRefusalChirho {
            status_chirho,
            identity_chirho,
        } => format!(
            "{WITNESS_PREFIX_CHIRHO}:site_chirho={site_chirho}:class_chirho=fixed-refusal-chirho:status_chirho={}:identity_chirho={identity_chirho}",
            status_chirho.as_u16()
        ),
        PublicFailureChirho::ExecutionRefusalChirho(observation_chirho) => format!(
            "{WITNESS_PREFIX_CHIRHO}:site_chirho={site_chirho}:class_chirho=execution-refusal-chirho:identity_chirho={}:knowledge_chirho={}:attempt_chirho={}",
            observation_chirho.identity_chirho().as_str_chirho(),
            observation_chirho.execution_knowledge_chirho().as_str_chirho(),
            observation_chirho.attempt_ordinal_chirho().as_str_chirho()
        ),
    }
}

/// The public answer for one failure: logs the witness, then answers JSON when the route declares it
/// or the request's Accept names it, and plain text with guidance otherwise. Status and content type
/// agree, and no Retry-After is sent, since no answer here authorizes a retry.
pub(crate) fn public_error_response_chirho(
    site_chirho: &'static str,
    failure_chirho: PublicFailureChirho,
    headers_chirho: &HeaderMap,
    declared_content_type_chirho: Option<&str>,
) -> Response {
    eprintln!("{}", witness_line_chirho(site_chirho, failure_chirho));
    let json_chirho = declared_content_type_chirho.is_some_and(super::media_type_is_json_chirho)
        || super::accept_names_json_chirho(headers_chirho);
    let (status_chirho, plain_chirho, json_body_chirho) = match failure_chirho {
        PublicFailureChirho::PreRunResourceChirho { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("error: {PRE_RUN_UNAVAILABLE_IDENTITY_CHIRHO}\n{PRE_RUN_GUIDANCE_CHIRHO}\n"),
            serde_json::json!({
                "ok_chirho": false,
                "error_chirho": PRE_RUN_UNAVAILABLE_IDENTITY_CHIRHO,
                "boundary_chirho": "pre-run-chirho",
            }),
        ),
        PublicFailureChirho::UnavailableChirho { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("error: {UNAVAILABLE_IDENTITY_CHIRHO}\n{UNAVAILABLE_GUIDANCE_CHIRHO}\n"),
            serde_json::json!({ "ok_chirho": false, "error_chirho": UNAVAILABLE_IDENTITY_CHIRHO }),
        ),
        PublicFailureChirho::FixedRefusalChirho {
            status_chirho,
            identity_chirho,
        } => (
            status_chirho,
            format!("error: {identity_chirho}\n"),
            serde_json::json!({ "ok_chirho": false, "error_chirho": identity_chirho }),
        ),
        PublicFailureChirho::ExecutionRefusalChirho(observation_chirho) => {
            let knowledge_chirho = observation_chirho.execution_knowledge_chirho();
            let attempt_chirho = observation_chirho.attempt_ordinal_chirho();
            (
                StatusCode::BAD_REQUEST,
                execution_refusal_plain_body_chirho(knowledge_chirho, attempt_chirho),
                serde_json::json!({
                    "ok_chirho": false,
                    "error_chirho": EXECUTION_REFUSED_IDENTITY_CHIRHO,
                    "knowledge_chirho": knowledge_chirho.as_str_chirho(),
                    "attempt_chirho": attempt_chirho.as_str_chirho(),
                    "scope_chirho": DAG_EFFECTS_SCOPE_CHIRHO,
                }),
            )
        }
    };
    if json_chirho {
        (
            status_chirho,
            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            json_body_chirho.to_string(),
        )
            .into_response()
    } else {
        (
            status_chirho,
            [(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            plain_chirho,
        )
            .into_response()
    }
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "hold_points_chirho.rs"]
pub(crate) mod hold_points_chirho;
