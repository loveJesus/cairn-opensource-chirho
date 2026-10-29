// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Request resource-gate selection for served app routes.

use super::{
    ResourceGateSelectionChirho, REQUEST_RESOURCE_ACTION_CHIRHO, REQUEST_RESOURCE_SECTION_CHIRHO,
};
use anyhow::Result;
use cairn_chirho::model_chirho::{RefsChirho, RequestContextChirho};
use cairn_chirho::{app_chirho, resource_chirho};

/// The gate's refusal of a request to a resource-gated app that carries no scoped app bearer token,
/// typed so its public answer can name it (public-error-bodies-chirho).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScopedBearerRequiredChirho;

impl std::fmt::Display for ScopedBearerRequiredChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("resource-gated app request requires a scoped app bearer token")
    }
}

impl std::error::Error for ScopedBearerRequiredChirho {}

fn default_app_selection_chirho(
    root_chirho: &std::path::Path,
    refs_chirho: &RefsChirho,
    app_name_chirho: &str,
) -> Result<ResourceGateSelectionChirho> {
    let resolved_chirho =
        app_chirho::resolve_app_dag_chirho(root_chirho, refs_chirho, app_name_chirho)?;
    let request_body_policy_chirho = app_chirho::app_root_request_body_policy_chirho(
        root_chirho,
        app_name_chirho,
        &resolved_chirho.owner_principal_chirho,
    )?;
    Ok(ResourceGateSelectionChirho {
        dag_chirho: resolved_chirho.dag_chirho,
        route_chirho: None,
        discard_request_body_chirho: false,
        request_body_policy_chirho,
        unreviewed_dev_chirho: resolved_chirho.unreviewed_dev_chirho,
    })
}

fn app_request_resource_gate_anonymous_allowed_chirho(
    root_chirho: &std::path::Path,
    app_name_chirho: &str,
) -> Result<Option<bool>> {
    let Some((_policy_hash_chirho, policy_chirho)) =
        resource_chirho::current_resource_policy_chirho(root_chirho, app_name_chirho)?
    else {
        return Ok(None);
    };
    Ok(policy_chirho
        .actions_chirho
        .iter()
        .find(|action_chirho| {
            action_chirho.section_chirho == REQUEST_RESOURCE_SECTION_CHIRHO
                && action_chirho.action_chirho == REQUEST_RESOURCE_ACTION_CHIRHO
                && action_chirho.effect_chirho.is_none()
        })
        .map(|action_chirho| action_chirho.allow_anonymous_chirho))
}

fn anonymous_request_resource_user_chirho(app_name_chirho: &str) -> String {
    format!("anon/app/{app_name_chirho}")
}

/// Select an app root only when doing so cannot enter request-usage accounting.
///
/// Elected SSR reads use this path because Gate1 usage writers still require the local-era writer
/// fence. `None` means a request resource gate is active and the caller must retain its fixed
/// unconverted refusal rather than bypassing the policy or attempting a local append.
pub(super) fn select_app_dag_without_resource_usage_chirho(
    root_chirho: &std::path::Path,
    refs_chirho: &RefsChirho,
    app_name_chirho: &str,
) -> Result<Option<ResourceGateSelectionChirho>> {
    if app_request_resource_gate_anonymous_allowed_chirho(root_chirho, app_name_chirho)?.is_some() {
        return Ok(None);
    }
    Ok(Some(default_app_selection_chirho(
        root_chirho,
        refs_chirho,
        app_name_chirho,
    )?))
}

pub(super) fn select_app_dag_with_resource_gate_chirho(
    root_chirho: &std::path::Path,
    refs_chirho: &RefsChirho,
    app_name_chirho: &str,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<ResourceGateSelectionChirho> {
    let Some(allow_anonymous_chirho) =
        app_request_resource_gate_anonymous_allowed_chirho(root_chirho, app_name_chirho)?
    else {
        return default_app_selection_chirho(root_chirho, refs_chirho, app_name_chirho);
    };
    let (resource_user_chirho, owner_principal_chirho) = resource_gate_actor_chirho(
        root_chirho,
        app_name_chirho,
        request_context_chirho,
        allow_anonymous_chirho,
    )?;
    let default_selection_chirho =
        default_app_selection_chirho(root_chirho, refs_chirho, app_name_chirho)?;
    let usage_chirho =
        record_request_resource_usage_chirho(root_chirho, app_name_chirho, resource_user_chirho)?;
    let (dag_chirho, routed_chirho) = match &usage_chirho.decision_chirho {
        resource_chirho::ResourceDecisionChirho::AllowedChirho => {
            return Ok(default_selection_chirho);
        }
        resource_chirho::ResourceDecisionChirho::RoutedChirho {
            route_chirho,
            forward_request_body_chirho,
            ..
        } => (
            app_chirho::resolve_app_route_chirho(
                root_chirho,
                refs_chirho,
                app_name_chirho,
                route_chirho,
                &owner_principal_chirho,
            )?,
            Some((route_chirho.clone(), *forward_request_body_chirho)),
        ),
    };
    let (route_chirho, forward_request_body_chirho) = routed_chirho
        .ok_or_else(|| anyhow::anyhow!("resource-routed app request missing fallback route"))?;
    let unreviewed_dev_chirho = app_chirho::app_route_unreviewed_dev_chirho(
        root_chirho,
        app_name_chirho,
        &route_chirho,
        &owner_principal_chirho,
        &dag_chirho,
    )?;
    let request_body_policy_chirho = app_chirho::verified_app_route_request_body_policy_chirho(
        root_chirho,
        app_name_chirho,
        &route_chirho,
        &owner_principal_chirho,
        &dag_chirho,
    )?;
    Ok(ResourceGateSelectionChirho {
        dag_chirho,
        route_chirho: Some(route_chirho),
        discard_request_body_chirho: !forward_request_body_chirho,
        request_body_policy_chirho,
        unreviewed_dev_chirho,
    })
}

pub(super) fn select_app_route_dag_without_resource_usage_chirho(
    root_chirho: &std::path::Path,
    refs_chirho: &RefsChirho,
    app_name_chirho: &str,
    route_chirho: &str,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Option<ResourceGateSelectionChirho>> {
    if app_request_resource_gate_anonymous_allowed_chirho(root_chirho, app_name_chirho)?.is_some() {
        return Ok(None);
    }
    default_app_route_selection_chirho(
        root_chirho,
        refs_chirho,
        app_name_chirho,
        route_chirho,
        request_context_chirho,
    )
    .map(Some)
}

fn default_app_route_selection_chirho(
    root_chirho: &std::path::Path,
    refs_chirho: &RefsChirho,
    app_name_chirho: &str,
    route_chirho: &str,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<ResourceGateSelectionChirho> {
    let owner_principal_chirho = match request_context_chirho {
        Some(context_chirho) => context_chirho.owner_principal_chirho.clone(),
        None => app_chirho::verified_app_owner_chirho(root_chirho, app_name_chirho)?
            .ok_or_else(|| anyhow::anyhow!("app '{app_name_chirho}' has no signed owner record"))?,
    };
    let dag_chirho = app_chirho::resolve_app_route_chirho(
        root_chirho,
        refs_chirho,
        app_name_chirho,
        route_chirho,
        &owner_principal_chirho,
    )?;
    let unreviewed_dev_chirho = app_chirho::app_route_unreviewed_dev_chirho(
        root_chirho,
        app_name_chirho,
        route_chirho,
        &owner_principal_chirho,
        &dag_chirho,
    )?;
    let request_body_policy_chirho = app_chirho::verified_app_route_request_body_policy_chirho(
        root_chirho,
        app_name_chirho,
        route_chirho,
        &owner_principal_chirho,
        &dag_chirho,
    )?;
    Ok(ResourceGateSelectionChirho {
        dag_chirho,
        route_chirho: Some(route_chirho.to_string()),
        discard_request_body_chirho: false,
        request_body_policy_chirho,
        unreviewed_dev_chirho,
    })
}

pub(super) fn select_app_route_dag_direct_chirho(
    root_chirho: &std::path::Path,
    refs_chirho: &RefsChirho,
    app_name_chirho: &str,
    route_chirho: &str,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<ResourceGateSelectionChirho> {
    let Some(allow_anonymous_chirho) =
        app_request_resource_gate_anonymous_allowed_chirho(root_chirho, app_name_chirho)?
    else {
        return default_app_route_selection_chirho(
            root_chirho,
            refs_chirho,
            app_name_chirho,
            route_chirho,
            request_context_chirho,
        );
    };
    let (resource_user_chirho, owner_principal_chirho) = resource_gate_actor_chirho(
        root_chirho,
        app_name_chirho,
        request_context_chirho,
        allow_anonymous_chirho,
    )?;
    let requested_dag_chirho = app_chirho::resolve_app_route_chirho(
        root_chirho,
        refs_chirho,
        app_name_chirho,
        route_chirho,
        &owner_principal_chirho,
    )?;
    let usage_chirho =
        record_request_resource_usage_chirho(root_chirho, app_name_chirho, resource_user_chirho)?;
    let (dag_chirho, route_chirho, discard_request_body_chirho, unreviewed_dev_chirho) =
        match &usage_chirho.decision_chirho {
            resource_chirho::ResourceDecisionChirho::AllowedChirho => {
                let unreviewed_dev_chirho = app_chirho::app_route_unreviewed_dev_chirho(
                    root_chirho,
                    app_name_chirho,
                    route_chirho,
                    &owner_principal_chirho,
                    &requested_dag_chirho,
                )?;
                (
                    requested_dag_chirho,
                    route_chirho.to_string(),
                    false,
                    unreviewed_dev_chirho,
                )
            }
            resource_chirho::ResourceDecisionChirho::RoutedChirho {
                route_chirho,
                forward_request_body_chirho,
                ..
            } => {
                let dag_chirho = app_chirho::resolve_app_route_chirho(
                    root_chirho,
                    refs_chirho,
                    app_name_chirho,
                    route_chirho,
                    &owner_principal_chirho,
                )?;
                let unreviewed_dev_chirho = app_chirho::app_route_unreviewed_dev_chirho(
                    root_chirho,
                    app_name_chirho,
                    route_chirho,
                    &owner_principal_chirho,
                    &dag_chirho,
                )?;
                (
                    dag_chirho,
                    route_chirho.clone(),
                    !forward_request_body_chirho,
                    unreviewed_dev_chirho,
                )
            }
        };
    let request_body_policy_chirho = app_chirho::verified_app_route_request_body_policy_chirho(
        root_chirho,
        app_name_chirho,
        &route_chirho,
        &owner_principal_chirho,
        &dag_chirho,
    )?;
    Ok(ResourceGateSelectionChirho {
        dag_chirho,
        route_chirho: Some(route_chirho),
        discard_request_body_chirho,
        request_body_policy_chirho,
        unreviewed_dev_chirho,
    })
}

fn resource_gate_actor_chirho(
    root_chirho: &std::path::Path,
    app_name_chirho: &str,
    request_context_chirho: Option<&RequestContextChirho>,
    allow_anonymous_chirho: bool,
) -> Result<(String, String)> {
    match request_context_chirho {
        Some(context_chirho) => {
            if context_chirho.app_chirho != app_name_chirho {
                anyhow::bail!(
                    "resource gate app '{}' does not match request context app '{}'",
                    app_name_chirho,
                    context_chirho.app_chirho
                );
            }
            Ok((
                context_chirho.user_principal_chirho.clone(),
                context_chirho.owner_principal_chirho.clone(),
            ))
        }
        None if allow_anonymous_chirho => Ok((
            anonymous_request_resource_user_chirho(app_name_chirho),
            app_chirho::verified_app_owner_chirho(root_chirho, app_name_chirho)?.ok_or_else(
                || anyhow::anyhow!("app '{app_name_chirho}' has no signed owner record"),
            )?,
        )),
        None => Err(ScopedBearerRequiredChirho.into()),
    }
}

fn record_request_resource_usage_chirho(
    root_chirho: &std::path::Path,
    app_name_chirho: &str,
    resource_user_chirho: String,
) -> Result<resource_chirho::ResourceUsageRecordChirho> {
    resource_chirho::record_resource_usage_chirho(
        root_chirho,
        resource_chirho::ResourceUsageInputChirho {
            app_chirho: app_name_chirho.to_string(),
            user_chirho: resource_user_chirho,
            actor_chirho: None,
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            run_chirho: None,
            bridges_chirho: Vec::new(),
        },
    )
}
