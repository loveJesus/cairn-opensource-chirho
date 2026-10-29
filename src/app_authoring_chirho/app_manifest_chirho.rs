// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Deploys an app from one manifest by orchestrating existing app, route, and package primitives.

use crate::model_chirho::{CapabilityChirho, HashChirho};
use crate::{
    app_chirho, app_source_manifest_chirho, dag_module_chirho, runtime_profile_chirho, store_chirho,
};
use anyhow::{bail, Result};
use cairn_capability_chirho::capability_key_grant_chirho::OWN_KEYS_CAPABILITY_PREFIX_CHIRHO;
use cairn_model_app_chirho::{AppRouteKeyAccessChirho, AppSourceUndoPlanBindingChirho};
use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionAuthorityPortChirho;
use std::collections::BTreeSet;
use std::path::Path;

#[path = "app_manifest_chirho/key_access_deploy_chirho.rs"]
mod key_access_deploy_chirho;
#[cfg(test)]
#[path = "app_manifest_chirho/own_keys_deploy_tests_chirho.rs"]
mod own_keys_deploy_tests_chirho;
// The race fixtures drive the opt-in's locked section on its own.
#[cfg(test)]
pub(crate) use key_access_deploy_chirho::open_app_to_limited_keys_chirho;
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub use key_access_deploy_chirho::set_opt_in_hold_chirho;
use key_access_deploy_chirho::{record_app_key_authority_chirho, validate_route_key_access_chirho};

pub use cairn_model_app_chirho::{
    validate_app_deploy_manifest_report_schema_chirho, AppDeployDagSourceChirho,
    AppDeployManifestChirho, AppDeployManifestReportChirho, AppDeployParamsManifestChirho,
    AppDeployRouteManifestChirho, AppDeployRouteReportChirho,
    AppDeployRuntimePackageManifestChirho, AppDeployRuntimePackageReportChirho,
    AppRequestAccessPolicyChirho, AppRouteRequestBodyPolicyChirho,
    APP_DEPLOY_MANIFEST_REPORT_SCHEMA_CHIRHO, APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedAppDeployManifestChirho {
    root_dag_chirho: Option<HashChirho>,
    request_access_policy_chirho: Option<AppRequestAccessPolicyChirho>,
    root_input_mode_chirho: Option<app_chirho::AppInputModeChirho>,
    root_request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    root_response_content_type_chirho: Option<String>,
    root_params_chirho: Option<AppDeployParamsManifestChirho>,
    routes_chirho: Vec<ValidatedAppDeployRouteChirho>,
    runtime_packages_chirho: Vec<ValidatedRuntimePackageChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedAppDeployRouteChirho {
    route_chirho: String,
    dag_chirho: HashChirho,
    input_mode_chirho: Option<app_chirho::AppInputModeChirho>,
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    key_access_chirho: Option<AppRouteKeyAccessChirho>,
    response_content_type_chirho: Option<String>,
    params_chirho: Option<AppDeployParamsManifestChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedRuntimePackageChirho {
    module_chirho: HashChirho,
    profile_chirho: runtime_profile_chirho::RuntimeProfileKindChirho,
}

pub fn deploy_app_manifest_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
) -> Result<AppDeployManifestReportChirho> {
    deploy_app_manifest_with_review_label_chirho(root_chirho, manifest_chirho, false, None, None)
}

pub fn deploy_app_manifest_unreviewed_dev_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
) -> Result<AppDeployManifestReportChirho> {
    deploy_app_manifest_with_review_label_chirho(root_chirho, manifest_chirho, true, None, None)
}

pub fn validate_app_deploy_manifest_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
) -> Result<()> {
    validate_manifest_for_descriptor_v2_deployment_chirho(root_chirho, manifest_chirho, None)
        .map(|_| ())
}

pub(crate) fn validate_app_deploy_manifest_with_descriptor_v2_bindings_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
    bindings_chirho: &[AppSourceUndoPlanBindingChirho],
) -> Result<()> {
    validate_manifest_for_descriptor_v2_deployment_chirho(
        root_chirho,
        manifest_chirho,
        Some(bindings_chirho),
    )
    .map(|_| ())
}

pub(crate) fn deploy_app_manifest_with_descriptor_v2_bindings_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
    bindings_chirho: &[AppSourceUndoPlanBindingChirho],
    unreviewed_dev_chirho: bool,
) -> Result<AppDeployManifestReportChirho> {
    deploy_app_manifest_with_review_label_chirho(
        root_chirho,
        manifest_chirho,
        unreviewed_dev_chirho,
        Some(bindings_chirho),
        None,
    )
}

pub(crate) fn deploy_app_manifest_with_descriptor_v2_bindings_and_head_transition_authority_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
    bindings_chirho: &[AppSourceUndoPlanBindingChirho],
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<AppDeployManifestReportChirho> {
    deploy_app_manifest_with_review_label_chirho(
        root_chirho,
        manifest_chirho,
        false,
        Some(bindings_chirho),
        Some(authority_chirho),
    )
}

fn deploy_app_manifest_with_review_label_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
    unreviewed_dev_chirho: bool,
    bindings_chirho: Option<&[AppSourceUndoPlanBindingChirho]>,
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
) -> Result<AppDeployManifestReportChirho> {
    if unreviewed_dev_chirho && authority_chirho.is_some() {
        bail!("unreviewed app deployment cannot consume elected head-transition authority");
    }
    let validated_chirho = validate_manifest_for_descriptor_v2_deployment_chirho(
        root_chirho,
        manifest_chirho,
        bindings_chirho,
    )?;

    let mut runtime_packages_chirho = Vec::new();
    for package_chirho in &validated_chirho.runtime_packages_chirho {
        let (runtime_package_chirho, package_hash_chirho) =
            runtime_profile_chirho::build_runtime_package_chirho(
                root_chirho,
                &package_chirho.module_chirho,
                package_chirho.profile_chirho,
            )?;
        runtime_packages_chirho.push(AppDeployRuntimePackageReportChirho {
            module_chirho: package_chirho.module_chirho.clone(),
            profile_chirho: package_chirho.profile_chirho,
            package_chirho: package_hash_chirho,
            executable_chirho: runtime_package_chirho.executable_chirho,
        });
    }

    if let Some(policy_chirho) = &validated_chirho.request_access_policy_chirho {
        let policy_root_dag_chirho = match &validated_chirho.root_dag_chirho {
            Some(root_dag_chirho) => root_dag_chirho.clone(),
            None => app_chirho::app_status_chirho(root_chirho, &manifest_chirho.app_chirho)?
                .dag_chirho
                .ok_or_else(|| anyhow::anyhow!("request access policy needs an active app root"))?,
        };
        app_chirho::set_app_request_access_policy_chirho(
            root_chirho,
            &manifest_chirho.app_chirho,
            &manifest_chirho.owner_chirho,
            policy_root_dag_chirho,
            policy_chirho.clone(),
        )?;
    }

    if let Some(dag_chirho) = &validated_chirho.root_dag_chirho {
        if unreviewed_dev_chirho {
            app_chirho::deploy_app_unreviewed_dev_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                dag_chirho.clone(),
                &manifest_chirho.owner_chirho,
            )?;
        } else if let Some(authority_chirho) = authority_chirho {
            app_chirho::deploy_app_with_head_transition_authority_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                dag_chirho.clone(),
                &manifest_chirho.owner_chirho,
                authority_chirho,
            )?;
        } else {
            app_chirho::deploy_app_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                dag_chirho.clone(),
                &manifest_chirho.owner_chirho,
            )?;
        }
    }
    if let Some(mode_chirho) = &validated_chirho.root_input_mode_chirho {
        if let Some(request_body_policy_chirho) = &validated_chirho.root_request_body_policy_chirho
        {
            app_chirho::set_app_root_input_policy_with_request_body_policy_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                &manifest_chirho.owner_chirho,
                mode_chirho.clone(),
                request_body_policy_chirho.clone(),
            )?;
        } else {
            app_chirho::set_app_input_policy_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                None,
                &manifest_chirho.owner_chirho,
                mode_chirho.clone(),
            )?;
        }
    }
    if let Some(response_content_type_chirho) = &validated_chirho.root_response_content_type_chirho
    {
        app_chirho::set_app_response_policy_chirho(
            root_chirho,
            &manifest_chirho.app_chirho,
            &manifest_chirho.owner_chirho,
            response_content_type_chirho,
        )?;
    }
    if let Some(params_chirho) = &validated_chirho.root_params_chirho {
        app_chirho::set_app_params_hash_chirho(
            root_chirho,
            &manifest_chirho.app_chirho,
            None,
            &manifest_chirho.owner_chirho,
            params_chirho.hash_chirho.clone(),
            params_chirho.required_chirho,
        )?;
    }

    for route_chirho in &validated_chirho.routes_chirho {
        if let Some(authority_chirho) = authority_chirho {
            app_chirho::deploy_app_route_with_request_body_policy_and_head_transition_authority_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                &route_chirho.route_chirho,
                route_chirho.dag_chirho.clone(),
                &manifest_chirho.owner_chirho,
                route_chirho.request_body_policy_chirho.clone(),
                authority_chirho,
            )?;
        } else {
            app_chirho::deploy_app_route_with_request_body_policy_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                &route_chirho.route_chirho,
                route_chirho.dag_chirho.clone(),
                &manifest_chirho.owner_chirho,
                route_chirho.request_body_policy_chirho.clone(),
                unreviewed_dev_chirho,
            )?;
        }
        if let Some(mode_chirho) = &route_chirho.input_mode_chirho {
            app_chirho::set_app_input_policy_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                Some(&route_chirho.route_chirho),
                &manifest_chirho.owner_chirho,
                mode_chirho.clone(),
            )?;
        }
        if let Some(response_content_type_chirho) = &route_chirho.response_content_type_chirho {
            app_chirho::set_app_route_response_policy_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                &route_chirho.route_chirho,
                &manifest_chirho.owner_chirho,
                response_content_type_chirho,
            )?;
        }
        if let Some(params_chirho) = &route_chirho.params_chirho {
            app_chirho::set_app_params_hash_chirho(
                root_chirho,
                &manifest_chirho.app_chirho,
                Some(&route_chirho.route_chirho),
                &manifest_chirho.owner_chirho,
                params_chirho.hash_chirho.clone(),
                params_chirho.required_chirho,
            )?;
        }
    }
    record_app_key_authority_chirho(
        root_chirho,
        manifest_chirho,
        &validated_chirho.routes_chirho,
    )?;

    Ok(AppDeployManifestReportChirho {
        schema_chirho: APP_DEPLOY_MANIFEST_REPORT_SCHEMA_CHIRHO.to_string(),
        app_chirho: manifest_chirho.app_chirho.clone(),
        owner_chirho: manifest_chirho.owner_chirho.clone(),
        request_access_policy_chirho: validated_chirho.request_access_policy_chirho,
        root_dag_chirho: validated_chirho.root_dag_chirho,
        request_body_policy_chirho: validated_chirho.root_request_body_policy_chirho,
        response_content_type_chirho: validated_chirho.root_response_content_type_chirho,
        routes_chirho: validated_chirho
            .routes_chirho
            .into_iter()
            .map(|route_chirho| AppDeployRouteReportChirho {
                route_chirho: route_chirho.route_chirho,
                dag_chirho: route_chirho.dag_chirho,
                request_body_policy_chirho: route_chirho.request_body_policy_chirho,
                key_access_chirho: route_chirho.key_access_chirho,
                response_content_type_chirho: route_chirho.response_content_type_chirho,
            })
            .collect(),
        runtime_packages_chirho,
    })
}

fn validate_manifest_for_descriptor_v2_deployment_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
    bindings_chirho: Option<&[AppSourceUndoPlanBindingChirho]>,
) -> Result<ValidatedAppDeployManifestChirho> {
    let validated_chirho = validate_manifest_chirho(root_chirho, manifest_chirho)?;
    let mut executable_dags_chirho = BTreeSet::new();
    if let Some(root_dag_chirho) = &validated_chirho.root_dag_chirho {
        executable_dags_chirho.insert(root_dag_chirho.clone());
    }
    executable_dags_chirho.extend(
        validated_chirho
            .routes_chirho
            .iter()
            .map(|route_chirho| route_chirho.dag_chirho.clone()),
    );
    app_source_manifest_chirho::verify_descriptor_v2_deployment_chirho(
        root_chirho,
        &executable_dags_chirho,
        bindings_chirho,
    )?;
    Ok(validated_chirho)
}

fn validate_manifest_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
) -> Result<ValidatedAppDeployManifestChirho> {
    if manifest_chirho.schema_chirho != APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO {
        bail!(
            "unsupported app deploy manifest schema '{}'",
            manifest_chirho.schema_chirho
        );
    }
    if manifest_chirho.root_chirho.is_none()
        && manifest_chirho.input_mode_chirho.is_none()
        && manifest_chirho.request_access_policy_chirho.is_none()
        && manifest_chirho.request_body_policy_chirho.is_none()
        && manifest_chirho.response_content_type_chirho.is_none()
        && manifest_chirho.params_chirho.is_none()
        && manifest_chirho.routes_chirho.is_empty()
        && manifest_chirho.runtime_packages_chirho.is_empty()
    {
        bail!(
            "manifest must deploy an app root, a request access policy, an input mode, a request-body policy, a response policy, a route, or a runtime package"
        );
    }
    if let Some(mode_chirho) = &manifest_chirho.input_mode_chirho {
        app_chirho::validate_app_input_mode_chirho(mode_chirho)?;
    }
    if manifest_chirho.request_body_policy_chirho.is_some()
        && manifest_chirho.input_mode_chirho.is_none()
    {
        bail!("root request-body policy requires an explicit root input mode");
    }
    let root_response_content_type_chirho = manifest_chirho
        .response_content_type_chirho
        .as_deref()
        .map(app_chirho::normalize_app_response_content_type_chirho)
        .transpose()?;
    let root_params_chirho = manifest_chirho
        .params_chirho
        .as_ref()
        .map(|params_chirho| validate_params_manifest_chirho(root_chirho, params_chirho))
        .transpose()?;
    app_chirho::validate_app_name_chirho(&manifest_chirho.app_chirho)?;
    app_chirho::ensure_owner_principal_chirho(root_chirho, &manifest_chirho.owner_chirho)?;
    if let Some(policy_chirho) = &manifest_chirho.request_access_policy_chirho {
        app_chirho::validate_app_request_access_policy_transition_chirho(
            root_chirho,
            &manifest_chirho.app_chirho,
            &manifest_chirho.owner_chirho,
            policy_chirho,
        )?;
    }

    let root_dag_chirho = manifest_chirho
        .root_chirho
        .as_ref()
        .map(|source_chirho| dag_for_source_chirho(root_chirho, source_chirho))
        .transpose()?;

    match app_chirho::verified_app_owner_chirho(root_chirho, &manifest_chirho.app_chirho)? {
        Some(owner_chirho) if owner_chirho != manifest_chirho.owner_chirho => bail!(
            "manifest owner '{}' does not match existing app owner '{}'",
            manifest_chirho.owner_chirho,
            owner_chirho
        ),
        Some(_) => {}
        None if root_dag_chirho.is_some() => {}
        None => bail!(
            "manifest for app '{}' has no root_chirho and the app is not deployed",
            manifest_chirho.app_chirho
        ),
    }
    if let Some(request_body_policy_chirho) = &manifest_chirho.request_body_policy_chirho {
        app_chirho::validate_app_root_request_body_policy_transition_chirho(
            root_chirho,
            &manifest_chirho.app_chirho,
            &manifest_chirho.owner_chirho,
            request_body_policy_chirho,
        )?;
    }

    if root_dag_chirho.is_none() {
        let status_chirho =
            app_chirho::app_status_chirho(root_chirho, &manifest_chirho.app_chirho)?;
        if !status_chirho.active_chirho {
            bail!(
                "manifest for app '{}' has no root_chirho and the app ref is not active",
                manifest_chirho.app_chirho
            );
        }
    }

    let mut seen_routes_chirho = BTreeSet::new();
    let mut routes_chirho = Vec::new();
    for route_chirho in &manifest_chirho.routes_chirho {
        app_chirho::validate_route_name_chirho(&route_chirho.route_chirho)?;
        if !seen_routes_chirho.insert(route_chirho.route_chirho.clone()) {
            bail!("duplicate route_chirho '{}'", route_chirho.route_chirho);
        }
        if let Some(mode_chirho) = &route_chirho.input_mode_chirho {
            app_chirho::validate_app_input_mode_chirho(mode_chirho)?;
        }
        let response_content_type_chirho = route_chirho
            .response_content_type_chirho
            .as_deref()
            .map(app_chirho::normalize_app_route_response_content_type_chirho)
            .transpose()?;
        let params_chirho = route_chirho
            .params_chirho
            .as_ref()
            .map(|params_chirho| validate_params_manifest_chirho(root_chirho, params_chirho))
            .transpose()?;
        let dag_chirho = dag_for_source_chirho(root_chirho, &route_chirho.source_chirho)?;
        let key_access_chirho = route_chirho
            .key_access_chirho
            .as_ref()
            .map(|access_chirho| {
                validate_route_key_access_chirho(
                    root_chirho,
                    &route_chirho.route_chirho,
                    &dag_chirho,
                    access_chirho,
                )
            })
            .transpose()?;
        routes_chirho.push(ValidatedAppDeployRouteChirho {
            route_chirho: route_chirho.route_chirho.clone(),
            dag_chirho,
            input_mode_chirho: route_chirho.input_mode_chirho.clone(),
            request_body_policy_chirho: route_chirho.request_body_policy_chirho.clone(),
            key_access_chirho,
            response_content_type_chirho,
            params_chirho,
        });
    }

    validate_signed_in_capability_access_chirho(
        root_chirho,
        manifest_chirho,
        root_dag_chirho.as_ref(),
        &routes_chirho,
    )?;

    let mut runtime_packages_chirho = Vec::new();
    for package_chirho in &manifest_chirho.runtime_packages_chirho {
        let profile_chirho = runtime_profile_chirho::parse_runtime_profile_kind_chirho(
            &package_chirho.profile_chirho,
        )?;
        dag_module_chirho::validate_stored_dag_module_chirho(
            root_chirho,
            &package_chirho.module_chirho,
        )?;
        runtime_packages_chirho.push(ValidatedRuntimePackageChirho {
            module_chirho: package_chirho.module_chirho.clone(),
            profile_chirho,
        });
    }

    Ok(ValidatedAppDeployManifestChirho {
        root_dag_chirho,
        request_access_policy_chirho: manifest_chirho.request_access_policy_chirho.clone(),
        root_input_mode_chirho: manifest_chirho.input_mode_chirho.clone(),
        root_request_body_policy_chirho: manifest_chirho.request_body_policy_chirho.clone(),
        root_response_content_type_chirho,
        root_params_chirho,
        routes_chirho,
        runtime_packages_chirho,
    })
}

/// Enforces, before any ref moves, the app-wide admission side of the two capabilities only a signed-in viewer's
/// request may use: viewer state, and the owner's keys (K3). Either needs an app-wide AuthenticatedChirho policy, each
/// scope must be its exact prefix, and the owner's keys are read only.
fn validate_signed_in_capability_access_chirho(
    root_chirho: &Path,
    manifest_chirho: &AppDeployManifestChirho,
    root_dag_chirho: Option<&HashChirho>,
    routes_chirho: &[ValidatedAppDeployRouteChirho],
) -> Result<()> {
    let viewer_state_prefix_chirho = crate::effect_chirho::viewer_state_capability_prefix_chirho();
    let own_keys_prefix_chirho = OWN_KEYS_CAPABILITY_PREFIX_CHIRHO;
    let executable_dags_chirho = root_dag_chirho.into_iter().chain(
        routes_chirho
            .iter()
            .map(|route_chirho| &route_chirho.dag_chirho),
    );
    let mut has_viewer_state_capability_chirho = false;
    let mut has_own_keys_capability_chirho = false;

    for dag_chirho in executable_dags_chirho {
        for capability_chirho in crate::dag_capability_scan_chirho::collect_dag_capabilities_chirho(
            root_chirho,
            dag_chirho,
        )? {
            match capability_chirho {
                CapabilityChirho::ReadStoreChirho { prefix_chirho }
                | CapabilityChirho::WriteStoreChirho { prefix_chirho }
                    if prefix_chirho.starts_with(viewer_state_prefix_chirho) =>
                {
                    if prefix_chirho != viewer_state_prefix_chirho {
                        bail!(
                            "viewer-state capability scope must be exactly '{viewer_state_prefix_chirho}', not '{prefix_chirho}'"
                        );
                    }
                    has_viewer_state_capability_chirho = true;
                }
                CapabilityChirho::WriteStoreChirho { prefix_chirho }
                    if prefix_chirho.starts_with(own_keys_prefix_chirho) =>
                {
                    bail!("the owner's keys are read only: no route may hold write-store:{prefix_chirho}");
                }
                CapabilityChirho::ReadStoreChirho { prefix_chirho }
                    if prefix_chirho.starts_with(own_keys_prefix_chirho) =>
                {
                    if prefix_chirho != own_keys_prefix_chirho {
                        bail!(
                            "own-keys capability scope must be exactly '{own_keys_prefix_chirho}', not '{prefix_chirho}'"
                        );
                    }
                    has_own_keys_capability_chirho = true;
                }
                _ => {}
            }
        }
    }

    if !has_viewer_state_capability_chirho && !has_own_keys_capability_chirho {
        return Ok(());
    }

    let effective_policy_chirho = match &manifest_chirho.request_access_policy_chirho {
        Some(policy_chirho) => policy_chirho.clone(),
        None => {
            let status_chirho =
                app_chirho::app_status_chirho(root_chirho, &manifest_chirho.app_chirho)?;
            if status_chirho.active_chirho {
                app_chirho::app_request_access_policy_chirho(
                    root_chirho,
                    &manifest_chirho.app_chirho,
                )?
            } else {
                AppRequestAccessPolicyChirho::PublicChirho
            }
        }
    };
    if !matches!(
        effective_policy_chirho,
        AppRequestAccessPolicyChirho::AuthenticatedChirho
    ) {
        if has_viewer_state_capability_chirho {
            bail!(
                "viewer-state capabilities require app-wide AuthenticatedChirho request access policy"
            );
        }
        bail!("own-keys capabilities require app-wide AuthenticatedChirho request access policy");
    }
    Ok(())
}

fn dag_for_source_chirho(
    root_chirho: &Path,
    source_chirho: &AppDeployDagSourceChirho,
) -> Result<HashChirho> {
    match source_chirho {
        AppDeployDagSourceChirho::DagChirho { hash_chirho } => {
            let _dag_chirho: crate::model_chirho::DagChirho =
                store_chirho::get_object_chirho(root_chirho, hash_chirho)?;
            Ok(hash_chirho.clone())
        }
        AppDeployDagSourceChirho::ModuleChirho { hash_chirho } => {
            let module_chirho =
                dag_module_chirho::validate_stored_dag_module_chirho(root_chirho, hash_chirho)?;
            Ok(module_chirho.dag_chirho)
        }
        AppDeployDagSourceChirho::CompositionChirho { hash_chirho } => {
            let composition_chirho =
                dag_module_chirho::validate_stored_dag_module_composition_chirho(
                    root_chirho,
                    hash_chirho,
                )?;
            Ok(composition_chirho.composed_dag_chirho)
        }
    }
}

fn validate_params_manifest_chirho(
    root_chirho: &Path,
    params_chirho: &AppDeployParamsManifestChirho,
) -> Result<AppDeployParamsManifestChirho> {
    let _value_chirho: serde_json::Value =
        store_chirho::get_object_chirho(root_chirho, &params_chirho.hash_chirho)?;
    Ok(params_chirho.clone())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::model_chirho::{CapabilityChirho, DagChirho, NodeDefChirho, PortChirho};
    use crate::{cas_chirho, identity_chirho, refs_chirho};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-app-manifest-test-{nanos_chirho}-{n_chirho}"))
    }

    fn build_single_node_module_chirho(root_chirho: &Path) -> Result<(HashChirho, HashChirho)> {
        let impl_hash_chirho = cas_chirho::add_chirho(
            root_chirho,
            include_str!("../../examples-chirho/upcase-chirho.wat").as_bytes(),
        )?;
        let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes")?;
        let node_chirho = NodeDefChirho {
            name_chirho: "upcase_chirho".to_string(),
            impl_wasm_chirho: impl_hash_chirho,
            entry_chirho: "upcase_chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho,
            }],
            capabilities_chirho: vec![],
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        };
        let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho)?;
        let dag_chirho = DagChirho {
            nodes_chirho: vec![node_hash_chirho.clone()],
            edges_chirho: vec![],
        };
        let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_chirho)?;
        let (_module_chirho, module_hash_chirho) = dag_module_chirho::build_dag_module_chirho(
            root_chirho,
            dag_module_chirho::DagModuleBuildInputChirho {
                name_chirho: "contact_chirho".to_string(),
                dag_chirho: dag_hash_chirho.clone(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![dag_module_chirho::DagModuleBindingInputChirho {
                    public_name_chirho: "input_chirho".to_string(),
                    node_chirho: node_hash_chirho.clone(),
                    node_port_chirho: "in".to_string(),
                }],
                output_bindings_chirho: vec![dag_module_chirho::DagModuleBindingInputChirho {
                    public_name_chirho: "output_chirho".to_string(),
                    node_chirho: node_hash_chirho,
                    node_port_chirho: "out".to_string(),
                }],
                route_labels_chirho: vec!["contact-chirho".to_string()],
                metadata_chirho: BTreeMap::new(),
            },
        )?;
        Ok((dag_hash_chirho, module_hash_chirho))
    }

    fn build_capability_dag_chirho(
        root_chirho: &Path,
        name_chirho: &str,
        capability_chirho: CapabilityChirho,
    ) -> HashChirho {
        let node_chirho = NodeDefChirho {
            name_chirho: name_chirho.to_string(),
            capabilities_chirho: vec![capability_chirho],
            ..Default::default()
        };
        let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
        store_chirho::put_object_chirho(
            root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_hash_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap()
    }

    fn build_effectful_legacy_dag_chirho(root_chirho: &Path) -> HashChirho {
        build_capability_dag_chirho(
            root_chirho,
            "legacy-write-chirho",
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "apps/legacy-chirho".to_string(),
            },
        )
    }

    #[test]
    fn viewer_state_manifest_requires_app_wide_authenticated_policy_chirho() {
        let root_chirho = tmp_root_chirho();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let viewer_dag_chirho = build_capability_dag_chirho(
            &root_chirho,
            "viewer-state-read-chirho",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: crate::effect_chirho::viewer_state_capability_prefix_chirho()
                    .to_string(),
            },
        );
        let mut manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "viewer-state-policy-chirho".to_string(),
            owner_chirho,
            root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: viewer_dag_chirho,
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
        };

        let error_chirho = deploy_app_manifest_chirho(&root_chirho, &manifest_chirho)
            .expect_err("an implicit public viewer-state app must be refused");
        assert!(error_chirho
            .to_string()
            .contains("require app-wide AuthenticatedChirho"));

        manifest_chirho.request_access_policy_chirho =
            Some(AppRequestAccessPolicyChirho::PublicChirho);
        let error_chirho = deploy_app_manifest_chirho(&root_chirho, &manifest_chirho)
            .expect_err("an explicit public viewer-state app must be refused");
        assert!(error_chirho
            .to_string()
            .contains("require app-wide AuthenticatedChirho"));
        assert!(!refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .contains_key("app/viewer-state-policy-chirho"));

        manifest_chirho.request_access_policy_chirho =
            Some(AppRequestAccessPolicyChirho::AuthenticatedChirho);
        validate_manifest_chirho(&root_chirho, &manifest_chirho)
            .expect("the authenticated viewer-state composition is valid");

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn viewer_state_route_inherits_an_applied_authenticated_app_policy_chirho() {
        let root_chirho = tmp_root_chirho();
        let (initial_root_dag_chirho, _module_chirho) =
            build_single_node_module_chirho(&root_chirho).unwrap();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let app_name_chirho = "viewer-state-inherited-policy-chirho";
        app_chirho::set_app_request_access_policy_chirho(
            &root_chirho,
            app_name_chirho,
            &owner_chirho,
            initial_root_dag_chirho.clone(),
            AppRequestAccessPolicyChirho::AuthenticatedChirho,
        )
        .unwrap();
        app_chirho::deploy_app_chirho(
            &root_chirho,
            app_name_chirho,
            initial_root_dag_chirho,
            &owner_chirho,
        )
        .unwrap();
        let viewer_route_dag_chirho = build_capability_dag_chirho(
            &root_chirho,
            "viewer-state-inherited-read-chirho",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: crate::effect_chirho::viewer_state_capability_prefix_chirho()
                    .to_string(),
            },
        );
        let manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_name_chirho.to_string(),
            owner_chirho,
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: vec![AppDeployRouteManifestChirho {
                route_chirho: "workspace-chirho".to_string(),
                source_chirho: AppDeployDagSourceChirho::DagChirho {
                    hash_chirho: viewer_route_dag_chirho,
                },
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                params_chirho: None,
                key_access_chirho: None,
            }],
            runtime_packages_chirho: Vec::new(),
        };

        validate_manifest_chirho(&root_chirho, &manifest_chirho).expect(
            "an applied authenticated app policy remains effective for a route-only change",
        );

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn viewer_state_manifest_refuses_nested_reserved_scope_chirho() {
        let root_chirho = tmp_root_chirho();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let dag_chirho = build_capability_dag_chirho(
            &root_chirho,
            "viewer-state-nested-read-chirho",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "viewer-state-chirho/private-chirho/".to_string(),
            },
        );
        let manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: Some(AppRequestAccessPolicyChirho::AuthenticatedChirho),
            request_body_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "viewer-state-nested-scope-chirho".to_string(),
            owner_chirho,
            root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: dag_chirho,
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
        };

        let error_chirho = deploy_app_manifest_chirho(&root_chirho, &manifest_chirho)
            .expect_err("nested viewer-state capability scope must be refused");
        assert!(error_chirho
            .to_string()
            .contains("viewer-state capability scope must be exactly"));
        assert!(!refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .contains_key("app/viewer-state-nested-scope-chirho"));

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn standalone_manifest_refuses_effectful_legacy_dag_before_ref_move_chirho() {
        let root_chirho = tmp_root_chirho();
        let dag_chirho = build_effectful_legacy_dag_chirho(&root_chirho);
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "legacy-effectful-chirho".to_string(),
            owner_chirho,
            root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: dag_chirho,
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
        };

        let error_chirho = deploy_app_manifest_chirho(&root_chirho, &manifest_chirho).unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("requires complete verified undo-plan bindings"));
        assert!(!refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .contains_key("app/legacy-effectful-chirho"));

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn manifest_deploys_app_route_and_runtime_package_chirho() {
        let root_chirho = tmp_root_chirho();
        let (dag_hash_chirho, module_hash_chirho) =
            build_single_node_module_chirho(&root_chirho).unwrap();
        let root_params_value_chirho = serde_json::json!({"business_name_chirho":"Root Bakery"});
        let root_params_hash_chirho =
            store_chirho::put_object_chirho(&root_chirho, &root_params_value_chirho).unwrap();
        let route_params_value_chirho = serde_json::json!({"business_name_chirho":"Route Bakery"});
        let route_params_hash_chirho =
            store_chirho::put_object_chirho(&root_chirho, &route_params_value_chirho).unwrap();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "contact".to_string(),
            owner_chirho: owner_chirho.clone(),
            root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: dag_hash_chirho.clone(),
            }),
            input_mode_chirho: None,
            response_content_type_chirho: Some("text/html".to_string()),
            params_chirho: Some(AppDeployParamsManifestChirho {
                hash_chirho: root_params_hash_chirho,
                required_chirho: true,
            }),
            routes_chirho: vec![AppDeployRouteManifestChirho {
                route_chirho: "api-contact".to_string(),
                source_chirho: AppDeployDagSourceChirho::ModuleChirho {
                    hash_chirho: module_hash_chirho.clone(),
                },
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: Some("text/html".to_string()),
                params_chirho: Some(AppDeployParamsManifestChirho {
                    hash_chirho: route_params_hash_chirho,
                    required_chirho: true,
                }),
                key_access_chirho: None,
            }],
            runtime_packages_chirho: vec![AppDeployRuntimePackageManifestChirho {
                module_chirho: module_hash_chirho.clone(),
                profile_chirho: "server-chirho".to_string(),
            }],
        };

        let report_chirho = deploy_app_manifest_chirho(&root_chirho, &manifest_chirho).unwrap();
        assert_eq!(
            report_chirho.schema_chirho,
            APP_DEPLOY_MANIFEST_REPORT_SCHEMA_CHIRHO
        );
        validate_app_deploy_manifest_report_schema_chirho(&report_chirho).unwrap();
        assert_eq!(
            serde_json::to_value(&report_chirho).unwrap()["schema_chirho"],
            APP_DEPLOY_MANIFEST_REPORT_SCHEMA_CHIRHO
        );
        let mut legacy_report_chirho = report_chirho.clone();
        legacy_report_chirho.schema_chirho.clear();
        validate_app_deploy_manifest_report_schema_chirho(&legacy_report_chirho).unwrap();
        let legacy_report_json_chirho = serde_json::to_string(&legacy_report_chirho).unwrap();
        assert!(!legacy_report_json_chirho.contains("schema_chirho"));
        let legacy_report_roundtrip_chirho: AppDeployManifestReportChirho =
            serde_json::from_str(&legacy_report_json_chirho).unwrap();
        assert!(legacy_report_roundtrip_chirho.schema_chirho.is_empty());
        let mut bad_report_chirho = report_chirho.clone();
        bad_report_chirho.schema_chirho = "app-deploy-manifest-report-v9-chirho".to_string();
        let error_chirho =
            validate_app_deploy_manifest_report_schema_chirho(&bad_report_chirho).unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("unsupported app deploy manifest report schema"));
        assert_eq!(report_chirho.root_dag_chirho, Some(dag_hash_chirho.clone()));
        assert_eq!(
            report_chirho.response_content_type_chirho.as_deref(),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(report_chirho.routes_chirho[0].dag_chirho, dag_hash_chirho);
        assert_eq!(
            report_chirho.routes_chirho[0]
                .response_content_type_chirho
                .as_deref(),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(report_chirho.runtime_packages_chirho.len(), 1);
        runtime_profile_chirho::validate_stored_runtime_package_chirho(
            &root_chirho,
            &report_chirho.runtime_packages_chirho[0].package_chirho,
        )
        .unwrap();

        let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
        assert_eq!(
            refs_chirho.branches_chirho.get("app/contact"),
            report_chirho.root_dag_chirho.as_ref()
        );
        let status_chirho = app_chirho::app_status_chirho(&root_chirho, "contact").unwrap();
        assert_eq!(status_chirho.owner_principal_chirho, Some(owner_chirho));
        assert!(status_chirho.active_chirho);
        assert_eq!(
            app_chirho::app_response_content_type_chirho(
                &root_chirho,
                "contact",
                status_chirho.owner_principal_chirho.as_deref().unwrap()
            )
            .unwrap()
            .as_deref(),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            app_chirho::app_route_response_content_type_chirho(
                &root_chirho,
                "contact",
                "api-contact",
                status_chirho.owner_principal_chirho.as_deref().unwrap()
            )
            .unwrap()
            .as_deref(),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            app_chirho::verify_app_params_chirho(&root_chirho).unwrap(),
            2
        );
        assert_eq!(
            app_chirho::app_params_chirho(
                &root_chirho,
                "contact",
                None,
                status_chirho.owner_principal_chirho.as_deref().unwrap()
            )
            .unwrap()
            .unwrap()
            .value_chirho,
            root_params_value_chirho
        );
        assert_eq!(
            app_chirho::app_params_chirho(
                &root_chirho,
                "contact",
                Some("api-contact"),
                status_chirho.owner_principal_chirho.as_deref().unwrap()
            )
            .unwrap()
            .unwrap()
            .value_chirho,
            route_params_value_chirho
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn root_body_policy_requires_input_mode_before_any_ref_move_chirho() {
        let root_chirho = tmp_root_chirho();
        let (dag_hash_chirho, _module_hash_chirho) =
            build_single_node_module_chirho(&root_chirho).unwrap();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "body-policy-without-mode".to_string(),
            owner_chirho,
            root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: dag_hash_chirho,
            }),
            input_mode_chirho: None,
            request_body_policy_chirho: Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
        };

        let error_chirho = deploy_app_manifest_chirho(&root_chirho, &manifest_chirho)
            .unwrap_err()
            .to_string();
        assert!(
            error_chirho.contains("root request-body policy requires an explicit root input mode")
        );
        assert!(!refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .contains_key("app/body-policy-without-mode"));
        assert!(app_chirho::load_app_records_chirho(&root_chirho)
            .unwrap()
            .is_empty());
        assert!(
            app_chirho::load_app_input_policy_records_chirho(&root_chirho)
                .unwrap()
                .is_empty()
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn root_body_policy_and_input_mode_share_one_signed_row_chirho() {
        let root_chirho = tmp_root_chirho();
        let (dag_hash_chirho, _module_hash_chirho) =
            build_single_node_module_chirho(&root_chirho).unwrap();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "atomic-root-policy".to_string(),
            owner_chirho: owner_chirho.clone(),
            root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: dag_hash_chirho,
            }),
            input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
            request_body_policy_chirho: Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
        };

        let report_chirho = deploy_app_manifest_chirho(&root_chirho, &manifest_chirho).unwrap();
        assert_eq!(
            report_chirho.request_body_policy_chirho,
            Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho)
        );
        let records_chirho =
            app_chirho::load_app_input_policy_records_chirho(&root_chirho).unwrap();
        assert_eq!(records_chirho.len(), 1);
        assert_eq!(
            records_chirho[0].mode_chirho,
            app_chirho::AppInputModeChirho::PlainChirho
        );
        assert_eq!(
            records_chirho[0].request_body_policy_chirho,
            Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho)
        );
        assert_eq!(
            app_chirho::verify_app_input_policies_chirho(&root_chirho).unwrap(),
            1
        );
        assert_eq!(
            app_chirho::app_root_request_body_policy_chirho(
                &root_chirho,
                "atomic-root-policy",
                &owner_chirho,
            )
            .unwrap(),
            Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho)
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn root_body_policy_downgrade_refuses_before_redeploying_app_chirho() {
        let root_chirho = tmp_root_chirho();
        let (first_dag_chirho, _module_hash_chirho) =
            build_single_node_module_chirho(&root_chirho).unwrap();
        let first_dag_value_chirho: DagChirho =
            store_chirho::get_object_chirho(&root_chirho, &first_dag_chirho).unwrap();
        let mut second_node_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(&root_chirho, &first_dag_value_chirho.nodes_chirho[0])
                .unwrap();
        second_node_chirho.name_chirho = "upcase-v2-chirho".to_string();
        let second_node_hash_chirho =
            store_chirho::put_object_chirho(&root_chirho, &second_node_chirho).unwrap();
        let second_dag_chirho = store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: vec![second_node_hash_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap();
        assert_ne!(first_dag_chirho, second_dag_chirho);
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let first_manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "sticky-redeploy".to_string(),
            owner_chirho: owner_chirho.clone(),
            root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: first_dag_chirho.clone(),
            }),
            input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
            request_body_policy_chirho: Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho),
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
        };
        deploy_app_manifest_chirho(&root_chirho, &first_manifest_chirho).unwrap();

        let mut second_manifest_chirho = first_manifest_chirho;
        second_manifest_chirho.root_chirho = Some(AppDeployDagSourceChirho::DagChirho {
            hash_chirho: second_dag_chirho,
        });
        second_manifest_chirho.request_body_policy_chirho =
            Some(AppRouteRequestBodyPolicyChirho::AcceptBodyChirho);
        let error_chirho = deploy_app_manifest_chirho(&root_chirho, &second_manifest_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho
            .contains("cannot downgrade to AcceptBodyChirho after a signed NoBodyChirho policy"));
        assert_eq!(
            refs_chirho::load_refs_chirho(&root_chirho)
                .unwrap()
                .branches_chirho
                .get("app/sticky-redeploy"),
            Some(&first_dag_chirho)
        );
        assert_eq!(
            app_chirho::load_app_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            app_chirho::load_app_input_policy_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            1
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn manifest_without_root_requires_existing_owned_app_chirho() {
        let root_chirho = tmp_root_chirho();
        let (_dag_hash_chirho, module_hash_chirho) =
            build_single_node_module_chirho(&root_chirho).unwrap();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "missing".to_string(),
            owner_chirho,
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: vec![AppDeployRouteManifestChirho {
                route_chirho: "api-contact".to_string(),
                source_chirho: AppDeployDagSourceChirho::ModuleChirho {
                    hash_chirho: module_hash_chirho,
                },
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                params_chirho: None,
                key_access_chirho: None,
            }],
            runtime_packages_chirho: Vec::new(),
        };

        assert!(deploy_app_manifest_chirho(&root_chirho, &manifest_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn manifest_validates_all_routes_before_moving_refs_chirho() {
        let root_chirho = tmp_root_chirho();
        let (dag_hash_chirho, _module_hash_chirho) =
            build_single_node_module_chirho(&root_chirho).unwrap();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let missing_dag_chirho = HashChirho("0".repeat(64));
        let manifest_chirho = AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
            app_chirho: "partial".to_string(),
            owner_chirho,
            root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: dag_hash_chirho,
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: vec![AppDeployRouteManifestChirho {
                route_chirho: "bad-route".to_string(),
                source_chirho: AppDeployDagSourceChirho::DagChirho {
                    hash_chirho: missing_dag_chirho,
                },
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                params_chirho: None,
                key_access_chirho: None,
            }],
            runtime_packages_chirho: Vec::new(),
        };

        assert!(deploy_app_manifest_chirho(&root_chirho, &manifest_chirho).is_err());
        let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
        assert!(!refs_chirho.branches_chirho.contains_key("app/partial"));
        assert!(!refs_chirho
            .branches_chirho
            .contains_key("app-route/partial/bad-route"));
        assert!(app_chirho::load_app_records_chirho(&root_chirho)
            .unwrap()
            .is_empty());
        assert!(app_chirho::load_app_route_records_chirho(&root_chirho)
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
