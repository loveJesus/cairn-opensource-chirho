// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! App record validation and signed-message helpers.

use super::{
    ensure_app_owner_chirho, resolve_app_dag_chirho, validate_app_name_chirho,
    validate_route_name_chirho, verified_selected_app_route_record_chirho, AppInputModeChirho,
    AppRouteRequestBodyPolicyChirho,
};
use crate::model_chirho::{DagChirho, HashChirho};
use crate::{privacy_chirho, refs_chirho, store_chirho};
use anyhow::{bail, Context, Result};
use std::path::Path;

pub(super) fn validate_app_route_deploy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    dag_chirho: &HashChirho,
    owner_principal_chirho: &str,
) -> Result<()> {
    validate_app_name_chirho(app_chirho)?;
    validate_route_name_chirho(route_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let resolved_chirho = resolve_app_dag_chirho(root_chirho, &refs_chirho, app_chirho)?;
    if resolved_chirho.owner_principal_chirho != owner_principal_chirho {
        bail!(
            "app '{app_chirho}' is owned by '{}', not '{owner_principal_chirho}'",
            resolved_chirho.owner_principal_chirho
        );
    }
    let _dag_obj_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_chirho)
        .with_context(|| format!("route DAG {} is not in the store", dag_chirho.0))?;
    Ok(())
}

pub fn validate_app_input_mode_chirho(mode_chirho: &AppInputModeChirho) -> Result<()> {
    match mode_chirho {
        AppInputModeChirho::PlainChirho => Ok(()),
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho,
            safe_metadata_chirho,
        } => {
            privacy_chirho::validate_privacy_subject_chirho(subject_chirho)?;
            super::validate_app_private_input_safe_metadata_chirho(safe_metadata_chirho)
        }
    }
}

/// Resolve only the signed route policy bound to the selected active route DAG.
/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/served-request-admission-workflow-chirho.md`.
pub fn verified_app_route_request_body_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    dag_chirho: &HashChirho,
) -> Result<Option<AppRouteRequestBodyPolicyChirho>> {
    validate_app_name_chirho(app_chirho)?;
    validate_route_name_chirho(route_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let selected_chirho = verified_selected_app_route_record_chirho(
        root_chirho,
        &refs_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
    )?;
    if selected_chirho.dag_chirho.as_ref() != Some(dag_chirho) {
        bail!("selected app route policy does not bind the requested DAG");
    }
    Ok(selected_chirho.request_body_policy_chirho)
}
