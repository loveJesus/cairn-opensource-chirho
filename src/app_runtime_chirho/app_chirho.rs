// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Records and verifies signed app ownership and owner-gated app/route deploy moves.

use crate::model_chirho::{DagChirho, HashChirho};
use crate::{identity_chirho, refs_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_economic_governance_chirho::ports_chirho::EconomicGovernanceAppOwnerPortChirho;
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::writer_head_chirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "app_chirho/app_deploy_evidence_chirho.rs"]
mod app_deploy_evidence_chirho;
#[path = "app_chirho/head_protocol_chirho/app_head_transition_chirho.rs"]
mod app_head_transition_chirho;
pub use app_head_transition_chirho::recover_app_head_chirho;
#[path = "app_chirho/app_route_chirho.rs"]
mod app_route_chirho;
#[path = "app_chirho/client_owner_binding_chirho.rs"]
mod client_owner_binding_chirho;
#[path = "app_chirho/head_protocol_chirho/key_authority_chirho.rs"]
mod key_authority_chirho;
#[path = "app_chirho/params_chirho.rs"]
mod params_chirho;
#[path = "app_chirho/record_validation_chirho.rs"]
mod record_validation_chirho;
#[path = "app_chirho/head_protocol_chirho/request_access_policy_chirho.rs"]
mod request_access_policy_chirho;
#[path = "app_chirho/static_assets_chirho.rs"]
mod static_assets_chirho;
#[path = "app_chirho/template_app_deploy_chirho.rs"]
mod template_app_deploy_chirho;
#[path = "app_chirho/template_registry_chirho.rs"]
mod template_registry_chirho;
pub use app_route_chirho::{
    app_route_response_content_type_chirho, app_route_unreviewed_dev_chirho,
    deploy_app_route_chirho, deploy_app_route_unreviewed_dev_chirho,
    deploy_app_route_unreviewed_dev_with_head_transition_authority_chirho,
    deploy_app_route_with_head_transition_authority_chirho, load_app_route_records_chirho,
    load_app_route_response_policy_records_chirho, recover_app_route_head_chirho,
    recover_app_route_head_removal_chirho, resolve_app_route_chirho,
    set_app_route_response_policy_chirho, undeploy_app_route_chirho,
    verified_app_route_records_chirho, verified_selected_app_route_record_chirho,
    verify_app_route_response_policies_chirho, verify_app_routes_chirho,
};
pub(crate) use app_route_chirho::{
    deploy_app_route_with_request_body_policy_and_head_transition_authority_chirho,
    deploy_app_route_with_request_body_policy_chirho,
};
use cairn_app_control_chirho::{
    app_head_removal_chirho::AppHeadRemovalAuthorityPortChirho, AppRouteAuthorityPortChirho,
};
use cairn_model_app_chirho::{
    app_head_transition_chirho::{
        app_deploy_dags_from_verified_records_chirho, app_owner_from_records_chirho,
        app_previous_is_verified_chirho, app_records_for_app_chirho,
        resolved_app_dag_from_selected_record_chirho,
        selected_app_record_from_verified_history_chirho, validate_app_record_schema_chirho,
        validate_app_record_transition_shape_chirho, verified_app_owner_from_records_chirho,
    },
    app_input_policy_record_signed_message_chirho as app_input_policy_record_message_chirho,
    app_policy_chirho::{
        app_input_mode_from_verified_records_chirho,
        app_input_policy_warnings_from_verified_state_chirho, app_ref_dag_chirho,
        app_response_content_type_from_verified_records_chirho,
        app_root_request_body_policy_from_verified_records_chirho, app_route_ref_target_chirho,
        app_route_response_content_type_from_verified_records_chirho,
        app_status_from_verified_state_chirho, deployed_app_names_chirho,
        deployed_app_route_names_chirho, deployed_app_routes_from_refs_chirho,
        root_input_surface_had_no_body_policy_chirho,
        validate_app_response_policy_record_shape_chirho,
        validate_app_route_response_policy_record_shape_chirho,
        validate_record_schema_chirho as verify_app_record_schema_chirho,
    },
    app_record_signed_message_chirho as app_record_message_chirho,
    app_response_policy_record_signed_message_chirho as app_response_policy_record_message_chirho,
    app_route_head_transition_chirho::{
        app_route_action_is_unreviewed_dev_chirho, validate_app_route_record_schema_chirho,
        validate_app_route_record_transition_shape_chirho,
    },
    app_route_record_signed_message_chirho as app_route_record_message_chirho,
    app_route_response_policy_record_signed_message_chirho as app_route_response_policy_record_message_chirho,
};
pub use cairn_model_app_chirho::{
    app_private_input_safe_metadata_value_allowed_chirho,
    normalize_app_response_content_type_chirho, normalize_app_route_response_content_type_chirho,
    normalize_app_static_asset_content_type_chirho, validate_app_name_chirho,
    validate_app_private_input_safe_metadata_chirho,
    validate_app_private_input_safe_metadata_value_chirho, validate_app_static_asset_name_chirho,
    validate_route_name_chirho, verified_app_owner_map_chirho, AppActionChirho, AppInputModeChirho,
    AppInputPolicyRecordChirho, AppInputPolicyWarningChirho, AppKeyAuthorityRecordChirho,
    AppKeyAuthorityRouteChirho, AppParamsRecordChirho, AppParamsSelectionChirho,
    AppPrivateInputSafeMetadataChirho, AppRecordChirho, AppRequestAccessPolicyChirho,
    AppRequestAccessPolicyRecordChirho, AppResponsePolicyRecordChirho, AppRouteActionChirho,
    AppRouteAuthorityStateChirho, AppRouteKeyAccessChirho, AppRouteRecordChirho,
    AppRouteRequestBodyPolicyChirho, AppRouteResponsePolicyRecordChirho,
    AppStaticAssetRecordChirho, AppStaticAssetSelectionChirho, AppStatusChirho,
    ClientOwnerBindingRecordChirho, ResolvedAppDagChirho, TemplateAppDeployRecordChirho,
    TemplateAppDeployResponseChirho, TemplateRegistryInputChirho, TemplateRegistryRecordChirho,
    TemplateRegistryTargetChirho, APP_INPUT_POLICY_RECORD_SCHEMA_CHIRHO,
    APP_KEY_AUTHORITY_RECORD_SCHEMA_CHIRHO, APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO,
    APP_RECORD_SCHEMA_CHIRHO, APP_RECORD_V2_SCHEMA_CHIRHO,
    APP_REQUEST_ACCESS_POLICY_RECORD_SCHEMA_CHIRHO, APP_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO,
    APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO, APP_ROUTE_RECORD_SCHEMA_CHIRHO,
    APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO, APP_ROUTE_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO,
    APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO, APP_STATIC_ASSET_JPEG_CONTENT_TYPE_CHIRHO,
    APP_STATIC_ASSET_PDF_CONTENT_TYPE_CHIRHO, APP_STATIC_ASSET_PNG_CONTENT_TYPE_CHIRHO,
    APP_STATIC_ASSET_WOFF2_CONTENT_TYPE_CHIRHO, APP_STATIC_ASSET_WOFF_CONTENT_TYPE_CHIRHO,
    APP_UNREVIEWED_DEV_HEADER_CHIRHO, APP_UNREVIEWED_DEV_HEADER_VALUE_CHIRHO,
};
use cairn_seqlog_chirho::jsonl_read_chirho::load_serialized_jsonl_chirho;
pub(crate) use cairn_verified_view_cache_chirho as verified_view_cache_chirho;
use cairn_writer_head_chirho::head_transition_authority_chirho::{
    dispatch_head_transition_chirho, HeadTransitionAuthorityPortChirho,
};
pub use client_owner_binding_chirho::{
    load_client_owner_binding_records_chirho, verify_client_owner_bindings_chirho,
};
#[cfg(test)]
pub(crate) use key_authority_chirho::key_authority_folds_chirho;
pub use key_authority_chirho::{
    app_key_authority_record_chirho, app_key_authority_records_path_chirho,
    append_app_key_authority_record_chirho,
    append_app_key_authority_record_under_append_lock_chirho,
    load_app_key_authority_records_chirho, verify_app_key_authority_records_chirho,
};
pub use params_chirho::{
    app_params_chirho, load_app_params_records_chirho, set_app_params_chirho,
    set_app_params_hash_chirho, verify_app_params_chirho,
};
use record_validation_chirho::validate_app_route_deploy_chirho;
pub use record_validation_chirho::{
    validate_app_input_mode_chirho, verified_app_route_request_body_policy_chirho,
};
pub(crate) use request_access_policy_chirho::validate_app_request_access_policy_transition_chirho;
pub use request_access_policy_chirho::{
    app_request_access_policy_chirho, load_app_request_access_policy_records_chirho,
    set_app_request_access_policy_chirho, verify_app_request_access_policies_chirho,
};
pub use static_assets_chirho::{
    app_static_asset_by_hash_chirho, app_static_asset_by_name_chirho,
    app_static_asset_bytes_chirho, load_app_static_asset_records_chirho,
    remove_app_static_asset_chirho, set_app_static_asset_bytes_chirho,
    set_app_static_asset_hash_chirho, verified_app_static_asset_records_chirho,
    verify_app_static_assets_chirho,
};
pub use template_app_deploy_chirho::{
    load_template_app_deploy_records_chirho, run_template_app_deploy_effect_chirho,
    verify_template_app_deploy_records_chirho,
};
pub use template_registry_chirho::{
    load_template_registry_records_chirho, register_template_app_template_chirho,
    verified_template_registry_chirho, verify_template_registry_chirho,
};
pub(crate) use template_registry_chirho::{validate_short_id_chirho, validate_template_id_chirho};

fn app_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-records-chirho.jsonl")
}

fn app_route_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-route-records-chirho.jsonl")
}

fn app_input_policy_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-input-policy-records-chirho.jsonl")
}

fn app_request_access_policy_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-request-access-policy-records-chirho.jsonl")
}

fn app_response_policy_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-response-policy-records-chirho.jsonl")
}

fn app_route_response_policy_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-route-response-policy-records-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn deploy_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
) -> Result<AppRecordChirho> {
    deploy_app_with_review_label_chirho(
        root_chirho,
        app_chirho,
        dag_chirho,
        owner_principal_chirho,
        None,
        false,
    )
}

pub fn deploy_app_with_head_transition_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<AppRecordChirho> {
    deploy_app_with_review_label_chirho(
        root_chirho,
        app_chirho,
        dag_chirho,
        owner_principal_chirho,
        Some(authority_chirho),
        false,
    )
}

pub fn deploy_app_unreviewed_dev_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
) -> Result<AppRecordChirho> {
    deploy_app_with_review_label_chirho(
        root_chirho,
        app_chirho,
        dag_chirho,
        owner_principal_chirho,
        None,
        true,
    )
}

pub fn deploy_app_unreviewed_dev_with_head_transition_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<AppRecordChirho> {
    deploy_app_with_review_label_chirho(
        root_chirho,
        app_chirho,
        dag_chirho,
        owner_principal_chirho,
        Some(authority_chirho),
        true,
    )
}

fn deploy_app_with_review_label_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    dag_chirho: HashChirho,
    owner_principal_chirho: &str,
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
    unreviewed_dev_chirho: bool,
) -> Result<AppRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    ensure_owner_principal_chirho(root_chirho, owner_principal_chirho)?;
    if let Some(existing_owner_chirho) = verified_app_owner_chirho(root_chirho, app_chirho)? {
        if existing_owner_chirho != owner_principal_chirho {
            bail!(
                "app '{app_chirho}' is owned by '{existing_owner_chirho}', not '{owner_principal_chirho}'"
            );
        }
    }
    let _dag_obj_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, &dag_chirho)
        .with_context(|| format!("target DAG {} is not in the store", dag_chirho.0))?;
    let action_chirho = if unreviewed_dev_chirho {
        AppActionChirho::DeployUnreviewedDevChirho
    } else {
        AppActionChirho::DeployChirho
    };
    let local_dag_chirho = dag_chirho.clone();
    let local_action_chirho = action_chirho.clone();
    dispatch_head_transition_chirho(
        root_chirho,
        authority_chirho,
        |fence_chirho| {
            deploy_app_local_unlocked_chirho(
                root_chirho,
                app_chirho,
                owner_principal_chirho,
                local_dag_chirho,
                local_action_chirho,
                fence_chirho,
            )
        },
        || {
            app_deploy_evidence_chirho::prepare_elected_app_deploy_chirho(
                root_chirho,
                app_chirho,
                owner_principal_chirho,
                dag_chirho,
                action_chirho,
            )
        },
        |prepared_chirho, scope_chirho| {
            app_deploy_evidence_chirho::commit_elected_app_deploy_chirho(
                root_chirho,
                prepared_chirho,
                scope_chirho,
            )
        },
    )
}

fn deploy_app_local_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    dag_chirho: HashChirho,
    action_chirho: AppActionChirho,
    fence_chirho: &cairn_writer_head_chirho::writer_head_chirho::WriterFenceTokenChirho,
) -> Result<AppRecordChirho> {
    cairn_app_control_chirho::app_head_removal_chirho::recover_app_head_removal_unlocked_chirho(
        &RootAppHeadRemovalAuthorityPortChirho,
        root_chirho,
        app_chirho,
        fence_chirho,
    )?;
    app_head_transition_chirho::recover_app_head_unlocked_chirho(
        root_chirho,
        app_chirho,
        fence_chirho,
    )?;
    let verified_records_chirho = verified_app_records_chirho(root_chirho)?;
    let previous_chirho = app_head_transition_chirho::app_ref_head_chirho(root_chirho, app_chirho)?;
    if let Some(previous_chirho) = &previous_chirho {
        if !app_previous_is_verified_chirho(
            &verified_records_chirho,
            app_chirho,
            owner_principal_chirho,
            previous_chirho,
        ) {
            bail!("app '{app_chirho}' ref does not select verified signed deploy history");
        }
    }
    if previous_chirho.as_ref() == Some(&dag_chirho) {
        let selected_chirho = selected_app_record_from_verified_history_chirho(
            &verified_records_chirho,
            app_chirho,
            &dag_chirho,
        )?;
        app_head_transition_chirho::require_applied_app_record_chirho(
            root_chirho,
            selected_chirho,
        )?;
        return Ok(selected_chirho.clone());
    }
    let record_chirho = app_head_transition_chirho::append_app_deploy_record_unlocked_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        dag_chirho,
        action_chirho,
        previous_chirho,
        fence_chirho,
    )?;
    let verified_record_chirho =
        app_head_transition_chirho::verified_record_at_seq_chirho(root_chirho, &record_chirho)?;
    app_head_transition_chirho::complete_verified_app_record_unlocked_chirho(
        root_chirho,
        &verified_record_chirho,
        fence_chirho,
    )?;
    Ok(record_chirho)
}

pub fn undeploy_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<bool> {
    validate_app_name_chirho(app_chirho)?;
    ensure_owner_principal_chirho(root_chirho, owner_principal_chirho)?;
    if let Some(existing_owner_chirho) = verified_app_owner_chirho(root_chirho, app_chirho)? {
        if existing_owner_chirho != owner_principal_chirho {
            bail!(
                "app '{app_chirho}' is owned by '{existing_owner_chirho}', not '{owner_principal_chirho}'"
            );
        }
    }
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        app_head_transition_chirho::recover_app_head_unlocked_chirho(
            root_chirho,
            app_chirho,
            fence_chirho,
        )?;
        cairn_app_control_chirho::app_head_removal_chirho::undeploy_app_head_unlocked_chirho(
            &RootAppHeadRemovalAuthorityPortChirho,
            root_chirho,
            app_chirho,
            owner_principal_chirho,
            fence_chirho,
        )
    })
}

pub fn recover_app_head_removal_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<
    Option<cairn_app_control_chirho::app_head_removal_chirho::AppHeadRemovalRecoveryOutcomeChirho>,
> {
    validate_app_name_chirho(app_chirho)?;
    cairn_app_control_chirho::app_head_removal_chirho::recover_app_head_removal_chirho(
        &RootAppHeadRemovalAuthorityPortChirho,
        root_chirho,
        app_chirho,
    )
}

pub(super) struct RootAppHeadRemovalAuthorityPortChirho;

pub(super) struct RootAppRouteAuthorityPortChirho;

impl AppHeadRemovalAuthorityPortChirho for RootAppHeadRemovalAuthorityPortChirho {
    fn verified_app_records_chirho(&self, root_chirho: &Path) -> Result<Vec<AppRecordChirho>> {
        verified_app_records_chirho(root_chirho)
    }

    fn append_signed_app_undeploy_record_unlocked_chirho(
        &self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_principal_chirho: &str,
    ) -> Result<AppRecordChirho> {
        append_app_record_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_principal_chirho,
            None,
            AppActionChirho::UndeployChirho,
        )
    }

    fn require_applied_historical_app_head_chirho(
        &self,
        root_chirho: &Path,
        record_chirho: &AppRecordChirho,
    ) -> Result<()> {
        app_head_transition_chirho::require_applied_app_record_chirho(root_chirho, record_chirho)
    }
}

pub fn set_app_input_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
    mode_chirho: AppInputModeChirho,
) -> Result<AppInputPolicyRecordChirho> {
    set_app_input_surface_policy_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
        mode_chirho,
        None,
    )
}

pub(crate) fn set_app_root_input_policy_with_request_body_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    mode_chirho: AppInputModeChirho,
    request_body_policy_chirho: AppRouteRequestBodyPolicyChirho,
) -> Result<AppInputPolicyRecordChirho> {
    set_app_input_surface_policy_chirho(
        root_chirho,
        app_chirho,
        None,
        owner_principal_chirho,
        mode_chirho,
        Some(request_body_policy_chirho),
    )
}

fn set_app_input_surface_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
    mode_chirho: AppInputModeChirho,
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
) -> Result<AppInputPolicyRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    if let Some(route_chirho) = route_chirho {
        validate_route_name_chirho(route_chirho)?;
    }
    validate_app_input_mode_chirho(&mode_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    if let Some(route_chirho) = route_chirho {
        let _route_dag_chirho = resolve_app_route_chirho(
            root_chirho,
            &refs_chirho,
            app_chirho,
            route_chirho,
            owner_principal_chirho,
        )?;
    } else {
        let resolved_chirho = resolve_app_dag_chirho(root_chirho, &refs_chirho, app_chirho)?;
        if resolved_chirho.owner_principal_chirho != owner_principal_chirho {
            bail!(
                "app '{app_chirho}' is owned by '{}', not '{owner_principal_chirho}'",
                resolved_chirho.owner_principal_chirho
            );
        }
    }
    if let Some(request_body_policy_chirho) = &request_body_policy_chirho {
        validate_app_root_request_body_policy_transition_chirho(
            root_chirho,
            app_chirho,
            owner_principal_chirho,
            request_body_policy_chirho,
        )?;
    }
    append_app_input_policy_record_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
        mode_chirho,
        request_body_policy_chirho,
    )
}

pub(crate) fn validate_app_root_request_body_policy_transition_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    request_body_policy_chirho: &AppRouteRequestBodyPolicyChirho,
) -> Result<()> {
    if matches!(
        request_body_policy_chirho,
        AppRouteRequestBodyPolicyChirho::AcceptBodyChirho
    ) && root_input_surface_had_no_body_policy_chirho(
        &verified_app_input_policy_records_chirho(root_chirho)?,
        app_chirho,
        owner_principal_chirho,
    ) {
        bail!(
            "app root '{app_chirho}' cannot downgrade to AcceptBodyChirho after a signed NoBodyChirho policy"
        );
    }
    Ok(())
}

pub fn set_app_response_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    response_content_type_chirho: &str,
) -> Result<AppResponsePolicyRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let response_content_type_chirho =
        normalize_app_response_content_type_chirho(response_content_type_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let resolved_chirho = resolve_app_dag_chirho(root_chirho, &refs_chirho, app_chirho)?;
    if resolved_chirho.owner_principal_chirho != owner_principal_chirho {
        bail!(
            "app '{app_chirho}' is owned by '{}', not '{owner_principal_chirho}'",
            resolved_chirho.owner_principal_chirho
        );
    }
    append_app_response_policy_record_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        &response_content_type_chirho,
    )
}

pub fn app_response_content_type_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<Option<String>> {
    validate_app_name_chirho(app_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let records_chirho = verified_app_response_policy_records_chirho(root_chirho)?;
    Ok(app_response_content_type_from_verified_records_chirho(
        &records_chirho,
        app_chirho,
        owner_principal_chirho,
    ))
}

pub fn app_input_mode_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
) -> Result<AppInputModeChirho> {
    validate_app_name_chirho(app_chirho)?;
    if let Some(route_chirho) = route_chirho {
        validate_route_name_chirho(route_chirho)?;
    }
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let records_chirho = verified_app_input_policy_records_chirho(root_chirho)?;
    app_input_mode_from_verified_records_chirho(
        &records_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
        true,
    )
}

pub fn app_root_request_body_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<Option<AppRouteRequestBodyPolicyChirho>> {
    validate_app_name_chirho(app_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let records_chirho = verified_app_input_policy_records_chirho(root_chirho)?;
    Ok(app_root_request_body_policy_from_verified_records_chirho(
        &records_chirho,
        app_chirho,
        owner_principal_chirho,
    ))
}

pub fn resolve_app_dag_chirho(
    root_chirho: &Path,
    refs_chirho: &crate::model_chirho::RefsChirho,
    app_chirho: &str,
) -> Result<ResolvedAppDagChirho> {
    let selected_chirho =
        verified_selected_app_record_chirho(root_chirho, refs_chirho, app_chirho)?;
    resolved_app_dag_from_selected_record_chirho(app_chirho, &selected_chirho)
}

pub fn verified_selected_app_record_chirho(
    root_chirho: &Path,
    refs_chirho: &crate::model_chirho::RefsChirho,
    app_chirho: &str,
) -> Result<AppRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    // The verified selection is a pure function of the root fingerprint plus the refs-derived app DAG,
    // so it is cached by that exact key, as route selection is. Uncached, every app-root request read
    // the whole reflog (bounded-growth census app A1). An absent ref falls through to the uncached body
    // so its "not deployed" error is unchanged.
    let Some(ref_dag_chirho) = app_ref_dag_chirho(refs_chirho, app_chirho) else {
        return verified_selected_app_record_uncached_chirho(root_chirho, refs_chirho, app_chirho);
    };
    let selection_key_chirho = verified_view_cache_chirho::SelectedAppKeyChirho {
        app_chirho: app_chirho.to_string(),
        app_ref_dag_chirho: ref_dag_chirho.0,
    };
    Ok(
        verified_view_cache_chirho::cached_selected_app_record_chirho(
            root_chirho,
            selection_key_chirho,
            || verified_selected_app_record_uncached_chirho(root_chirho, refs_chirho, app_chirho),
        )?
        .as_ref()
        .clone(),
    )
}

fn verified_selected_app_record_uncached_chirho(
    root_chirho: &Path,
    refs_chirho: &crate::model_chirho::RefsChirho,
    app_chirho: &str,
) -> Result<AppRecordChirho> {
    let ref_dag_chirho = app_ref_dag_chirho(refs_chirho, app_chirho)
        .ok_or_else(|| anyhow!("no deployed app '{app_chirho}'"))?;
    let records_chirho = verified_app_records_chirho(root_chirho)?;
    let selected_chirho = selected_app_record_from_verified_history_chirho(
        &records_chirho,
        app_chirho,
        &ref_dag_chirho,
    )?;
    app_head_transition_chirho::require_applied_app_record_chirho(root_chirho, selected_chirho)?;
    Ok(selected_chirho.clone())
}

pub fn maybe_resolve_app_dag_chirho(
    root_chirho: &Path,
    refs_chirho: &crate::model_chirho::RefsChirho,
    app_chirho: &str,
) -> Result<Option<ResolvedAppDagChirho>> {
    validate_app_name_chirho(app_chirho)?;
    if app_ref_dag_chirho(refs_chirho, app_chirho).is_none() {
        return Ok(None);
    }
    resolve_app_dag_chirho(root_chirho, refs_chirho, app_chirho).map(Some)
}

pub fn app_owner_chirho(root_chirho: &Path, app_chirho: &str) -> Result<Option<String>> {
    validate_app_name_chirho(app_chirho)?;
    Ok(app_owner_from_records_chirho(
        &load_app_records_chirho(root_chirho)?,
        app_chirho,
    ))
}

pub fn verified_app_owner_chirho(root_chirho: &Path, app_chirho: &str) -> Result<Option<String>> {
    validate_app_name_chirho(app_chirho)?;
    Ok(verified_app_owner_from_records_chirho(
        &verified_app_records_chirho(root_chirho)?,
        app_chirho,
    ))
}

pub fn verified_app_owners_chirho(root_chirho: &Path) -> Result<BTreeMap<String, String>> {
    Ok(verified_app_owner_map_chirho(verified_app_records_chirho(
        root_chirho,
    )?))
}

pub struct RootAppOwnerPortChirho;

impl EconomicGovernanceAppOwnerPortChirho for RootAppOwnerPortChirho {
    fn ensure_app_owner_chirho(
        &self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_principal_chirho: &str,
    ) -> Result<()> {
        ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)
    }

    fn verified_app_owner_chirho(
        &self,
        root_chirho: &Path,
        app_chirho: &str,
    ) -> Result<Option<String>> {
        verified_app_owner_chirho(root_chirho, app_chirho)
    }
}

pub fn verified_app_deploy_dags_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<BTreeSet<HashChirho>> {
    validate_app_name_chirho(app_chirho)?;
    Ok(app_deploy_dags_from_verified_records_chirho(
        &verified_app_records_chirho(root_chirho)?,
        app_chirho,
    ))
}

pub fn app_status_chirho(root_chirho: &Path, app_chirho: &str) -> Result<AppStatusChirho> {
    validate_app_name_chirho(app_chirho)?;
    // The cached verified view, not a raw load-and-verify on every call: this serves the public
    // descriptor, docs and MCP routes, anonymous included (bounded-growth census app A3).
    let all_records_chirho = verified_app_records_chirho(root_chirho)?;
    let records_chirho = app_records_for_app_chirho(all_records_chirho, app_chirho);
    let refs_val_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let resolved_chirho = maybe_resolve_app_dag_chirho(root_chirho, &refs_val_chirho, app_chirho)?;
    let mut routes_chirho = BTreeMap::new();
    if let Some(resolved_chirho) = &resolved_chirho {
        for route_chirho in deployed_app_route_names_chirho(&refs_val_chirho, app_chirho) {
            let route_dag_chirho = resolve_app_route_chirho(
                root_chirho,
                &refs_val_chirho,
                app_chirho,
                &route_chirho,
                &resolved_chirho.owner_principal_chirho,
            )?;
            routes_chirho.insert(route_chirho, route_dag_chirho);
        }
    }
    Ok(app_status_from_verified_state_chirho(
        app_chirho,
        &records_chirho,
        resolved_chirho.as_ref(),
        routes_chirho,
    ))
}

pub fn verified_deployed_apps_chirho(root_chirho: &Path) -> Result<Vec<AppStatusChirho>> {
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let mut apps_chirho = Vec::new();
    for app_chirho in deployed_app_names_chirho(&refs_chirho) {
        apps_chirho.push(app_status_chirho(root_chirho, &app_chirho)?);
    }
    apps_chirho.sort_by(|a_chirho, b_chirho| a_chirho.app_chirho.cmp(&b_chirho.app_chirho));
    Ok(apps_chirho)
}

/// Whole-log JSONL read, counted (test-only) as one full-log load so the verified-view cache's
/// warm-request "zero full reads" invariant is observable at the real leaf read.
pub(crate) fn load_counted_serialized_jsonl_chirho<T: serde::de::DeserializeOwned>(
    path_chirho: &Path,
) -> Result<Vec<T>> {
    #[cfg(test)]
    verified_view_cache_chirho::test_metrics_chirho::note_full_log_load_chirho();
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    control_log_load_metrics_chirho::note_load_chirho(path_chirho);
    load_serialized_jsonl_chirho(path_chirho)
}

/// Whole control-plane log loads on the calling thread, for the serve-runtime growth arms: how many, and which logs
/// by file name, so an arm can tell the app control plane from the identity log. This is in the
/// `serve-runtime-test-hooks-chirho` family. Thread-local, so parallel tests with their own roots never perturb one
/// another's counts.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub mod control_log_load_metrics_chirho {
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    thread_local! {
        static LOADS_CHIRHO: Cell<u64> = const { Cell::new(0) };
        static LOGS_CHIRHO: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub fn reset_chirho() {
        LOADS_CHIRHO.with(|cell_chirho| cell_chirho.set(0));
        LOGS_CHIRHO.with(|logs_chirho| logs_chirho.borrow_mut().clear());
    }

    pub fn count_chirho() -> u64 {
        LOADS_CHIRHO.with(|cell_chirho| cell_chirho.get())
    }

    /// The file name of each log loaded since the last reset, in load order.
    pub fn loaded_logs_chirho() -> Vec<String> {
        LOGS_CHIRHO.with(|logs_chirho| logs_chirho.borrow().clone())
    }

    /// Add loads counted on another thread, such as a served run's blocking-pool thread, to this thread's counts.
    pub fn absorb_chirho(count_chirho: u64, logs_chirho: Vec<String>) {
        LOADS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + count_chirho));
        LOGS_CHIRHO.with(|loaded_chirho| loaded_chirho.borrow_mut().extend(logs_chirho));
    }

    pub(crate) fn note_load_chirho(path_chirho: &Path) {
        LOADS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
        let name_chirho = path_chirho
            .file_name()
            .map(|name_chirho| name_chirho.to_string_lossy().into_owned())
            .unwrap_or_default();
        LOGS_CHIRHO.with(|logs_chirho| logs_chirho.borrow_mut().push(name_chirho));
    }
}

/// The ed25519 signature-verify leaf every control-plane verify loop calls, counted (test-only) so
/// the cache's warm-request "zero verifies" invariant is observable.
pub(crate) fn verify_record_sig_chirho(
    pubkey_chirho: &str,
    message_chirho: &[u8],
    sig_chirho: &str,
) -> Result<bool> {
    #[cfg(test)]
    verified_view_cache_chirho::test_metrics_chirho::note_ed25519_verify_chirho();
    signer_chirho::verify_with_pubkey_chirho(pubkey_chirho, message_chirho, sig_chirho)
}

/// The verified (app -> owner) map, cached per root fingerprint; the O(1) owner gate on the hot path.
fn verified_app_owner_map_arc_chirho(
    root_chirho: &Path,
) -> Result<std::sync::Arc<BTreeMap<String, String>>> {
    verified_view_cache_chirho::cached_owner_map_chirho(root_chirho, || {
        Ok(verified_app_owner_map_chirho(verified_app_records_chirho(
            root_chirho,
        )?))
    })
}

/// The verified (principal -> kind) map now lives with identity (R2b): the served owner gate reaches it here unchanged.
pub use crate::identity_chirho::verified_identity_kind_map_arc_chirho;

pub fn load_app_records_chirho(root_chirho: &Path) -> Result<Vec<AppRecordChirho>> {
    load_counted_serialized_jsonl_chirho(&app_records_path_chirho(root_chirho))
}

pub fn load_app_input_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppInputPolicyRecordChirho>> {
    load_counted_serialized_jsonl_chirho(&app_input_policy_records_path_chirho(root_chirho))
}

pub fn load_app_response_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppResponsePolicyRecordChirho>> {
    load_counted_serialized_jsonl_chirho(&app_response_policy_records_path_chirho(root_chirho))
}

pub fn verify_apps_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(verified_app_records_chirho(root_chirho)?.len())
}

pub fn verified_app_records_chirho(root_chirho: &Path) -> Result<Vec<AppRecordChirho>> {
    Ok(
        verified_view_cache_chirho::cached_app_records_chirho(root_chirho, || {
            let records_chirho = load_app_records_chirho(root_chirho)?;
            verify_app_records_chirho(root_chirho, &records_chirho)?;
            Ok(records_chirho)
        })?
        .as_ref()
        .clone(),
    )
}

fn verify_app_records_chirho(root_chirho: &Path, records_chirho: &[AppRecordChirho]) -> Result<()> {
    if records_chirho.is_empty() {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        validate_app_record_schema_chirho(record_chirho)?;
        validate_app_record_transition_shape_chirho(
            record_chirho,
            cairn_writer_head_chirho::head_transition_chirho::HEAD_TRANSITION_ID_PREFIX_CHIRHO,
        )?;
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "app record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_app_name_chirho(&record_chirho.app_chirho)?;
        ensure_owner_principal_chirho(root_chirho, &record_chirho.owner_principal_chirho)?;
        if let Some(dag_chirho) = &record_chirho.dag_chirho {
            let _dag_obj_chirho: DagChirho =
                store_chirho::get_object_chirho(root_chirho, dag_chirho).with_context(|| {
                    format!(
                        "app record {} points at missing DAG {}",
                        record_chirho.seq_chirho, dag_chirho.0
                    )
                })?;
        }
        let message_chirho = app_record_message_chirho(record_chirho)?;
        if !verify_record_sig_chirho(&pubkey_chirho, &message_chirho, &record_chirho.sig_chirho)? {
            bail!("app record {} signature invalid", record_chirho.seq_chirho);
        }
    }
    Ok(())
}

pub fn verify_app_input_policies_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_app_input_policy_records_chirho(root_chirho)?;
    verify_app_input_policy_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

pub fn verify_app_response_policies_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_app_response_policy_records_chirho(root_chirho)?;
    verify_app_response_policy_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

pub(crate) fn verified_app_input_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppInputPolicyRecordChirho>> {
    Ok(
        verified_view_cache_chirho::cached_input_policy_records_chirho(root_chirho, || {
            let records_chirho = load_app_input_policy_records_chirho(root_chirho)?;
            verify_app_input_policy_records_chirho(root_chirho, &records_chirho)?;
            Ok(records_chirho)
        })?
        .as_ref()
        .clone(),
    )
}

fn verified_app_response_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppResponsePolicyRecordChirho>> {
    Ok(
        verified_view_cache_chirho::cached_response_policy_records_chirho(root_chirho, || {
            let records_chirho = load_app_response_policy_records_chirho(root_chirho)?;
            verify_app_response_policy_records_chirho(root_chirho, &records_chirho)?;
            Ok(records_chirho)
        })?
        .as_ref()
        .clone(),
    )
}

fn verify_app_input_policy_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppInputPolicyRecordChirho],
) -> Result<()> {
    if records_chirho.is_empty() {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut owner_check_chirho = AppOwnerLoopCheckChirho::new_chirho();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        verify_app_record_schema_chirho(
            &record_chirho.schema_chirho,
            APP_INPUT_POLICY_RECORD_SCHEMA_CHIRHO,
            "app input policy record",
        )?;
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "app input policy record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_app_name_chirho(&record_chirho.app_chirho)?;
        if let Some(route_chirho) = &record_chirho.route_chirho {
            validate_route_name_chirho(route_chirho)?;
            if record_chirho.request_body_policy_chirho.is_some() {
                bail!(
                    "app input policy record {} must not carry a named-route request-body policy",
                    record_chirho.seq_chirho
                );
            }
        }
        validate_app_input_mode_chirho(&record_chirho.mode_chirho)?;
        if matches!(
            record_chirho.request_body_policy_chirho,
            Some(AppRouteRequestBodyPolicyChirho::AcceptBodyChirho)
        ) && root_input_surface_had_no_body_policy_chirho(
            &records_chirho[..i_chirho],
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        ) {
            bail!(
                "app root '{}' cannot downgrade to AcceptBodyChirho after a signed NoBodyChirho policy",
                record_chirho.app_chirho
            );
        }
        owner_check_chirho.ensure_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let message_chirho = app_input_policy_record_message_chirho(record_chirho)?;
        if !verify_record_sig_chirho(&pubkey_chirho, &message_chirho, &record_chirho.sig_chirho)? {
            bail!(
                "app input policy record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn verify_app_response_policy_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppResponsePolicyRecordChirho],
) -> Result<()> {
    if records_chirho.is_empty() {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut owner_check_chirho = AppOwnerLoopCheckChirho::new_chirho();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        validate_app_response_policy_record_shape_chirho(record_chirho, i_chirho)?;
        owner_check_chirho.ensure_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let message_chirho = app_response_policy_record_message_chirho(record_chirho)?;
        if !verify_record_sig_chirho(&pubkey_chirho, &message_chirho, &record_chirho.sig_chirho)? {
            bail!(
                "app response policy record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

pub fn app_input_policy_warnings_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppInputPolicyWarningChirho>> {
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let policy_records_chirho = verified_app_input_policy_records_chirho(root_chirho)?;
    let deployed_routes_chirho = deployed_app_routes_from_refs_chirho(&refs_chirho);
    app_input_policy_warnings_from_verified_state_chirho(
        &policy_records_chirho,
        &deployed_routes_chirho,
        &verified_app_owners_chirho(root_chirho)?,
    )
}

fn append_app_record_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    dag_chirho: Option<HashChirho>,
    action_chirho: AppActionChirho,
) -> Result<AppRecordChirho> {
    let path_chirho = app_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = AppRecordChirho {
            seq_chirho,
            schema_chirho: APP_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            dag_chirho,
            action_chirho,
            at_ms_chirho: now_ms_chirho(),
            previous_chirho: None,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: String::new(),
        };
        let message_chirho = app_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn append_app_route_record_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    dag_chirho: Option<HashChirho>,
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    action_chirho: AppRouteActionChirho,
) -> Result<AppRouteRecordChirho> {
    let path_chirho = app_route_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = AppRouteRecordChirho {
            seq_chirho,
            schema_chirho: APP_ROUTE_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            route_chirho: route_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            dag_chirho,
            action_chirho,
            request_body_policy_chirho,
            at_ms_chirho: now_ms_chirho(),
            previous_chirho: None,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: String::new(),
        };
        let message_chirho = app_route_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn append_app_input_policy_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
    mode_chirho: AppInputModeChirho,
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
) -> Result<AppInputPolicyRecordChirho> {
    let path_chirho = app_input_policy_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = AppInputPolicyRecordChirho {
            seq_chirho,
            schema_chirho: APP_INPUT_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            route_chirho: route_chirho.map(str::to_string),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            mode_chirho: mode_chirho.clone(),
            request_body_policy_chirho: request_body_policy_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = app_input_policy_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn append_app_response_policy_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    response_content_type_chirho: &str,
) -> Result<AppResponsePolicyRecordChirho> {
    let path_chirho = app_response_policy_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = AppResponsePolicyRecordChirho {
            seq_chirho,
            schema_chirho: APP_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            response_content_type_chirho: response_content_type_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = app_response_policy_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

/// The authoritative owner-kind check, over the VERIFIED identity map.
///
/// `pub` so the publish route can apply this exact fact BEFORE any durable CAS write. The raw
/// `find_identity_chirho` is NOT equivalent: it reads `load_identities_chirho`, which checks the
/// schema string only. A user row edited to `owner` without re-signing passes the raw read and fails
/// here — so an early raw check would admit the write and leave the refusal to this one, which is
/// the ordering defect it was meant to close.
pub fn ensure_owner_principal_chirho(
    root_chirho: &Path,
    owner_principal_chirho: &str,
) -> Result<()> {
    let kind_map_chirho = verified_identity_kind_map_arc_chirho(root_chirho)?;
    match kind_map_chirho.get(owner_principal_chirho) {
        None => bail!("unknown owner principal '{owner_principal_chirho}'"),
        Some(kind_chirho) if *kind_chirho != identity_chirho::PrincipalKindChirho::OwnerChirho => {
            bail!("app owner must be an owner principal")
        }
        Some(_) => Ok(()),
    }
}

pub(crate) fn ensure_app_owner_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<()> {
    ensure_owner_principal_chirho(root_chirho, owner_principal_chirho)?;
    let owner_map_chirho = verified_app_owner_map_arc_chirho(root_chirho)?;
    ensure_app_owned_by_chirho(&owner_map_chirho, app_chirho, owner_principal_chirho)
}

fn ensure_app_owned_by_chirho(
    owner_map_chirho: &BTreeMap<String, String>,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<()> {
    match owner_map_chirho.get(app_chirho) {
        None => bail!("app '{app_chirho}' has no signed owner record"),
        Some(existing_owner_chirho) if existing_owner_chirho == owner_principal_chirho => Ok(()),
        Some(existing_owner_chirho) => bail!(
            "app '{app_chirho}' is owned by '{existing_owner_chirho}', not '{owner_principal_chirho}'"
        ),
    }
}

/// Per-verify-loop owner check that memoizes the identity-principal check and reuses the cached
/// verified owner map, so an R-row log costs O(R + M) signature work, not O(R * M) (Fix B). The
/// per-record semantics are identical to `ensure_app_owner_chirho`, just hoisted out of the loop.
struct AppOwnerLoopCheckChirho {
    owner_map_chirho: Option<std::sync::Arc<BTreeMap<String, String>>>,
    checked_principals_chirho: BTreeSet<String>,
}

impl AppOwnerLoopCheckChirho {
    fn new_chirho() -> Self {
        Self {
            owner_map_chirho: None,
            checked_principals_chirho: BTreeSet::new(),
        }
    }

    fn ensure_chirho(
        &mut self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_principal_chirho: &str,
    ) -> Result<()> {
        if self
            .checked_principals_chirho
            .insert(owner_principal_chirho.to_string())
        {
            ensure_owner_principal_chirho(root_chirho, owner_principal_chirho)?;
        }
        let owner_map_chirho = match &self.owner_map_chirho {
            Some(owner_map_chirho) => owner_map_chirho.clone(),
            None => {
                let owner_map_chirho = verified_app_owner_map_arc_chirho(root_chirho)?;
                self.owner_map_chirho = Some(owner_map_chirho.clone());
                owner_map_chirho
            }
        };
        ensure_app_owned_by_chirho(&owner_map_chirho, app_chirho, owner_principal_chirho)
    }
}

#[cfg(test)]
#[path = "app_chirho/app_tests_chirho/app_owner_port_tests_chirho.rs"]
mod app_owner_port_tests_chirho;
#[cfg(test)]
#[path = "app_chirho/head_protocol_chirho/head_removal_tests_chirho.rs"]
mod head_removal_tests_chirho;
#[cfg(test)]
#[path = "app_chirho/app_tests_chirho/mod_tests_chirho.rs"]
mod tests_chirho;

/// The ONE app-branch ref-name coordinate (raw `app/` strings stay centralized in this module —
/// the source guard pins every other production site to verified helpers or THIS constructor).
pub fn app_branch_ref_name_chirho(app_chirho: &str) -> String {
    format!("app/{app_chirho}")
}
