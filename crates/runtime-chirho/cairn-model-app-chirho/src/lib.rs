// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure app model records and validation helpers.
//!
//! This crate is intentionally data-only: it owns serializable app records, pure request-input
//! assembly, and low-level string/content-type validation. It does not read a cairn root, append signed logs, verify owners,
//! decrypt private blobs, run DAGs, or serve HTTP.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::{EdgePrivacyChirho, HashChirho};
use cairn_model_review_chirho::ReviewSurfaceDiffChirho;
use cairn_model_runtime_chirho::RuntimeProfileKindChirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

mod app_record_fold_chirho;
pub use app_record_fold_chirho::verified_app_owner_map_chirho;
mod app_control_plane_records_chirho;
pub use app_control_plane_records_chirho::{
    validate_key_action_name_chirho, AppActionChirho, AppKeyAuthorityRecordChirho,
    AppKeyAuthorityRouteChirho, AppRecordChirho, AppRequestAccessPolicyChirho,
    AppRequestAccessPolicyRecordChirho, AppRouteActionChirho, AppRouteAuthorityStateChirho,
    AppRouteKeyAccessChirho, AppRouteRecordChirho, AppRouteRequestBodyPolicyChirho,
    AppStatusChirho, APP_KEY_AUTHORITY_RECORD_SCHEMA_CHIRHO, APP_RECORD_SCHEMA_CHIRHO,
    APP_RECORD_V2_SCHEMA_CHIRHO, APP_REQUEST_ACCESS_POLICY_RECORD_SCHEMA_CHIRHO,
    APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO, APP_ROUTE_RECORD_SCHEMA_CHIRHO,
    APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO, KEY_ACTION_NAME_MAX_LEN_CHIRHO,
};
pub mod app_head_transition_chirho;
pub mod app_params_policy_chirho;
pub mod app_policy_chirho;
pub mod app_request_input_chirho;
pub mod app_route_head_transition_chirho;
mod app_source_manifest_v2_chirho;
pub use app_source_manifest_v2_chirho::{
    canonical_app_source_manifest_v2_bytes_chirho, parse_canonical_app_source_manifest_v2_chirho,
    validate_app_source_manifest_v2_chirho, AppSourceManifestV2Chirho,
    AppSourceNodeManifestV2Chirho, APP_SOURCE_MANIFEST_V2_SCHEMA_CHIRHO,
};
pub mod onboarding_chirho;
mod source_manifest_lowering_chirho;
pub use source_manifest_lowering_chirho::{
    lower_app_source_deploy_manifest_chirho, resolve_app_source_hash_id_chirho,
    reviewed_app_source_deploy_manifest_chirho,
};
mod signed_record_messages_chirho;
pub use signed_record_messages_chirho::{
    app_input_policy_record_signed_message_chirho, app_key_authority_record_signed_message_chirho,
    app_record_signed_message_chirho, app_request_access_policy_record_signed_message_chirho,
    app_response_policy_record_signed_message_chirho, app_route_record_signed_message_chirho,
    app_route_response_policy_record_signed_message_chirho,
};
mod subscription_view_declaration_chirho;
pub use subscription_view_declaration_chirho::{
    SubscriptionViewAuthorizationChirho, SubscriptionViewDeclarationChirho,
    SubscriptionViewDeclarationReportChirho, SubscriptionViewDependencyChirho,
    SubscriptionViewDependencyGroupChirho, SubscriptionViewScopeChirho,
};

pub const APP_INPUT_POLICY_RECORD_SCHEMA_CHIRHO: &str = "app-input-policy-record-v1-chirho";
pub const APP_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO: &str = "app-response-policy-record-v1-chirho";
pub const APP_ROUTE_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO: &str =
    "app-route-response-policy-record-v1-chirho";
pub const APP_UNREVIEWED_DEV_HEADER_CHIRHO: &str = "x-cairn-unreviewed-chirho";
pub const APP_UNREVIEWED_DEV_HEADER_VALUE_CHIRHO: &str = "dev-unreviewed-chirho";

fn bool_is_false_chirho(value_chirho: &bool) -> bool {
    !*value_chirho
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppInputModeChirho {
    PlainChirho,
    PrivateBlobRefChirho {
        subject_chirho: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        safe_metadata_chirho: Vec<AppPrivateInputSafeMetadataChirho>,
    },
}

pub const APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO: &str = "request_kind_chirho";
const APP_PRIVATE_INPUT_SAFE_METADATA_MAX_KEYS_CHIRHO: usize = 8;
const APP_PRIVATE_INPUT_SAFE_METADATA_MAX_VALUES_CHIRHO: usize = 16;
const APP_PRIVATE_INPUT_SAFE_METADATA_MAX_VALUE_BYTES_CHIRHO: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPrivateInputSafeMetadataChirho {
    pub key_chirho: String,
    pub allowed_values_chirho: Vec<String>,
}

pub fn validate_app_private_input_safe_metadata_chirho(
    policies_chirho: &[AppPrivateInputSafeMetadataChirho],
) -> Result<()> {
    if policies_chirho.len() > APP_PRIVATE_INPUT_SAFE_METADATA_MAX_KEYS_CHIRHO {
        bail!(
            "private input safe metadata allows at most {} keys",
            APP_PRIVATE_INPUT_SAFE_METADATA_MAX_KEYS_CHIRHO
        );
    }
    let mut seen_chirho = std::collections::BTreeSet::new();
    for policy_chirho in policies_chirho {
        validate_app_private_input_safe_metadata_key_chirho(&policy_chirho.key_chirho)?;
        if !seen_chirho.insert(&policy_chirho.key_chirho) {
            bail!(
                "duplicate private input safe metadata key '{}'",
                policy_chirho.key_chirho
            );
        }
        if policy_chirho.allowed_values_chirho.is_empty() {
            bail!(
                "private input safe metadata key '{}' must declare allowed values",
                policy_chirho.key_chirho
            );
        }
        if policy_chirho.allowed_values_chirho.len()
            > APP_PRIVATE_INPUT_SAFE_METADATA_MAX_VALUES_CHIRHO
        {
            bail!(
                "private input safe metadata key '{}' allows at most {} values",
                policy_chirho.key_chirho,
                APP_PRIVATE_INPUT_SAFE_METADATA_MAX_VALUES_CHIRHO
            );
        }
        let mut seen_value_chirho = std::collections::BTreeSet::new();
        for value_chirho in &policy_chirho.allowed_values_chirho {
            validate_app_private_input_safe_metadata_value_chirho(
                &policy_chirho.key_chirho,
                value_chirho,
            )?;
            if !seen_value_chirho.insert(value_chirho) {
                bail!(
                    "duplicate private input safe metadata value '{}' for key '{}'",
                    value_chirho,
                    policy_chirho.key_chirho
                );
            }
        }
    }
    Ok(())
}

pub fn validate_app_private_input_safe_metadata_key_chirho(key_chirho: &str) -> Result<()> {
    if key_chirho != APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO {
        bail!("unsupported private input safe metadata key '{key_chirho}'");
    }
    Ok(())
}

pub fn validate_app_private_input_safe_metadata_value_chirho(
    key_chirho: &str,
    value_chirho: &str,
) -> Result<()> {
    validate_app_private_input_safe_metadata_key_chirho(key_chirho)?;
    if value_chirho.is_empty() {
        bail!("private input safe metadata value for '{key_chirho}' must not be empty");
    }
    if value_chirho.len() > APP_PRIVATE_INPUT_SAFE_METADATA_MAX_VALUE_BYTES_CHIRHO {
        bail!(
            "private input safe metadata value for '{key_chirho}' exceeds {} bytes",
            APP_PRIVATE_INPUT_SAFE_METADATA_MAX_VALUE_BYTES_CHIRHO
        );
    }
    if !value_chirho.ends_with("_chirho") {
        bail!("private input safe metadata value for '{key_chirho}' must be a Chirho slug");
    }
    if !value_chirho.bytes().all(|byte_chirho| {
        byte_chirho.is_ascii_lowercase()
            || byte_chirho.is_ascii_digit()
            || byte_chirho == b'_'
            || byte_chirho == b'-'
    }) {
        bail!("private input safe metadata value for '{key_chirho}' must be a safe slug");
    }
    Ok(())
}

pub fn app_private_input_safe_metadata_value_allowed_chirho(
    policies_chirho: &[AppPrivateInputSafeMetadataChirho],
    key_chirho: &str,
    value_chirho: &str,
) -> bool {
    policies_chirho.iter().any(|policy_chirho| {
        policy_chirho.key_chirho == key_chirho
            && policy_chirho
                .allowed_values_chirho
                .iter()
                .any(|allowed_chirho| allowed_chirho == value_chirho)
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInputPolicyRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_chirho: Option<String>,
    pub owner_principal_chirho: String,
    pub mode_chirho: AppInputModeChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppResponsePolicyRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub response_content_type_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRouteResponsePolicyRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub route_chirho: String,
    pub owner_principal_chirho: String,
    pub response_content_type_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInputPolicyWarningChirho {
    pub app_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_chirho: Option<String>,
    pub mode_chirho: AppInputModeChirho,
    pub reason_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAppDagChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub dag_chirho: HashChirho,
    pub unreviewed_dev_chirho: bool,
}

pub const APP_STATIC_ASSET_RECORD_SCHEMA_CHIRHO: &str = "app-static-asset-record-v1-chirho";
pub const APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO: &str = "text/css; charset=utf-8";
pub const APP_STATIC_ASSET_PNG_CONTENT_TYPE_CHIRHO: &str = "image/png";
pub const APP_STATIC_ASSET_JPEG_CONTENT_TYPE_CHIRHO: &str = "image/jpeg";
pub const APP_STATIC_ASSET_PDF_CONTENT_TYPE_CHIRHO: &str = "application/pdf";
pub const APP_STATIC_ASSET_WOFF_CONTENT_TYPE_CHIRHO: &str = "font/woff";
pub const APP_STATIC_ASSET_WOFF2_CONTENT_TYPE_CHIRHO: &str = "font/woff2";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStaticAssetRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub name_chirho: String,
    pub asset_chirho: HashChirho,
    pub content_type_chirho: String,
    pub byte_len_chirho: u64,
    #[serde(default, skip_serializing_if = "is_false_chirho")]
    pub removed_chirho: bool,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppStaticAssetSelectionChirho {
    pub record_chirho: AppStaticAssetRecordChirho,
}

fn is_false_chirho(value_chirho: &bool) -> bool {
    !*value_chirho
}

pub const APP_PARAMS_RECORD_SCHEMA_CHIRHO: &str = "app-params-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppParamsRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_chirho: Option<String>,
    pub owner_principal_chirho: String,
    pub params_chirho: HashChirho,
    pub required_chirho: bool,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppParamsSelectionChirho {
    pub params_chirho: HashChirho,
    pub value_chirho: serde_json::Value,
    pub required_chirho: bool,
}

pub const TEMPLATE_REGISTRY_RECORD_SCHEMA_CHIRHO: &str = "template-registry-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateRegistryInputChirho {
    pub template_id_chirho: String,
    pub root_dag_chirho: HashChirho,
    pub response_content_type_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateRegistryTargetChirho {
    pub template_id_chirho: String,
    pub root_dag_chirho: HashChirho,
    pub response_content_type_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateRegistryRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub template_id_chirho: String,
    pub root_dag_chirho: HashChirho,
    pub response_content_type_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub const CLIENT_OWNER_BINDING_RECORD_SCHEMA_CHIRHO: &str = "client-owner-binding-v1-chirho";
pub const CLIENT_OWNER_BINDING_ACTIVE_STATUS_CHIRHO: &str = "active-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientOwnerBindingRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub user_principal_chirho: String,
    pub owner_principal_chirho: String,
    pub status_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub const TEMPLATE_APP_DEPLOY_RECORD_SCHEMA_CHIRHO: &str = "template-app-deploy-record-v1-chirho";
pub const TEMPLATE_APP_DEPLOY_RESPONSE_SCHEMA_CHIRHO: &str =
    "template-app-deploy-response-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateAppDeployRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub user_principal_chirho: String,
    pub owner_principal_chirho: String,
    pub template_id_chirho: String,
    pub app_chirho: String,
    pub display_slug_chirho: String,
    pub root_dag_chirho: HashChirho,
    pub params_chirho: HashChirho,
    pub request_payload_chirho: HashChirho,
    pub idempotency_key_hash_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_usage_seq_chirho: Option<u64>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateAppDeployResponseChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub url_chirho: String,
    pub owner_principal_chirho: String,
    pub user_principal_chirho: String,
    pub template_id_chirho: String,
    pub display_slug_chirho: String,
    pub params_chirho: HashChirho,
    pub deploy_record_seq_chirho: u64,
}

pub const APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO: &str = "app-deploy-manifest-v1-chirho";
pub const APP_DEPLOY_MANIFEST_REPORT_SCHEMA_CHIRHO: &str = "app-deploy-manifest-report-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDeployManifestChirho {
    #[serde(default = "app_deploy_manifest_schema_chirho")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_access_policy_chirho: Option<AppRequestAccessPolicyChirho>,
    #[serde(default)]
    pub root_chirho: Option<AppDeployDagSourceChirho>,
    #[serde(default)]
    pub input_mode_chirho: Option<AppInputModeChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_chirho: Option<AppDeployParamsManifestChirho>,
    #[serde(default)]
    pub routes_chirho: Vec<AppDeployRouteManifestChirho>,
    #[serde(default)]
    pub runtime_packages_chirho: Vec<AppDeployRuntimePackageManifestChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDeployRouteManifestChirho {
    pub route_chirho: String,
    pub source_chirho: AppDeployDagSourceChirho,
    #[serde(default)]
    pub input_mode_chirho: Option<AppInputModeChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_access_chirho: Option<AppRouteKeyAccessChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_chirho: Option<AppDeployParamsManifestChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDeployRuntimePackageManifestChirho {
    pub module_chirho: HashChirho,
    pub profile_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDeployParamsManifestChirho {
    pub hash_chirho: HashChirho,
    #[serde(default)]
    pub required_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppDeployDagSourceChirho {
    DagChirho { hash_chirho: HashChirho },
    ModuleChirho { hash_chirho: HashChirho },
    CompositionChirho { hash_chirho: HashChirho },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDeployManifestReportChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_access_policy_chirho: Option<AppRequestAccessPolicyChirho>,
    pub root_dag_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
    pub routes_chirho: Vec<AppDeployRouteReportChirho>,
    pub runtime_packages_chirho: Vec<AppDeployRuntimePackageReportChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDeployRouteReportChirho {
    pub route_chirho: String,
    pub dag_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_access_chirho: Option<AppRouteKeyAccessChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDeployRuntimePackageReportChirho {
    pub module_chirho: HashChirho,
    pub profile_chirho: RuntimeProfileKindChirho,
    pub package_chirho: HashChirho,
    pub executable_chirho: HashChirho,
}

fn app_deploy_manifest_schema_chirho() -> String {
    APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string()
}

pub const APP_SOURCE_MANIFEST_SCHEMA_CHIRHO: &str = "app-source-manifest-v1-chirho";
pub const APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO: &str = "app-source-deploy-report-v1-chirho";
pub const APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO: &str = "app-source-candidate-report-v1-chirho";
pub const APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO: &str = "app-source-review-report-v1-chirho";
pub const APP_SOURCE_BUILTIN_NODE_TEMPLATE_CHIRHO: &str = "node-template-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceManifestChirho {
    #[serde(default = "app_source_manifest_schema_chirho")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_chirho: String,
    #[serde(default)]
    pub nodes_chirho: Vec<AppSourceNodeManifestChirho>,
    #[serde(default)]
    pub dags_chirho: Vec<AppSourceDagManifestChirho>,
    #[serde(default)]
    pub modules_chirho: Vec<AppSourceModuleManifestChirho>,
    #[serde(default)]
    pub assets_chirho: Vec<AppSourceAssetManifestChirho>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contract_refs_chirho: Vec<String>,
    pub deploy_chirho: AppSourceDeployManifestChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceNodeManifestChirho {
    pub id_chirho: String,
    pub name_chirho: String,
    #[serde(default)]
    pub entry_chirho: Option<String>,
    #[serde(default = "default_node_fuel_chirho")]
    pub fuel_chirho: u64,
    #[serde(default)]
    pub capabilities_chirho: Vec<String>,
    pub source_chirho: AppSourceNodeSourceChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppSourceNodeSourceChirho {
    PathChirho {
        path_chirho: PathBuf,
    },
    StoredNodeChirho {
        hash_chirho: HashChirho,
    },
    BuiltinNodeTemplateChirho {
        template_chirho: String,
    },
    CargoExampleChirho {
        package_chirho: String,
        example_chirho: String,
        #[serde(default)]
        features_chirho: Vec<String>,
        #[serde(default)]
        manifest_path_chirho: Option<PathBuf>,
        #[serde(default)]
        target_chirho: Option<String>,
        artifact_path_chirho: PathBuf,
    },
    BuiltinPhiChirho {
        input_ports_chirho: Vec<String>,
        #[serde(default = "default_phi_output_port_chirho")]
        output_port_chirho: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceDagManifestChirho {
    pub id_chirho: String,
    pub nodes_chirho: Vec<String>,
    #[serde(default)]
    pub edges_chirho: Vec<AppSourceDagEdgeManifestChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceDagEdgeManifestChirho {
    pub from_node_chirho: String,
    pub from_port_chirho: String,
    pub to_node_chirho: String,
    pub to_port_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_chirho: Option<EdgePrivacyChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceModuleManifestChirho {
    pub id_chirho: String,
    pub dag_chirho: String,
    pub name_chirho: String,
    #[serde(default = "default_module_version_chirho")]
    pub version_chirho: String,
    #[serde(default)]
    pub previous_module_chirho: Option<HashChirho>,
    #[serde(default)]
    pub input_bindings_chirho: Vec<AppSourceModuleBindingManifestChirho>,
    #[serde(default)]
    pub output_bindings_chirho: Vec<AppSourceModuleBindingManifestChirho>,
    #[serde(default)]
    pub route_labels_chirho: Vec<String>,
    #[serde(default)]
    pub metadata_chirho: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subscription_views_chirho: Vec<SubscriptionViewDeclarationChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceModuleBindingManifestChirho {
    pub public_name_chirho: String,
    pub node_chirho: String,
    pub node_port_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceAssetManifestChirho {
    pub name_chirho: String,
    pub content_type_chirho: String,
    pub source_chirho: AppSourceAssetSourceChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppSourceAssetSourceChirho {
    PathChirho {
        path_chirho: PathBuf,
    },
    StoredAssetChirho {
        hash_chirho: HashChirho,
        byte_len_chirho: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceDeployManifestChirho {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_access_policy_chirho: Option<AppRequestAccessPolicyChirho>,
    #[serde(default)]
    pub root_chirho: Option<AppSourceDeploySourceChirho>,
    #[serde(default)]
    pub input_mode_chirho: Option<AppInputModeChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_chirho: Option<AppDeployParamsManifestChirho>,
    #[serde(default)]
    pub routes_chirho: Vec<AppSourceDeployRouteManifestChirho>,
    #[serde(default)]
    pub runtime_packages_chirho: Vec<AppSourceRuntimePackageManifestChirho>,
    #[serde(default = "default_deploy_target_chirho")]
    pub target_chirho: AppSourceDeployTargetChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceDeployRouteManifestChirho {
    pub route_chirho: String,
    pub source_chirho: AppSourceDeploySourceChirho,
    #[serde(default)]
    pub input_mode_chirho: Option<AppInputModeChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_access_chirho: Option<AppRouteKeyAccessChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_chirho: Option<AppDeployParamsManifestChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceRuntimePackageManifestChirho {
    pub module_chirho: AppSourceModuleRefChirho,
    pub profile_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppSourceDeployTargetChirho {
    LocalDeployChirho,
    LocalInstallChirho {
        root_chirho: PathBuf,
    },
    HttpPublishChirho {
        server_chirho: String,
        #[serde(default)]
        token_chirho: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppSourceDeploySourceChirho {
    DagIdChirho { id_chirho: String },
    ModuleIdChirho { id_chirho: String },
    StoredDagChirho { hash_chirho: HashChirho },
    StoredModuleChirho { hash_chirho: HashChirho },
    StoredCompositionChirho { hash_chirho: HashChirho },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppSourceModuleRefChirho {
    ModuleIdChirho { id_chirho: String },
    StoredModuleChirho { hash_chirho: HashChirho },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceDeployReportChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    #[serde(default, skip_serializing_if = "bool_is_false_chirho")]
    pub unreviewed_dev_chirho: bool,
    pub app_chirho: String,
    pub owner_chirho: String,
    pub nodes_chirho: Vec<AppSourceNodeReportChirho>,
    pub dags_chirho: Vec<AppSourceDagReportChirho>,
    pub modules_chirho: Vec<AppSourceModuleReportChirho>,
    #[serde(default)]
    pub assets_chirho: Vec<AppSourceAssetReportChirho>,
    #[serde(default)]
    pub deploy_chirho: Option<AppDeployManifestReportChirho>,
    #[serde(default)]
    pub package_chirho: Option<AppSourcePackageReportChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_plan_bindings_chirho: Option<Vec<AppSourceUndoPlanBindingChirho>>,
    pub target_chirho: AppSourceDeployTargetReportChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceCandidateReportChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_manifest_chirho: Option<AppSourceManifestEvidenceChirho>,
    pub app_chirho: String,
    pub owner_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_access_policy_chirho: Option<AppRequestAccessPolicyChirho>,
    pub nodes_chirho: Vec<AppSourceNodeReportChirho>,
    pub dags_chirho: Vec<AppSourceDagReportChirho>,
    pub modules_chirho: Vec<AppSourceModuleReportChirho>,
    #[serde(default)]
    pub assets_chirho: Vec<AppSourceAssetReportChirho>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contract_refs_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_plan_bindings_chirho: Option<Vec<AppSourceUndoPlanBindingChirho>>,
    pub root_dag_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mode_chirho: Option<AppInputModeChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
    #[serde(default)]
    pub routes_chirho: Vec<AppSourceCandidateRouteReportChirho>,
}

/// One exact stored executable DAG and its canonical, authority-inert static undo-plan artifact.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSourceUndoPlanBindingChirho {
    pub dag_chirho: HashChirho,
    pub plan_cas_chirho: HashChirho,
    pub plan_digest_chirho: HashChirho,
    pub contract_set_digest_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceManifestEvidenceChirho {
    pub effective_manifest_hash_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_manifest_hash_chirho: Option<HashChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceReviewReportChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_review_report_chirho: Option<HashChirho>,
    pub candidate_chirho: AppSourceCandidateReportChirho,
    pub review_chirho: ReviewSurfaceDiffChirho,
    pub non_authoritative_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceCandidateRouteReportChirho {
    pub route_chirho: String,
    pub dag_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mode_chirho: Option<AppInputModeChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    /// Carried through review and promote, and skipped when absent so every report hashed before it keeps its hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_access_chirho: Option<AppRouteKeyAccessChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceNodeReportChirho {
    pub id_chirho: String,
    pub node_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceDagReportChirho {
    pub id_chirho: String,
    pub dag_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceModuleReportChirho {
    pub id_chirho: String,
    pub module_chirho: HashChirho,
    pub dag_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subscription_views_chirho: Vec<SubscriptionViewDeclarationReportChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourceAssetReportChirho {
    pub name_chirho: String,
    pub asset_chirho: HashChirho,
    pub content_type_chirho: String,
    pub byte_len_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSourcePackageReportChirho {
    pub package_hash_chirho: HashChirho,
    pub app_chirho: String,
    pub owner_chirho: String,
    pub dag_chirho: HashChirho,
    #[serde(default)]
    pub runtime_packages_chirho: Vec<HashChirho>,
    pub objects_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppSourceDeployTargetReportChirho {
    LocalDeployChirho,
    LocalInstallChirho {
        root_chirho: PathBuf,
        objects_installed_chirho: usize,
    },
    HttpPublishChirho {
        server_chirho: String,
        status_chirho: u16,
        response_chirho: String,
    },
}

fn app_source_manifest_schema_chirho() -> String {
    APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string()
}

fn default_node_fuel_chirho() -> u64 {
    1_000_000
}

fn default_module_version_chirho() -> String {
    "v1".to_string()
}

fn default_phi_output_port_chirho() -> String {
    "out".to_string()
}

fn default_deploy_target_chirho() -> AppSourceDeployTargetChirho {
    AppSourceDeployTargetChirho::LocalDeployChirho
}

pub fn validate_app_source_id_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.is_empty() {
        bail!("{name_chirho} cannot be empty");
    }
    if !value_chirho.chars().all(|char_chirho| {
        char_chirho.is_ascii_alphanumeric() || char_chirho == '_' || char_chirho == '-'
    }) {
        bail!("{name_chirho} '{value_chirho}' must contain only ASCII letters, digits, '_' or '-'");
    }
    Ok(())
}

pub fn resolve_app_source_path_chirho(base_chirho: &Path, path_chirho: &Path) -> PathBuf {
    if path_chirho.is_absolute() {
        path_chirho.to_path_buf()
    } else {
        base_chirho.join(path_chirho)
    }
}

pub fn validate_app_source_deploy_report_schema_chirho(
    report_chirho: &AppSourceDeployReportChirho,
) -> Result<()> {
    if !report_chirho.schema_chirho.is_empty()
        && report_chirho.schema_chirho != APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported app source deploy report schema '{}'",
            report_chirho.schema_chirho
        );
    }
    if let Some(deploy_chirho) = &report_chirho.deploy_chirho {
        validate_app_deploy_manifest_report_schema_chirho(deploy_chirho)?;
    }
    if let Some(bindings_chirho) = &report_chirho.undo_plan_bindings_chirho {
        validate_undo_plan_bindings_shape_chirho(bindings_chirho)?;
    }
    Ok(())
}

pub fn validate_app_deploy_manifest_report_schema_chirho(
    report_chirho: &AppDeployManifestReportChirho,
) -> Result<()> {
    if !report_chirho.schema_chirho.is_empty()
        && report_chirho.schema_chirho != APP_DEPLOY_MANIFEST_REPORT_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported app deploy manifest report schema '{}'",
            report_chirho.schema_chirho
        );
    }
    Ok(())
}

pub fn validate_app_source_candidate_report_schema_chirho(
    report_chirho: &AppSourceCandidateReportChirho,
) -> Result<()> {
    if !report_chirho.schema_chirho.is_empty()
        && report_chirho.schema_chirho != APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported app source candidate report schema '{}'",
            report_chirho.schema_chirho
        );
    }
    if let Some(bindings_chirho) = &report_chirho.undo_plan_bindings_chirho {
        validate_undo_plan_bindings_shape_chirho(bindings_chirho)?;
    }
    Ok(())
}

fn validate_undo_plan_bindings_shape_chirho(
    bindings_chirho: &[AppSourceUndoPlanBindingChirho],
) -> Result<()> {
    if bindings_chirho.is_empty() {
        bail!("plan-bearing app source report has an empty undo-plan binding list");
    }
    if bindings_chirho
        .windows(2)
        .any(|pair_chirho| pair_chirho[0].dag_chirho >= pair_chirho[1].dag_chirho)
    {
        bail!("app source undo-plan bindings must be strictly sorted by unique DAG hash");
    }
    Ok(())
}

pub fn validate_builtin_phi_ports_chirho(
    input_ports_chirho: &[String],
    output_port_chirho: &str,
) -> Result<()> {
    if input_ports_chirho.is_empty() {
        bail!("builtin phi node must declare at least one input port");
    }
    let mut seen_chirho = BTreeSet::new();
    for input_port_chirho in input_ports_chirho {
        validate_app_source_id_chirho("builtin phi input port", input_port_chirho)?;
        if !seen_chirho.insert(input_port_chirho) {
            bail!("duplicate builtin phi input port '{input_port_chirho}'");
        }
    }
    validate_app_source_id_chirho("builtin phi output port", output_port_chirho)
}

pub fn validate_app_name_chirho(app_chirho: &str) -> Result<()> {
    if app_chirho.trim().is_empty() {
        bail!("app_chirho is required");
    }
    if app_chirho.contains('/') || app_chirho.chars().any(char::is_whitespace) {
        bail!("app_chirho must not contain slashes or whitespace");
    }
    Ok(())
}

pub fn validate_route_name_chirho(route_chirho: &str) -> Result<()> {
    if route_chirho.trim().is_empty() {
        bail!("route_chirho is required");
    }
    if route_chirho.contains('/') || route_chirho.chars().any(char::is_whitespace) {
        bail!("route_chirho must not contain slashes or whitespace");
    }
    Ok(())
}

pub fn normalize_app_route_response_content_type_chirho(
    response_content_type_chirho: &str,
) -> Result<String> {
    normalize_app_response_content_type_chirho(response_content_type_chirho)
}

/// The one HTML answer type a verified app or route can carry: the normalized form of `text/html`. A
/// check for "answers HTML" compares to it exactly, never by prefix.
pub const APP_RESPONSE_HTML_CONTENT_TYPE_CHIRHO: &str = "text/html; charset=utf-8";

pub fn normalize_app_response_content_type_chirho(
    response_content_type_chirho: &str,
) -> Result<String> {
    if response_content_type_chirho
        .chars()
        .any(|char_chirho| char_chirho.is_control())
    {
        bail!("response_content_type_chirho must not contain control characters");
    }
    let value_chirho = response_content_type_chirho.trim().to_ascii_lowercase();
    match value_chirho.as_str() {
        "text/html" | "text/html; charset=utf-8" => {
            Ok(APP_RESPONSE_HTML_CONTENT_TYPE_CHIRHO.to_string())
        }
        "text/plain" | "text/plain; charset=utf-8" => Ok("text/plain; charset=utf-8".to_string()),
        "application/json" | "application/json; charset=utf-8" => {
            Ok("application/json; charset=utf-8".to_string())
        }
        _ => bail!(
            "response_content_type_chirho must be one of text/html, text/plain, or application/json"
        ),
    }
}

pub fn normalize_app_static_asset_content_type_chirho(content_type_chirho: &str) -> Result<String> {
    if content_type_chirho
        .chars()
        .any(|char_chirho| char_chirho.is_control())
    {
        bail!("asset content_type_chirho must not contain control characters");
    }
    match content_type_chirho.trim().to_ascii_lowercase().as_str() {
        "text/css" | "text/css; charset=utf-8" => {
            Ok(APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO.to_string())
        }
        "image/png" => Ok(APP_STATIC_ASSET_PNG_CONTENT_TYPE_CHIRHO.to_string()),
        "image/jpeg" => Ok(APP_STATIC_ASSET_JPEG_CONTENT_TYPE_CHIRHO.to_string()),
        "application/pdf" => Ok(APP_STATIC_ASSET_PDF_CONTENT_TYPE_CHIRHO.to_string()),
        "font/woff" | "application/font-woff" => {
            Ok(APP_STATIC_ASSET_WOFF_CONTENT_TYPE_CHIRHO.to_string())
        }
        "font/woff2" => Ok(APP_STATIC_ASSET_WOFF2_CONTENT_TYPE_CHIRHO.to_string()),
        _ => bail!(
            "asset content_type_chirho must be one of text/css, image/png, image/jpeg, application/pdf, font/woff, or font/woff2"
        ),
    }
}

pub fn validate_app_static_asset_name_chirho(name_chirho: &str) -> Result<()> {
    if name_chirho.trim().is_empty() {
        bail!("asset name_chirho is required");
    }
    if name_chirho.len() > 128 {
        bail!("asset name_chirho is too long");
    }
    if name_chirho != name_chirho.trim() {
        bail!("asset name_chirho must not have surrounding whitespace");
    }
    if name_chirho == "." || name_chirho == ".." {
        bail!("asset name_chirho must not be '.' or '..'");
    }
    if !name_chirho.chars().all(|char_chirho| {
        char_chirho.is_ascii_alphanumeric()
            || char_chirho == '-'
            || char_chirho == '_'
            || char_chirho == '.'
    }) {
        bail!("asset name_chirho must contain only ASCII letters, digits, '-', '_' or '.'");
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests_chirho/lib_tests_chirho.rs"]
mod tests_chirho;
