// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure lowering helpers from source-review app records to deploy manifests.

use crate::*;
use anyhow::Result;
use cairn_core_chirho::model_chirho::HashChirho;
use std::collections::BTreeMap;

pub fn lower_app_source_deploy_manifest_chirho(
    manifest_chirho: &AppSourceManifestChirho,
    dag_hashes_chirho: &BTreeMap<String, HashChirho>,
    module_hashes_chirho: &BTreeMap<String, HashChirho>,
) -> Result<AppDeployManifestChirho> {
    Ok(AppDeployManifestChirho {
        schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: manifest_chirho.app_chirho.clone(),
        owner_chirho: manifest_chirho.owner_chirho.clone(),
        request_access_policy_chirho: manifest_chirho
            .deploy_chirho
            .request_access_policy_chirho
            .clone(),
        root_chirho: manifest_chirho
            .deploy_chirho
            .root_chirho
            .as_ref()
            .map(|source_chirho| {
                lower_app_source_deploy_source_chirho(
                    source_chirho,
                    dag_hashes_chirho,
                    module_hashes_chirho,
                )
            })
            .transpose()?,
        input_mode_chirho: manifest_chirho.deploy_chirho.input_mode_chirho.clone(),
        request_body_policy_chirho: manifest_chirho
            .deploy_chirho
            .request_body_policy_chirho
            .clone(),
        response_content_type_chirho: manifest_chirho
            .deploy_chirho
            .response_content_type_chirho
            .as_deref()
            .map(normalize_app_response_content_type_chirho)
            .transpose()?,
        params_chirho: manifest_chirho.deploy_chirho.params_chirho.clone(),
        routes_chirho: manifest_chirho
            .deploy_chirho
            .routes_chirho
            .iter()
            .map(|route_chirho| {
                Ok(AppDeployRouteManifestChirho {
                    route_chirho: route_chirho.route_chirho.clone(),
                    source_chirho: lower_app_source_deploy_source_chirho(
                        &route_chirho.source_chirho,
                        dag_hashes_chirho,
                        module_hashes_chirho,
                    )?,
                    input_mode_chirho: route_chirho.input_mode_chirho.clone(),
                    request_body_policy_chirho: route_chirho.request_body_policy_chirho.clone(),
                    key_access_chirho: route_chirho.key_access_chirho.clone(),
                    response_content_type_chirho: route_chirho
                        .response_content_type_chirho
                        .as_deref()
                        .map(normalize_app_route_response_content_type_chirho)
                        .transpose()?,
                    params_chirho: route_chirho.params_chirho.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        runtime_packages_chirho: manifest_chirho
            .deploy_chirho
            .runtime_packages_chirho
            .iter()
            .map(|package_chirho| {
                Ok(AppDeployRuntimePackageManifestChirho {
                    module_chirho: lower_app_source_module_ref_chirho(
                        &package_chirho.module_chirho,
                        module_hashes_chirho,
                    )?,
                    profile_chirho: package_chirho.profile_chirho.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

pub fn reviewed_app_source_deploy_manifest_chirho(
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
) -> AppDeployManifestChirho {
    let candidate_chirho = &report_chirho.candidate_chirho;
    AppDeployManifestChirho {
        schema_chirho: APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: candidate_chirho.app_chirho.clone(),
        owner_chirho: owner_chirho.to_string(),
        request_access_policy_chirho: candidate_chirho.request_access_policy_chirho.clone(),
        root_chirho: Some(AppDeployDagSourceChirho::DagChirho {
            hash_chirho: candidate_chirho.root_dag_chirho.clone(),
        }),
        input_mode_chirho: candidate_chirho.input_mode_chirho.clone(),
        request_body_policy_chirho: candidate_chirho.request_body_policy_chirho.clone(),
        response_content_type_chirho: candidate_chirho.response_content_type_chirho.clone(),
        params_chirho: None,
        routes_chirho: candidate_chirho
            .routes_chirho
            .iter()
            .map(|route_chirho| AppDeployRouteManifestChirho {
                route_chirho: route_chirho.route_chirho.clone(),
                source_chirho: AppDeployDagSourceChirho::DagChirho {
                    hash_chirho: route_chirho.dag_chirho.clone(),
                },
                input_mode_chirho: route_chirho.input_mode_chirho.clone(),
                request_body_policy_chirho: route_chirho.request_body_policy_chirho.clone(),
                key_access_chirho: route_chirho.key_access_chirho.clone(),
                response_content_type_chirho: route_chirho.response_content_type_chirho.clone(),
                params_chirho: None,
            })
            .collect(),
        runtime_packages_chirho: Vec::new(),
    }
}

fn lower_app_source_deploy_source_chirho(
    source_chirho: &AppSourceDeploySourceChirho,
    dag_hashes_chirho: &BTreeMap<String, HashChirho>,
    module_hashes_chirho: &BTreeMap<String, HashChirho>,
) -> Result<AppDeployDagSourceChirho> {
    match source_chirho {
        AppSourceDeploySourceChirho::DagIdChirho { id_chirho } => {
            Ok(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: resolve_app_source_hash_id_chirho(
                    "dag",
                    dag_hashes_chirho,
                    id_chirho,
                )?,
            })
        }
        AppSourceDeploySourceChirho::ModuleIdChirho { id_chirho } => {
            Ok(AppDeployDagSourceChirho::ModuleChirho {
                hash_chirho: resolve_app_source_hash_id_chirho(
                    "module",
                    module_hashes_chirho,
                    id_chirho,
                )?,
            })
        }
        AppSourceDeploySourceChirho::StoredDagChirho { hash_chirho } => {
            Ok(AppDeployDagSourceChirho::DagChirho {
                hash_chirho: hash_chirho.clone(),
            })
        }
        AppSourceDeploySourceChirho::StoredModuleChirho { hash_chirho } => {
            Ok(AppDeployDagSourceChirho::ModuleChirho {
                hash_chirho: hash_chirho.clone(),
            })
        }
        AppSourceDeploySourceChirho::StoredCompositionChirho { hash_chirho } => {
            Ok(AppDeployDagSourceChirho::CompositionChirho {
                hash_chirho: hash_chirho.clone(),
            })
        }
    }
}

fn lower_app_source_module_ref_chirho(
    module_chirho: &AppSourceModuleRefChirho,
    module_hashes_chirho: &BTreeMap<String, HashChirho>,
) -> Result<HashChirho> {
    match module_chirho {
        AppSourceModuleRefChirho::ModuleIdChirho { id_chirho } => {
            resolve_app_source_hash_id_chirho("module", module_hashes_chirho, id_chirho)
        }
        AppSourceModuleRefChirho::StoredModuleChirho { hash_chirho } => Ok(hash_chirho.clone()),
    }
}

pub fn resolve_app_source_hash_id_chirho(
    kind_chirho: &str,
    map_chirho: &BTreeMap<String, HashChirho>,
    id_chirho: &str,
) -> Result<HashChirho> {
    map_chirho
        .get(id_chirho)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unknown {kind_chirho} id '{id_chirho}'"))
}
