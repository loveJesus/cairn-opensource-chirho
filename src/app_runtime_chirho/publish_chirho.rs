// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Publish — package a dagapp's content-addressed root/route closures, private input policies, and
//! runtime package manifests for install on a running cairn server. Content-addressing makes
//! transfer safe: every object's bytes must hash to its claimed name, or it is rejected.

use crate::model_chirho::{DagChirho, HashChirho};
use crate::{
    app_chirho, app_source_manifest_chirho, cas_chirho, runtime_profile_chirho, store_chirho,
};
use anyhow::{bail, Result};
use cairn_model_app_chirho::AppSourceUndoPlanBindingChirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishObjectChirho {
    pub hash_chirho: String,
    pub bytes_hex_chirho: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishPackageChirho {
    pub name_chirho: String,
    pub owner_chirho: String,
    pub dag_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mode_chirho: Option<app_chirho::AppInputModeChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
    #[serde(default)]
    pub routes_chirho: Vec<PublishRouteChirho>,
    #[serde(default)]
    pub runtime_packages_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_plan_bindings_chirho: Option<Vec<AppSourceUndoPlanBindingChirho>>,
    pub objects_chirho: Vec<PublishObjectChirho>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishRouteChirho {
    pub route_chirho: String,
    pub dag_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mode_chirho: Option<app_chirho::AppInputModeChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<app_chirho::AppRouteRequestBodyPolicyChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_type_chirho: Option<String>,
}

/// Build a publish package: app name + root DAG hash + closure (each object as hex bytes).
pub fn build_package_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    dag_chirho: &HashChirho,
    owner_chirho: &str,
) -> Result<PublishPackageChirho> {
    build_package_with_routes_chirho(
        root_chirho,
        name_chirho,
        dag_chirho,
        owner_chirho,
        None,
        &[],
    )
}

pub fn build_package_with_routes_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    dag_chirho: &HashChirho,
    owner_chirho: &str,
    input_mode_chirho: Option<app_chirho::AppInputModeChirho>,
    routes_chirho: &[PublishRouteChirho],
) -> Result<PublishPackageChirho> {
    build_package_with_routes_and_runtime_chirho(PublishPackageWithRoutesAndRuntimeInputChirho {
        root_chirho,
        name_chirho,
        dag_chirho,
        owner_chirho,
        input_mode_chirho,
        response_content_type_chirho: None,
        routes_chirho,
        runtime_packages_chirho: &[],
    })
}

pub struct PublishPackageWithRoutesAndRuntimeInputChirho<'a> {
    pub root_chirho: &'a Path,
    pub name_chirho: &'a str,
    pub dag_chirho: &'a HashChirho,
    pub owner_chirho: &'a str,
    pub input_mode_chirho: Option<app_chirho::AppInputModeChirho>,
    pub response_content_type_chirho: Option<String>,
    pub routes_chirho: &'a [PublishRouteChirho],
    pub runtime_packages_chirho: &'a [HashChirho],
}

pub fn build_package_with_routes_and_runtime_chirho(
    input_chirho: PublishPackageWithRoutesAndRuntimeInputChirho<'_>,
) -> Result<PublishPackageChirho> {
    let PublishPackageWithRoutesAndRuntimeInputChirho {
        root_chirho,
        name_chirho,
        dag_chirho,
        owner_chirho,
        input_mode_chirho,
        response_content_type_chirho,
        routes_chirho,
        runtime_packages_chirho,
    } = input_chirho;
    app_chirho::validate_app_name_chirho(name_chirho)?;
    if let Some(mode_chirho) = &input_mode_chirho {
        app_chirho::validate_app_input_mode_chirho(mode_chirho)?;
    }
    if let Some(response_content_type_chirho) = &response_content_type_chirho {
        app_chirho::normalize_app_response_content_type_chirho(response_content_type_chirho)?;
    }
    let _root_dag_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_chirho)?;
    let mut closure_chirho =
        crate::object_graph_chirho::gather_closure_chirho(root_chirho, dag_chirho)?;
    for route_chirho in routes_chirho {
        app_chirho::validate_route_name_chirho(&route_chirho.route_chirho)?;
        if let Some(mode_chirho) = &route_chirho.input_mode_chirho {
            app_chirho::validate_app_input_mode_chirho(mode_chirho)?;
        }
        if let Some(response_content_type_chirho) = &route_chirho.response_content_type_chirho {
            app_chirho::normalize_app_route_response_content_type_chirho(
                response_content_type_chirho,
            )?;
        }
        let route_dag_hash_chirho = HashChirho(route_chirho.dag_chirho.clone());
        let _route_dag_chirho: DagChirho =
            store_chirho::get_object_chirho(root_chirho, &route_dag_hash_chirho)?;
        closure_chirho.extend(crate::object_graph_chirho::gather_closure_chirho(
            root_chirho,
            &route_dag_hash_chirho,
        )?);
    }
    for runtime_package_chirho in runtime_packages_chirho {
        let package_chirho: runtime_profile_chirho::RuntimePackageChirho =
            store_chirho::get_object_chirho(root_chirho, runtime_package_chirho)?;
        for object_hash_chirho in &package_chirho.object_hashes_chirho {
            cas_chirho::get_chirho(root_chirho, object_hash_chirho)?;
        }
        runtime_profile_chirho::validate_runtime_package_chirho(root_chirho, &package_chirho)?;
        closure_chirho.extend(crate::object_graph_chirho::gather_closure_chirho(
            root_chirho,
            runtime_package_chirho,
        )?);
    }
    let mut seen_chirho = HashSet::new();
    let objects_chirho = closure_chirho
        .into_iter()
        .filter(|(hash_chirho, _bytes_chirho)| seen_chirho.insert(hash_chirho.clone()))
        .map(|(hash_chirho, bytes_chirho)| PublishObjectChirho {
            hash_chirho,
            bytes_hex_chirho: hex_of_chirho(&bytes_chirho),
        })
        .collect();
    Ok(PublishPackageChirho {
        name_chirho: name_chirho.to_string(),
        owner_chirho: owner_chirho.to_string(),
        dag_chirho: dag_chirho.0.clone(),
        input_mode_chirho,
        response_content_type_chirho,
        routes_chirho: routes_chirho.to_vec(),
        runtime_packages_chirho: runtime_packages_chirho
            .iter()
            .map(|hash_chirho| hash_chirho.0.clone())
            .collect(),
        undo_plan_bindings_chirho: None,
        objects_chirho,
    })
}

/// Carries exact descriptor-v2 authority and its immutable plan artifacts with a source package.
/// Workflow: `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` 4.2.1.
pub(crate) fn attach_descriptor_v2_bindings_chirho(
    root_chirho: &Path,
    package_chirho: &mut PublishPackageChirho,
    bindings_chirho: &[AppSourceUndoPlanBindingChirho],
) -> Result<()> {
    let executable_dags_chirho = package_executable_dags_chirho(package_chirho);
    app_source_manifest_chirho::verify_descriptor_v2_deployment_chirho(
        root_chirho,
        &executable_dags_chirho,
        Some(bindings_chirho),
    )?;

    let mut object_hashes_chirho = package_chirho
        .objects_chirho
        .iter()
        .map(|object_chirho| object_chirho.hash_chirho.clone())
        .collect::<HashSet<_>>();
    for binding_chirho in bindings_chirho {
        let plan_bytes_chirho =
            cas_chirho::get_chirho(root_chirho, &binding_chirho.plan_cas_chirho)?;
        if object_hashes_chirho.insert(binding_chirho.plan_cas_chirho.0.clone()) {
            package_chirho.objects_chirho.push(PublishObjectChirho {
                hash_chirho: binding_chirho.plan_cas_chirho.0.clone(),
                bytes_hex_chirho: hex_of_chirho(&plan_bytes_chirho),
            });
        }
    }
    package_chirho.undo_plan_bindings_chirho = Some(bindings_chirho.to_vec());
    Ok(())
}

/// Install a package on this server: verify each object's bytes hash to its claimed name, store
/// it, then deploy `app/<name>`, route refs, and input policies. Returns the object count.
pub fn install_package_chirho(
    root_chirho: &Path,
    package_chirho: &PublishPackageChirho,
) -> Result<usize> {
    app_chirho::validate_app_name_chirho(&package_chirho.name_chirho)?;
    if let Some(mode_chirho) = &package_chirho.input_mode_chirho {
        app_chirho::validate_app_input_mode_chirho(mode_chirho)?;
    }
    if let Some(response_content_type_chirho) = &package_chirho.response_content_type_chirho {
        app_chirho::normalize_app_response_content_type_chirho(response_content_type_chirho)?;
    }
    for route_chirho in &package_chirho.routes_chirho {
        app_chirho::validate_route_name_chirho(&route_chirho.route_chirho)?;
        if let Some(mode_chirho) = &route_chirho.input_mode_chirho {
            app_chirho::validate_app_input_mode_chirho(mode_chirho)?;
        }
        if let Some(response_content_type_chirho) = &route_chirho.response_content_type_chirho {
            app_chirho::normalize_app_route_response_content_type_chirho(
                response_content_type_chirho,
            )?;
        }
    }
    for object_chirho in &package_chirho.objects_chirho {
        let bytes_chirho = hex_to_chirho(&object_chirho.bytes_hex_chirho)?;
        let computed_chirho = cas_chirho::hash_chirho(&bytes_chirho);
        if computed_chirho.0 != object_chirho.hash_chirho {
            bail!(
                "object integrity failure: claimed {} but bytes hash to {}",
                object_chirho.hash_chirho,
                computed_chirho.0
            );
        }
        cas_chirho::add_chirho(root_chirho, &bytes_chirho)?;
    }
    let root_dag_chirho = HashChirho(package_chirho.dag_chirho.clone());
    let _root_dag: DagChirho = store_chirho::get_object_chirho(root_chirho, &root_dag_chirho)?;
    let route_dags_chirho = package_chirho
        .routes_chirho
        .iter()
        .map(|route_chirho| {
            let dag_hash_chirho = HashChirho(route_chirho.dag_chirho.clone());
            let _dag_chirho: DagChirho =
                store_chirho::get_object_chirho(root_chirho, &dag_hash_chirho)?;
            Ok((route_chirho, dag_hash_chirho))
        })
        .collect::<Result<Vec<_>>>()?;
    let executable_dags_chirho = package_executable_dags_chirho(package_chirho);
    app_source_manifest_chirho::verify_descriptor_v2_deployment_chirho(
        root_chirho,
        &executable_dags_chirho,
        package_chirho.undo_plan_bindings_chirho.as_deref(),
    )?;
    for runtime_package_chirho in &package_chirho.runtime_packages_chirho {
        let package_hash_chirho = HashChirho(runtime_package_chirho.clone());
        let package_obj_chirho: runtime_profile_chirho::RuntimePackageChirho =
            store_chirho::get_object_chirho(root_chirho, &package_hash_chirho)?;
        for object_hash_chirho in &package_obj_chirho.object_hashes_chirho {
            cas_chirho::get_chirho(root_chirho, object_hash_chirho)?;
        }
        runtime_profile_chirho::validate_runtime_package_chirho(root_chirho, &package_obj_chirho)?;
    }
    app_chirho::deploy_app_chirho(
        root_chirho,
        &package_chirho.name_chirho,
        root_dag_chirho,
        &package_chirho.owner_chirho,
    )?;
    if let Some(mode_chirho) = &package_chirho.input_mode_chirho {
        app_chirho::set_app_input_policy_chirho(
            root_chirho,
            &package_chirho.name_chirho,
            None,
            &package_chirho.owner_chirho,
            mode_chirho.clone(),
        )?;
    }
    if let Some(response_content_type_chirho) = &package_chirho.response_content_type_chirho {
        app_chirho::set_app_response_policy_chirho(
            root_chirho,
            &package_chirho.name_chirho,
            &package_chirho.owner_chirho,
            response_content_type_chirho,
        )?;
    }
    for (route_chirho, route_dag_hash_chirho) in route_dags_chirho {
        app_chirho::deploy_app_route_with_request_body_policy_chirho(
            root_chirho,
            &package_chirho.name_chirho,
            &route_chirho.route_chirho,
            route_dag_hash_chirho,
            &package_chirho.owner_chirho,
            route_chirho.request_body_policy_chirho.clone(),
            false,
        )?;
        if let Some(mode_chirho) = &route_chirho.input_mode_chirho {
            app_chirho::set_app_input_policy_chirho(
                root_chirho,
                &package_chirho.name_chirho,
                Some(&route_chirho.route_chirho),
                &package_chirho.owner_chirho,
                mode_chirho.clone(),
            )?;
        }
        if let Some(response_content_type_chirho) = &route_chirho.response_content_type_chirho {
            app_chirho::set_app_route_response_policy_chirho(
                root_chirho,
                &package_chirho.name_chirho,
                &route_chirho.route_chirho,
                &package_chirho.owner_chirho,
                response_content_type_chirho,
            )?;
        }
    }
    Ok(package_chirho.objects_chirho.len())
}

fn package_executable_dags_chirho(package_chirho: &PublishPackageChirho) -> BTreeSet<HashChirho> {
    let mut dags_chirho = BTreeSet::from([HashChirho(package_chirho.dag_chirho.clone())]);
    dags_chirho.extend(
        package_chirho
            .routes_chirho
            .iter()
            .map(|route_chirho| HashChirho(route_chirho.dag_chirho.clone())),
    );
    dags_chirho
}

fn hex_of_chirho(bytes_chirho: &[u8]) -> String {
    let mut out_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        out_chirho.push_str(&format!("{byte_chirho:02x}"));
    }
    out_chirho
}

fn hex_to_chirho(hex_chirho: &str) -> Result<Vec<u8>> {
    if !hex_chirho.len().is_multiple_of(2) {
        bail!("hex length must be even");
    }
    (0..hex_chirho.len())
        .step_by(2)
        .map(|i_chirho| {
            u8::from_str_radix(&hex_chirho[i_chirho..i_chirho + 2], 16)
                .map_err(|e_chirho| anyhow::anyhow!("bad hex: {e_chirho}"))
        })
        .collect()
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::model_chirho::{CapabilityChirho, DagChirho, NodeDefChirho, PortChirho};
    use crate::store_chirho;
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
        std::env::temp_dir().join(format!("cairn-publish-test-{nanos_chirho}-{n_chirho}"))
    }

    fn build_dag_chirho(root_chirho: &Path) -> HashChirho {
        let impl_chirho = cas_chirho::add_chirho(
            root_chirho,
            include_str!("../../examples-chirho/upcase-chirho.wat").as_bytes(),
        )
        .unwrap();
        let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
        let node_chirho = NodeDefChirho {
            name_chirho: "upcase_chirho".to_string(),
            impl_wasm_chirho: impl_chirho,
            entry_chirho: "upcase_chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho,
            }],
            capabilities_chirho: vec![],
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        };
        let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
        let dag_chirho = DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        };
        store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap()
    }

    fn build_effectful_legacy_dag_chirho(root_chirho: &Path) -> HashChirho {
        let node_chirho = NodeDefChirho {
            name_chirho: "legacy-package-write-chirho".to_string(),
            capabilities_chirho: vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "apps/legacy-package-chirho".to_string(),
            }],
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

    #[test]
    fn legacy_effectful_package_refuses_before_ref_move_chirho() {
        let source_chirho = tmp_root_chirho();
        let target_chirho = tmp_root_chirho();
        let dag_chirho = build_effectful_legacy_dag_chirho(&source_chirho);
        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &target_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let package_chirho = build_package_chirho(
            &source_chirho,
            "legacy-package-chirho",
            &dag_chirho,
            &owner_chirho,
        )
        .unwrap();
        assert!(package_chirho.undo_plan_bindings_chirho.is_none());

        let error_chirho = install_package_chirho(&target_chirho, &package_chirho).unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("requires complete verified undo-plan bindings"));
        assert!(!crate::refs_chirho::load_refs_chirho(&target_chirho)
            .unwrap()
            .branches_chirho
            .contains_key("app/legacy-package-chirho"));

        let _ = std::fs::remove_dir_all(&source_chirho);
        let _ = std::fs::remove_dir_all(&target_chirho);
    }

    #[test]
    fn package_missing_bound_plan_artifact_refuses_before_ref_move_chirho() {
        let source_chirho = tmp_root_chirho();
        let target_chirho = tmp_root_chirho();
        let dag_chirho = build_dag_chirho(&source_chirho);
        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &target_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let source_manifest_chirho =
            crate::app_source_manifest_chirho::AppSourceManifestChirho {
                schema_chirho:
                    crate::app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
                app_chirho: "missing-plan-package-chirho".to_string(),
                owner_chirho: owner_chirho.clone(),
                nodes_chirho: Vec::new(),
                dags_chirho: Vec::new(),
                modules_chirho: Vec::new(),
                assets_chirho: Vec::new(),
                contract_refs_chirho: Vec::new(),
                deploy_chirho:
                    crate::app_source_manifest_chirho::AppSourceDeployManifestChirho {
                        request_access_policy_chirho: None,
                        request_body_policy_chirho: None,
                        root_chirho: Some(
                            crate::app_source_manifest_chirho::AppSourceDeploySourceChirho::StoredDagChirho {
                                hash_chirho: dag_chirho.clone(),
                            },
                        ),
                        input_mode_chirho: None,
                        response_content_type_chirho: None,
                        params_chirho: None,
                        routes_chirho: Vec::new(),
                        runtime_packages_chirho: Vec::new(),
                        target_chirho:
                            crate::app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
                    },
            };
        let candidate_chirho =
            crate::app_source_manifest_chirho::build_app_source_candidate_chirho(
                &source_chirho,
                Path::new("."),
                &source_manifest_chirho,
            )
            .unwrap();
        let bindings_chirho = candidate_chirho.undo_plan_bindings_chirho.unwrap();
        let mut package_chirho = build_package_chirho(
            &source_chirho,
            "missing-plan-package-chirho",
            &dag_chirho,
            &owner_chirho,
        )
        .unwrap();
        attach_descriptor_v2_bindings_chirho(&source_chirho, &mut package_chirho, &bindings_chirho)
            .unwrap();
        let plan_cas_chirho = bindings_chirho[0].plan_cas_chirho.0.clone();
        package_chirho
            .objects_chirho
            .retain(|object_chirho| object_chirho.hash_chirho != plan_cas_chirho);

        let error_chirho = install_package_chirho(&target_chirho, &package_chirho).unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("load candidate undo-plan CAS artifact"));
        assert!(!crate::refs_chirho::load_refs_chirho(&target_chirho)
            .unwrap()
            .branches_chirho
            .contains_key("app/missing-plan-package-chirho"));

        let _ = std::fs::remove_dir_all(&source_chirho);
        let _ = std::fs::remove_dir_all(&target_chirho);
    }

    #[test]
    fn package_transfers_closure_and_rejects_tamper_chirho() {
        let src_chirho = tmp_root_chirho();
        let dst_chirho = tmp_root_chirho();
        let dag_hash_chirho = build_dag_chirho(&src_chirho);

        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &dst_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let package_chirho =
            build_package_chirho(&src_chirho, "myapp", &dag_hash_chirho, &owner_chirho).unwrap();
        assert!(serde_json::to_value(&package_chirho)
            .unwrap()
            .get("undo_plan_bindings_chirho")
            .is_none());
        // dag + node + impl wasm + schema (at least 3 distinct objects).
        assert!(package_chirho.objects_chirho.len() >= 3);

        // Install into a fresh dst; the app goes live there.
        install_package_chirho(&dst_chirho, &package_chirho).unwrap();
        let refs_chirho = crate::refs_chirho::load_refs_chirho(&dst_chirho).unwrap();
        assert_eq!(
            refs_chirho.branches_chirho.get("app/myapp"),
            Some(&dag_hash_chirho)
        );
        // the DAG object itself transferred:
        let _dag_obj_chirho: DagChirho =
            store_chirho::get_object_chirho(&dst_chirho, &dag_hash_chirho).unwrap();

        // Tampered bytes are rejected (hash mismatch).
        let mut forged_chirho =
            build_package_chirho(&src_chirho, "evil", &dag_hash_chirho, &owner_chirho).unwrap();
        forged_chirho.objects_chirho[0]
            .bytes_hex_chirho
            .push_str("00");
        assert!(install_package_chirho(&dst_chirho, &forged_chirho).is_err());

        let _ = std::fs::remove_dir_all(&src_chirho);
        let _ = std::fs::remove_dir_all(&dst_chirho);
    }

    #[test]
    fn package_installs_routes_and_input_policies_chirho() {
        let src_chirho = tmp_root_chirho();
        let dst_chirho = tmp_root_chirho();
        let root_dag_chirho = build_dag_chirho(&src_chirho);
        let route_dag_chirho = build_dag_chirho(&src_chirho);
        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &dst_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let root_mode_chirho = app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact/root".to_string(),
            safe_metadata_chirho: Vec::new(),
        };
        let route_mode_chirho = app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact/route".to_string(),
            safe_metadata_chirho: Vec::new(),
        };
        let package_chirho = build_package_with_routes_chirho(
            &src_chirho,
            "contact",
            &root_dag_chirho,
            &owner_chirho,
            Some(root_mode_chirho.clone()),
            &[PublishRouteChirho {
                route_chirho: "submit".to_string(),
                dag_chirho: route_dag_chirho.0.clone(),
                input_mode_chirho: Some(route_mode_chirho.clone()),
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
            }],
        )
        .unwrap();

        install_package_chirho(&dst_chirho, &package_chirho).unwrap();
        let status_chirho = app_chirho::app_status_chirho(&dst_chirho, "contact").unwrap();
        assert_eq!(status_chirho.dag_chirho, Some(root_dag_chirho));
        assert_eq!(
            status_chirho.routes_chirho.get("submit"),
            Some(&route_dag_chirho)
        );
        assert_eq!(
            app_chirho::app_input_mode_chirho(&dst_chirho, "contact", None, &owner_chirho).unwrap(),
            root_mode_chirho
        );
        assert_eq!(
            app_chirho::app_input_mode_chirho(
                &dst_chirho,
                "contact",
                Some("submit"),
                &owner_chirho,
            )
            .unwrap(),
            route_mode_chirho
        );

        let _ = std::fs::remove_dir_all(&src_chirho);
        let _ = std::fs::remove_dir_all(&dst_chirho);
    }

    #[test]
    fn package_rejects_missing_route_dag_before_ref_move_chirho() {
        let src_chirho = tmp_root_chirho();
        let dst_chirho = tmp_root_chirho();
        let root_dag_chirho = build_dag_chirho(&src_chirho);
        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &dst_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let mut package_chirho =
            build_package_chirho(&src_chirho, "contact", &root_dag_chirho, &owner_chirho).unwrap();
        package_chirho.routes_chirho.push(PublishRouteChirho {
            route_chirho: "submit".to_string(),
            dag_chirho: "0".repeat(64),
            input_mode_chirho: None,
            request_body_policy_chirho: None,
            response_content_type_chirho: None,
        });

        assert!(install_package_chirho(&dst_chirho, &package_chirho).is_err());
        let status_chirho = app_chirho::app_status_chirho(&dst_chirho, "contact").unwrap();
        assert!(!status_chirho.active_chirho);

        let _ = std::fs::remove_dir_all(&src_chirho);
        let _ = std::fs::remove_dir_all(&dst_chirho);
    }

    #[test]
    fn package_rejects_missing_runtime_package_before_ref_move_chirho() {
        let src_chirho = tmp_root_chirho();
        let dst_chirho = tmp_root_chirho();
        let root_dag_chirho = build_dag_chirho(&src_chirho);
        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &dst_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let mut package_chirho =
            build_package_chirho(&src_chirho, "contact", &root_dag_chirho, &owner_chirho).unwrap();
        package_chirho.runtime_packages_chirho.push("0".repeat(64));

        assert!(install_package_chirho(&dst_chirho, &package_chirho).is_err());
        let status_chirho = app_chirho::app_status_chirho(&dst_chirho, "contact").unwrap();
        assert!(!status_chirho.active_chirho);

        let _ = std::fs::remove_dir_all(&src_chirho);
        let _ = std::fs::remove_dir_all(&dst_chirho);
    }
}
