// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Builds the per-app API descriptor — the agent-readable route map with each route's input mode and capability verdict — from verified app records and DAG capabilities; the descriptor DTO itself lives in `cairn-app-docs-chirho`.

use crate::{app_chirho, capability_plain_chirho};
use anyhow::{bail, Result};
use cairn_model_app_chirho::app_policy_chirho::{
    app_input_mode_descriptor_resolution_chirho, AppInputModeResolutionChirho,
};
use std::path::Path;

pub use cairn_app_docs_chirho::app_descriptor_chirho::{
    AppDescriptorChirho, AppRouteDescriptorChirho,
};

fn input_mode_label_chirho(mode_chirho: &app_chirho::AppInputModeChirho) -> String {
    match mode_chirho {
        app_chirho::AppInputModeChirho::PlainChirho => "plain".to_string(),
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho { .. } => {
            "private-encrypted".to_string()
        }
    }
}

fn route_descriptor_chirho(
    root_chirho: &Path,
    input_policy_records_chirho: &[app_chirho::AppInputPolicyRecordChirho],
    app_chirho: &str,
    owner_principal_chirho: &str,
    route_chirho: Option<&str>,
    dag_chirho: &crate::model_chirho::HashChirho,
) -> Result<AppRouteDescriptorChirho> {
    let capabilities_chirho = crate::dag_capability_scan_chirho::collect_dag_capabilities_chirho(
        root_chirho,
        dag_chirho,
    )?;
    let capability_summary_chirho =
        capability_plain_chirho::summarize_capabilities_chirho(&capabilities_chirho);
    // A surface whose VERIFIED history proves no applicable signed input policy is honestly
    // "unset" (not body-ready yet). Verifier failure never reaches here — the caller fails the
    // whole descriptor closed — and an anomalous verified history (an illegal Plain-after-Private
    // downgrade record) makes the descriptor unavailable rather than rendering a benign label.
    let input_mode_chirho = match app_input_mode_descriptor_resolution_chirho(
        input_policy_records_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
    ) {
        AppInputModeResolutionChirho::SetChirho(mode_chirho) => {
            input_mode_label_chirho(&mode_chirho)
        }
        AppInputModeResolutionChirho::UnsetChirho => "unset".to_string(),
        AppInputModeResolutionChirho::RefusedDowngradeChirho => {
            let label_chirho = route_chirho.unwrap_or(app_chirho);
            bail!(
                "app descriptor unavailable: input surface '{label_chirho}' has an anomalous signed policy history (Plain after PrivateBlobRef)"
            );
        }
    };
    let response_content_type_chirho = match route_chirho {
        Some(route_chirho) => app_chirho::app_route_response_content_type_chirho(
            root_chirho,
            app_chirho,
            route_chirho,
            owner_principal_chirho,
        )?,
        None => None,
    };
    let path_chirho = match route_chirho {
        Some(route_chirho) => format!("/app-chirho/{app_chirho}/{route_chirho}"),
        None => format!("/app-chirho/{app_chirho}"),
    };
    Ok(AppRouteDescriptorChirho {
        path_chirho,
        route_chirho: route_chirho.map(|r_chirho| r_chirho.to_string()),
        input_mode_chirho,
        response_content_type_chirho,
        capability_summary_chirho,
    })
}

/// Build the agent-readable descriptor for a deployed app (or None when it is not deployed).
/// Read-only over verified content-addressed objects and signed app records; a signed
/// input-policy log that fails verification makes the descriptor UNAVAILABLE (fail closed),
/// never a plausible benign one.
pub fn app_descriptor_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<AppDescriptorChirho>> {
    let status_chirho = app_chirho::app_status_chirho(root_chirho, app_chirho)?;
    let (Some(root_dag_chirho), Some(owner_principal_chirho)) = (
        &status_chirho.dag_chirho,
        &status_chirho.owner_principal_chirho,
    ) else {
        return Ok(None);
    };
    let input_policy_records_chirho =
        app_chirho::verified_app_input_policy_records_chirho(root_chirho)?;
    let mut routes_chirho = Vec::new();
    routes_chirho.push(route_descriptor_chirho(
        root_chirho,
        &input_policy_records_chirho,
        app_chirho,
        owner_principal_chirho,
        None,
        root_dag_chirho,
    )?);
    for (route_chirho, route_dag_chirho) in &status_chirho.routes_chirho {
        routes_chirho.push(route_descriptor_chirho(
            root_chirho,
            &input_policy_records_chirho,
            app_chirho,
            owner_principal_chirho,
            Some(route_chirho),
            route_dag_chirho,
        )?);
    }
    Ok(Some(AppDescriptorChirho {
        schema_chirho: "app-descriptor-v1-chirho".to_string(),
        app_chirho: app_chirho.to_string(),
        active_chirho: status_chirho.active_chirho,
        route_count_chirho: routes_chirho.len(),
        routes_chirho,
    }))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::model_chirho::{CapabilityChirho, DagChirho, NodeDefChirho, PortChirho};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-app-descriptor-test-{n_chirho}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d_chirho| d_chirho.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    fn writer_dag_chirho(root_chirho: &Path) -> crate::model_chirho::HashChirho {
        let schema_chirho = crate::cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
        let wasm_chirho = crate::cas_chirho::add_chirho(root_chirho, b"node").unwrap();
        let node_chirho = crate::store_chirho::put_object_chirho(
            root_chirho,
            &NodeDefChirho {
                name_chirho: "w".to_string(),
                impl_wasm_chirho: wasm_chirho,
                entry_chirho: "w".to_string(),
                inputs_chirho: vec![PortChirho {
                    name_chirho: "in".to_string(),
                    schema_chirho: schema_chirho.clone(),
                }],
                outputs_chirho: vec![PortChirho {
                    name_chirho: "out".to_string(),
                    schema_chirho,
                }],
                capabilities_chirho: vec![CapabilityChirho::WriteStoreChirho {
                    prefix_chirho: "contact/".to_string(),
                }],
                fuel_limit_chirho: 1,
                ..Default::default()
            },
        )
        .unwrap();
        crate::store_chirho::put_object_chirho(
            root_chirho,
            &DagChirho {
                nodes_chirho: vec![node_chirho],
                edges_chirho: vec![],
            },
        )
        .unwrap()
    }

    #[test]
    fn descriptor_lists_root_and_routes_with_verdicts_chirho() {
        let root_chirho = temp_root_chirho();
        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &root_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let dag_chirho = writer_dag_chirho(&root_chirho);
        app_chirho::deploy_app_chirho(&root_chirho, "cardshop", dag_chirho.clone(), &owner_chirho)
            .unwrap();
        app_chirho::deploy_app_route_chirho(
            &root_chirho,
            "cardshop",
            "orders",
            dag_chirho,
            &owner_chirho,
        )
        .unwrap();
        app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            "cardshop",
            None,
            &owner_chirho,
            app_chirho::AppInputModeChirho::PlainChirho,
        )
        .unwrap();
        app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            "cardshop",
            Some("orders"),
            &owner_chirho,
            app_chirho::AppInputModeChirho::PlainChirho,
        )
        .unwrap();

        let descriptor_chirho = app_descriptor_chirho(&root_chirho, "cardshop")
            .unwrap()
            .unwrap();
        let descriptor_json_chirho = serde_json::to_string(&descriptor_chirho).unwrap();
        assert!(!descriptor_json_chirho.contains(&owner_chirho));
        assert!(!descriptor_json_chirho.contains("owner_principal"));
        assert_eq!(descriptor_chirho.schema_chirho, "app-descriptor-v1-chirho");
        assert_eq!(descriptor_chirho.route_count_chirho, 2);
        let root_route_chirho = descriptor_chirho
            .routes_chirho
            .iter()
            .find(|r_chirho| r_chirho.route_chirho.is_none())
            .unwrap();
        assert_eq!(root_route_chirho.path_chirho, "/app-chirho/cardshop");
        assert_eq!(root_route_chirho.input_mode_chirho, "plain");
        assert!(
            root_route_chirho
                .capability_summary_chirho
                .can_write_data_chirho
        );
        let orders_chirho = descriptor_chirho
            .routes_chirho
            .iter()
            .find(|r_chirho| r_chirho.route_chirho.as_deref() == Some("orders"))
            .unwrap();
        assert_eq!(orders_chirho.path_chirho, "/app-chirho/cardshop/orders");
        assert!(orders_chirho
            .capability_summary_chirho
            .sentence_chirho
            .contains("save data under \"contact/\""));

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn undeployed_app_has_no_descriptor_chirho() {
        let root_chirho = temp_root_chirho();
        assert!(app_descriptor_chirho(&root_chirho, "nope-chirho")
            .unwrap()
            .is_none());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn absent_input_policy_is_honestly_unset_chirho() {
        let root_chirho = temp_root_chirho();
        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &root_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let dag_chirho = writer_dag_chirho(&root_chirho);
        app_chirho::deploy_app_chirho(&root_chirho, "bareapp", dag_chirho, &owner_chirho).unwrap();

        let descriptor_chirho = app_descriptor_chirho(&root_chirho, "bareapp")
            .unwrap()
            .unwrap();
        assert_eq!(
            descriptor_chirho.routes_chirho[0].input_mode_chirho,
            "unset"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn tampered_input_policy_log_fails_descriptor_closed_chirho() {
        let root_chirho = temp_root_chirho();
        let owner_chirho = crate::identity_chirho::register_identity_chirho(
            &root_chirho,
            crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let dag_chirho = writer_dag_chirho(&root_chirho);
        app_chirho::deploy_app_chirho(&root_chirho, "tamperapp", dag_chirho, &owner_chirho)
            .unwrap();
        app_chirho::set_app_input_policy_chirho(
            &root_chirho,
            "tamperapp",
            None,
            &owner_chirho,
            app_chirho::AppInputModeChirho::PlainChirho,
        )
        .unwrap();
        assert!(app_descriptor_chirho(&root_chirho, "tamperapp")
            .unwrap()
            .is_some());

        let log_path_chirho = root_chirho.join("app-input-policy-records-chirho.jsonl");
        let tampered_chirho = std::fs::read_to_string(&log_path_chirho)
            .unwrap()
            .replace("tamperapp", "tamperapq");
        std::fs::write(&log_path_chirho, tampered_chirho).unwrap();

        let result_chirho = app_descriptor_chirho(&root_chirho, "tamperapp");
        assert!(
            result_chirho.is_err(),
            "a tampered signed input-policy log must make the descriptor unavailable, not benign"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
